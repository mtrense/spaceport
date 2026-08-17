//! Tunnelling WebSocket upgrades to apps — and cutting the tunnel when the
//! credential that opened it dies.
//!
//! A WebSocket is authenticated exactly once, at the handshake: after the
//! `101` there is no request the gate could re-check, no JWT cache to purge,
//! and a connection could outlive every revocation lever the spec built —
//! which is precisely what the spec forbids: "WS connections are tracked per
//! session and terminated when their session is dropped, revoked or expires,
//! so handshake auth never outlives revocation". So a tunnel through a gated
//! app registers itself with the process's revocation fan-out (the
//! [`crate::auth::JwtCache`], which every purge lever already reaches) and
//! selects on its kill switch beside the byte-copying; expiry — known to the
//! second at handshake, since the credential's `expires_at` is in the row that
//! admitted it — is a deadline timer armed once, exact and with no sweep loop
//! to supervise.
//!
//! Open apps' WebSockets, and upgrades under a gated app's public prefixes,
//! tunnel untracked: no session authenticated them, so no session's death can
//! have anything to say about them — they end when either side hangs up, as
//! any proxy would have it.
//!
//! Mechanically this is hyper's upgrade dance on both sides. The edge already
//! serves every connection `with_upgrades`, so the client half is the
//! `OnUpgrade` riding the request; the upstream half is a dedicated HTTP/1.1
//! connection — not the pooled [`super::proxy::Upstreams`] client, because an
//! upgraded connection is spoken for and must never return to a pool — driven
//! `with_upgrades` too. Once both futures resolve, the tunnel is
//! `copy_bidirectional` with no opinion about frames: spaceport moves bytes,
//! and the WebSocket protocol stays the app's and the client's business.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use http::uri::PathAndQuery;
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::EdgeState;
use super::gate;
use super::proxy;
use super::service::ConnInfo;
use crate::app::Auth;
use crate::app::manifest::Host;
use crate::app::store::App;
use crate::auth::UserId;
use crate::secret::Secret;

/// Whether `req` asks for a WebSocket upgrade: a GET whose `Upgrade` header
/// names `websocket` among its offers. Any other upgrade keeps the old
/// behaviour — the hop-by-hop strip terminates it and the request crosses as
/// plain HTTP — because `websocket` is the one protocol the spec contracts
/// spaceport to carry.
pub(super) fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    req.method() == Method::GET
        && req
            .headers()
            .get(header::UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|offer| offer.trim().eq_ignore_ascii_case("websocket"))
            })
}

/// What holds a tracked tunnel open: whose credential it is, and the moment it
/// stops counting.
struct Leash {
    user: UserId,
    expires_at: String,
}

/// Tunnel an admitted WebSocket upgrade to `app`, tracking it when a session
/// or API key vouched for it.
///
/// The gate has already run: `bearer` is its verdict, and doubles as the
/// tracking decision — a JWT was minted exactly when a credential
/// authenticated the request, so `Some` is a tunnel to track and `None` (an
/// open app, a public prefix) is one to leave alone. The credential is
/// re-read from the still-unstripped headers rather than threaded out of the
/// gate, because the gate's admission answer is deliberately narrow and the
/// upgrade path is the one caller that needs more.
pub(super) async fn tunnel(
    state: Arc<EdgeState>,
    app: Arc<App>,
    host: &Host,
    conn: Option<ConnInfo>,
    bearer: Option<Secret>,
    mut req: Request<Incoming>,
) -> Response<Body> {
    let name = host.as_str();
    // The leash before anything irreversible. Ordering matters for the race
    // with revocation: the credential is read (user, expiry), the kill switch
    // registered, and the credential read *again* — a revoke that lands before
    // the second read refuses the upgrade, and one that lands after it finds
    // the switch already registered and fires it. No interleaving lets a
    // just-revoked credential keep an untracked socket.
    let leash = match &bearer {
        Some(_) => match credential_leash(&state, &app, &req).await {
            Ok(Some(leash)) => {
                let kill = state.jwt_cache.track_socket(&leash.user);
                match credential_leash(&state, &app, &req).await {
                    Ok(Some(_)) => Some((leash, kill)),
                    Ok(None) => {
                        return proxy::refuse(StatusCode::UNAUTHORIZED, "signed out\n".into());
                    }
                    Err(error) => {
                        warn!(error = %format!("{error:#}"), "could not re-check a websocket credential");
                        return proxy::refuse(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "spaceport could not check the session\n".into(),
                        );
                    }
                }
            }
            // The gate admitted it a moment ago; a credential gone since is a
            // revocation winning the race, and failing closed is the point.
            Ok(None) => {
                return proxy::refuse(StatusCode::UNAUTHORIZED, "signed out\n".into());
            }
            Err(error) => {
                warn!(error = %format!("{error:#}"), "could not check a websocket credential");
                return proxy::refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "spaceport could not check the session\n".into(),
                );
            }
        },
        None => None,
    };

    // The deadline, armed from the expiry the handshake just read: exact, and
    // the only expiry enforcement this connection will ever see.
    let deadline = match &leash {
        Some((leash, _)) => match deadline_at(&leash.expires_at) {
            Some(deadline) => Some(deadline),
            // Every authoritative check parses this same stamp and would have
            // refused; an unreadable one here still must not mean "forever".
            None => {
                return proxy::refuse(StatusCode::UNAUTHORIZED, "signed out\n".into());
            }
        },
        None => None,
    };

    // The client's half of the upgrade, taken off the request before the
    // rewrite: hyper completes it once this handler answers `101`.
    let client_upgrade = hyper::upgrade::on(&mut req);

    // The same rewrite every proxied request gets — and then the upgrade
    // headers restored in spaceport's own voice, since the hop-by-hop strip
    // rightly took the client's: the upgrade is negotiated per hop, and this
    // is the next hop asking for it.
    *req.uri_mut() = origin_form(req.uri());
    *req.version_mut() = http::Version::HTTP_11;
    proxy::forwarded_headers(req.headers_mut(), host, state.https_port, conn);
    proxy::strip_spaceport_headers(
        req.headers_mut(),
        matches!(app.manifest.auth, Auth::Edge { .. }),
    );
    req.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    req.headers_mut()
        .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    if let Some(jwt) = bearer {
        match HeaderValue::from_str(&format!("Bearer {}", jwt.expose())) {
            Ok(value) => {
                req.headers_mut().insert(header::AUTHORIZATION, value);
            }
            // The same refusal the plain path gives an unrenderable token:
            // failing closed at the edge, not open at the app.
            Err(error) => {
                warn!(app = %app.id, %error, "could not render the minted jwt as a header");
                return proxy::refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "spaceport could not attach its credentials\n".into(),
                );
            }
        }
    }

    let mut response = match upstream_handshake(app.upstream, req).await {
        Ok(response) => response,
        Err(error) => {
            warn!(app = %app.id, upstream = %app.upstream, error = %format!("{error:#}"), "websocket upstream handshake failed");
            return proxy::refuse(
                StatusCode::BAD_GATEWAY,
                format!("spaceport could not reach the app serving {name}\n"),
            );
        }
    };

    // The app declined to upgrade — an ordinary response, forwarded as one.
    // Nothing to track either: no tunnel exists to outlive anything.
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        let (mut parts, body) = response.into_parts();
        proxy::strip_hop_by_hop(&mut parts.headers);

        return Response::from_parts(parts, Body::new(body));
    }

    let upstream_upgrade = hyper::upgrade::on(&mut response);
    let app_id = app.id.clone();
    tokio::spawn(async move {
        let (client, upstream) = match tokio::try_join!(client_upgrade, upstream_upgrade) {
            Ok(both) => both,
            // A side that never upgraded is a client or app gone mid-dance;
            // dropping the halves closes whatever did open.
            Err(error) => {
                debug!(app = %app_id, %error, "a websocket upgrade never completed");
                return;
            }
        };
        let mut client = TokioIo::new(client);
        let mut upstream = TokioIo::new(upstream);

        // The kill switch outlives this task's interest in it through the
        // guard: when the tunnel ends — either side hanging up, the switch
        // firing, the deadline passing — the guard cancels the token and the
        // registry sweeps the entry on its next pass.
        let (watch, _guard) = match leash {
            Some((_, kill)) => (Some(kill.clone()), Some(kill.drop_guard())),
            None => (None, None),
        };
        let killed = async {
            match &watch {
                Some(watch) => watch.cancelled().await,
                None => std::future::pending().await,
            }
        };
        let expired = async {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            shovelled = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {
                if let Err(error) = shovelled {
                    debug!(app = %app_id, %error, "a websocket tunnel closed with an error");
                }
            }
            () = killed => {
                debug!(app = %app_id, "cut a websocket tunnel: its credential was revoked");
            }
            () = expired => {
                debug!(app = %app_id, "cut a websocket tunnel: its session expired");
            }
        }
        // Dropping both halves is the teardown, in every arm alike: the TCP
        // connections close, and each side sees the socket end.
    });

    // The `101` back to the client — hyper sees the status and hands the
    // connection to the `OnUpgrade` the spawned task is awaiting.
    let (mut parts, _) = response.into_parts();
    proxy::strip_hop_by_hop(&mut parts.headers);
    parts
        .headers
        .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    parts
        .headers
        .insert(header::UPGRADE, HeaderValue::from_static("websocket"));

    Response::from_parts(parts, Body::empty())
}

/// The user and expiry behind the credential this request presented — the API
/// key when one rode `Authorization`, the app-session cookie otherwise,
/// mirroring the gate's own precedence so the tunnel is leashed to the very
/// credential that authenticated it.
async fn credential_leash<B>(
    state: &EdgeState,
    app: &App,
    req: &Request<B>,
) -> anyhow::Result<Option<Leash>> {
    if let Some(key) = gate::bearer_api_key(req.headers()) {
        return Ok(state
            .sessions
            .api_key_grant(&key, &app.id)
            .await?
            .map(|(user, _, expires_at)| Leash { user, expires_at }));
    }

    if let Some(token) = super::home::cookie_value(req.headers(), gate::APP_SESSION_COOKIE) {
        return Ok(state
            .sessions
            .app_session_grant(&Secret::new(token), &app.id)
            .await?
            .map(|(user, expires_at)| Leash { user, expires_at }));
    }

    Ok(None)
}

/// When the RFC 3339 stamp `expires_at` falls, as an instant the deadline
/// timer can sleep until — `None` for a stamp this build cannot read, which
/// the caller refuses rather than serving without a fuse.
fn deadline_at(expires_at: &str) -> Option<tokio::time::Instant> {
    let expires =
        time::OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339)
            .ok()?;
    let left = expires - time::OffsetDateTime::now_utc();
    let left: std::time::Duration = left.try_into().unwrap_or_default();

    Some(tokio::time::Instant::now() + left)
}

/// The request line an upstream expects: origin-form. The dedicated
/// connection knows where it is going — the socket is the address — so unlike
/// [`super::proxy::upstream_uri`] there is no authority to carry, and hyper
/// would write an absolute-form request line if one were left in.
fn origin_form(uri: &http::Uri) -> http::Uri {
    uri.path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"))
        .to_string()
        .parse()
        .unwrap_or_else(|_| http::Uri::from_static("/"))
}

/// One dedicated HTTP/1.1 connection to `upstream`, the request sent, the
/// response head returned with its upgrade still pending. The connection task
/// is spawned `with_upgrades`, which is what lets `hyper::upgrade::on` hand
/// the raw IO back after a `101`.
async fn upstream_handshake(
    upstream: SocketAddr,
    req: Request<Incoming>,
) -> anyhow::Result<Response<Incoming>> {
    use anyhow::Context as _;

    let stream = tokio::time::timeout(proxy::CONNECT_TIMEOUT, TcpStream::connect(upstream))
        .await
        .context("connecting to the app timed out")?
        .context("connecting to the app")?;
    stream.set_nodelay(true).ok();

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("speaking http to the app")?;
    tokio::spawn(async move {
        // The connection future owns the socket for as long as the tunnel
        // lives; an error here after teardown is the ordinary end of it.
        if let Err(error) = connection.with_upgrades().await {
            debug!(%error, "a websocket upstream connection ended with an error");
        }
    });

    sender
        .send_request(req)
        .await
        .context("asking the app for the upgrade")
}

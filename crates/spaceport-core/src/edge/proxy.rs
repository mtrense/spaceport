//! Forwarding requests to apps.
//!
//! The request arrives with hyper's `Incoming` body intact and unboxed and is
//! handed to the upstream that way, so a body streams through spaceport
//! without ever being buffered or copied.
//!
//! Upstreams are plain HTTP/1.1 on loopback: apps are published on a local port
//! by the container runtime, so there is nothing to encrypt and no name to
//! resolve. What the app *sees* is still the original request — same `Host`,
//! same path — plus the `X-Forwarded-*` headers describing the hop it can no
//! longer observe for itself.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use http::uri::{Authority, PathAndQuery, Scheme as UriScheme};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, header};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use tower::ServiceExt;
use tracing::{debug, warn};

use super::EdgeState;
use super::gate;
use super::service::{self, ConnInfo};
use super::websocket;
use crate::app::Auth;
use crate::app::manifest::Host;
use crate::app::store::Route;

/// Headers that describe one hop and must not be passed on to the next.
///
/// `upgrade` among them, because an upgrade is negotiated per hop: WebSocket
/// requests take [`super::websocket`]'s tunnel, which strips the client's
/// headers here and then asks the upstream for the upgrade in spaceport's own
/// voice. Any *other* upgrade is terminated by this strip and crosses as plain
/// HTTP — `websocket` is the one protocol the spec contracts spaceport to
/// carry.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");

/// How long to wait for an app to accept a connection. Loopback either answers
/// immediately or is not listening; a longer wait only holds the client open.
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The connection pool spaceport forwards through, shared by every request.
pub struct Upstreams {
    client: Client<HttpConnector, Incoming>,
}

impl Upstreams {
    pub fn new() -> Self {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        connector.set_connect_timeout(Some(CONNECT_TIMEOUT));

        Self {
            client: Client::builder(TokioExecutor::new())
                .pool_idle_timeout(Duration::from_secs(30))
                .build(connector),
        }
    }
}

impl Default for Upstreams {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn handle(
    state: Arc<EdgeState>,
    mut req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    // Copied out before the request is rewritten: the rewrite is what destroys
    // them, and the error paths still want to name the host that failed.
    let conn = req.extensions().get::<ConnInfo>().copied();
    let Some(authority) = service::request_host(&req).map(str::to_owned) else {
        return Ok(refuse(
            StatusCode::BAD_REQUEST,
            "spaceport cannot route a request that names no host\n".into(),
        ));
    };
    // What the client said, used to match a route and to name the host in a
    // refusal — and for nothing else. Routing only reads up to the first `:`,
    // so the rest of this string was never checked against anything: a
    // `Host: alpha.test:@evil.com` matches `alpha.test` and carries userinfo
    // that would make a browser resolve the app's own absolute URLs to
    // somewhere else entirely. Past this point the name comes from `matched`.
    let name = service::host_name(&authority).unwrap_or(&authority);

    let routes = state.apps.routes();
    let Some((matched, route)) = routes.matched(name) else {
        debug!(
            host = name,
            path = req.uri().path(),
            "no app serves this host"
        );
        return Ok(refuse(
            StatusCode::NOT_FOUND,
            format!("spaceport has no app for {name}\n"),
        ));
    };
    // Out of the routing snapshot, so it can be dropped rather than pinned for
    // the length of an upstream request.
    let (host, route) = (matched.clone(), route.clone());
    drop(routes);
    let name = host.as_str();

    let app = match route {
        Route::Live(app) => app,
        // Spaceport's own host, which is served in this process. The body is
        // boxed on the way in, as it is for every other route spaceport answers
        // itself — the cost axum's ergonomics are worth on everything that is
        // not the proxy path.
        Route::Spaceport => {
            let home = state.home.clone();
            return Ok(home
                .oneshot(req.map(Body::new))
                .await
                .unwrap_or_else(|never| match never {}));
        }
        // The host is spoken for, by an app an operator has taken out of
        // service on purpose. Saying so — rather than 404, which would mean
        // spaceport has never heard of this name — is the difference between a
        // caller that retries later and one that gives up on the address.
        Route::Suspended(app) => {
            debug!(
                app = %app,
                host = name,
                path = req.uri().path(),
                "the app serving this host is suspended"
            );
            return Ok(refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("the app serving {name} is suspended\n"),
            ));
        }
        // The host is spoken for by an app that should be serving and is not,
        // and spaceport is already trying to get it back. Answering here rather
        // than forwarding is the difference between a caller that waits a
        // second and one that waits out a connect timeout for a container that
        // is not there — and 503, not 502, because there is nothing wrong with
        // the request.
        Route::Down(app) => {
            debug!(
                app = %app,
                host = name,
                path = req.uri().path(),
                "the app serving this host is not running"
            );
            return Ok(refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("the app serving {name} is not running\n"),
            ));
        }
    };

    // The gate stands between routing and forwarding, which is the only place
    // it can: it needs the app's manifest to know whether there is a door, and
    // it must run before the rewrite below destroys the headers it reads. An
    // open app costs one enum match here; a gated one costs a cache lookup on
    // the hot path, and the database reads plus one signature on a miss.
    let bearer = match gate::gate(&state, &app, name, &req).await {
        gate::Admission::Refused(refused) => return Ok(refused),
        gate::Admission::Pass { bearer } => bearer,
    };

    // A WebSocket upgrade leaves the request/response world here: the tunnel
    // does its own rewrite, speaks to the upstream on a dedicated connection,
    // and — when a credential vouched for it — registers with the revocation
    // fan-out so the socket dies with the session. After the gate, so an
    // unauthenticated upgrade got its 401 above like any other fetch.
    if websocket::is_websocket_upgrade(&req) {
        return Ok(websocket::tunnel(state.clone(), app, &host, conn, bearer, req).await);
    }

    let upstream = app.upstream;
    // Kept for the event at the end, which is written after the request has
    // been rewritten into something addressed to the upstream instead.
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let started = Instant::now();

    *req.uri_mut() = upstream_uri(req.uri(), upstream);
    // Upstreams are spoken to over HTTP/1.1 whatever the client used, so an
    // HTTP/2 request must not carry its version into the pool.
    *req.version_mut() = http::Version::HTTP_11;
    forwarded_headers(req.headers_mut(), &host, state.https_port, conn);
    strip_spaceport_headers(
        req.headers_mut(),
        matches!(app.manifest.auth, Auth::Edge { .. }),
    );
    // After the strip, deliberately: every `Authorization` a client sent is
    // gone by now, so the header the app reads can only ever be spaceport's
    // own voice — the JWT contract's `Bearer`, minted by the gate above.
    if let Some(jwt) = bearer {
        match HeaderValue::from_str(&format!("Bearer {}", jwt.expose())) {
            Ok(value) => {
                req.headers_mut().insert(header::AUTHORIZATION, value);
            }
            // A token this build minted always fits in a header; one that does
            // not was never minted here, and forwarding without it fails
            // closed at the app's own verifier rather than open.
            Err(error) => {
                warn!(app = %app.id, %error, "could not render the minted jwt as a header");

                return Ok(refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "spaceport could not attach its credentials\n".into(),
                ));
            }
        }
    }

    match state.upstreams.client.request(req).await {
        Ok(response) => {
            let (mut parts, body) = response.into_parts();
            strip_hop_by_hop(&mut parts.headers);

            // At debug, because one line per request is more than a service's
            // log wants and exactly what `spaceport stream` is for. It costs
            // nothing while nobody is watching: the event is not built unless
            // something is subscribed to it.
            debug!(
                app = %app.id,
                host = name,
                %method,
                path,
                status = parts.status.as_u16(),
                ms = started.elapsed().as_millis(),
                "proxied",
            );

            Ok(Response::from_parts(parts, Body::new(body)))
        }
        Err(error) => {
            warn!(app = %app.id, %upstream, %error, "upstream request failed");
            Ok(refuse(
                StatusCode::BAD_GATEWAY,
                format!("spaceport could not reach the app serving {name}\n"),
            ))
        }
    }
}

/// The same request, re-addressed to `upstream`.
///
/// Only the scheme and authority change: the path and query the client sent
/// are what the app is asked for, byte for byte.
fn upstream_uri(uri: &Uri, upstream: SocketAddr) -> Uri {
    let mut parts = uri.clone().into_parts();
    parts.scheme = Some(UriScheme::HTTP);
    parts.authority = Authority::from_str(&upstream.to_string()).ok();
    // An origin-form request line always has one; `OPTIONS *` and absolute
    // forms may not, and hyper insists on one once there is an authority.
    parts.path_and_query = parts
        .path_and_query
        .or(Some(PathAndQuery::from_static("/")));

    Uri::from_parts(parts).expect("a socket address is a valid authority")
}

/// Prepare `headers` for the next hop: drop what belongs to this one, then say
/// what the app can no longer see for itself.
///
/// The `X-Forwarded-*` headers are set, not appended to. Spaceport is the
/// outermost hop, so anything a client sent under these names is a claim about
/// itself that nothing has checked — passing it through would let any client
/// pick its own address.
///
/// `host` is a [`Host`] rather than a string on purpose, and the authority is
/// rebuilt from it rather than echoed. Routing only ever matches the request's
/// name up to its first `:`, so the `Host` header a client sent has an
/// unchecked tail: `alpha.test:@evil.com` routes to `alpha.test` and, passed
/// on whole, makes every absolute URL the app builds from it resolve at
/// `evil.com` — a password-reset link poisoned through the very proxy that was
/// meant to pin the name. A `Host` was validated and lowercased on its way
/// into a manifest, so there is nothing in it for a client to have chosen.
pub(super) fn forwarded_headers(
    headers: &mut HeaderMap,
    host: &Host,
    https_port: u16,
    conn: Option<ConnInfo>,
) {
    strip_hop_by_hop(headers);

    // HTTP/2 requests carry the host in `:authority` and no `Host` header at
    // all. Restoring it keeps every app on one way of asking "who was I
    // addressed as?", and stops hyper filling it in with the upstream's
    // loopback address. The port is named beside it exactly when a browser
    // would have named it, by the same rule the edge's own redirects use.
    if let Ok(value) = HeaderValue::from_str(&gate::authority(host.as_str(), https_port)) {
        headers.insert(header::HOST, value.clone());
        headers.insert(X_FORWARDED_HOST, value);
    }

    let Some(conn) = conn else { return };
    if let Ok(value) = HeaderValue::from_str(&conn.peer.ip().to_string()) {
        headers.insert(X_FORWARDED_FOR, value);
    }
    headers.insert(
        X_FORWARDED_PROTO,
        HeaderValue::from_static(match conn.scheme {
            super::Scheme::Http => "http",
            super::Scheme::Https => "https",
        }),
    );
}

/// Remove the headers that govern this connection rather than the message.
pub(super) fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // `Connection` names further headers that are hop-by-hop by declaration,
    // so they have to go before `Connection` itself does.
    let declared: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_str(name.trim()).ok())
        .collect();

    for name in declared {
        headers.remove(&name);
    }
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

/// Remove what spaceport speaks for from a request about to cross to the app.
///
/// Any request header under the `X-Spaceport` prefix is dropped whichever way
/// the app is gated: those names are spaceport's own voice to the app, and a
/// client that could smuggle one in would be putting words in it — the check
/// is case-insensitive by construction, since [`HeaderMap`] keys are already
/// lowercased however the wire spelled them.
///
/// For `gating: edge`, the credentials go too. Every `Authorization` header is
/// stripped — that header is spaceport's channel for its own `Bearer` JWT, and
/// the gate has already read and validated any API key out of it *before*
/// this line removes it, exactly as the spec orders those steps. And the
/// spaceport cookies come out of the `Cookie` header while the app's own ride
/// on: the session tokens are credentials *to spaceport*, and an app that saw
/// one could replay its users to every other app on the same edge. A cookie
/// header that cannot be read as text is dropped whole — failing closed costs
/// the app its own cookies on a malformed header, where failing open would
/// cost it the tokens. `gating: open` keeps `Authorization` untouched, as the
/// spec promises: spaceport holds no credentials there to confuse anyone's
/// with.
pub(super) fn strip_spaceport_headers(headers: &mut HeaderMap, gated: bool) {
    let forged: Vec<HeaderName> = headers
        .keys()
        .filter(|name| name.as_str().starts_with("x-spaceport"))
        .cloned()
        .collect();
    for name in forged {
        headers.remove(name);
    }

    if !gated {
        return;
    }

    headers.remove(header::AUTHORIZATION);

    let kept: Vec<&str> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter(|pair| {
            let name = pair.split('=').next().unwrap_or(pair);
            name != super::home::SESSION_COOKIE && name != gate::APP_SESSION_COOKIE
        })
        .collect();
    let kept = kept.join("; ");
    headers.remove(header::COOKIE);
    if !kept.is_empty()
        && let Ok(value) = HeaderValue::from_str(&kept)
    {
        headers.insert(header::COOKIE, value);
    }
}

/// A plain-text refusal, for the cases where no app ever sees the request.
pub(super) fn refuse(status: StatusCode, body: String) -> Response<Body> {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::manifest::AppManifest;
    use crate::app::{App, AppStore};
    use crate::edge::Scheme;
    use crate::edge::routes;
    use crate::edge::service::EdgeService;
    use axum::Router;
    use axum::routing::any;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    use hyper_util::rt::TokioIo;
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;
    use tokio::net::TcpListener;

    fn header(map: &HeaderMap, name: &str) -> String {
        map.get(name)
            .map(|value| value.to_str().unwrap().to_owned())
            .unwrap_or_default()
    }

    #[test]
    fn re_addresses_the_request_without_touching_the_path() {
        let uri = upstream_uri(
            &"/a/b?c=d".parse().unwrap(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        assert_eq!(uri.to_string(), "http://127.0.0.1:8080/a/b?c=d");
    }

    #[test]
    fn gives_a_pathless_request_a_path() {
        let uri = upstream_uri(&"/".parse().unwrap(), "[::1]:8080".parse().unwrap());
        assert_eq!(uri.to_string(), "http://[::1]:8080/");
    }

    #[test]
    fn strips_standard_hop_by_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert(header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(header::ACCEPT, "text/html".parse().unwrap());

        strip_hop_by_hop(&mut headers);

        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key(header::ACCEPT));
    }

    #[test]
    fn strips_headers_the_connection_header_declares() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, "close, X-Hop, x-other".parse().unwrap());
        headers.insert("x-hop", "1".parse().unwrap());
        headers.insert("x-other", "2".parse().unwrap());
        headers.insert("x-kept", "3".parse().unwrap());

        strip_hop_by_hop(&mut headers);

        assert_eq!(headers.len(), 1);
        assert_eq!(header(&headers, "x-kept"), "3");
    }

    #[test]
    fn tells_the_app_who_it_is_talking_to() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "10.0.0.1".parse().unwrap());
        let conn = ConnInfo {
            peer: "203.0.113.7:54321".parse().unwrap(),
            scheme: Scheme::Https,
        };

        forwarded_headers(
            &mut headers,
            &"alpha.test".parse().unwrap(),
            443,
            Some(conn),
        );

        assert_eq!(header(&headers, "host"), "alpha.test");
        assert_eq!(header(&headers, "x-forwarded-host"), "alpha.test");
        assert_eq!(header(&headers, "x-forwarded-proto"), "https");
        // The client's own claim is replaced, not appended to.
        assert_eq!(header(&headers, "x-forwarded-for"), "203.0.113.7");
    }

    /// An edge that is not on 443 names its port, because that is what the
    /// browser put in the header it would otherwise have echoed — an app
    /// building its own absolute URLs needs the address it is really reached
    /// at, not one that drops the port.
    #[test]
    fn names_the_port_the_edge_actually_answers_on() {
        let mut headers = HeaderMap::new();

        forwarded_headers(&mut headers, &"alpha.test".parse().unwrap(), 8443, None);

        assert_eq!(header(&headers, "host"), "alpha.test:8443");
        assert_eq!(header(&headers, "x-forwarded-host"), "alpha.test:8443");
    }

    /// On a gated app the credentials come out — every `Authorization`, and
    /// exactly the spaceport cookies while the app's own ride on.
    #[test]
    fn strips_credentials_for_a_gated_app() {
        let mut headers = HeaderMap::new();
        headers.append(header::AUTHORIZATION, "Bearer smuggled".parse().unwrap());
        headers.append(header::AUTHORIZATION, "Basic YWxzbw==".parse().unwrap());
        headers.append(
            header::COOKIE,
            "__Host-spaceport-session=global; theme=dark"
                .parse()
                .unwrap(),
        );
        headers.append(
            header::COOKIE,
            "__Host-spaceport-app-session=app; lang=en".parse().unwrap(),
        );

        strip_spaceport_headers(&mut headers, true);

        assert!(!headers.contains_key(header::AUTHORIZATION));
        assert_eq!(header(&headers, "cookie"), "theme=dark; lang=en");
    }

    /// A cookie header holding nothing but spaceport's own tokens vanishes
    /// whole rather than crossing as an empty header.
    #[test]
    fn drops_the_cookie_header_when_only_spaceport_cookies_rode_in_it() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "__Host-spaceport-app-session=app".parse().unwrap(),
        );

        strip_spaceport_headers(&mut headers, true);

        assert!(!headers.contains_key(header::COOKIE));
    }

    /// `gating: open` is the spec's promise that `Authorization` passes
    /// through untouched — spaceport holds no credentials there.
    #[test]
    fn leaves_authorization_alone_for_an_open_app() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer theirs".parse().unwrap());
        headers.insert(
            header::COOKIE,
            "__Host-spaceport-session=stray; theme=dark"
                .parse()
                .unwrap(),
        );

        strip_spaceport_headers(&mut headers, false);

        assert_eq!(header(&headers, "authorization"), "Bearer theirs");
        // The cookie jar is untouched too: an open app got no spaceport
        // cookie set on its domain, and what a client sends anyway is not
        // spaceport's to edit.
        assert!(header(&headers, "cookie").contains("theme=dark"));
    }

    /// The `X-Spaceport` prefix is stripped whichever way the app is gated
    /// and however the wire spelled it: header names are lowercased on parse,
    /// so the prefix check cannot be dodged by case.
    #[test]
    fn strips_the_spaceport_prefix_on_any_gating_and_any_spelling() {
        for gated in [true, false] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "X-SpacePort-User".parse::<HeaderName>().unwrap(),
                "smuggled".parse().unwrap(),
            );
            headers.insert(
                "x-spaceport-login".parse::<HeaderName>().unwrap(),
                "smuggled".parse().unwrap(),
            );
            headers.insert(
                "x-spacecraft".parse::<HeaderName>().unwrap(),
                "kept".parse().unwrap(),
            );

            strip_spaceport_headers(&mut headers, gated);

            assert_eq!(headers.len(), 1, "{gated}");
            assert_eq!(header(&headers, "x-spacecraft"), "kept", "{gated}");
        }
    }

    /// An app that reports back what it was asked, so the test can assert on
    /// what actually crossed the hop.
    async fn upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = Router::new().fallback(any(|req: Request<Body>| async move {
            format!(
                "host={} xfh={} xff={} xfp={} path={}",
                header(req.headers(), "host"),
                header(req.headers(), "x-forwarded-host"),
                header(req.headers(), "x-forwarded-for"),
                header(req.headers(), "x-forwarded-proto"),
                req.uri().path_and_query().unwrap(),
            )
        }));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        addr
    }

    /// The edge itself, on a loopback port, so requests reach it the way a real
    /// client's would — `Incoming` body and all.
    async fn edge(apps: Arc<AppStore>) -> SocketAddr {
        edge_over(apps, crate::state::Db::in_memory().unwrap()).await
    }

    /// The same, over a database the test also holds — for the gating tests,
    /// which have to plant users, sessions and entitlements behind the edge's
    /// back and then knock on the front.
    async fn edge_over(apps: Arc<AppStore>, db: crate::state::Db) -> SocketAddr {
        edge_with(apps, db, Arc::new(crate::auth::JwtCache::new())).await
    }

    /// And the same again, sharing the test's own JWT cache — for the purge
    /// tests, whose repositories on the operator side must be emptying the
    /// very cache the edge mints into, exactly as the daemon wires them.
    async fn edge_with(
        apps: Arc<AppStore>,
        db: crate::state::Db,
        jwt_cache: Arc<crate::auth::JwtCache>,
    ) -> SocketAddr {
        let sessions = Arc::new(crate::auth::SessionRepository::with_jwt_cache(
            db.clone(),
            jwt_cache.clone(),
        ));
        let entitlements = Arc::new(crate::auth::EntitlementRepository::with_jwt_cache(
            db.clone(),
            jwt_cache.clone(),
        ));
        let signer = Arc::new(crate::auth::JwtSigner::new(db.clone()));
        let hostname = Some("spaceport.test".to_owned());
        let state = Arc::new(EdgeState {
            router: routes::router(routes::SpaceportRoutes {
                challenges: std::sync::Arc::new(crate::acme::Challenges::new()),
                apps: apps.clone(),
                sessions: sessions.clone(),
                hostname: hostname.clone(),
                https_port: 443,
            }),
            // The home router is wired over the same database as the gate, as
            // the daemon wires it: the full-exchange test signs in there and
            // spends the session here.
            home: crate::edge::home::router(Arc::new(crate::edge::home::Home {
                attempts: Arc::new(crate::connections::github::Attempts::new()),
                connections: Arc::new(crate::connections::github::ConnectionRepository::new(
                    db.clone(),
                )),
                tracking: Arc::new(crate::connections::github::TrackingRepository::new(
                    db.clone(),
                )),
                github: crate::connections::github::api::testing::FakeGitHub::new(),
                nudge: crate::connections::github::Nudge::new(),
                builds: crate::connections::github::Nudge::new(),
                hostname: hostname.clone(),
                sessions: sessions.clone(),
                entitlements: entitlements.clone(),
                auth_log: Arc::new(crate::auth::AuthLogRepository::new(db.clone())),
                apps: apps.clone(),
                signer: signer.clone(),
                jwt_cache: jwt_cache.clone(),
                https_port: 443,
                logins: Arc::new(crate::edge::home::LoginAttempts::new()),
                sso: Arc::new(crate::auth::SsoRepository::new(db)),
            })),
            apps,
            upstreams: Upstreams::new(),
            sessions,
            entitlements,
            signer,
            jwt_cache,
            hostname,
            https_port: 443,
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (stream, peer) = listener.accept().await.unwrap();
                // Https, so the plaintext redirect stays out of the way.
                let conn = ConnInfo {
                    peer,
                    scheme: Scheme::Https,
                };
                let service = TowerToHyperService::new(EdgeService::new(state.clone(), conn));

                // With upgrades, as the daemon serves every connection — the
                // WebSocket tests upgrade through this very fixture.
                tokio::spawn(async move {
                    let _ = Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        addr
    }

    async fn get(edge: SocketAddr, host: &str, path: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .uri(format!("http://{edge}{path}"))
            .header(header::HOST, host)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = Client::builder(TokioExecutor::new())
            .build_http()
            .request(req)
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    fn app(id: &str, host: &str, upstream: SocketAddr) -> App {
        App {
            id: id.parse().unwrap(),
            manifest: AppManifest::parse(&format!(
                "schema_version: 1\nsource:\n  type: image\n  image: x\nrouting:\n  hosts: [{host}]\nauth:\n  gating: open\n"
            ))
            .unwrap(),
            container: crate::runtime::ContainerId::new("test-container"),
            upstream,
        }
    }

    #[tokio::test]
    async fn forwards_a_request_to_the_app_serving_its_host() {
        let apps = Arc::new(AppStore::new());
        apps.insert(app("hello", "alpha.test", upstream().await))
            .unwrap();
        let edge = edge(apps).await;

        let (status, body) = get(edge, "alpha.test", "/greet?loud=1").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            "host=alpha.test xfh=alpha.test xff=127.0.0.1 xfp=https path=/greet?loud=1"
        );
    }

    /// What the app is told it was addressed as is built from the routing
    /// table, never echoed from the request.
    ///
    /// Routing reads the request's host only as far as its first `:`, so
    /// everything after one crosses unexamined if it is passed on whole. The
    /// `@` spelling is the one that bites: it is a legal header byte, it makes
    /// what follows the authority and what precedes it userinfo, and an app
    /// that builds a password-reset link out of its own `Host` would mail a
    /// URL every browser resolves at `evil.com` — through the very proxy whose
    /// job was to pin the name. A matched route key cannot spell any of this:
    /// it is lowercase letters, digits, hyphens and dots, checked on its way
    /// into a manifest.
    #[tokio::test]
    async fn rebuilds_the_host_it_gives_the_app_from_the_route_it_matched() {
        let apps = Arc::new(AppStore::new());
        apps.insert(app("hello", "alpha.test", upstream().await))
            .unwrap();
        let edge = edge(apps).await;

        for spelling in [
            "alpha.test:@evil.com",
            "alpha.test:8080",
            "ALPHA.TEST",
            "alpha.test:evil.com",
        ] {
            let (status, body) = get(edge, spelling, "/greet").await;

            assert_eq!(status, StatusCode::OK, "{spelling}");
            assert!(
                body.starts_with("host=alpha.test xfh=alpha.test "),
                "{spelling}: {body}"
            );
        }
    }

    #[tokio::test]
    async fn does_not_route_a_host_no_app_claims() {
        let apps = Arc::new(AppStore::new());
        apps.insert(app("hello", "alpha.test", upstream().await))
            .unwrap();
        let edge = edge(apps).await;

        let (status, body) = get(edge, "nope.test", "/").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("no app for nope.test"), "{body}");
    }

    /// The host is spoken for by an app somebody took out of service. A 404
    /// would say spaceport has never heard of the name, which is what makes a
    /// caller give up on the address rather than come back later.
    #[tokio::test]
    async fn answers_for_a_suspended_app_instead_of_forwarding() {
        let apps = Arc::new(AppStore::new());
        apps.insert(app("hello", "alpha.test", upstream().await))
            .unwrap();
        apps.suspend(&"hello".parse().unwrap(), None).unwrap();
        let edge = edge(apps).await;

        let (status, body) = get(edge, "alpha.test", "/").await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("serving alpha.test is suspended"), "{body}");
    }

    /// The host is spoken for by an app spaceport is already trying to get
    /// back. Forwarding would spend a connect timeout on a container that is
    /// not there, and a 404 would tell the caller to give up on the address.
    #[tokio::test]
    async fn answers_for_a_down_app_instead_of_forwarding() {
        let apps = Arc::new(AppStore::new());
        apps.insert(app("hello", "alpha.test", upstream().await))
            .unwrap();
        apps.take_down(&"hello".parse().unwrap(), "the container stopped")
            .unwrap();
        let edge = edge(apps).await;

        let (status, body) = get(edge, "alpha.test", "/").await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("serving alpha.test is not running"), "{body}");
    }

    #[tokio::test]
    async fn reports_a_bad_gateway_when_the_app_is_not_listening() {
        // Bound and dropped: nothing is listening there, but the port is real.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = dead.local_addr().unwrap();
        drop(dead);

        let apps = Arc::new(AppStore::new());
        apps.insert(app("hello", "alpha.test", addr)).unwrap();
        let edge = edge(apps).await;

        let (status, _) = get(edge, "alpha.test", "/").await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn keeps_serving_its_own_routes() {
        let edge = edge(Arc::new(AppStore::new())).await;

        let (status, body) = get(edge, "alpha.test", "/.spaceport/health").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok\n");
    }

    /// Reached over the same listener, by the same host lookup, as any app —
    /// and answered in this process rather than forwarded anywhere.
    #[tokio::test]
    async fn serves_its_own_hostname_itself() {
        let apps = Arc::new(AppStore::answering_to(Some(
            "spaceport.test".parse().unwrap(),
        )));
        apps.insert(app("hello", "alpha.test", upstream().await))
            .unwrap();
        let edge = edge(apps).await;

        let (status, body) = get(edge, "spaceport.test", "/").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with("spaceport "), "{body}");
    }

    /// Its own host is one host, not a catch-all: an app applied alongside it
    /// still gets its traffic.
    #[tokio::test]
    async fn goes_on_forwarding_every_other_host() {
        let apps = Arc::new(AppStore::answering_to(Some(
            "spaceport.test".parse().unwrap(),
        )));
        apps.insert(app("hello", "alpha.test", upstream().await))
            .unwrap();
        let edge = edge(apps).await;

        let (status, body) = get(edge, "alpha.test", "/greet").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with("host=alpha.test"), "{body}");
    }

    /// A spaceport that was given no hostname answers to none: the host that
    /// would have been its own is a 404 like any other name.
    #[tokio::test]
    async fn serves_no_host_of_its_own_unless_configured() {
        let edge = edge(Arc::new(AppStore::new())).await;

        let (status, _) = get(edge, "spaceport.test", "/").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// A gated app, in the shape [`app`] makes an open one.
    fn gated(id: &str, host: &str, upstream: SocketAddr, public: &str) -> App {
        let public = if public.is_empty() {
            String::new()
        } else {
            format!("  public_path_prefixes: [{public}]\n")
        };

        App {
            id: id.parse().unwrap(),
            manifest: AppManifest::parse(&format!(
                "schema_version: 1\nsource:\n  type: image\n  image: x\nrouting:\n  hosts: [{host}]\nauth:\n  gating: edge\n{public}  roles: [reader]\n"
            ))
            .unwrap(),
            container: crate::runtime::ContainerId::new("test-container"),
            upstream,
        }
    }

    /// One request with whatever headers the test needs, answering with the
    /// whole response head and body.
    async fn get_headed(
        edge: SocketAddr,
        host: &str,
        path: &str,
        extra: &[(&str, &str)],
    ) -> (StatusCode, HeaderMap, String) {
        send(edge, "GET", host, path, extra).await
    }

    /// The same, with the method in the test's hands — what the CSRF tests
    /// need, since the whole check hangs on it.
    async fn send(
        edge: SocketAddr,
        method: &str,
        host: &str,
        path: &str,
        extra: &[(&str, &str)],
    ) -> (StatusCode, HeaderMap, String) {
        let mut req = Request::builder()
            .method(method)
            .uri(format!("http://{edge}{path}"))
            .header(header::HOST, host);
        for (name, value) in extra {
            req = req.header(*name, *value);
        }

        let response = Client::builder(TokioExecutor::new())
            .build_http()
            .request(req.body(Empty::<Bytes>::new()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    const NAVIGATE: &[(&str, &str)] = &[("accept", "text/html"), ("sec-fetch-mode", "navigate")];

    /// The front door of milestone 5a: a browser knocking on a gated app is
    /// sent to the exchange with the app, the host it asked, and its whole
    /// path and query — and nothing reached the app.
    #[tokio::test]
    async fn a_navigation_to_a_gated_app_without_a_cookie_bounces_to_the_exchange() {
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let edge = edge(apps).await;

        let (status, headers, _) = get_headed(edge, "alpha.test", "/posts?q=1", NAVIGATE).await;

        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            header(&headers, "location"),
            "https://spaceport.test/auth/exchange?app=blog&host=alpha.test&next=%2Fposts%3Fq%3D1"
        );
    }

    /// A fetch, an XHR or a WebSocket handshake would swallow a redirect
    /// invisibly, so they are told in headers instead — and never forwarded.
    #[tokio::test]
    async fn a_non_navigation_to_a_gated_app_gets_a_401_with_directions() {
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let edge = edge(apps).await;

        let (status, headers, _) = get_headed(
            edge,
            "alpha.test",
            "/api/posts",
            &[("accept", "application/json")],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(header(&headers, "www-authenticate"), "Bearer");
        assert!(
            header(&headers, "x-spaceport-login")
                .starts_with("https://spaceport.test/auth/exchange?app=blog"),
            "{headers:?}"
        );
    }

    /// `gating: open` is the whole of the old behaviour, untouched: no
    /// redirect, no headers, the request straight through.
    #[tokio::test]
    async fn an_open_app_is_forwarded_exactly_as_before() {
        let apps = Arc::new(AppStore::new());
        apps.insert(app("hello", "alpha.test", upstream().await))
            .unwrap();
        let edge = edge(apps).await;

        let (status, headers, body) = get_headed(edge, "alpha.test", "/greet", NAVIGATE).await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with("host=alpha.test"), "{body}");
        assert!(header(&headers, "x-spaceport-login").is_empty());
    }

    /// Public prefixes hold the door open at segment boundaries and nowhere
    /// else: `/public/x` passes, `/publicfoo` is gated, and the dot-segment
    /// spellings of a private path cannot borrow the prefix's pass.
    #[tokio::test]
    async fn public_prefixes_pass_at_segment_boundaries_only() {
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, "'/public'"))
            .unwrap();
        let edge = edge(apps).await;

        for open in ["/public", "/public/style.css"] {
            let (status, _, _) = get_headed(edge, "alpha.test", open, NAVIGATE).await;
            assert_eq!(status, StatusCode::OK, "{open}");
        }
        for gated in [
            "/publicfoo",
            "/public/../secret",
            "/public/%2e%2e/secret",
            "/",
        ] {
            let (status, _, _) = get_headed(edge, "alpha.test", gated, NAVIGATE).await;
            assert_eq!(status, StatusCode::SEE_OTHER, "{gated}");
        }
        // And the dodges cannot fake a match from outside the prefix either
        // way round: canonicalized, `//public/x` is public and passes.
        let (status, _, _) = get_headed(edge, "alpha.test", "//public/x", NAVIGATE).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// The whole exchange, driven as one browser would drive it: gate to
    /// exchange, exchange to callback, callback to the original path — which
    /// then serves, because the cookie set on the app's domain is real.
    #[tokio::test]
    async fn the_redirect_chain_ends_with_an_app_cookie_and_the_original_path() {
        let db = crate::state::Db::in_memory().unwrap();
        // The logout at the end is a purge lever, so the repository the test
        // drops sessions through must share the cache the edge mints into —
        // the same wiring the daemon does.
        let jwt_cache = Arc::new(crate::auth::JwtCache::new());
        let users = crate::auth::UserRepository::new(db.clone());
        let sessions =
            crate::auth::SessionRepository::with_jwt_cache(db.clone(), jwt_cache.clone());
        let entitlements = crate::auth::EntitlementRepository::new(db.clone());
        let alice: crate::auth::UserRef = "alice".parse().unwrap();
        users.create(&"alice".parse().unwrap(), None).await.unwrap();
        entitlements
            .grant(&alice, &"reader@blog".parse().unwrap())
            .await
            .unwrap();
        let minted = sessions
            .mint_code(&alice, crate::auth::DEFAULT_SESSION_LIFETIME)
            .await
            .unwrap();
        let fresh = sessions.redeem(&minted.code).await.unwrap();

        let apps = Arc::new(AppStore::answering_to(Some(
            "spaceport.test".parse().unwrap(),
        )));
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let edge = edge_with(apps, db, jwt_cache).await;

        // Hop one: the gate.
        let (status, headers, _) = get_headed(edge, "alpha.test", "/posts?q=1", NAVIGATE).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let (host, path) = split_https(&header(&headers, "location"));
        assert_eq!(host, "spaceport.test");

        // Hop two: the exchange, with the global session cookie.
        let cookie = format!("__Host-spaceport-session={}", fresh.token.expose());
        let (status, headers, _) = get_headed(
            edge,
            &host,
            &path,
            &[("accept", "text/html"), ("cookie", &cookie)],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let (host, path) = split_https(&header(&headers, "location"));
        assert_eq!(host, "alpha.test");
        assert!(path.starts_with("/.spaceport/callback?nonce="), "{path}");

        // Hop three: the callback, on the app's own domain.
        let (status, headers, _) = get_headed(edge, &host, &path, NAVIGATE).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(header(&headers, "location"), "/posts?q=1");
        let set = header(&headers, "set-cookie");
        assert!(set.starts_with("__Host-spaceport-app-session="), "{set}");
        for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/", "Max-Age="] {
            assert!(set.contains(attribute), "{set}");
        }

        // And the destination: the original path and query, actually served.
        let app_cookie = set.split(';').next().unwrap().to_owned();
        let (status, _, body) = get_headed(
            edge,
            "alpha.test",
            "/posts?q=1",
            &[("accept", "text/html"), ("cookie", &app_cookie)],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.ends_with("path=/posts?q=1"), "{body}");

        // Logging out on the edge kills the derived cookie too: the next
        // knock on the app is a stranger's again.
        sessions.logout(&fresh.token).await.unwrap();
        let (status, _, _) = get_headed(
            edge,
            "alpha.test",
            "/posts?q=1",
            &[("accept", "text/html"), ("cookie", &app_cookie)],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }

    /// A nonce is one redemption: replaying the callback URL — a reload, a
    /// bookmark — restarts the exchange rather than erroring, so the second
    /// visit heals into a fresh sign-in instead of stranding the browser.
    #[tokio::test]
    async fn a_replayed_callback_restarts_the_exchange() {
        let db = crate::state::Db::in_memory().unwrap();
        let users = crate::auth::UserRepository::new(db.clone());
        let sessions = crate::auth::SessionRepository::new(db.clone());
        let alice: crate::auth::UserRef = "alice".parse().unwrap();
        users.create(&"alice".parse().unwrap(), None).await.unwrap();
        let minted = sessions
            .mint_code(&alice, crate::auth::DEFAULT_SESSION_LIFETIME)
            .await
            .unwrap();
        let fresh = sessions.redeem(&minted.code).await.unwrap();
        let (session, user) = sessions.session_of(&fresh.token).await.unwrap().unwrap();
        let nonce = sessions
            .mint_nonce(&user, &"blog".parse().unwrap(), &session)
            .await
            .unwrap();

        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let edge = edge_over(apps, db).await;
        let path = format!(
            "/.spaceport/callback?nonce={}&next=%2Fposts",
            nonce.expose()
        );

        let (first, headers, _) = get_headed(edge, "alpha.test", &path, NAVIGATE).await;
        assert_eq!(first, StatusCode::SEE_OTHER);
        assert!(!header(&headers, "set-cookie").is_empty());

        let (second, headers, _) = get_headed(edge, "alpha.test", &path, NAVIGATE).await;
        assert_eq!(second, StatusCode::SEE_OTHER);
        assert!(header(&headers, "set-cookie").is_empty());
        assert_eq!(
            header(&headers, "location"),
            "https://spaceport.test/auth/exchange?app=blog&host=alpha.test&next=%2Fposts"
        );
    }

    /// The open-redirect gate at the callback: a `next` that is not a plain
    /// absolute path lands on `/`, never on another origin.
    #[tokio::test]
    async fn the_callback_refuses_a_next_that_leaves_the_apps_origin() {
        for hostile in ["%2F%2Fevil.example", "https%3A%2F%2Fevil.example", "posts"] {
            let db = crate::state::Db::in_memory().unwrap();
            let users = crate::auth::UserRepository::new(db.clone());
            let sessions = crate::auth::SessionRepository::new(db.clone());
            let alice: crate::auth::UserRef = "alice".parse().unwrap();
            users.create(&"alice".parse().unwrap(), None).await.unwrap();
            let minted = sessions
                .mint_code(&alice, crate::auth::DEFAULT_SESSION_LIFETIME)
                .await
                .unwrap();
            let fresh = sessions.redeem(&minted.code).await.unwrap();
            let (session, user) = sessions.session_of(&fresh.token).await.unwrap().unwrap();
            let nonce = sessions
                .mint_nonce(&user, &"blog".parse().unwrap(), &session)
                .await
                .unwrap();

            let apps = Arc::new(AppStore::new());
            apps.insert(gated("blog", "alpha.test", upstream().await, ""))
                .unwrap();
            let edge = edge_over(apps, db).await;

            let (status, headers, _) = get_headed(
                edge,
                "alpha.test",
                &format!(
                    "/.spaceport/callback?nonce={}&next={hostile}",
                    nonce.expose()
                ),
                NAVIGATE,
            )
            .await;

            assert_eq!(status, StatusCode::SEE_OTHER, "{hostile}");
            assert_eq!(header(&headers, "location"), "/", "{hostile}");
        }
    }

    /// A live app-session cookie for `blog`, planted straight into the
    /// database the way the whole exchange would have — user, entitlement,
    /// session, nonce, redemption — so a test can arrive authenticated
    /// without driving three redirects first.
    async fn app_cookie(db: &crate::state::Db) -> String {
        let users = crate::auth::UserRepository::new(db.clone());
        let sessions = crate::auth::SessionRepository::new(db.clone());
        let entitlements = crate::auth::EntitlementRepository::new(db.clone());
        let alice: crate::auth::UserRef = "alice".parse().unwrap();
        users.create(&"alice".parse().unwrap(), None).await.unwrap();
        entitlements
            .grant(&alice, &"reader@blog".parse().unwrap())
            .await
            .unwrap();
        let minted = sessions
            .mint_code(&alice, crate::auth::DEFAULT_SESSION_LIFETIME)
            .await
            .unwrap();
        let fresh = sessions.redeem(&minted.code).await.unwrap();
        let (session, user) = sessions.session_of(&fresh.token).await.unwrap().unwrap();
        let nonce = sessions
            .mint_nonce(&user, &"blog".parse().unwrap(), &session)
            .await
            .unwrap();
        let fresh = sessions
            .redeem_nonce(&nonce, &"blog".parse().unwrap())
            .await
            .unwrap()
            .unwrap();

        format!("__Host-spaceport-app-session={}", fresh.token.expose())
    }

    /// A POST is what a cross-site form sends, and the cookie is what it
    /// rides: with the browser's own metadata saying `cross-site`, the edge
    /// answers `403` and the app never hears of it — no redirect, which
    /// would hand the forger a signed-in retry.
    #[tokio::test]
    async fn a_cross_site_post_with_the_app_cookie_is_refused() {
        let db = crate::state::Db::in_memory().unwrap();
        let cookie = app_cookie(&db).await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let edge = edge_over(apps, db).await;

        let (status, headers, body) = send(
            edge,
            "POST",
            "alpha.test",
            "/submit",
            &[("cookie", &cookie), ("sec-fetch-site", "cross-site")],
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("CSRF"), "{body}");
        assert!(!headers.contains_key("location"), "{headers:?}");
    }

    /// The same POST from the app's own pages passes — `same-origin` said so
    /// — and a GET passes whatever the metadata says, because a safe method
    /// is not worth forging and cross-site links must keep working.
    #[tokio::test]
    async fn a_same_origin_post_passes_and_a_get_is_never_checked() {
        let db = crate::state::Db::in_memory().unwrap();
        let cookie = app_cookie(&db).await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let edge = edge_over(apps, db).await;

        let (status, _, body) = send(
            edge,
            "POST",
            "alpha.test",
            "/submit",
            &[("cookie", &cookie), ("sec-fetch-site", "same-origin")],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("path=/submit"), "{body}");

        let (status, _, _) = send(
            edge,
            "GET",
            "alpha.test",
            "/posts",
            &[("cookie", &cookie), ("sec-fetch-site", "cross-site")],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    /// The fallback for clients without fetch metadata — old Safari,
    /// WebViews: the `Origin` header must name the app's own host, a wrong
    /// one is refused, and saying nothing at all is refused too.
    #[tokio::test]
    async fn without_fetch_metadata_the_origin_header_decides_at_the_edge() {
        let db = crate::state::Db::in_memory().unwrap();
        let cookie = app_cookie(&db).await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let edge = edge_over(apps, db).await;

        let (status, _, _) = send(
            edge,
            "POST",
            "alpha.test",
            "/submit",
            &[("cookie", &cookie), ("origin", "https://alpha.test")],
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _, _) = send(
            edge,
            "POST",
            "alpha.test",
            "/submit",
            &[("cookie", &cookie), ("origin", "https://evil.test")],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _, _) = send(
            edge,
            "POST",
            "alpha.test",
            "/submit",
            &[("cookie", &cookie)],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// CSRF is a property of cookie authentication and of nothing else: a
    /// stranger's POST is the gate's `401`, not the CSRF check's `403`, and
    /// an open app's POST crosses untouched however cross-site it is.
    #[tokio::test]
    async fn only_a_cookie_authenticated_request_is_csrf_checked() {
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        apps.insert(app("hello", "beta.test", upstream().await))
            .unwrap();
        let edge = edge(apps).await;

        // No cookie: the gate answers before CSRF is even a question.
        let (status, headers, _) = send(
            edge,
            "POST",
            "alpha.test",
            "/submit",
            &[("sec-fetch-site", "cross-site")],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(header(&headers, "www-authenticate"), "Bearer");

        // `gating: open`: no cookie-auth semantics, so no CSRF either.
        let (status, _, _) = send(
            edge,
            "POST",
            "beta.test",
            "/submit",
            &[("sec-fetch-site", "cross-site")],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    /// An app that echoes the credential-shaped headers, for proving what
    /// the strip actually let across the hop.
    async fn credential_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = Router::new().fallback(any(|req: Request<Body>| async move {
            format!(
                "authorization=[{}] cookie=[{}] x-spaceport-user=[{}]",
                header(req.headers(), "authorization"),
                header(req.headers(), "cookie"),
                header(req.headers(), "x-spaceport-user"),
            )
        }));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        addr
    }

    /// What a gated app actually receives: the smuggled `Authorization` and
    /// `X-Spaceport` headers gone, the spaceport cookie gone, the app's own
    /// cookie still riding — and in `Authorization`'s place, spaceport's own
    /// `Bearer`, which is the milestone-6 contract and never the client's word.
    #[tokio::test]
    async fn a_gated_app_never_sees_spaceports_credentials() {
        let db = crate::state::Db::in_memory().unwrap();
        let cookie = app_cookie(&db).await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", credential_echo().await, ""))
            .unwrap();
        let edge = edge_over(apps, db).await;

        let (status, _, body) = send(
            edge,
            "GET",
            "alpha.test",
            "/",
            &[
                ("cookie", &format!("{cookie}; theme=dark")),
                ("authorization", "Bearer smuggled"),
                ("X-SpacePort-User", "smuggled"),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("authorization=[Bearer ey"), "{body}");
        assert!(!body.contains("smuggled"), "{body}");
        assert!(body.contains("cookie=[theme=dark]"), "{body}");
        assert!(body.contains("x-spaceport-user=[]"), "{body}");
    }

    /// And an open app keeps its `Authorization` — that header is its own
    /// affair there — while the `X-Spaceport` prefix dies at the edge for
    /// every gating.
    #[tokio::test]
    async fn an_open_app_keeps_authorization_but_never_sees_the_prefix() {
        let apps = Arc::new(AppStore::new());
        apps.insert(app("hello", "alpha.test", credential_echo().await))
            .unwrap();
        let edge = edge(apps).await;

        let (status, _, body) = send(
            edge,
            "GET",
            "alpha.test",
            "/",
            &[
                ("authorization", "Bearer theirs"),
                ("x-spaceport-user", "smuggled"),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            "authorization=[Bearer theirs] cookie=[] x-spaceport-user=[]"
        );
    }

    /// A live app-session cookie for `user` at `app`, planted the way
    /// [`app_cookie`] plants alice's, with the grants the test names — and the
    /// user id handed back, because the JWT tests assert on `sub`.
    async fn planted_cookie(
        db: &crate::state::Db,
        user: &str,
        grants: &[&str],
        app: &str,
    ) -> (String, crate::auth::UserId) {
        let users = crate::auth::UserRepository::new(db.clone());
        let sessions = crate::auth::SessionRepository::new(db.clone());
        let entitlements = crate::auth::EntitlementRepository::new(db.clone());
        let named: crate::auth::UserRef = user.parse().unwrap();
        let created = users.create(&user.parse().unwrap(), None).await.unwrap();
        for grant in grants {
            entitlements
                .grant(&named, &grant.parse().unwrap())
                .await
                .unwrap();
        }
        let minted = sessions
            .mint_code(&named, crate::auth::DEFAULT_SESSION_LIFETIME)
            .await
            .unwrap();
        let fresh = sessions.redeem(&minted.code).await.unwrap();
        let (session, user) = sessions.session_of(&fresh.token).await.unwrap().unwrap();
        let nonce = sessions
            .mint_nonce(&user, &app.parse().unwrap(), &session)
            .await
            .unwrap();
        let fresh = sessions
            .redeem_nonce(&nonce, &app.parse().unwrap())
            .await
            .unwrap()
            .unwrap();

        (
            format!("__Host-spaceport-app-session={}", fresh.token.expose()),
            created.id,
        )
    }

    /// A gated app whose manifest declares `roles`, for the intersection tests
    /// the fixed `[reader]` of [`gated`] cannot express.
    fn gated_roles(id: &str, host: &str, upstream: SocketAddr, roles: &str) -> App {
        App {
            id: id.parse().unwrap(),
            manifest: AppManifest::parse(&format!(
                "schema_version: 1\nsource:\n  type: image\n  image: x\nrouting:\n  hosts: [{host}]\nauth:\n  gating: edge\n  roles: {roles}\n"
            ))
            .unwrap(),
            container: crate::runtime::ContainerId::new("test-container"),
            upstream,
        }
    }

    /// The `Bearer` the echoing upstream reported receiving, out of its body.
    fn echoed_jwt(body: &str) -> String {
        body.split("authorization=[Bearer ")
            .nth(1)
            .unwrap_or_else(|| panic!("no bearer reached the app: {body}"))
            .split(']')
            .next()
            .unwrap()
            .to_owned()
    }

    fn jwt_payload(jwt: &str) -> serde_json::Value {
        use base64::Engine as _;

        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwt.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap()
    }

    /// The whole milestone-6 contract, end to end: a gated request arrives at
    /// the app carrying a `Bearer` JWT whose claims are the spec's — `iss` the
    /// edge's https origin, `sub` the stable user id, `aud` the app id, five
    /// minutes of `exp`, and `roles` the intersection of the user's
    /// entitlements with what the manifest declares — and whose signature
    /// verifies against the JWKS the same edge serves at the well-known path.
    #[tokio::test]
    async fn a_gated_request_reaches_the_app_with_a_jwt_the_jwks_verifies() {
        use base64::Engine as _;

        let db = crate::state::Db::in_memory().unwrap();
        // Entitled to `reader` (declared), `admin` at this app (undeclared)
        // and `reader` at another app entirely: only the first may surface.
        let (cookie, user) = planted_cookie(
            &db,
            "alice",
            &["reader@blog", "admin@blog", "reader@wiki"],
            "blog",
        )
        .await;
        let apps = Arc::new(AppStore::answering_to(Some(
            "spaceport.test".parse().unwrap(),
        )));
        apps.insert(gated_roles(
            "blog",
            "alpha.test",
            credential_echo().await,
            "[reader, writer]",
        ))
        .unwrap();
        let edge = edge_over(apps, db).await;

        let (status, _, body) = get_headed(edge, "alpha.test", "/", &[("cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::OK);
        let jwt = echoed_jwt(&body);

        let header: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwt.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");

        let payload = jwt_payload(&jwt);
        assert_eq!(payload["iss"], "https://spaceport.test");
        assert_eq!(payload["sub"], user.as_str());
        assert_eq!(payload["aud"], "blog");
        assert_eq!(payload["roles"], serde_json::json!(["reader"]));
        assert_eq!(
            payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap(),
            300
        );

        // The verification an app's middleware performs, against the JWKS the
        // edge itself serves on spaceport's own hostname.
        let (status, _, jwks) =
            get_headed(edge, "spaceport.test", "/.well-known/jwks.json", &[]).await;
        assert_eq!(status, StatusCode::OK);
        let jwks: serde_json::Value = serde_json::from_str(&jwks).unwrap();
        let key = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["kid"] == header["kid"])
            .expect("the jwks names the kid the token claims");
        let public = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(key["x"].as_str().unwrap())
            .unwrap();
        let (message, signature) = jwt.rsplit_once('.').unwrap();
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public)
            .verify(
                message.as_bytes(),
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(signature)
                    .unwrap(),
            )
            .expect("the edge's jwks should verify the edge's token");
    }

    /// The four-minute cache at work: the second request rides the first's
    /// token — same `jti`, no re-mint — and a purge makes the third a fresh
    /// mint with a fresh `jti`.
    #[tokio::test]
    async fn the_cache_reuses_a_jwt_and_a_purge_re_mints() {
        let db = crate::state::Db::in_memory().unwrap();
        let (cookie, user) = planted_cookie(&db, "alice", &["reader@blog"], "blog").await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", credential_echo().await, ""))
            .unwrap();
        let jwt_cache = Arc::new(crate::auth::JwtCache::new());
        let edge = edge_with(apps, db, jwt_cache.clone()).await;

        let (_, _, first) = get_headed(edge, "alpha.test", "/", &[("cookie", &cookie)]).await;
        let (_, _, second) = get_headed(edge, "alpha.test", "/", &[("cookie", &cookie)]).await;
        assert_eq!(
            jwt_payload(&echoed_jwt(&first))["jti"],
            jwt_payload(&echoed_jwt(&second))["jti"],
        );

        jwt_cache.purge_user(&user);

        let (status, _, third) = get_headed(edge, "alpha.test", "/", &[("cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(
            jwt_payload(&echoed_jwt(&first))["jti"],
            jwt_payload(&echoed_jwt(&third))["jti"],
        );
    }

    /// `spaceport auth session drop` is a purge lever: the moment the drop
    /// commits, the cookie stops answering — where a cache nobody purged would
    /// have gone on serving the dropped session for four minutes.
    #[tokio::test]
    async fn a_session_drop_stops_cached_access_immediately() {
        let db = crate::state::Db::in_memory().unwrap();
        let (cookie, _) = planted_cookie(&db, "alice", &["reader@blog"], "blog").await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let jwt_cache = Arc::new(crate::auth::JwtCache::new());
        let edge = edge_with(apps, db.clone(), jwt_cache.clone()).await;
        let extra = [("cookie", cookie.as_str()), ("accept", "text/html")];

        let (status, _, _) = get_headed(edge, "alpha.test", "/", &extra).await;
        assert_eq!(status, StatusCode::OK);

        crate::auth::SessionRepository::with_jwt_cache(db, jwt_cache)
            .drop_sessions(&"alice".parse().unwrap(), None)
            .await
            .unwrap();

        let (status, _, _) = get_headed(edge, "alpha.test", "/", &extra).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }

    /// Suspending the user is the same lever pulled from the pool's side.
    #[tokio::test]
    async fn a_suspend_stops_cached_access_immediately() {
        let db = crate::state::Db::in_memory().unwrap();
        let (cookie, _) = planted_cookie(&db, "alice", &["reader@blog"], "blog").await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let jwt_cache = Arc::new(crate::auth::JwtCache::new());
        let edge = edge_with(apps, db.clone(), jwt_cache.clone()).await;
        let extra = [("cookie", cookie.as_str()), ("accept", "text/html")];

        let (status, _, _) = get_headed(edge, "alpha.test", "/", &extra).await;
        assert_eq!(status, StatusCode::OK);

        crate::auth::UserRepository::with_jwt_cache(db, jwt_cache)
            .suspend(&"alice".parse().unwrap())
            .await
            .unwrap();

        let (status, _, _) = get_headed(edge, "alpha.test", "/", &extra).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }

    /// A revoke leaves the session alive and the access gone: the purge makes
    /// the next request re-intersect, the intersection is empty, and the
    /// spec's rule is a `403` — never an empty-`roles` JWT.
    #[tokio::test]
    async fn a_revoke_turns_the_next_request_into_a_403() {
        let db = crate::state::Db::in_memory().unwrap();
        let (cookie, _) = planted_cookie(&db, "alice", &["reader@blog"], "blog").await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let jwt_cache = Arc::new(crate::auth::JwtCache::new());
        let edge = edge_with(apps, db.clone(), jwt_cache.clone()).await;
        let extra = [("cookie", cookie.as_str()), ("accept", "text/html")];

        let (status, _, _) = get_headed(edge, "alpha.test", "/", &extra).await;
        assert_eq!(status, StatusCode::OK);

        crate::auth::EntitlementRepository::with_jwt_cache(db, jwt_cache)
            .revoke(&"alice".parse().unwrap(), None)
            .await
            .unwrap();

        let (status, _, body) = get_headed(edge, "alpha.test", "/", &extra).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("no access"), "{body}");
    }

    /// The cache is keyed so that nothing ever crosses: two users on one app
    /// are vouched for as themselves, and one user on two apps gets a token
    /// per audience.
    #[tokio::test]
    async fn the_cache_never_serves_across_users_or_apps() {
        let db = crate::state::Db::in_memory().unwrap();
        let (alices, alice) =
            planted_cookie(&db, "alice", &["reader@blog", "reader@wiki"], "blog").await;
        let (bobs, bob) = planted_cookie(&db, "bob", &["reader@blog"], "blog").await;
        // Alice's second cookie, on the other app's domain.
        let sessions = crate::auth::SessionRepository::new(db.clone());
        let minted = sessions
            .mint_code(
                &"alice".parse().unwrap(),
                crate::auth::DEFAULT_SESSION_LIFETIME,
            )
            .await
            .unwrap();
        let fresh = sessions.redeem(&minted.code).await.unwrap();
        let (session, user) = sessions.session_of(&fresh.token).await.unwrap().unwrap();
        let nonce = sessions
            .mint_nonce(&user, &"wiki".parse().unwrap(), &session)
            .await
            .unwrap();
        let wiki_cookie = format!(
            "__Host-spaceport-app-session={}",
            sessions
                .redeem_nonce(&nonce, &"wiki".parse().unwrap())
                .await
                .unwrap()
                .unwrap()
                .token
                .expose()
        );

        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", credential_echo().await, ""))
            .unwrap();
        apps.insert(gated("wiki", "beta.test", credential_echo().await, ""))
            .unwrap();
        let edge = edge_over(apps, db).await;

        let (_, _, hers) = get_headed(edge, "alpha.test", "/", &[("cookie", &alices)]).await;
        let (_, _, his) = get_headed(edge, "alpha.test", "/", &[("cookie", &bobs)]).await;
        assert_eq!(jwt_payload(&echoed_jwt(&hers))["sub"], alice.as_str());
        assert_eq!(jwt_payload(&echoed_jwt(&his))["sub"], bob.as_str());

        let (_, _, wiki) = get_headed(edge, "beta.test", "/", &[("cookie", &wiki_cookie)]).await;
        assert_eq!(jwt_payload(&echoed_jwt(&wiki))["aud"], "wiki");
        assert_eq!(jwt_payload(&echoed_jwt(&hers))["aud"], "blog");
    }

    /// A minted API key for `user` granting `grants`, beside the header value
    /// a machine caller sends it as — planted straight through the
    /// repositories, the way [`planted_cookie`] plants a cookie.
    async fn planted_key(
        db: &crate::state::Db,
        user: &str,
        grants: &str,
    ) -> (String, crate::auth::UserId, crate::auth::MintedApiKey) {
        let users = crate::auth::UserRepository::new(db.clone());
        let sessions = crate::auth::SessionRepository::new(db.clone());
        let created = users.create(&user.parse().unwrap(), None).await.unwrap();
        let minted = sessions
            .mint_api_key(
                &user.parse().unwrap(),
                &grants.parse().unwrap(),
                crate::auth::DEFAULT_API_KEY_LIFETIME,
            )
            .await
            .unwrap();

        (
            format!("Bearer {}", minted.key.expose()),
            created.id,
            minted,
        )
    }

    /// The whole machine path, end to end: a bare `Authorization: Bearer
    /// spk_…` — no cookie, no session, no exchange — reaches the app as the
    /// same JWT shape a signed-in user's request carries, with `sub` the
    /// owning user and `roles` exactly the key's single role, and the
    /// original header never crosses the hop.
    #[tokio::test]
    async fn an_api_key_authenticates_a_gated_request_end_to_end() {
        let db = crate::state::Db::in_memory().unwrap();
        let (header_value, user, minted) = planted_key(&db, "ci-bot", "reader@blog").await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated_roles(
            "blog",
            "alpha.test",
            credential_echo().await,
            "[reader, writer]",
        ))
        .unwrap();
        let edge = edge_over(apps, db).await;

        let (status, _, body) =
            get_headed(edge, "alpha.test", "/", &[("authorization", &header_value)]).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        let payload = jwt_payload(&echoed_jwt(&body));
        assert_eq!(payload["sub"], user.as_str());
        assert_eq!(payload["aud"], "blog");
        assert_eq!(payload["roles"], serde_json::json!(["reader"]));
        // The key itself was read, spent on the check, and stripped: the app
        // sees spaceport's voice and never the credential.
        assert!(!body.contains(minted.key.expose()), "{body}");
    }

    /// A key is pinned to its app: presented anywhere else it is a machine
    /// caller's `401` with directions in the one header machines read — and
    /// never a redirect, whatever the request's shape.
    #[tokio::test]
    async fn a_key_for_another_app_is_refused_with_a_401() {
        let db = crate::state::Db::in_memory().unwrap();
        let (header_value, ..) = planted_key(&db, "ci-bot", "reader@wiki").await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let edge = edge_over(apps, db).await;

        let (status, headers, _) =
            get_headed(edge, "alpha.test", "/", &[("authorization", &header_value)]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(header(&headers, "www-authenticate"), "Bearer");
    }

    #[tokio::test]
    async fn an_expired_key_is_refused_with_a_401() {
        let db = crate::state::Db::in_memory().unwrap();
        let (header_value, ..) = planted_key(&db, "ci-bot", "reader@blog").await;
        db.call(|connection| {
            connection
                .execute(
                    "UPDATE api_keys SET expires_at = '2000-01-01T00:00:00Z'",
                    [],
                )
                .map(|_| ())
                .map_err(anyhow::Error::from)
        })
        .await
        .unwrap();
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let edge = edge_over(apps, db).await;

        let (status, _, _) =
            get_headed(edge, "alpha.test", "/", &[("authorization", &header_value)]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// Revoking a key over the socket is a purge lever like dropping a
    /// session: the moment the revoke commits, the key stops answering —
    /// where a cache nobody purged would have served it four more minutes.
    #[tokio::test]
    async fn a_key_revoke_stops_cached_access_immediately() {
        let db = crate::state::Db::in_memory().unwrap();
        let (header_value, _, minted) = planted_key(&db, "ci-bot", "reader@blog").await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let jwt_cache = Arc::new(crate::auth::JwtCache::new());
        let edge = edge_with(apps, db.clone(), jwt_cache.clone()).await;
        let extra = [("authorization", header_value.as_str())];

        let (status, _, _) = get_headed(edge, "alpha.test", "/", &extra).await;
        assert_eq!(status, StatusCode::OK);

        crate::auth::SessionRepository::with_jwt_cache(db, jwt_cache)
            .drop_sessions(
                &"ci-bot".parse().unwrap(),
                Some(&minted.id.as_str().parse().unwrap()),
            )
            .await
            .unwrap();

        let (status, _, _) = get_headed(edge, "alpha.test", "/", &extra).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// Suspending the owner is the same lever pulled from the pool's side:
    /// the offboard cascade takes the key rows and the purge takes the cache.
    #[tokio::test]
    async fn suspending_the_owner_stops_key_access_immediately() {
        let db = crate::state::Db::in_memory().unwrap();
        let (header_value, ..) = planted_key(&db, "ci-bot", "reader@blog").await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let jwt_cache = Arc::new(crate::auth::JwtCache::new());
        let edge = edge_with(apps, db.clone(), jwt_cache.clone()).await;
        let extra = [("authorization", header_value.as_str())];

        let (status, _, _) = get_headed(edge, "alpha.test", "/", &extra).await;
        assert_eq!(status, StatusCode::OK);

        crate::auth::UserRepository::with_jwt_cache(db, jwt_cache)
            .suspend(&"ci-bot".parse().unwrap())
            .await
            .unwrap();

        let (status, _, _) = get_headed(edge, "alpha.test", "/", &extra).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// CSRF is a property of cookie authentication, and a key is the
    /// opposite: a POST wearing nothing but the key — no fetch metadata, no
    /// Origin — crosses, because a header a caller sets by hand cannot be
    /// forged by a cross-site form.
    #[tokio::test]
    async fn a_post_with_key_auth_passes_with_no_csrf_headers() {
        let db = crate::state::Db::in_memory().unwrap();
        let (header_value, ..) = planted_key(&db, "ci-bot", "reader@blog").await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let edge = edge_over(apps, db).await;

        let (status, _, body) = send(
            edge,
            "POST",
            "alpha.test",
            "/submit",
            &[("authorization", &header_value)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("path=/submit"), "{body}");
    }

    /// A bad key on a top-level navigation is still a machine calling: the
    /// answer is the `401`, never the redirect exchange — a script that
    /// followed one into a login page would be worse off than one that read
    /// the status.
    #[tokio::test]
    async fn a_navigation_with_a_bad_key_gets_a_401_not_a_redirect() {
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let edge = edge(apps).await;

        let (status, headers, _) = get_headed(
            edge,
            "alpha.test",
            "/",
            &[
                ("accept", "text/html"),
                ("sec-fetch-mode", "navigate"),
                ("authorization", "Bearer spk_not-a-key"),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(header(&headers, "www-authenticate"), "Bearer");
        assert!(!headers.contains_key("location"), "{headers:?}");
    }

    /// `gating: open` is the spec's promise, keys included: an `spk_` token
    /// sent to an open app is that app's business, and spaceport neither
    /// validates nor strips it.
    #[tokio::test]
    async fn an_open_app_receives_an_spk_bearer_untouched() {
        let apps = Arc::new(AppStore::new());
        apps.insert(app("hello", "alpha.test", credential_echo().await))
            .unwrap();
        let edge = edge(apps).await;

        let (status, _, body) = get_headed(
            edge,
            "alpha.test",
            "/",
            &[("authorization", "Bearer spk_theirs")],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("authorization=[Bearer spk_theirs]"), "{body}");
    }

    /// A raw WebSocket upstream: answers any handshake with a `101` and then
    /// echoes bytes. Hand-rolled TCP rather than a WebSocket library, because
    /// spaceport's tunnel has no opinion about frames — bytes in, bytes out is
    /// exactly the property under test, and a frame-speaking fixture would
    /// only obscure it.
    async fn ws_echo_upstream() -> SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buf = [0_u8; 1024];
                    loop {
                        let n = match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        head.extend_from_slice(&buf[..n]);
                        if head.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    if stream
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\n\r\n",
                        )
                        .await
                        .is_err()
                    {
                        return;
                    }
                    loop {
                        let n = match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        if stream.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        addr
    }

    /// Knock on the edge with a WebSocket handshake, answering the response
    /// head and the raw connection — which, after a `101`, *is* the tunnel.
    async fn ws_connect(
        edge: SocketAddr,
        host: &str,
        path: &str,
        extra: &[(&str, &str)],
    ) -> (String, tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(edge).await.unwrap();
        let mut request = format!(
            "GET {path} HTTP/1.1\r\nhost: {host}\r\nconnection: upgrade\r\nupgrade: websocket\r\nsec-websocket-key: dGVzdCBrZXkgMTIzNDU=\r\nsec-websocket-version: 13\r\n"
        );
        for (name, value) in extra {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut head = Vec::new();
        let mut buf = [0_u8; 1];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            head.push(buf[0]);
        }

        (String::from_utf8_lossy(&head).into_owned(), stream)
    }

    /// One round through the tunnel: bytes out, the same bytes back.
    async fn echoes(stream: &mut tokio::net::TcpStream, payload: &[u8]) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        stream.write_all(payload).await.unwrap();
        let mut echoed = vec![0_u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
            .await
            .expect("the echo should arrive")
            .unwrap();
        assert_eq!(echoed, payload);
    }

    /// The tunnel is dead: the next read sees the socket end, promptly.
    async fn closed(stream: &mut tokio::net::TcpStream) {
        use tokio::io::AsyncReadExt;

        let mut buf = [0_u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("the cut should close the socket promptly")
            .unwrap_or(0);
        assert_eq!(n, 0, "the socket should be closed");
    }

    /// The milestone's front door: an authenticated WebSocket upgrade to a
    /// gated app completes the handshake and bytes flow both ways — through
    /// spaceport, which until this milestone terminated every upgrade.
    #[tokio::test]
    async fn an_authenticated_websocket_upgrade_tunnels_end_to_end() {
        let db = crate::state::Db::in_memory().unwrap();
        let (cookie, _) = planted_cookie(&db, "alice", &["reader@blog"], "blog").await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", ws_echo_upstream().await, ""))
            .unwrap();
        let edge = edge_over(apps, db).await;

        let (head, mut stream) =
            ws_connect(edge, "alpha.test", "/live", &[("cookie", &cookie)]).await;

        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        echoes(&mut stream, b"first frame-shaped bytes").await;
        echoes(&mut stream, b"and more").await;
    }

    /// The gate stands in front of the tunnel exactly as it stands in front of
    /// every request: no credential, no upgrade — a `401` with directions,
    /// never a redirect a socket cannot follow.
    #[tokio::test]
    async fn a_websocket_without_credentials_is_refused_with_a_401() {
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", ws_echo_upstream().await, ""))
            .unwrap();
        let edge = edge(apps).await;

        let (head, _stream) = ws_connect(edge, "alpha.test", "/live", &[]).await;

        assert!(head.starts_with("HTTP/1.1 401"), "{head}");
        assert!(!head.to_lowercase().contains("location:"), "{head}");
    }

    /// The spec's sentence, live: dropping the session terminates the
    /// WebSocket it authenticated, promptly — handshake auth must not outlive
    /// revocation.
    #[tokio::test]
    async fn dropping_the_session_cuts_its_live_websocket() {
        let db = crate::state::Db::in_memory().unwrap();
        let (cookie, _) = planted_cookie(&db, "alice", &["reader@blog"], "blog").await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", ws_echo_upstream().await, ""))
            .unwrap();
        let jwt_cache = Arc::new(crate::auth::JwtCache::new());
        let edge = edge_with(apps, db.clone(), jwt_cache.clone()).await;

        let (head, mut stream) =
            ws_connect(edge, "alpha.test", "/live", &[("cookie", &cookie)]).await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        echoes(&mut stream, b"alive").await;

        crate::auth::SessionRepository::with_jwt_cache(db, jwt_cache)
            .drop_sessions(&"alice".parse().unwrap(), None)
            .await
            .unwrap();

        closed(&mut stream).await;
    }

    /// The same lever for the machine path: revoking the API key kills the
    /// WebSocket it opened.
    #[tokio::test]
    async fn revoking_the_api_key_cuts_its_websocket() {
        let db = crate::state::Db::in_memory().unwrap();
        let (header_value, _, minted) = planted_key(&db, "ci-bot", "reader@blog").await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", ws_echo_upstream().await, ""))
            .unwrap();
        let jwt_cache = Arc::new(crate::auth::JwtCache::new());
        let edge = edge_with(apps, db.clone(), jwt_cache.clone()).await;

        let (head, mut stream) = ws_connect(
            edge,
            "alpha.test",
            "/live",
            &[("authorization", &header_value)],
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        echoes(&mut stream, b"alive").await;

        crate::auth::SessionRepository::with_jwt_cache(db, jwt_cache)
            .drop_sessions(
                &"ci-bot".parse().unwrap(),
                Some(&minted.id.as_str().parse().unwrap()),
            )
            .await
            .unwrap();

        closed(&mut stream).await;
    }

    /// Suspend is the immediate-offboarding lever, and the socket is part of
    /// what it offboards.
    #[tokio::test]
    async fn suspending_the_user_cuts_their_websocket() {
        let db = crate::state::Db::in_memory().unwrap();
        let (cookie, _) = planted_cookie(&db, "alice", &["reader@blog"], "blog").await;
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", ws_echo_upstream().await, ""))
            .unwrap();
        let jwt_cache = Arc::new(crate::auth::JwtCache::new());
        let edge = edge_with(apps, db.clone(), jwt_cache.clone()).await;

        let (head, mut stream) =
            ws_connect(edge, "alpha.test", "/live", &[("cookie", &cookie)]).await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        echoes(&mut stream, b"alive").await;

        crate::auth::UserRepository::with_jwt_cache(db, jwt_cache)
            .suspend(&"alice".parse().unwrap())
            .await
            .unwrap();

        closed(&mut stream).await;
    }

    /// Expiry needs no lever: the deadline armed at handshake — the session's
    /// own `expires_at` — closes the tunnel when it passes, which is the one
    /// enforcement an already-upgraded connection can ever get.
    #[tokio::test]
    async fn an_expiring_session_closes_its_websocket_at_the_deadline() {
        let db = crate::state::Db::in_memory().unwrap();
        let (cookie, _) = planted_cookie(&db, "alice", &["reader@blog"], "blog").await;
        // Two seconds of session left, planted before the handshake arms the
        // deadline off this very stamp.
        let soon = (time::OffsetDateTime::now_utc() + time::Duration::seconds(2))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        db.call(move |connection| {
            connection
                .execute(
                    "UPDATE app_sessions SET expires_at = ?1",
                    rusqlite::params![soon],
                )
                .map(|_| ())
                .map_err(anyhow::Error::from)
        })
        .await
        .unwrap();
        let apps = Arc::new(AppStore::new());
        apps.insert(gated("blog", "alpha.test", ws_echo_upstream().await, ""))
            .unwrap();
        let edge = edge_over(apps, db).await;

        let (head, mut stream) =
            ws_connect(edge, "alpha.test", "/live", &[("cookie", &cookie)]).await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        echoes(&mut stream, b"alive").await;

        // No lever is pulled: the deadline alone must close it.
        closed(&mut stream).await;
    }

    /// `gating: open` stays the spec's untouched path for sockets too: the
    /// tunnel works, nothing registers it, and no revocation lever reaches it.
    #[tokio::test]
    async fn an_open_apps_websocket_is_neither_tracked_nor_cut() {
        let apps = Arc::new(AppStore::new());
        apps.insert(app("hello", "alpha.test", ws_echo_upstream().await))
            .unwrap();
        let jwt_cache = Arc::new(crate::auth::JwtCache::new());
        let edge = edge_with(
            apps,
            crate::state::Db::in_memory().unwrap(),
            jwt_cache.clone(),
        )
        .await;

        let (head, mut stream) = ws_connect(edge, "alpha.test", "/live", &[]).await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        echoes(&mut stream, b"open bytes").await;

        assert_eq!(jwt_cache.tracked_sockets(), 0);
        // The heaviest lever there is finds nothing of this connection's.
        jwt_cache.purge_user(&"3f29b1d4-8a6e-4c2b-9e77-1d5f6a2b9c40".parse().unwrap());
        echoes(&mut stream, b"still open").await;
    }

    /// A public prefix holds the door open for sockets exactly as for
    /// requests: no credential authenticated it, so nothing tracks it.
    #[tokio::test]
    async fn a_public_prefix_websocket_tunnels_untracked() {
        let apps = Arc::new(AppStore::new());
        apps.insert(gated(
            "blog",
            "alpha.test",
            ws_echo_upstream().await,
            "'/public'",
        ))
        .unwrap();
        let jwt_cache = Arc::new(crate::auth::JwtCache::new());
        let edge = edge_with(
            apps,
            crate::state::Db::in_memory().unwrap(),
            jwt_cache.clone(),
        )
        .await;

        let (head, mut stream) = ws_connect(edge, "alpha.test", "/public/live", &[]).await;

        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        echoes(&mut stream, b"public bytes").await;
        assert_eq!(jwt_cache.tracked_sockets(), 0);
    }

    /// An app is free to decline the upgrade, and its refusal crosses back as
    /// the ordinary response it is — no tunnel, nothing tracked.
    #[tokio::test]
    async fn an_upstream_that_declines_the_upgrade_answers_as_plain_http() {
        let db = crate::state::Db::in_memory().unwrap();
        let (cookie, _) = planted_cookie(&db, "alice", &["reader@blog"], "blog").await;
        let apps = Arc::new(AppStore::new());
        // The plain fixture: answers 200 to anything, upgrades nothing.
        apps.insert(gated("blog", "alpha.test", upstream().await, ""))
            .unwrap();
        let edge = edge_over(apps, db).await;

        let (head, _stream) = ws_connect(edge, "alpha.test", "/live", &[("cookie", &cookie)]).await;

        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    }

    /// `https://host/path?query` in two pieces, for following a redirect by
    /// hand.
    fn split_https(location: &str) -> (String, String) {
        let rest = location.strip_prefix("https://").expect(location);
        let slash = rest.find('/').expect(location);

        (rest[..slash].to_owned(), rest[slash..].to_owned())
    }
}

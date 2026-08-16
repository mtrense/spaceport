//! The gate in front of edge-gated apps, and the app-domain half of the
//! redirect exchange.
//!
//! An app whose manifest says `gating: edge` never sees a request spaceport
//! has not vouched for. The proxy asks this module first, per request, and the
//! answer is either "let it through" — an open app, a public path, a valid app
//! session cookie — or a response of this module's own: a redirect into the
//! exchange for a browser that can sign in, a `401` with directions for the
//! fetch or WebSocket that cannot.
//!
//! The exchange is three hops. The proxy bounces an unauthenticated top-level
//! navigation to `/auth/exchange` on spaceport's own hostname, carrying which
//! app and which path — never which scheme or host, which are re-derived from
//! the app's manifest at every step. The edge checks the global session and
//! the user's entitlements there (see [`super::home`]), mints a one-time nonce
//! and bounces back to `/.spaceport/callback` on the app's domain. That
//! callback — handled here, by spaceport, before any app could see it —
//! redeems the nonce into an app session, sets the cookie on the app's own
//! host, and lands the browser on the path it first asked for.
//!
//! `/.spaceport/*` is spaceport's reserved path space on every host it serves,
//! gated apps included: [`super::service`] claims the prefix before routing,
//! so an app cannot shadow the callback and the callback cannot be forwarded
//! to an app by mistake. This is documented in the manifest's terms too — the
//! path space simply does not belong to apps.
//!
//! A used or expired nonce restarts the exchange rather than rendering an
//! error, on purpose: the URLs a nonce rides end up in histories and
//! bookmarks, and a stale one re-opened should heal into a signed-in page —
//! bounce to the exchange, get a fresh nonce or a login form — not dead-end on
//! a sentence about a token nobody remembers minting.

use axum::body::Body;
use axum::extract::{Query, State};
use axum::response::Response;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri, header};
use serde::Deserialize;
use tracing::warn;

use super::EdgeState;
use super::home::{cookie_value, safe_next};
use super::routes::SpaceportRoutes;
use super::service::{ConnInfo, Scheme};
use crate::app::store::App;
use crate::app::{Auth, canonical_path};
use crate::secret::Secret;

/// The app-domain session cookie's name. The `__Host-` prefix carries the
/// same promise it does on [`super::home::SESSION_COOKIE`] — `Secure`,
/// `Path=/`, no `Domain` — and it can be afforded for the same reason: the
/// edge terminates TLS even in development, and the callback that sets this
/// cookie refuses to do so over plaintext.
pub(crate) const APP_SESSION_COOKIE: &str = "__Host-spaceport-app-session";

/// What the gate said about one request: pass — with the JWT spaceport vouches
/// for a gated request with, or without one for an open app or a public path —
/// or the response refusing it instead.
pub(super) enum Admission {
    /// Forward it. For a gated request the bearer is the JWT to inject as
    /// `Authorization` after the strip; an open app's and a public path's
    /// requests carry none, because the spec mints no JWTs there.
    Pass { bearer: Option<Secret> },
    /// Answer with this and let no app hear of it.
    Refused(Response<Body>),
}

/// Ask whether `req`, addressed to `host` and routed to the gated-or-open
/// `app`, may pass to it — and with which JWT, when it may.
///
/// The hot path is the four-minute cache: a request whose cookie has a live
/// entry costs no database read at all, which is milestone 6's whole point,
/// and the four minutes are exactly the staleness window the spec accepts
/// between purges. A miss costs the app-session lookup, the entitlement read
/// and one Ed25519 signature, and refills the cache for everyone after.
pub(super) async fn gate<B>(
    state: &EdgeState,
    app: &App,
    host: &str,
    req: &Request<B>,
) -> Admission {
    let Auth::Edge {
        public_path_prefixes,
        roles,
    } = &app.manifest.auth
    else {
        // `gating: open`: spaceport holds no door here at all.
        return Admission::Pass { bearer: None };
    };

    // Public prefixes are matched against the canonical spelling, so neither
    // `/css/../secret` nor `//public/x` can dodge or fake a match — see
    // `canonical_path` for the full argument. No JWT either: a public path is
    // reachable signed out, and a token that sometimes rode along would be a
    // contract the app cannot rely on.
    let canonical = canonical_path(req.uri().path());
    if public_path_prefixes
        .iter()
        .any(|prefix| prefix.matches(&canonical))
    {
        return Admission::Pass { bearer: None };
    }

    // An API key authenticates without any cookie or session — the machine
    // path, checked before the cookie so a caller sending both is judged by
    // the credential it deliberately attached. This read happens here, before
    // the proxy's rewrite strips every `Authorization` header, which is the
    // ordering the spec fixes: read and validate, then strip. Only the
    // `Bearer` scheme is accepted, and only a token wearing the `spk_`
    // prefix engages this branch at all — any other bearer token is not
    // spaceport's to judge and simply falls through to the cookie path (and
    // the strip). CSRF does not apply on this branch: the check exists for
    // credentials a browser attaches on its own, and a header a caller sets
    // by hand is the opposite of that. A bad key never redirects either —
    // it is a machine calling, so the answer is the machine-readable `401`,
    // navigation or not.
    if let Some(key) = bearer_api_key(req.headers()) {
        // The cache first, exactly as for cookies: a hit *is* the
        // authentication, keyed under the key's own hash, and every lever
        // that revokes a key purges these entries in the same breath.
        if let Some(jwt) = state.jwt_cache.lookup(&key, &app.id) {
            return Admission::Pass { bearer: Some(jwt) };
        }

        return match state.sessions.api_key_identity(&key, &app.id).await {
            Ok(Some((user, role))) => vouch_key(state, app, &key, &user, role).await,
            Ok(None) => {
                // A warning and nothing in the auth event log: a wrong key
                // costs its sender nothing to repeat, and a log an outsider
                // can flood is a log nobody reads.
                warn!(app = %app.id, "refused an api key");

                let mut response =
                    plain(StatusCode::UNAUTHORIZED, "the api key was not accepted\n");
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));

                Admission::Refused(response)
            }
            // Failing open would make a database hiccup an authentication
            // bypass; failing closed makes it an error page.
            Err(error) => {
                warn!(error = %format!("{error:#}"), "could not check an api key");

                Admission::Refused(plain(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "spaceport could not check the api key\n",
                ))
            }
        };
    }

    if let Some(token) = cookie_value(req.headers(), APP_SESSION_COOKIE) {
        let token = Secret::new(token);

        // The cache first: a hit *is* the authentication — an entry only
        // exists because this very cookie passed the database no more than
        // four minutes ago, and every lever that could have revoked it since
        // purges this cache in the same breath.
        if let Some(jwt) = state.jwt_cache.lookup(&token, &app.id) {
            // Authenticated by the cookie — which is exactly the credential a
            // cross-site form rides, so unsafe methods pass through the CSRF
            // check before the request may pass to the app. Requests an API
            // key authenticates are exempt by spec (a key never travels in a
            // cookie); that branch returned above, before this check.
            if let Some(refusal) =
                csrf_refusal(req.method(), req.headers(), Some(host), state.https_port)
            {
                return Admission::Refused(refusal);
            }

            return Admission::Pass { bearer: Some(jwt) };
        }

        match state.sessions.app_session_user(&token, &app.id).await {
            Ok(Some(user)) => {
                // The CSRF check, before anything is minted — same rule and
                // same placement as on the cache hit above.
                if let Some(refusal) =
                    csrf_refusal(req.method(), req.headers(), Some(host), state.https_port)
                {
                    return Admission::Refused(refusal);
                }

                return vouch(state, app, roles, &token, &user).await;
            }
            Ok(None) => {}
            // Failing open would make a database hiccup an authentication
            // bypass; failing closed makes it an error page.
            Err(error) => {
                warn!(error = %format!("{error:#}"), "could not check an app session");

                return Admission::Refused(plain(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "spaceport could not check the session\n",
                ));
            }
        }
    }

    let login = state
        .hostname
        .as_deref()
        .map(|hostname| exchange_url(hostname, state.https_port, app.id.as_str(), host, req.uri()));

    if is_navigation(req.method(), req.headers()) {
        return Admission::Refused(match login {
            Some(login) => see_other(&login),
            // A gated app on a spaceport with no hostname has no exchange to
            // send anyone through. 503 rather than 401: the request is fine,
            // the deployment is missing a piece only an operator can add.
            None => plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "this app is gated and spaceport has no `edge.hostname` to sign you in at\n",
            ),
        });
    }

    // Not a navigation: a fetch, an XHR, a POST, a WebSocket upgrade. A
    // redirect would be swallowed invisibly by whatever scripted this, so the
    // answer is machine-readable instead — the spec's contract for SPAs, which
    // read `X-Spaceport-Login` and drive the exchange themselves.
    let mut response = plain(StatusCode::UNAUTHORIZED, "signed out\n");
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    if let Some(login) = login
        && let Ok(value) = HeaderValue::from_str(&login)
    {
        response.headers_mut().insert(X_SPACEPORT_LOGIN, value);
    }

    Admission::Refused(response)
}

/// Mint the JWT that vouches for `user` to `app`, cache it, and pass — or
/// refuse, when the roles have moved since the session was minted.
///
/// `roles` in the token is the intersection of the user's entitlements with
/// what the deployed manifest declares, computed here per mint rather than
/// per session: the exchange checked the same question before the cookie ever
/// existed, but a revoke or a redeployed manifest since then can empty it —
/// and the spec's rule is that an empty intersection is a `403`, never an
/// empty-`roles` JWT. The check below is that rule at the mint site, so the
/// exchange's gate and this one cannot drift apart; [`crate::auth::jwt::mint`]
/// refuses an empty slate once more as the last line.
async fn vouch(
    state: &EdgeState,
    app: &App,
    roles: &[crate::auth::Role],
    token: &Secret,
    user: &crate::auth::UserId,
) -> Admission {
    // The iss the token claims must be an origin the app can fetch the JWKS
    // from, and without a hostname spaceport has neither — the same missing
    // piece the sign-in redirect refuses over, worded the same way.
    let Some(hostname) = state.hostname.as_deref() else {
        return Admission::Refused(plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "this app is gated and spaceport has no `edge.hostname` to vouch for you as\n",
        ));
    };

    let held = match state
        .entitlements
        .audit(&crate::auth::UserRef::Id(user.clone()))
        .await
    {
        Ok((_, held)) => held,
        // A user the pool no longer knows cannot be vouched for; their
        // sessions died in the same transaction, so this is a race's width
        // wide and "no access" is the honest answer on the losing side.
        Err(crate::auth::EntitlementError::UnknownUser(_)) => Vec::new(),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "could not read entitlements to mint a jwt");

            return Admission::Refused(plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "spaceport could not check your access\n",
            ));
        }
    };

    // Sorted and deduplicated by the set, so two mints for one user render
    // the claim identically whatever order the grants arrived in.
    let intersection: std::collections::BTreeSet<crate::auth::Role> = held
        .into_iter()
        .filter(|entitlement| entitlement.app == app.id && roles.contains(&entitlement.role))
        .map(|entitlement| entitlement.role)
        .collect();
    if intersection.is_empty() {
        return Admission::Refused(plain(
            StatusCode::FORBIDDEN,
            "you are signed in, and your account has no access to this app\n",
        ));
    }
    let intersection: Vec<crate::auth::Role> = intersection.into_iter().collect();

    let key = match state.signer.signing_key().await {
        Ok(key) => key,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "could not load the jwt signing key");

            return Admission::Refused(plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "spaceport could not sign for you\n",
            ));
        }
    };

    // exp is iat plus five minutes and the cache holds it for four, so a
    // cached token always reaches the app with at least a minute left — the
    // spec's arithmetic, with the app-side verifier's sixty seconds of clock
    // leeway on top of that.
    let jwt = match crate::auth::jwt::mint(
        &key,
        &crate::auth::jwt::issuer(hostname, state.https_port),
        user,
        &app.id,
        &intersection,
        time::OffsetDateTime::now_utc(),
    ) {
        Ok(jwt) => jwt,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "could not mint a jwt");

            return Admission::Refused(plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "spaceport could not sign for you\n",
            ));
        }
    };

    state.jwt_cache.insert(token, &app.id, user, jwt.clone());

    Admission::Pass { bearer: Some(jwt) }
}

/// The API key a request presents, if it presents one: the first
/// `Authorization` header, when its scheme is `Bearer` (case-insensitively,
/// as RFC 9110 reads schemes) and its token wears the `spk_` prefix.
///
/// Anything else — another scheme, a bearer token that is not spaceport's,
/// a value that is not text — answers `None` and takes the cookie path,
/// where the strip disposes of it. Deliberately the *first* header and not a
/// search across duplicates: a request carrying several `Authorization`
/// headers is already malformed, and hunting through it for one that pleases
/// us would be doing a confused client's guessing for it.
pub(super) fn bearer_api_key(headers: &HeaderMap) -> Option<Secret> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let token = token.trim();
    token
        .starts_with(crate::auth::api_key::KEY_PREFIX)
        .then(|| Secret::new(token))
}

/// Mint the JWT a validated API key buys, cache it under the key's own hash,
/// and pass.
///
/// The claim shape is the cookie path's exactly — same `iss`, `aud`, `exp`
/// arithmetic — with `sub` the owning user and `roles` the key's single
/// role, no more and no less. Deliberately *not* intersected with the
/// deployed manifest's declared roles: a key grants exactly its role, the
/// spec's sentence, and the mint over the operator socket already warned when
/// that role opens no door — an app handed a role it never declared simply
/// authorises nothing by it, which is the app's own contract to enforce.
async fn vouch_key(
    state: &EdgeState,
    app: &App,
    key: &Secret,
    user: &crate::auth::UserId,
    role: crate::auth::Role,
) -> Admission {
    // The same missing piece the cookie path refuses over, worded the same
    // way: without a hostname there is no `iss` an app could fetch a JWKS from.
    let Some(hostname) = state.hostname.as_deref() else {
        return Admission::Refused(plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "this app is gated and spaceport has no `edge.hostname` to vouch for you as\n",
        ));
    };

    let signing_key = match state.signer.signing_key().await {
        Ok(key) => key,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "could not load the jwt signing key");

            return Admission::Refused(plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "spaceport could not sign for you\n",
            ));
        }
    };

    let jwt = match crate::auth::jwt::mint(
        &signing_key,
        &crate::auth::jwt::issuer(hostname, state.https_port),
        user,
        &app.id,
        &[role],
        time::OffsetDateTime::now_utc(),
    ) {
        Ok(jwt) => jwt,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "could not mint a jwt");

            return Admission::Refused(plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "spaceport could not sign for you\n",
            ));
        }
    };

    // Cached under the key itself — hashed by the cache, like every
    // credential it holds — with the user beside it so `purge_user`, the
    // lever behind every key revocation, reaches these entries too.
    state.jwt_cache.insert(key, &app.id, user, jwt.clone());

    Admission::Pass { bearer: Some(jwt) }
}

/// The header a `401` carries the exchange URL in, so a SPA that caught the
/// refusal knows where a top-level navigation would have been sent.
const X_SPACEPORT_LOGIN: http::HeaderName = http::HeaderName::from_static("x-spaceport-login");

/// The CSRF gate for a request a spaceport cookie authenticates: `None` lets
/// it pass, a `403` refuses it as another site's doing.
///
/// Safe methods pass unexamined — a GET changes nothing worth forging, and
/// checking it would break every cross-site link to a signed-in app. For the
/// rest, the browser's own word decides: `Sec-Fetch-Site` where it is sent,
/// which must not say `cross-site`; the `Origin` header where it is not (old
/// Safari, WebViews), which must name the very host the request was routed to,
/// over https. Both absent is a refusal — a browser that says nothing about
/// where a POST came from does not get the benefit of the doubt, because the
/// doubt is the entire attack.
///
/// The refusal is a plain `403` and never a redirect: the request is hostile
/// or malformed, not signed out, and bouncing it through the exchange would
/// hand the forger a signed-in retry. Nothing is written to the auth event
/// log either — a forged POST costs its sender nothing to repeat, and a log
/// an outsider can flood is a log nobody reads. The `warn!` is the trace.
pub(super) fn csrf_refusal(
    method: &Method,
    headers: &HeaderMap,
    host: Option<&str>,
    https_port: u16,
) -> Option<Response<Body>> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return None;
    }
    if !cross_site(headers, host, https_port) {
        return None;
    }

    warn!(
        host = host.unwrap_or_default(),
        "refused a cross-site request"
    );

    Some(plain(
        StatusCode::FORBIDDEN,
        "cross-site request refused (CSRF)\n",
    ))
}

/// Whether `headers` fail to vouch that the request is the named host's own.
///
/// A present `Sec-Fetch-Site` settles it alone — the spec's rule is "must not
/// be cross-site", so `same-origin`, `same-site` and `none` (a direct
/// navigation: a bookmark, an address bar) all pass, and a value that cannot
/// be read fails closed. Only in its absence is `Origin` consulted, and then
/// it must equal `https://<host>` — with the https port beside it when that
/// is not 443, since that is how a browser on a development port spells the
/// same origin.
fn cross_site(headers: &HeaderMap, host: Option<&str>, https_port: u16) -> bool {
    if let Some(site) = headers.get("sec-fetch-site") {
        return !site
            .to_str()
            .is_ok_and(|site| !site.eq_ignore_ascii_case("cross-site"));
    }

    let Some(host) = host else { return true };
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|origin| origin.to_str().ok())
    else {
        return true;
    };

    !(origin.eq_ignore_ascii_case(&format!("https://{host}"))
        || origin.eq_ignore_ascii_case(&format!("https://{host}:{https_port}")))
}

/// Whether this request is a top-level GET navigation — the one shape of
/// request a redirect into the exchange helps rather than strands.
///
/// `Sec-Fetch-Mode` settles the question wherever a browser sends it: a mode
/// that is not `navigate` is a fetch whatever the `Accept` header offers, and
/// a `cors` request for html must not be redirected as though a user typed it.
/// Only clients that predate fetch metadata fall back to `Accept: text/html`.
/// An upgrade is never a navigation whatever its headers say — a WebSocket
/// handshake redirected to a login page is a broken socket, not a signed-in
/// user.
fn is_navigation(method: &Method, headers: &HeaderMap) -> bool {
    if method != Method::GET || headers.contains_key(header::UPGRADE) {
        return false;
    }

    match headers.get("sec-fetch-mode") {
        Some(mode) => mode
            .to_str()
            .is_ok_and(|mode| mode.eq_ignore_ascii_case("navigate")),
        None => headers
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("text/html")),
    }
}

/// The exchange URL for `app` as requested at `host`, carrying `uri`'s path
/// and query and nothing else of the request.
///
/// The scheme and edge authority come from configuration, and the `host`
/// carried along is not trusted either — it is the host the routing table
/// just matched to this app, and the exchange re-checks it against the app's
/// manifest before ever redirecting to it. What the client controls is the
/// path and query, which travel as one encoded value and come back out only
/// through the same open-redirect gate the login form uses.
pub(super) fn exchange_url(
    hostname: &str,
    https_port: u16,
    app: &str,
    host: &str,
    uri: &Uri,
) -> String {
    let next = uri
        .path_and_query()
        .map_or_else(|| uri.path(), http::uri::PathAndQuery::as_str);

    format!(
        "https://{}/auth/exchange?app={}&host={}&next={}",
        authority(hostname, https_port),
        query_encode(app),
        query_encode(host),
        query_encode(next),
    )
}

/// `hostname`, with the https port beside it when it is not the default —
/// the same rule the plaintext redirect applies.
pub(super) fn authority(hostname: &str, https_port: u16) -> String {
    match https_port {
        443 => hostname.to_owned(),
        port => format!("{hostname}:{port}"),
    }
}

/// `value` as one query-string value: everything but the unreserved characters
/// percent-encoded. Stricter than a URL needs and exactly as strict as never
/// having to reason about which delimiter survives where.
pub(crate) fn query_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            byte => encoded.push_str(&format!("%{byte:02X}")),
        }
    }

    encoded
}

/// A 303: fetched with GET whatever the request was, which is what every hop
/// of the exchange wants.
fn see_other(location: &str) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }

    response
}

fn plain(status: StatusCode, body: &str) -> Response<Body> {
    let mut response = Response::new(Body::from(body.to_owned()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );

    response
}

#[derive(Debug, Deserialize)]
pub(super) struct CallbackQuery {
    nonce: Option<String>,
    next: Option<String>,
}

/// `GET /.spaceport/callback?nonce=…&next=…` — on the app's domain, answered
/// by spaceport before any app is consulted.
///
/// This is where the nonce becomes the cookie. The app the nonce must have
/// been minted for is not in the URL: it is whichever app the routing table
/// says serves the host the browser arrived at, which is exactly the binding
/// the exchange promised — a nonce replayed at any other domain names a
/// different app and dies in the repository's check.
pub(super) async fn callback(
    State(state): State<SpaceportRoutes>,
    Query(query): Query<CallbackQuery>,
    req: Request<Body>,
) -> Response<Body> {
    let Some(host) = request_host(&req).map(str::to_owned) else {
        return plain(
            StatusCode::BAD_REQUEST,
            "spaceport cannot answer a callback that names no host\n",
        );
    };
    let name = super::service::host_name(&host).unwrap_or(&host).to_owned();

    let Some(app) = state.apps.routes().serving(&name).cloned() else {
        // No live gated app, no session to mint. 404 like any unclaimed path:
        // this endpoint only means something on a domain an app serves.
        return plain(
            StatusCode::NOT_FOUND,
            "no app is being served on this host\n",
        );
    };
    if matches!(app.manifest.auth, Auth::Open {}) {
        return plain(
            StatusCode::NOT_FOUND,
            "this app is not gated, so there is no session to mint\n",
        );
    }

    // The cookie about to be set is `__Host-`-prefixed and `Secure`; setting
    // it over plaintext would be a promise the connection breaks. The nonce
    // is still unspent, so the same URL over https completes normally.
    if req
        .extensions()
        .get::<ConnInfo>()
        .is_some_and(|conn| conn.scheme == Scheme::Http)
    {
        let path = req
            .uri()
            .path_and_query()
            .map_or_else(|| req.uri().path(), http::uri::PathAndQuery::as_str);

        return see_other(&format!(
            "https://{}{path}",
            authority(&name, state.https_port)
        ));
    }

    // Where a refused nonce goes: back through the exchange, so a stale
    // bookmark heals into a fresh login instead of an error page. Without a
    // hostname there is no exchange to restart, and saying so plainly is all
    // that is left.
    let next = safe_next(query.next.as_deref());
    let restart = state.hostname.as_deref().map(|hostname| {
        exchange_url(
            hostname,
            state.https_port,
            app.id.as_str(),
            &name,
            &next.parse().unwrap_or_else(|_| Uri::from_static("/")),
        )
    });
    let restarted = || match &restart {
        Some(url) => see_other(url),
        None => plain(
            StatusCode::UNAUTHORIZED,
            "the sign-in link has expired and spaceport has no `edge.hostname` to restart it\n",
        ),
    };

    let Some(nonce) = query.nonce.filter(|nonce| !nonce.is_empty()) else {
        return restarted();
    };

    match state
        .sessions
        .redeem_nonce(&Secret::new(nonce), &app.id)
        .await
    {
        Ok(Some(fresh)) => {
            // The Location is a bare absolute path, which the browser resolves
            // against the app's own https origin — the scheme and host forced
            // to the app's, as the spec asks, by construction rather than by
            // filtering.
            let mut response = see_other(next);
            match HeaderValue::from_str(&app_cookie(&fresh)) {
                Ok(cookie) => {
                    response.headers_mut().insert(header::SET_COOKIE, cookie);

                    response
                }
                Err(error) => {
                    warn!(%error, "could not render the app session cookie");

                    plain(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "spaceport could not set the session cookie\n",
                    )
                }
            }
        }
        // Used, expired, minted elsewhere, or orphaned — all one answer.
        Ok(None) => restarted(),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "a callback could not be answered");

            plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "spaceport could not complete the sign-in\n",
            )
        }
    }
}

/// The `Set-Cookie` value an app session travels out as: the discipline of
/// [`super::home::session_cookie`], on the app's domain.
fn app_cookie(fresh: &crate::auth::FreshAppSession) -> String {
    let max_age = time::OffsetDateTime::parse(
        &fresh.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map(|expires| {
        (expires - time::OffsetDateTime::now_utc())
            .whole_seconds()
            .max(0)
    });

    let mut cookie = format!(
        "{APP_SESSION_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Lax",
        fresh.token.expose()
    );
    if let Ok(max_age) = max_age {
        cookie.push_str(&format!("; Max-Age={max_age}"));
    }

    cookie
}

/// The host a callback was addressed to — [`super::service::request_host`]'s
/// logic over an axum request.
fn request_host(req: &Request<Body>) -> Option<&str> {
    req.headers()
        .get(header::HOST)
        .and_then(|host| host.to_str().ok())
        .or_else(|| req.uri().host())
        .filter(|host| !host.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }

        map
    }

    /// The two signals the spec names, each sufficient on its own — and the
    /// shapes that must never redirect: POSTs, fetches, upgrades.
    #[test]
    fn a_navigation_is_a_get_that_says_so_either_way() {
        assert!(is_navigation(
            &Method::GET,
            &headers(&[("sec-fetch-mode", "navigate")])
        ));
        assert!(is_navigation(
            &Method::GET,
            &headers(&[("accept", "text/html,application/xhtml+xml")])
        ));

        assert!(!is_navigation(&Method::GET, &headers(&[])));
        assert!(!is_navigation(
            &Method::GET,
            &headers(&[("sec-fetch-mode", "cors"), ("accept", "application/json")])
        ));
        // Where fetch metadata is sent it decides alone: a `cors` fetch asking
        // for html is a script's request, and redirecting it strands the
        // script — `Accept` is only the fallback for clients that say nothing.
        assert!(!is_navigation(
            &Method::GET,
            &headers(&[("sec-fetch-mode", "cors"), ("accept", "text/html")])
        ));
        assert!(!is_navigation(
            &Method::POST,
            &headers(&[("accept", "text/html")])
        ));
        // A WebSocket handshake is a GET and often accepts anything; a
        // redirect would break the socket, never sign anyone in.
        assert!(!is_navigation(
            &Method::GET,
            &headers(&[("accept", "text/html"), ("upgrade", "websocket")])
        ));
    }

    /// The one shape that engages key auth: the `Bearer` scheme, in any
    /// case, carrying an `spk_` token. Everything else is not spaceport's to
    /// judge — it falls through to the cookie path and the strip.
    #[test]
    fn only_a_bearer_spk_token_reads_as_an_api_key() {
        let key = |pairs: &[(&str, &str)]| bearer_api_key(&headers(pairs));

        assert_eq!(
            key(&[("authorization", "Bearer spk_abc")]).map(|k| k.expose().to_owned()),
            Some("spk_abc".to_owned())
        );
        // The scheme is case-insensitive, as RFC 9110 reads schemes.
        assert!(key(&[("authorization", "bearer spk_abc")]).is_some());

        // Another scheme, another issuer's bearer token, or no header at all:
        // not a key, and not this branch's business.
        assert!(key(&[("authorization", "Basic spk_abc")]).is_none());
        assert!(key(&[("authorization", "Bearer eyJhbGciOi")]).is_none());
        assert!(key(&[("authorization", "spk_abc")]).is_none());
        assert!(key(&[]).is_none());
    }

    /// Safe methods pass the CSRF gate unexamined: a GET, HEAD or OPTIONS
    /// changes nothing worth forging, and checking one would break every
    /// cross-site link to a signed-in app.
    #[test]
    fn safe_methods_are_never_csrf_checked() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(
                csrf_refusal(
                    &method,
                    &headers(&[("sec-fetch-site", "cross-site")]),
                    Some("alpha.test"),
                    443,
                )
                .is_none(),
                "{method}"
            );
        }
    }

    /// The spec's rule is "must not be cross-site", exactly: `same-origin`,
    /// `same-site` and `none` — a bookmark, an address bar — all pass, and
    /// only `cross-site` (in any spelling) is another site's doing.
    #[test]
    fn sec_fetch_site_decides_alone_when_present() {
        for site in ["same-origin", "same-site", "none"] {
            assert!(
                csrf_refusal(
                    &Method::POST,
                    &headers(&[("sec-fetch-site", site)]),
                    Some("alpha.test"),
                    443,
                )
                .is_none(),
                "{site}"
            );
        }

        let refused = csrf_refusal(
            &Method::POST,
            // Present and hostile beats an Origin that would have passed:
            // the browser's own metadata is the stronger witness.
            &headers(&[
                ("sec-fetch-site", "Cross-Site"),
                ("origin", "https://alpha.test"),
            ]),
            Some("alpha.test"),
            443,
        )
        .expect("a cross-site post must be refused");
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }

    /// Without fetch metadata — old Safari, WebViews — the `Origin` header
    /// must name this very host over https; anything else, including silence,
    /// is a refusal.
    #[test]
    fn without_fetch_metadata_the_origin_header_must_match_the_host() {
        let passes = |origin: &str, port: u16| {
            csrf_refusal(
                &Method::POST,
                &headers(&[("origin", origin)]),
                Some("alpha.test"),
                port,
            )
            .is_none()
        };

        assert!(passes("https://alpha.test", 443));
        assert!(passes("https://ALPHA.test", 443));
        // A development spaceport off 443 sees the port in the origin.
        assert!(passes("https://alpha.test:8443", 8443));

        assert!(!passes("https://evil.test", 443));
        assert!(!passes("http://alpha.test", 443));
        assert!(!passes("https://alpha.test.evil.test", 443));
        assert!(!passes("null", 443));
        assert!(!passes("https://alpha.test:8443", 443));

        // Both signals absent: no benefit of the doubt.
        assert!(csrf_refusal(&Method::POST, &headers(&[]), Some("alpha.test"), 443).is_some());
        // And with no host to hold the origin against, silence about the
        // site is a refusal too.
        assert!(
            csrf_refusal(
                &Method::POST,
                &headers(&[("origin", "https://alpha.test")]),
                None,
                443
            )
            .is_some()
        );
    }

    /// Everything the client controls travels encoded, so an ampersand in a
    /// query cannot split the exchange URL's own parameters.
    #[test]
    fn the_exchange_url_encodes_the_path_and_query_as_one_value() {
        let url = exchange_url(
            "spaceport.test",
            443,
            "blog",
            "alpha.test",
            &"/a/b?c=d&e=f".parse().unwrap(),
        );

        assert_eq!(
            url,
            "https://spaceport.test/auth/exchange?app=blog&host=alpha.test&next=%2Fa%2Fb%3Fc%3Dd%26e%3Df"
        );
    }

    /// A development spaceport listens off 443, and its exchange URLs must
    /// name the port or the browser knocks on a door nothing answers.
    #[test]
    fn the_exchange_url_names_a_non_default_port() {
        let url = exchange_url(
            "spaceport.test",
            8443,
            "blog",
            "a.test",
            &"/".parse().unwrap(),
        );

        assert!(url.starts_with("https://spaceport.test:8443/"), "{url}");
    }
}

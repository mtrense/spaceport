//! The request chain: one tower service, entered once per request.
//!
//! Ordering matters here. Requests spaceport answers itself are recognised by
//! a prefix check *before* anything else, so a proxied site can never shadow
//! them — an upstream that serves `/.well-known/acme-challenge/` must not be
//! able to break certificate renewal.
//!
//! The prefix check comes first for a second reason: it keeps [`axum`] off the
//! proxy path. `axum::Router` is `Service<Request<axum::body::Body>>`, so
//! routing every request through it would mean boxing hyper's `Incoming` body
//! on the way in — a heap allocation per request, and a request body that can
//! no longer be handed to the upstream untouched. Proxied traffic is the
//! overwhelming majority and pays two `starts_with` calls instead; the routes
//! spaceport serves itself are low-volume and happily pay for the ergonomics.

use std::convert::Infallible;
use std::future::Future;
use std::net::{Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use http::uri::PathAndQuery;
use http::{HeaderValue, Request, Response, StatusCode, header};
use hyper::body::Incoming;
use tower::{Service, ServiceExt};

use super::proxy;
use super::{ConnectionSlot, EdgeState};
use crate::app::manifest::Host;

/// Path prefixes spaceport claims for itself. Everything else is proxied.
///
/// `/.spaceport/` is ours to choose; `/.well-known/acme-challenge/` is pinned
/// by RFC 8555 and cannot move.
const SPACEPORT_PREFIXES: &[&str] = &["/.spaceport/", "/.well-known/acme-challenge/"];

/// Whether spaceport answers `path` itself rather than proxying it.
fn is_spaceport_path(path: &str) -> bool {
    SPACEPORT_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Which listener a request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// What the connection knows that the request itself doesn't. Attached to
/// every request's extensions, so handlers and the proxy can see it.
#[derive(Debug, Clone, Copy)]
pub struct ConnInfo {
    pub peer: SocketAddr,
    pub scheme: Scheme,
}

/// The service hyper drives, one clone per connection.
#[derive(Clone)]
pub struct EdgeService {
    state: Arc<EdgeState>,
    conn: ConnInfo,
    slot: ConnectionSlot,
}

impl EdgeService {
    pub fn new(state: Arc<EdgeState>, conn: ConnInfo, slot: ConnectionSlot) -> Self {
        Self { state, conn, slot }
    }
}

type BoxFuture = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

impl Service<Request<Incoming>> for EdgeService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: Request<Incoming>) -> Self::Future {
        req.extensions_mut().insert(self.conn);
        // Along for the ride so that a handler which turns this request into
        // something outliving the connection — the WebSocket tunnel, and only
        // it so far — can keep the connection counted. It goes out with the
        // request when the request is dropped, which for everything else is
        // exactly the right moment.
        req.extensions_mut().insert(self.slot.clone());

        if is_spaceport_path(req.uri().path()) {
            let router = self.state.router.clone();
            return Box::pin(async move {
                router
                    .oneshot(req.map(Body::new))
                    .await
                    .map_err(|never| match never {})
            });
        }

        // Plaintext is only ever a stop on the way to TLS. The redirect
        // deliberately sits behind the prefix check: the ACME challenge has to
        // stay reachable over plaintext, or certificates can never renew.
        //
        // A request naming no host has nowhere to be redirected to, so it
        // falls through and is answered as-is.
        if self.conn.scheme == Scheme::Http
            && let Some(location) = https_location(&req, self.state.https_port)
        {
            return Box::pin(async move { Ok(redirect(location)) });
        }

        Box::pin(proxy::handle(self.state.clone(), req))
    }
}

/// The host a request is addressed to, port included if the client sent one.
///
/// HTTP/1.1 puts it in `Host`; HTTP/2 puts it in `:authority`, which hyper
/// surfaces on the URI. Either way this is what picks the upstream, so both
/// have to be understood.
pub(super) fn request_host<B>(req: &Request<B>) -> Option<&str> {
    req.headers()
        .get(header::HOST)
        .and_then(|host| host.to_str().ok())
        .or_else(|| req.uri().host())
        .filter(|host| !host.is_empty())
}

/// The `https` URL matching `req`, or `None` if the request names no host that
/// could be one — with nothing to redirect *to*, the caller falls through and
/// the request is answered over plaintext as-is.
///
/// The name is checked before it is built into a URL, and that check is
/// load-bearing: [`host_name`] only cuts at the first `:`, so what it hands
/// back is otherwise entirely the client's. `Host: evil.com/x` would make
/// `evil.com` the authority and the rest of it path, and the browser would be
/// sent somewhere spaceport has never served. This runs before routing — it
/// has to, since a name gets its certificate by being reachable first — so
/// there is no matched route key to rebuild from here as there is on the
/// proxy path, and the name is validated in place instead.
fn https_location<B>(req: &Request<B>, https_port: u16) -> Option<HeaderValue> {
    // Drop the plaintext port, and name the https one unless it is the default.
    let name = host_name(request_host(req)?)?;
    if !is_addressable(name) {
        return None;
    }
    let path = req
        .uri()
        .path_and_query()
        .map_or_else(|| req.uri().path(), PathAndQuery::as_str);

    let location = format!("https://{}{path}", super::gate::authority(name, https_port));
    HeaderValue::try_from(location).ok()
}

/// Whether `name` is something spaceport can put in a URL and mean it.
///
/// A [`Host`] is letters, digits, hyphens and dots, so one that parses cannot
/// carry a delimiter that means something else further along — no `/` to start
/// a path, no `@` to turn the whole thing into userinfo, no second `:`. A
/// bracketed IPv6 literal is the one shape that legitimately holds colons, and
/// it is admitted only once the address inside the brackets really parses.
fn is_addressable(name: &str) -> bool {
    match name
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(literal) => literal.parse::<Ipv6Addr>().is_ok(),
        None => name.parse::<Host>().is_ok(),
    }
}

/// The host without its port. Handles bracketed IPv6 literals.
pub(super) fn host_name(host: &str) -> Option<&str> {
    if host.is_empty() {
        return None;
    }
    if host.starts_with('[') {
        // `[::1]:8080` -> `[::1]`
        return host.find(']').map(|end| &host[..=end]);
    }
    Some(host.split(':').next().unwrap_or(host))
}

/// 308 rather than 301: it forbids clients from rewriting the method, so a
/// redirected POST stays a POST.
fn redirect(location: HeaderValue) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::PERMANENT_REDIRECT;
    response.headers_mut().insert(header::LOCATION, location);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Incoming` has no public constructor, but `https_location` only reads
    /// the head, so the tests use the unit body.
    fn request(host: &str, uri: &str) -> Request<()> {
        Request::builder()
            .uri(uri)
            .header(header::HOST, host)
            .body(())
            .unwrap()
    }

    #[test]
    fn claims_its_own_prefixes() {
        assert!(is_spaceport_path("/.spaceport/health"));
        assert!(is_spaceport_path("/.well-known/acme-challenge/tok3n"));
    }

    #[test]
    fn proxies_everything_else() {
        assert!(!is_spaceport_path("/"));
        assert!(!is_spaceport_path("/.well-known/openid-configuration"));
        // Only the exact prefix counts, not a lookalike segment.
        assert!(!is_spaceport_path("/app/.spaceport/health"));
        assert!(!is_spaceport_path("/.spaceportish"));
    }

    #[test]
    fn redirects_to_the_default_port_without_naming_it() {
        let location = https_location(&request("example.com", "/a?b=c"), 443).unwrap();
        assert_eq!(location, "https://example.com/a?b=c");
    }

    #[test]
    fn replaces_the_plaintext_port_with_the_https_one() {
        let location = https_location(&request("example.com:8080", "/"), 8443).unwrap();
        assert_eq!(location, "https://example.com:8443/");
    }

    #[test]
    fn keeps_ipv6_literals_bracketed() {
        let location = https_location(&request("[::1]:8080", "/"), 8443).unwrap();
        assert_eq!(location, "https://[::1]:8443/");
    }

    #[test]
    fn declines_to_redirect_without_a_host() {
        assert!(https_location(&request("", "/"), 443).is_none());
    }

    /// The redirect is built out of a name the client sent, so a name that is
    /// not one gets no redirect at all. Everything here would otherwise put a
    /// second host — or a whole other origin, once `@` makes the front of it
    /// userinfo — where the browser reads the authority.
    #[test]
    fn declines_to_redirect_to_a_host_that_is_not_a_name() {
        for hostile in [
            "evil.com/x",
            "example.com@evil.com",
            "example.com\\@evil.com",
            "exa mple.com",
            "[not-an-address]",
        ] {
            assert!(
                https_location(&request(hostile, "/a"), 443).is_none(),
                "{hostile}"
            );
        }
    }

    /// Anything past the first `:` is the port's business and is dropped, so a
    /// tail that was trying to be a second authority never reaches the URL —
    /// this one redirects, and redirects to the name in front of the colon.
    #[test]
    fn drops_a_hostile_tail_along_with_the_port() {
        let location = https_location(&request("example.com:@evil.com", "/a"), 443).unwrap();
        assert_eq!(location, "https://example.com/a");
    }

    #[test]
    fn reads_the_host_from_the_uri_when_there_is_no_header() {
        // What an HTTP/2 `:authority` looks like by the time hyper is done.
        let req = Request::builder()
            .uri("https://example.com:8443/a")
            .body(())
            .unwrap();

        assert_eq!(request_host(&req), Some("example.com"));
    }
}

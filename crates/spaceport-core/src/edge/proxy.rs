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
use tracing::{debug, warn};

use super::EdgeState;
use super::service::{self, ConnInfo};

/// Headers that describe one hop and must not be passed on to the next.
///
/// `upgrade` among them: spaceport terminates upgrades rather than forwarding
/// them, so websockets do not work through an app yet.
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
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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
    let name = service::host_name(&authority).unwrap_or(&authority);

    let Some(app) = state.apps.routes().lookup(name).cloned() else {
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
    forwarded_headers(req.headers_mut(), &authority, conn);

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
fn forwarded_headers(headers: &mut HeaderMap, authority: &str, conn: Option<ConnInfo>) {
    strip_hop_by_hop(headers);

    // HTTP/2 requests carry the host in `:authority` and no `Host` header at
    // all. Restoring it keeps every app on one way of asking "who was I
    // addressed as?", and stops hyper filling it in with the upstream's
    // loopback address.
    if let Ok(value) = HeaderValue::from_str(authority) {
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
fn strip_hop_by_hop(headers: &mut HeaderMap) {
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

/// A plain-text refusal, for the cases where no app ever sees the request.
fn refuse(status: StatusCode, body: String) -> Response<Body> {
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

        forwarded_headers(&mut headers, "alpha.test", Some(conn));

        assert_eq!(header(&headers, "host"), "alpha.test");
        assert_eq!(header(&headers, "x-forwarded-host"), "alpha.test");
        assert_eq!(header(&headers, "x-forwarded-proto"), "https");
        // The client's own claim is replaced, not appended to.
        assert_eq!(header(&headers, "x-forwarded-for"), "203.0.113.7");
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
        let state = Arc::new(EdgeState {
            router: routes::router(std::sync::Arc::new(crate::acme::Challenges::new())),
            apps,
            upstreams: Upstreams::new(),
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

                tokio::spawn(async move {
                    let _ = Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
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
                "schema_version: 1\nsource:\n  type: image\n  image: x\nrouting:\n  hosts: [{host}]\n"
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
}

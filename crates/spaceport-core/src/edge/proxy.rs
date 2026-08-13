//! Forwarding requests to upstreams.
//!
//! A placeholder for now: no upstreams exist in the configuration yet, so
//! every request is refused with the reason. The shape is what matters — the
//! request arrives with hyper's `Incoming` body intact and unboxed, so once
//! there is an upstream to talk to, the body can be streamed straight into the
//! outgoing request without a copy.

use std::convert::Infallible;

use axum::body::Body;
use http::{Request, Response, StatusCode, header};
use hyper::body::Incoming;
use tracing::debug;

use super::service::{self, ConnInfo};

pub async fn handle(req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    let host = service::request_host(&req).unwrap_or("<none>");

    if let Some(conn) = req.extensions().get::<ConnInfo>() {
        debug!(
            peer = %conn.peer,
            scheme = conn.scheme.as_str(),
            method = %req.method(),
            host,
            path = req.uri().path(),
            "no upstream configured",
        );
    }

    let body = format!(
        "spaceport has no upstream configured for {host}{}\n",
        req.uri().path()
    );

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::BAD_GATEWAY;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    Ok(response)
}

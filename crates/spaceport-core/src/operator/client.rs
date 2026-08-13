//! The operator interface's client side, as used by `spaceport apps`.
//!
//! One request per command and no connection reuse, so this drives a single
//! hyper connection directly rather than carrying a pooled client. The
//! endpoint decides the transport; everything above that is the same HTTP.

use std::path::Path;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

use super::OperatorEndpoint;
use crate::app::AppId;

/// Ask a running spaceport to apply `manifest` as the app named `id`.
///
/// Returns what the server said, which is text meant for whoever ran the
/// command.
pub async fn apply(endpoint: &OperatorEndpoint, id: &AppId, manifest: String) -> Result<String> {
    let request = Request::builder()
        .method("PUT")
        .uri(format!("/apps/{id}"))
        // Required by HTTP/1.1 and meaningless here: there is no name to send,
        // the endpoint is the address.
        .header(http::header::HOST, "spaceport")
        .header(http::header::CONTENT_TYPE, "application/yaml")
        .body(Full::new(Bytes::from(manifest)))?;

    match endpoint {
        OperatorEndpoint::Unix(path) => {
            let stream = UnixStream::connect(path)
                .await
                .with_context(|| unreachable_at(path))?;

            send(stream, request).await
        }
        OperatorEndpoint::Tcp(addr) => {
            let stream = TcpStream::connect(addr)
                .await
                .with_context(|| format!("no spaceport is listening on {addr}"))?;

            send(stream, request).await
        }
    }
}

fn unreachable_at(path: &Path) -> String {
    format!(
        "no spaceport is listening on `{}` — is it running, and was it started with `--operator {}`?",
        path.display(),
        path.display(),
    )
}

async fn send<S>(stream: S, request: Request<Full<Bytes>>) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .context("speaking http to the operator interface")?;

    // The connection has to be driven for the request to make progress, and it
    // finishes on its own once the response is done with.
    tokio::spawn(connection);

    let response = sender
        .send_request(request)
        .await
        .context("sending the request to the operator interface")?;

    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    let body = String::from_utf8_lossy(&body).into_owned();

    if !status.is_success() {
        // The server's message is the useful part; the status only says whose
        // problem it is.
        bail!("{}", body.trim_end());
    }

    if status == StatusCode::NO_CONTENT {
        return Ok(String::new());
    }

    Ok(body)
}

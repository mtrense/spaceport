//! The operator interface's client side, as used by `spaceport apps` and
//! `spaceport stream`.
//!
//! One request per command and no connection reuse, so this drives a single
//! hyper connection directly rather than carrying a pooled client. The
//! endpoint decides the transport; everything above that is the same HTTP.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

use super::OperatorEndpoint;
use crate::app::{AppId, Pattern};
use crate::events::{Category, Event, Level};
use crate::status::Status;

/// Ask a running spaceport to apply `manifest` as the app named `id`.
///
/// Returns what the server said, which is text meant for whoever ran the
/// command.
/// With `suspended`, the app is recorded and claims its hosts without being
/// started.
pub async fn apply(
    endpoint: &OperatorEndpoint,
    id: &AppId,
    manifest: String,
    suspended: bool,
) -> Result<String> {
    let uri = match suspended {
        true => format!("/apps/{id}?suspended=true"),
        false => format!("/apps/{id}"),
    };
    let request = builder("PUT", &uri)
        .header(http::header::CONTENT_TYPE, "application/yaml")
        .body(Full::new(Bytes::from(manifest)))?;

    send_to(endpoint, request).await
}

/// Ask it to stop serving the app named `id`, keeping everything about it.
///
/// With `stop_container`, its container is stopped and kept rather than left
/// running.
pub async fn suspend(
    endpoint: &OperatorEndpoint,
    id: &AppId,
    stop_container: bool,
) -> Result<String> {
    let uri = match stop_container {
        true => format!("/apps/{id}/suspend?stop_container=true"),
        false => format!("/apps/{id}/suspend"),
    };

    send_to(endpoint, builder("POST", &uri).body(Full::default())?).await
}

/// Ask it to serve the app named `id` again.
pub async fn resume(endpoint: &OperatorEndpoint, id: &AppId) -> Result<String> {
    let request = builder("POST", &format!("/apps/{id}/resume")).body(Full::default())?;

    send_to(endpoint, request).await
}

/// Ask for the apps it is running, optionally only those matching `pattern`.
pub async fn list(endpoint: &OperatorEndpoint, pattern: Option<&Pattern>) -> Result<String> {
    // A pattern is lowercase letters, digits, hyphens and `*`, all of which a
    // query string carries as they are.
    let uri = match pattern {
        Some(pattern) => format!("/apps?pattern={pattern}"),
        None => "/apps".to_owned(),
    };

    send_to(endpoint, builder("GET", &uri).body(Full::default())?).await
}

/// Ask for everything it knows about the app named `id`.
///
/// With `manifest`, the document that was applied comes back verbatim and on
/// its own, rather than a report about it.
pub async fn show(endpoint: &OperatorEndpoint, id: &AppId, manifest: bool) -> Result<String> {
    let uri = match manifest {
        true => format!("/apps/{id}?manifest=true"),
        false => format!("/apps/{id}"),
    };

    send_to(endpoint, builder("GET", &uri).body(Full::default())?).await
}

/// Ask what this spaceport is and how it is doing.
///
/// The one call that comes back as data rather than as prose: what a status
/// should look like depends on whether a person is reading it, and only this
/// side knows that.
pub async fn status(endpoint: &OperatorEndpoint) -> Result<Status> {
    let body = send_to(endpoint, builder("GET", "/status").body(Full::default())?).await?;

    serde_json::from_str(&body)
        .context("the operator interface sent something that is not a status")
}

/// Ask it to stop the app named `id` and forget it.
pub async fn destroy(endpoint: &OperatorEndpoint, id: &AppId) -> Result<String> {
    let request = builder("DELETE", &format!("/apps/{id}")).body(Full::default())?;

    send_to(endpoint, request).await
}

/// Ask it to hold a GitHub App an operator registered by hand.
///
/// The registration is sent as JSON rather than as a document, because it is a
/// handful of typed fields and three of them are secrets that should not have
/// to touch a file on the way.
pub async fn connect_github(
    endpoint: &OperatorEndpoint,
    registration: &GithubRegistration,
) -> Result<String> {
    let body = serde_json::to_vec(registration).context("writing the github app registration")?;
    let request = builder("POST", "/connections/github")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))?;

    send_to(endpoint, request).await
}

/// Ask it to begin the flow that has GitHub create the app.
///
/// Comes back as prose holding a url, because that is all there is to hand
/// over: the app is created by a browser posting a manifest to github.com, and
/// nothing this side can do that. The command prints the url and exits — it
/// does not wait, because what it would be waiting on is a person.
pub async fn register_github(
    endpoint: &OperatorEndpoint,
    request: &GithubAppRequest,
) -> Result<String> {
    let body = serde_json::to_vec(request).context("writing the github app request")?;
    let request = builder("POST", "/connections/github/register")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))?;

    send_to(endpoint, request).await
}

/// What GitHub should be asked to create.
///
/// Both fields optional, and for different reasons: an app with no organisation
/// belongs to whoever is logged in, and an app with no name is named after the
/// spaceport's hostname — which only the spaceport knows.
#[derive(Debug, Clone, Serialize)]
pub struct GithubAppRequest {
    pub org: Option<String>,
    pub name: Option<String>,
}

/// Ask for the connections it holds.
pub async fn connections(endpoint: &OperatorEndpoint) -> Result<String> {
    send_to(
        endpoint,
        builder("GET", "/connections").body(Full::default())?,
    )
    .await
}

/// Ask for everything it knows about the connection named `slug`.
pub async fn connection(endpoint: &OperatorEndpoint, slug: &str) -> Result<String> {
    let request = builder("GET", &format!("/connections/{slug}")).body(Full::default())?;

    send_to(endpoint, request).await
}

/// Ask it to forget the connection named `slug`, and everything cached under
/// it.
pub async fn forget_connection(endpoint: &OperatorEndpoint, slug: &str) -> Result<String> {
    let request = builder("DELETE", &format!("/connections/{slug}")).body(Full::default())?;

    send_to(endpoint, request).await
}

/// A GitHub App registration on its way to a spaceport.
///
/// A type of this side's own rather than
/// [`crate::connections::github::Registration`], because that one deliberately
/// cannot be serialised: its secrets are [`crate::connections::Secret`]s, and
/// the whole point of that type is that nothing writes one out by accident.
/// Writing one out is exactly what this does, so it says so.
#[derive(Debug, Clone, Serialize)]
pub struct GithubRegistration {
    pub slug: String,
    pub app_id: i64,
    pub name: String,
    pub owner: String,
    pub client_id: String,
    pub client_secret: String,
    pub webhook_secret: String,
    /// The contents of the `.pem` file, not a path to it: the spaceport being
    /// talked to may be on another host entirely.
    pub private_key: String,
}

/// Which events `stream` asks for.
#[derive(Debug, Default, Clone)]
pub struct Watch {
    pub app: Option<Pattern>,
    pub category: Option<Category>,
    pub level: Option<Level>,
    /// How many events from before now to be sent first.
    pub history: usize,
}

impl Watch {
    /// The query string that asks for exactly this.
    ///
    /// Nothing here needs escaping: a pattern is app-id characters and `*`, a
    /// category is lowercase and dots, and the rest are a word and a number.
    fn query(&self) -> String {
        let mut query = String::new();
        let mut add = |name: &str, value: &dyn std::fmt::Display| {
            let separator = if query.is_empty() { '?' } else { '&' };
            let _ = write!(query, "{separator}{name}={value}");
        };

        if let Some(app) = &self.app {
            add("app", app);
        }
        if let Some(category) = &self.category {
            add("category", category);
        }
        if let Some(level) = &self.level {
            add("level", level);
        }
        if self.history > 0 {
            add("history", &self.history);
        }

        query
    }
}

/// Watch what a running spaceport is doing, handing each event to `on_event`
/// as it arrives.
///
/// Returns only when spaceport stops streaming — which it does when it shuts
/// down, and otherwise not at all. A caller that wants to stop before then
/// drops the future.
pub async fn stream(
    endpoint: &OperatorEndpoint,
    watch: &Watch,
    mut on_event: impl FnMut(Event),
) -> Result<()> {
    let request = builder("GET", &format!("/events{}", watch.query())).body(Full::default())?;
    let mut response = send_request(connect(endpoint).await?, request).await?;

    let status = response.status();
    if !status.is_success() {
        let body = response.into_body().collect().await?.to_bytes();
        bail!("{}", String::from_utf8_lossy(&body).trim_end());
    }

    // Lines, not frames: what arrives is whatever the network chose to deliver,
    // and one read can hold half an event or three of them.
    let mut pending = Vec::new();
    while let Some(frame) = response.frame().await {
        let frame = frame.context("reading from the event stream")?;
        let Some(chunk) = frame.data_ref() else {
            continue;
        };
        pending.extend_from_slice(chunk);

        while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            let line = &line[..line.len() - 1];
            // An empty line is a keep-alive, not an event.
            if line.is_empty() {
                continue;
            }

            on_event(
                serde_json::from_slice(line)
                    .context("the operator interface sent something that is not an event")?,
            );
        }
    }

    Ok(())
}

fn builder(method: &str, uri: &str) -> http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        // Required by HTTP/1.1 and meaningless here: there is no name to send,
        // the endpoint is the address.
        .header(http::header::HOST, "spaceport")
}

/// Whatever the endpoint turned out to be. The transport is chosen once, on
/// connecting, and nothing above this cares which one it got.
trait Transport: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Transport for T {}

/// Make the one connection a request needs, over whichever transport the
/// endpoint names.
async fn connect(endpoint: &OperatorEndpoint) -> Result<Box<dyn Transport>> {
    Ok(match endpoint {
        OperatorEndpoint::Unix(path) => Box::new(
            UnixStream::connect(path)
                .await
                .with_context(|| unreachable_at(path))?,
        ),
        OperatorEndpoint::Tcp(addr) => Box::new(
            TcpStream::connect(addr)
                .await
                .with_context(|| format!("no spaceport is listening on {addr}"))?,
        ),
    })
}

fn unreachable_at(path: &Path) -> String {
    format!(
        "no spaceport is listening on `{}` — is it running, and was it started with `--operator {}`?",
        path.display(),
        path.display(),
    )
}

/// Send `request` and hand back the response with its body still coming: a
/// command collects it, a stream reads it for as long as it lasts.
async fn send_request(
    stream: Box<dyn Transport>,
    request: Request<Full<Bytes>>,
) -> Result<http::Response<hyper::body::Incoming>> {
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .context("speaking http to the operator interface")?;

    // The connection has to be driven for the request to make progress, and it
    // finishes on its own once the response is done with.
    tokio::spawn(connection);

    sender
        .send_request(request)
        .await
        .context("sending the request to the operator interface")
}

async fn send_to(endpoint: &OperatorEndpoint, request: Request<Full<Bytes>>) -> Result<String> {
    let response = send_request(connect(endpoint).await?, request).await?;

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

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

use super::{OperatorEndpoint, SecretSet};
use crate::app::manifest::VarName;
use crate::app::{AppId, Pattern};
use crate::auth::{RevokeScope, RoleAtApp, SessionId, UserId, UserRef, UserSlug};
use crate::events::{Category, Event, Level};
use crate::secret::Secret;
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

/// Ask it to run what it built for the app named `id`.
///
/// Without `revision`, it runs the newest image it has finished building.
///
/// A commit sha is hex and needs no encoding, which is the same argument
/// [`list`] makes for a pattern: nothing here can carry a character a query
/// string would swallow, and a spaceport asked for a revision that is not one
/// answers that it has no build of it.
pub async fn deploy(
    endpoint: &OperatorEndpoint,
    id: &AppId,
    revision: Option<&str>,
) -> Result<String> {
    let uri = match revision {
        Some(revision) => format!("/apps/{id}/deployment?revision={revision}"),
        None => format!("/apps/{id}/deployment"),
    };

    send_to(endpoint, builder("POST", &uri).body(Full::default())?).await
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

/// Ask it to remember that the app named `id` is built from `repository`.
///
/// Without `branch`, the spaceport asks GitHub for the repository's default
/// branch and records what it answers, so the app follows a branch by name from
/// then on rather than following whatever the default becomes. Without
/// `manifest_path`, the manifest is looked for at the top of the repository.
///
/// Whichever branch it settles on, the spaceport asks GitHub where that branch
/// is and records the commit — so what comes back names a build that has been
/// asked for, not only the pushes to come.
///
/// `deploy` is three answers and not two. `Some` arms or disarms the app, so
/// that a build which succeeds is run without anybody asking, or is not; `None`
/// is a caller who has not raised the subject, and leaves the app exactly as
/// armed as it already was. That is why it goes into the query string only when
/// it is `Some`: an absent parameter is what the far end reads as "not
/// mentioned", and sending `deploy=false` for a re-track that only corrected a
/// manifest path would quietly stop an app deploying itself.
///
/// The values go into the query string as they are, which is what every other
/// call here does and is enough for these: a full name and a slug are github's
/// own characters, a path is a path, and a branch may hold `/`, which a query
/// string carries. It is not enough for a branch holding `&`, `#` or `%` —
/// unusual, and permitted by git — and the answer to that is an encoder this
/// crate does not have and will not gain a dependency for over a branch nobody
/// has yet. Such a branch is refused by the spaceport as a repository or a
/// branch it cannot find rather than silently tracking something else.
pub async fn track(
    endpoint: &OperatorEndpoint,
    id: &AppId,
    repository: &str,
    connection: &str,
    branch: Option<&str>,
    manifest_path: Option<&str>,
    deploy: Option<bool>,
) -> Result<String> {
    let mut uri = format!("/apps/{id}/tracking?repository={repository}&connection={connection}");
    if let Some(branch) = branch {
        let _ = write!(uri, "&branch={branch}");
    }
    if let Some(manifest_path) = manifest_path {
        let _ = write!(uri, "&manifest_path={manifest_path}");
    }
    if let Some(deploy) = deploy {
        let _ = write!(uri, "&deploy={deploy}");
    }

    send_to(endpoint, builder("PUT", &uri).body(Full::default())?).await
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

/// Ask for the names of the secrets set for the app named `id`, optionally only
/// those matching `pattern`.
///
/// Names, one per line, and never a value: the route behind this cannot answer
/// with one.
pub async fn secrets(
    endpoint: &OperatorEndpoint,
    id: &AppId,
    pattern: Option<&Pattern>,
) -> Result<String> {
    // A pattern over secret names is letters, digits, underscores and `*`,
    // which a query string carries as they are — the argument [`list`] makes.
    let uri = match pattern {
        Some(pattern) => format!("/apps/{id}/secrets?pattern={pattern}"),
        None => format!("/apps/{id}/secrets"),
    };

    send_to(endpoint, builder("GET", &uri).body(Full::default())?).await
}

/// Ask it to set the secret `name` of the app named `id` to `value`.
///
/// The value goes in the body and emphatically not in the uri, which is the
/// one thing about this call worth knowing: a query parameter would be written
/// to every access log between here and the spaceport, and would rule out
/// every value holding a character a url reserves. The name is safe there —
/// the C rules for an environment variable admit nothing a url would swallow.
///
/// What comes back says what the spaceport did about it, because storing a
/// value can leave an app untouched, resume it, or replace its container, and
/// only this side knows how to say that to a person.
pub async fn set_secret(
    endpoint: &OperatorEndpoint,
    id: &AppId,
    name: &VarName,
    value: &Secret,
) -> Result<SecretSet> {
    let request = builder("PUT", &format!("/apps/{id}/secrets/{name}"))
        // Text rather than octets, because that is the promise being made: a
        // value that is not utf-8 is one the far end refuses.
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(value.expose().to_owned())))?;

    let body = send_to(endpoint, request).await?;

    serde_json::from_str(&body)
        .context("the operator interface sent something that is not what setting a secret did")
}

/// Ask it to forget the secret `name` of the app named `id`.
pub async fn delete_secret(
    endpoint: &OperatorEndpoint,
    id: &AppId,
    name: &VarName,
) -> Result<String> {
    let request = builder("DELETE", &format!("/apps/{id}/secrets/{name}")).body(Full::default())?;

    send_to(endpoint, request).await
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

/// Ask for the users it knows, optionally only those whose slug matches
/// `pattern`.
pub async fn auth_user_list(
    endpoint: &OperatorEndpoint,
    pattern: Option<&Pattern>,
) -> Result<String> {
    // A pattern over slugs is lowercase letters, digits, hyphens and `*`,
    // which a query string carries as they are — the argument [`list`] makes.
    let uri = match pattern {
        Some(pattern) => format!("/auth/users?pattern={pattern}"),
        None => "/auth/users".to_owned(),
    };

    send_to(endpoint, builder("GET", &uri).body(Full::default())?).await
}

/// Ask it to create a user under `slug`, minting the id it keeps for life.
///
/// The email goes in the body rather than the uri, because an address may
/// carry a `+` that a query string would silently read as a space — and an
/// absent address is an empty body. The slug is safe in the path: its alphabet
/// is the app id's.
pub async fn auth_user_create(
    endpoint: &OperatorEndpoint,
    slug: &UserSlug,
    email: Option<&str>,
) -> Result<String> {
    let request = builder("PUT", &format!("/auth/users/{slug}"))
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(email.unwrap_or("").to_owned())))?;

    send_to(endpoint, request).await
}

/// Ask it to suspend the user `user` names — a slug or a user id, and the far
/// end resolves which. Resolution lives there rather than here because the far
/// end holds the pool the answer is about.
pub async fn auth_user_suspend(endpoint: &OperatorEndpoint, user: &UserRef) -> Result<String> {
    let request = builder("POST", &format!("/auth/users/{user}/suspend")).body(Full::default())?;

    send_to(endpoint, request).await
}

/// Ask it to let the user `user` names back in.
pub async fn auth_user_resume(endpoint: &OperatorEndpoint, user: &UserRef) -> Result<String> {
    let request = builder("POST", &format!("/auth/users/{user}/resume")).body(Full::default())?;

    send_to(endpoint, request).await
}

/// Ask it to drop the user `user` names, keeping only the auth log's memory.
pub async fn auth_user_drop(endpoint: &OperatorEndpoint, user: &UserRef) -> Result<String> {
    let request = builder("DELETE", &format!("/auth/users/{user}")).body(Full::default())?;

    send_to(endpoint, request).await
}

/// Ask it to grant `entitlement` to the user `user` names.
///
/// Both halves are safe in a path as they are: a slug, a role and an app id
/// share one alphabet with nothing a url reserves, a UUID is hex and hyphens,
/// and the `@` between role and app is an ordinary path character.
pub async fn auth_grant(
    endpoint: &OperatorEndpoint,
    user: &UserRef,
    entitlement: &RoleAtApp,
) -> Result<String> {
    let request = builder(
        "PUT",
        &format!("/auth/users/{user}/entitlements/{entitlement}"),
    )
    .body(Full::default())?;

    send_to(endpoint, request).await
}

/// Ask it to revoke what `scope` names of the user's entitlements — one role
/// at an app, every role at an app, or (`None`, the CLI's `--all`) everything
/// across apps.
///
/// The absence of a scope is spelled as the absence of a path segment rather
/// than a magic value, so nothing an operator could type can accidentally mean
/// "everything".
pub async fn auth_revoke(
    endpoint: &OperatorEndpoint,
    user: &UserRef,
    scope: Option<&RevokeScope>,
) -> Result<String> {
    let uri = match scope {
        Some(scope) => format!("/auth/users/{user}/entitlements/{scope}"),
        None => format!("/auth/users/{user}/entitlements"),
    };

    send_to(endpoint, builder("DELETE", &uri).body(Full::default())?).await
}

/// Ask for the sessions and API keys of the user `user` names — one listing,
/// told apart by its KIND column.
pub async fn auth_session_list(endpoint: &OperatorEndpoint, user: &UserRef) -> Result<String> {
    let request = builder("GET", &format!("/auth/users/{user}/sessions")).body(Full::default())?;

    send_to(endpoint, request).await
}

/// Ask it to mint an API key for the user `user` names, granting exactly
/// `grants` until `expires` (a duration like `90d`, the far end's default
/// when absent) from now.
///
/// The duration travels as the operator spelled it for [`auth_session_mint`]'s
/// reason: the server's parser stays the authority. Everything else is safe in
/// a path as a grant's arguments are — one shared alphabet, and an `@` is an
/// ordinary path character.
pub async fn auth_api_key_mint(
    endpoint: &OperatorEndpoint,
    user: &UserRef,
    grants: &RoleAtApp,
    expires: Option<&str>,
) -> Result<String> {
    let uri = match expires {
        Some(expires) => format!("/auth/users/{user}/api-keys/{grants}?expires={expires}"),
        None => format!("/auth/users/{user}/api-keys/{grants}"),
    };

    send_to(endpoint, builder("POST", &uri).body(Full::default())?).await
}

/// Ask it to mint a one-time code for the user `user` names, redeeming into a
/// session that lives `expires` (a duration like `12h`, the far end's default
/// when absent).
///
/// The duration travels as the operator spelled it and is parsed at the far
/// end, where the refusal can come from the same parser every manifest goes
/// through — two parsers would be two opinions about what `90m` means. Its
/// alphabet is digits and letters, which a query string carries as they are.
pub async fn auth_session_mint(
    endpoint: &OperatorEndpoint,
    user: &UserRef,
    expires: Option<&str>,
) -> Result<String> {
    let uri = match expires {
        Some(expires) => format!("/auth/users/{user}/sessions?expires={expires}"),
        None => format!("/auth/users/{user}/sessions"),
    };

    send_to(endpoint, builder("POST", &uri).body(Full::default())?).await
}

/// Ask it to drop one session of the user's, or (`None`) every one they hold.
///
/// Absence is the absence of a path segment, exactly as [`auth_revoke`]
/// spells it, so nothing an operator could type can accidentally mean
/// "everything".
pub async fn auth_session_drop(
    endpoint: &OperatorEndpoint,
    user: &UserRef,
    session: Option<&SessionId>,
) -> Result<String> {
    let uri = match session {
        Some(session) => format!("/auth/users/{user}/sessions/{session}"),
        None => format!("/auth/users/{user}/sessions"),
    };

    send_to(endpoint, builder("DELETE", &uri).body(Full::default())?).await
}

/// Ask for one user's whole standing: the record, the SSO connection, every
/// entitlement with its origin, and the apps they actually reach.
pub async fn auth_audit(endpoint: &OperatorEndpoint, user: &UserRef) -> Result<String> {
    let request = builder("GET", &format!("/auth/users/{user}/audit")).body(Full::default())?;

    send_to(endpoint, request).await
}

/// Ask it to rotate the JWT signing key now — the compromise-response lever;
/// the ninety-day clock rotates on its own.
pub async fn auth_key_rotate(endpoint: &OperatorEndpoint) -> Result<String> {
    let request = builder("POST", "/auth/keys/rotate").body(Full::default())?;

    send_to(endpoint, request).await
}

/// Ask for the signing keys still in the store: the current one, and any
/// retired key the JWKS is still serving out its grace.
pub async fn auth_key_list(endpoint: &OperatorEndpoint) -> Result<String> {
    let request = builder("GET", "/auth/keys").body(Full::default())?;

    send_to(endpoint, request).await
}

/// Ask for the auth event log, optionally only what happened to one user.
pub async fn auth_log(endpoint: &OperatorEndpoint, user: Option<&UserId>) -> Result<String> {
    // A user id is hex and hyphens, which a query string carries as they are.
    let uri = match user {
        Some(user) => format!("/auth/log?user={user}"),
        None => "/auth/log".to_owned(),
    };

    send_to(endpoint, builder("GET", &uri).body(Full::default())?).await
}

/// A GitHub App registration on its way to a spaceport.
///
/// A type of this side's own rather than
/// [`crate::connections::github::Registration`], because that one deliberately
/// cannot be serialised: its secrets are [`crate::secret::Secret`]s, and
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

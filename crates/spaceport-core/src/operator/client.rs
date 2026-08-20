//! The operator interface's client side, as used by `spaceport apps` and
//! `spaceport stream`.
//!
//! One request per command and no connection reuse, so this drives a single
//! hyper connection directly rather than carrying a pooled client. Always over
//! the unix socket [`super`] describes, which is why nothing here presents a
//! credential: the socket's mode already said who may ask.
//!
//! Every URI here is built by interpolation, and a value an operator typed goes
//! through [`query_encode`] on the way in. A value that names itself — an app
//! id, a pattern, a uuid — is a type whose parser already refused everything a
//! URI reserves, and those say so where they are used; a value that is a
//! free-form string is encoded, because there is nothing else standing between
//! what was typed and what the far end reads as a parameter.

use std::fmt::Write as _;
use std::future::Future;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;

use super::{Operator, PATIENT_MULTIPLE, SecretSet, wire};
use crate::app::manifest::VarName;
use crate::app::{AppId, Pattern};
use crate::auth::{Condition, RevokeScope, Role, RoleAtApp, SessionId, UserId, UserRef, UserSlug};
use crate::events::{Category, Event, Level};
use crate::secret::Secret;
use crate::status::Status;
use crate::uri::query_encode;

/// Ask a running spaceport to apply `manifest` as the app named `id`.
///
/// Returns what the server said, which is text meant for whoever ran the
/// command.
/// With `suspended`, the app is recorded and claims its hosts without being
/// started.
pub async fn apply(
    operator: &Operator,
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

    send_to(operator, Pace::Patient, request).await
}

/// Ask it to run what it built for the app named `id`.
///
/// Without `revision`, it runs the newest image it has finished building.
///
/// A commit sha is hex, but nothing checks that before it is sent — it is a
/// free-form string an operator typed, so it is encoded like every other one.
/// A spaceport asked for a revision that is not one answers that it has no
/// build of it, which is what should happen to a value that is not a sha.
pub async fn deploy(operator: &Operator, id: &AppId, revision: Option<&str>) -> Result<String> {
    let uri = match revision {
        Some(revision) => format!("/apps/{id}/deployment?revision={}", query_encode(revision)),
        None => format!("/apps/{id}/deployment"),
    };

    send_to(
        operator,
        Pace::Patient,
        builder("POST", &uri).body(Full::default())?,
    )
    .await
}

/// Ask it to stop serving the app named `id`, keeping everything about it.
///
/// With `stop_container`, its container is stopped and kept rather than left
/// running.
pub async fn suspend(operator: &Operator, id: &AppId, stop_container: bool) -> Result<String> {
    let uri = match stop_container {
        true => format!("/apps/{id}/suspend?stop_container=true"),
        false => format!("/apps/{id}/suspend"),
    };

    send_to(
        operator,
        Pace::Patient,
        builder("POST", &uri).body(Full::default())?,
    )
    .await
}

/// Ask it to serve the app named `id` again.
pub async fn resume(operator: &Operator, id: &AppId) -> Result<String> {
    let request = builder("POST", &format!("/apps/{id}/resume")).body(Full::default())?;

    send_to(operator, Pace::Patient, request).await
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
/// Every one of these four values is a free-form string an operator typed, so
/// every one of them is encoded on the way into the query string. What that
/// buys is not politeness about odd branch names: an unencoded value ends the
/// parameter it is in and begins the next one, so a manifest path of
/// `spaceport.yaml&deploy=true` would arm the app for automatic deployment
/// without ever going near the flag that asks for it — and `deny_unknown_fields`
/// at the far end cannot help, because the field being smuggled in is a real
/// one. Encoded, a value arrives as the one value it was, whatever it held.
///
/// So a branch holding `&`, `#`, `%` or a space — unusual, and permitted by git
/// — now travels honestly and comes back as a branch the spaceport could not
/// find, which is the truth about it.
pub async fn track(
    operator: &Operator,
    id: &AppId,
    repository: &str,
    connection: &str,
    branch: Option<&str>,
    manifest_path: Option<&str>,
    deploy: Option<bool>,
) -> Result<String> {
    let uri = tracking_uri(id, repository, connection, branch, manifest_path, deploy);

    send_to(
        operator,
        Pace::Patient,
        builder("PUT", &uri).body(Full::default())?,
    )
    .await
}

/// The URI [`track`] sends, apart from it so that what it comes to for a given
/// set of arguments can be asked without a spaceport to send it to — and so
/// that the route on the other side can be tested against the very string this
/// builds rather than against one a test wrote out by hand.
pub(super) fn tracking_uri(
    id: &AppId,
    repository: &str,
    connection: &str,
    branch: Option<&str>,
    manifest_path: Option<&str>,
    deploy: Option<bool>,
) -> String {
    let mut uri = format!(
        "/apps/{id}/tracking?repository={}&connection={}",
        query_encode(repository),
        query_encode(connection),
    );
    if let Some(branch) = branch {
        let _ = write!(uri, "&branch={}", query_encode(branch));
    }
    if let Some(manifest_path) = manifest_path {
        let _ = write!(uri, "&manifest_path={}", query_encode(manifest_path));
    }
    // Not encoded and needing no encoding: this one is not a string anybody
    // typed, it is `true` or `false`. It is here at all only when the caller
    // answered the question — see above.
    if let Some(deploy) = deploy {
        let _ = write!(uri, "&deploy={deploy}");
    }

    uri
}

/// Ask for the apps it is running, optionally only those matching `pattern`.
///
/// The rows, not the columns: how wide they are and which cell is worth
/// colouring is the caller's to decide, and an empty answer is an empty list
/// rather than a sentence about it.
pub async fn list(operator: &Operator, pattern: Option<&Pattern>) -> Result<Vec<wire::AppRow>> {
    // A pattern is lowercase letters, digits, hyphens and `*`, all of which a
    // query string carries as they are.
    let uri = match pattern {
        Some(pattern) => format!("/apps?pattern={pattern}"),
        None => "/apps".to_owned(),
    };

    send_json_to(
        operator,
        Pace::Quick,
        builder("GET", &uri).body(Full::default())?,
    )
    .await
}

/// Ask for everything it knows about the app named `id`.
///
/// With `manifest`, the document that was applied comes back verbatim and on
/// its own, rather than a report about it.
pub async fn show(operator: &Operator, id: &AppId, manifest: bool) -> Result<String> {
    let uri = match manifest {
        true => format!("/apps/{id}?manifest=true"),
        false => format!("/apps/{id}"),
    };

    send_to(
        operator,
        Pace::Quick,
        builder("GET", &uri).body(Full::default())?,
    )
    .await
}

/// Ask for the names of the secrets set for the app named `id`, optionally only
/// those matching `pattern`.
///
/// Names, one per line, and never a value: the route behind this cannot answer
/// with one.
pub async fn secrets(operator: &Operator, id: &AppId, pattern: Option<&Pattern>) -> Result<String> {
    // A pattern over secret names is letters, digits, underscores and `*`,
    // which a query string carries as they are — the argument [`list`] makes.
    let uri = match pattern {
        Some(pattern) => format!("/apps/{id}/secrets?pattern={pattern}"),
        None => format!("/apps/{id}/secrets"),
    };

    send_to(
        operator,
        Pace::Quick,
        builder("GET", &uri).body(Full::default())?,
    )
    .await
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
    operator: &Operator,
    id: &AppId,
    name: &VarName,
    value: &Secret,
) -> Result<SecretSet> {
    let request = builder("PUT", &format!("/apps/{id}/secrets/{name}"))
        // Text rather than octets, because that is the promise being made: a
        // value that is not utf-8 is one the far end refuses.
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(value.expose().to_owned())))?;

    let body = send_to(operator, Pace::Patient, request).await?;

    serde_json::from_str(&body)
        .context("the operator interface sent something that is not what setting a secret did")
}

/// Ask it to forget the secret `name` of the app named `id`.
pub async fn delete_secret(operator: &Operator, id: &AppId, name: &VarName) -> Result<String> {
    let request = builder("DELETE", &format!("/apps/{id}/secrets/{name}")).body(Full::default())?;

    send_to(operator, Pace::Quick, request).await
}

/// Ask what this spaceport is and how it is doing.
///
/// The one call that comes back as data rather than as prose: what a status
/// should look like depends on whether a person is reading it, and only this
/// side knows that.
pub async fn status(operator: &Operator) -> Result<Status> {
    let body = send_to(
        operator,
        Pace::Quick,
        builder("GET", "/status").body(Full::default())?,
    )
    .await?;

    serde_json::from_str(&body)
        .context("the operator interface sent something that is not a status")
}

/// Ask it to stop the app named `id` and forget it.
pub async fn destroy(operator: &Operator, id: &AppId) -> Result<String> {
    let request = builder("DELETE", &format!("/apps/{id}")).body(Full::default())?;

    send_to(operator, Pace::Patient, request).await
}

/// Ask it to hold a GitHub App an operator registered by hand.
///
/// The registration is sent as JSON rather than as a document, because it is a
/// handful of typed fields and three of them are secrets that should not have
/// to touch a file on the way.
pub async fn connect_github(
    operator: &Operator,
    registration: &GithubRegistration,
) -> Result<String> {
    let body = serde_json::to_vec(registration).context("writing the github app registration")?;
    let request = builder("POST", "/connections/github")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))?;

    send_to(operator, Pace::Patient, request).await
}

/// Ask it to begin the flow that has GitHub create the app.
///
/// Comes back as prose holding a url, because that is all there is to hand
/// over: the app is created by a browser posting a manifest to github.com, and
/// nothing this side can do that. The command prints the url and exits — it
/// does not wait, because what it would be waiting on is a person.
pub async fn register_github(operator: &Operator, request: &GithubAppRequest) -> Result<String> {
    let body = serde_json::to_vec(request).context("writing the github app request")?;
    let request = builder("POST", "/connections/github/register")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))?;

    send_to(operator, Pace::Patient, request).await
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
pub async fn connections(operator: &Operator) -> Result<Vec<wire::ConnectionRow>> {
    send_json_to(
        operator,
        Pace::Quick,
        builder("GET", "/connections").body(Full::default())?,
    )
    .await
}

/// Ask for everything it knows about the connection named `slug`.
///
/// The slug is encoded for the reason [`track`] gives, in the path rather than
/// the query: nothing has held it to a slug's alphabet, and a `/` or a `?` in
/// an unencoded segment addresses a different route entirely. Encoded, a slug
/// that is not one comes back as a connection that does not exist.
pub async fn connection(operator: &Operator, slug: &str) -> Result<wire::Connection> {
    let request =
        builder("GET", &format!("/connections/{}", query_encode(slug))).body(Full::default())?;

    send_json_to(operator, Pace::Quick, request).await
}

/// Ask it to forget the connection named `slug`, and everything cached under
/// it.
pub async fn forget_connection(operator: &Operator, slug: &str) -> Result<String> {
    let request =
        builder("DELETE", &format!("/connections/{}", query_encode(slug))).body(Full::default())?;

    send_to(operator, Pace::Quick, request).await
}

/// Ask for the users it knows, optionally only those whose slug matches
/// `pattern`.
pub async fn auth_user_list(
    operator: &Operator,
    pattern: Option<&Pattern>,
) -> Result<Vec<wire::UserRow>> {
    // A pattern over slugs is lowercase letters, digits, hyphens and `*`,
    // which a query string carries as they are — the argument [`list`] makes.
    let uri = match pattern {
        Some(pattern) => format!("/auth/users?pattern={pattern}"),
        None => "/auth/users".to_owned(),
    };

    send_json_to(
        operator,
        Pace::Quick,
        builder("GET", &uri).body(Full::default())?,
    )
    .await
}

/// Ask it to create a user under `slug`, minting the id it keeps for life.
///
/// The email goes in the body rather than the uri, because an address may
/// carry a `+` that a query string would silently read as a space — and an
/// absent address is an empty body. The slug is safe in the path: its alphabet
/// is the app id's.
pub async fn auth_user_create(
    operator: &Operator,
    slug: &UserSlug,
    email: Option<&str>,
) -> Result<String> {
    let request = builder("PUT", &format!("/auth/users/{slug}"))
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(email.unwrap_or("").to_owned())))?;

    send_to(operator, Pace::Quick, request).await
}

/// Ask it to suspend the user `user` names — a slug or a user id, and the far
/// end resolves which. Resolution lives there rather than here because the far
/// end holds the pool the answer is about.
pub async fn auth_user_suspend(operator: &Operator, user: &UserRef) -> Result<String> {
    let request = builder("POST", &format!("/auth/users/{user}/suspend")).body(Full::default())?;

    send_to(operator, Pace::Quick, request).await
}

/// Ask it to let the user `user` names back in.
pub async fn auth_user_resume(operator: &Operator, user: &UserRef) -> Result<String> {
    let request = builder("POST", &format!("/auth/users/{user}/resume")).body(Full::default())?;

    send_to(operator, Pace::Quick, request).await
}

/// Ask it to drop the user `user` names, keeping only the auth log's memory.
pub async fn auth_user_drop(operator: &Operator, user: &UserRef) -> Result<String> {
    let request = builder("DELETE", &format!("/auth/users/{user}")).body(Full::default())?;

    send_to(operator, Pace::Quick, request).await
}

/// Ask it to grant `entitlement` to the user `user` names.
///
/// Both halves are safe in a path as they are: a slug, a role and an app id
/// share one alphabet with nothing a url reserves, a UUID is hex and hyphens,
/// and the `@` between role and app is an ordinary path character.
pub async fn auth_grant(
    operator: &Operator,
    user: &UserRef,
    entitlement: &RoleAtApp,
) -> Result<String> {
    let request = builder(
        "PUT",
        &format!("/auth/users/{user}/entitlements/{entitlement}"),
    )
    .body(Full::default())?;

    send_to(operator, Pace::Quick, request).await
}

/// Ask it to revoke what `scope` names of the user's entitlements — one role
/// at an app, every role at an app, or (`None`, the CLI's `--all`) everything
/// across apps.
///
/// The absence of a scope is spelled as the absence of a path segment rather
/// than a magic value, so nothing an operator could type can accidentally mean
/// "everything".
pub async fn auth_revoke(
    operator: &Operator,
    user: &UserRef,
    scope: Option<&RevokeScope>,
) -> Result<String> {
    let uri = match scope {
        Some(scope) => format!("/auth/users/{user}/entitlements/{scope}"),
        None => format!("/auth/users/{user}/entitlements"),
    };

    send_to(
        operator,
        Pace::Quick,
        builder("DELETE", &uri).body(Full::default())?,
    )
    .await
}

/// Ask for the sessions and API keys of the user `user` names — one listing,
/// told apart by its KIND column.
pub async fn auth_session_list(operator: &Operator, user: &UserRef) -> Result<wire::Sessions> {
    let request = builder("GET", &format!("/auth/users/{user}/sessions")).body(Full::default())?;

    send_json_to(operator, Pace::Quick, request).await
}

/// Ask it to mint an API key for the user `user` names, granting exactly
/// `grants` until `expires` (a duration like `90d`, the far end's default
/// when absent) from now.
///
/// The duration travels as the operator spelled it for [`auth_session_mint`]'s
/// reason: the server's parser stays the authority. Travelling as they spelled
/// it is why it is encoded — the whole point is that this side did not look at
/// it. Everything else is safe in a path as a grant's arguments are — one
/// shared alphabet, and an `@` is an ordinary path character.
pub async fn auth_api_key_mint(
    operator: &Operator,
    user: &UserRef,
    grants: &RoleAtApp,
    expires: Option<&str>,
) -> Result<String> {
    let uri = match expires {
        Some(expires) => format!(
            "/auth/users/{user}/api-keys/{grants}?expires={}",
            query_encode(expires)
        ),
        None => format!("/auth/users/{user}/api-keys/{grants}"),
    };

    send_to(
        operator,
        Pace::Quick,
        builder("POST", &uri).body(Full::default())?,
    )
    .await
}

/// Ask it to mint a one-time code for the user `user` names, redeeming into a
/// session that lives `expires` (a duration like `12h`, the far end's default
/// when absent).
///
/// The duration travels as the operator spelled it and is parsed at the far
/// end, where the refusal can come from the same parser every manifest goes
/// through — two parsers would be two opinions about what `90m` means. Which
/// means this side has not established that it is digits and letters at all, so
/// it is encoded: a value nobody here has checked is exactly the value that
/// must not be able to write a second parameter.
pub async fn auth_session_mint(
    operator: &Operator,
    user: &UserRef,
    expires: Option<&str>,
) -> Result<String> {
    let uri = match expires {
        Some(expires) => format!(
            "/auth/users/{user}/sessions?expires={}",
            query_encode(expires)
        ),
        None => format!("/auth/users/{user}/sessions"),
    };

    send_to(
        operator,
        Pace::Quick,
        builder("POST", &uri).body(Full::default())?,
    )
    .await
}

/// Ask it to drop one session of the user's, or (`None`) every one they hold.
///
/// Absence is the absence of a path segment, exactly as [`auth_revoke`]
/// spells it, so nothing an operator could type can accidentally mean
/// "everything".
pub async fn auth_session_drop(
    operator: &Operator,
    user: &UserRef,
    session: Option<&SessionId>,
) -> Result<String> {
    let uri = match session {
        Some(session) => format!("/auth/users/{user}/sessions/{session}"),
        None => format!("/auth/users/{user}/sessions"),
    };

    send_to(
        operator,
        Pace::Quick,
        builder("DELETE", &uri).body(Full::default())?,
    )
    .await
}

/// Ask for one user's whole standing: the record, the SSO connection, every
/// entitlement with its origin, and the apps they actually reach.
pub async fn auth_audit(operator: &Operator, user: &UserRef) -> Result<wire::Audit> {
    let request = builder("GET", &format!("/auth/users/{user}/audit")).body(Full::default())?;

    send_json_to(operator, Pace::Quick, request).await
}

/// A mapping rule on its way to a spaceport: the parts of `spaceport auth
/// mapping add`, typed here so the far end deserialises them through the same
/// parsers the CLI already ran.
///
/// JSON in the body rather than a path, because a rule is several values deep
/// and two of them are lists — the same argument a registration makes.
#[derive(Debug, Clone, Serialize)]
pub struct MappingAdd {
    /// The connection `--via` names.
    pub via: String,
    pub app: AppId,
    pub roles: Vec<Role>,
    pub conditions: Vec<Condition>,
}

/// Ask it to add an SSO mapping rule. What comes back names the stable rule
/// id, which this response is the operator's first sight of.
pub async fn auth_mapping_add(operator: &Operator, add: &MappingAdd) -> Result<String> {
    let body = serde_json::to_vec(add).context("writing the mapping")?;
    let request = builder("POST", "/auth/mappings")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))?;

    send_to(operator, Pace::Quick, request).await
}

/// Ask for the mapping rules it holds, optionally only those about one app.
pub async fn auth_mapping_list(
    operator: &Operator,
    app: Option<&AppId>,
) -> Result<Vec<wire::MappingRow>> {
    // An app id is the shared lowercase alphabet, which a query string
    // carries as it is — the argument [`list`] makes.
    let uri = match app {
        Some(app) => format!("/auth/mappings?app={app}"),
        None => "/auth/mappings".to_owned(),
    };

    send_json_to(
        operator,
        Pace::Quick,
        builder("GET", &uri).body(Full::default())?,
    )
    .await
}

/// Ask it to replay every mapping against the attributes stored from the
/// user's last IdP login — a dry run that changes nothing at the far end.
pub async fn auth_mapping_test(operator: &Operator, user: &UserRef) -> Result<String> {
    let request =
        builder("GET", &format!("/auth/users/{user}/mapping-test")).body(Full::default())?;

    send_to(operator, Pace::Quick, request).await
}

/// Ask it to drop the mapping rule `rule` names, and with it every
/// entitlement the rule produced.
///
/// The id is held to a rule id's alphabet before it rides the path: a rule id
/// is hex and hyphens, and anything else could carry a character the URI
/// would swallow — the far end would then 404 about a string the operator
/// never typed.
pub async fn auth_mapping_drop(operator: &Operator, rule: &str) -> Result<String> {
    if rule.is_empty()
        || !rule
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        bail!(
            "`{rule}` is not a rule id — `spaceport auth mapping list` prints them beside each rule"
        );
    }
    let request = builder("DELETE", &format!("/auth/mappings/{rule}")).body(Full::default())?;

    send_to(operator, Pace::Quick, request).await
}

/// Ask it to rotate the JWT signing key now — the compromise-response lever;
/// the ninety-day clock rotates on its own.
pub async fn auth_key_rotate(operator: &Operator) -> Result<String> {
    let request = builder("POST", "/auth/keys/rotate").body(Full::default())?;

    send_to(operator, Pace::Quick, request).await
}

/// Ask for the signing keys still in the store: the current one, and any
/// retired key the JWKS is still serving out its grace.
pub async fn auth_key_list(operator: &Operator) -> Result<Vec<wire::SigningKeyRow>> {
    let request = builder("GET", "/auth/keys").body(Full::default())?;

    send_json_to(operator, Pace::Quick, request).await
}

/// Ask for the auth event log, optionally only what happened to one user.
pub async fn auth_log(operator: &Operator, user: Option<&UserId>) -> Result<Vec<wire::LogRow>> {
    // A user id is hex and hyphens, which a query string carries as they are.
    let uri = match user {
        Some(user) => format!("/auth/log?user={user}"),
        None => "/auth/log".to_owned(),
    };

    send_json_to(
        operator,
        Pace::Quick,
        builder("GET", &uri).body(Full::default())?,
    )
    .await
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
    /// Every value goes through the encoder, though none of them has ever
    /// needed it — a pattern is app-id characters and `*`, a category is
    /// lowercase and dots, and the rest are a word and a number. It is one
    /// place that builds parameters out of values, and a place like that is
    /// better off encoding unconditionally than resting on what each of its
    /// callers happens to pass today.
    fn query(&self) -> String {
        let mut query = String::new();
        let mut add = |name: &str, value: &dyn std::fmt::Display| {
            let separator = if query.is_empty() { '?' } else { '&' };
            let _ = write!(
                query,
                "{separator}{name}={}",
                query_encode(&value.to_string())
            );
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
    operator: &Operator,
    watch: &Watch,
    mut on_event: impl FnMut(Event),
) -> Result<()> {
    // The deadline covers getting connected and hearing the response head, and
    // stops there: reaching a spaceport is as quick here as anywhere. One clock
    // across both phases, as everywhere else.
    let deadline = Deadline::starting_now(Pace::Quick.deadline(operator));
    let request = builder("GET", &format!("/events{}", watch.query())).body(Full::default())?;
    let mut response = send_request(connect(operator, deadline).await?, request, deadline).await?;

    let status = response.status();
    if !status.is_success() {
        let body = response.into_body().collect().await?.to_bytes();
        bail!("{}", String::from_utf8_lossy(&body).trim_end());
    }

    // Deliberately unbounded, and it must stay that way: the server sends no
    // keep-alive on `/events`, so an idle spaceport sends zero bytes for as
    // long as nothing happens. Any deadline on this loop would kill a stream
    // that is working perfectly, on the grounds that nothing was going wrong.
    //
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

/// How long a call is willing to wait, which depends on what it asked for.
///
/// The two tiers are [`super::PATIENT_MULTIPLE`]'s subject: an ordinary route
/// answers from state, while an apply or a github command is work the far end
/// does while the operator waits.
#[derive(Debug, Clone, Copy)]
enum Pace {
    Quick,
    Patient,
}

impl Pace {
    /// What this pace comes to for `operator`, whose `timeout` is the quick
    /// tier by definition and the patient tier by multiplication.
    ///
    /// [`Duration::ZERO`] survives the multiplication as itself, which is the
    /// escape hatch behaving the same at both tiers.
    fn deadline(self, operator: &Operator) -> Duration {
        match self {
            Self::Quick => operator.timeout,
            Self::Patient => operator.timeout * PATIENT_MULTIPLE,
        }
    }
}

/// One budget spanning a whole request, from the first connect to the last
/// byte of the body.
///
/// A request is several waits in a row — connecting, the http handshake, the
/// response head, then the body — and the budget belongs to the request rather
/// than to any of them. Handing each phase the full number would let a far end
/// that stalls a little at every step take several times the deadline the
/// operator set, and the whole point of the number is that they can predict it.
///
/// So the clock starts once and every phase races what is left of it.
#[derive(Debug, Clone, Copy)]
struct Deadline {
    /// What was in force, kept for the message: [`Instant`] arithmetic would
    /// otherwise report whatever fraction happened to be left when it ran out.
    budget: Duration,
    /// When the budget runs out, or `None` for the operator who asked for no
    /// deadline at all.
    until: Option<Instant>,
}

impl Deadline {
    /// Start the clock. Called once per request, never per phase.
    fn starting_now(budget: Duration) -> Self {
        Self {
            budget,
            until: (!budget.is_zero()).then(|| Instant::now() + budget),
        }
    }

    /// What is left, in the form [`within`] reads.
    ///
    /// An exhausted budget comes back as the smallest non-zero duration rather
    /// than as zero, because zero is how "no deadline" is spelled and a request
    /// that has run out of time is the one case that must not be granted it.
    fn remaining(self) -> Duration {
        match self.until {
            None => Duration::ZERO,
            Some(until) => until
                .saturating_duration_since(Instant::now())
                .max(Duration::from_nanos(1)),
        }
    }

    /// The number to quote at whoever set it.
    fn budget(self) -> Duration {
        self.budget
    }
}

/// Run `work` under `deadline`, calling `elapsed` for the message if it runs
/// out.
///
/// A `deadline` of [`Duration::ZERO`] is not a deadline of no time at all — it
/// is no deadline, and `work` is awaited for however long it takes.
///
/// The failure is the timeout's own and nothing to do with what `work` was
/// trying to say, so `work`'s own result comes back untouched inside.
async fn within<T>(
    deadline: Duration,
    elapsed: impl FnOnce() -> String,
    work: impl Future<Output = T>,
) -> Result<T> {
    if deadline.is_zero() {
        return Ok(work.await);
    }

    match tokio::time::timeout(deadline, work).await {
        Ok(done) => Ok(done),
        Err(_) => Err(anyhow!(elapsed())),
    }
}

/// What to say when the far end took the request and never answered.
///
/// It names the deadline that was actually in force, not the one that was
/// configured: a patient command is ten times the number the operator set, and
/// telling them `30s` when they waited five minutes would be a lie.
fn no_answer_within(deadline: Duration) -> String {
    format!(
        "spaceport did not answer within {} — it may still be working; set `SPACEPORT_TIMEOUT` higher (`SPACEPORT_TIMEOUT=2m`) to wait longer",
        spelled(deadline),
    )
}

/// A duration as an operator would have typed it, so that what comes back is
/// something they can put straight back into `SPACEPORT_TIMEOUT`.
fn spelled(duration: Duration) -> String {
    let millis = duration.as_millis();
    match millis {
        _ if millis.is_multiple_of(3_600_000) => format!("{}h", millis / 3_600_000),
        _ if millis.is_multiple_of(60_000) => format!("{}m", millis / 60_000),
        _ if millis.is_multiple_of(1_000) => format!("{}s", millis / 1_000),
        _ => format!("{millis}ms"),
    }
}

/// Make the one connection a request needs.
///
/// A connection that times out is reported as one that was refused. The
/// distinction between nothing listening and something listening that never
/// accepts is real, and it is not the concern of the person who typed the
/// command: either way no spaceport is answering there.
async fn connect(operator: &Operator, deadline: Deadline) -> Result<UnixStream> {
    let path = operator.endpoint.path();

    within(
        deadline.remaining(),
        || unreachable_at(path),
        UnixStream::connect(path),
    )
    .await?
    .with_context(|| unreachable_at(path))
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
///
/// The handshake and the response head are both under `deadline`; the body is
/// the caller's, because how long a body may take is what the caller is for.
async fn send_request(
    stream: UnixStream,
    request: Request<Full<Bytes>>,
    deadline: Deadline,
) -> Result<http::Response<hyper::body::Incoming>> {
    let (mut sender, connection) = within(
        deadline.remaining(),
        || no_answer_within(deadline.budget()),
        http1::handshake(TokioIo::new(stream)),
    )
    .await?
    .context("speaking http to the operator interface")?;

    // The connection has to be driven for the request to make progress, and it
    // finishes on its own once the response is done with.
    //
    // It outlives a future that times out, since nothing here cancels it. That
    // costs nothing where this is used — the CLI makes one request per process
    // and then exits — but it is not a seam a long-lived caller should reuse
    // without giving the driver something to be cancelled by.
    tokio::spawn(connection);

    within(
        deadline.remaining(),
        || no_answer_within(deadline.budget()),
        sender.send_request(request),
    )
    .await?
    .context("sending the request to the operator interface")
}

async fn send_to(operator: &Operator, pace: Pace, request: Request<Full<Bytes>>) -> Result<String> {
    // One clock for the whole call: connecting, the head and the body share it
    // rather than each starting it again.
    let deadline = Deadline::starting_now(pace.deadline(operator));
    let response = send_request(connect(operator, deadline).await?, request, deadline).await?;

    let status = response.status();
    let body = within(
        deadline.remaining(),
        || no_answer_within(deadline.budget()),
        response.into_body().collect(),
    )
    .await??
    .to_bytes();
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

/// Send `request` asking to be answered in [`wire`] rather than in columns,
/// and read back what it sent.
///
/// A refusal is still prose — an error message is written for a person however
/// the request was framed — so the failure path is [`send_to`]'s exactly: the
/// body is the message.
async fn send_json_to<T: DeserializeOwned>(
    operator: &Operator,
    pace: Pace,
    mut request: Request<Full<Bytes>>,
) -> Result<T> {
    request.headers_mut().insert(
        http::header::ACCEPT,
        http::HeaderValue::from_static(wire::JSON),
    );

    let body = send_to(operator, pace, request).await?;

    serde_json::from_str(&body)
        .context("the operator interface sent something this version cannot read")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Instant;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::UnixListener;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::operator::DEFAULT_TIMEOUT;

    /// A spaceport on `path`, waiting `timeout` for a quick answer.
    fn operator_on(path: PathBuf, timeout: Duration) -> Operator {
        Operator {
            endpoint: path.into(),
            timeout,
        }
    }

    /// A socket path of this test's own.
    ///
    /// Short by design: a unix socket address is a little over a hundred bytes
    /// on every platform this runs on, and a temp directory has already spent
    /// most of them.
    fn a_socket(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("sp-{name}-{unique}"));
        std::fs::create_dir_all(&directory).unwrap();

        directory.join("s")
    }

    /// Bind one, and hand back the path the client will reach it on.
    fn bound(name: &str) -> (UnixListener, PathBuf) {
        let path = a_socket(name);
        let listener = UnixListener::bind(&path).unwrap();

        (listener, path)
    }

    /// A far end that accepts the connection and then says nothing at all.
    ///
    /// The case a deadline exists for, and the only one the transport cannot
    /// report on its own: a spaceport that is gone refuses the connection at
    /// once, while one that has wedged looks from here exactly like one that is
    /// thinking.
    ///
    /// The handle comes back so the test holds the listener — and the accepted
    /// connections — open for its whole length. Dropping either would turn the
    /// silence into a refusal and prove nothing about the clock.
    async fn a_silent_spaceport(name: &str) -> (PathBuf, JoinHandle<()>) {
        let (listener, path) = bound(name);
        let held = tokio::spawn(async move {
            let mut accepted = Vec::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                accepted.push(stream);
            }
        });

        (path, held)
    }

    /// A far end that takes `delay` to answer, and then answers `body` — an
    /// apply waiting on a container that is slow to become healthy.
    async fn a_spaceport_that_answers_after(
        name: &str,
        delay: Duration,
        body: &'static str,
    ) -> (PathBuf, JoinHandle<()>) {
        let (listener, path) = bound(name);
        let held = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    // One read is the whole request here: every call under test
                    // sends a head and at most a few bytes of body, which
                    // arrive together.
                    let _ = stream.read(&mut [0_u8; 1024]).await;
                    tokio::time::sleep(delay).await;
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                                body.len(),
                            )
                            .as_bytes(),
                        )
                        .await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        (path, held)
    }

    /// A far end that answers `/events` and then streams nothing: an idle
    /// spaceport, which sends no keep-alive and so is byte for byte
    /// indistinguishable on the wire from one that has hung.
    async fn a_spaceport_that_streams_nothing(name: &str) -> (PathBuf, JoinHandle<()>) {
        let (listener, path) = bound(name);
        let held = tokio::spawn(async move {
            let mut accepted = Vec::new();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _ = stream.read(&mut [0_u8; 1024]).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n",
                    )
                    .await;
                // And not one byte more, for the rest of the test.
                accepted.push(stream);
            }
        });

        (path, held)
    }

    /// The app every tracking here is about.
    fn an_app() -> AppId {
        "site".parse().unwrap()
    }

    /// THE REGRESSION GUARD, this side of the wire. A manifest path is a
    /// free-form string, and an unencoded `&` in one ends the parameter it is
    /// in and starts another — so `spaceport.yaml&deploy=true` used to arm the
    /// app for automatic deployment, and every push after it went to production
    /// without anybody asking. Nothing at the far end can catch that: `deploy`
    /// is a field the route really has.
    #[test]
    fn a_manifest_path_cannot_arm_the_app() {
        let uri = tracking_uri(
            &an_app(),
            "an-organisation/site",
            "spaceport-acme",
            Some("main"),
            Some("spaceport.yaml&deploy=true"),
            None,
        );

        assert_eq!(
            uri,
            "/apps/site/tracking?repository=an-organisation%2Fsite&connection=spaceport-acme\
             &branch=main&manifest_path=spaceport.yaml%26deploy%3Dtrue"
        );
        // Said the other way round, in the terms the finding was in: there is
        // no such parameter, at any value.
        assert!(!uri.contains("&deploy="), "{uri}");
    }

    /// The same trick through each of the other three, since all four are
    /// strings an operator typed and only one of them was reported.
    #[test]
    fn no_argument_of_a_tracking_can_write_a_parameter_of_its_own() {
        for hostile in [
            "an-organisation/site&deploy=true",
            "spaceport-acme&deploy=true",
        ] {
            let uri = tracking_uri(
                &an_app(),
                hostile,
                hostile,
                Some(hostile),
                Some(hostile),
                None,
            );

            assert!(!uri.contains("&deploy="), "{uri}");
            // Four parameters went in and four came out: the `&`s in the uri
            // are the ones this built, not ones a value smuggled in.
            assert_eq!(uri.matches('&').count(), 3, "{uri}");
        }
    }

    /// A branch may hold any of these, and git will not stop anybody. What
    /// travels has to be the branch that was typed rather than a request that
    /// happens to parse.
    #[test]
    fn a_branch_survives_every_character_a_uri_reserves() {
        let uri = tracking_uri(
            &an_app(),
            "an-organisation/site",
            "spaceport-acme",
            Some("feature/a&b#c%d e+f"),
            None,
            None,
        );

        assert!(
            uri.ends_with("&branch=feature%2Fa%26b%23c%25d%20e%2Bf"),
            "{uri}"
        );
    }

    /// The three answers, still three. An encoder that also had opinions about
    /// absence would be the same bug pointing the other way: a re-track that
    /// only corrected a manifest path must not disarm an app.
    #[test]
    fn the_switch_is_mentioned_only_when_the_caller_answered() {
        let tracking = |deploy| {
            tracking_uri(
                &an_app(),
                "an-organisation/site",
                "spaceport-acme",
                None,
                None,
                deploy,
            )
        };

        assert!(!tracking(None).contains("deploy"), "{}", tracking(None));
        assert!(tracking(Some(true)).ends_with("&deploy=true"));
        assert!(tracking(Some(false)).ends_with("&deploy=false"));
    }

    /// The stream's query is built by one closure over every filter, which is
    /// the sort of place that is worth encoding whether or not today's callers
    /// need it to.
    #[test]
    fn a_watch_encodes_what_it_asks_for() {
        let watch = Watch {
            app: Some("*".parse().unwrap()),
            history: 20,
            ..Watch::default()
        };

        assert_eq!(watch.query(), "?app=%2A&history=20");
    }

    /// A path nothing has ever bound, for the tests that only ask what a
    /// deadline works out to and never connect.
    fn nowhere() -> PathBuf {
        PathBuf::from("/nonexistent/spaceport.sock")
    }

    #[test]
    fn a_quick_call_waits_exactly_what_the_operator_asked_for() {
        let operator = operator_on(nowhere(), Duration::from_secs(30));

        assert_eq!(Pace::Quick.deadline(&operator), Duration::from_secs(30));
    }

    #[test]
    fn a_patient_call_waits_ten_times_it() {
        let operator = operator_on(nowhere(), Duration::from_secs(30));

        assert_eq!(Pace::Patient.deadline(&operator), Duration::from_secs(300));
    }

    /// The escape hatch has to survive the multiplication, or the operator who
    /// asked for no deadline would get one on every patient command.
    #[test]
    fn neither_pace_invents_a_deadline_for_an_operator_who_asked_for_none() {
        let operator = operator_on(nowhere(), Duration::ZERO);

        assert_eq!(Pace::Quick.deadline(&operator), Duration::ZERO);
        assert_eq!(Pace::Patient.deadline(&operator), Duration::ZERO);
    }

    /// What comes back has to be something an operator can put straight back
    /// into `SPACEPORT_TIMEOUT`, which rules out `300s` and `Duration { .. }`
    /// alike.
    #[test]
    fn spells_a_deadline_the_way_an_operator_would_have_typed_it() {
        assert_eq!(spelled(DEFAULT_TIMEOUT), "30s");
        assert_eq!(spelled(DEFAULT_TIMEOUT * PATIENT_MULTIPLE), "5m");
        assert_eq!(spelled(Duration::from_millis(500)), "500ms");
        assert_eq!(spelled(Duration::from_secs(3600)), "1h");
        assert_eq!(spelled(Duration::from_millis(1500)), "1500ms");
    }

    /// The deadline names itself in the message, because the number in force is
    /// not always the number that was configured.
    #[test]
    fn says_what_to_set_when_nothing_came_back() {
        let message = no_answer_within(Duration::from_secs(300));

        assert!(message.contains("5m"), "{message}");
        assert!(message.contains("SPACEPORT_TIMEOUT"), "{message}");
    }

    #[tokio::test]
    async fn gives_up_on_a_spaceport_that_takes_the_request_and_never_answers() {
        let (path, _held) = a_silent_spaceport("silent").await;
        let operator = operator_on(path, Duration::from_millis(100));

        let started = Instant::now();
        let err = list(&operator, None).await.unwrap_err().to_string();
        let waited = started.elapsed();

        assert!(err.contains("SPACEPORT_TIMEOUT"), "{err}");
        assert!(err.contains("100ms"), "{err}");
        // The clock is what ended this, not the test being slow: the whole
        // budget was a tenth of a second, and anything near a second means
        // nothing was enforcing it.
        assert!(waited < Duration::from_millis(500), "waited {waited:?}");
    }

    /// A far end that stalls at every phase must not get the budget afresh at
    /// each one. This one answers the head promptly and then dribbles the body
    /// forever: connecting, the handshake and the head each cost a little, and
    /// if every phase started its own clock the call would outlive the number
    /// the operator set by a multiple of it.
    #[tokio::test]
    async fn spends_one_budget_across_the_whole_call_rather_than_one_per_phase() {
        let (listener, path) = bound("dribble");
        let _held = tokio::spawn(async move {
            let mut accepted = Vec::new();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _ = stream.read(&mut [0_u8; 1024]).await;
                // Most of the budget spent before the head, so that a clock
                // starting again for the body would be visibly generous. Then a
                // head promising a body that never comes.
                tokio::time::sleep(Duration::from_millis(160)).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n")
                    .await;
                accepted.push(stream);
            }
        });

        let operator = operator_on(path, Duration::from_millis(200));

        let started = Instant::now();
        let err = list(&operator, None).await.unwrap_err().to_string();
        let waited = started.elapsed();

        assert!(err.contains("SPACEPORT_TIMEOUT"), "{err}");
        // One budget ends this at ~200ms. A clock restarting for the body would
        // spend 160ms reaching the head and then grant a further 200ms — ~360ms
        // — so the bound has to sit between the two rather than merely under
        // the sum.
        assert!(waited < Duration::from_millis(280), "waited {waited:?}");
    }

    /// THE REGRESSION GUARD. `/events` sends nothing while nothing is
    /// happening, so a spaceport that is working perfectly and one that has
    /// hung look identical from here — and only one of them should be hung up
    /// on. Anybody who later puts a uniform deadline over the frame loop breaks
    /// this test, which is the entire reason it exists.
    #[tokio::test]
    async fn a_stream_keeps_waiting_long_after_a_command_would_have_given_up() {
        let (path, _held) = a_spaceport_that_streams_nothing("quiet").await;
        let operator = operator_on(path, Duration::from_millis(50));

        let watching = tokio::time::timeout(
            Duration::from_millis(300),
            stream(&operator, &Watch::default(), |_| {
                unreachable!("the far end sent no events")
            }),
        )
        .await;

        let Err(_still_waiting) = watching else {
            panic!("the stream returned instead of waiting on events that had not happened yet");
        };
    }

    /// The two tiers earning their keep: one server, one deadline, and the
    /// command that is doing work the operator is waiting on gets to finish.
    #[tokio::test]
    async fn a_patient_command_outlasts_what_a_quick_one_is_given() {
        let (path, _held) =
            a_spaceport_that_answers_after("slow", Duration::from_millis(200), "resumed").await;
        let operator = operator_on(path, Duration::from_millis(50));

        let quick = list(&operator, None).await;
        assert!(
            quick.is_err(),
            "fifty milliseconds should not have outlasted an answer two hundred away",
        );

        let patient = resume(&operator, &"web".parse().unwrap()).await.unwrap();
        assert_eq!(patient, "resumed");
    }

    /// The operator who knows their apply takes an hour, and would rather watch
    /// it than argue with a clock.
    #[tokio::test]
    async fn a_deadline_of_zero_waits_for_however_long_it_takes() {
        let (path, _held) = a_silent_spaceport("patient").await;
        let operator = operator_on(path, Duration::ZERO);

        let waiting = tokio::time::timeout(Duration::from_millis(300), list(&operator, None)).await;

        let Err(_still_waiting) = waiting else {
            panic!("a command with no deadline should not have given up on a silent spaceport");
        };
    }
}

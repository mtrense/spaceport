//! The operator interface's server side.
//!
//! Plain HTTP over whichever endpoint was configured, so the client is a few
//! lines of hyper and anything else that can speak to a socket — `curl
//! --unix-socket` included — can drive spaceport too. Bodies are the manifest
//! files themselves, verbatim; responses are plain text meant to be read by a
//! person, because that is who is running the command.

use std::convert::Infallible;
use std::path::{Component, Path};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Body;
use axum::extract::{FromRef, Path as UrlPath, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use bytes::Bytes;
use futures_util::StreamExt;
use http::StatusCode;
use serde::Deserialize;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::{OperatorEndpoint, SecretOutcome, SecretSet};
use crate::app::apply::{Applied, Applier, ApplyError, DestroyError, ResumeError, SuspendError};
use crate::app::manifest::VarName;
use crate::app::secrets::Set;
use crate::app::{App, AppId, AppManifest, AppRecord, AppRepository, DataDir, Pattern, health};
use crate::auth::{
    AuthLogRepository, EntitlementError, EntitlementRepository, Granted, JwtSigner, RevokeScope,
    Revoked, Role, RoleAtApp, SessionError, SessionId, SessionRepository, UserError, UserId,
    UserRecord, UserRef, UserRepository,
};
use crate::build::repository::{Build, BuildRepository, BuildState};
use crate::connections::github::{
    Client, ConnectionRepository, Installation, Nudge, Registration, Tracking, TrackingRepository,
    Transport, manifest, register,
};
use crate::events::{Event, EventBus, EventFilter, Level};
use crate::runtime::Adopted;
use crate::secret::Secret;
use crate::status::Instance;

/// Only the owner may talk to the socket: reaching it is the right to start
/// containers on this host.
#[cfg(unix)]
const SOCKET_MODE: u32 = 0o600;

/// Serve the operator interface until `shutdown` is cancelled.
pub async fn serve(
    endpoint: &OperatorEndpoint,
    instance: Arc<Instance>,
    events: Arc<EventBus>,
    shutdown: CancellationToken,
) -> Result<()> {
    let router = router(instance, events, shutdown.clone());

    match endpoint {
        OperatorEndpoint::Tcp(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding the operator interface to {addr}"))?;
            info!(%endpoint, "operator interface listening");

            run(listener, router, shutdown).await
        }
        OperatorEndpoint::Unix(path) => {
            let listener = bind_socket(path)?;
            info!(%endpoint, "operator interface listening");

            let result = run(listener, router, shutdown).await;
            // The socket file outlives the process that bound it, and a stale
            // one is indistinguishable from a live one to anything that tries
            // to connect.
            if let Err(error) = std::fs::remove_file(path) {
                warn!(path = %path.display(), %error, "could not remove the operator socket");
            }

            result
        }
    }
}

/// Bind a unix socket, clearing a socket left behind by a previous run.
#[cfg(unix)]
fn bind_socket(path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    // Only ever unlink a socket. Pointing `--operator` at a real file is a
    // mistake, and deleting it would be a worse one.
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path).with_context(|| {
                format!("removing the stale operator socket `{}`", path.display())
            })?;
        }
        Ok(_) => anyhow::bail!(
            "`{}` exists and is not a socket, so spaceport will not replace it",
            path.display()
        ),
        Err(_) => {}
    }

    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding the operator interface to `{}`", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))
        .with_context(|| format!("restricting access to `{}`", path.display()))?;

    Ok(listener)
}

async fn run<L>(listener: L, router: Router, shutdown: CancellationToken) -> Result<()>
where
    L: axum::serve::Listener,
    L::Addr: std::fmt::Debug,
{
    axum::serve(listener, router)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .context("serving the operator interface")?;

    info!("operator interface stopped");

    Ok(())
}

fn router(instance: Arc<Instance>, events: Arc<EventBus>, shutdown: CancellationToken) -> Router {
    Router::new()
        .route("/apps", get(list))
        .route("/apps/{id}", get(show).put(apply).delete(destroy))
        .route("/apps/{id}/deployment", post(deploy))
        .route("/apps/{id}/tracking", put(track))
        .route("/apps/{id}/suspend", post(suspend))
        .route("/apps/{id}/resume", post(resume))
        .route("/apps/{id}/secrets", get(secrets))
        .route(
            "/apps/{id}/secrets/{name}",
            put(set_secret).delete(delete_secret),
        )
        .route("/auth/users", get(list_users))
        .route("/auth/users/{user}", put(create_user).delete(drop_user))
        .route("/auth/users/{user}/suspend", post(suspend_user))
        .route("/auth/users/{user}/resume", post(resume_user))
        .route("/auth/users/{user}/audit", get(audit_user))
        .route(
            "/auth/users/{user}/sessions",
            get(list_sessions)
                .post(mint_session)
                .delete(drop_all_sessions),
        )
        .route(
            "/auth/users/{user}/sessions/{session}",
            delete(drop_session),
        )
        .route("/auth/users/{user}/api-keys/{grants}", post(mint_api_key))
        .route(
            "/auth/users/{user}/entitlements",
            delete(revoke_all_entitlements),
        )
        .route(
            "/auth/users/{user}/entitlements/{scope}",
            put(grant_entitlement).delete(revoke_entitlement),
        )
        .route("/auth/keys", get(list_signing_keys))
        .route("/auth/keys/rotate", post(rotate_signing_key))
        .route("/auth/log", get(auth_log))
        .route("/connections", get(connections))
        .route("/connections/github", post(connect_github))
        .route("/connections/github/register", post(register_github))
        .route(
            "/connections/{slug}",
            get(connection).delete(forget_connection),
        )
        .route("/events", get(events_stream))
        .route("/status", get(status))
        .with_state(Operator {
            instance,
            events,
            shutdown,
        })
}

/// What the handlers work from. Each of them extracts the one part it needs,
/// so a handler that only applies apps never learns that there is an event bus
/// or a config file anywhere near it.
#[derive(Clone)]
struct Operator {
    instance: Arc<Instance>,
    events: Arc<EventBus>,
    shutdown: CancellationToken,
}

impl FromRef<Operator> for Arc<Applier> {
    fn from_ref(operator: &Operator) -> Self {
        operator.instance.applier.clone()
    }
}

impl FromRef<Operator> for Arc<Instance> {
    fn from_ref(operator: &Operator) -> Self {
        operator.instance.clone()
    }
}

impl FromRef<Operator> for Arc<ConnectionRepository> {
    fn from_ref(operator: &Operator) -> Self {
        operator.instance.connections.clone()
    }
}

/// So the handler that points an app at a repository can extract the store with
/// `State` and never learn that there is an instance around it.
impl FromRef<Operator> for Arc<TrackingRepository> {
    fn from_ref(operator: &Operator) -> Self {
        operator.instance.tracking.clone()
    }
}

/// The same, for the handlers that report what became of a tracked revision and
/// the one that forgets it.
impl FromRef<Operator> for Arc<BuildRepository> {
    fn from_ref(operator: &Operator) -> Self {
        operator.instance.builds.clone()
    }
}

/// The same, for the handlers that manage the user pool.
impl FromRef<Operator> for Arc<UserRepository> {
    fn from_ref(operator: &Operator) -> Self {
        operator.instance.users.clone()
    }
}

/// And for the one that reads the auth event log back.
impl FromRef<Operator> for Arc<AuthLogRepository> {
    fn from_ref(operator: &Operator) -> Self {
        operator.instance.auth_log.clone()
    }
}

/// And for the handlers that grant, revoke and audit entitlements.
impl FromRef<Operator> for Arc<EntitlementRepository> {
    fn from_ref(operator: &Operator) -> Self {
        operator.instance.entitlements.clone()
    }
}

/// And for the handlers that mint, list and drop sessions.
impl FromRef<Operator> for Arc<SessionRepository> {
    fn from_ref(operator: &Operator) -> Self {
        operator.instance.sessions.clone()
    }
}

/// And for the two that rotate and list the JWT signing keys.
impl FromRef<Operator> for Arc<JwtSigner> {
    fn from_ref(operator: &Operator) -> Self {
        operator.instance.signer.clone()
    }
}

impl FromRef<Operator> for Arc<dyn Transport> {
    fn from_ref(operator: &Operator) -> Self {
        operator.instance.github.clone()
    }
}

impl FromRef<Operator> for Nudge {
    fn from_ref(operator: &Operator) -> Self {
        operator.instance.nudge.clone()
    }
}

/// The shove that tells the build worker to go and look, told apart from the
/// reconciler's by its type and by nothing else.
///
/// Both are a [`Nudge`], and a handler extracting one by that type alone would
/// get whichever the state happened to offer. They are emphatically not
/// interchangeable: waking the reconciler is a GitHub round trip per
/// connection, which is the amplification `connections::github::webhook`
/// refuses to build, and waking the builder is two queries against a local
/// database. A newtype is what makes asking for the wrong one impossible rather
/// than merely unlikely.
#[derive(Clone)]
struct Building(Nudge);

impl FromRef<Operator> for Building {
    fn from_ref(operator: &Operator) -> Self {
        Self(operator.instance.building.clone())
    }
}

/// The shove that tells the deploying worker to go and look, told apart from
/// the other two the same way and for the same reason.
///
/// Waking it is one query for the armed trackings and one per armed app, all
/// local — the cheapest of the three, and the one an operator is waiting on:
/// see [`crate::status::Instance::deploying`] for what makes a handler here the
/// thing that has to say so.
#[derive(Clone)]
struct Deploying(Nudge);

impl FromRef<Operator> for Deploying {
    fn from_ref(operator: &Operator) -> Self {
        Self(operator.instance.deploying.clone())
    }
}

impl FromRef<Operator> for Arc<EventBus> {
    fn from_ref(operator: &Operator) -> Self {
        operator.events.clone()
    }
}

impl FromRef<Operator> for CancellationToken {
    fn from_ref(operator: &Operator) -> Self {
        operator.shutdown.clone()
    }
}

/// `GET /events?app=&category=&level=&history=`: what spaceport is doing, as
/// it does it.
///
/// One JSON object per line, and the response never ends on its own — a
/// watcher stays connected until it or spaceport goes away. Filtering happens
/// here rather than at the far end so that watching one app does not mean
/// shipping every event to a client that will discard nearly all of them.
///
/// "Spaceport goes away" has to end the stream from this side: a graceful
/// shutdown waits for the responses still in flight, and a stream that only
/// ends when the client hangs up would hold the whole process open for as long
/// as somebody is watching it.
async fn events_stream(
    State(events): State<Arc<EventBus>>,
    State(shutdown): State<CancellationToken>,
    Query(query): Query<EventQuery>,
) -> Response {
    let filter = match query.filter() {
        Ok(filter) => filter,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let (past, receiver) = events.watch(query.history.unwrap_or(0), &filter);

    let history = futures_util::stream::iter(
        past.into_iter()
            .map(|event| Ok::<Bytes, Infallible>(line(&event))),
    );
    let live = futures_util::stream::unfold(
        (receiver, filter, shutdown),
        |(mut receiver, filter, shutdown)| async {
            loop {
                let received = tokio::select! {
                    // Spaceport is stopping, so there is nothing more to
                    // report and nothing to wait for.
                    () = shutdown.cancelled() => return None,
                    received = receiver.recv() => received,
                };

                match received {
                    Ok(event) if filter.matches(&event) => {
                        return Some((Ok(line(&event)), (receiver, filter, shutdown)));
                    }
                    // Not for this watcher; wait for one that is.
                    Ok(_) => {}
                    // A watcher too slow to keep up is told so in the stream
                    // itself, which is the only place it would notice.
                    Err(RecvError::Lagged(missed)) => {
                        let event = Event::now(
                            Level::Warn,
                            "stream",
                            format!("dropped {missed} events this client could not keep up with"),
                        );

                        return Some((Ok(line(&event)), (receiver, filter, shutdown)));
                    }
                    Err(RecvError::Closed) => return None,
                }
            }
        },
    );

    Response::builder()
        .header(http::header::CONTENT_TYPE, "application/x-ndjson")
        // Nothing between here and the client should be holding lines back
        // waiting for a buffer to fill.
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(history.chain(live)))
        .expect("a response with a valid content type")
}

/// One event as a line of NDJSON.
fn line(event: &Event) -> Bytes {
    // An event that will not serialise is a bug in the event, not a reason to
    // break the stream carrying it.
    let mut line = serde_json::to_string(event)
        .unwrap_or_else(|error| format!(r#"{{"message":"unserialisable event: {error}"}}"#));
    line.push('\n');

    Bytes::from(line)
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    app: Option<String>,
    category: Option<String>,
    level: Option<String>,
    /// How many events from before the watcher arrived to send first.
    history: Option<usize>,
}

impl EventQuery {
    fn filter(&self) -> Result<EventFilter> {
        Ok(EventFilter {
            app: self
                .app
                .as_deref()
                .map(str::parse::<Pattern>)
                .transpose()
                .context("the `app` filter")?,
            category: self
                .category
                .as_deref()
                .map(str::parse::<crate::events::Category>)
                .transpose()
                .context("the `category` filter")?,
            level: self
                .level
                .as_deref()
                .map(str::parse::<Level>)
                .transpose()
                .context("the `level` filter")?,
        })
    }
}

/// `GET /apps?pattern=…`: what is running, as a table.
///
/// An app that is only tracked is listed with the rest, under a status of its
/// own. Leaving it out would mean `spaceport apps track` accepting a name and
/// this then denying there is an app by it — and the name is the one thing an
/// operator has to go on until a manifest arrives.
async fn list(State(instance): State<Arc<Instance>>, Query(query): Query<ListQuery>) -> Response {
    let pattern = match query
        .pattern
        .as_deref()
        .map(str::parse::<Pattern>)
        .transpose()
    {
        Ok(pattern) => pattern,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let matches = |id: &AppId| pattern.as_ref().is_none_or(|p| p.matches(id));
    let store = instance.applier.store();
    let running: Vec<_> = store
        .apps()
        .into_iter()
        .filter(|app| matches(&app.id))
        .collect();
    let suspended: Vec<_> = store
        .suspended_apps()
        .into_iter()
        .filter(|app| matches(&app.id))
        .collect();

    // Suspended apps are listed with the rest, in with them rather than after:
    // an operator asking what spaceport has wants the whole answer, and the
    // status column is where the difference belongs.
    let mut rows: Vec<Listed> = running
        .iter()
        .zip(statuses(&running).await)
        .map(|(app, status)| Listed {
            id: app.id.clone(),
            source: app.manifest.source.to_string(),
            status,
            hosts: app.hosts().to_vec(),
        })
        .chain(suspended.iter().map(|app| Listed {
            id: app.id.clone(),
            source: app.manifest.source.to_string(),
            status: "suspended",
            hosts: app.hosts().to_vec(),
        }))
        .collect();
    rows.extend(tracked_only(&instance, &matches).await);

    if rows.is_empty() {
        let body = match &pattern {
            Some(pattern) => format!("no app matches `{pattern}`\n"),
            None => "no apps are running\n".to_owned(),
        };

        return (StatusCode::OK, body).into_response();
    }

    rows.sort_by(|a, b| a.id.cmp(&b.id));

    (StatusCode::OK, table(&rows)).into_response()
}

/// The apps that are tracked and have no manifest applied, as listing lines.
///
/// The repository stands in for the source, because it is where the source will
/// come from and there is nothing else to name: no image was chosen here. There
/// are no hosts either — those are in a manifest nobody has applied, so the
/// column is empty rather than guessed at.
///
/// A store that will not answer costs these apps their lines rather than the
/// whole listing: the apps that *are* running are the ones an operator is most
/// often asking after, and half a table beats a refusal.
async fn tracked_only(instance: &Instance, matches: &impl Fn(&AppId) -> bool) -> Vec<Listed> {
    let mut listed = Vec::new();

    for tracking in instance.tracking.all().await.unwrap_or_default() {
        // A read that fails is taken as the app having a manifest, which is the
        // safer way to be wrong: it leaves a line out of the table rather than
        // printing the same app twice.
        if !matches(&tracking.app) || holds(instance, &tracking.app).await.unwrap_or(true) {
            continue;
        }

        listed.push(Listed {
            id: tracking.app,
            source: format!("repository {}@{}", tracking.repository, tracking.branch),
            status: TRACKED,
            hosts: Vec::new(),
        });
    }

    listed
}

/// What an app with a tracking and no manifest is called wherever a status is
/// printed.
///
/// A word of its own beside `ready`, `suspended` and `down`, because those are
/// all states of something spaceport is running and this is not one of them:
/// spaceport knows where the app's code is and has nothing to run.
const TRACKED: &str = "tracked";

/// `GET /apps/{id}?manifest=`: everything spaceport knows about one app.
///
/// The report is what an operator reads; `?manifest=true` is the document they
/// applied, byte for byte and on its own, so that
/// `spaceport apps show x --manifest > x.yaml` gives back a file
/// `spaceport apps apply` takes.
///
/// Answers for an app that is recorded but not in the routing table at all —
/// the one spaceport failed to bring back at startup — because that is exactly
/// the app somebody is asking about. And for one that is only tracked, whose
/// manifest is in a repository and has never been applied here: `track` took
/// that name, so this has to know it.
async fn show(
    State(instance): State<Arc<Instance>>,
    State(builds): State<Arc<BuildRepository>>,
    UrlPath(id): UrlPath<String>,
    Query(query): Query<ShowQuery>,
) -> Response {
    let id: AppId = match id.parse() {
        Ok(id) => id,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let store = instance.applier.store();
    let held = if let Some(app) = store.get(&id) {
        Held::Running(app)
    } else if let Some(suspended) = store.suspended(&id) {
        Held::Suspended(suspended)
    } else if let Some(downed) = store.downed(&id) {
        Held::Down(downed)
    } else {
        match AppRepository::new(instance.db.clone()).recorded(&id).await {
            Ok(Some(record)) => match AppManifest::parse(&record.manifest) {
                Ok(manifest) => Held::Recorded(manifest),
                // Recorded by a build that understood something this one does
                // not. The document is still the operator's, so it is handed
                // over rather than withheld — but nothing can be said about it.
                Err(error) => {
                    if query.manifest {
                        return manifest_response(&record.manifest);
                    }

                    return refuse(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!(
                            "app `{id}` is recorded, but this spaceport cannot read its manifest: {error:#}\nask for it with `--manifest` to see it as it was applied"
                        ),
                    );
                }
            },
            Ok(None) => {
                let Some(tracked) = tracked(&instance, &id).await else {
                    return refuse(StatusCode::NOT_FOUND, &format!("no app named `{id}`"));
                };

                // Asking for the manifest of an app that has none is answered
                // with where it is rather than with an empty document: the
                // file exists, and not on this host.
                if query.manifest {
                    return refuse(
                        StatusCode::NOT_FOUND,
                        &format!(
                            "app `{id}` has no manifest here — it tracks {}, where the manifest is {}",
                            tracked.tracking.repository, tracked.tracking.manifest_path,
                        ),
                    );
                }

                let built = built(&builds, &id).await;
                // Nothing is applied under this name, so nothing here was ever
                // deployed — but there may well be an image waiting, and this
                // report is where an operator would look for it.
                let deployment = deployment(&builds, &id, None).await;

                return (
                    StatusCode::OK,
                    tracked_report(
                        &id,
                        &Origin {
                            tracked: &tracked,
                            built: &built,
                            deployment: &deployment,
                        },
                    ),
                )
                    .into_response();
            }
            Err(error) => {
                return refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("could not read what is recorded for `{id}`: {error:#}"),
                );
            }
        }
    };

    if query.manifest {
        return manifest_response(held.manifest().source_text());
    }

    // Only for the timestamp and the revision: everything else is already in
    // hand, and an app that is running is worth reporting on even if the state
    // store has since become unreadable.
    let record = AppRepository::new(instance.db.clone())
        .recorded(&id)
        .await
        .ok()
        .flatten();
    let applied_at = record.as_ref().map(|record| record.applied_at.clone());

    let status = match &held {
        Held::Running(app) => statuses(std::slice::from_ref(app)).await[0].to_owned(),
        Held::Suspended(_) => "suspended".to_owned(),
        Held::Down(downed) => format!("down ({})", downed.reason),
        Held::Recorded(_) => "not running".to_owned(),
    };

    let tracked = tracked(&instance, &id).await;
    // Only asked for when there is a tracking, because the answer is only about
    // one: an app somebody applied an image to has no revision this could be
    // reporting on.
    let (built, deployment) = match &tracked {
        Some(_) => (
            built(&builds, &id).await,
            deployment(&builds, &id, record.and_then(|record| record.revision)).await,
        ),
        None => (Built::None, Deployment::default()),
    };
    let data = DataDir::new(instance.config.data.directory.clone());
    let origin = tracked.as_ref().map(|tracked| Origin {
        tracked,
        built: &built,
        deployment: &deployment,
    });
    // A read that fails costs the stanza its second half rather than the whole
    // report: an app that is running is worth reporting on whatever the secret
    // store has to say, and every declared name then reads as not set — which
    // is the safer way to be wrong here, because it is the answer that has an
    // operator go and look.
    let stored = instance
        .applier
        .secrets()
        .names(&id, None)
        .await
        .unwrap_or_default();

    (
        StatusCode::OK,
        report(
            &id,
            &held,
            &status,
            applied_at.as_deref(),
            &data,
            origin,
            &stored,
        ),
    )
        .into_response()
}

/// What an app tracks, with the connection named as an operator named it.
///
/// A tracking knows the numeric id of the GitHub App that reaches it, which is
/// the right key to hold and the wrong thing to print: the slug is what every
/// command takes and what `spaceport connect list` shows.
struct Tracked {
    tracking: Tracking,
    /// `None` for a connection that is no longer there — which nothing should be
    /// able to leave behind, since forgetting a connection forgets what it
    /// reached, and which is still worth reporting rather than hiding.
    connection: Option<String>,
}

/// Everything a report says about where an app came from: the repository its
/// code is in, what became of the last build, and which revision is running.
///
/// One subject and so one argument. The three stanzas are only ever present or
/// absent together — an app somebody applied an image to has none of them — and
/// each is nearly meaningless without the two beside it.
struct Origin<'a> {
    tracked: &'a Tracked,
    built: &'a Built,
    deployment: &'a Deployment,
}

/// Where the app's code lives, if an operator has said.
///
/// A read that fails is answered as tracking nothing rather than as no answer
/// at all: everything else about the app is still worth having, and a caller
/// that has nothing else has a 404 to fall back on.
async fn tracked(instance: &Instance, id: &AppId) -> Option<Tracked> {
    let tracking = instance.tracking.by_app(id).await.ok().flatten()?;
    let connection = instance
        .connections
        .by_app_id(tracking.github_app_id)
        .await
        .ok()
        .flatten()
        .map(|connection| connection.slug);

    Some(Tracked {
        tracking,
        connection,
    })
}

/// What became of the revision an app tracks.
///
/// Three answers rather than an `Option`, because the two empty ones mean quite
/// different things to the operator reading them: a tracking nothing has been
/// built from yet is an ordinary state on the way to the first build, and a
/// store that will not answer is a fault in this host that a report claiming
/// "nothing yet" would hide.
enum Built {
    /// The most recent build, whatever became of it.
    Latest(Box<Build>),
    /// Nothing has been asked for under this app.
    None,
    /// The builds could not be read, and why.
    Unreadable(String),
}

/// The last build of `id`, as much as the store will say about it.
async fn built(builds: &BuildRepository, id: &AppId) -> Built {
    match builds.latest(id).await {
        Ok(Some(build)) => Built::Latest(Box::new(build)),
        Ok(None) => Built::None,
        Err(error) => Built::Unreadable(format!("{error:#}")),
    }
}

/// What the app is running, against what it could be.
///
/// Two revisions and not one, because the interesting thing about either of
/// them is the other: an operator asking why their change is not live is asking
/// whether an image exists that nothing has deployed, and neither number
/// answers that alone.
#[derive(Default)]
struct Deployment {
    /// The revision the applied manifest was deployed from, for an app that was
    /// deployed rather than applied by hand.
    deployed: Option<String>,
    /// The newest revision there is an image for.
    built: Option<String>,
    /// Why the deployment of that newest revision failed, if one was tried and
    /// did not take.
    ///
    /// Off the same row as [`Deployment::built`], because the deployment that
    /// matters is the one an operator is waiting on. It has nowhere else to
    /// appear: the build stanza above says the image was made, which is true and
    /// is not the answer to why the app is still on the commit before.
    failed: Option<String>,
}

/// What is deployed against what is waiting, for one app's report.
///
/// A read that fails is answered as nothing waiting, on [`built`]'s reasoning:
/// the rest of the report is still worth having, and the build stanza above
/// this one has already said that the store would not answer.
async fn deployment(builds: &BuildRepository, id: &AppId, deployed: Option<String>) -> Deployment {
    let latest = builds.latest_built(id).await.ok().flatten();

    Deployment {
        deployed,
        built: latest.as_ref().map(|build| build.revision.clone()),
        failed: latest.and_then(|build| build.deploy_reason),
    }
}

/// The manifest verbatim, as the document it is.
fn manifest_response(manifest: &str) -> Response {
    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "application/yaml")],
        manifest.to_owned(),
    )
        .into_response()
}

/// Where `show` found the app, which is also what there is to say about it.
enum Held {
    Running(Arc<App>),
    Suspended(crate::app::Suspended),
    Down(crate::app::Downed),
    /// Recorded, and not in the routing table at all.
    Recorded(AppManifest),
}

impl Held {
    fn manifest(&self) -> &AppManifest {
        match self {
            Self::Running(app) => &app.manifest,
            Self::Suspended(suspended) => &suspended.manifest,
            Self::Down(downed) => &downed.manifest,
            Self::Recorded(manifest) => manifest,
        }
    }

    /// The container serving it, when there is one to name.
    fn container(&self) -> Option<String> {
        match self {
            Self::Running(app) => Some(app.container.to_string()),
            Self::Suspended(suspended) => match suspended.container.as_ref()? {
                Adopted::Running(container) => Some(container.id.to_string()),
                Adopted::Stopped(id) => Some(format!("{id} (stopped)")),
            },
            Self::Down(_) | Self::Recorded(_) => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ShowQuery {
    /// Send the manifest verbatim instead of a report.
    #[serde(default)]
    manifest: bool,
}

/// Everything known about one app, as labelled lines.
///
/// Laid out rather than tabulated: this is one app, and the fields it has are
/// worth naming. Sections an app does not use are left out entirely — an app
/// with no volumes should not have to read a line saying so.
// One more argument than is comfortable, and every one of them is a different
// store's answer about the same app. Bundling them would mean a struct whose
// only purpose is to be taken apart on the first line of this function.
#[allow(clippy::too_many_arguments)]
fn report(
    id: &AppId,
    held: &Held,
    status: &str,
    applied_at: Option<&str>,
    data: &DataDir,
    origin: Option<Origin<'_>>,
    // The names of the secrets this app has values for, which is the half of
    // the secrets stanza that is not in the manifest.
    stored: &[VarName],
) -> String {
    let manifest = held.manifest();
    let container = &manifest.container;
    let mut out = Report::default();

    out.field("app", id.to_string());
    out.field("status", status.to_owned());
    out.field("source", manifest.source.to_string());
    let hosts: Vec<&str> = manifest
        .routing
        .hosts
        .iter()
        .map(|host| host.as_str())
        .collect();
    out.field("hosts", hosts.join(", "));

    if let Held::Running(app) = held {
        out.field("upstream", app.upstream.to_string());
    }
    if let Some(container) = held.container() {
        out.field("container", container);
    }
    if let Some(applied_at) = applied_at {
        out.field("applied", applied_at.to_owned());
    }

    // The port as the manifest settled it. What the image exposes is the
    // engine's business, and an app that named no port is better described as
    // having named none than as having named whatever was found.
    match container.port {
        Some(port) => out.field("port", port.to_string()),
        None => out.field("port", "from the image".to_owned()),
    }

    out.field("readiness", probe(&container.health.readiness));
    out.field(
        "liveness",
        match &container.health.liveness {
            Some(liveness) => probe(liveness),
            None => "none — spaceport never restarts it for being unwell".to_owned(),
        },
    );

    for (index, volume) in container.volumes.iter().enumerate() {
        out.field(
            if index == 0 { "volumes" } else { "" },
            format!(
                "{} at {} ({}), kept in {}",
                volume.name,
                volume.mount.display(),
                if volume.read_only {
                    "read-only"
                } else {
                    "writable"
                },
                data.volume(id, &volume.name).display(),
            ),
        );
    }

    // Verbatim, placeholders and all: an env value is not resolved until the
    // container is created, and showing a resolved one would be showing
    // something that is not what was applied.
    for (index, (name, value)) in container.env.iter().enumerate() {
        out.field(
            if index == 0 { "env" } else { "" },
            format!("{name}={value}"),
        );
    }

    // The names and whether each has a value, and never a word about what the
    // value is. Both halves are needed to answer the question this stanza is
    // read for — "why is this app suspended?" — because a manifest that
    // declares three secrets and a store that holds two is exactly what that
    // looks like, and neither the document nor the listing says so alone.
    for (index, secret) in container.secrets.iter().enumerate() {
        out.field(
            if index == 0 { "secrets" } else { "" },
            match stored.contains(secret) {
                true => format!("{secret} (set)"),
                false => format!("{secret} (not set — the app stays suspended until it is)"),
            },
        );
    }

    // Where the code is, when an operator has said. An app that tracks nothing
    // gets no stanza at all, like every other section here: most apps are an
    // image somebody applied, and a line saying they track nothing would be a
    // line about a thing they are not doing.
    if let Some(origin) = origin {
        came_from(&mut out, id, &origin);
    }

    out.render()
}

/// The three stanzas about where an app came from, in the order they answer an
/// operator's questions: where the code is, what became of the last push, and
/// whether the app is running it.
fn came_from(out: &mut Report, id: &AppId, origin: &Origin<'_>) {
    tracks(out, origin.tracked);
    builds(out, origin.built);
    deploys(
        out,
        id,
        origin.deployment,
        origin.tracked.tracking.automatic,
    );
}

/// Everything known about an app that is only tracked.
///
/// Written apart from [`report`] rather than through it, because nearly every
/// line there is read off a manifest and this app has none: no source, no
/// hosts, no port and no probes. Reporting those as empty would describe a
/// container that does not exist, so what is said instead is the one thing that
/// is true — spaceport knows where the code is and has nothing to run.
fn tracked_report(id: &AppId, origin: &Origin<'_>) -> String {
    let mut out = Report::default();

    out.field("app", id.to_string());
    out.field("status", TRACKED.to_owned());
    came_from(&mut out, id, origin);
    out.field(
        "manifest",
        "none applied here yet — nothing runs, no hosts are claimed, and the edge routes nothing to it".to_owned(),
    );
    // The two ways out of this state, in the order an operator reaches them: a
    // tracked app is one whose manifest is in its repository, so deploying a
    // build is the ordinary answer and writing a manifest by hand is the other
    // one. The deploy stanza above has already named the revision if there is
    // one, so this says nothing about which. An armed app is on its way out of
    // this state without anybody typing, and telling its operator to type
    // something would have them race a worker for it.
    out.field(
        "",
        match origin.tracked.tracking.automatic {
            true => format!(
                "spaceport runs what a build produces as soon as there is one, manifest and all — or apply one of your own with `spaceport apps apply {id} …`"
            ),
            false => format!(
                "run what a build produced with `spaceport apps deploy {id}`, which applies the manifest the commit carried — or apply one of your own with `spaceport apps apply {id} …`"
            ),
        },
    );

    out.render()
}

/// The tracking stanza both reports carry.
fn tracks(out: &mut Report, tracked: &Tracked) {
    let tracking = &tracked.tracking;

    out.field(
        "tracks",
        format!("{} on {}", tracking.repository, tracking.branch),
    );
    out.field("", format!("  manifest {}", tracking.manifest_path));
    out.field(
        "",
        match &tracked.connection {
            Some(slug) => format!("  through the `{slug}` connection"),
            None => format!(
                "  through github app {}, which nothing is connected as any more",
                tracking.github_app_id
            ),
        },
    );
    // Only when there is one. An app pointed at a branch nothing has been taken
    // from yet is not an app at revision nothing.
    if let Some(revision) = &tracking.revision {
        out.field("", format!("  last saw {revision}"));
    }
    // Both ways round, unlike most of this report, which leaves out the
    // sections an app does not use. Whether a push reaches production on its
    // own is not a feature an app either has or does not — it is the answer to
    // "when I push this, what happens?", and an operator reading a stanza that
    // said nothing would have to go and find out which of the two it was.
    out.field(
        "",
        match tracking.automatic {
            true => "  deploys its own builds — a build that succeeds is run without being asked".to_owned(),
            false => "  deploys nothing on its own — a build that succeeds waits for `spaceport apps deploy`".to_owned(),
        },
    );
}

/// How many lines of a failed build's output the report prints.
///
/// The stored log is already only the tail of what the build printed, and
/// sixteen kilobytes of it is more than belongs in a report about one app. The
/// end is where a build stops, so the end is what is kept again here — enough
/// for the failing step and what led to it, which is what an operator reads.
const LOG_LINES: usize = 20;

/// What became of the tracked revision, under the stanza that named it.
///
/// The reason and the log are the whole point of this: a build that failed
/// hours ago on a host that has since restarted is answered for nowhere else,
/// and an operator who cannot read why is left rerunning a push to find out.
fn builds(out: &mut Report, built: &Built) {
    let build = match built {
        Built::Latest(build) => build,
        // An app pointed at a branch whose revision nothing has got to yet.
        // Said plainly, because an empty stanza would read as a build that
        // produced nothing.
        Built::None => {
            out.field(
                "build",
                "nothing built from this yet — a pass is due within minutes of the tracking or a push"
                    .to_owned(),
            );

            return;
        }
        Built::Unreadable(error) => {
            out.field("build", format!("could not be read: {error}"));

            return;
        }
    };

    out.field("build", format!("{} at {}", build.state, build.revision));

    if let Some(image) = &build.image_tag {
        out.field("", format!("  image {image}"));
    }
    if build.state != BuildState::Failed {
        return;
    }

    if let Some(reason) = &build.reason {
        out.field("", format!("  reason {reason}"));
    }
    if let Some(log) = &build.log {
        let lines: Vec<&str> = log.lines().collect();
        let from = lines.len().saturating_sub(LOG_LINES);

        out.field(
            "",
            match from {
                0 => "  it printed".to_owned(),
                _ => format!("  it printed, of which the last {LOG_LINES} lines"),
            },
        );
        for line in &lines[from..] {
            out.field("", format!("    {line}"));
        }
    }
}

/// Which revision the app is running, against the newest one it could be.
///
/// A stanza of its own under the build, because the build stanza answers "did
/// it build?" and this answers "is it live?" — and an operator watching a
/// change reach production is asking the second one. A build that says `built`
/// looks like an answer to it and is not: an image finishing is exactly the
/// moment at which the two numbers can part company, whether because nothing
/// has been asked to run it or because running it was tried and did not take.
///
/// Nothing at all when neither is known, like every other section here: an app
/// tracked a minute ago has nothing to say on this and should not be given a
/// line saying so.
fn deploys(out: &mut Report, id: &AppId, deployment: &Deployment, armed: bool) {
    match (&deployment.deployed, &deployment.built) {
        (Some(deployed), Some(built)) if deployed == built => out.field(
            "deployed",
            format!("{deployed}, which is the newest build there is"),
        ),
        (Some(deployed), Some(built)) => {
            out.field("deployed", deployed.clone());
            out.field(
                "",
                format!(
                    "  a newer build is waiting at {built} — {}",
                    waiting(id, armed)
                ),
            );
        }
        // A deployed revision whose build the store would not say anything
        // about. Worth reporting on its own: what is running is what was asked
        // for, and only the comparison is missing.
        (Some(deployed), None) => out.field("deployed", deployed.clone()),
        (None, Some(built)) => out.field(
            "deployed",
            format!(
                "nothing built here is running — {built} is waiting, {}",
                waiting(id, armed)
            ),
        ),
        (None, None) => {}
    }

    // The one thing `deploy_reason` is for. A build that succeeded and a
    // deployment that failed are two different sentences, and every other line
    // in this report tells the first story: the image exists, the app is on the
    // commit before, and nothing says why. Under the stanza rather than beside
    // it, because it is the second half of the line above — the newer build
    // that is waiting is waiting for this reason.
    if let (Some(built), Some(reason)) = (&deployment.built, &deployment.failed) {
        out.field("", format!("  deploying {built} failed: {reason}"));
        out.field(
            "",
            format!(
                "  it is not deployed again on its own — push over it, or ask for it by name with `spaceport apps deploy {id} --revision {built}`"
            ),
        );
    }
}

/// What to do about an image nothing is running, in the voice the app's own
/// switch calls for.
///
/// An armed app has already been told to run this one, so naming the command
/// again would be telling an operator to do spaceport's job. What is worth
/// saying instead is that a build still waiting is a symptom rather than the
/// ordinary state: either the pass that runs it has not come round yet, which
/// is minutes, or it came round and the deployment failed — and the line under
/// this one then says so.
fn waiting(id: &AppId, armed: bool) -> String {
    match armed {
        true => "which this app deploys on its own, so it is either about to run or the line below says why it did not".to_owned(),
        false => format!("run it with `spaceport apps deploy {id}`"),
    }
}

/// One probe in a line.
fn probe(probe: &crate::app::manifest::Probe) -> String {
    use crate::app::manifest::Check;

    let what = match probe.kind {
        Check::None => return "none".to_owned(),
        Check::Tcp => "tcp connect".to_owned(),
        Check::Http => format!("http {}", probe.path.as_deref().unwrap_or("/")),
    };

    format!(
        "{what} every {:?}, {} failures to give up, {:?} timeout",
        probe.interval, probe.failure_threshold, probe.timeout
    )
}

/// Label-and-value lines, with the labels padded to line the values up.
#[derive(Default)]
struct Report {
    fields: Vec<(String, String)>,
}

impl Report {
    fn field(&mut self, label: &str, value: String) {
        self.fields.push((label.to_owned(), value));
    }

    fn render(&self) -> String {
        let width = self
            .fields
            .iter()
            .map(|(label, _)| label.len())
            .max()
            .unwrap_or(0);

        let mut out = String::new();
        for (label, value) in &self.fields {
            out.push_str(label);
            out.push_str(&" ".repeat(width - label.len()));
            out.push_str("  ");
            out.push_str(value);
            out.push('\n');
        }

        out
    }
}

/// One line of what `spaceport apps list` prints.
struct Listed {
    id: AppId,
    source: String,
    status: &'static str,
    hosts: Vec<crate::app::manifest::Host>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    pattern: Option<String>,
}

/// `GET /status`: what this spaceport is, as JSON.
///
/// JSON where the app routes answer in prose, because this is the one response
/// whose rendering depends on who is reading it: `spaceport status` lays it out
/// and colours it for a terminal, `--json` hands it straight on, and a script
/// with `curl` gets something it can read either way.
async fn status(State(instance): State<Arc<Instance>>) -> Response {
    let status = instance.snapshot().await;

    match serde_json::to_vec(&status) {
        Ok(body) => (
            StatusCode::OK,
            [(http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        // Nothing in a status can fail to serialise, and if one ever does the
        // operator should hear about it rather than get half a report.
        Err(error) => {
            warn!(%error, "could not serialise the status");
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not serialise the status: {error}"),
            )
        }
    }
}

/// Where each app stands right now, in the order it was given.
async fn statuses(apps: &[Arc<App>]) -> Vec<&'static str> {
    health::probe_all(apps)
        .await
        .into_iter()
        .map(|ready| if ready { "ready" } else { "unreachable" })
        .collect()
}

/// Render the apps as columns, wide enough for what is in them.
fn table(apps: &[Listed]) -> String {
    let rows: Vec<Vec<String>> = apps
        .iter()
        .map(|app| {
            let hosts: Vec<&str> = app.hosts.iter().map(|host| host.as_str()).collect();

            vec![
                app.id.to_string(),
                app.source.clone(),
                app.status.to_owned(),
                hosts.join(", "),
            ]
        })
        .collect();

    columns(&["APP", "SOURCE", "STATUS", "HOSTS"], &rows)
}

/// A header row and its rows, each column as wide as the widest thing in it.
fn columns(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }

    let header: Vec<String> = headers.iter().map(|header| (*header).to_owned()).collect();
    let mut out = String::new();
    for row in std::iter::once(&header).chain(rows) {
        let mut line = String::new();
        for (cell, width) in row.iter().zip(&widths) {
            // The last column is not padded: trailing spaces would be the only
            // thing past the end of it.
            if !line.is_empty() {
                line.push_str("  ");
            }
            line.push_str(cell);
            line.push_str(&" ".repeat(width - cell.len()));
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }

    out
}

/// `DELETE /apps/{id}`: stop the app and forget it.
///
/// The tracking goes with it. There is no `spaceport apps untrack`, so this is
/// the only way to undo a tracking — and one left behind would be spaceport
/// still watching a branch on behalf of an app that no longer exists, which
/// nothing would ever show anybody.
///
/// So do the builds, for the same reason and one more: a pending row is a piece
/// of work the queue would go on offering a worker, and it names an app there is
/// nothing left to build for. An app applied again under the name it had is a
/// fresh app, and it should not inherit the failures of the one before it.
///
/// So this succeeds for an app that is nothing *but* a tracking, too. A 404
/// there would leave the only record of it with no way to remove it.
async fn destroy(
    State(instance): State<Arc<Instance>>,
    State(builds): State<Arc<BuildRepository>>,
    UrlPath(id): UrlPath<String>,
) -> Response {
    let id: AppId = match id.parse() {
        Ok(id) => id,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    // Read before anything is removed, so the response can name the repository
    // the app has stopped tracking.
    let tracking = instance.tracking.by_app(&id).await.ok().flatten();

    match instance.applier.destroy(&id).await {
        Ok(app) => {
            let mut body = match app.container() {
                Some(container) => {
                    format!("app `{}` destroyed\n  container {container}\n", app.id())
                }
                None => format!("app `{}` destroyed\n  it had no container\n", app.id()),
            };
            body.push_str(&forgotten(&instance, &id, tracking.as_ref()).await);
            body.push_str(&unbuilt(&builds, &id).await);

            (StatusCode::OK, body).into_response()
        }
        // Nothing was applied under this name, and something is still tracked
        // under it: what there is to destroy is the tracking.
        Err(DestroyError::Unknown(_)) if tracking.is_some() => {
            let body = format!(
                "app `{id}` destroyed\n  it had no manifest applied, so nothing was running\n{}{}",
                forgotten(&instance, &id, tracking.as_ref()).await,
                unbuilt(&builds, &id).await,
            );

            (StatusCode::OK, body).into_response()
        }
        Err(error) => {
            let status = match error {
                DestroyError::Unknown(_) => StatusCode::NOT_FOUND,
                DestroyError::Failed(_) => {
                    warn!(%error, "destroy failed");
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            };

            refuse(status, &error.to_string())
        }
    }
}

/// Stop tracking anything for `id`, and say so in the words the response uses.
///
/// A store that will not answer is reported in the body and not as a failure:
/// the app is gone either way, and telling an operator the destroy failed would
/// be telling them to run a command that has nothing left to do.
async fn forgotten(instance: &Instance, id: &AppId, tracking: Option<&Tracking>) -> String {
    let Some(tracking) = tracking else {
        return String::new();
    };

    match instance.tracking.forget(id).await {
        Ok(_) => format!(
            "  it no longer tracks {} on {}\n",
            tracking.repository, tracking.branch
        ),
        Err(error) => {
            warn!(app = %id, %error, "could not forget what the app tracked");

            format!(
                "  it still tracks {} on {}, which could not be forgotten: {error:#}\n",
                tracking.repository, tracking.branch
            )
        }
    }
}

/// Forget every build recorded for `id`, and say so in the same words.
///
/// The same discipline [`forgotten`] applies, and for the same reason: a store
/// that will not answer is reported in the body and logged, never turned into a
/// failure. An app that had no builds says nothing at all — most apps are an
/// image somebody applied, and they were never built here.
async fn unbuilt(builds: &BuildRepository, id: &AppId) -> String {
    match builds.forget(id).await {
        Ok(0) => String::new(),
        Ok(1) => "  the build it had recorded is forgotten\n".to_owned(),
        Ok(forgotten) => format!("  the {forgotten} builds it had recorded are forgotten\n"),
        Err(error) => {
            warn!(app = %id, %error, "could not forget the builds of the app");

            format!("  its builds could not be forgotten: {error:#}\n")
        }
    }
}

/// `PUT /apps/{id}?suspended=` with a manifest as the body: run this, under
/// this name.
///
/// A `PUT` because that is what it does — the app named `id` ends up as the
/// body describes it, whether or not it was already running.
///
/// `suspended=true` records and claims without starting. So does applying to an
/// app that is already suspended, whatever the query says: see
/// [`Applier::apply`].
async fn apply(
    State(applier): State<Arc<Applier>>,
    UrlPath(id): UrlPath<String>,
    Query(query): Query<ApplyQuery>,
    body: String,
) -> Response {
    let id: AppId = match id.parse() {
        Ok(id) => id,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let manifest = match AppManifest::parse(&body) {
        Ok(manifest) => manifest,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    match applier.apply(id, manifest, query.suspended).await {
        Ok(Applied::Running(app)) => {
            let hosts: Vec<&str> = app.hosts().iter().map(|host| host.as_str()).collect();
            let body = format!(
                "app `{}` applied\n  container {}\n  upstream  {}\n  routes    {}\n",
                app.id,
                app.container,
                app.upstream,
                hosts.join(", "),
            );

            (StatusCode::OK, body).into_response()
        }
        Ok(Applied::Suspended(app)) => {
            let hosts: Vec<&str> = app.hosts().iter().map(|host| host.as_str()).collect();
            let body = format!(
                "app `{}` applied, suspended\n  claims  {}\n  resume it with `spaceport apps resume {}`\n",
                app.id,
                hosts.join(", "),
                app.id,
            );

            (StatusCode::OK, body).into_response()
        }
        Err(error) => {
            warn!(%error, "apply failed");
            let status = match error {
                // A conflict in the sense the status code means it: the app is
                // recorded, it is holding its hosts, and the state it is in is
                // not the one that was asked for. Not a 500, because nothing is
                // wrong with this host, and not a 422, because the document is
                // fine — what is missing is a value that is deliberately not in
                // it.
                ApplyError::Conflict(_) | ApplyError::MissingSecrets(_) => StatusCode::CONFLICT,
                ApplyError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };

            refuse(status, &error.to_string())
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct ApplyQuery {
    #[serde(default)]
    suspended: bool,
}

/// `POST /apps/{id}/deployment?revision=`: run what spaceport built.
///
/// A `POST` and a noun, where applying is a `PUT`, because the two say
/// different things about repetition. An apply is the app *being* the document
/// in the body, and running it twice leaves the same app; a deploy adds one
/// deployment to an app's history, and which revision it lands on is a decision
/// taken here and now out of what has been built since. The revision an
/// operator does not name is the newest image there is, and that is a different
/// answer this afternoon than it was this morning.
///
/// The manifest is the one the commit carried, taken off the build row rather
/// than fetched again: the checkout it was read from is swept once newer
/// revisions exist, and a deploy of a fortnight-old revision has to be able to
/// say what that commit asked for. So this never reads github, and works on a
/// host that cannot reach it at all.
///
/// Deploying to a suspended app records and claims without starting it, exactly
/// as applying to one does — the rule belongs to [`Applier::deploy`] and is not
/// restated here. Deciding what an app runs and deciding whether it is being
/// run stay two decisions.
///
/// However it goes, the revision is stamped as having had its deployment. An
/// operator's deploy and an armed app's are the same event to the row that
/// records it, and the alternative is the two of them disagreeing about whether
/// a revision has been tried.
async fn deploy(
    State(instance): State<Arc<Instance>>,
    State(applier): State<Arc<Applier>>,
    State(builds): State<Arc<BuildRepository>>,
    UrlPath(id): UrlPath<String>,
    Query(query): Query<DeployQuery>,
) -> Response {
    let id: AppId = match id.parse() {
        Ok(id) => id,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let build = match chosen(&builds, &instance, &id, query.revision.as_deref()).await {
        Ok(build) => build,
        Err(refusal) => return refusal,
    };

    // A row an earlier spaceport wrote, from before the manifest was kept. The
    // document is the whole of what there is to deploy, and there is nowhere
    // left to read it from — the commit's checkout is long swept — so this says
    // what will produce one rather than leaving an operator to work it out.
    let Some(document) = build
        .manifest
        .as_deref()
        .filter(|document| !document.trim().is_empty())
    else {
        return refuse(
            StatusCode::CONFLICT,
            &format!(
                "the build of revision `{}` of app `{id}` kept no manifest — it was built by a spaceport that did not record one, and the checkout it was read from is gone\n  push the branch again, and deploy the revision that builds from it",
                build.revision,
            ),
        );
    };

    let manifest = match AppManifest::parse(document) {
        Ok(manifest) => manifest,
        // The document is the repository's rather than the operator's, so the
        // sentence says where it came from: what has to change is a file in a
        // commit, not the command that was just typed.
        Err(error) => {
            return refuse(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!(
                    "the `{}` that revision `{}` of app `{id}` carried is one this spaceport cannot read: {error:#}",
                    build.manifest_path, build.revision,
                ),
            );
        }
    };

    // Checked here as well as in the applier, which refuses the same row for the
    // same reason: this is the only place that can name the image in the answer,
    // and an answer that named none would leave the operator asking what it is
    // now running.
    let Some(image) = build.image_tag.clone() else {
        return refuse(
            StatusCode::CONFLICT,
            &format!(
                "the build of revision `{}` of app `{id}` recorded no image to run\n  push the branch again, and deploy the revision that builds from it",
                build.revision,
            ),
        );
    };

    let outcome = applier
        .deploy(id.clone(), manifest, Some(&build.revision), false)
        .await;

    // Recorded either way, before a word of the response is written.
    //
    // On success, because otherwise the revision an operator has just put in
    // front of the traffic still reads as awaiting deployment, and the worker
    // behind an armed app would come along within minutes and deploy it again —
    // restarting a running app to arrive where it already is.
    //
    // On failure too, and that is the argued half. It looks redundant: this
    // operator is at a terminal, is being handed the reason in the response, and
    // is not the audience `deploy_reason` was written for. But the row is not a
    // message to them — it is what stops the deployment being *retried*, and an
    // armed app has a worker that would find this same revision built,
    // undeployed and newest, and take the app down with the exact failure a
    // person just watched. Leaving the column clear would mean a manual attempt
    // and an automatic one disagreeing about whether a revision has had its go.
    // The cost of writing it is that `spaceport apps deploy --revision` is the
    // way back to a revision recorded as failed, which is a command an operator
    // can type; the cost of not writing it is an outage on a timer.
    match &outcome {
        Ok(_) => {
            if let Err(error) = builds.deployed(&id, &build.revision).await {
                warn!(app = %id, %error, "could not record a deployment that worked");
            }
        }
        Err(error) => {
            if let Err(error) = builds
                .deploy_failed(&id, &build.revision, &error.to_string())
                .await
            {
                warn!(app = %id, %error, "could not record a deployment that failed");
            }
        }
    }

    match outcome {
        Ok(Applied::Running(app)) => {
            let hosts: Vec<&str> = app.hosts().iter().map(|host| host.as_str()).collect();
            let body = format!(
                "app `{}` is running revision {}\n  image     {image}\n  container {}\n  upstream  {}\n  routes    {}\n",
                app.id,
                build.revision,
                app.container,
                app.upstream,
                hosts.join(", "),
            );

            (StatusCode::OK, body).into_response()
        }
        Ok(Applied::Suspended(app)) => {
            let hosts: Vec<&str> = app.hosts().iter().map(|host| host.as_str()).collect();
            let body = format!(
                "app `{}` is deployed at revision {}, and still suspended\n  image  {image}\n  claims {}\n  resume it with `spaceport apps resume {}`\n",
                app.id,
                build.revision,
                hosts.join(", "),
                app.id,
            );

            (StatusCode::OK, body).into_response()
        }
        Err(error) => {
            warn!(%error, "deploy failed");
            let status = match error {
                // A conflict in the sense the status code means it: the app is
                // recorded, it is holding its hosts, and the state it is in is
                // not the one that was asked for. Not a 500, because nothing is
                // wrong with this host, and not a 422, because the document is
                // fine — what is missing is a value that is deliberately not in
                // it.
                ApplyError::Conflict(_) | ApplyError::MissingSecrets(_) => StatusCode::CONFLICT,
                ApplyError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };

            refuse(status, &error.to_string())
        }
    }
}

/// Which build a deploy is about, or the sentence saying why there is none.
///
/// Every path out of here that is not a build is a refusal an operator can act
/// on, which is the whole of what this is for: "not found" is true of an app
/// nobody tracks, of a commit still in the queue and of a build that failed an
/// hour ago, and those are three different mornings.
async fn chosen(
    builds: &BuildRepository,
    instance: &Instance,
    id: &AppId,
    revision: Option<&str>,
) -> Result<Build, Response> {
    match revision {
        Some(revision) => named(builds, instance, id, revision).await,
        None => newest(builds, instance, id).await,
    }
}

/// The newest image there is for the app.
async fn newest(
    builds: &BuildRepository,
    instance: &Instance,
    id: &AppId,
) -> Result<Build, Response> {
    match builds.latest_built(id).await {
        Ok(Some(build)) => Ok(build),
        Ok(None) => Err(nothing_built(builds, instance, id).await),
        Err(error) => Err(refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("could not read what has been built for `{id}`: {error:#}"),
        )),
    }
}

/// Why an app has no image at all, in the words its own state calls for.
///
/// An app that was never tracked and an app whose first build has not finished
/// are different mistakes: the first is missing a command nobody has run, the
/// second is missing a few minutes. Answering both with "nothing to deploy"
/// would send the second operator looking for a command they have already run.
async fn nothing_built(builds: &BuildRepository, instance: &Instance, id: &AppId) -> Response {
    let Some(tracked) = tracked(instance, id).await else {
        return refuse(
            StatusCode::NOT_FOUND,
            &format!(
                "app `{id}` has nothing to deploy — it tracks no repository, so spaceport has never built anything for it\n  point it at one with `spaceport apps track {id} <owner/name> --connection <slug>`"
            ),
        );
    };
    let tracking = &tracked.tracking;

    match builds.latest(id).await {
        // Something was asked for and did not become an image. Which of the
        // three that was is the answer, since a commit in the queue is waited
        // for and a failed one is pushed over.
        Ok(Some(build)) => refuse(
            StatusCode::CONFLICT,
            &format!(
                "app `{id}` has no finished build to deploy — the last one is {}\n  `spaceport apps show {id}` says what became of it",
                became_of(&build),
            ),
        ),
        Ok(None) => refuse(
            StatusCode::NOT_FOUND,
            &format!(
                "app `{id}` has nothing to deploy yet — it tracks {} on {}, and nothing has been built from it\n  a pass is due within minutes of a push, and `spaceport apps show {id}` says when one has run",
                tracking.repository, tracking.branch,
            ),
        ),
        Err(error) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("could not read what has been built for `{id}`: {error:#}"),
        ),
    }
}

/// The build of the revision an operator named.
///
/// An abbreviation is taken, and the check is the same read the refusals need
/// anyway: one query for the app's own rows, matched by prefix in memory. That
/// is what makes it cheap — an app has a handful of builds, not a repository's
/// worth of commits — and an abbreviation that names two of them is refused
/// rather than resolved, because deploying the wrong one of two commits is
/// exactly what the operator was hoping the sha would prevent.
///
/// The exact spelling wins over any prefix it is also a prefix of, so a
/// revision typed in full is never called ambiguous by a longer one.
async fn named(
    builds: &BuildRepository,
    instance: &Instance,
    id: &AppId,
    revision: &str,
) -> Result<Build, Response> {
    match builds.built(id, revision).await {
        Ok(Some(build)) => return Ok(build),
        Ok(None) => {}
        Err(error) => {
            return Err(refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not read the build of revision `{revision}` of `{id}`: {error:#}"),
            ));
        }
    }

    let recorded = match builds.by_app(id).await {
        Ok(recorded) => recorded,
        Err(error) => {
            return Err(refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not read what has been built for `{id}`: {error:#}"),
            ));
        }
    };

    let matching: Vec<&Build> = match recorded.iter().find(|build| build.revision == revision) {
        Some(exact) => vec![exact],
        None => recorded
            .iter()
            .filter(|build| build.revision.starts_with(revision))
            .collect(),
    };

    match matching.as_slice() {
        [] => Err(unrequested(instance, id, revision).await),
        [build] if build.state == BuildState::Built => Ok((*build).clone()),
        [build] => Err(refuse(
            StatusCode::CONFLICT,
            &format!(
                "app `{id}` cannot run revision `{revision}` — its build is {}\n  `spaceport apps show {id}` says what became of it",
                became_of(build),
            ),
        )),
        many => Err(refuse(
            StatusCode::BAD_REQUEST,
            &ambiguous(id, revision, many),
        )),
    }
}

/// A revision nothing was ever asked to build, said against what the app
/// tracks: a commit on another branch and a commit on a repository nobody
/// pointed the app at both arrive here, and neither is a typo the operator can
/// see on their own.
async fn unrequested(instance: &Instance, id: &AppId, revision: &str) -> Response {
    match tracked(instance, id).await {
        Some(tracked) => refuse(
            StatusCode::NOT_FOUND,
            &format!(
                "app `{id}` has no build of revision `{revision}` — it tracks {} on {}, and nothing has asked for that commit\n  `spaceport apps show {id}` says what has been built",
                tracked.tracking.repository, tracked.tracking.branch,
            ),
        ),
        None => refuse(
            StatusCode::NOT_FOUND,
            &format!(
                "app `{id}` has no build of revision `{revision}` — it tracks no repository, so spaceport has never built anything for it"
            ),
        ),
    }
}

/// What became of a build, as the clause a refusal is written around.
fn became_of(build: &Build) -> String {
    match build.state {
        BuildState::Pending => format!("waiting for a worker at {}", build.revision),
        BuildState::Building => format!("still being built at {}", build.revision),
        BuildState::Failed => match &build.reason {
            Some(reason) => format!("the failure at {}: {reason}", build.revision),
            None => format!("the failure at {}", build.revision),
        },
        // Never reached from either caller, both of which take a finished build
        // as their answer rather than as a refusal — and a sentence is a better
        // thing to leave here than a panic.
        BuildState::Built => format!("built at {}, with no image recorded", build.revision),
    }
}

/// An abbreviation that names more than one build, with every one it names.
///
/// All of them, not the first few: the operator is about to retype one, and the
/// list is what they are choosing from.
fn ambiguous(id: &AppId, revision: &str, matching: &[&Build]) -> String {
    let revisions: Vec<&str> = matching
        .iter()
        .map(|build| build.revision.as_str())
        .collect();

    format!(
        "`{revision}` names {} builds of app `{id}` — {} — so spaceport will not guess which\n  name the revision in full",
        matching.len(),
        revisions.join(", "),
    )
}

/// Which revision to run, and how much of it was typed.
///
/// `deny_unknown_fields` for the reason [`TrackQuery`] has it: an option that is
/// silently ignored is an operator deploying something other than what they
/// named.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeployQuery {
    /// The commit to run, in full or abbreviated to anything that names one
    /// build of this app. Without one, the newest image there is.
    revision: Option<String>,
}

/// `POST /apps/{id}/suspend?stop_container=`: stop serving the app, keep
/// everything about it.
async fn suspend(
    State(applier): State<Arc<Applier>>,
    UrlPath(id): UrlPath<String>,
    Query(query): Query<SuspendQuery>,
) -> Response {
    let id: AppId = match id.parse() {
        Ok(id) => id,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    match applier.suspend(&id, query.stop_container).await {
        Ok(()) => {
            let container = if query.stop_container {
                "  its container is stopped and kept\n"
            } else {
                "  its container is left running\n"
            };
            let body = format!(
                "app `{id}` suspended\n{container}  it still claims its hosts, and still renews their certificates\n"
            );

            (StatusCode::OK, body).into_response()
        }
        Err(error) => {
            let status = match error {
                SuspendError::Unknown(_) => StatusCode::NOT_FOUND,
                SuspendError::Failed(_) => {
                    warn!(%error, "suspend failed");
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            };

            refuse(status, &error.to_string())
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct SuspendQuery {
    #[serde(default)]
    stop_container: bool,
}

/// `POST /apps/{id}/resume`: serve the app again.
///
/// Resuming is also the moment a build that was already finished becomes
/// deployable: the deploying loop leaves a suspended app alone, deliberately,
/// so a push during a suspension ends as an image and a row saying nothing has
/// run it. Nothing builds when an app comes back, so nothing would wake that
/// loop — hence the shove below, which is what turns "up to five minutes" into
/// "as soon as this app is serving again".
async fn resume(
    State(applier): State<Arc<Applier>>,
    State(deploying): State<Deploying>,
    UrlPath(id): UrlPath<String>,
) -> Response {
    let id: AppId = match id.parse() {
        Ok(id) => id,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    match applier.resume(&id).await {
        Ok(app) => {
            // After the app is running and never before, which is the order the
            // builder shoves in and for its reason: the loop reads the store
            // and the record for itself, and a shove that arrived first would
            // send it to look at an app that is still suspended.
            deploying.0.nudge();

            let hosts: Vec<&str> = app.hosts().iter().map(|host| host.as_str()).collect();
            let body = format!(
                "app `{}` resumed\n  container {}\n  upstream  {}\n  routes    {}\n",
                app.id,
                app.container,
                app.upstream,
                hosts.join(", "),
            );

            (StatusCode::OK, body).into_response()
        }
        Err(error) => {
            warn!(%error, "resume failed");
            let status = match error {
                ResumeError::Unknown(_) => StatusCode::NOT_FOUND,
                // As for an apply: the app is still there, still suspended, and
                // still waiting for a value somebody has to set.
                ResumeError::Conflict(_) | ResumeError::MissingSecrets(_) => StatusCode::CONFLICT,
                ResumeError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };

            refuse(status, &error.to_string())
        }
    }
}

/// `GET /apps/{id}/secrets?pattern=…`: the names of the secrets set for an app,
/// one per line.
///
/// Names and nothing else, which is what the query behind it can answer — see
/// [`SecretRepository::names`], which never reads the value column. There is no
/// switch anywhere that turns values on: the only thing that reads them is the
/// code that renders a container's environment, and an operator who has
/// forgotten a password sets a new one.
///
/// Lines rather than a table, because this is the one listing something other
/// than a person reads: `for name in $(spaceport apps secret list web)` is the
/// shape of a rotation script, and a header would be its first secret.
///
/// An app nothing has heard of is answered with no names rather than a 404,
/// unlike the two routes below it. Nothing is being changed here, an app that
/// has no secrets and an app that does not exist have the same empty answer,
/// and a listing that refused would be refusing to say the true thing.
///
/// [`SecretRepository::names`]: crate::app::SecretRepository::names
async fn secrets(
    State(applier): State<Arc<Applier>>,
    UrlPath(id): UrlPath<String>,
    Query(query): Query<ListQuery>,
) -> Response {
    let id: AppId = match id.parse() {
        Ok(id) => id,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let pattern = match query
        .pattern
        .as_deref()
        .map(str::parse::<Pattern>)
        .transpose()
    {
        Ok(pattern) => pattern,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    match applier.secrets().names(&id, pattern.as_ref()).await {
        Ok(names) => {
            let body: String = names.iter().map(|name| format!("{name}\n")).collect();

            (StatusCode::OK, body).into_response()
        }
        Err(error) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("could not read the secrets of `{id}`: {error:#}"),
        ),
    }
}

/// `PUT /apps/{id}/secrets/{name}`: this is the value, and bring the app up to
/// date with it.
///
/// The value is the request body, verbatim, and that is the whole reason this
/// route is shaped the way it is. A value in the path or the query string is
/// written into the access log of anything between here and the caller, into
/// this process's own request logging the day somebody adds any, and into the
/// url of every error message that quotes it. A body is none of those places.
/// It is also the only shape that carries an arbitrary value: a secret is bytes
/// somebody generated, and `&`, `#` and `%` are three of them.
///
/// It still has to be text, because what it becomes is an environment variable
/// and an environment cannot hold a byte that is not one. A body that is not
/// UTF-8 is refused without a word of it being quoted back.
///
/// What happens after it is stored is the substantive part:
///
/// * a value identical to the one already there changes nothing and starts
///   nothing — see [`Set::Unchanged`], which exists for this;
/// * a value that changed, on an app that now has every secret its manifest
///   declares, brings the app up to date: a suspended one is resumed, and a
///   running one is redeployed, because a changed value is a changed container
///   fingerprint and the running container is carrying the old one;
/// * a value that changed, on an app still missing others, is stored and
///   reported — the app stays where it is, which is suspended;
/// * a value for an app with no manifest applied here is simply stored.
///   Setting the secrets before applying the manifest that needs them is the
///   right order to do it in, and refusing would make it impossible.
///
/// An app this spaceport has never heard of at all — no record, nothing in the
/// routing table, no tracking — is a 404. That is the difference between an
/// app whose manifest has not arrived yet and a typo, and only the second is
/// worth refusing.
///
/// An app something else is already working on is a 409, refused before the
/// value is written. A secret is set by somebody at a terminal, and the useful
/// answer for them is "not now, and nothing changed" — not a request that hangs
/// for the length of a deploy and then writes into a world that has moved.
async fn set_secret(
    State(instance): State<Arc<Instance>>,
    State(applier): State<Arc<Applier>>,
    State(deploying): State<Deploying>,
    UrlPath((id, name)): UrlPath<(String, String)>,
    body: Bytes,
) -> Response {
    let (id, name) = match about(&id, &name) {
        Ok(named) => named,
        Err(refusal) => return *refusal,
    };

    // Never quoted back, however wrong it is: the bytes of a value that failed
    // to decode are still the bytes of somebody's secret.
    let Ok(value) = std::str::from_utf8(&body) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "a secret's value is the body of the request, and this one is not valid utf-8 — a value has to be text, because what it becomes is an environment variable",
        );
    };
    let value = Secret::new(value);

    // Taken from before the app is looked up until after its value is written,
    // the way every verb on the applier takes it: this is the app being seen to,
    // and a `destroy` that ran alongside would be removing the app whose secret
    // this is writing.
    //
    // Immediately or not at all, and before the value is written. Somebody is
    // holding a terminal waiting for this, and an answer that says the app is
    // busy is worth more to them than a request that hangs for the length of a
    // deploy. Refusing *before* the write is the part that matters: a caller
    // who is told no has to be able to take it that nothing changed.
    let Some(working) = applier.try_working(&id) else {
        return refuse(
            StatusCode::CONFLICT,
            &format!(
                "app `{id}` is busy being worked on, so the secret `{name}` was not set — nothing was changed, try again once the app has settled"
            ),
        );
    };

    let record = match AppRepository::new(instance.db.clone()).recorded(&id).await {
        Ok(record) => record,
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not read what is recorded for `{id}`: {error:#}"),
            );
        }
    };
    if !known(&instance, &id, record.as_ref()).await {
        return refuse(StatusCode::NOT_FOUND, &format!("no app named `{id}`"));
    }

    let set = match applier.secrets().set(&id, &name, &value).await {
        Ok(set) => set,
        Err(error) => {
            warn!(app = %id, secret = %name, %error, "could not set an app secret");

            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not set the secret `{name}` of app `{id}`: {error:#}"),
            );
        }
    };

    // Asked again, after the write, because the check above and the write are
    // two awaits and a `destroy` used to fit between them: it removes the app
    // from the store, forgets its record, and only then forgets its secrets, so
    // a value written after that step is one nothing will ever remove. An app of
    // the same id applied tomorrow would inherit the credentials of the one
    // destroyed today, which is the outcome `Applier::destroy` forgets secrets
    // to prevent. Looking again strictly after the write closes it: either the
    // destroy's own forget runs later and takes this row with it, or it has
    // already run and the app is gone from everywhere this looks.
    //
    // The lock taken above now excludes that destroy outright, so this is a net
    // under a net. It stays: it costs one read, and the promise it keeps — that
    // no value outlives the app it was set for — should not rest on every future
    // path that forgets an app remembering to take the lock first.
    match AppRepository::new(instance.db.clone()).recorded(&id).await {
        Ok(still) if !known(&instance, &id, still.as_ref()).await => {
            if let Err(error) = applier.secrets().delete(&id, &name).await {
                warn!(app = %id, secret = %name, %error, "the app was destroyed while its secret was being set, and the value could not be removed");
            }

            return refuse(
                StatusCode::NOT_FOUND,
                &format!("no app named `{id}` — it was destroyed while this secret was being set"),
            );
        }
        Ok(_) => {}
        // A read that failed says nothing about whether the app is gone, and
        // dropping a value on the strength of it would throw away what an
        // operator has just set. This check is a net, not a gate.
        Err(error) => {
            warn!(app = %id, %error, "could not check that the app still exists after setting its secret");
        }
    }

    // Nothing observable changed, so nothing observable happens. This is the
    // whole reason `set` answers with three states rather than two: a rotation
    // script that re-sets what it set yesterday must not restart production.
    if set == Set::Unchanged {
        return answered(&SecretSet {
            created: false,
            outcome: SecretOutcome::Unchanged,
        });
    }

    let created = set == Set::Created;
    // Stored, and there is no manifest here to be brought up to date by it.
    let Some(record) = record else {
        return answered(&SecretSet {
            created,
            outcome: SecretOutcome::Stored,
        });
    };

    let manifest = match AppManifest::parse(&record.manifest) {
        Ok(manifest) => manifest,
        // Recorded by a build that understood something this one does not. The
        // value is stored either way — it is a row in a table, and nothing
        // about the manifest makes it less stored — so what is refused is only
        // the part this cannot do.
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "the secret `{name}` of app `{id}` is stored, but this spaceport cannot read the app's manifest, so it did not act on it: {error:#}"
                ),
            );
        }
    };

    let held = match applier.secrets().names(&id, None).await {
        Ok(held) => held,
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "the secret `{name}` of app `{id}` is stored, but the secrets of the app could not be read back, so it did not act on it: {error:#}"
                ),
            );
        }
    };

    // Asked of the store rather than of the manifest's resolved values, because
    // the manifest was just parsed out of a text column and carries none.
    let missing: Vec<String> = manifest
        .container
        .secrets
        .iter()
        .filter(|secret| !held.contains(secret))
        .map(ToString::to_string)
        .collect();
    if !missing.is_empty() {
        return answered(&SecretSet {
            created,
            outcome: SecretOutcome::Missing { secrets: missing },
        });
    }

    // A value nothing reads. The fingerprint a container is labelled with
    // covers the secrets the manifest *declares* — see `manifest::written` —
    // so this one has not changed what the running container should be, and
    // replacing it would be a restart of somebody's app for nothing. Checked
    // after the missing ones on purpose: an operator who typed `DB_PASSWD` is
    // better served by being told the app is still waiting for `DB_PASSWORD`
    // than by being told this name is unused.
    if !manifest.container.secrets.contains(&name) {
        warn!(app = %id, secret = %name, "the app's manifest declares no such secret, so nothing will read it");

        return answered(&SecretSet {
            created,
            outcome: SecretOutcome::Stored,
        });
    }

    // The store is asked before the record, and asked what is *running* first,
    // because the two can disagree and only one of them knows what is serving
    // traffic. A record saying an app is suspended while the app is up is not a
    // hypothetical: `suspend` and `resume` both warn and carry on when the flag
    // cannot be written, which leaves exactly that. Reading the record first
    // would answer `Stored` with a 200 for an app that is up and would go on
    // serving the value this call replaced — for good, since nothing else is
    // coming to notice.
    //
    // The lock goes here, and it has to: everything below re-enters the applier,
    // and the applier's lock is not reentrant. What it was protecting is done —
    // the value is written and the app was still there afterwards — and the verb
    // this hands off to takes the lock again for itself, so the app is marked as
    // being worked on for the whole of the part that touches a container. The
    // gap is two reads of the store.
    drop(working);

    if applier.store().get(&id).is_some() {
        return redeployed(&applier, record, id, name, manifest, created, true).await;
    }

    if applier.store().suspended(&id).is_some() {
        return resumed(&applier, &deploying, &id, &name, created).await;
    }

    // Suspended in the record and neither running nor suspended in the store,
    // which is an app this spaceport failed to bring back at its last start.
    // There is nothing to resume and starting it would overrule the suspension,
    // so the value is stored and left for whatever brings the app back.
    if record.suspended {
        return answered(&SecretSet {
            created,
            outcome: SecretOutcome::Stored,
        });
    }

    // Recorded as wanting to run and not running: down, or never brought back.
    // The same call puts it up, and it is not a redeploy — there is no
    // container to replace.
    redeployed(&applier, record, id, name, manifest, created, false).await
}

/// The app was waiting for exactly this, so put it back into service.
async fn resumed(
    applier: &Applier,
    deploying: &Deploying,
    id: &AppId,
    name: &VarName,
    created: bool,
) -> Response {
    match applier.resume(id).await {
        Ok(_) => {
            // After the app is serving and never before, exactly as `resume`
            // does it and for its reason: an app that came back may have an
            // image built during the suspension that nothing has run.
            deploying.0.nudge();

            answered(&SecretSet {
                created,
                outcome: SecretOutcome::Resumed,
            })
        }
        // The value is stored and the app is not up. Said as a refusal rather
        // than as an outcome, so that a script setting the last missing secret
        // of an app exits non-zero when the app did not actually come back.
        Err(error) => {
            warn!(app = %id, secret = %name, %error, "the secret was set and the app did not resume");
            let status = match error {
                ResumeError::Unknown(_) => StatusCode::NOT_FOUND,
                ResumeError::Conflict(_) | ResumeError::MissingSecrets(_) => StatusCode::CONFLICT,
                ResumeError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };

            refuse(
                status,
                &format!(
                    "the secret `{name}` of app `{id}` is stored, but the app did not come back: {error}"
                ),
            )
        }
    }
}

/// The app is on a container built from the value this one replaced — or on no
/// container at all — so put it on one built from this value.
///
/// A redeploy of the manifest the record holds and not a restart, because that
/// is what a changed secret is: the version of every secret goes into the
/// fingerprint the container is labelled with — deliberately the version and
/// never the value — so a container built from the old value no longer matches
/// the app's spec, and replacing it is what applying the same manifest already
/// means.
///
/// `running` says which of the two this was, and it changes only what is
/// reported: an app that was down had no container to replace, and telling an
/// operator one was replaced would describe something that did not happen.
async fn redeployed(
    applier: &Applier,
    record: AppRecord,
    id: AppId,
    name: VarName,
    manifest: AppManifest,
    created: bool,
    running: bool,
) -> Response {
    let revision = record.revision.clone();

    match applier
        .deploy(id.clone(), manifest, revision.as_deref(), false)
        .await
    {
        Ok(Applied::Running(_)) => {
            // `deploy` records what it applied, and recording says the app was
            // applied now — but nobody applied anything here, somebody rotated
            // a password. So the record read on the way in goes back exactly as
            // it was read, the way a rolled-back deployment puts one back, and
            // `apps show` goes on saying when the app was last applied. Not
            // suspended, whatever it said before: the app is running, and this
            // is the one field that has genuinely changed.
            let applied = AppRecord {
                suspended: false,
                ..record
            };
            if let Err(error) = applier.repository().put_back(&applied).await {
                warn!(app = %id, %error, "the app is running on the new value, and its record now says it was applied just now");
            }

            answered(&SecretSet {
                created,
                outcome: match running {
                    true => SecretOutcome::Redeployed,
                    false => SecretOutcome::Started,
                },
            })
        }
        // Nothing here asked for a suspension and every secret was in hand, so
        // this is the app having been suspended between two of these awaits —
        // and staging takes the container with it. Refused rather than
        // answered, for the reason a failed resume is: the value is stored and
        // the app is not serving, and a script that got a 200 for that would
        // carry on to the next thing.
        Ok(Applied::Suspended(_)) => {
            warn!(app = %id, secret = %name, "the secret was set and the app was suspended while it was being applied");

            refuse(
                StatusCode::CONFLICT,
                &format!(
                    "the secret `{name}` of app `{id}` is stored, but the app was suspended while it was being applied, so it is not serving — `spaceport apps resume {id}` puts it back on the new value"
                ),
            )
        }
        Err(error) => {
            warn!(app = %id, secret = %name, %error, "the secret was set and the app was not redeployed");
            let status = match error {
                ApplyError::Conflict(_) | ApplyError::MissingSecrets(_) => StatusCode::CONFLICT,
                ApplyError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };

            // Not "it is still running the value from before": replacing a
            // container removes the old one before it creates the new one, so
            // an app whose replacement never became ready is not running at
            // all. What is true is that the value is stored, the app is not
            // back, and somebody has to look at it.
            refuse(
                status,
                &format!(
                    "the secret `{name}` of app `{id}` is stored, but the app did not come back on it and is not serving — it needs attention: {error}"
                ),
            )
        }
    }
}

/// `DELETE /apps/{id}/secrets/{name}`: forget this value.
///
/// Refused with a 409 while the app's recorded manifest declares the name. A
/// secret an app declares is one it cannot start without, so deleting one under
/// a running app arms a trap: the app carries on serving from the container it
/// already has, and the next thing that restarts it — a redeploy, a crash, a
/// reboot of the host at four in the morning — finds a manifest it cannot run.
/// The order that works is the other one: take the name out of the manifest,
/// apply that, and the value is then a leftover this will remove.
async fn delete_secret(
    State(instance): State<Arc<Instance>>,
    State(applier): State<Arc<Applier>>,
    UrlPath((id, name)): UrlPath<(String, String)>,
) -> Response {
    let (id, name) = match about(&id, &name) {
        Ok(named) => named,
        Err(refusal) => return *refusal,
    };

    let record = match AppRepository::new(instance.db.clone()).recorded(&id).await {
        Ok(record) => record,
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not read what is recorded for `{id}`: {error:#}"),
            );
        }
    };
    if !known(&instance, &id, record.as_ref()).await {
        return refuse(StatusCode::NOT_FOUND, &format!("no app named `{id}`"));
    }

    // Every manifest this spaceport is holding for the app, not only the
    // recorded one. A record can be out of date in the direction that matters:
    // an apply that could not write its row warns and carries on, and the app
    // is running on the manifest it was given whatever the table ended up
    // saying. So the store is asked too — running, suspended and down all carry
    // a manifest — and either of them declaring the name is a refusal.
    //
    // What is deliberately not asked is the manifest of a build that has been
    // built and not yet deployed. No container carries those values, and a
    // deploy that then finds the secret missing stages the app suspended and
    // rolls it back onto what it was running: a bad minute, rather than a
    // running app quietly losing the credential it cannot restart without.
    //
    // A manifest this spaceport cannot parse is treated as declaring nothing,
    // which is the wrong way round from the check above and is deliberate:
    // there is no version of this where a document nobody can read makes a
    // value undeletable forever.
    let store = applier.store();
    let declared = [
        record
            .as_ref()
            .and_then(|record| AppManifest::parse(&record.manifest).ok()),
        store.get(&id).map(|app| app.manifest.clone()),
        store.suspended(&id).map(|app| app.manifest),
        store.downed(&id).map(|app| app.manifest),
    ]
    .into_iter()
    .flatten()
    .any(|manifest| manifest.container.secrets.contains(&name));
    if declared {
        return refuse(
            StatusCode::CONFLICT,
            &format!(
                "app `{id}` declares the secret `{name}` in its manifest, so spaceport will not delete it — the app is running on it and would not start again without it\n  take `{name}` out of the manifest, apply that, and delete the value then"
            ),
        );
    }

    match applier.secrets().delete(&id, &name).await {
        Ok(true) => (
            StatusCode::OK,
            format!(
                "the secret `{name}` of app `{id}` is deleted\n  nothing was restarted — its manifest does not declare it, so nothing was reading it\n"
            ),
        )
            .into_response(),
        // The difference between having removed it and having spelled it wrong,
        // which is the one thing an operator deleting a secret wants to know.
        Ok(false) => refuse(
            StatusCode::NOT_FOUND,
            &format!(
                "app `{id}` has no secret named `{name}` — `spaceport apps secret list {id}` says which it has"
            ),
        ),
        Err(error) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("could not delete the secret `{name}` of app `{id}`: {error:#}"),
        ),
    }
}

/// The app and the secret a request is about, or the refusal that says which of
/// the two was not a name.
fn about(id: &str, name: &str) -> Result<(AppId, VarName), Box<Response>> {
    let refusal =
        |error: anyhow::Error| Box::new(refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")));

    let id: AppId = id.parse().map_err(refusal)?;
    let name: VarName = name.parse().map_err(refusal)?;

    Ok((id, name))
}

/// Whether spaceport has heard of this app at all.
///
/// The same three places [`show`] looks, and for its reason: an app exists here
/// as a record, as something in the routing table, or as a tracking that took
/// the name before any manifest was applied under it. Setting a secret before
/// the manifest arrives is the ordinary order — an app whose first deploy needs
/// a database password needs it set beforehand — so all three count.
async fn known(instance: &Instance, id: &AppId, recorded: Option<&AppRecord>) -> bool {
    if recorded.is_some() {
        return true;
    }

    let store = instance.applier.store();

    store.get(id).is_some()
        || store.suspended(id).is_some()
        || store.downed(id).is_some()
        || tracked(instance, id).await.is_some()
}

/// What a `set` did, as the JSON the CLI turns into a sentence.
fn answered(set: &SecretSet) -> Response {
    match serde_json::to_vec(set) {
        Ok(body) => (
            StatusCode::OK,
            [(http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        // Nothing in here can fail to serialise — it is a bool, a tag and a
        // list of names — and if one ever does, the operator has just changed
        // a secret and should hear that something went wrong.
        Err(error) => {
            warn!(%error, "could not serialise what setting a secret did");
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not say what setting the secret did: {error}"),
            )
        }
    }
}

/// Where an app's manifest is looked for when nobody names a path.
const DEFAULT_MANIFEST_PATH: &str = "spaceport.yaml";

/// `PUT /apps/{id}/tracking?repository=&connection=&branch=&manifest_path=`:
/// this app's code lives there.
///
/// A `PUT` for the same reason applying one is: an app is built from a single
/// place, so this ends with the app tracking exactly what the query describes,
/// whether or not it tracked something before.
///
/// The branch's current head is built at once, and every push to it from then
/// on. The first of those is what makes tracking a repository that already has
/// commits do anything at all: the builder only ever builds a revision written
/// down beside a tracking, and a repository whose last push is older than the
/// tracking would otherwise wait for a push that may never come.
///
/// What becomes of those builds is `deploy`'s to say. Without it, none of them
/// is deployed by anything: what a build produces is an image, and running it is
/// `spaceport apps deploy`, which is a decision an operator takes. With it, a
/// build that succeeds is run as soon as it exists, this one included. The
/// response says which of the two the app is now in, because an operator who has
/// just pointed an app at a branch would otherwise sit waiting for a deployment
/// that is not coming — or not be waiting for one that is.
///
/// `deploy` is optional, and the missing case is the interesting one: it means
/// the request did not raise the subject, so whatever the app was set to stays
/// as it was. See [`TrackingRepository::record`], which is where that is
/// enforced. Correcting a manifest path is not a request to stop deploying.
///
/// The app does not have to have been applied first. Applying and tracking are
/// the two ways an app comes to exist: one hands spaceport a manifest, the other
/// says where to find one. Demanding the first before the second would mean
/// copying a manifest out of the repository by hand, which is the work tracking
/// exists to remove.
///
/// That is safe because an app with no applied manifest has nothing to conflict
/// with: nothing runs, there is no container, no host is claimed, and the edge
/// routes nothing to it. A tracking on its own is a note about where to look —
/// so there is nothing for a stricter check to protect.
///
/// Everything is settled before anything is written down, in the order the
/// answers stop being guesses: the connection has to exist before it can be
/// asked what it reaches, and the repository has to be one it actually reaches
/// before there is an installation to ask GitHub as.
///
/// A branch nobody named is asked of GitHub once, here, and the answer is stored
/// as though it had been typed. Storing the name rather than the words "the
/// default branch" is the point: a default branch is a setting on github.com
/// that somebody may change months from now, and an app that followed it would
/// silently start building from somewhere else — a repointing nobody asked for,
/// recorded nowhere, on an app that is already running.
// The argument list is axum's dependency injection rather than a signature
// anybody calls: every one of them is a `State` or an extractor, and bundling
// two of them into a struct to get under a count would hide which pieces of the
// instance this handler touches.
#[allow(clippy::too_many_arguments)]
async fn track(
    State(instance): State<Arc<Instance>>,
    State(connections): State<Arc<ConnectionRepository>>,
    State(tracking): State<Arc<TrackingRepository>>,
    State(github): State<Arc<dyn Transport>>,
    State(building): State<Building>,
    State(deploying): State<Deploying>,
    UrlPath(id): UrlPath<String>,
    Query(query): Query<TrackQuery>,
) -> Response {
    let id: AppId = match id.parse() {
        Ok(id) => id,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let connection = match connections.by_slug(&query.connection).await {
        Ok(Some(connection)) => connection,
        Ok(None) => return refuse(StatusCode::NOT_FOUND, &unconnected(&query.connection)),
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "could not read the connection `{}`: {error:#}",
                    query.connection
                ),
            );
        }
    };

    let installations = match connections.installations(connection.app_id).await {
        Ok(installations) => installations,
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "could not read what `{}` reaches: {error:#}",
                    connection.slug
                ),
            );
        }
    };

    let Some((installation_id, cached_name)) = granting(&installations, &query.repository) else {
        return refuse(
            StatusCode::NOT_FOUND,
            &format!(
                "`{}` does not reach `{}` — either it was never installed on that repository, or spaceport's copy of what it reaches is older than the installation is\n  the copy is refreshed hourly, and `spaceport connect show {}` says when it last was and what is in it",
                connection.slug, query.repository, connection.slug,
            ),
        );
    };

    let manifest_path = match manifest_path(query.manifest_path.as_deref()) {
        Ok(path) => path,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &error),
    };

    // Built once and used for both questions GitHub is asked here, since the
    // second of them is asked whether or not the first was: an operator who
    // named the branch has said which branch, and not which commit it is at.
    let client = match Client::new(&connection, github) {
        Ok(client) => client,
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not act as `{}`: {error:#}", connection.slug),
            );
        }
    };

    let (branch, repository) = match query.branch.as_deref() {
        Some(branch) => match branch_named(branch) {
            Ok(branch) => (branch, cached_name),
            Err(error) => return refuse(StatusCode::BAD_REQUEST, &error),
        },
        None => match client.repository(installation_id, &cached_name).await {
            Ok(record) => (record.default_branch, record.full_name),
            // GitHub's own sentence, under the status the edge uses for the
            // same thing: what failed is the far end, and there is nothing
            // wrong with the request that got here.
            Err(error) => return refuse(StatusCode::BAD_GATEWAY, &format!("{error:#}")),
        },
    };

    // Where the branch has got to, whether it was named or asked for. This is
    // what gives the tracking something to build: a repository whose last push
    // is older than the tracking produces no delivery, and the builder only
    // ever builds a revision that is written down.
    //
    // Asked before anything is recorded, on the same reasoning as everything
    // above it — a branch this repository does not have, and a GitHub having a
    // bad minute, both leave the app tracking whatever it tracked before.
    let head = match client
        .branch_head(installation_id, &repository, &branch)
        .await
    {
        Ok(Some(head)) => head,
        // Under the status the request deserves rather than the far end's: a
        // branch that is not there is something somebody typed, and `502` would
        // send them to look at GitHub for a mistake of their own. The
        // installation is still named, because a repository whose branches this
        // app cannot see answers the same way and reads the same from here.
        Ok(None) => {
            return refuse(
                StatusCode::NOT_FOUND,
                &format!(
                    "`{repository}` has no branch `{branch}` — check the spelling, or that `{}` still reaches every branch of it\n  omit `--branch` to track whichever branch the repository calls its default",
                    connection.slug,
                ),
            );
        }
        Err(error) => return refuse(StatusCode::BAD_GATEWAY, &format!("{error:#}")),
    };

    // Read before the row is rewritten, because the answer to "is this app
    // armed now?" is the operator's request where they made one and the old row
    // where they did not — which is exactly what `record` does to the column,
    // said here so the response can be written from it. Reading it back
    // afterwards would be a second query for a fact already in hand, and a read
    // that failed would leave the response with nothing to say. A read that
    // fails here is taken as unarmed, which is the state the response makes the
    // smaller promise about.
    let armed = match query.deploy {
        Some(deploy) => deploy,
        None => tracking
            .by_app(&id)
            .await
            .ok()
            .flatten()
            .is_some_and(|recorded| recorded.automatic),
    };

    if let Err(error) = tracking
        .record(
            &Tracking {
                app: id.clone(),
                github_app_id: connection.app_id,
                repository: repository.clone(),
                branch: branch.clone(),
                manifest_path: manifest_path.clone(),
                // Stamped by the store as it writes the row, so what is recorded is
                // when it was recorded.
                tracked_at: String::new(),
                revision: None,
                revision_seen_at: None,
                // Ignored by the store, which takes the switch from the
                // argument beside this one so that "not mentioned" can be said
                // at all. Written as the state the request settled on, so the
                // struct is not a lie for the length of the call.
                automatic: armed,
            },
            query.deploy,
        )
        .await
    {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("could not record what `{id}` tracks: {error:#}"),
        );
    }

    // Written after the row rather than through it, because `record` clears the
    // revision on purpose: a sha carried across a re-track was never on the new
    // ref. This is the head that *is* on it, resolved a moment ago — so a
    // re-track resolves afresh rather than keeping a stale one.
    if let Err(error) = tracking.record_revision(&id, &head).await {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("could not record the commit `{id}` is to be built from: {error:#}"),
        );
    }

    // After the rows and never before, which is the order a push writes in and
    // for its reason: the builder reads the trackings for itself, so a shove
    // that arrived first would send it to look at a revision that is not
    // written down yet.
    building.0.nudge();

    // And the loop that runs what was built, because arming is the other way a
    // finished image becomes deployable with nothing being built: an app whose
    // head was already built while it deployed nothing on its own has a row
    // waiting, and the build about to happen may well be a no-op that shoves
    // nothing. Unconditional on `armed`, because the pass reads the trackings
    // itself and a shove for an unarmed app costs one local query.
    deploying.0.nudge();

    let head = abbreviated(&head);

    // What the last lines say turns on two things: whether there is anything to
    // deploy to, and whether the operator armed the app. A read that fails is
    // taken as the app having a manifest, because that is the case the sentence
    // is vaguest about and so the safer one to be wrong in: it promises nothing
    // that is not true of both.
    let applied = holds(&instance, &id).await.unwrap_or(true);
    let nothing_applied = match applied {
        true => String::new(),
        false => format!(
            "  nothing has been applied under `{id}`, so spaceport knows where its code is and has nothing to run\n"
        ),
    };
    // Said before the deployment line either way, because the build is what
    // happens first and the sentence after it is about what becomes of it.
    let building = format!(
        "  `{branch}` is at {head}, which is being built now, and every push to it is built from here on\n"
    );
    // The head is already on its way through the builder, so an armed app is
    // told about *this* build rather than about the pushes to come: what the
    // operator is about to watch is a deployment nobody is going to ask for.
    let deployment = match (armed, applied) {
        (true, true) => "  what comes out is deployed without being asked, this build and every one after it\n".to_owned(),
        (true, false) => "  what comes out is deployed without being asked, manifest and all, so this build is what starts the app\n".to_owned(),
        (false, true) => format!(
            "  what comes out is deployed by nothing — run it with `spaceport apps deploy {id}`\n"
        ),
        (false, false) => format!(
            "  `spaceport apps deploy {id}` then runs what came out, manifest and all\n"
        ),
    };
    let last = format!("{nothing_applied}{building}{deployment}");

    let body = format!(
        "app `{id}` tracks {repository}\n  branch     {branch}\n  manifest   {manifest_path}\n  connection {}\n{last}",
        connection.slug,
    );

    (StatusCode::OK, body).into_response()
}

/// Whether a manifest has been applied under this name.
///
/// The same four places [`show`] looks, because an app is applied wherever it
/// ends up: running, suspended, down, or recorded and never brought back. What
/// this answers is what separates an app that is only tracked from one that is
/// tracked *and* applied — which is the difference [`list`] prints and [`track`]
/// words its answer on.
async fn holds(instance: &Instance, id: &AppId) -> Result<bool> {
    let store = instance.applier.store();
    if store.get(id).is_some() || store.suspended(id).is_some() || store.downed(id).is_some() {
        return Ok(true);
    }

    Ok(AppRepository::new(instance.db.clone())
        .recorded(id)
        .await?
        .is_some())
}

/// The installation that grants `repository`, and the name GitHub spells it
/// with.
///
/// Matched without regard to case, because github.com resolves `Acme/Site` and
/// `acme/site` to the same repository and an operator typing what they see in a
/// browser is typing whichever the page showed them. What comes back is the
/// cached spelling rather than the typed one: everything downstream compares a
/// tracking against what a webhook delivery says, and that is GitHub's spelling.
fn granting(installations: &[Installation], repository: &str) -> Option<(i64, String)> {
    installations.iter().find_map(|installation| {
        installation
            .repositories
            .iter()
            .find(|full_name| full_name.eq_ignore_ascii_case(repository))
            .map(|full_name| (installation.installation_id, full_name.clone()))
    })
}

/// Where in the repository to look for the app's manifest.
///
/// The path is resolved inside a checkout spaceport makes, which is the same
/// argument [`crate::app::manifest::Volume`] makes for having no host path in
/// it: a path that may leave the tree it is rooted in is a path that may name
/// any file on this host, and the only reliable moment to refuse that is before
/// it is written down. So it has to be relative, has to stay inside, and has to
/// name a file — a directory is not a manifest, however it is spelled.
fn manifest_path(given: Option<&str>) -> Result<String, String> {
    let path = given.unwrap_or(DEFAULT_MANIFEST_PATH);

    if path.is_empty() {
        return Err(format!(
            "the manifest path must not be empty — leave it out for `{DEFAULT_MANIFEST_PATH}`"
        ));
    }

    let candidate = Path::new(path);
    if candidate.has_root() || candidate.components().next() == Some(Component::RootDir) {
        return Err(format!(
            "`{path}` is an absolute path, and a manifest is named from the root of the repository rather than from the root of this host"
        ));
    }
    if candidate
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(format!(
            "`{path}` climbs out of the repository with `..`, and a manifest spaceport reads has to be inside the repository it was checked out of"
        ));
    }
    if path.ends_with('/')
        || !matches!(
            candidate.components().next_back(),
            Some(Component::Normal(_))
        )
    {
        return Err(format!(
            "`{path}` names a directory, and spaceport needs the file in it — `{path}/{DEFAULT_MANIFEST_PATH}`, say"
        ));
    }

    Ok(path.to_owned())
}

/// How much of a sha the operator interface prints when it names one.
///
/// Seven, which is what [`crate::build::image`] tags an image with and what
/// `connections::github::push` logs a pushed head as. An operator reads the
/// three side by side — the answer to a track, the tag it produced, the line
/// that says a branch moved — and a fourth spelling would make them do the
/// comparison by eye.
const ABBREVIATED_SHA: usize = 7;

/// The first few digits of a sha, which is how a person says one out loud.
///
/// Whole where it is shorter than that, so a fixture or a truncated field is
/// printed as itself rather than silently cut to nothing.
fn abbreviated(sha: &str) -> &str {
    sha.get(..ABBREVIATED_SHA).unwrap_or(sha)
}

/// The branch as it was given, if it is a branch.
///
/// A branch and not a ref: `refs/heads/main` is how git names the ref that a
/// branch is, and taking one here would record a branch nothing has, since every
/// comparison downstream is against the branch name a push carries.
fn branch_named(branch: &str) -> Result<String, String> {
    if branch.is_empty() {
        return Err(
            "the branch must not be empty — leave it out to take the repository's default branch"
                .to_owned(),
        );
    }
    if branch.starts_with("refs/") {
        return Err(format!(
            "`{branch}` is a ref rather than a branch — name the branch itself, as `{}`",
            branch
                .trim_start_matches("refs/")
                .trim_start_matches("heads/")
        ));
    }

    Ok(branch.to_owned())
}

/// Which repository an app is built from, and how much of that was said.
///
/// `deny_unknown_fields` so a misspelled option is refused rather than silently
/// doing something else: an operator who typed `--manifest` and meant
/// `--manifest-path` would otherwise get an app tracking a file they did not
/// name.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrackQuery {
    /// `owner/name`, as github.com spells it.
    repository: String,
    /// The slug of the connection that reaches it.
    connection: String,
    branch: Option<String>,
    manifest_path: Option<String>,
    /// Whether a build that succeeds is run without being asked, if the request
    /// says anything about it at all.
    ///
    /// Absent is not `false`. It is the request declining to answer, and it
    /// leaves an armed app armed — which is why this is an `Option` all the way
    /// down to [`TrackingRepository::record`] rather than being defaulted here.
    deploy: Option<bool>,
}

/// Where GitHub takes an operator to install an app on an account.
///
/// GitHub's own path, spelled out here because a registered app that nobody has
/// installed can see nothing at all — so the address is the next thing an
/// operator needs, and having to go and find it is where the flow stalls.
const INSTALL_URL: &str = "https://github.com/apps";

/// `POST /connections/github` with a registration as the body: hold this
/// GitHub App as one of spaceport's own.
///
/// The body is JSON rather than a manifest because it is a handful of fields an
/// operator typed, three of which are secrets — and nothing about them wants to
/// go through a file on disk.
///
/// The transport comes along because connecting asks GitHub to confirm the
/// credentials before anything is written down, and the answer to that is what
/// the operator is really waiting for.
async fn connect_github(
    State(connections): State<Arc<ConnectionRepository>>,
    State(github): State<Arc<dyn Transport>>,
    State(nudge): State<Nudge>,
    body: String,
) -> Response {
    let registration: Registration = match serde_json::from_str(&body) {
        Ok(registration) => registration,
        Err(error) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                &format!("that is not a github app registration: {error}"),
            );
        }
    };

    match register::connect(&connections, github, registration, &nudge).await {
        Ok(connection) => {
            let body = format!(
                "connected `{}` as github app {}, owned by {}\n  install it on an account at {INSTALL_URL}/{}/installations/new\n",
                connection.slug, connection.app_id, connection.owner, connection.slug,
            );

            (StatusCode::OK, body).into_response()
        }
        // Almost everything `connect` refuses is something about the
        // registration, and the message says which part of it. The exception is
        // GitHub having a bad minute, which the message says too — and which is
        // still an operator retrying the same command, so it is not worth a
        // second status code to tell them apart.
        Err(error) => refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    }
}

/// The longest name GitHub will create an App under.
///
/// GitHub's rule rather than a choice, and it applies to the name a manifest
/// asks for: a longer one is refused at the moment the browser posts the form,
/// which is a page an operator reads on github.com rather than a message
/// spaceport could improve on. So the derived default is kept inside it.
const NAME_LIMIT: usize = 34;

/// `POST /connections/github/register` with `{"org": …, "name": …}`: begin the
/// flow that has GitHub create the app.
///
/// Answers with a url and not with a connection, because the middle of this
/// flow is a person in a browser: GitHub will only take an App manifest as a
/// form post from a logged-in session, so spaceport can prepare the form and
/// nothing more. The command that called this exits here; whether an app is
/// ever created is settled at the edge, minutes later.
async fn register_github(State(instance): State<Arc<Instance>>, body: String) -> Response {
    let request: RegisterRequest = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(error) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                &format!("that is not a github app registration request: {error}"),
            );
        }
    };

    // The whole flow is a redirect back to an address GitHub can reach, and
    // without a hostname there is no such address — so this fails now, rather
    // than as a manifest naming a url that goes nowhere.
    let Some(hostname) = instance
        .config
        .edge
        .hostname
        .as_ref()
        .map(ToString::to_string)
    else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "this spaceport has no hostname of its own, and github has to be able to reach one to hand the app back — set `edge.hostname` in its config and restart it, or register an app made by hand with `spaceport connect github --manual`",
        );
    };

    let name = request
        .name
        .unwrap_or_else(|| default_name(&hostname, request.org.as_deref()));
    let state = match instance.attempts.begin(
        request.org.clone(),
        name.clone(),
        time::OffsetDateTime::now_utc(),
    ) {
        Ok(state) => state,
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not begin a registration: {error:#}"),
            );
        }
    };

    let owner = match &request.org {
        Some(org) => format!("the `{org}` organisation"),
        None => "your own github account".to_owned(),
    };

    (
        StatusCode::OK,
        format!(
            "open this in a browser signed in to github as somebody who may create an app on {owner}:\n\n  {}\n\ngithub will create an app called `{name}` and send the browser back here, and spaceport records it then\nthe link is good for {} minutes\n",
            manifest::setup_url(&hostname, &state),
            manifest::LIFETIME.whole_minutes(),
        ),
    )
        .into_response()
}

/// What to call an app nobody named.
///
/// Built from the hostname because a GitHub App's name has to be unique across
/// the whole of github.com, and a hostname is the one thing about a spaceport
/// that is already unique — `spaceport` on its own is long taken.
///
/// The organisation is in it for the same reason. A spaceport may hold one app
/// per organisation, and a name built from the hostname alone is the same name
/// every time: connecting a second organisation with defaults would ask GitHub
/// to create an app called what the first one is already called, and GitHub
/// refuses that on the form — after the operator has clicked through, with an
/// error page spaceport never sees and cannot improve on. So the default is
/// distinct per organisation before it is ever offered.
///
/// The organisation goes last and is kept whole when the two together are too
/// long. Truncating the end is the obvious way to fit [`NAME_LIMIT`] and it is
/// the wrong one here: the tail is the only part that distinguishes one of
/// these names from another, and cutting it would reinstate exactly the
/// collision this is here to avoid. So the hostname gives up its characters
/// first, and only an organisation that fills the limit on its own truncates.
fn default_name(hostname: &str, org: Option<&str>) -> String {
    let host = hostname.replace('.', "-");

    let Some(org) = org else {
        return trimmed(&host, NAME_LIMIT);
    };

    // One character for the hyphen that joins them.
    let Some(room) = NAME_LIMIT.checked_sub(org.chars().count() + 1) else {
        return trimmed(org, NAME_LIMIT);
    };

    match trimmed(&host, room) {
        // An organisation long enough to leave the hostname nothing is still an
        // organisation, and its name alone is distinct — which is the property
        // that matters.
        host if host.is_empty() => trimmed(org, NAME_LIMIT),
        host => format!("{host}-{org}"),
    }
}

/// `text` cut to `limit` characters, and to no trailing hyphen, so what is left
/// reads as a name rather than as a cut-off one.
fn trimmed(text: &str, limit: usize) -> String {
    text.chars()
        .take(limit)
        .collect::<String>()
        .trim_end_matches('-')
        .to_owned()
}

/// What an operator asks for when they ask GitHub to create the app.
///
/// `name` is optional here and not on the command line's side of things,
/// because the default is derived from this spaceport's hostname and the
/// command has no idea what that is.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    /// The organisation the app should belong to, or none for the operator's
    /// own account.
    org: Option<String>,
    name: Option<String>,
}

/// `GET /connections`: the github apps this spaceport is, one per line.
///
/// Never a secret, not even a redacted one: a listing is the response most
/// likely to be pasted somewhere, and a column of `Secret(…)` would say nothing
/// an operator did not already know.
async fn connections(State(connections): State<Arc<ConnectionRepository>>) -> Response {
    let held = match connections.all().await {
        Ok(held) => held,
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not read the connections: {error:#}"),
            );
        }
    };

    if held.is_empty() {
        return (
            StatusCode::OK,
            "no github apps are connected — connect one with `spaceport connect github --manual`\n",
        )
            .into_response();
    }

    let rows: Vec<Vec<String>> = held
        .iter()
        .map(|connection| {
            vec![
                connection.slug.clone(),
                connection.app_id.to_string(),
                connection.owner.clone(),
                connection.connected_at.clone(),
            ]
        })
        .collect();

    (
        StatusCode::OK,
        columns(&["SLUG", "APP ID", "OWNER", "CONNECTED"], &rows),
    )
        .into_response()
}

/// `GET /connections/{slug}`: everything spaceport knows about one connection.
///
/// The secrets are reported as being set and never as their values: that they
/// are there at all is the question an operator has — the alternative is
/// reading them back, and a command that prints a private key is one somebody
/// will eventually run in front of a screen share.
async fn connection(
    State(connections): State<Arc<ConnectionRepository>>,
    UrlPath(slug): UrlPath<String>,
) -> Response {
    let held = match connections.by_slug(&slug).await {
        Ok(Some(held)) => held,
        Ok(None) => return refuse(StatusCode::NOT_FOUND, &unconnected(&slug)),
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not read the connection `{slug}`: {error:#}"),
            );
        }
    };

    let mut out = Report::default();
    out.field("app", held.slug.clone());
    out.field("name", held.name.clone());
    out.field("app id", held.app_id.to_string());
    out.field("owner", held.owner.clone());
    out.field("client id", held.client_id.clone());
    out.field("connected", held.connected_at.clone());
    out.field(
        "secrets",
        "client secret, webhook secret, private key (not shown)".to_owned(),
    );

    // What GitHub last said, which is a cache and is empty until the first
    // reconciliation has run — so an app nobody has installed says so rather
    // than saying nothing.
    match connections.installations(held.app_id).await {
        Ok(installations) if installations.is_empty() => out.field(
            "installed",
            format!(
                "nowhere yet — install it at {INSTALL_URL}/{}/installations/new",
                held.slug
            ),
        ),
        Ok(installations) => {
            for (index, installation) in installations.iter().enumerate() {
                out.field(
                    if index == 0 { "installed" } else { "" },
                    format!(
                        "{} ({}), {}",
                        installation.account,
                        installation.account_type.to_lowercase(),
                        counted(installation.repositories.len()),
                    ),
                );

                // Named rather than counted, because the count answers a
                // question nobody has. What an operator wants off this command
                // is whether one particular repository is in reach, and a
                // number cannot answer that — and the names are already in
                // hand, cached by the same pass that counted them.
                //
                // Every one of them, however many there are. Printing the
                // first few and a "and 40 more" reads as an answer while being
                // one only when the repository being looked for happens to
                // sort early, which is the worst of both.
                for repository in &installation.repositories {
                    out.field("", format!("  {repository}"));
                }
            }
        }
        Err(error) => out.field("installed", format!("could not be read: {error:#}")),
    }

    // How old that answer is, which is the question behind "why is my
    // repository not here" — a cache nothing has refreshed yet and a cache
    // refreshed a minute ago call for quite different next steps.
    match connections.last_reconciled(held.app_id).await {
        Ok(Some(reconciled)) => out.field("refreshed", reconciled),
        Ok(None) => out.field(
            "refreshed",
            "not yet — a pass is due within seconds of connecting, and hourly after that"
                .to_owned(),
        ),
        Err(error) => out.field("refreshed", format!("could not be read: {error:#}")),
    }

    (StatusCode::OK, out.render()).into_response()
}

/// How many repositories an installation reaches, said in English.
///
/// An installation with none is a real state and not an empty list to be
/// printed as nothing: somebody installed the app and granted it no
/// repository, and "0 repositories" reads as a failure to look rather than as
/// what was found.
fn counted(repositories: usize) -> String {
    match repositories {
        0 => "no repositories".to_owned(),
        1 => "1 repository".to_owned(),
        many => format!("{many} repositories"),
    }
}

/// `DELETE /connections/{slug}`: forget the app, and everything cached under
/// it.
///
/// No nudge, unlike connecting: forgetting deletes the connection's own rows
/// here and now, so the cache is already right when this answers. A pass would
/// find one fewer connection to ask GitHub about and change nothing — an API
/// round trip per remaining connection to confirm what is already true.
async fn forget_connection(
    State(connections): State<Arc<ConnectionRepository>>,
    UrlPath(slug): UrlPath<String>,
) -> Response {
    match connections.forget(&slug).await {
        Ok(true) => {
            let body = format!(
                "forgot `{slug}`\n  its secrets, its cached installations and its recent deliveries are gone\n  the app itself still exists on github, and can be deleted there\n"
            );

            (StatusCode::OK, body).into_response()
        }
        Ok(false) => refuse(StatusCode::NOT_FOUND, &unconnected(&slug)),
        Err(error) => {
            warn!(%error, "forgetting a connection failed");

            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not forget `{slug}`: {error:#}"),
            )
        }
    }
}

/// What is said about a slug nothing is connected under, in the one wording
/// both handlers that can meet one use.
fn unconnected(slug: &str) -> String {
    format!("`{slug}` is not connected — `spaceport connect list` says what is")
}

/// `GET /auth/users?pattern=…`: who spaceport knows, as a table.
///
/// The id is a column and not an aside: it is the stable identity everything
/// later hangs off, and the listing is where an operator goes to copy one.
async fn list_users(
    State(users): State<Arc<UserRepository>>,
    Query(query): Query<ListQuery>,
) -> Response {
    let pattern = match query
        .pattern
        .as_deref()
        .map(str::parse::<Pattern>)
        .transpose()
    {
        Ok(pattern) => pattern,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let listed = match users.list(pattern.as_ref()).await {
        Ok(listed) => listed,
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not read the users: {error:#}"),
            );
        }
    };

    if listed.is_empty() {
        let body = match &pattern {
            Some(pattern) => format!("no user matches `{pattern}`\n"),
            None => {
                "no users exist — create one with `spaceport auth user create <slug>`\n".to_owned()
            }
        };

        return (StatusCode::OK, body).into_response();
    }

    let rows: Vec<Vec<String>> = listed
        .iter()
        .map(|user| {
            vec![
                user.slug.to_string(),
                user.id.to_string(),
                user_status(user).to_owned(),
                user.email.clone().unwrap_or_default(),
                user.created_at.clone(),
            ]
        })
        .collect();

    (
        StatusCode::OK,
        columns(&["USER", "ID", "STATUS", "EMAIL", "CREATED"], &rows),
    )
        .into_response()
}

/// The one word a listing and a report say about a user's standing.
fn user_status(user: &UserRecord) -> &'static str {
    match user.suspended {
        true => "suspended",
        false => "active",
    }
}

/// `PUT /auth/users/{slug}` with the email, if any, as the body: know this
/// person, under this name.
///
/// The email travels in the body rather than the query string for the small
/// version of the reason a secret's value does: `user+ci@example.com` is an
/// ordinary address, and a query string reads its `+` as a space — silently,
/// which is the worst way. A body carries it as it is, and an absent email is
/// an empty body.
///
/// A `PUT` like applying an app, and unlike it in one way: applying twice is
/// idempotent because the id *is* the document, while a user's identity is
/// minted here — so a slug that already exists is a 409, not a replacement.
/// Replacing would quietly hand the same name a new UUID, which is exactly the
/// confusion the never-reused rule exists to prevent.
async fn create_user(
    State(users): State<Arc<UserRepository>>,
    UrlPath(slug): UrlPath<String>,
    body: String,
) -> Response {
    let slug: crate::auth::UserSlug = match slug.parse() {
        Ok(slug) => slug,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    // The lightest check that catches a slug pasted where the address goes.
    // Anything stricter would be this build deciding what an address is, and
    // the address's real test — a code arriving — is a later milestone's.
    let email = body.trim();
    let email = match email {
        "" => None,
        address if address.contains('@') && !address.contains(char::is_whitespace) => Some(address),
        address => {
            return refuse(
                StatusCode::BAD_REQUEST,
                &format!("`{address}` does not read as an email address"),
            );
        }
    };

    match users.create(&slug, email).await {
        Ok(created) => {
            let mut body = format!("user `{slug}` created\n  id     {}\n", created.id);
            if let Some(email) = &created.email {
                body.push_str(&format!("  email  {email}\n"));
            }

            (StatusCode::OK, body).into_response()
        }
        Err(error) => refuse_user(error),
    }
}

/// `POST /auth/users/{ref}/suspend`: keep the record, close the door.
async fn suspend_user(
    State(users): State<Arc<UserRepository>>,
    UrlPath(user): UrlPath<String>,
) -> Response {
    let user: UserRef = match user.parse() {
        Ok(user) => user,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    match users.suspend(&user).await {
        Ok(suspended) => {
            let body = format!(
                "user `{}` suspended\n  the record and its id {} are kept\n  `spaceport auth user resume {}` lets them back in\n",
                suspended.slug, suspended.id, suspended.slug,
            );

            (StatusCode::OK, body).into_response()
        }
        Err(error) => refuse_user(error),
    }
}

/// `POST /auth/users/{ref}/resume`: open the door again.
async fn resume_user(
    State(users): State<Arc<UserRepository>>,
    UrlPath(user): UrlPath<String>,
) -> Response {
    let user: UserRef = match user.parse() {
        Ok(user) => user,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    match users.resume(&user).await {
        Ok(resumed) => {
            let body = format!("user `{}` resumed\n", resumed.slug);

            (StatusCode::OK, body).into_response()
        }
        Err(error) => refuse_user(error),
    }
}

/// `DELETE /auth/users/{ref}`: forget the user, keeping only the log.
async fn drop_user(
    State(users): State<Arc<UserRepository>>,
    UrlPath(user): UrlPath<String>,
) -> Response {
    let user: UserRef = match user.parse() {
        Ok(user) => user,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    match users.drop_user(&user).await {
        Ok(dropped) => {
            let body = format!(
                "user `{}` dropped\n  its id {} is never reused — `{}` created again is a different user\n  the auth log keeps its history\n",
                dropped.slug, dropped.id, dropped.slug,
            );

            (StatusCode::OK, body).into_response()
        }
        Err(error) => refuse_user(error),
    }
}

/// One mapping from what went wrong to whose problem it is, for every verb on
/// the user pool: a mistyped name is a 404, a slug already held is a 409, and
/// a store that would not answer is a 500.
fn refuse_user(error: UserError) -> Response {
    let status = match &error {
        UserError::Unknown(_) => StatusCode::NOT_FOUND,
        UserError::SlugTaken(_) => StatusCode::CONFLICT,
        UserError::Failed(_) => {
            warn!(%error, "a user command failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };

    refuse(status, &error.to_string())
}

/// `GET /auth/users/{ref}/sessions`: what is signed in — or can sign a
/// request — as this user: sessions, their derived app sessions, and API
/// keys, told apart by the KIND column the listing has carried since before
/// keys existed.
///
/// A key's row shows the prefix-and-tail glimpse fixed at mint and what the
/// key grants; the KEY and GRANTS columns sit empty on session rows, which is
/// cheaper to read than a second table would be to remember to ask for.
async fn list_sessions(
    State(sessions): State<Arc<SessionRepository>>,
    UrlPath(user): UrlPath<String>,
) -> Response {
    let user: UserRef = match user.parse() {
        Ok(user) => user,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let (user, listed, keys) = match sessions.list(&user).await {
        Ok(listed) => listed,
        Err(error) => return refuse_session(error),
    };

    if listed.is_empty() && keys.is_empty() {
        return (
            StatusCode::OK,
            format!(
                "`{}` has no sessions or api keys — `spaceport auth session mint {}` starts a session\n",
                user.slug, user.slug
            ),
        )
            .into_response();
    }

    // Derived app sessions render directly under their parent, KIND `app`
    // and the app's id where a session id would be: the indentation of the
    // ordering is what says "this one dies with the row above", which is the
    // one thing an operator deciding what to drop needs to read.
    let mut rows: Vec<Vec<String>> = Vec::new();
    for session in &listed {
        rows.push(vec![
            "session".to_owned(),
            session.id.to_string(),
            String::new(),
            String::new(),
            session.created_at.clone(),
            session.expires_at.clone(),
        ]);
        for derived in &session.derived {
            rows.push(vec![
                "app".to_owned(),
                format!("↳ {}", derived.app),
                String::new(),
                String::new(),
                derived.created_at.clone(),
                derived.expires_at.clone(),
            ]);
        }
    }
    for key in &keys {
        rows.push(vec![
            "key".to_owned(),
            key.id.to_string(),
            key.prefix_tail.clone(),
            format!("{}@{}", key.role, key.app),
            key.created_at.clone(),
            key.expires_at.clone(),
        ]);
    }

    (
        StatusCode::OK,
        columns(
            &["KIND", "ID", "KEY", "GRANTS", "CREATED", "EXPIRES"],
            &rows,
        ),
    )
        .into_response()
}

/// `POST /auth/users/{ref}/sessions?expires=…`: mint a one-time code.
///
/// The one response in the auth family that carries a credential, and it does
/// so exactly once: the code is printed here, stored only as a hash, and no
/// later command can recover it. An operator who loses it mints another.
async fn mint_session(
    State(sessions): State<Arc<SessionRepository>>,
    UrlPath(user): UrlPath<String>,
    Query(query): Query<MintQuery>,
) -> Response {
    let user: UserRef = match user.parse() {
        Ok(user) => user,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };
    let lifetime = match &query.expires {
        Some(expires) => match crate::duration::parse(expires) {
            Ok(lifetime) => lifetime,
            Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
        },
        None => crate::auth::DEFAULT_SESSION_LIFETIME,
    };

    match sessions.mint_code(&user, lifetime).await {
        Ok(minted) => {
            let body = format!(
                "one-time code for `{}`: {}\n  shown once — it is stored only as a hash\n  good for 10 minutes, a single use, and 5 failed attempts\n  the session it redeems expires {}\n",
                minted.user.slug,
                // The deliberate exposure: this response is the terminal the
                // spec says the code is printed to.
                minted.code.expose(),
                minted.session_expires_at,
            );

            (StatusCode::OK, body).into_response()
        }
        Err(error) => refuse_session(error),
    }
}

#[derive(Debug, Deserialize)]
struct MintQuery {
    /// How long the redeemed session lives, as a duration like `12h`.
    expires: Option<String>,
}

/// `DELETE /auth/users/{ref}/sessions`: sign this user out everywhere — every
/// session, and every API key with them, which is the spec's "all sessions
/// and keys".
async fn drop_all_sessions(
    State(sessions): State<Arc<SessionRepository>>,
    UrlPath(user): UrlPath<String>,
) -> Response {
    drop_scoped(&sessions, &user, None).await
}

/// `DELETE /auth/users/{ref}/sessions/{id}`: sign one session out, or revoke
/// one API key — the id decides which, by lookup rather than by shape, since
/// the two handles are deliberately spelled alike.
async fn drop_session(
    State(sessions): State<Arc<SessionRepository>>,
    UrlPath((user, session)): UrlPath<(String, String)>,
) -> Response {
    let session: SessionId = match session.parse() {
        Ok(session) => session,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    drop_scoped(&sessions, &user, Some(&session)).await
}

/// The shared tail of the two drop routes: resolve, drop, count what went —
/// sessions and keys each in their own sentence, because "dropped" and
/// "revoked" are different verbs to the person reading.
async fn drop_scoped(
    sessions: &SessionRepository,
    user: &str,
    session: Option<&SessionId>,
) -> Response {
    let user: UserRef = match user.parse() {
        Ok(user) => user,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let (user, dropped, revoked) = match sessions.drop_sessions(&user, session).await {
        Ok(dropped) => dropped,
        Err(error) => return refuse_session(error),
    };

    let mut body = match dropped.as_slice() {
        [] => String::new(),
        [one] => format!("dropped session {} of `{}`\n", one.id, user.slug),
        many => {
            let mut lines = format!("dropped {} sessions of `{}`\n", many.len(), user.slug);
            for session in many {
                lines.push_str(&format!("  {}\n", session.id));
            }

            lines
        }
    };
    match revoked.as_slice() {
        [] => {}
        [one] => body.push_str(&format!(
            "revoked api key {} ({}) of `{}`\n",
            one.id, one.prefix_tail, user.slug
        )),
        many => {
            body.push_str(&format!(
                "revoked {} api keys of `{}`\n",
                many.len(),
                user.slug
            ));
            for key in many {
                body.push_str(&format!("  {} ({})\n", key.id, key.prefix_tail));
            }
        }
    }
    if body.is_empty() {
        body = format!(
            "`{}` had no sessions or api keys — nothing to drop\n",
            user.slug
        );
    }

    (StatusCode::OK, body).into_response()
}

/// `POST /auth/users/{ref}/api-keys/{role}@{app}?expires=…`: mint an API key.
///
/// A POST and not a PUT, unlike a grant, because nothing about a key is
/// idempotent: every mint is a fresh credential, and two keys for the same
/// role at the same app coexist so each caller can be revoked alone. The
/// response is the one place the key is ever shown — stored as a hash, like
/// every credential in the state database — and it carries the same
/// undeclared-role warning a grant does, from the same check: a key is not an
/// entitlement, but "does this open a door today?" is the same question.
async fn mint_api_key(
    State(sessions): State<Arc<SessionRepository>>,
    State(instance): State<Arc<Instance>>,
    UrlPath((user, grants)): UrlPath<(String, String)>,
    Query(query): Query<MintQuery>,
) -> Response {
    let user: UserRef = match user.parse() {
        Ok(user) => user,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };
    let grants: RoleAtApp = match grants.parse() {
        Ok(grants) => grants,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };
    let lifetime = match &query.expires {
        Some(expires) => match crate::duration::parse(expires) {
            Ok(lifetime) => lifetime,
            Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
        },
        None => crate::auth::DEFAULT_API_KEY_LIFETIME,
    };

    let minted = match sessions.mint_api_key(&user, &grants, lifetime).await {
        Ok(minted) => minted,
        Err(error) => return refuse_session(error),
    };

    let mut body = format!(
        "api key for `{}`: {}\n  shown once — it is stored only as a hash\n  id       {}\n  grants   role `{}` at app `{}`\n  expires  {}\n",
        minted.user.slug,
        // The deliberate exposure: this response is the terminal the spec
        // says the key is printed to, exactly once.
        minted.key.expose(),
        minted.id,
        minted.grants.role,
        minted.grants.app,
        minted.expires_at,
    );

    if let Some(warning) = DeclaredRoles::of(instance.applier.repository(), &grants.app)
        .await
        .warning(&grants)
    {
        warn!(entitlement = %grants, "{warning}");
        body.push_str(&format!("  warning: {warning}\n"));
    }

    (StatusCode::OK, body).into_response()
}

/// One mapping from what went wrong to whose problem it is, for every verb on
/// sessions — the shape [`refuse_user`] sets: a mistyped user or session is a
/// 404, a suspended user is a 409 (a state only `resume` changes), and a store
/// that would not answer is a 500.
fn refuse_session(error: SessionError) -> Response {
    let status = match &error {
        SessionError::UnknownUser(_) | SessionError::Nothing(_) => StatusCode::NOT_FOUND,
        SessionError::Suspended(_) => StatusCode::CONFLICT,
        SessionError::Failed(_) => {
            warn!(%error, "a session command failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };

    refuse(status, &error.to_string())
}

/// `GET /auth/log?user=…`: the append-only record, oldest first.
///
/// A table like the listings rather than lines of prose: the log is read to
/// answer "what happened to this user, when", and aligned columns are how a
/// timestamp and a kind scan. An entry about no user leaves the column empty.
async fn auth_log(
    State(log): State<Arc<AuthLogRepository>>,
    Query(query): Query<AuthLogQuery>,
) -> Response {
    let user = match query.user.as_deref().map(str::parse::<UserId>).transpose() {
        Ok(user) => user,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let entries = match log.entries(user.as_ref()).await {
        Ok(entries) => entries,
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not read the auth log: {error:#}"),
            );
        }
    };

    if entries.is_empty() {
        let body = match &user {
            Some(user) => format!("nothing is recorded about `{user}`\n"),
            None => {
                "nothing has happened yet — every auth command that changes something lands here\n"
                    .to_owned()
            }
        };

        return (StatusCode::OK, body).into_response();
    }

    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|entry| {
            vec![
                entry.at.clone(),
                entry.kind.clone(),
                entry.user.clone().unwrap_or_default(),
                entry.origin.clone(),
                entry.detail.clone().unwrap_or_default(),
            ]
        })
        .collect();

    (
        StatusCode::OK,
        columns(&["AT", "KIND", "USER", "ORIGIN", "DETAIL"], &rows),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct AuthLogQuery {
    /// Only the entries about this user id.
    user: Option<String>,
}

/// `POST /auth/keys/rotate`: retire the current JWT signing key and mint a
/// fresh one, now.
///
/// The ninety-day clock does this on its own; this route is for the day a key
/// is suspected compromised and waiting is not an answer. The response says
/// what the retention rule means in the operator's terms, because "rotate"
/// invites the question of whether apps break — they do not: old JWTs verify
/// against the retired key the JWKS keeps serving until every one of them has
/// expired.
async fn rotate_signing_key(State(signer): State<Arc<JwtSigner>>) -> Response {
    let rotation = match signer.rotate(crate::auth::OPERATOR_ORIGIN).await {
        Ok(rotation) => rotation,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "a key rotation failed");

            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not rotate the signing key: {error:#}"),
            );
        }
    };

    let body = match &rotation.retired {
        Some(retired) => format!(
            "rotated the jwt signing key\n  now signing with  {}\n  retired           {retired} — the jwks serves it until every jwt it signed has expired\n",
            rotation.kid
        ),
        None => format!(
            "minted the first jwt signing key {} — there was nothing to retire\n",
            rotation.kid
        ),
    };

    (StatusCode::OK, body).into_response()
}

/// `GET /auth/keys`: every signing key still in the store — the current one,
/// and any retired key whose tokens have not all expired out of the JWKS yet.
async fn list_signing_keys(State(signer): State<Arc<JwtSigner>>) -> Response {
    let keys = match signer.keys().await {
        Ok(keys) => keys,
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("could not list the signing keys: {error:#}"),
            );
        }
    };

    if keys.is_empty() {
        return (
            StatusCode::OK,
            "no signing key yet — the first gated request or jwks read mints one\n",
        )
            .into_response();
    }

    let rows: Vec<Vec<String>> = keys
        .iter()
        .map(|key| {
            vec![
                key.kid.clone(),
                if key.current { "current" } else { "retired" }.to_owned(),
                key.created_at.clone(),
                key.retired_at.clone().unwrap_or_default(),
            ]
        })
        .collect();

    (
        StatusCode::OK,
        columns(&["KID", "STATE", "CREATED", "RETIRED"], &rows),
    )
        .into_response()
}

/// What the deployed manifest says about an app's roles, for the one question
/// grant and audit both ask: does this entitlement open a door?
///
/// Read from [`AppRepository`] — the record of what was applied — rather than
/// from the store of what is running, because a suspended app's roles are
/// still its roles: an operator granting ahead of a resume is doing the
/// ordinary thing, and warning them would be crying wolf.
enum DeclaredRoles {
    /// Spaceport runs no app under that id.
    Unknown,
    /// The app is recorded, but its stored manifest would not read — written
    /// by a newer build, most likely. Carries why, because "could not check"
    /// with no reason is the least useful warning there is.
    Unreadable(String),
    /// `gating: open` — the app declares no roles, and no entitlement can
    /// open a door that is not closed.
    Open,
    /// `gating: edge`, with these roles.
    Declares(Vec<Role>),
}

impl DeclaredRoles {
    async fn of(apps: &AppRepository, app: &AppId) -> Self {
        let record = match apps.recorded(app).await {
            Ok(Some(record)) => record,
            Ok(None) => return Self::Unknown,
            Err(error) => return Self::Unreadable(format!("{error:#}")),
        };

        match AppManifest::parse(&record.manifest) {
            Ok(manifest) => match manifest.auth {
                crate::app::Auth::Edge { roles, .. } => Self::Declares(roles),
                crate::app::Auth::Open {} => Self::Open,
            },
            Err(error) => Self::Unreadable(format!("{error:#}")),
        }
    }

    /// Whether an entitlement for `role` grants access, as far as the
    /// deployed manifest is concerned. `Unreadable` answers `false`: a warning
    /// that turns out unnecessary costs a shrug, access claimed on a manifest
    /// nobody could read costs trust.
    fn declares(&self, role: &Role) -> bool {
        match self {
            Self::Declares(roles) => roles.contains(role),
            Self::Unknown | Self::Unreadable(_) | Self::Open => false,
        }
    }

    /// The warning a grant for `role` deserves, or `None` for a grant that
    /// opens a door today.
    fn warning(&self, entitlement: &RoleAtApp) -> Option<String> {
        let RoleAtApp { role, app } = entitlement;

        match self {
            Self::Unknown => Some(format!(
                "spaceport runs no app `{app}` — the entitlement is stored, and takes effect \
                 if an app by that id declares role `{role}`"
            )),
            Self::Unreadable(reason) => Some(format!(
                "whether `{app}` declares role `{role}` could not be checked: {reason}"
            )),
            Self::Open => Some(format!(
                "app `{app}` is `gating: open` and declares no roles — the entitlement is \
                 stored but gates nothing"
            )),
            Self::Declares(_) if !self.declares(role) => Some(format!(
                "app `{app}` does not declare role `{role}` in its manifest — the entitlement \
                 is stored but grants no access until it does"
            )),
            Self::Declares(_) => None,
        }
    }
}

/// `PUT /auth/users/{ref}/entitlements/{role}@{app}`: let this user hold this
/// role at this app.
///
/// A `PUT` because the triple is the identity, exactly as an apply's id is:
/// granting what is already granted lands on the row that exists and says so,
/// rather than erroring or duplicating. The grant succeeds even when the app
/// does not declare the role — the spec stores it with a warning, because
/// granting ahead of a deploy is the ordinary order of operations — and the
/// warning goes to both the operator and the log stream, since the operator
/// reading it now and the one grepping later are usually different people.
async fn grant_entitlement(
    State(entitlements): State<Arc<EntitlementRepository>>,
    State(instance): State<Arc<Instance>>,
    UrlPath((user, scope)): UrlPath<(String, String)>,
) -> Response {
    let user: UserRef = match user.parse() {
        Ok(user) => user,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };
    let entitlement: RoleAtApp = match scope.parse() {
        Ok(entitlement) => entitlement,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let granted = match entitlements.grant(&user, &entitlement).await {
        Ok(granted) => granted,
        Err(error) => return refuse_entitlement(error),
    };

    let mut body = match &granted {
        Granted::Fresh(user) => format!("granted `{entitlement}` to `{}`\n", user.slug),
        Granted::Already(user, None) => format!(
            "`{entitlement}` was already granted to `{}` — nothing changed\n",
            user.slug
        ),
        Granted::Already(user, Some(rule)) => format!(
            "`{entitlement}` is already mapped to `{}` from SSO by rule `{rule}` — nothing \
             changed, and dropping that rule would take it away again\n",
            user.slug
        ),
    };

    if let Some(warning) = DeclaredRoles::of(instance.applier.repository(), &entitlement.app)
        .await
        .warning(&entitlement)
    {
        warn!(%entitlement, "{warning}");
        body.push_str(&format!("  warning: {warning}\n"));
    }

    (StatusCode::OK, body).into_response()
}

/// `DELETE /auth/users/{ref}/entitlements/{[role@]app}`: take one role away,
/// or every role at one app.
async fn revoke_entitlement(
    State(entitlements): State<Arc<EntitlementRepository>>,
    UrlPath((user, scope)): UrlPath<(String, String)>,
) -> Response {
    let scope: RevokeScope = match scope.parse() {
        Ok(scope) => scope,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    revoke_scoped(&entitlements, &user, Some(&scope)).await
}

/// `DELETE /auth/users/{ref}/entitlements`: the whole slate, across apps —
/// what the CLI spells `--all`, and deliberately a different route from naming
/// an app, so nothing ambiguous can ever mean "everything".
async fn revoke_all_entitlements(
    State(entitlements): State<Arc<EntitlementRepository>>,
    UrlPath(user): UrlPath<String>,
) -> Response {
    revoke_scoped(&entitlements, &user, None).await
}

/// The shared tail of the two revoke routes: resolve, revoke, and say what
/// went and what a mapping held on to.
async fn revoke_scoped(
    entitlements: &EntitlementRepository,
    user: &str,
    scope: Option<&RevokeScope>,
) -> Response {
    let user: UserRef = match user.parse() {
        Ok(user) => user,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let Revoked {
        user,
        removed,
        kept,
    } = match entitlements.revoke(&user, scope).await {
        Ok(revoked) => revoked,
        Err(error) => return refuse_entitlement(error),
    };

    let mut body = match removed.as_slice() {
        [one] => format!("revoked `{one}` from `{}`\n", user.slug),
        many => {
            let mut lines = format!("revoked {} entitlements from `{}`\n", many.len(), user.slug);
            for entitlement in many {
                lines.push_str(&format!("  {entitlement}\n"));
            }

            lines
        }
    };
    // The rows a mapping holds are named rather than silently skipped: an
    // operator who asked for "everything at blog" should leave knowing what
    // is still standing and which command actually removes it.
    for (entitlement, rule) in &kept {
        body.push_str(&format!(
            "  kept `{entitlement}` — mapped from SSO by rule `{rule}`, which is what removes it\n"
        ));
    }

    (StatusCode::OK, body).into_response()
}

/// `GET /auth/users/{ref}/audit`: one user's whole standing — who they are,
/// how they sign in, what they hold, and where that actually gets them.
///
/// The last two are deliberately different sections. An entitlement is stored
/// whether or not the app declares its role, so "what they hold" is the table
/// as it is; "access" is the spec's judgement over it — the apps where at
/// least one entitled role is declared — and an entitlement that grants
/// nothing is flagged in place rather than hidden, because a grant that
/// silently does nothing is precisely what an audit exists to surface.
async fn audit_user(
    State(entitlements): State<Arc<EntitlementRepository>>,
    State(instance): State<Arc<Instance>>,
    UrlPath(user): UrlPath<String>,
) -> Response {
    let user: UserRef = match user.parse() {
        Ok(user) => user,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    let (user, held) = match entitlements.audit(&user).await {
        Ok(audited) => audited,
        Err(error) => return refuse_entitlement(error),
    };

    let mut out = Report::default();
    out.field("user", user.slug.to_string());
    out.field("id", user.id.to_string());
    out.field("status", user_status(&user).to_owned());
    if let Some(email) = &user.email {
        out.field("email", email.clone());
    }
    // Said rather than omitted: an auditor looking for the SSO connection the
    // spec promises should read that there is none to look for yet, not wonder
    // whether the report forgot it.
    out.field("sso", "none — SSO is a later milestone".to_owned());

    // What each app's manifest declares, asked once per app rather than once
    // per entitlement: an audit of a user with twelve roles at one app is
    // still one read of that app's record.
    let mut declared: std::collections::BTreeMap<AppId, DeclaredRoles> = Default::default();
    for entitlement in &held {
        if !declared.contains_key(&entitlement.app) {
            declared.insert(
                entitlement.app.clone(),
                DeclaredRoles::of(instance.applier.repository(), &entitlement.app).await,
            );
        }
    }

    let access: Vec<String> = declared
        .iter()
        .filter(|(app, roles)| {
            held.iter()
                .any(|entitlement| &&entitlement.app == app && roles.declares(&entitlement.role))
        })
        .map(|(app, _)| app.to_string())
        .collect();
    out.field(
        "access",
        match access.is_empty() {
            true => "no app — no entitled role is declared by a deployed manifest".to_owned(),
            false => access.join(", "),
        },
    );

    let mut body = out.render();
    if held.is_empty() {
        body.push_str(
            "\nno entitlements — `spaceport auth grant` is what hands out the first one\n",
        );

        return (StatusCode::OK, body).into_response();
    }

    let rows: Vec<Vec<String>> = held
        .iter()
        .map(|entitlement| {
            vec![
                format!("{}@{}", entitlement.role, entitlement.app),
                match &entitlement.mapped_rule {
                    Some(rule) => format!("mapped by rule `{rule}`"),
                    None => "manual".to_owned(),
                },
                match declared[&entitlement.app].declares(&entitlement.role) {
                    true => "yes".to_owned(),
                    false => "no — role not declared by the app".to_owned(),
                },
                entitlement.granted_at.clone(),
            ]
        })
        .collect();
    body.push('\n');
    body.push_str(&columns(
        &["ENTITLEMENT", "ORIGIN", "ACCESS", "GRANTED"],
        &rows,
    ));

    (StatusCode::OK, body).into_response()
}

/// One mapping from what went wrong to whose problem it is, for every verb on
/// entitlements — the shape [`refuse_user`] sets: a mistyped user or a revoke
/// that matched nothing is a 404, a revoke that only mapped rows answered is a
/// 409 (a conflict only a mapping command resolves), and a store that would
/// not answer is a 500.
fn refuse_entitlement(error: EntitlementError) -> Response {
    let status = match &error {
        EntitlementError::UnknownUser(_) | EntitlementError::Nothing(_) => StatusCode::NOT_FOUND,
        EntitlementError::Mapped(_) => StatusCode::CONFLICT,
        EntitlementError::Failed(_) => {
            warn!(%error, "an entitlement command failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };

    refuse(status, &error.to_string())
}

fn refuse(status: StatusCode, message: &str) -> Response {
    (status, format!("{message}\n")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{App, AppRepository, AppStore, SecretRepository};
    use crate::connections::github::api::testing::{FakeGitHub, HEAD};
    use crate::events::Level;
    use crate::runtime::{Container, ContainerId, ContainerRuntime, Managed};
    use crate::state::Db;
    use async_trait::async_trait;
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use std::collections::{BTreeMap, HashMap};
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;
    use tracing_subscriber::layer::SubscriberExt as _;

    /// Every app it starts ends up at the same address, which nothing is
    /// listening on unless a test says otherwise.
    struct OneContainer {
        upstream: SocketAddr,
        /// How many containers it has been asked to build.
        ///
        /// The one thing a fake runtime can say that the store cannot: every
        /// container it makes has the same id, so "was this app given a fresh
        /// container?" is not a question the routing table answers. Shared
        /// rather than owned, so a test can still read it after the runtime has
        /// gone into the applier.
        launches: Arc<AtomicUsize>,
        /// The environment the last container of each app was launched with,
        /// rendered as the engine would see it — the one place a secret's value
        /// is supposed to appear, and the only place a test can check that a
        /// value set over HTTP reached the process that was going to read it.
        environments: Arc<Mutex<HashMap<AppId, BTreeMap<VarName, String>>>>,
        /// The containers it has been asked to remove, so that a test can tell
        /// an app that stopped being routed to from one whose container really
        /// went away with it.
        removed: Arc<Mutex<Vec<ContainerId>>>,
    }

    impl Default for OneContainer {
        fn default() -> Self {
            Self {
                upstream: SocketAddr::from(([127, 0, 0, 1], 9000)),
                launches: Arc::default(),
                environments: Arc::default(),
                removed: Arc::default(),
            }
        }
    }

    #[async_trait]
    impl ContainerRuntime for OneContainer {
        async fn launch(&self, app: &AppId, manifest: &AppManifest) -> Result<Container> {
            self.launches.fetch_add(1, Ordering::SeqCst);
            // Rendered exactly where the real runtime renders it, and refused
            // exactly where it refuses: a manifest whose placeholders nothing
            // has filled in cannot become an environment. A fake that ignored
            // the manifest would pass every secret test in this file even if
            // interpolation did nothing at all.
            self.environments
                .lock()
                .unwrap()
                .insert(app.clone(), manifest.container.environment()?);

            Ok(Container {
                id: ContainerId::new(format!("{app}0123456789abcdef")),
                upstream: self.upstream,
            })
        }

        async fn remove(&self, id: &ContainerId) -> Result<()> {
            self.removed.lock().unwrap().push(id.clone());

            Ok(())
        }

        async fn stop(&self, _id: &ContainerId) -> Result<()> {
            Ok(())
        }

        async fn start(&self, id: &ContainerId, _manifest: &AppManifest) -> Result<Container> {
            Ok(Container {
                id: id.clone(),
                upstream: self.upstream,
            })
        }

        /// Nothing here reconciles, so nothing here has leftovers.
        async fn managed(&self) -> Result<Vec<Managed>> {
            Ok(Vec::new())
        }
    }

    const CONFIG: &str = "schema_version: 1
edge:
  listen:
    http: 0.0.0.0:8080
    https: 0.0.0.0:8443
";

    /// A second commit, for the tests that move an app from one branch to
    /// another and have to tell the two heads apart.
    const OTHER_HEAD: &str = "89abcdef0123456789abcdef0123456789abcdef";

    const MANIFEST: &str = "schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [alpha.test]
auth:
  gating: open
container:
  health:
    readiness:
      type: none
";

    /// The same manifest, under a host of its own.
    fn manifest_for(host: &str) -> String {
        MANIFEST.replace("alpha.test", host)
    }

    fn store_and_router() -> (Arc<AppStore>, Router) {
        store_and_router_on(OneContainer::default())
    }

    fn store_and_router_on(runtime: OneContainer) -> (Arc<AppStore>, Router) {
        let (store, router, _) = store_router_and_events_on(runtime);

        (store, router)
    }

    fn router_and_events() -> (Router, Arc<EventBus>) {
        let (_, router, events, _, _, _, _, _, _, _) = parts_on(OneContainer::default());

        (router, events)
    }

    /// A router and the GitHub behind it, for the connection tests — which are
    /// the only ones that care what GitHub answers.
    fn router_and_github() -> (Router, Arc<FakeGitHub>) {
        let (_, router, _, _, github, _, _, _, _, _) = parts_on(OneContainer::default());

        (router, github)
    }

    fn store_router_and_events_on(runtime: OneContainer) -> (Arc<AppStore>, Router, Arc<EventBus>) {
        let (store, router, events, _, _, _, _, _, _, _) = parts_on(runtime);

        (store, router, events)
    }

    /// Everything a test might want a hand on, shutdown token included.
    ///
    /// A tuple and not a struct, because every test takes it apart on the line
    /// it is built and names only the two or three pieces it uses. Named as a
    /// type only so that the shape is written once.
    type Parts = (
        Arc<AppStore>,
        Router,
        Arc<EventBus>,
        CancellationToken,
        Arc<FakeGitHub>,
        Arc<ConnectionRepository>,
        Arc<TrackingRepository>,
        Arc<BuildRepository>,
        // The shove a track gives the build worker, which is the only way a
        // test can see that the worker was told at all.
        Nudge,
        // And the one a resume or a track gives the deploying worker, which is
        // the only way a test can see that a built revision waiting on a
        // suspension will be looked at now rather than in five minutes.
        Nudge,
    );

    fn parts_on(runtime: OneContainer) -> Parts {
        parts_configured(runtime, CONFIG)
    }

    /// A router over a spaceport that answers to a hostname of its own, which
    /// is the only thing the manifest flow needs and nothing else here has.
    fn router_answering_to_a_hostname() -> Router {
        let config = CONFIG.replace("edge:\n", "edge:\n  hostname: spaceport.example.com\n");

        parts_configured(OneContainer::default(), &config).1
    }

    fn parts_configured(runtime: OneContainer, config: &str) -> Parts {
        parts_with_state(runtime, config).0
    }

    /// The same, and the two things behind the router that no route exposes:
    /// the state database, for a test that has to read what a route recorded,
    /// and the applier, for one that has to put an app into a state no request
    /// can ask for — a record that disagrees with the store, say.
    fn parts_with_state(runtime: OneContainer, config: &str) -> (Parts, Db, Arc<Applier>) {
        let store = Arc::new(AppStore::new());
        let db = Db::in_memory().unwrap();
        let applier = Arc::new(Applier::new(
            store.clone(),
            Arc::new(runtime),
            AppRepository::new(db.clone()),
            BuildRepository::new(db.clone()),
            SecretRepository::new(db.clone()),
        ));
        let events = Arc::new(EventBus::new());
        let shutdown = CancellationToken::new();
        let github = FakeGitHub::new();
        // The two apps the connection tests register, so that `/app` can answer
        // as whichever of them signed.
        github.app_is(
            42,
            "spaceport-acme",
            "Spaceport for Acme",
            "an-organisation",
        );
        github.also_hosts(
            43,
            "spaceport-other",
            "Spaceport for Acme",
            "an-organisation",
        );

        let connections = Arc::new(ConnectionRepository::new(db.clone()));
        let tracking = Arc::new(TrackingRepository::new(db.clone()));
        let builds = Arc::new(BuildRepository::new(db.clone()));
        // Held rather than made in place, so that a test can watch it: this is
        // the builder's signal and emphatically not the reconciler's.
        let building = Nudge::new();
        // Held for the same reason, and apart from it: they are two loops.
        let deploying = Nudge::new();
        let instance = Arc::new(Instance {
            version: "9.9.9".to_owned(),
            started_at: time::OffsetDateTime::now_utc(),
            config_path: "/etc/spaceport/spaceport.yaml".into(),
            config: crate::Config::parse(config).unwrap(),
            operator: "/run/spaceport.sock".parse().unwrap(),
            applier,
            connections: connections.clone(),
            tracking: tracking.clone(),
            builds: builds.clone(),
            github: github.clone(),
            attempts: Arc::new(crate::connections::github::Attempts::new()),
            nudge: Nudge::new(),
            building: building.clone(),
            deploying: deploying.clone(),
            users: Arc::new(UserRepository::new(db.clone())),
            auth_log: Arc::new(AuthLogRepository::new(db.clone())),
            entitlements: Arc::new(EntitlementRepository::new(db.clone())),
            sessions: Arc::new(SessionRepository::new(db.clone())),
            signer: Arc::new(JwtSigner::new(db.clone())),
            db: db.clone(),
            certificates: None,
            reconciled: crate::app::reconcile::Report::default(),
        });
        let applier = instance.applier.clone();

        (
            (
                store,
                router(instance, events.clone(), shutdown.clone()),
                events,
                shutdown,
                github,
                connections,
                tracking,
                builds,
                building,
                deploying,
            ),
            db,
            applier,
        )
    }

    /// An event as a call site would have produced it.
    fn event(level: Level, app: Option<&str>, message: &str) -> Event {
        Event {
            app: app.map(|app| app.parse().unwrap()),
            ..Event::now(level, "app.apply", message)
        }
    }

    /// The next line of a stream, which is a response that never completes —
    /// so it is read a frame at a time rather than collected.
    async fn next_line(body: &mut axum::body::BodyDataStream) -> Event {
        let bytes = body
            .next()
            .await
            .expect("the stream had a line")
            .expect("the line arrived intact");
        let line = String::from_utf8(bytes.to_vec()).unwrap();

        serde_json::from_str(line.trim_end()).expect("a line of the stream is an event")
    }

    async fn watch(router: &Router, query: &str) -> axum::body::BodyDataStream {
        let request = Request::builder()
            .uri(format!("/events{query}"))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[http::header::CONTENT_TYPE],
            "application/x-ndjson"
        );

        response.into_body().into_data_stream()
    }

    async fn put_app(router: &Router, id: &str, manifest: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/apps/{id}"))
            .body(Body::from(manifest.to_owned()))
            .unwrap();

        call(router, request).await
    }

    async fn call(router: &Router, request: Request<Body>) -> (StatusCode, String) {
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    async fn get_apps(router: &Router, query: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .uri(format!("/apps{query}"))
            .body(Body::empty())
            .unwrap();

        call(router, request).await
    }

    async fn show_app(router: &Router, id: &str, query: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .uri(format!("/apps/{id}{query}"))
            .body(Body::empty())
            .unwrap();

        call(router, request).await
    }

    /// A manifest that uses every part of a container an app can configure.
    ///
    /// Readiness is `none` for the same reason `MANIFEST`'s is: nothing is
    /// listening at the fake runtime's address, so any real check would spend
    /// its whole budget failing before the app was ever applied.
    const CONFIGURED: &str = "# an app with everything on
schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [alpha.test, beta.test]
auth:
  gating: open
container:
  port: 8080
  health:
    readiness:
      type: none
  volumes:
    - name: data
      mount: /var/lib/my-app/data
  env:
    ENVIRONMENT: production
";

    #[tokio::test]
    async fn shows_a_running_app() {
        let (_, router) = store_and_router();
        put_app(&router, "web-api", CONFIGURED).await;

        let (status, body) = show_app(&router, "web-api", "").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("app        web-api"), "{body}");
        assert!(body.contains("image strm/helloworld-http:latest"), "{body}");
        assert!(body.contains("alpha.test, beta.test"), "{body}");
        assert!(body.contains("127.0.0.1:9000"), "{body}");
        // Short, the way the engine's own tools print one.
        assert!(body.contains("web-api01234"), "{body}");
        assert!(body.contains("8080"), "{body}");
    }

    /// How an app is watched is the answer to "why is this not being
    /// restarted?", and it is nowhere else in the operator interface.
    ///
    /// Applied suspended so that nothing tries to run the checks: this is
    /// about how they are reported, not whether they pass.
    #[tokio::test]
    async fn shows_the_checks_an_app_is_watched_with() {
        let (_, router) = store_and_router();
        let manifest = "schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [alpha.test]
auth:
  gating: open
container:
  health:
    readiness:
      type: http
      path: /healthz
    liveness:
      type: tcp
      interval: 10s
      failure_threshold: 3
";
        put_app_suspended(&router, "web-api", manifest).await;

        let (_, body) = show_app(&router, "web-api", "").await;

        assert!(body.contains("http /healthz"), "{body}");
        assert!(body.contains("tcp connect"), "{body}");
        assert!(body.contains("3 failures"), "{body}");
    }

    /// An app that named no port is described as having named none. What the
    /// image exposes is the engine's business, and reporting the resolved port
    /// as though the manifest had said it would be putting words in it.
    #[tokio::test]
    async fn says_when_a_port_comes_from_the_image() {
        let (_, router) = store_and_router();
        put_app(&router, "web-api", MANIFEST).await;

        let (_, body) = show_app(&router, "web-api", "").await;

        assert!(body.contains("from the image"), "{body}");
    }

    /// The point of the command: what an app was given is nowhere else in the
    /// operator interface, and `apps list` has no room for it.
    #[tokio::test]
    async fn shows_the_configuration_an_app_was_given() {
        let (_, router) = store_and_router();
        put_app(&router, "web-api", CONFIGURED).await;

        let (_, body) = show_app(&router, "web-api", "").await;

        assert!(body.contains("ENVIRONMENT=production"), "{body}");
        // The volume, and where it actually is on the host — which the
        // manifest never says, because spaceport is the one that decides it.
        assert!(body.contains("data at /var/lib/my-app/data"), "{body}");
        assert!(
            body.contains("/var/lib/spaceport/apps/web-api/data"),
            "{body}"
        );
    }

    /// An app that never asked for a liveness check should be able to see that
    /// it does not have one, since that is the answer to "why was this not
    /// restarted?".
    #[tokio::test]
    async fn says_when_an_app_has_no_liveness_check() {
        let (_, router) = store_and_router();
        put_app(&router, "web-api", MANIFEST).await;

        let (_, body) = show_app(&router, "web-api", "").await;

        assert!(body.contains("liveness"), "{body}");
        assert!(body.contains("none"), "{body}");
    }

    /// Byte for byte, so it can be written to a file and applied again.
    #[tokio::test]
    async fn shows_the_manifest_verbatim_when_asked_for_it() {
        let (_, router) = store_and_router();
        put_app(&router, "web-api", CONFIGURED).await;

        let (status, body) = show_app(&router, "web-api", "?manifest=true").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, CONFIGURED);
        // Including the comment, which is the part a re-serialisation would
        // have quietly dropped.
        assert!(body.starts_with("# an app with everything on"), "{body}");
    }

    #[tokio::test]
    async fn shows_a_suspended_app_as_suspended() {
        let (_, router) = store_and_router();
        put_app_suspended(&router, "web-api", MANIFEST).await;

        let (status, body) = show_app(&router, "web-api", "").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("suspended"), "{body}");
        // It claims its hosts all the same, and that is why.
        assert!(body.contains("alpha.test"), "{body}");
    }

    #[tokio::test]
    async fn refuses_to_show_an_app_nobody_applied() {
        let (_, router) = store_and_router();

        let (status, body) = show_app(&router, "web-api", "").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("no app named `web-api`"), "{body}");
    }

    #[tokio::test]
    async fn refuses_an_app_id_that_is_not_one() {
        let (_, router) = store_and_router();

        let (status, _) = show_app(&router, "Web_API", "").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    async fn delete_app(router: &Router, id: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/apps/{id}"))
            .body(Body::empty())
            .unwrap();

        call(router, request).await
    }

    async fn put_app_suspended(router: &Router, id: &str, manifest: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/apps/{id}?suspended=true"))
            .body(Body::from(manifest.to_owned()))
            .unwrap();

        call(router, request).await
    }

    async fn suspend_app(router: &Router, id: &str, stop: bool) -> (StatusCode, String) {
        let uri = match stop {
            true => format!("/apps/{id}/suspend?stop_container=true"),
            false => format!("/apps/{id}/suspend"),
        };
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        call(router, request).await
    }

    async fn resume_app(router: &Router, id: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/apps/{id}/resume"))
            .body(Body::empty())
            .unwrap();

        call(router, request).await
    }

    #[tokio::test]
    async fn suspends_and_resumes_an_app() {
        let (store, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;

        let (status, body) = suspend_app(&router, "hello", false).await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("app `hello` suspended"), "{body}");
        assert!(body.contains("still claims its hosts"), "{body}");
        assert!(store.routes().serving("alpha.test").is_none());

        let (status, body) = resume_app(&router, "hello").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("app `hello` resumed"), "{body}");
        assert!(store.routes().serving("alpha.test").is_some());
    }

    /// A push during a suspension is built and, correctly, not deployed — so
    /// the moment the app comes back is the moment that image becomes
    /// deployable, with nothing being built to say so. Without this shove the
    /// operator watches a commit they can see was built sit there for the
    /// length of the deploying loop's interval.
    #[tokio::test]
    async fn resuming_an_app_wakes_the_deploying_worker() {
        let (_, router, _, _, _, _, _, _, _, deploying) = parts_on(OneContainer::default());
        put_app(&router, "hello", MANIFEST).await;
        suspend_app(&router, "hello", false).await;
        let woken = deploying.changed();

        resume_app(&router, "hello").await;

        assert!(woken.has_changed().unwrap());
    }

    /// A resume that did not happen is not a deployment to go looking for: the
    /// app is exactly where it was, which is what the loop already believes.
    #[tokio::test]
    async fn a_resume_that_failed_wakes_nothing() {
        let (_, router, _, _, _, _, _, _, _, deploying) = parts_on(OneContainer::default());
        let woken = deploying.changed();

        assert_eq!(resume_app(&router, "ghost").await.0, StatusCode::NOT_FOUND);

        assert!(!woken.has_changed().unwrap());
    }

    #[tokio::test]
    async fn says_which_way_the_container_went() {
        let (_, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;

        let (_, kept) = suspend_app(&router, "hello", false).await;
        assert!(kept.contains("left running"), "{kept}");

        let (_, stopped) = suspend_app(&router, "hello", true).await;
        assert!(stopped.contains("stopped and kept"), "{stopped}");
    }

    #[tokio::test]
    async fn suspending_an_unknown_app_is_not_found() {
        let (_, router) = store_and_router();

        let (status, _) = suspend_app(&router, "ghost", false).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(resume_app(&router, "ghost").await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn applies_an_app_into_suspension() {
        let (store, router) = store_and_router();

        let (status, body) = put_app_suspended(&router, "hello", MANIFEST).await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("applied, suspended"), "{body}");
        assert!(body.contains("spaceport apps resume hello"), "{body}");
        assert!(store.apps().is_empty());
        // Claimed, so its certificates are ordered before it ever runs.
        assert!(store.routes().hosts().contains("alpha.test"));
    }

    /// A suspended app is one of the apps spaceport has, and listing them
    /// without it would have an operator think it was destroyed.
    #[tokio::test]
    async fn lists_a_suspended_app_with_the_rest() {
        let (_, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;
        suspend_app(&router, "hello", false).await;

        let (status, body) = get_apps(&router, "").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("hello"), "{body}");
        assert!(body.contains("suspended"), "{body}");
    }

    #[tokio::test]
    async fn a_suspended_app_still_holds_its_host_against_another() {
        let (_, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;
        suspend_app(&router, "hello", false).await;

        let (status, body) = put_app(&router, "other", MANIFEST).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.contains("already claimed by app `hello`"), "{body}");
    }

    #[tokio::test]
    async fn destroys_a_suspended_app() {
        let (store, router) = store_and_router();
        put_app_suspended(&router, "hello", MANIFEST).await;

        let (status, body) = delete_app(&router, "hello").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("no container"), "{body}");
        assert!(store.routes().is_empty());
    }

    #[tokio::test]
    async fn applies_a_manifest() {
        let (store, router) = store_and_router();

        let (status, body) = put_app(&router, "hello", MANIFEST).await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("app `hello` applied"), "{body}");
        assert!(body.contains("127.0.0.1:9000"), "{body}");
        assert!(body.contains("alpha.test"), "{body}");
        assert!(store.routes().serving("alpha.test").is_some());
    }

    #[tokio::test]
    async fn rejects_an_unparseable_manifest() {
        let (store, router) = store_and_router();

        let (status, body) = put_app(&router, "hello", "schema_version: 9\n").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("unsupported schema version 9"), "{body}");
        assert!(store.apps().is_empty());
    }

    #[tokio::test]
    async fn rejects_an_unusable_app_id() {
        let (_, router) = store_and_router();

        let (status, body) = put_app(&router, "Hello", MANIFEST).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("lowercase"), "{body}");
    }

    #[tokio::test]
    async fn reports_a_host_conflict_as_such() {
        let (store, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;

        let (status, body) = put_app(&router, "other", MANIFEST).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.contains("already claimed by app `hello`"), "{body}");
        assert_eq!(store.apps().len(), 1);
    }

    #[tokio::test]
    async fn re_applying_an_app_succeeds() {
        let (store, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;

        let (status, _) = put_app(&router, "hello", MANIFEST).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(store.apps().len(), 1);
    }

    /// The whole point of the container id in the response is naming a
    /// container the operator can then look at, so it has to be the short form
    /// `docker ps` shows.
    #[tokio::test]
    async fn names_the_container_the_way_docker_does() {
        let (_, router) = store_and_router();

        let (_, body) = put_app(&router, "hello", MANIFEST).await;

        assert!(body.contains("container hello0123456\n"), "{body}");
    }

    #[tokio::test]
    async fn lists_every_app_with_its_source_and_hosts() {
        let (_, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;
        put_app(&router, "other", &manifest_for("beta.test")).await;

        let (status, body) = get_apps(&router, "").await;

        assert_eq!(status, StatusCode::OK);
        let lines: Vec<&str> = body.lines().collect();
        assert!(lines[0].starts_with("APP"), "{body}");
        assert!(lines[0].contains("SOURCE"), "{body}");
        assert!(lines[1].starts_with("hello"), "{body}");
        assert!(
            lines[1].contains("image strm/helloworld-http:latest"),
            "{body}"
        );
        assert!(lines[1].ends_with("alpha.test"), "{body}");
        assert!(lines[2].starts_with("other"), "{body}");
        assert!(lines[2].ends_with("beta.test"), "{body}");
    }

    /// Columns only pay for themselves if they line up.
    #[tokio::test]
    async fn lines_the_columns_up() {
        let (_, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;
        put_app(
            &router,
            "a-much-longer-app-name",
            &manifest_for("beta.test"),
        )
        .await;

        let (_, body) = get_apps(&router, "").await;

        let at = |line: &str| line.find("image").unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(at(lines[1]), at(lines[2]), "{body}");
    }

    #[tokio::test]
    async fn says_when_nothing_is_running() {
        let (_, router) = store_and_router();

        let (status, body) = get_apps(&router, "").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "no apps are running\n");
    }

    #[tokio::test]
    async fn lists_only_the_apps_a_pattern_matches() {
        let (_, router) = store_and_router();
        put_app(&router, "web-api", MANIFEST).await;
        put_app(&router, "web-ui", &manifest_for("beta.test")).await;
        put_app(&router, "worker", &manifest_for("gamma.test")).await;

        let (status, body) = get_apps(&router, "?pattern=web-*").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("web-api"), "{body}");
        assert!(body.contains("web-ui"), "{body}");
        assert!(!body.contains("worker"), "{body}");
    }

    #[tokio::test]
    async fn says_when_a_pattern_matches_nothing() {
        let (_, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;

        let (status, body) = get_apps(&router, "?pattern=web-*").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "no app matches `web-*`\n");
    }

    #[tokio::test]
    async fn rejects_an_empty_pattern() {
        let (_, router) = store_and_router();

        let (status, body) = get_apps(&router, "?pattern=").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("must not be empty"), "{body}");
    }

    #[tokio::test]
    async fn reports_an_app_that_answers_as_ready() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_, router) = store_and_router_on(OneContainer {
            upstream: listener.local_addr().unwrap(),
            ..OneContainer::default()
        });
        put_app(&router, "hello", MANIFEST).await;

        let (_, body) = get_apps(&router, "").await;

        assert!(body.contains("ready"), "{body}");
    }

    /// The status is worth having precisely because the store cannot tell:
    /// this app was applied and routed, and is not answering any more.
    #[tokio::test]
    async fn reports_an_app_that_does_not_answer_as_unreachable() {
        let (_, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;

        let (_, body) = get_apps(&router, "").await;

        assert!(body.contains("unreachable"), "{body}");
    }

    #[tokio::test]
    async fn destroys_an_app() {
        let (store, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;

        let (status, body) = delete_app(&router, "hello").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("app `hello` destroyed"), "{body}");
        assert!(body.contains("container hello0123456"), "{body}");
        assert!(store.apps().is_empty());
        assert!(store.routes().serving("alpha.test").is_none());
    }

    /// And the host it was serving is free for the next app to claim.
    #[tokio::test]
    async fn a_destroyed_app_stops_holding_its_hosts() {
        let (store, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;
        delete_app(&router, "hello").await;

        let (status, _) = put_app(&router, "other", MANIFEST).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            store.routes().serving("alpha.test").unwrap().id.as_str(),
            "other"
        );
    }

    #[tokio::test]
    async fn destroying_an_unknown_app_is_a_404() {
        let (_, router) = store_and_router();

        let (status, body) = delete_app(&router, "ghost").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("no app named `ghost`"), "{body}");
    }

    #[tokio::test]
    async fn destroying_an_unusable_app_id_is_refused() {
        let (_, router) = store_and_router();

        let (status, body) = delete_app(&router, "Ghost").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("lowercase"), "{body}");
    }

    #[tokio::test]
    async fn streams_events_as_they_are_emitted() {
        let (router, events) = router_and_events();
        let mut stream = watch(&router, "").await;

        events.emit(event(Level::Info, Some("web-api"), "app is ready"));

        let event = next_line(&mut stream).await;
        assert_eq!(event.message, "app is ready");
        assert_eq!(event.app.unwrap().as_str(), "web-api");
        assert_eq!(event.category.as_str(), "app.apply");
    }

    #[tokio::test]
    async fn streams_only_the_app_that_was_asked_for() {
        let (router, events) = router_and_events();
        let mut stream = watch(&router, "?app=web-*").await;

        events.emit(event(Level::Info, Some("worker"), "not this one"));
        events.emit(event(Level::Info, Some("web-api"), "this one"));

        assert_eq!(next_line(&mut stream).await.message, "this one");
    }

    #[tokio::test]
    async fn streams_only_the_category_that_was_asked_for() {
        let (router, events) = router_and_events();
        let mut stream = watch(&router, "?category=acme").await;

        events.emit(event(Level::Info, None, "not this one"));
        events.emit(Event::now(Level::Info, "acme", "got a certificate"));

        assert_eq!(next_line(&mut stream).await.message, "got a certificate");
    }

    /// The whole point of the history: the interesting thing has already
    /// happened by the time anyone thinks to watch.
    #[tokio::test]
    async fn sends_what_happened_before_the_watcher_arrived() {
        let (router, events) = router_and_events();
        events.emit(event(Level::Warn, Some("web-api"), "apply failed"));

        let mut stream = watch(&router, "?history=10").await;

        assert_eq!(next_line(&mut stream).await.message, "apply failed");
    }

    #[tokio::test]
    async fn a_watcher_that_asked_for_no_history_starts_from_now() {
        let (router, events) = router_and_events();
        events.emit(event(Level::Info, None, "before"));

        let mut stream = watch(&router, "").await;
        events.emit(event(Level::Info, None, "after"));

        assert_eq!(next_line(&mut stream).await.message, "after");
    }

    /// A stream that outlived the shutdown would be a response still in
    /// flight, and a graceful shutdown waits for those: the process would hang
    /// for as long as anyone was watching it.
    #[tokio::test]
    async fn a_watcher_is_let_go_when_spaceport_shuts_down() {
        let (_, router, _, shutdown, _, _, _, _, _, _) = parts_on(OneContainer::default());
        let mut stream = watch(&router, "").await;

        shutdown.cancel();

        assert!(
            stream.next().await.is_none(),
            "the stream should have ended"
        );
    }

    #[tokio::test]
    async fn refuses_a_filter_it_cannot_parse() {
        let (router, _) = router_and_events();

        let request = Request::builder()
            .uri("/events?level=shout")
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(&router, request).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("level"), "{body}");
    }

    /// The one response that is not prose, and that a client parses back into
    /// the type it was serialised from.
    #[tokio::test]
    async fn answers_the_status_as_json() {
        let (router, _) = router_and_events();
        put_app(&router, "hello", MANIFEST).await;

        let request = Request::builder()
            .uri("/status")
            .body(Body::empty())
            .unwrap();
        let (code, body) = call(&router, request).await;

        assert_eq!(code, StatusCode::OK);
        let status: crate::status::Status = serde_json::from_str(&body).expect("a status");
        assert_eq!(status.version, "9.9.9");
        assert_eq!(status.apps.running, 1);
        assert_eq!(status.edge.routed_hosts, 1);
    }

    /// A registration as the cli sends one, with the fixture key so that it
    /// gets past validation.
    fn registration(slug: &str, app_id: i64) -> String {
        serde_json::json!({
            "slug": slug,
            "app_id": app_id,
            "name": "Spaceport for Acme",
            "owner": "an-organisation",
            "client_id": "Iv1.0123456789abcdef",
            "client_secret": "a-client-secret",
            "webhook_secret": "a-webhook-secret",
            "private_key": crate::connections::github::key::testing::PKCS1,
        })
        .to_string()
    }

    async fn post_connection(router: &Router, body: String) -> (StatusCode, String) {
        let request = Request::builder()
            .method("POST")
            .uri("/connections/github")
            .body(Body::from(body))
            .unwrap();

        call(router, request).await
    }

    async fn get_connections(router: &Router, path: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .uri(format!("/connections{path}"))
            .body(Body::empty())
            .unwrap();

        call(router, request).await
    }

    async fn delete_connection(router: &Router, slug: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/connections/{slug}"))
            .body(Body::empty())
            .unwrap();

        call(router, request).await
    }

    #[tokio::test]
    async fn connects_a_github_app_and_says_where_to_install_it() {
        let (router, _) = router_and_events();

        let (status, body) = post_connection(&router, registration("spaceport-acme", 42)).await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("connected `spaceport-acme` as github app 42"),
            "{body}"
        );
        assert!(body.contains("owned by an-organisation"), "{body}");
        assert!(
            body.contains("https://github.com/apps/spaceport-acme/installations/new"),
            "{body}"
        );
    }

    /// Connecting is the one operator command that goes out to the internet,
    /// and it goes out before anything is written down.
    #[tokio::test]
    async fn connecting_asks_github_to_confirm_the_credentials_first() {
        let (router, github) = router_and_github();

        post_connection(&router, registration("spaceport-acme", 42)).await;

        let paths: Vec<String> = github
            .requests()
            .into_iter()
            .map(|request| request.path)
            .collect();
        assert_eq!(paths, ["/app"]);
    }

    /// A connection that is recorded and does not work looks connected in
    /// every listing, and the first sign that it is not comes hours later.
    #[tokio::test]
    async fn a_registration_github_rejects_is_not_recorded() {
        let (router, github) = router_and_github();
        github.refuse_with(StatusCode::UNAUTHORIZED, "Bad credentials");

        let (status, body) = post_connection(&router, registration("spaceport-acme", 42)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("does not accept this app's credentials"),
            "{body}"
        );
        let (_, listing) = get_connections(&router, "").await;
        assert!(
            listing.contains("no github apps are connected"),
            "{listing}"
        );
    }

    /// GitHub is the authority on how its own slug is spelled, and the
    /// corrected one is what every later command has to be given — so the
    /// response has to say it.
    #[tokio::test]
    async fn a_mistyped_slug_is_recorded_as_the_one_github_uses() {
        let (router, _) = router_and_github();

        let (status, body) = post_connection(&router, registration("spaceport-acmee", 42)).await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("connected `spaceport-acme`"), "{body}");
        let (found, _) = get_connections(&router, "/spaceport-acme").await;
        assert_eq!(found, StatusCode::OK);
        let (missing, _) = get_connections(&router, "/spaceport-acmee").await;
        assert_eq!(missing, StatusCode::NOT_FOUND);
    }

    async fn post_registration(router: &Router, body: serde_json::Value) -> (StatusCode, String) {
        let request = Request::builder()
            .method("POST")
            .uri("/connections/github/register")
            .body(Body::from(body.to_string()))
            .unwrap();

        call(router, request).await
    }

    #[tokio::test]
    async fn hands_back_a_link_for_an_operator_to_open() {
        let router = router_answering_to_a_hostname();

        let (status, body) = post_registration(
            &router,
            serde_json::json!({"org": "an-organisation", "name": "Spaceport for Acme"}),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("https://spaceport.example.com/connections/github/setup/"),
            "{body}"
        );
        assert!(body.contains("open this in a browser"), "{body}");
        assert!(body.contains("`an-organisation` organisation"), "{body}");
        assert!(body.contains("30 minutes"), "{body}");
    }

    /// An app nobody named still has to be called something, and a name that
    /// is already taken on github.com is refused at the far end.
    #[tokio::test]
    async fn names_the_app_after_the_hostname_when_nobody_named_it() {
        let router = router_answering_to_a_hostname();

        let (status, body) = post_registration(&router, serde_json::json!({})).await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("spaceport-example-com"), "{body}");
        assert!(body.contains("your own github account"), "{body}");
    }

    /// The reason the organisation is in the default at all: one spaceport may
    /// hold an app per organisation, and connecting the second one with
    /// defaults must not ask github for a name the first one already has.
    #[tokio::test]
    async fn names_the_app_after_the_organisation_as_well() {
        let router = router_answering_to_a_hostname();

        let (_, first) = post_registration(&router, serde_json::json!({"org": "acme-inc"})).await;
        let (_, second) =
            post_registration(&router, serde_json::json!({"org": "beta-works"})).await;

        assert!(
            first.contains("`spaceport-example-com-acme-inc`"),
            "{first}"
        );
        assert!(
            second.contains("`spaceport-example-com-beta-works`"),
            "{second}"
        );
    }

    #[test]
    fn a_default_name_is_the_hostname_when_there_is_no_organisation() {
        assert_eq!(
            default_name("spaceport.example.com", None),
            "spaceport-example-com"
        );
    }

    #[test]
    fn a_default_name_carries_the_organisation_that_makes_it_distinct() {
        assert_eq!(
            default_name("spaceport.example.com", Some("acme-inc")),
            "spaceport-example-com-acme-inc"
        );
    }

    /// The hostname gives up its characters first. Cutting the tail instead
    /// would fit the limit and lose the only part that tells two of these
    /// names apart, which is the collision this default exists to avoid.
    #[test]
    fn a_default_name_too_long_to_fit_keeps_the_organisation_whole() {
        let name = default_name(
            "spaceport.a-rather-long-hostname.example.com",
            Some("acme-inc"),
        );

        assert!(name.chars().count() <= NAME_LIMIT, "{name}");
        assert!(name.ends_with("-acme-inc"), "{name}");
    }

    /// An organisation long enough to fill the limit on its own is still
    /// distinct on its own, which is the property that matters.
    #[test]
    fn a_default_name_for_an_enormous_organisation_is_the_organisation() {
        let org = "a".repeat(NAME_LIMIT + 10);
        let name = default_name("spaceport.example.com", Some(&org));

        assert_eq!(name.chars().count(), NAME_LIMIT);
        assert!(name.starts_with("aaaa"), "{name}");
    }

    /// Whatever is cut, what is left has to read as a name rather than as a
    /// name that ran out.
    #[test]
    fn a_default_name_never_ends_in_the_hyphen_it_was_cut_at() {
        for hostname in ["a-very-long-hostname-indeed.example.com", "x.y.z"] {
            for org in [None, Some("acme-inc"), Some(&"o".repeat(30)[..])] {
                let name = default_name(hostname, org);

                assert!(!name.ends_with('-'), "{name}");
                assert!(name.chars().count() <= NAME_LIMIT, "{name}");
            }
        }
    }

    /// The whole flow is a redirect back to an address GitHub can reach, and
    /// without a hostname there is none — so it fails here rather than as an
    /// app whose webhooks go nowhere.
    #[tokio::test]
    async fn refuses_to_begin_without_a_hostname_of_its_own() {
        let (router, _) = router_and_events();

        let (status, body) =
            post_registration(&router, serde_json::json!({"name": "Spaceport for Acme"})).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("no hostname of its own"), "{body}");
        assert!(body.contains("edge.hostname"), "{body}");
    }

    /// Beginning a registration promises nothing: the app is created minutes
    /// later, in a browser, or never.
    #[tokio::test]
    async fn beginning_a_registration_asks_github_nothing_and_records_nothing() {
        let router = router_answering_to_a_hostname();

        post_registration(&router, serde_json::json!({})).await;

        let (_, listing) = get_connections(&router, "").await;
        assert!(
            listing.contains("no github apps are connected"),
            "{listing}"
        );
    }

    #[tokio::test]
    async fn refuses_a_registration_that_is_not_json() {
        let (router, _) = router_and_events();

        let (status, body) = post_connection(&router, "not json at all".to_owned()).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("not a github app registration"), "{body}");
    }

    #[tokio::test]
    async fn refuses_a_registration_whose_key_is_not_a_key() {
        let (router, _) = router_and_events();
        let body = registration("spaceport-acme", 42).replace(
            &serde_json::to_string(crate::connections::github::key::testing::PKCS1).unwrap(),
            "\"hunter2\"",
        );

        let (status, body) = post_connection(&router, body).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("not pem"), "{body}");
    }

    #[tokio::test]
    async fn lists_the_connections_in_columns() {
        let (router, _) = router_and_events();
        post_connection(&router, registration("spaceport-acme", 42)).await;
        post_connection(&router, registration("spaceport-other", 43)).await;

        let (status, body) = get_connections(&router, "").await;

        assert_eq!(status, StatusCode::OK);
        let lines: Vec<&str> = body.lines().collect();
        assert!(lines[0].starts_with("SLUG"), "{body}");
        assert!(lines[0].contains("APP ID"), "{body}");
        assert!(lines[1].starts_with("spaceport-acme"), "{body}");
        assert!(lines[2].starts_with("spaceport-other"), "{body}");
    }

    /// An empty listing has to say what to do next, or it reads as spaceport
    /// having failed to answer.
    #[tokio::test]
    async fn says_when_nothing_is_connected() {
        let (router, _) = router_and_events();

        let (status, body) = get_connections(&router, "").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("no github apps are connected"), "{body}");
        assert!(body.contains("spaceport connect github --manual"), "{body}");
    }

    #[tokio::test]
    async fn shows_one_connection() {
        let (router, _) = router_and_events();
        post_connection(&router, registration("spaceport-acme", 42)).await;

        let (status, body) = get_connections(&router, "/spaceport-acme").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("app        spaceport-acme"), "{body}");
        assert!(body.contains("Iv1.0123456789abcdef"), "{body}");
        assert!(body.contains("nowhere yet"), "{body}");
    }

    /// What an operator actually wants off this command is whether one
    /// particular repository is in reach, and a count cannot answer that.
    #[tokio::test]
    async fn shows_the_repositories_each_installation_reaches() {
        let (_, router, _, _, _, connections, _, _, _, _) = parts_on(OneContainer::default());
        post_connection(&router, registration("spaceport-acme", 42)).await;
        connections
            .record_installations(
                42,
                &[
                    Installation {
                        installation_id: 100,
                        account: "mtrense".to_owned(),
                        account_type: "User".to_owned(),
                        repositories: vec![
                            "mtrense/spaceport-test1".to_owned(),
                            "mtrense/spaceport-test2".to_owned(),
                        ],
                    },
                    Installation {
                        installation_id: 200,
                        account: "acme-inc".to_owned(),
                        account_type: "Organization".to_owned(),
                        repositories: vec!["acme-inc/the-only-one".to_owned()],
                    },
                ],
            )
            .await
            .unwrap();

        let (status, body) = get_connections(&router, "/spaceport-acme").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("mtrense (user), 2 repositories"), "{body}");
        assert!(body.contains("mtrense/spaceport-test1"), "{body}");
        assert!(body.contains("mtrense/spaceport-test2"), "{body}");
        // One is a repository, not 1 repositories.
        assert!(
            body.contains("acme-inc (organization), 1 repository\n"),
            "{body}"
        );
        assert!(body.contains("acme-inc/the-only-one"), "{body}");
    }

    /// An installation somebody granted nothing is a real state, and reads as
    /// a failure to look if it is printed as an empty list.
    #[tokio::test]
    async fn says_when_an_installation_reaches_no_repository_at_all() {
        let (_, router, _, _, _, connections, _, _, _, _) = parts_on(OneContainer::default());
        post_connection(&router, registration("spaceport-acme", 42)).await;
        connections
            .record_installations(
                42,
                &[Installation {
                    installation_id: 100,
                    account: "mtrense".to_owned(),
                    account_type: "User".to_owned(),
                    repositories: Vec::new(),
                }],
            )
            .await
            .unwrap();

        let (_, body) = get_connections(&router, "/spaceport-acme").await;

        assert!(body.contains("mtrense (user), no repositories"), "{body}");
    }

    /// The one thing a connection must never do: an operator asking what is
    /// connected must not be shown what proves it.
    #[tokio::test]
    async fn never_prints_a_secret() {
        let (router, _) = router_and_events();
        post_connection(&router, registration("spaceport-acme", 42)).await;

        let (_, shown) = get_connections(&router, "/spaceport-acme").await;
        let (_, listed) = get_connections(&router, "").await;

        for body in [&shown, &listed] {
            assert!(!body.contains("a-client-secret"), "{body}");
            assert!(!body.contains("a-webhook-secret"), "{body}");
            assert!(!body.contains("PRIVATE KEY"), "{body}");
        }
        assert!(shown.contains("(not shown)"), "{shown}");
    }

    #[tokio::test]
    async fn showing_a_connection_nobody_made_is_a_404() {
        let (router, _) = router_and_events();

        let (status, body) = get_connections(&router, "/ghost").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("`ghost` is not connected"), "{body}");
    }

    #[tokio::test]
    async fn forgets_a_connection() {
        let (router, _) = router_and_events();
        post_connection(&router, registration("spaceport-acme", 42)).await;

        let (status, body) = delete_connection(&router, "spaceport-acme").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("forgot `spaceport-acme`"), "{body}");
        assert!(body.contains("still exists on github"), "{body}");
        assert_eq!(
            delete_connection(&router, "spaceport-acme").await.0,
            StatusCode::NOT_FOUND
        );
    }

    /// An app applied, a connection made, and one repository cached as
    /// reachable through it — which is the state every tracking starts from.
    async fn tracking_router() -> (Router, Arc<FakeGitHub>) {
        let (router, github, _, _, _) = tracking_parts().await;

        (router, github)
    }

    /// The same, with the stores themselves and the shove the build worker
    /// waits on — for the tests that ask what was written down rather than what
    /// was said back.
    async fn tracking_parts() -> (
        Router,
        Arc<FakeGitHub>,
        Arc<TrackingRepository>,
        Arc<BuildRepository>,
        Nudge,
    ) {
        let (_, router, _, _, github, connections, tracking, builds, building, _) =
            parts_on(OneContainer::default());
        put_app(&router, "site", MANIFEST).await;
        connected_and_reaching(&router, &connections).await;

        (router, github, tracking, builds, building)
    }

    /// The connection every tracking here goes through, with the one repository
    /// it reaches cached under it.
    ///
    /// Apart from [`tracking_parts`] so that a test which wants the app store
    /// as well can build its own fixture out of [`parts_on`] rather than being
    /// handed an app it is not about.
    async fn connected_and_reaching(router: &Router, connections: &ConnectionRepository) {
        post_connection(router, registration("spaceport-acme", 42)).await;
        connections
            .record_installations(
                42,
                &[Installation {
                    installation_id: 100,
                    account: "an-organisation".to_owned(),
                    account_type: "Organization".to_owned(),
                    repositories: vec!["an-organisation/site".to_owned()],
                }],
            )
            .await
            .unwrap();
    }

    async fn track_app(router: &Router, id: &str, query: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/apps/{id}/tracking{query}"))
            .body(Body::empty())
            .unwrap();

        call(router, request).await
    }

    /// Whether anything went out to github for a repository, which is the whole
    /// question when a branch was given explicitly.
    fn repositories_read(github: &FakeGitHub) -> Vec<String> {
        github
            .requests()
            .into_iter()
            .map(|request| request.path)
            .filter(|path| path.starts_with("/repos/"))
            .collect()
    }

    /// Applying and tracking are the two ways an app comes to exist, and
    /// requiring the first before the second would mean copying a manifest out
    /// of the repository by hand — the work tracking exists to remove.
    #[tokio::test]
    async fn tracks_an_app_nobody_applied() {
        let (router, _) = tracking_router().await;

        let (status, body) = track_app(
            &router,
            "echo",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("app `echo` tracks an-organisation/site"),
            "{body}"
        );
        assert!(
            body.contains("nothing has been applied under `echo`"),
            "{body}"
        );
        assert!(body.contains("has nothing to run"), "{body}");
        // A push builds and deploys nothing, and the app has no manifest here
        // either — so the answer names the command that ends both.
        assert!(body.contains("is built from here on"), "{body}");
        assert!(body.contains("spaceport apps deploy echo"), "{body}");
    }

    /// Accepting the tracking and then denying the app exists would leave an
    /// operator with a name that answers nowhere.
    #[tokio::test]
    async fn shows_an_app_that_is_only_tracked() {
        let (router, _) = tracking_router().await;
        track_app(
            &router,
            "echo",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        let (status, body) = show_app(&router, "echo", "").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("status    tracked"), "{body}");
        assert!(body.contains("an-organisation/site on main"), "{body}");
        assert!(
            body.contains("through the `spaceport-acme` connection"),
            "{body}"
        );
        assert!(body.contains("none applied here yet"), "{body}");
        // Nothing of a manifest, because there is no manifest to read it off.
        assert!(!body.contains("readiness"), "{body}");
        assert!(!body.contains("source"), "{body}");
    }

    /// The document is in a repository rather than here, and saying where is a
    /// better answer than an empty file.
    #[tokio::test]
    async fn refuses_the_manifest_of_an_app_that_is_only_tracked() {
        let (router, _) = tracking_router().await;
        track_app(
            &router,
            "echo",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        let (status, body) = show_app(&router, "echo", "?manifest=true").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("has no manifest here"), "{body}");
        assert!(body.contains("an-organisation/site"), "{body}");
        assert!(body.contains("spaceport.yaml"), "{body}");
    }

    #[tokio::test]
    async fn lists_an_app_that_is_only_tracked_beside_one_that_is_running() {
        let (router, _) = tracking_router().await;
        track_app(
            &router,
            "echo",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        let (status, body) = get_apps(&router, "").await;

        assert_eq!(status, StatusCode::OK);
        let lines: Vec<&str> = body.lines().collect();
        assert!(lines[1].starts_with("echo"), "{body}");
        assert!(
            lines[1].contains("repository an-organisation/site@main"),
            "{body}"
        );
        assert!(lines[1].contains("tracked"), "{body}");
        // It claims nothing, so there is nothing in the hosts column.
        assert!(!lines[1].contains(".test"), "{body}");
        assert!(lines[2].starts_with("site"), "{body}");
        assert!(lines[2].contains("unreachable"), "{body}");
    }

    /// A tracked-only app is one of the apps a pattern is asked about, and one
    /// the pattern misses is as absent as any other.
    #[tokio::test]
    async fn lists_only_the_tracked_apps_a_pattern_matches() {
        let (router, _) = tracking_router().await;
        track_app(
            &router,
            "echo",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        let (matched, body) = get_apps(&router, "?pattern=ech*").await;
        assert_eq!(matched, StatusCode::OK);
        assert!(body.contains("echo"), "{body}");
        assert!(!body.contains("site  "), "{body}");

        let (missed, body) = get_apps(&router, "?pattern=worker").await;
        assert_eq!(missed, StatusCode::OK);
        assert_eq!(body, "no app matches `worker`\n");
    }

    /// The order the two arrive in is the operator's, not spaceport's: the
    /// manifest may be applied long after the tracking that named the app.
    #[tokio::test]
    async fn applying_a_manifest_for_an_app_already_tracked_keeps_the_tracking() {
        let (router, _) = tracking_router().await;
        track_app(
            &router,
            "echo",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        let (applied, _) = put_app(&router, "echo", &manifest_for("gamma.test")).await;

        assert_eq!(applied, StatusCode::OK);
        let (status, body) = show_app(&router, "echo", "").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("gamma.test"), "{body}");
        assert!(body.contains("an-organisation/site on main"), "{body}");
        assert!(!body.contains("none applied here yet"), "{body}");
    }

    /// There is no `spaceport apps untrack`, so destroying the app is the only
    /// way to undo a tracking — and a tracking nothing can reach is spaceport
    /// watching a branch for an app that does not exist.
    #[tokio::test]
    async fn destroys_an_app_that_is_only_tracked() {
        let (router, _, tracking, _, _) = tracking_parts().await;
        track_app(
            &router,
            "echo",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        let (status, body) = delete_app(&router, "echo").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("app `echo` destroyed"), "{body}");
        assert!(body.contains("no manifest applied"), "{body}");
        assert!(
            body.contains("no longer tracks an-organisation/site on main"),
            "{body}"
        );
        assert!(
            tracking
                .by_app(&"echo".parse().unwrap())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn destroying_a_running_app_forgets_what_it_tracked() {
        let (router, _, tracking, _, _) = tracking_parts().await;
        track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        let (status, body) = delete_app(&router, "site").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("container site0123456"), "{body}");
        assert!(
            body.contains("no longer tracks an-organisation/site on main"),
            "{body}"
        );
        assert!(
            tracking
                .by_app(&"site".parse().unwrap())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Tracked-only apps are apps; a name that is neither is still nothing.
    #[tokio::test]
    async fn showing_an_app_that_is_neither_applied_nor_tracked_is_a_404() {
        let (router, _) = tracking_router().await;

        let (status, body) = show_app(&router, "ghost", "").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("no app named `ghost`"), "{body}");
    }

    #[tokio::test]
    async fn refuses_to_track_through_a_connection_nobody_made() {
        let (router, _) = tracking_router().await;

        let (status, body) = track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=ghost&branch=main",
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("`ghost` is not connected"), "{body}");
    }

    /// The connection is what reaches the repository, and one that does not
    /// reach it can neither read the manifest nor hear the push. The cache
    /// being stale is the likeliest reason, so the refusal says so.
    #[tokio::test]
    async fn refuses_a_repository_the_connection_does_not_reach() {
        let (router, _) = tracking_router().await;

        let (status, body) = track_app(
            &router,
            "site",
            "?repository=an-organisation/elsewhere&connection=spaceport-acme&branch=main",
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("does not reach"), "{body}");
        assert!(body.contains("hourly"), "{body}");
        assert!(
            body.contains("spaceport connect show spaceport-acme"),
            "{body}"
        );
    }

    /// github.com resolves `Acme/Site` and `acme/site` to one repository, and
    /// an operator types whichever spelling the page showed them — but what is
    /// stored is github's, because that is what a delivery will say.
    #[tokio::test]
    async fn matches_the_repository_however_it_was_spelled() {
        let (router, _) = tracking_router().await;

        let (status, body) = track_app(
            &router,
            "site",
            "?repository=An-Organisation/Site&connection=spaceport-acme&branch=main",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("an-organisation/site"), "{body}");
        let (_, shown) = show_app(&router, "site", "").await;
        assert!(shown.contains("an-organisation/site"), "{shown}");
    }

    /// The same argument the app manifest makes for a volume having no host
    /// path: a path that may leave the tree it is rooted in may name any file
    /// on this host.
    #[tokio::test]
    async fn refuses_a_manifest_path_that_leaves_the_repository() {
        let (router, _) = tracking_router().await;
        let base = "?repository=an-organisation/site&connection=spaceport-acme&branch=main";

        let (climbing, body) = track_app(
            &router,
            "site",
            &format!("{base}&manifest_path=../etc/passwd"),
        )
        .await;
        assert_eq!(climbing, StatusCode::BAD_REQUEST);
        assert!(body.contains("climbs out"), "{body}");

        let (absolute, body) = track_app(
            &router,
            "site",
            &format!("{base}&manifest_path=/etc/spaceport.yaml"),
        )
        .await;
        assert_eq!(absolute, StatusCode::BAD_REQUEST);
        assert!(body.contains("absolute"), "{body}");

        let (directory, body) =
            track_app(&router, "site", &format!("{base}&manifest_path=apps/")).await;
        assert_eq!(directory, StatusCode::BAD_REQUEST);
        assert!(body.contains("names a directory"), "{body}");
    }

    /// A branch is a branch and not a ref: every comparison downstream is
    /// against the name a push carries.
    #[tokio::test]
    async fn refuses_a_branch_that_is_a_ref() {
        let (router, _) = tracking_router().await;

        let (status, body) = track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=refs/heads/main",
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("is a ref rather than a branch"), "{body}");
        assert!(body.contains("`main`"), "{body}");
    }

    /// An operator who named the branch has said which branch, and nothing
    /// about which commit it is at — so the repository itself is left unread
    /// and the branch is asked for, which is the round trip that has something
    /// to say.
    #[tokio::test]
    async fn takes_the_branch_it_was_given_without_asking_for_the_default() {
        let (router, github) = tracking_router().await;
        github.branch_is_at("an-organisation/site", "release/2026", HEAD);

        let (status, body) = track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=release/2026",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("branch     release/2026"), "{body}");
        assert!(body.contains("manifest   spaceport.yaml"), "{body}");
        assert!(body.contains("connection spaceport-acme"), "{body}");
        assert!(body.contains("deployed by nothing"), "{body}");
        assert_eq!(
            repositories_read(&github),
            ["/repos/an-organisation/site/branches/release/2026"]
        );
    }

    /// Resolved once and stored by name, so that changing the default branch on
    /// github.com months from now cannot silently re-point a running app.
    #[tokio::test]
    async fn resolves_the_branch_from_github_when_none_was_given() {
        let (router, github) = tracking_router().await;
        github.repository_defaults_to("an-organisation/site", "trunk");
        github.branch_is_at("an-organisation/site", "trunk", HEAD);

        let (status, body) = track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("branch     trunk"), "{body}");
        // The repository for the branch, and then that branch for its head.
        assert_eq!(
            repositories_read(&github),
            [
                "/repos/an-organisation/site",
                "/repos/an-organisation/site/branches/trunk"
            ]
        );
        let (_, shown) = show_app(&router, "site", "").await;
        assert!(shown.contains("an-organisation/site on trunk"), "{shown}");
    }

    /// GitHub's own sentence, under the status that says whose trouble it is.
    #[tokio::test]
    async fn says_when_github_will_not_say_what_the_default_branch_is() {
        let (router, github) = tracking_router().await;
        github.refuse_with(StatusCode::INTERNAL_SERVER_ERROR, "<html>");

        let (status, body) = track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme",
        )
        .await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.contains("github's own trouble"), "{body}");
    }

    /// The bug this is all for: a repository whose last push is older than the
    /// tracking produces no delivery, and the builder only ever builds a
    /// revision written down beside a tracking — so tracking one resolves the
    /// branch's head itself rather than waiting for a push that may never come.
    #[tokio::test]
    async fn tracking_a_repository_records_the_head_its_branch_is_at() {
        let (router, _, tracking, _, _) = tracking_parts().await;

        let (status, body) = track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let read = tracking
            .by_app(&"site".parse().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.revision.as_deref(), Some(HEAD));
        // Stamped as a push stamps one, so that "when did spaceport last see
        // this ref move" has an answer from the moment the tracking exists.
        assert!(
            read.revision_seen_at.as_deref().unwrap().ends_with('Z'),
            "{read:?}"
        );
        // And the operator is told which commit that is, abbreviated as every
        // other sha spaceport prints for a person.
        assert!(body.contains("`main` is at 0123456"), "{body}");
        assert!(body.contains("being built now"), "{body}");
    }

    /// A revision written down is a build wanted, and an operator who has just
    /// tracked a repository should not wait out the builder's interval to see
    /// it start.
    #[tokio::test]
    async fn tracking_a_repository_wakes_the_build_worker() {
        let (router, _, _, _, building) = tracking_parts().await;
        let woken = building.changed();

        track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        assert!(woken.has_changed().unwrap());
    }

    /// The other loop too, and for a case the build has no way to announce:
    /// arming an app whose head was already built produces a build request that
    /// is a no-op, so nothing finishes and nothing shoves the deploying worker
    /// — while the row saying that image has run nowhere is sitting there.
    ///
    /// Built out of [`parts_on`] rather than [`tracking_parts`], which hands
    /// back the builder's shove and not this one.
    #[tokio::test]
    async fn tracking_a_repository_wakes_the_deploying_worker() {
        let (_, router, _, _, _, connections, _, _, _, deploying) =
            parts_on(OneContainer::default());
        put_app(&router, "site", MANIFEST).await;
        connected_and_reaching(&router, &connections).await;
        let woken = deploying.changed();

        track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main&deploy=true",
        )
        .await;

        assert!(woken.has_changed().unwrap());
    }

    /// A mistyped `--branch` is the likeliest way anybody reaches this, and
    /// until now nothing checked that a named branch existed at all — so it
    /// would have been recorded, and nothing would ever have built it.
    ///
    /// Refused as a request that named something that is not there, not as a
    /// far end that failed: what went wrong is on this side of the wire.
    #[tokio::test]
    async fn refuses_a_branch_github_does_not_have() {
        let (router, _, tracking, _, _) = tracking_parts().await;

        let (status, body) = track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=mian",
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("has no branch `mian`"), "{body}");
        assert!(body.contains("an-organisation/site"), "{body}");
        // And says the way out that costs nothing to take.
        assert!(body.contains("omit `--branch`"), "{body}");
        assert!(
            tracking
                .by_app(&"site".parse().unwrap())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Settled before anything is written down, like everything above it: a
    /// github having a bad minute leaves the app tracking what it tracked
    /// before rather than a repository nothing can be built from.
    #[tokio::test]
    async fn records_nothing_when_github_will_not_say_where_the_branch_is() {
        let (router, github, tracking, _, _) = tracking_parts().await;
        github.refuse_with(StatusCode::INTERNAL_SERVER_ERROR, "<html>");

        let (status, body) = track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.contains("github's own trouble"), "{body}");
        assert!(
            tracking
                .by_app(&"site".parse().unwrap())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A head belonged to the ref it was seen on, so a re-track resolves the
    /// new branch's afresh — carrying the old one over would make the first
    /// build of the new branch look like one that had already happened.
    #[tokio::test]
    async fn re_tracking_resolves_the_new_branchs_head_rather_than_keeping_the_old() {
        let (router, github, tracking, _, _) = tracking_parts().await;
        github.branch_is_at("an-organisation/site", "release", OTHER_HEAD);
        track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        let (status, _) = track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=release",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let read = tracking
            .by_app(&"site".parse().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.branch, "release");
        assert_eq!(read.revision.as_deref(), Some(OTHER_HEAD));
    }

    /// An app is built from one place, so pointing it somewhere else replaces
    /// rather than adds.
    #[tokio::test]
    async fn re_tracking_an_app_replaces_what_it_tracked() {
        let (router, github) = tracking_router().await;
        github.branch_is_at("an-organisation/site", "release", OTHER_HEAD);
        track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        let (status, _) = track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=release&manifest_path=apps/site/spaceport.yaml",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let (_, shown) = show_app(&router, "site", "").await;
        assert!(shown.contains("an-organisation/site on release"), "{shown}");
        assert!(shown.contains("apps/site/spaceport.yaml"), "{shown}");
        assert!(!shown.contains(" on main"), "{shown}");
    }

    /// Whether a build reaches production on its own is the question an
    /// operator is really asking when they track something, so the answer to
    /// it is in the same breath as the branch.
    #[tokio::test]
    async fn tracking_with_the_deploy_flag_arms_the_app_and_says_so() {
        let (router, _, tracking, _, _) = tracking_parts().await;

        let (status, body) = track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main&deploy=true",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            tracking
                .by_app(&"site".parse().unwrap())
                .await
                .unwrap()
                .unwrap()
                .automatic
        );
        // The head is already on its way through the builder, so what the
        // operator is about to watch is this build being deployed.
        assert!(body.contains("being built now"), "{body}");
        assert!(
            body.contains("deployed without being asked, this build and every one after it"),
            "{body}"
        );
        assert!(!body.contains("deployed by nothing"), "{body}");
    }

    /// An app with no manifest here is one an armed tracking *starts*, and the
    /// answer says so rather than naming a command nobody has to run.
    #[tokio::test]
    async fn arming_an_app_nobody_applied_says_the_build_is_what_starts_it() {
        let (router, _) = tracking_router().await;

        let (status, body) = track_app(
            &router,
            "echo",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main&deploy=true",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("nothing has been applied under `echo`"),
            "{body}"
        );
        assert!(
            body.contains("manifest and all, so this build is what starts the app"),
            "{body}"
        );
        assert!(!body.contains("spaceport apps deploy echo"), "{body}");
    }

    /// The whole reason the switch travels as an option. Correcting a manifest
    /// path is not a request to stop deploying, and an app that quietly stopped
    /// would stay stopped until a commit that was supposed to go out did not.
    #[tokio::test]
    async fn re_tracking_without_mentioning_deployment_leaves_an_armed_app_armed() {
        let (router, _, tracking, _, _) = tracking_parts().await;
        track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main&deploy=true",
        )
        .await;

        let (status, body) = track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main&manifest_path=apps/site/spaceport.yaml",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            tracking
                .by_app(&"site".parse().unwrap())
                .await
                .unwrap()
                .unwrap()
                .automatic
        );
        // And the answer to a request that said nothing about it still says
        // what is true, which is that the app deploys itself.
        assert!(body.contains("deployed without being asked"), "{body}");
    }

    /// There is no `spaceport apps autodeploy`, so re-tracking with the
    /// negative flag is the only way back — and it has to actually work.
    #[tokio::test]
    async fn re_tracking_with_the_negative_flag_disarms_the_app() {
        let (router, _, tracking, _, _) = tracking_parts().await;
        track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main&deploy=true",
        )
        .await;

        let (status, body) = track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main&deploy=false",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            !tracking
                .by_app(&"site".parse().unwrap())
                .await
                .unwrap()
                .unwrap()
                .automatic
        );
        assert!(body.contains("deployed by nothing"), "{body}");
        assert!(body.contains("spaceport apps deploy site"), "{body}");
    }

    /// The report is where an operator finds out what a push to this app would
    /// be about, and the connection is named by the slug every command takes.
    #[tokio::test]
    async fn shows_what_an_app_tracks() {
        let (router, _) = tracking_router().await;
        track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        let (status, body) = show_app(&router, "site", "").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("tracks"), "{body}");
        assert!(body.contains("an-organisation/site on main"), "{body}");
        assert!(body.contains("manifest spaceport.yaml"), "{body}");
        assert!(
            body.contains("through the `spaceport-acme` connection"),
            "{body}"
        );
        // Tracking resolved the branch's head, so there is a revision from the
        // moment the tracking was made rather than only after a push.
        assert!(body.contains(&format!("last saw {HEAD}")), "{body}");
    }

    /// "When I push this, what happens?" is the question the stanza exists to
    /// answer, and both answers are worth a line: an operator reading nothing
    /// would have to go and find out which of the two they had.
    #[tokio::test]
    async fn shows_whether_an_app_deploys_its_own_builds() {
        let (router, _) = tracking_router().await;
        let base = "?repository=an-organisation/site&connection=spaceport-acme&branch=main";
        track_app(&router, "site", base).await;

        let (_, by_hand) = show_app(&router, "site", "").await;
        assert!(by_hand.contains("deploys nothing on its own"), "{by_hand}");
        assert!(
            by_hand.contains("waits for `spaceport apps deploy`"),
            "{by_hand}"
        );

        track_app(&router, "site", &format!("{base}&deploy=true")).await;

        let (status, armed) = show_app(&router, "site", "").await;
        assert_eq!(status, StatusCode::OK);
        assert!(armed.contains("deploys its own builds"), "{armed}");
        assert!(armed.contains("without being asked"), "{armed}");
        assert!(!armed.contains("deploys nothing on its own"), "{armed}");
    }

    /// Most apps are an image somebody applied, and a line telling them they
    /// track nothing is a line about a thing they are not doing.
    #[tokio::test]
    async fn says_nothing_about_tracking_when_an_app_tracks_nothing() {
        let (router, _) = tracking_router().await;

        let (_, body) = show_app(&router, "site", "").await;

        assert!(!body.contains("tracks"), "{body}");
    }

    /// A build as the worker would have asked for one: the revision an app
    /// tracks, through the connection that reaches it.
    fn build_of(id: &str, revision: &str) -> Build {
        Build {
            app: id.parse().unwrap(),
            revision: revision.to_owned(),
            connection: "spaceport-acme".to_owned(),
            repository: "an-organisation/site".to_owned(),
            branch: "main".to_owned(),
            manifest_path: "spaceport.yaml".to_owned(),
            state: BuildState::Pending,
            image_tag: None,
            image_id: None,
            reason: None,
            log: None,
            started_at: String::new(),
            finished_at: None,
            manifest: None,
            deployed_at: None,
            deploy_reason: None,
        }
    }

    /// A tracked app whose revision has been asked for, and nothing more.
    async fn tracked_and_requested(builds: &BuildRepository, router: &Router, revision: &str) {
        track_app(
            router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;
        builds.request(&build_of("site", revision)).await.unwrap();
    }

    /// A build nobody has got to yet is the ordinary state a minute after a
    /// push, and the report says which revision is waiting rather than nothing
    /// at all.
    #[tokio::test]
    async fn shows_a_build_that_is_still_waiting_for_a_worker() {
        let (router, _, _, builds, _) = tracking_parts().await;
        tracked_and_requested(&builds, &router, "0123abc").await;

        let (status, body) = show_app(&router, "site", "").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("build      pending at 0123abc"), "{body}");
    }

    #[tokio::test]
    async fn shows_the_image_a_successful_build_produced() {
        let (router, _, _, builds, _) = tracking_parts().await;
        tracked_and_requested(&builds, &router, "0123abc").await;
        builds
            .succeeded(
                &"site".parse().unwrap(),
                "0123abc",
                "spaceport/site:0123abc",
                "sha256:0123",
                "",
                "step 1/1 : FROM scratch\n",
            )
            .await
            .unwrap();

        let (_, body) = show_app(&router, "site", "").await;

        assert!(body.contains("build      built at 0123abc"), "{body}");
        assert!(body.contains("image spaceport/site:0123abc"), "{body}");
        // A build that worked is not one an operator has to read the log of.
        assert!(!body.contains("it printed"), "{body}");
    }

    /// The whole reason the stanza exists: an operator who cannot read why a
    /// build failed is left pushing again to find out.
    #[tokio::test]
    async fn shows_why_a_build_failed_and_what_it_printed() {
        let (router, _, _, builds, _) = tracking_parts().await;
        tracked_and_requested(&builds, &router, "0123abc").await;
        builds
            .failed(
                &"site".parse().unwrap(),
                "0123abc",
                "the manifest names no image or build",
                "step 1/2 : FROM scratch\nthe dockerfile would not parse\n",
            )
            .await
            .unwrap();

        let (_, body) = show_app(&router, "site", "").await;
        assert!(body.contains("build      failed at 0123abc"), "{body}");
        assert!(
            body.contains("reason the manifest names no image or build"),
            "{body}"
        );
        assert!(body.contains("the dockerfile would not parse"), "{body}");
        // Nothing was produced, so nothing is named as though it had been.
        assert!(!body.contains("image spaceport/"), "{body}");
    }

    /// A log longer than the report prints is cut to its end, where a build
    /// stops — and the line above it says that is what happened.
    #[tokio::test]
    async fn shows_the_end_of_a_long_build_log() {
        let (router, _, _, builds, _) = tracking_parts().await;
        tracked_and_requested(&builds, &router, "0123abc").await;
        let noisy = format!("{}the last line\n", "chatter\n".repeat(LOG_LINES * 2));
        builds
            .failed(
                &"site".parse().unwrap(),
                "0123abc",
                "the engine refused",
                &noisy,
            )
            .await
            .unwrap();

        let (_, body) = show_app(&router, "site", "").await;

        assert!(body.contains("the last 20 lines"), "{body}");
        assert!(body.contains("the last line"), "{body}");
        assert_eq!(body.matches("chatter").count(), LOG_LINES - 1, "{body}");
    }

    /// An app pointed at a branch nothing has been built from yet says so: an
    /// empty stanza would read as a build that produced nothing.
    #[tokio::test]
    async fn says_a_tracked_app_has_not_been_built_yet() {
        let (router, _) = tracking_router().await;
        track_app(
            &router,
            "site",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;

        let (_, body) = show_app(&router, "site", "").await;

        assert!(
            body.contains("build      nothing built from this yet"),
            "{body}"
        );
    }

    /// An app that is only tracked is the one a build matters most for — its
    /// manifest is in the repository, and the build is the whole of what has
    /// happened to it here.
    #[tokio::test]
    async fn shows_the_build_of_an_app_that_is_only_tracked() {
        let (router, _, _, builds, _) = tracking_parts().await;
        track_app(
            &router,
            "echo",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;
        builds.request(&build_of("echo", "0123abc")).await.unwrap();
        builds
            .failed(
                &"echo".parse().unwrap(),
                "0123abc",
                "the commit holds no `spaceport.yaml`",
                "",
            )
            .await
            .unwrap();

        let (status, body) = show_app(&router, "echo", "").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("failed at 0123abc"), "{body}");
        assert!(body.contains("no `spaceport.yaml`"), "{body}");
    }

    /// An app somebody applied an image to has no revision to report on, and a
    /// build stanza would be a line about a thing it is not doing.
    #[tokio::test]
    async fn says_nothing_about_builds_when_an_app_tracks_nothing() {
        let (router, _) = tracking_router().await;

        let (_, body) = show_app(&router, "site", "").await;

        assert!(!body.contains("build"), "{body}");
    }

    /// The manifest a commit carries: an app built from its own repository,
    /// which is the only kind a deploy ever runs. Under a host of its own, so
    /// that deploying `echo` never argues with the `site` the fixture applied.
    const FROM_A_BUILD: &str = "# built from the repository
schema_version: 1
source:
  type: build
routing:
  hosts: [gamma.test]
auth:
  gating: open
container:
  health:
    readiness:
      type: none
";

    async fn deploy_app(router: &Router, id: &str, query: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/apps/{id}/deployment{query}"))
            .body(Body::empty())
            .unwrap();

        call(router, request).await
    }

    /// Point `id` at the repository the fixture's connection reaches.
    async fn tracked_app(router: &Router, id: &str) {
        track_app(
            router,
            id,
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main",
        )
        .await;
    }

    /// A finished build of `revision`, with the image and the manifest a real
    /// one would have recorded — the state every deploy starts from.
    async fn build_succeeded(builds: &BuildRepository, id: &str, revision: &str, manifest: &str) {
        let app: AppId = id.parse().unwrap();
        builds.request(&build_of(id, revision)).await.unwrap();
        builds
            .succeeded(
                &app,
                revision,
                &format!("spaceport/{id}:{revision}"),
                "sha256:0123",
                manifest,
                "step 1/1 : FROM scratch\n",
            )
            .await
            .unwrap();
    }

    /// What an operator who has just pushed is asking for, and the only thing
    /// they can be asking for without naming a revision.
    #[tokio::test]
    async fn deploys_the_newest_build_when_no_revision_is_named() {
        let (store, router, _, _, _, connections, _, builds, _, _) =
            parts_on(OneContainer::default());
        connected_and_reaching(&router, &connections).await;
        tracked_app(&router, "echo").await;
        build_succeeded(&builds, "echo", "0123abc", FROM_A_BUILD).await;
        build_succeeded(&builds, "echo", "89abcde", FROM_A_BUILD).await;

        let (status, body) = deploy_app(&router, "echo", "").await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("app `echo` is running revision 89abcde"),
            "{body}"
        );
        assert!(body.contains("image     spaceport/echo:89abcde"), "{body}");
        assert!(body.contains("gamma.test"), "{body}");
        assert!(store.routes().serving("gamma.test").is_some());
    }

    /// Naming a revision is how a deploy is repeated, and how an app is put
    /// back on what it was running — so it has to beat the newest image there
    /// is rather than being a hint towards it.
    #[tokio::test]
    async fn deploys_the_revision_it_was_given_rather_than_the_newest() {
        let (_, router, _, _, _, connections, _, builds, _, _) = parts_on(OneContainer::default());
        connected_and_reaching(&router, &connections).await;
        tracked_app(&router, "echo").await;
        build_succeeded(&builds, "echo", "0123abc", FROM_A_BUILD).await;
        build_succeeded(&builds, "echo", "89abcde", FROM_A_BUILD).await;

        let (status, body) = deploy_app(&router, "echo", "?revision=0123abc").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("revision 0123abc"), "{body}");
        assert!(body.contains("spaceport/echo:0123abc"), "{body}");
        assert!(!body.contains("89abcde"), "{body}");
    }

    /// A sha is typed off a terminal that abbreviated it, and one that names a
    /// single build of this app is not a guess.
    #[tokio::test]
    async fn takes_an_abbreviated_revision_that_names_one_build() {
        let (_, router, _, _, _, connections, _, builds, _, _) = parts_on(OneContainer::default());
        connected_and_reaching(&router, &connections).await;
        tracked_app(&router, "echo").await;
        build_succeeded(&builds, "echo", "0123abc", FROM_A_BUILD).await;

        let (status, body) = deploy_app(&router, "echo", "?revision=0123").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("revision 0123abc"), "{body}");
    }

    /// Deploying the wrong one of two commits is exactly what naming a sha was
    /// meant to prevent, so an abbreviation that names both is refused with
    /// them in it.
    #[tokio::test]
    async fn refuses_an_abbreviation_that_names_two_builds() {
        let (_, router, _, _, _, connections, _, builds, _, _) = parts_on(OneContainer::default());
        connected_and_reaching(&router, &connections).await;
        tracked_app(&router, "echo").await;
        build_succeeded(&builds, "echo", "0123abc", FROM_A_BUILD).await;
        build_succeeded(&builds, "echo", "0123def", FROM_A_BUILD).await;

        let (status, body) = deploy_app(&router, "echo", "?revision=0123").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("names 2 builds of app `echo`"), "{body}");
        assert!(body.contains("0123abc"), "{body}");
        assert!(body.contains("0123def"), "{body}");
        assert!(body.contains("name the revision in full"), "{body}");
    }

    /// An app nobody tracked and an app whose first build has not finished are
    /// different mistakes, and an operator who has already run `apps track`
    /// should not be told to run it again.
    #[tokio::test]
    async fn refuses_to_deploy_an_app_with_no_build() {
        let (router, _, _, _, _) = tracking_parts().await;

        let (untracked, body) = deploy_app(&router, "site", "").await;
        assert_eq!(untracked, StatusCode::NOT_FOUND);
        assert!(body.contains("it tracks no repository"), "{body}");
        assert!(body.contains("spaceport apps track site"), "{body}");

        tracked_app(&router, "echo").await;
        let (tracked, body) = deploy_app(&router, "echo", "").await;
        assert_eq!(tracked, StatusCode::NOT_FOUND);
        assert!(
            body.contains("it tracks an-organisation/site on main"),
            "{body}"
        );
        assert!(body.contains("nothing has been built from it"), "{body}");
    }

    /// An operator deploying a revision a worker is in the middle of wants to
    /// be told to wait, not told there is no such commit.
    #[tokio::test]
    async fn says_a_revision_that_is_still_building_is_not_one_to_run() {
        let (router, _, _, builds, _) = tracking_parts().await;
        tracked_and_requested(&builds, &router, "0123abc").await;
        builds
            .claim()
            .await
            .unwrap()
            .expect("the build was claimed");

        let (status, body) = deploy_app(&router, "site", "?revision=0123abc").await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.contains("still being built at 0123abc"), "{body}");
        assert!(body.contains("spaceport apps show site"), "{body}");
    }

    /// A build that will never produce an image is worth its own sentence, with
    /// the reason in it: what an operator does next is push over it.
    #[tokio::test]
    async fn says_why_the_build_of_a_revision_failed() {
        let (router, _, _, builds, _) = tracking_parts().await;
        tracked_and_requested(&builds, &router, "0123abc").await;
        builds
            .failed(
                &"site".parse().unwrap(),
                "0123abc",
                "the dockerfile would not parse",
                "",
            )
            .await
            .unwrap();

        let (status, body) = deploy_app(&router, "site", "?revision=0123abc").await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            body.contains("the failure at 0123abc: the dockerfile would not parse"),
            "{body}"
        );
    }

    /// The document the commit carried, byte for byte: what is recorded is what
    /// the repository said at that revision, and `apps show --manifest` is
    /// where an operator compares the two.
    #[tokio::test]
    async fn records_the_manifest_the_commit_carried() {
        let (_, router, _, _, _, connections, _, builds, _, _) = parts_on(OneContainer::default());
        connected_and_reaching(&router, &connections).await;
        tracked_app(&router, "echo").await;
        build_succeeded(&builds, "echo", "0123abc", FROM_A_BUILD).await;

        deploy_app(&router, "echo", "").await;

        let (status, body) = show_app(&router, "echo", "?manifest=true").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, FROM_A_BUILD);
        // The `type: build` it was written with, not the image it resolved to:
        // the record is the repository's document, and a restart resolves the
        // revision again.
        assert!(body.contains("type: build"), "{body}");
    }

    /// Deploying decides what an app runs, never whether it is being run — the
    /// same rule applying a manifest to a suspended app follows.
    #[tokio::test]
    async fn deploying_to_a_suspended_app_leaves_it_suspended() {
        let (store, router, _, _, _, connections, _, builds, _, _) =
            parts_on(OneContainer::default());
        connected_and_reaching(&router, &connections).await;
        tracked_app(&router, "echo").await;
        build_succeeded(&builds, "echo", "0123abc", FROM_A_BUILD).await;
        put_app_suspended(&router, "echo", &manifest_for("gamma.test")).await;

        let (status, body) = deploy_app(&router, "echo", "").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("still suspended"), "{body}");
        assert!(body.contains("spaceport apps resume echo"), "{body}");
        assert!(store.apps().is_empty());
        // Claimed all the same, so resuming it serves the revision at once.
        assert!(store.routes().hosts().contains("gamma.test"));
    }

    /// The question behind "why is my change not live": an image exists and
    /// nothing is running it, which the build stanza on its own reads as
    /// success.
    #[tokio::test]
    async fn shows_the_deployed_revision_against_the_newest_build() {
        let (_, router, _, _, _, connections, _, builds, _, _) = parts_on(OneContainer::default());
        connected_and_reaching(&router, &connections).await;
        tracked_app(&router, "echo").await;
        build_succeeded(&builds, "echo", "0123abc", FROM_A_BUILD).await;
        deploy_app(&router, "echo", "").await;

        let (_, deployed) = show_app(&router, "echo", "").await;
        assert!(
            deployed.contains("deployed   0123abc, which is the newest build there is"),
            "{deployed}"
        );

        build_succeeded(&builds, "echo", "89abcde", FROM_A_BUILD).await;

        let (_, waiting) = show_app(&router, "echo", "").await;
        assert!(waiting.contains("deployed   0123abc"), "{waiting}");
        assert!(
            waiting.contains("a newer build is waiting at 89abcde"),
            "{waiting}"
        );
        assert!(waiting.contains("spaceport apps deploy echo"), "{waiting}");
    }

    /// A build that succeeded and a deployment that failed are two different
    /// sentences, and until now only the first had anywhere to appear: the
    /// image exists, the app is on the commit before, and nothing said why.
    #[tokio::test]
    async fn shows_a_deployment_that_failed_with_its_reason() {
        let (_, router, _, _, _, connections, _, builds, _, _) = parts_on(OneContainer::default());
        connected_and_reaching(&router, &connections).await;
        tracked_app(&router, "echo").await;
        build_succeeded(&builds, "echo", "0123abc", FROM_A_BUILD).await;
        deploy_app(&router, "echo", "").await;
        build_succeeded(&builds, "echo", "89abcde", FROM_A_BUILD).await;
        builds
            .deploy_failed(
                &"echo".parse().unwrap(),
                "89abcde",
                "the container stopped before it answered",
            )
            .await
            .unwrap();

        let (status, body) = show_app(&router, "echo", "").await;

        assert_eq!(status, StatusCode::OK);
        // The build worked, and is still reported as having worked.
        assert!(body.contains("build      built at 89abcde"), "{body}");
        // What is running is what was running before it.
        assert!(body.contains("deployed   0123abc"), "{body}");
        assert!(
            body.contains("deploying 89abcde failed: the container stopped before it answered"),
            "{body}"
        );
        // And the way out, since nothing will try this revision again.
        assert!(
            body.contains("spaceport apps deploy echo --revision 89abcde"),
            "{body}"
        );
    }

    /// Under automatic deployment a newer build still waiting is a symptom
    /// rather than the ordinary state, so the sentence about it stops telling
    /// an operator to race the worker for it.
    #[tokio::test]
    async fn a_waiting_build_reads_differently_for_an_app_that_deploys_itself() {
        let (_, router, _, _, _, connections, _, builds, _, _) = parts_on(OneContainer::default());
        connected_and_reaching(&router, &connections).await;
        track_app(
            &router,
            "echo",
            "?repository=an-organisation/site&connection=spaceport-acme&branch=main&deploy=true",
        )
        .await;
        build_succeeded(&builds, "echo", "0123abc", FROM_A_BUILD).await;

        let (status, body) = show_app(&router, "echo", "").await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("nothing built here is running — 0123abc is waiting"),
            "{body}"
        );
        assert!(body.contains("which this app deploys on its own"), "{body}");
        assert!(!body.contains("spaceport apps deploy echo`"), "{body}");
    }

    /// An operator's deploy and an armed app's are the same event to the row
    /// that records one: without this, the worker would find the revision
    /// undeployed and restart a running app to arrive where it already is.
    #[tokio::test]
    async fn deploying_by_hand_marks_the_revision_deployed() {
        let (_, router, _, _, _, connections, _, builds, _, _) = parts_on(OneContainer::default());
        connected_and_reaching(&router, &connections).await;
        tracked_app(&router, "echo").await;
        build_succeeded(&builds, "echo", "0123abc", FROM_A_BUILD).await;

        let (status, _) = deploy_app(&router, "echo", "").await;

        assert_eq!(status, StatusCode::OK);
        let read = builds
            .built(&"echo".parse().unwrap(), "0123abc")
            .await
            .unwrap()
            .unwrap();
        assert!(
            read.deployed_at.as_deref().unwrap().ends_with('Z'),
            "{read:?}"
        );
        // Nothing failed, so there is no reason recorded beside it.
        assert_eq!(read.deploy_reason, None);
        assert!(!read.awaits_deployment());
    }

    /// The argued half: the operator is watching and is being told anyway, but
    /// the row is what stops an armed app's worker taking production down with
    /// the very failure a person has just read.
    #[tokio::test]
    async fn a_deploy_that_fails_by_hand_is_not_left_for_a_worker_to_repeat() {
        let (_, router, _, _, _, connections, _, builds, _, _) = parts_on(OneContainer::default());
        connected_and_reaching(&router, &connections).await;
        tracked_app(&router, "echo").await;
        build_succeeded(&builds, "echo", "0123abc", FROM_A_BUILD).await;
        // Somebody else is already on the host this app's manifest claims.
        put_app(&router, "occupant", &manifest_for("gamma.test")).await;

        let (status, body) = deploy_app(&router, "echo", "").await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.contains("already claimed by app `occupant`"), "{body}");
        let read = builds
            .built(&"echo".parse().unwrap(), "0123abc")
            .await
            .unwrap()
            .unwrap();
        assert!(
            read.deploy_reason
                .as_deref()
                .unwrap()
                .contains("already claimed"),
            "{read:?}"
        );
        assert!(!read.awaits_deployment());
    }

    /// An app that is only tracked and has an image waiting is one command away
    /// from running, and that command is the whole of what its report has to
    /// say.
    #[tokio::test]
    async fn tells_a_tracked_app_with_an_image_to_deploy_it() {
        let (_, router, _, _, _, connections, _, builds, _, _) = parts_on(OneContainer::default());
        connected_and_reaching(&router, &connections).await;
        tracked_app(&router, "echo").await;
        build_succeeded(&builds, "echo", "0123abc", FROM_A_BUILD).await;

        let (status, body) = show_app(&router, "echo", "").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("status    tracked"), "{body}");
        assert!(
            body.contains("nothing built here is running — 0123abc is waiting"),
            "{body}"
        );
        assert!(body.contains("spaceport apps deploy echo"), "{body}");
    }

    /// An app that is gone has no builds — a pending row would be work the
    /// queue goes on offering for an app there is nothing left to build for.
    #[tokio::test]
    async fn destroying_an_app_forgets_the_builds_it_recorded() {
        let (router, _, _, builds, _) = tracking_parts().await;
        tracked_and_requested(&builds, &router, "0123abc").await;
        builds.request(&build_of("site", "89abcde")).await.unwrap();
        builds.request(&build_of("echo", "0123abc")).await.unwrap();

        let (status, body) = delete_app(&router, "site").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("the 2 builds it had recorded"), "{body}");
        assert!(
            builds
                .by_app(&"site".parse().unwrap())
                .await
                .unwrap()
                .is_empty()
        );
        // Another app's builds are another app's.
        assert_eq!(
            builds.by_app(&"echo".parse().unwrap()).await.unwrap().len(),
            1
        );
    }

    /// A connection that is gone can no longer fetch a commit, so a build taken
    /// through it is a row pointing at nothing — and one taken through another
    /// connection is untouched.
    #[tokio::test]
    async fn forgetting_a_connection_forgets_the_builds_it_fetched() {
        let (router, _, _, builds, _) = tracking_parts().await;
        tracked_and_requested(&builds, &router, "0123abc").await;
        builds
            .request(&Build {
                connection: "spaceport-other".to_owned(),
                ..build_of("echo", "0123abc")
            })
            .await
            .unwrap();

        let (status, _) = delete_connection(&router, "spaceport-acme").await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            builds
                .by_app(&"site".parse().unwrap())
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            builds.by_app(&"echo".parse().unwrap()).await.unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn keeps_the_app_when_a_later_one_conflicts() {
        let (store, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;
        put_app(&router, "other", MANIFEST).await;

        let app: Arc<App> = store.get(&"hello".parse().unwrap()).unwrap();
        assert_eq!(store.routes().serving("alpha.test").unwrap().id, app.id);
    }

    /// An app whose manifest declares a secret and interpolates it, which is
    /// the app every test below is about. Applying it before the value is set
    /// stages it suspended — that is the state a `set` is there to end.
    const NEEDS_SECRET: &str = "schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [alpha.test]
auth:
  gating: open
container:
  secrets: [DB_PASSWORD]
  env:
    DATABASE_URL: \"postgres://user:{{DB_PASSWORD}}@db/app\"
  health:
    readiness:
      type: none
";

    /// The same, waiting on two values rather than one.
    const NEEDS_TWO: &str = "schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [alpha.test]
auth:
  gating: open
container:
  secrets: [DB_PASSWORD, API_KEY]
  env:
    DATABASE_URL: \"postgres://user:{{DB_PASSWORD}}@db/app\"
    TOKEN: \"{{API_KEY}}\"
  health:
    readiness:
      type: none
";

    fn app_id(id: &str) -> AppId {
        id.parse().expect("a test names an app it can name")
    }

    fn var(name: &str) -> VarName {
        name.parse().expect("a test names a variable it can name")
    }

    async fn get_secrets(router: &Router, id: &str, query: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .uri(format!("/apps/{id}/secrets{query}"))
            .body(Body::empty())
            .unwrap();

        call(router, request).await
    }

    async fn put_secret(
        router: &Router,
        id: &str,
        name: &str,
        value: &str,
    ) -> (StatusCode, String) {
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/apps/{id}/secrets/{name}"))
            .body(Body::from(value.to_owned()))
            .unwrap();

        call(router, request).await
    }

    async fn delete_secret_of(router: &Router, id: &str, name: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/apps/{id}/secrets/{name}"))
            .body(Body::empty())
            .unwrap();

        call(router, request).await
    }

    /// What a `PUT` of a secret answered — JSON, where its neighbours are prose,
    /// because the CLI decides which sentence this becomes.
    fn outcome(body: &str) -> SecretSet {
        serde_json::from_str(body).expect("setting a secret answers with what it did")
    }

    /// The value the app's container would actually be given, read off the
    /// manifest the routing table is holding.
    ///
    /// The only way a test can see the whole path a value takes: it went up as
    /// a request body, through the store, and back out of the resolution the
    /// container was rendered from.
    fn carried(store: &AppStore, id: &str, name: &str) -> Secret {
        store
            .get(&app_id(id))
            .expect("the app is running")
            .manifest
            .container
            .resolved[&var(name)]
            .value
            .clone()
    }

    /// The point of the whole feature: an app that could not start because
    /// nobody had set its password starts the moment somebody does, without the
    /// operator having to know that `spaceport apps resume` is the second half
    /// of the job.
    #[tokio::test]
    async fn setting_the_last_secret_an_app_is_missing_brings_it_up() {
        let runtime = OneContainer::default();
        let environments = runtime.environments.clone();
        let (store, router, _, _, _, _, _, _, _, deploying) = parts_on(runtime);
        let (applied, _) = put_app(&router, "hello", NEEDS_SECRET).await;
        assert_eq!(applied, StatusCode::CONFLICT);
        assert!(store.suspended(&app_id("hello")).is_some());
        let woken = deploying.changed();

        let (status, body) = put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(outcome(&body).outcome, SecretOutcome::Resumed);
        assert!(outcome(&body).created);
        assert!(store.suspended(&app_id("hello")).is_none());
        assert!(store.routes().serving("alpha.test").is_some());
        assert_eq!(
            carried(&store, "hello", "DB_PASSWORD"),
            Secret::new("hunter2")
        );
        // The whole path, end to end: the value went up as a request body and
        // came out interpolated in the environment the engine was handed. Every
        // other assertion here would hold even if `{{DB_PASSWORD}}` reached the
        // container verbatim.
        assert_eq!(
            environments.lock().unwrap()[&app_id("hello")][&var("DATABASE_URL")],
            "postgres://user:hunter2@db/app"
        );
        // An app that came back may have an image built during its suspension
        // that nothing has run, exactly as a resume does.
        assert!(woken.has_changed().unwrap());
    }

    /// A secret set into an app somebody else is in the middle of applying is a
    /// value written against a world that is moving: the deploy in flight has
    /// already read the secrets it is building a container from, so the value
    /// would be stored and silently not used, and the answer would say the app
    /// had been brought up to date on it. Refused instead — and refused before
    /// the write, because "409" has to mean nothing changed, or a script that
    /// retries would have no way to know what it had already done.
    #[tokio::test]
    async fn refuses_to_set_a_secret_of_an_app_something_else_is_working_on() {
        let ((_, router, ..), _, applier) = parts_with_state(OneContainer::default(), CONFIG);
        let (applied, _) = put_app(&router, "hello", NEEDS_SECRET).await;
        assert_eq!(applied, StatusCode::CONFLICT);
        let working = applier.working(&app_id("hello")).await;

        let (status, body) = put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.contains("busy being worked on"), "{body}");
        assert!(body.contains("was not set"), "{body}");
        // The substance of the refusal: the value is not there. A 409 that had
        // stored it would leave an operator retrying a write that had already
        // happened, and the app on a password nobody believes it has.
        assert!(
            applier
                .secrets()
                .names(&app_id("hello"), None)
                .await
                .unwrap()
                .is_empty()
        );

        drop(working);

        // And once the app is free, the same call goes through.
        let (status, _) = put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;
        assert_eq!(status, StatusCode::OK);
    }

    /// A rotation script that re-sets what it set yesterday, or an operator who
    /// runs the same command twice after losing a terminal, must not restart
    /// production for it. This is the reason the store answers with three
    /// states rather than two.
    #[tokio::test]
    async fn setting_a_secret_to_the_value_it_already_has_replaces_nothing() {
        let runtime = OneContainer::default();
        let launches = runtime.launches.clone();
        let (store, router, _, _, _, _, _, _, _, _) = parts_on(runtime);
        put_app(&router, "hello", NEEDS_SECRET).await;
        put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;
        let before = launches.load(Ordering::SeqCst);

        let (status, body) = put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(outcome(&body).outcome, SecretOutcome::Unchanged);
        assert!(!outcome(&body).created);
        assert_eq!(launches.load(Ordering::SeqCst), before);
        assert!(store.routes().serving("alpha.test").is_some());
    }

    /// And the other half. A value that really did change only reaches the app
    /// through a new container: the old one has the old value baked into the
    /// environment it was started with, and no amount of updating a row changes
    /// a process that is already running.
    #[tokio::test]
    async fn setting_a_secret_on_a_running_app_replaces_its_container() {
        let runtime = OneContainer::default();
        let launches = runtime.launches.clone();
        let (store, router, _, _, _, _, _, _, _, _) = parts_on(runtime);
        put_app(&router, "hello", NEEDS_SECRET).await;
        put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;
        let before = launches.load(Ordering::SeqCst);

        let (status, body) = put_secret(&router, "hello", "DB_PASSWORD", "hunter3").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(outcome(&body).outcome, SecretOutcome::Redeployed);
        assert!(!outcome(&body).created);
        assert_eq!(launches.load(Ordering::SeqCst), before + 1);
        assert_eq!(
            carried(&store, "hello", "DB_PASSWORD"),
            Secret::new("hunter3")
        );
    }

    /// The record and the store can disagree, and only one of them knows what
    /// is serving traffic. Both `suspend` and `resume` warn and carry on when
    /// they cannot write the flag, so a running app whose record says
    /// "suspended" is a state this spaceport reaches on its own — and reading
    /// the record first would answer 200 to a rotation while leaving the app
    /// serving the credential that was rotated away, with nothing else coming
    /// to notice.
    #[tokio::test]
    async fn redeploys_a_running_app_whose_record_says_it_is_suspended() {
        let runtime = OneContainer::default();
        let launches = runtime.launches.clone();
        let ((store, router, _, _, _, _, _, _, _, _), _, applier) =
            parts_with_state(runtime, CONFIG);
        put_app(&router, "hello", NEEDS_SECRET).await;
        put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;
        // Exactly what a failed `set_suspended` leaves behind.
        applier
            .repository()
            .set_suspended(&app_id("hello"), true)
            .await
            .unwrap();
        let before = launches.load(Ordering::SeqCst);

        let (status, body) = put_secret(&router, "hello", "DB_PASSWORD", "hunter3").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(outcome(&body).outcome, SecretOutcome::Redeployed);
        assert_eq!(launches.load(Ordering::SeqCst), before + 1);
        assert_eq!(
            carried(&store, "hello", "DB_PASSWORD"),
            Secret::new("hunter3")
        );
    }

    /// An app that is down has no container to replace, so saying its container
    /// was replaced would describe something that did not happen — and the
    /// value did put it back up, which is the part the operator wants.
    #[tokio::test]
    async fn setting_a_secret_on_an_app_that_is_down_starts_it() {
        let (store, router, _, _, _, _, _, _, _, _) = parts_on(OneContainer::default());
        put_app(&router, "hello", NEEDS_SECRET).await;
        put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;
        store.take_down(&app_id("hello"), "its container went away");

        let (status, body) = put_secret(&router, "hello", "DB_PASSWORD", "hunter3").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(outcome(&body).outcome, SecretOutcome::Started);
        assert!(store.get(&app_id("hello")).is_some());
        assert_eq!(
            carried(&store, "hello", "DB_PASSWORD"),
            Secret::new("hunter3")
        );
    }

    /// Rotating a password is not applying an app. The redeploy behind it goes
    /// through the same call an apply does, which records the app as applied
    /// now — so `apps show` would tell an operator their app was applied at
    /// four in the morning by the cron job that rotates its credentials.
    #[tokio::test]
    async fn rotating_a_secret_does_not_restate_when_the_app_was_applied() {
        let ((_, router, _, _, _, _, _, _, _, _), db, _) =
            parts_with_state(OneContainer::default(), CONFIG);
        put_app(&router, "hello", NEEDS_SECRET).await;
        put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;
        // Dated in the past rather than read back, so that the assertion cannot
        // pass by two writes landing within the same second.
        let repository = AppRepository::new(db.clone());
        let record = repository
            .recorded(&app_id("hello"))
            .await
            .unwrap()
            .unwrap();
        const APPLIED: &str = "1999-01-01T00:00:00Z";
        repository
            .put_back(&AppRecord {
                applied_at: APPLIED.to_owned(),
                ..record
            })
            .await
            .unwrap();

        put_secret(&router, "hello", "DB_PASSWORD", "hunter3").await;

        let record = repository
            .recorded(&app_id("hello"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.applied_at, APPLIED);
        assert!(!record.suspended, "{record:?}");
    }

    /// Setting the secrets before applying the manifest that needs them is the
    /// right order to do it in — an app whose first deploy talks to a database
    /// needs the password beforehand — so a spaceport that refused would be
    /// refusing the ordinary case.
    #[tokio::test]
    async fn setting_a_secret_for_an_app_that_is_not_applied_stores_it_and_deploys_nothing() {
        let runtime = OneContainer::default();
        let launches = runtime.launches.clone();
        let (store, router, _, _, _, _, tracking, _, _, _) = parts_on(runtime);
        tracking
            .record(
                &Tracking {
                    app: app_id("hello"),
                    github_app_id: 42,
                    repository: "an-organisation/site".to_owned(),
                    branch: "main".to_owned(),
                    manifest_path: "spaceport.yaml".to_owned(),
                    tracked_at: String::new(),
                    revision: None,
                    revision_seen_at: None,
                    automatic: false,
                },
                None,
            )
            .await
            .unwrap();

        let (status, body) = put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(outcome(&body).outcome, SecretOutcome::Stored);
        assert!(outcome(&body).created);
        assert_eq!(launches.load(Ordering::SeqCst), 0);
        assert!(store.get(&app_id("hello")).is_none());
        assert_eq!(get_secrets(&router, "hello", "").await.1, "DB_PASSWORD\n");
    }

    /// The app is not up yet and this did not put it up, so what an operator
    /// needs is the list of what is still missing — which is also the answer
    /// that catches a name typed wrong, since the secret they meant to set is
    /// on it.
    #[tokio::test]
    async fn setting_one_of_the_secrets_an_app_needs_says_which_are_left() {
        let (store, router) = store_and_router();
        put_app(&router, "hello", NEEDS_TWO).await;

        let (status, body) = put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            outcome(&body).outcome,
            SecretOutcome::Missing {
                secrets: vec!["API_KEY".to_owned()],
            }
        );
        assert!(store.suspended(&app_id("hello")).is_some());
        assert!(store.routes().serving("alpha.test").is_none());
    }

    /// Deleting a secret an app declares would arm a trap: the app carries on
    /// serving from the container it already has, and the next thing that
    /// restarts it — a redeploy, a crash, a reboot at four in the morning —
    /// finds a manifest it cannot run. So the manifest goes first, and until it
    /// does the value stays exactly where it was.
    #[tokio::test]
    async fn refuses_to_delete_a_secret_the_manifest_declares() {
        let (store, router) = store_and_router();
        put_app(&router, "hello", NEEDS_SECRET).await;
        put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;

        let (status, body) = delete_secret_of(&router, "hello", "DB_PASSWORD").await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            body.contains("app `hello` declares the secret `DB_PASSWORD`"),
            "{body}"
        );
        assert_eq!(get_secrets(&router, "hello", "").await.1, "DB_PASSWORD\n");
        assert_eq!(
            carried(&store, "hello", "DB_PASSWORD"),
            Secret::new("hunter2")
        );
    }

    /// The record is not the only place a manifest lives, and it is the one
    /// that can be missing: an apply whose record could not be written warns
    /// and carries on, leaving an app that is running on a manifest no row
    /// mentions. Consulting only the record there would hand out the deletion
    /// that takes a running app's credential away.
    #[tokio::test]
    async fn refuses_to_delete_a_secret_only_the_store_knows_is_declared() {
        let ((store, router, _, _, _, _, _, _, _, _), _, applier) =
            parts_with_state(OneContainer::default(), CONFIG);
        put_app(&router, "hello", NEEDS_SECRET).await;
        put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;
        // Exactly what an apply that could not write its row leaves behind.
        applier.repository().forget(&app_id("hello")).await.unwrap();
        assert!(store.get(&app_id("hello")).is_some());

        let (status, body) = delete_secret_of(&router, "hello", "DB_PASSWORD").await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            body.contains("app `hello` declares the secret `DB_PASSWORD`"),
            "{body}"
        );
        assert_eq!(get_secrets(&router, "hello", "").await.1, "DB_PASSWORD\n");
    }

    /// Adding a secret to the manifest of an app that is already up is the
    /// ordinary way a secret arrives, and it is not free: staging the new
    /// manifest takes the container built from the old one away, so the app
    /// stops serving there and then. That is intended — the alternative is an
    /// app running a manifest nobody applied — but it has to be said out loud,
    /// because an operator reading "it stays suspended" would think their
    /// running app was untouched.
    #[tokio::test]
    async fn re_applying_a_manifest_with_a_secret_nobody_has_set_takes_a_running_app_down() {
        let runtime = OneContainer::default();
        let removed = runtime.removed.clone();
        let (store, router, _, _, _, _, _, _, _, _) = parts_on(runtime);
        let (applied, _) = put_app(&router, "hello", MANIFEST).await;
        assert_eq!(applied, StatusCode::OK);
        let container = store.get(&app_id("hello")).unwrap().container.clone();

        let (status, body) = put_app(&router, "hello", NEEDS_SECRET).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.contains("`DB_PASSWORD`"), "{body}");
        assert!(body.contains("not serving"), "{body}");
        assert!(store.get(&app_id("hello")).is_none());
        assert!(store.suspended(&app_id("hello")).is_some());
        assert!(store.routes().serving("alpha.test").is_none());
        assert!(removed.lock().unwrap().contains(&container), "{container}");
    }

    /// The leftovers of an env line somebody deleted, or a name typed wrong
    /// once. Nothing reads it, so removing it is a row and not a restart.
    #[tokio::test]
    async fn deletes_a_secret_the_manifest_does_not_declare() {
        let runtime = OneContainer::default();
        let launches = runtime.launches.clone();
        let (_, router, _, _, _, _, _, _, _, _) = parts_on(runtime);
        put_app(&router, "hello", MANIFEST).await;
        put_secret(&router, "hello", "LEFTOVER", "whatever").await;
        let before = launches.load(Ordering::SeqCst);

        let (status, body) = delete_secret_of(&router, "hello", "LEFTOVER").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("is deleted"), "{body}");
        assert_eq!(get_secrets(&router, "hello", "").await.1, "");
        assert_eq!(launches.load(Ordering::SeqCst), before);
        assert_eq!(
            delete_secret_of(&router, "hello", "LEFTOVER").await.0,
            StatusCode::NOT_FOUND
        );
    }

    /// Names, filtered as `spaceport apps list` filters apps, and no value
    /// anywhere near the answer — the query behind this one does not read the
    /// column values live in.
    #[tokio::test]
    async fn lists_the_names_of_an_apps_secrets_and_never_a_value() {
        let (_, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;
        put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;
        put_secret(&router, "hello", "DB_HOST", "db.internal").await;
        put_secret(&router, "hello", "API_KEY", "sk-live-9").await;

        let (status, all) = get_secrets(&router, "hello", "").await;
        let (_, matching) = get_secrets(&router, "hello", "?pattern=DB_*").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(all, "API_KEY\nDB_HOST\nDB_PASSWORD\n");
        assert_eq!(matching, "DB_HOST\nDB_PASSWORD\n");
        for body in [&all, &matching] {
            assert!(!body.contains("hunter2"), "{body}");
            assert!(!body.contains("db.internal"), "{body}");
            assert!(!body.contains("sk-live-9"), "{body}");
        }
    }

    /// The one promise the whole feature rests on. A value goes up in a request
    /// body and must not come back out anywhere: not in what the route answers,
    /// not in what the route logs, and not in what any of the routes around it
    /// say afterwards. Asserted rather than reasoned about, because every one of
    /// those is one careless `{value}` away.
    ///
    /// What it does *not* cover, because nothing here can: a subscriber
    /// installed with `set_default` is this thread's, and a value logged from a
    /// task somebody spawns later would go past it unseen. The alternative is a
    /// global default, which is one per process and would be this test
    /// collecting every other test's logging for the rest of the run. Nothing
    /// on the routes below spawns anything today — the applier does its work in
    /// the caller's task — so the net covers what it is aimed at, and the day
    /// one of them spawns, this test will not notice.
    #[tokio::test]
    async fn never_says_a_secret_value_in_a_response_or_a_log() {
        const VALUE: &str = "s3cr3t-nobody-should-see";
        let (_, router, _, _, _, _, _, _, _, _) = parts_on(OneContainer::default());
        put_app(&router, "hello", NEEDS_SECRET).await;

        // Installed for this thread only, and around the request itself, so
        // what it collects is what this route logged.
        let bus = Arc::new(EventBus::new());
        let (_, mut logged) = bus.watch(0, &EventFilter::default());
        let bodies = {
            let _guard = tracing::subscriber::set_default(
                tracing_subscriber::registry().with(crate::events::layer(bus.clone())),
            );

            let (status, set) = put_secret(&router, "hello", "DB_PASSWORD", VALUE).await;
            assert_eq!(status, StatusCode::OK);

            let (_, again) = put_secret(&router, "hello", "DB_PASSWORD", VALUE).await;
            let (_, shown) = show_app(&router, "hello", "").await;
            let (_, listed) = get_secrets(&router, "hello", "").await;
            let (_, refused) = delete_secret_of(&router, "hello", "DB_PASSWORD").await;

            [set, again, shown, listed, refused]
        };

        for body in &bodies {
            assert!(!body.contains(VALUE), "{body}");
        }
        while let Ok(event) = logged.try_recv() {
            assert!(!event.message.contains(VALUE), "{}", event.message);
            for (field, value) in &event.fields {
                assert!(!value.contains(VALUE), "{field} = {value}");
            }
        }
    }

    /// A typo in an app id must not quietly store a value under a name nothing
    /// will ever read — where it would sit until somebody applied an app that
    /// happened to be called that.
    #[tokio::test]
    async fn setting_a_secret_for_an_app_nobody_has_heard_of_is_a_404() {
        let (_, router) = store_and_router();

        let (status, body) = put_secret(&router, "ghost", "DB_PASSWORD", "hunter2").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("no app named `ghost`"), "{body}");
        assert_eq!(
            delete_secret_of(&router, "ghost", "DB_PASSWORD").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(get_secrets(&router, "ghost", "").await.1, "");
    }

    /// A value is bytes somebody generated, and an environment variable is not:
    /// a value that cannot be one has to be refused here rather than at the
    /// moment the container will not start.
    #[tokio::test]
    async fn refuses_a_value_that_is_not_text() {
        let (_, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;
        let request = Request::builder()
            .method("PUT")
            .uri("/apps/hello/secrets/DB_PASSWORD")
            .body(Body::from(vec![0xff, 0xfe]))
            .unwrap();

        let (status, body) = call(&router, request).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("not valid utf-8"), "{body}");
        assert_eq!(get_secrets(&router, "hello", "").await.1, "");
    }

    /// The question an operator asks a suspended app: why. The manifest says
    /// what it needs and the store says what it has, and only the two together
    /// name the value that is missing.
    #[tokio::test]
    async fn says_which_of_an_apps_secrets_are_set() {
        let (_, router) = store_and_router();
        put_app(&router, "hello", NEEDS_TWO).await;
        put_secret(&router, "hello", "DB_PASSWORD", "hunter2").await;

        let (status, body) = show_app(&router, "hello", "").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("DB_PASSWORD (set)"), "{body}");
        assert!(body.contains("API_KEY (not set"), "{body}");
        assert!(!body.contains("hunter2"), "{body}");
    }

    async fn create_user_named(router: &Router, slug: &str, email: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/auth/users/{slug}"))
            .body(Body::from(email.to_owned()))
            .unwrap();

        call(router, request).await
    }

    async fn user_command(router: &Router, method: &str, uri: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        call(router, request).await
    }

    /// The id in a `created` response, which is the only place a test can
    /// learn the UUID the server minted.
    fn id_in(body: &str) -> String {
        let id = body
            .lines()
            .find_map(|line| line.trim().strip_prefix("id"))
            .expect("the response names the id")
            .trim()
            .to_owned();
        id.parse::<crate::auth::UserId>().expect("the id is a uuid");

        id
    }

    #[tokio::test]
    async fn creates_a_user_and_lists_them_over_http() {
        let (_, router) = store_and_router();

        let (status, created) = create_user_named(&router, "alice", "alice@example.com").await;
        assert_eq!(status, StatusCode::OK, "{created}");
        assert!(created.contains("user `alice` created"), "{created}");
        assert!(created.contains("alice@example.com"), "{created}");

        let (status, listed) = user_command(&router, "GET", "/auth/users").await;
        assert_eq!(status, StatusCode::OK);
        assert!(listed.contains("USER"), "{listed}");
        assert!(listed.contains("alice"), "{listed}");
        assert!(listed.contains("active"), "{listed}");
        assert!(listed.contains(&id_in(&created)), "{listed}");
    }

    /// An empty pool answers with what to do about it, not with a bare header
    /// over nothing.
    #[tokio::test]
    async fn an_empty_user_pool_says_how_to_fill_it() {
        let (_, router) = store_and_router();

        let (status, body) = user_command(&router, "GET", "/auth/users").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("no users exist"), "{body}");
        assert!(body.contains("spaceport auth user create"), "{body}");
    }

    #[tokio::test]
    async fn lists_only_the_users_a_pattern_asks_for() {
        let (_, router) = store_and_router();
        for slug in ["alice", "bob", "ci-bot"] {
            create_user_named(&router, slug, "").await;
        }

        let (status, body) = user_command(&router, "GET", "/auth/users?pattern=ci-*").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("ci-bot"), "{body}");
        assert!(!body.contains("alice"), "{body}");

        let (status, body) = user_command(&router, "GET", "/auth/users?pattern=ghost-*").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("no user matches `ghost-*`"), "{body}");
    }

    #[tokio::test]
    async fn refuses_a_second_user_under_the_same_slug() {
        let (_, router) = store_and_router();
        create_user_named(&router, "alice", "").await;

        let (status, body) = create_user_named(&router, "alice", "").await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.contains("already answers to `alice`"), "{body}");
    }

    #[tokio::test]
    async fn refuses_a_slug_that_is_not_one() {
        let (_, router) = store_and_router();

        let (status, body) = create_user_named(&router, "2Fast", "").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("lowercase"), "{body}");
    }

    /// `user+ci@example.com` is an ordinary address; a slug pasted where the
    /// address goes is the mistake worth catching.
    #[tokio::test]
    async fn refuses_a_body_that_is_not_an_email_address() {
        let (_, router) = store_and_router();

        let (status, body) = create_user_named(&router, "alice", "not-an-address").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("does not read as an email address"), "{body}");

        let (status, _) = create_user_named(&router, "alice", "user+ci@example.com").await;
        assert_eq!(status, StatusCode::OK);
    }

    /// The two halves of `<slug|user-id>`, driven over HTTP: the slug and the
    /// UUID land on the same user, and suspension shows in the listing.
    #[tokio::test]
    async fn suspends_by_slug_and_resumes_by_id() {
        let (_, router) = store_and_router();
        let (_, created) = create_user_named(&router, "alice", "").await;
        let id = id_in(&created);

        let (status, body) = user_command(&router, "POST", "/auth/users/alice/suspend").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("user `alice` suspended"), "{body}");
        let (_, listed) = user_command(&router, "GET", "/auth/users").await;
        assert!(listed.contains("suspended"), "{listed}");

        let (status, body) =
            user_command(&router, "POST", &format!("/auth/users/{id}/resume")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("user `alice` resumed"), "{body}");
        let (_, listed) = user_command(&router, "GET", "/auth/users").await;
        assert!(listed.contains("active"), "{listed}");
    }

    #[tokio::test]
    async fn a_command_aimed_at_no_user_is_not_found() {
        let (_, router) = store_and_router();

        for (method, uri) in [
            ("POST", "/auth/users/ghost/suspend"),
            ("POST", "/auth/users/ghost/resume"),
            ("DELETE", "/auth/users/ghost"),
        ] {
            let (status, body) = user_command(&router, method, uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}: {body}");
            assert!(body.contains("no user answers to `ghost`"), "{body}");
        }
    }

    /// The never-reused rule, end to end: dropping frees the slug, and the
    /// user created under it again is somebody else.
    #[tokio::test]
    async fn a_dropped_slug_recreated_over_http_yields_a_fresh_id() {
        let (_, router) = store_and_router();
        let (_, first) = create_user_named(&router, "alice", "").await;

        let (status, dropped) = user_command(&router, "DELETE", "/auth/users/alice").await;
        assert_eq!(status, StatusCode::OK, "{dropped}");
        assert!(dropped.contains("never reused"), "{dropped}");

        let (status, second) = create_user_named(&router, "alice", "").await;
        assert_eq!(status, StatusCode::OK, "{second}");
        assert_ne!(id_in(&first), id_in(&second));
    }

    /// The route the spec calls the auth event log: every mutation lands in
    /// it, and `?user=` narrows it to one user's story.
    #[tokio::test]
    async fn the_auth_log_records_every_mutation_and_filters_by_user() {
        let (_, router) = store_and_router();
        let (_, alice) = create_user_named(&router, "alice", "").await;
        let alice = id_in(&alice);
        create_user_named(&router, "bob", "").await;
        user_command(&router, "POST", "/auth/users/alice/suspend").await;
        user_command(&router, "POST", "/auth/users/alice/resume").await;
        user_command(&router, "DELETE", "/auth/users/alice").await;

        let (status, everything) = user_command(&router, "GET", "/auth/log").await;
        assert_eq!(status, StatusCode::OK);
        for kind in [
            "user.created",
            "user.suspended",
            "user.resumed",
            "user.dropped",
        ] {
            assert!(everything.contains(kind), "{everything}");
        }
        assert!(everything.contains("operator"), "{everything}");

        let (status, hers) = user_command(&router, "GET", &format!("/auth/log?user={alice}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(hers.contains("user.dropped"), "{hers}");
        assert!(hers.contains("slug `alice`"), "{hers}");
        assert!(!hers.contains("slug `bob`"), "{hers}");
    }

    #[tokio::test]
    async fn an_empty_auth_log_says_what_it_is_for() {
        let (_, router) = store_and_router();

        let (status, body) = user_command(&router, "GET", "/auth/log").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("nothing has happened yet"), "{body}");
    }

    #[tokio::test]
    async fn refuses_an_auth_log_filter_that_is_not_a_user_id() {
        let (_, router) = store_and_router();

        let (status, body) = user_command(&router, "GET", "/auth/log?user=alice").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("not a user id"), "{body}");
    }

    /// The manual rotation lever, end to end over the socket: the response
    /// names both kids, the listing shows the retired key beside the current
    /// one, and the log entry is the operator's — because this route exists
    /// for compromise response, and its audit trail is the point.
    #[tokio::test]
    async fn rotating_the_signing_key_over_the_socket_retires_and_lists_and_logs() {
        let (_, router) = store_and_router();

        let (status, first) = user_command(&router, "POST", "/auth/keys/rotate").await;
        assert_eq!(status, StatusCode::OK);
        // A spaceport that never signed mints its first key here.
        assert!(first.contains("first jwt signing key"), "{first}");

        let (status, body) = user_command(&router, "POST", "/auth/keys/rotate").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("now signing with"), "{body}");
        assert!(body.contains("retired"), "{body}");
        assert!(
            body.contains("until every jwt it signed has expired"),
            "{body}"
        );

        let (status, listed) = user_command(&router, "GET", "/auth/keys").await;
        assert_eq!(status, StatusCode::OK);
        assert!(listed.contains("current"), "{listed}");
        assert!(listed.contains("retired"), "{listed}");

        let (_, log) = user_command(&router, "GET", "/auth/log").await;
        assert!(log.contains("key.rotated"), "{log}");
        assert!(log.contains("operator"), "{log}");
    }

    #[tokio::test]
    async fn an_unsigned_spaceport_lists_no_keys_and_says_so() {
        let (_, router) = store_and_router();

        let (status, body) = user_command(&router, "GET", "/auth/keys").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("no signing key yet"), "{body}");
    }

    /// A router and the database behind it, for the session tests: redemption
    /// happens on the edge, not on this socket, so a test that needs a live
    /// session redeems the printed code straight through the repository.
    fn router_and_db() -> (Router, Db) {
        let (parts, db, _) = parts_with_state(OneContainer::default(), CONFIG);

        (parts.1, db)
    }

    /// The code out of a mint response — the one place it is ever printed.
    fn code_in(body: &str) -> String {
        body.lines()
            .next()
            .and_then(|line| line.rsplit_once(": "))
            .expect("the response prints the code")
            .1
            .trim()
            .to_owned()
    }

    /// Redeem a mint response's code, as the login page would.
    async fn redeem(db: &Db, minted: &str) -> crate::auth::FreshSession {
        crate::auth::SessionRepository::new(db.clone())
            .redeem(&Secret::new(code_in(minted)))
            .await
            .expect("the printed code redeems")
    }

    /// The mint prints the code exactly once, with the session expiry that was
    /// fixed by `--expires`; the listing that follows shows the session the
    /// code became and never the code or token.
    #[tokio::test]
    async fn mints_a_code_that_redeems_into_a_listed_session() {
        let (router, db) = router_and_db();
        create_user_named(&router, "alice", "").await;

        let (status, minted) =
            user_command(&router, "POST", "/auth/users/alice/sessions?expires=1h").await;
        assert_eq!(status, StatusCode::OK, "{minted}");
        assert!(minted.contains("one-time code for `alice`"), "{minted}");
        assert!(minted.contains("shown once"), "{minted}");
        let code = code_in(&minted);
        assert_eq!(code.len(), 8, "{minted}");

        let fresh = redeem(&db, &minted).await;

        let (status, listed) = user_command(&router, "GET", "/auth/users/alice/sessions").await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert!(listed.contains("KIND"), "{listed}");
        assert!(listed.contains("session"), "{listed}");
        assert!(listed.contains(fresh.id.as_str()), "{listed}");
        assert!(!listed.contains(&code), "{listed}");
        assert!(!listed.contains(fresh.token.expose()), "{listed}");
    }

    #[tokio::test]
    async fn a_user_with_no_sessions_is_told_how_to_start_one() {
        let (router, _) = router_and_db();
        create_user_named(&router, "alice", "").await;

        let (status, body) = user_command(&router, "GET", "/auth/users/alice/sessions").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("has no sessions"), "{body}");
        assert!(body.contains("spaceport auth session mint alice"), "{body}");
    }

    #[tokio::test]
    async fn drops_one_session_by_id_over_http() {
        let (router, db) = router_and_db();
        create_user_named(&router, "alice", "").await;
        let (_, first) = user_command(&router, "POST", "/auth/users/alice/sessions").await;
        let first = redeem(&db, &first).await;
        let (_, second) = user_command(&router, "POST", "/auth/users/alice/sessions").await;
        let second = redeem(&db, &second).await;

        let (status, body) = user_command(
            &router,
            "DELETE",
            &format!("/auth/users/alice/sessions/{}", first.id),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains(&format!("dropped session {}", first.id)),
            "{body}"
        );
        let (_, listed) = user_command(&router, "GET", "/auth/users/alice/sessions").await;
        assert!(!listed.contains(first.id.as_str()), "{listed}");
        assert!(listed.contains(second.id.as_str()), "{listed}");
    }

    #[tokio::test]
    async fn drops_every_session_when_none_is_named() {
        let (router, db) = router_and_db();
        create_user_named(&router, "alice", "").await;
        for _ in 0..2 {
            let (_, minted) = user_command(&router, "POST", "/auth/users/alice/sessions").await;
            redeem(&db, &minted).await;
        }

        let (status, body) = user_command(&router, "DELETE", "/auth/users/alice/sessions").await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("dropped 2 sessions"), "{body}");
        let (_, listed) = user_command(&router, "GET", "/auth/users/alice/sessions").await;
        assert!(listed.contains("has no sessions"), "{listed}");
    }

    #[tokio::test]
    async fn refuses_a_session_command_nobody_can_answer() {
        let (router, _) = router_and_db();
        create_user_named(&router, "alice", "").await;
        user_command(&router, "POST", "/auth/users/alice/suspend").await;

        // A mistyped user is a 404, a suspended one a 409, a bad duration and
        // a bad session id a 400 apiece — each with a sentence to act on.
        let (status, body) = user_command(&router, "POST", "/auth/users/ghost/sessions").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        let (status, body) = user_command(&router, "POST", "/auth/users/alice/sessions").await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.contains("suspended"), "{body}");

        let (status, body) =
            user_command(&router, "POST", "/auth/users/alice/sessions?expires=soon").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        let (status, body) =
            user_command(&router, "DELETE", "/auth/users/alice/sessions/not-an-id").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("not a session id"), "{body}");

        let (status, body) = user_command(
            &router,
            "DELETE",
            "/auth/users/alice/sessions/00000000000000aa",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(body.contains("no such session"), "{body}");
    }

    /// The spec's session verbs land in the same log the user verbs do, with
    /// the mint and the drop stamped as the operator's and the login as the
    /// web's.
    #[tokio::test]
    async fn session_mutations_land_in_the_auth_log() {
        let (router, db) = router_and_db();
        create_user_named(&router, "alice", "").await;
        let (_, minted) = user_command(&router, "POST", "/auth/users/alice/sessions").await;
        redeem(&db, &minted).await;
        user_command(&router, "DELETE", "/auth/users/alice/sessions").await;

        let (status, log) = user_command(&router, "GET", "/auth/log").await;

        assert_eq!(status, StatusCode::OK);
        for kind in ["session.minted", "login.succeeded", "session.dropped"] {
            assert!(log.contains(kind), "{log}");
        }
        assert!(log.contains("web"), "{log}");
        assert!(!log.contains(&code_in(&minted)), "{log}");
    }

    /// An app whose edge declares roles, for the entitlement tests: `blog`
    /// understands `reader` and `writer`, and nothing else.
    const GATED: &str = "schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [blog.test]
auth:
  gating: edge
  roles: [reader, writer]
container:
  health:
    readiness:
      type: none
";

    /// A router with a user `alice` and the gated `blog` app already in place,
    /// which is the stage every entitlement test opens on.
    async fn router_with_alice_and_blog() -> (Router, Db) {
        let ((_, router, ..), db, _) = parts_with_state(OneContainer::default(), CONFIG);
        create_user_named(&router, "alice", "").await;
        let (status, body) = put_app(&router, "blog", GATED).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        (router, db)
    }

    /// Plant a row as an IdP login will one day write it: tagged with the rule
    /// that produced it. Nothing can create one over HTTP yet — mappings are a
    /// later milestone — which is exactly why the refusal has to be tested
    /// through the back door.
    async fn plant_mapped(db: &Db, user: &str, role: &str, app: &str, rule: &str) {
        let (user, role, app, rule) = (
            user.to_owned(),
            role.to_owned(),
            app.to_owned(),
            rule.to_owned(),
        );
        db.call(move |connection| {
            connection
                .execute(
                    "INSERT INTO entitlements
                         (user_id, spaceport_app, role, mapped_rule, granted_at)
                     VALUES (?1, ?2, ?3, ?4, '2026-01-01T00:00:00Z')",
                    rusqlite::params![user, app, role, rule],
                )
                .map(|_| ())
                .map_err(anyhow::Error::from)
        })
        .await
        .unwrap();
    }

    /// The key out of a mint response — the one place it is ever printed.
    fn key_in(body: &str) -> String {
        body.lines()
            .next()
            .and_then(|line| line.rsplit_once(": "))
            .expect("the response prints the key")
            .1
            .trim()
            .to_owned()
    }

    /// The key id out of a mint response's `id` line.
    fn key_id_in(body: &str) -> String {
        body.lines()
            .find_map(|line| line.trim().strip_prefix("id "))
            .expect("the response prints the key id")
            .trim()
            .to_owned()
    }

    /// The mint prints the key exactly once — `spk_`-prefixed, beside its id
    /// and what it grants — and the listing that follows shows the tail
    /// glimpse and never the credential.
    #[tokio::test]
    async fn mints_an_api_key_shown_once_and_listed_as_its_tail() {
        let (router, _) = router_with_alice_and_blog().await;

        let (status, minted) = user_command(
            &router,
            "POST",
            "/auth/users/alice/api-keys/reader@blog?expires=30d",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{minted}");
        assert!(minted.contains("api key for `alice`: spk_"), "{minted}");
        assert!(minted.contains("shown once"), "{minted}");
        assert!(minted.contains("role `reader` at app `blog`"), "{minted}");
        assert!(!minted.contains("warning"), "{minted}");
        let key = key_in(&minted);
        let id = key_id_in(&minted);

        let (status, listed) = user_command(&router, "GET", "/auth/users/alice/sessions").await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert!(listed.contains("key"), "{listed}");
        assert!(listed.contains(&id), "{listed}");
        assert!(listed.contains("spk_…"), "{listed}");
        assert!(listed.contains("reader@blog"), "{listed}");
        assert!(!listed.contains(&key), "{listed}");
    }

    /// The `grant` semantics, mirrored: a role the deployed manifest does not
    /// declare still mints — granting ahead of the deploy is the ordinary
    /// order — with the warning beside the key rather than instead of it.
    #[tokio::test]
    async fn an_api_key_mint_for_an_undeclared_role_warns_but_mints() {
        let (router, _) = router_with_alice_and_blog().await;

        let (status, body) =
            user_command(&router, "POST", "/auth/users/alice/api-keys/ghost@blog").await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("api key for `alice`: spk_"), "{body}");
        assert!(body.contains("warning"), "{body}");
        assert!(body.contains("does not declare role `ghost`"), "{body}");
    }

    /// The refusals, each with the status whose problem it is: a mistyped
    /// user a 404, a suspended one a 409, a bad duration or grants a 400.
    #[tokio::test]
    async fn refuses_an_api_key_mint_nobody_can_answer() {
        let (router, _) = router_with_alice_and_blog().await;

        let (status, body) =
            user_command(&router, "POST", "/auth/users/ghost/api-keys/reader@blog").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        let (status, body) = user_command(
            &router,
            "POST",
            "/auth/users/alice/api-keys/reader@blog?expires=soon",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        let (status, body) =
            user_command(&router, "POST", "/auth/users/alice/api-keys/reader").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("not an entitlement"), "{body}");

        user_command(&router, "POST", "/auth/users/alice/suspend").await;
        let (status, body) =
            user_command(&router, "POST", "/auth/users/alice/api-keys/reader@blog").await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.contains("suspended"), "{body}");
    }

    /// `session drop <user> <key-id>` revokes exactly that key, and the log
    /// carries the mint and the revoke — never the credential.
    #[tokio::test]
    async fn a_key_drop_revokes_it_and_the_log_says_so() {
        let (router, _) = router_with_alice_and_blog().await;
        let (_, minted) =
            user_command(&router, "POST", "/auth/users/alice/api-keys/reader@blog").await;
        let key = key_in(&minted);
        let id = key_id_in(&minted);

        let (status, body) = user_command(
            &router,
            "DELETE",
            &format!("/auth/users/alice/sessions/{id}"),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains(&format!("revoked api key {id}")), "{body}");
        let (_, listed) = user_command(&router, "GET", "/auth/users/alice/sessions").await;
        assert!(!listed.contains(&id), "{listed}");

        let (_, log) = user_command(&router, "GET", "/auth/log").await;
        assert!(log.contains("key.minted"), "{log}");
        assert!(log.contains("key.revoked"), "{log}");
        assert!(!log.contains(&key), "{log}");
    }

    /// The bare drop is the spec's "all sessions and keys": one command, both
    /// credentials gone, each named by its own verb.
    #[tokio::test]
    async fn a_bare_session_drop_takes_keys_too() {
        let ((_, router, ..), db, _) = parts_with_state(OneContainer::default(), CONFIG);
        create_user_named(&router, "alice", "").await;
        let (_, minted) = user_command(&router, "POST", "/auth/users/alice/sessions").await;
        redeem(&db, &minted).await;
        user_command(&router, "POST", "/auth/users/alice/api-keys/reader@blog").await;

        let (status, body) = user_command(&router, "DELETE", "/auth/users/alice/sessions").await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("dropped session"), "{body}");
        assert!(body.contains("revoked api key"), "{body}");
        let (_, listed) = user_command(&router, "GET", "/auth/users/alice/sessions").await;
        assert!(listed.contains("has no sessions or api keys"), "{listed}");
    }

    /// The happy path the spec is for: a declared role, granted, audited,
    /// opening the app — and no warning anywhere near it.
    #[tokio::test]
    async fn grants_a_declared_role_and_the_audit_shows_the_access() {
        let (router, _) = router_with_alice_and_blog().await;

        let (status, body) =
            user_command(&router, "PUT", "/auth/users/alice/entitlements/reader@blog").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("granted `reader@blog` to `alice`"), "{body}");
        assert!(!body.contains("warning"), "{body}");

        let (status, audit) = user_command(&router, "GET", "/auth/users/alice/audit").await;
        assert_eq!(status, StatusCode::OK, "{audit}");
        assert!(audit.contains("reader@blog"), "{audit}");
        assert!(audit.contains("manual"), "{audit}");
        assert!(audit.contains("blog"), "{audit}");
        assert!(audit.contains("SSO is a later milestone"), "{audit}");
    }

    /// The spec's one sentence about undeclared roles: stored nevertheless,
    /// with a warning — in the response an operator reads and on the stream
    /// one greps.
    #[tokio::test]
    async fn a_grant_for_an_undeclared_role_is_stored_but_warns() {
        let (router, _) = router_with_alice_and_blog().await;

        let (status, body) =
            user_command(&router, "PUT", "/auth/users/alice/entitlements/editor@blog").await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("granted `editor@blog` to `alice`"), "{body}");
        assert!(
            body.contains("warning: app `blog` does not declare role `editor`"),
            "{body}"
        );

        // Stored: the audit lists it, flagged as opening nothing.
        let (_, audit) = user_command(&router, "GET", "/auth/users/alice/audit").await;
        assert!(audit.contains("editor@blog"), "{audit}");
        assert!(audit.contains("role not declared"), "{audit}");
        assert!(audit.contains("no app"), "{audit}");
    }

    /// Granting for an app spaceport has never heard of is the same story one
    /// step earlier — the ordinary case being an operator granting ahead of
    /// the first deploy.
    #[tokio::test]
    async fn a_grant_for_an_unknown_app_is_stored_but_warns() {
        let (router, _) = router_with_alice_and_blog().await;

        let (status, body) = user_command(
            &router,
            "PUT",
            "/auth/users/alice/entitlements/reader@ghost",
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("granted `reader@ghost`"), "{body}");
        assert!(
            body.contains("warning: spaceport runs no app `ghost`"),
            "{body}"
        );
    }

    /// An app with `gating: open` declares no roles, so any grant for it can
    /// only ever gate nothing — worth its own wording.
    #[tokio::test]
    async fn a_grant_for_an_open_app_warns_that_it_gates_nothing() {
        let (router, _) = router_with_alice_and_blog().await;
        put_app(&router, "open-app", MANIFEST).await;

        let (status, body) = user_command(
            &router,
            "PUT",
            "/auth/users/alice/entitlements/reader@open-app",
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("`gating: open`"), "{body}");
    }

    /// The idempotence the primary key buys, seen from the socket: the second
    /// grant succeeds, says nothing changed, and the log counts one grant.
    #[tokio::test]
    async fn granting_twice_over_http_says_already_granted() {
        let (router, _) = router_with_alice_and_blog().await;
        user_command(&router, "PUT", "/auth/users/alice/entitlements/reader@blog").await;

        let (status, body) =
            user_command(&router, "PUT", "/auth/users/alice/entitlements/reader@blog").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("already granted"), "{body}");
        assert!(body.contains("nothing changed"), "{body}");

        let (_, log) = user_command(&router, "GET", "/auth/log").await;
        assert_eq!(log.matches("entitlement.granted").count(), 1, "{log}");
    }

    /// The three widths of a revoke: one role, one app, everything — each
    /// taking exactly what it names and nothing beside it.
    #[tokio::test]
    async fn revokes_one_role_a_whole_app_or_everything() {
        let (router, _) = router_with_alice_and_blog().await;
        for entitlement in ["reader@blog", "writer@blog", "reader@wiki", "reader@docs"] {
            user_command(
                &router,
                "PUT",
                &format!("/auth/users/alice/entitlements/{entitlement}"),
            )
            .await;
        }

        // One role: `writer@blog` stays.
        let (status, body) = user_command(
            &router,
            "DELETE",
            "/auth/users/alice/entitlements/reader@blog",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains("revoked `reader@blog` from `alice`"),
            "{body}"
        );
        let (_, audit) = user_command(&router, "GET", "/auth/users/alice/audit").await;
        assert!(audit.contains("writer@blog"), "{audit}");

        // One app: only `blog`'s remaining role goes.
        let (status, body) =
            user_command(&router, "DELETE", "/auth/users/alice/entitlements/blog").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains("revoked `writer@blog` from `alice`"),
            "{body}"
        );

        // Everything: the slate is wiped across apps.
        let (status, body) =
            user_command(&router, "DELETE", "/auth/users/alice/entitlements").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains("revoked 2 entitlements from `alice`"),
            "{body}"
        );
        assert!(body.contains("reader@wiki"), "{body}");
        assert!(body.contains("reader@docs"), "{body}");
        let (_, audit) = user_command(&router, "GET", "/auth/users/alice/audit").await;
        assert!(audit.contains("no entitlements"), "{audit}");
    }

    /// The refusal built ahead of its trigger: a mapped entitlement is not the
    /// operator's to revoke, and the conflict names the rule that is.
    #[tokio::test]
    async fn refuses_to_revoke_a_mapped_entitlement_and_names_the_rule() {
        let (router, db) = router_with_alice_and_blog().await;
        let (_, listed) = user_command(&router, "GET", "/auth/users").await;
        let alice = listed
            .lines()
            .find(|line| line.starts_with("alice"))
            .and_then(|line| line.split_whitespace().nth(1))
            .expect("the listing names alice's id")
            .to_owned();
        plant_mapped(&db, &alice, "reader", "blog", "rule-7").await;

        let (status, body) = user_command(
            &router,
            "DELETE",
            "/auth/users/alice/entitlements/reader@blog",
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.contains("nothing was revoked"), "{body}");
        assert!(body.contains("rule-7"), "{body}");
        // Still standing, and the audit says where it came from.
        let (_, audit) = user_command(&router, "GET", "/auth/users/alice/audit").await;
        assert!(audit.contains("mapped by rule `rule-7`"), "{audit}");
    }

    /// A sweep that meets both kinds takes the manual rows and names what the
    /// mapping held on to, rather than failing over rows it may not touch.
    #[tokio::test]
    async fn a_broad_revoke_names_the_mapped_rows_it_kept() {
        let (router, db) = router_with_alice_and_blog().await;
        let (_, listed) = user_command(&router, "GET", "/auth/users").await;
        let alice = listed
            .lines()
            .find(|line| line.starts_with("alice"))
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap()
            .to_owned();
        user_command(&router, "PUT", "/auth/users/alice/entitlements/writer@blog").await;
        plant_mapped(&db, &alice, "reader", "blog", "rule-7").await;

        let (status, body) =
            user_command(&router, "DELETE", "/auth/users/alice/entitlements/blog").await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("revoked `writer@blog`"), "{body}");
        assert!(body.contains("kept `reader@blog`"), "{body}");
        assert!(body.contains("rule `rule-7`"), "{body}");
    }

    /// A revoke that matches nothing is a mistyped name, and answers like one.
    #[tokio::test]
    async fn a_revoke_that_matches_nothing_is_not_found() {
        let (router, _) = router_with_alice_and_blog().await;

        let (status, body) = user_command(
            &router,
            "DELETE",
            "/auth/users/alice/entitlements/reader@blog",
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(body.contains("no such entitlement"), "{body}");
        assert!(body.contains("spaceport auth audit"), "{body}");
    }

    /// Entitlement commands aimed at nobody get the user pool's refusal, not a
    /// new one.
    #[tokio::test]
    async fn an_entitlement_command_aimed_at_no_user_is_not_found() {
        let (router, _) = router_with_alice_and_blog().await;

        for (method, uri) in [
            ("PUT", "/auth/users/ghost/entitlements/reader@blog"),
            ("DELETE", "/auth/users/ghost/entitlements/reader@blog"),
            ("DELETE", "/auth/users/ghost/entitlements"),
            ("GET", "/auth/users/ghost/audit"),
        ] {
            let (status, body) = user_command(&router, method, uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}: {body}");
            assert!(body.contains("no user answers to `ghost`"), "{body}");
        }
    }

    /// The spec's drop cascade over HTTP: the user goes, their entitlements go
    /// with them in the same commit, and the recreated slug starts clean.
    #[tokio::test]
    async fn dropping_a_user_takes_their_entitlements_with_them() {
        let (router, db) = router_with_alice_and_blog().await;
        user_command(&router, "PUT", "/auth/users/alice/entitlements/reader@blog").await;

        user_command(&router, "DELETE", "/auth/users/alice").await;

        let rows: i64 = db
            .call(|connection| {
                connection
                    .query_row("SELECT count(*) FROM entitlements", [], |row| row.get(0))
                    .map_err(anyhow::Error::from)
            })
            .await
            .unwrap();
        assert_eq!(rows, 0);

        // And the drop is in the log while per-row revokes are not: the rows
        // went as a cascade of the drop, not as commands somebody gave.
        let (_, log) = user_command(&router, "GET", "/auth/log").await;
        assert!(log.contains("user.dropped"), "{log}");
        assert!(!log.contains("entitlement.revoked"), "{log}");
    }

    /// What the log gains from this milestone: grants and revokes land beside
    /// the user events, each naming the role and the app it was about.
    #[tokio::test]
    async fn the_log_records_grants_and_revokes() {
        let (router, _) = router_with_alice_and_blog().await;
        user_command(&router, "PUT", "/auth/users/alice/entitlements/reader@blog").await;
        user_command(
            &router,
            "DELETE",
            "/auth/users/alice/entitlements/reader@blog",
        )
        .await;

        let (status, log) = user_command(&router, "GET", "/auth/log").await;

        assert_eq!(status, StatusCode::OK);
        assert!(log.contains("entitlement.granted"), "{log}");
        assert!(log.contains("entitlement.revoked"), "{log}");
        assert!(log.contains("role `reader` at app `blog`"), "{log}");
    }
}

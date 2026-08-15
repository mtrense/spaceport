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
use axum::routing::{get, post, put};
use bytes::Bytes;
use futures_util::StreamExt;
use http::StatusCode;
use serde::Deserialize;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::OperatorEndpoint;
use crate::app::apply::{Applied, Applier, ApplyError, DestroyError, ResumeError, SuspendError};
use crate::app::{App, AppId, AppManifest, AppRepository, DataDir, Pattern, health};
use crate::build::repository::{Build, BuildRepository, BuildState};
use crate::connections::github::{
    Client, ConnectionRepository, Installation, Nudge, Registration, Tracking, TrackingRepository,
    Transport, manifest, register,
};
use crate::events::{Event, EventBus, EventFilter, Level};
use crate::runtime::Adopted;
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

    (
        StatusCode::OK,
        report(&id, &held, &status, applied_at.as_deref(), &data, origin),
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
}

/// What is deployed against what is waiting, for one app's report.
///
/// A read that fails is answered as nothing waiting, on [`built`]'s reasoning:
/// the rest of the report is still worth having, and the build stanza above
/// this one has already said that the store would not answer.
async fn deployment(builds: &BuildRepository, id: &AppId, deployed: Option<String>) -> Deployment {
    Deployment {
        deployed,
        built: builds
            .latest_built(id)
            .await
            .ok()
            .flatten()
            .map(|build| build.revision),
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
fn report(
    id: &AppId,
    held: &Held,
    status: &str,
    applied_at: Option<&str>,
    data: &DataDir,
    origin: Option<Origin<'_>>,
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

    for (index, secret) in container.secrets.iter().enumerate() {
        out.field(
            if index == 0 { "secrets" } else { "" },
            format!("{secret} (not supported yet)"),
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
    deploys(out, id, origin.deployment);
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
    // one, so this says nothing about which.
    out.field(
        "",
        format!(
            "run what a build produced with `spaceport apps deploy {id}`, which applies the manifest the commit carried — or apply one of your own with `spaceport apps apply {id} …`"
        ),
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
/// looks like an answer to it and is not: spaceport builds every push and
/// deploys none of them, so an image finishing is exactly the moment at which
/// the two numbers part company.
///
/// Nothing at all when neither is known, like every other section here: an app
/// tracked a minute ago has nothing to say on this and should not be given a
/// line saying so.
fn deploys(out: &mut Report, id: &AppId, deployment: &Deployment) {
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
                    "  a newer build is waiting at {built} — run it with `spaceport apps deploy {id}`"
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
                "nothing built here is running — {built} is waiting, run it with `spaceport apps deploy {id}`"
            ),
        ),
        (None, None) => {}
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
                ApplyError::Conflict(_) => StatusCode::CONFLICT,
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

    match applier
        .deploy(id, manifest, Some(&build.revision), false)
        .await
    {
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
                ApplyError::Conflict(_) => StatusCode::CONFLICT,
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
async fn resume(State(applier): State<Arc<Applier>>, UrlPath(id): UrlPath<String>) -> Response {
    let id: AppId = match id.parse() {
        Ok(id) => id,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    match applier.resume(&id).await {
        Ok(app) => {
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
                ResumeError::Conflict(_) => StatusCode::CONFLICT,
                ResumeError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };

            refuse(status, &error.to_string())
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
/// None of it is deployed by anything: what a build produces is an image, and
/// running it is `spaceport apps deploy`, which is a decision an operator takes.
/// The response says so, because an operator who has just pointed an app at a
/// branch would otherwise sit waiting for a deployment that is not coming.
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
async fn track(
    State(instance): State<Arc<Instance>>,
    State(connections): State<Arc<ConnectionRepository>>,
    State(tracking): State<Arc<TrackingRepository>>,
    State(github): State<Arc<dyn Transport>>,
    State(building): State<Building>,
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

    if let Err(error) = tracking
        .record(&Tracking {
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
        })
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

    let head = abbreviated(&head);

    // What the last lines say turns on whether there is anything to deploy to.
    // A read that fails is taken as the app having a manifest, because that is
    // the case the sentence is vaguest about and so the safer one to be wrong
    // in: it promises nothing that is not true of both.
    let last = if holds(&instance, &id).await.unwrap_or(true) {
        format!(
            "  `{branch}` is at {head}, which is being built now, and every push to it is built from here on\n  what comes out is deployed by nothing — run it with `spaceport apps deploy {id}`\n"
        )
    } else {
        format!(
            "  nothing has been applied under `{id}`, so spaceport knows where its code is and has nothing to run\n  `{branch}` is at {head}, which is being built now, and every push to it is built from here on\n  `spaceport apps deploy {id}` then runs what came out, manifest and all\n"
        )
    };

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

fn refuse(status: StatusCode, message: &str) -> Response {
    (status, format!("{message}\n")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{App, AppRepository, AppStore};
    use crate::connections::github::api::testing::{FakeGitHub, HEAD};
    use crate::events::Level;
    use crate::runtime::{Container, ContainerId, ContainerRuntime, Managed};
    use crate::state::Db;
    use async_trait::async_trait;
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    /// Every app it starts ends up at the same address, which nothing is
    /// listening on unless a test says otherwise.
    struct OneContainer {
        upstream: SocketAddr,
    }

    impl Default for OneContainer {
        fn default() -> Self {
            Self {
                upstream: SocketAddr::from(([127, 0, 0, 1], 9000)),
            }
        }
    }

    #[async_trait]
    impl ContainerRuntime for OneContainer {
        async fn launch(&self, app: &AppId, _manifest: &AppManifest) -> Result<Container> {
            Ok(Container {
                id: ContainerId::new(format!("{app}0123456789abcdef")),
                upstream: self.upstream,
            })
        }

        async fn remove(&self, _id: &ContainerId) -> Result<()> {
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
        let (_, router, events, _, _, _, _, _, _) = parts_on(OneContainer::default());

        (router, events)
    }

    /// A router and the GitHub behind it, for the connection tests — which are
    /// the only ones that care what GitHub answers.
    fn router_and_github() -> (Router, Arc<FakeGitHub>) {
        let (_, router, _, _, github, _, _, _, _) = parts_on(OneContainer::default());

        (router, github)
    }

    fn store_router_and_events_on(runtime: OneContainer) -> (Arc<AppStore>, Router, Arc<EventBus>) {
        let (store, router, events, _, _, _, _, _, _) = parts_on(runtime);

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
        let store = Arc::new(AppStore::new());
        let db = Db::in_memory().unwrap();
        let applier = Arc::new(Applier::new(
            store.clone(),
            Arc::new(runtime),
            AppRepository::new(db.clone()),
            BuildRepository::new(db.clone()),
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
            db,
            certificates: None,
            reconciled: crate::app::reconcile::Report::default(),
        });

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
        let (_, router, _, shutdown, _, _, _, _, _) = parts_on(OneContainer::default());
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
        let (_, router, _, _, _, connections, _, _, _) = parts_on(OneContainer::default());
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
        let (_, router, _, _, _, connections, _, _, _) = parts_on(OneContainer::default());
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
        let (_, router, _, _, github, connections, tracking, builds, building) =
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
        let (store, router, _, _, _, connections, _, builds, _) = parts_on(OneContainer::default());
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
        let (_, router, _, _, _, connections, _, builds, _) = parts_on(OneContainer::default());
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
        let (_, router, _, _, _, connections, _, builds, _) = parts_on(OneContainer::default());
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
        let (_, router, _, _, _, connections, _, builds, _) = parts_on(OneContainer::default());
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
        let (_, router, _, _, _, connections, _, builds, _) = parts_on(OneContainer::default());
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
        let (store, router, _, _, _, connections, _, builds, _) = parts_on(OneContainer::default());
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
        let (_, router, _, _, _, connections, _, builds, _) = parts_on(OneContainer::default());
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

    /// An app that is only tracked and has an image waiting is one command away
    /// from running, and that command is the whole of what its report has to
    /// say.
    #[tokio::test]
    async fn tells_a_tracked_app_with_an_image_to_deploy_it() {
        let (_, router, _, _, _, connections, _, builds, _) = parts_on(OneContainer::default());
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
}

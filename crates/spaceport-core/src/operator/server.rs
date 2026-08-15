//! The operator interface's server side.
//!
//! Plain HTTP over whichever endpoint was configured, so the client is a few
//! lines of hyper and anything else that can speak to a socket — `curl
//! --unix-socket` included — can drive spaceport too. Bodies are the manifest
//! files themselves, verbatim; responses are plain text meant to be read by a
//! person, because that is who is running the command.

use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Body;
use axum::extract::{FromRef, Path as UrlPath, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
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
use crate::connections::github::{
    ConnectionRepository, Registration, Transport, manifest, register,
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

impl FromRef<Operator> for Arc<dyn Transport> {
    fn from_ref(operator: &Operator) -> Self {
        operator.instance.github.clone()
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
async fn list(State(applier): State<Arc<Applier>>, Query(query): Query<ListQuery>) -> Response {
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
    let store = applier.store();
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

    if running.is_empty() && suspended.is_empty() {
        let body = match &pattern {
            Some(pattern) => format!("no app matches `{pattern}`\n"),
            None => "no apps are running\n".to_owned(),
        };

        return (StatusCode::OK, body).into_response();
    }

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
    rows.sort_by(|a, b| a.id.cmp(&b.id));

    (StatusCode::OK, table(&rows)).into_response()
}

/// `GET /apps/{id}?manifest=`: everything spaceport knows about one app.
///
/// The report is what an operator reads; `?manifest=true` is the document they
/// applied, byte for byte and on its own, so that
/// `spaceport apps show x --manifest > x.yaml` gives back a file
/// `spaceport apps apply` takes.
///
/// Answers for an app that is recorded but not in the routing table at all —
/// the one spaceport failed to bring back at startup — because that is exactly
/// the app somebody is asking about.
async fn show(
    State(instance): State<Arc<Instance>>,
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
                return refuse(StatusCode::NOT_FOUND, &format!("no app named `{id}`"));
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

    // Only for the timestamp: everything else is already in hand, and an app
    // that is running is worth reporting on even if the state store has since
    // become unreadable.
    let applied_at = AppRepository::new(instance.db.clone())
        .recorded(&id)
        .await
        .ok()
        .flatten()
        .map(|record| record.applied_at);

    let status = match &held {
        Held::Running(app) => statuses(std::slice::from_ref(app)).await[0].to_owned(),
        Held::Suspended(_) => "suspended".to_owned(),
        Held::Down(downed) => format!("down ({})", downed.reason),
        Held::Recorded(_) => "not running".to_owned(),
    };

    let data = DataDir::new(instance.config.data.directory.clone());

    (
        StatusCode::OK,
        report(&id, &held, &status, applied_at.as_deref(), &data),
    )
        .into_response()
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

    out.render()
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
async fn destroy(State(applier): State<Arc<Applier>>, UrlPath(id): UrlPath<String>) -> Response {
    let id: AppId = match id.parse() {
        Ok(id) => id,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };

    match applier.destroy(&id).await {
        Ok(app) => {
            let body = match app.container() {
                Some(container) => {
                    format!("app `{}` destroyed\n  container {container}\n", app.id())
                }
                None => format!("app `{}` destroyed\n  it had no container\n", app.id()),
            };

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

    match register::connect(&connections, github, registration).await {
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

    let name = request.name.unwrap_or_else(|| default_name(&hostname));
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
/// that is already unique — `spaceport` on its own is long taken. Trimmed to
/// [`NAME_LIMIT`], and to no trailing hyphen, so what is left still reads as a
/// name rather than as a cut-off one.
fn default_name(hostname: &str) -> String {
    let name: String = hostname
        .replace('.', "-")
        .chars()
        .take(NAME_LIMIT)
        .collect();

    name.trim_end_matches('-').to_owned()
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
                        "{} ({}), {} repositories",
                        installation.account,
                        installation.account_type.to_lowercase(),
                        installation.repositories.len(),
                    ),
                );
            }
        }
        Err(error) => out.field("installed", format!("could not be read: {error:#}")),
    }

    // How old that answer is, which is the question behind "why is my
    // repository not here" — a cache nothing has refreshed yet and a cache
    // refreshed a minute ago call for quite different next steps.
    match connections.last_reconciled(held.app_id).await {
        Ok(Some(reconciled)) => out.field("refreshed", reconciled),
        Ok(None) => out.field("refreshed", "not yet — the first pass is hourly".to_owned()),
        Err(error) => out.field("refreshed", format!("could not be read: {error:#}")),
    }

    (StatusCode::OK, out.render()).into_response()
}

/// `DELETE /connections/{slug}`: forget the app, and everything cached under
/// it.
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
    use crate::connections::github::api::testing::FakeGitHub;
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
        let (_, router, events, _, _) = parts_on(OneContainer::default());

        (router, events)
    }

    /// A router and the GitHub behind it, for the connection tests — which are
    /// the only ones that care what GitHub answers.
    fn router_and_github() -> (Router, Arc<FakeGitHub>) {
        let (_, router, _, _, github) = parts_on(OneContainer::default());

        (router, github)
    }

    fn store_router_and_events_on(runtime: OneContainer) -> (Arc<AppStore>, Router, Arc<EventBus>) {
        let (store, router, events, _, _) = parts_on(runtime);

        (store, router, events)
    }

    /// Everything a test might want a hand on, shutdown token included.
    fn parts_on(
        runtime: OneContainer,
    ) -> (
        Arc<AppStore>,
        Router,
        Arc<EventBus>,
        CancellationToken,
        Arc<FakeGitHub>,
    ) {
        parts_configured(runtime, CONFIG)
    }

    /// A router over a spaceport that answers to a hostname of its own, which
    /// is the only thing the manifest flow needs and nothing else here has.
    fn router_answering_to_a_hostname() -> Router {
        let config = CONFIG.replace("edge:\n", "edge:\n  hostname: spaceport.example.com\n");

        parts_configured(OneContainer::default(), &config).1
    }

    fn parts_configured(
        runtime: OneContainer,
        config: &str,
    ) -> (
        Arc<AppStore>,
        Router,
        Arc<EventBus>,
        CancellationToken,
        Arc<FakeGitHub>,
    ) {
        let store = Arc::new(AppStore::new());
        let db = Db::in_memory().unwrap();
        let applier = Arc::new(Applier::new(
            store.clone(),
            Arc::new(runtime),
            AppRepository::new(db.clone()),
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

        let instance = Arc::new(Instance {
            version: "9.9.9".to_owned(),
            started_at: time::OffsetDateTime::now_utc(),
            config_path: "/etc/spaceport/spaceport.yaml".into(),
            config: crate::Config::parse(config).unwrap(),
            operator: "/run/spaceport.sock".parse().unwrap(),
            applier,
            connections: Arc::new(ConnectionRepository::new(db.clone())),
            github: github.clone(),
            attempts: Arc::new(crate::connections::github::Attempts::new()),
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
        let (_, router, _, shutdown, _) = parts_on(OneContainer::default());
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

    #[tokio::test]
    async fn keeps_the_app_when_a_later_one_conflicts() {
        let (store, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;
        put_app(&router, "other", MANIFEST).await;

        let app: Arc<App> = store.get(&"hello".parse().unwrap()).unwrap();
        assert_eq!(store.routes().serving("alpha.test").unwrap().id, app.id);
    }
}

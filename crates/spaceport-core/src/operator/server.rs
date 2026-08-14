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
use crate::app::{App, AppId, AppManifest, Pattern, health};
use crate::events::{Event, EventBus, EventFilter, Level};
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
        .route("/apps/{id}", put(apply).delete(destroy))
        .route("/apps/{id}/suspend", post(suspend))
        .route("/apps/{id}/resume", post(resume))
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
    let rows: Vec<[String; 4]> = apps
        .iter()
        .map(|app| {
            let hosts: Vec<&str> = app.hosts.iter().map(|host| host.as_str()).collect();

            [
                app.id.to_string(),
                app.source.clone(),
                app.status.to_owned(),
                hosts.join(", "),
            ]
        })
        .collect();

    let headers = ["APP", "SOURCE", "STATUS", "HOSTS"];
    let mut widths = headers.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }

    let mut out = String::new();
    for row in std::iter::once(headers.map(str::to_owned)).chain(rows) {
        let mut line = String::new();
        for (cell, width) in row.iter().zip(widths) {
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

fn refuse(status: StatusCode, message: &str) -> Response {
    (status, format!("{message}\n")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{App, AppRepository, AppStore};
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
        let (_, router, events, _) = parts_on(OneContainer::default());

        (router, events)
    }

    fn store_router_and_events_on(runtime: OneContainer) -> (Arc<AppStore>, Router, Arc<EventBus>) {
        let (store, router, events, _) = parts_on(runtime);

        (store, router, events)
    }

    /// Everything a test might want a hand on, shutdown token included.
    fn parts_on(
        runtime: OneContainer,
    ) -> (Arc<AppStore>, Router, Arc<EventBus>, CancellationToken) {
        let store = Arc::new(AppStore::new());
        let db = Db::in_memory().unwrap();
        let applier = Arc::new(Applier::new(
            store.clone(),
            Arc::new(runtime),
            AppRepository::new(db.clone()),
        ));
        let events = Arc::new(EventBus::new());
        let shutdown = CancellationToken::new();

        let instance = Arc::new(Instance {
            version: "9.9.9".to_owned(),
            started_at: time::OffsetDateTime::now_utc(),
            config_path: "/etc/spaceport/spaceport.yaml".into(),
            config: crate::Config::parse(CONFIG).unwrap(),
            operator: "/run/spaceport.sock".parse().unwrap(),
            applier,
            db,
            certificates: None,
            reconciled: crate::app::reconcile::Report::default(),
        });

        (
            store,
            router(instance, events.clone(), shutdown.clone()),
            events,
            shutdown,
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
        let (_, router, _, shutdown) = parts_on(OneContainer::default());
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

    #[tokio::test]
    async fn keeps_the_app_when_a_later_one_conflicts() {
        let (store, router) = store_and_router();
        put_app(&router, "hello", MANIFEST).await;
        put_app(&router, "other", MANIFEST).await;

        let app: Arc<App> = store.get(&"hello".parse().unwrap()).unwrap();
        assert_eq!(store.routes().serving("alpha.test").unwrap().id, app.id);
    }
}

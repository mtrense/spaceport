//! Keeping running the apps spaceport was told to run.
//!
//! Reconciliation happens once, at startup, and settles what should be running
//! against what is. Everything after that is drift: a container exits, an app
//! deadlocks, somebody stops one by hand, the host runs out of memory. Without
//! this, spaceport would go on routing traffic to all of it until an operator
//! noticed and applied the manifest again.
//!
//! Two ways of finding out, because neither is enough on its own. The engine's
//! event stream is the fast one — a container that dies is heard about in the
//! same second — but a stream can break, and a watcher that only ever reacted
//! to events would take a broken connection for a quiet host. So there is also
//! a sweep on a timer, which asks the engine outright what it is running and
//! compares that with what spaceport thinks. The sweep is what makes the
//! supervision correct; the events are what make it quick.
//!
//! A third way for the case the other two cannot see: an app whose container is
//! up and which has stopped working. Only the app can answer that, and only if
//! its manifest asked to be asked — a `liveness` check is a standing
//! instruction to restart, and spaceport does not assume one.
//!
//! What it does about all of it is the same thing: take the app out of service
//! so the edge answers for it rather than forwarding into nothing, start it
//! again, and back off when that does not work. It gives up eventually. An app
//! that has failed to start ten times in a row is not going to start on the
//! eleventh for any reason spaceport can supply, and a host quietly relaunching
//! a broken container forever is worse than one that says it has stopped
//! trying.
//!
//! Two things it never touches. A suspended app is not down, it is where an
//! operator put it. And an app the applier is in the middle of a verb on is not
//! broken, however much the engine's report of its old container being replaced
//! looks like it — [`Applier::is_settling`] is what tells those apart.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::manifest::Check;
use super::store::Downed;
use super::{App, AppId, Applier, health};
use crate::runtime::{ContainerId, RuntimeEvent};

/// How hard spaceport tries to get an app back, and how long it waits to find
/// out that it has to.
///
/// One struct rather than four constants because these numbers only mean
/// anything together — the number of attempts is a length of time only when
/// read against the backoff — and because a test that had to sit out the real
/// ones would take four minutes to find out what it already knows.
///
/// Not configurable from a manifest. Every app on a host wants the same answer
/// to "how long should a crash loop go on for", and the operator who genuinely
/// wants a different one wants a different app.
#[derive(Debug, Clone)]
struct Policy {
    /// How long to wait before the first attempt to start an app again.
    ///
    /// Short: the overwhelming majority of restarts are an app that crashed and
    /// will come straight back up, and every moment here is a moment of 503s.
    first_backoff: Duration,

    /// The longest spaceport waits between attempts.
    ///
    /// The failures that survive a minute of backoff are the ones nothing here
    /// can fix — a missing image, a full disk, a config the app refuses — and
    /// trying them faster than this only fills the log.
    longest_backoff: Duration,

    /// How many attempts in a row may fail before spaceport stops trying.
    ///
    /// With the backoff above, that is a little over four minutes of trying. An
    /// app that has not come up in four minutes of restarts is not going to,
    /// and leaving it as a fault an operator can read is more use than going on
    /// relaunching a container that does not work.
    attempts: u32,

    /// How often to ask the engine what it is actually running.
    ///
    /// The backstop for everything the event stream missed. Not frequent: it is
    /// a listing of a handful of containers, and the events are what make the
    /// common case quick.
    sweep: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            first_backoff: Duration::from_secs(1),
            longest_backoff: Duration::from_secs(60),
            attempts: 10,
            sweep: Duration::from_secs(60),
        }
    }
}

impl Policy {
    /// How long to wait after `failures` attempts in a row.
    ///
    /// Doubles from the first attempt's wait, and stops doubling at the
    /// longest. Shifting a saturating multiply rather than doubling in a loop,
    /// so that a pathological number of failures cannot overflow its way back
    /// to a short wait.
    fn backoff(&self, failures: u32) -> Duration {
        self.first_backoff
            .saturating_mul(1_u32 << failures.saturating_sub(1).min(16))
            .min(self.longest_backoff)
    }
}

/// What spaceport has tried so far about one app that is down.
#[derive(Debug)]
struct Attempt {
    /// How many attempts in a row have failed.
    failures: u32,
    /// When to try again, or `None` once spaceport has given up. An app that
    /// has been given up on keeps its entry, because that entry is what stops
    /// the next sweep from starting the whole thing over.
    next: Option<Instant>,
}

/// One app's liveness check, running for as long as that app is routed to that
/// container.
struct Watcher {
    /// Which container it is watching. When the app is running a different one
    /// it is a different app to watch, and this one is replaced.
    container: ContainerId,
    task: JoinHandle<()>,
}

impl Drop for Watcher {
    /// The check is an endless loop against an address that is about to stop
    /// being this app's. Nothing it could say from here would be true.
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Keep the apps in `applier`'s store running until `shutdown` is cancelled.
///
/// Wakes on five things: the engine reporting a container of spaceport's is no
/// longer one, a liveness check giving up on an app, the store saying the apps
/// are not the ones it was watching, the deadline of the next attempt to start
/// something again, and the sweep.
///
/// The store is in there because a deployment is not something the engine
/// announces in a form this loop acts on — the old container's death arrives
/// while the applier is settling, and the new container starting is not an
/// event at all. Without it the watchers are re-synced at the next pass, so a
/// liveness check would go on asking the address of the container the deploy
/// replaced for up to [`Policy::sweep`]: a minute of checks that cannot fail
/// usefully and cannot succeed, and of log lines about an app that is fine.
pub async fn supervise(applier: Arc<Applier>, shutdown: CancellationToken) {
    let mut supervisor = Supervisor::new(applier, Policy::default());
    let mut events = supervisor.applier.runtime().watch();
    let mut store_changed = supervisor.applier.store().changed();
    let (broken, mut is_broken) = mpsc::channel(WATCHER_BUFFER);
    // Whether the store's signal is still worth selecting on. See the arm.
    let mut store_speaks = true;

    info!("supervising apps");

    // Everything recorded that reconciliation could not bring back is already
    // in the store as down, and this is what picks it up: a first sweep, before
    // anything else has happened, so a boot failure gets the same patience as a
    // crash five minutes in.
    supervisor.sweep().await;

    loop {
        // Whatever the store has done up to here is what the two calls below are
        // about to read for themselves, so it is not also a reason to come round
        // again. A change from here on is — including the ones this pass makes,
        // which cost one more pass over a handful of apps and nothing else,
        // because a pass that changes nothing is the last one.
        store_changed.mark_unchanged();

        supervisor.retry_what_is_due().await;
        supervisor.watch_the_live_ones(&broken);

        let sweep = supervisor.policy.sweep;
        let wait = supervisor
            .until_the_next_attempt()
            .unwrap_or(sweep)
            .min(sweep);

        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(wait) => {}
            // The engine's news, or the news that there is no more of it.
            Some(event) = events.next() => supervisor.heard(event).await,
            // A liveness check that has given up. `None` is unreachable while
            // the supervisor holds the sender, and stopping is the only safe
            // answer if it somehow is not.
            broken = is_broken.recv() => match broken {
                Some((app, reason)) => supervisor.found_broken(&app, &reason).await,
                None => break,
            },
            // An app was applied, deployed, resumed, suspended or taken down,
            // so the watchers are about somebody else's containers. The sender
            // is the store this loop holds through the applier, so the error
            // arm cannot happen; disabling the arm rather than stopping is
            // still the right answer if it somehow does, because a supervisor
            // that gave up over a lost signal would leave the host unsupervised
            // over the one thing the sweep already covers.
            result = store_changed.changed(), if store_speaks => {
                if result.is_err() {
                    warn!("the app store stopped saying when it changes, so the sweep is the only thing left that notices");
                    store_speaks = false;
                }
            }
        }
    }

    debug!("stopped supervising apps");
}

/// How many liveness failures may be waiting while the supervisor is busy.
///
/// One per app is the most that can ever be outstanding — a watcher sends once
/// and then its app is taken down, which drops it — so this is generous for any
/// host a single spaceport is running.
const WATCHER_BUFFER: usize = 64;

/// The reason a liveness check gave up on an app, on its way to the loop.
type Broken = (AppId, String);

struct Supervisor {
    applier: Arc<Applier>,
    policy: Policy,
    /// What has been tried, for every app that is down. An app not in here is
    /// one nothing has gone wrong with.
    attempts: HashMap<AppId, Attempt>,
    watchers: HashMap<AppId, Watcher>,
}

impl Supervisor {
    fn new(applier: Arc<Applier>, policy: Policy) -> Self {
        Self {
            applier,
            policy,
            attempts: HashMap::new(),
            watchers: HashMap::new(),
        }
    }

    /// Act on what the engine just said.
    async fn heard(&mut self, event: RuntimeEvent) {
        // The stream broke and came back, so the engine may have taken half the
        // host down while nobody was listening. Nothing to act on, and every
        // reason to go and look.
        if matches!(event, RuntimeEvent::Desynchronised) {
            debug!("lost the engine's events, checking every app instead");
            self.sweep().await;

            return;
        }

        // A container spaceport labelled but can no longer name. There is
        // nothing to restart — the app it belonged to is whatever the sweep
        // finds is missing a container — so this is the sweep's to deal with.
        let Some(app) = event.app().cloned() else {
            debug!(container = ?event.container().map(ContainerId::as_str), "the engine reported a container that names no app");
            return;
        };

        let running = self.applier.store().get(&app);
        // Stale by the time it arrived: spaceport has since started this app on
        // a different container, and the one that died is the one it replaced.
        if let Some(running) = &running
            && event.container() != Some(&running.container)
        {
            debug!(app = %app, "the engine reported a container this app has already replaced");
            return;
        }

        self.trouble(&app, event.describe()).await;
    }

    /// A liveness check has given up on an app.
    async fn found_broken(&mut self, app: &AppId, reason: &str) {
        // The watcher is checking an address this app may have stopped being at
        // between the check failing and this arriving.
        if self.watchers.get(app).is_none_or(|watcher| {
            self.applier
                .store()
                .get(app)
                .is_none_or(|running| running.container != watcher.container)
        }) {
            debug!(app = %app, "a liveness check gave up on a container this app no longer runs");
            return;
        }

        self.trouble(app, format!("it stopped answering: {reason}"))
            .await;
    }

    /// Take an app out of service and line it up to be started again.
    ///
    /// Everything that goes wrong with an app arrives here, whichever of the
    /// three noticed it, and from here on there is only one story.
    async fn trouble(&mut self, app: &AppId, reason: String) {
        // Spaceport's own doing. An apply replaces a container, a suspend stops
        // one, a destroy removes one, and the engine reports all three exactly
        // as it reports a crash.
        if self.applier.is_settling(app) {
            debug!(app = %app, reason = %reason, "the engine reported an app spaceport is in the middle of, so nothing is wrong");
            return;
        }

        // Already down and already being retried. The first reason is the one
        // worth keeping — a container that died and was then removed is one
        // fault, and "its container was removed" is the less useful half of it.
        if self.attempts.contains_key(app) {
            debug!(app = %app, reason = %reason, "the app is already down");
            return;
        }

        if self.applier.store().take_down(app, &reason).is_none() {
            // Not running, and nothing has been tried: it is suspended, or it
            // was destroyed between the engine noticing and this. Either way it
            // is not spaceport's to bring back.
            debug!(app = %app, reason = %reason, "the engine reported an app spaceport is not running");
            return;
        }

        warn!(app = %app, reason = %reason, "app is down, starting it again");
        self.attempts.insert(
            app.clone(),
            Attempt {
                failures: 0,
                // Now: the first attempt does not wait, because most of them
                // work and the backoff is for the ones that do not.
                next: Some(Instant::now()),
            },
        );
    }

    /// Try again everything whose time has come.
    async fn retry_what_is_due(&mut self) {
        let now = Instant::now();
        let due: Vec<AppId> = self
            .attempts
            .iter()
            .filter(|(_, attempt)| attempt.next.is_some_and(|next| next <= now))
            .map(|(app, _)| app.clone())
            .collect();

        for app in due {
            self.try_once(&app).await;
        }
    }

    /// One attempt to start an app again, and what to make of how it went.
    async fn try_once(&mut self, app: &AppId) {
        let Some(attempt) = self.attempts.get(app) else {
            return;
        };
        let waited = attempt.failures + 1;
        info!(app = %app, attempt = waited, "starting the app again");

        let reason = self
            .applier
            .store()
            .downed(app)
            .map(|down| down.reason)
            .unwrap_or_else(|| "it stopped running".to_owned());

        match self.applier.restart(app, &reason).await {
            Ok(_) => {
                // Back in the store as a running app, which is also what took
                // it out of the down map. Nothing left to remember about it.
                self.attempts.remove(app);
            }
            Err(error) => {
                let failures = waited;
                // Whether to try again is a decision about `failures` and the
                // policy alone, so it is made before the entry is touched and
                // the entry is written once.
                let next = match failures >= self.policy.attempts {
                    true => None,
                    false => Some(Instant::now() + self.policy.backoff(failures)),
                };
                self.attempts
                    .insert(app.clone(), Attempt { failures, next });

                match next {
                    Some(_) => {
                        warn!(app = %app, attempt = failures, backoff = ?self.policy.backoff(failures), %error, "could not start the app, trying again later");
                    }
                    None => {
                        error!(app = %app, attempts = failures, %error, "giving up on the app, it needs an operator");
                        self.applier.store().note_down(
                            app,
                            format!(
                                "spaceport gave up after {failures} attempts to start it: {error:#}"
                            ),
                        );
                    }
                }
            }
        }
    }

    /// How long until there is something to do, if there is anything.
    fn until_the_next_attempt(&self) -> Option<Duration> {
        let now = Instant::now();

        self.attempts
            .values()
            .filter_map(|attempt| attempt.next)
            .map(|next| next.saturating_duration_since(now))
            .min()
    }

    /// Ask the engine what it is running and believe it over the store.
    ///
    /// The backstop. Everything the event stream is for is found here too, only
    /// later — which is what makes it safe for the events to be best-effort.
    async fn sweep(&mut self) {
        let containers = match self.applier.runtime().managed().await {
            Ok(containers) => containers,
            // Nothing to conclude: an engine that will not answer is not an
            // engine that has stopped running everything. Acting on this would
            // take every app on the host down over one failed request.
            Err(error) => {
                warn!(%error, "could not ask the engine what it is running, leaving every app as it is");
                return;
            }
        };

        for app in self.applier.store().apps() {
            let Some(trouble) = missing(&app, &containers) else {
                continue;
            };
            self.trouble(&app.id, trouble.to_owned()).await;
        }

        // An app that was down before this supervisor started — one that
        // reconciliation could not bring back — has nobody trying for it until
        // it is picked up here.
        for down in self.applier.store().down_apps() {
            self.take_over(&down);
        }
    }

    /// Start trying for an app that is down and that nothing is trying for.
    fn take_over(&mut self, down: &Downed) {
        if self.attempts.contains_key(&down.id) {
            return;
        }

        info!(app = %down.id, reason = %down.reason, "taking over an app that is not running");
        self.attempts.insert(
            down.id.clone(),
            Attempt {
                failures: 0,
                next: Some(Instant::now()),
            },
        );
    }

    /// Make sure every running app that asked to be watched is being watched,
    /// and that nothing else is.
    ///
    /// Cheap enough to run on every pass of the loop: it is a walk over a
    /// handful of apps, and spawning is what costs, which only a change causes.
    fn watch_the_live_ones(&mut self, broken: &mpsc::Sender<Broken>) {
        let running = self.applier.store().apps();

        // Apps that have stopped running, been replaced by a different
        // container, or been suspended. Dropping the watcher aborts its check.
        self.watchers.retain(|id, watcher| {
            running
                .iter()
                .any(|app| app.id == *id && app.container == watcher.container)
        });

        for app in running {
            let Some(liveness) = app.manifest.container.health.liveness.clone() else {
                continue;
            };
            // `type: none` is the other way of saying there is no liveness
            // check, and a watcher for it would be a task that never finishes
            // and never says anything.
            if liveness.kind == Check::None {
                continue;
            }
            if self.watchers.contains_key(&app.id) {
                continue;
            }

            let broken = broken.clone();
            let watched = app.clone();
            let task = tokio::spawn(async move {
                // Any host of the app's own will do; the check is addressed to
                // the upstream either way.
                let host = watched.hosts()[0].as_str();
                let reason = health::watch(watched.upstream, host, &liveness).await;

                // A full channel means the supervisor is behind, and a liveness
                // failure that waits is better than one that is dropped.
                let _ = broken.send((watched.id.clone(), reason)).await;
            });

            debug!(app = %app.id, container = %app.container, "watching the app for as long as it is running");
            self.watchers.insert(
                app.id.clone(),
                Watcher {
                    container: app.container.clone(),
                    task,
                },
            );
        }
    }
}

/// What is wrong with a running app's container, according to a listing.
fn missing(app: &App, containers: &[crate::runtime::Managed]) -> Option<&'static str> {
    match containers
        .iter()
        .find(|container| container.id == app.container)
    {
        Some(container) if container.running => None,
        Some(_) => Some("its container is not running"),
        None => Some("its container is gone"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::repository::AppRepository;
    use crate::app::secrets::SecretRepository;
    use crate::app::{AppManifest, AppStore};
    use crate::build::repository::BuildRepository;
    use crate::runtime::{Container, ContainerId, ContainerRuntime, Managed};
    use crate::state::Db;
    use anyhow::{Result, bail};
    use async_trait::async_trait;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    /// A runtime that starts nothing, so the supervisor's decisions can be
    /// watched without a container engine anywhere near it.
    ///
    /// It keeps a listing rather than a set of containers, because what a sweep
    /// asks it is precisely what a listing answers: is this container here, and
    /// is it running?
    #[derive(Default)]
    struct FakeRuntime {
        launched: Mutex<Vec<AppId>>,
        containers: Mutex<Vec<Managed>>,
        /// Refuse to start anything, so that every attempt fails.
        refuse: Mutex<bool>,
        /// Refuse to say what is running, as an engine that has gone away.
        refuse_listing: bool,
        /// Where to say the next container is listening, for the one test that
        /// needs something real to answer a check. Otherwise a port per launch,
        /// which nothing is behind.
        upstream: Mutex<Option<SocketAddr>>,
    }

    impl FakeRuntime {
        /// What the engine reports once a container has exited: still there,
        /// not running.
        fn exited(&self, container: &ContainerId) {
            let mut containers = self.containers.lock().unwrap();
            for managed in containers.iter_mut().filter(|it| it.id == *container) {
                managed.running = false;
            }
        }

        /// What the engine reports once a container has been removed.
        fn gone(&self, container: &ContainerId) {
            self.containers
                .lock()
                .unwrap()
                .retain(|managed| managed.id != *container);
        }

        fn refuse_to_launch(&self) {
            *self.refuse.lock().unwrap() = true;
        }

        /// Put everything it starts from now on at `addr`.
        fn launches_at(&self, addr: SocketAddr) {
            *self.upstream.lock().unwrap() = Some(addr);
        }
    }

    #[async_trait]
    impl ContainerRuntime for FakeRuntime {
        async fn launch(&self, app: &AppId, _manifest: &AppManifest) -> Result<Container> {
            if *self.refuse.lock().unwrap() {
                bail!("no image for you");
            }
            let mut launched = self.launched.lock().unwrap();
            launched.push(app.clone());

            // A different port and id per launch, so a replacement is visible.
            let port = 9000 + u16::try_from(launched.len()).unwrap();
            let id = ContainerId::new(format!("{app}-{port}"));

            let mut containers = self.containers.lock().unwrap();
            containers.retain(|managed| managed.app.as_ref() != Some(app));
            containers.push(Managed {
                id: id.clone(),
                app: Some(app.clone()),
                running: true,
            });

            let upstream = self
                .upstream
                .lock()
                .unwrap()
                .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], port)));

            Ok(Container { id, upstream })
        }

        async fn stop(&self, id: &ContainerId) -> Result<()> {
            self.exited(id);

            Ok(())
        }

        async fn start(&self, id: &ContainerId, _manifest: &AppManifest) -> Result<Container> {
            Ok(Container {
                id: id.clone(),
                upstream: SocketAddr::from(([127, 0, 0, 1], 7777)),
            })
        }

        async fn remove(&self, id: &ContainerId) -> Result<()> {
            self.gone(id);

            Ok(())
        }

        async fn managed(&self) -> Result<Vec<Managed>> {
            if self.refuse_listing {
                bail!("the daemon is not answering");
            }

            Ok(self.containers.lock().unwrap().clone())
        }
    }

    /// A manifest whose app is routed the moment it starts: these tests are
    /// about what the supervisor decides, and a fake runtime's ports have
    /// nothing behind them to answer a check.
    fn manifest(extra: &str) -> AppManifest {
        AppManifest::parse(&format!(
            "schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [alpha.test]
container:
  health:
    readiness:
      type: none
{extra}"
        ))
        .unwrap()
    }

    fn id(app: &str) -> AppId {
        app.parse().unwrap()
    }

    /// A policy with the same shape as the real one and none of its patience,
    /// so a test can watch spaceport give up without sitting out four minutes
    /// of backoff.
    fn impatient() -> Policy {
        Policy {
            first_backoff: Duration::from_millis(1),
            longest_backoff: Duration::from_millis(4),
            attempts: 3,
            sweep: Duration::from_millis(10),
        }
    }

    /// One app, applied and running, with a supervisor watching it.
    async fn supervising(manifest: AppManifest) -> (Supervisor, Arc<AppStore>, Arc<FakeRuntime>) {
        let runtime = Arc::new(FakeRuntime::default());
        let store = Arc::new(AppStore::new());
        let db = Db::in_memory().unwrap();
        let applier = Arc::new(Applier::new(
            store.clone(),
            runtime.clone(),
            AppRepository::new(db.clone()),
            BuildRepository::new(db.clone()),
            SecretRepository::new(db),
        ));
        applier
            .apply(id("hello"), manifest, false)
            .await
            .expect("the app should have started");

        (
            Supervisor::new(applier, impatient()),
            store,
            runtime.clone(),
        )
    }

    fn container_of(store: &AppStore, app: &str) -> ContainerId {
        store
            .get(&id(app))
            .expect("app should be running")
            .container
            .clone()
    }

    fn died(container: &ContainerId, app: &str) -> RuntimeEvent {
        RuntimeEvent::Died {
            container: container.clone(),
            app: Some(id(app)),
            exit_code: Some(1),
        }
    }

    #[tokio::test]
    async fn starts_an_app_again_when_its_container_dies() {
        let (mut supervisor, store, runtime) = supervising(manifest("")).await;
        let before = container_of(&store, "hello");
        runtime.exited(&before);

        supervisor.heard(died(&before, "hello")).await;
        supervisor.retry_what_is_due().await;

        let after = store.get(&id("hello")).expect("the app should be back");
        assert_ne!(after.container, before);
        assert_eq!(runtime.launched.lock().unwrap().len(), 2);
        assert_eq!(
            store.routes().serving("alpha.test").unwrap().id,
            id("hello")
        );
        assert!(store.down_apps().is_empty());
    }

    /// The window between an app dying and coming back is the reason the down
    /// state exists: the edge has to answer for the host rather than forward
    /// into a container that is not there.
    #[tokio::test]
    async fn stops_serving_the_host_the_moment_the_app_dies() {
        let (mut supervisor, store, runtime) = supervising(manifest("")).await;
        let container = container_of(&store, "hello");
        runtime.exited(&container);

        supervisor.heard(died(&container, "hello")).await;

        assert!(store.routes().serving("alpha.test").is_none());
        // Still claimed, so nothing else can take the host while it is away and
        // its certificates go on being renewed.
        assert!(store.routes().lookup("alpha.test").is_some());
        assert!(store.routes().hosts().contains("alpha.test"));
        assert_eq!(store.down_apps().len(), 1);
    }

    /// Suspension is a decision, and an operator who stopped an app's container
    /// on purpose must not have spaceport start it again on their behalf.
    #[tokio::test]
    async fn leaves_a_suspended_app_where_the_operator_put_it() {
        let (mut supervisor, store, runtime) = supervising(manifest("")).await;
        let container = container_of(&store, "hello");
        supervisor
            .applier
            .suspend(&id("hello"), true)
            .await
            .unwrap();

        supervisor.heard(died(&container, "hello")).await;
        supervisor.retry_what_is_due().await;

        assert_eq!(store.suspended_apps().len(), 1);
        assert!(store.down_apps().is_empty());
        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
    }

    /// Every apply replaces a container, and the engine reports the old one
    /// dying exactly as it reports a crash. Acting on that would restart an app
    /// that had just been deployed.
    #[tokio::test]
    async fn ignores_an_event_about_a_container_the_app_has_already_replaced() {
        let (mut supervisor, store, runtime) = supervising(manifest("")).await;
        let replaced = ContainerId::new("hello-8000");

        supervisor.heard(died(&replaced, "hello")).await;

        assert!(store.down_apps().is_empty());
        assert!(store.routes().serving("alpha.test").is_some());
        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
    }

    /// A container spaceport labelled but can no longer name says nothing about
    /// which app to start again. The sweep is what finds that app, by noticing
    /// it has no container.
    #[tokio::test]
    async fn ignores_an_event_that_names_no_app() {
        let (mut supervisor, store, _) = supervising(manifest("")).await;

        supervisor
            .heard(RuntimeEvent::Died {
                container: ContainerId::new("nameless"),
                app: None,
                exit_code: None,
            })
            .await;

        assert!(store.down_apps().is_empty());
        assert!(supervisor.attempts.is_empty());
    }

    #[tokio::test]
    async fn gives_up_on_an_app_that_will_not_start() {
        let (mut supervisor, store, runtime) = supervising(manifest("")).await;
        let container = container_of(&store, "hello");
        runtime.refuse_to_launch();

        supervisor.heard(died(&container, "hello")).await;
        for _ in 0..impatient().attempts {
            supervisor.retry_what_is_due().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let reason = store
            .downed(&id("hello"))
            .expect("it should be down")
            .reason;
        assert!(reason.contains("gave up after 3 attempts"), "{reason}");
        // Nothing is due any more, so the loop has nothing to wake up for.
        assert!(supervisor.until_the_next_attempt().is_none());

        // And it does not quietly start trying again.
        let attempted = runtime.launched.lock().unwrap().len();
        supervisor.retry_what_is_due().await;
        supervisor.sweep().await;
        supervisor.retry_what_is_due().await;
        assert_eq!(runtime.launched.lock().unwrap().len(), attempted);
    }

    /// An operator who applies an app spaceport has given up on gets it back:
    /// the apply puts it in the store as running, which is what the supervisor
    /// was waiting to be true.
    #[tokio::test]
    async fn an_apply_takes_an_app_back_from_the_supervisor() {
        let (mut supervisor, store, runtime) = supervising(manifest("")).await;
        let container = container_of(&store, "hello");
        runtime.refuse_to_launch();
        supervisor.heard(died(&container, "hello")).await;
        supervisor.retry_what_is_due().await;
        assert_eq!(store.down_apps().len(), 1);

        *runtime.refuse.lock().unwrap() = false;
        supervisor
            .applier
            .apply(id("hello"), manifest(""), false)
            .await
            .unwrap();

        assert!(store.down_apps().is_empty());
        assert!(store.routes().serving("alpha.test").is_some());
    }

    #[tokio::test]
    async fn a_sweep_finds_an_app_whose_container_is_gone() {
        let (mut supervisor, store, runtime) = supervising(manifest("")).await;
        runtime.gone(&container_of(&store, "hello"));

        supervisor.sweep().await;

        let reason = store
            .downed(&id("hello"))
            .expect("it should be down")
            .reason;
        assert!(reason.contains("container is gone"), "{reason}");
    }

    /// A container that exited while the event stream was broken is still on
    /// the engine's listing, and only its state says it is not serving.
    #[tokio::test]
    async fn a_sweep_finds_an_app_whose_container_has_stopped() {
        let (mut supervisor, store, runtime) = supervising(manifest("")).await;
        runtime.exited(&container_of(&store, "hello"));

        supervisor.sweep().await;
        supervisor.retry_what_is_due().await;

        assert_eq!(runtime.launched.lock().unwrap().len(), 2);
        assert!(store.routes().serving("alpha.test").is_some());
    }

    /// One failed request to the daemon is not evidence that every app on the
    /// host has stopped, and treating it as such would take them all down.
    #[tokio::test]
    async fn a_sweep_that_cannot_reach_the_engine_changes_nothing() {
        let runtime = Arc::new(FakeRuntime {
            refuse_listing: true,
            ..FakeRuntime::default()
        });
        let store = Arc::new(AppStore::new());
        let db = Db::in_memory().unwrap();
        let applier = Arc::new(Applier::new(
            store.clone(),
            runtime.clone(),
            AppRepository::new(db.clone()),
            BuildRepository::new(db.clone()),
            SecretRepository::new(db),
        ));
        applier
            .apply(id("hello"), manifest(""), false)
            .await
            .unwrap();
        let mut supervisor = Supervisor::new(applier, impatient());

        supervisor.sweep().await;

        assert!(store.down_apps().is_empty());
        assert!(store.routes().serving("alpha.test").is_some());
    }

    /// An app that could not be started at boot is left in the store as down,
    /// and this is what picks it up — otherwise it would stay down until an
    /// operator applied it again.
    #[tokio::test]
    async fn takes_over_an_app_that_was_already_down() {
        let (mut supervisor, store, runtime) = supervising(manifest("")).await;
        supervisor.applier.destroy(&id("hello")).await.unwrap();
        store
            .insert_down(Downed {
                id: id("hello"),
                manifest: manifest(""),
                reason: "no image `x:1`".to_owned(),
            })
            .unwrap();

        supervisor.sweep().await;
        supervisor.retry_what_is_due().await;

        assert!(store.routes().serving("alpha.test").is_some());
        assert_eq!(runtime.launched.lock().unwrap().len(), 2);
    }

    /// The engine went away and came back, so anything that happened in between
    /// was missed. The only safe response is to look at everything.
    #[tokio::test]
    async fn a_broken_event_stream_makes_it_check_every_app() {
        let (mut supervisor, store, runtime) = supervising(manifest("")).await;
        runtime.gone(&container_of(&store, "hello"));

        supervisor.heard(RuntimeEvent::Desynchronised).await;

        assert_eq!(store.down_apps().len(), 1);
    }

    // Liveness.

    const LIVENESS: &str = "    liveness:
      type: tcp
      interval: 1h
";

    #[tokio::test]
    async fn watches_an_app_whose_manifest_asks_to_be_watched() {
        let (mut supervisor, _, _) = supervising(manifest(LIVENESS)).await;
        let (broken, _receiver) = mpsc::channel(WATCHER_BUFFER);

        supervisor.watch_the_live_ones(&broken);

        assert_eq!(supervisor.watchers.len(), 1);
    }

    /// A liveness check is a standing instruction to restart, and an app that
    /// never asked for one must not acquire it by being applied to a newer
    /// spaceport.
    #[tokio::test]
    async fn does_not_watch_an_app_that_did_not_ask() {
        let (mut supervisor, _, _) = supervising(manifest("")).await;
        let (broken, _receiver) = mpsc::channel(WATCHER_BUFFER);

        supervisor.watch_the_live_ones(&broken);

        assert!(supervisor.watchers.is_empty());
    }

    #[tokio::test]
    async fn stops_watching_an_app_that_is_suspended() {
        let (mut supervisor, _, _) = supervising(manifest(LIVENESS)).await;
        let (broken, _receiver) = mpsc::channel(WATCHER_BUFFER);
        supervisor.watch_the_live_ones(&broken);

        supervisor
            .applier
            .suspend(&id("hello"), false)
            .await
            .unwrap();
        supervisor.watch_the_live_ones(&broken);

        assert!(supervisor.watchers.is_empty());
    }

    /// A watcher is checking one container's address. When the app is running a
    /// different container, the old watcher's answer would be about nothing.
    #[tokio::test]
    async fn watches_the_new_container_after_a_restart() {
        let (mut supervisor, store, runtime) = supervising(manifest(LIVENESS)).await;
        let (broken, _receiver) = mpsc::channel(WATCHER_BUFFER);
        supervisor.watch_the_live_ones(&broken);
        let before = container_of(&store, "hello");

        runtime.exited(&before);
        supervisor.heard(died(&before, "hello")).await;
        supervisor.retry_what_is_due().await;
        supervisor.watch_the_live_ones(&broken);

        assert_eq!(supervisor.watchers.len(), 1);
        assert_eq!(
            supervisor.watchers[&id("hello")].container,
            container_of(&store, "hello")
        );
        assert_ne!(supervisor.watchers[&id("hello")].container, before);
    }

    /// A liveness failure about a container the app no longer runs is stale by
    /// the time it arrives, and acting on it would restart a healthy app.
    #[tokio::test]
    async fn ignores_a_liveness_failure_about_a_container_that_is_gone() {
        let (mut supervisor, store, _) = supervising(manifest(LIVENESS)).await;

        supervisor
            .found_broken(&id("hello"), "it stopped answering")
            .await;

        assert!(store.down_apps().is_empty());
        assert!(store.routes().serving("alpha.test").is_some());
    }

    // The policy itself.

    #[test]
    fn waits_longer_after_every_failure_and_then_stops_waiting_longer() {
        let policy = Policy::default();

        assert_eq!(policy.backoff(1), Duration::from_secs(1));
        assert_eq!(policy.backoff(2), Duration::from_secs(2));
        assert_eq!(policy.backoff(3), Duration::from_secs(4));
        assert_eq!(policy.backoff(7), Duration::from_secs(60));
        // However many times it has failed, and whatever that does to the
        // arithmetic, it never comes back round to a short wait.
        assert_eq!(policy.backoff(u32::MAX), Duration::from_secs(60));
    }

    /// A deployment replaces an app's container, and nothing the engine says
    /// about that reaches this loop: the old container's death arrives while
    /// the applier is settling, and a container starting is not an event at
    /// all. So the store is what says so, and the watcher has to move at once —
    /// otherwise the check goes on asking the replaced container's address for
    /// the rest of the sweep, which is a minute of failures about an app that
    /// is running perfectly well.
    ///
    /// Run against the loop rather than [`Supervisor::watch_the_live_ones`],
    /// which is where the retention rule already has its test: what is at stake
    /// here is *when* that runs. The real [`Policy`] and its sixty-second sweep
    /// are what make the assertion mean anything — a connection inside five
    /// seconds cannot have come from a sweep.
    #[tokio::test]
    async fn watches_a_replaced_container_without_waiting_for_the_sweep() {
        // Two real addresses, so that a connection is evidence of which
        // container is being checked and of nothing else.
        let before = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let after = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (supervisor, _, runtime) = supervising(manifest(LIVENESS)).await;
        let applier = supervisor.applier.clone();
        let shutdown = CancellationToken::new();

        runtime.launches_at(before.local_addr().unwrap());
        applier
            .apply(id("hello"), manifest(LIVENESS), false)
            .await
            .unwrap();
        let running = tokio::spawn(supervise(applier.clone(), shutdown.clone()));
        // The first pass has watched the container the app is on, which is what
        // makes the next connection a decision rather than a coincidence: the
        // loop is now asleep with nothing due until the sweep.
        tokio::time::timeout(Duration::from_secs(5), before.accept())
            .await
            .expect("the app that was applied should be being checked")
            .expect("the check should have connected");

        runtime.launches_at(after.local_addr().unwrap());
        applier
            .apply(id("hello"), manifest(LIVENESS), false)
            .await
            .unwrap();

        let checked = tokio::time::timeout(Duration::from_secs(5), after.accept()).await;

        shutdown.cancel();
        running.await.unwrap();
        assert!(
            checked.is_ok(),
            "the check should have followed the app to its new container"
        );
    }

    #[tokio::test]
    async fn the_loop_stops_when_it_is_shut_down() {
        let (supervisor, _, _) = supervising(manifest("")).await;
        let shutdown = CancellationToken::new();
        let running = tokio::spawn(supervise(supervisor.applier.clone(), shutdown.clone()));

        tokio::task::yield_now().await;
        shutdown.cancel();

        running.await.unwrap();
    }
}

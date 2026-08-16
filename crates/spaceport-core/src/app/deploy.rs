//! The loop that runs what the builder finished, for the apps that asked for it.
//!
//! An armed tracking is an operator saying "and then put it in front of the
//! traffic": a commit on the branch becomes an image, and the image becomes the
//! app. [`crate::build::worker`] does the first half and stops, deliberately;
//! this is the second half, and it is a worker of its own rather than a few
//! lines at the end of a build for two reasons that have nothing to do with
//! tidiness.
//!
//! **A deploy waits, and the build slot must not.** Applying a manifest starts a
//! container and then waits for the app inside it to answer — up to a readiness
//! budget an operator wrote, which for a service that warms a cache is minutes.
//! The builder builds one revision at a time on purpose, because four
//! simultaneous `cargo build`s is how a small host runs out of memory, and that
//! single slot is the scarcest thing spaceport has. A deploy at the end of
//! `run` would hold it for the whole of somebody's startup, so a push to one
//! app would stall the builds of every other app on the host behind a container
//! that is still booting. Here, the waiting happens on a task nothing is queued
//! behind.
//!
//! **The trigger is a row, not a message.** A process killed between recording a
//! successful build and applying it would, if the deployment were a step inside
//! the build, lose the deployment entirely: the row says `built`, nothing in any
//! process's memory remembers that it was going to be run, and the operator's
//! commit sits there deployed nowhere with no failure to read. What makes that
//! impossible is that "this revision has not been deployed yet" is a column —
//! see [`Build::awaits_deployment`] — so the pass after the restart finds it
//! exactly as the pass before the crash would have. The nudge from the builder
//! is only an optimisation on top of that, in the sense every nudge in spaceport
//! is: it decides *when* to look, never *what* is true.
//!
//! So a pass reads the world, like the two loops it is shaped after
//! ([`crate::build::worker::maintain`] and
//! [`crate::connections::github::reconcile::maintain`]): the armed trackings,
//! each app's newest successful build, whether that revision has already been
//! deployed, and whether the app is suspended. Nothing is taken from the shove
//! that woke it.
//!
//! **A suspended app is left alone.** It is the one state an operator put the
//! app in on purpose, and a commit landing on a branch is not an argument
//! against it — an armed tracking says what to run, and suspension says whether
//! to be running, which stay two decisions. Everything else is fair game, and
//! knowingly so: an automatic deployment may replace a manifest an operator
//! applied by hand, and may start an app that has never run in its life,
//! claiming its hosts and taking traffic. That is what arming asked for.
//!
//! **A deployment that fails puts the app back.** Not because rolling back is
//! always right — an operator deploying by hand is left where they landed,
//! because they are at a terminal and can decide — but because nobody is
//! watching this one. The alternative is an app that a commit took down and
//! that stays down until the supervisor's sweep notices, which is a minute of
//! an outage nobody asked for on a revision that was working. See [`roll_back`].
//!
//! **A revision whose deployment failed is never tried again.** The row is
//! stamped either way, which is what stops this loop from taking the same app
//! down every pass for ever over a commit that cannot be made to work by being
//! tried harder. The retry is the next commit, which is a thing a person can
//! push once they have read why.

use std::sync::Arc;

use time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::repository::AppRecord;
use super::{AppId, AppManifest, Applier};
use crate::build::repository::{Build, BuildRepository};
use crate::connections::github::reconcile::Nudge;
use crate::connections::github::tracking::TrackingRepository;

/// Who asked for the deployment, as a field on every event here.
///
/// A field and emphatically not a target: an event's target says which module
/// wrote it, and writing `spaceport_core::operator::server` from this loop to
/// make a deployment look like an operator's — or the other way about — would
/// make the one field that says where an event came from lie. Whoever is
/// reading a stream and wondering why their app restarted at three in the
/// morning is answered by `by=spaceport` on a line they can filter for.
const BY_SPACEPORT: &str = "spaceport";

/// How often a pass runs, and how long a shove is allowed to settle.
///
/// One struct rather than two constants, for the reason the builder's is one:
/// the numbers are an argument about time that only makes sense read together,
/// and a test that had to sit out the real ones would spend minutes finding out
/// what it already knows.
#[derive(Debug, Clone)]
pub struct Policy {
    /// How long between passes.
    ///
    /// The outer bound on how long a built revision that nothing woke this loop
    /// about stays undeployed — the crash-between-the-row-and-the-apply case the
    /// module header is about. Five minutes, the builder's number, because a
    /// pass over a spaceport with nothing to do is one query for the armed
    /// trackings and none at all if there are none.
    pub interval: Duration,

    /// How long to let a wake-up settle before acting on it.
    ///
    /// A push to a monorepo builds several apps, and each finished build shoves
    /// this loop. Waiting costs only itself, because the pass reads every armed
    /// tracking either way — the second build of a burst is deployed by the pass
    /// the first one started, if it has finished by then, and by the next one if
    /// it has not.
    ///
    /// Two seconds, the same as the builder's and the reconciler's, so that the
    /// loops behave alike where nothing argues for a difference.
    pub settle: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            interval: Duration::minutes(5),
            settle: Duration::seconds(2),
        }
    }
}

/// Everything a deployment needs, gathered once at startup.
///
/// A struct rather than three arguments to [`maintain`], for the reason the
/// builder's [`crate::build::worker::Worker`] is one: every field is held for
/// the life of the process, and public because assembling it is the daemon's
/// job and there is nothing here to enforce.
pub struct Worker {
    /// The one thing that starts an app, and the record of what each app was
    /// told to run — which is also what a failed deployment goes back to.
    pub applier: Arc<Applier>,
    /// Which apps deploy their own builds. Read afresh every pass, because
    /// arming and disarming are an operator's to change while this is running.
    pub trackings: Arc<TrackingRepository>,
    /// What has been built, and what has already been deployed.
    pub builds: BuildRepository,
}

/// Keep deploying what the armed apps have had built, until `shutdown` is
/// cancelled.
///
/// Wakes on three things — the interval, a [`Nudge`], and shutdown. The
/// interval is what makes a finished build eventually deployed whatever went
/// missing; the nudge is what makes it deployed in seconds when the builder did
/// reach this loop, which is nearly always. Both run the same pass, because the
/// pass is what reads the builds, and a wake-up that acted on what it was told
/// would be a deployment of whatever the last message happened to say.
pub async fn maintain(
    worker: Arc<Worker>,
    policy: Policy,
    nudge: Nudge,
    shutdown: CancellationToken,
) {
    debug!(
        minutes = policy.interval.whole_minutes(),
        "deploying what the armed apps have built"
    );

    let mut woken = nudge.changed();

    loop {
        // Everything learned up to this point is what this pass is about to go
        // and read for itself, so it is not also a reason to run again. Anything
        // that arrives from here on is — a build may have finished after this
        // pass read the rows.
        woken.mark_unchanged();

        pass(&worker, &shutdown).await;

        tokio::select! {
            () = shutdown.cancelled() => break,
            // `unsigned_abs` for the reason the other loops use it: a policy or
            // a clock that has done something strange should cost a busy loop
            // at worst rather than a panic.
            () = tokio::time::sleep(policy.interval.unsigned_abs()) => {}
            // A build finished.
            result = woken.changed() => {
                // Every sender has gone, so nothing can ever say so again. A
                // wake-up that can no longer happen is not worth a task.
                if result.is_err() {
                    break;
                }

                // Only on this arm: a burst is a property of how many apps one
                // push builds, and the interval has nothing to settle.
                // Interruptible, because a settle that outlived a shutdown would
                // be a shutdown that waits for it.
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(policy.settle.unsigned_abs()) => {}
                }
            }
        }
    }

    debug!("stopped deploying what the armed apps have built");
}

/// One pass: every armed app, in turn.
///
/// Only the app id is taken off the tracking. Where the commit came from is the
/// builder's business and was settled when the image was made; what is left to
/// decide here is about this host — what has been built, what is running, and
/// whether an operator has taken the app out of service.
///
/// Shutdown is checked between apps rather than only around the wait, because
/// each app here is a container starting and a readiness budget elapsing, and
/// ten armed apps must not be ten of those a stopping spaceport sits through.
async fn pass(worker: &Worker, shutdown: &CancellationToken) {
    let armed = match worker.trackings.armed().await {
        Ok(armed) => armed,
        // The state store, not the engine. Nothing in a pass can be done
        // without it, and asking again immediately would not make it readable.
        Err(error) => {
            warn!(error = %format!("{error:#}"), "could not read which apps deploy themselves");

            return;
        }
    };

    for tracking in armed {
        if shutdown.is_cancelled() {
            break;
        }

        deploy(worker, &tracking.app).await;
    }
}

/// Deploy `app`'s newest built revision, if there is one nothing has deployed.
///
/// One app's failure is written down and never propagated, exactly as a build's
/// is: there is nobody above this loop to return an error to, and a worker that
/// gave up on a manifest it could not read would be a spaceport that stops
/// deploying every armed app because one of them is broken.
async fn deploy(worker: &Worker, app: &AppId) {
    let build = match worker.builds.latest_built(app).await {
        Ok(Some(build)) => build,
        // Armed, and nothing built yet — an app tracked a moment ago, or one
        // whose every build has failed. Ordinary, and not this loop's business.
        Ok(None) => return,
        Err(error) => {
            warn!(
                app = %app,
                error = %format!("{error:#}"),
                "could not read what has been built for this app",
            );

            return;
        }
    };

    // Already deployed, by this loop or by an operator who got there first, or
    // deployed and failed and so never to be tried again. The ordinary answer
    // on every pass but the one that follows a build, which is what makes
    // running this every five minutes free.
    if !build.awaits_deployment() {
        return;
    }

    // Read before anything is started, because it is two things at once: what
    // says whether the app is suspended, and — since `record_applied` runs only
    // when an apply has worked — the manifest and revision this app is running
    // right now, which is what a failure goes back to. Reading it afterwards
    // would be reading what the deployment just wrote.
    let record = match worker.applier.repository().recorded(app).await {
        Ok(record) => record,
        // Deploying blind is possible and rolling back blind is not, and a
        // deployment that cannot be undone is not one to start unwatched.
        Err(error) => {
            warn!(
                app = %app,
                error = %format!("{error:#}"),
                "could not read what this app is running, so it was left where it is",
            );

            return;
        }
    };

    if is_suspended(worker, app, record.as_ref()) {
        debug!(
            app = %app,
            revision = %build.revision,
            "this app is suspended, so its build was not deployed",
        );

        return;
    }

    let Some(manifest) = manifest(worker, app, &build).await else {
        return;
    };

    match worker
        .applier
        .deploy(app.clone(), manifest, Some(&build.revision), false)
        .await
    {
        Ok(_) => {
            if let Err(error) = worker.builds.deployed(app, &build.revision).await {
                warn!(
                    app = %app,
                    error = %format!("{error:#}"),
                    "could not record a deployment that worked",
                );
            }

            info!(
                app = %app,
                revision = %build.revision,
                image = build.image_tag.as_deref().unwrap_or_default(),
                by = BY_SPACEPORT,
                "deployed this app's revision",
            );
        }
        Err(error) => {
            // Written down before the rollback and not after: the row is what
            // stops this revision from being deployed again, and a process that
            // died halfway through putting the app back must not come up and
            // take it down again with the same commit.
            failed(worker, app, &build.revision, &format!("{error:#}")).await;

            roll_back(worker, app, record.as_ref()).await;
        }
    }
}

/// Whether an operator has taken this app out of service.
///
/// Both answers are asked for, and they are two different facts. The store is
/// what is true in this process now; the record is what survives a restart, and
/// is what an app suspended by a spaceport that has since restarted is holding.
/// Either of them saying so is enough — the failure to prefer here is deploying
/// over a suspension, not declining to deploy over a stale one, since the next
/// commit asks again.
fn is_suspended(worker: &Worker, app: &AppId, record: Option<&AppRecord>) -> bool {
    worker.applier.store().suspended(app).is_some() || record.is_some_and(|record| record.suspended)
}

/// The manifest the revision's commit carried.
///
/// Off the build row rather than fetched again, for the reason the operator's
/// deploy reads it there: the checkout it came out of is swept once newer
/// revisions exist, so this never touches GitHub and works on a host that
/// cannot reach it. Both ways of having no manifest end the deployment before
/// anything is started, and are recorded as a failed deployment rather than
/// skipped — an armed app that will never be deployable has to say so
/// somewhere an operator will look, and the build row is where they look.
async fn manifest(worker: &Worker, app: &AppId, build: &Build) -> Option<AppManifest> {
    let document = build
        .manifest
        .as_deref()
        .filter(|document| !document.trim().is_empty());

    let parsed = match document {
        Some(document) => AppManifest::parse(document).map_err(|error| {
            format!(
                "the `{}` that revision `{}` carried is one this spaceport cannot read: {error:#}",
                build.manifest_path, build.revision
            )
        }),
        None => Err(format!(
            "the build of revision `{}` kept no manifest — it was built by a spaceport that did not record one, and the checkout it was read from is gone",
            build.revision
        )),
    };

    match parsed {
        Ok(manifest) => Some(manifest),
        Err(reason) => {
            failed(worker, app, &build.revision, &reason).await;

            None
        }
    }
}

/// Write down that a deployment did not work, and say so out loud.
///
/// The row and the line are two audiences: the row is what an operator reads
/// days later from `spaceport apps show`, and the line is what somebody
/// watching `spaceport stream` after a push sees the moment it happens. Both
/// carry the revision, because "which commit" is the first question either of
/// them has.
async fn failed(worker: &Worker, app: &AppId, revision: &str, reason: &str) {
    if let Err(error) = worker.builds.deploy_failed(app, revision, reason).await {
        warn!(
            app = %app,
            error = %format!("{error:#}"),
            "could not record a deployment that failed, so it may be attempted again",
        );
    }

    warn!(
        app = %app,
        %revision,
        %reason,
        by = BY_SPACEPORT,
        "could not deploy this app's revision",
    );
}

/// Put `app` back on the manifest and revision its record still names.
///
/// **Here rather than as a verb on [`Applier`]**, and the reason is what a
/// rollback actually is. It is not a new capability: it is
/// [`Applier::restore`] — the call a restart makes — over the record, which is
/// still the previous one precisely because `record_applied` runs only when an
/// apply has worked. What would make it an `Applier` verb is a contract nobody
/// else could use safely: "go back" only means anything in the moment
/// immediately after a failed deploy by the same caller, and every other verb on
/// that type is self-contained and says what it does from its arguments alone.
/// So the ordering rule — read the record first, deploy, restore it if the
/// deploy failed — stays visible in the one loop that needs it, rather than
/// becoming an invariant an `Applier` would have to document and could not
/// enforce.
///
/// **It does not loop.** A rollback that fails is warned about and left, never
/// retried, because the two failures together are a host that cannot start
/// either revision — and trying harder at that is how a loop takes an app up
/// and down every pass. What the app is in that case is: not serving, still
/// claiming its hosts so nothing else can take them and its certificates go on
/// being renewed, still recorded as wanting the *previous* manifest, and with
/// the sentence on the build row saying which commit did this. The supervisor's
/// sweep is what tries it again, which is exactly the state an app that had
/// crashed on its own would be in. The rollback is not a second safety net —
/// it is the same net, arriving in a second rather than in a minute.
///
/// **It puts the record back too.** Nearly every failed deployment leaves the
/// record untouched, because `record_applied` runs only when an apply has
/// worked — but one does not: a manifest whose secrets are not all set is
/// *staged*, recorded, and only then refused, which is what makes an app
/// waiting for a secret survive a restart. Left alone, that record would say
/// this app is suspended on the manifest of a commit that never ran, while it
/// is in fact serving the one before it — and the next restart would take the
/// running container away to honour it, with no further commit involved. So the
/// record read at the top of the deployment is written back, which is a no-op
/// for every other kind of failure.
///
/// An app with no record was never running, so there is nothing to go back to.
/// It stays down, saying why — or, if the deployment got as far as staging it,
/// suspended and waiting for its secrets, which is a state a resume can finish.
async fn roll_back(worker: &Worker, app: &AppId, record: Option<&AppRecord>) {
    let Some(record) = record else {
        warn!(
            app = %app,
            by = BY_SPACEPORT,
            "this app had nothing running before, so there is nothing to put it back on — it is down",
        );

        return;
    };

    let manifest = match AppManifest::parse(&record.manifest) {
        Ok(manifest) => manifest,
        // The document this spaceport itself recorded when the app last
        // started. Unreadable here means the record was written by a build that
        // understood a schema this one does not.
        Err(error) => {
            warn!(
                app = %app,
                error = %format!("{error:#}"),
                by = BY_SPACEPORT,
                "could not read the manifest this app was running, so it stays down",
            );

            return;
        }
    };

    // Before the app is put back rather than after, because this is the half
    // that must happen even if the restore does not: an app that cannot be
    // started is one the supervisor will keep trying, and what it should keep
    // trying is the manifest this record names.
    if let Err(error) = worker.applier.repository().put_back(record).await {
        warn!(
            app = %app,
            error = %format!("{error:#}"),
            by = BY_SPACEPORT,
            "could not put this app's record back, so a restart may bring back the manifest that failed",
        );
    }

    // `restore` and not `deploy`, because nothing new is being decided: this is
    // the record being made true again, and re-recording it would restate when
    // the app was applied as though somebody had just applied it.
    match worker
        .applier
        .restore(
            app.clone(),
            manifest,
            record.revision.as_deref(),
            record.suspended,
        )
        .await
    {
        Ok(_) => info!(
            app = %app,
            revision = record.revision.as_deref().unwrap_or_default(),
            by = BY_SPACEPORT,
            "put this app back on what it was running",
        ),
        // The one path where what this doc says about the supervisor's sweep
        // does not hold. A restore that fails before it reaches the store
        // leaves the app in neither the routing table nor the down list, and
        // the sweep only looks at apps it can see — so nothing here retries it,
        // and what brings it back is the next apply, deploy or restart of
        // spaceport, which the record is now correct for.
        Err(error) => warn!(
            app = %app,
            error = %format!("{error:#}"),
            by = BY_SPACEPORT,
            "could not put this app back on what it was running, so it is down until it is started again",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    use anyhow::{Result, bail};
    use async_trait::async_trait;

    use crate::app::manifest::Source;
    use crate::app::repository::AppRepository;
    use crate::app::secrets::SecretRepository;
    use crate::app::store::AppStore;
    use crate::build::repository::{Build, BuildState};
    use crate::connections::github::tracking::Tracking;
    use crate::runtime::{Adopted, Container, ContainerId, ContainerRuntime, Managed};
    use crate::state::Db;

    const APP: &str = "site";
    const HOST: &str = "site.example.com";
    /// Two revisions, ordered so that the newer one also sorts later: builds
    /// recorded in the same test finish within the same timestamp, and the
    /// store's tie-break is the revision.
    const RUNNING: &str = "aaaaaaa1111111111111111111111111111111111";
    const PUSHED: &str = "bbbbbbb2222222222222222222222222222222222";

    /// A manifest as a commit carries one: built rather than pulled, so that a
    /// deployment has to resolve the revision to the image its build produced.
    ///
    /// Routed the moment its container starts, which is what makes the
    /// successful cases fast — the failing ones ask for readiness on purpose.
    fn manifest_document() -> String {
        format!(
            "schema_version: 1
source:
  type: build
  dockerfile: Dockerfile
routing:
  hosts: [{HOST}]
auth:
  gating: open
container:
  health:
    readiness:
      type: none
"
        )
    }

    /// The same, but waiting on an app that has to answer — and the fake
    /// runtime's ports have nothing behind them, so it never will. This is a
    /// container that comes up and does not work, which is the commonest way a
    /// deployment of a perfectly good image fails.
    fn manifest_that_never_becomes_ready() -> String {
        format!(
            "schema_version: 1
source:
  type: build
  dockerfile: Dockerfile
routing:
  hosts: [{HOST}]
auth:
  gating: open
container:
  health:
    readiness:
      interval: 10ms
      timeout: 50ms
      failure_threshold: 2
"
        )
    }

    /// A container engine that starts nothing, and remembers what it was asked
    /// to run.
    ///
    /// It replaces an app's container on every launch, as a real engine does,
    /// and it refuses to adopt a container whose image is not the one the
    /// manifest names — which is what the real one's label and image check
    /// amount to, and what makes a relaunch visible here.
    #[derive(Default)]
    struct FakeRuntime {
        /// Every image it has been asked to launch, in order. The whole of what
        /// these tests assert about the engine: which image, and how often.
        launched: Mutex<Vec<String>>,
        /// Images it will refuse, for the failures that happen before a
        /// container exists at all.
        refused: Mutex<Vec<String>>,
        /// What it is running for each app, and from which image.
        running: Mutex<HashMap<AppId, (String, Container)>>,
    }

    impl FakeRuntime {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn refuses(&self, image: &str) {
            self.refused.lock().unwrap().push(image.to_owned());
        }

        fn launches(&self) -> Vec<String> {
            self.launched.lock().unwrap().clone()
        }
    }

    /// The image a manifest that has been through the applier names.
    ///
    /// A manifest still saying `build` never reaches a runtime — that is what
    /// [`Applier::deploy`] resolves on the way in — so a fake that met one
    /// would be a fake meeting something production cannot produce.
    fn image_of(manifest: &AppManifest) -> Result<String> {
        match &manifest.source {
            Source::Image { image } => Ok(image.clone()),
            Source::Build { .. } => bail!("this app builds its own image, which nothing can run"),
        }
    }

    #[async_trait]
    impl ContainerRuntime for FakeRuntime {
        async fn adopt(&self, app: &AppId, manifest: &AppManifest) -> Result<Option<Adopted>> {
            let wanted = image_of(manifest)?;

            Ok(self
                .running
                .lock()
                .unwrap()
                .get(app)
                .filter(|(image, _)| *image == wanted)
                .map(|(_, container)| Adopted::Running(container.clone())))
        }

        async fn stop(&self, _id: &ContainerId) -> Result<()> {
            Ok(())
        }

        async fn start(&self, id: &ContainerId, _manifest: &AppManifest) -> Result<Container> {
            Ok(Container {
                id: id.clone(),
                upstream: SocketAddr::from(([127, 0, 0, 1], 7777)),
            })
        }

        async fn launch(&self, app: &AppId, manifest: &AppManifest) -> Result<Container> {
            let image = image_of(manifest)?;
            if self.refused.lock().unwrap().contains(&image) {
                bail!("no image `{image}` here");
            }

            let mut launched = self.launched.lock().unwrap();
            launched.push(image.clone());

            // A different port per launch, so that a container replacing
            // another is visible from the routing table.
            let port = 9000 + u16::try_from(launched.len()).unwrap();
            let container = Container {
                id: ContainerId::new(format!("{app}-{port}")),
                upstream: SocketAddr::from(([127, 0, 0, 1], port)),
            };
            self.running
                .lock()
                .unwrap()
                .insert(app.clone(), (image, container.clone()));

            Ok(container)
        }

        async fn remove(&self, id: &ContainerId) -> Result<()> {
            self.running
                .lock()
                .unwrap()
                .retain(|_, (_, container)| container.id != *id);

            Ok(())
        }

        async fn managed(&self) -> Result<Vec<Managed>> {
            Ok(Vec::new())
        }
    }

    /// A spaceport with one app, over an in-memory store and a fake engine.
    struct Fixture {
        worker: Arc<Worker>,
        applier: Arc<Applier>,
        runtime: Arc<FakeRuntime>,
        store: Arc<AppStore>,
        builds: BuildRepository,
        trackings: Arc<TrackingRepository>,
    }

    impl Fixture {
        fn new() -> Self {
            let db = Db::in_memory().unwrap();
            let store = Arc::new(AppStore::new());
            let runtime = FakeRuntime::new();
            let builds = BuildRepository::new(db.clone());
            let applier = Arc::new(Applier::new(
                store.clone(),
                runtime.clone(),
                AppRepository::new(db.clone()),
                builds.clone(),
                SecretRepository::new(db.clone()),
            ));
            let trackings = Arc::new(TrackingRepository::new(db));

            Self {
                worker: Arc::new(Worker {
                    applier: applier.clone(),
                    trackings: trackings.clone(),
                    builds: builds.clone(),
                }),
                applier,
                runtime,
                store,
                builds,
                trackings,
            }
        }

        fn app(&self) -> AppId {
            APP.parse().unwrap()
        }

        /// Track [`APP`], armed or not, as `spaceport apps track` would.
        async fn track(&self, automatic: bool) {
            self.trackings
                .record(
                    &Tracking {
                        app: self.app(),
                        github_app_id: 42,
                        repository: "an-organisation/site".to_owned(),
                        branch: "main".to_owned(),
                        manifest_path: "spaceport.yaml".to_owned(),
                        tracked_at: String::new(),
                        revision: None,
                        revision_seen_at: None,
                        automatic,
                    },
                    Some(automatic),
                )
                .await
                .unwrap();
        }

        /// A finished build of `revision`, exactly as the builder leaves one.
        async fn built(&self, revision: &str, document: &str) {
            self.builds
                .request(&Build {
                    app: self.app(),
                    revision: revision.to_owned(),
                    connection: "spaceport-for-acme".to_owned(),
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
                })
                .await
                .unwrap();
            self.builds
                .succeeded(
                    &self.app(),
                    revision,
                    &image(revision),
                    "sha256:0123",
                    document,
                    "",
                )
                .await
                .unwrap();
        }

        /// The app running [`RUNNING`], deployed and recorded as an operator's
        /// deploy would have left it.
        async fn already_running(&self) {
            self.built(RUNNING, &manifest_document()).await;
            self.applier
                .deploy(
                    self.app(),
                    AppManifest::parse(&manifest_document()).unwrap(),
                    Some(RUNNING),
                    false,
                )
                .await
                .unwrap();
            self.builds.deployed(&self.app(), RUNNING).await.unwrap();
        }

        async fn pass(&self) {
            pass(&self.worker, &CancellationToken::new()).await;
        }

        async fn build_of(&self, revision: &str) -> Build {
            self.builds
                .get(&self.app(), revision)
                .await
                .unwrap()
                .unwrap()
        }

        async fn recorded_revision(&self) -> Option<String> {
            self.applier
                .repository()
                .recorded(&self.app())
                .await
                .unwrap()
                .and_then(|record| record.revision)
        }
    }

    /// The image the builder tags a revision with, as these tests spell it.
    fn image(revision: &str) -> String {
        format!("spaceport/{APP}:{}", &revision[..7])
    }

    /// The whole point: a commit that built is a commit that is running, with
    /// nobody typing anything.
    #[tokio::test]
    async fn an_armed_apps_built_revision_is_deployed() {
        let fixture = Fixture::new();
        fixture.track(true).await;
        fixture.built(PUSHED, &manifest_document()).await;

        fixture.pass().await;

        assert_eq!(fixture.runtime.launches(), [image(PUSHED)]);
        assert_eq!(
            fixture.store.routes().serving(HOST).unwrap().id,
            "site".parse().unwrap()
        );
        // And the revision is recorded as what the app runs, which is what a
        // restart resolves again.
        assert_eq!(fixture.recorded_revision().await.as_deref(), Some(PUSHED));
        // The row says a deployment concluded, and that it worked.
        let build = fixture.build_of(PUSHED).await;
        assert!(build.deployed_at.is_some());
        assert_eq!(build.deploy_reason, None);
        assert!(!build.awaits_deployment());
    }

    /// Arming is asked for, never assumed: a tracked app that nobody armed goes
    /// on waiting for `spaceport apps deploy`.
    #[tokio::test]
    async fn an_app_that_is_not_armed_is_left_where_it_is() {
        let fixture = Fixture::new();
        fixture.track(false).await;
        fixture.built(PUSHED, &manifest_document()).await;

        fixture.pass().await;

        assert!(fixture.runtime.launches().is_empty());
        assert!(fixture.store.apps().is_empty());
        // Still waiting, so arming the app tomorrow deploys this very commit.
        assert!(fixture.build_of(PUSHED).await.awaits_deployment());
    }

    /// Suspension is where an operator put the app, and a push is not an
    /// argument against it.
    #[tokio::test]
    async fn a_suspended_app_is_not_deployed_over() {
        let fixture = Fixture::new();
        fixture.track(true).await;
        fixture.already_running().await;
        fixture.applier.suspend(&fixture.app(), true).await.unwrap();
        fixture.built(PUSHED, &manifest_document()).await;

        fixture.pass().await;

        // One launch in total: the one that put the running revision there.
        assert_eq!(fixture.runtime.launches(), [image(RUNNING)]);
        assert!(fixture.store.suspended(&fixture.app()).is_some());
        assert_eq!(fixture.recorded_revision().await.as_deref(), Some(RUNNING));
        // Untouched rather than refused: resuming and deploying by hand is
        // still open, and so is this loop once the app is resumed.
        assert!(fixture.build_of(PUSHED).await.awaits_deployment());
    }

    /// The commonest failure there is — an image that starts and never answers
    /// — and the app is back on the revision that was working before the
    /// supervisor has even had a chance to notice.
    #[tokio::test]
    async fn a_deploy_that_fails_puts_the_app_back_on_what_it_was_running() {
        let fixture = Fixture::new();
        fixture.track(true).await;
        fixture.already_running().await;
        fixture
            .built(PUSHED, &manifest_that_never_becomes_ready())
            .await;

        fixture.pass().await;

        // The new image was tried, and the old one is what is running again.
        assert_eq!(
            fixture.runtime.launches(),
            [image(RUNNING), image(PUSHED), image(RUNNING)]
        );
        assert!(fixture.store.routes().serving(HOST).is_some());
        // The record was never rewritten, because the deployment never
        // succeeded — which is exactly why it is what the rollback goes back to.
        assert_eq!(fixture.recorded_revision().await.as_deref(), Some(RUNNING));
        // And the failure is on the row, in a sentence naming what went wrong.
        let build = fixture.build_of(PUSHED).await;
        assert!(build.deployed_at.is_some());
        let reason = build.deploy_reason.unwrap();
        assert!(reason.contains("never became ready"), "{reason}");
    }

    /// The other kind of failure: one that happens before a container exists at
    /// all, so nothing was displaced. The app is serving throughout, and the
    /// rollback is the no-op it should be rather than an interruption of its
    /// own.
    #[tokio::test]
    async fn a_deploy_whose_image_will_not_start_leaves_the_app_serving() {
        let fixture = Fixture::new();
        fixture.track(true).await;
        fixture.already_running().await;
        fixture.built(PUSHED, &manifest_document()).await;
        fixture.runtime.refuses(&image(PUSHED));

        fixture.pass().await;

        // The container it was serving from is the one it is still serving
        // from: nothing was started, and nothing had to be started again.
        assert_eq!(fixture.runtime.launches(), [image(RUNNING)]);
        assert!(fixture.store.routes().serving(HOST).is_some());
        assert_eq!(fixture.recorded_revision().await.as_deref(), Some(RUNNING));
        let reason = fixture.build_of(PUSHED).await.deploy_reason.unwrap();
        assert!(reason.contains("no image"), "{reason}");
    }

    /// The property that keeps this loop from taking an app down once a minute
    /// for ever: the retry is the next commit, not the next pass.
    #[tokio::test]
    async fn a_revision_whose_deploy_failed_is_never_attempted_again() {
        let fixture = Fixture::new();
        fixture.track(true).await;
        fixture.already_running().await;
        fixture
            .built(PUSHED, &manifest_that_never_becomes_ready())
            .await;
        fixture.pass().await;
        let after_the_failure = fixture.runtime.launches();

        fixture.pass().await;
        fixture.pass().await;

        assert_eq!(fixture.runtime.launches(), after_the_failure);
        assert_eq!(fixture.recorded_revision().await.as_deref(), Some(RUNNING));
    }

    /// An app that has never run has nothing to go back to, and this must not
    /// be the case that panics or loops — it is left down, with the reason
    /// somewhere an operator reads.
    #[tokio::test]
    async fn an_app_that_never_ran_is_left_down_when_its_first_deploy_fails() {
        let fixture = Fixture::new();
        fixture.track(true).await;
        fixture
            .built(PUSHED, &manifest_that_never_becomes_ready())
            .await;

        fixture.pass().await;

        assert_eq!(fixture.runtime.launches(), [image(PUSHED)]);
        assert!(fixture.store.apps().is_empty());
        assert!(fixture.store.routes().serving(HOST).is_none());
        // Nothing was recorded for it, so a restart brings back no app either.
        assert_eq!(fixture.recorded_revision().await, None);
        let reason = fixture.build_of(PUSHED).await.deploy_reason.unwrap();
        assert!(reason.contains("never became ready"), "{reason}");
    }

    /// A revision an operator deployed by hand is deployed. Coming along
    /// afterwards and deploying it again would restart a running app for no
    /// reason at all.
    #[tokio::test]
    async fn a_revision_that_has_already_been_deployed_is_not_deployed_twice() {
        let fixture = Fixture::new();
        fixture.track(true).await;
        fixture.already_running().await;

        fixture.pass().await;
        fixture.pass().await;

        assert_eq!(fixture.runtime.launches(), [image(RUNNING)]);
    }

    /// A build kept by a spaceport that did not record manifests has nothing to
    /// deploy and nowhere left to read one from. It fails like any other
    /// deployment — once, in a sentence — rather than being retried every pass.
    #[tokio::test]
    async fn a_build_that_kept_no_manifest_fails_readably_and_starts_nothing() {
        let fixture = Fixture::new();
        fixture.track(true).await;
        fixture.built(PUSHED, "").await;

        fixture.pass().await;

        assert!(fixture.runtime.launches().is_empty());
        let reason = fixture.build_of(PUSHED).await.deploy_reason.unwrap();
        assert!(reason.contains("kept no manifest"), "{reason}");
    }

    /// A commit that starts reading a secret, as one does the day somebody adds
    /// a database to an app.
    fn manifest_needing_a_secret() -> String {
        format!(
            "schema_version: 1
source:
  type: build
  dockerfile: Dockerfile
routing:
  hosts: [{HOST}]
auth:
  gating: open
container:
  secrets: [DB_PASSWORD]
  env:
    DATABASE_URL: \"postgres://user:{{{{DB_PASSWORD}}}}@db/app\"
  health:
    readiness:
      type: none
"
        )
    }

    /// The commit that adds a secret and lands before anybody sets it. Nothing
    /// about it is special to this loop: it is a deployment that did not work,
    /// so the app goes back to the revision that did and the row says which
    /// secret it was — which is where an operator finds out that all they have
    /// to do is set it and push again.
    #[tokio::test]
    async fn a_build_whose_manifest_needs_a_secret_nobody_set_is_rolled_back() {
        let fixture = Fixture::new();
        fixture.track(true).await;
        fixture.already_running().await;
        fixture.built(PUSHED, &manifest_needing_a_secret()).await;

        fixture.pass().await;

        // The new revision never reached the engine — there was nothing safe to
        // start — and the old one is running again in a container of its own,
        // because staging the new manifest took the one it had away.
        assert_eq!(
            fixture.runtime.launches(),
            [image(RUNNING), image(RUNNING)],
            "the image needing the secret must never have been launched",
        );
        assert!(fixture.store.routes().serving(HOST).is_some());
        assert!(fixture.store.suspended(&fixture.app()).is_none());

        // The record is the one it was running before, down to not being
        // suspended: the applier records what it stages, and a rollback is what
        // undoes that. Otherwise this app would come back suspended on a
        // manifest that never ran, and no later commit would ever be deployed.
        let record = fixture
            .applier
            .repository()
            .recorded(&fixture.app())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.revision.as_deref(), Some(RUNNING));
        assert_eq!(record.manifest, manifest_document());
        assert!(!record.suspended);

        // And the row names the secret, for whoever reads `spaceport apps show`
        // tomorrow morning.
        let reason = fixture.build_of(PUSHED).await.deploy_reason.unwrap();
        assert!(reason.contains("DB_PASSWORD"), "{reason}");

        // Tried once and never again: a secret nobody has set is not something
        // the next pass can do any better at.
        fixture.pass().await;
        fixture.pass().await;
        assert_eq!(fixture.runtime.launches(), [image(RUNNING), image(RUNNING)]);
    }

    /// Give the loop enough turns to have acted on what it was told, without
    /// moving the clock: a task that has not been polled has not started.
    async fn let_the_loop_run() {
        for _ in 0..200 {
            tokio::task::yield_now().await;
        }
    }

    /// A build that finished must not wait out the interval, which is the whole
    /// reason this loop takes a nudge.
    #[tokio::test(start_paused = true)]
    async fn a_nudge_deploys_what_the_interval_would_have_left_for_minutes() {
        let fixture = Fixture::new();
        fixture.track(true).await;
        let policy = Policy::default();
        let nudge = Nudge::new();
        let shutdown = CancellationToken::new();
        let running = tokio::spawn(maintain(
            fixture.worker.clone(),
            policy.clone(),
            nudge.clone(),
            shutdown.clone(),
        ));
        // The first pass has nothing to do, and has to have finished before the
        // build arrives — otherwise it is the pass under test.
        let_the_loop_run().await;
        fixture.built(PUSHED, &manifest_document()).await;

        let woken = tokio::time::Instant::now();
        nudge.nudge();
        let_the_loop_run().await;
        tokio::time::advance(policy.settle.unsigned_abs()).await;
        let_the_loop_run().await;

        assert_eq!(fixture.runtime.launches(), [image(PUSHED)]);
        assert!(
            woken.elapsed() < policy.interval.unsigned_abs(),
            "the deployment waited out the interval"
        );
        shutdown.cancel();
        running.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn the_loop_stops_when_it_is_shut_down() {
        let fixture = Fixture::new();
        fixture.track(true).await;
        fixture.built(PUSHED, &manifest_document()).await;
        let shutdown = CancellationToken::new();

        let running = tokio::spawn(maintain(
            fixture.worker.clone(),
            Policy::default(),
            Nudge::new(),
            shutdown.clone(),
        ));
        let_the_loop_run().await;
        // Cancelled while the loop is sleeping off an interval that is minutes
        // away: without the select arm this would never return.
        shutdown.cancel();
        running.await.unwrap();

        assert_eq!(
            fixture.runtime.launches(),
            [image(PUSHED)],
            "the first pass ran"
        );
    }
}

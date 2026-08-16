//! Applying a manifest: the one verb the operator interface has.
//!
//! An apply is three things that can each fail — the routes an app claims have
//! to be free, a container has to start, and the app inside it has to answer —
//! and the order matters. Routing is checked first because it is cheap and
//! because the alternative is starting a container for an app that was never
//! going to be reachable, having already torn down the one it replaced on the
//! way in.
//!
//! There is a fourth thing that can fail, and it fails differently: the secrets
//! a manifest declares have to be set before there is anything to start. An
//! apply that finds one missing does not refuse outright — it stages the app
//! suspended, claiming its hosts and recording what it would run, and *then*
//! says which secrets it is waiting for. That is the only failure here that
//! leaves the app in a state somebody can finish, because finishing it is
//! setting a value and resuming, and the resume is what resolves them again.
//!
//! Suspending is the fourth verb, and the only one that leaves an app halfway:
//! recorded, claiming its hosts, not served. Everything it does happens in the
//! same order a destroy does — the routes go first, so nothing is forwarded to
//! a container that is about to stop — and the difference is only in how far it
//! goes. A destroy forgets the app and deletes its container; a suspend
//! remembers both.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::anyhow;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tracing::{debug, info, warn};

use super::manifest::{Source, VarName};
use super::repository::AppRepository;
use super::secrets::SecretRepository;
use super::store::{Removed, Suspended};
use super::{App, AppId, AppManifest, AppStore, health};
use crate::build::repository::BuildRepository;
use crate::runtime::{Adopted, Container, ContainerRuntime};

/// Why an apply did not happen. The distinction is worth keeping because the
/// operator interface answers differently: a conflict is the operator's to fix,
/// a failure is the host's.
#[derive(Debug)]
pub enum ApplyError {
    /// Another app already serves one of the manifest's hosts.
    Conflict(anyhow::Error),
    /// The manifest declares secrets nothing has set, so the app was staged
    /// suspended rather than started.
    ///
    /// A variant of its own because it is neither of the other two: the host is
    /// fine and the document is fine, and what is missing is a value somebody
    /// has to go and set. It is an error all the same — the operator asked for
    /// a running app and has not got one — and it carries the names, because
    /// "which secret" is the only thing they need to know.
    MissingSecrets(Vec<VarName>),
    /// The app could not be started.
    Failed(anyhow::Error),
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict(error) | Self::Failed(error) => write!(f, "{error:#}"),
            // Two cases and one sentence, because both are true of the app the
            // operator is holding: one that was never started is suspended
            // waiting, and one that *was* running has been taken down by
            // `stage` — its container was built from the manifest this one
            // replaces. Saying only "it stays suspended" would let somebody
            // who re-applied a manifest with a new secret in it believe their
            // app is still serving, which is the one thing it is not.
            Self::MissingSecrets(secrets) => write!(
                f,
                "this app needs secrets nothing has set: {} — it is suspended until they are set, and it is not serving: an app that was running has been taken down for this",
                named(secrets)
            ),
        }
    }
}

/// Secret names as a sentence lists them: quoted, in the order they were
/// declared, and nothing else about them.
fn named<'a>(secrets: impl IntoIterator<Item = &'a VarName>) -> String {
    secrets
        .into_iter()
        .map(|secret| format!("`{secret}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

impl std::error::Error for ApplyError {}

/// Why an app could not be destroyed.
#[derive(Debug)]
pub enum DestroyError {
    /// No app is running under that id.
    Unknown(anyhow::Error),
    /// Its container would not go away.
    Failed(anyhow::Error),
}

impl fmt::Display for DestroyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(error) | Self::Failed(error) => write!(f, "{error:#}"),
        }
    }
}

impl std::error::Error for DestroyError {}

/// Why an app could not be suspended.
#[derive(Debug)]
pub enum SuspendError {
    /// Nothing is recorded under that id.
    Unknown(anyhow::Error),
    /// Its container would not stop.
    Failed(anyhow::Error),
}

impl fmt::Display for SuspendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(error) | Self::Failed(error) => write!(f, "{error:#}"),
        }
    }
}

impl std::error::Error for SuspendError {}

/// Why an app could not be resumed.
#[derive(Debug)]
pub enum ResumeError {
    /// Nothing is recorded under that id.
    Unknown(anyhow::Error),
    /// Another app claimed one of its hosts. Only reachable for an app that was
    /// suspended by a spaceport that did not hold its hosts for it.
    Conflict(anyhow::Error),
    /// Secrets its manifest declares are still not set. The way back for an app
    /// suspended for a missing secret is a resume, so this is the answer
    /// somebody who tries it too early gets — and the app is left exactly where
    /// it was rather than started with a placeholder in its environment.
    MissingSecrets(Vec<VarName>),
    /// It could not be started.
    Failed(anyhow::Error),
}

impl fmt::Display for ResumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(error) | Self::Conflict(error) | Self::Failed(error) => {
                write!(f, "{error:#}")
            }
            // A resume never takes anything down — a running app is answered
            // before this is reachable — so what is true here is only the
            // second half of what an apply says: still suspended, still not
            // serving.
            Self::MissingSecrets(secrets) => write!(
                f,
                "this app needs secrets nothing has set: {} — it stays suspended, and not serving, until they are set",
                named(secrets)
            ),
        }
    }
}

impl std::error::Error for ResumeError {}

impl From<ApplyError> for ResumeError {
    fn from(error: ApplyError) -> Self {
        match error {
            ApplyError::Conflict(error) => Self::Conflict(error),
            // Kept as itself rather than flattened into `Failed`: this is the
            // one refusal a resume has that an operator can do something about,
            // and it is worth its own answer all the way out to HTTP.
            ApplyError::MissingSecrets(secrets) => Self::MissingSecrets(secrets),
            ApplyError::Failed(error) => Self::Failed(error),
        }
    }
}

/// What an apply left behind.
///
/// The suspended side is boxed: a running app is behind an `Arc` and a
/// suspended one carries its whole manifest, and there is no reason for the
/// common case to pay for the size of the other.
#[derive(Debug, Clone)]
pub enum Applied {
    /// Started and serving.
    Running(Arc<App>),
    /// Recorded and claiming its hosts, deliberately not started.
    Suspended(Box<Suspended>),
}

impl Applied {
    pub fn id(&self) -> &AppId {
        match self {
            Self::Running(app) => &app.id,
            Self::Suspended(app) => &app.id,
        }
    }

    /// The app if it is running, which a suspended one is not.
    pub fn running(&self) -> Option<&Arc<App>> {
        match self {
            Self::Running(app) => Some(app),
            Self::Suspended(_) => None,
        }
    }
}

/// How an app came back at a restart.
///
/// The first two mean the app is running and routed; they differ in what it
/// cost. The distinction is worth reporting, because "adopted" is the answer
/// that says a restart of spaceport did not interrupt anybody's traffic.
#[derive(Debug)]
pub enum Restored {
    /// Its container was still running and was taken over untouched.
    Adopted(Arc<App>),
    /// There was nothing to take over, so it was started again.
    Relaunched(Arc<App>),
    /// It was recorded as suspended, and was put back the way it was left
    /// rather than started. Suspension is intent, and a restart of spaceport is
    /// not a reason to overrule it.
    Suspended(AppId),
}

impl Restored {
    pub fn id(&self) -> &AppId {
        match self {
            Self::Adopted(app) | Self::Relaunched(app) => &app.id,
            Self::Suspended(id) => id,
        }
    }

    /// The app if it is running again, which a suspended one is not.
    pub fn app(&self) -> Option<&Arc<App>> {
        match self {
            Self::Adopted(app) | Self::Relaunched(app) => Some(app),
            Self::Suspended(_) => None,
        }
    }

    pub fn was_adopted(&self) -> bool {
        matches!(self, Self::Adopted(_))
    }

    pub fn was_suspended(&self) -> bool {
        matches!(self, Self::Suspended(_))
    }
}

/// Turns manifests into running, routed apps, and takes them back down again.
pub struct Applier {
    store: Arc<AppStore>,
    runtime: Arc<dyn ContainerRuntime>,
    repository: AppRepository,
    /// What spaceport has built, and so what a `type: build` manifest can be
    /// run as. Read on the way in to every verb that starts an app, and never
    /// written to from here — building is somebody else's business.
    builds: BuildRepository,
    /// The values an app's manifest names and never contains. Read on the way
    /// in to every verb that starts an app, for the same reason `builds` is: a
    /// manifest that reaches the runtime has to be one the runtime can run, and
    /// one whose environment still says `{{DB_PASSWORD}}` is not.
    secrets: SecretRepository,
    /// The apps something is in the middle of doing something to, and the lock
    /// that keeps it to one thing at a time.
    ///
    /// Two jobs in one map, because they are the same question asked twice.
    ///
    /// The first is what the supervisor asks. Every verb here takes containers
    /// down and puts them up, and the engine reports all of it — a replaced
    /// container dying is indistinguishable, in an event stream, from one that
    /// crashed. An app in here is being seen to, and whatever the engine has to
    /// say about it is spaceport's own doing.
    ///
    /// The second is exclusion. Every verb is a read of the world followed by a
    /// series of awaits that change it, and two of them interleaved on one app
    /// produce states no single verb can: a destroy that removes the container
    /// an apply is about to route to, two applies whose containers both survive
    /// with only one of them routed, a suspend that stops the container a resume
    /// has just started. The per-app lock is what makes each verb see the world
    /// its predecessor left.
    ///
    /// A [`tokio::sync::Mutex`] and not a `std` one because the critical section
    /// is the whole verb: engine calls and a readiness wait that is allowed to
    /// take tens of seconds. The `std` mutex around the map guards the map and
    /// nothing else, and is never held across an await — holding it while
    /// waiting would serialise every app against every other, which is the one
    /// thing a per-app lock exists not to do.
    ///
    /// The count beside each lock is holders *and* waiters. It is what lets the
    /// entry go when the last of them leaves without a waiter being left holding
    /// an `Arc` to an entry a newcomer has already replaced with a second lock
    /// for the same id — two locks for one app being exactly no lock at all.
    worked_on: Mutex<WorkedOn>,
}

/// One lock per app, and beside it the number of holders and waiters that lock
/// has — which is what says when the app can be forgotten again. Named only so
/// that the shape is written once.
type WorkedOn = HashMap<AppId, (Arc<AsyncMutex<()>>, usize)>;

impl Applier {
    pub fn new(
        store: Arc<AppStore>,
        runtime: Arc<dyn ContainerRuntime>,
        repository: AppRepository,
        builds: BuildRepository,
        secrets: SecretRepository,
    ) -> Self {
        Self {
            store,
            runtime,
            repository,
            builds,
            secrets,
            worked_on: Mutex::default(),
        }
    }

    /// Take `id` for as long as the returned guard is held, waiting for whoever
    /// has it now.
    ///
    /// The one way to work on an app. Everything a verb reads about the world
    /// must be read *after* this returns, because the world the caller looked at
    /// before it is the world some other verb was in the middle of changing: an
    /// app that was running when the caller checked can be destroyed, suspended
    /// or replaced while it waits here.
    ///
    /// Not reentrant, and deliberately so — a lock that could be taken twice by
    /// the same task would excuse exactly the nesting that makes a verb's view
    /// of the world stale. Nothing here takes it twice: the six verbs are the
    /// only holders and none of them calls another, and the callers outside that
    /// re-enter the applier drop the guard first.
    ///
    /// Public for one caller outside this type: the operator interface's `set`,
    /// which writes a secret of an app it did not start. That is not a verb
    /// here, but it changes what the app's container would be built from, and it
    /// races a `destroy` for the row it writes — so it takes the same lock
    /// rather than reaching for a second mechanism.
    pub async fn working(&self, id: &AppId) -> Working<'_> {
        // The map's guard is dropped at the end of this statement, before the
        // await below: what is waited on is one app's lock, never the map's.
        let lock = self.enrol(id);

        Working {
            applier: self,
            id: id.clone(),
            held: Some(lock.lock_owned().await),
        }
    }

    /// The same, for a caller that would rather be told no than wait.
    ///
    /// What the operator interface's `set` uses. A secret is set by somebody
    /// holding a terminal, and an answer that says "the app is busy, try again"
    /// is worth more to them than a request that hangs for the length of a
    /// deploy and then writes a value into a world that has moved.
    pub fn try_working(&self, id: &AppId) -> Option<Working<'_>> {
        let lock = self.enrol(id);

        match lock.try_lock_owned() {
            Ok(held) => Some(Working {
                applier: self,
                id: id.clone(),
                held: Some(held),
            }),
            // Enrolling counted this caller as a waiter, and it is not one.
            // Leaving the count behind would be an app marked as being worked on
            // by nobody, for good, which is a container the supervisor would
            // never restart.
            Err(_) => {
                self.leave(id);
                None
            }
        }
    }

    /// Whether something is in the middle of doing something to `id`.
    ///
    /// The supervisor's one question before it acts on an event: an app that is
    /// being applied, resumed, suspended or destroyed is not an app that has
    /// broken, however much the engine's event stream makes it look like one.
    ///
    /// Presence in the map, which counts waiters as well as holders — and that
    /// is the right answer, because a waiter is something that is going to work
    /// on this app the moment it can, and the container it will take down is not
    /// a container that failed.
    pub fn is_settling(&self, id: &AppId) -> bool {
        self.marks().contains_key(id)
    }

    /// Count this caller among the holders and waiters of `id`'s lock, and hand
    /// back the lock itself to be waited on with the map released.
    fn enrol(&self, id: &AppId) -> Arc<AsyncMutex<()>> {
        let mut marks = self.marks();
        let (lock, held) = marks
            .entry(id.clone())
            .or_insert_with(|| (Arc::new(AsyncMutex::new(())), 0));
        *held += 1;

        lock.clone()
    }

    /// Stop counting one holder or waiter, and forget the app entirely once
    /// there are none.
    fn leave(&self, id: &AppId) {
        let mut marks = self.marks();
        match marks.get_mut(id) {
            Some((_, 1)) | None => {
                marks.remove(id);
            }
            Some((_, held)) => *held -= 1,
        }
    }

    /// A poisoned lock means a thread panicked mid-mutation. Nothing here can
    /// repair that, and carrying on would leave an app marked as being worked
    /// on by nobody, which the supervisor would take as a reason to leave it
    /// down forever.
    fn marks(&self) -> std::sync::MutexGuard<'_, WorkedOn> {
        self.worked_on.lock().expect("applier settle lock poisoned")
    }

    /// How many apps the map is holding a lock for, for the tests that are
    /// about the map itself rather than about one app: an entry that outlives
    /// its last holder is a leak `is_settling` cannot see once the id it leaked
    /// under is forgotten.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.marks().len()
    }

    /// The apps this applier has running.
    pub fn store(&self) -> &AppStore {
        &self.store
    }

    /// What this applier has been told to run, across restarts.
    pub fn repository(&self) -> &AppRepository {
        &self.repository
    }

    /// The secrets of the apps it runs.
    ///
    /// Exposed for the same reason the record is: setting and listing secrets
    /// is the operator interface's business, and the applier is what holds the
    /// one repository every start already reads.
    pub fn secrets(&self) -> &SecretRepository {
        &self.secrets
    }

    /// The engine it runs apps on.
    pub fn runtime(&self) -> &dyn ContainerRuntime {
        self.runtime.as_ref()
    }

    /// Start the app named `id` again, because it has stopped serving.
    ///
    /// The supervisor's one verb, and it does not consult the record: an app
    /// gets here because it is recorded as wanted and is not running, which is
    /// the question already answered. What it does is take the app out of
    /// service if it is still nominally in it — so the edge answers rather than
    /// forwarding to a container that is not there — and then start it the way
    /// an apply would.
    ///
    /// Deliberately a fresh container every time, rather than starting again
    /// the one that exited. The two reasons an app gets here are that its
    /// container has gone and that its container is up and no longer working,
    /// and only one of those has anything worth keeping; a restart that
    /// sometimes reused a container and sometimes did not would differ from an
    /// apply in a way nobody could predict from the outside.
    ///
    /// Failing leaves the app down, claiming its hosts, with `reason` on it for
    /// a status report to show. The supervisor is what decides to try again.
    pub async fn restart(&self, id: &AppId, reason: &str) -> Result<Arc<App>, ApplyError> {
        // Waited for, and the app is looked up afterwards. The supervisor
        // decided this app was down before it called, and the wait here is
        // exactly long enough for that to stop being true — a deploy finishing
        // in the meantime has put the app back up, and the lookup below finds it
        // running rather than down.
        let _working = self.working(id).await;

        // Whichever of the two it is, the manifest is the same one: what the
        // store is holding for this app, which is what the record said.
        let manifest = match self.store.take_down(id, reason) {
            Some(app) => app.manifest.clone(),
            None => match self.store.downed(id) {
                Some(down) => down.manifest,
                None => {
                    return Err(ApplyError::Failed(anyhow!(
                        "no app named `{id}` is running or down"
                    )));
                }
            },
        };

        // Resolved again rather than taken off the manifest the store is
        // holding: a restart is a container being built afresh, and it must be
        // built from the secrets as they are now — including one an operator
        // set in the minute since the app broke, which is a fair description of
        // why it broke.
        let started = match self.runnable(id, manifest).await {
            Ok(manifest) => self.start(id.clone(), manifest).await,
            Err(error) => Err(error),
        };

        match started {
            Ok(app) => {
                info!(app = %id, container = %app.container, upstream = %app.upstream, "app restarted");

                Ok(app)
            }
            Err(error) => {
                // It came out of `apps` on the way in and never went back, so
                // all this does is say why for whoever reads the status next.
                self.store.note_down(id, format!("{error:#}"));

                Err(error)
            }
        }
    }

    /// Stop the app named `id` and forget it, routes and container both.
    ///
    /// The routes go first, so nothing is forwarded to a container on its way
    /// out. If the engine then refuses to remove it, the app is already gone
    /// from the store and nothing will ever route to that container again —
    /// the error names it, because by then it is a container only the operator
    /// can clean up.
    pub async fn destroy(&self, id: &AppId) -> Result<Removed, DestroyError> {
        // Removed after the wait and not before, so that what this destroys is
        // the app as the verb it waited for left it: the container an apply
        // started while this was queued is the one that goes, rather than the
        // one that apply already replaced.
        let _working = self.working(id).await;
        let app = self
            .store
            .remove(id)
            .ok_or_else(|| DestroyError::Unknown(anyhow!("no app named `{id}` is running")))?;

        // Forgotten before the container goes, so that a crash in between
        // leaves a container no record claims — which the next start cleans up
        // — rather than a record for an app that is not coming back.
        if let Err(error) = self.repository.forget(id).await {
            warn!(app = %id, %error, "could not forget the app, it will come back on restart");
        }

        // Secrets go with the app, unlike its volumes: a volume is the data an
        // operator may still want after the app is gone, and a secret is a
        // value that only ever meant anything to the app that read it. Leaving
        // them would mean an app applied under the same id tomorrow silently
        // inheriting the credentials of the one destroyed today.
        //
        // Warned about rather than fatal, exactly as forgetting the record is:
        // the app is already unrouted and about to have no container, and
        // failing here would report a destroy that did not happen when what did
        // not happen is a `DELETE` against the state store.
        if let Err(error) = self.secrets.forget(id).await {
            warn!(app = %id, %error, "could not forget the app's secrets, they will outlive it");
        }

        // A suspended app that was applied and never started has no container,
        // and destroying it is only the record and the claim on its hosts.
        if let Some(container) = app.container() {
            self.runtime.remove(container).await.map_err(|error| {
                DestroyError::Failed(error.context(format!(
                    "app `{id}` is no longer routed, but its container {container} is still there"
                )))
            })?;
            info!(app = %id, container = %container, "app destroyed");
        } else {
            info!(app = %id, "app destroyed, it had no container");
        }

        Ok(app)
    }

    /// Stop serving the app named `id`, keeping everything about it.
    ///
    /// The routes go first, as in a destroy: from the moment this returns, no
    /// request reaches the app. What it does *not* do is give up its hosts —
    /// they stay claimed, so no other app can take them and so its certificates
    /// go on being renewed while it is down.
    ///
    /// With `stop_container`, its container is stopped too, and kept. Without,
    /// the container is left running and only stops receiving traffic, which
    /// makes suspending and resuming cost nothing.
    ///
    /// Suspending an app that is already suspended is not an error: it is asked
    /// for the same state it is in. It will still stop the container if that is
    /// now being asked for and it is still running.
    pub async fn suspend(&self, id: &AppId, stop_container: bool) -> Result<(), SuspendError> {
        // The store is read after the wait: whether this app is running,
        // suspended or neither is the question a suspend is about, and it is
        // precisely what the verb ahead of it in the queue was changing.
        let _working = self.working(id).await;
        let held = match self.store.get(id) {
            // Unroute first, holding on to where its container was: until the
            // engine says otherwise, it is running and reachable there.
            Some(app) => {
                let container = Adopted::Running(Container {
                    id: app.container.clone(),
                    upstream: app.upstream,
                });
                self.store.suspend(id, Some(container.clone()));
                info!(app = %id, container = %app.container, "app suspended");

                Some(container)
            }
            None => match self.store.suspended(id) {
                Some(app) => app.container,
                None => {
                    return Err(SuspendError::Unknown(anyhow!(
                        "no app named `{id}` is running or suspended"
                    )));
                }
            },
        };

        if stop_container && let Some(Adopted::Running(container)) = held {
            self.runtime.stop(&container.id).await.map_err(|error| {
                SuspendError::Failed(error.context(format!(
                    "app `{id}` is suspended, but its container {} would not stop",
                    container.id
                )))
            })?;
            self.store.stopped(id);
            info!(app = %id, container = %container.id, "the suspended app's container was stopped");
        }

        if let Err(error) = self.repository.set_suspended(id, true).await {
            warn!(app = %id, %error, "the app is suspended but that was not recorded, so it will come back running");
        }

        Ok(())
    }

    /// Serve the app named `id` again.
    ///
    /// Where its container survived — stopped by a suspend, or left running by
    /// one — that container is what comes back, started again if it needs to be
    /// and checked before any traffic reaches it. An app whose container is
    /// gone, or no longer matches its manifest, is started fresh, which is what
    /// resuming used to cost every app.
    ///
    /// Resuming an app that is already running is not an error, for the same
    /// reason suspending a suspended one is not.
    pub async fn resume(&self, id: &AppId) -> Result<Arc<App>, ResumeError> {
        let _working = self.working(id).await;
        // Asked after the wait, and this is the one that matters most: "already
        // running, nothing to do" is the answer a resume gives, and an app that
        // was suspended when the caller asked may have been resumed by the verb
        // this waited for. Checking before the wait would start a second
        // container for an app that is already serving.
        if let Some(app) = self.store.get(id) {
            return Ok(app);
        }

        let suspended = self.store.suspended(id).ok_or_else(|| {
            ResumeError::Unknown(anyhow!("no app named `{id}` is running or suspended"))
        })?;
        // Resolved here and not taken as the manifest was staged, because this
        // is how an app suspended for a missing secret comes back: the secret
        // was set between the apply that refused and this call, and the whole
        // point of resuming is to pick it up. One that is still missing refuses
        // rather than starting a container with a placeholder in its
        // environment, and leaves the app suspended exactly as it was.
        let manifest = self.runnable(id, suspended.manifest).await?;

        // Asked of the engine rather than taken from the store: what spaceport
        // last saw is not what is true after somebody has used `docker` by
        // hand, and this is the moment it costs something to be wrong.
        let app = match self.reclaim(id, &manifest).await {
            Some(app) => app,
            None => self.start(id.clone(), manifest).await?,
        };

        if let Err(error) = self.repository.set_suspended(id, false).await {
            warn!(app = %id, %error, "the app is running but is still recorded as suspended, so it will not come back at a restart");
        }
        info!(app = %id, container = %app.container, upstream = %app.upstream, "app resumed");

        Ok(app)
    }

    /// Bring back the container a suspended app was left holding, if it still
    /// has one worth bringing back.
    ///
    /// Every way this can fail is a way of saying "start a fresh one instead",
    /// so it answers with an app or with nothing and never with an error.
    async fn reclaim(&self, id: &AppId, manifest: &AppManifest) -> Option<Arc<App>> {
        let held = match self.runtime.adopt(id, manifest).await {
            Ok(Some(held)) => held,
            Ok(None) => return None,
            Err(error) => {
                warn!(app = %id, %error, "could not tell what container the suspended app was left with");
                return None;
            }
        };

        let container = match held {
            Adopted::Running(container) => {
                info!(app = %id, container = %container.id, "the suspended app's container never stopped");
                container
            }
            Adopted::Stopped(container) => match self.runtime.start(&container, manifest).await {
                Ok(container) => container,
                Err(error) => {
                    warn!(app = %id, container = %container, %error, "the container the suspended app kept would not start, starting a new one");
                    return None;
                }
            },
        };

        match self.route(id.clone(), manifest.clone(), container).await {
            Ok(app) => Some(app),
            // `route` has already taken it back down. Whatever is wrong with
            // it, a container started fresh from the same manifest is the best
            // answer spaceport has — the same call a restart makes.
            Err(error) => {
                warn!(app = %id, %error, "the container the suspended app kept is not serving, starting a new one");
                None
            }
        }
    }

    /// Start `manifest` as the app named `id` and route traffic to it,
    /// replacing whatever was running under that id.
    ///
    /// Not atomic, and cannot be: replacing an app means its old container is
    /// gone before the new one is up, so an apply that fails halfway leaves the
    /// app down. What it does guarantee is that it leaves nothing behind — a
    /// container that ends up unroutable is removed rather than left running.
    /// Applying a suspended app records it and claims its hosts without ever
    /// starting it. So does applying to an app that is *already* suspended,
    /// whatever `suspend` says: an apply changes what an app would run, not
    /// whether it is being run. Only [`Applier::resume`] does that, and it is
    /// the deliberate step that makes staging a new manifest and cutting over
    /// to it two decisions rather than one.
    pub async fn apply(
        &self,
        id: AppId,
        manifest: AppManifest,
        suspend: bool,
    ) -> Result<Applied, ApplyError> {
        self.deploy(id, manifest, None, suspend).await
    }

    /// Apply `manifest` as the app named `id`, running the image spaceport
    /// built from `revision`.
    ///
    /// A verb of its own rather than a longer `apply`, because the two are
    /// asked by different people. An operator applies a document they wrote and
    /// have in front of them; a deploy replays a document that came out of a
    /// commit, and the commit is the other half of what it is asking for.
    /// Keeping them apart leaves the operator's verb reading exactly as it did,
    /// and makes the revision impossible to forget where one is meant.
    ///
    /// The revision is resolved to an image here and now, before anything is
    /// started and for the suspended path as much as the running one, so that a
    /// manifest which reaches the runtime is always one the runtime can run.
    /// What is *recorded* is the revision, never the image it resolved to — see
    /// [`AppManifest::built_as`].
    pub async fn deploy(
        &self,
        id: AppId,
        manifest: AppManifest,
        revision: Option<&str>,
        suspend: bool,
    ) -> Result<Applied, ApplyError> {
        let _working = self.working(&id).await;

        // Everything below is read after the wait, and none of it is a
        // formality: the build this revision resolves to, the secrets the
        // manifest needs and whether the app is suspended are all things the
        // verb ahead of this one in the queue may have changed — a `set` of the
        // last missing secret, or a `suspend` of the app this is about to start.
        //
        // The document, taken before anything is resolved: what is recorded is
        // what the operator or the repository wrote, and resolving a build
        // deliberately leaves that text alone.
        let recorded = manifest.source_text().to_owned();
        let manifest = self.resolved(&id, manifest, revision).await?;
        let (manifest, missing) = self.with_secrets(&id, manifest).await?;

        let held = self.store.suspended(&id);
        // A secret nothing has set is the third way to be suspended, alongside
        // being asked for it and already being it. Suspended and not failed,
        // because everything a suspend is for applies: the hosts are this app's
        // and stay claimed and certified, the manifest is what a resume will
        // run, and the one thing missing is a value somebody can go and set.
        // Starting it instead would put `{{DB_PASSWORD}}` in a connection
        // string, and the app would report that as a database problem.
        let suspend = suspend || held.is_some() || !missing.is_empty();

        let applied = if suspend {
            self.stage(id, manifest, held).await?
        } else {
            Applied::Running(self.start(id, manifest).await?)
        };

        // Recorded last, and only on success: a manifest that never ran is not
        // something to bring back at the next start. The cost is a window —
        // from here to the commit — in which a successful apply can be lost to
        // a crash, and the answer to that is to apply it again.
        //
        // A staged app whose secrets are missing counts as a success for this
        // purpose, and is recorded suspended: it is in the store, it is holding
        // its hosts, and a restart that brought it back running would start the
        // container this refused to start.
        if let Err(error) = self
            .repository
            .record_applied(applied.id(), &recorded, revision, suspend)
            .await
        {
            warn!(app = %applied.id(), %error, "the app was not recorded, so it will not survive a restart");
        }

        // Everything is in place and the answer is still no. The operator asked
        // for a running app and has a suspended one, and nothing else in this
        // function is in a position to say which secrets it is waiting for.
        if !missing.is_empty() {
            return Err(ApplyError::MissingSecrets(missing));
        }

        Ok(applied)
    }

    /// Claim an app's hosts for a manifest without starting it.
    ///
    /// Whatever container the app had goes, because it was built from the
    /// manifest this one replaces. Keeping it would mean a resume that quietly
    /// brought back the old image, which is the one thing an operator staging a
    /// new manifest is entitled to assume cannot happen.
    async fn stage(
        &self,
        id: AppId,
        manifest: AppManifest,
        held: Option<Suspended>,
    ) -> Result<Applied, ApplyError> {
        self.free_of_conflict(&id, &manifest)?;

        // Either the container of the app it is replacing while it runs, or the
        // one a previous suspended manifest was left holding.
        let previous = held
            .and_then(|app| app.container)
            .map(|container| container.id().clone())
            .or_else(|| self.store.get(&id).map(|app| app.container.clone()));

        let suspended = Suspended {
            id: id.clone(),
            manifest,
            container: None,
        };
        self.store
            .insert_suspended(suspended.clone())
            .map_err(ApplyError::Conflict)?;

        if let Some(container) = previous {
            // Worth saying, not worth failing for: the app is staged either
            // way, and a container nothing routes to is the next sweep's.
            if let Err(error) = self.runtime.remove(&container).await {
                warn!(app = %id, container = %container, %error, "could not remove the container of the manifest this one replaces");
            }
        }

        Ok(Applied::Suspended(Box::new(suspended)))
    }

    /// Bring back an app that is *already* recorded, without recording it again.
    ///
    /// This is what a restart runs. It leaves `applied_at` saying when the
    /// operator applied the app, not when spaceport last rebooted.
    ///
    /// The container from before is taken over where the engine still has one,
    /// so an app that never stopped running is not stopped now: what spaceport
    /// is restarting is spaceport, and an app whose container survived it only
    /// has to be found, checked and routed to. Everything that is not that —
    /// no container, the wrong container, or one that has stopped answering —
    /// is a relaunch, which is what a restart used to cost every app.
    ///
    /// `revision` is the one the record carries, and it is resolved again here
    /// rather than being taken as an image from anywhere. That is the whole
    /// point of recording a commit instead of a tag: a spaceport that restarts
    /// a week later runs the revision somebody deployed, not whatever has been
    /// built for the app since.
    pub async fn restore(
        &self,
        id: AppId,
        manifest: AppManifest,
        revision: Option<&str>,
        suspended: bool,
    ) -> Result<Restored, ApplyError> {
        // The revision is resolved and the hosts are checked after the wait, for
        // the reason `deploy` does the same: a restore that queued behind an
        // apply must not claim hosts against the routing table as it was before
        // that apply, nor start a container from a build record it read while
        // the app was somebody else's.
        let _working = self.working(&id).await;
        let manifest = self.resolved(&id, manifest, revision).await?;
        let (manifest, missing) = self.with_secrets(&id, manifest).await?;
        self.free_of_conflict(&id, &manifest)?;

        // Before the missing ones are refused, and deliberately: an app that
        // was suspended because a secret was never set is recorded suspended,
        // and a restart has to put it back the way it was left rather than
        // refuse to bring it back at all. Nothing is started here, so nothing
        // can be started with a placeholder in it.
        if suspended {
            return self.restore_suspended(id, manifest).await;
        }

        // A running app whose secret has been deleted since. It stays down,
        // claiming its hosts and saying what it is waiting for, which is what
        // the reconciler does with every other app it cannot start.
        if !missing.is_empty() {
            return Err(ApplyError::MissingSecrets(missing));
        }

        match self.runtime.adopt(&id, &manifest).await {
            Ok(Some(Adopted::Running(container))) => {
                info!(app = %id, container = %container.id, upstream = %container.upstream, "the container from before is still running");

                match self.route(id.clone(), manifest.clone(), container).await {
                    Ok(app) => return Ok(Restored::Adopted(app)),
                    // It is running but it is not serving, and `route` has
                    // already taken it down. Whatever is wrong with it, a
                    // container started fresh from the same manifest is the
                    // best answer spaceport has.
                    Err(error) => {
                        warn!(app = %id, %error, "the container from before is not serving, starting a new one");
                    }
                }
            }
            // A container that exited while spaceport was down has nothing
            // behind it. Starting it again is what `launch` is for, and it is
            // the same work as starting a new one.
            Ok(Some(Adopted::Stopped(container))) => {
                debug!(app = %id, container = %container, "the container from before is not running");
            }
            Ok(None) => {}
            // Adoption is an optimisation, and a failed one costs a relaunch
            // rather than an app.
            Err(error) => {
                warn!(app = %id, %error, "could not tell what the previous spaceport left running");
            }
        }

        self.start(id, manifest).await.map(Restored::Relaunched)
    }

    /// Put a suspended app back the way it was left: claiming its hosts, still
    /// holding whatever container it had, and not served.
    ///
    /// Nothing is started and nothing is stopped. A container left running by a
    /// suspend without `--stop-container` is still running after a restart of
    /// spaceport, which is the same promise adoption makes to every other app.
    async fn restore_suspended(
        &self,
        id: AppId,
        manifest: AppManifest,
    ) -> Result<Restored, ApplyError> {
        // Only a container this manifest would have produced: `adopt` checks
        // spaceport's label and the image, so a suspended app does not come
        // back holding on to somebody else's container.
        let container = match self.runtime.adopt(&id, &manifest).await {
            Ok(container) => container,
            Err(error) => {
                warn!(app = %id, %error, "could not tell what container the suspended app was left with");
                None
            }
        };

        if let Some(container) = &container {
            debug!(app = %id, container = %container.id(), "the suspended app is still holding its container");
        }

        self.store
            .insert_suspended(Suspended {
                id: id.clone(),
                manifest,
                container,
            })
            .map_err(ApplyError::Conflict)?;

        Ok(Restored::Suspended(id))
    }

    /// The manifest as this spaceport can run it, at the revision it was
    /// deployed from.
    ///
    /// A manifest that names its image is already runnable and is handed back
    /// untouched, without the build store being asked anything: an app pulled
    /// from a registry has no commit behind it, and looking one up would invent
    /// a relationship it does not have.
    ///
    /// A manifest that is built is not runnable as written — `type: build`
    /// describes a Dockerfile in somebody's repository, and what a container
    /// runs is an image — so the successful build of that revision is what
    /// stands in for it. Both ways of having no image are refusals rather than
    /// substitutions: an app that cannot be run at the revision it was deployed
    /// at stays down, saying which revision, which is the one answer that lets
    /// an operator go and look. Running the newest image lying about instead
    /// would deploy a commit nobody asked for, silently.
    ///
    /// Done here, in memory, on the way in to every verb that starts an app,
    /// which is why the runtime's own refusal of `Source::Build` is now
    /// unreachable — where a last line of defence belongs.
    async fn resolved(
        &self,
        id: &AppId,
        manifest: AppManifest,
        revision: Option<&str>,
    ) -> Result<AppManifest, ApplyError> {
        if !matches!(manifest.source, Source::Build { .. }) {
            return Ok(manifest);
        }

        let Some(revision) = revision else {
            return Err(ApplyError::Failed(anyhow!(
                "app `{id}` is built from its repository, and spaceport has not built it yet"
            )));
        };

        let build = self
            .builds
            .built(id, revision)
            .await
            .map_err(ApplyError::Failed)?
            .ok_or_else(|| {
                ApplyError::Failed(anyhow!(
                    "app `{id}` cannot run revision `{revision}`, because spaceport has no finished build of it"
                ))
            })?;

        let image = build.image_tag.ok_or_else(|| {
            ApplyError::Failed(anyhow!(
                "the build of revision `{revision}` of app `{id}` recorded no image to run"
            ))
        })?;

        manifest.built_as(&image).map_err(ApplyError::Failed)
    }

    /// The manifest with the app's stored secrets to hand, and the names of the
    /// ones it declares that nothing has set.
    ///
    /// Every verb that can reach the runtime goes through here, because every
    /// one of them renders a container spec: `launch` builds the environment
    /// from it, and `adopt` and `start` fingerprint it — a manifest that
    /// arrived without its secrets would not match the container it belongs to,
    /// and the app would be given a new one for no reason.
    ///
    /// Missing secrets are reported rather than refused, because the two
    /// callers want different things: an apply stages the app suspended and
    /// says so, and everything that starts one refuses. Both need the names.
    ///
    /// Every stored secret is attached and not only the declared ones — that is
    /// what [`AppManifest::with_secrets`] takes — and what the manifest does not
    /// declare is said out loud once here. A stored value nothing reads is a
    /// typo or the leftovers of an env line somebody deleted, and neither is
    /// worth failing an apply for.
    async fn with_secrets(
        &self,
        id: &AppId,
        manifest: AppManifest,
    ) -> Result<(AppManifest, Vec<VarName>), ApplyError> {
        let stored = self.secrets.resolve(id).await.map_err(|error| {
            ApplyError::Failed(error.context(format!("resolving the secrets of app `{id}`")))
        })?;
        let manifest = manifest.with_secrets(stored);

        let unused = manifest.container.unused_secrets();
        if !unused.is_empty() {
            warn!(
                app = %id,
                secrets = %named(unused),
                "these secrets are set for this app and its manifest declares none of them, so nothing will read them",
            );
        }

        let missing = manifest
            .container
            .missing_secrets()
            .into_iter()
            .cloned()
            .collect();

        Ok((manifest, missing))
    }

    /// The same, for the verbs that are about to start something: a manifest
    /// that can actually be run, or the names of the secrets stopping it.
    async fn runnable(&self, id: &AppId, manifest: AppManifest) -> Result<AppManifest, ApplyError> {
        let (manifest, missing) = self.with_secrets(id, manifest).await?;
        if !missing.is_empty() {
            return Err(ApplyError::MissingSecrets(missing));
        }

        Ok(manifest)
    }

    /// Everything an apply does except remember it.
    ///
    /// The manifest must already carry its secrets — every caller has been
    /// through [`Applier::with_secrets`] — and the check below is the last line
    /// of defence for a path that forgets, in the shape of the runtime's own
    /// refusal of `Source::Build`: it costs one comparison and it is the
    /// difference between an app that will not start and an app that starts
    /// with `{{DB_PASSWORD}}` in its environment.
    async fn start(&self, id: AppId, manifest: AppManifest) -> Result<Arc<App>, ApplyError> {
        let missing = manifest.container.missing_secrets();
        if !missing.is_empty() {
            return Err(ApplyError::MissingSecrets(
                missing.into_iter().cloned().collect(),
            ));
        }

        self.free_of_conflict(&id, &manifest)?;

        let container = self
            .runtime
            .launch(&id, &manifest)
            .await
            .map_err(ApplyError::Failed)?;

        self.route(id, manifest, container).await
    }

    /// Refuse early what the store would refuse later anyway, so that no
    /// container is started for an app that was never going to be reachable.
    fn free_of_conflict(&self, id: &AppId, manifest: &AppManifest) -> Result<(), ApplyError> {
        match self.store.conflict(id, &manifest.routing.hosts) {
            Some((host, owner)) => Err(ApplyError::Conflict(anyhow!(
                "host `{host}` is already claimed by {owner}"
            ))),
            None => Ok(()),
        }
    }

    /// Wait for a container to answer, then send the app's traffic to it.
    ///
    /// Takes the container back down if it never does: whether it was just
    /// started or adopted from the spaceport before, a container nothing will
    /// ever route to is not one to leave running.
    async fn route(
        &self,
        id: AppId,
        manifest: AppManifest,
        container: Container,
    ) -> Result<Arc<App>, ApplyError> {
        // The routes go in only once the app answers. A container's port is
        // published the moment it starts, well before whatever is inside has
        // finished booting, so routing on `launch` alone means the first
        // requests after every apply hit an app that is not there yet.
        let readiness = &manifest.container.health.readiness;
        let host = manifest.routing.hosts[0].as_str();
        info!(app = %id, upstream = %container.upstream, within = ?readiness.budget(), "waiting for the app to become ready");

        let waited = Instant::now();
        if let Err(error) = health::wait_until_ready(container.upstream, host, readiness).await {
            // Nothing is watching an app that never became ready, so leaving
            // it running would leave a container nothing points at and nothing
            // will ever route to.
            let _ = self.runtime.remove(&container.id).await;

            return Err(ApplyError::Failed(
                error.context(format!("app `{id}` never became ready")),
            ));
        }
        info!(app = %id, after = ?waited.elapsed(), "app is ready");

        let app = App {
            id,
            manifest,
            container: container.id.clone(),
            upstream: container.upstream,
        };

        match self.store.insert(app) {
            Ok(app) => Ok(app),
            // Only reachable if another apply claimed one of these hosts while
            // this container was starting. The container is running and
            // unreachable, so it goes back down.
            Err(error) => {
                let _ = self.runtime.remove(&container.id).await;
                Err(ApplyError::Conflict(error))
            }
        }
    }
}

/// The right to work on one app, for as long as it is held.
///
/// Held by value and never inspected: it exists for its `Drop`, and the one
/// thing a caller must do with it is keep it alive until the work is finished.
/// Dropping it hands the app to whoever is waiting and, if nobody is, forgets
/// it — which is what makes [`Applier::is_settling`] answer no again.
pub struct Working<'a> {
    applier: &'a Applier,
    id: AppId,
    /// An `Option` only so that `Drop` can release the app before it stops
    /// counting itself among its holders. See the comment there: the order is
    /// the whole correctness argument.
    held: Option<OwnedMutexGuard<()>>,
}

impl Drop for Working<'_> {
    fn drop(&mut self) {
        // The lock goes first and the count second, and never the other way
        // round. Decrementing first can take the count to zero and drop the map
        // entry while this guard still holds the lock — and a newcomer arriving
        // in that window would find no entry, make a *second* lock for the same
        // app, and take it. Two locks for one app is two verbs on one app.
        //
        // This way the worst case is a count that is one too high for the length
        // of a `HashMap` lookup: whoever arrives in the window finds the entry,
        // takes the lock this has just released, and is correctly serialised
        // behind it.
        drop(self.held.take());
        self.applier.leave(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::store::Downed;
    use crate::build::repository::{Build, BuildState};
    use crate::runtime::{Container, ContainerId, Managed};
    use crate::secret::Secret;
    use crate::state::Db;
    use anyhow::{Result, bail};
    use async_trait::async_trait;
    use std::collections::{BTreeMap, HashMap};
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    /// A runtime that starts nothing, so the apply logic can be tested without
    /// a container engine anywhere near it.
    #[derive(Default)]
    struct FakeRuntime {
        launched: Mutex<Vec<AppId>>,
        /// What each launch was asked to run, so a test can tell which image a
        /// manifest resolved to — and, for a manifest that builds, that it was
        /// resolved at all before it got this far.
        images: Mutex<Vec<String>>,
        /// The environment each launch was asked to run with, rendered as the
        /// engine would see it — which is the one place a secret's value is
        /// supposed to appear at all.
        environments: Mutex<Vec<BTreeMap<VarName, String>>>,
        removed: Mutex<Vec<ContainerId>>,
        /// Containers this runtime has been asked to stop and keep, and the
        /// ones it has been asked to start again.
        stopped: Mutex<Vec<ContainerId>>,
        started: Mutex<Vec<ContainerId>>,
        /// The container it is running for each app, so that a resume has
        /// something to find its way back to.
        running: Mutex<HashMap<AppId, Container>>,
        refuse: bool,
        refuse_removal: bool,
        refuse_stop: bool,
        /// What the spaceport before this one is pretending to have left
        /// running, for every app. Overrides `running` where it is set.
        survivor: Option<Container>,
        /// How long a launch takes. A real one takes long enough for a second
        /// verb to arrive during it, and a fake one that returns immediately
        /// would let two verbs on the same app pass each other without ever
        /// being in flight at the same instant — so a test about exclusion
        /// would pass whether or not anything excluded anything.
        launch_takes: Option<Duration>,
        /// How many launches this runtime has had in flight at once.
        concurrency: Mutex<Concurrency>,
    }

    /// Launches in flight, and the most there have ever been at one time.
    ///
    /// The peak is the whole point: it is the one number that says whether two
    /// verbs overlapped, and unlike an ordering of events it cannot be satisfied
    /// by a scheduler that happened to run them in the right order anyway.
    #[derive(Default)]
    struct Concurrency {
        active: usize,
        peak: usize,
    }

    impl FakeRuntime {
        /// A launch slow enough that anything else working on the same app
        /// would be caught in flight beside it.
        fn slow_to_launch() -> Self {
            Self {
                launch_takes: Some(Duration::from_millis(50)),
                ..Self::default()
            }
        }

        /// The most launches this runtime has ever had in flight at once.
        fn overlap(&self) -> usize {
            self.concurrency.lock().unwrap().peak
        }
    }

    impl FakeRuntime {
        /// Where a container it started again is published. Deliberately not
        /// the port it had, so that a resume which trusted the old address
        /// rather than asking the engine would be caught.
        const RESTARTED_PORT: u16 = 7777;
    }

    #[async_trait]
    impl ContainerRuntime for FakeRuntime {
        async fn adopt(&self, app: &AppId, _manifest: &AppManifest) -> Result<Option<Adopted>> {
            let found = match self.survivor.clone() {
                Some(survivor) => survivor,
                None => match self.running.lock().unwrap().get(app).cloned() {
                    Some(container) => container,
                    None => return Ok(None),
                },
            };
            if self.removed.lock().unwrap().contains(&found.id) {
                return Ok(None);
            }

            Ok(Some(
                match self.stopped.lock().unwrap().contains(&found.id) {
                    true => Adopted::Stopped(found.id),
                    false => Adopted::Running(found),
                },
            ))
        }

        async fn stop(&self, id: &ContainerId) -> Result<()> {
            if self.refuse_stop {
                bail!("that container is staying up");
            }
            self.stopped.lock().unwrap().push(id.clone());

            Ok(())
        }

        async fn start(&self, id: &ContainerId, _manifest: &AppManifest) -> Result<Container> {
            self.stopped.lock().unwrap().retain(|stopped| stopped != id);
            self.started.lock().unwrap().push(id.clone());

            Ok(Container {
                id: id.clone(),
                upstream: SocketAddr::from(([127, 0, 0, 1], Self::RESTARTED_PORT)),
            })
        }

        async fn launch(&self, app: &AppId, manifest: &AppManifest) -> Result<Container> {
            if self.refuse {
                bail!("no image for you");
            }
            // What the real runtime does with a manifest that still says
            // `build`, and the reason nothing may reach it saying so.
            let Source::Image { image } = &manifest.source else {
                bail!("app `{app}` builds its own image, which spaceport cannot do yet");
            };
            self.images.lock().unwrap().push(image.clone());
            // Refused exactly where the real runtime refuses it: a manifest
            // whose placeholders nothing has filled in cannot be rendered into
            // an environment, and a fake that shrugged at one would be a fake
            // accepting what production cannot.
            self.environments
                .lock()
                .unwrap()
                .push(manifest.container.environment()?);

            let port = {
                let mut launched = self.launched.lock().unwrap();
                launched.push(app.clone());

                // A different port per launch, so a replacement is visible.
                9000 + u16::try_from(launched.len()).unwrap()
            };

            {
                let mut concurrency = self.concurrency.lock().unwrap();
                concurrency.active += 1;
                concurrency.peak = concurrency.peak.max(concurrency.active);
            }
            if let Some(takes) = self.launch_takes {
                tokio::time::sleep(takes).await;
            }
            self.concurrency.lock().unwrap().active -= 1;

            let container = Container {
                id: ContainerId::new(format!("{app}-{port}")),
                upstream: SocketAddr::from(([127, 0, 0, 1], port)),
            };
            self.running
                .lock()
                .unwrap()
                .insert(app.clone(), container.clone());

            Ok(container)
        }

        async fn remove(&self, id: &ContainerId) -> Result<()> {
            if self.refuse_removal {
                bail!("that container is staying right where it is");
            }
            self.removed.lock().unwrap().push(id.clone());
            Ok(())
        }

        async fn managed(&self) -> Result<Vec<Managed>> {
            let removed = self.removed.lock().unwrap();

            Ok(self
                .launched
                .lock()
                .unwrap()
                .iter()
                .enumerate()
                .map(|(index, app)| Managed {
                    id: ContainerId::new(format!("{app}-{}", 9001 + index)),
                    app: Some(app.clone()),
                    running: true,
                })
                .filter(|container| !removed.contains(&container.id))
                .collect())
        }
    }

    /// A manifest whose app is routed the moment it starts: these tests are
    /// about the apply logic, and a fake runtime has nothing to connect to.
    fn manifest(hosts: &str) -> AppManifest {
        AppManifest::parse(&format!(
            "schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [{hosts}]
container:
  health:
    readiness:
      type: none
"
        ))
        .unwrap()
    }

    /// The app an apply started, for the tests that are not about suspension.
    fn started(applied: Applied) -> Arc<App> {
        match applied {
            Applied::Running(app) => app,
            Applied::Suspended(app) => panic!("app `{}` was suspended, not started", app.id),
        }
    }

    fn applier(runtime: Arc<FakeRuntime>) -> (Applier, Arc<AppStore>) {
        let (applier, store, _) = applier_over(runtime, Db::in_memory().unwrap());

        (applier, store)
    }

    /// The same, over a database the test keeps hold of: for the tests that
    /// record a build first, or that restart a spaceport over what the last one
    /// wrote down.
    fn applier_over(
        runtime: Arc<FakeRuntime>,
        db: Db,
    ) -> (Applier, Arc<AppStore>, BuildRepository) {
        let store = Arc::new(AppStore::new());
        let repository = AppRepository::new(db.clone());
        let builds = BuildRepository::new(db.clone());

        (
            Applier::new(
                store.clone(),
                runtime,
                repository,
                builds.clone(),
                SecretRepository::new(db),
            ),
            store,
            builds,
        )
    }

    #[tokio::test]
    async fn starts_an_app_and_routes_it() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());

        let app = started(
            applier
                .apply(
                    "hello".parse().unwrap(),
                    manifest("alpha.test, beta.test"),
                    false,
                )
                .await
                .unwrap(),
        );

        assert_eq!(app.upstream.port(), 9001);
        assert_eq!(store.routes().serving("alpha.test").unwrap().id, app.id);
        assert_eq!(store.routes().serving("beta.test").unwrap().id, app.id);
        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn re_applying_repoints_the_routes() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());

        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap();
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap();

        assert_eq!(store.apps().len(), 1);
        assert_eq!(
            store
                .routes()
                .serving("alpha.test")
                .unwrap()
                .upstream
                .port(),
            9002
        );
    }

    #[tokio::test]
    async fn refuses_a_conflict_before_starting_anything() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap();

        let error = applier
            .apply("other".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap_err();

        assert!(matches!(error, ApplyError::Conflict(_)));
        assert!(error.to_string().contains("already claimed by app `hello`"));
        // The point of checking first: no container was started for it.
        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
        assert_eq!(store.apps().len(), 1);
    }

    /// The same manifest, but waiting on an app that has to answer — and the
    /// fake runtime's ports have nothing behind them, so it never will.
    fn manifest_awaiting_readiness(hosts: &str) -> AppManifest {
        AppManifest::parse(&format!(
            "schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [{hosts}]
container:
  health:
    readiness:
      interval: 10ms
      timeout: 50ms
      failure_threshold: 2
"
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn does_not_route_an_app_that_never_becomes_ready() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());

        let error = applier
            .apply(
                "hello".parse().unwrap(),
                manifest_awaiting_readiness("alpha.test"),
                false,
            )
            .await
            .unwrap_err();

        assert!(matches!(error, ApplyError::Failed(_)));
        assert!(error.to_string().contains("never became ready"), "{error}");
        assert!(store.routes().serving("alpha.test").is_none());
        assert!(store.apps().is_empty());
        // And the container it started is not left behind.
        assert_eq!(runtime.removed.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_failed_apply_leaves_the_previous_app_serving() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap();

        applier
            .apply(
                "hello".parse().unwrap(),
                manifest_awaiting_readiness("alpha.test"),
                false,
            )
            .await
            .unwrap_err();

        // The route still points at the old container, which the runtime has
        // in fact already replaced — see the note on `apply`.
        assert_eq!(
            store
                .routes()
                .serving("alpha.test")
                .unwrap()
                .upstream
                .port(),
            9001
        );
    }

    #[tokio::test]
    async fn destroying_an_app_stops_it_and_drops_its_routes() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        let app = started(
            applier
                .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
                .await
                .unwrap(),
        );

        let destroyed = applier.destroy(&"hello".parse().unwrap()).await.unwrap();

        assert_eq!(*destroyed.id(), app.id);
        assert!(store.apps().is_empty());
        assert!(store.routes().serving("alpha.test").is_none());
        assert_eq!(
            *runtime.removed.lock().unwrap(),
            std::slice::from_ref(&app.container)
        );
    }

    #[tokio::test]
    async fn destroying_an_unknown_app_says_so() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime.clone());

        let error = applier
            .destroy(&"ghost".parse().unwrap())
            .await
            .unwrap_err();

        assert!(matches!(error, DestroyError::Unknown(_)));
        assert!(error.to_string().contains("no app named `ghost`"));
        assert!(runtime.removed.lock().unwrap().is_empty());
    }

    /// A container that will not go away is still worth unrouting — but the
    /// operator has to hear that it is still running.
    #[tokio::test]
    async fn reports_a_container_that_would_not_go_away() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap();
        let runtime = Arc::new(FakeRuntime {
            refuse_removal: true,
            ..Default::default()
        });
        let db = Db::in_memory().unwrap();
        let applier = Applier::new(
            store.clone(),
            runtime,
            AppRepository::new(db.clone()),
            BuildRepository::new(db.clone()),
            SecretRepository::new(db),
        );

        let error = applier
            .destroy(&"hello".parse().unwrap())
            .await
            .unwrap_err();

        assert!(matches!(error, DestroyError::Failed(_)));
        assert!(error.to_string().contains("is still there"), "{error}");
        assert!(store.apps().is_empty());
        assert!(store.routes().serving("alpha.test").is_none());
    }

    #[tokio::test]
    async fn records_an_applied_app_verbatim() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime);
        let manifest = manifest("alpha.test");

        applier
            .apply("hello".parse().unwrap(), manifest.clone(), false)
            .await
            .unwrap();

        let desired = applier.repository().desired().await.unwrap();
        assert_eq!(desired.len(), 1);
        assert_eq!(desired[0].id.as_str(), "hello");
        assert_eq!(desired[0].manifest, manifest.source_text());
    }

    /// An app that never came up is not something to bring back at the next
    /// start, so nothing about it is written down.
    #[tokio::test]
    async fn records_nothing_for_an_app_that_never_started() {
        let runtime = Arc::new(FakeRuntime {
            refuse: true,
            ..Default::default()
        });
        let (applier, _) = applier(runtime);

        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap_err();

        assert!(applier.repository().desired().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn destroying_an_app_forgets_it() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime);
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap();

        applier.destroy(&"hello".parse().unwrap()).await.unwrap();

        assert!(applier.repository().desired().await.unwrap().is_empty());
    }

    /// A restart re-runs what was recorded; it did not learn anything new, so
    /// it must not restate when the operator applied it.
    #[tokio::test]
    async fn restoring_an_app_does_not_re_record_it() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime);
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap();
        let applied_at = applier.repository().desired().await.unwrap()[0]
            .applied_at
            .clone();

        applier
            .restore(
                "hello".parse().unwrap(),
                manifest("alpha.test"),
                None,
                false,
            )
            .await
            .unwrap();

        let desired = applier.repository().desired().await.unwrap();
        assert_eq!(desired.len(), 1);
        assert_eq!(desired[0].applied_at, applied_at);
        // It is running all the same.
        assert!(store.routes().serving("alpha.test").is_some());
    }

    /// The point of adoption: the app that was running before the restart is
    /// the app that is running after it, in the same container.
    #[tokio::test]
    async fn restoring_takes_over_the_container_that_survived() {
        let survivor = Container {
            id: ContainerId::new("survivor"),
            upstream: SocketAddr::from(([127, 0, 0, 1], 7000)),
        };
        let runtime = Arc::new(FakeRuntime {
            survivor: Some(survivor.clone()),
            ..Default::default()
        });
        let (applier, store) = applier(runtime.clone());

        let restored = applier
            .restore(
                "hello".parse().unwrap(),
                manifest("alpha.test"),
                None,
                false,
            )
            .await
            .unwrap();

        assert!(restored.was_adopted(), "{restored:?}");
        assert_eq!(restored.app().unwrap().container, survivor.id);
        assert_eq!(
            store.routes().serving("alpha.test").unwrap().upstream,
            survivor.upstream
        );
        // Nothing was started, and nothing was taken down, to get there.
        assert!(runtime.launched.lock().unwrap().is_empty());
        assert!(runtime.removed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn restoring_starts_an_app_whose_container_is_gone() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());

        let restored = applier
            .restore(
                "hello".parse().unwrap(),
                manifest("alpha.test"),
                None,
                false,
            )
            .await
            .unwrap();

        assert!(!restored.was_adopted(), "{restored:?}");
        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
        assert!(store.routes().serving("alpha.test").is_some());
    }

    /// A container that is up but no longer answering is not something to route
    /// traffic to just because it survived.
    #[tokio::test]
    async fn restoring_starts_again_when_the_survivor_does_not_answer() {
        let runtime = Arc::new(FakeRuntime {
            survivor: Some(Container {
                id: ContainerId::new("survivor"),
                upstream: SocketAddr::from(([127, 0, 0, 1], 7000)),
            }),
            ..Default::default()
        });
        let (applier, store) = applier(runtime.clone());

        // Nothing is listening on either port, so the relaunched container
        // fails its readiness check too — what this asserts is that spaceport
        // stopped trusting the survivor and went and started one.
        applier
            .restore(
                "hello".parse().unwrap(),
                manifest_awaiting_readiness("alpha.test"),
                None,
                false,
            )
            .await
            .unwrap_err();

        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
        // And the survivor it gave up on was not left running.
        assert!(
            runtime
                .removed
                .lock()
                .unwrap()
                .contains(&ContainerId::new("survivor"))
        );
        assert!(store.apps().is_empty());
    }

    #[tokio::test]
    async fn reports_a_runtime_failure_and_stores_nothing() {
        let runtime = Arc::new(FakeRuntime {
            refuse: true,
            ..Default::default()
        });
        let (applier, store) = applier(runtime);

        let error = applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap_err();

        assert!(matches!(error, ApplyError::Failed(_)));
        assert!(error.to_string().contains("no image for you"));
        assert!(store.apps().is_empty());
    }

    // Suspending and resuming.

    /// Suspended by default is the cheap case: nothing is stopped, the app just
    /// stops receiving traffic.
    #[tokio::test]
    async fn suspending_stops_serving_and_leaves_the_container_running() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap();

        applier
            .suspend(&"hello".parse().unwrap(), false)
            .await
            .unwrap();

        assert!(store.routes().serving("alpha.test").is_none());
        assert!(store.routes().lookup("alpha.test").is_some());
        assert_eq!(store.suspended_apps().len(), 1);
        // Nothing was stopped and nothing was removed to get there.
        assert!(runtime.stopped.lock().unwrap().is_empty());
        assert!(runtime.removed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn suspending_with_stop_container_stops_it_and_keeps_it() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime.clone());
        let app = started(
            applier
                .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
                .await
                .unwrap(),
        );

        applier
            .suspend(&"hello".parse().unwrap(), true)
            .await
            .unwrap();

        assert_eq!(
            *runtime.stopped.lock().unwrap(),
            std::slice::from_ref(&app.container)
        );
        // Stopped, not deleted — that is the whole difference from a destroy.
        assert!(runtime.removed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn suspending_records_it_and_resuming_clears_it() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime);
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap();

        applier
            .suspend(&"hello".parse().unwrap(), false)
            .await
            .unwrap();
        assert!(applier.repository().desired().await.unwrap()[0].suspended);

        applier.resume(&"hello".parse().unwrap()).await.unwrap();
        assert!(!applier.repository().desired().await.unwrap()[0].suspended);
    }

    #[tokio::test]
    async fn suspending_an_unknown_app_says_so() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime);

        let error = applier
            .suspend(&"ghost".parse().unwrap(), false)
            .await
            .unwrap_err();

        assert!(matches!(error, SuspendError::Unknown(_)));
        assert!(
            error.to_string().contains("no app named `ghost`"),
            "{error}"
        );
    }

    /// A container that will not stop leaves the app suspended all the same —
    /// it is already unrouted — but the operator has to hear that it is still
    /// running.
    #[tokio::test]
    async fn reports_a_container_that_would_not_stop() {
        let runtime = Arc::new(FakeRuntime {
            refuse_stop: true,
            ..Default::default()
        });
        let (applier, store) = applier(runtime);
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap();

        let error = applier
            .suspend(&"hello".parse().unwrap(), true)
            .await
            .unwrap_err();

        assert!(matches!(error, SuspendError::Failed(_)));
        assert!(error.to_string().contains("would not stop"), "{error}");
        assert!(store.routes().serving("alpha.test").is_none());
    }

    /// The cheap round trip: nothing was stopped, so nothing has to be started.
    #[tokio::test]
    async fn resuming_routes_a_container_that_never_stopped() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        let before = started(
            applier
                .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
                .await
                .unwrap(),
        );
        applier
            .suspend(&"hello".parse().unwrap(), false)
            .await
            .unwrap();

        let after = applier.resume(&"hello".parse().unwrap()).await.unwrap();

        assert_eq!(after.container, before.container);
        assert_eq!(after.upstream, before.upstream);
        assert!(store.routes().serving("alpha.test").is_some());
        // One launch in total: the one the apply did.
        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
        assert!(runtime.started.lock().unwrap().is_empty());
    }

    /// The point of `--stop-container`: the container comes back, rather than
    /// a new one being built from the image again.
    #[tokio::test]
    async fn resuming_starts_the_container_it_stopped() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        let before = started(
            applier
                .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
                .await
                .unwrap(),
        );
        applier
            .suspend(&"hello".parse().unwrap(), true)
            .await
            .unwrap();

        let after = applier.resume(&"hello".parse().unwrap()).await.unwrap();

        assert_eq!(after.container, before.container);
        assert_eq!(
            *runtime.started.lock().unwrap(),
            std::slice::from_ref(&before.container)
        );
        // A port it did not have before: the old one belonged to the run, not
        // to the container.
        assert_eq!(after.upstream.port(), FakeRuntime::RESTARTED_PORT);
        assert_eq!(
            store.routes().serving("alpha.test").unwrap().upstream,
            after.upstream
        );
        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
    }

    /// A container removed by hand while the app was suspended costs a
    /// relaunch, not the app.
    #[tokio::test]
    async fn resuming_starts_a_fresh_container_when_the_kept_one_is_gone() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        let before = started(
            applier
                .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
                .await
                .unwrap(),
        );
        applier
            .suspend(&"hello".parse().unwrap(), true)
            .await
            .unwrap();
        runtime.remove(&before.container).await.unwrap();

        let after = applier.resume(&"hello".parse().unwrap()).await.unwrap();

        assert_ne!(after.container, before.container);
        assert_eq!(runtime.launched.lock().unwrap().len(), 2);
        assert!(store.routes().serving("alpha.test").is_some());
    }

    #[tokio::test]
    async fn resuming_an_app_that_is_running_is_a_no_op() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime.clone());
        let before = started(
            applier
                .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
                .await
                .unwrap(),
        );

        let after = applier.resume(&"hello".parse().unwrap()).await.unwrap();

        assert_eq!(after.container, before.container);
        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn resuming_an_unknown_app_says_so() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime);

        let error = applier.resume(&"ghost".parse().unwrap()).await.unwrap_err();

        assert!(matches!(error, ResumeError::Unknown(_)));
    }

    // Applying into suspension.

    #[tokio::test]
    async fn applying_suspended_claims_the_hosts_without_starting_anything() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());

        let applied = applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), true)
            .await
            .unwrap();

        assert!(matches!(applied, Applied::Suspended(_)));
        assert!(runtime.launched.lock().unwrap().is_empty());
        assert!(store.apps().is_empty());
        // The host is claimed all the same — that is what makes it possible to
        // certify it before the app ever runs.
        assert!(store.routes().lookup("alpha.test").is_some());
        assert!(store.routes().hosts().contains("alpha.test"));
        let desired = applier.repository().desired().await.unwrap();
        assert!(desired[0].suspended);
    }

    /// The whole point of applying suspended: the manifest is staged and the
    /// cutover is a second, deliberate command.
    #[tokio::test]
    async fn an_app_applied_suspended_starts_when_it_is_resumed() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), true)
            .await
            .unwrap();

        let app = applier.resume(&"hello".parse().unwrap()).await.unwrap();

        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
        assert_eq!(
            store.routes().serving("alpha.test").unwrap().upstream,
            app.upstream
        );
    }

    /// An apply says what an app would run, not whether it is being run.
    #[tokio::test]
    async fn applying_to_a_suspended_app_leaves_it_suspended() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), true)
            .await
            .unwrap();

        // No `--suspended` this time, and it still does not start.
        let applied = applier
            .apply("hello".parse().unwrap(), manifest("beta.test"), false)
            .await
            .unwrap();

        assert!(matches!(applied, Applied::Suspended(_)));
        assert!(runtime.launched.lock().unwrap().is_empty());
        assert!(applier.repository().desired().await.unwrap()[0].suspended);
        // The new manifest is what it claims, and the old host is given up.
        assert!(store.routes().lookup("beta.test").is_some());
        assert!(store.routes().lookup("alpha.test").is_none());
    }

    /// Staging a new manifest must not leave a resume able to bring back the
    /// image it replaced.
    #[tokio::test]
    async fn applying_to_a_suspended_app_removes_the_container_it_was_holding() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime.clone());
        let before = started(
            applier
                .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
                .await
                .unwrap(),
        );
        applier
            .suspend(&"hello".parse().unwrap(), true)
            .await
            .unwrap();

        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap();

        assert_eq!(
            *runtime.removed.lock().unwrap(),
            std::slice::from_ref(&before.container)
        );
        // And resuming now builds a new one rather than the one it was holding.
        let after = applier.resume(&"hello".parse().unwrap()).await.unwrap();
        assert_ne!(after.container, before.container);
    }

    /// Applying `--suspended` over a running app takes it out of service.
    #[tokio::test]
    async fn applying_suspended_over_a_running_app_suspends_it() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        let before = started(
            applier
                .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
                .await
                .unwrap(),
        );

        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), true)
            .await
            .unwrap();

        assert!(store.routes().serving("alpha.test").is_none());
        assert!(store.routes().lookup("alpha.test").is_some());
        assert_eq!(
            *runtime.removed.lock().unwrap(),
            std::slice::from_ref(&before.container)
        );
    }

    /// The reason hosts stay claimed, at the level that enforces it.
    #[tokio::test]
    async fn another_app_cannot_take_a_suspended_app_s_host() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime.clone());
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap();
        applier
            .suspend(&"hello".parse().unwrap(), false)
            .await
            .unwrap();

        let error = applier
            .apply("other".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap_err();

        assert!(matches!(error, ApplyError::Conflict(_)));
        assert!(error.to_string().contains("already claimed by app `hello`"));
        // No container was started for it, as for any other conflict.
        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn destroying_a_suspended_app_removes_its_container_too() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        let before = started(
            applier
                .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
                .await
                .unwrap(),
        );
        applier
            .suspend(&"hello".parse().unwrap(), true)
            .await
            .unwrap();

        applier.destroy(&"hello".parse().unwrap()).await.unwrap();

        assert!(store.routes().is_empty());
        assert!(store.suspended_apps().is_empty());
        assert!(applier.repository().desired().await.unwrap().is_empty());
        assert_eq!(
            *runtime.removed.lock().unwrap(),
            std::slice::from_ref(&before.container)
        );
    }

    /// An app that was applied suspended and never ran has nothing to remove,
    /// and destroying it must not fail looking for one.
    #[tokio::test]
    async fn destroying_an_app_that_never_ran_removes_nothing() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), true)
            .await
            .unwrap();

        let destroyed = applier.destroy(&"hello".parse().unwrap()).await.unwrap();

        assert!(destroyed.container().is_none());
        assert!(store.routes().is_empty());
        assert!(runtime.removed.lock().unwrap().is_empty());
    }

    // Restarting, and the mark that keeps the supervisor off an app spaceport
    // is already seeing to.

    #[tokio::test]
    async fn restarting_a_running_app_gives_it_a_new_container() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        let before = started(
            applier
                .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
                .await
                .unwrap(),
        );

        let after = applier
            .restart(&"hello".parse().unwrap(), "its container exited")
            .await
            .unwrap();

        assert_ne!(after.container, before.container);
        assert_eq!(runtime.launched.lock().unwrap().len(), 2);
        assert_eq!(
            store.routes().serving("alpha.test").unwrap().upstream,
            after.upstream
        );
        assert!(store.down_apps().is_empty());
    }

    /// A restart that fails leaves the app claiming its hosts and saying why,
    /// because that is what the supervisor tries again from and what a status
    /// report reads.
    #[tokio::test]
    async fn a_restart_that_fails_leaves_the_app_down_with_a_reason() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"), false)
            .await
            .unwrap();
        let runtime = Arc::new(FakeRuntime {
            refuse: true,
            ..Default::default()
        });
        let db = Db::in_memory().unwrap();
        let applier = Applier::new(
            store.clone(),
            runtime,
            AppRepository::new(db.clone()),
            BuildRepository::new(db.clone()),
            SecretRepository::new(db),
        );

        let error = applier
            .restart(&"hello".parse().unwrap(), "its container exited")
            .await
            .unwrap_err();

        assert!(matches!(error, ApplyError::Failed(_)));
        let reason = store
            .downed(&"hello".parse().unwrap())
            .expect("it should be down")
            .reason;
        assert!(reason.contains("no image for you"), "{reason}");
        // Not serving, and still spoken for.
        assert!(store.routes().serving("alpha.test").is_none());
        assert!(store.routes().lookup("alpha.test").is_some());
    }

    /// The supervisor's way back for an app that never started: it is in the
    /// store as down rather than as running, and a restart has to work from
    /// that as readily as from a container that has just died.
    #[tokio::test]
    async fn restarting_an_app_that_is_already_down_starts_it() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        store
            .insert_down(Downed {
                id: "hello".parse().unwrap(),
                manifest: manifest("alpha.test"),
                reason: "no image `x:1`".to_owned(),
            })
            .unwrap();

        let app = applier
            .restart(&"hello".parse().unwrap(), "trying again")
            .await
            .unwrap();

        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
        assert_eq!(
            store.routes().serving("alpha.test").unwrap().upstream,
            app.upstream
        );
        assert!(store.down_apps().is_empty());
    }

    #[tokio::test]
    async fn restarting_an_app_nobody_has_heard_of_says_so() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime);

        let error = applier
            .restart(&"ghost".parse().unwrap(), "its container exited")
            .await
            .unwrap_err();

        assert!(
            error.to_string().contains("no app named `ghost`"),
            "{error}"
        );
    }

    /// What keeps the supervisor off an app spaceport is already working on:
    /// every verb takes containers down and puts them up, and the engine
    /// reports all of it exactly as it reports a crash.
    #[tokio::test]
    async fn marks_an_app_while_it_is_being_worked_on() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime);
        let id: AppId = "hello".parse().unwrap();

        assert!(!applier.is_settling(&id));
        {
            let _held = applier.working(&id).await;
            assert!(applier.is_settling(&id));
        }
        assert!(!applier.is_settling(&id));
    }

    /// Two operators applying the same app at once must not have the first one
    /// to finish clear the mark for the second — the second is only about to
    /// start, and the container it is going to replace is not one that broke.
    #[tokio::test]
    async fn the_mark_outlasts_the_first_of_two_verbs_to_finish() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime);
        let id: AppId = "hello".parse().unwrap();

        let first = applier.working(&id).await;
        let queued = async {
            // Waiting counts: this is something that is going to work on the
            // app the instant it can.
            let second = applier.working(&id).await;
            assert!(applier.is_settling(&id), "the second holder is not marked");
            drop(second);
        };
        let finishing = async {
            assert!(applier.is_settling(&id));
            drop(first);
            // Long enough for the waiter to be woken and to take the app.
            tokio::task::yield_now().await;
        };

        tokio::join!(queued, finishing);

        assert!(!applier.is_settling(&id));
        assert_eq!(applier.tracked(), 0, "the app was left in the map");
    }

    /// The mark is one app's, not the applier's: an apply of one app must not
    /// stop the supervisor acting on another that died at the same moment.
    #[tokio::test]
    async fn the_mark_is_only_about_the_app_it_names() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime);

        let _held = applier.working(&"hello".parse().unwrap()).await;

        assert!(!applier.is_settling(&"other".parse().unwrap()));
    }

    /// The race the lock exists for. Two applies of one app both take its
    /// container down and put a new one up, and interleaved they leave a
    /// container running that nothing routes to — or route to one the other has
    /// already removed. Neither is a state either apply could produce alone,
    /// which is why nothing downstream can be written to cope with it.
    #[tokio::test]
    async fn two_deploys_of_one_app_do_not_overlap() {
        let runtime = Arc::new(FakeRuntime::slow_to_launch());
        let (applier, store) = applier(runtime.clone());
        let id: AppId = "hello".parse().unwrap();

        let (first, second) = tokio::join!(
            applier.apply(id.clone(), manifest("alpha.test"), false),
            applier.apply(id.clone(), manifest("alpha.test"), false),
        );

        first.unwrap();
        second.unwrap();
        // Both ran — one did not refuse or get skipped — and they ran one after
        // the other.
        assert_eq!(runtime.launched.lock().unwrap().len(), 2);
        assert_eq!(runtime.overlap(), 1, "two applies of one app overlapped");
        // And the app is on the second of them, not on whichever finished last.
        assert_eq!(store.routes().serving("alpha.test").unwrap().id, id);
        assert_eq!(applier.tracked(), 0);
    }

    /// And the lock is one app's. A per-applier lock would pass every test
    /// above and make one slow deploy hold up every other app on the host,
    /// which is the whole reason the map is keyed by id.
    #[tokio::test]
    async fn work_on_two_apps_happens_at_the_same_time() {
        let runtime = Arc::new(FakeRuntime::slow_to_launch());
        let (applier, _) = applier(runtime.clone());

        let (hello, other) = tokio::join!(
            applier.apply("hello".parse().unwrap(), manifest("alpha.test"), false),
            applier.apply("other".parse().unwrap(), manifest("beta.test"), false),
        );

        hello.unwrap();
        other.unwrap();
        assert_eq!(runtime.overlap(), 2, "one app's apply held up another's");
        assert_eq!(applier.tracked(), 0);
    }

    /// What the operator interface's `set` needs: an answer now. Somebody is
    /// holding a terminal, and a request that hangs for the length of a deploy
    /// is worse for them than being told to try again.
    #[tokio::test]
    async fn the_immediate_form_refuses_an_app_somebody_else_is_working_on() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime);
        let id: AppId = "hello".parse().unwrap();

        let held = applier.working(&id).await;
        assert!(applier.try_working(&id).is_none());

        drop(held);

        assert!(applier.try_working(&id).is_some());
        // A refusal that counted itself among the holders would leave the app
        // marked as being worked on by nobody, for good — and the supervisor
        // would never restart its container again.
        assert!(!applier.is_settling(&id));
        assert_eq!(applier.tracked(), 0);
    }

    /// An entry that outlives its last holder is a lock nothing will ever take
    /// again and an app the supervisor will never touch again. Checked after a
    /// contended pair rather than a lone holder, because contention is where a
    /// count can be got wrong.
    #[tokio::test]
    async fn nothing_is_left_behind_once_every_holder_and_waiter_is_done() {
        let runtime = Arc::new(FakeRuntime::slow_to_launch());
        let (applier, _) = applier(runtime);
        let id: AppId = "hello".parse().unwrap();

        let (first, second) = tokio::join!(
            applier.apply(id.clone(), manifest("alpha.test"), false),
            applier.destroy(&id),
        );

        first.unwrap();
        second.unwrap();
        assert!(!applier.is_settling(&id));
        assert_eq!(applier.tracked(), 0);
    }

    // Deploying an app spaceport builds itself.

    /// A manifest that is built rather than pulled, and so says nothing about
    /// what image to run.
    fn built_manifest(hosts: &str) -> AppManifest {
        AppManifest::parse(&format!(
            "schema_version: 1
source:
  type: build
  dockerfile: Dockerfile
  context: .
routing:
  hosts: [{hosts}]
container:
  health:
    readiness:
      type: none
"
        ))
        .unwrap()
    }

    /// A build of `revision` that produced `image`, exactly as the worker would
    /// have left it behind.
    async fn record_build(builds: &BuildRepository, app: &str, revision: &str, image: &str) {
        let id: AppId = app.parse().unwrap();
        builds
            .request(&Build {
                app: id.clone(),
                revision: revision.to_owned(),
                connection: "spaceport".to_owned(),
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
        // The document the commit carried, which is the one these tests deploy.
        let manifest = built_manifest("alpha.test");
        builds
            .succeeded(
                &id,
                revision,
                image,
                "sha256:0123",
                manifest.source_text(),
                "",
            )
            .await
            .unwrap();
    }

    /// The whole point: a manifest that describes a Dockerfile reaches the
    /// runtime describing an image, and it is the image that revision's build
    /// produced.
    #[tokio::test]
    async fn deploying_a_revision_runs_the_image_its_build_produced() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store, builds) = applier_over(runtime.clone(), Db::in_memory().unwrap());
        record_build(&builds, "hello", "abc1234", "spaceport/hello:abc1234").await;

        let app = started(
            applier
                .deploy(
                    "hello".parse().unwrap(),
                    built_manifest("alpha.test"),
                    Some("abc1234"),
                    false,
                )
                .await
                .unwrap(),
        );

        assert_eq!(
            *runtime.images.lock().unwrap(),
            ["spaceport/hello:abc1234".to_owned()]
        );
        assert_eq!(store.routes().serving("alpha.test").unwrap().id, app.id);
    }

    /// The resolved image is this spaceport's answer for today; the document is
    /// the repository's, and it is the document that is written down.
    #[tokio::test]
    async fn deploying_records_the_document_and_the_revision_it_came_from() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _, builds) = applier_over(runtime, Db::in_memory().unwrap());
        record_build(&builds, "hello", "abc1234", "spaceport/hello:abc1234").await;
        let manifest = built_manifest("alpha.test");

        applier
            .deploy(
                "hello".parse().unwrap(),
                manifest.clone(),
                Some("abc1234"),
                false,
            )
            .await
            .unwrap();

        let desired = applier.repository().desired().await.unwrap();
        assert_eq!(desired[0].manifest, manifest.source_text());
        assert!(desired[0].manifest.contains("type: build"));
        assert!(!desired[0].manifest.contains("spaceport/hello:abc1234"));
        // And the revision, which is what a restart resolves again.
        assert_eq!(desired[0].revision.as_deref(), Some("abc1234"));
    }

    /// Running something else would be running a commit nobody deployed, so the
    /// app stays down — saying which revision has no image, which is what sends
    /// an operator to the build that failed.
    #[tokio::test]
    async fn refuses_a_revision_that_was_never_built() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store, builds) = applier_over(runtime.clone(), Db::in_memory().unwrap());
        record_build(&builds, "hello", "abc1234", "spaceport/hello:abc1234").await;

        let error = applier
            .deploy(
                "hello".parse().unwrap(),
                built_manifest("alpha.test"),
                Some("def5678"),
                false,
            )
            .await
            .unwrap_err();

        assert!(matches!(error, ApplyError::Failed(_)));
        assert!(error.to_string().contains("def5678"), "{error}");
        assert!(error.to_string().contains("no finished build"), "{error}");
        // Nothing was started, and the older build was not run in its place.
        assert!(runtime.launched.lock().unwrap().is_empty());
        assert!(store.apps().is_empty());
        assert!(applier.repository().desired().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn refuses_a_built_manifest_that_names_no_revision() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime.clone());

        let error = applier
            .apply(
                "hello".parse().unwrap(),
                built_manifest("alpha.test"),
                false,
            )
            .await
            .unwrap_err();

        assert!(matches!(error, ApplyError::Failed(_)));
        assert!(
            error.to_string().contains("has not built it yet"),
            "{error}"
        );
        assert!(runtime.launched.lock().unwrap().is_empty());
    }

    /// A suspended deploy is resolved on the way in as much as a running one:
    /// staging a manifest nothing could ever run would leave the refusal for
    /// the resume, hours later and to somebody else.
    #[tokio::test]
    async fn refuses_an_unbuilt_revision_even_when_it_is_only_being_staged() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime);

        let error = applier
            .deploy(
                "hello".parse().unwrap(),
                built_manifest("alpha.test"),
                Some("def5678"),
                true,
            )
            .await
            .unwrap_err();

        assert!(matches!(error, ApplyError::Failed(_)));
        assert!(store.suspended_apps().is_empty());
        assert!(store.routes().lookup("alpha.test").is_none());
    }

    /// What recording the revision rather than the tag is for: the restart runs
    /// the commit that was deployed, however many newer images exist by then.
    #[tokio::test]
    async fn a_restart_re_resolves_the_revision_that_was_deployed() {
        let db = Db::in_memory().unwrap();
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _, builds) = applier_over(runtime.clone(), db.clone());
        record_build(&builds, "hello", "abc1234", "spaceport/hello:abc1234").await;
        applier
            .deploy(
                "hello".parse().unwrap(),
                built_manifest("alpha.test"),
                Some("abc1234"),
                false,
            )
            .await
            .unwrap();
        // A push nobody has deployed, built while this spaceport was down.
        record_build(&builds, "hello", "def5678", "spaceport/hello:def5678").await;

        // A new spaceport over the same records and a runtime with nothing left
        // in it, so the app has to be started again from what was written down.
        let restarted = Arc::new(FakeRuntime::default());
        let (applier, store, _) = applier_over(restarted.clone(), db);
        let record = applier.repository().desired().await.unwrap().remove(0);
        applier
            .restore(
                record.id.clone(),
                AppManifest::parse(&record.manifest).unwrap(),
                record.revision.as_deref(),
                record.suspended,
            )
            .await
            .unwrap();

        assert_eq!(
            *restarted.images.lock().unwrap(),
            ["spaceport/hello:abc1234".to_owned()]
        );
        assert!(store.routes().serving("alpha.test").is_some());
    }

    /// An app that names its image has no commit behind it, and asking the
    /// build store about one would invent a relationship it does not have.
    #[tokio::test]
    async fn an_app_that_names_its_image_runs_it_whatever_was_built() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _, builds) = applier_over(runtime.clone(), Db::in_memory().unwrap());
        record_build(&builds, "hello", "abc1234", "spaceport/hello:abc1234").await;

        applier
            .deploy(
                "hello".parse().unwrap(),
                manifest("alpha.test"),
                Some("abc1234"),
                false,
            )
            .await
            .unwrap();

        assert_eq!(
            *runtime.images.lock().unwrap(),
            ["strm/helloworld-http:latest".to_owned()]
        );
    }

    // The values a manifest names and never contains.

    /// A manifest that reads a secret out of its environment, which is the only
    /// way a container ever sees one.
    fn manifest_needing_a_secret(hosts: &str) -> AppManifest {
        AppManifest::parse(&format!(
            "schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [{hosts}]
container:
  secrets: [DB_PASSWORD]
  env:
    DATABASE_URL: \"postgres://user:{{{{DB_PASSWORD}}}}@db/app\"
  health:
    readiness:
      type: none
"
        ))
        .unwrap()
    }

    fn secret(name: &str) -> VarName {
        name.parse().unwrap()
    }

    /// What the app being started was given as `DATABASE_URL`, on the launch
    /// numbered `launch`.
    fn database_url(runtime: &FakeRuntime, launch: usize) -> String {
        runtime.environments.lock().unwrap()[launch]["DATABASE_URL"].clone()
    }

    /// The connection string the manifest above describes once `DB_PASSWORD` is
    /// `hunter2`. Spelled out, because a test that built it from the same
    /// pieces the code does would pass however the interpolation went wrong.
    const INTERPOLATED: &str = "postgres://user:hunter2@db/app";

    /// The refusal an operator gets for a secret nobody set, and what it leaves
    /// behind: an app that exists, holds its hosts and is not running, rather
    /// than a container coming up with `{{DB_PASSWORD}}` in its connection
    /// string and reporting it as a database problem an hour later.
    #[tokio::test]
    async fn applying_a_manifest_whose_secret_is_not_set_suspends_the_app() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        let id: AppId = "hello".parse().unwrap();

        let error = applier
            .apply(id.clone(), manifest_needing_a_secret("alpha.test"), false)
            .await
            .unwrap_err();

        assert!(matches!(error, ApplyError::MissingSecrets(_)), "{error:?}");
        assert!(error.to_string().contains("DB_PASSWORD"), "{error}");
        // Nothing was started, and the app is suspended rather than absent: its
        // hosts are claimed, so nothing else can take them and they can be
        // certified while somebody goes and finds the password.
        assert!(runtime.launched.lock().unwrap().is_empty());
        assert!(store.apps().is_empty());
        assert!(store.suspended(&id).is_some());
        assert!(store.routes().lookup("alpha.test").is_some());
        assert!(store.routes().serving("alpha.test").is_none());
        // And it is recorded as suspended, so a restart agrees with the store
        // rather than trying to start the app this refused to start.
        let desired = applier.repository().desired().await.unwrap();
        assert_eq!(desired.len(), 1);
        assert!(desired[0].suspended);

        // Applying it again says the same thing and leaves the same app: an
        // apply is a `PUT`, whatever it happens to be waiting for.
        let again = applier
            .apply(id.clone(), manifest_needing_a_secret("alpha.test"), false)
            .await
            .unwrap_err();
        assert!(matches!(again, ApplyError::MissingSecrets(_)), "{again:?}");
        assert!(store.suspended(&id).is_some());
        assert!(runtime.launched.lock().unwrap().is_empty());
    }

    /// The way back: the resume re-resolves, so the app that was staged waiting
    /// for a password comes up with the password in it, and nothing had to be
    /// applied a second time.
    #[tokio::test]
    async fn once_the_secret_is_set_resuming_starts_the_app_with_its_value() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        let id: AppId = "hello".parse().unwrap();
        applier
            .apply(id.clone(), manifest_needing_a_secret("alpha.test"), false)
            .await
            .unwrap_err();

        applier
            .secrets()
            .set(&id, &secret("DB_PASSWORD"), &Secret::new("hunter2"))
            .await
            .unwrap();
        let app = applier.resume(&id).await.unwrap();

        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
        assert_eq!(database_url(&runtime, 0), INTERPOLATED);
        assert_eq!(store.routes().serving("alpha.test").unwrap().id, app.id);
        assert!(!applier.repository().desired().await.unwrap()[0].suspended);
    }

    /// Resuming is the one command that would start the container, so it is the
    /// one that has to refuse: an operator who resumes before they have set the
    /// secret is told which one, and finds their app exactly where they left it.
    #[tokio::test]
    async fn resuming_while_a_secret_is_still_missing_leaves_the_app_suspended() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        let id: AppId = "hello".parse().unwrap();
        applier
            .apply(id.clone(), manifest_needing_a_secret("alpha.test"), false)
            .await
            .unwrap_err();

        let error = applier.resume(&id).await.unwrap_err();

        assert!(matches!(error, ResumeError::MissingSecrets(_)), "{error:?}");
        assert!(error.to_string().contains("DB_PASSWORD"), "{error}");
        assert!(runtime.launched.lock().unwrap().is_empty());
        assert!(store.suspended(&id).is_some());
        assert!(store.routes().serving("alpha.test").is_none());
        // Still recorded as suspended, so nothing brings it back running later.
        assert!(applier.repository().desired().await.unwrap()[0].suspended);
    }

    /// The ordinary case, and the only one in which a value reaches a
    /// container: every declared secret is set, so the app starts like any
    /// other and its environment holds the value rather than the placeholder.
    #[tokio::test]
    async fn an_app_whose_secrets_are_all_set_starts_with_them_interpolated() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        let id: AppId = "hello".parse().unwrap();
        applier
            .secrets()
            .set(&id, &secret("DB_PASSWORD"), &Secret::new("hunter2"))
            .await
            .unwrap();

        let app = started(
            applier
                .apply(id.clone(), manifest_needing_a_secret("alpha.test"), false)
                .await
                .unwrap(),
        );

        assert_eq!(database_url(&runtime, 0), INTERPOLATED);
        assert_eq!(store.routes().serving("alpha.test").unwrap().id, app.id);
        assert!(!applier.repository().desired().await.unwrap()[0].suspended);
    }

    /// A stored secret the manifest stopped reading is dead weight or a typo,
    /// and neither is a reason to refuse to run somebody's app.
    #[tokio::test]
    async fn a_stored_secret_the_manifest_does_not_declare_does_not_stop_it() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        let id: AppId = "hello".parse().unwrap();
        applier
            .secrets()
            .set(&id, &secret("DB_PASSWORD"), &Secret::new("hunter2"))
            .await
            .unwrap();
        applier
            .secrets()
            .set(&id, &secret("LEFTOVER"), &Secret::new("from last year"))
            .await
            .unwrap();

        applier
            .apply(id.clone(), manifest_needing_a_secret("alpha.test"), false)
            .await
            .unwrap();

        assert!(store.routes().serving("alpha.test").is_some());
        // The value nothing declares reached no container: the environment is
        // what the manifest wrote, and the manifest never mentions it.
        let environment = runtime.environments.lock().unwrap()[0].clone();
        assert_eq!(environment[&secret("DATABASE_URL")], INTERPOLATED);
        assert!(!environment.contains_key(&secret("LEFTOVER")));
    }

    /// A restart resolves secrets again, exactly as it resolves revisions
    /// again: an app comes back with the values as they are now, not with the
    /// placeholders its recorded document still carries.
    #[tokio::test]
    async fn a_restart_brings_back_an_app_with_its_secrets_resolved() {
        let db = Db::in_memory().unwrap();
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _, _) = applier_over(runtime, db.clone());
        let id: AppId = "hello".parse().unwrap();
        applier
            .secrets()
            .set(&id, &secret("DB_PASSWORD"), &Secret::new("hunter2"))
            .await
            .unwrap();
        applier
            .apply(id.clone(), manifest_needing_a_secret("alpha.test"), false)
            .await
            .unwrap();

        // A new spaceport over the same records, with a runtime that has
        // nothing left in it, so the app has to be started from what was
        // written down — which is a document with `{{DB_PASSWORD}}` in it.
        let restarted = Arc::new(FakeRuntime::default());
        let (applier, store, _) = applier_over(restarted.clone(), db);
        let record = applier.repository().desired().await.unwrap().remove(0);
        applier
            .restore(
                record.id.clone(),
                AppManifest::parse(&record.manifest).unwrap(),
                record.revision.as_deref(),
                record.suspended,
            )
            .await
            .unwrap();

        assert_eq!(database_url(&restarted, 0), INTERPOLATED);
        assert!(store.routes().serving("alpha.test").is_some());
    }

    /// A restart of an app that was left waiting for a secret has to put it
    /// back as it was — suspended and claiming its hosts — rather than refuse
    /// it and leave the hosts to whoever asks next.
    #[tokio::test]
    async fn a_restart_brings_back_an_app_that_is_still_waiting_for_a_secret() {
        let db = Db::in_memory().unwrap();
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _, _) = applier_over(runtime, db.clone());
        let id: AppId = "hello".parse().unwrap();
        applier
            .apply(id.clone(), manifest_needing_a_secret("alpha.test"), false)
            .await
            .unwrap_err();

        let restarted = Arc::new(FakeRuntime::default());
        let (applier, store, _) = applier_over(restarted.clone(), db);
        let record = applier.repository().desired().await.unwrap().remove(0);
        let restored = applier
            .restore(
                record.id.clone(),
                AppManifest::parse(&record.manifest).unwrap(),
                record.revision.as_deref(),
                record.suspended,
            )
            .await
            .unwrap();

        assert!(restored.was_suspended(), "{restored:?}");
        assert!(restarted.launched.lock().unwrap().is_empty());
        assert!(store.routes().lookup("alpha.test").is_some());
        // And setting the secret now is all it takes, on this spaceport as much
        // as on the one that refused.
        applier
            .secrets()
            .set(&id, &secret("DB_PASSWORD"), &Secret::new("hunter2"))
            .await
            .unwrap();
        applier.resume(&id).await.unwrap();
        assert_eq!(database_url(&restarted, 0), INTERPOLATED);
    }

    /// Secrets go with the app they belonged to, and with no other: unlike a
    /// volume, a secret means nothing once the app that read it is gone, and an
    /// app applied under the same id tomorrow must not inherit it.
    #[tokio::test]
    async fn destroying_an_app_forgets_its_secrets_and_only_its_own() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime);
        let id: AppId = "hello".parse().unwrap();
        let other: AppId = "other".parse().unwrap();
        for app in [&id, &other] {
            applier
                .secrets()
                .set(app, &secret("DB_PASSWORD"), &Secret::new("hunter2"))
                .await
                .unwrap();
        }
        applier
            .apply(id.clone(), manifest_needing_a_secret("alpha.test"), false)
            .await
            .unwrap();

        applier.destroy(&id).await.unwrap();

        assert!(applier.secrets().names(&id, None).await.unwrap().is_empty());
        assert_eq!(
            applier.secrets().names(&other, None).await.unwrap(),
            [secret("DB_PASSWORD")]
        );
    }
}

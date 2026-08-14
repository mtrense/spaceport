//! Making the host match what spaceport was told to run.
//!
//! Records say what should be running; the container engine says what is. On
//! every start those two are brought back together, in that order — desired
//! first, because an operator's intent is the thing worth preserving, and the
//! containers of the previous spaceport are only evidence of how it once got
//! there.
//!
//! An app whose container survived is *adopted*: the engine is asked where it
//! published that container, the app is health-checked there, and traffic goes
//! back to it untouched. Restarting spaceport then costs its apps nothing, and
//! only what is actually missing — a container that was removed, exited, or no
//! longer matches its manifest — is started again.
//!
//! Nothing here is fatal. An app whose manifest no longer parses, or whose
//! image has since been deleted, must not stop the other nine coming back.

use std::sync::Arc;

use anyhow::Result;
use tracing::{info, warn};

use super::apply::Applier;
use super::{AppId, AppManifest};

/// What a reconciliation did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Apps that are running and routed again.
    pub restored: Vec<AppId>,
    /// How many of them never had to be restarted, because their container was
    /// still running and was taken over as it was.
    pub adopted: usize,
    /// Apps that were recorded as suspended, and so were claimed rather than
    /// started.
    pub suspended: Vec<AppId>,
    /// Apps that were recorded but could not be brought back, and why.
    pub failed: Vec<(AppId, String)>,
    /// Containers left over from a previous spaceport that no record claims.
    pub swept: usize,
}

impl Report {
    /// Whether anything at all had to be done. A first start on a clean host
    /// reconciles to nothing, and should say nothing.
    pub fn is_empty(&self) -> bool {
        self.restored.is_empty()
            && self.suspended.is_empty()
            && self.failed.is_empty()
            && self.swept == 0
    }
}

/// Bring back everything spaceport was running, and clean up what it was not.
///
/// Runs before the edge accepts traffic, so that a restart does not answer 404
/// for apps it is about to start.
pub async fn reconcile(applier: &Arc<Applier>) -> Result<Report> {
    let desired = applier.repository().desired().await?;
    let mut report = Report::default();

    for record in &desired {
        let manifest = match AppManifest::parse(&record.manifest) {
            Ok(manifest) => manifest,
            // Recorded by a spaceport that understood something this one does
            // not. Left in the store rather than deleted: a downgrade is a
            // reason to leave an app down, not to forget it was ever asked for.
            Err(error) => {
                warn!(app = %record.id, %error, "cannot read the recorded manifest, leaving the app down");
                report
                    .failed
                    .push((record.id.clone(), format!("{error:#}")));
                continue;
            }
        };

        match applier
            .restore(record.id.clone(), manifest, record.suspended)
            .await
        {
            Ok(restored) if restored.was_suspended() => {
                info!(app = %record.id, "app is suspended, claiming its hosts without starting it");
                report.suspended.push(record.id.clone());
            }
            Ok(restored) => {
                let Some(app) = restored.app() else { continue };
                if restored.was_adopted() {
                    report.adopted += 1;
                }
                info!(app = %app.id, upstream = %app.upstream, adopted = restored.was_adopted(), "restored app");
                report.restored.push(app.id.clone());
            }
            Err(error) => {
                warn!(app = %record.id, %error, "could not restore app");
                report
                    .failed
                    .push((record.id.clone(), format!("{error:#}")));
            }
        }
    }

    report.swept = sweep(applier).await?;

    Ok(report)
}

/// Remove every container spaceport manages that no app in the store owns.
///
/// These are containers of apps that were destroyed while spaceport was down,
/// or that a crash left behind mid-apply. Only ever spaceport's own: the list
/// comes from the managed label, so nothing else on the host is in scope.
///
/// A suspended app's container is owned as much as a running one's — a stopped
/// container is precisely what suspending with `--stop-container` leaves behind,
/// and sweeping it would turn every restart into the relaunch that keeping it
/// was meant to avoid.
async fn sweep(applier: &Arc<Applier>) -> Result<usize> {
    let claimed = applier.store().containers();

    let mut swept = 0;
    for container in applier.runtime().managed().await? {
        if claimed.contains(&container.id) {
            continue;
        }

        match applier.runtime().remove(&container.id).await {
            Ok(()) => {
                info!(container = %container.id, app = ?container.app.as_ref().map(AppId::as_str), "removed a container no app claims");
                swept += 1;
            }
            // Worth saying, not worth stopping for: the container is not routed
            // to and never will be.
            Err(error) => {
                warn!(container = %container.id, %error, "could not remove a leftover container");
            }
        }
    }

    Ok(swept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppStore;
    use crate::app::repository::AppRepository;
    use crate::runtime::{Adopted, Container, ContainerId, ContainerRuntime, Managed};
    use crate::state::Db;
    use anyhow::bail;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    /// A runtime that remembers what it is running, so a sweep has something
    /// to find.
    #[derive(Default)]
    struct FakeRuntime {
        containers: Mutex<Vec<Managed>>,
        /// Where each container it started was published, so a restart can find
        /// its way back to one.
        upstreams: Mutex<HashMap<ContainerId, SocketAddr>>,
        /// The containers it has been asked to stop and keep. They are still in
        /// `containers` — that is the whole point of stopping rather than
        /// removing — but they have no address until they start again.
        stopped: Mutex<Vec<ContainerId>>,
        launches: Mutex<usize>,
        refuse: Vec<String>,
    }

    #[async_trait]
    impl ContainerRuntime for FakeRuntime {
        async fn launch(&self, app: &AppId, _manifest: &AppManifest) -> Result<Container> {
            if self.refuse.contains(&app.to_string()) {
                bail!("no image for app `{app}`");
            }

            let mut launches = self.launches.lock().unwrap();
            *launches += 1;
            let port = 9000 + u16::try_from(*launches).unwrap();
            let id = ContainerId::new(format!("{app}-{port}"));
            let upstream = SocketAddr::from(([127, 0, 0, 1], port));

            let mut containers = self.containers.lock().unwrap();
            containers.retain(|container| container.app.as_ref() != Some(app));
            containers.push(Managed {
                id: id.clone(),
                app: Some(app.clone()),
            });
            self.upstreams.lock().unwrap().insert(id.clone(), upstream);

            Ok(Container { id, upstream })
        }

        /// Whatever this runtime still has under that app's name — which is
        /// what a second `Applier` over the same runtime finds.
        async fn adopt(&self, app: &AppId, _manifest: &AppManifest) -> Result<Option<Adopted>> {
            let containers = self.containers.lock().unwrap();
            let Some(found) = containers
                .iter()
                .find(|container| container.app.as_ref() == Some(app))
            else {
                return Ok(None);
            };

            if self.stopped.lock().unwrap().contains(&found.id) {
                return Ok(Some(Adopted::Stopped(found.id.clone())));
            }

            Ok(self
                .upstreams
                .lock()
                .unwrap()
                .get(&found.id)
                .map(|upstream| {
                    Adopted::Running(Container {
                        id: found.id.clone(),
                        upstream: *upstream,
                    })
                }))
        }

        async fn stop(&self, id: &ContainerId) -> Result<()> {
            self.stopped.lock().unwrap().push(id.clone());
            // A stopped container is published nowhere.
            self.upstreams.lock().unwrap().remove(id);

            Ok(())
        }

        async fn start(&self, id: &ContainerId, _manifest: &AppManifest) -> Result<Container> {
            self.stopped.lock().unwrap().retain(|stopped| stopped != id);

            // A port of its own, so that a resume that trusted the address it
            // had before this stopped would be caught.
            let upstream = SocketAddr::from(([127, 0, 0, 1], 7000));
            self.upstreams.lock().unwrap().insert(id.clone(), upstream);

            Ok(Container {
                id: id.clone(),
                upstream,
            })
        }

        async fn remove(&self, id: &ContainerId) -> Result<()> {
            self.containers
                .lock()
                .unwrap()
                .retain(|container| container.id != *id);

            Ok(())
        }

        async fn managed(&self) -> Result<Vec<Managed>> {
            Ok(self.containers.lock().unwrap().clone())
        }
    }

    fn manifest(hosts: &str) -> String {
        format!(
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
        )
    }

    /// A spaceport that has already run: a database with records in it, and a
    /// runtime with whatever the previous process left behind.
    fn restarted(
        runtime: Arc<FakeRuntime>,
        db: Db,
    ) -> (Arc<Applier>, Arc<AppStore>, AppRepository) {
        let store = Arc::new(AppStore::new());
        let repository = AppRepository::new(db);
        let applier = Arc::new(Applier::new(store.clone(), runtime, repository.clone()));

        (applier, store, repository)
    }

    fn id(id: &str) -> AppId {
        id.parse().unwrap()
    }

    #[tokio::test]
    async fn a_first_start_has_nothing_to_do() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _, _) = restarted(runtime, Db::in_memory().unwrap());

        let report = reconcile(&applier).await.unwrap();

        assert!(report.is_empty(), "{report:?}");
    }

    #[tokio::test]
    async fn brings_back_every_recorded_app() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store, repository) = restarted(runtime, Db::in_memory().unwrap());
        repository
            .record_applied(&id("hello"), &manifest("alpha.test"), false)
            .await
            .unwrap();
        repository
            .record_applied(&id("other"), &manifest("beta.test"), false)
            .await
            .unwrap();

        let report = reconcile(&applier).await.unwrap();

        assert_eq!(report.restored, [id("hello"), id("other")]);
        assert!(report.failed.is_empty());
        assert!(store.routes().serving("alpha.test").is_some());
        assert!(store.routes().serving("beta.test").is_some());
    }

    /// One app that cannot come back is one app down, not a spaceport that
    /// refuses to start.
    #[tokio::test]
    async fn keeps_going_when_an_app_cannot_be_started() {
        let runtime = Arc::new(FakeRuntime {
            refuse: vec!["broken".to_owned()],
            ..Default::default()
        });
        let (applier, store, repository) = restarted(runtime, Db::in_memory().unwrap());
        repository
            .record_applied(&id("broken"), &manifest("alpha.test"), false)
            .await
            .unwrap();
        repository
            .record_applied(&id("healthy"), &manifest("beta.test"), false)
            .await
            .unwrap();

        let report = reconcile(&applier).await.unwrap();

        assert_eq!(report.restored, [id("healthy")]);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, id("broken"));
        assert!(store.routes().serving("beta.test").is_some());
        // And the app that failed is still recorded, so fixing the host and
        // restarting is enough to bring it back.
        assert_eq!(repository.desired().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn leaves_an_app_whose_manifest_it_cannot_read_alone() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store, repository) = restarted(runtime, Db::in_memory().unwrap());
        repository
            .record_applied(&id("future"), "schema_version: 99\n", false)
            .await
            .unwrap();

        let report = reconcile(&applier).await.unwrap();

        assert!(report.restored.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].1.contains("schema version"), "{report:?}");
        assert!(store.apps().is_empty());
        assert_eq!(repository.desired().await.unwrap().len(), 1);
    }

    /// An app destroyed while spaceport was down leaves a container nothing
    /// will ever route to.
    #[tokio::test]
    async fn sweeps_a_container_no_record_claims() {
        let runtime = Arc::new(FakeRuntime::default());
        runtime.containers.lock().unwrap().push(Managed {
            id: ContainerId::new("orphan-1"),
            app: Some(id("gone")),
        });
        let (applier, _, repository) = restarted(runtime.clone(), Db::in_memory().unwrap());
        repository
            .record_applied(&id("hello"), &manifest("alpha.test"), false)
            .await
            .unwrap();

        let report = reconcile(&applier).await.unwrap();

        assert_eq!(report.swept, 1);
        // The restored app's own container is not swept with it.
        let left = runtime.containers.lock().unwrap().clone();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].app, Some(id("hello")));
    }

    /// A container spaceport marked as its own but can no longer name is still
    /// spaceport's to clean up.
    #[tokio::test]
    async fn sweeps_a_container_with_no_readable_app() {
        let runtime = Arc::new(FakeRuntime::default());
        runtime.containers.lock().unwrap().push(Managed {
            id: ContainerId::new("nameless-1"),
            app: None,
        });
        let (applier, _, _) = restarted(runtime.clone(), Db::in_memory().unwrap());

        let report = reconcile(&applier).await.unwrap();

        assert_eq!(report.swept, 1);
        assert!(runtime.containers.lock().unwrap().is_empty());
    }

    /// The whole point of the records: what was applied before the restart is
    /// what is running after it — and, because its container outlived the
    /// spaceport that started it, in the very same container.
    #[tokio::test]
    async fn survives_a_restart_end_to_end() {
        let db = Db::in_memory().unwrap();
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _, _) = restarted(runtime.clone(), db.clone());
        let applied = applier
            .apply(
                id("hello"),
                AppManifest::parse(&manifest("alpha.test")).unwrap(),
                false,
            )
            .await
            .unwrap();
        let before = applied.running().unwrap();

        // A new spaceport over the same database and the same engine.
        let (restarted_applier, store, _) = restarted(runtime.clone(), db);
        let report = reconcile(&restarted_applier).await.unwrap();

        assert_eq!(report.restored, [id("hello")]);
        assert_eq!(report.adopted, 1);
        assert_eq!(report.swept, 0);
        let after = store.routes().serving("alpha.test").unwrap().clone();
        assert_eq!(after.container, before.container);
        assert_eq!(after.upstream, before.upstream);
        // Nothing was started to get there: the app never went down.
        assert_eq!(*runtime.launches.lock().unwrap(), 1);
    }

    /// And where the container did not survive — removed by hand, or exited
    /// while spaceport was down — the app is started again.
    #[tokio::test]
    async fn starts_an_app_again_when_its_container_did_not_survive() {
        let db = Db::in_memory().unwrap();
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _, _) = restarted(runtime.clone(), db.clone());
        let applied = applier
            .apply(
                id("hello"),
                AppManifest::parse(&manifest("alpha.test")).unwrap(),
                false,
            )
            .await
            .unwrap();
        let before = applied.running().unwrap();
        runtime.remove(&before.container).await.unwrap();

        let (restarted_applier, store, _) = restarted(runtime.clone(), db);
        let report = reconcile(&restarted_applier).await.unwrap();

        assert_eq!(report.restored, [id("hello")]);
        assert_eq!(report.adopted, 0);
        assert_eq!(*runtime.launches.lock().unwrap(), 2);
        assert_ne!(
            store.routes().serving("alpha.test").unwrap().container,
            before.container
        );
    }

    /// Suspension is intent, and a restart of spaceport is not a reason to
    /// overrule it: the app comes back claiming its hosts and not serving.
    #[tokio::test]
    async fn a_suspended_app_comes_back_suspended() {
        let db = Db::in_memory().unwrap();
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _, _) = restarted(runtime.clone(), db.clone());
        applier
            .apply(
                id("hello"),
                AppManifest::parse(&manifest("alpha.test")).unwrap(),
                false,
            )
            .await
            .unwrap();
        applier.suspend(&id("hello"), true).await.unwrap();

        let (restarted_applier, store, _) = restarted(runtime.clone(), db);
        let report = reconcile(&restarted_applier).await.unwrap();

        assert_eq!(report.suspended, [id("hello")]);
        assert!(report.restored.is_empty());
        assert!(store.routes().serving("alpha.test").is_none());
        assert!(store.routes().lookup("alpha.test").is_some());
        // Nothing was started to bring it back, and nothing was swept.
        assert_eq!(*runtime.launches.lock().unwrap(), 1);
        assert_eq!(report.swept, 0);
    }

    /// The container a suspend stopped is spoken for. Sweeping it would turn
    /// every restart into the relaunch that keeping it was meant to avoid.
    #[tokio::test]
    async fn a_sweep_spares_the_container_a_suspended_app_kept() {
        let db = Db::in_memory().unwrap();
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _, _) = restarted(runtime.clone(), db.clone());
        let applied = applier
            .apply(
                id("hello"),
                AppManifest::parse(&manifest("alpha.test")).unwrap(),
                false,
            )
            .await
            .unwrap();
        let before = applied.running().unwrap().container.clone();
        applier.suspend(&id("hello"), true).await.unwrap();

        let (restarted_applier, _, _) = restarted(runtime.clone(), db);
        let report = reconcile(&restarted_applier).await.unwrap();

        assert_eq!(report.swept, 0);
        let left = runtime.containers.lock().unwrap().clone();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, before);
    }

    /// And it is still the container it kept that comes back when the app is
    /// resumed after the restart.
    #[tokio::test]
    async fn resuming_after_a_restart_starts_the_container_it_kept() {
        let db = Db::in_memory().unwrap();
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _, _) = restarted(runtime.clone(), db.clone());
        let applied = applier
            .apply(
                id("hello"),
                AppManifest::parse(&manifest("alpha.test")).unwrap(),
                false,
            )
            .await
            .unwrap();
        let before = applied.running().unwrap().container.clone();
        applier.suspend(&id("hello"), true).await.unwrap();

        let (restarted_applier, store, _) = restarted(runtime.clone(), db);
        reconcile(&restarted_applier).await.unwrap();
        let after = restarted_applier.resume(&id("hello")).await.unwrap();

        assert_eq!(after.container, before);
        // No relaunch: the container outlived both the suspend and the restart.
        assert_eq!(*runtime.launches.lock().unwrap(), 1);
        assert!(store.routes().serving("alpha.test").is_some());
    }

    /// An app applied straight into suspension has no container at all, and a
    /// restart must bring back the claim without inventing one.
    #[tokio::test]
    async fn an_app_applied_suspended_survives_a_restart() {
        let db = Db::in_memory().unwrap();
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _, _) = restarted(runtime.clone(), db.clone());
        applier
            .apply(
                id("hello"),
                AppManifest::parse(&manifest("alpha.test")).unwrap(),
                true,
            )
            .await
            .unwrap();

        let (restarted_applier, store, _) = restarted(runtime.clone(), db);
        let report = reconcile(&restarted_applier).await.unwrap();

        assert_eq!(report.suspended, [id("hello")]);
        assert_eq!(*runtime.launches.lock().unwrap(), 0);
        assert!(store.routes().lookup("alpha.test").is_some());
        // And certificate acquisition still hears about the host.
        assert!(store.routes().hosts().contains("alpha.test"));
    }
}

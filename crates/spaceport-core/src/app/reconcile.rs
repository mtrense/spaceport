//! Making the host match what spaceport was told to run.
//!
//! Records say what should be running; the container engine says what is. On
//! every start those two are brought back together, in that order — desired
//! first, because an operator's intent is the thing worth preserving, and the
//! containers of the previous spaceport are only evidence of how it once got
//! there.
//!
//! Every recorded app is *relaunched*. A container that survived the restart is
//! stopped and started again rather than adopted, which costs each app a few
//! seconds of downtime at every restart of spaceport itself. Reattaching to a
//! survivor — reading back the port the engine published it on, health-checking
//! it, and routing to it untouched — is the obvious next step, and it slots
//! into this same loop without changing a single record.
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
    /// Apps that were recorded but could not be brought back, and why.
    pub failed: Vec<(AppId, String)>,
    /// Containers left over from a previous spaceport that no record claims.
    pub swept: usize,
}

impl Report {
    /// Whether anything at all had to be done. A first start on a clean host
    /// reconciles to nothing, and should say nothing.
    pub fn is_empty(&self) -> bool {
        self.restored.is_empty() && self.failed.is_empty() && self.swept == 0
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

        match applier.restore(record.id.clone(), manifest).await {
            Ok(app) => {
                info!(app = %app.id, upstream = %app.upstream, "restored app");
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
async fn sweep(applier: &Arc<Applier>) -> Result<usize> {
    let running: Vec<_> = applier
        .store()
        .apps()
        .iter()
        .map(|app| app.container.clone())
        .collect();

    let mut swept = 0;
    for container in applier.runtime().managed().await? {
        if running.contains(&container.id) {
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
    use crate::runtime::{Container, ContainerId, ContainerRuntime, Managed};
    use crate::state::Db;
    use anyhow::bail;
    use async_trait::async_trait;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    /// A runtime that remembers what it is running, so a sweep has something
    /// to find.
    #[derive(Default)]
    struct FakeRuntime {
        containers: Mutex<Vec<Managed>>,
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

            let mut containers = self.containers.lock().unwrap();
            containers.retain(|container| container.app.as_ref() != Some(app));
            containers.push(Managed {
                id: id.clone(),
                app: Some(app.clone()),
            });

            Ok(Container {
                id,
                upstream: SocketAddr::from(([127, 0, 0, 1], port)),
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
            .record_applied(&id("hello"), &manifest("alpha.test"))
            .await
            .unwrap();
        repository
            .record_applied(&id("other"), &manifest("beta.test"))
            .await
            .unwrap();

        let report = reconcile(&applier).await.unwrap();

        assert_eq!(report.restored, [id("hello"), id("other")]);
        assert!(report.failed.is_empty());
        assert!(store.routes().lookup("alpha.test").is_some());
        assert!(store.routes().lookup("beta.test").is_some());
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
            .record_applied(&id("broken"), &manifest("alpha.test"))
            .await
            .unwrap();
        repository
            .record_applied(&id("healthy"), &manifest("beta.test"))
            .await
            .unwrap();

        let report = reconcile(&applier).await.unwrap();

        assert_eq!(report.restored, [id("healthy")]);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, id("broken"));
        assert!(store.routes().lookup("beta.test").is_some());
        // And the app that failed is still recorded, so fixing the host and
        // restarting is enough to bring it back.
        assert_eq!(repository.desired().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn leaves_an_app_whose_manifest_it_cannot_read_alone() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store, repository) = restarted(runtime, Db::in_memory().unwrap());
        repository
            .record_applied(&id("future"), "schema_version: 99\n")
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
            .record_applied(&id("hello"), &manifest("alpha.test"))
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
    /// what is running after it.
    #[tokio::test]
    async fn survives_a_restart_end_to_end() {
        let db = Db::in_memory().unwrap();
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _, _) = restarted(runtime.clone(), db.clone());
        applier
            .apply(
                id("hello"),
                AppManifest::parse(&manifest("alpha.test")).unwrap(),
            )
            .await
            .unwrap();

        // A new spaceport over the same database and the same engine.
        let (restarted_applier, store, _) = restarted(runtime, db);
        let report = reconcile(&restarted_applier).await.unwrap();

        assert_eq!(report.restored, [id("hello")]);
        assert_eq!(report.swept, 0);
        assert!(store.routes().lookup("alpha.test").is_some());
    }
}

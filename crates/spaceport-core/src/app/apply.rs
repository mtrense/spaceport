//! Applying a manifest: the one verb the operator interface has.
//!
//! An apply is three things that can each fail — the routes an app claims have
//! to be free, a container has to start, and the app inside it has to answer —
//! and the order matters. Routing is checked first because it is cheap and
//! because the alternative is starting a container for an app that was never
//! going to be reachable, having already torn down the one it replaced on the
//! way in.

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use anyhow::anyhow;
use tracing::{info, warn};

use super::repository::AppRepository;
use super::{App, AppId, AppManifest, AppStore, health};
use crate::runtime::{Container, ContainerRuntime};

/// Why an apply did not happen. The distinction is worth keeping because the
/// operator interface answers differently: a conflict is the operator's to fix,
/// a failure is the host's.
#[derive(Debug)]
pub enum ApplyError {
    /// Another app already serves one of the manifest's hosts.
    Conflict(anyhow::Error),
    /// The app could not be started.
    Failed(anyhow::Error),
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict(error) | Self::Failed(error) => write!(f, "{error:#}"),
        }
    }
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

/// How an app came back at a restart.
///
/// Both mean the app is running and routed; they differ in what it cost. The
/// distinction is worth reporting, because "adopted" is the answer that says a
/// restart of spaceport did not interrupt anybody's traffic.
#[derive(Debug)]
pub enum Restored {
    /// Its container was still running and was taken over untouched.
    Adopted(Arc<App>),
    /// There was nothing to take over, so it was started again.
    Relaunched(Arc<App>),
}

impl Restored {
    pub fn app(&self) -> &Arc<App> {
        match self {
            Self::Adopted(app) | Self::Relaunched(app) => app,
        }
    }

    pub fn was_adopted(&self) -> bool {
        matches!(self, Self::Adopted(_))
    }
}

/// Turns manifests into running, routed apps, and takes them back down again.
pub struct Applier {
    store: Arc<AppStore>,
    runtime: Arc<dyn ContainerRuntime>,
    repository: AppRepository,
}

impl Applier {
    pub fn new(
        store: Arc<AppStore>,
        runtime: Arc<dyn ContainerRuntime>,
        repository: AppRepository,
    ) -> Self {
        Self {
            store,
            runtime,
            repository,
        }
    }

    /// The apps this applier has running.
    pub fn store(&self) -> &AppStore {
        &self.store
    }

    /// What this applier has been told to run, across restarts.
    pub fn repository(&self) -> &AppRepository {
        &self.repository
    }

    /// The engine it runs apps on.
    pub fn runtime(&self) -> &dyn ContainerRuntime {
        self.runtime.as_ref()
    }

    /// Stop the app named `id` and forget it, routes and container both.
    ///
    /// The routes go first, so nothing is forwarded to a container on its way
    /// out. If the engine then refuses to remove it, the app is already gone
    /// from the store and nothing will ever route to that container again —
    /// the error names it, because by then it is a container only the operator
    /// can clean up.
    pub async fn destroy(&self, id: &AppId) -> Result<Arc<App>, DestroyError> {
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

        self.runtime.remove(&app.container).await.map_err(|error| {
            DestroyError::Failed(error.context(format!(
                "app `{id}` is no longer routed, but its container {} is still there",
                app.container
            )))
        })?;
        info!(app = %id, container = %app.container, "app destroyed");

        Ok(app)
    }

    /// Start `manifest` as the app named `id` and route traffic to it,
    /// replacing whatever was running under that id.
    ///
    /// Not atomic, and cannot be: replacing an app means its old container is
    /// gone before the new one is up, so an apply that fails halfway leaves the
    /// app down. What it does guarantee is that it leaves nothing behind — a
    /// container that ends up unroutable is removed rather than left running.
    pub async fn apply(&self, id: AppId, manifest: AppManifest) -> Result<Arc<App>, ApplyError> {
        let recorded = manifest.source_text().to_owned();
        let app = self.start(id, manifest).await?;

        // Recorded last, and only on success: a manifest that never ran is not
        // something to bring back at the next start. The cost is a window —
        // from here to the commit — in which a successful apply can be lost to
        // a crash, and the answer to that is to apply it again.
        if let Err(error) = self.repository.record_applied(&app.id, &recorded).await {
            warn!(app = %app.id, %error, "the app is running but was not recorded, so it will not survive a restart");
        }

        Ok(app)
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
    pub async fn restore(&self, id: AppId, manifest: AppManifest) -> Result<Restored, ApplyError> {
        self.free_of_conflict(&id, &manifest)?;

        match self.runtime.adopt(&id, &manifest).await {
            Ok(Some(container)) => {
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
            Ok(None) => {}
            // Adoption is an optimisation, and a failed one costs a relaunch
            // rather than an app.
            Err(error) => {
                warn!(app = %id, %error, "could not tell what the previous spaceport left running");
            }
        }

        self.start(id, manifest).await.map(Restored::Relaunched)
    }

    /// Everything an apply does except remember it.
    async fn start(&self, id: AppId, manifest: AppManifest) -> Result<Arc<App>, ApplyError> {
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
                "host `{host}` is already served by app `{owner}`"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Container, ContainerId, Managed};
    use crate::state::Db;
    use anyhow::{Result, bail};
    use async_trait::async_trait;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    /// A runtime that starts nothing, so the apply logic can be tested without
    /// a container engine anywhere near it.
    #[derive(Default)]
    struct FakeRuntime {
        launched: Mutex<Vec<AppId>>,
        removed: Mutex<Vec<ContainerId>>,
        refuse: bool,
        refuse_removal: bool,
        /// What the spaceport before this one is pretending to have left
        /// running, for every app.
        survivor: Option<Container>,
    }

    #[async_trait]
    impl ContainerRuntime for FakeRuntime {
        async fn adopt(&self, _app: &AppId, _manifest: &AppManifest) -> Result<Option<Container>> {
            Ok(self.survivor.clone())
        }

        async fn launch(&self, app: &AppId, _manifest: &AppManifest) -> Result<Container> {
            if self.refuse {
                bail!("no image for you");
            }
            let mut launched = self.launched.lock().unwrap();
            launched.push(app.clone());

            // A different port per launch, so a replacement is visible.
            let port = 9000 + u16::try_from(launched.len()).unwrap();
            Ok(Container {
                id: ContainerId::new(format!("{app}-{port}")),
                upstream: SocketAddr::from(([127, 0, 0, 1], port)),
            })
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

    fn applier(runtime: Arc<FakeRuntime>) -> (Applier, Arc<AppStore>) {
        let store = Arc::new(AppStore::new());
        let repository = AppRepository::new(Db::in_memory().unwrap());

        (Applier::new(store.clone(), runtime, repository), store)
    }

    #[tokio::test]
    async fn starts_an_app_and_routes_it() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());

        let app = applier
            .apply("hello".parse().unwrap(), manifest("alpha.test, beta.test"))
            .await
            .unwrap();

        assert_eq!(app.upstream.port(), 9001);
        assert_eq!(store.routes().lookup("alpha.test").unwrap().id, app.id);
        assert_eq!(store.routes().lookup("beta.test").unwrap().id, app.id);
        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn re_applying_repoints_the_routes() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());

        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"))
            .await
            .unwrap();
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"))
            .await
            .unwrap();

        assert_eq!(store.apps().len(), 1);
        assert_eq!(
            store.routes().lookup("alpha.test").unwrap().upstream.port(),
            9002
        );
    }

    #[tokio::test]
    async fn refuses_a_conflict_before_starting_anything() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"))
            .await
            .unwrap();

        let error = applier
            .apply("other".parse().unwrap(), manifest("alpha.test"))
            .await
            .unwrap_err();

        assert!(matches!(error, ApplyError::Conflict(_)));
        assert!(error.to_string().contains("already served by app `hello`"));
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
            )
            .await
            .unwrap_err();

        assert!(matches!(error, ApplyError::Failed(_)));
        assert!(error.to_string().contains("never became ready"), "{error}");
        assert!(store.routes().lookup("alpha.test").is_none());
        assert!(store.apps().is_empty());
        // And the container it started is not left behind.
        assert_eq!(runtime.removed.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_failed_apply_leaves_the_previous_app_serving() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"))
            .await
            .unwrap();

        applier
            .apply(
                "hello".parse().unwrap(),
                manifest_awaiting_readiness("alpha.test"),
            )
            .await
            .unwrap_err();

        // The route still points at the old container, which the runtime has
        // in fact already replaced — see the note on `apply`.
        assert_eq!(
            store.routes().lookup("alpha.test").unwrap().upstream.port(),
            9001
        );
    }

    #[tokio::test]
    async fn destroying_an_app_stops_it_and_drops_its_routes() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, store) = applier(runtime.clone());
        let app = applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"))
            .await
            .unwrap();

        let destroyed = applier.destroy(&"hello".parse().unwrap()).await.unwrap();

        assert_eq!(destroyed.id, app.id);
        assert!(store.apps().is_empty());
        assert!(store.routes().lookup("alpha.test").is_none());
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
            .apply("hello".parse().unwrap(), manifest("alpha.test"))
            .await
            .unwrap();
        let runtime = Arc::new(FakeRuntime {
            refuse_removal: true,
            ..Default::default()
        });
        let applier = Applier::new(
            store.clone(),
            runtime,
            AppRepository::new(Db::in_memory().unwrap()),
        );

        let error = applier
            .destroy(&"hello".parse().unwrap())
            .await
            .unwrap_err();

        assert!(matches!(error, DestroyError::Failed(_)));
        assert!(error.to_string().contains("is still there"), "{error}");
        assert!(store.apps().is_empty());
        assert!(store.routes().lookup("alpha.test").is_none());
    }

    #[tokio::test]
    async fn records_an_applied_app_verbatim() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime);
        let manifest = manifest("alpha.test");

        applier
            .apply("hello".parse().unwrap(), manifest.clone())
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
            .apply("hello".parse().unwrap(), manifest("alpha.test"))
            .await
            .unwrap_err();

        assert!(applier.repository().desired().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn destroying_an_app_forgets_it() {
        let runtime = Arc::new(FakeRuntime::default());
        let (applier, _) = applier(runtime);
        applier
            .apply("hello".parse().unwrap(), manifest("alpha.test"))
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
            .apply("hello".parse().unwrap(), manifest("alpha.test"))
            .await
            .unwrap();
        let applied_at = applier.repository().desired().await.unwrap()[0]
            .applied_at
            .clone();

        applier
            .restore("hello".parse().unwrap(), manifest("alpha.test"))
            .await
            .unwrap();

        let desired = applier.repository().desired().await.unwrap();
        assert_eq!(desired.len(), 1);
        assert_eq!(desired[0].applied_at, applied_at);
        // It is running all the same.
        assert!(store.routes().lookup("alpha.test").is_some());
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
            .restore("hello".parse().unwrap(), manifest("alpha.test"))
            .await
            .unwrap();

        assert!(restored.was_adopted(), "{restored:?}");
        assert_eq!(restored.app().container, survivor.id);
        assert_eq!(
            store.routes().lookup("alpha.test").unwrap().upstream,
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
            .restore("hello".parse().unwrap(), manifest("alpha.test"))
            .await
            .unwrap();

        assert!(!restored.was_adopted(), "{restored:?}");
        assert_eq!(runtime.launched.lock().unwrap().len(), 1);
        assert!(store.routes().lookup("alpha.test").is_some());
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
            .apply("hello".parse().unwrap(), manifest("alpha.test"))
            .await
            .unwrap_err();

        assert!(matches!(error, ApplyError::Failed(_)));
        assert!(error.to_string().contains("no image for you"));
        assert!(store.apps().is_empty());
    }
}

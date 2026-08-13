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
use tracing::info;

use super::{App, AppId, AppManifest, AppStore, health};
use crate::runtime::ContainerRuntime;

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

/// Turns manifests into running, routed apps.
pub struct Applier {
    store: Arc<AppStore>,
    runtime: Arc<dyn ContainerRuntime>,
}

impl Applier {
    pub fn new(store: Arc<AppStore>, runtime: Arc<dyn ContainerRuntime>) -> Self {
        Self { store, runtime }
    }

    /// Start `manifest` as the app named `id` and route traffic to it,
    /// replacing whatever was running under that id.
    ///
    /// Not atomic, and cannot be: replacing an app means its old container is
    /// gone before the new one is up, so an apply that fails halfway leaves the
    /// app down. What it does guarantee is that it leaves nothing behind — a
    /// container that ends up unroutable is removed rather than left running.
    pub async fn apply(&self, id: AppId, manifest: AppManifest) -> Result<Arc<App>, ApplyError> {
        if let Some((host, owner)) = self.store.conflict(&id, &manifest.routing.hosts) {
            return Err(ApplyError::Conflict(anyhow!(
                "host `{host}` is already served by app `{owner}`"
            )));
        }

        let container = self
            .runtime
            .launch(&id, &manifest)
            .await
            .map_err(ApplyError::Failed)?;

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
                error.context(format!("app `{id}` started but never became ready")),
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
    use crate::runtime::{Container, ContainerId};
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
    }

    #[async_trait]
    impl ContainerRuntime for FakeRuntime {
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
            self.removed.lock().unwrap().push(id.clone());
            Ok(())
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

        (Applier::new(store.clone(), runtime), store)
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

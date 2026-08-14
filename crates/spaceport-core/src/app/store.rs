//! The apps spaceport is running, and the routes they claim.
//!
//! Two views of the same thing. Operators think in apps — apply this manifest
//! under this id — while the edge only ever asks "which upstream serves this
//! host?". So mutations go through [`AppStore`], and every one of them rebuilds
//! the immutable [`Routes`] snapshot the edge reads.
//!
//! The snapshot is what keeps the proxy path off the lock: a request clones an
//! `Arc<Routes>` while holding the read lock for the length of that clone, then
//! looks up its host with no lock at all. A concurrent apply builds an entirely
//! new map, so a request already holding a snapshot keeps serving the routes it
//! started with rather than seeing a half-applied one.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use anyhow::{Result, bail};
use tokio::sync::watch;
use tracing::info;

use super::AppId;
use super::manifest::{AppManifest, Host};
use crate::runtime::ContainerId;

/// An app that is running and reachable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
    pub id: AppId,
    pub manifest: AppManifest,
    /// The container serving it.
    pub container: ContainerId,
    /// Where the edge forwards this app's traffic.
    pub upstream: SocketAddr,
}

impl App {
    /// The hosts this app claims.
    pub fn hosts(&self) -> &[Host] {
        &self.manifest.routing.hosts
    }
}

/// An immutable host-to-app map: what the edge sees.
#[derive(Debug, Default)]
pub struct Routes {
    by_host: HashMap<Host, Arc<App>>,
}

impl Routes {
    /// Every host anything is served on.
    ///
    /// What certificate acquisition works from: these are the names spaceport
    /// answers to, and so the names it needs to be trusted for.
    pub fn hosts(&self) -> BTreeSet<Host> {
        self.by_host.keys().cloned().collect()
    }

    /// The app serving `host`, if any.
    ///
    /// Case-insensitive, because `Host` headers are — but the common case is a
    /// client that already sent lowercase, and that one borrows rather than
    /// allocating.
    pub fn lookup(&self, host: &str) -> Option<&Arc<App>> {
        if host.bytes().any(|b| b.is_ascii_uppercase()) {
            self.by_host.get(host.to_ascii_lowercase().as_str())
        } else {
            self.by_host.get(host)
        }
    }

    pub fn len(&self) -> usize {
        self.by_host.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_host.is_empty()
    }
}

/// The apps spaceport is running.
#[derive(Debug)]
pub struct AppStore {
    inner: RwLock<Inner>,
    /// Bumped whenever the routes change, so that work which depends on *which
    /// hosts are served* — certificate acquisition, so far — can act on an
    /// apply instead of finding out at its next tick.
    generation: watch::Sender<u64>,
}

impl Default for AppStore {
    fn default() -> Self {
        Self {
            inner: RwLock::default(),
            generation: watch::Sender::new(0),
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    /// Ordered, so listing apps is stable between calls.
    apps: BTreeMap<AppId, Arc<App>>,
    routes: Arc<Routes>,
}

impl AppStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current routing snapshot. Cheap, and safe to hold across an await:
    /// the lock is released before this returns.
    pub fn routes(&self) -> Arc<Routes> {
        self.read().routes.clone()
    }

    /// Install `app`, replacing any app already under its id.
    ///
    /// Fails if one of its hosts is claimed by a *different* app — first claim
    /// wins, so a typo in a new manifest cannot silently steal live traffic.
    /// Re-applying the same id may keep, drop or add hosts freely.
    pub fn insert(&self, app: App) -> Result<Arc<App>> {
        let app = Arc::new(app);
        let mut inner = self.write();

        if let Some((host, owner)) = conflict(&inner.routes, &app.id, app.hosts()) {
            bail!("host `{host}` is already served by app `{owner}`");
        }

        inner.apps.insert(app.id.clone(), app.clone());
        inner.rebuild_routes();
        let routes = inner.routes.len();
        drop(inner);
        self.announce();

        // What the edge will do differently from now on, which is the part an
        // apply is ultimately about and the only place it is known exactly.
        info!(
            app = %app.id,
            hosts = %hosts(app.hosts()),
            upstream = %app.upstream,
            routes,
            "routes now send these hosts to this app",
        );

        Ok(app)
    }

    /// A handle that resolves whenever the routes change.
    ///
    /// The value is a generation counter and means nothing on its own; what
    /// matters is that it moved, and that the reader then asks
    /// [`AppStore::routes`] what it moved to.
    pub fn changed(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    /// Say that the routes are not what they were. Called with no lock held:
    /// a receiver wakes and asks for the routes, and should not find them held
    /// by the thread that just told it to look.
    fn announce(&self) {
        self.generation.send_modify(|generation| *generation += 1);
    }

    /// The first of `hosts` another app already serves, and which app that is.
    ///
    /// [`AppStore::insert`] enforces this too — this is for asking *before*
    /// doing the expensive part of an apply, so a manifest that could never be
    /// routed does not get a container started for it first.
    pub fn conflict(&self, id: &AppId, hosts: &[Host]) -> Option<(Host, AppId)> {
        conflict(&self.read().routes, id, hosts)
    }

    /// Drop the app under `id`, along with its routes.
    pub fn remove(&self, id: &AppId) -> Option<Arc<App>> {
        let mut inner = self.write();
        let removed = inner.apps.remove(id)?;
        inner.rebuild_routes();
        let routes = inner.routes.len();
        drop(inner);
        self.announce();

        info!(
            app = %id,
            hosts = %hosts(removed.hosts()),
            routes,
            "routes no longer serve these hosts",
        );

        Some(removed)
    }

    pub fn get(&self, id: &AppId) -> Option<Arc<App>> {
        self.read().apps.get(id).cloned()
    }

    /// Every app, by id.
    pub fn apps(&self) -> Vec<Arc<App>> {
        self.read().apps.values().cloned().collect()
    }

    /// A poisoned lock means some other thread panicked mid-mutation. Nothing
    /// here can repair that, and serving from a half-built table would be worse
    /// than stopping.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().expect("app store lock poisoned")
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().expect("app store lock poisoned")
    }
}

/// The hosts as one field, because an event carries values rather than lists.
fn hosts(hosts: &[Host]) -> String {
    hosts
        .iter()
        .map(Host::as_str)
        .collect::<Vec<&str>>()
        .join(", ")
}

/// Which of `hosts` is already taken by an app other than `id`.
fn conflict(routes: &Routes, id: &AppId, hosts: &[Host]) -> Option<(Host, AppId)> {
    hosts.iter().find_map(|host| {
        routes
            .by_host
            .get(host)
            .filter(|owner| owner.id != *id)
            .map(|owner| (host.clone(), owner.id.clone()))
    })
}

impl Inner {
    /// Rebuild the snapshot from scratch. Apps are few and applies are rare, so
    /// the cost buys the edge a map it never has to lock.
    fn rebuild_routes(&mut self) {
        let mut by_host = HashMap::new();
        for app in self.apps.values() {
            for host in app.hosts() {
                by_host.insert(host.clone(), app.clone());
            }
        }

        self.routes = Arc::new(Routes { by_host });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(id: &str, hosts: &[&str], port: u16) -> App {
        let hosts = hosts.join(", ");
        let manifest = AppManifest::parse(&format!(
            "schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [{hosts}]
"
        ))
        .unwrap();

        App {
            id: id.parse().unwrap(),
            manifest,
            container: ContainerId::new(format!("container-of-{id}")),
            upstream: format!("127.0.0.1:{port}").parse().unwrap(),
        }
    }

    fn upstream(store: &AppStore, host: &str) -> Option<SocketAddr> {
        store.routes().lookup(host).map(|app| app.upstream)
    }

    #[test]
    fn starts_empty() {
        let store = AppStore::new();

        assert!(store.routes().is_empty());
        assert!(store.apps().is_empty());
    }

    #[test]
    fn routes_every_host_of_an_app() {
        let store = AppStore::new();
        store
            .insert(app("hello", &["alpha.test", "beta.test"], 8080))
            .unwrap();

        let expected = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(upstream(&store, "alpha.test"), Some(expected));
        assert_eq!(upstream(&store, "beta.test"), Some(expected));
        assert_eq!(store.routes().len(), 2);
    }

    #[test]
    fn does_not_route_an_unknown_host() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();

        assert!(upstream(&store, "nope.test").is_none());
    }

    #[test]
    fn looks_hosts_up_case_insensitively() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();

        assert!(upstream(&store, "ALPHA.Test").is_some());
    }

    #[test]
    fn refuses_a_host_another_app_already_serves() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();

        let err = store
            .insert(app("other", &["alpha.test"], 9090))
            .unwrap_err()
            .to_string();

        assert!(err.contains("already served by app `hello`"), "{err}");
        // The rejected app is not half-installed.
        assert_eq!(store.apps().len(), 1);
        assert_eq!(upstream(&store, "alpha.test").unwrap().port(), 8080);
    }

    #[test]
    fn re_applying_an_app_replaces_it() {
        let store = AppStore::new();
        store
            .insert(app("hello", &["alpha.test", "beta.test"], 8080))
            .unwrap();
        store
            .insert(app("hello", &["alpha.test", "gamma.test"], 9090))
            .unwrap();

        assert_eq!(store.apps().len(), 1);
        assert_eq!(upstream(&store, "alpha.test").unwrap().port(), 9090);
        assert_eq!(upstream(&store, "gamma.test").unwrap().port(), 9090);
        // The host it stopped claiming stops routing.
        assert!(upstream(&store, "beta.test").is_none());
    }

    #[test]
    fn removing_an_app_drops_its_routes() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();

        let removed = store.remove(&"hello".parse().unwrap()).unwrap();

        assert_eq!(removed.id.as_str(), "hello");
        assert!(store.routes().is_empty());
        assert!(store.get(&"hello".parse().unwrap()).is_none());
    }

    #[test]
    fn removing_an_unknown_app_is_a_no_op() {
        let store = AppStore::new();
        assert!(store.remove(&"ghost".parse().unwrap()).is_none());
    }

    #[test]
    fn a_snapshot_keeps_serving_after_a_change() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();

        let snapshot = store.routes();
        store.remove(&"hello".parse().unwrap());

        assert!(snapshot.lookup("alpha.test").is_some());
        assert!(store.routes().lookup("alpha.test").is_none());
    }

    #[test]
    fn lists_apps_in_a_stable_order() {
        let store = AppStore::new();
        store.insert(app("zulu", &["z.test"], 8080)).unwrap();
        store.insert(app("alpha", &["a.test"], 8081)).unwrap();

        let ids: Vec<_> = store.apps().iter().map(|app| app.id.to_string()).collect();
        assert_eq!(ids, ["alpha", "zulu"]);
    }
}

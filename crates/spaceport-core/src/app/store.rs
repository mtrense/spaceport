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
//!
//! A suspended app stays in the table. It is not served — a request for one of
//! its hosts is answered rather than forwarded — but the hosts are still its
//! own, and that one decision settles three questions at once: another app
//! cannot take a suspended app's host out from under it, so resuming always
//! works; the edge can tell "suspended" from "never heard of it"; and
//! [`Routes::hosts`], which is where certificate acquisition gets its names,
//! goes on naming a suspended app's hosts, so its certificates go on being
//! renewed and are valid the moment it comes back.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use anyhow::{Result, bail};
use tokio::sync::watch;
use tracing::info;

use super::AppId;
use super::manifest::{AppManifest, Host};
use crate::runtime::{Adopted, ContainerId};

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

/// An app that is recorded and claims its hosts, but that spaceport has been
/// told not to run for now.
///
/// It keeps its manifest, because that is what resuming it starts, and the id
/// of the container it was left with, because that is what resuming it starts
/// *from*. The container is optional: an app applied straight into suspension
/// never had one, and one suspended with `--stop-container` may have had its
/// container removed by hand since.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suspended {
    pub id: AppId,
    pub manifest: AppManifest,
    /// The container it is holding on to, as the engine last reported it.
    ///
    /// A suspended app that was not stopped keeps a *running* container — it is
    /// simply not routed to — and that one still has its address, which is what
    /// makes suspending and resuming cost nothing by default. One suspended
    /// with `--stop-container` has only an id, because a stopped container is
    /// published nowhere until it is started again.
    pub container: Option<Adopted>,
}

impl Suspended {
    /// The hosts it goes on claiming.
    pub fn hosts(&self) -> &[Host] {
        &self.manifest.routing.hosts
    }
}

/// What the edge finds when it looks up a host.
#[derive(Debug, Clone)]
pub enum Route {
    /// An app that is running. Forward to it.
    Live(Arc<App>),
    /// An app that is suspended. Answer for it, and do not forward.
    Suspended(AppId),
}

impl Route {
    /// Whose route this is, running or not.
    pub fn app(&self) -> &AppId {
        match self {
            Self::Live(app) => &app.id,
            Self::Suspended(id) => id,
        }
    }

    /// The app to forward to, if this route leads to one.
    pub fn live(&self) -> Option<&Arc<App>> {
        match self {
            Self::Live(app) => Some(app),
            Self::Suspended(_) => None,
        }
    }
}

/// An immutable host-to-app map: what the edge sees.
#[derive(Debug, Default)]
pub struct Routes {
    by_host: HashMap<Host, Route>,
}

impl Routes {
    /// Every host spaceport answers to.
    ///
    /// What certificate acquisition works from: these are the names spaceport
    /// answers to, and so the names it needs to be trusted for. A suspended
    /// app's hosts are in here, which is what keeps its certificates renewed
    /// while it is down — an app comes back to traffic it can serve, not to a
    /// handshake it cannot complete.
    pub fn hosts(&self) -> BTreeSet<Host> {
        self.by_host.keys().cloned().collect()
    }

    /// What `host` leads to, if anything.
    ///
    /// Case-insensitive, because `Host` headers are — but the common case is a
    /// client that already sent lowercase, and that one borrows rather than
    /// allocating.
    pub fn lookup(&self, host: &str) -> Option<&Route> {
        if host.bytes().any(|b| b.is_ascii_uppercase()) {
            self.by_host.get(host.to_ascii_lowercase().as_str())
        } else {
            self.by_host.get(host)
        }
    }

    /// The app serving `host`, if one is.
    pub fn serving(&self, host: &str) -> Option<&Arc<App>> {
        self.lookup(host).and_then(Route::live)
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
    /// The apps that are recorded and claiming hosts but are not being run.
    ///
    /// Kept apart from `apps` rather than as a flag on one map, because almost
    /// everything that asks the store for apps means the running ones and
    /// would have to remember to filter. The two maps are disjoint: an id is in
    /// one or the other, never both.
    suspended: BTreeMap<AppId, Suspended>,
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
            bail!("host `{host}` is already claimed by app `{owner}`");
        }

        // An app that starts is no longer a suspended one, however it got here:
        // resuming it, or applying over it without `--suspended`.
        inner.suspended.remove(&app.id);
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

    /// Stop serving the app under `id`, without giving up its hosts.
    ///
    /// The routes stay, pointing at a suspended app instead of a running one,
    /// so its hosts keep being spoken for and keep being certified. What it
    /// stops doing is receiving traffic.
    ///
    /// Returns the app as it was running, or `None` if no *running* app is
    /// under that id — suspending a suspended app is a question for the caller,
    /// which knows whether there is a record behind it.
    pub fn suspend(&self, id: &AppId, container: Option<Adopted>) -> Option<Arc<App>> {
        let mut inner = self.write();
        let app = inner.apps.remove(id)?;

        inner.suspended.insert(
            id.clone(),
            Suspended {
                id: id.clone(),
                manifest: app.manifest.clone(),
                container,
            },
        );
        inner.rebuild_routes();
        drop(inner);
        self.announce();

        info!(
            app = %id,
            hosts = %hosts(app.hosts()),
            "routes still claim these hosts but no longer serve them",
        );

        Some(app)
    }

    /// Put a suspended app into the store without ever having run it.
    ///
    /// What `apply --suspended` and a restart of an already-suspended app both
    /// do. Conflict-checked like an insert, because claiming hosts is exactly
    /// what it is for.
    pub fn insert_suspended(&self, suspended: Suspended) -> Result<()> {
        let mut inner = self.write();

        if let Some((host, owner)) = conflict(&inner.routes, &suspended.id, suspended.hosts()) {
            bail!("host `{host}` is already claimed by app `{owner}`");
        }

        let id = suspended.id.clone();
        let claimed = hosts(suspended.hosts());
        inner.apps.remove(&id);
        inner.suspended.insert(id.clone(), suspended);
        inner.rebuild_routes();
        drop(inner);
        self.announce();

        info!(app = %id, hosts = %claimed, "app is suspended and claims these hosts without serving them");

        Ok(())
    }

    /// Drop the app under `id`, along with its routes — running or suspended.
    pub fn remove(&self, id: &AppId) -> Option<Removed> {
        let mut inner = self.write();
        let removed = match inner.apps.remove(id) {
            Some(app) => Removed::Live(app),
            None => Removed::Suspended(Box::new(inner.suspended.remove(id)?)),
        };
        inner.rebuild_routes();
        let routes = inner.routes.len();
        drop(inner);
        self.announce();

        info!(
            app = %id,
            hosts = %hosts(removed.hosts()),
            routes,
            "routes no longer claim these hosts",
        );

        Some(removed)
    }

    pub fn get(&self, id: &AppId) -> Option<Arc<App>> {
        self.read().apps.get(id).cloned()
    }

    /// The suspended app under `id`, if it is suspended.
    pub fn suspended(&self, id: &AppId) -> Option<Suspended> {
        self.read().suspended.get(id).cloned()
    }

    /// Note that a suspended app's container has stopped.
    ///
    /// Its address goes with it: an ephemeral published port belongs to a run
    /// of a container, so where it lands next is not knowable until it starts
    /// again — and must be asked for rather than remembered.
    ///
    /// Does not touch the routes — a suspended app is not served either way —
    /// so no announcement, and nothing for certificate acquisition to wake up
    /// for.
    pub fn stopped(&self, id: &AppId) -> bool {
        let mut inner = self.write();
        let Some(app) = inner.suspended.get_mut(id) else {
            return false;
        };

        app.container = app
            .container
            .as_ref()
            .map(|container| Adopted::Stopped(container.id().clone()));

        true
    }

    /// Every running app, by id.
    ///
    /// Running: a suspended app is not in here. Everything that asks the store
    /// what it has means the apps it is serving — health probes, the status
    /// report's reachability counts — and a suspended app has nothing to
    /// answer.
    pub fn apps(&self) -> Vec<Arc<App>> {
        self.read().apps.values().cloned().collect()
    }

    /// Every suspended app, by id.
    pub fn suspended_apps(&self) -> Vec<Suspended> {
        self.read().suspended.values().cloned().collect()
    }

    /// Every container this store is accounting for, running app or suspended.
    ///
    /// What a sweep checks against: a container in here belongs to an app
    /// spaceport knows about and is not a leftover, and a suspended app's
    /// container is exactly the one a sweep must not mistake for one.
    pub fn containers(&self) -> Vec<ContainerId> {
        let inner = self.read();

        inner
            .apps
            .values()
            .map(|app| app.container.clone())
            .chain(
                inner
                    .suspended
                    .values()
                    .filter_map(|app| app.container.as_ref())
                    .map(|container| container.id().clone()),
            )
            .collect()
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

/// An app that was in the store, as it was when it was taken out.
///
/// Destroying an app has the same three steps either way — unroute it, forget
/// it, remove its container — and the only thing that differs is whether there
/// is a container to remove, which a suspended app may not have.
///
/// The suspended side is boxed, as in [`crate::app::Applied`]: it carries a
/// whole manifest where the live side carries an `Arc`.
#[derive(Debug, Clone)]
pub enum Removed {
    Live(Arc<App>),
    Suspended(Box<Suspended>),
}

impl Removed {
    pub fn id(&self) -> &AppId {
        match self {
            Self::Live(app) => &app.id,
            Self::Suspended(app) => &app.id,
        }
    }

    pub fn manifest(&self) -> &AppManifest {
        match self {
            Self::Live(app) => &app.manifest,
            Self::Suspended(app) => &app.manifest,
        }
    }

    pub fn hosts(&self) -> &[Host] {
        &self.manifest().routing.hosts
    }

    /// The container to take down with it, if it had one.
    pub fn container(&self) -> Option<&ContainerId> {
        match self {
            Self::Live(app) => Some(&app.container),
            Self::Suspended(app) => app.container.as_ref().map(Adopted::id),
        }
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
///
/// Taken, not served: a suspended app holds its hosts against every other app
/// exactly as a running one does. Anything else and an app could not be counted
/// on to come back — the operator would resume it and find its name gone.
fn conflict(routes: &Routes, id: &AppId, hosts: &[Host]) -> Option<(Host, AppId)> {
    hosts.iter().find_map(|host| {
        routes
            .by_host
            .get(host)
            .filter(|route| route.app() != id)
            .map(|route| (host.clone(), route.app().clone()))
    })
}

impl Inner {
    /// Rebuild the snapshot from scratch. Apps are few and applies are rare, so
    /// the cost buys the edge a map it never has to lock.
    fn rebuild_routes(&mut self) {
        let mut by_host = HashMap::new();
        for app in self.apps.values() {
            for host in app.hosts() {
                by_host.insert(host.clone(), Route::Live(app.clone()));
            }
        }
        for app in self.suspended.values() {
            for host in app.hosts() {
                by_host.insert(host.clone(), Route::Suspended(app.id.clone()));
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

    fn suspended(id: &str, hosts: &[&str]) -> Suspended {
        let app = app(id, hosts, 1);

        Suspended {
            id: app.id,
            manifest: app.manifest,
            container: None,
        }
    }

    fn upstream(store: &AppStore, host: &str) -> Option<SocketAddr> {
        store.routes().serving(host).map(|app| app.upstream)
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

        assert!(err.contains("already claimed by app `hello`"), "{err}");
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

        assert_eq!(removed.id().as_str(), "hello");
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

        assert!(snapshot.serving("alpha.test").is_some());
        assert!(store.routes().lookup("alpha.test").is_none());
    }

    #[test]
    fn a_suspended_app_is_routed_but_not_served() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();

        let was = store.suspend(&"hello".parse().unwrap(), None).unwrap();

        assert_eq!(was.upstream.port(), 8080);
        // The host is still spoken for — that is what the edge answers 503 on.
        assert!(store.routes().lookup("alpha.test").is_some());
        assert!(store.routes().serving("alpha.test").is_none());
        // And it is no longer one of the apps that are running.
        assert!(store.apps().is_empty());
        assert!(store.get(&"hello".parse().unwrap()).is_none());
        assert_eq!(store.suspended_apps().len(), 1);
    }

    /// The reason hosts stay claimed: an app that could lose its name while
    /// suspended could not be counted on to come back.
    #[test]
    fn a_suspended_app_keeps_its_hosts_from_another_app() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();
        store.suspend(&"hello".parse().unwrap(), None);

        let err = store
            .insert(app("other", &["alpha.test"], 9090))
            .unwrap_err()
            .to_string();

        assert!(err.contains("already claimed by app `hello`"), "{err}");
    }

    /// Certificates are acquired for every name spaceport answers to, and a
    /// suspended app is still one of them — so that resuming it does not then
    /// wait on a challenge.
    #[test]
    fn a_suspended_app_still_asks_for_certificates() {
        let store = AppStore::new();
        store
            .insert(app("hello", &["alpha.test", "beta.test"], 8080))
            .unwrap();
        store.suspend(&"hello".parse().unwrap(), None);

        let hosts = store.routes().hosts();
        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains("alpha.test"));
        assert!(hosts.contains("beta.test"));
    }

    #[test]
    fn suspending_an_app_that_is_not_running_says_so() {
        let store = AppStore::new();
        assert!(store.suspend(&"ghost".parse().unwrap(), None).is_none());
    }

    #[test]
    fn an_app_can_be_suspended_without_ever_having_run() {
        let store = AppStore::new();

        store
            .insert_suspended(suspended("hello", &["alpha.test"]))
            .unwrap();

        assert!(store.routes().lookup("alpha.test").is_some());
        assert!(store.routes().serving("alpha.test").is_none());
        assert!(store.apps().is_empty());
    }

    #[test]
    fn suspending_an_app_over_a_claimed_host_is_refused() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();

        let err = store
            .insert_suspended(suspended("other", &["alpha.test"]))
            .unwrap_err()
            .to_string();

        assert!(err.contains("already claimed by app `hello`"), "{err}");
    }

    #[test]
    fn starting_a_suspended_app_makes_it_live_again() {
        let store = AppStore::new();
        store
            .insert_suspended(suspended("hello", &["alpha.test"]))
            .unwrap();

        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();

        assert_eq!(upstream(&store, "alpha.test").unwrap().port(), 8080);
        assert!(store.suspended_apps().is_empty());
        assert_eq!(store.apps().len(), 1);
    }

    #[test]
    fn removing_a_suspended_app_drops_its_claim() {
        let store = AppStore::new();
        store
            .insert_suspended(suspended("hello", &["alpha.test"]))
            .unwrap();

        let removed = store.remove(&"hello".parse().unwrap()).unwrap();

        assert_eq!(removed.id().as_str(), "hello");
        assert!(removed.container().is_none());
        assert!(store.routes().is_empty());
        assert!(store.suspended_apps().is_empty());
    }

    /// What a sweep checks against: a suspended app's container is spoken for
    /// and must not be mistaken for a leftover.
    #[test]
    fn counts_the_containers_of_running_and_suspended_apps_alike() {
        let store = AppStore::new();
        store.insert(app("running", &["a.test"], 8080)).unwrap();
        store.insert(app("kept", &["b.test"], 8081)).unwrap();
        store.suspend(
            &"kept".parse().unwrap(),
            Some(Adopted::Stopped(ContainerId::new("container-of-kept"))),
        );

        let containers = store.containers();

        assert_eq!(containers.len(), 2);
        assert!(containers.contains(&ContainerId::new("container-of-running")));
        assert!(containers.contains(&ContainerId::new("container-of-kept")));
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

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
//!
//! An app the supervisor has taken out of the table because its container died
//! is in exactly the same position, and is kept the same way. The difference is
//! only in what an operator should read into it — one is a decision, the other
//! is a fault — and so it is only a difference in what the edge says and what a
//! status reports, never in what is claimed.
//!
//! One entry in the table belongs to no app at all: the host spaceport answers
//! to as itself, configured as `edge.hostname` and served in spaceport's own
//! process. It could have been a check in front of the edge instead, and is not,
//! because being a route is what buys everything an address needs — the host is
//! claimed against every app that will ever be applied, [`Routes::hosts`] names
//! it so it is certified and renewed like any other, and the edge reaches it by
//! the one lookup it already does. The only thing it does not do is forward.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use anyhow::{Result, bail};
use tokio::sync::watch;
use tracing::{info, warn};

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

/// An app that is recorded and claims its hosts, and that spaceport is failing
/// to run.
///
/// What the supervisor puts an app into the moment its container stops being
/// one, and takes it out of when it has started it again. It carries only what
/// starting it again needs — there is no container, because the container is
/// the thing that has gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Downed {
    pub id: AppId,
    pub manifest: AppManifest,
    /// What the supervisor last saw go wrong, in the words an operator will
    /// read in a status report.
    pub reason: String,
}

impl Downed {
    /// The hosts it goes on claiming while it is not serving.
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
    /// An app that should be running and is not. Answer for it too — the same
    /// answer as for a suspended one, because the caller can do the same thing
    /// about both, which is to come back — and say something different, because
    /// the operator cannot.
    Down(AppId),
    /// The host spaceport answers to as itself. Served in-process rather than
    /// forwarded anywhere, and belonging to no app.
    ///
    /// A route rather than a check in front of the edge on purpose: being in
    /// the table is what claims the host against every app, what gets it a
    /// certificate, and what makes it reachable by exactly the same lookup as
    /// everything else.
    Spaceport,
}

impl Route {
    /// Whose route this is, running or not. `None` for spaceport's own host,
    /// which is nobody's.
    pub fn app(&self) -> Option<&AppId> {
        match self {
            Self::Live(app) => Some(&app.id),
            Self::Suspended(id) | Self::Down(id) => Some(id),
            Self::Spaceport => None,
        }
    }

    /// The app to forward to, if this route leads to one.
    pub fn live(&self) -> Option<&Arc<App>> {
        match self {
            Self::Live(app) => Some(app),
            Self::Suspended(_) | Self::Down(_) | Self::Spaceport => None,
        }
    }
}

/// Who holds a host another app asked for.
///
/// An app is the usual answer and spaceport itself is the other one, and they
/// read differently to an operator: one is a name to negotiate for, the other
/// is a name to pick again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    App(AppId),
    Spaceport,
}

impl std::fmt::Display for Claim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::App(id) => write!(f, "app `{id}`"),
            Self::Spaceport => f.write_str("spaceport itself"),
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
    /// The host spaceport answers to as itself, if it was given one. Not an
    /// app, and so not in any of the three maps — but in every routing table
    /// they build, which is the whole point of it being here.
    hostname: Option<Host>,
    /// Ordered, so listing apps is stable between calls.
    apps: BTreeMap<AppId, Arc<App>>,
    /// The apps that are recorded and claiming hosts but are not being run.
    ///
    /// Kept apart from `apps` rather than as a flag on one map, because almost
    /// everything that asks the store for apps means the running ones and
    /// would have to remember to filter.
    suspended: BTreeMap<AppId, Suspended>,
    /// The apps that should be running and are not, as the supervisor found
    /// them.
    ///
    /// Apart from `suspended` for the same reason `suspended` is apart from
    /// `apps`: an operator asking which apps are deliberately down must not be
    /// told about the ones that are down because something broke. The three
    /// maps are disjoint — an id is in exactly one of them, never two.
    down: BTreeMap<AppId, Downed>,
    routes: Arc<Routes>,
}

impl AppStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A store whose routing table also answers to `hostname` as spaceport
    /// itself.
    ///
    /// The host is claimed from the first table onwards, before any app has
    /// been applied, so there is no window in which an app could take it.
    pub fn answering_to(hostname: Option<Host>) -> Self {
        let store = Self::default();
        if let Some(hostname) = hostname {
            let mut inner = store.write();
            inner.hostname = Some(hostname);
            inner.rebuild_routes();
        }

        store
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
            bail!("host `{host}` is already claimed by {owner}");
        }

        // An app that starts is no longer a suspended one, however it got here:
        // resuming it, or applying over it without `--suspended`. Nor is it a
        // down one — this is exactly what the supervisor does about that.
        inner.suspended.remove(&app.id);
        inner.down.remove(&app.id);
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

    /// The first of `hosts` that is already spoken for, and who by.
    ///
    /// [`AppStore::insert`] enforces this too — this is for asking *before*
    /// doing the expensive part of an apply, so a manifest that could never be
    /// routed does not get a container started for it first.
    pub fn conflict(&self, id: &AppId, hosts: &[Host]) -> Option<(Host, Claim)> {
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
            bail!("host `{host}` is already claimed by {owner}");
        }

        let id = suspended.id.clone();
        let claimed = hosts(suspended.hosts());
        inner.apps.remove(&id);
        // Suspending outranks being down: an app an operator has taken out of
        // service is not one the supervisor should go on trying to start.
        inner.down.remove(&id);
        inner.suspended.insert(id.clone(), suspended);
        inner.rebuild_routes();
        drop(inner);
        self.announce();

        info!(app = %id, hosts = %claimed, "app is suspended and claims these hosts without serving them");

        Ok(())
    }

    /// Take the app under `id` out of service without giving up its hosts,
    /// because it is not serving whether spaceport likes it or not.
    ///
    /// The counterpart of [`AppStore::suspend`], and it keeps the same promise:
    /// the hosts stay claimed, so nothing else can take them while spaceport is
    /// getting the app back, and the certificates for them go on being renewed.
    /// What differs is the answer the edge gives and what a status calls it.
    ///
    /// Returns the app as it was running, or `None` if no *running* app is
    /// under that id — an app that is already down is left as it was, reason
    /// and all, because the first thing that went wrong is the one worth
    /// reporting.
    pub fn take_down(&self, id: &AppId, reason: impl Into<String>) -> Option<Arc<App>> {
        let mut inner = self.write();
        let app = inner.apps.remove(id)?;
        let reason = reason.into();

        inner.down.insert(
            id.clone(),
            Downed {
                id: id.clone(),
                manifest: app.manifest.clone(),
                reason: reason.clone(),
            },
        );
        inner.rebuild_routes();
        drop(inner);
        self.announce();

        warn!(
            app = %id,
            hosts = %hosts(app.hosts()),
            reason = %reason,
            "the app is not serving, and its hosts are answered rather than forwarded",
        );

        Some(app)
    }

    /// Put an app that was never running into the down map: recorded, claiming
    /// its hosts, and known to be broken.
    ///
    /// What a restore that failed leaves behind, so that an app which could not
    /// be started at boot is supervised from then on rather than only being
    /// mentioned once in the startup log.
    pub fn insert_down(&self, downed: Downed) -> Result<()> {
        let mut inner = self.write();

        if let Some((host, owner)) = conflict(&inner.routes, &downed.id, downed.hosts()) {
            bail!("host `{host}` is already claimed by {owner}");
        }

        let id = downed.id.clone();
        let claimed = hosts(downed.hosts());
        let reason = downed.reason.clone();
        inner.apps.remove(&id);
        inner.suspended.remove(&id);
        inner.down.insert(id.clone(), downed);
        inner.rebuild_routes();
        drop(inner);
        self.announce();

        warn!(app = %id, hosts = %claimed, %reason, "app is not running and claims these hosts without serving them");

        Ok(())
    }

    /// Say something new about why an app that is already down is down.
    ///
    /// What a failed attempt to start it again leaves behind. Touches no
    /// routes — it was not serving before and it is not serving now — so
    /// nothing is announced and nothing wakes up for it.
    ///
    /// Does nothing for an app that is not down, which is the right answer for
    /// an attempt that was overtaken by an operator applying the app in the
    /// meantime: that app is running, and last week's reason is not news.
    pub fn note_down(&self, id: &AppId, reason: impl Into<String>) -> bool {
        let mut inner = self.write();
        let Some(down) = inner.down.get_mut(id) else {
            return false;
        };
        down.reason = reason.into();

        true
    }

    /// The down app under `id`, if it is one.
    pub fn downed(&self, id: &AppId) -> Option<Downed> {
        self.read().down.get(id).cloned()
    }

    /// Every app that should be running and is not.
    pub fn down_apps(&self) -> Vec<Downed> {
        self.read().down.values().cloned().collect()
    }

    /// Drop the app under `id`, along with its routes — running, suspended or
    /// down.
    pub fn remove(&self, id: &AppId) -> Option<Removed> {
        let mut inner = self.write();
        let removed = match inner.apps.remove(id) {
            Some(app) => Removed::Live(app),
            None => match inner.suspended.remove(id) {
                Some(app) => Removed::Suspended(Box::new(app)),
                None => Removed::Down(Box::new(inner.down.remove(id)?)),
            },
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
/// The suspended and down sides are boxed, as in [`crate::app::Applied`]: they
/// carry a whole manifest where the live side carries an `Arc`.
#[derive(Debug, Clone)]
pub enum Removed {
    Live(Arc<App>),
    Suspended(Box<Suspended>),
    Down(Box<Downed>),
}

impl Removed {
    pub fn id(&self) -> &AppId {
        match self {
            Self::Live(app) => &app.id,
            Self::Suspended(app) => &app.id,
            Self::Down(app) => &app.id,
        }
    }

    pub fn manifest(&self) -> &AppManifest {
        match self {
            Self::Live(app) => &app.manifest,
            Self::Suspended(app) => &app.manifest,
            Self::Down(app) => &app.manifest,
        }
    }

    pub fn hosts(&self) -> &[Host] {
        &self.manifest().routing.hosts
    }

    /// The container to take down with it, if it had one. A down app has none:
    /// its container going is what put it there.
    pub fn container(&self) -> Option<&ContainerId> {
        match self {
            Self::Live(app) => Some(&app.container),
            Self::Suspended(app) => app.container.as_ref().map(Adopted::id),
            Self::Down(_) => None,
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

/// Which of `hosts` is already taken by someone other than `id`.
///
/// Taken, not served: a suspended app holds its hosts against every other app
/// exactly as a running one does. Anything else and an app could not be counted
/// on to come back — the operator would resume it and find its name gone.
///
/// Spaceport's own hostname is taken by nobody who will ever give it up, which
/// is why the answer says who holds a host rather than which app does.
fn conflict(routes: &Routes, id: &AppId, hosts: &[Host]) -> Option<(Host, Claim)> {
    hosts.iter().find_map(|host| {
        let claim = match routes.by_host.get(host)? {
            // Its own host, which it may keep, drop or re-claim freely.
            route if route.app() == Some(id) => return None,
            Route::Spaceport => Claim::Spaceport,
            route => Claim::App(route.app()?.clone()),
        };

        Some((host.clone(), claim))
    })
}

impl Inner {
    /// Rebuild the snapshot from scratch. Apps are few and applies are rare, so
    /// the cost buys the edge a map it never has to lock.
    fn rebuild_routes(&mut self) {
        let mut by_host = HashMap::new();
        // Spaceport's own host goes in last, so that it wins the map outright
        // rather than only by the conflict checks having done their job. The
        // checks are what tell an operator why their app was refused; this is
        // what makes it true whatever else went in.
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
        for app in self.down.values() {
            for host in app.hosts() {
                by_host.insert(host.clone(), Route::Down(app.id.clone()));
            }
        }
        if let Some(hostname) = &self.hostname {
            by_host.insert(hostname.clone(), Route::Spaceport);
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
auth:
  gating: open
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

    fn downed(id: &str, hosts: &[&str], reason: &str) -> Downed {
        let app = app(id, hosts, 1);

        Downed {
            id: app.id,
            manifest: app.manifest,
            reason: reason.to_owned(),
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

    #[test]
    fn a_down_app_is_routed_but_not_served() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();

        let was = store
            .take_down(&"hello".parse().unwrap(), "the container stopped")
            .unwrap();

        assert_eq!(was.upstream.port(), 8080);
        // The host is still spoken for — that is what the edge answers 503 on.
        assert!(store.routes().lookup("alpha.test").is_some());
        assert!(store.routes().serving("alpha.test").is_none());
        // And it is no longer one of the apps that are running.
        assert!(store.apps().is_empty());
        assert!(store.get(&"hello".parse().unwrap()).is_none());
        assert_eq!(store.down_apps().len(), 1);
    }

    /// The hosts stay claimed while the supervisor works: an app that lost its
    /// name the moment its container died could not be started again.
    #[test]
    fn a_down_app_keeps_its_hosts_from_another_app() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();
        store.take_down(&"hello".parse().unwrap(), "the container stopped");

        let err = store
            .insert(app("other", &["alpha.test"], 9090))
            .unwrap_err()
            .to_string();

        assert!(err.contains("already claimed by app `hello`"), "{err}");
    }

    /// Certificates are acquired for every name spaceport answers to, and a
    /// down app is still one of them — so that an app comes back to traffic it
    /// can serve rather than to a handshake it cannot complete.
    #[test]
    fn a_down_app_still_asks_for_certificates() {
        let store = AppStore::new();
        store
            .insert(app("hello", &["alpha.test", "beta.test"], 8080))
            .unwrap();
        store.take_down(&"hello".parse().unwrap(), "the container stopped");

        let hosts = store.routes().hosts();
        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains("alpha.test"));
        assert!(hosts.contains("beta.test"));
    }

    #[test]
    fn taking_down_an_app_that_is_not_running_says_so() {
        let store = AppStore::new();
        assert!(
            store
                .take_down(&"ghost".parse().unwrap(), "the container stopped")
                .is_none()
        );
    }

    /// The supervisor sees an app fail more than once, and the first thing that
    /// went wrong is the one worth reporting — a later, vaguer reason
    /// overwriting it would lose the fault an operator is looking for.
    #[test]
    fn taking_down_an_app_that_is_already_down_leaves_the_first_reason_alone() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();
        let id: AppId = "hello".parse().unwrap();

        store.take_down(&id, "the container exited with 1").unwrap();
        // Nothing to take down any more, which is how the first reason survives.
        assert!(store.take_down(&id, "the container is gone").is_none());

        assert_eq!(
            store.downed(&id).unwrap().reason,
            "the container exited with 1"
        );
        assert_eq!(store.down_apps().len(), 1);
    }

    #[test]
    fn starting_a_down_app_makes_it_live_again() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();
        store.take_down(&"hello".parse().unwrap(), "the container stopped");

        store.insert(app("hello", &["alpha.test"], 9090)).unwrap();

        assert_eq!(upstream(&store, "alpha.test").unwrap().port(), 9090);
        assert!(store.down_apps().is_empty());
        assert_eq!(store.apps().len(), 1);
    }

    /// An attempt to start a down app that fails again says something newer
    /// about why, and an attempt overtaken by an operator applying the app must
    /// not put last week's reason back on a running one.
    #[test]
    fn saying_why_an_app_is_down_only_lands_on_an_app_that_is_down() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();
        let id: AppId = "hello".parse().unwrap();
        store.take_down(&id, "the container stopped");

        assert!(store.note_down(&id, "the image is not there"));
        assert_eq!(store.downed(&id).unwrap().reason, "the image is not there");

        store.insert(app("hello", &["alpha.test"], 9090)).unwrap();
        assert!(!store.note_down(&id, "still nothing"));
    }

    /// Suspending outranks being down: an app an operator has taken out of
    /// service is not one the supervisor should go on trying to start.
    #[test]
    fn suspending_a_down_app_takes_it_out_of_the_down_apps() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();
        store.take_down(&"hello".parse().unwrap(), "the container stopped");

        store
            .insert_suspended(suspended("hello", &["alpha.test"]))
            .unwrap();

        assert!(store.down_apps().is_empty());
        assert_eq!(store.suspended_apps().len(), 1);
        assert!(matches!(
            store.routes().lookup("alpha.test"),
            Some(Route::Suspended(_))
        ));
    }

    #[test]
    fn removing_a_down_app_drops_its_claim() {
        let store = AppStore::new();
        store
            .insert_down(downed("hello", &["alpha.test"], "the container stopped"))
            .unwrap();

        let removed = store.remove(&"hello".parse().unwrap()).unwrap();

        assert_eq!(removed.id().as_str(), "hello");
        assert!(matches!(removed, Removed::Down(_)));
        // Its container going is what put it there, so there is none to remove.
        assert!(removed.container().is_none());
        assert!(store.routes().is_empty());
        assert!(store.down_apps().is_empty());
    }

    #[test]
    fn recording_a_down_app_over_a_claimed_host_is_refused() {
        let store = AppStore::new();
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();

        let err = store
            .insert_down(downed("other", &["alpha.test"], "the container stopped"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("already claimed by app `hello`"), "{err}");
        assert!(store.down_apps().is_empty());
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

    /// A store with a hostname of spaceport's own.
    fn answering_to(hostname: &str) -> AppStore {
        AppStore::answering_to(Some(hostname.parse().unwrap()))
    }

    /// Reachable by the same lookup as everything else — that is what makes it
    /// "routed like an app" rather than a special case in front of the edge.
    #[test]
    fn routes_its_own_hostname() {
        let store = answering_to("spaceport.test");

        assert!(matches!(
            store.routes().lookup("spaceport.test"),
            Some(Route::Spaceport)
        ));
        // Nothing to forward to: it is served in spaceport's own process.
        assert!(store.routes().serving("spaceport.test").is_none());
        assert!(store.apps().is_empty());
    }

    #[test]
    fn has_no_host_of_its_own_unless_configured() {
        assert!(AppStore::answering_to(None).routes().is_empty());
    }

    #[test]
    fn looks_its_own_hostname_up_case_insensitively() {
        let store = answering_to("spaceport.test");

        assert!(store.routes().lookup("Spaceport.TEST").is_some());
    }

    /// The claim holds from the very first routing table, before any app has
    /// been applied — there is no window in which one could take it.
    #[test]
    fn refuses_an_app_that_wants_spaceports_own_hostname() {
        let store = answering_to("spaceport.test");

        let err = store
            .insert(app("thief", &["spaceport.test"], 8080))
            .unwrap_err()
            .to_string();

        assert!(err.contains("already claimed by spaceport itself"), "{err}");
        assert!(store.apps().is_empty());
        assert!(matches!(
            store.routes().lookup("spaceport.test"),
            Some(Route::Spaceport)
        ));
    }

    /// Refused before the expensive part of an apply, like any other conflict.
    #[test]
    fn says_who_holds_its_own_hostname_before_anything_is_started() {
        let store = answering_to("spaceport.test");
        let hosts: [Host; 1] = ["spaceport.test".parse().unwrap()];

        let (host, claim) = store.conflict(&"thief".parse().unwrap(), &hosts).unwrap();

        assert_eq!(host.as_str(), "spaceport.test");
        assert_eq!(claim, Claim::Spaceport);
        assert_eq!(claim.to_string(), "spaceport itself");
    }

    #[test]
    fn refuses_a_suspended_or_down_app_over_its_own_hostname_too() {
        let store = answering_to("spaceport.test");

        let suspending = store
            .insert_suspended(suspended("thief", &["spaceport.test"]))
            .unwrap_err()
            .to_string();
        let downing = store
            .insert_down(downed("thief", &["spaceport.test"], "never started"))
            .unwrap_err()
            .to_string();

        assert!(
            suspending.contains("claimed by spaceport itself"),
            "{suspending}"
        );
        assert!(downing.contains("claimed by spaceport itself"), "{downing}");
    }

    /// Certificates are acquired for every name spaceport answers to, and its
    /// own is one of them — an address an outside service is given has to
    /// complete a handshake like any other.
    #[test]
    fn its_own_hostname_asks_for_a_certificate() {
        let store = answering_to("spaceport.test");
        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();

        let hosts = store.routes().hosts();

        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains("spaceport.test"));
        assert!(hosts.contains("alpha.test"));
    }

    /// Every mutation rebuilds the table from scratch, and the host has to
    /// survive all of them — it is not an app, so nothing else would put it back.
    #[test]
    fn keeps_its_own_hostname_across_every_rebuild() {
        let store = answering_to("spaceport.test");
        let id: AppId = "hello".parse().unwrap();

        store.insert(app("hello", &["alpha.test"], 8080)).unwrap();
        store.suspend(&id, None);
        store.insert(app("hello", &["alpha.test"], 9090)).unwrap();
        store.take_down(&id, "the container stopped");
        store.remove(&id);

        assert!(matches!(
            store.routes().lookup("spaceport.test"),
            Some(Route::Spaceport)
        ));
        assert_eq!(store.routes().len(), 1);
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

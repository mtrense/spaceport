//! Running an app's container.
//!
//! Spaceport talks to a container engine through [`ContainerRuntime`], which
//! exists so that the apply path — the interesting logic — can be exercised
//! without a daemon, and so a second engine can be added without touching it.
//!
//! The runtime's whole job is to turn a manifest into an address the edge can
//! forward to. How it gets there is its own business; what comes back is a
//! [`Container`], and that is all the rest of spaceport knows about it.

pub mod docker;

use std::fmt;
use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;

use crate::app::{AppId, AppManifest};

pub use docker::DockerRuntime;

/// A container engine's handle on a container.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContainerId(String);

impl ContainerId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Container ids are 64 hex characters and nothing reads past the
        // first few, which is also all `docker ps` shows.
        f.write_str(&self.0[..self.0.len().min(12)])
    }
}

/// A running container, and where to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub id: ContainerId,
    /// The loopback address the engine published the container's port on.
    pub upstream: SocketAddr,
}

/// A container this runtime is running on spaceport's behalf, as found rather
/// than as started.
///
/// This is how a restarted spaceport sees what the one before it left behind.
/// The app is optional because the label can be missing or unreadable, and a
/// container spaceport marked as its own is still its own to clean up even when
/// it can no longer say whose it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Managed {
    pub id: ContainerId,
    pub app: Option<AppId>,
}

/// A container the engine already has for an app, which the app's manifest
/// would have produced.
///
/// The two cases are the same container answering two different questions.
/// `Running` has an address, because it is up and the edge could forward to it
/// now. `Stopped` has only an id, because a stopped container publishes no
/// port — where it lands is decided when it is started, and is not knowable
/// until then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Adopted {
    /// Up, and reachable here.
    Running(Container),
    /// Not up. Spaceport stopped it, or it exited on its own.
    Stopped(ContainerId),
}

impl Adopted {
    pub fn id(&self) -> &ContainerId {
        match self {
            Self::Running(container) => &container.id,
            Self::Stopped(id) => id,
        }
    }
}

/// A container engine spaceport can run apps on.
#[async_trait]
pub trait ContainerRuntime: Send + Sync {
    /// Start `manifest` as the app named `app`, replacing any container this
    /// runtime is already running under that name.
    ///
    /// Returns only once the container is started and its port is published —
    /// not once the app inside it is ready to serve. Readiness is what health
    /// checks are for, and they do not exist yet.
    async fn launch(&self, app: &AppId, manifest: &AppManifest) -> Result<Container>;

    /// The container this runtime *already* has for `app`, if it is one this
    /// manifest would have produced — running or not.
    ///
    /// This is what makes a restart of spaceport cheap: the apps it was running
    /// keep running, and it only has to find out where they ended up. Returning
    /// `None` is always allowed and always safe — it costs the app a relaunch,
    /// which is what every restart used to cost — so anything the engine cannot
    /// vouch for it should decline rather than guess at.
    ///
    /// A stopped container is reported rather than skipped, because a suspended
    /// app's container is stopped on purpose and is the one to start again when
    /// it resumes. What makes it adoptable is the same as for a running one:
    /// spaceport's label, and the image its manifest names.
    ///
    /// Note what adoption deliberately does *not* do: re-resolve the image. A
    /// container started from `:latest` a week ago is adopted as it is, tag
    /// moved or not. Restarting spaceport is not a way to redeploy an app;
    /// applying its manifest again is.
    ///
    /// The default is to adopt nothing, for an engine that cannot tell.
    async fn adopt(&self, app: &AppId, manifest: &AppManifest) -> Result<Option<Adopted>> {
        let _ = (app, manifest);

        Ok(None)
    }

    /// Stop a container without deleting it, so that it can be started again.
    ///
    /// What suspending an app with `--stop-container` does. The container keeps
    /// its name, its labels and its writable layer; all it gives up is the port
    /// it was published on, which it gets a new one of when it starts again.
    ///
    /// Succeeds if it is already stopped, and if it is already gone: both mean
    /// what the caller asked for is true.
    async fn stop(&self, id: &ContainerId) -> Result<()>;

    /// Start a container this runtime stopped earlier, and find out where its
    /// port ended up this time.
    ///
    /// The address must not be assumed to be the one it had before: an
    /// ephemeral published port belongs to a run of a container rather than to
    /// the container. A resumed app is routed to wherever the engine has just
    /// put it — which is the whole reason this returns a [`Container`] rather
    /// than nothing — and the engine is as free to hand back the port it just
    /// freed as it is to pick another.
    ///
    /// The manifest is here to say which of the container's ports to publish,
    /// and for no other reason: the caller has already decided this is the
    /// right container.
    async fn start(&self, id: &ContainerId, manifest: &AppManifest) -> Result<Container>;

    /// Stop and delete a container. Succeeds if it is already gone.
    async fn remove(&self, id: &ContainerId) -> Result<()>;

    /// What this engine is, in a few words for an operator to read.
    ///
    /// Asked of the engine rather than remembered, so that an answer arriving
    /// at all is itself the news: this is how a status report finds out that
    /// the daemon everything else depends on has gone away.
    ///
    /// The default is for engines that have nothing to say about themselves,
    /// which is no real one.
    async fn engine(&self) -> Result<String> {
        Ok("an engine that does not name itself".to_owned())
    }

    /// Every container this runtime is running for spaceport, running or not.
    ///
    /// Spaceport's containers outlive the spaceport that started them, so this
    /// is what a restart reconciles against: anything here that no app is
    /// recorded for is a leftover, and nothing else may be touched.
    async fn managed(&self) -> Result<Vec<Managed>>;
}

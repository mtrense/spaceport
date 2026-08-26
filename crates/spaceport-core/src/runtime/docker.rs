//! The docker engine, spoken to over its API socket.
//!
//! Containers are published on an ephemeral loopback port rather than joined
//! to a network spaceport shares: the edge then reaches an app the same way
//! anything else on the host would, and nothing about the app's networking has
//! to be understood beyond "which port did the engine give it?".
//!
//! Every container spaceport creates is named and labelled after its app. The
//! name is what makes re-applying a manifest idempotent — the old container is
//! found and removed by name, and found and adopted by name across a restart —
//! and the label is what lets a restarted spaceport find every container it
//! left behind, including the ones no app is named for any more.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use bollard::Docker;
use bollard::errors::Error as DockerError;
use bollard::models::{
    ContainerCreateBody, EventMessage, HostConfig, Mount, MountType, PortBinding, PortMap,
};
use bollard::query_parameters::{
    BuildImageOptionsBuilder, CreateContainerOptionsBuilder, CreateImageOptionsBuilder,
    EventsOptionsBuilder, InspectContainerOptions, ListContainersOptionsBuilder,
    RemoveContainerOptionsBuilder, StartContainerOptions, StopContainerOptionsBuilder,
};
use futures_util::{StreamExt, stream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::{Adopted, Container, ContainerId, ContainerRuntime, Events, Managed, RuntimeEvent};
use crate::app::data::{DataDir, Owner};
use crate::app::manifest::Source;
use crate::app::{AppId, AppManifest, Auth};
use crate::build::image::{BuildRequest, BuiltImage, ImageBuilder};

/// Marks a container as spaceport's, and says whose it is.
const MANAGED_LABEL: &str = "spaceport.managed";
const APP_LABEL: &str = "spaceport.app";

/// Records what the container was created from, so a manifest that has changed
/// in a way the engine cannot be asked about — an environment variable, a
/// volume — is noticed the next time the container is looked at.
const SPEC_LABEL: &str = "spaceport.spec";

/// How long the engine waits for a container to exit before killing it.
const STOP_TIMEOUT: i32 = 10;

/// The docker daemon.
pub struct DockerRuntime {
    docker: Docker,

    /// Where the volumes an app asks for are made. Held here because it is
    /// the runtime that has to have them on disk before a container starts.
    data: DataDir,

    /// `https://<edge.hostname>` — what a gated app's container receives as
    /// `SPACEPORT_ISSUER`, with the JWKS URL derived from it. Held here
    /// because the runtime is what fixes a container's environment at
    /// creation, and absent when the config named no hostname — in which case
    /// a gated app cannot be signed into anyway, and the two URL variables
    /// are withheld rather than invented.
    issuer: Option<String>,
}

impl DockerRuntime {
    /// Connect the way the docker CLI would, honouring `DOCKER_HOST`.
    ///
    /// Connecting is lazy — nothing reaches the daemon until the first
    /// request — so this succeeding does not mean there is a daemon there.
    /// Use [`DockerRuntime::ping`] to find that out at startup rather than at
    /// the first apply.
    pub fn connect(data: DataDir, issuer: Option<String>) -> Result<Self> {
        let docker = Docker::connect_with_defaults().context("connecting to the docker daemon")?;

        Ok(Self {
            docker,
            data,
            issuer,
        })
    }

    /// Check that the daemon is actually there and talking.
    pub async fn ping(&self) -> Result<()> {
        let version = self
            .docker
            .version()
            .await
            .context("the docker daemon did not answer")?;

        debug!(
            version = version.version.as_deref().unwrap_or("unknown"),
            api = version.api_version.as_deref().unwrap_or("unknown"),
            "connected to docker",
        );

        Ok(())
    }

    /// What `image` says about itself, pulling it if the daemon does not have
    /// it yet.
    ///
    /// The pull is not optional even when the manifest names a port: the
    /// engine will not fetch an image on its own when a container is created
    /// from it, so an image that is not here yet has to be fetched here.
    async fn image_config(&self, image: &str) -> Result<ImageConfig> {
        let config = match self.docker.inspect_image(image).await {
            Ok(inspect) => inspect,
            Err(error) if is_not_found(&error) => {
                info!(image, "pulling image");
                self.pull(image).await?;
                self.docker
                    .inspect_image(image)
                    .await
                    .with_context(|| format!("inspecting image `{image}`"))?
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting image `{image}`"));
            }
        }
        .config
        .unwrap_or_default();

        Ok(ImageConfig {
            exposed: config.exposed_ports.unwrap_or_default(),
            user: config.user.unwrap_or_default(),
        })
    }

    async fn pull(&self, image: &str) -> Result<()> {
        let options = CreateImageOptionsBuilder::new().from_image(image).build();
        let mut progress = self.docker.create_image(Some(options), None, None);

        // The stream is progress reporting; what matters is that every item
        // arrives without an error and the stream ends.
        while let Some(item) = progress.next().await {
            item.with_context(|| format!("pulling image `{image}`"))?;
        }

        Ok(())
    }

    /// Where the engine published `port` for a running container.
    async fn published_upstream(&self, id: &str, port: u16) -> Result<SocketAddr> {
        let inspect = self
            .docker
            .inspect_container(id, None::<InspectContainerOptions>)
            .await
            .context("inspecting the container just started")?;

        let ports = inspect
            .network_settings
            .and_then(|settings| settings.ports)
            .unwrap_or_default();

        published_upstream(&ports, port)
    }

    /// Delete a container by name or id, saying whether there was one.
    async fn remove_container(&self, container: &str) -> Result<bool> {
        let options = RemoveContainerOptionsBuilder::new().force(true).build();

        match self.docker.remove_container(container, Some(options)).await {
            Ok(()) => Ok(true),
            Err(error) if is_not_found(&error) => Ok(false),
            Err(error) => Err(error).with_context(|| format!("removing container `{container}`")),
        }
    }
}

#[async_trait]
impl ContainerRuntime for DockerRuntime {
    async fn launch(&self, app: &AppId, manifest: &AppManifest) -> Result<Container> {
        let image = match &manifest.source {
            Source::Image { image } => image.as_str(),
            Source::Build { .. } => {
                bail!("app `{app}` builds its own image, which spaceport cannot do yet")
            }
        };

        let config = self.image_config(image).await?;
        let port = container_port(manifest.container.port, image, &config.exposed)?;
        let name = container_name(app);

        let mounts = self.provision(app, manifest, &config.user).await?;

        // Re-applying an app replaces it, so whatever is running under this
        // name is on its way out either way.
        if self.remove_container(&name).await? {
            debug!(app = %app, container = name, "removed the previous container");
        }

        let body = ContainerCreateBody {
            image: Some(image.to_owned()),
            env: Some(environment(app, manifest, self.issuer.as_deref())?),
            labels: Some(HashMap::from([
                (MANAGED_LABEL.to_owned(), "true".to_owned()),
                (APP_LABEL.to_owned(), app.to_string()),
                (
                    SPEC_LABEL.to_owned(),
                    self.fingerprint(app, image, manifest),
                ),
            ])),
            host_config: Some(HostConfig {
                port_bindings: Some(loopback_binding(port)),
                mounts: Some(mounts),
                ..Default::default()
            }),
            ..Default::default()
        };

        let created = self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::new().name(&name).build()),
                body,
            )
            .await
            .with_context(|| format!("creating a container for app `{app}` from `{image}`"))?;

        for warning in &created.warnings {
            debug!(app = %app, warning, "docker warned about the container");
        }

        // From here on the container exists, so any failure has to take it
        // back down rather than leave a stopped shell behind under a name the
        // next apply would silently reuse.
        match self.run(&created.id, port).await {
            Ok(upstream) => {
                let id = ContainerId::new(created.id);
                info!(app = %app, container = %id, %upstream, "app started");

                Ok(Container { id, upstream })
            }
            Err(error) => {
                let _ = self.remove_container(&created.id).await;
                Err(error.context(format!("starting app `{app}`")))
            }
        }
    }

    async fn adopt(&self, app: &AppId, manifest: &AppManifest) -> Result<Option<Adopted>> {
        // Every question below is asked of the container the engine already
        // has, and of nothing else: no image is inspected, and nothing is
        // pulled. A restart of spaceport must not depend on a registry being
        // reachable to bring back apps that never stopped running.
        let Source::Image { image } = &manifest.source else {
            return Ok(None);
        };

        let name = container_name(app);
        let inspect = match self
            .docker
            .inspect_container(&name, None::<InspectContainerOptions>)
            .await
        {
            Ok(inspect) => inspect,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting container `{name}`"));
            }
        };

        let Some(id) = inspect.id.map(ContainerId::new) else {
            return Ok(None);
        };

        let running = inspect.state.and_then(|state| state.running) == Some(true);
        let config = inspect.config.unwrap_or_default();

        // The name is spaceport's own, but the label is what says so. A
        // container under this name that spaceport did not create is somebody
        // else's, and adopting it would route traffic into it.
        if config
            .labels
            .as_ref()
            .and_then(|labels| labels.get(MANAGED_LABEL))
            .map(String::as_str)
            != Some("true")
        {
            warn!(app = %app, container = %id, "a container named `{name}` is not spaceport's, so it is not adopted");
            return Ok(None);
        }

        // Not the image *id*: two manifests can resolve to the same digest and
        // it is the manifest this container was created from that says whether
        // it is still the right container.
        if config.image.as_deref() != Some(image.as_str()) {
            debug!(app = %app, container = %id, running = ?config.image, wanted = %image, "the container from before runs another image");
            return Ok(None);
        }

        // The image is only half the question. Everything else a manifest
        // decides about a container — its environment, its volumes — is fixed
        // at creation and cannot be changed on a container that already
        // exists, so a manifest that has moved on since means this container
        // has to be replaced rather than adopted.
        let labels = config.labels.unwrap_or_default();
        match labels.get(SPEC_LABEL) {
            Some(spec) if spec == &self.fingerprint(app, image, manifest) => {}
            Some(_) => {
                debug!(app = %app, container = %id, "the container from before was created from an older manifest");
                return Ok(None);
            }
            // Created by a spaceport that had no configuration to record. Such
            // a container has no environment and no volumes, so it still
            // matches any manifest that asks for none — and an upgrade that
            // restarted every app on the host to relabel it would be a far
            // worse answer than leaving the ones that still fit alone.
            // The secrets are asked about here as well as the environment, so
            // that this branch is safe by what it reads rather than by the
            // validation two modules away which says a declared secret must be
            // interpolated by some env value.
            None if manifest.container.env.is_empty()
                && manifest.container.volumes.is_empty()
                && manifest.container.secrets.is_empty() => {}
            None => {
                debug!(app = %app, container = %id, "the container from before predates app configuration");
                return Ok(None);
            }
        }

        // This far, the container is the one this manifest describes. Whether
        // it happens to be up is a separate question, and one a suspended app
        // has already answered on purpose.
        if !running {
            debug!(app = %app, container = %id, "the container from before is not running");
            return Ok(Some(Adopted::Stopped(id)));
        }

        // Both of these can only fail for a container spaceport would refuse
        // to launch anyway, so they decline rather than report: whatever the
        // real problem is, `launch` is about to say it properly.
        let Ok(port) = container_port(
            manifest.container.port,
            image,
            &config.exposed_ports.unwrap_or_default(),
        ) else {
            return Ok(None);
        };
        let ports = inspect
            .network_settings
            .and_then(|settings| settings.ports)
            .unwrap_or_default();
        let upstream = match published_upstream(&ports, port) {
            Ok(upstream) => upstream,
            Err(error) => {
                debug!(app = %app, container = %id, %error, "cannot reach the container from before");
                return Ok(None);
            }
        };

        Ok(Some(Adopted::Running(Container { id, upstream })))
    }

    async fn stop(&self, id: &ContainerId) -> Result<()> {
        let options = StopContainerOptionsBuilder::new().t(STOP_TIMEOUT).build();

        match self.docker.stop_container(id.as_str(), Some(options)).await {
            Ok(()) => Ok(()),
            // Already gone, or already stopped. Either way the container is not
            // running, which is all this was asked to arrange.
            Err(error) if is_not_found(&error) || is_not_modified(&error) => Ok(()),
            Err(error) => Err(error).with_context(|| format!("stopping container {id}")),
        }
    }

    async fn start(&self, id: &ContainerId, manifest: &AppManifest) -> Result<Container> {
        // Asked of the container rather than of the image, for the same reason
        // adoption is: resuming an app must not depend on a registry being
        // reachable, and the ports this container has are the ones it was
        // created with whatever the image says today.
        let inspect = self
            .docker
            .inspect_container(id.as_str(), None::<InspectContainerOptions>)
            .await
            .with_context(|| format!("inspecting container {id}"))?;

        let image = match &manifest.source {
            Source::Image { image } => image.as_str(),
            Source::Build { .. } => bail!("that container's app builds its own image"),
        };
        let config = inspect.config.unwrap_or_default();
        let exposed = config.exposed_ports.clone().unwrap_or_default();
        let port = container_port(manifest.container.port, image, &exposed)?;

        // The container's binds were fixed when it was created, but the
        // directories they point at are on the host and may not have survived
        // whatever stopped it. Docker would make the missing ones itself, as
        // root, which is how an app that ran fine yesterday comes back unable
        // to write to its own volume.
        //
        // Asked of the container rather than the image for the same reason as
        // the ports above: the engine copied the image's user in at creation,
        // so there is no image to inspect and no registry to depend on.
        if let Some(app) = config
            .labels
            .as_ref()
            .and_then(|labels| labels.get(APP_LABEL))
            .and_then(|app| app.parse::<AppId>().ok())
        {
            let user = config.user.clone().unwrap_or_default();
            self.provision(&app, manifest, &user).await?;
        }

        let upstream = self
            .run(id.as_str(), port)
            .await
            .with_context(|| format!("starting container {id} again"))?;
        info!(container = %id, %upstream, "container started again");

        Ok(Container {
            id: id.clone(),
            upstream,
        })
    }

    async fn remove(&self, id: &ContainerId) -> Result<()> {
        let options = StopContainerOptionsBuilder::new().t(STOP_TIMEOUT).build();

        // A container that is already stopped is not an error here; only one
        // that refuses to go away is.
        match self.docker.stop_container(id.as_str(), Some(options)).await {
            Ok(()) => {}
            Err(error) if is_not_found(&error) => return Ok(()),
            Err(error) => return Err(error).with_context(|| format!("stopping container {id}")),
        }

        self.remove_container(id.as_str()).await?;

        Ok(())
    }

    async fn engine(&self) -> Result<String> {
        let version = self
            .docker
            .version()
            .await
            .context("the docker daemon did not answer")?;
        let unknown = || "unknown".to_owned();

        Ok(format!(
            "docker {} (api {})",
            version.version.unwrap_or_else(unknown),
            version.api_version.unwrap_or_else(unknown),
        ))
    }

    async fn managed(&self) -> Result<Vec<Managed>> {
        // `all`, not just the running ones: a container that died while
        // spaceport was down is still spaceport's to account for, and one left
        // stopped under an app's name is exactly what the next launch would
        // collide with.
        let managed = format!("{MANAGED_LABEL}=true");
        let options = ListContainersOptionsBuilder::new()
            .all(true)
            .filters(&HashMap::from([("label", vec![managed.as_str()])]))
            .build();

        let containers = self
            .docker
            .list_containers(Some(options))
            .await
            .context("listing the containers spaceport manages")?;

        Ok(containers
            .into_iter()
            .filter_map(|container| {
                let id = ContainerId::new(container.id?);
                let app = container
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(APP_LABEL))
                    .and_then(|app| match app.parse::<AppId>() {
                        Ok(app) => Some(app),
                        Err(error) => {
                            warn!(container = %id, label = app, %error, "a spaceport container is labelled with an id spaceport cannot read");
                            None
                        }
                    });

                // The daemon's own word for it, and the only one that means
                // running: `restarting`, `paused` and `exited` are all
                // containers that are not serving.
                let running = container.state
                    == Some(bollard::models::ContainerSummaryStateEnum::RUNNING);

                Some(Managed { id, app, running })
            })
            .collect())
    }

    fn watch(&self) -> Events {
        // The daemon is asked for spaceport's containers only, and only for the
        // three things that mean one has stopped serving. Everything else the
        // daemon has to say about a container is something spaceport asked it
        // to do.
        let docker = self.docker.clone();
        let (events, mut received) = mpsc::channel(WATCH_BUFFER);
        tokio::spawn(pump(docker, events));

        // The task ends when this stream is dropped, because that is when the
        // channel it is sending into closes.
        Box::pin(stream::poll_fn(move |context| received.poll_recv(context)))
    }
}

/// How many events may be waiting while the supervisor deals with one.
///
/// Generous, because a docker daemon restarting reports every container it is
/// taking down at once and the supervisor may be several seconds into a
/// restart when it does. Overflowing is not a disaster — the supervisor sweeps
/// on a timer regardless — but it is a lost second.
const WATCH_BUFFER: usize = 256;

/// How long to wait before asking the daemon for its events again.
///
/// The stream ends whenever the daemon is restarted or the socket goes, and
/// neither is a reason to stop supervising: spaceport outlives the daemon it
/// talks to, and this is how it comes back to it.
const RECONNECT: Duration = Duration::from_secs(5);

/// Read the daemon's event stream into `events` forever, reconnecting whenever
/// it breaks and saying so when it does.
async fn pump(docker: Docker, events: mpsc::Sender<RuntimeEvent>) {
    let managed = format!("{MANAGED_LABEL}=true");
    let filters = HashMap::from([
        ("type", vec!["container"]),
        ("label", vec![managed.as_str()]),
        ("event", vec!["die", "oom", "destroy"]),
    ]);
    let options = EventsOptionsBuilder::new().filters(&filters).build();

    // The first connection is not a reconnection: whoever is watching has just
    // asked for the stream and has not missed anything yet.
    let mut interrupted = false;
    loop {
        if interrupted && events.send(RuntimeEvent::Desynchronised).await.is_err() {
            return;
        }

        let mut stream = docker.events(Some(options.clone()));
        while let Some(message) = stream.next().await {
            match message {
                Ok(message) => {
                    let Some(event) = translate(&message) else {
                        continue;
                    };
                    if events.send(event).await.is_err() {
                        return;
                    }
                }
                Err(error) => {
                    debug!(%error, "the docker event stream broke");
                    break;
                }
            }
        }

        interrupted = true;
        tokio::time::sleep(RECONNECT).await;
    }
}

/// What one of the daemon's messages means to spaceport, if it means anything.
///
/// A message spaceport cannot place — no id, an action it did not ask for — is
/// dropped rather than guessed at. The supervisor's sweep is what catches
/// anything this cannot read.
fn translate(message: &EventMessage) -> Option<RuntimeEvent> {
    let actor = message.actor.as_ref()?;
    let container = ContainerId::new(actor.id.clone()?);
    let attributes = actor.attributes.as_ref();

    // Straight off the event: a container that has been removed cannot be
    // inspected afterwards, so the label it carried is the only thing that can
    // still say whose it was.
    let app = attributes
        .and_then(|attributes| attributes.get(APP_LABEL))
        .and_then(|app| match app.parse::<AppId>() {
            Ok(app) => Some(app),
            Err(error) => {
                warn!(container = %container, label = app, %error, "a spaceport container reported an id spaceport cannot read");
                None
            }
        });

    match message.action.as_deref()? {
        "die" => Some(RuntimeEvent::Died {
            container,
            app,
            // The daemon reports it as an attribute, as a string, and only
            // sometimes. A status nobody can read is the same as none.
            exit_code: attributes
                .and_then(|attributes| attributes.get("exitCode"))
                .and_then(|code| code.parse().ok()),
        }),
        "oom" => Some(RuntimeEvent::OutOfMemory { container, app }),
        "destroy" => Some(RuntimeEvent::Destroyed { container, app }),
        _ => None,
    }
}

impl DockerRuntime {
    /// Start a container and find out where it ended up.
    ///
    /// Not called `start`: that is the trait's, and this is the half of it that
    /// both starting a container spaceport just created and starting one it
    /// stopped earlier have in common.
    async fn run(&self, id: &str, port: u16) -> Result<SocketAddr> {
        self.docker
            .start_container(id, None::<StartContainerOptions>)
            .await
            .context("starting the container")?;

        self.published_upstream(id, port).await
    }

    /// Make sure every volume the manifest asks for exists on the host, and
    /// describe them the way the engine wants them.
    ///
    /// Blocking file work, on the runtime's own thread: creating a handful of
    /// directories is not worth a `spawn_blocking`, and it happens once per
    /// launch rather than once per request.
    async fn provision(
        &self,
        app: &AppId,
        manifest: &AppManifest,
        user: &str,
    ) -> Result<Vec<Mount>> {
        let volumes = &manifest.container.volumes;
        if volumes.is_empty() {
            return Ok(Vec::new());
        }

        // An empty `User` means the container runs as root, which owns the
        // directories anyway. It is the user the image named and spaceport
        // could not resolve that is worth saying something about.
        let owner = Owner::parse(user);
        if owner.is_none() && !user.trim().is_empty() {
            self.data.warn_unresolved_owner(app, volumes, user.trim());
        }

        self.data.create()?;

        let mut mounts = Vec::with_capacity(volumes.len());
        for volume in volumes {
            let source = self.data.provision(app, volume, owner)?;

            mounts.push(Mount {
                typ: Some(MountType::BIND),
                source: Some(source.to_string_lossy().into_owned()),
                target: Some(volume.mount.to_string_lossy().into_owned()),
                read_only: Some(volume.read_only),
                ..Default::default()
            });
        }

        Ok(mounts)
    }

    fn fingerprint(&self, app: &AppId, image: &str, manifest: &AppManifest) -> String {
        fingerprint(&self.data, app, image, manifest, self.issuer.as_deref())
    }
}

/// How many lines of a build's log spaceport keeps.
///
/// A build is free to print as much as it likes, and some do: a package
/// manager fetching a thousand dependencies is a thousand lines nobody will
/// read. The log is kept because a failed build's output is the only thing
/// that explains it, and what explains one is the end of it — so this is a cap
/// on the tail rather than a truncation of the head. Uncapped, a single
/// unlucky `RUN` would put a megabyte into the event stream and another into
/// the database, for every build, forever.
const MAX_LOG_LINES: usize = 500;

/// How many of those lines an error message carries.
///
/// An operator reading "the build failed" wants the last thing the build said,
/// not its whole output; the rest is on the build record.
const LOG_TAIL: usize = 20;

/// Building is implemented on [`DockerRuntime`] rather than on a `DockerBuilder`
/// of its own because the daemon handle is already here, along with the
/// connecting and the ping that say whether there is a daemon to talk to at
/// all. A second type would either clone the client or open a second connection
/// to the same socket, and would have to be constructed and checked in parallel
/// with this one everywhere spaceport starts up. Building an image and running
/// a container are two things asked of one engine.
#[async_trait]
impl ImageBuilder for DockerRuntime {
    async fn build(&self, request: &BuildRequest) -> Result<BuiltImage> {
        // Non-UTF-8 is refused rather than lossily converted: a path that went
        // through `to_string_lossy` would name a file that is not there, and
        // the daemon's complaint would be about the replacement characters.
        let dockerfile = request.dockerfile.to_str().ok_or_else(|| {
            anyhow!(
                "the dockerfile path `{}` is not utf-8",
                request.dockerfile.display()
            )
        })?;

        // Walking and reading a source tree is blocking work, and unlike the
        // handful of directories `provision` makes it is proportional to the
        // size of the repository. It goes on the blocking pool so that a large
        // context does not stall the reactor the edge is serving on.
        let context = request.context.clone();
        let tar = tokio::task::spawn_blocking(move || pack(&context))
            .await
            .context("packing the build context")??;

        let labels: HashMap<String, String> = request
            .labels
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();

        // `version` is left at its default, `BuilderVersion::BuilderV1`. Asking
        // for version 2 without bollard's `buildkit` feature reaches a branch
        // bollard itself documents as "should not be possible" and panics
        // there — the classic builder is the only one this build of spaceport
        // has. `nocache` is left at its default too: a context is a fresh
        // unpacked commit, so the cache can only ever hit on layers that really
        // are the same.
        let options = BuildImageOptionsBuilder::new()
            .dockerfile(dockerfile)
            .t(&request.tag)
            .labels(&labels)
            .rm(true)
            .build();

        info!(tag = request.tag, "building image");

        // Hazard: `build_image` *unwraps* its tar argument, so a call that
        // passes `None` panics rather than failing. There is exactly one call
        // and the body is always `Some`; nothing here may be refactored into a
        // shape where it is optional.
        //
        // It is also not an async fn — it returns a stream borrowing the client
        // — so the stream is created and drained here, inside a method that
        // holds `&self`, and never handed back to a caller.
        let mut progress =
            self.docker
                .build_image(options, None, Some(bollard::body_full(tar.into())));

        let mut log = VecDeque::new();
        let mut id = None;

        while let Some(item) = progress.next().await {
            // Bollard turns a build step's `errorDetail` into a stream error,
            // so a Dockerfile that failed and a socket that broke arrive the
            // same way. Both mean there is no image, and both are worth the
            // log: it is what says which of the two happened.
            let info = match item {
                Ok(info) => info,
                Err(error) => {
                    return Err(error).context(format!(
                        "building image `{}`{}",
                        request.tag,
                        tail(&log)
                    ));
                }
            };

            // Unlike a pull, whose progress is discarded, every line is kept.
            if let Some(stream) = info.stream {
                record(&mut log, &stream);
            }

            // Where the classic builder puts the id of what it made. With
            // bollard's `buildkit` feature this field is a different type
            // entirely, which is the whole reason there is a trait above this.
            if let Some(image) = info.aux.and_then(|aux| aux.id) {
                id = Some(image);
            }
        }

        // A stream that ended without ever carrying an `aux` is a build that
        // produced no image and did not say so, which is a failure however
        // cleanly the connection closed.
        let Some(id) = id else {
            bail!(
                "the docker daemon finished building `{}` without naming an image{}",
                request.tag,
                tail(&log),
            );
        };

        info!(tag = request.tag, image = id, "image built");

        Ok(BuiltImage {
            tag: request.tag.clone(),
            id,
            log: log.into(),
        })
    }
}

/// Pack `context` into a tar in memory, as the engine wants its build context.
///
/// In memory because that is what the daemon is going to hold anyway — the
/// whole archive is the request body — and a temporary file would only add a
/// path that has to be cleaned up after a failure.
///
/// Symlinks are packed as symlinks rather than followed. Following them would
/// let a `Dockerfile`'s neighbour — a symlink to `/etc/shadow`, say, committed
/// to a repository spaceport builds — arrive in the build context as the file
/// it points at, on the host spaceport is running on.
fn pack(context: &Path) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    builder.follow_symlinks(false);

    // An empty prefix, so entries are named the way the Dockerfile path is:
    // relative to the root of the context and with nothing in front of them.
    builder
        .append_dir_all("", context)
        .with_context(|| format!("packing the build context at `{}`", context.display()))?;

    builder
        .into_inner()
        .context("finishing the build context archive")
}

/// Keep whatever the engine has just said, in whole lines and no more than
/// [`MAX_LOG_LINES`] of them.
///
/// The engine emits fragments rather than lines — one chunk can carry several
/// lines, or half of one — so this splits on newlines and drops what is empty
/// afterwards. A log kept verbatim would be a list of arbitrary fragments,
/// which is neither what an operator reads nor what a line cap counts.
fn record(log: &mut VecDeque<String>, chunk: &str) {
    for line in chunk.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }

        if log.len() == MAX_LOG_LINES {
            log.pop_front();
        }
        log.push_back(line.to_owned());
    }
}

/// The last [`LOG_TAIL`] lines of a build's log, introduced so that an error
/// message reads as one sentence.
///
/// Empty when the build said nothing at all: a message ending in a heading with
/// nothing under it reads like something went missing.
fn tail(log: &VecDeque<String>) -> String {
    let lines: Vec<&str> = log
        .iter()
        .skip(log.len().saturating_sub(LOG_TAIL))
        .map(String::as_str)
        .collect();

    if lines.is_empty() {
        return String::new();
    }

    format!(", whose last output was:\n{}", lines.join("\n"))
}

/// What this manifest says the container should be, in 32 hex characters.
///
/// Covers what is decided when a container is created and cannot be changed
/// afterwards. The host paths go in as well as the volume names: moving the
/// data directory in the config moves the app's data, and a container still
/// bound to the old path is not the container the config now describes.
///
/// What it deliberately leaves out is the manifest's text. Two documents that
/// describe the same container have to fingerprint the same however they were
/// written, or an app would be restarted for having a comment added to it.
///
/// And what it leaves out for a second reason is any secret's value. The
/// environment goes in exactly as the manifest wrote it, `{{NAME}}` and all,
/// never as the container will actually see it. This string is hashed and the
/// digest is written onto the container as a label, which anybody who can talk
/// to the daemon can read — and a hash is only as unguessable as what went into
/// it. A database password is not a random 32 bytes; it is something somebody
/// can put through the same hash a few billion times offline.
///
/// So what stands in for the value is its `version`, one per secret the
/// manifest declares, in the manifest's own order. A counter says "not the
/// value you saw last time" and nothing else, which is the only thing the
/// fingerprint is asking — and it is what makes a changed secret replace a
/// container, since a container's environment is fixed when it is created.
/// `UNSET` marks a secret nothing has resolved, so that setting one for the
/// first time counts as a change too.
///
/// A manifest that declares no secrets fields nothing extra at all, and so
/// fingerprints exactly as it did before secrets existed. Anything else would
/// have replaced every container running on every host, on upgrade, to record
/// the absence of something none of them had.
fn fingerprint(
    data: &DataDir,
    app: &AppId,
    image: &str,
    manifest: &AppManifest,
    issuer: Option<&str>,
) -> String {
    let spec = specification(data, app, image, manifest, issuer);

    let digest = ring::digest::digest(&ring::digest::SHA256, spec.as_bytes());
    digest.as_ref()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The string a fingerprint is the digest of.
///
/// Split out from [`fingerprint`] so that a test can read what is about to be
/// hashed. Everything else about a hash can be asserted from the outside; that
/// no secret went into it cannot, because a digest looks the same either way.
fn specification(
    data: &DataDir,
    app: &AppId,
    image: &str,
    manifest: &AppManifest,
    issuer: Option<&str>,
) -> String {
    let container = &manifest.container;

    let mut spec = String::new();
    field(&mut spec, image);
    field(
        &mut spec,
        &container
            .port
            .map_or(String::new(), |port| port.to_string()),
    );

    // Already ordered: `env` is a `BTreeMap`, and the volumes are sorted by
    // the name that decides their host path.
    for (name, value) in &container.env {
        field(&mut spec, name.as_str());
        field(&mut spec, value);
    }

    // The names the manifest declares and not the ones that resolved: a value
    // sitting in the database that this manifest never asks for reaches no
    // container, so it must not restart one either.
    //
    // Sorted, for the reason the volumes below are: `secrets` is a list in a
    // document, and an operator who alphabetises it has not changed the app.
    let mut secrets: Vec<_> = container.secrets.iter().collect();
    secrets.sort();
    for secret in secrets {
        field(&mut spec, secret.as_str());
        field(
            &mut spec,
            &container
                .resolved
                .get(secret)
                .map_or_else(|| UNSET.to_owned(), |secret| secret.version.to_string()),
        );
    }

    let mut volumes: Vec<_> = container.volumes.iter().collect();
    volumes.sort_by(|a, b| a.name.cmp(&b.name));
    for volume in volumes {
        field(&mut spec, volume.name.as_str());
        field(&mut spec, &data.volume(app, &volume.name).to_string_lossy());
        field(&mut spec, &volume.mount.to_string_lossy());
        field(&mut spec, if volume.read_only { "ro" } else { "rw" });
    }

    // What spaceport itself injects — the milestone-6 `SPACEPORT_*` variables
    // — is part of a gated container's environment, and an environment fixed
    // at creation has to be replaced when it changes: a gated container from
    // before the variables existed, or from before the hostname did, must not
    // be adopted as current. Fielded via the same function that injects, so
    // the fingerprint and the environment cannot say different things — and
    // empty for `gating: open`, so every open app's fingerprint stays exactly
    // as it always was.
    for var in spaceport_environment(app, manifest, issuer) {
        field(&mut spec, &var);
    }

    spec
}

/// What an image says about itself that spaceport has to know before it can
/// create a container from it.
#[derive(Debug, Default)]
struct ImageConfig {
    /// The ports the image declares.
    exposed: Vec<String>,

    /// Who the image runs as, verbatim — see [`Owner::parse`].
    user: String,
}

/// What a fingerprint says in place of the version of a secret nothing has
/// resolved. Not a number, so that no version can ever be mistaken for it.
const UNSET: &str = "unset";

/// Append one length-prefixed field to a fingerprint.
///
/// Length-prefixed rather than separated by some character, because an
/// environment value may contain any character at all, newlines and separators
/// included. Two different specs that render to one string would mean an app
/// whose configuration changed and was never restarted.
fn field(spec: &mut String, value: &str) {
    spec.push_str(&value.len().to_string());
    spec.push(':');
    spec.push_str(value);
}

/// The environment to give a container, as the engine wants it: the manifest's
/// own values with every secret it interpolates put in, and — for a gated app
/// — the `SPACEPORT_*` variables of the JWT contract after them.
///
/// The grammar of a placeholder lives in the manifest module and is not
/// repeated here — this only turns the map that comes back into the list of
/// `NAME=value` strings docker takes. The injected names cannot collide with
/// the manifest's: the `SPACEPORT` prefix is reserved at manifest validation,
/// which exists precisely so this append never has to ask who wins.
fn environment(app: &AppId, manifest: &AppManifest, issuer: Option<&str>) -> Result<Vec<String>> {
    let mut env: Vec<String> = manifest
        .container
        .environment()?
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    env.extend(spaceport_environment(app, manifest, issuer));

    Ok(env)
}

/// The variables spaceport speaks to an app through: `SPACEPORT_APP_ID` for
/// the `aud` it must expect, `SPACEPORT_ISSUER` for the `iss`, and
/// `SPACEPORT_JWKS_URL` for where the verifying keys live.
///
/// Only for `gating: edge`, deliberately: the spec ties these variables to the
/// JWT contract, and spaceport never mints a JWT for an open app — variables
/// naming an issuer that will never issue would be an invitation to verify
/// tokens that cannot arrive. And only the two URL variables when a hostname
/// is configured: without one a gated app cannot be signed into at all (the
/// gate refuses with the same missing piece), so the app id — which needs no
/// hostname — is injected alone rather than beside invented URLs.
fn spaceport_environment(app: &AppId, manifest: &AppManifest, issuer: Option<&str>) -> Vec<String> {
    if !matches!(manifest.auth, Auth::Edge { .. }) {
        return Vec::new();
    }

    let mut vars = vec![format!("SPACEPORT_APP_ID={app}")];
    if let Some(issuer) = issuer {
        vars.push(format!("SPACEPORT_ISSUER={issuer}"));
        vars.push(format!(
            "SPACEPORT_JWKS_URL={}",
            crate::auth::jwt::jwks_url(issuer)
        ));
    }

    vars
}

/// The container name spaceport gives an app. Prefixed, so a container that is
/// not spaceport's cannot be mistaken for one that is.
fn container_name(app: &AppId) -> String {
    format!("spaceport-{app}")
}

/// The port to route an app's traffic to: what its manifest says, or what its
/// image says if the manifest does not.
///
/// The manifest wins outright and is not checked against the image. An app may
/// perfectly well listen on a port its image never declared — `EXPOSE` is
/// documentation, not configuration — and second-guessing an operator who has
/// said which port to use would only make that case impossible to express.
fn container_port(manifest: Option<u16>, image: &str, exposed: &[String]) -> Result<u16> {
    match manifest {
        Some(port) => Ok(port),
        None => single_tcp_port(image, exposed),
    }
}

/// The one TCP port `image` exposes.
///
/// Anything else is refused rather than guessed at: picking the lowest of two
/// exposed ports would work often enough to be trusted and fail silently the
/// rest of the time.
fn single_tcp_port(image: &str, exposed: &[String]) -> Result<u16> {
    let mut ports: Vec<u16> = exposed
        .iter()
        .filter_map(|port| port.strip_suffix("/tcp"))
        .filter_map(|port| port.parse().ok())
        .collect();
    ports.sort_unstable();
    ports.dedup();

    match ports.as_slice() {
        [port] => Ok(*port),
        [] => bail!(
            "image `{image}` exposes no tcp port, so set `container.port` to the port the app listens on"
        ),
        many => {
            let listed: Vec<String> = many.iter().map(u16::to_string).collect();
            bail!(
                "image `{image}` exposes {} tcp ports ({}), so set `container.port` to the one to route traffic to",
                many.len(),
                listed.join(", "),
            )
        }
    }
}

/// Ask the engine to publish `port` on a loopback port of its choosing.
///
/// Loopback, not `0.0.0.0`: an app is reachable through spaceport or not at
/// all, and a published port on every interface would quietly route around the
/// edge — no TLS, no host matching, no forwarded headers.
fn loopback_binding(port: u16) -> PortMap {
    PortMap::from([(
        format!("{port}/tcp"),
        Some(vec![PortBinding {
            host_ip: Some(Ipv4Addr::LOCALHOST.to_string()),
            // Empty rather than "0": this is what the engine reads as "any
            // free port", the same as `docker run -p 127.0.0.1::80`.
            host_port: Some(String::new()),
        }]),
    )])
}

/// The loopback address the engine published `port` on.
fn published_upstream(ports: &PortMap, port: u16) -> Result<SocketAddr> {
    let key = format!("{port}/tcp");
    let bindings = ports
        .get(&key)
        .and_then(Option::as_ref)
        .filter(|bindings| !bindings.is_empty())
        .ok_or_else(|| anyhow!("docker published no host port for {key}"))?;

    // One binding was asked for, but an image or a daemon default can add
    // others; the loopback one is the one spaceport can actually use.
    let binding = bindings
        .iter()
        .find(|binding| binding.host_ip.as_deref() == Some("127.0.0.1"))
        .ok_or_else(|| {
            anyhow!("docker published {key} off loopback, where the edge cannot use it")
        })?;

    let published: u16 = binding
        .host_port
        .as_deref()
        .unwrap_or_default()
        .parse()
        .with_context(|| format!("reading the host port docker published for {key}"))?;

    Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, published)))
}

/// Whether the daemon answered "no such thing", which is usually not an error
/// so much as an answer.
fn is_not_found(error: &DockerError) -> bool {
    matches!(
        error,
        DockerError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

/// Whether the daemon answered "it already is", which docker says by refusing
/// to change a container that is in the state it was asked for.
fn is_not_modified(error: &DockerError) -> bool {
    matches!(
        error,
        DockerError::DockerResponseServerError {
            status_code: 304,
            ..
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::StoredSecret;
    use crate::secret::Secret;

    fn exposed(ports: &[&str]) -> Vec<String> {
        ports.iter().map(|port| (*port).to_owned()).collect()
    }

    #[test]
    fn names_containers_after_their_app() {
        assert_eq!(container_name(&"hello".parse().unwrap()), "spaceport-hello");
    }

    #[test]
    fn takes_the_only_exposed_port() {
        assert_eq!(
            single_tcp_port("img", &exposed(&["8080/tcp"])).unwrap(),
            8080
        );
    }

    #[test]
    fn ignores_exposed_udp_ports() {
        assert_eq!(
            single_tcp_port("img", &exposed(&["53/udp", "8080/tcp"])).unwrap(),
            8080
        );
    }

    #[test]
    fn refuses_an_image_that_exposes_nothing() {
        let err = single_tcp_port("img", &[]).unwrap_err().to_string();
        assert!(err.contains("exposes no tcp port"), "{err}");
        assert!(err.contains("container.port"), "{err}");
    }

    #[test]
    fn takes_the_port_the_manifest_names() {
        let port = container_port(Some(3000), "img", &exposed(&["8080/tcp"])).unwrap();
        assert_eq!(port, 3000);
    }

    /// An image that spaceport could not choose a port for on its own is
    /// exactly the case `container.port` exists for, so naming one has to be
    /// enough by itself.
    #[test]
    fn takes_the_named_port_even_when_the_image_declares_none() {
        assert_eq!(container_port(Some(3000), "img", &[]).unwrap(), 3000);
    }

    #[test]
    fn falls_back_to_the_image_when_the_manifest_says_nothing() {
        let port = container_port(None, "img", &exposed(&["8080/tcp"])).unwrap();
        assert_eq!(port, 8080);
    }

    #[test]
    fn refuses_to_guess_between_exposed_ports() {
        let err = single_tcp_port("img", &exposed(&["8080/tcp", "9090/tcp"]))
            .unwrap_err()
            .to_string();

        assert!(err.contains("8080, 9090"), "{err}");
    }

    fn binding(host_ip: &str, host_port: &str) -> PortBinding {
        PortBinding {
            host_ip: Some(host_ip.to_owned()),
            host_port: Some(host_port.to_owned()),
        }
    }

    #[test]
    fn reads_the_published_loopback_port() {
        let ports = PortMap::from([(
            "80/tcp".to_owned(),
            Some(vec![binding("127.0.0.1", "49153")]),
        )]);

        assert_eq!(
            published_upstream(&ports, 80).unwrap(),
            "127.0.0.1:49153".parse().unwrap()
        );
    }

    #[test]
    fn picks_the_loopback_binding_among_several() {
        let ports = PortMap::from([(
            "80/tcp".to_owned(),
            Some(vec![binding("::", "49154"), binding("127.0.0.1", "49153")]),
        )]);

        assert_eq!(published_upstream(&ports, 80).unwrap().port(), 49153);
    }

    #[test]
    fn refuses_a_port_published_off_loopback() {
        let ports = PortMap::from([("80/tcp".to_owned(), Some(vec![binding("0.0.0.0", "49153")]))]);
        let err = published_upstream(&ports, 80).unwrap_err().to_string();

        assert!(err.contains("off loopback"), "{err}");
    }

    #[test]
    fn refuses_an_unpublished_port() {
        let ports = PortMap::from([("80/tcp".to_owned(), None)]);
        let err = published_upstream(&ports, 80).unwrap_err().to_string();

        assert!(err.contains("no host port"), "{err}");
    }

    /// A manifest built from `MINIMAL` plus an indented container section.
    fn manifest(container: &str) -> AppManifest {
        let container: String = container
            .lines()
            .map(|line| format!("  {line}\n"))
            .collect();

        AppManifest::parse(&format!(
            "schema_version: 1
source:
  type: image
  image: traefik/whoami:latest
routing:
  hosts: [alpha.test]
auth:
  gating: open
container:
{container}"
        ))
        .unwrap()
    }

    fn spec(manifest: &AppManifest) -> String {
        fingerprint(
            &data(),
            &"my-app".parse().unwrap(),
            "traefik/whoami:latest",
            manifest,
            None,
        )
    }

    /// The string a fingerprint is taken of, for the one test that has to look
    /// at what goes into the hash rather than at what comes out.
    fn spec_input(manifest: &AppManifest) -> String {
        specification(
            &data(),
            &"my-app".parse().unwrap(),
            "traefik/whoami:latest",
            manifest,
            None,
        )
    }

    fn data() -> DataDir {
        DataDir::new(std::path::PathBuf::from("/var/lib/spaceport/apps"))
    }

    fn my_app() -> AppId {
        "my-app".parse().unwrap()
    }

    /// A gated counterpart of [`manifest`], for what only `gating: edge`
    /// containers receive. Indented the same way, for the same reason.
    fn gated_manifest(container: &str) -> AppManifest {
        let container: String = container
            .lines()
            .map(|line| format!("  {line}\n"))
            .collect();

        AppManifest::parse(&format!(
            "schema_version: 1
source:
  type: image
  image: traefik/whoami:latest
routing:
  hosts: [alpha.test]
auth:
  gating: edge
  roles: [reader]
container:
{container}"
        ))
        .unwrap()
    }

    #[test]
    fn gives_the_container_its_environment_in_order() {
        let manifest = manifest("env:\n  ZULU: last\n  ALPHA: first");

        assert_eq!(
            environment(&my_app(), &manifest, None).unwrap(),
            ["ALPHA=first", "ZULU=last"]
        );
    }

    #[test]
    fn gives_a_container_with_no_environment_an_empty_one() {
        assert!(
            environment(&my_app(), &manifest("port: 80"), None)
                .unwrap()
                .is_empty()
        );
    }

    /// The JWT contract's variables, injected exactly where the contract
    /// applies: a gated container gets all three, after the manifest's own
    /// environment — whose names the reserved `SPACEPORT` prefix keeps clear.
    #[test]
    fn gives_a_gated_container_the_spaceport_variables() {
        let manifest = gated_manifest("env:\n  MODE: production");

        assert_eq!(
            environment(&my_app(), &manifest, Some("https://spaceport.test")).unwrap(),
            [
                "MODE=production",
                "SPACEPORT_APP_ID=my-app",
                "SPACEPORT_ISSUER=https://spaceport.test",
                "SPACEPORT_JWKS_URL=https://spaceport.test/.well-known/jwks.json",
            ]
        );
    }

    /// An open app is outside the JWT contract, so it gets none of the
    /// contract's variables — an issuer that will never issue to it included.
    #[test]
    fn gives_an_open_container_no_spaceport_variables() {
        let manifest = manifest("env:\n  MODE: production");

        assert_eq!(
            environment(&my_app(), &manifest, Some("https://spaceport.test")).unwrap(),
            ["MODE=production"]
        );
    }

    /// Without a hostname there is no issuer and no JWKS to point at, and a
    /// gated app cannot be signed into anyway — so only the app id, which
    /// needs no hostname, is injected rather than URLs invented from nothing.
    #[test]
    fn withholds_the_url_variables_when_no_hostname_is_configured() {
        let manifest = gated_manifest("port: 80");

        assert_eq!(
            environment(&my_app(), &manifest, None).unwrap(),
            ["SPACEPORT_APP_ID=my-app"]
        );
    }

    /// The injected variables are part of the container's fixed environment,
    /// so they are part of the fingerprint too: a gated container from before
    /// the hostname existed must be replaced, not adopted — while an open
    /// app's fingerprint stays exactly as it always was, hostname or not.
    #[test]
    fn fingerprints_the_injected_variables_for_gated_apps_only() {
        let gated = gated_manifest("port: 80");
        let open = manifest("port: 80");
        let with = |manifest: &AppManifest, issuer: Option<&str>| {
            fingerprint(
                &data(),
                &my_app(),
                "traefik/whoami:latest",
                manifest,
                issuer,
            )
        };

        assert_ne!(
            with(&gated, None),
            with(&gated, Some("https://spaceport.test"))
        );
        assert_eq!(
            with(&open, None),
            with(&open, Some("https://spaceport.test"))
        );
    }

    /// A manifest of `container` with `secrets` resolved to the given values,
    /// each at the given version.
    fn resolved(container: &str, secrets: &[(&str, &str, u64)]) -> AppManifest {
        let values = secrets
            .iter()
            .map(|(name, value, version)| {
                (
                    name.parse().unwrap(),
                    StoredSecret {
                        value: Secret::new(*value),
                        version: *version,
                    },
                )
            })
            .collect();

        manifest(container).with_secrets(values)
    }

    /// The point of the whole feature: what the app actually reads from its
    /// environment is the secret, not the name of one.
    #[test]
    fn puts_a_secret_where_the_environment_referred_to_it() {
        let manifest = resolved(
            "secrets: [DB_PASSWORD]
env:
  DATABASE_URL: postgres://user:{{DB_PASSWORD}}@db:5432/app",
            &[("DB_PASSWORD", "hunter2", 1)],
        );

        assert_eq!(
            environment(&my_app(), &manifest, None).unwrap(),
            ["DATABASE_URL=postgres://user:hunter2@db:5432/app"]
        );
    }

    /// Two secrets in one value, which is what any connection string with a
    /// user and a password looks like — a substitution that stopped after the
    /// first would leave the second as literal text in a URL.
    #[test]
    fn puts_several_secrets_into_one_value() {
        let manifest = resolved(
            "secrets: [USER, PW]
env:
  DATABASE_URL: \"postgres://{{USER}}:{{ PW }}@db/app\"",
            &[("USER", "admin", 1), ("PW", "hunter2", 1)],
        );

        assert_eq!(
            environment(&my_app(), &manifest, None).unwrap(),
            ["DATABASE_URL=postgres://admin:hunter2@db/app"]
        );
    }

    /// One secret read by two variables is the ordinary way an app and its
    /// migration tool are given the same password.
    #[test]
    fn puts_one_secret_into_every_value_that_names_it() {
        let manifest = resolved(
            "secrets: [PW]
env:
  A: \"{{PW}}\"
  B: \"before {{PW}} after\"",
            &[("PW", "hunter2", 1)],
        );

        assert_eq!(
            environment(&my_app(), &manifest, None).unwrap(),
            ["A=hunter2", "B=before hunter2 after"]
        );
    }

    /// Spaceport's own bug, not an operator's: applying refuses a manifest
    /// whose secrets are not all set, so by here a missing value means the
    /// resolution went wrong. Saying so beats handing the app a connection
    /// string with `{{DB_PASSWORD}}` in it and letting it report a database
    /// problem.
    #[test]
    fn refuses_to_run_an_app_whose_secret_never_resolved() {
        let manifest = manifest(
            "secrets: [DB_PASSWORD]
env:
  DATABASE_URL: \"pw={{DB_PASSWORD}}\"",
        );

        let err = environment(&my_app(), &manifest, None)
            .unwrap_err()
            .to_string();

        assert!(err.contains("DB_PASSWORD"), "{err}");
        assert!(err.contains("not resolved"), "{err}");
    }

    /// A container's environment is fixed when it is created, so a secret that
    /// changed only reaches the app if the fingerprint changed with it — and
    /// the document says exactly the same thing either way, so the version is
    /// the only thing that can carry the difference.
    #[test]
    fn fingerprints_a_new_version_of_a_secret_differently() {
        let container = "secrets: [PW]\nenv:\n  A: \"{{PW}}\"";
        let before = resolved(container, &[("PW", "old", 1)]);
        let after = resolved(container, &[("PW", "new", 2)]);

        assert_ne!(spec(&before), spec(&after));
        // And the text really is identical, so nothing else could have.
        assert_eq!(before.source_text(), after.source_text());
    }

    /// Setting a secret for the first time has to count as a change too, or an
    /// app that came up before its secret existed would never pick it up.
    #[test]
    fn fingerprints_an_unresolved_secret_differently_from_a_resolved_one() {
        let container = "secrets: [PW]\nenv:\n  A: \"{{PW}}\"";

        assert_ne!(
            spec(&manifest(container)),
            spec(&resolved(container, &[("PW", "hunter2", 1)]))
        );
    }

    /// A secret the manifest does not declare reaches no container, so it must
    /// not restart one. An operator setting a secret for an app that does not
    /// read it yet — or leaving an old value behind — is ordinary.
    #[test]
    fn ignores_a_resolved_secret_the_manifest_does_not_declare() {
        let container = "secrets: [PW]\nenv:\n  A: \"{{PW}}\"";
        let declared = resolved(container, &[("PW", "hunter2", 1)]);
        let with_extra = resolved(
            container,
            &[("PW", "hunter2", 1), ("LEFTOVER", "whatever", 7)],
        );

        assert_eq!(spec(&declared), spec(&with_extra));
    }

    /// The upgrade check. Every app already running was fingerprinted without
    /// secrets in the spec at all, and a manifest that declares none has to
    /// hash to the same 32 characters it did then — otherwise installing this
    /// version replaces every container on the host to record the absence of
    /// something none of them have. The digests are the ones the code produced
    /// before this field existed, written down here so that nothing can quietly
    /// change them again.
    #[test]
    fn fingerprints_a_manifest_without_secrets_as_it_always_did() {
        assert_eq!(
            spec(&manifest("port: 80")),
            "43c46231dca4c839a69e6d80d74a324f"
        );
        assert_eq!(
            spec(&manifest("port: 80\nenv:\n  MODE: production")),
            "b90145b4ab7274240ae11e39438cdc86"
        );
    }

    /// The fingerprint is a docker label, readable by anybody who can talk to
    /// the daemon, and a hash of a password somebody chose is a password
    /// somebody can guess offline. Asserted on the string that is hashed and
    /// not only on the digest, because it is the input that has to be clean.
    #[test]
    fn never_puts_a_secret_into_what_it_hashes() {
        let manifest = resolved(
            "secrets: [PW]\nenv:\n  A: \"pw={{PW}}\"",
            &[("PW", "hunter2", 1)],
        );

        let spec = spec_input(&manifest);

        assert!(!spec.contains("hunter2"), "{spec}");
        // The placeholder is what went in instead, exactly as written.
        assert!(spec.contains("{{PW}}"), "{spec}");
    }

    /// The whole point of the label: neither of these can be asked of a
    /// running container, so a fingerprint that missed them would leave an app
    /// running with the configuration it was applied with a week ago.
    #[test]
    fn fingerprints_a_changed_environment_or_volume_differently() {
        let base = manifest("env:\n  MODE: production");

        for changed in [
            "env:\n  MODE: staging",
            "env:\n  MODE: production\n  DEBUG: \"1\"",
            "env:\n  mode: production",
            "env:\n  MODE: production\nvolumes:\n  - name: data\n    mount: /data",
            "port: 8080\nenv:\n  MODE: production",
        ] {
            assert_ne!(spec(&base), spec(&manifest(changed)), "for `{changed}`");
        }
    }

    #[test]
    fn fingerprints_a_changed_volume_differently() {
        let base = manifest("volumes:\n  - name: data\n    mount: /data");

        for changed in [
            "volumes:\n  - name: cache\n    mount: /data",
            "volumes:\n  - name: data\n    mount: /var/data",
            "volumes:\n  - name: data\n    mount: /data\n    read_only: true",
        ] {
            assert_ne!(spec(&base), spec(&manifest(changed)), "for `{changed}`");
        }
    }

    /// An app that restarted because somebody reordered its manifest, or
    /// documented it, would teach an operator not to touch the file.
    #[test]
    fn fingerprints_the_same_container_the_same_however_it_was_written() {
        let one = manifest(
            "env:
  ALPHA: first
  ZULU: last
volumes:
  - name: data
    mount: /data
  - name: cache
    mount: /cache",
        );
        let other = manifest(
            "# the same app, said differently
volumes:
  - name: cache
    mount: /cache
  - name: data
    mount: /data
env:
  ZULU: last
  ALPHA: first",
        );

        assert_eq!(spec(&one), spec(&other));
    }

    /// Length-prefixing is what makes this work: `A=1, B=2` and `A=1B, =2`
    /// would otherwise render to the same bytes.
    #[test]
    fn fingerprints_values_that_run_into_each_other_differently() {
        let one = manifest("env:\n  A: \"1\"\n  B: \"2\"");
        let other = manifest("env:\n  A: \"1B\"\n  B: \"\"");

        assert_ne!(spec(&one), spec(&other));
    }

    fn log_of(lines: &[&str]) -> VecDeque<String> {
        let mut log = VecDeque::new();
        for line in lines {
            record(&mut log, line);
        }

        log
    }

    /// The engine emits fragments, not lines: one chunk can carry several, or
    /// half of one and the rest of it next time. A log kept verbatim would be
    /// a list of arbitrary fragments rather than of build output.
    #[test]
    fn keeps_what_the_engine_says_as_whole_lines() {
        let log = log_of(&["Step 1/2 : FROM scratch\n ---> ok\n", "\n", "Step 2/2\n"]);

        assert_eq!(
            log,
            ["Step 1/2 : FROM scratch", " ---> ok", "Step 2/2"]
                .map(str::to_owned)
                .to_vec()
        );
    }

    /// A build that prints a megabyte must not put a megabyte in the event
    /// stream, and the end is the part that explains a failure.
    #[test]
    fn keeps_only_the_end_of_a_talkative_build() {
        let noise: Vec<String> = (0..MAX_LOG_LINES + 50).map(|n| n.to_string()).collect();
        let log = log_of(&noise.iter().map(String::as_str).collect::<Vec<_>>());

        assert_eq!(log.len(), MAX_LOG_LINES);
        assert_eq!(log.front().unwrap(), "50");
        assert_eq!(log.back().unwrap(), &(MAX_LOG_LINES + 49).to_string());
    }

    #[test]
    fn puts_the_last_of_the_log_in_the_message_that_reports_a_failure() {
        let noise: Vec<String> = (0..100).map(|n| n.to_string()).collect();
        let tail = tail(&log_of(
            &noise.iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        assert!(tail.contains("\n99"), "{tail}");
        assert!(tail.contains(&format!("\n{}", 100 - LOG_TAIL)), "{tail}");
        assert!(
            !tail.contains(&format!("\n{}", 100 - LOG_TAIL - 1)),
            "{tail}"
        );
    }

    /// A build that said nothing at all gets no heading: a message that ends
    /// in one with nothing under it reads like something went missing.
    #[test]
    fn says_nothing_about_a_log_that_is_empty() {
        assert_eq!(tail(&VecDeque::new()), "");
    }

    /// The daemon-backed tests below are skipped rather than failed where
    /// there is no daemon: they are the only way to check the parts that are
    /// nothing but daemon, so they should run wherever one exists, but a
    /// checkout with no docker installed is not a broken checkout.
    async fn daemon() -> Option<DockerRuntime> {
        let runtime = DockerRuntime::connect(DataDir::new(temp_dir()), None).ok()?;
        runtime.ping().await.ok()?;

        Some(runtime)
    }

    /// A data directory of this test's own, so a test that makes volumes can
    /// look at what it made without seeing another test's.
    fn temp_dir() -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        std::env::temp_dir().join(format!("spaceport-runtime-{unique}"))
    }

    /// Wait for an app to start listening. `launch` returns as soon as the
    /// port is published, and gating on readiness is the apply path's job
    /// rather than the runtime's, so a test at this level does it itself.
    async fn wait_until_listening(addr: SocketAddr) -> bool {
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        false
    }

    /// A tiny http server that exposes exactly one port, and — unlike the
    /// image the examples use — is built for every architecture spaceport
    /// runs on. An emulated container takes seconds to start and seconds more
    /// to answer a signal, all of it paid by this test.
    fn hello_manifest() -> AppManifest {
        AppManifest::parse(
            "schema_version: 1
source:
  type: image
  image: traefik/whoami:latest
routing:
  hosts: [alpha.test]
auth:
  gating: open
",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn launches_an_app_and_publishes_it_on_loopback() {
        let Some(runtime) = daemon().await else {
            eprintln!("skipping: no docker daemon");
            return;
        };
        let app: AppId = "spaceport-selftest".parse().unwrap();

        let container = runtime.launch(&app, &hello_manifest()).await.unwrap();

        assert!(container.upstream.ip().is_loopback());
        assert!(
            wait_until_listening(container.upstream).await,
            "nothing was listening on {}",
            container.upstream
        );

        // Re-applying replaces the container rather than colliding on its name.
        let replacement = runtime.launch(&app, &hello_manifest()).await.unwrap();
        assert_ne!(replacement.id, container.id);

        runtime.remove(&replacement.id).await.unwrap();
        // Removing what is already gone is not an error.
        runtime.remove(&replacement.id).await.unwrap();
    }

    /// What a restarted spaceport sees. Nothing else on the host may be in
    /// this list, and the label has to survive a round trip through the engine
    /// well enough to say which app a container belongs to.
    #[tokio::test]
    async fn finds_the_containers_it_manages() {
        let Some(runtime) = daemon().await else {
            eprintln!("skipping: no docker daemon");
            return;
        };
        let app: AppId = "spaceport-selftest-managed".parse().unwrap();
        let container = runtime.launch(&app, &hello_manifest()).await.unwrap();

        let managed = runtime.managed().await.unwrap();

        let found = managed
            .iter()
            .find(|found| found.id == container.id)
            .unwrap_or_else(|| panic!("{} is not in {managed:?}", container.id));
        assert_eq!(found.app, Some(app));

        runtime.remove(&container.id).await.unwrap();
        // And a container that is gone is no longer managed.
        let managed = runtime.managed().await.unwrap();
        assert!(
            !managed.iter().any(|found| found.id == container.id),
            "{managed:?}",
        );
    }

    /// What a restart is now able to skip: the container the previous spaceport
    /// started is found by name, at the port it was published on.
    #[tokio::test]
    async fn gives_a_launched_app_its_environment() {
        let Some(runtime) = daemon().await else {
            eprintln!("skipping: no docker daemon");
            return;
        };
        let app: AppId = "spaceport-selftest-env".parse().unwrap();
        let manifest = manifest("port: 80\nenv:\n  MODE: production\n  GREETING: hello world");

        let container = runtime.launch(&app, &manifest).await.unwrap();

        let inspect = runtime
            .docker
            .inspect_container(container.id.as_str(), None::<InspectContainerOptions>)
            .await
            .unwrap();
        let env = inspect.config.unwrap().env.unwrap();

        assert!(env.contains(&"MODE=production".to_owned()), "{env:?}");
        // Spaces and all: the value is whatever the manifest said, and nothing
        // between here and the container gets to re-quote it.
        assert!(env.contains(&"GREETING=hello world".to_owned()), "{env:?}");

        runtime.remove(&container.id).await.unwrap();
    }

    #[tokio::test]
    async fn makes_a_volume_on_the_host_and_binds_it_into_the_container() {
        let Some(runtime) = daemon().await else {
            eprintln!("skipping: no docker daemon");
            return;
        };
        let app: AppId = "spaceport-selftest-volume".parse().unwrap();
        let manifest = manifest(
            "port: 80
volumes:
  - name: data
    mount: /var/lib/whoami",
        );

        let container = runtime.launch(&app, &manifest).await.unwrap();

        let expected = runtime.data.volume(&app, &"data".parse().unwrap());
        assert!(expected.is_dir(), "{} was not created", expected.display());

        let inspect = runtime
            .docker
            .inspect_container(container.id.as_str(), None::<InspectContainerOptions>)
            .await
            .unwrap();
        let mounts = inspect.mounts.unwrap();

        assert_eq!(mounts.len(), 1, "{mounts:?}");
        assert_eq!(mounts[0].source.as_deref(), expected.to_str());
        assert_eq!(mounts[0].destination.as_deref(), Some("/var/lib/whoami"));
        assert_eq!(mounts[0].rw, Some(true));

        runtime.remove(&container.id).await.unwrap();
        // The container is gone; the data it was keeping is not.
        assert!(expected.is_dir(), "removing the container took the volume");

        let _ = std::fs::remove_dir_all(runtime.data.root());
    }

    /// The gap this closes: neither environment nor volumes can be changed on
    /// a container that exists, so a spaceport that adopted one on the
    /// strength of its image alone would go on running last week's
    /// configuration and report the app as healthy.
    #[tokio::test]
    async fn refuses_to_adopt_a_container_whose_configuration_has_moved_on() {
        let Some(runtime) = daemon().await else {
            eprintln!("skipping: no docker daemon");
            return;
        };
        let app: AppId = "spaceport-selftest-respec".parse().unwrap();
        let applied = manifest("port: 80\nenv:\n  MODE: production");

        let container = runtime.launch(&app, &applied).await.unwrap();

        // The same manifest still describes this container.
        assert_eq!(
            runtime.adopt(&app, &applied).await.unwrap(),
            Some(Adopted::Running(container.clone()))
        );

        for changed in [
            "port: 80\nenv:\n  MODE: staging",
            "port: 80",
            "port: 80\nenv:\n  MODE: production\nvolumes:\n  - name: data\n    mount: /data",
        ] {
            assert_eq!(
                runtime.adopt(&app, &manifest(changed)).await.unwrap(),
                None,
                "adopted the old container for `{changed}`"
            );
        }

        runtime.remove(&container.id).await.unwrap();
        let _ = std::fs::remove_dir_all(runtime.data.root());
    }

    /// The upgrade path. A container created before spaceport recorded what it
    /// was created from has no spec label, and restarting every app on the
    /// host to give it one would be a worse answer than leaving the ones that
    /// still fit their manifest alone.
    #[tokio::test]
    async fn adopts_a_container_from_before_spaceport_recorded_its_spec() {
        let Some(runtime) = daemon().await else {
            eprintln!("skipping: no docker daemon");
            return;
        };
        let app: AppId = "spaceport-selftest-unlabelled".parse().unwrap();
        let name = container_name(&app);
        let _ = runtime.remove_container(&name).await;

        // Pulled by hand, because this test creates the container by hand: the
        // pull is `launch`'s, and a machine that has never run this image has
        // nothing for `create_container` to find.
        runtime.pull("traefik/whoami:latest").await.unwrap();

        // What an older spaceport would have created: managed and named, with
        // nothing said about its configuration.
        let body = ContainerCreateBody {
            image: Some("traefik/whoami:latest".to_owned()),
            labels: Some(HashMap::from([
                (MANAGED_LABEL.to_owned(), "true".to_owned()),
                (APP_LABEL.to_owned(), app.to_string()),
            ])),
            host_config: Some(HostConfig {
                port_bindings: Some(loopback_binding(80)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let created = runtime
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::new().name(&name).build()),
                body,
            )
            .await
            .unwrap();
        runtime.run(&created.id, 80).await.unwrap();

        // A manifest that asks for no configuration is still satisfied by it.
        let plain = manifest("port: 80");
        assert!(matches!(
            runtime.adopt(&app, &plain).await.unwrap(),
            Some(Adopted::Running(_))
        ));

        // One that asks for some is not: this container cannot have it.
        let configured = manifest("port: 80\nenv:\n  MODE: production");
        assert_eq!(runtime.adopt(&app, &configured).await.unwrap(), None);

        runtime.remove(&ContainerId::new(created.id)).await.unwrap();
    }

    #[tokio::test]
    async fn adopts_the_container_it_left_running() {
        let Some(runtime) = daemon().await else {
            eprintln!("skipping: no docker daemon");
            return;
        };
        let app: AppId = "spaceport-selftest-adopt".parse().unwrap();
        let container = runtime.launch(&app, &hello_manifest()).await.unwrap();

        let adopted = runtime.adopt(&app, &hello_manifest()).await.unwrap();

        assert_eq!(adopted, Some(Adopted::Running(container.clone())));

        // A manifest that names another image does not describe this
        // container, so there is nothing here to adopt — and answering that
        // must not need the image to be pullable.
        let elsewhere = AppManifest::parse(
            "schema_version: 1
source:
  type: image
  image: spaceport.invalid/nothing:v1
routing:
  hosts: [alpha.test]
auth:
  gating: open
container:
  port: 80
",
        )
        .unwrap();
        assert_eq!(runtime.adopt(&app, &elsewhere).await.unwrap(), None);

        // Nor is there once it is gone.
        runtime.remove(&container.id).await.unwrap();
        assert_eq!(runtime.adopt(&app, &hello_manifest()).await.unwrap(), None);

        // And an app that never ran here has nothing to adopt either.
        let unknown: AppId = "spaceport-selftest-never-ran".parse().unwrap();
        assert_eq!(
            runtime.adopt(&unknown, &hello_manifest()).await.unwrap(),
            None
        );
    }

    /// What suspending with `--stop-container` and resuming come to at the
    /// engine: the container is kept, and comes back somewhere new.
    #[tokio::test]
    async fn stops_a_container_and_starts_the_same_one_again() {
        let Some(runtime) = daemon().await else {
            eprintln!("skipping: no docker daemon");
            return;
        };
        let app: AppId = "spaceport-selftest-stop".parse().unwrap();
        let before = runtime.launch(&app, &hello_manifest()).await.unwrap();

        runtime.stop(&before.id).await.unwrap();

        // Kept, so it is still spaceport's to account for — this is what a
        // sweep must not mistake for a leftover.
        let managed = runtime.managed().await.unwrap();
        assert!(
            managed.iter().any(|found| found.id == before.id),
            "{managed:?}",
        );
        // And still adoptable, as the container it is rather than as one that
        // is running.
        assert_eq!(
            runtime.adopt(&app, &hello_manifest()).await.unwrap(),
            Some(Adopted::Stopped(before.id.clone())),
        );
        // Stopping it twice is not an error: it is being asked for the state it
        // is already in.
        runtime.stop(&before.id).await.unwrap();

        let after = runtime.start(&before.id, &hello_manifest()).await.unwrap();

        assert_eq!(after.id, before.id);
        // A published port belongs to a run of a container rather than to the
        // container, so the address is read again rather than remembered. It
        // usually *is* a different port — but the engine is free to hand back
        // the one it just freed, so what this asserts is that the address came
        // from the engine and is usable, not that it changed.
        assert!(after.upstream.ip().is_loopback());
        assert_ne!(after.upstream.port(), 0);
        assert_eq!(
            runtime.adopt(&app, &hello_manifest()).await.unwrap(),
            Some(Adopted::Running(after.clone())),
        );

        runtime.remove(&before.id).await.unwrap();
        // Stopping something that is gone is not an error either.
        runtime.stop(&before.id).await.unwrap();
    }

    #[tokio::test]
    async fn refuses_to_launch_an_app_it_cannot_build() {
        let Some(runtime) = daemon().await else {
            eprintln!("skipping: no docker daemon");
            return;
        };
        let manifest = AppManifest::parse(
            "schema_version: 1\nsource:\n  type: build\nrouting:\n  hosts: [alpha.test]\nauth:\n  gating: open\n",
        )
        .unwrap();

        let err = runtime
            .launch(&"builder".parse().unwrap(), &manifest)
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("cannot do yet"), "{err}");
    }

    /// A build context on disk, written the way one arrives: a directory with
    /// a Dockerfile in it. `FROM scratch` so that the test needs no registry —
    /// a build that pulled a base image would be testing the network.
    fn build_context(dockerfile: &str) -> std::path::PathBuf {
        let root = temp_dir();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("Dockerfile"), dockerfile).unwrap();
        std::fs::write(root.join("hello.txt"), "hello").unwrap();

        root
    }

    #[tokio::test]
    async fn builds_an_image_and_says_what_the_engine_called_it() {
        let Some(runtime) = daemon().await else {
            eprintln!("skipping: no docker daemon");
            return;
        };
        let app: AppId = "spaceport-selftest-build".parse().unwrap();
        let context = build_context("FROM scratch\nCOPY hello.txt /hello.txt\n");
        let tag = crate::build::image::tag(&app, "0123456789abcdef");

        let built = runtime
            .build(&BuildRequest {
                context: context.clone(),
                dockerfile: "Dockerfile".into(),
                tag: tag.clone(),
                labels: std::collections::BTreeMap::from([(
                    MANAGED_LABEL.to_owned(),
                    "true".to_owned(),
                )]),
            })
            .await
            .unwrap();

        assert_eq!(built.tag, tag);
        assert!(!built.id.is_empty());
        // The log is kept, unlike a pull's progress: it is the only thing that
        // could ever explain a build.
        assert!(!built.log.is_empty(), "{:?}", built.log);

        // The tag and the labels reached the daemon, so what was asked for is
        // what is now on the host.
        let inspect = runtime.docker.inspect_image(&tag).await.unwrap();
        assert!(
            inspect.repo_tags.unwrap_or_default().contains(&tag),
            "the image is not tagged `{tag}`"
        );
        let labels = inspect.config.unwrap().labels.unwrap_or_default();
        assert_eq!(labels.get(MANAGED_LABEL).map(String::as_str), Some("true"));

        let _ = runtime
            .docker
            .remove_image(
                &tag,
                None::<bollard::query_parameters::RemoveImageOptions>,
                None,
            )
            .await;
        let _ = std::fs::remove_dir_all(&context);
    }

    /// The whole reason the log is retained: a build that failed has to come
    /// back saying what the engine was doing when it did.
    #[tokio::test]
    async fn reports_a_build_that_failed_with_the_output_that_explains_it() {
        let Some(runtime) = daemon().await else {
            eprintln!("skipping: no docker daemon");
            return;
        };
        let app: AppId = "spaceport-selftest-build-fails".parse().unwrap();
        let context = build_context("FROM scratch\nCOPY nothing-is-here.txt /\n");
        let tag = crate::build::image::tag(&app, "0123456789abcdef");

        let err = runtime
            .build(&BuildRequest {
                context: context.clone(),
                dockerfile: "Dockerfile".into(),
                tag: tag.clone(),
                labels: std::collections::BTreeMap::new(),
            })
            .await
            .unwrap_err();

        let err = format!("{err:#}");
        assert!(err.contains(&tag), "{err}");
        assert!(err.contains("nothing-is-here.txt"), "{err}");

        let _ = std::fs::remove_dir_all(&context);
    }

    /// The supervisor's fast path, end to end against a real daemon: the label
    /// on the event is what says whose container it was, and a container that
    /// has been removed cannot be inspected afterwards to ask.
    #[tokio::test]
    async fn reports_a_container_of_its_own_dying() {
        let Some(runtime) = daemon().await else {
            eprintln!("skipping: no docker daemon");
            return;
        };
        let app: AppId = "spaceport-selftest-events".parse().unwrap();
        // Subscribed before anything is started, because an event that happened
        // before the stream existed is one the stream will never carry.
        let mut events = runtime.watch();
        let container = runtime.launch(&app, &hello_manifest()).await.unwrap();
        assert!(wait_until_listening(container.upstream).await);

        runtime.stop(&container.id).await.unwrap();

        // The daemon has plenty else to say about a busy host, so this waits
        // for the one event it is about rather than for the first to arrive.
        let died = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while let Some(event) = events.next().await {
                if event.container() == Some(&container.id)
                    && matches!(event, RuntimeEvent::Died { .. })
                {
                    return event;
                }
            }
            panic!("the event stream ended");
        })
        .await
        .expect("the daemon never reported the container dying");

        assert_eq!(died.app(), Some(&app));

        runtime.remove(&container.id).await.unwrap();
    }
}

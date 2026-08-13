//! The docker engine, spoken to over its API socket.
//!
//! Containers are published on an ephemeral loopback port rather than joined
//! to a network spaceport shares: the edge then reaches an app the same way
//! anything else on the host would, and nothing about the app's networking has
//! to be understood beyond "which port did the engine give it?".
//!
//! Every container spaceport creates is named and labelled after its app. The
//! name is what makes re-applying a manifest idempotent — the old container is
//! found and removed by name — and the label is what will let a restarted
//! spaceport find the containers it left running.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use bollard::Docker;
use bollard::errors::Error as DockerError;
use bollard::models::{ContainerCreateBody, HostConfig, PortBinding, PortMap};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, CreateImageOptionsBuilder, InspectContainerOptions,
    ListContainersOptionsBuilder, RemoveContainerOptionsBuilder, StartContainerOptions,
    StopContainerOptionsBuilder,
};
use futures_util::StreamExt;
use tracing::{debug, info, warn};

use super::{Container, ContainerId, ContainerRuntime, Managed};
use crate::app::manifest::Source;
use crate::app::{AppId, AppManifest};

/// Marks a container as spaceport's, and says whose it is.
const MANAGED_LABEL: &str = "spaceport.managed";
const APP_LABEL: &str = "spaceport.app";

/// How long the engine waits for a container to exit before killing it.
const STOP_TIMEOUT: i32 = 10;

/// The docker daemon.
pub struct DockerRuntime {
    docker: Docker,
}

impl DockerRuntime {
    /// Connect the way the docker CLI would, honouring `DOCKER_HOST`.
    ///
    /// Connecting is lazy — nothing reaches the daemon until the first
    /// request — so this succeeding does not mean there is a daemon there.
    /// Use [`DockerRuntime::ping`] to find that out at startup rather than at
    /// the first apply.
    pub fn connect() -> Result<Self> {
        let docker = Docker::connect_with_defaults().context("connecting to the docker daemon")?;

        Ok(Self { docker })
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

    /// The ports `image` declares, pulling the image if the daemon does not
    /// have it yet.
    ///
    /// The pull is not optional even when the manifest names a port: the
    /// engine will not fetch an image on its own when a container is created
    /// from it, so an image that is not here yet has to be fetched here.
    async fn exposed_ports(&self, image: &str) -> Result<Vec<String>> {
        let exposed = match self.docker.inspect_image(image).await {
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
        .and_then(|config| config.exposed_ports)
        .unwrap_or_default();

        Ok(exposed)
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

        let exposed = self.exposed_ports(image).await?;
        let port = container_port(manifest.container.port, image, &exposed)?;
        let name = container_name(app);

        // Re-applying an app replaces it, so whatever is running under this
        // name is on its way out either way.
        if self.remove_container(&name).await? {
            debug!(app = %app, container = name, "removed the previous container");
        }

        let body = ContainerCreateBody {
            image: Some(image.to_owned()),
            labels: Some(HashMap::from([
                (MANAGED_LABEL.to_owned(), "true".to_owned()),
                (APP_LABEL.to_owned(), app.to_string()),
            ])),
            host_config: Some(HostConfig {
                port_bindings: Some(loopback_binding(port)),
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
        match self.start(&created.id, port).await {
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

                Some(Managed { id, app })
            })
            .collect())
    }
}

impl DockerRuntime {
    /// Start a created container and find out where it ended up.
    async fn start(&self, id: &str, port: u16) -> Result<SocketAddr> {
        self.docker
            .start_container(id, None::<StartContainerOptions>)
            .await
            .context("starting the container")?;

        self.published_upstream(id, port).await
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The daemon-backed tests below are skipped rather than failed where
    /// there is no daemon: they are the only way to check the parts that are
    /// nothing but daemon, so they should run wherever one exists, but a
    /// checkout with no docker installed is not a broken checkout.
    async fn daemon() -> Option<DockerRuntime> {
        let runtime = DockerRuntime::connect().ok()?;
        runtime.ping().await.ok()?;

        Some(runtime)
    }

    /// Wait for an app to start listening. Nothing gates a launch on
    /// readiness yet, so the test has to do what health checks will.
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

    #[tokio::test]
    async fn refuses_to_launch_an_app_it_cannot_build() {
        let Some(runtime) = daemon().await else {
            eprintln!("skipping: no docker daemon");
            return;
        };
        let manifest = AppManifest::parse(
            "schema_version: 1\nsource:\n  type: build\nrouting:\n  hosts: [alpha.test]\n",
        )
        .unwrap();

        let err = runtime
            .launch(&"builder".parse().unwrap(), &manifest)
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("cannot do yet"), "{err}");
    }
}

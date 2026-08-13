//! App manifests: what an operator hands spaceport to run an app.
//!
//! The manifest describes the app alone. Its id is not in here — that is what
//! the operator names it as, on the command line, so the same file can be
//! applied under two ids without editing.

use std::borrow::Borrow;
use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, de};

use crate::config::SchemaVersion;
use crate::duration;

/// Longest a routing host may be, and its individual labels, per RFC 1035.
const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// A parsed and validated app manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppManifest {
    /// Declares which schema the rest of the document is written against.
    /// Shares the config's version: one schema, one spaceport.
    pub schema_version: SchemaVersion,

    /// Where the app's image comes from.
    pub source: Source,

    /// Which traffic reaches the app.
    pub routing: Routing,

    /// How the app runs. Every part of it has a default, so a manifest that
    /// says nothing here is complete.
    #[serde(default)]
    pub container: Container,
}

/// Where the app's image comes from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Source {
    /// A pre-built image, pulled as given.
    Image { image: String },

    /// An image built from a local context. Parses, but nothing builds it yet.
    Build {
        #[serde(default = "default_dockerfile")]
        dockerfile: PathBuf,
        #[serde(default = "default_context")]
        context: PathBuf,
    },
}

impl fmt::Display for Source {
    /// One line, for listings: where the image comes from, and what from
    /// there.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image { image } => write!(f, "image {image}"),
            Self::Build {
                dockerfile,
                context,
            } => write!(f, "build {} in {}", dockerfile.display(), context.display()),
        }
    }
}

fn default_dockerfile() -> PathBuf {
    PathBuf::from("Dockerfile")
}

fn default_context() -> PathBuf {
    PathBuf::from(".")
}

/// Which traffic reaches the app.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routing {
    /// Hosts served by this app. At least one, or nothing could ever reach it.
    pub hosts: Vec<Host>,
}

/// How the app's container runs.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Container {
    /// The port the app listens on inside its container.
    ///
    /// Optional because an image that exposes exactly one port has already
    /// said. This is for the images that expose several, or none, or one they
    /// do not actually serve on.
    pub port: Option<u16>,

    /// How spaceport decides the app is working.
    #[serde(default)]
    pub health: Health,
}

/// How spaceport decides an app is working.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    /// What has to succeed before traffic is routed to a newly applied app.
    #[serde(default)]
    pub readiness: Readiness,
}

/// The check an app has to pass before it is routed to.
///
/// A single struct rather than a tagged enum per check kind, so that
/// `deny_unknown_fields` keeps working — a manifest that misspells `path` is
/// far more common than one that needs the extra type safety, and it is the
/// one worth catching.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Readiness {
    /// Which kind of check to make.
    #[serde(rename = "type", default)]
    pub kind: Check,

    /// The path to request. Required by `http`, meaningless otherwise.
    pub path: Option<String>,

    /// The port to check. Not supported yet — see [`Readiness::validate`].
    pub port: Option<u16>,

    /// How long to wait before the first check. Containers that are going to
    /// answer at all usually answer quickly, so this is short by default and
    /// the retries do the rest of the waiting.
    #[serde(
        default = "default_initial_delay",
        deserialize_with = "duration::deserialize"
    )]
    pub initial_delay: Duration,

    /// How long to wait between checks.
    #[serde(
        default = "default_interval",
        deserialize_with = "duration::deserialize"
    )]
    pub interval: Duration,

    /// How long a single check may take before it counts as failed.
    #[serde(
        default = "default_timeout",
        deserialize_with = "duration::deserialize"
    )]
    pub timeout: Duration,

    /// How many checks in a row have to fail before the app is given up on.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    /// How many checks in a row have to pass before the app is routed to.
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
}

/// The kind of readiness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Check {
    /// Connect to the app's port. The default: it needs no cooperation from
    /// the app, and an app that is not accepting connections is not ready by
    /// any definition.
    #[default]
    Tcp,
    /// Request a path and require a non-error status.
    Http,
    /// Route to the app the moment its container starts.
    None,
}

fn default_initial_delay() -> Duration {
    // None: a check costs a connection, and an app that is ready immediately
    // should be routed immediately rather than made to sit out a delay.
    Duration::ZERO
}

fn default_interval() -> Duration {
    Duration::from_secs(1)
}

fn default_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_failure_threshold() -> u32 {
    30
}

fn default_success_threshold() -> u32 {
    1
}

impl Default for Readiness {
    fn default() -> Self {
        Self {
            kind: Check::default(),
            path: None,
            port: None,
            initial_delay: default_initial_delay(),
            interval: default_interval(),
            timeout: default_timeout(),
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
        }
    }
}

impl Readiness {
    /// How long a wholly unresponsive app is given before an apply gives up.
    pub fn budget(&self) -> Duration {
        self.initial_delay + self.interval * self.failure_threshold
    }

    fn validate(&self) -> Result<()> {
        match self.kind {
            Check::Http if self.path.is_none() => {
                bail!("a readiness check of type `http` needs a `path` to request");
            }
            Check::Http => {}
            _ if self.path.is_some() => {
                bail!(
                    "`path` only means something for a readiness check of type `http`, not `{}`",
                    self.kind.as_str()
                );
            }
            _ => {}
        }

        // Publishing a second host port to reach it is not implemented, and a
        // port that is never published would fail every check.
        if self.port.is_some() {
            bail!(
                "a readiness `port` of its own is not supported yet: the check uses the port traffic is routed to"
            );
        }

        if self.failure_threshold == 0 || self.success_threshold == 0 {
            bail!("readiness thresholds count checks, so they must be at least 1");
        }
        if self.interval.is_zero() {
            bail!("a readiness `interval` of zero would check without ever pausing");
        }
        if self.timeout.is_zero() {
            bail!("a readiness `timeout` of zero would fail every check");
        }

        Ok(())
    }
}

impl Check {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Http => "http",
            Self::None => "none",
        }
    }
}

/// A hostname an app answers to.
///
/// Lowercased on the way in, because `Host` headers are case-insensitive and
/// the routing table is a plain map: normalising once here means the edge
/// never has to think about it again.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Host(String);

impl Host {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Host {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("a routing host must not be empty");
        }
        if s.len() > MAX_HOST_LEN {
            bail!("host `{s}` is longer than {MAX_HOST_LEN} characters");
        }
        // A port here would silently never match: the edge strips the port off
        // the request before looking a host up.
        if s.contains(':') {
            bail!("host `{s}` must name a host without a port");
        }

        let host = s.to_ascii_lowercase();
        for label in host.split('.') {
            check_label(&host, label)?;
        }

        Ok(Self(host))
    }
}

/// Validate one dot-separated label of `host`.
fn check_label(host: &str, label: &str) -> Result<()> {
    if label.is_empty() {
        bail!("host `{host}` has an empty label");
    }
    if label.len() > MAX_LABEL_LEN {
        bail!("label `{label}` in host `{host}` is longer than {MAX_LABEL_LEN} characters");
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        bail!("host `{host}` may only contain letters, digits, hyphens and dots");
    }
    if label.starts_with('-') || label.ends_with('-') {
        bail!("label `{label}` in host `{host}` must not start or end with a hyphen");
    }

    Ok(())
}

impl<'de> Deserialize<'de> for Host {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lets a routing table keyed by `Host` be looked up with a plain `&str`, so
/// the edge never allocates to find a request's app. Sound because `Host`
/// hashes and compares exactly as its inner string does.
impl Borrow<str> for Host {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AppManifest {
    /// Read, parse and validate the manifest at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading app manifest `{}`", path.display()))?;

        Self::parse(&raw).with_context(|| format!("invalid app manifest `{}`", path.display()))
    }

    /// Parse and validate a manifest document.
    pub fn parse(raw: &str) -> Result<Self> {
        let manifest: Self = serde_norway::from_str(raw)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// What serde cannot express: the rules that span more than one field.
    fn validate(&self) -> Result<()> {
        if self.routing.hosts.is_empty() {
            bail!("routing.hosts must name at least one host");
        }

        let mut seen = HashSet::with_capacity(self.routing.hosts.len());
        for host in &self.routing.hosts {
            if !seen.insert(host) {
                bail!("routing.hosts lists `{host}` twice");
            }
        }

        if self.container.port == Some(0) {
            bail!("container.port must be a port an app can listen on, not 0");
        }

        self.container.health.readiness.validate()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest with everything mandatory filled in, for tests to extend.
    const MINIMAL: &str = "
schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [alpha.test, beta.test]
";

    fn hosts(manifest: &AppManifest) -> Vec<&str> {
        manifest.routing.hosts.iter().map(Host::as_str).collect()
    }

    /// The example is documentation, and documentation that does not parse is
    /// worse than none.
    #[test]
    fn the_shipped_example_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/hello-app.yaml");
        let raw = std::fs::read_to_string(&path).unwrap();

        AppManifest::parse(&raw).unwrap();
    }

    #[test]
    fn parses_an_image_source() {
        let manifest = AppManifest::parse(MINIMAL).unwrap();

        assert_eq!(
            manifest.source,
            Source::Image {
                image: "strm/helloworld-http:latest".into()
            }
        );
        assert_eq!(hosts(&manifest), ["alpha.test", "beta.test"]);
    }

    #[test]
    fn parses_a_build_source_with_defaults() {
        let raw = "
schema_version: 1
source:
  type: build
routing:
  hosts: [alpha.test]
";
        assert_eq!(
            AppManifest::parse(raw).unwrap().source,
            Source::Build {
                dockerfile: "Dockerfile".into(),
                context: ".".into(),
            }
        );
    }

    #[test]
    fn rejects_an_unknown_source_type() {
        let raw = MINIMAL.replace("type: image", "type: magic");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("magic"), "{err}");
    }

    #[test]
    fn rejects_a_source_field_from_another_variant() {
        let raw = MINIMAL.replace("  image: strm", "  dockerfile: Dockerfile\n  image: strm");
        assert!(AppManifest::parse(&raw).is_err());
    }

    #[test]
    fn rejects_a_missing_schema_version() {
        let raw = MINIMAL.replace("schema_version: 1\n", "");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("schema_version"), "{err}");
    }

    #[test]
    fn rejects_a_future_schema_version() {
        let raw = MINIMAL.replace("schema_version: 1", "schema_version: 2");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("unsupported schema version 2"), "{err}");
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = AppManifest::parse(&format!("{MINIMAL}secrets: [DB_PASSWORD]\n"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("secrets"), "{err}");
    }

    #[test]
    fn leaves_the_container_port_to_the_image_by_default() {
        assert_eq!(AppManifest::parse(MINIMAL).unwrap().container.port, None);
    }

    #[test]
    fn parses_a_container_port() {
        let raw = format!("{MINIMAL}container:\n  port: 8080\n");
        assert_eq!(AppManifest::parse(&raw).unwrap().container.port, Some(8080));
    }

    #[test]
    fn rejects_a_container_port_of_zero() {
        let raw = format!("{MINIMAL}container:\n  port: 0\n");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("not 0"), "{err}");
    }

    #[test]
    fn rejects_a_container_port_that_is_not_a_port() {
        let raw = format!("{MINIMAL}container:\n  port: 70000\n");
        assert!(AppManifest::parse(&raw).is_err());
    }

    #[test]
    fn rejects_an_unknown_container_field() {
        let raw = format!("{MINIMAL}container:\n  ports: 8080\n");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("ports"), "{err}");
    }

    /// `MINIMAL` with a readiness section, indented into place.
    fn with_readiness(fields: &str) -> String {
        let fields: String = fields
            .lines()
            .map(|line| format!("      {line}\n"))
            .collect();

        format!("{MINIMAL}container:\n  health:\n    readiness:\n{fields}")
    }

    #[test]
    fn waits_for_a_tcp_connection_by_default() {
        let readiness = AppManifest::parse(MINIMAL)
            .unwrap()
            .container
            .health
            .readiness;

        assert_eq!(readiness, Readiness::default());
        assert_eq!(readiness.kind, Check::Tcp);
        assert_eq!(readiness.budget(), Duration::from_secs(30));
    }

    #[test]
    fn parses_an_http_readiness_check() {
        let raw = with_readiness(
            "type: http
path: /healthz
interval: 500ms
timeout: 2s
initial_delay: 1m
failure_threshold: 6
success_threshold: 2",
        );

        let readiness = AppManifest::parse(&raw).unwrap().container.health.readiness;

        assert_eq!(readiness.kind, Check::Http);
        assert_eq!(readiness.path.as_deref(), Some("/healthz"));
        assert_eq!(readiness.interval, Duration::from_millis(500));
        assert_eq!(readiness.timeout, Duration::from_secs(2));
        assert_eq!(readiness.initial_delay, Duration::from_secs(60));
        assert_eq!(readiness.failure_threshold, 6);
        assert_eq!(readiness.success_threshold, 2);
    }

    #[test]
    fn keeps_the_defaults_for_whatever_a_check_leaves_out() {
        let raw = with_readiness("type: http\npath: /healthz");
        let readiness = AppManifest::parse(&raw).unwrap().container.health.readiness;

        assert_eq!(readiness.interval, Duration::from_secs(1));
        assert_eq!(readiness.failure_threshold, 30);
    }

    #[test]
    fn rejects_an_http_check_without_a_path() {
        let err = AppManifest::parse(&with_readiness("type: http"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("needs a `path`"), "{err}");
    }

    #[test]
    fn rejects_a_path_on_a_check_that_cannot_use_one() {
        let err = AppManifest::parse(&with_readiness("type: tcp\npath: /healthz"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("only means something"), "{err}");
    }

    /// Reaching a port of its own would mean publishing a second host port,
    /// which nothing does yet — so it is refused rather than silently failing
    /// every check.
    #[test]
    fn rejects_a_readiness_port_of_its_own() {
        let err = AppManifest::parse(&with_readiness("port: 9000"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("not supported yet"), "{err}");
    }

    #[test]
    fn rejects_thresholds_that_count_nothing() {
        for field in ["failure_threshold: 0", "success_threshold: 0"] {
            let err = AppManifest::parse(&with_readiness(field))
                .unwrap_err()
                .to_string();

            assert!(err.contains("at least 1"), "{err}");
        }
    }

    #[test]
    fn rejects_a_pointless_interval_or_timeout() {
        assert!(AppManifest::parse(&with_readiness("interval: 0s")).is_err());
        assert!(AppManifest::parse(&with_readiness("timeout: 0s")).is_err());
    }

    #[test]
    fn rejects_a_duration_without_a_unit() {
        let err = AppManifest::parse(&with_readiness("interval: 30"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("duration"), "{err}");
    }

    #[test]
    fn rejects_an_unknown_readiness_field() {
        let err = AppManifest::parse(&with_readiness("timeout_seconds: 3"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("timeout_seconds"), "{err}");
    }

    #[test]
    fn rejects_an_unknown_check_type() {
        let err = AppManifest::parse(&with_readiness("type: ping"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("ping"), "{err}");
    }

    #[test]
    fn rejects_a_manifest_without_hosts() {
        let raw = MINIMAL.replace("hosts: [alpha.test, beta.test]", "hosts: []");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("at least one host"), "{err}");
    }

    #[test]
    fn rejects_a_repeated_host() {
        let raw = MINIMAL.replace("beta.test", "ALPHA.test");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn lowercases_hosts() {
        let raw = MINIMAL.replace("alpha.test", "ALPHA.Test");
        let manifest = AppManifest::parse(&raw).unwrap();

        assert_eq!(hosts(&manifest)[0], "alpha.test");
    }

    #[test]
    fn accepts_a_single_label_host() {
        assert_eq!("localhost".parse::<Host>().unwrap().as_str(), "localhost");
    }

    #[test]
    fn rejects_a_host_with_a_port() {
        let err = "alpha.test:8080".parse::<Host>().unwrap_err().to_string();
        assert!(err.contains("without a port"), "{err}");
    }

    #[test]
    fn rejects_a_malformed_host() {
        for host in [
            "",
            "alpha..test",
            "alpha.test.",
            "al pha.test",
            "-alpha.test",
            "alpha-.test",
        ] {
            assert!(host.parse::<Host>().is_err(), "accepted `{host}`");
        }
    }

    #[test]
    fn rejects_an_overlong_label() {
        let host = format!("{}.test", "a".repeat(64));
        let err = host.parse::<Host>().unwrap_err().to_string();

        assert!(err.contains("longer than 63"), "{err}");
    }
}

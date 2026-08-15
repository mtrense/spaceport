//! App manifests: what an operator hands spaceport to run an app.
//!
//! The manifest describes the app alone. Its id is not in here — that is what
//! the operator names it as, on the command line, so the same file can be
//! applied under two ids without editing.

use std::borrow::Borrow;
use std::collections::{BTreeMap, HashSet};
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

/// Longest a volume name may be. It becomes one path segment on the host, and
/// 63 is the shortest limit any filesystem spaceport might run on imposes.
const MAX_VOLUME_NAME_LEN: usize = 63;

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

    /// The document this was parsed from, kept verbatim.
    ///
    /// Private, and filled in by [`AppManifest::parse`] rather than by serde:
    /// it is not a field of the schema, it is the schema's own text. Spaceport
    /// stores this, not a re-serialization, so that what an operator applied is
    /// what a later spaceport reads back — including whatever this build's
    /// structs do not model.
    #[serde(skip)]
    source_text: String,
}

/// Where the app's image comes from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Source {
    /// A pre-built image, pulled as given.
    Image { image: String },

    /// An image built from a checkout of the app's repository.
    ///
    /// Both paths are inside that checkout and are kept there — see
    /// [`Source::validate`].
    Build {
        #[serde(default = "default_dockerfile")]
        dockerfile: PathBuf,
        #[serde(default = "default_context")]
        context: PathBuf,
    },
}

impl Source {
    /// What serde cannot express about where an image comes from: that a build
    /// stays inside the tree it was given.
    ///
    /// The principle is [`Volume`]'s, and these two paths were violating it by
    /// construction. A manifest may not name a host path — the host path is
    /// spaceport's to choose — and `context: /etc` or `dockerfile: ../../../x`
    /// is a manifest naming one. Both would be read by whatever unpacked the
    /// commit and by the engine after it, so the file that reaches the build is
    /// whatever the document asked for, from anywhere on the host.
    ///
    /// Refused here rather than where a build happens, because there is more
    /// than one place a build happens and only one place a manifest is
    /// accepted. This was unreachable for as long as every path bailed on
    /// `Source::Build`; building makes it reachable.
    fn validate(&self) -> Result<()> {
        let Self::Build {
            dockerfile,
            context,
        } = self
        else {
            return Ok(());
        };

        for (field, path) in [("dockerfile", dockerfile), ("context", context)] {
            if path.as_os_str().is_empty() {
                bail!("source.{field} must name a path inside the repository, not nothing");
            }
            if path.is_absolute() {
                bail!(
                    "source.{field} must be relative to the repository, not `{}`",
                    path.display()
                );
            }
            // Component-wise rather than by looking for `..` in the text: a
            // path is not a string, and `a..b` is a perfectly ordinary
            // directory name that a substring search would refuse.
            if path
                .components()
                .any(|component| component == std::path::Component::ParentDir)
            {
                bail!(
                    "source.{field} must stay inside the repository, and `{}` climbs out of it",
                    path.display()
                );
            }
        }

        Ok(())
    }
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

    /// Directories the app keeps across restarts, redeploys and its own
    /// deletion.
    #[serde(default)]
    pub volumes: Vec<Volume>,

    /// Secrets the app's `env` may interpolate. Parses and validates, but
    /// nothing supplies a value yet, so applying a manifest that declares one
    /// is refused — see `apply`.
    ///
    /// Declared as a list of bare names rather than name-and-value: the whole
    /// point is that the value is not in the document.
    #[serde(default)]
    pub secrets: Vec<VarName>,

    /// The environment the app runs with.
    ///
    /// A `BTreeMap`, so the environment a manifest describes has exactly one
    /// order. Docker takes it as a list, and a list that reshuffled between two
    /// reads of the same document would make an unchanged app look changed.
    #[serde(default)]
    pub env: BTreeMap<VarName, String>,
}

/// A directory the app keeps.
///
/// The host path is not in here: it is spaceport's to choose, from the
/// configured data directory and the id the operator applied the app under.
/// A manifest that could name a host path could name any host path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Volume {
    /// Names the volume within the app, and nothing else — it is the last
    /// segment of the host path, so it is kept to what is safe to put there.
    pub name: VolumeName,

    /// Where the app sees it, inside the container.
    pub mount: PathBuf,

    /// Whether the app may write to it. Off by default: a volume exists to be
    /// written to, and the read-only case is the one worth spelling out.
    #[serde(default)]
    pub read_only: bool,
}

/// The name of a volume, safe to use as one path segment.
///
/// Kept to letters, digits, hyphens and underscores, which is what makes it
/// safe: no separator, no `..`, no leading dot, nothing a shell or a path
/// walker reads as anything but a name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VolumeName(String);

impl VolumeName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for VolumeName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("a volume name must not be empty");
        }
        if s.len() > MAX_VOLUME_NAME_LEN {
            bail!("volume name `{s}` is longer than {MAX_VOLUME_NAME_LEN} characters");
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            bail!("volume name `{s}` may only contain letters, digits, hyphens and underscores");
        }

        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for VolumeName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl fmt::Display for VolumeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of an environment variable, and so also of a secret: a secret is
/// only ever delivered by being interpolated into one.
///
/// The C rules, because that is what the shell in the container will enforce
/// anyway — a name it cannot export is a name the app cannot read.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VarName(String);

impl VarName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for VarName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("an environment variable name must not be empty");
        }
        let mut bytes = s.bytes();
        let first = bytes.next().expect("checked non-empty");
        if !(first.is_ascii_alphabetic() || first == b'_') {
            bail!("`{s}` must start with a letter or an underscore to be an environment variable");
        }
        if !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            bail!("`{s}` may only contain letters, digits and underscores");
        }

        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for VarName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl fmt::Display for VarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lets a map keyed by `VarName` be looked up with a plain `&str`.
impl Borrow<str> for VarName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// The secrets an env value interpolates, in the order they appear.
///
/// `{{` always opens a reference and there is no way to escape it. A literal
/// `{{` in an environment value is rare enough to wait for someone to want
/// one; inventing an escape now would be guessing at a syntax nobody has had
/// to write yet, and the guess would be permanent.
fn placeholders(value: &str) -> Result<Vec<&str>> {
    let mut found = Vec::new();
    let mut rest = value;

    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            bail!("`{value}` opens a `{{{{` that is never closed");
        };
        found.push(after[..close].trim());
        rest = &after[close + 2..];
    }

    Ok(found)
}

impl Container {
    /// What serde cannot express about a container: the rules that span more
    /// than one field.
    fn validate(&self) -> Result<()> {
        if self.port == Some(0) {
            bail!("container.port must be a port an app can listen on, not 0");
        }

        let mut names = HashSet::with_capacity(self.volumes.len());
        let mut mounts = HashSet::with_capacity(self.volumes.len());
        for volume in &self.volumes {
            // Two volumes of one name would be one directory on the host, and
            // whichever mount won would depend on the order docker read them.
            if !names.insert(&volume.name) {
                bail!("container.volumes names `{}` twice", volume.name);
            }
            if !volume.mount.is_absolute() {
                bail!(
                    "volume `{}` must be mounted at an absolute path, not `{}`",
                    volume.name,
                    volume.mount.display()
                );
            }
            if volume.mount == Path::new("/") {
                bail!("volume `{}` must not be mounted over `/`", volume.name);
            }
            if !mounts.insert(&volume.mount) {
                bail!(
                    "container.volumes mounts two volumes at `{}`",
                    volume.mount.display()
                );
            }
        }

        let mut declared = HashSet::with_capacity(self.secrets.len());
        for secret in &self.secrets {
            if !declared.insert(secret) {
                bail!("container.secrets names `{secret}` twice");
            }
        }

        let mut used = HashSet::new();
        for (name, value) in &self.env {
            for reference in placeholders(value)? {
                let secret: VarName = reference
                    .parse()
                    .with_context(|| format!("`{name}` interpolates `{{{{{reference}}}}}`"))?;
                if !declared.contains(&secret) {
                    bail!(
                        "`{name}` interpolates `{secret}`, which container.secrets does not declare"
                    );
                }
                used.insert(secret);
            }
        }

        // A secret nothing reads is a typo on one side or the other, and both
        // ways round the app would come up missing something it was promised.
        for secret in &self.secrets {
            if !used.contains(secret) {
                bail!("container.secrets declares `{secret}`, which no env value interpolates");
            }
        }

        Ok(())
    }
}

/// How spaceport decides an app is working.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    /// What has to succeed before traffic is routed to a newly applied app.
    #[serde(default)]
    pub readiness: Probe,

    /// What has to keep succeeding for spaceport to leave the app alone.
    ///
    /// Optional, and off when it is not there — which is the one default in
    /// this file that is not simply the safe value. A liveness check is a
    /// standing instruction to restart the app, and an app that never asked for
    /// one must not acquire it by being applied to a newer spaceport. Saying
    /// `type: none` is the other way to say the same thing, for a manifest that
    /// wants to be explicit about it.
    ///
    /// A container that has exited is restarted either way: that is the engine
    /// reporting a fact, not spaceport forming an opinion. This is for the app
    /// that is still running and has stopped working, which is the only case
    /// nobody but the app itself can settle.
    pub liveness: Option<Probe>,
}

/// A check spaceport makes against a running app.
///
/// A single struct rather than a tagged enum per check kind, so that
/// `deny_unknown_fields` keeps working — a manifest that misspells `path` is
/// far more common than one that needs the extra type safety, and it is the
/// one worth catching.
///
/// The same fields answer both questions the manifest asks. Readiness is "may
/// traffic go here yet?", where `failure_threshold` is how long an apply waits
/// before giving up; liveness is "is it still working?", where the very same
/// number is how many checks in a row have to fail before spaceport restarts
/// it. One kind of check, two moments to ask it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    /// Which kind of check to make.
    #[serde(rename = "type", default)]
    pub kind: Check,

    /// The path to request. Required by `http`, meaningless otherwise.
    pub path: Option<String>,

    /// The port to check. Not supported yet — see [`Probe::validate`].
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

/// The kind of check to make.
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
    /// Ask nothing. For readiness, route to the app the moment its container
    /// starts; for liveness, never restart an app whose container is still
    /// running.
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

impl Default for Probe {
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

impl Probe {
    /// How long a wholly unresponsive app is given before an apply gives up.
    pub fn budget(&self) -> Duration {
        self.initial_delay + self.interval * self.failure_threshold
    }

    /// `which` is the name the manifest gave this check — `readiness` or
    /// `liveness` — so that an operator with both is told which one is wrong.
    fn validate(&self, which: &str) -> Result<()> {
        match self.kind {
            Check::Http if self.path.is_none() => {
                bail!("a {which} check of type `http` needs a `path` to request");
            }
            Check::Http => {}
            _ if self.path.is_some() => {
                bail!(
                    "`path` only means something for a {which} check of type `http`, not `{}`",
                    self.kind.as_str()
                );
            }
            _ => {}
        }

        // Publishing a second host port to reach it is not implemented, and a
        // port that is never published would fail every check.
        if self.port.is_some() {
            bail!(
                "a {which} `port` of its own is not supported yet: the check uses the port traffic is routed to"
            );
        }

        if self.failure_threshold == 0 || self.success_threshold == 0 {
            bail!("{which} thresholds count checks, so they must be at least 1");
        }
        if self.interval.is_zero() {
            bail!("a {which} `interval` of zero would check without ever pausing");
        }
        if self.timeout.is_zero() {
            bail!("a {which} `timeout` of zero would fail every check");
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
        let mut manifest: Self = serde_norway::from_str(raw)?;
        manifest.validate()?;
        manifest.source_text = raw.to_owned();

        Ok(manifest)
    }

    /// The document this manifest was parsed from, byte for byte.
    pub fn source_text(&self) -> &str {
        &self.source_text
    }

    /// What serde cannot express: the rules that span more than one field.
    fn validate(&self) -> Result<()> {
        self.source.validate()?;

        if self.routing.hosts.is_empty() {
            bail!("routing.hosts must name at least one host");
        }

        let mut seen = HashSet::with_capacity(self.routing.hosts.len());
        for host in &self.routing.hosts {
            if !seen.insert(host) {
                bail!("routing.hosts lists `{host}` twice");
            }
        }

        self.container.validate()?;

        self.container.health.readiness.validate("readiness")?;
        // Nothing cross-checks the two: liveness starts only once readiness has
        // already passed, so a liveness check that gives up far sooner than an
        // apply would is the normal way to write one, not a mistake.
        if let Some(liveness) = &self.container.health.liveness {
            liveness.validate("liveness")?;
        }

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

    /// The examples are documentation, and documentation that does not parse
    /// is worse than none. `app-manifest.yaml` is the one that matters most
    /// here: it is where every field spaceport understands is written down.
    #[test]
    fn the_shipped_examples_are_valid() {
        let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");

        for name in ["hello-app.yaml", "echo.yaml", "app-manifest.yaml"] {
            let raw = std::fs::read_to_string(examples.join(name)).unwrap();

            if let Err(err) = AppManifest::parse(&raw) {
                panic!("examples/{name}: {err:#}");
            }
        }
    }

    /// The state store keeps this text and nothing else, so a manifest that
    /// dropped a comment or normalized its quoting on the way through would
    /// give an operator back something they never wrote.
    #[test]
    fn keeps_the_document_it_was_parsed_from() {
        let raw = "# what this app is for\nschema_version: 1\nsource:\n  type: image\n  image: \"strm/helloworld-http:latest\"\nrouting:\n  hosts: [alpha.test]\n";

        let manifest = AppManifest::parse(raw).unwrap();

        assert_eq!(manifest.source_text(), raw);
        // And what it kept parses back to the same manifest.
        assert_eq!(
            AppManifest::parse(manifest.source_text()).unwrap(),
            manifest
        );
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

    /// `MINIMAL` with a build source in place of its image one.
    fn with_build(fields: &str) -> String {
        let fields: String = fields.lines().map(|line| format!("  {line}\n")).collect();

        MINIMAL.replace(
            "source:\n  type: image\n  image: strm/helloworld-http:latest\n",
            &format!("source:\n  type: build\n{fields}"),
        )
    }

    /// The defaults are a build of the repository as it arrives, and they are
    /// what a manifest that says `type: build` and nothing else gets — so they
    /// have to survive the rules below.
    #[test]
    fn builds_the_repository_as_it_arrives_by_default() {
        let manifest = AppManifest::parse(&with_build("")).unwrap();

        assert_eq!(
            manifest.source,
            Source::Build {
                dockerfile: "Dockerfile".into(),
                context: ".".into(),
            }
        );
    }

    /// The host path is spaceport's to choose. A manifest that could name one
    /// could name any, and `/etc` is the same document asking to build the
    /// host's configuration.
    #[test]
    fn rejects_a_build_path_that_is_absolute() {
        for field in ["dockerfile: /etc/Dockerfile", "context: /etc"] {
            let err = AppManifest::parse(&with_build(field))
                .unwrap_err()
                .to_string();

            assert!(err.contains("must be relative"), "for `{field}`: {err}");
        }
    }

    /// The other way out of the checkout, and the one that does not look like
    /// a host path in the document.
    #[test]
    fn rejects_a_build_path_that_climbs_out_of_the_repository() {
        for field in [
            "dockerfile: ../../../x",
            "context: ..",
            "dockerfile: build/../../elsewhere/Dockerfile",
        ] {
            let err = AppManifest::parse(&with_build(field))
                .unwrap_err()
                .to_string();

            assert!(err.contains("climbs out"), "for `{field}`: {err}");
        }
    }

    /// An empty path is not the default: it is a field somebody meant to fill
    /// in, and it would be joined to the checkout to mean the checkout itself.
    #[test]
    fn rejects_a_build_path_that_is_empty() {
        for field in ["dockerfile: \"\"", "context: \"\""] {
            let err = AppManifest::parse(&with_build(field))
                .unwrap_err()
                .to_string();

            assert!(err.contains("not nothing"), "for `{field}`: {err}");
        }
    }

    /// A directory named `a..b` is an ordinary directory, and refusing it would
    /// be a substring search standing in for reading a path.
    #[test]
    fn accepts_a_build_path_with_dots_in_a_name() {
        let manifest = AppManifest::parse(&with_build("context: services/a..b")).unwrap();

        assert_eq!(
            manifest.source,
            Source::Build {
                dockerfile: "Dockerfile".into(),
                context: "services/a..b".into(),
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
        let err = AppManifest::parse(&format!("{MINIMAL}replicas: 3\n"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("replicas"), "{err}");
    }

    /// `secrets` is a container field, so at the root it is still a mistake —
    /// and one an operator who read the example half-way is likely to make.
    #[test]
    fn rejects_a_container_field_at_the_root() {
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

    /// `MINIMAL` with a container section, indented into place.
    fn with_container(fields: &str) -> String {
        let fields: String = fields.lines().map(|line| format!("  {line}\n")).collect();

        format!("{MINIMAL}container:\n{fields}")
    }

    #[test]
    fn runs_with_no_environment_and_no_volumes_by_default() {
        let container = AppManifest::parse(MINIMAL).unwrap().container;

        assert!(container.env.is_empty());
        assert!(container.volumes.is_empty());
        assert!(container.secrets.is_empty());
    }

    #[test]
    fn parses_an_environment() {
        let raw = with_container("env:\n  ENVIRONMENT: production\n  LOG_LEVEL: debug");
        let env = AppManifest::parse(&raw).unwrap().container.env;

        assert_eq!(env.len(), 2);
        assert_eq!(env["ENVIRONMENT"], "production");
        assert_eq!(env["LOG_LEVEL"], "debug");
    }

    #[test]
    fn rejects_an_environment_name_a_shell_could_not_export() {
        for name in ["1ST", "WITH-HYPHEN", "with space", ""] {
            let raw = with_container(&format!("env:\n  \"{name}\": x"));
            assert!(AppManifest::parse(&raw).is_err(), "accepted `{name}`");
        }
    }

    #[test]
    fn parses_a_volume() {
        let raw = with_container(
            "volumes:
  - name: data
    mount: /var/lib/my-app/data
  - name: cache
    mount: /var/cache/my-app
    read_only: true",
        );

        let volumes = AppManifest::parse(&raw).unwrap().container.volumes;

        assert_eq!(volumes.len(), 2);
        assert_eq!(volumes[0].name.as_str(), "data");
        assert_eq!(volumes[0].mount, Path::new("/var/lib/my-app/data"));
        // Off unless asked for: a volume exists to be written to.
        assert!(!volumes[0].read_only);
        assert!(volumes[1].read_only);
    }

    /// The name becomes one segment of a host path, so anything that could
    /// climb out of the app's own directory has to be refused here, before it
    /// is ever joined to one.
    #[test]
    fn rejects_a_volume_name_that_is_not_one_path_segment() {
        for name in ["..", "a/b", ".hidden", "", "with space", "\"a\\\\b\""] {
            let raw = with_container(&format!("volumes:\n  - name: {name}\n    mount: /data"));
            assert!(AppManifest::parse(&raw).is_err(), "accepted `{name}`");
        }
    }

    #[test]
    fn rejects_an_overlong_volume_name() {
        let name = "a".repeat(64);
        let raw = with_container(&format!("volumes:\n  - name: {name}\n    mount: /data"));
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("longer than 63"), "{err}");
    }

    #[test]
    fn rejects_a_relative_mount() {
        let raw = with_container("volumes:\n  - name: data\n    mount: var/lib/data");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("absolute path"), "{err}");
    }

    /// Mounting a volume over `/` would replace the image's whole filesystem
    /// with an empty directory.
    #[test]
    fn rejects_a_mount_over_the_root() {
        let raw = with_container("volumes:\n  - name: data\n    mount: /");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("over `/`"), "{err}");
    }

    /// Two volumes of one name are one host directory, and which mount won
    /// would come down to the order docker happened to read them in.
    #[test]
    fn rejects_two_volumes_of_the_same_name() {
        let raw = with_container(
            "volumes:
  - name: data
    mount: /one
  - name: data
    mount: /two",
        );
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn rejects_two_volumes_at_the_same_mount() {
        let raw = with_container(
            "volumes:
  - name: one
    mount: /data
  - name: two
    mount: /data",
        );
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("/data"), "{err}");
    }

    #[test]
    fn parses_a_secret_interpolated_into_the_environment() {
        let raw = with_container(
            "secrets:
  - DB_PASSWORD
env:
  DATABASE_URL: postgres://user:{{DB_PASSWORD}}@db:5432/my-app",
        );

        let container = AppManifest::parse(&raw).unwrap().container;

        assert_eq!(container.secrets[0].as_str(), "DB_PASSWORD");
        // Kept unresolved: the manifest is stored as written, and there is
        // nothing to resolve it with yet.
        assert_eq!(
            container.env["DATABASE_URL"],
            "postgres://user:{{DB_PASSWORD}}@db:5432/my-app"
        );
    }

    /// The typo that would otherwise reach the app as a literal `{{...}}` in
    /// a connection string, and be diagnosed as a database problem.
    #[test]
    fn rejects_a_reference_to_a_secret_nobody_declared() {
        let raw = with_container("env:\n  DATABASE_URL: \"pw={{DB_PASSWORD}}\"");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("DB_PASSWORD"), "{err}");
        assert!(err.contains("does not declare"), "{err}");
    }

    /// The same typo from the other side: the secret is declared, and it is
    /// the reference that is misspelt, so nothing would ever read it.
    #[test]
    fn rejects_a_declared_secret_nothing_interpolates() {
        let raw = with_container("secrets: [DB_PASSWORD]\nenv:\n  A: b");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("no env value interpolates"), "{err}");
    }

    #[test]
    fn rejects_a_repeated_secret() {
        let raw =
            with_container("secrets: [DB_PASSWORD, DB_PASSWORD]\nenv:\n  A: \"{{DB_PASSWORD}}\"");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn rejects_an_unclosed_placeholder() {
        let raw = with_container("secrets: [DB_PASSWORD]\nenv:\n  A: \"{{DB_PASSWORD\"");
        let err = AppManifest::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("never closed"), "{err}");
    }

    #[test]
    fn reads_a_secret_into_more_than_one_variable() {
        let raw = with_container(
            "secrets: [PW]
env:
  A: \"{{PW}}\"
  B: \"user:{{PW}}@host and again {{PW}}\"",
        );

        assert!(AppManifest::parse(&raw).is_ok());
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

        assert_eq!(readiness, Probe::default());
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

    /// `MINIMAL` with a liveness section, indented into place.
    fn with_liveness(fields: &str) -> String {
        let fields: String = fields
            .lines()
            .map(|line| format!("      {line}\n"))
            .collect();

        format!("{MINIMAL}container:\n  health:\n    liveness:\n{fields}")
    }

    /// The one default here that is not simply the safe value. Every app
    /// already applied was written without a liveness block, and if absence
    /// meant "watch it" they would all quietly acquire a standing instruction
    /// to restart on the next upgrade.
    #[test]
    fn watches_nothing_unless_a_manifest_asks_for_it() {
        let health = AppManifest::parse(MINIMAL).unwrap().container.health;

        assert_eq!(health.liveness, None);
        // And readiness is still there, so absent liveness is absence and not
        // a health section that failed to parse.
        assert_eq!(health.readiness, Probe::default());
    }

    #[test]
    fn parses_an_http_liveness_check() {
        let raw = with_liveness(
            "type: http
path: /livez
interval: 15s
timeout: 3s
initial_delay: 30s
failure_threshold: 4
success_threshold: 1",
        );

        let liveness = AppManifest::parse(&raw)
            .unwrap()
            .container
            .health
            .liveness
            .unwrap();

        assert_eq!(liveness.kind, Check::Http);
        assert_eq!(liveness.path.as_deref(), Some("/livez"));
        assert_eq!(liveness.interval, Duration::from_secs(15));
        assert_eq!(liveness.timeout, Duration::from_secs(3));
        assert_eq!(liveness.initial_delay, Duration::from_secs(30));
        assert_eq!(liveness.failure_threshold, 4);
        assert_eq!(liveness.success_threshold, 1);
    }

    /// An operator with both checks configured gets one error message, and it
    /// has to say which of the two they need to go and fix.
    #[test]
    fn says_liveness_when_it_is_the_liveness_check_that_is_wrong() {
        let err = AppManifest::parse(&with_liveness("type: http"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("liveness"), "{err}");
        assert!(!err.contains("readiness"), "{err}");
    }

    /// The other half of the same worry: naming the check must not have turned
    /// every message into the liveness one.
    #[test]
    fn says_readiness_when_it_is_the_readiness_check_that_is_wrong() {
        let err = AppManifest::parse(&with_readiness("type: http"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("readiness"), "{err}");
        assert!(!err.contains("liveness"), "{err}");
    }

    /// The two checks answer different questions and are written to different
    /// budgets — a slow apply and a twitchy restart are both reasonable — so
    /// neither may be allowed to inherit the other's settings.
    #[test]
    fn takes_the_two_checks_independently() {
        let raw = format!(
            "{MINIMAL}container:
  health:
    readiness:
      type: http
      path: /healthz
      interval: 500ms
      failure_threshold: 60
    liveness:
      type: tcp
      interval: 10s
      failure_threshold: 3
"
        );

        let health = AppManifest::parse(&raw).unwrap().container.health;
        let liveness = health.liveness.unwrap();

        assert_eq!(health.readiness.kind, Check::Http);
        assert_eq!(health.readiness.path.as_deref(), Some("/healthz"));
        assert_eq!(health.readiness.interval, Duration::from_millis(500));
        assert_eq!(health.readiness.failure_threshold, 60);

        assert_eq!(liveness.kind, Check::Tcp);
        assert_eq!(liveness.path, None);
        assert_eq!(liveness.interval, Duration::from_secs(10));
        assert_eq!(liveness.failure_threshold, 3);
    }

    #[test]
    fn rejects_a_liveness_interval_of_zero() {
        let err = AppManifest::parse(&with_liveness("interval: 0s"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("without ever pausing"), "{err}");
        assert!(err.contains("liveness"), "{err}");
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

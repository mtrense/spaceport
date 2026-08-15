//! Configuration loading and validation.
//!
//! Every section but `edge` is defaulted, and that is what lets a config file
//! written against an older spaceport go on working when a new section appears.
//! The reverse is not true: `deny_unknown_fields` at the top level means an
//! older binary handed a config that names a newer section — `build:`, say —
//! refuses to start rather than run with a setting it will not honour. That is
//! the same judgement [`Config::validate`] makes about ACME settings the
//! provider would ignore: configuration nobody reads still reads, to the
//! operator who wrote it, as configuration in force. Downgrading a spaceport
//! therefore means downgrading its config with it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, de};

use crate::app::manifest::Host;

/// Path used when no `--config` is given.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/spaceport/spaceport.yaml";

/// The only schema this build understands, for configs and app manifests alike.
pub const SCHEMA_VERSION: u64 = 1;

/// The config [`crate::setup`] writes when a host has none yet.
///
/// Everything mandatory, filled in with what a fresh host wants, and everything
/// else named in a comment: the file an operator opens next has to say what it
/// is they can change, because there is nowhere else on the host that does.
pub const REFERENCE_CONFIG: &str = "\
# Written by `spaceport setup` because this host had no config yet. Yours now —
# setup will not overwrite it again.
schema_version: 1
edge:
  # The host spaceport answers to as itself, rather than on behalf of an app.
  # Routed and certified exactly as an app's host is, and no app may claim it.
  # This is the address to hand to an outside service that has to call back.
  # Leave it out and spaceport answers to no name but its apps'.
  #
  # hostname: spaceport.example.com
  listen:
    http: 0.0.0.0:80
    https: 0.0.0.0:443
  tls:
    # `self-signed` generates a throwaway certificate at every start. Nothing
    # trusts it, so it is for development and nothing else.
    provider: self-signed

    # `acme` gets a real certificate per host from a CA, proving control of each
    # host over the plaintext listener. It needs the hosts' DNS to point here
    # and port 80 to be reachable from the internet.
    #
    # provider: acme
    # acme:
    #   # `staging`, `production`, or another CA's directory URL. Staging by
    #   # default: the first run of a new setup is the one most likely to be
    #   # wrong, and staging is the environment that forgives that.
    #   directory: staging
    #   # Where the CA sends expiry and revocation notices.
    #   contact: [mailto:ops@example.com]
    #   # No CA issues without this, so spaceport refuses to start without it.
    #   terms_of_service_agreed: true
state:
  # Where spaceport remembers the apps it has been told to run, and the
  # certificates it has been issued. Created if it is not there, and readable
  # only by the user spaceport runs as.
  directory: /var/lib/spaceport
data:
  # Where apps' own volumes live, one directory per app. Kept out of the state
  # directory: this is the data an app writes and an operator backs up, not
  # spaceport's own, and the two are not readable by the same people.
  directory: /var/lib/spaceport/apps
build:
  # Where a commit is unpacked and built, one subtree per connection and app.
  # Unlike the two directories above, spaceport deletes in here: a build tree is
  # scratch that the commit can produce again, and it is readable only by the
  # user spaceport runs as because it holds an app's source code.
  directory: /var/lib/spaceport/builds

  # How many built revisions of each app to keep. Three: the one running, the
  # one a rollback goes back to, and the one being built. At least 1 — the
  # sweep runs after a build, so keeping none would delete what was just built.
  #
  # keep: 3

  # The largest commit archive spaceport will download, in bytes. Refused on
  # what github says the size is, before any of it is read. 64 MiB by default:
  # a source tree larger than that is one with build outputs committed into it.
  #
  # max_archive_bytes: 67108864
";

/// A parsed and validated spaceport configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Declares which schema the rest of the document is written against.
    /// Mandatory, so a file that predates versioning is refused rather than
    /// guessed at.
    pub schema_version: SchemaVersion,

    /// How spaceport faces the outside world.
    pub edge: Edge,

    /// Where spaceport keeps what it must not forget. Defaulted, so an
    /// existing config file keeps working and a host that is happy with
    /// `/var/lib/spaceport` never has to say so.
    #[serde(default)]
    pub state: State,

    /// Where apps keep what *they* must not forget. Defaulted for the same
    /// reason `state` is: a config written before volumes existed has to go on
    /// working untouched.
    #[serde(default)]
    pub data: Data,

    /// Where commits are unpacked and built, and what a build is allowed to
    /// cost. Defaulted like the two above: a config written before spaceport
    /// built anything must go on working untouched.
    #[serde(default)]
    pub build: Build,
}

/// Where spaceport's durable state lives.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// The directory holding the state database and its lock. Created at
    /// startup if it is not there, owner-only.
    #[serde(default = "default_state_dir")]
    pub directory: PathBuf,
}

impl Default for State {
    fn default() -> Self {
        Self {
            directory: default_state_dir(),
        }
    }
}

fn default_state_dir() -> PathBuf {
    PathBuf::from(crate::state::DEFAULT_STATE_DIR)
}

/// Where apps' volumes live.
///
/// Separate from [`State`] on purpose. The state directory is owner-only
/// because it holds spaceport's keys; app data is the operator's to back up,
/// restore and hand to somebody else, and a directory cannot be both.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Data {
    /// The directory holding one subdirectory per app. Created at startup if
    /// it is not there.
    #[serde(default = "default_data_dir")]
    pub directory: PathBuf,
}

impl Default for Data {
    fn default() -> Self {
        Self {
            directory: default_data_dir(),
        }
    }
}

fn default_data_dir() -> PathBuf {
    PathBuf::from(crate::app::data::DEFAULT_DATA_DIR)
}

/// Where commits are unpacked and built.
///
/// A third directory rather than a corner of one of the other two, because it
/// is the only one of the three that is thrown away: [`crate::build::dir`]
/// deletes what has aged out, and a routine that deletes has no business
/// pointed at the directory holding an operator's backups or spaceport's keys.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Build {
    /// The directory a commit's source tree is unpacked under, one subtree per
    /// connection and app. Created at startup if it is not there, and readable
    /// only by the user spaceport runs as — it holds somebody's source code.
    #[serde(default = "default_build_dir")]
    pub directory: PathBuf,

    /// How many built revisions of each app to keep on disk.
    ///
    /// At least one: the sweep runs after a build, so `0` would mean deleting
    /// the tree the build just produced and the image was made from. An
    /// operator who wants nothing kept wants the build directory on a tmpfs,
    /// not a setting that makes every build delete its own evidence.
    #[serde(default = "default_builds_kept")]
    pub keep: usize,

    /// The largest commit archive that will be downloaded, in bytes, refused on
    /// the strength of what GitHub says before a byte of it is read.
    ///
    /// Spelled in bytes and named for it. There is a [`crate::duration`] module
    /// because durations appear all over a manifest and `30` was genuinely
    /// ambiguous; sizes appear exactly here, and one setting is not enough to
    /// justify a parser and a second syntax for an operator to remember. A
    /// number whose field name ends in `_bytes` is unambiguous without either.
    #[serde(default = "default_max_archive_bytes")]
    pub max_archive_bytes: u64,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            directory: default_build_dir(),
            keep: default_builds_kept(),
            max_archive_bytes: default_max_archive_bytes(),
        }
    }
}

fn default_build_dir() -> PathBuf {
    PathBuf::from(crate::build::dir::DEFAULT_BUILD_DIR)
}

fn default_builds_kept() -> usize {
    crate::build::dir::DEFAULT_REVISIONS_KEPT
}

/// 64 MiB. A source tree that does not fit is a repository with build outputs
/// or media committed into it, and unpacking one on a host that runs other
/// people's apps is a poor way to find out how much disk it wanted. The
/// constant lives with the config rather than with the code that enforces it
/// because the limit is an operator's judgement about their host, not a
/// property of the download.
const DEFAULT_MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;

fn default_max_archive_bytes() -> u64 {
    DEFAULT_MAX_ARCHIVE_BYTES
}

/// A schema version this build accepts.
///
/// Carries no value: the only version that parses is [`SCHEMA_VERSION`], so
/// having a parsed one in hand already says which schema it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaVersion;

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let version = u64::deserialize(deserializer)?;
        if version != SCHEMA_VERSION {
            return Err(de::Error::custom(format!(
                "unsupported schema version {version}, this spaceport reads {SCHEMA_VERSION}"
            )));
        }
        Ok(Self)
    }
}

/// The edge is where client traffic enters spaceport.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    /// The host spaceport answers to as itself, rather than on behalf of an
    /// app. It is routed exactly as an app's host is — claimed against every
    /// app, certified with the same machinery — and it is what an outside
    /// service is given when it needs somewhere to call back to.
    ///
    /// Optional, because a host that only proxies apps needs no address of its
    /// own and a config written before this existed has to go on working. A
    /// spaceport without one simply answers to no name but its apps'.
    #[serde(default)]
    pub hostname: Option<Host>,

    pub listen: Listen,

    /// Where the `https` listener gets its certificate.
    #[serde(default)]
    pub tls: Tls,
}

/// How the edge obtains its certificates.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    #[serde(default)]
    pub provider: TlsProvider,

    /// Which CA to order from, and on whose behalf. Only meaningful — and
    /// mandatory — when the provider is [`TlsProvider::Acme`].
    pub acme: Option<Acme>,
}

/// The source of the certificate the `https` listener serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsProvider {
    /// Generate a throwaway certificate at every start. Nothing trusts it;
    /// this is for development only.
    #[default]
    SelfSigned,
    /// Order a certificate per host from an ACME CA, proving control over each
    /// one with an `HTTP-01` challenge served off the plaintext listener.
    Acme,
}

/// What an ACME CA has to be told before it will issue anything.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acme {
    /// The CA to order from. Defaults to Let's Encrypt's staging environment,
    /// because the first run of a new setup is the one most likely to be wrong
    /// and staging is the environment that forgives that.
    #[serde(default)]
    pub directory: Directory,

    /// How the CA reaches the operator — `mailto:` URIs — for expiry warnings
    /// and the occasional "we are revoking your certificate" mail. Optional,
    /// and a setup that gives none gets no warning.
    #[serde(default)]
    pub contact: Vec<String>,

    /// Whether the operator agrees to the CA's terms of service. No CA issues
    /// without it, so spaceport refuses to start rather than ask the CA a
    /// question it already knows the answer to.
    #[serde(default)]
    pub terms_of_service_agreed: bool,
}

/// The ACME directory to order from.
///
/// Two well-known environments have names, because typing a Let's Encrypt URL
/// from memory is how a setup meant for staging ends up burning production rate
/// limits. Anything else is given as a URL.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Directory {
    /// Let's Encrypt's staging environment. Certificates nothing trusts, rate
    /// limits nothing minds.
    #[default]
    Staging,
    /// Let's Encrypt proper.
    Production,
    /// Any other CA's directory URL.
    Url(String),
}

impl Directory {
    /// The directory URL to point an ACME client at.
    pub fn url(&self) -> &str {
        match self {
            Self::Staging => instant_acme::LetsEncrypt::Staging.url(),
            Self::Production => instant_acme::LetsEncrypt::Production.url(),
            Self::Url(url) => url,
        }
    }
}

impl<'de> Deserialize<'de> for Directory {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        match raw.as_str() {
            "staging" => Ok(Self::Staging),
            "production" => Ok(Self::Production),
            // An ACME account key travels over this connection. A directory
            // that is not `https` is not one to send it to.
            url if url.starts_with("https://") => Ok(Self::Url(raw)),
            other => Err(de::Error::custom(format!(
                "`{other}` is neither `staging`, `production`, nor an https directory URL"
            ))),
        }
    }
}

/// Addresses the edge binds to. Both are mandatory: spaceport always serves
/// plaintext (ACME `HTTP-01` needs it) and always serves TLS.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    pub http: SocketAddr,
    pub https: SocketAddr,
}

impl Config {
    /// Read, parse and validate the configuration at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file `{}`", path.display()))?;

        Self::parse(&raw).with_context(|| format!("invalid config file `{}`", path.display()))
    }

    /// Parse and validate a configuration document.
    pub fn parse(raw: &str) -> Result<Self> {
        let config: Self = serde_norway::from_str(raw)?;
        config.validate()?;

        Ok(config)
    }

    /// What serde cannot express: the rules that span more than one field.
    fn validate(&self) -> Result<()> {
        // The sweep runs after a build, so keeping none would delete the tree
        // the running image was built from — and the operator who wrote `0`
        // meant "keep the current one", which is `1`.
        if self.build.keep == 0 {
            bail!(
                "build.keep must be at least 1: a build's own source tree is swept away with the rest, so keeping none would delete what was just built"
            );
        }
        if self.build.max_archive_bytes == 0 {
            bail!(
                "build.max_archive_bytes must be at least 1: a limit of zero refuses every commit"
            );
        }

        match (self.edge.tls.provider, &self.edge.tls.acme) {
            (TlsProvider::Acme, None) => {
                bail!("edge.tls.acme is required when the tls provider is `acme`")
            }
            (TlsProvider::Acme, Some(acme)) if !acme.terms_of_service_agreed => bail!(
                "edge.tls.acme.terms_of_service_agreed must be `true`: no CA issues a \
                 certificate to somebody who has not agreed to its terms"
            ),
            // Settings that are read by nobody are settings an operator
            // believes are in force. Say so now rather than at the incident.
            (TlsProvider::SelfSigned, Some(_)) => {
                bail!("edge.tls.acme is set, but the tls provider is `self-signed`")
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config with everything mandatory filled in, for tests to extend.
    const MINIMAL: &str = "
schema_version: 1
edge:
  listen:
    http: 0.0.0.0:80
    https: 0.0.0.0:443
";

    /// The example is documentation, and documentation that does not parse is
    /// worse than none.
    #[test]
    fn the_shipped_example_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/config.yaml");
        let raw = std::fs::read_to_string(&path).unwrap();

        Config::parse(&raw).unwrap();
    }

    /// `spaceport setup` writes this one onto hosts, unread, and a host whose
    /// service will not start is a poor way to find out it does not parse.
    #[test]
    fn the_reference_config_is_valid() {
        let config = Config::parse(REFERENCE_CONFIG).unwrap();

        assert_eq!(config.edge.tls.provider, TlsProvider::SelfSigned);
        assert_eq!(
            config.state.directory,
            PathBuf::from(crate::state::DEFAULT_STATE_DIR)
        );
        assert_eq!(
            config.build.directory,
            PathBuf::from(crate::build::dir::DEFAULT_BUILD_DIR)
        );
    }

    #[test]
    fn accepts_the_current_schema_version() {
        assert_eq!(
            Config::parse(MINIMAL).unwrap().schema_version,
            SchemaVersion
        );
    }

    #[test]
    fn rejects_a_future_schema_version() {
        let raw = MINIMAL.replace("schema_version: 1", "schema_version: 2");
        let err = Config::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("unsupported schema version 2"), "{err}");
    }

    #[test]
    fn rejects_a_missing_schema_version() {
        let raw = MINIMAL.replace("schema_version: 1\n", "");
        let err = Config::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("schema_version"), "{err}");
    }

    #[test]
    fn rejects_a_non_numeric_schema_version() {
        let raw = MINIMAL.replace("schema_version: 1", "schema_version: '1'");
        assert!(Config::parse(&raw).is_err());
    }

    #[test]
    fn defaults_to_a_self_signed_certificate() {
        let config = Config::parse(MINIMAL).unwrap();
        assert_eq!(config.edge.tls.provider, TlsProvider::SelfSigned);
    }

    #[test]
    fn rejects_an_unknown_tls_provider() {
        let err = Config::parse(&format!("{MINIMAL}  tls:\n    provider: magic\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("magic"), "{err}");
    }

    /// An acme block, indented to sit under `edge.tls`.
    fn with_acme(body: &str) -> String {
        format!("{MINIMAL}  tls:\n    provider: acme\n    acme:\n{body}")
    }

    #[test]
    fn orders_from_staging_unless_told_otherwise() {
        let config = Config::parse(&with_acme("      terms_of_service_agreed: true\n")).unwrap();
        let acme = config.edge.tls.acme.unwrap();

        assert_eq!(config.edge.tls.provider, TlsProvider::Acme);
        assert_eq!(acme.directory, Directory::Staging);
        assert!(acme.contact.is_empty());
        assert!(acme.directory.url().contains("staging"));
    }

    #[test]
    fn takes_the_directory_and_contacts_the_config_names() {
        let config = Config::parse(&with_acme(
            "      terms_of_service_agreed: true\n      directory: production\n      \
             contact: [mailto:ops@example.com]\n",
        ))
        .unwrap();
        let acme = config.edge.tls.acme.unwrap();

        assert_eq!(acme.directory, Directory::Production);
        assert_eq!(
            acme.directory.url(),
            instant_acme::LetsEncrypt::Production.url()
        );
        assert_eq!(acme.contact, ["mailto:ops@example.com"]);
    }

    #[test]
    fn takes_another_cas_directory_url() {
        let config = Config::parse(&with_acme(
            "      terms_of_service_agreed: true\n      directory: https://acme.example/dir\n",
        ))
        .unwrap();

        assert_eq!(
            config.edge.tls.acme.unwrap().directory.url(),
            "https://acme.example/dir"
        );
    }

    /// The account key is posted to this URL. Plaintext is not a place to
    /// send it, and a typo that downgrades it must not pass silently.
    #[test]
    fn rejects_a_directory_that_is_not_https() {
        let err = Config::parse(&with_acme(
            "      terms_of_service_agreed: true\n      directory: http://acme.example/dir\n",
        ))
        .unwrap_err()
        .to_string();

        assert!(err.contains("https"), "{err}");
    }

    #[test]
    fn rejects_acme_without_a_ca_to_order_from() {
        let err = Config::parse(&format!("{MINIMAL}  tls:\n    provider: acme\n"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("edge.tls.acme is required"), "{err}");
    }

    #[test]
    fn rejects_acme_without_agreeing_to_the_terms() {
        let err = Config::parse(&with_acme("      contact: [mailto:ops@example.com]\n"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("terms_of_service_agreed"), "{err}");
    }

    /// Configuration that is read by nobody reads as configuration that is in
    /// force. It is not, and saying so at startup is the cheapest place to.
    #[test]
    fn rejects_acme_settings_the_provider_would_ignore() {
        let err = Config::parse(&format!(
            "{MINIMAL}  tls:\n    provider: self-signed\n    acme:\n      \
             terms_of_service_agreed: true\n"
        ))
        .unwrap_err()
        .to_string();

        assert!(err.contains("self-signed"), "{err}");
    }

    /// A config written before spaceport had an address of its own has to go on
    /// working, and does: without the key it simply answers to no name but its
    /// apps'.
    #[test]
    fn has_no_hostname_of_its_own_unless_given_one() {
        assert_eq!(Config::parse(MINIMAL).unwrap().edge.hostname, None);
    }

    #[test]
    fn takes_the_hostname_the_config_names() {
        let raw = MINIMAL.replace("edge:\n", "edge:\n  hostname: Spaceport.Example.COM\n");
        let config = Config::parse(&raw).unwrap();

        // Normalised on the way in, exactly as an app's host is: the routing
        // table is a plain map and the edge never has to think about case.
        assert_eq!(
            config.edge.hostname.unwrap().as_str(),
            "spaceport.example.com"
        );
    }

    /// The same validation an app's host gets — a hostname spaceport cannot
    /// route is worth refusing at startup rather than at the first callback.
    #[test]
    fn rejects_a_hostname_that_could_never_be_routed() {
        // A port never matches (the edge strips it before looking a host up), a
        // leading hyphen is not a label, and an underscore is not a hostname.
        for (bad, reason) in [
            ("spaceport.example.com:443", "without a port"),
            ("-nope.test", "hyphen"),
            ("not_a_host.test", "letters, digits, hyphens and dots"),
        ] {
            let raw = MINIMAL.replace("edge:\n", &format!("edge:\n  hostname: {bad}\n"));
            let err = Config::parse(&raw).unwrap_err().to_string();

            assert!(err.contains(reason), "{bad}: {err}");
        }
    }

    #[test]
    fn parses_both_listeners() {
        let config = Config::parse(MINIMAL).unwrap();

        assert_eq!(
            config.edge.listen,
            Listen {
                http: "0.0.0.0:80".parse().unwrap(),
                https: "0.0.0.0:443".parse().unwrap(),
            }
        );
    }

    #[test]
    fn rejects_a_missing_listener() {
        let err = Config::parse("schema_version: 1\nedge:\n  listen:\n    https: '[::]:443'\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("http"), "{err}");
    }

    #[test]
    fn defaults_the_state_directory() {
        let config = Config::parse(MINIMAL).unwrap();

        assert_eq!(config.state.directory, PathBuf::from("/var/lib/spaceport"));
    }

    #[test]
    fn takes_the_state_directory_the_config_names() {
        let config =
            Config::parse(&format!("{MINIMAL}state:\n  directory: /srv/spaceport\n")).unwrap();

        assert_eq!(config.state.directory, PathBuf::from("/srv/spaceport"));
    }

    /// A config written before apps could ask for a volume has to go on
    /// working untouched, and that is what the default is for.
    #[test]
    fn defaults_the_data_directory() {
        let config = Config::parse(MINIMAL).unwrap();

        assert_eq!(
            config.data.directory,
            PathBuf::from("/var/lib/spaceport/apps")
        );
    }

    #[test]
    fn takes_the_data_directory_the_config_names() {
        let config = Config::parse(&format!("{MINIMAL}data:\n  directory: /srv/apps\n")).unwrap();

        assert_eq!(config.data.directory, PathBuf::from("/srv/apps"));
    }

    /// They default to one inside the other, but they are separate settings:
    /// app data is what an operator backs up and hands around, and spaceport's
    /// keys are not.
    #[test]
    fn keeps_the_data_directory_independent_of_the_state_directory() {
        let config =
            Config::parse(&format!("{MINIMAL}state:\n  directory: /srv/spaceport\n")).unwrap();

        assert_eq!(
            config.data.directory,
            PathBuf::from("/var/lib/spaceport/apps")
        );
    }

    /// A config written before spaceport built anything has to go on working,
    /// and these are the numbers such a host silently gets.
    #[test]
    fn defaults_the_build_settings() {
        let config = Config::parse(MINIMAL).unwrap();

        assert_eq!(
            config.build.directory,
            PathBuf::from("/var/lib/spaceport/builds")
        );
        assert_eq!(config.build.keep, 3);
        assert_eq!(config.build.max_archive_bytes, 64 * 1024 * 1024);
        assert_eq!(config.build, Build::default());
    }

    #[test]
    fn takes_the_build_settings_the_config_names() {
        let config = Config::parse(&format!(
            "{MINIMAL}build:\n  directory: /srv/builds\n  keep: 1\n  max_archive_bytes: 1024\n"
        ))
        .unwrap();

        assert_eq!(config.build.directory, PathBuf::from("/srv/builds"));
        assert_eq!(config.build.keep, 1);
        assert_eq!(config.build.max_archive_bytes, 1024);
    }

    /// The sweep runs after the build, so `keep: 0` would take away the tree
    /// the running image was built from — which is not what anybody typing it
    /// means.
    #[test]
    fn rejects_keeping_no_builds_at_all() {
        let err = Config::parse(&format!("{MINIMAL}build:\n  keep: 0\n"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("build.keep must be at least 1"), "{err}");
    }

    #[test]
    fn rejects_an_archive_limit_that_refuses_everything() {
        let err = Config::parse(&format!("{MINIMAL}build:\n  max_archive_bytes: 0\n"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("max_archive_bytes"), "{err}");
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = Config::parse(&format!("{MINIMAL}  typo: 1\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("typo"), "{err}");
    }

    #[test]
    fn rejects_a_malformed_address() {
        let raw = MINIMAL.replace("http: 0.0.0.0:80", "http: 0.0.0.0");
        let err = Config::parse(&raw).unwrap_err().to_string();

        assert!(err.contains("edge.listen.http"), "{err}");
    }
}

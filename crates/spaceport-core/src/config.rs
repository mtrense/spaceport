//! Configuration loading and validation.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, de};

/// Path used when no `--config` is given.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/spaceport/spaceport.yaml";

/// The only schema this build understands, for configs and app manifests alike.
pub const SCHEMA_VERSION: u64 = 1;

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

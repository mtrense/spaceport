//! Configuration loading and validation.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Path used when no `--config` is given.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/spaceport/spaceport.yaml";

/// A parsed and validated spaceport configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// How spaceport faces the outside world.
    pub edge: Edge,
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
}

/// The source of the certificate the `https` listener serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsProvider {
    /// Generate a throwaway certificate at every start. Nothing trusts it;
    /// this is for development only.
    #[default]
    SelfSigned,
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
        Ok(serde_norway::from_str(raw)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config with everything mandatory filled in, for tests to extend.
    const MINIMAL: &str = "
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
    fn defaults_to_a_self_signed_certificate() {
        let config = Config::parse(MINIMAL).unwrap();
        assert_eq!(config.edge.tls.provider, TlsProvider::SelfSigned);
    }

    #[test]
    fn rejects_an_unknown_tls_provider() {
        let err = Config::parse(&format!("{MINIMAL}  tls:\n    provider: acme\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("acme"), "{err}");
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
        let err = Config::parse("edge:\n  listen:\n    https: '[::]:443'\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("http"), "{err}");
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
        assert!(Config::parse("edge:\n  listen:\n    http: 0.0.0.0\n    https: 0.0.0.0:443\n").is_err());
    }
}

//! Configuration loading and validation.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};
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
}

/// Addresses the edge binds to. Both are optional individually, but at least
/// one has to be present for spaceport to be reachable.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    pub http: Option<SocketAddr>,
    pub https: Option<SocketAddr>,
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

    /// Check the invariants that the type system doesn't cover.
    fn validate(&self) -> Result<()> {
        if self.edge.listen.http.is_none() && self.edge.listen.https.is_none() {
            bail!("edge.listen: at least one of `http` or `https` must be set");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_listeners() {
        let config = Config::parse(
            "
edge:
  listen:
    http: 0.0.0.0:80
    https: 0.0.0.0:443
",
        )
        .unwrap();

        assert_eq!(
            config.edge.listen,
            Listen {
                http: Some("0.0.0.0:80".parse().unwrap()),
                https: Some("0.0.0.0:443".parse().unwrap()),
            }
        );
    }

    #[test]
    fn parses_a_single_listener() {
        let config = Config::parse("edge:\n  listen:\n    https: '[::]:443'\n").unwrap();

        assert_eq!(config.edge.listen.http, None);
        assert_eq!(config.edge.listen.https, Some("[::]:443".parse().unwrap()));
    }

    #[test]
    fn rejects_an_edge_without_listeners() {
        let err = Config::parse("edge:\n  listen: {}\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("at least one of"), "{err}");
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = Config::parse("edge:\n  listen:\n    http: 0.0.0.0:80\n  typo: 1\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("typo"), "{err}");
    }

    #[test]
    fn rejects_a_malformed_address() {
        assert!(Config::parse("edge:\n  listen:\n    http: 0.0.0.0\n").is_err());
    }
}

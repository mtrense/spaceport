//! Apps: what spaceport runs and routes traffic to.

pub mod apply;
pub mod data;
pub mod deploy;
pub mod health;
pub mod manifest;
pub mod pattern;
pub mod reconcile;
pub mod repository;
pub mod secrets;
pub mod store;
pub mod supervisor;

pub use apply::{Applied, Applier, Restored};
pub use data::DataDir;
pub use manifest::{AppManifest, VarName};
pub use pattern::Pattern;
pub use reconcile::reconcile;
pub use repository::{AppRecord, AppRepository};
pub use secrets::{SecretRepository, StoredSecret};
pub use store::{App, AppStore, Downed, Removed, Route, Routes, Suspended};
pub use supervisor::supervise;

use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Longest an app id may be, matching a single DNS label.
const MAX_ID_LEN: usize = 63;

/// The name an operator gives an app.
///
/// Deliberately narrow: an id ends up in container labels, host directory
/// names and log lines, so it is restricted to what all of them accept
/// without quoting or escaping.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AppId(String);

impl AppId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for AppId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("an app id must not be empty");
        }
        if s.len() > MAX_ID_LEN {
            bail!("app id `{s}` is longer than {MAX_ID_LEN} characters");
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            bail!("app id `{s}` may only contain lowercase letters, digits and hyphens");
        }
        if s.starts_with('-') || s.ends_with('-') {
            bail!("app id `{s}` must not start or end with a hyphen");
        }

        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for AppId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// An id off the wire is as untrusted as one off the command line, so it is
/// held to the same rules rather than being taken as read.
impl<'de> Deserialize<'de> for AppId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let id = String::deserialize(deserializer)?;

        id.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_plain_id() {
        assert_eq!(
            "hello-world".parse::<AppId>().unwrap().as_str(),
            "hello-world"
        );
    }

    #[test]
    fn rejects_an_empty_id() {
        assert!("".parse::<AppId>().is_err());
    }

    #[test]
    fn rejects_uppercase() {
        let err = "Hello".parse::<AppId>().unwrap_err().to_string();
        assert!(err.contains("lowercase"), "{err}");
    }

    #[test]
    fn rejects_separators_that_would_need_escaping() {
        for id in ["my app", "my/app", "my.app", "my_app"] {
            assert!(id.parse::<AppId>().is_err(), "accepted `{id}`");
        }
    }

    #[test]
    fn rejects_a_leading_or_trailing_hyphen() {
        assert!("-app".parse::<AppId>().is_err());
        assert!("app-".parse::<AppId>().is_err());
    }

    #[test]
    fn rejects_an_overlong_id() {
        let err = "a".repeat(64).parse::<AppId>().unwrap_err().to_string();
        assert!(err.contains("longer than 63"), "{err}");
    }
}

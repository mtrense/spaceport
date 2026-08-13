//! Apps: what spaceport runs and routes traffic to.

pub mod apply;
pub mod health;
pub mod manifest;
pub mod pattern;
pub mod reconcile;
pub mod repository;
pub mod store;

pub use apply::{Applier, Restored};
pub use manifest::AppManifest;
pub use pattern::Pattern;
pub use reconcile::reconcile;
pub use repository::{AppRecord, AppRepository};
pub use store::{App, AppStore, Routes};

use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};

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

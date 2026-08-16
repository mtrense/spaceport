//! The operator interface: where spaceport is told what to run.
//!
//! Separate from the edge in every way that matters. The edge is public and
//! serves whoever connects; this is private, and whoever reaches it can start
//! containers. Hence the default of a unix socket, where the filesystem does
//! the access control — a TCP endpoint is available for the cases that need it
//! and is nobody's default.

pub mod client;
pub mod server;

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

/// What setting a secret did, as the operator interface answers it.
///
/// Data where every other app route answers in prose, for the reason `/status`
/// does: what is worth saying depends on who is reading. Storing a value can
/// leave the app untouched, still waiting for other secrets, serving again, or
/// on a fresh container — four different next steps for whoever typed the
/// command — and a sentence composed on the server would have the CLI reading
/// it back to find out which.
///
/// It lives here rather than in either half, because both halves need it and
/// neither owns it: the server writes one and the client reads it, exactly as
/// they share [`crate::status::Status`].
///
/// There is no value anywhere in it and there never can be one. The value went
/// up in the request body; what comes back is a flag, a verb and a list of
/// names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretSet {
    /// Whether there was no value under this name before.
    ///
    /// `false` both for a value that replaced a different one and for one that
    /// replaced nothing because it was the same — [`SecretOutcome::Unchanged`]
    /// is what tells those apart.
    pub created: bool,

    #[serde(flatten)]
    pub outcome: SecretOutcome,
}

/// What became of the app once its secret was stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SecretOutcome {
    /// The stored value was byte for byte the one being set, so nothing was
    /// touched. Re-running a `set` must not restart anybody's app.
    Unchanged,
    /// Stored, and nothing here was waiting on it, so nothing was started.
    ///
    /// Three ways to arrive at the same fact: no manifest is applied under this
    /// app at all, or the one that is does not declare this name — so nothing
    /// reads it and the container it would produce is the one already running —
    /// or the app is recorded suspended and is not in this spaceport's routing
    /// table, which is not a suspension a secret ends.
    Stored,
    /// Stored, and the app's manifest declares secrets that are still not set.
    Missing { secrets: Vec<String> },
    /// Stored, and it was the last thing the suspended app was waiting for, so
    /// it is serving again.
    Resumed,
    /// Stored, and the app was already running, so its container was replaced
    /// with one carrying the new value.
    Redeployed,
    /// Stored, and the app was down rather than running, so it was started on
    /// the new value.
    ///
    /// Its own answer and not [`SecretOutcome::Redeployed`], because there was
    /// no container to replace: an app that is down has already lost the one it
    /// had, and telling an operator their container was replaced would describe
    /// something that did not happen.
    Started,
}

/// Where `spaceport apps` looks for a running spaceport when not told
/// otherwise.
pub const DEFAULT_OPERATOR_ENDPOINT: &str = "/run/spaceport.sock";

/// Address the operator interface listens on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorEndpoint {
    /// A unix domain socket at the given path.
    Unix(PathBuf),
    /// A TCP socket bound to a local address.
    Tcp(SocketAddr),
}

impl FromStr for OperatorEndpoint {
    type Err = anyhow::Error;

    /// Anything that looks like a path (contains a `/`, or carries an explicit
    /// `unix:` scheme) is a unix socket; everything else must parse as a
    /// socket address.
    fn from_str(s: &str) -> Result<Self> {
        if let Some(path) = s.strip_prefix("unix:") {
            return Ok(Self::Unix(PathBuf::from(path)));
        }
        if s.contains('/') {
            return Ok(Self::Unix(PathBuf::from(s)));
        }
        s.parse::<SocketAddr>()
            .map(Self::Tcp)
            .map_err(|e| anyhow!("`{s}` is neither a unix socket path nor a socket address: {e}"))
    }
}

impl fmt::Display for OperatorEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
            Self::Tcp(addr) => write!(f, "{addr}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_socket_addresses() {
        assert_eq!(
            "127.0.0.1:8080".parse::<OperatorEndpoint>().unwrap(),
            OperatorEndpoint::Tcp("127.0.0.1:8080".parse().unwrap())
        );
        assert_eq!(
            "[::1]:8080".parse::<OperatorEndpoint>().unwrap(),
            OperatorEndpoint::Tcp("[::1]:8080".parse().unwrap())
        );
    }

    #[test]
    fn parses_unix_socket_paths() {
        assert_eq!(
            "/run/spaceport.sock".parse::<OperatorEndpoint>().unwrap(),
            OperatorEndpoint::Unix("/run/spaceport.sock".into())
        );
        assert_eq!(
            "unix:spaceport.sock".parse::<OperatorEndpoint>().unwrap(),
            OperatorEndpoint::Unix("spaceport.sock".into())
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!("not-an-endpoint".parse::<OperatorEndpoint>().is_err());
    }
}

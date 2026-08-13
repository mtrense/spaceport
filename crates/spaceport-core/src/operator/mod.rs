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

//! The operator interface: where spaceport is told what to run.
//!
//! Separate from the edge in every way that matters. The edge is public and
//! serves whoever connects; this is private, and whoever reaches it can start
//! containers, read every secret and mint credentials for anybody. So it is a
//! unix socket and only ever a unix socket, where the filesystem does the
//! access control and the kernel refuses anything off this host.
//!
//! There is deliberately no way to put it on a port. Serving this interface —
//! unauthenticated and in the clear, because a mode-0600 socket needs neither —
//! on a TCP address would hand whoever can reach that address the whole host,
//! and the address is the sort of thing that gets widened to `0.0.0.0` by
//! somebody in a hurry. Reaching a spaceport from elsewhere is what SSH is
//! for: `ssh host spaceport apps ...`, or a forwarded socket.

pub mod client;
pub mod server;
pub mod wire;

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

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

/// Where the operator interface listens: the path of a unix socket.
///
/// A named type over a bare [`PathBuf`] because a socket address used to be
/// spellable here, and the parser is where an operator who still spells one
/// finds out it is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorEndpoint(PathBuf);

impl OperatorEndpoint {
    /// The socket to bind, or to connect to.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl From<PathBuf> for OperatorEndpoint {
    fn from(path: PathBuf) -> Self {
        Self(path)
    }
}

impl FromStr for OperatorEndpoint {
    type Err = anyhow::Error;

    /// A path, with or without an explicit `unix:` scheme.
    ///
    /// Something shaped like a socket address is refused rather than taken as
    /// the peculiar filename it technically is: it is what a spaceport
    /// configured before the TCP endpoint was removed says, and silently
    /// binding `./127.0.0.1:8080` would leave an operator hunting for a socket
    /// nobody is listening on.
    fn from_str(s: &str) -> Result<Self> {
        if let Some(path) = s.strip_prefix("unix:") {
            return named(path);
        }
        if !s.contains('/') && s.contains(':') {
            return Err(anyhow!(
                "`{s}` is a network address, and the operator interface only listens on a unix \
                 socket — give it a path (`{DEFAULT_OPERATOR_ENDPOINT}`), and reach a spaceport \
                 elsewhere over ssh. Spell it `unix:{s}` if that really is the filename you meant."
            ));
        }
        named(s)
    }
}

fn named(path: &str) -> Result<OperatorEndpoint> {
    if path.is_empty() {
        return Err(anyhow!("the operator interface needs a socket path"));
    }

    Ok(OperatorEndpoint(PathBuf::from(path)))
}

/// How long a command waits for an answer before it decides nothing is coming.
///
/// Thirty seconds is far longer than any ordinary route takes and far shorter
/// than a person will sit in front of a terminal wondering.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// What the patient tier multiplies a deadline by.
///
/// Two tiers exist because two kinds of request live behind one interface.
/// Ordinary routes read state and answer at once. Apply, deploy, resume and
/// setting a secret block server-side while the [`crate::app::Applier`] waits
/// for the new container to become healthy — a wait the manifest spells, and
/// manifests spell minutes (see [`crate::app::health`]). The github commands
/// page outbound to github.com, up to five hundred requests deep. A thirty
/// second deadline on those would not catch a spaceport that has stopped
/// answering; it would abort work that is succeeding, and leave the operator
/// with a half-applied app and an error saying nothing happened.
const PATIENT_MULTIPLE: u32 = 10;

/// A spaceport to talk to, and how long to wait for it.
///
/// The two travel together because neither is any use alone: every call in
/// [`client`] needs a socket to reach and a point at which to stop hoping.
///
/// A `timeout` of [`Duration::ZERO`] is the escape hatch — no deadline at all,
/// for the operator who knows their apply takes an hour and would rather watch
/// it than argue with a clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operator {
    pub endpoint: OperatorEndpoint,
    pub timeout: Duration,
}

impl fmt::Display for OperatorEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unix:{}", self.0.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(raw: &str) -> OperatorEndpoint {
        raw.parse().unwrap()
    }

    #[test]
    fn parses_unix_socket_paths() {
        assert_eq!(
            parsed("/run/spaceport.sock").path(),
            Path::new("/run/spaceport.sock")
        );
        assert_eq!(
            parsed("unix:spaceport.sock").path(),
            Path::new("spaceport.sock")
        );
        assert_eq!(parsed("spaceport.sock").path(), Path::new("spaceport.sock"));
    }

    /// The security fix, in the one place an operator meets it: whoever
    /// upgrades with a port in their unit file is told, rather than handed a
    /// socket named after an address they cannot reach.
    #[test]
    fn refuses_a_network_address() {
        for raw in [
            "127.0.0.1:8080",
            "0.0.0.0:8080",
            "[::1]:8080",
            "example.com:9000",
        ] {
            let err = raw.parse::<OperatorEndpoint>().unwrap_err().to_string();

            assert!(err.contains("unix socket"), "{raw}: {err}");
        }
    }

    /// The escape hatch the refusal names has to actually work.
    #[test]
    fn takes_an_address_shaped_filename_under_the_scheme() {
        assert_eq!(
            parsed("unix:127.0.0.1:8080").path(),
            Path::new("127.0.0.1:8080")
        );
    }

    #[test]
    fn rejects_nothing_at_all() {
        assert!("".parse::<OperatorEndpoint>().is_err());
        assert!("unix:".parse::<OperatorEndpoint>().is_err());
    }
}

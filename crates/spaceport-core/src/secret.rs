//! A string that must not turn up in a log line.
//!
//! A spaceport holds values it has to keep: the client secret, webhook secret
//! and private key of a connection, and the secrets an operator has set on an
//! app. Every one of them grants somebody the right to act as something. The
//! danger is never that an operator deliberately prints one; it is that the
//! struct holding it is `Debug`-formatted into a `tracing` field, or panics
//! inside an `assert_eq!`, or gets a field added to a response struct one
//! afternoon, and the secret rides along because a `String` has no opinion
//! about where it is allowed to go.
//!
//! It lives at the crate root and not under one of the things that has
//! secrets, because both of those want the same type and neither owns it — a
//! connection's private key and an app's database password are the same
//! problem twice.
//!
//! So the plaintext lives behind a type whose `Debug` and `Display` both print
//! `Secret(…)`, and whose only way out is [`Secret::expose`] — a name chosen to
//! read badly at the call site, so that every place the plaintext is actually
//! needed is one grep away and one review comment away.
//!
//! [`serde::Serialize`] is deliberately **not** implemented. What holds a
//! secret is rendered to an operator, and a derived `Serialize` would leak the
//! moment somebody put the field in a response. `Deserialize` is implemented,
//! because secrets arrive from GitHub's manifest-conversion response and from
//! an operator on the command line, and refusing to read them in would only
//! mean reading them in as a `String` somewhere less careful.
//!
//! What this is not: encryption at rest, or a guard against a process that can
//! read spaceport's own memory. Anybody with the state database has the secrets
//! already — see the migration that stores them.

use std::fmt;

use serde::{Deserialize, Deserializer};

/// What a formatted secret says instead of its value.
///
/// The ellipsis rather than a run of asterisks, because a fixed number of stars
/// invites the reader to guess at a length and a variable one would tell them
/// the length outright.
const REDACTED: &str = "Secret(…)";

/// A value that grants something, wrapped so it cannot be printed by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The plaintext, for the one call that genuinely needs it — signing a JWT,
    /// verifying an HMAC, writing the row.
    ///
    /// Named to be conspicuous: an operator reading a diff should be able to
    /// see every place a secret leaves this type.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for Secret {
    /// The same as `Debug`, on purpose. A `Display` that printed the value
    /// would mean `{secret}` in a message string is a leak while `{secret:?}`
    /// is not, which is a distinction nobody remembers at three in the morning.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<'de> Deserialize<'de> for Secret {
    /// Read as a plain string, because that is what GitHub sends and what an
    /// operator types. The protection is on the way out, not on the way in.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAINTEXT: &str = "ghp-not-a-real-token-0123456789";

    /// The whole reason the type exists: neither formatting trait may put the
    /// value anywhere a log line or a panic message could pick it up.
    #[test]
    fn debug_and_display_both_hide_the_value() {
        let secret = Secret::new(PLAINTEXT);

        let debugged = format!("{secret:?}");
        let displayed = format!("{secret}");

        assert!(!debugged.contains(PLAINTEXT), "{debugged}");
        assert!(!displayed.contains(PLAINTEXT), "{displayed}");
        assert_eq!(debugged, REDACTED);
        assert_eq!(displayed, REDACTED);
    }

    /// A secret nested in a struct is the realistic leak, and it stays hidden
    /// because the field's own `Debug` is what runs.
    #[test]
    fn stays_hidden_inside_a_struct_that_derives_debug() {
        #[derive(Debug)]
        struct Holder {
            #[expect(dead_code, reason = "only ever read by the derived `Debug`")]
            token: Secret,
        }

        let printed = format!(
            "{:?}",
            Holder {
                token: Secret::new(PLAINTEXT),
            }
        );

        assert!(!printed.contains(PLAINTEXT), "{printed}");
    }

    #[test]
    fn exposes_the_value_when_it_is_asked_for_by_name() {
        assert_eq!(Secret::new(PLAINTEXT).expose(), PLAINTEXT);
        assert_eq!(Secret::from(PLAINTEXT.to_owned()).expose(), PLAINTEXT);
    }

    #[test]
    fn deserialises_from_a_json_string() {
        let secret: Secret = serde_json::from_str(&format!("\"{PLAINTEXT}\"")).unwrap();

        assert_eq!(secret, Secret::new(PLAINTEXT));
    }

    #[test]
    fn compares_by_value_so_tests_can_assert_on_it() {
        assert_eq!(Secret::new("same"), Secret::new("same"));
        assert_ne!(Secret::new("one"), Secret::new("another"));
    }
}

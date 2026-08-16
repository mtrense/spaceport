//! The global user pool: who spaceport knows, whatever it later lets them do.
//!
//! Everything the auth spec builds — sessions, entitlements, API keys, the
//! JWTs handed down to apps — hangs off the one identity this module mints: a
//! user id that is a UUID, made once and never reused. The slug beside it is a
//! handle for operators, unique only among live users; dropping a user deletes
//! the record, and the same slug created again names a *different* user with a
//! fresh id. That asymmetry is deliberate, and it is why the pool and the
//! append-only event log ship together: the log is the only place a dropped
//! user's history survives.
//!
//! Entitlements are the first thing to hang off that identity: one row per
//! user, app and role, granted by hand over the operator socket and — in a
//! later milestone — mapped from SSO logins. Sessions are the second: an
//! opaque token in a cookie on the edge hostname, backed by a database row,
//! reached today through a one-time code an operator mints and — when SSO and
//! SMTP land — through logins that arrive from outside. Suspending or dropping
//! a user is the immediate-offboarding lever, and the repository's `offboard`
//! cascade is where sessions and pending codes already die with the user.

pub mod api_key;
pub mod app_session;
pub mod entitlement;
pub mod jwt;
pub mod log;
pub mod mapping;
pub mod repository;
pub mod session;
pub mod sso;

pub use api_key::{ApiKeyId, ApiKeyRecord, DEFAULT_API_KEY_LIFETIME, MintedApiKey};
pub use app_session::{AppSessionRecord, FreshAppSession};
pub use entitlement::{
    EntitlementError, EntitlementRecord, EntitlementRepository, Granted, RevokeScope, Revoked,
    RoleAtApp,
};
pub use jwt::{JwtCache, JwtSigner, Rotation, SigningKeyRecord};
pub use log::{AuthEvent, AuthLogRepository, OPERATOR_ORIGIN, SYSTEM_ORIGIN, WEB_ORIGIN};
pub use mapping::{
    Attributes, Condition, DroppedRule, IdentityRecord, IdentityRepository, MappingError,
    MappingRecord, MappingRepository, RolesAtApp, evaluate,
};
pub use repository::UserRepository;
pub use session::{
    DEFAULT_SESSION_LIFETIME, FreshSession, MintedCode, RedeemError, SessionError, SessionId,
    SessionRecord, SessionRepository,
};
pub use sso::{SsoLogin, SsoOutcome, SsoRepository};

use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};
use ring::rand::SecureRandom;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Longest a user slug may be. The same bound as an app id, and for the same
/// kind of reason: a slug ends up in log lines, event details and command
/// output, and nothing that short ever needed truncating.
const MAX_SLUG_LEN: usize = 63;

/// The stable identity of a user: a UUID (version 4), minted at creation and
/// never reused.
///
/// Hand-rolled from [`ring::rand::SystemRandom`] rather than pulled in through
/// a `uuid` crate: a v4 UUID is sixteen random bytes with six bits pinned and
/// a fixed rendering, `ring` is already a direct dependency, and every entry
/// in the workspace manifest carries a justification — "format sixteen bytes
/// as hex" would not survive as one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId(String);

impl UserId {
    /// Mint a fresh id from the host's randomness.
    ///
    /// The only fallible part is the randomness itself, and a host that will
    /// not produce random bytes is a host that should not be minting
    /// identities.
    pub fn generate() -> Result<Self> {
        uuid_v4().map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A fresh version-4 UUID off the host's randomness, rendered in the canonical
/// hyphenated lowercase form.
///
/// One function for the two things this module tree mints in UUID shape — a
/// user's id and a JWT's `jti` — so the pinned bits and the rendering are
/// written once. Hand-rolled from [`ring::rand::SystemRandom`] rather than a
/// `uuid` crate, for [`UserId`]'s reason: sixteen random bytes with six bits
/// pinned would not survive as a dependency justification.
pub(crate) fn uuid_v4() -> Result<String> {
    let mut bytes = [0_u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        // ring's own error says nothing; what an operator can act on is
        // that the host's randomness is what failed.
        .map_err(|_| anyhow::anyhow!("this host would not produce random bytes"))?;

    // What makes sixteen random bytes a v4 UUID: the version nibble says 4,
    // and the two variant bits say RFC 4122.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let mut rendered = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            rendered.push('-');
        }
        rendered.push_str(&format!("{byte:02x}"));
    }

    Ok(rendered)
}

impl FromStr for UserId {
    type Err = anyhow::Error;

    /// The canonical hyphenated form, and only that: 8-4-4-4-12 hex digits.
    /// Uppercase is accepted and folded, because a UUID pasted out of another
    /// tool is the ordinary way one arrives, but it is stored and compared
    /// lowercase — one spelling in the database, one in every log line.
    fn from_str(s: &str) -> Result<Self> {
        let lowered = s.to_ascii_lowercase();
        let dashes_at = [8, 13, 18, 23];
        let shaped = lowered.len() == 36
            && lowered.bytes().enumerate().all(|(index, byte)| {
                if dashes_at.contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            });

        if !shaped {
            bail!("`{s}` is not a user id — one looks like `3f29b1d4-8a6e-4c2b-9e77-1d5f6a2b9c40`");
        }

        Ok(Self(lowered))
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for UserId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// An id off the wire is as untrusted as one off the command line, so it is
/// held to the same rules rather than being taken as read.
impl<'de> Deserialize<'de> for UserId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let id = String::deserialize(deserializer)?;

        id.parse().map_err(serde::de::Error::custom)
    }
}

/// A role, as an app's manifest declares one and an entitlement grants one.
///
/// The spec's constraint — a lowercase letter, then lowercase letters, digits
/// and hyphens — is the [`UserSlug`] alphabet, and deliberately so: a role
/// travels the same places a slug does (JWT claims, log lines, `grant`
/// commands), and two alphabets would mean two quoting stories. Bounded by the
/// same length for the same reason.
///
/// `admin` is an ordinary role here. The rule that `admin` is never mappable
/// belongs to SSO mappings, not to the name itself — a manifest may well
/// declare an `admin` role for an operator to grant by hand.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Role(String);

impl Role {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Role {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("a role must not be empty");
        }
        if s.len() > MAX_SLUG_LEN {
            bail!("role `{s}` is longer than {MAX_SLUG_LEN} characters");
        }
        if !s.as_bytes()[0].is_ascii_lowercase() {
            bail!("role `{s}` must start with a lowercase letter");
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            bail!("role `{s}` may only contain lowercase letters, digits and hyphens");
        }

        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Role {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// A role out of a manifest or off the wire is held to the same rules as one
/// off the command line.
impl<'de> Deserialize<'de> for Role {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let role = String::deserialize(deserializer)?;

        role.parse().map_err(serde::de::Error::custom)
    }
}

/// The name an operator gives a user.
///
/// The spec's role constraint — a lowercase letter, then lowercase letters,
/// digits and hyphens — used for slugs too, so the two alphabets never
/// diverge. One more rule on top: a slug must not itself parse as a UUID.
/// Every command that takes `<slug|user-id>` resolves a UUID as an id first,
/// so a slug that read as one would name a user nobody could ever address.
///
/// A slug may also carry a single `provider:` prefix — lowercase letters, one
/// colon — which is how the SSO login flow names the users it auto-creates
/// (`github:octocat`). The prefix keeps those out of the plain namespace an
/// operator types into: `spaceport auth user create` can never collide with a
/// login that arrived overnight unless the operator spelled the prefix out on
/// purpose. Behind the colon the leading character may also be a digit,
/// because the name is the *provider's* and GitHub hands out logins like
/// `8bit`; a plain slug still has to start with a letter, so nothing an
/// operator could always type has changed meaning.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserSlug(String);

impl UserSlug {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for UserSlug {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("a user slug must not be empty");
        }
        if s.len() > MAX_SLUG_LEN {
            bail!("user slug `{s}` is longer than {MAX_SLUG_LEN} characters");
        }
        // The optional provider prefix, split on the *first* colon; a second
        // one lands in the name and fails the alphabet check below, which is
        // what makes "single colon" a rule rather than a hope.
        let (provider, name) = match s.split_once(':') {
            Some((provider, name)) => (Some(provider), name),
            None => (None, s),
        };
        if let Some(provider) = provider
            && (provider.is_empty() || !provider.bytes().all(|b| b.is_ascii_lowercase()))
        {
            bail!(
                "user slug `{s}` has a malformed provider prefix — one is lowercase letters \
                 and a single colon, as in `github:octocat`"
            );
        }
        if name.is_empty() {
            bail!("user slug `{s}` names nobody after its provider prefix");
        }
        // A digit may lead only behind a prefix: the name there is the
        // provider's to hand out, and GitHub hands out logins like `8bit`.
        let first = name.as_bytes()[0];
        if !(first.is_ascii_lowercase() || (provider.is_some() && first.is_ascii_digit())) {
            bail!("user slug `{s}` must start with a lowercase letter");
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            bail!("user slug `{s}` may only contain lowercase letters, digits and hyphens");
        }
        // The rule that keeps `<slug|user-id>` from ever guessing. The two
        // alphabets genuinely overlap — `abcdefab-abcd-4abc-8abc-abcdefabcdef`
        // is hex all the way through and starts with a letter — and a user
        // created under such a slug could never be named again: every command
        // would resolve the string as an id first and find nobody.
        if s.parse::<UserId>().is_ok() {
            bail!("user slug `{s}` reads as a user id, which every command would resolve first");
        }

        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for UserSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for UserSlug {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// A slug off the wire is held to the same rules as one off the command line.
impl<'de> Deserialize<'de> for UserSlug {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let slug = String::deserialize(deserializer)?;

        slug.parse().map_err(serde::de::Error::custom)
    }
}

/// What `<slug|user-id>` means once it is parsed: the spec's resolution rule,
/// written down once.
///
/// Anything that parses as a UUID names a user by id; everything else is held
/// to the slug rules. No stored slug can parse as a UUID — [`UserSlug`]
/// refuses those — so the rule never has two users it could mean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserRef {
    Id(UserId),
    Slug(UserSlug),
}

impl FromStr for UserRef {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if let Ok(id) = s.parse::<UserId>() {
            return Ok(Self::Id(id));
        }

        match s.parse::<UserSlug>() {
            Ok(slug) => Ok(Self::Slug(slug)),
            Err(_) => bail!("`{s}` is neither a user id nor a user slug"),
        }
    }
}

impl fmt::Display for UserRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => id.fmt(f),
            Self::Slug(slug) => slug.fmt(f),
        }
    }
}

/// A user as the pool stores one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    pub id: UserId,
    pub slug: UserSlug,
    /// Where a one-time code would be sent, and — when SSO lands — the address
    /// an IdP login links through. Absent for the technical users that have
    /// neither.
    pub email: Option<String>,
    pub suspended: bool,
    pub created_at: String,
}

/// Why a command against the user pool did not happen. The distinction is
/// worth keeping because the operator interface answers differently: an
/// unknown user is a name the operator mistyped, a taken slug is a conflict
/// only they can resolve, and a failure is the host's.
#[derive(Debug)]
pub enum UserError {
    /// No live user answers to that slug or id.
    Unknown(anyhow::Error),
    /// A live user already holds the slug, so creating another would be
    /// creating an ambiguity rather than a user.
    SlugTaken(anyhow::Error),
    /// The store would not do it.
    Failed(anyhow::Error),
}

impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(error) | Self::SlugTaken(error) | Self::Failed(error) => {
                write!(f, "{error:#}")
            }
        }
    }
}

impl std::error::Error for UserError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_id_is_a_version_4_uuid() {
        let id = UserId::generate().unwrap();
        let rendered = id.to_string();

        assert_eq!(rendered.len(), 36, "{rendered}");
        assert_eq!(rendered.as_bytes()[14], b'4', "{rendered}");
        assert!(
            matches!(rendered.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
            "{rendered}"
        );
        // And it round-trips through its own parser, which is what every
        // command that takes an id relies on.
        assert_eq!(rendered.parse::<UserId>().unwrap(), id);
    }

    /// Sixteen random bytes colliding is not something a test can rule out,
    /// but two calls handing back the same string would mean the randomness is
    /// not being asked at all.
    #[test]
    fn generated_ids_differ() {
        assert_ne!(UserId::generate().unwrap(), UserId::generate().unwrap());
    }

    /// A UUID pasted out of another tool is often uppercase, and refusing it
    /// would be refusing the same id in a different spelling.
    #[test]
    fn an_id_is_folded_to_lowercase() {
        let id: UserId = "3F29B1D4-8A6E-4C2B-9E77-1D5F6A2B9C40".parse().unwrap();

        assert_eq!(id.as_str(), "3f29b1d4-8a6e-4c2b-9e77-1d5f6a2b9c40");
    }

    #[test]
    fn rejects_an_id_that_is_not_one() {
        for id in [
            "",
            "3f29b1d4",
            "3f29b1d4-8a6e-4c2b-9e77-1d5f6a2b9c4", // one short
            "3f29b1d4-8a6e-4c2b-9e77-1d5f6a2b9c401", // one long
            "3f29b1d4x8a6e-4c2b-9e77-1d5f6a2b9c40", // wrong separator
            "gf29b1d4-8a6e-4c2b-9e77-1d5f6a2b9c40", // not hex
        ] {
            assert!(id.parse::<UserId>().is_err(), "accepted `{id}`");
        }
    }

    #[test]
    fn accepts_a_plain_role() {
        assert_eq!("reader".parse::<Role>().unwrap().as_str(), "reader");
        assert_eq!("tier-2".parse::<Role>().unwrap().as_str(), "tier-2");
        // Not refused here: "never mappable" is a rule about SSO mappings, and
        // a manifest declaring `admin` for manual grants is legitimate.
        assert_eq!("admin".parse::<Role>().unwrap().as_str(), "admin");
    }

    /// The same alphabet as a slug, on purpose — so what a slug refuses, a
    /// role refuses too.
    #[test]
    fn rejects_a_role_that_breaks_the_charset() {
        for role in ["", "Reader", "2fast", "-lead", "my role", "my_role"] {
            assert!(role.parse::<Role>().is_err(), "accepted `{role}`");
        }
    }

    #[test]
    fn rejects_an_overlong_role() {
        let err = "a".repeat(64).parse::<Role>().unwrap_err().to_string();
        assert!(err.contains("longer than 63"), "{err}");
    }

    #[test]
    fn accepts_a_plain_slug() {
        assert_eq!("alice".parse::<UserSlug>().unwrap().as_str(), "alice");
        assert_eq!("ci-bot-2".parse::<UserSlug>().unwrap().as_str(), "ci-bot-2");
    }

    #[test]
    fn rejects_a_slug_that_breaks_the_charset() {
        for slug in ["", "Alice", "2fast", "-lead", "my user", "my_user"] {
            assert!(slug.parse::<UserSlug>().is_err(), "accepted `{slug}`");
        }
    }

    /// The provider-prefixed form the SSO login flow mints: lowercase
    /// provider, one colon, and — only there — a name that may lead with a
    /// digit, because GitHub hands out logins like `8bit`.
    #[test]
    fn accepts_a_provider_prefixed_slug() {
        assert_eq!(
            "github:octocat".parse::<UserSlug>().unwrap().as_str(),
            "github:octocat"
        );
        assert_eq!(
            "github:8bit".parse::<UserSlug>().unwrap().as_str(),
            "github:8bit"
        );
        assert_eq!(
            "github:octo-cat-2".parse::<UserSlug>().unwrap().as_str(),
            "github:octo-cat-2"
        );
    }

    /// The widening is exactly one prefix wide: a malformed provider, a second
    /// colon, an empty half or a digit leading a *plain* slug are all still
    /// refused — and a UUID is refused however it is spelled.
    #[test]
    fn rejects_a_prefixed_slug_that_breaks_the_grammar() {
        for slug in [
            "github:",
            ":octocat",
            "Github:octocat",
            "gith_ub:octocat",
            "github:octo:cat",
            "github:Octocat",
            "github:-lead",
            "2fast", // a digit still may not lead a plain slug
        ] {
            assert!(slug.parse::<UserSlug>().is_err(), "accepted `{slug}`");
        }
        assert!(
            "abcdefab-abcd-4abc-8abc-abcdefabcdef"
                .parse::<UserSlug>()
                .is_err(),
            "a UUID-shaped slug slipped through"
        );
    }

    #[test]
    fn rejects_an_overlong_slug() {
        let err = "a".repeat(64).parse::<UserSlug>().unwrap_err().to_string();
        assert!(err.contains("longer than 63"), "{err}");
    }

    /// The resolution rule the spec writes as `<slug|user-id>`: a UUID is an
    /// id, everything else is a slug, and garbage is neither.
    #[test]
    fn a_reference_resolves_as_id_or_slug() {
        assert!(matches!(
            "3f29b1d4-8a6e-4c2b-9e77-1d5f6a2b9c40".parse::<UserRef>(),
            Ok(UserRef::Id(_))
        ));
        assert!(matches!("alice".parse::<UserRef>(), Ok(UserRef::Slug(_))));
        assert!("Not A User".parse::<UserRef>().is_err());
    }
}

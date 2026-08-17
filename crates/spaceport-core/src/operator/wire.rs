//! What the routes that answer with a table send, before anybody lays it out.
//!
//! Data where those routes used to send columns, for the reason
//! [`crate::status::Status`] and [`super::SecretSet`] are data: what is worth
//! saying depends on who is reading. A person at a terminal wants the widths
//! computed for their screen and the one bad cell coloured; a script wants the
//! field, not the padding around it. A server that has already decided has
//! taken that choice away from both.
//!
//! These live here rather than in either half because both halves need them
//! and neither owns them: the server fills them in and the client renders
//! them.
//!
//! The prose is not gone. A route answers with one of these only when the
//! request asks for it by `Accept: application/json`; anything else — `curl`,
//! a shell script written against the old output — still gets the columns it
//! got before.
//!
//! What is *not* here: the empty cases. A route with nothing to report sends
//! an empty list, and the sentence about how to get a first one is the
//! client's to write, because it names the command the operator would type and
//! only the client knows what they typed to get here.

use serde::{Deserialize, Serialize};

use crate::app::AppId;
use crate::auth::{Role, UserId, UserSlug};

/// One app, as `spaceport apps list` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRow {
    pub id: AppId,
    /// Where it came from, already said in words: a manifest's own source, the
    /// repository and branch a tracked app follows, or that it could not be
    /// read. The distinctions inside it are the server's to draw.
    pub source: String,
    pub state: AppState,
    pub hosts: Vec<String>,
}

/// Where an app stands, as the one column worth colouring.
///
/// A closed set, so the client can decide what each one deserves rather than
/// matching on a sentence. [`AppState::Down`] carries its reason, which is the
/// part an operator is reading the line for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AppState {
    /// Running, and answering its probe.
    Ready,
    /// Running, and not answering its probe.
    Unreachable,
    /// Recorded suspended: claiming its hosts, running nothing.
    Suspended,
    /// It had a container and lost it.
    Down { reason: Option<String> },
    /// Recorded, and claiming nothing.
    NotRunning,
    /// A manifest this build cannot parse.
    Unreadable,
    /// A tracking with no manifest applied under it yet.
    Tracked,
}

impl AppState {
    /// The word the column used to carry, which is still the word to print.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Unreachable => "unreachable",
            Self::Suspended => "suspended",
            Self::Down { .. } => "down",
            Self::NotRunning => "not running",
            Self::Unreadable => "unreadable",
            Self::Tracked => "tracked",
        }
    }

    /// Whether this is a state to go and do something about, which is what
    /// decides whether the cell is coloured at all.
    pub fn is_trouble(&self) -> bool {
        matches!(
            self,
            Self::Unreachable | Self::Down { .. } | Self::Unreadable
        )
    }
}

/// One GitHub App this spaceport is registered as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionRow {
    pub slug: String,
    pub app_id: i64,
    pub owner: String,
    pub connected_at: String,
}

/// One user in the pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRow {
    pub slug: UserSlug,
    pub id: UserId,
    /// Whether they are locked out. A flag rather than the word, because the
    /// word is a rendering.
    pub suspended: bool,
    pub email: Option<String>,
    pub created_at: String,
}

/// One thing that happened to the user pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRow {
    pub at: String,
    /// Which kind of thing it was. An open set — the writers name these, and
    /// nothing here is exhaustive over them.
    pub kind: String,
    pub user: Option<String>,
    pub origin: String,
    pub detail: Option<String>,
}

/// One key the JWTs are signed with, or were.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningKeyRow {
    pub kid: String,
    /// Whether this is the one being signed with now. Retired keys stay in the
    /// JWKS until the last JWT they signed has expired.
    pub current: bool,
    pub created_at: String,
    pub retired_at: Option<String>,
}

/// One rule turning an SSO login into entitlements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingRow {
    pub rule_id: String,
    /// What it hands out, in the `role[,role]@app` spelling the rule was
    /// written in.
    pub grants: String,
    pub connection: String,
    /// What has to be true for it to match, one condition per entry.
    pub conditions: Vec<String>,
    pub created_at: String,
}

/// What a user can currently log in or call with.
///
/// Nested rather than flat, because the nesting is the point: a derived
/// session belongs to the session it came from, and a flat list of rows can
/// only say so with an indent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sessions {
    /// Whose these are, as resolved rather than as asked for: an operator may
    /// name a user by their id, and the sentence about having no sessions yet
    /// names the command to type next, which wants the slug.
    pub user: UserSlug,
    pub sessions: Vec<SessionRow>,
    pub keys: Vec<ApiKeyRow>,
}

impl Sessions {
    /// Whether there is nothing here at all — the case that gets a sentence
    /// instead of a table.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty() && self.keys.is_empty()
    }
}

/// One session, and whatever it has been exchanged for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRow {
    pub id: String,
    pub created_at: String,
    pub expires_at: String,
    /// The per-app sessions this one was exchanged for.
    pub derived: Vec<DerivedRow>,
}

/// A session derived from another, for one app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedRow {
    /// Text rather than an [`AppId`], for the reason the record behind it is
    /// text: a row written by a newer build must still list, and a listing is
    /// the one place that has to survive an id this build would refuse.
    pub app: String,
    pub created_at: String,
    pub expires_at: String,
}

/// One API key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyRow {
    pub id: String,
    /// The tail of the key, which is all that is kept of it and enough to tell
    /// two of them apart.
    pub prefix_tail: String,
    /// Both text, for the reason [`DerivedRow::app`] is.
    pub role: String,
    pub app: String,
    pub created_at: String,
    pub expires_at: String,
}

/// Everything spaceport holds about one GitHub App it is registered as.
///
/// What is not on here is the line about the secrets. It is the same sentence
/// on every connection — the three are set or the connection would not exist —
/// so it carries no information across the wire, and a client rendering this
/// writes it from nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub slug: String,
    pub name: String,
    pub app_id: i64,
    pub owner: String,
    pub client_id: String,
    pub connected_at: String,
    pub installations: Installations,
    pub refreshed: Refreshed,
}

/// Where GitHub last said the app was installed.
///
/// Three cases rather than a list that happens to be empty, because the three
/// call for quite different next steps: nothing installed anywhere is answered
/// by an install URL, and a cache that would not be read is answered by looking
/// at the store. The URL itself is not here — it is a fixed string built from
/// the slug, which the client already has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "installed", rename_all = "snake_case")]
pub enum Installations {
    /// The cache is populated and holds nothing: nobody has installed it yet.
    Nowhere,
    /// Where it is installed, in the order the cache holds them.
    Somewhere { installations: Vec<Installation> },
    /// The cache would not be read, said in the store's own words.
    Unreadable { error: String },
}

/// One account the app is installed on, and what it reaches there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Installation {
    pub account: String,
    /// `User` or `Organization`, in GitHub's own spelling, for the reason the
    /// stored row keeps it that way: a new account kind must not make this
    /// unreadable. Lowercasing it is a rendering.
    pub account_type: String,
    /// The repositories it grants, as `owner/name` — named and not counted,
    /// because the question behind the command is whether one particular
    /// repository is in reach, and a number cannot answer that.
    pub repositories: Vec<String>,
}

/// How old what GitHub said is, which is the question behind "why is my
/// repository not here".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refreshed", rename_all = "snake_case")]
pub enum Refreshed {
    /// When the last reconciliation pass finished.
    At { at: String },
    /// No pass has run yet, which for a connection made seconds ago is
    /// ordinary and for an older one is not.
    Never,
    /// The record would not be read, said in the store's own words.
    Unreadable { error: String },
}

/// One user's whole standing: who they are, how they sign in, what they hold,
/// and where that actually gets them.
///
/// The last two are separate fields and not one, deliberately. An entitlement
/// is stored whether or not the app declares its role, so `entitlements` is
/// what was granted and `access` is the judgement over it — and an entitlement
/// that grants nothing is flagged in place by
/// [`EntitlementRow::grants_access`] rather than dropped, because a grant that
/// silently does nothing is what an audit exists to surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Audit {
    /// Whose standing this is, as resolved rather than as asked for: an
    /// operator may name a user by their id.
    pub user: UserSlug,
    pub id: UserId,
    /// Whether they are locked out, as a flag for [`UserRow::suspended`]'s
    /// reason.
    pub suspended: bool,
    pub email: Option<String>,
    /// Every IdP login recorded against them; empty when no IdP has vouched
    /// for this user at all.
    pub sso: Vec<IdentityRow>,
    /// The apps they can actually reach — the ones where at least one entitled
    /// role is declared by a deployed manifest.
    pub access: Vec<AppId>,
    pub entitlements: Vec<EntitlementRow>,
}

/// One IdP account linked to the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRow {
    /// The GitHub App slug the login arrived through.
    pub connection: String,
    /// The IdP's stable id for the account, as text, because it is an opaque
    /// key from somebody else's id-space.
    pub external_id: String,
    /// The renameable handle beside it, for the human reading the audit.
    pub external_login: String,
    pub last_login_at: String,
}

/// One entitlement the user holds, and whether it reaches anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementRow {
    pub role: Role,
    pub app: AppId,
    /// The SSO mapping rule that produced the row, or `None` for a grant an
    /// operator made by hand — which is also what says which command would
    /// take it away again.
    pub mapped_rule: Option<String>,
    /// Whether the app's deployed manifest declares this role. A flag and not
    /// the sentence about it, for the reason the sentence names no data.
    pub grants_access: bool,
    pub granted_at: String,
}

/// What a client sends to be answered in [`self`] rather than in prose.
pub const JSON: &str = "application/json";

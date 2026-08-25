//! SSO role mappings, and the IdP identities they will one day be evaluated
//! against.
//!
//! A mapping is the rule the spec writes as `<role>[,<role>...]@<app-id> --via
//! <idp> --when <attr>=<value> ...`: whoever arrives through that connection
//! carrying attributes that satisfy *every* condition holds those roles at
//! that app. The rules land in the store now, ahead of the OAuth flow that
//! will apply them, because the operator commands that manage them — add,
//! list, test, drop — are how an operator prepares the ground before the
//! first SSO login ever happens, and because `entitlements.mapped_rule`
//! already refuses revokes in the name of rules that must therefore exist.
//!
//! The identity half is the same story one table over: [`IdentityRepository`]
//! stores who a user is at an IdP and the attribute snapshot their last login
//! carried. Nothing writes a snapshot yet — the login flow is a later slice —
//! and `mapping test` says so in as many words rather than pretending an
//! empty answer is a real one.
//!
//! An identity may also arrive without a login behind it: an operator who
//! knows that alice is `octo-alice` at a connection may assert the binding
//! themselves, with `auth user connect` or with `auth user create --connect`,
//! so that alice's first login lands on the account they already prepared
//! rather than minting a stranger beside it. Such a row carries no attributes
//! and no last login, and says so — see [`IdentityRecord::last_login_at`].
//!
//! A binding deliberately grants nothing. It says who somebody is, never what
//! they may do: no entitlement is written, no mapping rule is consulted, and
//! no cached JWT is purged, because nothing a JWT already carries got narrower
//! or wider. Whatever a bound user may reach is exactly what an operator
//! granted them by hand or what a mapping rule gives them at their next
//! login — and that separation is the point, since a binding is an assertion
//! about identity made at the unix socket, not an authorisation decision.
//!
//! [`evaluate`] is the one piece both halves meet in, and it is deliberately a
//! pure function: the login re-sync that lands later must apply exactly the
//! judgement `mapping test` previews, and two implementations would be two
//! opinions about who gets in.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use tracing::info;

use super::log::{OPERATOR_ORIGIN, record_in};
use super::{IdentityError, Role, UserId, uuid_v4};
use crate::app::AppId;
use crate::state::{Db, now};

/// The attributes an IdP login asserts, as the store keeps them: attribute
/// name to the list of values it holds.
///
/// Always a list, even for attributes that can only ever have one value — a
/// login is one string, an org membership is many — so [`evaluate`] needs
/// exactly one rule: a condition matches when the list contains its value. A
/// `BTreeMap` rather than a hash map so a snapshot renders in one order
/// however it was built, which is what lets `mapping test` print it.
pub type Attributes = BTreeMap<String, Vec<String>>;

/// One `--when` clause: an attribute name and the value it must hold.
///
/// The attribute name is IdP vocabulary and deliberately unvalidated beyond
/// being non-empty — the spec is explicit that a typo silently never matches,
/// and `mapping test` is the tool that exists to catch it. Serialised as it
/// is, because the pair travels the wire and sits in the `conditions` column
/// in the same JSON spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    pub attr: String,
    pub value: String,
}

impl FromStr for Condition {
    type Err = anyhow::Error;

    /// The `<attr>=<value>` spelling. Split on the *first* `=` so a value may
    /// itself carry one — a claim value is the IdP's string, not ours to
    /// constrain — while an attribute name may not, because nothing could
    /// ever assert it.
    fn from_str(s: &str) -> Result<Self> {
        let Some((attr, value)) = s.split_once('=') else {
            bail!("`{s}` is not a condition — one looks like `org=acme-corp`");
        };
        if attr.is_empty() {
            bail!("the condition `{s}` names no attribute");
        }
        if value.is_empty() {
            bail!("the condition `{s}` names no value — an empty value can never be asserted");
        }

        Ok(Self {
            attr: attr.to_owned(),
            value: value.to_owned(),
        })
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.attr, self.value)
    }
}

/// One or more roles at one app, as `mapping add` names them:
/// `<role>[,<role>...]@<app-id>`.
///
/// A type of its own rather than a `Vec` beside an [`AppId`], for
/// [`super::entitlement::RoleAtApp`]'s reason: the spelling is parsed in
/// exactly one place, and the CLI, the wire and the tests all hold the same
/// string to the same alphabets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolesAtApp {
    pub roles: Vec<Role>,
    pub app: AppId,
}

impl FromStr for RolesAtApp {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        // `split_once`, exactly as a single-role grant splits: a second `@`
        // belongs to nobody.
        let Some((roles, app)) = s.split_once('@') else {
            bail!("`{s}` is not a mapping grant — one looks like `reader,writer@blog`");
        };

        let roles = roles
            .split(',')
            .map(|role| {
                role.parse::<Role>()
                    .with_context(|| format!("reading the roles in `{s}`"))
            })
            .collect::<Result<Vec<Role>>>()?;
        // Refused rather than silently collapsed: `reader,reader` is a typo,
        // and a rule that stored one copy would have the listing disagree
        // with what the operator remembers typing.
        for (index, role) in roles.iter().enumerate() {
            if roles[..index].contains(role) {
                bail!("role `{role}` appears twice in `{s}`");
            }
        }

        Ok(Self {
            roles,
            app: app
                .parse::<AppId>()
                .map_err(|error| anyhow!("{error:#}"))
                .with_context(|| format!("reading the app id in `{s}`"))?,
        })
    }
}

impl fmt::Display for RolesAtApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let roles: Vec<&str> = self.roles.iter().map(Role::as_str).collect();

        write!(f, "{}@{}", roles.join(","), self.app)
    }
}

/// One mapping rule as the table stores it, stable id included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingRecord {
    /// The rule's name for life, minted at `add` and printed by `list`:
    /// entitlements are tagged with it, and dropping it must aim at exactly
    /// one rule.
    pub rule_id: String,
    /// The GitHub App slug the spec's `--via` names.
    pub connection: String,
    pub app: AppId,
    pub roles: Vec<Role>,
    /// ANDed at evaluation; never empty — a rule with no conditions would
    /// grant to everyone the connection lets in, and `add` refuses to write
    /// one.
    pub conditions: Vec<Condition>,
    pub created_at: String,
}

impl MappingRecord {
    /// The `<role>[,<role>...]@<app-id>` half of the rule, as the operator
    /// spelled it.
    pub fn grants(&self) -> RolesAtApp {
        RolesAtApp {
            roles: self.roles.clone(),
            app: self.app.clone(),
        }
    }
}

/// What dropping a rule took with it, beside the rule itself: how many mapped
/// entitlements went, and whose — the users whose cached JWTs the caller's
/// commit then purges.
#[derive(Debug)]
pub struct DroppedRule {
    pub mapping: MappingRecord,
    /// The mapped entitlement rows the cascade deleted.
    pub removed: usize,
    /// The users those rows belonged to, each purged from the JWT cache after
    /// the commit.
    pub users: Vec<UserId>,
}

/// Why a mapping command did not happen. Kept apart because the operator
/// interface answers differently: an unknown connection or rule is a name the
/// operator mistyped, a refused rule is one the spec forbids writing, and a
/// failure is the host's.
#[derive(Debug)]
pub enum MappingError {
    /// `--via` names no connection this spaceport holds.
    UnknownConnection(anyhow::Error),
    /// No rule answers to that id.
    UnknownRule(anyhow::Error),
    /// The rule itself is one the spec forbids: `admin` in the roles, or no
    /// condition at all.
    Refused(anyhow::Error),
    /// The store would not do it.
    Failed(anyhow::Error),
}

impl fmt::Display for MappingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownConnection(error)
            | Self::UnknownRule(error)
            | Self::Refused(error)
            | Self::Failed(error) => write!(f, "{error:#}"),
        }
    }
}

impl std::error::Error for MappingError {}

/// Which of `mappings` an arrival through `connection` carrying `attributes`
/// satisfies.
///
/// A condition matches when the attribute's value list contains its value
/// exactly; a rule matches when every one of its conditions does — `AND`
/// across `--when` clauses, which is deliberately all the expressiveness
/// there is. Pure on purpose: this is the judgement the login re-sync will
/// apply and `mapping test` previews, and keeping it free of I/O is what
/// keeps it one judgement.
pub fn evaluate<'m>(
    mappings: &'m [MappingRecord],
    connection: &str,
    attributes: &Attributes,
) -> Vec<&'m MappingRecord> {
    mappings
        .iter()
        .filter(|mapping| {
            mapping.connection == connection
                && mapping.conditions.iter().all(|condition| {
                    attributes
                        .get(&condition.attr)
                        .is_some_and(|values| values.iter().any(|value| value == &condition.value))
                })
        })
        .collect()
}

/// The `mappings` table, over the state database.
///
/// Same discipline as [`super::entitlement::EntitlementRepository`], whose
/// closest neighbour this is: every mutation writes its [`super::log`] entry
/// in the same transaction, and the JWT cache is purged only after a commit
/// that actually narrowed somebody's access.
#[derive(Clone)]
pub struct MappingRepository {
    db: Db,
    /// The JWT cache the edge mints into: `drop_rule` deletes entitlements,
    /// which is a revocation lever like `revoke` is, and a cached JWT must not
    /// outlive it by more than the spec's four minutes. `add` purges nothing —
    /// a rule grants only at the next login, and nothing cached got wider.
    jwt_cache: std::sync::Arc<super::jwt::JwtCache>,
}

impl MappingRepository {
    pub fn new(db: Db) -> Self {
        Self::with_jwt_cache(db, std::sync::Arc::new(super::jwt::JwtCache::new()))
    }

    /// The constructor the daemon uses: the one process-wide cache, so a rule
    /// dropped here empties exactly the entries the edge would serve next.
    pub fn with_jwt_cache(db: Db, jwt_cache: std::sync::Arc<super::jwt::JwtCache>) -> Self {
        Self { db, jwt_cache }
    }

    /// Write a new rule: whoever arrives through `via` satisfying every one of
    /// `conditions` holds `grants`.
    ///
    /// `via` must name a connection this spaceport holds — the spec has it
    /// verified, unlike attribute names, because a connection is spaceport's
    /// own record and a typo here would be a rule that can never fire with
    /// nothing to catch it. `admin` is refused by name: the admin is whoever
    /// reaches the operator socket, and a role an IdP's group list could hand
    /// out would be an admin nobody on this host appointed. At least one
    /// condition is required for the same reason turned around — a rule with
    /// none would grant to every account the IdP lets through the door.
    ///
    /// Whether the app declares the roles is deliberately not asked here,
    /// exactly as `grant` does not ask: the rule is stored either way, and the
    /// warning belongs to the operator response, where the deployed manifest
    /// is at hand.
    pub async fn add(
        &self,
        via: &str,
        grants: &RolesAtApp,
        conditions: &[Condition],
    ) -> Result<MappingRecord, MappingError> {
        if let Some(admin) = grants.roles.iter().find(|role| role.as_str() == "admin") {
            return Err(MappingError::Refused(anyhow!(
                "`{admin}` is never a mappable role — the admin is whoever reaches the operator \
                 socket, and no IdP attribute may appoint one"
            )));
        }
        if conditions.is_empty() {
            return Err(MappingError::Refused(anyhow!(
                "a mapping needs at least one `--when <attr>=<value>` condition — one with none \
                 would grant to everyone the connection lets in"
            )));
        }
        // Held to the same rules the CLI parser enforces, because a condition
        // can also arrive over the wire as JSON that never met the parser.
        for condition in conditions {
            if condition.attr.is_empty() || condition.value.is_empty() {
                return Err(MappingError::Refused(anyhow!(
                    "the condition `{condition}` is missing its attribute or its value"
                )));
            }
        }

        // Minted out here for `create`'s reason: randomness has no business
        // inside a database lock.
        let record = MappingRecord {
            rule_id: uuid_v4().map_err(MappingError::Failed)?,
            connection: via.to_owned(),
            app: grants.app.clone(),
            roles: grants.roles.clone(),
            conditions: conditions.to_vec(),
            created_at: now(),
        };
        let written = record.clone();

        let known = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to add a mapping")?;

                // The one verification `--via` gets, against the table the
                // connect command writes: a slug spaceport holds no App under
                // is a rule aimed at logins that can never arrive.
                let held: Option<String> = transaction
                    .query_row(
                        "SELECT slug FROM github_apps WHERE slug = ?1",
                        rusqlite::params![written.connection],
                        |row| row.get(0),
                    )
                    .optional()
                    .context("looking the mapping's connection up")?;
                if held.is_none() {
                    return Ok(false);
                }

                transaction
                    .execute(
                        "INSERT INTO mappings
                             (rule_id, connection, spaceport_app, roles, conditions, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        rusqlite::params![
                            written.rule_id,
                            written.connection,
                            written.app.as_str(),
                            joined(&written.roles),
                            conditions_json(&written.conditions)?,
                            written.created_at
                        ],
                    )
                    .context("adding a mapping")?;

                record_in(
                    &transaction,
                    &written.created_at,
                    "mapping.added",
                    None,
                    OPERATOR_ORIGIN,
                    Some(&format!(
                        "rule `{}`: `{}` via `{}` when {}",
                        written.rule_id,
                        written.grants(),
                        written.connection,
                        conditions_prose(&written.conditions),
                    )),
                )?;

                transaction.commit().context("committing a new mapping")?;

                Ok(true)
            })
            .await
            .map_err(MappingError::Failed)?;

        if !known {
            return Err(MappingError::UnknownConnection(anyhow!(
                "no connection answers to `{via}` — `spaceport connect list` says which exist"
            )));
        }

        info!(rule = %record.rule_id, grants = %record.grants(), via, "mapping added");

        Ok(record)
    }

    /// Every rule, in the order they were added, optionally only those about
    /// `app`.
    ///
    /// A row this build cannot read is skipped with a warning rather than
    /// costing the listing, exactly as a broken user row costs nobody else's.
    pub async fn list(&self, app: Option<&AppId>) -> Result<Vec<MappingRecord>> {
        let app = app.cloned();

        let rows: Vec<MappingRow> = self
            .db
            .call(move |connection| {
                let (query, params) = match &app {
                    None => (
                        "SELECT rule_id, connection, spaceport_app, roles, conditions, created_at
                         FROM mappings ORDER BY created_at, rule_id",
                        Vec::new(),
                    ),
                    Some(app) => (
                        "SELECT rule_id, connection, spaceport_app, roles, conditions, created_at
                         FROM mappings WHERE spaceport_app = ?1 ORDER BY created_at, rule_id",
                        vec![app.to_string()],
                    ),
                };

                let mut statement = connection
                    .prepare(query)
                    .context("preparing the mapping listing query")?;
                let rows = statement
                    .query_map(rusqlite::params_from_iter(params.iter()), mapping_row)
                    .context("listing the mappings")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("listing the mappings")?;

                Ok(rows)
            })
            .await?;

        Ok(rows
            .into_iter()
            .filter_map(|row| match mapping_record(row) {
                Ok(record) => Some(record),
                Err(error) => {
                    tracing::warn!(%error, "skipping a stored mapping this build cannot read");
                    None
                }
            })
            .collect())
    }

    /// One rule by its id, or `None` when nothing answers to it.
    ///
    /// Loud where the listing is forgiving: a command aimed at exactly this
    /// row has nothing useful to do with a row that will not read.
    pub async fn get(&self, rule_id: &str) -> Result<Option<MappingRecord>> {
        let asked = rule_id.to_owned();

        let row: Option<MappingRow> = self
            .db
            .call(move |connection| {
                connection
                    .query_row(
                        "SELECT rule_id, connection, spaceport_app, roles, conditions, created_at
                         FROM mappings WHERE rule_id = ?1",
                        rusqlite::params![asked],
                        mapping_row,
                    )
                    .optional()
                    .context("looking a mapping up")
            })
            .await?;

        row.map(mapping_record).transpose()
    }

    /// Delete a rule and everything it produced, as one commit: the mapping
    /// row, every entitlement tagged with it, and the `mapping.dropped` entry
    /// that records both.
    ///
    /// The entitlements go without per-row log entries, for the reason a
    /// user's drop gives: the rows went as a cascade of this one command, and
    /// a fan of `entitlement.revoked` lines nobody typed would read as
    /// commands that were never given. The affected users' cached JWTs are
    /// purged after the commit — this is the spec's `mapping drop` purge
    /// lever, and the discipline of "commit, then purge" keeps the cache a
    /// strict copy of the tables.
    pub async fn drop_rule(&self, rule_id: &str) -> Result<DroppedRule, MappingError> {
        let asked = rule_id.to_owned();

        let found = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to drop a mapping")?;

                let Some(row) = transaction
                    .query_row(
                        "SELECT rule_id, connection, spaceport_app, roles, conditions, created_at
                         FROM mappings WHERE rule_id = ?1",
                        rusqlite::params![asked],
                        mapping_row,
                    )
                    .optional()
                    .context("looking the mapping to drop up")?
                else {
                    return Ok(None);
                };
                let mapping = mapping_record(row)?;

                // Whose access is about to narrow, read before the delete
                // takes the only record of it. An id that will not parse is
                // still deleted below; it just cannot be purged, and a warning
                // says so rather than the whole drop failing over a row some
                // other build wrote.
                let mut statement = transaction
                    .prepare("SELECT DISTINCT user_id FROM entitlements WHERE mapped_rule = ?1")
                    .context("preparing the affected-users query")?;
                let users: Vec<String> = statement
                    .query_map(rusqlite::params![mapping.rule_id], |row| row.get(0))
                    .context("reading the users a mapping empowered")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("reading the users a mapping empowered")?;
                drop(statement);
                let users: Vec<UserId> = users
                    .into_iter()
                    .filter_map(|user| match user.parse() {
                        Ok(user) => Some(user),
                        Err(error) => {
                            tracing::warn!(%error, "cannot purge a user id this build cannot read");
                            None
                        }
                    })
                    .collect();

                let removed = transaction
                    .execute(
                        "DELETE FROM entitlements WHERE mapped_rule = ?1",
                        rusqlite::params![mapping.rule_id],
                    )
                    .context("removing a dropped mapping's entitlements")?;
                transaction
                    .execute(
                        "DELETE FROM mappings WHERE rule_id = ?1",
                        rusqlite::params![mapping.rule_id],
                    )
                    .context("dropping a mapping")?;

                record_in(
                    &transaction,
                    &now(),
                    "mapping.dropped",
                    None,
                    OPERATOR_ORIGIN,
                    Some(&format!(
                        "rule `{}`: `{}` via `{}`, taking {removed} mapped entitlements with it",
                        mapping.rule_id,
                        mapping.grants(),
                        mapping.connection,
                    )),
                )?;

                transaction
                    .commit()
                    .context("committing a mapping's drop")?;

                Ok(Some(DroppedRule {
                    mapping,
                    removed,
                    users,
                }))
            })
            .await
            .map_err(MappingError::Failed)?;

        let dropped: DroppedRule = found.ok_or_else(|| {
            MappingError::UnknownRule(anyhow!(
                "no mapping answers to `{rule_id}` — `spaceport auth mapping list` says which exist"
            ))
        })?;

        // Something may have actually been taken away, so the cached JWTs
        // still carrying it go too — after the commit, so the cache is never
        // emptier than the tables ahead of a rollback.
        for user in &dropped.users {
            self.jwt_cache.purge_user(user);
        }

        info!(
            rule = %dropped.mapping.rule_id,
            removed = dropped.removed,
            "mapping dropped"
        );

        Ok(dropped)
    }
}

/// One account at one connection, as `auth user connect` names it:
/// `<connection>:<login>`.
///
/// A type of its own rather than a bare `String` the handler pulls apart, for
/// [`super::entitlement::RoleAtApp`]'s reason and one more: the spelling is
/// parsed in exactly one place, and a parse the CLI runs is a parse that makes
/// `--help` and the refusal honest. Clap prints the type's name where the
/// value goes and rejects a malformed one with the sentence below, so an
/// operator who typed `octo-alice` learns which connection they forgot to name
/// before anything reaches the socket — a `String` argument would have carried
/// the same mistake across it and let the far end explain it after a round trip
/// to github.com.
///
/// The connection half is held to nothing beyond being non-empty, exactly as
/// `mapping add --via` is: which slugs exist is the connection store's
/// knowledge, and this side guessing at the alphabet github mints app slugs in
/// would only refuse a connection that works.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountAtConnection {
    /// The connection slug, as `spaceport connect list` prints it.
    pub connection: String,
    /// The handle at that connection — what a human recognises the account by,
    /// and never what the binding it becomes is keyed on: see
    /// [`AssertedIdentity::external_id`].
    pub login: String,
}

impl FromStr for AccountAtConnection {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let Some((connection, login)) = s.split_once(':') else {
            bail!(
                "`{s}` does not name an account at a connection — one looks like \
                 `spaceport-for-acme:octo-alice`, where the first half is a connection as \
                 `spaceport connect list` prints it"
            );
        };
        if connection.is_empty() {
            bail!("`{s}` names no connection — one looks like `spaceport-for-acme:octo-alice`");
        }
        if login.is_empty() {
            bail!("`{s}` names no account at `{connection}` — the handle goes after the colon");
        }
        // Split on the *first* colon, and then refuse a second rather than
        // folding it into the handle: no IdP spaceport speaks to mints handles
        // carrying one, so a second colon is a mistyped value, and a binding
        // made from it would resolve against github, fail, and blame a handle
        // the operator never meant to assert.
        if login.contains(':') {
            bail!("`{s}` carries a second colon — a handle has none, so this names no account");
        }

        Ok(Self {
            connection: connection.to_owned(),
            login: login.to_owned(),
        })
    }
}

impl fmt::Display for AccountAtConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.connection, self.login)
    }
}

/// The identity an operator asserts somebody holds: which connection, which
/// account there, under which handle.
///
/// A struct rather than three more arguments, for the reason
/// [`super::sso::SsoLogin`] gives: three strings in a row is a call site that
/// swapped two and still compiled. It lives here rather than beside the user
/// pool because both writers need it — [`IdentityRepository::bind`] on its
/// own, and [`super::UserRepository::create`] inside the commit that mints the
/// user — and a second spelling in the other module would be a second opinion
/// about what an assertion carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertedIdentity {
    /// The connection slug, as `spaceport connect list` prints it — a GitHub
    /// App slug, never the literal `github`, because a host may hold several.
    pub connection: String,
    /// The IdP's stable id for the account, as text. What the binding is
    /// *keyed* by: handles are renameable and reassignable, and a binding made
    /// on one would follow the name to whoever holds it next.
    pub external_id: String,
    /// The handle beside it, resolved at the moment of the assertion, so that
    /// a human reading an audit recognises the account the id names.
    pub external_login: String,
}

/// What the IdP calls the person behind an identity: display data, and nothing
/// a decision is ever made on.
///
/// Kept apart from [`Attributes`] on purpose, though both are things the same
/// login carried. Attributes are the input to the mapping rules — an operator
/// writes `--when org=acme-corp` and entitlements follow — so anything that
/// lands there becomes something access can be granted off. A profile must
/// never be that: the address is a claim GitHub makes about a mailbox, made at
/// some past moment and never revalidated, and the name is free text the
/// account holder can change to anybody else's this afternoon. They travel to
/// the app so it can greet the person by name; they decide nothing.
///
/// Both halves are optional and ordinarily absent. An identity an operator
/// asserted with `auth user connect` has neither until the person signs in, for
/// the reason [`IdentityRecord::last_login_at`] is absent there too.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdpProfile {
    /// The IdP's display name for the account, when it has one.
    pub name: Option<String>,
    /// The address the IdP asserts the account holder reads, when the IdP has
    /// one it has verified.
    ///
    /// Emphatically not [`super::UserRecord::email`], which is the *credential*
    /// the email connection signs somebody in by — a mailbox proven today, with
    /// a code. This is somebody else's word about the same kind of thing, and
    /// nothing resolves a user by it.
    pub email: Option<String>,
}

impl IdpProfile {
    /// Whether the IdP said anything at all — what an audit checks before
    /// printing a line about a profile that is two absences.
    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.email.is_none()
    }
}

/// What spaceport is willing to tell an app about the person behind a `sub`:
/// one name and one address, drawn from however many identities the user
/// holds, or nothing when nobody ever said.
///
/// A type of its own rather than another [`IdpProfile`], because it is no
/// longer one IdP's word: the address here may be the one the *email*
/// connection proved with a code, and the name may come from a different
/// connection than the address did. It is the answer to "who shall the JWT
/// say this is", and the only thing that ever builds one is
/// [`IdentityRepository::vouched`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VouchedProfile {
    /// The display name to greet the person by, absent when no connection has
    /// ever asserted one.
    pub name: Option<String>,
    /// The address to reach them at, absent when neither spaceport nor any
    /// connection has one.
    pub email: Option<String>,
}

impl VouchedProfile {
    /// Resolve what a JWT says from `credential` — the address the *email*
    /// connection signs this user in by, when they have one — and every
    /// identity they hold.
    ///
    /// Three rules, and each is a choice with a discarded alternative behind
    /// it.
    ///
    /// *The credential outranks the claims.* A mailbox proven today with a
    /// one-time code is a better answer than GitHub's undated word about the
    /// same kind of thing, so `users.email` wins whenever it is there — which
    /// for an SSO-only user is never, which is why the fallthrough exists at
    /// all. The name has no such counterpart: [`super::UserRecord::slug`] is a
    /// handle an operator chose for their own listings, not what the person is
    /// called, and shipping it as `name` would have every app greeting people
    /// by a slug.
    ///
    /// *The most recent login wins among identities.* The ordering is by
    /// [`IdentityRecord::last_login_at`], latest first, and an identity nobody
    /// has ever used sorts last — which costs nothing, since a binding an
    /// operator asserted carries no profile to lose. It needs no schema and no
    /// configuration, and it tracks the account the person actually signs in
    /// with. The alternative — recording which connection minted the session
    /// and preferring that one — is truer where it applies and has no answer
    /// at all for a one-time-code session or an API key, which mint JWTs too.
    ///
    /// *The two halves are resolved apart.* A connection that asserts a name
    /// and no address cannot blank an address another one gave us. The halves
    /// may therefore come from different connections, which reads like mixing
    /// two people — except that every identity here is bound to one user, by
    /// an operator or by a login that proved it, so by construction they are
    /// all the same person.
    pub fn resolve(credential: Option<&str>, identities: &[IdentityRecord]) -> Self {
        // Cloned and sorted rather than indexed in place: `for_user` hands
        // these back in connection order, which is the order an audit reads,
        // and re-ordering the caller's slice to answer a question about it
        // would be this function changing what it was lent.
        let mut recent: Vec<&IdentityRecord> = identities.iter().collect();
        recent.sort_by(|left, right| {
            signed_in_at(right)
                .cmp(&signed_in_at(left))
                // Two identities of the same age — both never used, most
                // often — fall back to connection name, so the answer is one
                // answer and not whatever order SQLite happened to hand over.
                .then_with(|| left.connection.cmp(&right.connection))
        });

        Self {
            name: recent
                .iter()
                .find_map(|identity| identity.profile.name.clone()),
            email: credential.map(str::to_owned).or_else(|| {
                recent
                    .iter()
                    .find_map(|identity| identity.profile.email.clone())
            }),
        }
    }

    /// Whether there is anything to say — what a mint checks before adding
    /// claims nobody can fill.
    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.email.is_none()
    }
}

/// When an identity was last signed in through, as an instant that sorts.
///
/// The stored text is parsed rather than compared as text, because RFC 3339
/// does not sort lexicographically once fractional seconds are in play — a
/// stamp with them reads as *earlier* than one without, since `.` precedes
/// `Z`. A stamp this build cannot parse, and an identity nobody has used,
/// both answer with the beginning of time: last place, where an unused
/// binding belongs anyway.
fn signed_in_at(identity: &IdentityRecord) -> time::OffsetDateTime {
    identity
        .last_login_at
        .as_deref()
        .and_then(|at| {
            time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).ok()
        })
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

/// One identity as the `idp_identities` table stores it, minus the user it
/// belongs to — a read is always about one user, exactly as an entitlement
/// read is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRecord {
    /// The GitHub App slug the login arrived through.
    pub connection: String,
    /// The IdP's stable id for the account — GitHub's numeric user id, as
    /// text, because it is an opaque key from somebody else's id-space.
    pub external_id: String,
    /// The renameable handle beside it, for the human reading an audit.
    pub external_login: String,
    /// What the IdP asserted at the last login: the snapshot `mapping test`
    /// replays.
    pub attributes: Attributes,
    /// When somebody last signed in through this identity, or `None` when
    /// nobody ever has — an operator asserted the binding with `auth user
    /// connect` and the person it names has not arrived yet. Absent rather
    /// than stamped with the moment of the assertion, because a timestamp
    /// there would claim a login that never happened, and `mapping test`
    /// would then replay an empty snapshot as though a login had carried it.
    pub last_login_at: Option<String>,
    /// What the IdP calls this person, as of that last login — empty until one
    /// has happened.
    pub profile: IdpProfile,
}

/// The `idp_identities` table, in the vocabulary of recording a login and
/// reading it back.
///
/// A repository of its own rather than more methods on [`MappingRepository`]:
/// the two tables meet only in [`evaluate`], which deliberately takes plain
/// data, and a handler that replays a snapshot has no business seeing the
/// verbs that rewrite rules.
#[derive(Debug, Clone)]
pub struct IdentityRepository {
    db: Db,
}

impl IdentityRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Record that `user` is `external_login` (`external_id`) at `connection`,
    /// asserting `attributes` — the write the login flow will make, replacing
    /// whatever the previous login recorded.
    ///
    /// The replace is spelled as delete-then-insert rather than an upsert,
    /// because two uniqueness claims can each be the one that fires: the same
    /// user through the same connection is a re-login, and the same external
    /// account now vouching for this user is a re-link — both must land on
    /// one fresh row, and one `ON CONFLICT` clause can only catch one of them.
    ///
    /// `profile` is replaced wholesale along with the attributes, absences
    /// included: a person who cleared their display name at the IdP has no
    /// display name here either the moment they sign in again. The row is a
    /// snapshot of what the IdP last said, and a field that kept its old value
    /// because the new answer was "nothing" would be this table remembering
    /// something the IdP no longer asserts.
    pub async fn record(
        &self,
        user: &UserId,
        connection: &str,
        external_id: &str,
        external_login: &str,
        attributes: &Attributes,
        profile: &IdpProfile,
    ) -> Result<()> {
        let user = user.clone();
        let connection_slug = connection.to_owned();
        let external_id = external_id.to_owned();
        let external_login = external_login.to_owned();
        let profile = profile.clone();
        let attributes =
            serde_json::to_string(attributes).context("writing an identity's attributes")?;

        self.db
            .call(move |db| {
                let transaction = db
                    .transaction()
                    .context("beginning to record an idp identity")?;

                transaction
                    .execute(
                        "DELETE FROM idp_identities
                         WHERE (user_id = ?1 AND connection = ?2)
                            OR (connection = ?2 AND external_id = ?3)",
                        rusqlite::params![user.as_str(), connection_slug, external_id],
                    )
                    .context("replacing an idp identity")?;
                transaction
                    .execute(
                        "INSERT INTO idp_identities
                             (user_id, connection, external_id, external_login, attributes,
                              last_login_at, profile_name, profile_email)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        rusqlite::params![
                            user.as_str(),
                            connection_slug,
                            external_id,
                            external_login,
                            attributes,
                            now(),
                            profile.name,
                            profile.email
                        ],
                    )
                    .context("recording an idp identity")?;

                transaction.commit().context("committing an idp identity")
            })
            .await
    }

    /// Every identity `user` holds, one per connection, in connection order —
    /// what an audit shows and what `mapping test` replays. Empty is the
    /// ordinary answer until SSO lands, and the callers say so in prose.
    pub async fn for_user(&self, user: &UserId) -> Result<Vec<IdentityRecord>> {
        let user = user.clone();

        let rows: Vec<IdentityRow> = self
            .db
            .call(move |connection| {
                let mut statement = connection
                    .prepare(
                        "SELECT connection, external_id, external_login, attributes,
                                last_login_at, profile_name, profile_email
                         FROM idp_identities WHERE user_id = ?1 ORDER BY connection",
                    )
                    .context("preparing the identity query")?;

                let rows = statement
                    .query_map(rusqlite::params![user.as_str()], |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    })
                    .context("reading the idp identities")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("reading the idp identities")?;

                Ok(rows)
            })
            .await?;

        Ok(rows
            .into_iter()
            .filter_map(
                |(
                    connection,
                    external_id,
                    external_login,
                    attributes,
                    last_login_at,
                    profile_name,
                    profile_email,
                )| {
                    match serde_json::from_str(&attributes) {
                        Ok(attributes) => Some(IdentityRecord {
                            connection,
                            external_id,
                            external_login,
                            attributes,
                            last_login_at,
                            profile: IdpProfile {
                                name: profile_name,
                                email: profile_email,
                            },
                        }),
                        Err(error) => {
                            tracing::warn!(
                                %error,
                                "skipping a stored identity this build cannot read"
                            );
                            None
                        }
                    }
                },
            )
            .collect())
    }

    /// Who a JWT minted for `user` should say they are: the credential and
    /// every identity, read in one transaction and resolved by
    /// [`VouchedProfile::resolve`].
    ///
    /// One transaction so the two tables are about one moment — the same
    /// reason [`super::EntitlementRepository::audit`] reads a user beside
    /// their grants — and one method rather than two reads at the gate, so
    /// that the cookie path and the API-key path cannot come to different
    /// answers about the same person.
    ///
    /// A user the pool no longer knows answers with an empty profile rather
    /// than an error. The gate meets the same race one line earlier and calls
    /// it "no access"; a mint that is already going to be refused has no use
    /// for a louder failure here, and an unknown user genuinely has nothing to
    /// vouch for.
    pub async fn vouched(&self, user: &UserId) -> Result<VouchedProfile> {
        let user = user.clone();

        self.db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to read a profile to vouch for")?;

                let credential =
                    match super::repository::find(&transaction, &super::UserRef::Id(user.clone()))?
                    {
                        Some(row) => super::repository::record(row)?.email,
                        None => return Ok(VouchedProfile::default()),
                    };

                let mut statement = transaction
                    .prepare(
                        "SELECT connection, last_login_at, profile_name, profile_email
                         FROM idp_identities WHERE user_id = ?1",
                    )
                    .context("preparing the profile query")?;
                let identities = statement
                    .query_map(rusqlite::params![user.as_str()], |row| {
                        // Built as whole records so the resolution runs over
                        // exactly the type the audit path hands it, with the
                        // two columns it never reads left at their empties:
                        // an id and a snapshot decide nothing here, and
                        // parsing the snapshot's JSON to throw it away would
                        // make a mint fail over a row a login could still fix.
                        Ok(IdentityRecord {
                            connection: row.get(0)?,
                            external_id: String::new(),
                            external_login: String::new(),
                            attributes: Attributes::default(),
                            last_login_at: row.get(1)?,
                            profile: IdpProfile {
                                name: row.get(2)?,
                                email: row.get(3)?,
                            },
                        })
                    })
                    .context("reading the identities to vouch from")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("reading the identities to vouch from")?;

                Ok(VouchedProfile::resolve(credential.as_deref(), &identities))
            })
            .await
    }

    /// Assert that `user` is `identity`, on its own commit — the write
    /// `spaceport auth user connect` makes.
    ///
    /// The wrapper around [`bind_in`] for the caller that has nothing else to
    /// write; creating a user with the binding attached goes the other way
    /// round, through [`super::UserRepository::create`], so that the user and
    /// the identity share one commit.
    pub async fn bind(
        &self,
        user: &UserId,
        identity: &AssertedIdentity,
    ) -> Result<(), IdentityError> {
        let user = user.clone();
        let identity = identity.clone();
        let logged = identity.clone();

        let outcome = self
            .db
            .call(move |db| {
                let transaction = db.transaction().context("beginning to bind an identity")?;

                if let Err(refusal) = bind_in(&transaction, &now(), &user, &identity) {
                    // Dropped unfinished rather than committed: a refusal must
                    // leave the table exactly as it found it, and the read that
                    // found the conflict happened inside this very transaction.
                    return Ok(Err(refusal));
                }

                transaction
                    .commit()
                    .context("committing an identity binding")?;

                Ok(Ok(()))
            })
            .await
            .map_err(IdentityError::Failed)?;
        outcome?;

        info!(
            connection = %logged.connection,
            external_login = %logged.external_login,
            "identity bound"
        );

        Ok(())
    }

    /// Take back a binding: `user` is nobody at `connection` any more.
    ///
    /// The write `spaceport auth user disconnect` makes, and the one an
    /// operator must make before re-pointing a user at a different account
    /// there. Only the link goes — the user, their entitlements and their
    /// sessions are untouched, because a binding never granted any of them.
    /// A binding that was not there to remove is [`IdentityError::NotBound`]
    /// rather than a quiet success: an operator told that a link is gone has
    /// to be able to believe it was there.
    pub async fn unbind(&self, user: &UserId, connection: &str) -> Result<(), IdentityError> {
        let user = user.clone();
        let connection_slug = connection.to_owned();
        let named = connection.to_owned();

        let outcome = self
            .db
            .call(move |db| {
                let transaction = db
                    .transaction()
                    .context("beginning to unbind an identity")?;

                // Read before deleting, so the log entry can name the account
                // that was let go — after the delete, this row is the only
                // place that pairing existed.
                let held: Option<(String, String)> = transaction
                    .query_row(
                        "SELECT external_id, external_login FROM idp_identities
                         WHERE user_id = ?1 AND connection = ?2",
                        rusqlite::params![user.as_str(), connection_slug],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .context("looking an identity binding up")?;
                let Some((external_id, external_login)) = held else {
                    return Ok(Err(IdentityError::NotBound(anyhow!(
                        "user `{user}` holds no identity at connection `{connection_slug}` — \
                         `spaceport auth audit {user}` says which they hold"
                    ))));
                };

                transaction
                    .execute(
                        "DELETE FROM idp_identities WHERE user_id = ?1 AND connection = ?2",
                        rusqlite::params![user.as_str(), connection_slug],
                    )
                    .context("unbinding an identity")?;

                record_in(
                    &transaction,
                    &now(),
                    "identity.unbound",
                    Some(&user),
                    OPERATOR_ORIGIN,
                    Some(&binding_detail(
                        &connection_slug,
                        &external_login,
                        &external_id,
                    )),
                )?;

                transaction
                    .commit()
                    .context("committing an identity unbinding")?;

                Ok(Ok(()))
            })
            .await
            .map_err(IdentityError::Failed)?;
        outcome?;

        info!(connection = %named, "identity unbound");

        Ok(())
    }
}

/// Assert that `user` is `identity`, inside the caller's transaction.
///
/// A function over a transaction for [`record_in`]'s reason turned round: the
/// binding and the `identity.bound` entry that records it must commit
/// together, and so must whatever else the caller is writing — creating a user
/// with `--connect` is one commit or it is a user whose binding silently did
/// not happen.
///
/// The two conflicts are *read* first, in this transaction, rather than left to
/// the unique indexes and untangled from a constraint violation afterwards.
/// That is [`IdentityRepository::record`]'s argument in the other direction:
/// two uniqueness claims can each be the one that fires — the external account
/// already vouching for somebody else, and this user already being somebody
/// else here — and a single `ON CONFLICT` clause can catch only one of them,
/// so an insert-then-map would have to guess which refusal to print. They are
/// different refusals with different remedies, and each gets its own sentence.
///
/// Asserting a binding that already exists is not an error. It refreshes the
/// stored handle and records the assertion, rather than being dropped as a
/// no-op: the handle is renameable, so re-asserting is exactly how an operator
/// corrects one that has moved on, and the log records the commands that were
/// given — [`super::UserRepository::suspend`] makes the same argument about a
/// second suspend. What it never touches is `last_login_at`: an assertion is
/// not a login, so an identity somebody has signed in through keeps the
/// timestamp that says so.
pub(super) fn bind_in(
    transaction: &Transaction<'_>,
    at: &str,
    user: &UserId,
    identity: &AssertedIdentity,
) -> Result<(), IdentityError> {
    let AssertedIdentity {
        connection,
        external_id,
        external_login,
    } = identity;

    let vouches_for: Option<String> = transaction
        .query_row(
            "SELECT user_id FROM idp_identities WHERE connection = ?1 AND external_id = ?2",
            rusqlite::params![connection, external_id],
            |row| row.get(0),
        )
        .optional()
        .context("checking who an external account already vouches for")
        .map_err(IdentityError::Failed)?;

    if let Some(holder) = &vouches_for
        && holder != user.as_str()
    {
        let named = names(transaction, holder).map_err(IdentityError::Failed)?;
        return Err(IdentityError::AccountBoundElsewhere(anyhow!(
            "`{external_login}` (`{external_id}`) at connection `{connection}` is already user \
             `{named}` — one external account vouches for one user, so disconnect it there first"
        )));
    }

    let holds: Option<String> = transaction
        .query_row(
            "SELECT external_id FROM idp_identities WHERE user_id = ?1 AND connection = ?2",
            rusqlite::params![user.as_str(), connection],
            |row| row.get(0),
        )
        .optional()
        .context("checking which identity a user already holds on this connection")
        .map_err(IdentityError::Failed)?;

    if let Some(held) = &holds
        && held != external_id
    {
        let named = names(transaction, user.as_str()).map_err(IdentityError::Failed)?;
        return Err(IdentityError::AlreadyBound(anyhow!(
            "user `{named}` is already external id `{held}` at connection `{connection}` — \
             re-pointing a binding is never implicit, so run `spaceport auth user disconnect \
             {named} {connection}` first"
        )));
    }

    match vouches_for {
        // The same assertion again: only the renameable half can have moved,
        // and the login timestamp is none of an assertion's business.
        Some(_) => transaction
            .execute(
                "UPDATE idp_identities SET external_login = ?3
                 WHERE connection = ?1 AND external_id = ?2",
                rusqlite::params![connection, external_id, external_login],
            )
            .context("refreshing an asserted identity's handle"),
        // Never signed in through, and asserting nothing about them: no
        // attributes to replay, and a `last_login_at` of NULL that says as
        // much rather than claiming a login that did not happen. The profile
        // columns are left off the insert for the same reason and take their
        // NULLs: `/users/{login}` does carry a display name and this command
        // has already read it, but an assertion says who an account *is*, and a
        // profile filled in here would be one spaceport read over the person's
        // shoulder rather than one they signed in and handed over. Their first
        // login fills it.
        None => transaction
            .execute(
                "INSERT INTO idp_identities
                     (user_id, connection, external_id, external_login, attributes,
                      last_login_at)
                 VALUES (?1, ?2, ?3, ?4, '{}', NULL)",
                rusqlite::params![user.as_str(), connection, external_id, external_login],
            )
            .context("binding an identity"),
    }
    .map_err(IdentityError::Failed)?;

    record_in(
        transaction,
        at,
        "identity.bound",
        Some(user),
        OPERATOR_ORIGIN,
        Some(&binding_detail(connection, external_login, external_id)),
    )
    .map_err(IdentityError::Failed)?;

    Ok(())
}

/// What a binding's log entry says: the connection, the handle a human
/// recognises, and the id the row is actually keyed by — worded once, because
/// `identity.bound` and `identity.unbound` are the same fact arriving and
/// leaving.
fn binding_detail(connection: &str, external_login: &str, external_id: &str) -> String {
    format!("connection `{connection}`, `{external_login}` (`{external_id}`)")
}

/// The slug a refusal calls a user by, falling back to the id.
///
/// A refusal names whoever the operator would have to go and fix, and they
/// typed a slug — but a row whose user has no slug to find is not a reason to
/// refuse to explain the conflict, so the id stands in.
fn names(transaction: &Transaction<'_>, user: &str) -> Result<String> {
    let slug: Option<String> = transaction
        .query_row(
            "SELECT user_slug FROM users WHERE user_id = ?1",
            rusqlite::params![user],
            |row| row.get(0),
        )
        .optional()
        .context("naming the user a binding conflicts with")?;

    Ok(slug.unwrap_or_else(|| user.to_owned()))
}

/// Delete every identity of `user`, inside the caller's transaction.
///
/// The drop cascade's tenant, a function over a transaction for the reason
/// every cascade here is: a user the pool has forgotten must not keep an IdP
/// link that the unique index would then refuse to the next holder of their
/// external account. Called from [`super::repository`]'s drop path and
/// deliberately *not* from suspend — a resumed user's next login must update
/// the link they had, not recreate it.
pub(super) fn remove_users_in(transaction: &Transaction<'_>, user: &UserId) -> Result<()> {
    transaction
        .execute(
            "DELETE FROM idp_identities WHERE user_id = ?1",
            rusqlite::params![user.as_str()],
        )
        .context("removing a dropped user's idp identities")?;

    Ok(())
}

/// One identity row as SQL hands it over: connection, external id, handle,
/// attributes as stored JSON, last login, and the two halves of the profile.
///
/// Named rather than spelled out at the call site because a seven-place tuple
/// in a signature is a swap waiting to happen — the last three are all
/// `Option<String>` and the compiler would not notice.
type IdentityRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The row as SQL hands it over, before the typed fields are parsed out.
///
/// `pub(super)` because [`super::sso`] reads the same table inside its login
/// transaction, and a second row-reader there would be a second opinion about
/// what a stored rule looks like.
pub(super) type MappingRow = (String, String, String, String, String, String);

pub(super) fn mapping_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MappingRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

/// Read a stored row back into a record, holding the stored halves to the
/// same alphabets `add` did — a row that will not read was written by
/// something other than this build, and the caller decides what that costs.
pub(super) fn mapping_record(row: MappingRow) -> Result<MappingRecord> {
    let (rule_id, connection, app, roles, conditions, created_at) = row;

    Ok(MappingRecord {
        rule_id,
        connection,
        app: app
            .parse()
            .map_err(|error| anyhow!("{error:#}"))
            .context("reading a stored mapping's app id")?,
        roles: roles
            .split(',')
            .map(|role| {
                role.parse::<Role>()
                    .context("reading a stored mapping's roles")
            })
            .collect::<Result<Vec<Role>>>()?,
        conditions: serde_json::from_str(&conditions)
            .context("reading a stored mapping's conditions")?,
        created_at,
    })
}

/// The roles as the column stores them: comma-joined, an alphabet with no
/// comma in it.
fn joined(roles: &[Role]) -> String {
    let roles: Vec<&str> = roles.iter().map(Role::as_str).collect();

    roles.join(",")
}

fn conditions_json(conditions: &[Condition]) -> Result<String> {
    serde_json::to_string(conditions).context("writing a mapping's conditions")
}

/// The conditions as a log entry or a listing says them: backticked,
/// comma-separated — the `AND` is the only semantics there is, so it goes
/// unsaid.
pub(crate) fn conditions_prose(conditions: &[Condition]) -> String {
    let spelled: Vec<String> = conditions
        .iter()
        .map(|condition| format!("`{condition}`"))
        .collect();

    spelled.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        AuthLogRepository, EntitlementRepository, UserRef, UserRepository, UserSlug,
    };

    fn repositories() -> (
        Db,
        UserRepository,
        MappingRepository,
        IdentityRepository,
        AuthLogRepository,
    ) {
        let db = Db::in_memory().unwrap();

        (
            db.clone(),
            UserRepository::new(db.clone()),
            MappingRepository::new(db.clone()),
            IdentityRepository::new(db.clone()),
            AuthLogRepository::new(db),
        )
    }

    fn slug(slug: &str) -> UserSlug {
        slug.parse().unwrap()
    }

    fn grants(s: &str) -> RolesAtApp {
        s.parse().unwrap()
    }

    fn condition(s: &str) -> Condition {
        s.parse().unwrap()
    }

    /// What an operator asserts, already resolved to a numeric id — the
    /// handle-to-id lookup happens against the IdP, above this seam.
    fn asserted(connection: &str, external_id: &str, external_login: &str) -> AssertedIdentity {
        AssertedIdentity {
            connection: connection.to_owned(),
            external_id: external_id.to_owned(),
            external_login: external_login.to_owned(),
        }
    }

    fn attributes(pairs: &[(&str, &[&str])]) -> Attributes {
        pairs
            .iter()
            .map(|(attr, values)| {
                (
                    (*attr).to_owned(),
                    values.iter().map(|value| (*value).to_owned()).collect(),
                )
            })
            .collect()
    }

    /// A profile with both halves said, for the tests about a login that
    /// carried one. The absent cases are spelled `IdpProfile::default()` in
    /// place, because "the IdP said nothing" is the thing being asserted.
    fn profile(name: &str, email: &str) -> IdpProfile {
        IdpProfile {
            name: Some(name.to_owned()),
            email: Some(email.to_owned()),
        }
    }

    /// One identity as [`VouchedProfile::resolve`] looks at it: which
    /// connection, when it was last signed in through, and what it calls the
    /// person. The id, handle and snapshot decide nothing there, so they are
    /// left empty rather than invented.
    fn identity(
        connection: &str,
        last_login_at: Option<&str>,
        profile: IdpProfile,
    ) -> IdentityRecord {
        IdentityRecord {
            connection: connection.to_owned(),
            external_id: String::new(),
            external_login: String::new(),
            attributes: Attributes::default(),
            last_login_at: last_login_at.map(str::to_owned),
            profile,
        }
    }

    /// Plant the connection `--via` is verified against, exactly as `connect`
    /// records one — the mapping code reads the table, not the API behind it.
    async fn plant_connection(db: &Db, slug: &str) {
        let slug = slug.to_owned();
        db.call(move |connection| {
            connection
                .execute(
                    "INSERT INTO github_apps
                         (slug, app_id, name, owner, client_id, client_secret, webhook_secret,
                          private_key, connected_at)
                     VALUES (?1, 42, 'Spaceport for Acme', 'an-organisation', 'iv1.abc', 'secret',
                             'hook', 'pem', '2026-01-01T00:00:00Z')",
                    rusqlite::params![slug],
                )
                .map(|_| ())
                .map_err(anyhow::Error::from)
        })
        .await
        .unwrap();
    }

    /// Plant a mapped entitlement as the login re-sync will one day write one:
    /// tagged with the rule that produced it.
    async fn plant_mapped(db: &Db, user: &UserId, granted: &str, rule: &str) {
        let user = user.to_string();
        let granted: crate::auth::RoleAtApp = granted.parse().unwrap();
        let rule = rule.to_owned();
        db.call(move |connection| {
            connection
                .execute(
                    "INSERT INTO entitlements
                         (user_id, spaceport_app, role, mapped_rule, granted_at)
                     VALUES (?1, ?2, ?3, ?4, '2026-01-01T00:00:00Z')",
                    rusqlite::params![user, granted.app.as_str(), granted.role.as_str(), rule],
                )
                .map(|_| ())
                .map_err(anyhow::Error::from)
        })
        .await
        .unwrap();
    }

    /// The spec's spelling, parsed both ways round: commas split roles, the
    /// `@` splits them from the app, and each half is held to its alphabet.
    #[test]
    fn parses_the_roles_at_app_spelling() {
        let parsed = grants("reader,writer@blog");
        assert_eq!(parsed.roles.len(), 2);
        assert_eq!(parsed.app.as_str(), "blog");
        assert_eq!(parsed.to_string(), "reader,writer@blog");
        assert_eq!(grants("reader@blog").roles.len(), 1);

        for broken in [
            "reader",
            "@blog",
            "reader@",
            "reader,@blog",
            "Reader@blog",
            "reader,writer@Blog",
        ] {
            assert!(broken.parse::<RolesAtApp>().is_err(), "accepted `{broken}`");
        }
    }

    /// A repeated role is a typo, and refusing it beats a listing that
    /// disagrees with what the operator remembers typing.
    #[test]
    fn refuses_a_role_named_twice() {
        let err = "reader,reader@blog"
            .parse::<RolesAtApp>()
            .unwrap_err()
            .to_string();
        assert!(err.contains("appears twice"), "{err}");
    }

    /// `<attr>=<value>`, split on the first `=`: the value is the IdP's
    /// string and may carry one of its own.
    #[test]
    fn parses_a_condition() {
        assert_eq!(condition("org=acme-corp").attr, "org");
        assert_eq!(condition("org=acme-corp").value, "acme-corp");
        assert_eq!(condition("claim=a=b").value, "a=b");

        for broken in ["org", "=value", "org="] {
            assert!(broken.parse::<Condition>().is_err(), "accepted `{broken}`");
        }
    }

    /// `<connection>:<login>`, the spelling `auth user connect` takes: the
    /// colon splits a connection from a handle, and both halves have to be
    /// there.
    #[test]
    fn parses_an_account_at_a_connection() {
        let parsed = "spaceport-for-acme:octo-alice"
            .parse::<AccountAtConnection>()
            .unwrap();
        assert_eq!(parsed.connection, "spaceport-for-acme");
        assert_eq!(parsed.login, "octo-alice");
        assert_eq!(parsed.to_string(), "spaceport-for-acme:octo-alice");
    }

    /// Every way of getting it wrong that clap has to catch before a round
    /// trip to github.com happens: a bare handle names no connection to
    /// resolve it against, an empty half names nobody, and a second colon
    /// makes a handle no IdP could ever mint.
    #[test]
    fn refuses_a_value_that_names_no_account_at_a_connection() {
        for broken in [
            "octo-alice",
            "",
            ":octo-alice",
            "spaceport-for-acme:",
            "spaceport-for-acme:octo:alice",
        ] {
            assert!(
                broken.parse::<AccountAtConnection>().is_err(),
                "accepted `{broken}`",
            );
        }

        // And the refusal shows the shape, because an operator who mistyped it
        // once has nothing else to go on.
        let err = "octo-alice"
            .parse::<AccountAtConnection>()
            .unwrap_err()
            .to_string();
        assert!(err.contains("spaceport-for-acme:octo-alice"), "{err}");
    }

    #[tokio::test]
    async fn adds_and_lists_a_mapping() {
        let (db, _, mappings, _, log) = repositories();
        plant_connection(&db, "spaceport-acme").await;

        let added = mappings
            .add(
                "spaceport-acme",
                &grants("reader,writer@blog"),
                &[condition("org=acme-corp")],
            )
            .await
            .unwrap();

        let listed = mappings.list(None).await.unwrap();
        assert_eq!(listed, std::slice::from_ref(&added));
        assert_eq!(listed[0].connection, "spaceport-acme");
        assert_eq!(listed[0].conditions, [condition("org=acme-corp")]);
        assert!(
            listed[0].created_at.ends_with('Z'),
            "{}",
            listed[0].created_at
        );
        // The stable id round-trips through `get`, which is what `drop` aims
        // by.
        assert_eq!(
            mappings.get(&added.rule_id).await.unwrap(),
            Some(added.clone())
        );
        assert_eq!(mappings.get("no-such-rule").await.unwrap(), None);
        // And the add is in the log, naming the rule.
        let entries = log.entries(None).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, "mapping.added");
        assert!(
            entries[0]
                .detail
                .as_deref()
                .unwrap()
                .contains(&added.rule_id)
        );
    }

    /// `mapping list [<app-id>]`: the filter is the app, and only the app.
    #[tokio::test]
    async fn lists_only_the_app_asked_for() {
        let (db, _, mappings, _, _) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        mappings
            .add(
                "spaceport-acme",
                &grants("reader@blog"),
                &[condition("org=acme-corp")],
            )
            .await
            .unwrap();
        mappings
            .add(
                "spaceport-acme",
                &grants("reader@wiki"),
                &[condition("org=acme-corp")],
            )
            .await
            .unwrap();

        let listed = mappings.list(Some(&"wiki".parse().unwrap())).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].app.as_str(), "wiki");
    }

    /// The spec's one hard rule about roles: `admin` is never mappable,
    /// because an IdP group must not appoint an admin nobody on this host did.
    #[tokio::test]
    async fn refuses_to_map_the_admin_role() {
        let (db, _, mappings, _, log) = repositories();
        plant_connection(&db, "spaceport-acme").await;

        let error = mappings
            .add(
                "spaceport-acme",
                &grants("reader,admin@blog"),
                &[condition("org=acme-corp")],
            )
            .await
            .unwrap_err();

        assert!(matches!(error, MappingError::Refused(_)), "{error}");
        assert!(
            error.to_string().contains("never a mappable role"),
            "{error}"
        );
        // And the refusal changed nothing.
        assert!(mappings.list(None).await.unwrap().is_empty());
        assert!(log.entries(None).await.unwrap().is_empty());
    }

    /// `--via` is verified where attribute names are not: a connection is
    /// spaceport's own record, so a typo has something to catch it.
    #[tokio::test]
    async fn refuses_a_connection_nobody_made() {
        let (_, _, mappings, _, _) = repositories();

        let error = mappings
            .add(
                "ghost",
                &grants("reader@blog"),
                &[condition("org=acme-corp")],
            )
            .await
            .unwrap_err();

        assert!(
            matches!(error, MappingError::UnknownConnection(_)),
            "{error}"
        );
        assert!(error.to_string().contains("ghost"), "{error}");
    }

    /// A rule with no conditions would grant to everyone the connection lets
    /// in, which no operator can have meant.
    #[tokio::test]
    async fn refuses_a_mapping_with_no_conditions() {
        let (db, _, mappings, _, _) = repositories();
        plant_connection(&db, "spaceport-acme").await;

        let error = mappings
            .add("spaceport-acme", &grants("reader@blog"), &[])
            .await
            .unwrap_err();

        assert!(matches!(error, MappingError::Refused(_)), "{error}");
        assert!(error.to_string().contains("at least one"), "{error}");
    }

    /// The spec's drop cascade, whole: the rule goes, the entitlements it
    /// produced go in the same commit, manual grants stand, and the log
    /// records one drop rather than a fan of revokes nobody typed.
    #[tokio::test]
    async fn dropping_a_rule_takes_its_entitlements_and_only_its() {
        let (db, users, mappings, _, log) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        let alice = users.create(&slug("alice"), None, None).await.unwrap();
        let bob = users.create(&slug("bob"), None, None).await.unwrap();
        let added = mappings
            .add(
                "spaceport-acme",
                &grants("reader@blog"),
                &[condition("org=acme-corp")],
            )
            .await
            .unwrap();
        plant_mapped(&db, &alice.id, "reader@blog", &added.rule_id).await;
        plant_mapped(&db, &bob.id, "reader@blog", &added.rule_id).await;
        plant_mapped(&db, &bob.id, "reader@wiki", "some-other-rule").await;
        let entitlements = EntitlementRepository::new(db.clone());
        entitlements
            .grant(
                &UserRef::Slug(slug("alice")),
                &"writer@blog".parse().unwrap(),
            )
            .await
            .unwrap();

        let dropped = mappings.drop_rule(&added.rule_id).await.unwrap();

        assert_eq!(dropped.mapping.rule_id, added.rule_id);
        assert_eq!(dropped.removed, 2);
        assert_eq!(dropped.users.len(), 2);
        assert!(dropped.users.contains(&alice.id));
        // Alice's manual grant and bob's other-rule row both survived.
        let (_, hers) = entitlements
            .audit(&UserRef::Slug(slug("alice")))
            .await
            .unwrap();
        assert_eq!(hers.len(), 1);
        assert_eq!(hers[0].role.as_str(), "writer");
        let (_, his) = entitlements
            .audit(&UserRef::Slug(slug("bob")))
            .await
            .unwrap();
        assert_eq!(his.len(), 1);
        assert_eq!(his[0].mapped_rule.as_deref(), Some("some-other-rule"));
        // One `mapping.dropped` entry, no `entitlement.revoked` fan.
        let kinds: Vec<String> = log
            .entries(None)
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.kind)
            .collect();
        assert!(kinds.contains(&"mapping.dropped".to_owned()), "{kinds:?}");
        assert!(
            !kinds.contains(&"entitlement.revoked".to_owned()),
            "{kinds:?}"
        );
        // And the rule is gone.
        assert_eq!(mappings.get(&added.rule_id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn dropping_a_rule_nobody_made_says_so() {
        let (_, _, mappings, _, _) = repositories();

        let error = mappings.drop_rule("no-such-rule").await.unwrap_err();

        assert!(matches!(error, MappingError::UnknownRule(_)), "{error}");
        assert!(error.to_string().contains("mapping list"), "{error}");
    }

    /// The whole of the matching rule, in one place: every condition must
    /// hold, a multi-valued attribute matches by containment, and a mistyped
    /// attribute never matches anything — which is the documented behaviour,
    /// not a bug.
    #[test]
    fn evaluate_ands_conditions_over_value_lists() {
        let rule = MappingRecord {
            rule_id: "rule-1".to_owned(),
            connection: "spaceport-acme".to_owned(),
            app: "blog".parse().unwrap(),
            roles: vec!["reader".parse().unwrap()],
            conditions: vec![condition("org=acme-corp"), condition("team=authors")],
            created_at: "2026-08-16T00:00:00Z".to_owned(),
        };
        let rules = [rule];

        // Both conditions hold — the team list contains the value.
        let matching = evaluate(
            &rules,
            "spaceport-acme",
            &attributes(&[("org", &["acme-corp"]), ("team", &["authors", "review"])]),
        );
        assert_eq!(matching.len(), 1);

        // One condition failing fails the rule: AND, not OR.
        assert!(
            evaluate(
                &rules,
                "spaceport-acme",
                &attributes(&[("org", &["acme-corp"]), ("team", &["review"])]),
            )
            .is_empty()
        );
        // An attribute the snapshot never asserts silently never matches.
        assert!(
            evaluate(
                &rules,
                "spaceport-acme",
                &attributes(&[("org", &["acme-corp"])]),
            )
            .is_empty()
        );
        // Containment is exact, not substring.
        assert!(
            evaluate(
                &rules,
                "spaceport-acme",
                &attributes(&[("org", &["acme-corporation"]), ("team", &["authors"])]),
            )
            .is_empty()
        );
        // And a rule is scoped to its connection: the same attributes through
        // another IdP satisfy nothing.
        assert!(
            evaluate(
                &rules,
                "spaceport-other",
                &attributes(&[("org", &["acme-corp"]), ("team", &["authors"])]),
            )
            .is_empty()
        );
    }

    #[tokio::test]
    async fn records_an_identity_and_reads_it_back() {
        let (_, users, _, identities, _) = repositories();
        let alice = users.create(&slug("alice"), None, None).await.unwrap();

        identities
            .record(
                &alice.id,
                "spaceport-acme",
                "583231",
                "octo-alice",
                &attributes(&[("login", &["octo-alice"]), ("org", &["acme-corp"])]),
                &profile("Alice Liddell", "alice@acme.example"),
            )
            .await
            .unwrap();

        let held = identities.for_user(&alice.id).await.unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].connection, "spaceport-acme");
        assert_eq!(held[0].external_id, "583231");
        assert_eq!(held[0].external_login, "octo-alice");
        assert_eq!(held[0].attributes["org"], ["acme-corp"]);
        let stamped = held[0].last_login_at.as_deref().unwrap();
        assert!(stamped.ends_with('Z'), "{stamped}");
        // The profile comes back as the IdP asserted it — and stays out of the
        // attributes, where a `--when` clause could have been aimed at it.
        assert_eq!(held[0].profile.name.as_deref(), Some("Alice Liddell"));
        assert_eq!(held[0].profile.email.as_deref(), Some("alice@acme.example"));
        assert!(!held[0].attributes.contains_key("email"), "");
        assert!(!held[0].attributes.contains_key("name"), "");
    }

    /// A re-login replaces the snapshot rather than sitting beside it: one
    /// row per user per connection is the table's whole claim.
    ///
    /// The profile goes the same way, and the second login here carries none —
    /// a name cleared at the IdP and an address that lost its verified flag are
    /// gone from here too, rather than being remembered by a spaceport nobody
    /// is asserting them to any more.
    #[tokio::test]
    async fn a_second_login_replaces_the_snapshot() {
        let (_, users, _, identities, _) = repositories();
        let alice = users.create(&slug("alice"), None, None).await.unwrap();
        identities
            .record(
                &alice.id,
                "spaceport-acme",
                "583231",
                "octo-alice",
                &attributes(&[("org", &["acme-corp"])]),
                &profile("Alice Liddell", "alice@acme.example"),
            )
            .await
            .unwrap();

        identities
            .record(
                &alice.id,
                "spaceport-acme",
                "583231",
                "octo-renamed",
                &attributes(&[("org", &["other-org"])]),
                &IdpProfile::default(),
            )
            .await
            .unwrap();

        let held = identities.for_user(&alice.id).await.unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].external_login, "octo-renamed");
        assert_eq!(held[0].attributes["org"], ["other-org"]);
        assert!(held[0].profile.is_empty(), "{:?}", held[0].profile);
    }

    /// The resolution's first rule: an address proven with a one-time code
    /// beats any number of connections asserting one, and the fallthrough
    /// exists for the ordinary SSO user, who has no credential at all.
    #[test]
    fn a_proven_address_outranks_every_claimed_one() {
        let claimed = [identity(
            "spaceport-acme",
            Some("2026-08-20T00:00:00Z"),
            profile("Alice Liddell", "alice@acme.example"),
        )];

        let credentialed = VouchedProfile::resolve(Some("alice@proven.example"), &claimed);
        assert_eq!(credentialed.email.as_deref(), Some("alice@proven.example"));
        // Only the address is outranked. The name has no credential to lose
        // to — a user slug is an operator's handle, not what somebody is
        // called — so the connection's word stands.
        assert_eq!(credentialed.name.as_deref(), Some("Alice Liddell"));

        let sso_only = VouchedProfile::resolve(None, &claimed);
        assert_eq!(sso_only.email.as_deref(), Some("alice@acme.example"));

        // And a user nobody has said anything about is vouched for by their
        // subject alone.
        assert!(VouchedProfile::resolve(None, &[]).is_empty());
    }

    /// The second rule: among identities, the one they signed in through most
    /// recently wins — and a binding an operator asserted, which has no login
    /// behind it, sorts last where it can never take a live answer's place.
    #[test]
    fn the_most_recent_login_says_who_the_person_is() {
        let identities = [
            identity(
                "spaceport-acme",
                Some("2026-08-20T00:00:00Z"),
                profile("Alice at Acme", "alice@acme.example"),
            ),
            identity(
                "spaceport-zeta",
                Some("2026-08-24T00:00:00Z"),
                profile("Alice at Zeta", "alice@zeta.example"),
            ),
            identity(
                "spaceport-old",
                None,
                profile("Stale Alice", "stale@example"),
            ),
        ];

        let vouched = VouchedProfile::resolve(None, &identities);
        assert_eq!(vouched.name.as_deref(), Some("Alice at Zeta"));
        assert_eq!(vouched.email.as_deref(), Some("alice@zeta.example"));

        // Ordered by the stamp and not by the order the rows arrive in: the
        // same three identities read back the other way round answer the same.
        let mut backwards = identities.clone();
        backwards.reverse();
        assert_eq!(VouchedProfile::resolve(None, &backwards), vouched);
    }

    /// Stamps are compared as moments, never as text: RFC 3339 with
    /// fractional seconds sorts *before* the same second without them, because
    /// `.` precedes `Z` — so a lexicographic winner would be the older login.
    #[test]
    fn a_fractional_second_does_not_reorder_two_logins() {
        let identities = [
            identity(
                "spaceport-acme",
                Some("2026-08-24T09:00:00Z"),
                profile("Earlier", "earlier@example"),
            ),
            identity(
                "spaceport-zeta",
                Some("2026-08-24T09:00:00.500Z"),
                profile("Later", "later@example"),
            ),
        ];

        assert_eq!(
            VouchedProfile::resolve(None, &identities).name.as_deref(),
            Some("Later")
        );
    }

    /// The third rule: the halves are resolved apart, so a connection that
    /// says a name and no address cannot blank an address another one gave
    /// us — the two may therefore come from different connections, which is
    /// one person's two accounts and not two people.
    #[test]
    fn each_half_of_a_profile_is_resolved_on_its_own() {
        let vouched = VouchedProfile::resolve(
            None,
            &[
                identity(
                    "spaceport-acme",
                    Some("2026-08-20T00:00:00Z"),
                    IdpProfile {
                        name: None,
                        email: Some("alice@acme.example".to_owned()),
                    },
                ),
                identity(
                    "spaceport-zeta",
                    Some("2026-08-24T00:00:00Z"),
                    IdpProfile {
                        name: Some("Alice Liddell".to_owned()),
                        email: None,
                    },
                ),
            ],
        );

        assert_eq!(vouched.name.as_deref(), Some("Alice Liddell"));
        assert_eq!(vouched.email.as_deref(), Some("alice@acme.example"));
    }

    /// What the gate actually calls: the credential and the identities read
    /// together, resolved into the two claims a JWT carries.
    #[tokio::test]
    async fn vouching_reads_the_credential_and_the_claims_as_one() {
        let (_, users, _, identities, _) = repositories();
        let alice = users
            .create(&slug("alice"), Some("alice@proven.example"), None)
            .await
            .unwrap();
        identities
            .record(
                &alice.id,
                "spaceport-acme",
                "583231",
                "octo-alice",
                &attributes(&[("org", &["acme-corp"])]),
                &profile("Alice Liddell", "alice@acme.example"),
            )
            .await
            .unwrap();

        let vouched = identities.vouched(&alice.id).await.unwrap();
        assert_eq!(vouched.name.as_deref(), Some("Alice Liddell"));
        assert_eq!(vouched.email.as_deref(), Some("alice@proven.example"));

        // A user the pool no longer knows is nobody to vouch for — the race
        // the gate meets one line before it refuses for want of access.
        users
            .drop_user(&UserRef::Id(alice.id.clone()))
            .await
            .unwrap();
        assert!(identities.vouched(&alice.id).await.unwrap().is_empty());
    }

    /// The drop cascade, seen from this table: the identity dies with the
    /// user, so the external account is free to vouch for a future one —
    /// while suspend keeps the link, because resume restores, never recreates.
    #[tokio::test]
    async fn dropping_a_user_takes_their_identity_and_suspending_does_not() {
        let (_, users, _, identities, _) = repositories();
        let alice = users.create(&slug("alice"), None, None).await.unwrap();
        identities
            .record(
                &alice.id,
                "spaceport-acme",
                "583231",
                "octo-alice",
                &attributes(&[("org", &["acme-corp"])]),
                &IdpProfile::default(),
            )
            .await
            .unwrap();

        users.suspend(&UserRef::Slug(slug("alice"))).await.unwrap();
        assert_eq!(identities.for_user(&alice.id).await.unwrap().len(), 1);

        users
            .drop_user(&UserRef::Slug(slug("alice")))
            .await
            .unwrap();
        assert!(identities.for_user(&alice.id).await.unwrap().is_empty());
    }

    /// An operator's assertion, as the table keeps one: the account it names
    /// and nothing else — no attributes to replay and no login to claim.
    #[tokio::test]
    async fn binds_an_identity_nobody_has_signed_in_through() {
        let (_, users, _, identities, log) = repositories();
        let alice = users.create(&slug("alice"), None, None).await.unwrap();

        identities
            .bind(
                &alice.id,
                &asserted("spaceport-acme", "583231", "octo-alice"),
            )
            .await
            .unwrap();

        let held = identities.for_user(&alice.id).await.unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].external_id, "583231");
        assert_eq!(held[0].external_login, "octo-alice");
        assert!(held[0].attributes.is_empty());
        assert_eq!(held[0].last_login_at, None);
        // And the assertion is in the log, as the operator's own act.
        let entries = log.entries(None).await.unwrap();
        assert_eq!(entries[1].kind, "identity.bound");
        assert_eq!(entries[1].origin, OPERATOR_ORIGIN);
        assert_eq!(entries[1].user.as_deref(), Some(alice.id.as_str()));
        let detail = entries[1].detail.as_deref().unwrap();
        assert!(detail.contains("spaceport-acme"), "{detail}");
        assert!(detail.contains("octo-alice"), "{detail}");
        assert!(detail.contains("583231"), "{detail}");
    }

    /// One external account vouches for one user. Binding it a second time
    /// would leave two users a single login could resolve to, which is the
    /// ambiguity the whole feature exists to avoid.
    #[tokio::test]
    async fn refuses_an_account_that_already_vouches_for_somebody_else() {
        let (_, users, _, identities, log) = repositories();
        let alice = users.create(&slug("alice"), None, None).await.unwrap();
        let bob = users.create(&slug("bob"), None, None).await.unwrap();
        identities
            .bind(
                &alice.id,
                &asserted("spaceport-acme", "583231", "octo-alice"),
            )
            .await
            .unwrap();

        let error = identities
            .bind(&bob.id, &asserted("spaceport-acme", "583231", "octo-alice"))
            .await
            .unwrap_err();

        assert!(
            matches!(error, IdentityError::AccountBoundElsewhere(_)),
            "{error}"
        );
        // Named by the slug the operator would have to go and fix.
        assert!(error.to_string().contains("alice"), "{error}");
        // And the refusal wrote nothing: bob holds nothing, and only alice's
        // binding was ever logged.
        assert!(identities.for_user(&bob.id).await.unwrap().is_empty());
        assert_eq!(identities.for_user(&alice.id).await.unwrap().len(), 1);
        let bound = log
            .entries(None)
            .await
            .unwrap()
            .into_iter()
            .filter(|entry| entry.kind == "identity.bound")
            .count();
        assert_eq!(bound, 1);
    }

    /// Re-pointing a user at a different account is never implicit: the
    /// delete-then-insert that would make it work silently moves somebody's
    /// identity from under them, so the operator has to say `disconnect`.
    #[tokio::test]
    async fn refuses_a_second_account_where_the_user_already_has_one() {
        let (_, users, _, identities, _) = repositories();
        let alice = users.create(&slug("alice"), None, None).await.unwrap();
        identities
            .bind(
                &alice.id,
                &asserted("spaceport-acme", "583231", "octo-alice"),
            )
            .await
            .unwrap();

        let error = identities
            .bind(&alice.id, &asserted("spaceport-acme", "99", "octo-other"))
            .await
            .unwrap_err();

        assert!(matches!(error, IdentityError::AlreadyBound(_)), "{error}");
        assert!(error.to_string().contains("disconnect"), "{error}");
        // The binding she had is the binding she still has.
        let held = identities.for_user(&alice.id).await.unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].external_id, "583231");
    }

    /// The same assertion again is not a refusal — it is how an operator
    /// corrects a handle that has been renamed. What it must never do is claim
    /// a login: the timestamp a real sign-in left stands.
    #[tokio::test]
    async fn asserting_the_same_binding_again_refreshes_only_the_handle() {
        let (_, users, _, identities, log) = repositories();
        let alice = users.create(&slug("alice"), None, None).await.unwrap();
        identities
            .record(
                &alice.id,
                "spaceport-acme",
                "583231",
                "octo-alice",
                &attributes(&[("org", &["acme-corp"])]),
                &profile("Alice Liddell", "alice@acme.example"),
            )
            .await
            .unwrap();

        identities
            .bind(
                &alice.id,
                &asserted("spaceport-acme", "583231", "octo-renamed"),
            )
            .await
            .unwrap();

        let held = identities.for_user(&alice.id).await.unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].external_login, "octo-renamed");
        assert!(held[0].last_login_at.is_some());
        assert_eq!(held[0].attributes["org"], ["acme-corp"]);
        // Including the profile: an assertion is not a login, so what the IdP
        // last said about this person is not an operator's to overwrite with
        // silence.
        assert_eq!(held[0].profile.name.as_deref(), Some("Alice Liddell"));
        // And the command that was given is recorded, as every command is.
        let entries = log.entries(None).await.unwrap();
        assert_eq!(entries.last().unwrap().kind, "identity.bound");
    }

    #[tokio::test]
    async fn unbinds_an_identity_and_records_that_it_went() {
        let (_, users, _, identities, log) = repositories();
        let alice = users.create(&slug("alice"), None, None).await.unwrap();
        identities
            .bind(
                &alice.id,
                &asserted("spaceport-acme", "583231", "octo-alice"),
            )
            .await
            .unwrap();

        identities
            .unbind(&alice.id, "spaceport-acme")
            .await
            .unwrap();

        assert!(identities.for_user(&alice.id).await.unwrap().is_empty());
        let last = log.entries(None).await.unwrap().pop().unwrap();
        assert_eq!(last.kind, "identity.unbound");
        assert_eq!(last.origin, OPERATOR_ORIGIN);
        // The entry names the account that was let go, because after the
        // delete this is the only place that pairing survives.
        assert!(
            last.detail.as_deref().unwrap().contains("583231"),
            "{:?}",
            last.detail
        );
    }

    /// Told apart from a success, so an operator is never told that a link
    /// they never made has been taken away.
    #[tokio::test]
    async fn unbinding_what_was_never_bound_says_so() {
        let (_, users, _, identities, log) = repositories();
        let alice = users.create(&slug("alice"), None, None).await.unwrap();

        let error = identities
            .unbind(&alice.id, "spaceport-acme")
            .await
            .unwrap_err();

        assert!(matches!(error, IdentityError::NotBound(_)), "{error}");
        assert!(error.to_string().contains("spaceport-acme"), "{error}");
        // Nothing happened, so nothing is logged as having happened.
        let kinds: Vec<String> = log
            .entries(None)
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.kind)
            .collect();
        assert_eq!(kinds, ["user.created"]);
    }

    /// The drop cascade holds for an asserted binding exactly as it does for a
    /// login-made one: the row goes with the user, so the external account is
    /// free to vouch for whoever holds the slug next.
    #[tokio::test]
    async fn dropping_a_bound_user_takes_the_binding_with_them() {
        let (_, users, _, identities, _) = repositories();
        let alice = users.create(&slug("alice"), None, None).await.unwrap();
        identities
            .bind(
                &alice.id,
                &asserted("spaceport-acme", "583231", "octo-alice"),
            )
            .await
            .unwrap();

        users
            .drop_user(&UserRef::Slug(slug("alice")))
            .await
            .unwrap();

        assert!(identities.for_user(&alice.id).await.unwrap().is_empty());
        // And the account is free again: a fresh user may hold it.
        let carol = users.create(&slug("carol"), None, None).await.unwrap();
        identities
            .bind(
                &carol.id,
                &asserted("spaceport-acme", "583231", "octo-alice"),
            )
            .await
            .unwrap();
        assert_eq!(identities.for_user(&carol.id).await.unwrap().len(), 1);
    }
}

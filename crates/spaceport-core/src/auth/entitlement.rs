//! The `entitlements` table: what a user may do, one row per user, app and
//! role.
//!
//! An entitlement is the triple the spec writes as `(user_id, app_id, role)`,
//! and the triple is the whole identity — granting the same one twice lands on
//! the row that exists, which is what makes `grant` idempotent. Rows carry
//! where they came from: a manual grant has no `mapped_rule`, and — when SSO
//! mappings land — a mapped one names the rule that produced it. That column
//! is read *now*, before anything can write it, because `revoke` already has
//! to refuse a mapped entitlement: revoking one by hand would only last until
//! the next IdP login re-syncs it back, so the honest answer is the rule id
//! and the mapping command that removes it.
//!
//! Nothing here knows what an app's manifest declares. Whether a granted role
//! actually opens a door is the manifest's business, checked where a grant is
//! reported and — later — where a JWT is minted; the store keeps every grant,
//! declared or not, exactly as the spec asks.
//!
//! Same discipline as [`crate::auth::repository`]: every mutation writes its
//! [`crate::auth::log`] entry in the same transaction, or not at all.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{OptionalExtension, Transaction};
use tracing::info;

use super::log::{OPERATOR_ORIGIN, record_in};
use super::repository::{find, record, unknown};
use super::{Role, UserId, UserRecord, UserRef};
use crate::app::AppId;
use crate::state::{Db, now};

/// One role at one app, as `grant` names it: `<role>@<app-id>`.
///
/// A newtype rather than a pair of arguments so the `<role>@<app-id>` spelling
/// is parsed in exactly one place — the CLI, the wire and the tests all hold
/// the same string to the same two alphabets, and a role can never be swapped
/// for an app id without the parse saying so.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RoleAtApp {
    pub role: Role,
    pub app: AppId,
}

impl FromStr for RoleAtApp {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        // `split_once` and not `splitn`: a second `@` belongs to nobody, and
        // letting it slide into the app id would have the app id's parser
        // report a character the operator never meant to type there.
        let Some((role, app)) = s.split_once('@') else {
            bail!("`{s}` is not an entitlement — one looks like `reader@blog`");
        };

        Ok(Self {
            role: role
                .parse()
                .with_context(|| format!("reading the role in `{s}`"))?,
            app: app
                .parse::<AppId>()
                .map_err(|error| anyhow!("{error:#}"))
                .with_context(|| format!("reading the app id in `{s}`"))?,
        })
    }
}

impl fmt::Display for RoleAtApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.role, self.app)
    }
}

/// What `revoke` may be aimed at: one role at an app, or every role at it.
///
/// The spec's `[<role>@]<app-id>` argument, written down as a type: anything
/// with an `@` is a [`RoleAtApp`], anything without is an app id, and garbage
/// is refused by whichever parser it failed. "Everything across apps" is
/// deliberately not a variant — that is `--all`, a flag the operator must
/// spell out, and an absent scope on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeScope {
    One(RoleAtApp),
    App(AppId),
}

impl FromStr for RevokeScope {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.contains('@') {
            return Ok(Self::One(s.parse()?));
        }

        Ok(Self::App(
            s.parse::<AppId>()
                .map_err(|error| anyhow!("{error:#}"))
                .with_context(|| format!("`{s}` is neither `<role>@<app-id>` nor an app id"))?,
        ))
    }
}

impl fmt::Display for RevokeScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::One(entitlement) => entitlement.fmt(f),
            Self::App(app) => app.fmt(f),
        }
    }
}

/// One entitlement as the table stores it, minus the user it belongs to — a
/// read is always about one user, and repeating the id on every row would be
/// the key spelled twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementRecord {
    pub app: AppId,
    pub role: Role,
    /// The SSO mapping rule that produced this row, or `None` for a grant an
    /// operator made by hand. Nothing writes `Some` yet — mappings are a later
    /// milestone — but rows carrying one must already be read and refused
    /// correctly, which is why the field exists now.
    pub mapped_rule: Option<String>,
    pub granted_at: String,
}

/// What a grant came to: the row was made, or it was already there.
///
/// Two answers rather than one, because the operator response differs — a
/// duplicate grant succeeds without a row or a log entry, and saying "granted"
/// about it would have the response disagree with the log.
#[derive(Debug)]
pub enum Granted {
    /// The entitlement is new, and its grant is in the log.
    Fresh(UserRecord),
    /// The very same entitlement already existed; nothing was written. Carries
    /// the mapping rule when the existing row is a mapped one, because "you
    /// already have this via SSO" is a different sentence from "you already
    /// granted this".
    Already(UserRecord, Option<String>),
}

/// What a revoke came to, when it came to anything: the manual rows that went,
/// and the mapped ones that were deliberately left.
///
/// `kept` is not an error path. A revoke aimed at a whole app, or `--all`,
/// legitimately sweeps past mapped rows on its way; deleting them would be
/// undone at the next IdP login, and failing the whole command over them would
/// leave the manual rows the operator *can* revoke still standing. So the
/// manual ones go, and the mapped ones are named with the rule that holds them.
#[derive(Debug)]
pub struct Revoked {
    pub user: UserRecord,
    pub removed: Vec<RoleAtApp>,
    /// The mapped entitlements the revoke refused to touch, each with the rule
    /// id that produced it.
    pub kept: Vec<(RoleAtApp, String)>,
}

/// Why an entitlement command did not happen. Kept apart because the operator
/// interface answers differently: an unknown user or an empty revoke is a
/// mistyped name, a mapped-only revoke is a conflict only a mapping command
/// resolves, and a failure is the host's.
#[derive(Debug)]
pub enum EntitlementError {
    /// No live user answers to that slug or id.
    UnknownUser(anyhow::Error),
    /// The revoke matched no entitlement at all.
    Nothing(anyhow::Error),
    /// Everything the revoke matched is mapped from SSO, so there was nothing
    /// it was allowed to remove.
    Mapped(anyhow::Error),
    /// The store would not do it.
    Failed(anyhow::Error),
}

impl fmt::Display for EntitlementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownUser(error)
            | Self::Nothing(error)
            | Self::Mapped(error)
            | Self::Failed(error) => write!(f, "{error:#}"),
        }
    }
}

impl std::error::Error for EntitlementError {}

/// The `entitlements` table, over the state database.
///
/// A repository of its own rather than more methods on
/// [`crate::auth::UserRepository`]: the one place the two tables must move
/// together — dropping a user — already runs through a free function over the
/// caller's transaction ([`remove_all_in`]), exactly as the log does, so
/// nothing about the cascade argues for one struct. What argues for two is
/// everything else: the user pool's vocabulary is create/suspend/drop and the
/// entitlements' is grant/revoke/audit, and a handler that grants roles has no
/// business seeing the verbs that delete users.
#[derive(Debug, Clone)]
pub struct EntitlementRepository {
    db: Db,
}

impl EntitlementRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Grant `entitlement` to the user `user` names.
    ///
    /// Idempotent by way of the primary key: the triple already existing is
    /// answered with [`Granted::Already`], no second row and — deliberately —
    /// no log entry, because nothing changed and a log that says "granted"
    /// twice about one row is a log that miscounts. A fresh grant and its
    /// `entitlement.granted` entry commit together.
    ///
    /// Whether the app declares the role is not asked here, on purpose: the
    /// spec stores the grant either way, and the warning belongs to the
    /// operator response, where the deployed manifest is at hand.
    pub async fn grant(
        &self,
        user: &UserRef,
        entitlement: &RoleAtApp,
    ) -> Result<Granted, EntitlementError> {
        let asked = user.clone();
        let entitlement = entitlement.clone();
        let said = entitlement.clone();

        let found = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to grant an entitlement")?;

                let Some(row) = find(&transaction, &asked)? else {
                    return Ok(None);
                };
                let user = record(row)?;

                // The existing row's origin, if there is one: `Some(None)` is a
                // manual grant already in place, `Some(Some(rule))` a mapped
                // one, and `None` a triple that is genuinely new. Asked before
                // the insert rather than read out of a constraint violation,
                // because the answer decides more than yes or no — a mapped
                // row has a rule to name.
                let existing: Option<Option<String>> = transaction
                    .query_row(
                        "SELECT mapped_rule FROM entitlements
                         WHERE user_id = ?1 AND spaceport_app = ?2 AND role = ?3",
                        rusqlite::params![
                            user.id.as_str(),
                            entitlement.app.as_str(),
                            entitlement.role.as_str()
                        ],
                        |row| row.get(0),
                    )
                    .optional()
                    .context("looking an entitlement up")?;

                if let Some(mapped_rule) = existing {
                    return Ok(Some(Granted::Already(user, mapped_rule)));
                }

                let at = now();
                transaction
                    .execute(
                        "INSERT INTO entitlements
                             (user_id, spaceport_app, role, mapped_rule, granted_at)
                         VALUES (?1, ?2, ?3, NULL, ?4)",
                        rusqlite::params![
                            user.id.as_str(),
                            entitlement.app.as_str(),
                            entitlement.role.as_str(),
                            at
                        ],
                    )
                    .context("granting an entitlement")?;

                record_in(
                    &transaction,
                    &at,
                    "entitlement.granted",
                    Some(&user.id),
                    OPERATOR_ORIGIN,
                    Some(&format!(
                        "role `{}` at app `{}`",
                        entitlement.role, entitlement.app
                    )),
                )?;

                transaction
                    .commit()
                    .context("committing an entitlement's grant")?;

                Ok(Some(Granted::Fresh(user)))
            })
            .await
            .map_err(EntitlementError::Failed)?;

        let granted = found.ok_or_else(|| EntitlementError::UnknownUser(unknown(user)))?;
        if let Granted::Fresh(user) = &granted {
            info!(user = %user.id, entitlement = %said, "entitlement granted");
        }

        Ok(granted)
    }

    /// Revoke what `scope` matches of the user's entitlements — one role at an
    /// app, every role at an app, or (`None`) everything across apps.
    ///
    /// Manual rows go, each with its `entitlement.revoked` log entry in the
    /// same transaction; mapped rows are kept and named, for the reason
    /// [`Revoked::kept`] gives. A scope that matches only mapped rows is a
    /// refusal rather than a quiet no-op — the operator asked for something
    /// this command must not do, and the answer names the mapping that can.
    pub async fn revoke(
        &self,
        user: &UserRef,
        scope: Option<&RevokeScope>,
    ) -> Result<Revoked, EntitlementError> {
        let asked = user.clone();
        let scope = scope.cloned();

        let found = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to revoke entitlements")?;

                let Some(row) = find(&transaction, &asked)? else {
                    return Ok(None);
                };
                let user = record(row)?;

                let matched = matching(&transaction, &user.id, scope.as_ref())?;

                let mut removed = Vec::new();
                let mut kept = Vec::new();
                let at = now();
                for entitlement in matched {
                    let named = RoleAtApp {
                        role: entitlement.role,
                        app: entitlement.app,
                    };

                    if let Some(rule) = entitlement.mapped_rule {
                        kept.push((named, rule));
                        continue;
                    }

                    transaction
                        .execute(
                            "DELETE FROM entitlements
                             WHERE user_id = ?1 AND spaceport_app = ?2 AND role = ?3",
                            rusqlite::params![
                                user.id.as_str(),
                                named.app.as_str(),
                                named.role.as_str()
                            ],
                        )
                        .context("revoking an entitlement")?;
                    record_in(
                        &transaction,
                        &at,
                        "entitlement.revoked",
                        Some(&user.id),
                        OPERATOR_ORIGIN,
                        Some(&format!("role `{}` at app `{}`", named.role, named.app)),
                    )?;
                    removed.push(named);
                }

                transaction
                    .commit()
                    .context("committing an entitlement's revoke")?;

                Ok(Some(Revoked {
                    user,
                    removed,
                    kept,
                }))
            })
            .await
            .map_err(EntitlementError::Failed)?;

        let revoked: Revoked = found.ok_or_else(|| EntitlementError::UnknownUser(unknown(user)))?;

        // The empty outcomes, told apart: nothing matched at all is a mistyped
        // scope, while mapped-only is a real refusal that must not read as
        // success — nothing was revoked.
        if revoked.removed.is_empty() {
            if revoked.kept.is_empty() {
                return Err(EntitlementError::Nothing(anyhow!(
                    "`{}` has no such entitlement — `spaceport auth audit {}` says what they hold",
                    revoked.user.slug,
                    revoked.user.slug,
                )));
            }

            let held = revoked
                .kept
                .iter()
                .map(|(entitlement, rule)| format!("`{entitlement}` (rule `{rule}`)"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(EntitlementError::Mapped(anyhow!(
                "nothing was revoked: {held} came from SSO mappings, and a mapped entitlement \
                 outlives a manual revoke — the next IdP login would put it back. Dropping the \
                 mapping rule is what removes it",
            )));
        }

        for entitlement in &revoked.removed {
            info!(user = %revoked.user.id, %entitlement, "entitlement revoked");
        }

        Ok(revoked)
    }

    /// Everything the user `user` names is entitled to, beside their record,
    /// read in one transaction so the two halves are about the same moment.
    ///
    /// Rows are ordered by app then role, which is the order an audit reads
    /// them in; a row this build cannot parse is skipped with a warning rather
    /// than costing the audit, exactly as a broken user row costs a listing.
    pub async fn audit(
        &self,
        user: &UserRef,
    ) -> Result<(UserRecord, Vec<EntitlementRecord>), EntitlementError> {
        let asked = user.clone();

        let found = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to audit a user")?;

                let Some(row) = find(&transaction, &asked)? else {
                    return Ok(None);
                };
                let user = record(row)?;
                let entitlements = matching(&transaction, &user.id, None)?;

                Ok(Some((user, entitlements)))
            })
            .await
            .map_err(EntitlementError::Failed)?;

        found.ok_or_else(|| EntitlementError::UnknownUser(unknown(user)))
    }
}

/// The user's entitlements that `scope` speaks about, oldest table order —
/// app, then role — inside the caller's transaction.
///
/// Rows whose app or role no longer parse are skipped with a warning: they
/// were written by something other than this build, and one of them must not
/// cost an operator the rest of the answer.
fn matching(
    transaction: &Transaction<'_>,
    user: &UserId,
    scope: Option<&RevokeScope>,
) -> Result<Vec<EntitlementRecord>> {
    let (query, params) = match scope {
        None => (
            "SELECT spaceport_app, role, mapped_rule, granted_at FROM entitlements
             WHERE user_id = ?1 ORDER BY spaceport_app, role",
            vec![user.to_string()],
        ),
        Some(RevokeScope::App(app)) => (
            "SELECT spaceport_app, role, mapped_rule, granted_at FROM entitlements
             WHERE user_id = ?1 AND spaceport_app = ?2 ORDER BY spaceport_app, role",
            vec![user.to_string(), app.to_string()],
        ),
        Some(RevokeScope::One(entitlement)) => (
            "SELECT spaceport_app, role, mapped_rule, granted_at FROM entitlements
             WHERE user_id = ?1 AND spaceport_app = ?2 AND role = ?3
             ORDER BY spaceport_app, role",
            vec![
                user.to_string(),
                entitlement.app.to_string(),
                entitlement.role.to_string(),
            ],
        ),
    };

    let mut statement = transaction
        .prepare(query)
        .context("preparing the entitlement query")?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .context("reading the entitlements")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the entitlements")?;

    Ok(rows
        .into_iter()
        .filter_map(|(app, role, mapped_rule, granted_at)| {
            let parsed = app
                .parse::<AppId>()
                .map_err(|error| anyhow!("{error:#}"))
                .and_then(|app| Ok((app, role.parse::<Role>()?)));
            match parsed {
                Ok((app, role)) => Some(EntitlementRecord {
                    app,
                    role,
                    mapped_rule,
                    granted_at,
                }),
                Err(error) => {
                    tracing::warn!(%error, "skipping a stored entitlement this build cannot read");
                    None
                }
            }
        })
        .collect())
}

/// Delete every entitlement of `user`, inside the caller's transaction.
///
/// This is the drop cascade, and — like the log's [`record_in`] — it only
/// exists as a function over a transaction: a user the pool has forgotten but
/// the entitlements table still empowers is exactly the record nobody can
/// trust, so the two deletes commit together or not at all. Called from
/// [`crate::auth::UserRepository::drop_user`] and deliberately *not* from
/// suspend: the spec keeps a suspended user's entitlements so that resume
/// restores access.
pub(super) fn remove_all_in(transaction: &Transaction<'_>, user: &UserId) -> Result<()> {
    transaction
        .execute(
            "DELETE FROM entitlements WHERE user_id = ?1",
            rusqlite::params![user.as_str()],
        )
        .context("removing a dropped user's entitlements")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthLogRepository, UserRepository, UserSlug};

    fn repositories() -> (UserRepository, EntitlementRepository, AuthLogRepository) {
        let db = Db::in_memory().unwrap();

        (
            UserRepository::new(db.clone()),
            EntitlementRepository::new(db.clone()),
            AuthLogRepository::new(db),
        )
    }

    fn slug(slug: &str) -> UserSlug {
        slug.parse().unwrap()
    }

    fn by_slug(name: &str) -> UserRef {
        UserRef::Slug(slug(name))
    }

    fn entitlement(s: &str) -> RoleAtApp {
        s.parse().unwrap()
    }

    /// Plant a row as an IdP login will one day: tagged with the rule that
    /// produced it. Nothing in this milestone can write one, and that is the
    /// point — the refusal branch has to work before its writer exists.
    async fn plant_mapped(
        entitlements: &EntitlementRepository,
        user: &UserId,
        granted: &str,
        rule: &str,
    ) {
        let user = user.to_string();
        let granted = entitlement(granted);
        let rule = rule.to_owned();
        entitlements
            .db
            .call(move |connection| {
                connection
                    .execute(
                        "INSERT INTO entitlements
                             (user_id, spaceport_app, role, mapped_rule, granted_at)
                         VALUES (?1, ?2, ?3, ?4, '2026-01-01T00:00:00Z')",
                        rusqlite::params![user, granted.app.as_str(), granted.role.as_str(), rule],
                    )
                    .context("planting a mapped entitlement")?;

                Ok(())
            })
            .await
            .unwrap();
    }

    /// The spec's spelling, parsed both ways round: an `@` splits a role from
    /// an app, and each half is held to its own alphabet.
    #[test]
    fn parses_the_role_at_app_spelling() {
        let parsed = entitlement("reader@blog");
        assert_eq!(parsed.role.as_str(), "reader");
        assert_eq!(parsed.app.as_str(), "blog");
        assert_eq!(parsed.to_string(), "reader@blog");

        for broken in ["reader", "@blog", "reader@", "Reader@blog", "reader@Blog"] {
            assert!(broken.parse::<RoleAtApp>().is_err(), "accepted `{broken}`");
        }
    }

    /// `[<role>@]<app-id>`: with an `@` it is one entitlement, without it is
    /// every role at the app.
    #[test]
    fn a_revoke_scope_is_an_entitlement_or_an_app() {
        assert!(matches!(
            "reader@blog".parse::<RevokeScope>(),
            Ok(RevokeScope::One(_))
        ));
        assert!(matches!(
            "blog".parse::<RevokeScope>(),
            Ok(RevokeScope::App(_))
        ));
        assert!("Not An App".parse::<RevokeScope>().is_err());
    }

    #[tokio::test]
    async fn grants_and_audits_an_entitlement() {
        let (users, entitlements, _) = repositories();
        let alice = users.create(&slug("alice"), None).await.unwrap();

        let granted = entitlements
            .grant(&by_slug("alice"), &entitlement("reader@blog"))
            .await
            .unwrap();
        assert!(matches!(granted, Granted::Fresh(user) if user.id == alice.id));

        let (user, held) = entitlements.audit(&by_slug("alice")).await.unwrap();
        assert_eq!(user.id, alice.id);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].role.as_str(), "reader");
        assert_eq!(held[0].app.as_str(), "blog");
        assert_eq!(held[0].mapped_rule, None);
        assert!(held[0].granted_at.ends_with('Z'), "{}", held[0].granted_at);
    }

    /// The idempotence the primary key buys: the second grant is a success
    /// that changed nothing — one row, one log entry.
    #[tokio::test]
    async fn granting_twice_is_idempotent_and_logged_once() {
        let (users, entitlements, log) = repositories();
        users.create(&slug("alice"), None).await.unwrap();

        entitlements
            .grant(&by_slug("alice"), &entitlement("reader@blog"))
            .await
            .unwrap();
        let again = entitlements
            .grant(&by_slug("alice"), &entitlement("reader@blog"))
            .await
            .unwrap();

        assert!(matches!(again, Granted::Already(_, None)));
        let (_, held) = entitlements.audit(&by_slug("alice")).await.unwrap();
        assert_eq!(held.len(), 1);
        let entries = log.entries(None).await.unwrap();
        let kinds: Vec<&str> = entries.iter().map(|entry| entry.kind.as_str()).collect();
        assert_eq!(kinds, ["user.created", "entitlement.granted"]);
    }

    /// Granting what a mapping already granted names the rule, so the operator
    /// learns their manual grant is not what holds the door open.
    #[tokio::test]
    async fn granting_over_a_mapped_row_says_where_it_came_from() {
        let (users, entitlements, _) = repositories();
        let alice = users.create(&slug("alice"), None).await.unwrap();
        plant_mapped(&entitlements, &alice.id, "reader@blog", "rule-7").await;

        let again = entitlements
            .grant(&by_slug("alice"), &entitlement("reader@blog"))
            .await
            .unwrap();

        assert!(matches!(again, Granted::Already(_, Some(rule)) if rule == "rule-7"));
    }

    #[tokio::test]
    async fn revokes_one_role_and_leaves_the_rest() {
        let (users, entitlements, log) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        for granted in ["reader@blog", "writer@blog", "reader@wiki"] {
            entitlements
                .grant(&by_slug("alice"), &entitlement(granted))
                .await
                .unwrap();
        }

        let revoked = entitlements
            .revoke(
                &by_slug("alice"),
                Some(&RevokeScope::One(entitlement("reader@blog"))),
            )
            .await
            .unwrap();

        assert_eq!(revoked.removed, [entitlement("reader@blog")]);
        assert!(revoked.kept.is_empty());
        let (_, held) = entitlements.audit(&by_slug("alice")).await.unwrap();
        assert_eq!(held.len(), 2);
        assert!(
            log.entries(None)
                .await
                .unwrap()
                .iter()
                .any(|entry| entry.kind == "entitlement.revoked"
                    && entry.detail.as_deref() == Some("role `reader` at app `blog`")),
        );
    }

    /// `revoke <user> <app-id>`: every role at that app goes, and only there.
    #[tokio::test]
    async fn revokes_a_whole_app_at_once() {
        let (users, entitlements, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        for granted in ["reader@blog", "writer@blog", "reader@wiki"] {
            entitlements
                .grant(&by_slug("alice"), &entitlement(granted))
                .await
                .unwrap();
        }

        let revoked = entitlements
            .revoke(
                &by_slug("alice"),
                Some(&RevokeScope::App("blog".parse().unwrap())),
            )
            .await
            .unwrap();

        assert_eq!(revoked.removed.len(), 2);
        let (_, held) = entitlements.audit(&by_slug("alice")).await.unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].app.as_str(), "wiki");
    }

    /// `revoke <user> --all` is the whole slate, across apps.
    #[tokio::test]
    async fn revokes_everything_with_no_scope() {
        let (users, entitlements, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        for granted in ["reader@blog", "reader@wiki"] {
            entitlements
                .grant(&by_slug("alice"), &entitlement(granted))
                .await
                .unwrap();
        }

        let revoked = entitlements.revoke(&by_slug("alice"), None).await.unwrap();

        assert_eq!(revoked.removed.len(), 2);
        assert!(
            entitlements
                .audit(&by_slug("alice"))
                .await
                .unwrap()
                .1
                .is_empty()
        );
    }

    /// The refusal this milestone builds ahead of its trigger: a mapped
    /// entitlement is not the operator's to revoke, and the answer names the
    /// rule that is.
    #[tokio::test]
    async fn refuses_to_revoke_a_mapped_entitlement() {
        let (users, entitlements, _) = repositories();
        let alice = users.create(&slug("alice"), None).await.unwrap();
        plant_mapped(&entitlements, &alice.id, "reader@blog", "rule-7").await;

        let error = entitlements
            .revoke(
                &by_slug("alice"),
                Some(&RevokeScope::One(entitlement("reader@blog"))),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, EntitlementError::Mapped(_)), "{error}");
        assert!(error.to_string().contains("rule-7"), "{error}");
        // And the row is still there.
        assert_eq!(
            entitlements.audit(&by_slug("alice")).await.unwrap().1.len(),
            1
        );
    }

    /// A sweep past mapped rows takes the manual ones and names what it left,
    /// rather than failing over rows it was never allowed to touch.
    #[tokio::test]
    async fn a_broad_revoke_keeps_mapped_rows_and_says_so() {
        let (users, entitlements, _) = repositories();
        let alice = users.create(&slug("alice"), None).await.unwrap();
        entitlements
            .grant(&by_slug("alice"), &entitlement("writer@blog"))
            .await
            .unwrap();
        plant_mapped(&entitlements, &alice.id, "reader@blog", "rule-7").await;

        let revoked = entitlements
            .revoke(
                &by_slug("alice"),
                Some(&RevokeScope::App("blog".parse().unwrap())),
            )
            .await
            .unwrap();

        assert_eq!(revoked.removed, [entitlement("writer@blog")]);
        assert_eq!(
            revoked.kept,
            [(entitlement("reader@blog"), "rule-7".to_owned())]
        );
    }

    #[tokio::test]
    async fn a_revoke_that_matches_nothing_says_so() {
        let (users, entitlements, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();

        let error = entitlements
            .revoke(
                &by_slug("alice"),
                Some(&RevokeScope::One(entitlement("reader@blog"))),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, EntitlementError::Nothing(_)), "{error}");
    }

    #[tokio::test]
    async fn a_command_aimed_at_nobody_says_so() {
        let (_, entitlements, _) = repositories();

        for result in [
            entitlements
                .grant(&by_slug("ghost"), &entitlement("reader@blog"))
                .await
                .map(|_| ()),
            entitlements
                .revoke(&by_slug("ghost"), None)
                .await
                .map(|_| ()),
            entitlements.audit(&by_slug("ghost")).await.map(|_| ()),
        ] {
            let error = result.unwrap_err();
            assert!(matches!(error, EntitlementError::UnknownUser(_)), "{error}");
        }
    }

    /// The spec's drop cascade, seen from this table: the user goes, and their
    /// entitlements go in the same commit.
    #[tokio::test]
    async fn dropping_a_user_takes_their_entitlements_with_them() {
        let (users, entitlements, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        users.create(&slug("bob"), None).await.unwrap();
        entitlements
            .grant(&by_slug("alice"), &entitlement("reader@blog"))
            .await
            .unwrap();
        entitlements
            .grant(&by_slug("bob"), &entitlement("reader@blog"))
            .await
            .unwrap();

        users.drop_user(&by_slug("alice")).await.unwrap();

        // Alice's slate went with her; a recreated `alice` is a different user
        // and starts with nothing.
        users.create(&slug("alice"), None).await.unwrap();
        assert!(
            entitlements
                .audit(&by_slug("alice"))
                .await
                .unwrap()
                .1
                .is_empty()
        );
        // And the cascade was hers alone.
        assert_eq!(
            entitlements.audit(&by_slug("bob")).await.unwrap().1.len(),
            1
        );
    }

    /// Suspension is the offboarding lever that keeps the slate: resume must
    /// restore exactly the access that was there.
    #[tokio::test]
    async fn suspending_a_user_leaves_their_entitlements_alone() {
        let (users, entitlements, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        entitlements
            .grant(&by_slug("alice"), &entitlement("reader@blog"))
            .await
            .unwrap();

        users.suspend(&by_slug("alice")).await.unwrap();

        assert_eq!(
            entitlements.audit(&by_slug("alice")).await.unwrap().1.len(),
            1
        );
    }
}

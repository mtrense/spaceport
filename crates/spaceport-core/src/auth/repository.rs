//! The `users` table, in the vocabulary of managing the pool.
//!
//! Every mutation here does two writes in one transaction: the row it is
//! about, and the [`crate::auth::log`] entry that records it. That coupling is
//! the module's one invariant — a user the pool holds and the log denies, or
//! the other way round, is a record nobody can trust — and it is why the log's
//! writer only exists as a function over the caller's transaction.
//!
//! Suspend and drop are also where offboarding will grow teeth. The spec has
//! both of them invalidating sessions, API keys and cached JWTs the moment
//! they run; none of those exist yet, and the `offboard` function at the
//! bottom of this file is the single place the cascade goes when they do.

use anyhow::{Context, Result, anyhow};
use rusqlite::{OptionalExtension, Transaction};
use tracing::info;

use super::log::{OPERATOR_ORIGIN, record_in};
use super::{UserError, UserId, UserRecord, UserRef, UserSlug};
use crate::app::Pattern;
use crate::state::{Db, now};

/// The row as SQL hands it over, before the typed fields are parsed out.
pub(super) type Row = (String, String, Option<String>, bool, String);

/// Read a stored row back into a record.
///
/// A row whose id or slug no longer parses was written by something other
/// than this build, and the caller decides what that costs: a listing skips
/// it, a lookup fails loudly — one bad row must not cost an operator the
/// listing of everyone else, but a command aimed at exactly that row has
/// nothing useful to do instead.
pub(super) fn record(row: Row) -> Result<UserRecord> {
    let (id, slug, email, suspended, created_at) = row;

    Ok(UserRecord {
        id: id
            .parse()
            .map_err(|error| anyhow!("{error:#}"))
            .context("reading a stored user id")?,
        slug: slug
            .parse()
            .map_err(|error| anyhow!("{error:#}"))
            .context("reading a stored user slug")?,
        email,
        suspended,
        created_at,
    })
}

/// One user's row, inside the caller's transaction, by whichever name the
/// operator used.
///
/// `pub(super)` because [`crate::auth::entitlement`] resolves the same
/// `<slug|user-id>` inside its own transactions, and two resolvers would be
/// two answers about which user a command meant.
pub(super) fn find(transaction: &Transaction<'_>, user: &UserRef) -> Result<Option<Row>> {
    let (query, key) = match user {
        UserRef::Id(id) => (
            "SELECT user_id, user_slug, email, suspended, created_at
             FROM users WHERE user_id = ?1",
            id.to_string(),
        ),
        UserRef::Slug(slug) => (
            "SELECT user_id, user_slug, email, suspended, created_at
             FROM users WHERE user_slug = ?1",
            slug.to_string(),
        ),
    };

    transaction
        .query_row(query, rusqlite::params![key], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .optional()
        .context("looking a user up")
}

/// The refusal every command aimed at a user that is not there gets, worded
/// once for every module that can meet one.
pub(super) fn unknown(user: &UserRef) -> anyhow::Error {
    anyhow!("no user answers to `{user}` — `spaceport auth user list` says who exists")
}

/// The global user pool, over the state database.
#[derive(Debug, Clone)]
pub struct UserRepository {
    db: Db,
}

impl UserRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Every live user, in slug order, optionally only those whose slug
    /// matches `pattern`.
    ///
    /// Filtered here rather than in SQL, for [`crate::app::SecretRepository`]'s
    /// reason: the glob is spaceport's own, and `LIKE` would be a second
    /// implementation of it that could disagree with the first. A row that no
    /// longer parses is skipped with a warning rather than failing the read —
    /// one bad row must not cost the listing of everyone else.
    pub async fn list(&self, pattern: Option<&Pattern>) -> Result<Vec<UserRecord>> {
        let rows: Vec<Row> = self
            .db
            .call(|connection| {
                let mut statement = connection
                    .prepare(
                        "SELECT user_id, user_slug, email, suspended, created_at
                         FROM users ORDER BY user_slug",
                    )
                    .context("preparing the user listing query")?;

                let rows = statement
                    .query_map([], |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    })
                    .context("listing the users")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("listing the users")?;

                Ok(rows)
            })
            .await?;

        Ok(rows
            .into_iter()
            .filter_map(|row| match record(row) {
                Ok(record) => Some(record),
                Err(error) => {
                    tracing::warn!(%error, "skipping a stored user this build cannot read");
                    None
                }
            })
            .filter(|record| pattern.is_none_or(|pattern| pattern.matches_slug(&record.slug)))
            .collect())
    }

    /// Create a user under `slug`, minting the id it keeps for life.
    ///
    /// The id is minted out here and the uniqueness check happens in the
    /// transaction: randomness has no business inside a database lock, and the
    /// slug being free is about the table as it is at the moment of writing.
    pub async fn create(
        &self,
        slug: &UserSlug,
        email: Option<&str>,
    ) -> Result<UserRecord, UserError> {
        let id = UserId::generate().map_err(UserError::Failed)?;
        let created = UserRecord {
            id,
            slug: slug.clone(),
            email: email.map(str::to_owned),
            suspended: false,
            created_at: now(),
        };
        let record = created.clone();

        self.db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to create a user")?;

                transaction
                    .execute(
                        "INSERT INTO users (user_id, user_slug, email, suspended, created_at)
                         VALUES (?1, ?2, ?3, 0, ?4)",
                        rusqlite::params![
                            record.id.as_str(),
                            record.slug.as_str(),
                            record.email,
                            record.created_at
                        ],
                    )
                    .context("creating a user")?;

                record_in(
                    &transaction,
                    &record.created_at,
                    "user.created",
                    Some(&record.id),
                    OPERATOR_ORIGIN,
                    Some(&match &record.email {
                        Some(email) => format!("slug `{}`, email `{email}`", record.slug),
                        None => format!("slug `{}`", record.slug),
                    }),
                )?;

                transaction.commit().context("committing a new user")
            })
            .await
            .map_err(|error| match slug_collision(&error) {
                true => UserError::SlugTaken(anyhow!(
                    "a user already answers to `{slug}` — drop it first, or pick another slug",
                    slug = created.slug
                )),
                false => UserError::Failed(error),
            })?;

        info!(user = %created.id, slug = %created.slug, "user created");

        Ok(created)
    }

    /// Mark a user suspended, keeping everything about them.
    ///
    /// Recorded and logged even when the user was already suspended: the log
    /// records the commands that were given, and a second suspend is a second
    /// command — collapsing it would have the log disagree with the operator's
    /// own history.
    pub async fn suspend(&self, user: &UserRef) -> Result<UserRecord, UserError> {
        let record = self.mark(user, true, "user.suspended").await?;
        info!(user = %record.id, slug = %record.slug, "user suspended");

        Ok(record)
    }

    /// Let a suspended user back in. Restores access and nothing else — the
    /// sessions and keys a suspend killed stay dead, per the spec.
    pub async fn resume(&self, user: &UserRef) -> Result<UserRecord, UserError> {
        let record = self.mark(user, false, "user.resumed").await?;
        info!(user = %record.id, slug = %record.slug, "user resumed");

        Ok(record)
    }

    /// Flip the suspension flag and log that it was flipped, as one commit.
    async fn mark(
        &self,
        user: &UserRef,
        suspended: bool,
        kind: &'static str,
    ) -> Result<UserRecord, UserError> {
        let asked = user.clone();

        let found = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to mark a user")?;

                let Some(row) = find(&transaction, &asked)? else {
                    return Ok(None);
                };
                let mut record = record(row)?;

                transaction
                    .execute(
                        "UPDATE users SET suspended = ?2 WHERE user_id = ?1",
                        rusqlite::params![record.id.as_str(), suspended],
                    )
                    .context("marking a user")?;
                record.suspended = suspended;

                let at = now();
                record_in(
                    &transaction,
                    &at,
                    kind,
                    Some(&record.id),
                    OPERATOR_ORIGIN,
                    Some(&format!("slug `{}`", record.slug)),
                )?;

                if suspended {
                    offboard(&transaction, &record.id)?;
                }

                transaction
                    .commit()
                    .context("committing a user's marking")?;

                Ok(Some(record))
            })
            .await
            .map_err(UserError::Failed)?;

        found.ok_or_else(|| UserError::Unknown(unknown(user)))
    }

    /// Delete a user, keeping only the log's memory of them.
    ///
    /// `drop_user` and not `drop`, though the command is `spaceport auth user
    /// drop`: a method called `drop` on anything held in an `Arc` resolves to
    /// the destructor at the call site, and the compiler refuses it.
    ///
    /// The row goes rather than being flagged, and that is the contract: the
    /// slug is free again the moment this commits, and creating it again mints
    /// a fresh id. The detail names the slug because the `users` row is the
    /// only other place that pairing existed — after this, the log is it.
    pub async fn drop_user(&self, user: &UserRef) -> Result<UserRecord, UserError> {
        let asked = user.clone();

        let found = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to drop a user")?;

                let Some(row) = find(&transaction, &asked)? else {
                    return Ok(None);
                };
                let record = record(row)?;

                transaction
                    .execute(
                        "DELETE FROM users WHERE user_id = ?1",
                        rusqlite::params![record.id.as_str()],
                    )
                    .context("dropping a user")?;

                let at = now();
                record_in(
                    &transaction,
                    &at,
                    "user.dropped",
                    Some(&record.id),
                    OPERATOR_ORIGIN,
                    Some(&format!("slug `{}`", record.slug)),
                )?;

                // The drop-only half of the cascade, beside `offboard` rather
                // than inside it: suspend runs `offboard` too, and the spec
                // keeps a suspended user's entitlements so resume restores
                // exactly the access that was there. Deleted, not logged row
                // by row — the `user.dropped` entry above is the record, and a
                // dozen `entitlement.revoked` lines nobody typed would read as
                // commands that were never given.
                super::entitlement::remove_all_in(&transaction, &record.id)?;

                offboard(&transaction, &record.id)?;

                transaction.commit().context("committing a user's drop")?;

                Ok(Some(record))
            })
            .await
            .map_err(UserError::Failed)?;

        found.ok_or_else(|| UserError::Unknown(unknown(user)))
    }
}

/// Whether an insert died on the table's unique constraints.
///
/// The uniqueness the table declares is the primary key — an id minted from
/// sixteen random bytes moments ago — and the slug, so a constraint violation
/// here *is* the slug being taken: letting the database say so is one check
/// where a SELECT-then-INSERT would be two answers about two moments. The
/// error is fished back out of the context chain because `Db::call` speaks
/// `anyhow`, and a typed error channel through it would exist for this one
/// case.
fn slug_collision(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<rusqlite::Error>(),
        Some(rusqlite::Error::SqliteFailure(cause, _))
            if cause.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

/// Where suspending or dropping a user grows its teeth.
///
/// HOOK POINT — first tenant in place. The spec has both verbs cascade the
/// same way: sessions (global and per-app, WebSocket connections included),
/// API keys and cached JWTs all die with the user, in this transaction, so
/// that a user the pool says is gone can never be one a session table still
/// lets in. Global sessions and their pending one-time codes now do; API
/// keys, derived app sessions and cached JWTs join here — and nowhere else —
/// as their milestones land. Entitlements deliberately do *not*: they cascade
/// on drop only — suspend keeps them so resume restores access — so their
/// delete lives at [`UserRepository::drop_user`]'s call site rather than in
/// this shared path.
fn offboard(transaction: &Transaction<'_>, user: &UserId) -> Result<()> {
    super::session::remove_all_in(transaction, user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthLogRepository;

    fn repositories() -> (UserRepository, AuthLogRepository) {
        let db = Db::in_memory().unwrap();

        (UserRepository::new(db.clone()), AuthLogRepository::new(db))
    }

    fn slug(slug: &str) -> UserSlug {
        slug.parse().unwrap()
    }

    fn by_slug(name: &str) -> UserRef {
        UserRef::Slug(slug(name))
    }

    fn pattern(pattern: &str) -> Pattern {
        pattern.parse().unwrap()
    }

    #[tokio::test]
    async fn knows_nobody_to_begin_with() {
        let (users, _) = repositories();

        assert!(users.list(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn creates_a_user_and_lists_them() {
        let (users, _) = repositories();

        let created = users
            .create(&slug("alice"), Some("alice@example.com"))
            .await
            .unwrap();

        let listed = users.list(None).await.unwrap();
        assert_eq!(listed, std::slice::from_ref(&created));
        assert_eq!(listed[0].email.as_deref(), Some("alice@example.com"));
        assert!(!listed[0].suspended);
    }

    #[tokio::test]
    async fn lists_only_the_slugs_a_pattern_asks_for() {
        let (users, _) = repositories();
        for name in ["alice", "bob", "ci-bot"] {
            users.create(&slug(name), None).await.unwrap();
        }

        let listed = users.list(Some(&pattern("ci-*"))).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].slug, slug("ci-bot"));
    }

    /// The slug's uniqueness is among *live* users, and this is the live half
    /// of it: while alice exists, there is exactly one alice.
    #[tokio::test]
    async fn refuses_a_slug_a_live_user_holds() {
        let (users, log) = repositories();
        users.create(&slug("alice"), None).await.unwrap();

        let error = users.create(&slug("alice"), None).await.unwrap_err();
        assert!(matches!(error, UserError::SlugTaken(_)), "{error}");
        // And the refusal changed nothing: one user, one creation logged.
        assert_eq!(users.list(None).await.unwrap().len(), 1);
        assert_eq!(log.entries(None).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn suspends_and_resumes_by_slug() {
        let (users, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();

        let suspended = users.suspend(&by_slug("alice")).await.unwrap();
        assert!(suspended.suspended);
        assert!(users.list(None).await.unwrap()[0].suspended);

        let resumed = users.resume(&by_slug("alice")).await.unwrap();
        assert!(!resumed.suspended);
        assert!(!users.list(None).await.unwrap()[0].suspended);
    }

    /// The other half of `<slug|user-id>`: the UUID names the same user the
    /// slug does, whichever way a command arrives.
    #[tokio::test]
    async fn resolves_a_user_by_id_too() {
        let (users, _) = repositories();
        let created = users.create(&slug("alice"), None).await.unwrap();

        let suspended = users
            .suspend(&UserRef::Id(created.id.clone()))
            .await
            .unwrap();
        assert_eq!(suspended.id, created.id);
        assert!(suspended.suspended);
    }

    #[tokio::test]
    async fn a_command_aimed_at_nobody_says_so() {
        let (users, _) = repositories();

        for result in [
            users.suspend(&by_slug("ghost")).await,
            users.resume(&by_slug("ghost")).await,
            users.drop_user(&by_slug("ghost")).await,
        ] {
            let error = result.unwrap_err();
            assert!(matches!(error, UserError::Unknown(_)), "{error}");
        }
    }

    /// The spec's one sentence about identity, as a test: a slug can come
    /// back, a user id cannot.
    #[tokio::test]
    async fn a_dropped_slug_recreated_yields_a_fresh_id() {
        let (users, _) = repositories();
        let first = users.create(&slug("alice"), None).await.unwrap();

        users.drop_user(&by_slug("alice")).await.unwrap();
        assert!(users.list(None).await.unwrap().is_empty());

        let second = users.create(&slug("alice"), None).await.unwrap();
        assert_ne!(second.id, first.id);
    }

    /// The log is the module's other half: every mutation appends exactly one
    /// entry, stamped with what happened and where the command came from.
    #[tokio::test]
    async fn every_mutation_is_recorded_in_the_log() {
        let (users, log) = repositories();
        let created = users.create(&slug("alice"), None).await.unwrap();
        users.suspend(&by_slug("alice")).await.unwrap();
        users.resume(&by_slug("alice")).await.unwrap();
        users.drop_user(&by_slug("alice")).await.unwrap();

        let entries = log.entries(None).await.unwrap();
        let kinds: Vec<&str> = entries.iter().map(|entry| entry.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "user.created",
                "user.suspended",
                "user.resumed",
                "user.dropped"
            ]
        );
        for entry in &entries {
            assert_eq!(entry.user.as_deref(), Some(created.id.as_str()));
            assert_eq!(entry.origin, OPERATOR_ORIGIN);
            assert!(entry.at.ends_with('Z'), "{}", entry.at);
        }
    }

    /// What the log is *for*: the only record of a user that no longer exists,
    /// and it names the slug because nothing else is left to.
    #[tokio::test]
    async fn the_log_outlives_the_user_it_is_about() {
        let (users, log) = repositories();
        let alice = users.create(&slug("alice"), None).await.unwrap();
        let bob = users.create(&slug("bob"), None).await.unwrap();
        users.drop_user(&by_slug("alice")).await.unwrap();

        let hers = log.entries(Some(&alice.id)).await.unwrap();
        assert_eq!(hers.len(), 2);
        assert_eq!(hers[1].kind, "user.dropped");
        assert_eq!(hers[1].detail.as_deref(), Some("slug `alice`"));

        // And the filter is a filter: bob's story is his own.
        let his = log.entries(Some(&bob.id)).await.unwrap();
        assert_eq!(his.len(), 1);
        assert_eq!(his[0].kind, "user.created");
    }
}

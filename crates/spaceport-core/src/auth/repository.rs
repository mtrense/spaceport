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
#[derive(Clone)]
pub struct UserRepository {
    db: Db,
    /// The JWT cache the edge mints into. Suspend and drop are two of the
    /// spec's purge levers, and the purge lives beside `offboard`'s call sites
    /// because that is the cascade's one home; it runs after the commit, since
    /// the cache is only ever a copy of what the tables allow and must never
    /// be emptier than them ahead of a rollback. Shared through
    /// [`UserRepository::with_jwt_cache`]; `new` makes a private one for the
    /// tests that never mint a JWT.
    jwt_cache: std::sync::Arc<super::jwt::JwtCache>,
}

impl UserRepository {
    pub fn new(db: Db) -> Self {
        Self::with_jwt_cache(db, std::sync::Arc::new(super::jwt::JwtCache::new()))
    }

    /// The constructor the daemon uses: the one process-wide cache, so a
    /// suspend or drop committed here empties exactly the entries the edge
    /// would serve next.
    pub fn with_jwt_cache(db: Db, jwt_cache: std::sync::Arc<super::jwt::JwtCache>) -> Self {
        Self { db, jwt_cache }
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

    /// Create a user under `slug`, minting the id it keeps for life, and — if
    /// `identity` is given — assert in the same breath who they are at a
    /// connection.
    ///
    /// The id is minted out here and the uniqueness check happens in the
    /// transaction: randomness has no business inside a database lock, and the
    /// slug being free is about the table as it is at the moment of writing.
    ///
    /// The binding shares this commit, and that is the whole reason it is a
    /// parameter rather than a second call the caller makes afterwards:
    /// `auth user create alice --connect spaceport-acme:octo-alice` either
    /// leaves alice bound or leaves nothing at all. A create that succeeded
    /// and a bind that then refused would leave an unbound alice behind whose
    /// slug the operator would have to drop before retyping the command they
    /// meant. Resolving the handle to an external id is the caller's job and
    /// happens before this — a network call has no business inside a database
    /// lock either.
    pub async fn create(
        &self,
        slug: &UserSlug,
        email: Option<&str>,
        identity: Option<&super::AssertedIdentity>,
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
        let identity = identity.cloned();

        let outcome = self
            .db
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

                if let Some(identity) = &identity
                    && let Err(refusal) = super::mapping::bind_in(
                        &transaction,
                        &record.created_at,
                        &record.id,
                        identity,
                    )
                {
                    // Dropped unfinished, so the user row above goes with it:
                    // the atomicity this parameter exists for.
                    return Ok(Err(refusal));
                }

                transaction.commit().context("committing a new user")?;

                Ok(Ok(()))
            })
            .await
            .map_err(|error| match slug_collision(&error) {
                true => UserError::SlugTaken(anyhow!(
                    "a user already answers to `{slug}` — drop it first, or pick another slug",
                    slug = created.slug
                )),
                false => UserError::Failed(error),
            })?;
        outcome.map_err(UserError::Binding)?;

        info!(user = %created.id, slug = %created.slug, "user created");

        Ok(created)
    }

    /// Change the name a user answers to, keeping the id they keep for life.
    ///
    /// One column moves and nothing follows it: entitlements, sessions, API
    /// keys, identity bindings and every JWT already minted all key on the id,
    /// so a rename costs the user nothing — they stay signed in, and an app
    /// that stored their `sub` never notices. That is the whole difference
    /// between this and dropping a user to create them again under the new
    /// name, which mints a fresh id and is a different person to everything
    /// downstream.
    ///
    /// The new slug being free is the same check a create makes, and it is
    /// made the same way — by letting the table's constraint answer, so that
    /// one question is asked about one moment. Renaming a user to the slug
    /// they already hold is allowed and logged, for `suspend`'s reason: the
    /// log records the commands that were given.
    pub async fn rename(&self, user: &UserRef, slug: &UserSlug) -> Result<UserRecord, UserError> {
        let asked = user.clone();
        let wanted = slug.clone();

        let found = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to rename a user")?;

                let Some(row) = find(&transaction, &asked)? else {
                    return Ok(None);
                };
                let mut record = record(row)?;
                let was = record.slug.clone();

                transaction
                    .execute(
                        "UPDATE users SET user_slug = ?2 WHERE user_id = ?1",
                        rusqlite::params![record.id.as_str(), wanted.as_str()],
                    )
                    .context("renaming a user")?;
                record.slug = wanted;

                let at = now();
                record_in(
                    &transaction,
                    &at,
                    "user.renamed",
                    Some(&record.id),
                    OPERATOR_ORIGIN,
                    Some(&format!("slug `{was}` is now `{}`", record.slug)),
                )?;

                transaction.commit().context("committing a user's rename")?;

                Ok(Some((was, record)))
            })
            .await
            .map_err(|error| match slug_collision(&error) {
                true => UserError::SlugTaken(anyhow!(
                    "a user already answers to `{slug}` — drop it first, or pick another slug"
                )),
                false => UserError::Failed(error),
            })?;

        let (was, record) = found.ok_or_else(|| UserError::Unknown(unknown(user)))?;
        info!(user = %record.id, was = %was, slug = %record.slug, "user renamed");

        Ok(record)
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

        let record = found.ok_or_else(|| UserError::Unknown(unknown(user)))?;
        // The cached-JWT half of the offboarding cascade, only when the door
        // actually closed: a resume purges nothing, because nothing about a
        // resumed user's access got narrower.
        if suspended {
            self.jwt_cache.purge_user(&record.id);
        }

        Ok(record)
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

                // The identity link is drop-only too, and for the same shape
                // of reason: suspend keeps it so the resumed user's next login
                // updates the link they had, while a drop must free the
                // external account to vouch for whoever holds the slug next.
                super::mapping::remove_users_in(&transaction, &record.id)?;

                offboard(&transaction, &record.id)?;

                transaction.commit().context("committing a user's drop")?;

                Ok(Some(record))
            })
            .await
            .map_err(UserError::Failed)?;

        let record = found.ok_or_else(|| UserError::Unknown(unknown(user)))?;
        // The dropped user's cached JWTs die with everything else of theirs —
        // after the commit, for `mark`'s reason.
        self.jwt_cache.purge_user(&record.id);

        Ok(record)
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
/// HOOK POINT — the database tenants live here. The spec has both verbs
/// cascade the same way: sessions (global and per-app, WebSocket connections
/// included), API keys and cached JWTs all die with the user, so that a user
/// the pool says is gone can never be one a session table still lets in.
/// Global sessions, pending one-time codes, app sessions, exchange nonces and
/// API keys all do, in this transaction.
/// Cached JWTs are the one tenant that cannot: the cache is in-memory, not a
/// table, so its purge sits at this function's call sites, after the commit —
/// a purge inside a transaction that then rolled back would leave the cache
/// emptier than the rows, which is harmless, but the discipline of "commit,
/// then purge" keeps the cache a strict copy. Entitlements deliberately do
/// *not* cascade here: they cascade
/// on drop only — suspend keeps them so resume restores access — so their
/// delete lives at [`UserRepository::drop_user`]'s call site rather than in
/// this shared path.
fn offboard(transaction: &Transaction<'_>, user: &UserId) -> Result<()> {
    super::session::remove_all_in(transaction, user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AssertedIdentity, AuthLogRepository, IdentityError, IdentityRepository};

    fn repositories() -> (UserRepository, AuthLogRepository) {
        let db = Db::in_memory().unwrap();

        (UserRepository::new(db.clone()), AuthLogRepository::new(db))
    }

    fn slug(slug: &str) -> UserSlug {
        slug.parse().unwrap()
    }

    /// What `--connect <connection>:<login>` becomes once the handle has been
    /// resolved to the id the binding is keyed by.
    fn asserted(external_id: &str) -> AssertedIdentity {
        AssertedIdentity {
            connection: "spaceport-acme".to_owned(),
            external_id: external_id.to_owned(),
            external_login: "octo-alice".to_owned(),
        }
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
            .create(&slug("alice"), Some("alice@example.com"), None)
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
            users.create(&slug(name), None, None).await.unwrap();
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
        users.create(&slug("alice"), None, None).await.unwrap();

        let error = users.create(&slug("alice"), None, None).await.unwrap_err();
        assert!(matches!(error, UserError::SlugTaken(_)), "{error}");
        // And the refusal changed nothing: one user, one creation logged.
        assert_eq!(users.list(None).await.unwrap().len(), 1);
        assert_eq!(log.entries(None).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn suspends_and_resumes_by_slug() {
        let (users, _) = repositories();
        users.create(&slug("alice"), None, None).await.unwrap();

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
        let created = users.create(&slug("alice"), None, None).await.unwrap();

        let suspended = users
            .suspend(&UserRef::Id(created.id.clone()))
            .await
            .unwrap();
        assert_eq!(suspended.id, created.id);
        assert!(suspended.suspended);
    }

    /// What a rename is *for*: the name moves, the identity does not — so
    /// everything keyed on the id keeps pointing at the same person.
    #[tokio::test]
    async fn renames_a_user_without_touching_their_id() {
        let (users, _) = repositories();
        let created = users.create(&slug("alice"), None, None).await.unwrap();

        let renamed = users
            .rename(&by_slug("alice"), &slug("alice-smith"))
            .await
            .unwrap();

        assert_eq!(renamed.id, created.id);
        assert_eq!(renamed.slug, slug("alice-smith"));
        let listed = users.list(None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].slug, slug("alice-smith"));
        // And the old name answers to nobody, so it is free to create again.
        assert!(
            matches!(
                users.rename(&by_slug("alice"), &slug("bob")).await,
                Err(UserError::Unknown(_))
            ),
            "the old slug still resolves"
        );
    }

    /// The slug's uniqueness holds against a rename too, and a refused rename
    /// leaves both users exactly as they were.
    #[tokio::test]
    async fn refuses_renaming_onto_a_slug_a_live_user_holds() {
        let (users, _) = repositories();
        let alice = users.create(&slug("alice"), None, None).await.unwrap();
        users.create(&slug("bob"), None, None).await.unwrap();

        let error = users
            .rename(&by_slug("alice"), &slug("bob"))
            .await
            .unwrap_err();

        assert!(matches!(error, UserError::SlugTaken(_)), "{error}");
        let listed = users.list(None).await.unwrap();
        assert_eq!(listed[0].id, alice.id);
        assert_eq!(listed[0].slug, slug("alice"));
    }

    /// The rename is logged under the id it happened to, naming both halves —
    /// which is what lets somebody reading the log follow one user through
    /// every name they have answered to.
    #[tokio::test]
    async fn a_rename_is_recorded_with_both_names() {
        let (users, log) = repositories();
        let created = users.create(&slug("alice"), None, None).await.unwrap();

        users
            .rename(&UserRef::Id(created.id.clone()), &slug("alice-smith"))
            .await
            .unwrap();

        let entries = log.entries(Some(&created.id)).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].kind, "user.renamed");
        assert_eq!(
            entries[1].detail.as_deref(),
            Some("slug `alice` is now `alice-smith`")
        );
        assert_eq!(entries[1].origin, OPERATOR_ORIGIN);
    }

    #[tokio::test]
    async fn a_command_aimed_at_nobody_says_so() {
        let (users, _) = repositories();

        for result in [
            users.suspend(&by_slug("ghost")).await,
            users.resume(&by_slug("ghost")).await,
            users.rename(&by_slug("ghost"), &slug("phantom")).await,
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
        let first = users.create(&slug("alice"), None, None).await.unwrap();

        users.drop_user(&by_slug("alice")).await.unwrap();
        assert!(users.list(None).await.unwrap().is_empty());

        let second = users.create(&slug("alice"), None, None).await.unwrap();
        assert_ne!(second.id, first.id);
    }

    /// The log is the module's other half: every mutation appends exactly one
    /// entry, stamped with what happened and where the command came from.
    #[tokio::test]
    async fn every_mutation_is_recorded_in_the_log() {
        let (users, log) = repositories();
        let created = users.create(&slug("alice"), None, None).await.unwrap();
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
        let alice = users.create(&slug("alice"), None, None).await.unwrap();
        let bob = users.create(&slug("bob"), None, None).await.unwrap();
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

    /// `auth user create --connect` in one commit: the user, the identity and
    /// both log entries land together, so the operator never has to type the
    /// second half of a command they already gave.
    #[tokio::test]
    async fn creates_a_user_with_the_identity_they_were_asserted_to_hold() {
        let (users, log) = repositories();
        let identities = IdentityRepository::new(users.db.clone());

        let alice = users
            .create(&slug("alice"), None, Some(&asserted("583231")))
            .await
            .unwrap();

        let held = identities.for_user(&alice.id).await.unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].connection, "spaceport-acme");
        assert_eq!(held[0].external_id, "583231");
        assert_eq!(held[0].last_login_at, None);
        let kinds: Vec<String> = log
            .entries(None)
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.kind)
            .collect();
        assert_eq!(kinds, ["user.created", "identity.bound"]);
    }

    /// The whole reason the binding shares the create's transaction: a
    /// conflict must leave no half-made user behind. An alice created and then
    /// left unbound is a slug the operator has to drop before they can retype
    /// the command they meant.
    #[tokio::test]
    async fn a_create_whose_binding_conflicts_leaves_no_user_behind() {
        let (users, log) = repositories();
        let bob = users
            .create(&slug("bob"), None, Some(&asserted("583231")))
            .await
            .unwrap();

        let error = users
            .create(&slug("alice"), None, Some(&asserted("583231")))
            .await
            .unwrap_err();

        assert!(
            matches!(
                error,
                UserError::Binding(IdentityError::AccountBoundElsewhere(_))
            ),
            "{error}"
        );
        assert!(error.to_string().contains("bob"), "{error}");
        // No alice, and no `user.created` for one either — the row and its log
        // entry rolled back together.
        assert_eq!(users.list(None).await.unwrap().len(), 1);
        assert_eq!(users.list(None).await.unwrap()[0].id, bob.id);
        let kinds: Vec<String> = log
            .entries(None)
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.kind)
            .collect();
        assert_eq!(kinds, ["user.created", "identity.bound"]);
    }
}

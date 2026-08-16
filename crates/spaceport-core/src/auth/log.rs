//! The append-only record of what happened to the user pool.
//!
//! This is persistence, not streaming: [`crate::events`] shows an operator
//! what spaceport is doing as it does it, and forgets; this table is the
//! answer to "what happened to this user, ever", and it survives restarts,
//! drops and everything else. The two overlap on purpose — every mutation is
//! both written here and said out loud through `tracing` — because they answer
//! different questions.
//!
//! Rows are only ever appended. There is no update, no delete and no
//! retention, because the log is the one place a dropped user still exists:
//! the `users` row goes, and these rows are what is left to say the slug was
//! ever held, by whom, and what became of them.

use anyhow::{Context, Result};
use rusqlite::Transaction;

use super::UserId;
use crate::state::Db;

/// What every entry a CLI command writes names as its origin. Extensible text
/// rather than an enum, exactly as `kind` is: when SSO lands, an IdP's name
/// goes in the same column, and this build must read those rows back without
/// having heard of the IdP.
pub const OPERATOR_ORIGIN: &str = "operator";

/// What an entry the login page writes names as its origin: a login, a failed
/// code attempt, a logout. Distinct from [`OPERATOR_ORIGIN`] because the two
/// answer the auditor's first question — was this a command somebody gave over
/// the socket, or something that arrived from the internet — and one word for
/// both would erase exactly that.
pub const WEB_ORIGIN: &str = "web";

/// One thing that happened, as the log stores it.
///
/// `kind` and `origin` stay text all the way out: a row written by a newer
/// spaceport — a login, a mint, a grant — must render in this build's
/// `spaceport auth log` as what it says it is, not vanish behind an enum that
/// never heard of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthEvent {
    /// When it happened, RFC 3339 UTC — the store's one timestamp convention.
    pub at: String,
    /// What happened: `user.created`, `user.suspended`, and in time logins,
    /// mints and grants.
    pub kind: String,
    /// The user it is about, when it is about one. Kept as text rather than a
    /// [`UserId`] because the row outlives everything else: an id written by
    /// some other tool must not cost an operator the reading of the log.
    pub user: Option<String>,
    /// Where the command came from: [`OPERATOR_ORIGIN`] for the CLI, an IdP's
    /// name later.
    pub origin: String,
    /// Whatever else is worth remembering, as a sentence fragment — the slug
    /// at the time, the email that was set. Free text on purpose: what a login
    /// wants to say here is not what a drop wants to say.
    pub detail: Option<String>,
}

/// Append one row inside `transaction` — the caller's transaction, always.
///
/// This is a free function over a [`Transaction`] rather than a method on the
/// repository, and the reason is the one property the log must have: a
/// mutation and its record commit together or not at all. A mutation that
/// succeeded but was never logged is worse than one rolled back entirely —
/// the pool would hold a user the log denies — so the write happens inside
/// whatever transaction performed the mutation, and there is deliberately no
/// convenient way to record an event on its own connection beside it.
pub(crate) fn record_in(
    transaction: &Transaction<'_>,
    at: &str,
    kind: &str,
    user: Option<&UserId>,
    origin: &str,
    detail: Option<&str>,
) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO auth_events (at, kind, user_id, origin, detail)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![at, kind, user.map(UserId::as_str), origin, detail],
        )
        .context("recording an auth event")?;

    Ok(())
}

/// The `auth_events` table, in the vocabulary of reading it back.
///
/// Reading only: writes go through [`record_in`], inside the transaction of
/// whatever they record.
#[derive(Debug, Clone)]
pub struct AuthLogRepository {
    db: Db,
}

impl AuthLogRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Every entry, oldest first, optionally only those about `user`.
    ///
    /// Oldest first because the log is read as a story, and `id` rather than
    /// `at` as the tiebreak: two events in one transaction share a timestamp,
    /// and the rowid is the order they were appended in.
    ///
    /// No paging yet. The log grows one row per operator command, and the day
    /// logins land in it is the day a `--since` belongs here.
    pub async fn entries(&self, user: Option<&UserId>) -> Result<Vec<AuthEvent>> {
        let user = user.map(|user| user.to_string());

        self.db
            .call(move |connection| {
                let query = match &user {
                    Some(_) => {
                        "SELECT at, kind, user_id, origin, detail FROM auth_events
                         WHERE user_id = ?1 ORDER BY id"
                    }
                    None => "SELECT at, kind, user_id, origin, detail FROM auth_events ORDER BY id",
                };

                let mut statement = connection
                    .prepare(query)
                    .context("preparing the auth log query")?;

                // The one optional parameter, bound as the zero-or-one values
                // an `Option` iterates as — which is exactly what the two
                // queries above take.
                let entries = statement
                    .query_map(rusqlite::params_from_iter(user.iter()), |row| {
                        Ok(AuthEvent {
                            at: row.get(0)?,
                            kind: row.get(1)?,
                            user: row.get(2)?,
                            origin: row.get(3)?,
                            detail: row.get(4)?,
                        })
                    })
                    .context("reading the auth log")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("reading the auth log")?;

                Ok(entries)
            })
            .await
    }
}

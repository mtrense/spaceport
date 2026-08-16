//! Global sessions, and the one-time codes that mint them.
//!
//! A session is a row in the database and an opaque token in a browser's
//! cookie, and only the row is authoritative: every use — a login, a logout, a
//! listing — asks the table, so dropping the row is dropping the access, with
//! no revocation list or grace window to reason about. The token is stored as
//! its SHA-256, because a read of this table must never yield a string
//! somebody could paste into a cookie; the plaintext exists only in the cookie
//! itself and in memory on the way to being hashed.
//!
//! One-time codes are the way in while SSO is still a later milestone. An
//! operator mints one over the socket, reads it off the terminal exactly once,
//! and hands it to the person it is for; the login page redeems it into a
//! session whose expiry was fixed when the code was minted — `--expires` is a
//! statement about the session being authorised, not about how quickly the
//! user types. Codes are hashed like tokens, die after ten minutes, after five
//! failed attempts, or on first use, whichever comes first.
//!
//! Same discipline as the rest of [`crate::auth`]: every mutation writes its
//! [`crate::auth::log`] entry in the same transaction, or not at all — and
//! suspending or dropping a user sweeps both tables through the shared
//! `offboard` cascade, so a user the pool has closed the door on is one no
//! session table still lets in.
//!
//! There is no background sweeper for expired rows, on purpose. The tables
//! only grow when a code is minted or redeemed, so those two paths delete
//! whatever has expired on their way past: growth and cleanup are the same
//! traffic, nothing can pile up faster than it is swept, and there is no loop
//! to supervise or to forget to start.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SecureRandom;
use rusqlite::{OptionalExtension, Transaction};
use tracing::info;

use super::log::{OPERATOR_ORIGIN, WEB_ORIGIN, record_in};
use super::repository::{find, record, unknown};
use super::{UserId, UserRecord, UserRef};
use crate::secret::Secret;
use crate::state::{Db, now};

/// How long a one-time code is good for, from the moment it is minted. Fixed
/// rather than configurable: the code exists to cross the gap between an
/// operator's terminal and a login form, and ten minutes is that gap with room
/// to spare — a longer window is only a longer time a leaked code works.
const CODE_TTL: Duration = Duration::from_secs(10 * 60);

/// How many failed redemptions a code survives. After the fifth, the code is
/// dead however much of its ten minutes remain.
const MAX_CODE_ATTEMPTS: i64 = 5;

/// How long a session lives when the mint names no `--expires`.
pub const DEFAULT_SESSION_LIFETIME: Duration = Duration::from_secs(12 * 3600);

/// The characters a one-time code is spelled in: lowercase letters and digits
/// with every look-alike removed — no `0`/`o`, no `1`/`i`/`l` — because the
/// code travels by voice, chat paste and hand-typing, and a character two
/// people read differently is a failed login nobody can explain.
const CODE_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// How many characters a code is. Eight from a 31-character alphabet is about
/// forty bits — five guesses against that is nothing, and five guesses is all
/// anybody gets.
const CODE_LEN: usize = 8;

/// How many random bytes a session token is made of, before encoding. The same
/// budget as everything else this codebase mints from `ring`.
const TOKEN_BYTES: usize = 32;

/// The handle an operator uses to name one session: sixteen hex characters,
/// minted at login.
///
/// A handle of its own rather than the token's hash, because it is printed by
/// `session list` and typed into `session drop` — the one identifier here that
/// is *meant* to travel in the clear, which is exactly why it must not be
/// derivable from, or useful as, the credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(String);

impl SessionId {
    /// Mint a fresh id from the host's randomness.
    fn generate() -> Result<Self> {
        let mut bytes = [0_u8; 8];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            // ring's own error says nothing; what an operator can act on is
            // that the host's randomness is what failed.
            .map_err(|_| anyhow!("this host would not produce random bytes"))?;

        let mut rendered = String::with_capacity(16);
        for byte in bytes {
            rendered.push_str(&format!("{byte:02x}"));
        }

        Ok(Self(rendered))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SessionId {
    type Err = anyhow::Error;

    /// Sixteen hex digits, folded to lowercase like a [`UserId`] and for the
    /// same reason: one spelling in the database, one in every log line.
    fn from_str(s: &str) -> Result<Self> {
        let lowered = s.to_ascii_lowercase();
        if lowered.len() != 16 || !lowered.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!(
                "`{s}` is not a session id — one is sixteen hex characters, as \
                 `spaceport auth session list` prints them"
            );
        }

        Ok(Self(lowered))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A one-time code as the mint hands it back: the code itself, shown exactly
/// once, and what redeeming it will buy.
#[derive(Debug)]
pub struct MintedCode {
    pub user: UserRecord,
    /// The code, behind [`Secret`] so no log line or panic message can pick it
    /// up on the way to the one place it is deliberately printed.
    pub code: Secret,
    /// When the session this code redeems into will expire — fixed now, at
    /// mint, whatever moment the code is actually used.
    pub session_expires_at: String,
}

/// What a successful redemption hands the login page: the token to set as the
/// cookie, and enough about the session to say how long the cookie lives.
#[derive(Debug)]
pub struct FreshSession {
    pub id: SessionId,
    pub user: UserId,
    /// The opaque token, behind [`Secret`]; the cookie is the only place it
    /// goes in the clear.
    pub token: Secret,
    pub expires_at: String,
}

/// One live session, as `session list` reports it. No token and no hash, on
/// purpose: a listing is the one read an operator does casually, and it must
/// not be the read that hands out credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub id: SessionId,
    pub created_at: String,
    pub expires_at: String,
}

/// Why a session command did not happen, kept apart the way
/// [`super::UserError`] is because the operator interface answers differently:
/// an unknown user or a drop that matched nothing is a mistyped name, a
/// suspended user is a state only `resume` changes, and a failure is the
/// host's.
#[derive(Debug)]
pub enum SessionError {
    /// No live user answers to that slug or id.
    UnknownUser(anyhow::Error),
    /// The user exists and is suspended, so minting them a way in would
    /// contradict the suspension.
    Suspended(anyhow::Error),
    /// The drop named a session the user does not have.
    Nothing(anyhow::Error),
    /// The store would not do it.
    Failed(anyhow::Error),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownUser(error)
            | Self::Suspended(error)
            | Self::Nothing(error)
            | Self::Failed(error) => write!(f, "{error:#}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Why a code did not redeem. Two variants and deliberately no more: every
/// way a code can be bad — unknown, expired, spent, out of attempts, its user
/// suspended or gone — is the same [`RedeemError::Refused`], because the login
/// page must answer them all with one neutral sentence. An error enum that
/// told them apart would be an oracle one `match` away from the response body.
#[derive(Debug)]
pub enum RedeemError {
    /// The code does not redeem, for a reason the asker is not told.
    Refused,
    /// The store would not answer, which is spaceport's problem and not the
    /// code's.
    Failed(anyhow::Error),
}

impl fmt::Display for RedeemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused => f.write_str("the code was not accepted"),
            Self::Failed(error) => write!(f, "{error:#}"),
        }
    }
}

impl std::error::Error for RedeemError {}

/// The `sessions` and `login_codes` tables, over the state database.
///
/// One repository for both tables rather than one apiece, because they are two
/// halves of one story — a code exists only to become a session, redemption
/// reads one and writes the other in a single transaction, and a caller who
/// could reach the codes without the sessions could mint ways in that nothing
/// lists.
#[derive(Debug, Clone)]
pub struct SessionRepository {
    db: Db,
}

impl SessionRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Mint a one-time code for the user `user` names, redeeming into a
    /// session that expires `lifetime` from now.
    ///
    /// This is the shared core the spec's email flow will call too. HOOK POINT:
    /// when SMTP lands, the email→code request handler resolves the address to
    /// a user, applies its own per-email rate limit (five codes per address
    /// per hour — a rule about the *trigger*, which is why it does not live
    /// here), calls this very function, and mails the code instead of printing
    /// it; the answer stays identical whether or not the address is known.
    /// Until then the operator socket is the only trigger, and the code's one
    /// exit is the terminal.
    ///
    /// A suspended user is refused rather than minted a dormant code: the code
    /// is an invitation to sign in, and issuing one against a closed door
    /// would either contradict the suspension or mint a code that can never
    /// work — both worse than saying so.
    pub async fn mint_code(
        &self,
        user: &UserRef,
        lifetime: Duration,
    ) -> Result<MintedCode, SessionError> {
        // Randomness has no business inside a database lock, exactly as a
        // fresh user id is minted outside its transaction.
        let code = generate_code().map_err(SessionError::Failed)?;
        let code_hash = hash(code.expose());
        let asked = user.clone();

        let found = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to mint a one-time code")?;

                let Some(row) = find(&transaction, &asked)? else {
                    return Ok(None);
                };
                let user = record(row)?;
                if user.suspended {
                    return Ok(Some(Err(user)));
                }

                sweep_expired_in(&transaction)?;

                let at = now();
                let session_expires_at = stamp_after(lifetime);
                transaction
                    .execute(
                        "INSERT INTO login_codes
                             (code_hash, user_id, created_at, code_expires_at, session_expires_at)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![
                            code_hash,
                            user.id.as_str(),
                            at,
                            stamp_after(CODE_TTL),
                            session_expires_at
                        ],
                    )
                    .context("minting a one-time code")?;

                record_in(
                    &transaction,
                    &at,
                    "session.minted",
                    Some(&user.id),
                    OPERATOR_ORIGIN,
                    Some(&format!(
                        "one-time code minted; the session it redeems expires {session_expires_at}"
                    )),
                )?;

                transaction.commit().context("committing a one-time code")?;

                Ok(Some(Ok((user, session_expires_at))))
            })
            .await
            .map_err(SessionError::Failed)?;

        match found {
            None => Err(SessionError::UnknownUser(unknown(user))),
            Some(Err(user)) => Err(SessionError::Suspended(anyhow!(
                "user `{}` is suspended — `spaceport auth user resume {}` first, then mint",
                user.slug,
                user.slug,
            ))),
            Some(Ok((user, session_expires_at))) => {
                info!(user = %user.id, slug = %user.slug, "one-time code minted");

                Ok(MintedCode {
                    user,
                    code,
                    session_expires_at,
                })
            }
        }
    }

    /// Redeem `code` into a session, or refuse without saying why.
    ///
    /// The failure path charges *every* pending code, not one. The login form
    /// carries only the code — no email, no user — so a wrong guess cannot be
    /// attributed to the code it was aimed at, and counting it against nothing
    /// would hand a guesser five attempts per outstanding code instead of five
    /// in total. Charging them all keeps the spec's arithmetic honest at the
    /// cost of a mistyped code burning one attempt for everybody, which ten
    /// minutes and a re-mint absorb. The failed attempt lands in the log
    /// either way — attributed to the code's user when the code was real, and
    /// to nobody when it never existed.
    pub async fn redeem(&self, code: &Secret) -> Result<FreshSession, RedeemError> {
        // Token and id minted out here for the mint's reason: no randomness
        // inside the lock. Made before we know the code is good, at the cost
        // of forty-eight wasted random bytes on a refusal.
        let id = SessionId::generate().map_err(RedeemError::Failed)?;
        let token = generate_token().map_err(RedeemError::Failed)?;
        let token_hash = hash(token.expose());
        let code_hash = hash(code.expose());
        let minted_id = id.clone();

        let outcome = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to redeem a one-time code")?;

                sweep_expired_in(&transaction)?;

                // The code's row, if the hash knows it — with its user's
                // standing read in the same breath, because a code whose user
                // is suspended or gone must not redeem however live it is.
                let matched: Option<(String, i64, String, String)> = transaction
                    .query_row(
                        "SELECT user_id, attempts, code_expires_at, session_expires_at
                         FROM login_codes WHERE code_hash = ?1",
                        rusqlite::params![code_hash],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .optional()
                    .context("looking a one-time code up")?;

                let at = now();
                let good = match &matched {
                    Some((user_id, attempts, code_expires_at, _)) => {
                        let live = *attempts < MAX_CODE_ATTEMPTS && !is_past(code_expires_at);
                        let user: Option<UserId> = user_id.parse().ok();
                        let standing = match &user {
                            Some(user) => find(&transaction, &UserRef::Id(user.clone()))?
                                .map(record)
                                .transpose()?,
                            None => None,
                        };

                        live && standing.is_some_and(|user| !user.suspended)
                    }
                    None => false,
                };

                if !good {
                    // Charge every pending code — see the method comment for
                    // why the guess cannot be aimed better than that.
                    transaction
                        .execute("UPDATE login_codes SET attempts = attempts + 1", [])
                        .context("counting a failed code attempt")?;

                    let user: Option<UserId> = matched
                        .as_ref()
                        .and_then(|(user_id, ..)| user_id.parse().ok());
                    record_in(
                        &transaction,
                        &at,
                        "login.failed",
                        user.as_ref(),
                        WEB_ORIGIN,
                        Some(match &matched {
                            Some(_) => "a one-time code was refused",
                            None => "a one-time code nobody is waiting on was refused",
                        }),
                    )?;

                    transaction
                        .commit()
                        .context("committing a refused code attempt")?;

                    return Ok(None);
                }

                let (user_id, _, _, session_expires_at) =
                    matched.expect("a good code matched a row");
                let user: UserId = user_id
                    .parse()
                    .map_err(|error| anyhow!("{error:#}"))
                    .context("reading a stored user id")?;

                // Single use: the row goes before the session exists, in the
                // same transaction, so there is no moment where both are true.
                transaction
                    .execute(
                        "DELETE FROM login_codes WHERE code_hash = ?1",
                        rusqlite::params![code_hash],
                    )
                    .context("spending a one-time code")?;

                transaction
                    .execute(
                        "INSERT INTO sessions
                             (session_id, user_id, token_hash, created_at, expires_at)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![
                            minted_id.as_str(),
                            user.as_str(),
                            token_hash,
                            at,
                            session_expires_at
                        ],
                    )
                    .context("minting a session")?;

                record_in(
                    &transaction,
                    &at,
                    "login.succeeded",
                    Some(&user),
                    WEB_ORIGIN,
                    Some(&format!("session {minted_id} minted by one-time code")),
                )?;

                transaction.commit().context("committing a login")?;

                Ok(Some((user, session_expires_at)))
            })
            .await
            .map_err(RedeemError::Failed)?;

        match outcome {
            None => Err(RedeemError::Refused),
            Some((user, expires_at)) => {
                info!(%user, session = %id, "login succeeded");

                Ok(FreshSession {
                    id,
                    user,
                    token,
                    expires_at,
                })
            }
        }
    }

    /// Drop the session `token` belongs to, if it names a live one. Answers
    /// whether anything was dropped, and deliberately nothing more: the logout
    /// page treats a token nobody recognises exactly like a real one, because
    /// either way the right response is a cleared cookie.
    ///
    /// HOOK POINT: when app sessions land, the derived sessions — and the
    /// WebSocket connections tracked under them — are dropped here, in this
    /// transaction, so a logout is one commit however many domains it reaches.
    pub async fn logout(&self, token: &Secret) -> Result<bool> {
        let token_hash = hash(token.expose());

        let dropped = self
            .db
            .call(move |connection| {
                let transaction = connection.transaction().context("beginning a logout")?;

                let found: Option<(String, String, String)> = transaction
                    .query_row(
                        "SELECT session_id, user_id, expires_at
                         FROM sessions WHERE token_hash = ?1",
                        rusqlite::params![token_hash],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()
                    .context("looking a session up")?;

                // An expired row is not a session anymore, so logging out of
                // it is logging out of nothing — but the row can go.
                let Some((session_id, user_id, expires_at)) = found else {
                    return Ok(None);
                };

                transaction
                    .execute(
                        "DELETE FROM sessions WHERE token_hash = ?1",
                        rusqlite::params![token_hash],
                    )
                    .context("dropping a session at logout")?;

                if is_past(&expires_at) {
                    transaction.commit().context("committing a logout")?;

                    return Ok(None);
                }

                let user: Option<UserId> = user_id.parse().ok();
                record_in(
                    &transaction,
                    &now(),
                    "logout",
                    user.as_ref(),
                    WEB_ORIGIN,
                    Some(&format!("session {session_id}")),
                )?;

                transaction.commit().context("committing a logout")?;

                Ok(Some((session_id, user_id)))
            })
            .await?;

        if let Some((session, user)) = &dropped {
            info!(%user, %session, "logout");
        }

        Ok(dropped.is_some())
    }

    /// Every live session of the user `user` names, oldest first.
    ///
    /// Live only: an expired row is swept by the next mint or redeem, and
    /// listing it in the meantime would be reporting access nobody has. The
    /// answer will grow API keys in a later milestone, which is why the
    /// operator interface renders these rows under a KIND column already.
    pub async fn list(
        &self,
        user: &UserRef,
    ) -> Result<(UserRecord, Vec<SessionRecord>), SessionError> {
        let asked = user.clone();

        let found = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to list sessions")?;

                let Some(row) = find(&transaction, &asked)? else {
                    return Ok(None);
                };
                let user = record(row)?;
                let sessions = live_sessions_in(&transaction, &user.id)?;

                Ok(Some((user, sessions)))
            })
            .await
            .map_err(SessionError::Failed)?;

        found.ok_or_else(|| SessionError::UnknownUser(unknown(user)))
    }

    /// Drop one session of the user's, or every one they have.
    ///
    /// A named session that is not there is a refusal rather than a quiet
    /// no-op — the operator typed an id, and "done" about an id that named
    /// nothing would be the answer disagreeing with the table. Dropping all of
    /// none succeeds and says zero, because "make it so there are no sessions"
    /// was already true.
    pub async fn drop_sessions(
        &self,
        user: &UserRef,
        session: Option<&SessionId>,
    ) -> Result<(UserRecord, Vec<SessionRecord>), SessionError> {
        let asked = user.clone();
        let session = session.cloned();

        let found = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to drop sessions")?;

                let Some(row) = find(&transaction, &asked)? else {
                    return Ok(None);
                };
                let user = record(row)?;

                let held = live_sessions_in(&transaction, &user.id)?;
                let dropping: Vec<SessionRecord> = match &session {
                    Some(id) => held.into_iter().filter(|held| &held.id == id).collect(),
                    None => held,
                };
                if session.is_some() && dropping.is_empty() {
                    return Ok(Some(Err(user)));
                }

                let at = now();
                for session in &dropping {
                    transaction
                        .execute(
                            "DELETE FROM sessions WHERE session_id = ?1",
                            rusqlite::params![session.id.as_str()],
                        )
                        .context("dropping a session")?;
                    record_in(
                        &transaction,
                        &at,
                        "session.dropped",
                        Some(&user.id),
                        OPERATOR_ORIGIN,
                        Some(&format!("session {}", session.id)),
                    )?;
                }

                transaction.commit().context("committing a session drop")?;

                Ok(Some(Ok((user, dropping))))
            })
            .await
            .map_err(SessionError::Failed)?;

        match found {
            None => Err(SessionError::UnknownUser(unknown(user))),
            Some(Err(user)) => Err(SessionError::Nothing(anyhow!(
                "`{}` has no such session — `spaceport auth session list {}` says what is live",
                user.slug,
                user.slug,
            ))),
            Some(Ok((user, dropped))) => {
                for session in &dropped {
                    info!(user = %user.id, session = %session.id, "session dropped");
                }

                Ok((user, dropped))
            }
        }
    }
}

/// The user's live sessions, oldest first, inside the caller's transaction.
fn live_sessions_in(transaction: &Transaction<'_>, user: &UserId) -> Result<Vec<SessionRecord>> {
    let mut statement = transaction
        .prepare(
            "SELECT session_id, created_at, expires_at FROM sessions
             WHERE user_id = ?1 ORDER BY created_at, session_id",
        )
        .context("preparing the session listing query")?;
    let rows = statement
        .query_map(rusqlite::params![user.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .context("listing the sessions")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("listing the sessions")?;

    Ok(rows
        .into_iter()
        .filter(|(_, _, expires_at)| !is_past(expires_at))
        .filter_map(|(id, created_at, expires_at)| match id.parse() {
            Ok(id) => Some(SessionRecord {
                id,
                created_at,
                expires_at,
            }),
            Err(error) => {
                tracing::warn!(%error, "skipping a stored session this build cannot read");
                None
            }
        })
        .collect())
}

/// Delete every session and pending code of `user`, inside the caller's
/// transaction.
///
/// This is the offboarding cascade's tenant, and — like the log's `record_in`
/// — it only exists as a function over a transaction: a user the pool says is
/// suspended or gone must never be one this table still lets in, so the
/// deletes commit with the suspend or drop that ordered them. Deleted, not
/// logged row by row, for the reason `drop_user` gives about entitlements:
/// the suspend or drop entry is the record, and a fan of `session.dropped`
/// lines nobody typed would read as commands that were never given.
pub(super) fn remove_all_in(transaction: &Transaction<'_>, user: &UserId) -> Result<()> {
    transaction
        .execute(
            "DELETE FROM sessions WHERE user_id = ?1",
            rusqlite::params![user.as_str()],
        )
        .context("removing an offboarded user's sessions")?;
    transaction
        .execute(
            "DELETE FROM login_codes WHERE user_id = ?1",
            rusqlite::params![user.as_str()],
        )
        .context("removing an offboarded user's pending codes")?;

    Ok(())
}

/// Delete what no longer counts: expired sessions, and codes that are expired
/// or out of attempts. Run by mint and redeem — the only writes that grow
/// these tables — which is the whole cleanup story; see the module comment.
///
/// The comparison is a string comparison against [`now`]'s output, which is
/// exact to the second and can misjudge inside one: two RFC 3339 stamps with
/// different fractional digits do not always order lexicographically within a
/// second of each other. A sweep that keeps a dead row one extra second, or
/// takes it one early, costs nothing — the *authoritative* checks parse.
fn sweep_expired_in(transaction: &Transaction<'_>) -> Result<()> {
    let at = now();
    transaction
        .execute(
            "DELETE FROM sessions WHERE expires_at < ?1",
            rusqlite::params![at],
        )
        .context("sweeping expired sessions")?;
    transaction
        .execute(
            "DELETE FROM login_codes WHERE code_expires_at < ?1 OR attempts >= ?2",
            rusqlite::params![at, MAX_CODE_ATTEMPTS],
        )
        .context("sweeping dead one-time codes")?;

    Ok(())
}

/// Whether the RFC 3339 stamp `at` is in the past. A stamp that will not parse
/// answers "past": it was written by something other than this build, and
/// treating it as live access on the strength of an unreadable date would be
/// the wrong side to fail on.
fn is_past(at: &str) -> bool {
    time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339)
        .map(|at| at <= time::OffsetDateTime::now_utc())
        .unwrap_or(true)
}

/// The RFC 3339 stamp `after` from now — how every expiry here is written.
fn stamp_after(after: Duration) -> String {
    (time::OffsetDateTime::now_utc() + after)
        .format(&time::format_description::well_known::Rfc3339)
        // The only way this fails is a format description that cannot render a
        // valid timestamp, which `Rfc3339` is not.
        .unwrap_or_else(|_| String::new())
}

/// SHA-256 of `value`, in hex — how tokens and codes are stored. A plain hash
/// with no salt or work factor, and that is enough here: the preimages are 40
/// and 256 bits of `ring` randomness, not passwords, so there is nothing a
/// rainbow table or a fast guess could do with the digest.
fn hash(value: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, value.as_bytes());

    let mut rendered = String::with_capacity(64);
    for byte in digest.as_ref() {
        rendered.push_str(&format!("{byte:02x}"));
    }

    rendered
}

/// A fresh one-time code: [`CODE_LEN`] characters of [`CODE_ALPHABET`].
///
/// Rejection sampling rather than `byte % 31`, because the modulo would favour
/// the alphabet's front by one part in eight — survivable at forty bits, and
/// still a bias there is no reason to ship when skipping a byte costs nothing.
fn generate_code() -> Result<Secret> {
    let random = ring::rand::SystemRandom::new();
    let mut code = String::with_capacity(CODE_LEN);

    while code.len() < CODE_LEN {
        let mut bytes = [0_u8; 16];
        random
            .fill(&mut bytes)
            .map_err(|_| anyhow!("this host would not produce random bytes"))?;

        for byte in bytes {
            // The largest multiple of the alphabet below 256; everything at or
            // past it would wrap unevenly, so it is thrown back.
            let cutoff = (256 / CODE_ALPHABET.len()) * CODE_ALPHABET.len();
            if (byte as usize) < cutoff && code.len() < CODE_LEN {
                code.push(CODE_ALPHABET[byte as usize % CODE_ALPHABET.len()] as char);
            }
        }
    }

    Ok(Secret::new(code))
}

/// A fresh session token: [`TOKEN_BYTES`] of randomness in the url-safe
/// alphabet, the same shape as every nonce this codebase mints — a cookie
/// value must survive the trip without quoting, and base64url does.
fn generate_token() -> Result<Secret> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("this host would not produce random bytes"))?;

    Ok(Secret::new(URL_SAFE_NO_PAD.encode(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthLogRepository, UserRepository, UserSlug};

    fn repositories() -> (UserRepository, SessionRepository, AuthLogRepository) {
        let db = Db::in_memory().unwrap();

        (
            UserRepository::new(db.clone()),
            SessionRepository::new(db.clone()),
            AuthLogRepository::new(db),
        )
    }

    fn slug(slug: &str) -> UserSlug {
        slug.parse().unwrap()
    }

    fn by_slug(name: &str) -> UserRef {
        UserRef::Slug(slug(name))
    }

    async fn mint(sessions: &SessionRepository, user: &str) -> MintedCode {
        sessions
            .mint_code(&by_slug(user), DEFAULT_SESSION_LIFETIME)
            .await
            .unwrap()
    }

    /// Rows in `table`, read straight off the database — for what no listing
    /// exposes on purpose, like a dropped user's leftovers.
    async fn rows_in(sessions: &SessionRepository, table: &'static str) -> i64 {
        sessions
            .db
            .call(move |connection| {
                connection
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .context("counting rows")
            })
            .await
            .unwrap()
    }

    /// Age a stored stamp into the past, to make expiry testable without a
    /// clock to wind.
    async fn expire(sessions: &SessionRepository, table: &'static str, column: &'static str) {
        sessions
            .db
            .call(move |connection| {
                connection
                    .execute(
                        &format!("UPDATE {table} SET {column} = '2000-01-01T00:00:00Z'"),
                        [],
                    )
                    .context("aging a row")?;

                Ok(())
            })
            .await
            .unwrap();
    }

    #[test]
    fn a_code_is_eight_unambiguous_characters() {
        let code = generate_code().unwrap();

        assert_eq!(code.expose().len(), CODE_LEN);
        for character in code.expose().bytes() {
            assert!(
                CODE_ALPHABET.contains(&character),
                "`{}` is outside the alphabet",
                character as char
            );
        }
    }

    /// Two calls handing back the same code would mean the randomness is not
    /// being asked — the same argument `UserId::generate` makes.
    #[test]
    fn generated_codes_and_tokens_differ() {
        assert_ne!(
            generate_code().unwrap().expose(),
            generate_code().unwrap().expose()
        );
        assert_ne!(
            generate_token().unwrap().expose(),
            generate_token().unwrap().expose()
        );
    }

    /// The credential must never be printable by accident, which is what the
    /// [`Secret`] wrapper is for — asserted here once for both kinds.
    #[test]
    fn a_minted_code_does_not_debug_print() {
        let code = generate_code().unwrap();

        let printed = format!("{code:?}");
        assert!(!printed.contains(code.expose()), "{printed}");
    }

    #[test]
    fn a_session_id_parses_and_folds_like_it_prints() {
        let id = SessionId::generate().unwrap();
        assert_eq!(id.to_string().parse::<SessionId>().unwrap(), id);

        let folded: SessionId = "0123456789ABCDEF".parse().unwrap();
        assert_eq!(folded.as_str(), "0123456789abcdef");

        for broken in ["", "0123", "0123456789abcdeg", "0123456789abcdef0"] {
            assert!(broken.parse::<SessionId>().is_err(), "accepted `{broken}`");
        }
    }

    /// The whole happy path: a code minted over the socket becomes a session
    /// the listing shows, whose expiry is the one fixed at mint.
    #[tokio::test]
    async fn a_minted_code_redeems_into_a_listed_session() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();

        let minted = mint(&sessions, "alice").await;
        let fresh = sessions.redeem(&minted.code).await.unwrap();

        assert_eq!(fresh.expires_at, minted.session_expires_at);
        let (user, listed) = sessions.list(&by_slug("alice")).await.unwrap();
        assert_eq!(user.slug, slug("alice"));
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, fresh.id);
        assert_eq!(listed[0].expires_at, minted.session_expires_at);
    }

    /// Single use is the "one-time" in the name: the second redemption meets a
    /// code that no longer exists.
    #[tokio::test]
    async fn a_code_redeems_exactly_once() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        let minted = mint(&sessions, "alice").await;

        sessions.redeem(&minted.code).await.unwrap();
        let again = sessions.redeem(&minted.code).await.unwrap_err();

        assert!(matches!(again, RedeemError::Refused), "{again}");
        // And the failure minted nothing: still the one session.
        assert_eq!(sessions.list(&by_slug("alice")).await.unwrap().1.len(), 1);
    }

    /// Five wrong guesses kill the code that was waiting, however right the
    /// sixth guess is — the brute-force arithmetic the spec fixes.
    #[tokio::test]
    async fn five_failed_attempts_kill_a_pending_code() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        let minted = mint(&sessions, "alice").await;

        for _ in 0..MAX_CODE_ATTEMPTS {
            let wrong = sessions.redeem(&Secret::new("wrongcod")).await.unwrap_err();
            assert!(matches!(wrong, RedeemError::Refused), "{wrong}");
        }

        let real = sessions.redeem(&minted.code).await.unwrap_err();
        assert!(matches!(real, RedeemError::Refused), "{real}");
    }

    /// Four failures leave the code alive: the counter kills at five, not
    /// before, or a fat-fingered user could never get in at all.
    #[tokio::test]
    async fn a_code_survives_four_failed_attempts() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        let minted = mint(&sessions, "alice").await;

        for _ in 0..(MAX_CODE_ATTEMPTS - 1) {
            let _ = sessions.redeem(&Secret::new("wrongcod")).await;
        }

        assert!(sessions.redeem(&minted.code).await.is_ok());
    }

    #[tokio::test]
    async fn an_expired_code_is_refused() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        let minted = mint(&sessions, "alice").await;
        expire(&sessions, "login_codes", "code_expires_at").await;

        let error = sessions.redeem(&minted.code).await.unwrap_err();

        assert!(matches!(error, RedeemError::Refused), "{error}");
    }

    /// A session's validity is asked of the database on use, so a row aged
    /// past its expiry stops being listed and stops being a logout.
    #[tokio::test]
    async fn an_expired_session_is_neither_listed_nor_logged_out() {
        let (users, sessions, log) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        let minted = mint(&sessions, "alice").await;
        let fresh = sessions.redeem(&minted.code).await.unwrap();
        expire(&sessions, "sessions", "expires_at").await;

        assert!(sessions.list(&by_slug("alice")).await.unwrap().1.is_empty());
        assert!(!sessions.logout(&fresh.token).await.unwrap());
        assert!(
            !log.entries(None)
                .await
                .unwrap()
                .iter()
                .any(|entry| entry.kind == "logout")
        );
    }

    /// Suspension is the immediate-offboarding lever: the session dies with
    /// it, the pending code dies with it, and resume resurrects neither.
    #[tokio::test]
    async fn suspending_a_user_kills_their_sessions_and_pending_codes() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        let spent = mint(&sessions, "alice").await;
        sessions.redeem(&spent.code).await.unwrap();
        let pending = mint(&sessions, "alice").await;

        users.suspend(&by_slug("alice")).await.unwrap();

        assert!(sessions.list(&by_slug("alice")).await.unwrap().1.is_empty());
        let code = sessions.redeem(&pending.code).await.unwrap_err();
        assert!(matches!(code, RedeemError::Refused), "{code}");

        users.resume(&by_slug("alice")).await.unwrap();
        assert!(sessions.list(&by_slug("alice")).await.unwrap().1.is_empty());
    }

    /// The drop half of the same cascade, read straight off the tables since
    /// no listing can name a user who is gone.
    #[tokio::test]
    async fn dropping_a_user_takes_their_sessions_and_codes_with_them() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        let minted = mint(&sessions, "alice").await;
        sessions.redeem(&minted.code).await.unwrap();
        mint(&sessions, "alice").await;

        users.drop_user(&by_slug("alice")).await.unwrap();

        assert_eq!(rows_in(&sessions, "sessions").await, 0);
        assert_eq!(rows_in(&sessions, "login_codes").await, 0);
    }

    #[tokio::test]
    async fn minting_for_a_suspended_user_is_refused() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        users.suspend(&by_slug("alice")).await.unwrap();

        let error = sessions
            .mint_code(&by_slug("alice"), DEFAULT_SESSION_LIFETIME)
            .await
            .unwrap_err();

        assert!(matches!(error, SessionError::Suspended(_)), "{error}");
    }

    #[tokio::test]
    async fn a_command_aimed_at_nobody_says_so() {
        let (_, sessions, _) = repositories();

        for result in [
            sessions
                .mint_code(&by_slug("ghost"), DEFAULT_SESSION_LIFETIME)
                .await
                .map(|_| ()),
            sessions.list(&by_slug("ghost")).await.map(|_| ()),
            sessions
                .drop_sessions(&by_slug("ghost"), None)
                .await
                .map(|_| ()),
        ] {
            let error = result.unwrap_err();
            assert!(matches!(error, SessionError::UnknownUser(_)), "{error}");
        }
    }

    #[tokio::test]
    async fn drops_one_session_by_id_and_leaves_the_other() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        let first = mint(&sessions, "alice").await;
        let first = sessions.redeem(&first.code).await.unwrap();
        let second = mint(&sessions, "alice").await;
        let second = sessions.redeem(&second.code).await.unwrap();

        let (_, dropped) = sessions
            .drop_sessions(&by_slug("alice"), Some(&first.id))
            .await
            .unwrap();

        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].id, first.id);
        let (_, listed) = sessions.list(&by_slug("alice")).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, second.id);
    }

    #[tokio::test]
    async fn drops_every_session_when_no_id_is_named() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        for _ in 0..2 {
            let minted = mint(&sessions, "alice").await;
            sessions.redeem(&minted.code).await.unwrap();
        }

        let (_, dropped) = sessions
            .drop_sessions(&by_slug("alice"), None)
            .await
            .unwrap();

        assert_eq!(dropped.len(), 2);
        assert!(sessions.list(&by_slug("alice")).await.unwrap().1.is_empty());
    }

    /// An id that names nothing is a refusal, not a quiet success — the
    /// operator typed it, and it did not do what they asked.
    #[tokio::test]
    async fn dropping_a_session_the_user_does_not_have_says_so() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();

        let ghost: SessionId = "00000000000000aa".parse().unwrap();
        let error = sessions
            .drop_sessions(&by_slug("alice"), Some(&ghost))
            .await
            .unwrap_err();

        assert!(matches!(error, SessionError::Nothing(_)), "{error}");
    }

    #[tokio::test]
    async fn logout_drops_the_session_the_token_names() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        let minted = mint(&sessions, "alice").await;
        let fresh = sessions.redeem(&minted.code).await.unwrap();

        assert!(sessions.logout(&fresh.token).await.unwrap());
        assert!(sessions.list(&by_slug("alice")).await.unwrap().1.is_empty());
        // A token that no longer names anything logs nobody out.
        assert!(!sessions.logout(&fresh.token).await.unwrap());
    }

    /// The log is the other half of every mutation here: mint, login, failed
    /// attempt, logout and drop each land exactly once, stamped with where
    /// they came from — the CLI for the operator's verbs, the web for the
    /// user's.
    #[tokio::test]
    async fn every_mutation_is_recorded_in_the_log() {
        let (users, sessions, log) = repositories();
        let alice = users.create(&slug("alice"), None).await.unwrap();
        let minted = mint(&sessions, "alice").await;
        let _ = sessions.redeem(&Secret::new("wrongcod")).await;
        sessions.redeem(&minted.code).await.unwrap();
        let second = mint(&sessions, "alice").await;
        let second = sessions.redeem(&second.code).await.unwrap();
        sessions.logout(&second.token).await.unwrap();
        sessions
            .drop_sessions(&by_slug("alice"), None)
            .await
            .unwrap();

        let entries = log.entries(None).await.unwrap();
        let kinds: Vec<&str> = entries.iter().map(|entry| entry.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "user.created",
                "session.minted",
                "login.failed",
                "login.succeeded",
                "session.minted",
                "login.succeeded",
                "logout",
                "session.dropped",
            ]
        );

        // The operator's verbs say so, and the web's say so.
        for entry in &entries {
            let expected = match entry.kind.as_str() {
                "login.failed" | "login.succeeded" | "logout" => WEB_ORIGIN,
                _ => OPERATOR_ORIGIN,
            };
            assert_eq!(entry.origin, expected, "{}", entry.kind);
        }
        // A failed guess at a code nobody minted is about nobody; everything
        // else here is about alice.
        let failed = entries
            .iter()
            .find(|entry| entry.kind == "login.failed")
            .unwrap();
        assert_eq!(failed.user, None);
        assert!(
            failed
                .detail
                .as_deref()
                .unwrap()
                .contains("nobody is waiting on"),
        );
        let succeeded = entries
            .iter()
            .find(|entry| entry.kind == "login.succeeded")
            .unwrap();
        assert_eq!(succeeded.user.as_deref(), Some(alice.id.as_str()));
    }

    /// Neither log entry nor error may say whether a code existed in any way a
    /// login page could echo: the two refusals must be the same variant.
    #[tokio::test]
    async fn an_unknown_and_a_dead_code_refuse_identically() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        let minted = mint(&sessions, "alice").await;
        sessions.redeem(&minted.code).await.unwrap();

        let unknown = sessions.redeem(&Secret::new("wrongcod")).await.unwrap_err();
        let spent = sessions.redeem(&minted.code).await.unwrap_err();

        assert_eq!(unknown.to_string(), spent.to_string());
    }

    /// The opportunistic sweep in action: an expired code is gone from the
    /// table after the next mint, not merely refused.
    #[tokio::test]
    async fn minting_sweeps_expired_codes_away() {
        let (users, sessions, _) = repositories();
        users.create(&slug("alice"), None).await.unwrap();
        mint(&sessions, "alice").await;
        expire(&sessions, "login_codes", "code_expires_at").await;

        mint(&sessions, "alice").await;

        assert_eq!(rows_in(&sessions, "login_codes").await, 1);
    }
}

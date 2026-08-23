//! API keys: the way a machine reaches a gated app without a browser.
//!
//! A key grants exactly one role at one app to the user it was minted for,
//! and that flatness is the design: a key is deliberately *not* an
//! entitlement row, because a credential sitting in some CI system's secrets
//! store must mean tomorrow what it meant when the operator read it off the
//! terminal — revoking or widening the user's grants must not quietly change
//! what the key buys. The one thing that revokes a key is a command aimed at
//! it, or the user it belongs to going away.
//!
//! The credential is `spk_` and thirty-two bytes of randomness, shown exactly
//! once at mint and stored only as its SHA-256, the discipline every session
//! table already follows; listings show the prefix and the last four
//! characters, which is enough to tell two keys apart and worthless to
//! present. The `key_id` beside it is the [`super::SessionId`] pattern again —
//! a short handle minted at creation, printed by `session list` and typed
//! into `session drop`, derivable from nothing.
//!
//! These methods live on [`SessionRepository`] in a file of their own for
//! [`super::app_session`]'s reason: keys share the session tables' cascades —
//! `session drop <user>` with no id takes sessions *and* keys, suspend and
//! drop sweep them in the same transaction — and a second repository over the
//! same offboarding story would be two owners of one cascade. Same
//! disciplines as the rest of [`crate::auth`]: mutations log through
//! `record_in` in their own transaction, expiries are swept by the writes
//! that grow the table, and validity is answered by the database with the
//! four-minute JWT cache as the only staleness window on the hot path.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{OptionalExtension, Transaction};
use tracing::info;

use super::log::{OPERATOR_ORIGIN, record_in};
use super::repository::{find, record, unknown};
use super::session::{
    SessionRepository, generate_token, hash, is_past, short_handle, stamp_after, sweep_expired_in,
};
use super::{Role, RoleAtApp, UserId, UserRecord, UserRef};
use crate::app::AppId;
use crate::secret::Secret;
use crate::state::now;

use super::session::SessionError;

/// How long a key lives when the mint names no `--expires`. The spec's ninety
/// days: long enough that a quarterly rotation is the natural cadence, short
/// enough that a key nobody rotates dies on its own.
pub const DEFAULT_API_KEY_LIFETIME: Duration = Duration::from_secs(90 * 24 * 3600);

/// What every key starts with. The prefix is what lets the edge tell a
/// spaceport key from any other bearer token a client might send, and what
/// lets a human tell a leaked one apart in a paste site's search results.
pub const KEY_PREFIX: &str = "spk_";

/// The handle an operator uses to name one API key: sixteen hex characters,
/// minted at creation — the [`super::SessionId`] discipline, and a type of
/// its own so a function asking for a key's id cannot be handed a session's.
///
/// A handle rather than the key's hash, for the reason `session_id` gives:
/// it is printed by `session list` and typed into `session drop`, the one
/// identifier here that is *meant* to travel in the clear, which is exactly
/// why it must not be derivable from, or useful as, the credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ApiKeyId(String);

impl ApiKeyId {
    /// Mint a fresh id from the host's randomness.
    fn generate() -> Result<Self> {
        short_handle().map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ApiKeyId {
    type Err = anyhow::Error;

    /// Sixteen hex digits, folded to lowercase like a [`super::SessionId`]
    /// and for the same reason: one spelling in the database, one in every
    /// log line.
    fn from_str(s: &str) -> Result<Self> {
        let lowered = s.to_ascii_lowercase();
        if lowered.len() != 16 || !lowered.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!(
                "`{s}` is not an api key id — one is sixteen hex characters, as \
                 `spaceport auth session list` prints them"
            );
        }

        Ok(Self(lowered))
    }
}

impl fmt::Display for ApiKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An API key as the mint hands it back: the credential itself, shown exactly
/// once, and everything a listing will ever show of it again.
#[derive(Debug)]
pub struct MintedApiKey {
    pub user: UserRecord,
    pub id: ApiKeyId,
    /// The key, behind [`Secret`] so no log line or panic message can pick it
    /// up on the way to the one place it is deliberately printed.
    pub key: Secret,
    /// What `session list` will show of the credential from now on: the
    /// prefix and the last four characters.
    pub prefix_tail: String,
    /// What the key grants — echoed back so the mint response can say it
    /// without re-parsing anything.
    pub grants: RoleAtApp,
    pub expires_at: String,
}

/// One live API key, as `session list` reports it. No key and no hash, on
/// purpose — [`super::SessionRecord`]'s rule: a listing is the one read an
/// operator does casually, and it must not be the read that hands out
/// credentials. `prefix_tail` is the whole exception, fixed at mint.
///
/// The app and role are text rather than [`AppId`] and [`Role`] so a row
/// written by a newer build still lists, exactly as
/// [`super::AppSessionRecord`] argues for its app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyRecord {
    pub id: ApiKeyId,
    pub app: String,
    pub role: String,
    pub prefix_tail: String,
    pub created_at: String,
    pub expires_at: String,
}

impl SessionRepository {
    /// Mint an API key for the user `user` names, granting `grants` until
    /// `lifetime` from now.
    ///
    /// A suspended user is refused for the mint-a-code reason: a key is a way
    /// in, and issuing one against a closed door would contradict the
    /// suspension. Whether the app's manifest declares the role is
    /// deliberately not asked here — the spec stores the key either way, and
    /// the warning belongs to the operator response, where the deployed
    /// manifest is at hand, exactly as `grant` splits the same question.
    ///
    /// Two keys for the same role at the same app coexist on purpose: each
    /// caller gets a credential of its own, so one machine's key can be
    /// revoked without rotating every other's.
    pub async fn mint_api_key(
        &self,
        user: &UserRef,
        grants: &RoleAtApp,
        lifetime: Duration,
    ) -> Result<MintedApiKey, SessionError> {
        // Randomness outside the lock, as every mint in this module tree.
        let id = ApiKeyId::generate().map_err(SessionError::Failed)?;
        let key = generate_api_key().map_err(SessionError::Failed)?;
        let key_hash = hash(key.expose());
        let prefix_tail = prefix_tail(key.expose());
        let asked = user.clone();
        let grants = grants.clone();
        let minted_id = id.clone();
        let shown = prefix_tail.clone();

        let found = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to mint an api key")?;

                let Some(row) = find(&transaction, &asked)? else {
                    return Ok(None);
                };
                let user = record(row)?;
                if user.suspended {
                    return Ok(Some(Err(user)));
                }

                sweep_expired_in(&transaction)?;

                let at = now();
                let expires_at = stamp_after(lifetime);
                transaction
                    .execute(
                        "INSERT INTO api_keys
                             (key_id, user_id, spaceport_app, role, key_hash, prefix_tail,
                              created_at, expires_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        rusqlite::params![
                            minted_id.as_str(),
                            user.id.as_str(),
                            grants.app.as_str(),
                            grants.role.as_str(),
                            key_hash,
                            shown,
                            at,
                            expires_at
                        ],
                    )
                    .context("minting an api key")?;

                record_in(
                    &transaction,
                    &at,
                    "key.minted",
                    Some(&user.id),
                    OPERATOR_ORIGIN,
                    Some(&format!(
                        "api key {minted_id} ({shown}): role `{}` at app `{}`, expires {expires_at}",
                        grants.role, grants.app
                    )),
                )?;

                transaction.commit().context("committing an api key")?;

                Ok(Some(Ok((user, grants, expires_at))))
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
            Some(Ok((user, grants, expires_at))) => {
                info!(user = %user.id, key = %id, %grants, "api key minted");

                Ok(MintedApiKey {
                    user,
                    id,
                    key,
                    prefix_tail,
                    grants,
                    expires_at,
                })
            }
        }
    }

    /// Who a presented API key speaks for at `app`, and with which role — the
    /// gate's question, once per key-authenticated request on a cache miss.
    ///
    /// `None` is every refusal at once — unknown, expired, minted for another
    /// app, its owner suspended or gone — because the edge answers them all
    /// with one `401`: a machine caller acts on the status, and an answer
    /// that told a guesser which part of a stolen key was wrong would be an
    /// oracle. The owner's standing is read in the same breath even though
    /// the offboarding cascade already deletes a suspended user's keys: the
    /// row's absence is the lever, and this check is the failing-closed
    /// second lock should any path ever leave a row behind.
    pub async fn api_key_identity(
        &self,
        key: &Secret,
        app: &AppId,
    ) -> Result<Option<(UserId, Role)>> {
        Ok(self
            .api_key_grant(key, app)
            .await?
            .map(|(user, role, _)| (user, role)))
    }

    /// The same lookup with the key's expiry beside the identity — what a
    /// WebSocket upgrade asks, for [`SessionRepository::app_session_grant`]'s
    /// reason: the tunnel arms its deadline at handshake, since no per-request
    /// check ever runs again on a socket that upgraded once.
    pub async fn api_key_grant(
        &self,
        key: &Secret,
        app: &AppId,
    ) -> Result<Option<(UserId, Role, String)>> {
        let key_hash = hash(key.expose());
        let app = app.clone();

        self.db
            .call(move |connection| {
                let found: Option<(String, String, String, String)> = connection
                    .query_row(
                        "SELECT user_id, spaceport_app, role, expires_at
                         FROM api_keys WHERE key_hash = ?1",
                        rusqlite::params![key_hash],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .optional()
                    .context("looking an api key up")?;

                let Some((user_id, minted_for, role, expires_at)) = found else {
                    return Ok(None);
                };
                if minted_for != app.as_str() || is_past(&expires_at) {
                    return Ok(None);
                }

                let suspended: Option<bool> = connection
                    .query_row(
                        "SELECT suspended FROM users WHERE user_id = ?1",
                        rusqlite::params![user_id],
                        |row| row.get(0),
                    )
                    .optional()
                    .context("checking an api key's owner")?;
                if suspended != Some(false) {
                    return Ok(None);
                }

                // A row this build cannot parse answers "nobody", the
                // failing-closed direction everything in this module takes.
                Ok(user_id
                    .parse()
                    .ok()
                    .zip(role.parse().ok())
                    .map(|(user, role)| (user, role, expires_at)))
            })
            .await
    }
}

/// A fresh API key: the prefix, then the same thirty-two bytes of randomness
/// every session token is made of. The prefix is part of the credential — it
/// is hashed with the rest — so a token pasted without it verifies nowhere.
fn generate_api_key() -> Result<Secret> {
    Ok(Secret::new(format!(
        "{KEY_PREFIX}{}",
        generate_token()?.expose()
    )))
}

/// What a listing shows of `key`: the prefix, an ellipsis, and the last four
/// characters — enough to tell two keys apart, worthless to present.
fn prefix_tail(key: &str) -> String {
    let tail = &key[key.len().saturating_sub(4)..];

    format!("{KEY_PREFIX}…{tail}")
}

/// The user's live API keys, oldest first, inside the caller's transaction —
/// what `session list` appends after the sessions, and what `session drop`
/// matches an id against.
pub(super) fn live_keys_in(
    transaction: &Transaction<'_>,
    user: &UserId,
) -> Result<Vec<ApiKeyRecord>> {
    let mut statement = transaction
        .prepare(
            "SELECT key_id, spaceport_app, role, prefix_tail, created_at, expires_at
             FROM api_keys WHERE user_id = ?1 ORDER BY created_at, key_id",
        )
        .context("preparing the api key listing query")?;
    let rows = statement
        .query_map(rusqlite::params![user.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .context("listing the api keys")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("listing the api keys")?;

    Ok(rows
        .into_iter()
        .filter(|(.., expires_at)| !is_past(expires_at))
        .filter_map(
            |(id, app, role, prefix_tail, created_at, expires_at)| match id.parse() {
                Ok(id) => Some(ApiKeyRecord {
                    id,
                    app,
                    role,
                    prefix_tail,
                    created_at,
                    expires_at,
                }),
                Err(error) => {
                    tracing::warn!(%error, "skipping a stored api key this build cannot read");
                    None
                }
            },
        )
        .collect())
}

/// Delete one key by id, inside the caller's transaction — `session drop`'s
/// half of this table, beside the sessions it drops in the same commit.
pub(super) fn remove_key_in(transaction: &Transaction<'_>, key: &ApiKeyId) -> Result<()> {
    transaction
        .execute(
            "DELETE FROM api_keys WHERE key_id = ?1",
            rusqlite::params![key.as_str()],
        )
        .context("revoking an api key")?;

    Ok(())
}

/// Delete every API key of `user`, inside the caller's transaction — the
/// offboarding cascade's tenant for this table, run on suspend and drop
/// alike: the spec has both kill keys, and resume resurrects none.
pub(super) fn remove_users_in(transaction: &Transaction<'_>, user: &UserId) -> Result<()> {
    transaction
        .execute(
            "DELETE FROM api_keys WHERE user_id = ?1",
            rusqlite::params![user.as_str()],
        )
        .context("removing an offboarded user's api keys")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthLogRepository, UserRepository, UserSlug};
    use crate::state::Db;

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

    fn grants(s: &str) -> RoleAtApp {
        s.parse().unwrap()
    }

    fn blog() -> AppId {
        "blog".parse().unwrap()
    }

    async fn mint(sessions: &SessionRepository, user: &str) -> MintedApiKey {
        sessions
            .mint_api_key(
                &by_slug(user),
                &grants("reader@blog"),
                DEFAULT_API_KEY_LIFETIME,
            )
            .await
            .unwrap()
    }

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

    async fn expire_keys(sessions: &SessionRepository) {
        sessions
            .db
            .call(move |connection| {
                connection
                    .execute(
                        "UPDATE api_keys SET expires_at = '2000-01-01T00:00:00Z'",
                        [],
                    )
                    .context("aging a key")?;

                Ok(())
            })
            .await
            .unwrap();
    }

    #[test]
    fn an_api_key_id_parses_and_folds_like_it_prints() {
        let id = ApiKeyId::generate().unwrap();
        assert_eq!(id.to_string().parse::<ApiKeyId>().unwrap(), id);

        let folded: ApiKeyId = "0123456789ABCDEF".parse().unwrap();
        assert_eq!(folded.as_str(), "0123456789abcdef");

        for broken in ["", "0123", "0123456789abcdeg", "0123456789abcdef0"] {
            assert!(broken.parse::<ApiKeyId>().is_err(), "accepted `{broken}`");
        }
    }

    /// The one glimpse a listing will ever show: the prefix and the last four
    /// characters, and never the middle that makes the credential one.
    #[test]
    fn the_prefix_tail_shows_the_prefix_and_the_last_four_characters() {
        assert_eq!(prefix_tail("spk_abcdefwxyz"), "spk_…wxyz");
    }

    /// The mint is the once: the key starts with `spk_`, travels behind
    /// [`Secret`], and the listing afterwards shows the prefix-and-tail and
    /// nothing recoverable.
    #[tokio::test]
    async fn a_minted_key_is_spk_prefixed_and_listed_only_as_its_tail() {
        let (users, sessions, _) = repositories();
        users.create(&slug("ci-bot"), None, None).await.unwrap();

        let minted = mint(&sessions, "ci-bot").await;

        assert!(minted.key.expose().starts_with(KEY_PREFIX));
        assert!(!format!("{minted:?}").contains(minted.key.expose()));
        let (_, _, keys) = sessions.list(&by_slug("ci-bot")).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].id, minted.id);
        assert_eq!(keys[0].prefix_tail, minted.prefix_tail);
        assert_eq!(keys[0].role, "reader");
        assert_eq!(keys[0].app, "blog");
        // The tail is four characters plus the prefix, not the key.
        assert!(minted.key.expose().len() > minted.prefix_tail.len());
        assert!(!keys[0].prefix_tail.contains(&minted.key.expose()[4..20]));
    }

    /// One caller, one credential: two keys for the same role at the same app
    /// coexist, so revoking one machine's key rotates nobody else's.
    #[tokio::test]
    async fn duplicate_mints_for_one_role_at_one_app_coexist() {
        let (users, sessions, _) = repositories();
        users.create(&slug("ci-bot"), None, None).await.unwrap();

        let first = mint(&sessions, "ci-bot").await;
        let second = mint(&sessions, "ci-bot").await;

        assert_ne!(first.id, second.id);
        assert_ne!(first.key.expose(), second.key.expose());
        for key in [&first.key, &second.key] {
            assert!(
                sessions
                    .api_key_identity(key, &blog())
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(sessions.list(&by_slug("ci-bot")).await.unwrap().2.len(), 2);
    }

    /// The identity a key answers with is its own triple and nothing wider:
    /// the owning user as `sub`, the one role it grants — and only at the app
    /// it was minted for.
    #[tokio::test]
    async fn a_key_answers_with_its_user_and_role_at_its_app_only() {
        let (users, sessions, _) = repositories();
        let created = users.create(&slug("ci-bot"), None, None).await.unwrap();
        let minted = mint(&sessions, "ci-bot").await;

        let (user, role) = sessions
            .api_key_identity(&minted.key, &blog())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user, created.id);
        assert_eq!(role.as_str(), "reader");

        assert!(
            sessions
                .api_key_identity(&minted.key, &"wiki".parse().unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            sessions
                .api_key_identity(&Secret::new("spk_not-a-key"), &blog())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Expiry is enforced on use and swept on the next mint, the session
    /// tables' whole cleanup story.
    #[tokio::test]
    async fn an_expired_key_stops_answering_and_is_swept() {
        let (users, sessions, _) = repositories();
        users.create(&slug("ci-bot"), None, None).await.unwrap();
        let minted = mint(&sessions, "ci-bot").await;
        expire_keys(&sessions).await;

        assert!(
            sessions
                .api_key_identity(&minted.key, &blog())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            sessions
                .list(&by_slug("ci-bot"))
                .await
                .unwrap()
                .2
                .is_empty()
        );

        mint(&sessions, "ci-bot").await;
        assert_eq!(rows_in(&sessions, "api_keys").await, 1);
    }

    /// `session drop <user> <key-id>` revokes that key and nothing else.
    #[tokio::test]
    async fn dropping_a_key_by_id_revokes_it_and_spares_the_rest() {
        let (users, sessions, _) = repositories();
        users.create(&slug("ci-bot"), None, None).await.unwrap();
        let first = mint(&sessions, "ci-bot").await;
        let second = mint(&sessions, "ci-bot").await;

        let (_, dropped_sessions, dropped_keys) = sessions
            .drop_sessions(
                &by_slug("ci-bot"),
                Some(&first.id.as_str().parse().unwrap()),
            )
            .await
            .unwrap();

        assert!(dropped_sessions.is_empty());
        assert_eq!(dropped_keys.len(), 1);
        assert_eq!(dropped_keys[0].id, first.id);
        assert!(
            sessions
                .api_key_identity(&first.key, &blog())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            sessions
                .api_key_identity(&second.key, &blog())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// The spec's sentence for the bare drop: "all sessions and keys" — one
    /// command, both tables, one commit.
    #[tokio::test]
    async fn dropping_without_an_id_takes_sessions_and_keys_alike() {
        let (users, sessions, _) = repositories();
        users.create(&slug("ci-bot"), None, None).await.unwrap();
        let minted = sessions
            .mint_code(&by_slug("ci-bot"), crate::auth::DEFAULT_SESSION_LIFETIME)
            .await
            .unwrap();
        sessions.redeem(&minted.code).await.unwrap();
        mint(&sessions, "ci-bot").await;

        let (_, dropped_sessions, dropped_keys) = sessions
            .drop_sessions(&by_slug("ci-bot"), None)
            .await
            .unwrap();

        assert_eq!(dropped_sessions.len(), 1);
        assert_eq!(dropped_keys.len(), 1);
        assert_eq!(rows_in(&sessions, "sessions").await, 0);
        assert_eq!(rows_in(&sessions, "api_keys").await, 0);
    }

    /// An id that names neither a session nor a key is a refusal, not a quiet
    /// success — the operator typed it, and it did nothing.
    #[tokio::test]
    async fn dropping_an_id_that_names_nothing_says_so() {
        let (users, sessions, _) = repositories();
        users.create(&slug("ci-bot"), None, None).await.unwrap();
        mint(&sessions, "ci-bot").await;

        let ghost = "00000000000000aa".parse().unwrap();
        let error = sessions
            .drop_sessions(&by_slug("ci-bot"), Some(&ghost))
            .await
            .unwrap_err();

        assert!(matches!(error, SessionError::Nothing(_)), "{error}");
    }

    /// Suspend and drop are the immediate-offboarding levers, and both take
    /// the keys — and resume resurrects none, per the spec.
    #[tokio::test]
    async fn suspending_or_dropping_the_owner_kills_their_keys() {
        let (users, sessions, _) = repositories();
        users.create(&slug("ci-bot"), None, None).await.unwrap();
        let minted = mint(&sessions, "ci-bot").await;

        users.suspend(&by_slug("ci-bot")).await.unwrap();

        assert_eq!(rows_in(&sessions, "api_keys").await, 0);
        assert!(
            sessions
                .api_key_identity(&minted.key, &blog())
                .await
                .unwrap()
                .is_none()
        );

        users.resume(&by_slug("ci-bot")).await.unwrap();
        assert!(
            sessions
                .list(&by_slug("ci-bot"))
                .await
                .unwrap()
                .2
                .is_empty()
        );

        let again = mint(&sessions, "ci-bot").await;
        users.drop_user(&by_slug("ci-bot")).await.unwrap();
        assert_eq!(rows_in(&sessions, "api_keys").await, 0);
        assert!(
            sessions
                .api_key_identity(&again.key, &blog())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn minting_for_a_suspended_or_unknown_user_is_refused() {
        let (users, sessions, _) = repositories();
        users.create(&slug("ci-bot"), None, None).await.unwrap();
        users.suspend(&by_slug("ci-bot")).await.unwrap();

        let suspended = sessions
            .mint_api_key(
                &by_slug("ci-bot"),
                &grants("reader@blog"),
                DEFAULT_API_KEY_LIFETIME,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(suspended, SessionError::Suspended(_)),
            "{suspended}"
        );

        let ghost = sessions
            .mint_api_key(
                &by_slug("ghost"),
                &grants("reader@blog"),
                DEFAULT_API_KEY_LIFETIME,
            )
            .await
            .unwrap_err();
        assert!(matches!(ghost, SessionError::UnknownUser(_)), "{ghost}");
    }

    /// The log is the other half of every mutation: the mint and the revoke
    /// land as the operator's, naming the key by its handle and its tail and
    /// never by the credential.
    #[tokio::test]
    async fn mint_and_revoke_land_in_the_log_without_the_credential() {
        let (users, sessions, log) = repositories();
        let created = users.create(&slug("ci-bot"), None, None).await.unwrap();
        let minted = mint(&sessions, "ci-bot").await;
        sessions
            .drop_sessions(
                &by_slug("ci-bot"),
                Some(&minted.id.as_str().parse().unwrap()),
            )
            .await
            .unwrap();

        let entries = log.entries(None).await.unwrap();
        let kinds: Vec<&str> = entries.iter().map(|entry| entry.kind.as_str()).collect();
        assert_eq!(kinds, ["user.created", "key.minted", "key.revoked"]);

        let minted_entry = entries.iter().find(|e| e.kind == "key.minted").unwrap();
        assert_eq!(minted_entry.user.as_deref(), Some(created.id.as_str()));
        assert_eq!(minted_entry.origin, OPERATOR_ORIGIN);
        let detail = minted_entry.detail.as_deref().unwrap();
        assert!(detail.contains(minted.id.as_str()), "{detail}");
        assert!(detail.contains("role `reader` at app `blog`"), "{detail}");
        assert!(!detail.contains(minted.key.expose()), "{detail}");

        let revoked = entries.iter().find(|e| e.kind == "key.revoked").unwrap();
        assert_eq!(revoked.origin, OPERATOR_ORIGIN);
        assert!(
            revoked
                .detail
                .as_deref()
                .unwrap()
                .contains(minted.id.as_str())
        );
    }
}

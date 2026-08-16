//! App sessions, and the exchange nonces that mint them.
//!
//! An app session is a global session's shadow on one app's domain: minted by
//! the redirect exchange, carried in a cookie scoped to the app's own host,
//! and worthless the moment its parent goes. It exists because a cookie set on
//! `edge.hostname` never travels to `blog.example.com` — each gated domain
//! needs a credential of its own — and it is *derived* rather than
//! free-standing so there is exactly one thing to revoke: dropping the global
//! session, logging out, suspending or dropping the user all take every app
//! session along in the same transaction.
//!
//! The exchange nonce is the one-time code pattern again, at a shorter fuse: a
//! value minted on the edge hostname for a user the edge has just checked, and
//! redeemed exactly once on the app's domain to become the app session. It is
//! hashed in storage for the login codes' reason — the plaintext rides a
//! redirect URL through a browser's history, and the table must be worth less
//! than the URL — and it is pinned to the app it was minted for, so a nonce
//! lifted from one domain's history buys nothing on another.
//!
//! These methods live on [`SessionRepository`], in a file of their own only
//! for reading's sake: app sessions and exchange nonces are session tables,
//! redemption reads `sessions` and writes `app_sessions` in one transaction,
//! and a second repository over the same rows would be two owners of one
//! cascade. Same disciplines as the rest of [`crate::auth`]: mutations log
//! through `record_in` in their own transaction, expiries are swept by the
//! writes that grow the tables, and validity is answered by the database —
//! per-request DB reads included, until milestone 6's JWT cache relieves the
//! hot path.

use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, Transaction};
use tracing::info;

use super::log::{WEB_ORIGIN, record_in};
use super::session::{
    SessionRepository, generate_token, hash, is_past, stamp_after, sweep_expired_in,
};
use super::{SessionId, UserId};
use crate::app::AppId;
use crate::secret::Secret;
use crate::state::now;

/// How long an exchange nonce is good for. The nonce crosses exactly two
/// redirects in one browser, which is a second on a bad day; a minute is that
/// with room for a stalled phone, and anything longer is only a longer time a
/// URL copied out of a history works.
const NONCE_TTL: Duration = Duration::from_secs(60);

/// What redeeming a nonce hands the callback: the token to set as the app
/// cookie, and the expiry it inherited so the cookie's `Max-Age` can say so.
#[derive(Debug)]
pub struct FreshAppSession {
    /// The opaque token, behind [`Secret`]; the app-domain cookie is the only
    /// place it goes in the clear.
    pub token: Secret,
    /// When it dies — the parent session's own expiry, copied at mint, which
    /// is what "inherits its expiry" means concretely.
    pub expires_at: String,
}

/// One derived app session, as `session list` shows it under its parent. Like
/// [`super::SessionRecord`], no token and no hash: the listing must never be
/// the read that hands out a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSessionRecord {
    /// The app it opens, as text rather than [`AppId`] so a row written by a
    /// newer build still lists.
    pub app: String,
    pub created_at: String,
    pub expires_at: String,
}

impl SessionRepository {
    /// The live session `token` names, if any: who is signed in on the edge.
    ///
    /// What the exchange asks before anything else. The answer comes from the
    /// database on every call, deliberately — a session dropped over the
    /// operator socket must stop answering here in the same instant, and the
    /// caching that relieves this on the per-request hot path is milestone 6's
    /// JWT cache, not a shortcut taken now.
    pub async fn session_of(&self, token: &Secret) -> Result<Option<(SessionId, UserId)>> {
        let token_hash = hash(token.expose());

        self.db
            .call(move |connection| {
                let found: Option<(String, String, String)> = connection
                    .query_row(
                        "SELECT session_id, user_id, expires_at
                         FROM sessions WHERE token_hash = ?1",
                        rusqlite::params![token_hash],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()
                    .context("looking a session up by token")?;

                let Some((session, user, expires_at)) = found else {
                    return Ok(None);
                };
                if is_past(&expires_at) {
                    return Ok(None);
                }

                // A row this build cannot parse answers "nobody", the failing-
                // closed direction: an unreadable identity must not sign in.
                Ok(session.parse().ok().zip(user.parse().ok()))
            })
            .await
    }

    /// Mint a one-time nonce for `user` to redeem on `app`'s domain, bound to
    /// the `parent` session the exchange just validated.
    ///
    /// Nothing is logged here on purpose: the nonce is plumbing, and the event
    /// worth an auditor's time is the app session it becomes —
    /// `session.app_minted`, written by [`SessionRepository::redeem_nonce`] in
    /// the transaction that creates the row.
    pub async fn mint_nonce(
        &self,
        user: &UserId,
        app: &AppId,
        parent: &SessionId,
    ) -> Result<Secret> {
        // Randomness outside the lock, as every mint in this module does it.
        let nonce = generate_token()?;
        let nonce_hash = hash(nonce.expose());
        let user = user.clone();
        let app = app.clone();
        let parent = parent.clone();

        self.db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to mint an exchange nonce")?;

                sweep_expired_in(&transaction)?;
                transaction
                    .execute(
                        "INSERT INTO exchange_nonces
                             (nonce_hash, user_id, spaceport_app, parent_session,
                              created_at, expires_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        rusqlite::params![
                            nonce_hash,
                            user.as_str(),
                            app.as_str(),
                            parent.as_str(),
                            now(),
                            stamp_after(NONCE_TTL)
                        ],
                    )
                    .context("minting an exchange nonce")?;

                transaction.commit().context("committing an exchange nonce")
            })
            .await?;

        Ok(nonce)
    }

    /// Redeem `nonce` on `app`'s domain into an app session, or refuse.
    ///
    /// `None` is every refusal at once — unknown, expired, spent, minted for
    /// another app, or orphaned by a logout that beat it here — because the
    /// callback answers them all the same way: restart the exchange. A found
    /// nonce is deleted whatever else is true of it; presenting one *is*
    /// spending it, and a nonce that survived being shown to the wrong app
    /// would be a replay budget nobody granted.
    ///
    /// The parent session is re-read inside this transaction rather than
    /// trusted from the mint sixty seconds ago: a logout or an offboarding in
    /// between must win, or revocation would have a one-minute back door.
    pub async fn redeem_nonce(
        &self,
        nonce: &Secret,
        app: &AppId,
    ) -> Result<Option<FreshAppSession>> {
        let token = generate_token()?;
        let token_hash = hash(token.expose());
        let nonce_hash = hash(nonce.expose());
        let app = app.clone();
        let asked = app.clone();

        let minted = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to redeem an exchange nonce")?;

                sweep_expired_in(&transaction)?;

                let found: Option<(String, String, String, String)> = transaction
                    .query_row(
                        "SELECT user_id, spaceport_app, parent_session, expires_at
                         FROM exchange_nonces WHERE nonce_hash = ?1",
                        rusqlite::params![nonce_hash],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .optional()
                    .context("looking an exchange nonce up")?;

                let Some((user_id, minted_for, parent, expires_at)) = found else {
                    return Ok(None);
                };

                // Single use, before any judgement: the delete commits with
                // whatever answer follows, so there is no path on which the
                // nonce was seen and still exists.
                transaction
                    .execute(
                        "DELETE FROM exchange_nonces WHERE nonce_hash = ?1",
                        rusqlite::params![nonce_hash],
                    )
                    .context("spending an exchange nonce")?;

                if is_past(&expires_at) || minted_for != app.as_str() {
                    transaction
                        .commit()
                        .context("committing a refused exchange nonce")?;

                    return Ok(None);
                }

                // The parent as it stands *now*: gone or expired means the
                // access this nonce promised has been revoked since.
                let parent_expires: Option<String> = transaction
                    .query_row(
                        "SELECT expires_at FROM sessions WHERE session_id = ?1",
                        rusqlite::params![parent],
                        |row| row.get(0),
                    )
                    .optional()
                    .context("checking an exchange nonce's parent session")?;
                let Some(parent_expires) = parent_expires.filter(|at| !is_past(at)) else {
                    transaction
                        .commit()
                        .context("committing an orphaned exchange nonce")?;

                    return Ok(None);
                };

                let at = now();
                transaction
                    .execute(
                        "INSERT INTO app_sessions
                             (token_hash, user_id, spaceport_app, parent_session,
                              created_at, expires_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        rusqlite::params![
                            token_hash,
                            user_id,
                            app.as_str(),
                            parent,
                            at,
                            parent_expires
                        ],
                    )
                    .context("minting an app session")?;

                let user: Option<UserId> = user_id.parse().ok();
                record_in(
                    &transaction,
                    &at,
                    "session.app_minted",
                    user.as_ref(),
                    WEB_ORIGIN,
                    Some(&format!(
                        "app session for `{}` derived from session {parent}",
                        app
                    )),
                )?;

                transaction.commit().context("committing an app session")?;

                Ok(Some((user, parent_expires)))
            })
            .await?;

        match minted {
            None => Ok(None),
            Some((user, expires_at)) => {
                if let Some(user) = &user {
                    info!(%user, app = %asked, "app session minted");
                }

                Ok(Some(FreshAppSession { token, expires_at }))
            }
        }
    }

    /// Whether `token` is a live app session for `app` — the proxy's question,
    /// once per gated request.
    ///
    /// A database read per request, on purpose: the spec's staleness budget on
    /// the hot path is the milestone-6 JWT cache, and until that lands the
    /// database being the only authority is what makes a drop immediate. No
    /// parent join is needed here — every way a parent dies deletes these rows
    /// in the same commit, so the row's own existence and expiry answer.
    pub async fn app_session_lives(&self, token: &Secret, app: &AppId) -> Result<bool> {
        Ok(self.app_session_user(token, app).await?.is_some())
    }

    /// The user a live app session for `app` belongs to, or `None` for a token
    /// that names no live one — the same question as
    /// [`SessionRepository::app_session_lives`], answered with the identity
    /// the JWT's `sub` needs.
    ///
    /// This is the read the milestone-6 cache stands in front of: it runs once
    /// per cache miss rather than once per request, and the four minutes an
    /// entry then lives are the spec's whole staleness budget on the hot path.
    /// A stored user id this build cannot parse answers "nobody", the
    /// failing-closed direction: an unreadable identity must not sign in, and
    /// must certainly not be vouched for to an app.
    pub async fn app_session_user(&self, token: &Secret, app: &AppId) -> Result<Option<UserId>> {
        let token_hash = hash(token.expose());
        let app = app.clone();

        self.db
            .call(move |connection| {
                let found: Option<(String, String)> = connection
                    .query_row(
                        "SELECT user_id, expires_at FROM app_sessions
                         WHERE token_hash = ?1 AND spaceport_app = ?2",
                        rusqlite::params![token_hash, app.as_str()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .context("looking an app session up")?;

                Ok(found
                    .filter(|(_, expires_at)| !is_past(expires_at))
                    .and_then(|(user, _)| user.parse().ok()))
            })
            .await
    }
}

/// The live app sessions derived from `parent`, inside the caller's
/// transaction — what a listing hangs under each session row.
pub(super) fn derived_in(
    transaction: &Transaction<'_>,
    parent: &str,
) -> Result<Vec<AppSessionRecord>> {
    let mut statement = transaction
        .prepare(
            "SELECT spaceport_app, created_at, expires_at FROM app_sessions
             WHERE parent_session = ?1 ORDER BY created_at, spaceport_app",
        )
        .context("preparing the app session listing query")?;
    let rows = statement
        .query_map(rusqlite::params![parent], |row| {
            Ok(AppSessionRecord {
                app: row.get(0)?,
                created_at: row.get(1)?,
                expires_at: row.get(2)?,
            })
        })
        .context("listing the app sessions")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("listing the app sessions")?;

    Ok(rows
        .into_iter()
        .filter(|record| !is_past(&record.expires_at))
        .collect())
}

/// Delete every app session derived from the session `parent` names, inside
/// the caller's transaction.
///
/// A free function over a transaction for the cascades' reason everywhere in
/// this module tree: a parent that is gone while its derivatives still let
/// people in is precisely the state that must be uncommittable. Deleted, not
/// logged row by row — the parent's logout or drop entry is the record, as the
/// offboarding cascade already argues.
pub(super) fn remove_derived_in(transaction: &Transaction<'_>, parent: &str) -> Result<()> {
    transaction
        .execute(
            "DELETE FROM app_sessions WHERE parent_session = ?1",
            rusqlite::params![parent],
        )
        .context("removing a dropped session's app sessions")?;

    Ok(())
}

/// Delete every app session and pending exchange nonce of `user`, inside the
/// caller's transaction — the offboarding cascade's tenant for these tables.
pub(super) fn remove_users_in(transaction: &Transaction<'_>, user: &UserId) -> Result<()> {
    transaction
        .execute(
            "DELETE FROM app_sessions WHERE user_id = ?1",
            rusqlite::params![user.as_str()],
        )
        .context("removing an offboarded user's app sessions")?;
    transaction
        .execute(
            "DELETE FROM exchange_nonces WHERE user_id = ?1",
            rusqlite::params![user.as_str()],
        )
        .context("removing an offboarded user's exchange nonces")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        AuthLogRepository, DEFAULT_SESSION_LIFETIME, FreshSession, UserRef, UserRepository,
    };
    use crate::state::Db;

    fn repositories() -> (UserRepository, SessionRepository, AuthLogRepository) {
        let db = Db::in_memory().unwrap();

        (
            UserRepository::new(db.clone()),
            SessionRepository::new(db.clone()),
            AuthLogRepository::new(db),
        )
    }

    fn blog() -> AppId {
        "blog".parse().unwrap()
    }

    fn alice() -> UserRef {
        UserRef::Slug("alice".parse().unwrap())
    }

    /// A signed-in alice, the way the login page produces one.
    async fn signed_in(users: &UserRepository, sessions: &SessionRepository) -> FreshSession {
        users.create(&"alice".parse().unwrap(), None).await.unwrap();
        let minted = sessions
            .mint_code(&alice(), DEFAULT_SESSION_LIFETIME)
            .await
            .unwrap();

        sessions.redeem(&minted.code).await.unwrap()
    }

    /// The whole exchange, from a session the edge holds to a cookie the app
    /// domain sets.
    async fn app_session(sessions: &SessionRepository, fresh: &FreshSession) -> FreshAppSession {
        let (session, user) = sessions.session_of(&fresh.token).await.unwrap().unwrap();
        let nonce = sessions.mint_nonce(&user, &blog(), &session).await.unwrap();

        sessions
            .redeem_nonce(&nonce, &blog())
            .await
            .unwrap()
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

    async fn expire(sessions: &SessionRepository, table: &'static str) {
        sessions
            .db
            .call(move |connection| {
                connection
                    .execute(
                        &format!("UPDATE {table} SET expires_at = '2000-01-01T00:00:00Z'"),
                        [],
                    )
                    .context("aging a row")?;

                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_session_token_answers_who_is_signed_in() {
        let (users, sessions, _) = repositories();
        let fresh = signed_in(&users, &sessions).await;

        let (session, user) = sessions.session_of(&fresh.token).await.unwrap().unwrap();

        assert_eq!(session, fresh.id);
        assert_eq!(user, fresh.user);
        assert!(
            sessions
                .session_of(&Secret::new("not-a-token"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn an_expired_session_token_answers_nobody() {
        let (users, sessions, _) = repositories();
        let fresh = signed_in(&users, &sessions).await;
        expire(&sessions, "sessions").await;

        assert!(sessions.session_of(&fresh.token).await.unwrap().is_none());
    }

    /// The happy path, end to end: a nonce becomes an app session the proxy
    /// then accepts for that app, with the parent's expiry and a log entry.
    #[tokio::test]
    async fn a_nonce_redeems_into_an_app_session_the_proxy_accepts() {
        let (users, sessions, log) = repositories();
        let fresh = signed_in(&users, &sessions).await;

        let minted = app_session(&sessions, &fresh).await;

        // Expiry inherited from the parent, which is the spec's rule.
        assert_eq!(minted.expires_at, fresh.expires_at);
        assert!(
            sessions
                .app_session_lives(&minted.token, &blog())
                .await
                .unwrap()
        );
        // For that app and no other.
        assert!(
            !sessions
                .app_session_lives(&minted.token, &"wiki".parse().unwrap())
                .await
                .unwrap()
        );
        let entries = log.entries(None).await.unwrap();
        let mint = entries
            .iter()
            .find(|entry| entry.kind == "session.app_minted")
            .unwrap();
        assert_eq!(mint.user.as_deref(), Some(fresh.user.as_str()));
        assert_eq!(mint.origin, WEB_ORIGIN);
        assert!(mint.detail.as_deref().unwrap().contains("`blog`"));
    }

    #[tokio::test]
    async fn a_nonce_redeems_exactly_once() {
        let (users, sessions, _) = repositories();
        let fresh = signed_in(&users, &sessions).await;
        let (session, user) = sessions.session_of(&fresh.token).await.unwrap().unwrap();
        let nonce = sessions.mint_nonce(&user, &blog(), &session).await.unwrap();

        assert!(
            sessions
                .redeem_nonce(&nonce, &blog())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            sessions
                .redeem_nonce(&nonce, &blog())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn an_expired_nonce_is_refused() {
        let (users, sessions, _) = repositories();
        let fresh = signed_in(&users, &sessions).await;
        let (session, user) = sessions.session_of(&fresh.token).await.unwrap().unwrap();
        let nonce = sessions.mint_nonce(&user, &blog(), &session).await.unwrap();
        expire(&sessions, "exchange_nonces").await;

        assert!(
            sessions
                .redeem_nonce(&nonce, &blog())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A nonce minted for one app must buy nothing on another — and showing
    /// it to the wrong app spends it, so it cannot be walked from domain to
    /// domain until one answers.
    #[tokio::test]
    async fn a_nonce_for_another_app_is_refused_and_spent() {
        let (users, sessions, _) = repositories();
        let fresh = signed_in(&users, &sessions).await;
        let (session, user) = sessions.session_of(&fresh.token).await.unwrap().unwrap();
        let nonce = sessions.mint_nonce(&user, &blog(), &session).await.unwrap();

        let wiki: AppId = "wiki".parse().unwrap();
        assert!(
            sessions
                .redeem_nonce(&nonce, &wiki)
                .await
                .unwrap()
                .is_none()
        );
        // Spent: the right app is now refused too.
        assert!(
            sessions
                .redeem_nonce(&nonce, &blog())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A logout between mint and redeem wins: the nonce's promise was the
    /// session's, and the session is gone.
    #[tokio::test]
    async fn a_nonce_whose_parent_was_dropped_is_refused() {
        let (users, sessions, _) = repositories();
        let fresh = signed_in(&users, &sessions).await;
        let (session, user) = sessions.session_of(&fresh.token).await.unwrap().unwrap();
        let nonce = sessions.mint_nonce(&user, &blog(), &session).await.unwrap();

        sessions.logout(&fresh.token).await.unwrap();

        assert!(
            sessions
                .redeem_nonce(&nonce, &blog())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The spec's one-lever revocation: `/logout` drops the global session
    /// and every app session derived from it, in one commit.
    #[tokio::test]
    async fn logout_kills_the_derived_app_sessions() {
        let (users, sessions, _) = repositories();
        let fresh = signed_in(&users, &sessions).await;
        let minted = app_session(&sessions, &fresh).await;

        sessions.logout(&fresh.token).await.unwrap();

        assert!(
            !sessions
                .app_session_lives(&minted.token, &blog())
                .await
                .unwrap()
        );
        assert_eq!(rows_in(&sessions, "app_sessions").await, 0);
    }

    /// The operator's lever does the same: dropping a session over the socket
    /// takes its derivatives, and leaves another session's alone.
    #[tokio::test]
    async fn dropping_a_session_by_id_kills_its_derived_and_spares_the_rest() {
        let (users, sessions, _) = repositories();
        let first = signed_in(&users, &sessions).await;
        let first_app = app_session(&sessions, &first).await;
        let second = sessions
            .mint_code(&alice(), DEFAULT_SESSION_LIFETIME)
            .await
            .unwrap();
        let second = sessions.redeem(&second.code).await.unwrap();
        let second_app = app_session(&sessions, &second).await;

        sessions
            .drop_sessions(&alice(), Some(&first.id))
            .await
            .unwrap();

        assert!(
            !sessions
                .app_session_lives(&first_app.token, &blog())
                .await
                .unwrap()
        );
        assert!(
            sessions
                .app_session_lives(&second_app.token, &blog())
                .await
                .unwrap()
        );
    }

    /// Suspend and drop are the immediate-offboarding levers, and both sweep
    /// the derived tables with everything else.
    #[tokio::test]
    async fn suspending_or_dropping_the_user_kills_app_sessions_and_nonces() {
        let (users, sessions, _) = repositories();
        let fresh = signed_in(&users, &sessions).await;
        let minted = app_session(&sessions, &fresh).await;
        let (session, user) = sessions.session_of(&fresh.token).await.unwrap().unwrap();
        sessions.mint_nonce(&user, &blog(), &session).await.unwrap();

        users.suspend(&alice()).await.unwrap();

        assert!(
            !sessions
                .app_session_lives(&minted.token, &blog())
                .await
                .unwrap()
        );
        assert_eq!(rows_in(&sessions, "app_sessions").await, 0);
        assert_eq!(rows_in(&sessions, "exchange_nonces").await, 0);
    }

    /// The identity half of the proxy's question: the user an app session
    /// answers with is the JWT's `sub`, and only for the app the session was
    /// minted for.
    #[tokio::test]
    async fn an_app_session_answers_with_its_user() {
        let (users, sessions, _) = repositories();
        let fresh = signed_in(&users, &sessions).await;
        let minted = app_session(&sessions, &fresh).await;

        let user = sessions
            .app_session_user(&minted.token, &blog())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user, fresh.user);
        assert!(
            sessions
                .app_session_user(&minted.token, &"wiki".parse().unwrap())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The inherited expiry is enforced, not only reported: an app session
    /// aged past it stops answering, however untouched its row's app cookie.
    #[tokio::test]
    async fn an_expired_app_session_stops_answering() {
        let (users, sessions, _) = repositories();
        let fresh = signed_in(&users, &sessions).await;
        let minted = app_session(&sessions, &fresh).await;
        expire(&sessions, "app_sessions").await;

        assert!(
            !sessions
                .app_session_lives(&minted.token, &blog())
                .await
                .unwrap()
        );
    }

    /// The listing shows the shadow under the session that casts it, so an
    /// operator reading `session list` sees where a drop will reach.
    #[tokio::test]
    async fn the_listing_hangs_derived_sessions_under_their_parent() {
        let (users, sessions, _) = repositories();
        let fresh = signed_in(&users, &sessions).await;
        app_session(&sessions, &fresh).await;

        let (_, listed, _) = sessions.list(&alice()).await.unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].derived.len(), 1);
        assert_eq!(listed[0].derived[0].app, "blog");
        assert_eq!(listed[0].derived[0].expires_at, listed[0].expires_at);
    }
}

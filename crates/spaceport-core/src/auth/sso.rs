//! What an SSO login *is*, once the OAuth choreography is over: one
//! transaction that turns "GitHub says this person is octocat, in these orgs
//! and on these teams" into a spaceport user with a session and exactly the
//! mapped entitlements the rules say.
//!
//! The edge handler that calls this has already done everything network-shaped
//! — the state nonce, the code exchange, the `/user` reads — and hands over
//! plain data. Everything here happens inside a single database transaction on
//! purpose: the identity snapshot, the entitlement re-sync, the session and
//! every log entry commit together or not at all, because a login whose
//! snapshot landed but whose entitlements did not would be a user `mapping
//! test` and the gate disagree about. The one thing that cannot live in the
//! transaction is the JWT cache purge, which follows the commit under the same
//! "commit, then purge" discipline every other revocation lever keeps.
//!
//! Resolution order is the spec's, written down once: a stored identity for
//! (connection, external id) wins — a returning login is the same user even if
//! every email changed — then an exact match on a GitHub-*verified* email, and
//! only then a fresh `github:<login>` user. Linking by unverified email is the
//! attack this module exists to refuse: anybody can type anybody's address
//! into their GitHub settings, and only the verified flag says GitHub checked.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use rusqlite::{OptionalExtension, Transaction};
use tracing::info;

use super::jwt::JwtCache;
use super::log::record_in;
use super::mapping::{self, Attributes, MappingRecord, evaluate};
use super::repository::{find, record};
use super::session::{
    DEFAULT_SESSION_LIFETIME, FreshSession, SessionId, generate_token, hash, short_handle,
    stamp_after, sweep_expired_in,
};
use super::{UserId, UserRecord, UserRef, UserSlug};
use crate::state::{Db, now};

/// Everything the callback learned from the IdP, as plain data.
///
/// A struct rather than six arguments, because five of them are strings and a
/// call site that swapped two would compile.
#[derive(Debug)]
pub struct SsoLogin {
    /// The connection slug the login arrived through — the auth log's origin
    /// for everything this login writes, per the spec's "which IdP".
    pub connection: String,
    /// The IdP's stable id for the account, as text.
    pub external_id: String,
    /// The renameable handle beside it, which also names an auto-created user.
    pub external_login: String,
    /// The addresses GitHub asserts as verified, in linking preference order —
    /// the primary address first, so the one a person actually reads is the
    /// one a fresh user record stores.
    pub verified_emails: Vec<String>,
    /// The snapshot [`evaluate`] judges and `mapping test` later replays.
    pub attributes: Attributes,
}

/// How a login ended.
#[derive(Debug)]
pub enum SsoOutcome {
    /// The session to set as the cookie, exactly as a one-time-code redemption
    /// hands one back.
    SignedIn(FreshSession),
    /// The account resolved to a suspended user, so no session was minted and
    /// the refusal is already in the log. Carries the record so the page can
    /// say whose door is closed — the person is looking at their own account.
    Suspended(UserRecord),
}

/// What the transaction closure hands back, before the pre-minted secrets are
/// folded in.
enum Inner {
    Suspended(UserRecord),
    SignedIn {
        user: UserId,
        expires_at: String,
        /// Whether the re-sync changed the entitlement slate — the purge
        /// trigger, kept out of [`SsoOutcome`] because it is this module's
        /// business and nobody else's.
        changed: bool,
    },
}

/// The login transaction, over the state database.
#[derive(Clone)]
pub struct SsoRepository {
    db: Db,
    /// The JWT cache the edge mints into. A re-sync can *narrow* access — a
    /// rule that no longer matches takes its entitlements with it — and a
    /// cached JWT must not outlive that by more than the spec's four minutes,
    /// so a login whose sync changed anything purges after its commit. A login
    /// that changed nothing purges nothing.
    jwt_cache: Arc<JwtCache>,
}

impl SsoRepository {
    pub fn new(db: Db) -> Self {
        Self::with_jwt_cache(db, Arc::new(JwtCache::new()))
    }

    /// The constructor the daemon uses: the one process-wide cache, so a login
    /// that narrowed somebody's slate empties exactly the entries the edge
    /// would serve next.
    pub fn with_jwt_cache(db: Db, jwt_cache: Arc<JwtCache>) -> Self {
        Self { db, jwt_cache }
    }

    /// Land one SSO login: resolve or create the user, record the identity
    /// snapshot, re-sync the mapped entitlements, mint the 12h session — one
    /// commit.
    ///
    /// Everything random is minted out here before the transaction opens, as
    /// every mint in this module tree does: randomness has no business inside
    /// a database lock. That includes the *fallback* slug — `github:<login>`
    /// plus a short random suffix — minted whether or not it is needed,
    /// because whether it is needed is only known inside the lock.
    pub async fn login(&self, login: SsoLogin) -> Result<SsoOutcome> {
        let id = SessionId::generate()?;
        let token = generate_token()?;
        let token_hash = hash(token.expose());
        let fresh_user = UserId::generate()?;
        let minted_id = id.clone();

        // The slug an auto-created user gets, held to the slug grammar before
        // any row exists: a login GitHub admits that the grammar refuses would
        // be a bug worth failing loudly over, not a user half-made.
        let slug: UserSlug = format!("github:{}", login.external_login.to_ascii_lowercase())
            .parse()
            .map_err(|error| anyhow!("{error:#}"))
            .with_context(|| {
                format!(
                    "turning the github login `{}` into a user slug",
                    login.external_login
                )
            })?;
        // Four hex characters of suffix: enough to step around a taken slug,
        // short enough that the result still reads as the login it came from.
        let suffixed: UserSlug = format!("{slug}-{}", &short_handle()?[..4])
            .parse()
            .map_err(|error| anyhow!("{error:#}"))
            .context("suffixing a colliding user slug")?;

        let outcome = self
            .db
            .call(move |connection| {
                let transaction = connection.transaction().context("beginning an sso login")?;

                sweep_expired_in(&transaction)?;

                let at = now();
                let user = match resolve(&transaction, &login)? {
                    Some(user) => user,
                    None => create(&transaction, &login, &fresh_user, &slug, &suffixed, &at)?,
                };

                // The suspension gate, after resolution and before anything is
                // written about this user: a suspended user's snapshot must
                // not move either, because resume restores the state suspend
                // froze. Logged as a failed login with the connection as its
                // origin — the auditor's question is "who kept knocking".
                if user.suspended {
                    record_in(
                        &transaction,
                        &at,
                        "login.failed",
                        Some(&user.id),
                        &login.connection,
                        Some(&format!(
                            "sso login as `{}` refused: user `{}` is suspended",
                            login.external_login, user.slug
                        )),
                    )?;
                    transaction
                        .commit()
                        .context("committing a refused sso login")?;

                    return Ok(Inner::Suspended(user));
                }

                record_identity_in(&transaction, &user.id, &login, &at)?;
                let changed = resync_in(&transaction, &user.id, &login, &at)?;

                let expires_at = stamp_after(DEFAULT_SESSION_LIFETIME);
                transaction
                    .execute(
                        "INSERT INTO sessions
                             (session_id, user_id, token_hash, created_at, expires_at)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![
                            minted_id.as_str(),
                            user.id.as_str(),
                            token_hash,
                            at,
                            expires_at
                        ],
                    )
                    .context("minting an sso session")?;
                record_in(
                    &transaction,
                    &at,
                    "login.succeeded",
                    Some(&user.id),
                    &login.connection,
                    Some(&format!(
                        "session {minted_id} minted for `{}` ({})",
                        login.external_login, login.external_id
                    )),
                )?;

                transaction.commit().context("committing an sso login")?;

                Ok(Inner::SignedIn {
                    user: user.id,
                    expires_at,
                    changed,
                })
            })
            .await?;

        match outcome {
            Inner::Suspended(user) => {
                info!(user = %user.id, slug = %user.slug, "sso login refused: suspended");

                Ok(SsoOutcome::Suspended(user))
            }
            Inner::SignedIn {
                user,
                expires_at,
                changed,
            } => {
                // The re-sync may have taken something away, so the cached
                // JWTs still carrying it go too — after the commit, for the
                // usual reason: the cache must never be emptier than the
                // tables ahead of a rollback.
                if changed {
                    self.jwt_cache.purge_user(&user);
                }
                info!(%user, session = %id, "sso login succeeded");

                Ok(SsoOutcome::SignedIn(FreshSession {
                    id,
                    user,
                    token,
                    expires_at,
                }))
            }
        }
    }
}

/// Whom this login is about, if spaceport already knows: the identity link
/// first, an exact verified-email match second.
fn resolve(transaction: &Transaction<'_>, login: &SsoLogin) -> Result<Option<UserRecord>> {
    // A returning identity wins outright, whatever their emails say now: the
    // external id is the IdP's stable name for the account, and a person who
    // changed every address on it is still that person.
    let linked: Option<String> = transaction
        .query_row(
            "SELECT user_id FROM idp_identities WHERE connection = ?1 AND external_id = ?2",
            rusqlite::params![login.connection, login.external_id],
            |row| row.get(0),
        )
        .optional()
        .context("looking an sso identity up")?;
    if let Some(user) = linked {
        let user: UserId = user
            .parse()
            .map_err(|error| anyhow!("{error:#}"))
            .context("reading a stored identity's user id")?;
        if let Some(row) = find(transaction, &UserRef::Id(user))? {
            return Ok(Some(record(row)?));
        }
    }

    // Then a verified email, compared case-insensitively: RFC 5321 makes the
    // domain case-insensitive and receivers fold the local part in practice,
    // so `Alice@Example.com` typed by an operator and `alice@example.com`
    // asserted by GitHub are one mailbox — refusing to link them would strand
    // the user behind a capital letter nobody can see. Only *verified*
    // addresses are consulted; an unverified one is a string anybody can type
    // into their GitHub settings, and linking on it would hand out accounts.
    // Should a suspended and a live user somehow share the address, the live
    // one is preferred — matching the suspended one would refuse a login the
    // operator has no reason to expect refused.
    for email in &login.verified_emails {
        let matched = transaction
            .query_row(
                "SELECT user_id, user_slug, email, suspended, created_at
                 FROM users WHERE lower(email) = lower(?1)
                 ORDER BY suspended, user_slug LIMIT 1",
                rusqlite::params![email],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .context("looking a user up by verified email")?;
        if let Some(row) = matched {
            return Ok(Some(record(row)?));
        }
    }

    Ok(None)
}

/// Create the user this login is for, under `slug` — or `suffixed` when a
/// different account already holds it.
///
/// The collision case is real: `github:octocat` may already name the user a
/// *dropped-and-recreated* GitHub account once linked to, or an operator's own
/// deliberate creation. Resolution already said this login is nobody spaceport
/// knows, so taking the existing row over would be handing one person
/// another's entitlements — a suffix costs an ugly slug and nothing else. The
/// primary verified email rides onto the record exactly as `user create
/// --email` stores one, so the future email flow can reach this user too.
fn create(
    transaction: &Transaction<'_>,
    login: &SsoLogin,
    id: &UserId,
    slug: &UserSlug,
    suffixed: &UserSlug,
    at: &str,
) -> Result<UserRecord> {
    let taken: Option<i64> = transaction
        .query_row(
            "SELECT 1 FROM users WHERE user_slug = ?1",
            rusqlite::params![slug.as_str()],
            |row| row.get(0),
        )
        .optional()
        .context("checking whether an sso slug is free")?;
    let slug = match taken {
        None => slug,
        Some(_) => suffixed,
    };

    let email = login.verified_emails.first().cloned();
    transaction
        .execute(
            "INSERT INTO users (user_id, user_slug, email, suspended, created_at)
             VALUES (?1, ?2, ?3, 0, ?4)",
            rusqlite::params![id.as_str(), slug.as_str(), email, at],
        )
        .context("creating a user for an sso login")?;
    record_in(
        transaction,
        at,
        "user.created",
        Some(id),
        &login.connection,
        Some(&match &email {
            Some(email) => format!(
                "slug `{slug}`, email `{email}`, auto-created for github login `{}`",
                login.external_login
            ),
            None => format!(
                "slug `{slug}`, auto-created for github login `{}`",
                login.external_login
            ),
        }),
    )?;

    Ok(UserRecord {
        id: id.clone(),
        slug: slug.clone(),
        email,
        suspended: false,
        created_at: at.to_owned(),
    })
}

/// Replace the identity snapshot, inside the login's transaction.
///
/// The same delete-then-insert [`super::mapping::IdentityRepository::record`]
/// spells out, and for its reason: a re-login and a re-link are two different
/// uniqueness claims, and one `ON CONFLICT` clause can only catch one of them.
/// Written here rather than through that repository because it must share this
/// commit — a snapshot that landed without its re-sync is exactly the record
/// the module comment refuses to leave behind.
fn record_identity_in(
    transaction: &Transaction<'_>,
    user: &UserId,
    login: &SsoLogin,
    at: &str,
) -> Result<()> {
    let attributes =
        serde_json::to_string(&login.attributes).context("writing an identity's attributes")?;

    transaction
        .execute(
            "DELETE FROM idp_identities
             WHERE (user_id = ?1 AND connection = ?2)
                OR (connection = ?2 AND external_id = ?3)",
            rusqlite::params![user.as_str(), login.connection, login.external_id],
        )
        .context("replacing an sso identity")?;
    transaction
        .execute(
            "INSERT INTO idp_identities
                 (user_id, connection, external_id, external_login, attributes, last_login_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                user.as_str(),
                login.connection,
                login.external_id,
                login.external_login,
                attributes,
                at
            ],
        )
        .context("recording an sso identity")?;

    Ok(())
}

/// The spec's full re-sync: every rule of this connection is re-judged against
/// the fresh snapshot, entitlements whose rule no longer matches go, new
/// matches arrive — and manual grants (`mapped_rule` NULL) and other
/// connections' rules are never touched. Answers whether anything moved.
///
/// The changes land as one `mapping.synced` log entry rather than a fan of
/// grants and revokes, for the reason `mapping drop` gives: the rows moved as
/// a cascade of one login, and per-row entries nobody commanded would read as
/// commands that were never given.
fn resync_in(
    transaction: &Transaction<'_>,
    user: &UserId,
    login: &SsoLogin,
    at: &str,
) -> Result<bool> {
    // Every rule of this connection, read the way `mapping list` reads them —
    // a row this build cannot parse is skipped with a warning rather than
    // costing the login, exactly as it does not cost the listing.
    let mut statement = transaction
        .prepare(
            "SELECT rule_id, connection, spaceport_app, roles, conditions, created_at
             FROM mappings WHERE connection = ?1 ORDER BY created_at, rule_id",
        )
        .context("preparing the login re-sync's mapping query")?;
    let rows: Vec<mapping::MappingRow> = statement
        .query_map(rusqlite::params![login.connection], mapping::mapping_row)
        .context("reading the connection's mappings")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the connection's mappings")?;
    drop(statement);
    let mappings: Vec<MappingRecord> = rows
        .into_iter()
        .filter_map(|row| match mapping::mapping_record(row) {
            Ok(record) => Some(record),
            Err(error) => {
                tracing::warn!(%error, "skipping a stored mapping this build cannot read");
                None
            }
        })
        .collect();
    let this_connections_rules: HashSet<&str> = mappings
        .iter()
        .map(|mapping| mapping.rule_id.as_str())
        .collect();

    // What the snapshot earns: (app, role, rule) triples, judged by the very
    // function `mapping test` previews with.
    let matched = evaluate(&mappings, &login.connection, &login.attributes);
    let desired: Vec<(String, String, String)> = matched
        .iter()
        .flat_map(|rule| {
            rule.roles
                .iter()
                .map(|role| (rule.app.to_string(), role.to_string(), rule.rule_id.clone()))
        })
        .collect();

    // What the user holds now — all of it, because the insert below must not
    // collide with a manual grant or another connection's row on the same
    // (app, role) triple.
    let mut statement = transaction
        .prepare("SELECT spaceport_app, role, mapped_rule FROM entitlements WHERE user_id = ?1")
        .context("preparing the login re-sync's entitlement query")?;
    let held: Vec<(String, String, Option<String>)> = statement
        .query_map(rusqlite::params![user.as_str()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .context("reading the entitlements to re-sync")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the entitlements to re-sync")?;
    drop(statement);

    // Out with what no longer matches: only rows tagged by *this* connection's
    // rules are candidates — a manual grant has no rule and another IdP's rows
    // are that connection's next login's business.
    let mut removed = Vec::new();
    let mut occupied: HashSet<(String, String)> = HashSet::new();
    for (app, role, mapped) in &held {
        let stale = mapped.as_deref().is_some_and(|rule| {
            this_connections_rules.contains(rule)
                && !desired
                    .iter()
                    .any(|(a, r, ru)| a == app && r == role && ru == rule)
        });
        if stale {
            transaction
                .execute(
                    "DELETE FROM entitlements
                     WHERE user_id = ?1 AND spaceport_app = ?2 AND role = ?3",
                    rusqlite::params![user.as_str(), app, role],
                )
                .context("removing a mapped entitlement that no longer matches")?;
            removed.push(format!(
                "`{role}@{app}` (rule `{}`)",
                mapped.as_deref().unwrap_or_default()
            ));
        } else {
            occupied.insert((app.clone(), role.clone()));
        }
    }

    // In with what now matches, skipping any (app, role) already held — a
    // manual grant or an earlier rule's row keeps the triple, since the triple
    // is the whole identity and a second row would be the key spelled twice.
    let mut added = Vec::new();
    for (app, role, rule) in &desired {
        if occupied.contains(&(app.clone(), role.clone())) {
            continue;
        }
        transaction
            .execute(
                "INSERT INTO entitlements (user_id, spaceport_app, role, mapped_rule, granted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![user.as_str(), app, role, rule, at],
            )
            .context("recording a mapped entitlement")?;
        occupied.insert((app.clone(), role.clone()));
        added.push(format!("`{role}@{app}` (rule `{rule}`)"));
    }

    let changed = !added.is_empty() || !removed.is_empty();
    if changed {
        let mut detail = Vec::new();
        if !added.is_empty() {
            detail.push(format!("added {}", added.join(", ")));
        }
        if !removed.is_empty() {
            detail.push(format!("removed {}", removed.join(", ")));
        }
        record_in(
            transaction,
            at,
            "mapping.synced",
            Some(user),
            &login.connection,
            Some(&detail.join("; ")),
        )?;
    }

    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        AuthLogRepository, EntitlementRepository, IdentityRepository, MappingRepository,
        UserRepository,
    };

    fn repositories() -> (
        Db,
        UserRepository,
        SsoRepository,
        EntitlementRepository,
        AuthLogRepository,
    ) {
        let db = Db::in_memory().unwrap();

        (
            db.clone(),
            UserRepository::new(db.clone()),
            SsoRepository::new(db.clone()),
            EntitlementRepository::new(db.clone()),
            AuthLogRepository::new(db),
        )
    }

    /// Plant the connection mappings verify `--via` against.
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

    fn octocat(emails: &[&str], attrs: &[(&str, &[&str])]) -> SsoLogin {
        SsoLogin {
            connection: "spaceport-acme".to_owned(),
            external_id: "1001".to_owned(),
            external_login: "octocat".to_owned(),
            verified_emails: emails.iter().map(|email| (*email).to_owned()).collect(),
            attributes: attributes(attrs),
        }
    }

    fn signed_in(outcome: SsoOutcome) -> FreshSession {
        match outcome {
            SsoOutcome::SignedIn(fresh) => fresh,
            SsoOutcome::Suspended(user) => panic!("refused as suspended: {}", user.slug),
        }
    }

    /// The whole auto-create path in one pass: a stranger's login makes a
    /// `github:<login>` user carrying the primary verified email, and the
    /// creation is in the log with the connection as its origin.
    #[tokio::test]
    async fn a_stranger_becomes_a_prefixed_user_with_their_primary_email() {
        let (db, users, sso, _, log) = repositories();
        plant_connection(&db, "spaceport-acme").await;

        let fresh = signed_in(
            sso.login(octocat(
                &["octocat@acme.example"],
                &[("login", &["octocat"])],
            ))
            .await
            .unwrap(),
        );

        let listed = users.list(None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].slug.as_str(), "github:octocat");
        assert_eq!(listed[0].email.as_deref(), Some("octocat@acme.example"));
        assert_eq!(listed[0].id, fresh.user);
        let created = log
            .entries(None)
            .await
            .unwrap()
            .into_iter()
            .find(|entry| entry.kind == "user.created")
            .unwrap();
        assert_eq!(created.origin, "spaceport-acme");
        assert!(created.detail.unwrap().contains("auto-created"), "");
    }

    /// A verified email links to the operator-made user rather than creating a
    /// double — and case-insensitively, because two spellings of one mailbox
    /// are not two people.
    #[tokio::test]
    async fn a_verified_email_links_to_the_existing_user_whatever_its_case() {
        let (db, users, sso, _, _) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        let alice = users
            .create(&"alice".parse().unwrap(), Some("Octocat@Acme.example"))
            .await
            .unwrap();

        let fresh = signed_in(
            sso.login(octocat(&["octocat@acme.example"], &[]))
                .await
                .unwrap(),
        );

        assert_eq!(fresh.user, alice.id);
        assert_eq!(users.list(None).await.unwrap().len(), 1);
    }

    /// The returning-identity rule: once linked, the external id names the
    /// user even when every email moved elsewhere — a rename or an address
    /// change must not fork the account.
    #[tokio::test]
    async fn a_returning_identity_wins_over_a_changed_email() {
        let (db, users, sso, _, _) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        let carol = users
            .create(&"carol".parse().unwrap(), Some("carol@acme.example"))
            .await
            .unwrap();
        let identities = IdentityRepository::new(db.clone());
        identities
            .record(
                &carol.id,
                "spaceport-acme",
                "1001",
                "octocat",
                &attributes(&[]),
            )
            .await
            .unwrap();
        // A second user now holds the email GitHub asserts.
        users
            .create(&"eve".parse().unwrap(), Some("octocat@acme.example"))
            .await
            .unwrap();

        let fresh = signed_in(
            sso.login(octocat(&["octocat@acme.example"], &[]))
                .await
                .unwrap(),
        );

        assert_eq!(fresh.user, carol.id);
    }

    /// A slug already held by somebody else's account gets stepped around with
    /// a suffix, never taken over: resolution already said this login is a
    /// stranger, and inheriting the row would be inheriting its entitlements.
    #[tokio::test]
    async fn a_taken_slug_is_suffixed_rather_than_taken_over() {
        let (db, users, sso, _, _) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        let squatter = users
            .create(&"github:octocat".parse().unwrap(), None)
            .await
            .unwrap();

        let fresh = signed_in(sso.login(octocat(&[], &[])).await.unwrap());

        assert_ne!(fresh.user, squatter.id);
        let listed = users.list(None).await.unwrap();
        assert_eq!(listed.len(), 2);
        let minted = listed.iter().find(|user| user.id == fresh.user).unwrap();
        assert!(
            minted.slug.as_str().starts_with("github:octocat-"),
            "{}",
            minted.slug
        );
    }

    /// The full re-sync in one login: the rule that matches gains its row, the
    /// stale mapped row goes, and the manual grant stands untouched — with one
    /// `mapping.synced` entry instead of a fan of grants and revokes.
    #[tokio::test]
    async fn a_login_resyncs_mapped_entitlements_and_spares_manual_grants() {
        let (db, users, sso, entitlements, log) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        let mappings = MappingRepository::new(db.clone());
        let matches_now = mappings
            .add(
                "spaceport-acme",
                &"reader@blog".parse().unwrap(),
                &["org=acme-corp".parse().unwrap()],
            )
            .await
            .unwrap();
        let no_longer = mappings
            .add(
                "spaceport-acme",
                &"writer@wiki".parse().unwrap(),
                &["team=authors".parse().unwrap()],
            )
            .await
            .unwrap();
        let alice = users
            .create(&"alice".parse().unwrap(), Some("octocat@acme.example"))
            .await
            .unwrap();
        entitlements
            .grant(
                &UserRef::Slug("alice".parse().unwrap()),
                &"editor@blog".parse().unwrap(),
            )
            .await
            .unwrap();
        // A mapped row from the rule that will stop matching, as an earlier
        // login would have written it.
        let planted = (alice.id.to_string(), no_longer.rule_id.clone());
        db.call(move |connection| {
            connection
                .execute(
                    "INSERT INTO entitlements
                         (user_id, spaceport_app, role, mapped_rule, granted_at)
                     VALUES (?1, 'wiki', 'writer', ?2, '2026-01-01T00:00:00Z')",
                    rusqlite::params![planted.0, planted.1],
                )
                .map(|_| ())
                .map_err(anyhow::Error::from)
        })
        .await
        .unwrap();

        signed_in(
            sso.login(octocat(
                &["octocat@acme.example"],
                &[("org", &["acme-corp"]), ("team", &["review"])],
            ))
            .await
            .unwrap(),
        );

        let (_, held) = entitlements
            .audit(&UserRef::Id(alice.id.clone()))
            .await
            .unwrap();
        let spelled: Vec<(String, Option<String>)> = held
            .iter()
            .map(|entitlement| {
                (
                    format!("{}@{}", entitlement.role, entitlement.app),
                    entitlement.mapped_rule.clone(),
                )
            })
            .collect();
        assert!(
            spelled.contains(&("reader@blog".to_owned(), Some(matches_now.rule_id.clone()))),
            "{spelled:?}"
        );
        assert!(
            spelled.contains(&("editor@blog".to_owned(), None)),
            "{spelled:?}"
        );
        assert!(
            !spelled.iter().any(|(grant, _)| grant == "writer@wiki"),
            "{spelled:?}"
        );
        let kinds: Vec<String> = log
            .entries(None)
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.kind)
            .collect();
        assert!(kinds.contains(&"mapping.synced".to_owned()), "{kinds:?}");
        assert!(
            !kinds.contains(&"entitlement.revoked".to_owned()),
            "{kinds:?}"
        );
    }

    /// A second identical login changes nothing and says so: no second user,
    /// no entitlement churn, and no `mapping.synced` entry for a sync that
    /// moved nothing.
    #[tokio::test]
    async fn a_repeat_login_writes_no_sync_entry_when_nothing_moved() {
        let (db, users, sso, _, log) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        let mappings = MappingRepository::new(db.clone());
        mappings
            .add(
                "spaceport-acme",
                &"reader@blog".parse().unwrap(),
                &["org=acme-corp".parse().unwrap()],
            )
            .await
            .unwrap();

        signed_in(
            sso.login(octocat(&[], &[("org", &["acme-corp"])]))
                .await
                .unwrap(),
        );
        signed_in(
            sso.login(octocat(&[], &[("org", &["acme-corp"])]))
                .await
                .unwrap(),
        );

        assert_eq!(users.list(None).await.unwrap().len(), 1);
        let synced = log
            .entries(None)
            .await
            .unwrap()
            .into_iter()
            .filter(|entry| entry.kind == "mapping.synced")
            .count();
        assert_eq!(synced, 1);
    }

    /// The suspension gate: no session, no snapshot movement, and a
    /// `login.failed` entry naming the connection as its origin.
    #[tokio::test]
    async fn a_suspended_users_login_is_refused_and_logged() {
        let (db, users, sso, _, log) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        users
            .create(&"alice".parse().unwrap(), Some("octocat@acme.example"))
            .await
            .unwrap();
        users
            .suspend(&UserRef::Slug("alice".parse().unwrap()))
            .await
            .unwrap();

        let outcome = sso
            .login(octocat(&["octocat@acme.example"], &[]))
            .await
            .unwrap();

        assert!(matches!(outcome, SsoOutcome::Suspended(_)), "signed in");
        let failed = log
            .entries(None)
            .await
            .unwrap()
            .into_iter()
            .find(|entry| entry.kind == "login.failed")
            .unwrap();
        assert_eq!(failed.origin, "spaceport-acme");
        assert!(failed.detail.unwrap().contains("suspended"), "");
        // And no identity was written for them.
        let identities = IdentityRepository::new(db);
        let alice = &users.list(None).await.unwrap()[0];
        assert!(identities.for_user(&alice.id).await.unwrap().is_empty());
    }
}

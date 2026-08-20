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
//! Resolution is the spec's, and it is one rule rather than a ladder: a stored
//! identity for (connection, external id) names the user, and a login with no
//! stored identity is a stranger who may become a fresh `github:<login>` user
//! if a mapping rule says so. Nothing else resolves anybody.
//!
//! What is deliberately *absent* here is linking by email, which this module
//! used to do and which the spec now forbids in as many words. A GitHub login
//! asserts one thing — that the person controls account `external_id` right
//! now. The addresses GitHub lists beside it are a claim about somebody else's
//! credential: the mailbox is the *email* connection's credential, proven there
//! by a code that has to arrive today. Accepting GitHub's `verified` flag in
//! its place accepted a stored assertion, made at some past moment and never
//! revalidated, as proof of present control — so anyone who had ever held an
//! address a spaceport user was recorded under could sign in as them, skipping
//! the one-time code and every limit around it. For the same reason a login
//! never *writes* `users.email`: minting the email connection's credential out
//! of a GitHub claim is the same confusion pointed the other way.

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
    /// GitHub confirmed who this is, and spaceport has neither an account for
    /// them nor a rule that would make one: no mapping of this connection
    /// matches the attributes the login arrived with. Nothing was written but
    /// the refusal itself, and there is no record to carry back — auto-creating
    /// here would leave a user, an identity snapshot, a session and a fan of
    /// log rows behind for somebody who could not have been entitled to
    /// anything anyway.
    Unmapped,
}

/// What the transaction closure hands back, before the pre-minted secrets are
/// folded in.
enum Inner {
    Suspended(UserRecord),
    Unmapped,
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

                // The judgement, made once and used twice: this connection's
                // rules read out of the table and evaluated against the
                // snapshot before anything is written. It gates auto-creation
                // below and it is the same verdict the re-sync applies further
                // down, because it is handed to `resync_in` rather than
                // recomputed there — two evaluations of the same slate could
                // only ever agree by luck.
                let mappings = connection_mappings(&transaction, &login.connection)?;
                let matched = evaluate(&mappings, &login.connection, &login.attributes);

                // The gate is on *creation* only, deliberately. A user resolved
                // by a stored identity or a verified email who currently
                // matches no rule still signs in with whatever slate they have:
                // operator-made accounts never match a rule at all, and a
                // member who temporarily fell out of an org must keep getting
                // through the door rather than losing their account to a
                // membership blip.
                let user = match resolve(&transaction, &login)? {
                    Some(user) => user,
                    // Nobody spaceport knows, and no rule that would make
                    // somebody of them: the login is refused before a single
                    // row is written about them. One audit entry is the whole
                    // trace it leaves, about no user because there is no user —
                    // `jwt.rs`'s `key.rotated` is the precedent for a userless
                    // entry. Returning here steps over the suspension gate
                    // below, which is right: suspension is a property of a
                    // resolved user, and there is none to be suspended.
                    None if matched.is_empty() => {
                        record_in(
                            &transaction,
                            &at,
                            "login.failed",
                            None,
                            &login.connection,
                            Some(&format!(
                                "sso login as `{}` ({}) refused: no mapping rule of this \
                                 connection matches the account",
                                login.external_login, login.external_id
                            )),
                        )?;
                        transaction
                            .commit()
                            .context("committing an unmapped sso login")?;

                        return Ok(Inner::Unmapped);
                    }
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
                let changed = resync_in(&transaction, &user.id, &login, &at, &mappings, &matched)?;

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
            Inner::Unmapped => {
                info!("sso login refused: no mapping rule matches the account");

                Ok(SsoOutcome::Unmapped)
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

/// Whom this login is about, if spaceport already knows: the stored identity
/// link, and nothing else.
///
/// One lookup rather than a ladder, because the login only ever proved one
/// thing. Everything else GitHub said — the handle, the organisations, the
/// addresses — is either a renameable label or a claim about a credential this
/// connection does not own, and none of it names a user. A person spaceport has
/// no identity row for is a stranger here even when the operator has an account
/// waiting for them under an address GitHub happens to list; the way that
/// account gets its GitHub identity is a deliberate binding made from a session
/// that is already authenticated, not a guess made during this one.
fn resolve(transaction: &Transaction<'_>, login: &SsoLogin) -> Result<Option<UserRecord>> {
    // Whatever their emails or handle say now: the external id is the IdP's
    // stable name for the account, and a person who changed every label on it
    // is still that person.
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

    Ok(None)
}

/// Create the user this login is for, under `slug` — or `suffixed` when a
/// different account already holds it.
///
/// The collision case is real: `github:octocat` may already name the user a
/// *dropped-and-recreated* GitHub account once linked to, or an operator's own
/// deliberate creation. Resolution already said this login is nobody spaceport
/// knows, so taking the existing row over would be handing one person
/// another's entitlements — a suffix costs an ugly slug and nothing else.
///
/// The row is created with no email, and that is the point rather than an
/// omission: `users.email` is what the email connection signs people in by, and
/// filling it from an address GitHub reported would hand this account a second
/// way in that spaceport never verified and cannot revoke by revoking anything
/// of GitHub's. An operator who wants this person to be able to sign in by
/// email sets `--email` themselves, having decided the address is theirs.
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

    transaction
        .execute(
            "INSERT INTO users (user_id, user_slug, email, suspended, created_at)
             VALUES (?1, ?2, NULL, 0, ?3)",
            rusqlite::params![id.as_str(), slug.as_str(), at],
        )
        .context("creating a user for an sso login")?;
    record_in(
        transaction,
        at,
        "user.created",
        Some(id),
        &login.connection,
        Some(&format!(
            "slug `{slug}`, auto-created for github login `{}`",
            login.external_login
        )),
    )?;

    Ok(UserRecord {
        id: id.clone(),
        slug: slug.clone(),
        email: None,
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
///
/// Re-linking is refused outright, and loudly. With resolution down to the
/// identity lookup this cannot be reached — a user resolved by (connection,
/// external id) holds that very row, and a freshly created one holds none — so
/// the check is an invariant rather than a branch anybody takes. It is written
/// anyway because of what the delete below would otherwise do if some later
/// path did reach it: silently move somebody else's GitHub account onto this
/// user, which is how an email-shaped resolution turned a one-off address into
/// standing access. A login is not the place to re-decide whose account this
/// is; that binding is deliberate, made from an authenticated session, and
/// anything else is a bug that should stop the transaction rather than commit.
fn record_identity_in(
    transaction: &Transaction<'_>,
    user: &UserId,
    login: &SsoLogin,
    at: &str,
) -> Result<()> {
    let held: Option<String> = transaction
        .query_row(
            "SELECT external_id FROM idp_identities WHERE user_id = ?1 AND connection = ?2",
            rusqlite::params![user.as_str(), login.connection],
            |row| row.get(0),
        )
        .optional()
        .context("checking which identity a user already holds on this connection")?;
    if let Some(held) = held
        && held != login.external_id
    {
        return Err(anyhow!(
            "refusing to re-link user `{user}` on connection `{}`: it already holds external id \
             `{held}` and this login carries `{}`",
            login.connection,
            login.external_id
        ));
    }

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

/// Every rule of one connection, read the way `mapping list` reads them.
///
/// A free function over the caller's transaction because the login needs this
/// slate twice over — once to decide whether an unknown account may become a
/// user at all, and once to re-sync whatever user it ends up being — and
/// reading the table twice inside one transaction would only invite the two
/// reads to disagree. A row this build cannot parse is skipped with a warning
/// rather than costing the login, exactly as it does not cost the listing: a
/// mapping written by some newer spaceport must not lock everybody out.
fn connection_mappings(
    transaction: &Transaction<'_>,
    connection: &str,
) -> Result<Vec<MappingRecord>> {
    let mut statement = transaction
        .prepare(
            "SELECT rule_id, connection, spaceport_app, roles, conditions, created_at
             FROM mappings WHERE connection = ?1 ORDER BY created_at, rule_id",
        )
        .context("preparing the login re-sync's mapping query")?;
    let rows: Vec<mapping::MappingRow> = statement
        .query_map(rusqlite::params![connection], mapping::mapping_row)
        .context("reading the connection's mappings")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the connection's mappings")?;
    drop(statement);

    Ok(rows
        .into_iter()
        .filter_map(|row| match mapping::mapping_record(row) {
            Ok(record) => Some(record),
            Err(error) => {
                tracing::warn!(%error, "skipping a stored mapping this build cannot read");
                None
            }
        })
        .collect())
}

/// The spec's full re-sync: every rule of this connection is re-judged against
/// the fresh snapshot, entitlements whose rule no longer matches go, new
/// matches arrive — and manual grants (`mapped_rule` NULL) and other
/// connections' rules are never touched. Answers whether anything moved.
///
/// The judgement arrives as an argument rather than being made here, and that
/// is the point: the login has already asked [`evaluate`] whether any rule
/// matches, because the answer decides whether an unknown account may become a
/// user at all, and handing that same `matched` slice down is what makes the
/// create-gate and the re-sync provably one judgement instead of two
/// evaluations that could drift apart the day either side grows a wrinkle.
/// `mappings` comes along for the same reason — it is the set the stale check
/// asks "was this row one of ours".
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
    mappings: &[MappingRecord],
    matched: &[&MappingRecord],
) -> Result<bool> {
    let this_connections_rules: HashSet<&str> = mappings
        .iter()
        .map(|mapping| mapping.rule_id.as_str())
        .collect();

    // What the snapshot earns: (app, role, rule) triples, from the verdict the
    // very function `mapping test` previews with already reached.
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
        AuthEvent, AuthLogRepository, EntitlementRepository, IdentityRepository, MappingRepository,
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

    fn octocat(attrs: &[(&str, &[&str])]) -> SsoLogin {
        SsoLogin {
            connection: "spaceport-acme".to_owned(),
            external_id: "1001".to_owned(),
            external_login: "octocat".to_owned(),
            attributes: attributes(attrs),
        }
    }

    /// Bind the octocat account to an existing user, as the deliberate linking
    /// step does — the only way an operator-made account is reachable by a
    /// GitHub login now that no address resolves anybody. Tests about what a
    /// *returning* login does start here.
    async fn link_octocat(db: &Db, user: &UserId) {
        IdentityRepository::new(db.clone())
            .record(user, "spaceport-acme", "1001", "octocat", &attributes(&[]))
            .await
            .unwrap();
    }

    fn signed_in(outcome: SsoOutcome) -> FreshSession {
        match outcome {
            SsoOutcome::SignedIn(fresh) => fresh,
            SsoOutcome::Suspended(user) => panic!("refused as suspended: {}", user.slug),
            SsoOutcome::Unmapped => panic!("refused as unmapped"),
        }
    }

    /// Plant one rule of `spaceport-acme` that the octocat login satisfies, so
    /// a test about something else than the create-gate gets past it.
    async fn plant_octocat_rule(db: &Db) {
        MappingRepository::new(db.clone())
            .add(
                "spaceport-acme",
                &"reader@blog".parse().unwrap(),
                &["login=octocat".parse().unwrap()],
            )
            .await
            .unwrap();
    }

    /// The whole auto-create path in one pass: a stranger's login makes a
    /// `github:<login>` user, and the creation is in the log with the
    /// connection as its origin. The record carries *no* email — the address
    /// is the email connection's credential and a GitHub login does not get to
    /// mint one, so an operator who wants this person signing in by code has
    /// to say so with `--email`.
    #[tokio::test]
    async fn a_stranger_becomes_a_prefixed_user_with_no_email_credential() {
        let (db, users, sso, _, log) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        plant_octocat_rule(&db).await;

        let fresh = signed_in(sso.login(octocat(&[("login", &["octocat"])])).await.unwrap());

        let listed = users.list(None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].slug.as_str(), "github:octocat");
        assert_eq!(listed[0].email, None);
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

    /// The credential boundary, from the side that used to be a hole: a GitHub
    /// login that arrives carrying an address an existing user is recorded
    /// under does *not* become that user. Whoever holds a mailbox proves it to
    /// the email connection, with a code, today — GitHub's word that somebody
    /// verified the address at some unrecoverable past moment is a claim about
    /// a credential this connection does not own. Here no rule matches the
    /// login either, so the stranger is refused outright rather than quietly
    /// inheriting alice's account and her manual grants.
    #[tokio::test]
    async fn a_verified_email_does_not_reach_the_user_recorded_under_it() {
        let (db, users, sso, _, _) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        let alice = users
            .create(&"alice".parse().unwrap(), Some("octocat@acme.example"))
            .await
            .unwrap();

        let outcome = sso.login(octocat(&[])).await.unwrap();

        assert!(matches!(outcome, SsoOutcome::Unmapped), "signed in");
        // Alice is untouched: still there, still hers, and no identity of
        // somebody else's GitHub account hanging off her.
        let listed = users.list(None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, alice.id);
        let identities = IdentityRepository::new(db);
        assert!(identities.for_user(&alice.id).await.unwrap().is_empty());
    }

    /// And the same address is no shortcut past the create-gate either: with a
    /// rule that does match, the login makes its *own* user rather than
    /// landing in the one holding the address.
    #[tokio::test]
    async fn a_verified_email_does_not_short_circuit_the_create_gate() {
        let (db, users, sso, _, _) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        plant_octocat_rule(&db).await;
        let alice = users
            .create(&"alice".parse().unwrap(), Some("octocat@acme.example"))
            .await
            .unwrap();

        let fresh = signed_in(sso.login(octocat(&[("login", &["octocat"])])).await.unwrap());

        assert_ne!(fresh.user, alice.id);
        assert_eq!(users.list(None).await.unwrap().len(), 2);
    }

    /// The returning-identity rule: once linked, the external id names the
    /// user even when every label around it moved — a rename or an address
    /// change must not fork the account. Eve holds the address this login
    /// would once have been resolved by, which is now simply not a question
    /// anybody asks.
    #[tokio::test]
    async fn a_returning_identity_names_the_user_whatever_the_labels_say() {
        let (db, users, sso, _, _) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        let carol = users
            .create(&"carol".parse().unwrap(), Some("carol@acme.example"))
            .await
            .unwrap();
        link_octocat(&db, &carol.id).await;
        users
            .create(&"eve".parse().unwrap(), Some("octocat@acme.example"))
            .await
            .unwrap();

        let fresh = signed_in(sso.login(octocat(&[])).await.unwrap());

        assert_eq!(fresh.user, carol.id);
    }

    /// A slug already held by somebody else's account gets stepped around with
    /// a suffix, never taken over: resolution already said this login is a
    /// stranger, and inheriting the row would be inheriting its entitlements.
    #[tokio::test]
    async fn a_taken_slug_is_suffixed_rather_than_taken_over() {
        let (db, users, sso, _, _) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        plant_octocat_rule(&db).await;
        let squatter = users
            .create(&"github:octocat".parse().unwrap(), None)
            .await
            .unwrap();

        let fresh = signed_in(sso.login(octocat(&[("login", &["octocat"])])).await.unwrap());

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
        let alice = users.create(&"alice".parse().unwrap(), None).await.unwrap();
        link_octocat(&db, &alice.id).await;
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
            sso.login(octocat(&[
                ("org", &["acme-corp"]),
                ("team", &["review"]),
            ]))
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

        signed_in(sso.login(octocat(&[("org", &["acme-corp"])])).await.unwrap());
        signed_in(sso.login(octocat(&[("org", &["acme-corp"])])).await.unwrap());

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
        let alice = users.create(&"alice".parse().unwrap(), None).await.unwrap();
        link_octocat(&db, &alice.id).await;
        users
            .suspend(&UserRef::Slug("alice".parse().unwrap()))
            .await
            .unwrap();

        let outcome = sso
            .login(octocat(&[("org", &["acme-corp"])]))
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
        // And their snapshot did not move: the login carried an `org` the
        // stored identity has never seen, and it still has not — resume must
        // restore exactly the state suspend froze.
        let identities = IdentityRepository::new(db);
        let held = identities.for_user(&alice.id).await.unwrap();
        assert_eq!(held.len(), 1);
        assert!(held[0].attributes.is_empty(), "{:?}", held[0].attributes);
    }

    /// The create-gate: a stranger no rule of the connection matches is refused
    /// outright and leaves nothing behind — no user, no snapshot, no session,
    /// and no `user.created` entry to read as an account that briefly existed.
    /// The single `login.failed` row is about no user at all, because at the
    /// moment of refusal there is none.
    #[tokio::test]
    async fn an_unmapped_stranger_is_refused_and_leaves_nothing_behind() {
        let (db, users, sso, _, log) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        let mappings = MappingRepository::new(db.clone());
        // A rule exists — it simply is not one this login satisfies, which is
        // the case worth testing: an empty table would pass for the wrong
        // reason.
        mappings
            .add(
                "spaceport-acme",
                &"reader@blog".parse().unwrap(),
                &["org=acme-corp".parse().unwrap()],
            )
            .await
            .unwrap();

        let outcome = sso
            .login(octocat(&[("org", &["some-other-org"])]))
            .await
            .unwrap();

        assert!(matches!(outcome, SsoOutcome::Unmapped), "not refused");
        assert!(users.list(None).await.unwrap().is_empty());
        let entries = log.entries(None).await.unwrap();
        assert!(
            !entries.iter().any(|entry| entry.kind == "user.created"),
            "{entries:?}"
        );
        assert!(
            !entries.iter().any(|entry| entry.kind == "login.succeeded"),
            "{entries:?}"
        );
        let failed: Vec<&AuthEvent> = entries
            .iter()
            .filter(|entry| entry.kind == "login.failed")
            .collect();
        assert_eq!(failed.len(), 1, "{entries:?}");
        assert_eq!(failed[0].origin, "spaceport-acme");
        assert_eq!(failed[0].user, None);
    }

    /// The guard against over-gating: the rule check stands in front of
    /// *creation* and nothing else. A user spaceport already knows — that is,
    /// one whose GitHub identity is on file — signs in with the slate they
    /// have even when no rule matches them at all, because operator-made
    /// accounts never match one and a member who fell out of an org for an
    /// afternoon must still get through the door.
    #[tokio::test]
    async fn a_linked_user_who_matches_no_rule_still_signs_in() {
        let (db, users, sso, _, _) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        let alice = users.create(&"alice".parse().unwrap(), None).await.unwrap();
        link_octocat(&db, &alice.id).await;

        let fresh = signed_in(sso.login(octocat(&[])).await.unwrap());

        assert_eq!(fresh.user, alice.id);
    }

    /// The re-link refusal, at its own level. No login can reach it — a user
    /// is only ever resolved by the very identity they hold — so it is tested
    /// against `record_identity_in` directly rather than through a `login`
    /// call that would have to be given a broken resolution first. That is the
    /// honest shape for an invariant: assert it where it is stated, so the day
    /// some future linking path calls in here, this says what it must not do.
    #[tokio::test]
    async fn recording_an_identity_refuses_to_rebind_a_user_who_holds_another() {
        let (db, users, _, _, _) = repositories();
        plant_connection(&db, "spaceport-acme").await;
        let alice = users.create(&"alice".parse().unwrap(), None).await.unwrap();
        link_octocat(&db, &alice.id).await;

        let alice_id = alice.id.clone();
        let refused = db
            .call(move |connection| {
                let transaction = connection.transaction()?;
                // Somebody else's GitHub account, arriving for alice.
                let mut login = octocat(&[]);
                login.external_id = "2002".to_owned();

                Ok(record_identity_in(
                    &transaction,
                    &alice_id,
                    &login,
                    "2026-01-01T00:00:00Z",
                )
                .is_err())
            })
            .await
            .unwrap();

        assert!(refused, "the re-link was allowed");
        // And the binding alice actually holds is untouched.
        let held = IdentityRepository::new(db)
            .for_user(&alice.id)
            .await
            .unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].external_id, "1001");
    }
}

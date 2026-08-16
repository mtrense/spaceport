//! The JWT contract to the hosted apps: the key that signs, the JWKS that
//! verifies, and the cache that keeps the hot path off the database.
//!
//! Spaceport terminates the session at the edge and vouches for the user to
//! the app as an `Authorization: Bearer <JWT>` — EdDSA over Ed25519, five
//! minutes of `exp`, `sub` the stable user id, `aud` the app id, and `roles`
//! the intersection of the user's entitlements with the roles the deployed
//! manifest declares. The app verifies against the JWKS this module serves at
//! `/.well-known/jwks.json` on spaceport's own hostname, applying the spec's
//! standard 60 seconds of clock-skew leeway; nothing spaceport runs ever
//! verifies one of these itself.
//!
//! The signing key is generated on first need and kept in the state database,
//! where every other key spaceport holds already lives — see migration 14 for
//! the argument. There is one current key, and rotation retires it rather than
//! replacing it: [`JwtSigner::rotate`] flips `current`, stamps `retired_at`,
//! and the JWKS keeps the retired row until every JWT it signed has expired.
//! `kid` is what tells a verifier holding both keys which one made a given
//! token. Rotation happens on the spec's ninety-day clock — checked lazily,
//! whenever the key is next needed — and on demand over the operator socket,
//! which is the compromise-response lever.
//!
//! The cache is the spec's staleness budget, whole: a JWT lives five minutes
//! and is cached for four, so a cached token always has at least a minute
//! left, and between purges the four minutes are the *only* window in which a
//! revoked user still reaches an app — every purge lever (session drop,
//! revoke, suspend, drop, a deploy that changes an app's roles) empties the
//! relevant entries in the same breath as the database write. It is in-memory
//! in the spaceport process because there is a single edge, which is what
//! makes a purge immediate rather than eventually consistent.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rusqlite::OptionalExtension;
use tokio_util::sync::CancellationToken;

use super::log::record_in;
use super::session::hash;
use super::{Role, UserId, uuid_v4};
use crate::app::AppId;
use crate::secret::Secret;
use crate::state::{Db, now};

/// How long a minted JWT claims to be good for. The spec's five minutes: long
/// enough that the four-minute cache below always hands out a token with at
/// least a minute left, short enough that revocation's worst case is minutes
/// and not sessions.
pub const JWT_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// How long a cached JWT is served before the gate re-mints. One minute less
/// than [`JWT_LIFETIME`], by the spec's design: a token straight out of the
/// cache is never closer than a minute to its `exp`, so an app verifying with
/// even zero leeway never sees a dead token that spaceport just vouched for.
pub const CACHE_TTL: Duration = Duration::from_secs(4 * 60);

/// How long a retired key stays in the JWKS after rotation flips away from it:
/// every JWT it signed, plus the verifier's 60 seconds of clock-skew leeway.
/// Past this horizon no honestly-issued token could still verify against it,
/// so the row is pruned by the next rotation rather than served forever.
const RETIRED_KEY_GRACE: Duration = Duration::from_secs(JWT_LIFETIME.as_secs() + 60);

/// How old the current key may grow before signing with it triggers a
/// rotation — the spec's ninety days. Checked lazily, on [`JwtSigner`] use,
/// rather than by a background task: a key that nothing asks to sign is a key
/// nobody presents tokens from, so "the next time it is needed" is exactly the
/// last moment rotation still matters — and a lazy check is one a test can
/// drive by backdating a row instead of waiting out a season.
pub const ROTATION_PERIOD: Duration = Duration::from_secs(90 * 24 * 3600);

/// The `iss` a spaceport at `hostname` puts in every JWT, which is also what
/// gated containers receive as `SPACEPORT_ISSUER`. One spelling for the three
/// places it appears — the claim, the env variable, and the base the JWKS URL
/// hangs off — with the https port beside the host when it is not 443, exactly
/// as every other URL spaceport builds about itself names it.
pub fn issuer(hostname: &str, https_port: u16) -> String {
    match https_port {
        443 => format!("https://{hostname}"),
        port => format!("https://{hostname}:{port}"),
    }
}

/// Where `issuer`'s JWKS is served: the RFC 8615 well-known path on the same
/// origin, which is what lets an app's middleware derive it from
/// `SPACEPORT_ISSUER` alone.
pub fn jwks_url(issuer: &str) -> String {
    format!("{issuer}/.well-known/jwks.json")
}

/// The Ed25519 key spaceport signs app JWTs with, over the state database.
///
/// The key is generated the first time anything needs it — a mint or a JWKS
/// read, whichever comes first — and persisted, so the `kid` an app pinned
/// survives every restart. Once loaded it is held in memory: the mint path
/// runs per request on a cache miss, and a database read per signature would
/// put the table on the hot path the cache exists to clear.
pub struct JwtSigner {
    db: Db,
    /// The current key once something has needed it. A `Mutex<Option<…>>` and
    /// not a `OnceLock`, because filling it is fallible and async — the slot
    /// is only written after the database transaction settled which key is
    /// current.
    current: Mutex<Option<std::sync::Arc<SigningKey>>>,
}

/// The loaded half of one `jwt_signing_keys` row: the parsed pair, ready to
/// sign, and the `kid` every token it makes carries.
///
/// Deliberately no `Debug` and no `Display` anywhere near this type: the pair
/// is private key material, and the [`Secret`] discipline for it is to never
/// exist as a printable value at all — the pkcs8 document goes from the
/// database column into [`Ed25519KeyPair::from_pkcs8`] and nowhere else.
pub struct SigningKey {
    kid: String,
    pair: Ed25519KeyPair,
    /// When the row was made, RFC 3339 — carried in memory so the ninety-day
    /// check costs a parse and a comparison, never a database read on the
    /// mint path.
    created_at: String,
}

impl SigningKey {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The raw 32-byte public key — the `x` of the OKP JWK, before encoding.
    pub fn public_key(&self) -> &[u8] {
        self.pair.public_key().as_ref()
    }
}

/// One `jwt_signing_keys` row as `auth key list` reports it: everything but
/// the key material, which no listing has any business showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyRecord {
    pub kid: String,
    pub current: bool,
    pub created_at: String,
    pub retired_at: Option<String>,
}

/// What a rotation did: the kid now signing, and the one it retired — absent
/// when there was nothing to retire, which only a manual rotate on a spaceport
/// that never signed can produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    pub kid: String,
    pub retired: Option<String>,
}

impl JwtSigner {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            current: Mutex::new(None),
        }
    }

    /// The current signing key, generating and persisting one if this
    /// spaceport has never signed before — and rotating it first when it has
    /// grown past [`ROTATION_PERIOD`], so every token minted through this
    /// method is signed by a key inside its ninety days.
    ///
    /// The keypair is generated *outside* the transaction — randomness has no
    /// business inside a database lock, as every mint in this module tree
    /// argues — and the transaction then re-checks for a current row before
    /// inserting, so two first-mints racing each other agree on one key and
    /// the loser's sixty-four random bytes are simply dropped.
    pub async fn signing_key(&self) -> Result<std::sync::Arc<SigningKey>> {
        let key = match self.loaded() {
            Some(key) => key,
            None => self.load_or_generate().await?,
        };
        if !rotation_due(&key.created_at) {
            return Ok(key);
        }

        // The clock, not an operator, ordered this one — the transaction
        // re-checks the age, so two overdue mints racing each other rotate
        // once between them and the loser signs with the winner's key.
        let (key, rotation) = self.rotate_inner(super::SYSTEM_ORIGIN, false).await?;
        if let Some(rotation) = &rotation {
            tracing::info!(
                kid = rotation.kid,
                retired = rotation.retired.as_deref().unwrap_or_default(),
                "rotated the jwt signing key on the ninety-day clock"
            );
        }

        Ok(key)
    }

    /// Retire the current signing key and mint a fresh one, unconditionally —
    /// the operator's lever, for the day a key is suspected compromised and
    /// ninety days is eighty-nine too many. `origin` lands in the auth event
    /// log's ORIGIN column: [`super::OPERATOR_ORIGIN`] from the socket, where
    /// the automatic path writes [`super::SYSTEM_ORIGIN`].
    ///
    /// Nothing is purged: JWTs signed by the retired key stay valid until
    /// their own `exp`, which is the whole point of keeping the key in the
    /// JWKS through [`RETIRED_KEY_GRACE`] — and the [`JwtCache`] keeps serving
    /// them for the same reason, since a cached token's old `kid` still names
    /// a key the JWKS serves. A compromise response that must also kill
    /// in-flight tokens is `session drop` / `suspend`, aimed at the users, not
    /// at the key.
    pub async fn rotate(&self, origin: &'static str) -> Result<Rotation> {
        let (_, rotation) = self.rotate_inner(origin, true).await?;

        // Forced, so the transaction always rotates and always reports.
        rotation.context("a forced rotation reported nothing rotated")
    }

    /// Every signing key the store holds, newest first — pruned rows excepted,
    /// which is what pruning means. The read behind `auth key list`.
    pub async fn keys(&self) -> Result<Vec<SigningKeyRecord>> {
        self.db
            .call(|connection| {
                let mut statement = connection
                    .prepare(
                        "SELECT kid, current, created_at, retired_at FROM jwt_signing_keys
                         ORDER BY kid DESC",
                    )
                    .context("preparing the signing key listing")?;
                let rows = statement
                    .query_map([], |row| {
                        Ok(SigningKeyRecord {
                            kid: row.get(0)?,
                            current: row.get::<_, i64>(1)? != 0,
                            created_at: row.get(2)?,
                            retired_at: row.get(3)?,
                        })
                    })
                    .context("listing the signing keys")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("listing the signing keys")?;

                Ok(rows)
            })
            .await
    }

    /// The shared rotation transaction: retire whatever is current, mint a
    /// fresh key, prune what nothing can verify against anymore, and log it —
    /// one commit for all four, so no failure can leave the store between
    /// keys.
    ///
    /// `force` is the difference between the two triggers. The operator's
    /// rotate always rotates; the ninety-day path re-checks the current row's
    /// age *inside* the transaction, because the age it saw in memory may be a
    /// race behind another task's rotation — the loser then keeps the winner's
    /// fresh key and reports no rotation of its own.
    async fn rotate_inner(
        &self,
        origin: &'static str,
        force: bool,
    ) -> Result<(std::sync::Arc<SigningKey>, Option<Rotation>)> {
        let rng = ring::rand::SystemRandom::new();
        let fresh = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow!("this host would not generate a signing key"))?;
        let fresh_pkcs8 = Secret::new(STANDARD.encode(fresh.as_ref()));
        let fresh_public = Ed25519KeyPair::from_pkcs8(fresh.as_ref())
            .map_err(|error| anyhow!("{error}"))
            .context("reading the signing key just generated")?;
        let fresh_public = URL_SAFE_NO_PAD.encode(fresh_public.public_key().as_ref());

        let (kid, pkcs8, created_at, rotation) = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to rotate the signing key")?;

                let current: Option<(String, String, String)> = transaction
                    .query_row(
                        "SELECT kid, pkcs8, created_at FROM jwt_signing_keys WHERE current = 1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()
                    .context("looking the current signing key up")?;

                // The race the ninety-day path can lose: another task rotated
                // between the in-memory age check and this lock. Its key is
                // young; keep it and rotate nothing.
                if !force
                    && let Some((kid, pkcs8, created_at)) = &current
                    && !rotation_due(created_at)
                {
                    return Ok((kid.clone(), Secret::new(pkcs8.clone()), created_at.clone(), None));
                }

                let at = now();
                let retired = current.as_ref().map(|(kid, ..)| kid.clone());
                transaction
                    .execute(
                        "UPDATE jwt_signing_keys SET current = 0, retired_at = ?1
                         WHERE current = 1",
                        rusqlite::params![at],
                    )
                    .context("retiring the signing key")?;
                prune_retired_in(&transaction)?;

                let kid = fresh_kid(&transaction, &at)?;
                transaction
                    .execute(
                        "INSERT INTO jwt_signing_keys
                             (kid, pkcs8, public_key, current, created_at)
                         VALUES (?1, ?2, ?3, 1, ?4)",
                        rusqlite::params![kid, fresh_pkcs8.expose(), fresh_public, at],
                    )
                    .context("persisting a fresh signing key")?;

                // About no user, deliberately: the key vouches for everybody,
                // and the origin is what tells an auditor whether an operator
                // ordered this or the calendar did.
                let detail = match &retired {
                    Some(retired) => format!(
                        "signing key {kid} minted; {retired} retired — the jwks serves it until every jwt it signed has expired"
                    ),
                    None => format!("signing key {kid} minted; nothing to retire"),
                };
                record_in(&transaction, &at, "key.rotated", None, origin, Some(&detail))?;

                transaction.commit().context("committing a key rotation")?;
                tracing::info!(kid, origin, "rotated the jwt signing key");

                Ok((
                    kid.clone(),
                    fresh_pkcs8,
                    at,
                    Some(Rotation { kid, retired }),
                ))
            })
            .await?;

        let key = std::sync::Arc::new(parse_key(kid, pkcs8, created_at)?);
        // Whichever task wrote last, both hold a key the store calls current
        // or called current a moment ago — and a moment-ago key still verifies
        // through the JWKS, so last-write-wins costs a re-sign at worst.
        *self.slot() = Some(key.clone());

        Ok((key, rotation))
    }

    /// The current key off the database, minting a first one when the table
    /// has none — the cold half of [`JwtSigner::signing_key`], split out so
    /// the hot path is one mutex peek.
    async fn load_or_generate(&self) -> Result<std::sync::Arc<SigningKey>> {
        let rng = ring::rand::SystemRandom::new();
        let fresh = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow!("this host would not generate a signing key"))?;
        let fresh_pkcs8 = Secret::new(STANDARD.encode(fresh.as_ref()));
        let fresh_public = Ed25519KeyPair::from_pkcs8(fresh.as_ref())
            .map_err(|error| anyhow!("{error}"))
            .context("reading the signing key just generated")?;
        let fresh_public = URL_SAFE_NO_PAD.encode(fresh_public.public_key().as_ref());

        let (kid, pkcs8, created_at) = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to settle the signing key")?;

                // Somebody else's first mint may have won the race between the
                // in-memory check above and this transaction; theirs is the
                // key, or every restart would fork the JWKS.
                let existing: Option<(String, String, String)> = transaction
                    .query_row(
                        "SELECT kid, pkcs8, created_at FROM jwt_signing_keys WHERE current = 1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()
                    .context("looking the current signing key up")?;
                if let Some((kid, pkcs8, created_at)) = existing {
                    return Ok((kid, Secret::new(pkcs8), created_at));
                }

                let at = now();
                let kid = fresh_kid(&transaction, &at)?;
                transaction
                    .execute(
                        "INSERT INTO jwt_signing_keys
                             (kid, pkcs8, public_key, current, created_at)
                         VALUES (?1, ?2, ?3, 1, ?4)",
                        rusqlite::params![kid, fresh_pkcs8.expose(), fresh_public, at],
                    )
                    .context("persisting a fresh signing key")?;

                transaction.commit().context("committing a signing key")?;
                tracing::info!(kid, "generated the jwt signing key");

                Ok((kid, fresh_pkcs8, at))
            })
            .await?;

        let key = std::sync::Arc::new(parse_key(kid, pkcs8, created_at)?);

        let mut slot = self.slot();
        // A racing task may have loaded it first; either way both hold the
        // same persisted key, so last-write-wins costs nothing.
        *slot = Some(key.clone());

        Ok(key)
    }

    /// The JWKS document, as `/.well-known/jwks.json` serves it: every key a
    /// JWT in flight might still verify against.
    ///
    /// That is the current key and any retired one whose tokens have not all
    /// expired yet — `retired_at` within [`RETIRED_KEY_GRACE`]. Read from the
    /// database per request rather than cached beside the signing key, because
    /// this path is an app's startup and the `Cache-Control` on the response
    /// already bounds how often anybody asks.
    pub async fn jwks(&self) -> Result<String> {
        // Serving the JWKS is a need too: an app asking before the first JWT
        // was ever minted must get the key that first JWT will carry.
        self.signing_key().await?;

        let rows: Vec<(String, String)> = self
            .db
            .call(move |connection| {
                let mut statement = connection
                    .prepare(
                        "SELECT kid, public_key, retired_at FROM jwt_signing_keys
                         ORDER BY kid",
                    )
                    .context("preparing the jwks query")?;
                let rows = statement
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    })
                    .context("reading the signing keys")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("reading the signing keys")?;

                Ok(rows
                    .into_iter()
                    .filter(|(_, _, retired_at)| match retired_at {
                        None => true,
                        Some(at) => !retired_beyond_grace(at),
                    })
                    .map(|(kid, public_key, _)| (kid, public_key))
                    .collect())
            })
            .await?;

        let keys: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|(kid, x)| {
                // The OKP/Ed25519 JWK of RFC 8037: the raw public key as `x`,
                // base64url. `use` and `alg` are advisory and included because
                // they let a strict verifier skip nothing it should not.
                serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": x,
                    "kid": kid,
                    "use": "sig",
                    "alg": "EdDSA",
                })
            })
            .collect();

        serde_json::to_string(&serde_json::json!({ "keys": keys }))
            .context("writing the jwks document")
    }

    fn loaded(&self) -> Option<std::sync::Arc<SigningKey>> {
        self.slot().clone()
    }

    /// A poisoned slot means a thread panicked holding it; the slot only ever
    /// holds a clone of an `Arc`, so nothing about the key can be half-written
    /// — but pretending the panic did not happen would be worse than joining it.
    fn slot(&self) -> std::sync::MutexGuard<'_, Option<std::sync::Arc<SigningKey>>> {
        self.current.lock().expect("signing key slot poisoned")
    }
}

/// The next free `kid` for a key made at `at`: the spec's `YYYYMMDD-NNN`, with
/// `NNN` counting keys made on the same day — which only rotation can cause.
///
/// One past the day's *highest* suffix rather than a row count, because
/// pruning deletes rows: a count would re-issue a pruned key's kid the same
/// day, and a kid must never name two keys — it is the one thing a verifier
/// holding several is allowed to trust.
fn fresh_kid(transaction: &rusqlite::Transaction<'_>, at: &str) -> Result<String> {
    // `now()` writes RFC 3339, so the date is the first ten characters with
    // the hyphens dropped.
    let date: String = at.chars().take(10).filter(|c| *c != '-').collect();
    if date.len() != 8 {
        anyhow::bail!("`{at}` does not carry a date to name a signing key after");
    }

    let highest: Option<String> = transaction
        .query_row(
            "SELECT kid FROM jwt_signing_keys WHERE kid LIKE ?1 ORDER BY kid DESC LIMIT 1",
            rusqlite::params![format!("{date}-%")],
            |row| row.get(0),
        )
        .optional()
        .context("finding the day's highest signing key")?;
    let taken = highest
        .as_deref()
        .and_then(|kid| kid.rsplit('-').next())
        .and_then(|suffix| suffix.parse::<i64>().ok())
        .unwrap_or(0);

    Ok(format!("{date}-{:03}", taken + 1))
}

/// The loaded half of one row, out of what the transaction handed back.
fn parse_key(kid: String, pkcs8: Secret, created_at: String) -> Result<SigningKey> {
    let pair = Ed25519KeyPair::from_pkcs8(
        &STANDARD
            .decode(pkcs8.expose())
            .context("decoding the stored signing key")?,
    )
    .map_err(|error| anyhow!("{error}"))
    .context("reading the stored signing key")?;

    Ok(SigningKey {
        kid,
        pair,
        created_at,
    })
}

/// Whether a key made at `at` has outlived [`ROTATION_PERIOD`]. An unreadable
/// stamp answers "not due", the opposite direction from every expiry check in
/// this module tree, and on purpose: a due-answer here *mints keys*, and a
/// stamp this build cannot read would mint one per signature, forever — where
/// a key that merely stays in service is exactly what `auth key rotate` exists
/// to fix by hand.
fn rotation_due(at: &str) -> bool {
    time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339)
        .map(|at| {
            time::OffsetDateTime::now_utc() - at
                >= time::Duration::seconds(ROTATION_PERIOD.as_secs() as i64)
        })
        .unwrap_or(false)
}

/// Delete the retired rows nothing can verify against anymore, inside the
/// rotation's transaction. Run at rotation rather than on JWKS reads because
/// rotation is the only write this table sees — the session tables' argument
/// that growth and cleanup should be the same traffic — and the JWKS read
/// already filters what it serves, so a row awaiting the next rotation costs
/// bytes, not correctness.
fn prune_retired_in(transaction: &rusqlite::Transaction<'_>) -> Result<()> {
    let mut statement = transaction
        .prepare("SELECT kid, retired_at FROM jwt_signing_keys WHERE retired_at IS NOT NULL")
        .context("preparing the retired key sweep")?;
    let retired = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .context("reading the retired keys")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the retired keys")?;
    drop(statement);

    for (kid, at) in retired {
        if retired_beyond_grace(&at) {
            transaction
                .execute(
                    "DELETE FROM jwt_signing_keys WHERE kid = ?1",
                    rusqlite::params![kid],
                )
                .context("pruning a retired signing key")?;
        }
    }

    Ok(())
}

/// Whether a key retired at `at` is past the point where any JWT it signed
/// could still be presented. An unreadable stamp answers "past": it was
/// written by something other than this build, and serving a key forever on
/// the strength of a date nobody can read helps no verifier.
fn retired_beyond_grace(at: &str) -> bool {
    time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339)
        .map(|at| {
            time::OffsetDateTime::now_utc() - at
                > time::Duration::seconds(RETIRED_KEY_GRACE.as_secs() as i64)
        })
        .unwrap_or(true)
}

/// Sign the JWT that vouches for `sub` to `aud`, as of `now`.
///
/// The clock is an argument for [`crate::connections::github::jwt`]'s reason:
/// a token is a statement about two moments, and a function handed the moment
/// can be asserted against. The segment mechanics are the same hand-rolled
/// base64url-dot-joining as that module's, and deliberately not shared with
/// it: the two builders agree on eight lines of JOSE plumbing and on nothing
/// else — different algorithm, different claims, different key type — and a
/// helper generic over all of that would be longer than the duplication.
///
/// `roles` must not be empty, and that is the caller's contract, checked
/// again here: the spec says an empty intersection is a `403` and never an
/// empty-`roles` JWT, and this refusal is the last line of defence against
/// the gate's check and this signature drifting apart.
pub fn mint(
    key: &SigningKey,
    iss: &str,
    sub: &UserId,
    aud: &AppId,
    roles: &[Role],
    now: time::OffsetDateTime,
) -> Result<Secret> {
    if roles.is_empty() {
        anyhow::bail!(
            "a JWT with no roles must never be minted — an empty intersection is a 403, and the gate should have refused before asking"
        );
    }

    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": key.kid,
    });
    let iat = now.unix_timestamp();
    let payload = serde_json::json!({
        "iss": iss,
        "sub": sub,
        "aud": aud.as_str(),
        "iat": iat,
        "exp": iat + JWT_LIFETIME.as_secs() as i64,
        "jti": uuid_v4()?,
        "roles": roles,
    });

    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).context("writing the jwt header")?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).context("writing the jwt payload")?),
    );
    let signature = key.pair.sign(message.as_bytes());

    Ok(Secret::new(format!(
        "{message}.{}",
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    )))
}

/// One cached JWT: who it vouches for, and when it stops being served.
///
/// The token is a bearer credential for its five minutes, so it sits behind
/// [`Secret`] like every other credential in memory — and the entry type
/// derives no `Debug`, so the map cannot be logged into a leak.
struct CachedJwt {
    /// Kept so a purge aimed at a user finds the entries their sessions put
    /// here, whichever app-session tokens they rode in on.
    user: UserId,
    jwt: Secret,
    minted_at: Instant,
}

/// One live WebSocket tunnel, as the fan-out below tracks it: whose credential
/// holds it open, and the switch that tears it down.
///
/// The user and not the credential's hash, although the connection was opened
/// by one specific app session or API key: every lever that could revoke the
/// credential — session drop, key revoke, suspend, drop, logout — already
/// purges this cache *by user*, because credentials are stored hashed and the
/// repositories never hold one to aim at. Tracking at the same granularity
/// means a kill can never miss a connection a purge meant to reach; the cost
/// is that dropping one of a user's sessions also cuts the WebSockets their
/// *other* sessions hold — which reconnect and re-authenticate against rows
/// that still answer, a blip where the alternative's failure mode is a revoked
/// credential's socket living on.
struct TrackedSocket {
    user: UserId,
    kill: CancellationToken,
}

/// The in-memory JWT cache: the gate's hot path, and every revocation lever's
/// purge target — which is why the live-WebSocket registry lives inside it
/// too, making this struct the process's whole revocation fan-out.
///
/// The registry could have been a struct beside the cache, but the spec's
/// WebSocket levers (session drop, revoke, expiry, suspend, drop) are exactly
/// the purge levers, letter for letter: a separate registry would be a second
/// handle threaded through every auth repository's constructor and the
/// daemon's wiring, only to be pulled in the very statements that already pull
/// this one. Folding them means no seam can purge the cache and forget the
/// sockets.
///
/// Keyed by `(app-session token, app)` rather than the spec's first sketch of
/// `(user, app)`, because the key has to be something the request itself
/// carries: on a hit the gate does *no* database read at all — that is the
/// entire point of the cache — and the only thing a request carries is the
/// cookie. A user-keyed cache would need a database read to learn the user,
/// which is the read being cached. The token is stored as its SHA-256, the
/// discipline every session table already follows: a dump of this map must be
/// worth less than the cookies it speaks for. The user rides along in the
/// entry so purges can still aim at a user, and the app id in the key is what
/// keeps one app's token from ever answering for another.
///
/// A `std::sync::Mutex` over a `HashMap`, held for hash-map operations and
/// never across an await: at one edge's request rate there is nothing here
/// worth sharding, and an async lock would only add a wake-up.
pub struct JwtCache {
    entries: Mutex<HashMap<(String, AppId), CachedJwt>>,
    /// The live WebSocket tunnels through gated apps, killable per user. A
    /// `Vec` and not a map: it holds one entry per open socket, is walked only
    /// on purge and on registration, and swept of finished connections on the
    /// way past — the entries' own cancellation doubles as the liveness bit,
    /// since a tunnel that ended dropped its guard and cancelled itself.
    sockets: Mutex<Vec<TrackedSocket>>,
    /// [`CACHE_TTL`] everywhere but in the tests that would otherwise wait
    /// four minutes to watch an entry die.
    ttl: Duration,
}

impl JwtCache {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            sockets: Mutex::new(Vec::new()),
            ttl: CACHE_TTL,
        }
    }

    #[cfg(test)]
    fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            sockets: Mutex::new(Vec::new()),
            ttl,
        }
    }

    /// Register a WebSocket tunnel `user`'s credential just opened, answering
    /// the token that kills it.
    ///
    /// The tunnel selects on the token and tears both directions down when it
    /// fires; it must also hold the token's `drop_guard`, so a connection that
    /// ends on its own cancels its own entry and the next registration or
    /// purge sweeps it out — the cache's own no-background-loop discipline.
    pub fn track_socket(&self, user: &UserId) -> CancellationToken {
        let kill = CancellationToken::new();
        let mut sockets = self.sockets_lock();
        sockets.retain(|socket| !socket.kill.is_cancelled());
        sockets.push(TrackedSocket {
            user: user.clone(),
            kill: kill.clone(),
        });

        kill
    }

    /// How many tunnels are currently tracked — for the tests that assert an
    /// open app's sockets never enter the registry at all.
    #[cfg(test)]
    pub(crate) fn tracked_sockets(&self) -> usize {
        let mut sockets = self.sockets_lock();
        sockets.retain(|socket| !socket.kill.is_cancelled());

        sockets.len()
    }

    /// The cached JWT for `token` at `app`, if one is still inside its four
    /// minutes. A dead entry is removed on the way past rather than left for
    /// a sweep, since this lookup is the only reader.
    pub fn lookup(&self, token: &Secret, app: &AppId) -> Option<Secret> {
        let key = (hash(token.expose()), app.clone());
        let mut entries = self.lock();

        match entries.get(&key) {
            Some(entry) if entry.minted_at.elapsed() < self.ttl => Some(entry.jwt.clone()),
            Some(_) => {
                entries.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Cache `jwt` for `token` at `app`, remembering `user` for the purges.
    ///
    /// Expired entries are swept here — the one write that grows the map, so
    /// growth and cleanup are the same traffic and nothing needs a background
    /// loop, exactly as the session tables argue.
    pub fn insert(&self, token: &Secret, app: &AppId, user: &UserId, jwt: Secret) {
        let mut entries = self.lock();
        entries.retain(|_, entry| entry.minted_at.elapsed() < self.ttl);
        entries.insert(
            (hash(token.expose()), app.clone()),
            CachedJwt {
                user: user.clone(),
                jwt,
                minted_at: Instant::now(),
            },
        );
    }

    /// Drop every cached JWT vouching for `user`, on any app — and cut every
    /// live WebSocket their credentials hold open. The lever behind `session
    /// drop`, `revoke`, suspend and drop: the database write those commit is
    /// the revocation, this is what keeps the hot path from outliving it by
    /// more than the four minutes the spec accepts, and the socket kill is the
    /// spec's "handshake auth never outlives revocation" — a tunnel admitted
    /// under a now-dead credential is cut in the same breath as the cache.
    pub fn purge_user(&self, user: &UserId) {
        self.lock().retain(|_, entry| &entry.user != user);
        self.sockets_lock().retain(|socket| {
            if &socket.user == user {
                socket.kill.cancel();
                return false;
            }

            !socket.kill.is_cancelled()
        });
    }

    /// Drop every cached JWT for `app`, whoever holds one. The lever behind a
    /// deploy that changes the app's declared roles: every cached token's
    /// `roles` was intersected against the old manifest, so all of them are
    /// stale at once.
    ///
    /// WebSockets are deliberately *not* cut here. The spec's termination
    /// levers are the session's — drop, revoke, expiry — and a redeploy
    /// revokes nobody: the sessions behind the sockets still answer, and a
    /// connection's JWT was delivered once at handshake either way, so cutting
    /// every socket per deploy would buy no freshness an app could observe.
    pub fn purge_app(&self, app: &AppId) {
        self.lock().retain(|(_, cached), _| cached != app);
    }

    /// A poisoned cache means a thread panicked inside a hash-map operation;
    /// nothing here can repair that, and limping on with a cache that may
    /// still serve what a purge tried to drop is the wrong side to fail on.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(String, AppId), CachedJwt>> {
        self.entries.lock().expect("jwt cache poisoned")
    }

    /// The same argument as [`JwtCache::lock`], for the sockets: limping on
    /// with a registry that may still hold what a kill tried to cut is the
    /// wrong side to fail on.
    fn sockets_lock(&self) -> std::sync::MutexGuard<'_, Vec<TrackedSocket>> {
        self.sockets.lock().expect("ws registry poisoned")
    }
}

impl Default for JwtCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Db {
        Db::in_memory().unwrap()
    }

    fn user(hex: &str) -> UserId {
        format!(
            "{hex}{}",
            &"3f29b1d4-8a6e-4c2b-9e77-1d5f6a2b9c40"[hex.len()..]
        )
        .parse()
        .unwrap()
    }

    fn app(id: &str) -> AppId {
        id.parse().unwrap()
    }

    fn roles(names: &[&str]) -> Vec<Role> {
        names.iter().map(|name| name.parse().unwrap()).collect()
    }

    /// A moment with no particular significance, fixed so the claims are
    /// arithmetic rather than a race with the clock.
    fn moment() -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(1_785_333_600).unwrap()
    }

    async fn key(signer: &JwtSigner) -> std::sync::Arc<SigningKey> {
        signer.signing_key().await.unwrap()
    }

    fn decode(segment: &str) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap()
    }

    #[test]
    fn the_issuer_names_the_port_only_off_443() {
        assert_eq!(issuer("spaceport.test", 443), "https://spaceport.test");
        assert_eq!(
            issuer("spaceport.test", 8443),
            "https://spaceport.test:8443"
        );
        assert_eq!(
            jwks_url("https://spaceport.test"),
            "https://spaceport.test/.well-known/jwks.json"
        );
    }

    /// The key is made once and then kept: a second signer over the same
    /// database — a restart — signs with the very key the first one made, so
    /// the `kid` an app has seen stays valid.
    #[tokio::test]
    async fn the_signing_key_survives_a_restart() {
        let db = db();
        let first = key(&JwtSigner::new(db.clone())).await;
        let second = key(&JwtSigner::new(db)).await;

        assert_eq!(first.kid(), second.kid());
        assert_eq!(first.public_key(), second.public_key());
    }

    /// The spec's `kid` spelling: the day the key was made and a counter,
    /// which is all rotation will ever need to disambiguate.
    #[tokio::test]
    async fn the_kid_is_the_date_and_a_counter() {
        let kid = key(&JwtSigner::new(db())).await.kid().to_owned();

        let (date, counter) = kid.split_once('-').expect(&kid);
        assert_eq!(date.len(), 8, "{kid}");
        assert!(date.bytes().all(|byte| byte.is_ascii_digit()), "{kid}");
        assert_eq!(counter, "001", "{kid}");
    }

    /// The exact shape the spec's example promises: header of three fields,
    /// payload of seven, five minutes between `iat` and `exp`.
    #[tokio::test]
    async fn a_minted_jwt_carries_the_contracted_claims() {
        let signer = JwtSigner::new(db());
        let key = key(&signer).await;

        let jwt = mint(
            &key,
            "https://spaceport.test",
            &user("aaaaaaaa"),
            &app("blog"),
            &roles(&["reader", "writer"]),
            moment(),
        )
        .unwrap();

        let token = jwt.expose();
        assert_eq!(token.split('.').count(), 3);
        let header = decode(token.split('.').next().unwrap());
        assert_eq!(
            header,
            serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": key.kid()})
        );

        let payload = decode(token.split('.').nth(1).unwrap());
        assert_eq!(payload["iss"], "https://spaceport.test");
        assert_eq!(payload["sub"], user("aaaaaaaa").as_str());
        assert_eq!(payload["aud"], "blog");
        assert_eq!(payload["iat"].as_i64().unwrap(), moment().unix_timestamp());
        assert_eq!(
            payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap(),
            300
        );
        assert_eq!(payload["roles"], serde_json::json!(["reader", "writer"]));
        // The jti is a UUID: unique per token, so an app that wants replay
        // detection has something to key it on.
        assert!(
            payload["jti"].as_str().unwrap().parse::<UserId>().is_ok(),
            "{payload}"
        );
    }

    /// Two mints are two tokens: the `jti` is fresh every time, which is what
    /// lets a test — and an app — tell a re-mint from a cache hit.
    #[tokio::test]
    async fn every_mint_gets_its_own_jti() {
        let signer = JwtSigner::new(db());
        let key = key(&signer).await;
        let one = |jwt: &Secret| {
            decode(jwt.expose().split('.').nth(1).unwrap())["jti"]
                .as_str()
                .unwrap()
                .to_owned()
        };

        let first = mint(
            &key,
            "https://s.test",
            &user("aaaaaaaa"),
            &app("blog"),
            &roles(&["reader"]),
            moment(),
        )
        .unwrap();
        let second = mint(
            &key,
            "https://s.test",
            &user("aaaaaaaa"),
            &app("blog"),
            &roles(&["reader"]),
            moment(),
        )
        .unwrap();

        assert_ne!(one(&first), one(&second));
    }

    /// The spec's invariant, held at the signature itself: an empty
    /// intersection is a `403` upstream, and a mint asked for one anyway is a
    /// bug this refusal keeps from becoming an empty-`roles` token.
    #[tokio::test]
    async fn a_mint_with_no_roles_is_refused() {
        let signer = JwtSigner::new(db());
        let key = key(&signer).await;

        let error = mint(
            &key,
            "https://s.test",
            &user("aaaaaaaa"),
            &app("blog"),
            &[],
            moment(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("no roles"), "{error}");
    }

    /// The test that proves the whole contract: the JWKS the endpoint serves
    /// names the key, and the raw `x` in it verifies a minted token — which is
    /// exactly the verification an app's middleware performs.
    #[tokio::test]
    async fn the_jwks_key_verifies_a_minted_jwt() {
        let signer = JwtSigner::new(db());
        let key = key(&signer).await;
        let jwt = mint(
            &key,
            "https://s.test",
            &user("aaaaaaaa"),
            &app("blog"),
            &roles(&["reader"]),
            moment(),
        )
        .unwrap();

        let jwks: serde_json::Value = serde_json::from_str(&signer.jwks().await.unwrap()).unwrap();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "OKP");
        assert_eq!(keys[0]["crv"], "Ed25519");
        assert_eq!(keys[0]["kid"], key.kid());

        let public = URL_SAFE_NO_PAD
            .decode(keys[0]["x"].as_str().unwrap())
            .unwrap();
        let (message, signature) = jwt.expose().rsplit_once('.').unwrap();
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public)
            .verify(
                message.as_bytes(),
                &URL_SAFE_NO_PAD.decode(signature).unwrap(),
            )
            .expect("the jwks public key should verify the token");
    }

    /// A JWKS asked for before anything was ever signed still has to answer
    /// with the key the first JWT will carry — serving is a first need too.
    #[tokio::test]
    async fn the_jwks_generates_the_key_on_first_read() {
        let signer = JwtSigner::new(db());

        let jwks: serde_json::Value = serde_json::from_str(&signer.jwks().await.unwrap()).unwrap();

        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    }

    /// A tampered payload dies at the signature, which is the property the
    /// whole scheme rides on.
    #[tokio::test]
    async fn a_tampered_token_does_not_verify() {
        let signer = JwtSigner::new(db());
        let key = key(&signer).await;
        let jwt = mint(
            &key,
            "https://s.test",
            &user("aaaaaaaa"),
            &app("blog"),
            &roles(&["reader"]),
            moment(),
        )
        .unwrap();

        let (message, signature) = jwt.expose().rsplit_once('.').unwrap();
        let tampered = format!(
            "{}.{}",
            message.split('.').next().unwrap(),
            URL_SAFE_NO_PAD.encode(br#"{"sub":"somebody-else"}"#)
        );

        assert!(
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::ED25519,
                key.public_key().to_vec()
            )
            .verify(
                tampered.as_bytes(),
                &URL_SAFE_NO_PAD.decode(signature).unwrap(),
            )
            .is_err()
        );
    }

    fn token(value: &str) -> Secret {
        Secret::new(value)
    }

    /// An RFC 3339 stamp `days` days ago — for backdating rows, which is how
    /// these tests move the clock without holding it.
    fn days_ago(days: i64) -> String {
        (time::OffsetDateTime::now_utc() - time::Duration::days(days))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    }

    async fn backdate(db: &Db, column: &'static str, to: String) {
        db.call(move |connection| {
            connection
                .execute(
                    &format!(
                        "UPDATE jwt_signing_keys SET {column} = ?1 WHERE {column} IS NOT NULL"
                    ),
                    rusqlite::params![to],
                )
                .context("backdating a signing key")?;

            Ok(())
        })
        .await
        .unwrap();
    }

    /// The whole retire-and-mint move: rotation flips `current` to a fresh
    /// kid, stamps the old row retired, and — same day — the `-NNN` counter is
    /// what tells the two keys apart.
    #[tokio::test]
    async fn a_rotation_retires_the_old_key_and_counts_the_kid_up() {
        let signer = JwtSigner::new(db());
        let old = key(&signer).await.kid().to_owned();

        let rotation = signer.rotate(crate::auth::OPERATOR_ORIGIN).await.unwrap();

        assert_eq!(rotation.retired.as_deref(), Some(old.as_str()));
        assert_ne!(rotation.kid, old);
        // Two keys on one day: same date, counter up by one.
        assert_eq!(&rotation.kid[..8], &old[..8]);
        assert!(
            old.ends_with("-001") && rotation.kid.ends_with("-002"),
            "{old} {rotation:?}"
        );

        let keys = signer.keys().await.unwrap();
        let retired = keys.iter().find(|record| record.kid == old).unwrap();
        assert!(
            !retired.current && retired.retired_at.is_some(),
            "{retired:?}"
        );
        let current = keys
            .iter()
            .find(|record| record.kid == rotation.kid)
            .unwrap();
        assert!(
            current.current && current.retired_at.is_none(),
            "{current:?}"
        );
        // And new tokens sign with the new kid immediately.
        assert_eq!(signer.signing_key().await.unwrap().kid(), rotation.kid);
    }

    /// The retention rule, end to end: a pre-rotation JWT verifies against the
    /// JWKS *after* rotation, because the retired key is still served — and a
    /// post-rotation JWT verifies against the new one, `kid` telling them
    /// apart exactly as the spec promises.
    #[tokio::test]
    async fn tokens_from_both_sides_of_a_rotation_verify_via_the_jwks() {
        let signer = JwtSigner::new(db());
        let before = mint(
            key(&signer).await.as_ref(),
            "https://s.test",
            &user("aaaaaaaa"),
            &app("blog"),
            &roles(&["reader"]),
            moment(),
        )
        .unwrap();

        signer.rotate(crate::auth::OPERATOR_ORIGIN).await.unwrap();
        let after = mint(
            key(&signer).await.as_ref(),
            "https://s.test",
            &user("aaaaaaaa"),
            &app("blog"),
            &roles(&["reader"]),
            moment(),
        )
        .unwrap();

        let jwks: serde_json::Value = serde_json::from_str(&signer.jwks().await.unwrap()).unwrap();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2, "{jwks}");
        for jwt in [&before, &after] {
            let header = decode(jwt.expose().split('.').next().unwrap());
            let public = keys
                .iter()
                .find(|key| key["kid"] == header["kid"])
                .unwrap_or_else(|| panic!("no jwks key for {header}"))["x"]
                .as_str()
                .unwrap();
            let (message, signature) = jwt.expose().rsplit_once('.').unwrap();
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::ED25519,
                URL_SAFE_NO_PAD.decode(public).unwrap(),
            )
            .verify(
                message.as_bytes(),
                &URL_SAFE_NO_PAD.decode(signature).unwrap(),
            )
            .expect("both sides of the rotation must verify");
        }
    }

    /// Past the grace horizon nothing honest can present the retired key's
    /// tokens anymore: the JWKS sheds it at read time, and the next rotation
    /// prunes the row itself.
    #[tokio::test]
    async fn the_jwks_sheds_a_retired_key_past_its_grace_and_rotation_prunes_it() {
        let database = db();
        let signer = JwtSigner::new(database.clone());
        key(&signer).await;
        signer.rotate(crate::auth::OPERATOR_ORIGIN).await.unwrap();

        let jwks: serde_json::Value = serde_json::from_str(&signer.jwks().await.unwrap()).unwrap();
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 2);

        backdate(&database, "retired_at", days_ago(1)).await;

        let jwks: serde_json::Value = serde_json::from_str(&signer.jwks().await.unwrap()).unwrap();
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1, "{jwks}");
        // The row is still there — pruning is the next rotation's business.
        assert_eq!(signer.keys().await.unwrap().len(), 2);

        signer.rotate(crate::auth::OPERATOR_ORIGIN).await.unwrap();
        let kept = signer.keys().await.unwrap();
        // The over-grace row went; the just-retired one stays for its tokens.
        assert_eq!(kept.len(), 2, "{kept:?}");
        assert!(kept.iter().all(|record| !record.kid.ends_with("-001")));
    }

    /// The ninety-day clock, driven by backdating the row: the next signer to
    /// need the key rotates first, and the log says the system did it — not an
    /// operator, which is the distinction an auditor reads the column for.
    #[tokio::test]
    async fn rotation_fires_on_its_own_past_ninety_days() {
        let database = db();
        let old = key(&JwtSigner::new(database.clone()))
            .await
            .kid()
            .to_owned();
        backdate(&database, "created_at", days_ago(91)).await;

        // A fresh signer, as after a restart: the age check runs on load too.
        let current = key(&JwtSigner::new(database.clone())).await;

        assert_ne!(current.kid(), old);
        let entries = crate::auth::AuthLogRepository::new(database)
            .entries(None)
            .await
            .unwrap();
        let rotated = entries
            .iter()
            .find(|entry| entry.kind == "key.rotated")
            .unwrap();
        assert_eq!(rotated.origin, crate::auth::SYSTEM_ORIGIN);
        assert_eq!(rotated.user, None);
    }

    /// A key inside its ninety days is left alone — the check must not rotate
    /// on every use, or the JWKS would grow a key per mint.
    #[tokio::test]
    async fn a_young_key_is_not_rotated_on_use() {
        let signer = JwtSigner::new(db());
        let first = key(&signer).await.kid().to_owned();

        assert_eq!(key(&signer).await.kid(), first);
        assert_eq!(signer.keys().await.unwrap().len(), 1);
    }

    /// The manual lever writes the operator's name on the log entry, with both
    /// kids in the detail — the compromise-response audit trail.
    #[tokio::test]
    async fn a_manual_rotation_logs_as_the_operators_doing() {
        let database = db();
        let signer = JwtSigner::new(database.clone());
        let old = key(&signer).await.kid().to_owned();

        let rotation = signer.rotate(crate::auth::OPERATOR_ORIGIN).await.unwrap();

        let entries = crate::auth::AuthLogRepository::new(database)
            .entries(None)
            .await
            .unwrap();
        let rotated = entries
            .iter()
            .find(|entry| entry.kind == "key.rotated")
            .unwrap();
        assert_eq!(rotated.origin, crate::auth::OPERATOR_ORIGIN);
        let detail = rotated.detail.as_deref().unwrap();
        assert!(
            detail.contains(&old) && detail.contains(&rotation.kid),
            "{detail}"
        );
    }

    #[test]
    fn the_cache_serves_what_was_inserted_and_only_that() {
        let cache = JwtCache::new();
        cache.insert(
            &token("alices-cookie"),
            &app("blog"),
            &user("aaaaaaaa"),
            Secret::new("alices-jwt"),
        );

        assert_eq!(
            cache.lookup(&token("alices-cookie"), &app("blog")),
            Some(Secret::new("alices-jwt"))
        );
        // Never across apps: the aud in the cached token is `blog`'s.
        assert_eq!(cache.lookup(&token("alices-cookie"), &app("wiki")), None);
        // And never across tokens, which is what "never across users" means
        // at this key: another cookie is another entry or nothing.
        assert_eq!(cache.lookup(&token("bobs-cookie"), &app("blog")), None);
    }

    /// The four-minute fuse: an entry past the TTL is not served, however
    /// untouched the map — tested at a zero TTL because nobody waits out four
    /// real minutes to watch it.
    #[test]
    fn an_expired_entry_stops_being_served() {
        let cache = JwtCache::with_ttl(Duration::ZERO);
        cache.insert(
            &token("alices-cookie"),
            &app("blog"),
            &user("aaaaaaaa"),
            Secret::new("alices-jwt"),
        );

        assert_eq!(cache.lookup(&token("alices-cookie"), &app("blog")), None);
    }

    /// A purge aimed at a user takes every entry their sessions put here —
    /// across apps and across cookies — and leaves everybody else's alone.
    #[test]
    fn purging_a_user_spares_the_others() {
        let cache = JwtCache::new();
        cache.insert(
            &token("alices-cookie"),
            &app("blog"),
            &user("aaaaaaaa"),
            Secret::new("alices-jwt"),
        );
        cache.insert(
            &token("alices-other-cookie"),
            &app("wiki"),
            &user("aaaaaaaa"),
            Secret::new("alices-wiki-jwt"),
        );
        cache.insert(
            &token("bobs-cookie"),
            &app("blog"),
            &user("bbbbbbbb"),
            Secret::new("bobs-jwt"),
        );

        cache.purge_user(&user("aaaaaaaa"));

        assert_eq!(cache.lookup(&token("alices-cookie"), &app("blog")), None);
        assert_eq!(
            cache.lookup(&token("alices-other-cookie"), &app("wiki")),
            None
        );
        assert!(cache.lookup(&token("bobs-cookie"), &app("blog")).is_some());
    }

    /// The socket half of the fan-out: a purge aimed at a user fires exactly
    /// their kill switches, spares everybody else's, and the fired entries
    /// leave the registry.
    #[test]
    fn purging_a_user_kills_their_sockets_and_spares_the_others() {
        let cache = JwtCache::new();
        let alices = cache.track_socket(&user("aaaaaaaa"));
        let bobs = cache.track_socket(&user("bbbbbbbb"));

        cache.purge_user(&user("aaaaaaaa"));

        assert!(alices.is_cancelled());
        assert!(!bobs.is_cancelled());
        assert_eq!(cache.tracked_sockets(), 1);
    }

    /// A tunnel that ends on its own cancels its own entry through the drop
    /// guard it holds, and the registry sweeps it on the next pass — no
    /// background loop, the cache's own discipline.
    #[test]
    fn a_finished_socket_sweeps_itself_out_of_the_registry() {
        let cache = JwtCache::new();
        let kill = cache.track_socket(&user("aaaaaaaa"));

        // What the tunnel task does at the end of its life.
        drop(kill.drop_guard());

        assert_eq!(cache.tracked_sockets(), 0);
    }

    /// A purge aimed at an app takes every user's entry for it — the deploy
    /// lever — and spares the same users' entries at other apps.
    #[test]
    fn purging_an_app_spares_the_others() {
        let cache = JwtCache::new();
        cache.insert(
            &token("alices-cookie"),
            &app("blog"),
            &user("aaaaaaaa"),
            Secret::new("alices-jwt"),
        );
        cache.insert(
            &token("alices-other-cookie"),
            &app("wiki"),
            &user("aaaaaaaa"),
            Secret::new("alices-wiki-jwt"),
        );

        cache.purge_app(&app("blog"));

        assert_eq!(cache.lookup(&token("alices-cookie"), &app("blog")), None);
        assert!(
            cache
                .lookup(&token("alices-other-cookie"), &app("wiki"))
                .is_some()
        );
    }
}

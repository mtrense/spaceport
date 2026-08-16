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
//! the argument. There is one current key; rotation is a later milestone, and
//! it only has to flip `current`, stamp `retired_at` and keep the retired row
//! in the JWKS until every JWT it signed has expired, which the schema and
//! [`JwtSigner::jwks`] are already shaped for. `kid` is what tells a verifier
//! holding both keys which one made a given token.
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
/// Nothing retires a key yet — rotation is a later milestone — but the read
/// side honouring `retired_at` now is what makes that milestone a command
/// rather than a schema change.
const RETIRED_KEY_GRACE: Duration = Duration::from_secs(JWT_LIFETIME.as_secs() + 60);

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

impl JwtSigner {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            current: Mutex::new(None),
        }
    }

    /// The current signing key, generating and persisting one if this
    /// spaceport has never signed before.
    ///
    /// The keypair is generated *outside* the transaction — randomness has no
    /// business inside a database lock, as every mint in this module tree
    /// argues — and the transaction then re-checks for a current row before
    /// inserting, so two first-mints racing each other agree on one key and
    /// the loser's sixty-four random bytes are simply dropped.
    pub async fn signing_key(&self) -> Result<std::sync::Arc<SigningKey>> {
        if let Some(key) = self.loaded() {
            return Ok(key);
        }

        let rng = ring::rand::SystemRandom::new();
        let fresh = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow!("this host would not generate a signing key"))?;
        let fresh_pkcs8 = Secret::new(STANDARD.encode(fresh.as_ref()));
        let fresh_public = Ed25519KeyPair::from_pkcs8(fresh.as_ref())
            .map_err(|error| anyhow!("{error}"))
            .context("reading the signing key just generated")?;
        let fresh_public = URL_SAFE_NO_PAD.encode(fresh_public.public_key().as_ref());

        let (kid, pkcs8) = self
            .db
            .call(move |connection| {
                let transaction = connection
                    .transaction()
                    .context("beginning to settle the signing key")?;

                // Somebody else's first mint may have won the race between the
                // in-memory check above and this transaction; theirs is the
                // key, or every restart would fork the JWKS.
                let existing: Option<(String, String)> = transaction
                    .query_row(
                        "SELECT kid, pkcs8 FROM jwt_signing_keys WHERE current = 1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .context("looking the current signing key up")?;
                if let Some((kid, pkcs8)) = existing {
                    return Ok((kid, Secret::new(pkcs8)));
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

                Ok((kid, fresh_pkcs8))
            })
            .await?;

        let pair = Ed25519KeyPair::from_pkcs8(
            &STANDARD
                .decode(pkcs8.expose())
                .context("decoding the stored signing key")?,
        )
        .map_err(|error| anyhow!("{error}"))
        .context("reading the stored signing key")?;
        let key = std::sync::Arc::new(SigningKey { kid, pair });

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
/// `NNN` counting keys made on the same day — which only rotation can cause,
/// and which the counter is already shaped for.
fn fresh_kid(transaction: &rusqlite::Transaction<'_>, at: &str) -> Result<String> {
    // `now()` writes RFC 3339, so the date is the first ten characters with
    // the hyphens dropped.
    let date: String = at.chars().take(10).filter(|c| *c != '-').collect();
    if date.len() != 8 {
        anyhow::bail!("`{at}` does not carry a date to name a signing key after");
    }

    let taken: i64 = transaction
        .query_row(
            "SELECT count(*) FROM jwt_signing_keys WHERE kid LIKE ?1",
            rusqlite::params![format!("{date}-%")],
            |row| row.get(0),
        )
        .context("counting the day's signing keys")?;

    Ok(format!("{date}-{:03}", taken + 1))
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

/// The in-memory JWT cache: the gate's hot path, and every revocation lever's
/// purge target.
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
    /// [`CACHE_TTL`] everywhere but in the tests that would otherwise wait
    /// four minutes to watch an entry die.
    ttl: Duration,
}

impl JwtCache {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl: CACHE_TTL,
        }
    }

    #[cfg(test)]
    fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
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

    /// Drop every cached JWT vouching for `user`, on any app. The lever behind
    /// `session drop`, `revoke`, suspend and drop: the database write those
    /// commit is the revocation, and this is what keeps the hot path from
    /// outliving it by more than the four minutes the spec accepts.
    pub fn purge_user(&self, user: &UserId) {
        self.lock().retain(|_, entry| &entry.user != user);
    }

    /// Drop every cached JWT for `app`, whoever holds one. The lever behind a
    /// deploy that changes the app's declared roles: every cached token's
    /// `roles` was intersected against the old manifest, so all of them are
    /// stale at once.
    pub fn purge_app(&self, app: &AppId) {
        self.lock().retain(|(_, cached), _| cached != app);
    }

    /// A poisoned cache means a thread panicked inside a hash-map operation;
    /// nothing here can repair that, and limping on with a cache that may
    /// still serve what a purge tried to drop is the wrong side to fail on.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(String, AppId), CachedJwt>> {
        self.entries.lock().expect("jwt cache poisoned")
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

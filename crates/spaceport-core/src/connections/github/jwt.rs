//! The token a GitHub App presents to say who it is.
//!
//! GitHub's App authentication has two levels and this module is the first of
//! them. Before an App may do anything at all it must prove it holds the private
//! key GitHub issued it, and the proof is a JSON Web Token the App signs itself:
//! RS256 over a header and three claims, presented as `Authorization: Bearer`.
//! That token unlocks exactly the endpoints that are about the App rather than
//! about anybody's code — `/app`, `/app/installations`, and the mint that turns
//! an installation into the second level, an installation token.
//!
//! The clock is an argument rather than something read here, and that is the
//! whole reason this is its own module. A JWT is a statement about two moments,
//! and a function that reads the clock can only be tested by trusting the claims
//! it wrote; one that is handed the moment can be asserted against. Everything
//! that does read the clock lives one level up, in the client.
//!
//! What this deliberately does not do is cache. An App JWT costs one RSA
//! signature and is valid for minutes, so keeping one alive would trade a
//! measurable amount of nothing for a token that outlives its request. Nor does
//! it verify: nothing spaceport signs is ever presented back to spaceport.
//!
//! A JWT library was the alternative. Rejected because every one of them wants
//! its own key type, and the key has already been parsed by [`super::key`] —
//! adding a crate to re-parse a `RsaKeyPair` into another `RsaKeyPair` buys two
//! base64 calls and a `serde_json::to_vec`.

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde::Serialize;
use time::{Duration, OffsetDateTime};

/// How far before `now` the token claims to have been issued.
///
/// GitHub rejects a JWT whose `iat` is in *its* future, and the two clocks are
/// not the same clock: this host's may be a little ahead, and a host that has
/// just booted may be a lot ahead. A minute is generous against the drift a
/// machine running `ntp` badly actually shows, and costs nothing — an `iat` in
/// the past is not a claim anybody checks the tightness of.
const BACKDATE: Duration = Duration::seconds(60);

/// How long the token claims to be good for, measured from `now`.
///
/// GitHub's ceiling is ten minutes and it is GitHub's rule, not a choice: a JWT
/// whose `exp` is further out than that is refused outright, so the whole
/// request fails rather than the token merely expiring early. Eight minutes
/// leaves two for the same clock skew [`BACKDATE`] is about — the backdating is
/// counted against the ceiling too, since GitHub measures `exp - iat`.
const LIFETIME: Duration = Duration::minutes(8);

/// The JOSE header, which for a GitHub App is always these two fields.
///
/// A struct rather than a formatted string so the algorithm named here and the
/// algorithm signed with below cannot drift apart without the compiler noticing
/// one of them.
#[derive(Serialize)]
struct Header {
    alg: &'static str,
    typ: &'static str,
}

/// The claims GitHub reads: when the token was issued, when it expires, and
/// which app is speaking.
#[derive(Serialize)]
struct Claims {
    iat: i64,
    exp: i64,
    /// The app id, as a string.
    ///
    /// GitHub accepts either spelling. A string is what GitHub's own
    /// documentation uses, and it is also the spelling that cannot be rounded:
    /// `iss` travels through JSON parsers that treat every number as a double,
    /// and an app id is only going to get longer.
    iss: String,
}

/// The signed JWT that authenticates the app `app_id` to GitHub, as of `now`.
///
/// `private_key` is already parsed — [`super::key::parse`] did that when the
/// connection was read, so a key that cannot sign has failed long before here.
pub fn app_jwt(app_id: i64, private_key: &RsaKeyPair, now: OffsetDateTime) -> Result<String> {
    let header = serde_json::to_vec(&Header {
        alg: "RS256",
        typ: "JWT",
    })
    .context("writing the app token's header")?;
    let claims = serde_json::to_vec(&Claims {
        iat: (now - BACKDATE).unix_timestamp(),
        exp: (now + LIFETIME).unix_timestamp(),
        iss: app_id.to_string(),
    })
    .context("writing the app token's claims")?;

    // The signed message is the two encoded segments joined by a dot, and the
    // token is that message with the signature appended the same way. Every
    // segment is base64url without padding, which is JOSE's spelling and not a
    // choice made here.
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&header),
        URL_SAFE_NO_PAD.encode(&claims)
    );

    let mut signature = vec![0; private_key.public().modulus_len()];
    private_key
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            message.as_bytes(),
            &mut signature,
        )
        .map_err(|_| anyhow!("the github app's private key could not sign — regenerate it on the app's settings page and connect again"))?;

    Ok(format!("{message}.{}", URL_SAFE_NO_PAD.encode(&signature)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::github::key;
    use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    /// A moment with no particular significance, fixed so the claims are
    /// arithmetic rather than a race with the clock.
    fn moment() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn signed() -> String {
        app_jwt(42, &key::parse(key::testing::PKCS1).unwrap(), moment()).unwrap()
    }

    fn decode(segment: &str) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap()
    }

    #[test]
    fn signs_a_token_of_three_segments() {
        let token = signed();

        assert_eq!(token.split('.').count(), 3);
        assert!(!token.contains('='), "{token}");
    }

    #[test]
    fn announces_itself_as_an_rs256_json_web_token() {
        let token = signed();

        let header = decode(token.split('.').next().unwrap());

        assert_eq!(header, serde_json::json!({"alg": "RS256", "typ": "JWT"}));
    }

    #[test]
    fn issues_the_token_backdated_and_expiring_a_lifetime_later() {
        let token = signed();

        let claims = decode(token.split('.').nth(1).unwrap());

        assert_eq!(claims["iss"], "42");
        assert_eq!(
            claims["iat"].as_i64().unwrap(),
            moment().unix_timestamp() - BACKDATE.whole_seconds()
        );
        assert_eq!(
            claims["exp"].as_i64().unwrap(),
            moment().unix_timestamp() + LIFETIME.whole_seconds()
        );
    }

    /// GitHub refuses a token whose `exp` is more than ten minutes past its
    /// `iat` outright, and it measures the span the token itself claims — so
    /// the backdating counts against the ceiling. Asserted here because the
    /// two constants are the sort of thing a later edit widens one of.
    #[test]
    fn claims_a_lifetime_within_githubs_ten_minute_ceiling() {
        let claims = decode(signed().split('.').nth(1).unwrap());

        let span = claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap();

        assert!(span < Duration::minutes(10).whole_seconds(), "{span}");
    }

    /// The test that proves the encoding: a verifier that agrees is one that
    /// signed the bytes it said it signed, in the segments it said they were
    /// in. Everything else here only checks that spaceport agrees with itself.
    #[test]
    fn signs_the_token_so_that_the_public_key_verifies_it() {
        let pair = key::parse(key::testing::PKCS1).unwrap();
        let token = app_jwt(42, &pair, moment()).unwrap();

        let (message, signature) = token.rsplit_once('.').unwrap();
        let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pair.public().as_ref());

        public
            .verify(
                message.as_bytes(),
                &URL_SAFE_NO_PAD.decode(signature).unwrap(),
            )
            .expect("the signature should verify against the key that made it");
    }

    #[test]
    fn refuses_a_token_whose_payload_has_been_changed() {
        let pair = key::parse(key::testing::PKCS1).unwrap();
        let token = app_jwt(42, &pair, moment()).unwrap();

        let (message, signature) = token.rsplit_once('.').unwrap();
        // The same header, a different app claiming it.
        let tampered = format!(
            "{}.{}",
            message.split('.').next().unwrap(),
            URL_SAFE_NO_PAD.encode(br#"{"iat":1,"exp":2,"iss":"43"}"#)
        );
        let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pair.public().as_ref());

        assert!(
            public
                .verify(
                    tampered.as_bytes(),
                    &URL_SAFE_NO_PAD.decode(signature).unwrap(),
                )
                .is_err()
        );
    }

    /// Signing again must produce a token that is still good. RSA PKCS#1 v1.5
    /// is deterministic, so the two may well be byte-identical — nothing here
    /// asserts either way, because neither is a promise spaceport relies on.
    #[test]
    fn signs_the_same_input_twice_into_a_token_that_still_verifies() {
        let pair = key::parse(key::testing::PKCS1).unwrap();
        let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pair.public().as_ref());

        for _ in 0..2 {
            let token = app_jwt(42, &pair, moment()).unwrap();
            let (message, signature) = token.rsplit_once('.').unwrap();

            public
                .verify(
                    message.as_bytes(),
                    &URL_SAFE_NO_PAD.decode(signature).unwrap(),
                )
                .unwrap();
        }
    }
}

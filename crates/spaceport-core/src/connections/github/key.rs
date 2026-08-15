//! The private key a GitHub App signs with, turned from a file into a signer.
//!
//! GitHub hands an operator a `.pem` file once, at the moment they click
//! "generate a private key", and everything this spaceport ever does as the App
//! is built on it: an installation token is minted by presenting a JWT signed
//! with this key, and nothing else proves the App is who it says it is.
//!
//! Two encodings turn up in practice. GitHub itself writes PKCS#1 — the
//! `-----BEGIN RSA PRIVATE KEY-----` block — and a good deal of tooling
//! (`openssl pkcs8`, several key managers, anything that has been through a
//! Kubernetes secret) rewrites it as PKCS#8, `-----BEGIN PRIVATE KEY-----`.
//! Both are accepted, because an operator who converted their key did nothing
//! wrong and a refusal at that point reads as spaceport rejecting a key GitHub
//! issued.
//!
//! Nothing here signs anything and nothing here talks to GitHub: this module
//! only decides whether a piece of text is a key that could sign. Signing the
//! JWT and asking GitHub for a token arrive with the step that needs them, and
//! keeping the parsing apart from them is what lets the parsing be tested
//! against a fixture on disk rather than against a network.
//!
//! The alternative was to keep the PEM as text and let the first signature find
//! out — rejected, because that puts the failure hours away from the mistake.

use anyhow::{Context, Result, anyhow, bail};
use ring::signature::RsaKeyPair;
use rustls::pki_types::PrivateKeyDer;

/// What every PEM block begins with, and so the cheapest way to tell "this is
/// not a PEM file at all" from "this is PEM, of the wrong kind".
///
/// Only ever used to choose which sentence to say: the parsing itself is
/// `rustls_pemfile`'s, which is the one that decides what the file really is.
const PEM_MARKER: &str = "-----BEGIN";

/// Read `pem` as the RSA key a GitHub App signs with.
///
/// Accepts both encodings GitHub's key turns up in, and refuses everything else
/// with a sentence that says which mistake was made.
pub fn parse(pem: &str) -> Result<RsaKeyPair> {
    let key = rustls_pemfile::private_key(&mut pem.as_bytes())
        .context("reading the github app's private key")?;

    let Some(key) = key else {
        if pem.contains(PEM_MARKER) {
            bail!(
                "the private key file is pem, but holds no private key — pass the `.pem` github offered under \"generate a private key\", not a certificate or a public key"
            );
        }

        bail!(
            "the private key is not pem — it should begin `-----BEGIN RSA PRIVATE KEY-----`, as the file github downloads does"
        );
    };

    let pair = match &key {
        // What GitHub writes.
        PrivateKeyDer::Pkcs1(der) => RsaKeyPair::from_der(der.secret_pkcs1_der()),
        // What converting it leaves behind. `ring` still refuses a PKCS#8 key
        // that is not RSA, which is where an Ed25519 key in a
        // `-----BEGIN PRIVATE KEY-----` block is caught.
        PrivateKeyDer::Pkcs8(der) => RsaKeyPair::from_pkcs8(der.secret_pkcs8_der()),
        // An elliptic-curve key. A GitHub App's key is always RSA, so this is
        // a file somebody picked up by mistake — a TLS key, or the key of some
        // other service that happened to be in the same directory.
        PrivateKeyDer::Sec1(_) => bail!(
            "that is an elliptic-curve key, and a github app's key is always rsa — this looks like a key for something else"
        ),
        _ => bail!("the private key is of a kind a github app never uses — it must be rsa"),
    };

    // `ring` refuses anything under 2048 bits and anything whose der does not
    // hold together, and its own words for why are more use than a summary.
    pair.map_err(|rejected| {
        anyhow!("the private key is not one github could have issued: {rejected}")
    })
}

/// Check that `pem` really is a key, and keep nothing.
///
/// Called when a connection is registered, which is the only moment an operator
/// is standing there with the file in their hand. A key that does not parse and
/// is recorded anyway fails at the first webhook instead — hours later, in a log
/// line, with nothing to point at and no obvious way back to the afternoon
/// somebody pasted the wrong file.
pub fn validate(pem: &str) -> Result<()> {
    parse(pem).map(drop)
}

/// The keys the tests in this crate sign with.
///
/// Two throwaway 2048-bit RSA keys, the same key in both encodings, committed
/// as files because there is no way to make one at test time: `ring` can
/// generate no RSA key at all, and `rcgen` generates ECDSA and Ed25519 only. A
/// fixture on disk is therefore the only way to test RS256 — the algorithm
/// every GitHub App JWT is signed with — in this workspace.
///
/// They are not secrets. Nothing trusts them, nothing has ever presented them
/// to GitHub, and anybody reading this repository has them.
#[cfg(test)]
pub(crate) mod testing {
    /// The key as GitHub writes it: `-----BEGIN RSA PRIVATE KEY-----`.
    pub(crate) const PKCS1: &str = include_str!("testing-key.pem");

    /// The very same key after a conversion to PKCS#8, which is what an
    /// operator's tooling often hands back.
    pub(crate) const PKCS8: &str = include_str!("testing-key-pkcs8.pem");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_key_github_hands_out() {
        assert!(parse(testing::PKCS1).is_ok());
        assert!(validate(testing::PKCS1).is_ok());
    }

    #[test]
    fn parses_a_key_that_has_been_converted_to_pkcs8() {
        assert!(parse(testing::PKCS8).is_ok());
        assert!(validate(testing::PKCS8).is_ok());
    }

    /// Both fixtures have to be one key, or a test that signs with one and
    /// verifies against the other would be proving nothing.
    #[test]
    fn reads_the_two_encodings_as_the_same_key() {
        let pkcs1 = parse(testing::PKCS1).unwrap();
        let pkcs8 = parse(testing::PKCS8).unwrap();

        assert_eq!(pkcs1.public().as_ref(), pkcs8.public().as_ref());
    }

    #[test]
    fn refuses_text_that_is_not_a_key_at_all() {
        let error = parse("hunter2\n").unwrap_err().to_string();

        assert!(error.contains("not pem"), "{error}");
        assert!(error.contains("BEGIN RSA PRIVATE KEY"), "{error}");
    }

    /// The realistic mistake is the file next to the key, not random text.
    #[test]
    fn refuses_a_pem_block_that_is_not_a_private_key() {
        let certificate = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

        let error = parse(certificate).unwrap_err().to_string();

        assert!(error.contains("no private key"), "{error}");
        assert!(error.contains("generate a private key"), "{error}");
    }

    /// An elliptic-curve key is a key, and is still the wrong file: saying so
    /// is the difference between "fix your key" and "find the other one".
    #[test]
    fn refuses_a_key_that_is_not_rsa() {
        // Refused for what the block says it is, so the body never has to be a
        // real curve key.
        let elliptic = "-----BEGIN EC PRIVATE KEY-----\nMIIB\n-----END EC PRIVATE KEY-----\n";

        let error = parse(elliptic).unwrap_err().to_string();

        assert!(error.contains("elliptic-curve"), "{error}");
        assert!(error.contains("rsa"), "{error}");
    }

    /// `ring` will not sign with a key under 2048 bits, so a key that is real
    /// and too small has to be refused here rather than at the first token.
    #[test]
    fn refuses_a_key_ring_will_not_sign_with() {
        // Well-formed pem, and der that is not a key.
        let nonsense = "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n";

        let error = parse(nonsense).unwrap_err().to_string();

        assert!(error.contains("github could have issued"), "{error}");
    }
}

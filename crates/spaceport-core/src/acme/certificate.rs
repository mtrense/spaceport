//! A certificate spaceport holds for one host.
//!
//! Kept as the PEM the CA issued, because that is what it *is*: re-encoding it
//! into some internal shape would mean spaceport's copy and the CA's copy could
//! disagree, and the CA's is the one that matters. Everything the rest of the
//! code wants to know — when it expires, whether it is time to renew, what
//! rustls should serve — is derived from that PEM rather than tracked beside it.

use std::fmt;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::sign::CertifiedKey;
use time::{Duration, OffsetDateTime};

use crate::app::manifest::Host;

/// How much of a certificate's lifetime is allowed to pass before spaceport
/// starts trying to replace it.
///
/// Two thirds rather than a fixed "30 days before expiry", because that fixed
/// number is only right for the 90-day certificates it was chosen for. A CA
/// issuing 7-day certificates would have spaceport renewing on every pass; one
/// issuing year-long ones would have it leaving the renewal far too late. A
/// fraction is right for both, and leaves a third of the lifetime — days, on
/// anything realistic — to keep retrying a renewal that is failing.
const RENEW_AFTER: (i32, i32) = (2, 3);

/// One host's certificate and the key that goes with it.
#[derive(Clone, PartialEq, Eq)]
pub struct Certificate {
    pub host: Host,
    /// The issued chain, PEM, leaf first.
    pub chain: String,
    /// The key the chain certifies, PEM.
    pub private_key: String,
    /// When spaceport wrote this down, RFC 3339. Not the certificate's own
    /// validity — that lives in the certificate — but a record of when this
    /// host last successfully finished an order.
    pub issued_at: String,
}

/// The window a certificate is good for, as the certificate itself states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl Validity {
    /// The moment spaceport should start trying to replace this certificate.
    pub fn renew_at(&self) -> OffsetDateTime {
        let (numerator, denominator) = RENEW_AFTER;
        let lifetime = self.not_after - self.not_before;

        self.not_before + (lifetime * numerator) / denominator
    }
}

impl Certificate {
    /// Take an issued chain and key as a certificate for `host`.
    ///
    /// The chain is parsed here rather than trusted, so a CA response that is
    /// not a certificate fails at issuance — where the error names the order —
    /// instead of at the first handshake.
    pub fn issued(host: Host, chain: String, private_key: String) -> Result<Self> {
        let certificate = Self {
            host,
            chain,
            private_key,
            issued_at: crate::state::now(),
        };
        certificate
            .validity()
            .context("the issued certificate could not be read back")?;

        Ok(certificate)
    }

    /// A certificate as it was read out of the state store.
    pub fn stored(host: Host, chain: String, private_key: String, issued_at: String) -> Self {
        Self {
            host,
            chain,
            private_key,
            issued_at,
        }
    }

    /// The window this certificate is good for, from the leaf itself.
    pub fn validity(&self) -> Result<Validity> {
        let leaf = self
            .der_chain()?
            .into_iter()
            .next()
            .context("the certificate chain is empty")?;

        let (_, parsed) = x509_parser::parse_x509_certificate(&leaf)
            .map_err(|error| anyhow::anyhow!("parsing the certificate: {error}"))?;

        let at = |timestamp: i64| {
            OffsetDateTime::from_unix_timestamp(timestamp)
                .context("the certificate names a time outside any calendar")
        };

        Ok(Validity {
            not_before: at(parsed.validity().not_before.timestamp())?,
            not_after: at(parsed.validity().not_after.timestamp())?,
        })
    }

    /// Whether it is time to replace this certificate.
    ///
    /// A certificate that cannot be parsed is due: something is wrong with it,
    /// and ordering a replacement is the only move that can put it right.
    pub fn is_due_for_renewal(&self, now: OffsetDateTime) -> bool {
        match self.validity() {
            Ok(validity) => now >= validity.renew_at(),
            Err(_) => true,
        }
    }

    /// How long until this certificate is due for renewal, or zero if it
    /// already is.
    pub fn until_renewal(&self, now: OffsetDateTime) -> Duration {
        match self.validity() {
            Ok(validity) => (validity.renew_at() - now).max(Duration::ZERO),
            Err(_) => Duration::ZERO,
        }
    }

    /// This certificate in the form rustls serves it in.
    pub fn certified_key(&self, provider: &CryptoProvider) -> Result<Arc<CertifiedKey>> {
        let chain = self.der_chain()?;
        let key = rustls_pemfile::private_key(&mut self.private_key.as_bytes())
            .context("reading the certificate's private key")?
            .context("the certificate's private key is not PEM")?;

        CertifiedKey::from_der(chain, key, provider)
            .map(Arc::new)
            .with_context(|| format!("loading the certificate for `{}`", self.host))
    }

    fn der_chain(&self) -> Result<Vec<CertificateDer<'static>>> {
        let chain = rustls_pemfile::certs(&mut self.chain.as_bytes())
            .collect::<std::io::Result<Vec<_>>>()
            .context("reading the certificate chain")?;

        if chain.is_empty() {
            bail!("the certificate for `{}` holds no certificate", self.host);
        }

        Ok(chain)
    }
}

impl fmt::Debug for Certificate {
    /// Never the key, and never the chain — one is a secret and the other is
    /// several kilobytes of base64 nobody wants in a log line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("host", &self.host)
            .field("issued_at", &self.issued_at)
            .finish_non_exhaustive()
    }
}

/// Generate a certificate for `hosts`, signed by nobody.
///
/// Used for the development provider, and by tests that need a certificate
/// without an ACME server to ask for one.
pub fn self_signed(hosts: &[String]) -> Result<(String, String)> {
    let generated = rcgen::generate_simple_self_signed(hosts.to_vec())
        .context("generating a self-signed certificate")?;

    Ok((generated.cert.pem(), generated.signing_key.serialize_pem()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// What a CA issues for. rcgen's own default runs to the year 4096, which
    /// would make every question about renewal answer "not for two thousand
    /// years" and test nothing.
    pub(crate) const LIFETIME: Duration = Duration::days(90);

    /// A self-signed certificate for `host`, as a stand-in for an issued one.
    /// Everything this module does works off the PEM, and a self-signed PEM is
    /// the same shape as one a CA hands over.
    pub(crate) fn certificate(host: &str) -> Certificate {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![host.to_owned()]).unwrap();
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = params.not_before + LIFETIME;
        let signed = params.self_signed(&key).unwrap();

        Certificate::issued(host.parse().unwrap(), signed.pem(), key.serialize_pem()).unwrap()
    }

    fn provider() -> CryptoProvider {
        rustls::crypto::ring::default_provider()
    }

    #[test]
    fn reads_its_own_validity() {
        let validity = certificate("alpha.test").validity().unwrap();

        assert!(validity.not_before < validity.not_after);
        assert!(validity.not_before <= OffsetDateTime::now_utc());
    }

    #[test]
    fn loads_as_something_rustls_can_serve() {
        let key = certificate("alpha.test")
            .certified_key(&provider())
            .unwrap();

        assert_eq!(key.cert.len(), 1);
    }

    /// The key and the chain have to belong together. A pairing that does not
    /// would serve a handshake nothing could verify.
    #[test]
    fn refuses_a_key_that_does_not_match_the_chain() {
        let mismatched = Certificate {
            private_key: certificate("beta.test").private_key,
            ..certificate("alpha.test")
        };

        assert!(mismatched.certified_key(&provider()).is_err());
    }

    #[test]
    fn refuses_a_chain_that_is_not_a_certificate() {
        let err = Certificate::issued(
            "alpha.test".parse().unwrap(),
            "not a certificate".to_owned(),
            String::new(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("read back"), "{err}");
    }

    #[test]
    fn is_due_for_renewal_two_thirds_of_the_way_through() {
        let validity = Validity {
            not_before: OffsetDateTime::from_unix_timestamp(0).unwrap(),
            not_after: OffsetDateTime::from_unix_timestamp(90).unwrap(),
        };

        assert_eq!(validity.renew_at().unix_timestamp(), 60);
    }

    #[test]
    fn a_fresh_certificate_is_not_due() {
        let certificate = certificate("alpha.test");
        let now = OffsetDateTime::now_utc();

        assert!(!certificate.is_due_for_renewal(now));
        assert!(certificate.until_renewal(now) > Duration::ZERO);
    }

    #[test]
    fn a_certificate_past_its_window_is_due() {
        let certificate = certificate("alpha.test");
        let expired = certificate.validity().unwrap().not_after + Duration::days(1);

        assert!(certificate.is_due_for_renewal(expired));
        assert_eq!(certificate.until_renewal(expired), Duration::ZERO);
    }

    /// Whatever is stored under this host, it is not something to keep serving.
    #[test]
    fn an_unreadable_certificate_is_due() {
        let broken = Certificate::stored(
            "alpha.test".parse().unwrap(),
            "garbage".to_owned(),
            String::new(),
            crate::state::now(),
        );

        assert!(broken.is_due_for_renewal(OffsetDateTime::now_utc()));
    }

    /// A private key in a log or an error message is a private key in a log.
    #[test]
    fn does_not_print_its_key() {
        let certificate = certificate("alpha.test");
        let printed = format!("{certificate:?}");

        assert!(printed.contains("alpha.test"), "{printed}");
        assert!(!printed.contains("PRIVATE KEY"), "{printed}");
    }
}

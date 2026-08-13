//! Which certificate the `https` listener presents, decided per handshake.
//!
//! rustls asks this once per connection, from inside the handshake, with the
//! name the client sent in SNI. That makes two things non-negotiable: the
//! lookup must not block, and it must always have an answer. So certificates
//! are kept parsed and ready behind an immutable snapshot the same way routes
//! are — a renewal builds a new map rather than mutating the one handshakes are
//! reading — and a host with no certificate falls back to the development
//! certificate rather than aborting.
//!
//! Falling back matters more than it looks. A brand new host has no certificate
//! *yet*: the order that gets it one is in flight, and until it lands the
//! browser sees a warning. Aborting the handshake instead would show a
//! connection failure, which says far less about what is going on.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{debug, warn};

use super::Certificate;

/// The certificates the edge serves, by host.
pub struct Resolver {
    /// What handshakes read. Replaced wholesale, never mutated in place.
    keys: RwLock<Arc<HashMap<String, Arc<CertifiedKey>>>>,
    /// Served for any host nothing has been issued for yet.
    fallback: Arc<CertifiedKey>,
    provider: Arc<CryptoProvider>,
}

impl Resolver {
    /// A resolver holding nothing but the fallback certificate.
    pub fn new(provider: Arc<CryptoProvider>, fallback: Arc<CertifiedKey>) -> Self {
        Self {
            keys: RwLock::new(Arc::new(HashMap::new())),
            fallback,
            provider,
        }
    }

    /// Serve `certificates` from now on, in place of whatever was held before.
    ///
    /// One that will not load is dropped with a warning rather than failing the
    /// install: the alternative is one unreadable certificate costing every
    /// other host the ones that are fine.
    pub fn install(&self, certificates: &[Certificate]) {
        let mut keys = HashMap::with_capacity(certificates.len());

        for certificate in certificates {
            match certificate.certified_key(&self.provider) {
                Ok(key) => {
                    keys.insert(certificate.host.to_string(), key);
                }
                Err(error) => {
                    warn!(host = %certificate.host, %error, "not serving a certificate")
                }
            }
        }

        *self.write() = Arc::new(keys);
    }

    /// How many hosts this resolver has a certificate of their own for.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether `host` is served something better than the fallback.
    pub fn has(&self, host: &str) -> bool {
        self.read().contains_key(host)
    }

    /// A `ServerConfig` that presents whatever this resolver decides, per
    /// connection. Offers HTTP/2 and falls back to 1.1.
    pub fn server_config(self: Arc<Self>) -> Result<ServerConfig> {
        let mut config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .context("building the TLS configuration")?
            .with_no_client_auth()
            .with_cert_resolver(self);

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(config)
    }

    /// A poisoned lock here would mean a panic while swapping an `Arc`. The
    /// map is still whole, and refusing to read it would mean every handshake
    /// failing from then on.
    fn read(&self) -> Arc<HashMap<String, Arc<CertifiedKey>>> {
        self.keys
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Arc<HashMap<String, Arc<CertifiedKey>>>> {
        self.keys
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // A client that sent no SNI has not said which host it wants, and
        // there is nothing to look one up by. rustls lowercases the name it
        // parses, so the map's lowercase keys match without allocating.
        let Some(host) = client_hello.server_name() else {
            debug!("a client asked for no host by name");
            return Some(self.fallback.clone());
        };

        Some(
            self.read()
                .get(host)
                .cloned()
                .unwrap_or_else(|| self.fallback.clone()),
        )
    }
}

impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolver")
            .field("hosts", &self.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::certificate::tests::certificate;

    fn resolver() -> Arc<Resolver> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let fallback = certificate("fallback.test")
            .certified_key(&provider)
            .unwrap();

        Arc::new(Resolver::new(provider, fallback))
    }

    /// `ClientHello` has no public constructor, so what SNI resolves to is
    /// tested through the map the resolver would consult.
    fn resolved(resolver: &Resolver, host: &str) -> Arc<CertifiedKey> {
        resolver
            .read()
            .get(host)
            .cloned()
            .unwrap_or_else(|| resolver.fallback.clone())
    }

    #[test]
    fn serves_the_certificate_issued_for_a_host() {
        let resolver = resolver();
        let alpha = certificate("alpha.test");
        resolver.install(&[alpha.clone(), certificate("beta.test")]);

        assert_eq!(resolver.len(), 2);
        assert!(resolver.has("alpha.test"));
        assert_eq!(
            resolved(&resolver, "alpha.test").cert,
            alpha.certified_key(&resolver.provider).unwrap().cert
        );
    }

    /// The window between a host being applied and its order finishing is
    /// exactly when a warning beats a failed connection.
    #[test]
    fn falls_back_for_a_host_nothing_has_been_issued_for() {
        let resolver = resolver();
        resolver.install(&[certificate("alpha.test")]);

        assert!(!resolver.has("unknown.test"));
        assert_eq!(
            resolved(&resolver, "unknown.test").cert,
            resolver.fallback.cert
        );
    }

    #[test]
    fn installing_replaces_everything_it_held() {
        let resolver = resolver();
        resolver.install(&[certificate("alpha.test")]);
        resolver.install(&[certificate("beta.test")]);

        assert!(!resolver.has("alpha.test"));
        assert!(resolver.has("beta.test"));
    }

    /// One certificate that will not load must not cost the others theirs.
    #[test]
    fn drops_a_certificate_it_cannot_load() {
        let resolver = resolver();
        let broken = Certificate::stored(
            "broken.test".parse().unwrap(),
            "not a certificate".to_owned(),
            String::new(),
            crate::state::now(),
        );

        resolver.install(&[broken, certificate("alpha.test")]);

        assert!(!resolver.has("broken.test"));
        assert!(resolver.has("alpha.test"));
    }

    #[test]
    fn builds_a_server_config_that_offers_http_2() {
        let config = resolver().server_config().unwrap();

        assert_eq!(
            config.alpn_protocols,
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }
}

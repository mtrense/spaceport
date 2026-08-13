//! TLS for the `https` listener.
//!
//! Every handshake goes through a [`Resolver`], whatever the configured
//! provider: the listener asks it which certificate to present for the name the
//! client sent, and it always has an answer. What differs between providers is
//! only who puts certificates *into* it — with `acme`, [`crate::acme`] does, as
//! orders complete; with `self-signed`, nobody ever does and every host is
//! served the development certificate.
//!
//! That development certificate is generated fresh at every start and is
//! trusted by nothing. It is also the fallback under `acme`, which is what a
//! host whose order has not finished yet is served: a browser warning says far
//! more about what is going on than a failed connection would.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio_rustls::TlsAcceptor;
use tracing::warn;

use crate::acme::Resolver;
use crate::acme::certificate::{self, Certificate};

/// Names the development certificate is valid for. Nothing trusts it anyway,
/// so this is about making the browser warning the *only* complaint.
const SELF_SIGNED_NAMES: &[&str] = &["localhost", "*.localhost", "127.0.0.1", "::1"];

/// The host the development certificate is filed under. Never a real host, and
/// only ever reached as the fallback.
const DEVELOPMENT_HOST: &str = "localhost";

/// A resolver holding nothing but a freshly generated development certificate.
pub fn resolver() -> Result<Arc<Resolver>> {
    // rustls needs a process-wide crypto provider. Installing it twice is not
    // an error worth failing a start over — a second call just loses the race.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        warn!("a rustls crypto provider was already installed");
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let names: Vec<String> = SELF_SIGNED_NAMES.iter().map(|&s| s.to_owned()).collect();
    let (chain, private_key) = certificate::self_signed(&names)?;
    let fallback = Certificate::issued(
        DEVELOPMENT_HOST
            .parse()
            .context("the development certificate's host")?,
        chain,
        private_key,
    )?
    .certified_key(&provider)?;

    Ok(Arc::new(Resolver::new(provider, fallback)))
}

/// The TLS acceptor serving whatever `resolver` decides, per connection.
pub fn acceptor(resolver: Arc<Resolver>) -> Result<TlsAcceptor> {
    Ok(TlsAcceptor::from(Arc::new(resolver.server_config()?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::certificate::tests::certificate;

    #[test]
    fn builds_an_acceptor() {
        assert!(acceptor(resolver().unwrap()).is_ok());
    }

    /// Nothing has been issued yet, and the listener still comes up serving
    /// something to every host that asks.
    #[test]
    fn starts_out_serving_only_the_development_certificate() {
        let resolver = resolver().unwrap();

        assert!(resolver.is_empty());
        assert!(!resolver.has("alpha.test"));
    }

    #[test]
    fn serves_what_is_installed_into_it() {
        let resolver = resolver().unwrap();
        resolver.install(&[certificate("alpha.test")]);

        assert!(resolver.has("alpha.test"));
    }
}

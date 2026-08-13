//! TLS for the `https` listener.
//!
//! Today the only provider is a self-signed certificate generated fresh at
//! every start, which is good enough to develop against and nothing else.
//! Everything goes through [`acceptor`] so that adding ACME means adding a
//! provider here, not touching the accept loop.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use tokio_rustls::TlsAcceptor;
use tracing::warn;

use crate::config::{Tls, TlsProvider};

/// Names the development certificate is valid for. Nothing trusts it anyway,
/// so this is about making the browser warning the *only* complaint.
const SELF_SIGNED_NAMES: &[&str] = &["localhost", "*.localhost", "127.0.0.1", "::1"];

/// The TLS acceptor for the configured provider.
pub fn acceptor(tls: &Tls) -> Result<TlsAcceptor> {
    match tls.provider {
        TlsProvider::SelfSigned => self_signed_acceptor(),
    }
}

/// A TLS acceptor holding a freshly generated self-signed certificate.
fn self_signed_acceptor() -> Result<TlsAcceptor> {
    // rustls needs a process-wide crypto provider. Installing it twice is not
    // an error worth failing a start over — a second call just loses the race.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        warn!("a rustls crypto provider was already installed");
    }

    let names: Vec<String> = SELF_SIGNED_NAMES.iter().map(|&s| s.to_owned()).collect();
    let generated = rcgen::generate_simple_self_signed(names)
        .context("generating a self-signed certificate")?;

    let cert = generated.cert.der().clone();
    let key = PrivateKeyDer::try_from(generated.signing_key.serialize_der())
        .map_err(|e| anyhow::anyhow!("encoding the generated private key: {e}"))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("building the TLS configuration")?;

    // Offer HTTP/2, and fall back to 1.1. hyper's auto builder handles either.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_an_acceptor() {
        assert!(acceptor(&Tls::default()).is_ok());
    }
}

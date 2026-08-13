//! What survives a restart of the certificate machinery: the account spaceport
//! orders as, and the certificates it has been issued.
//!
//! Both are things that cost something to lose. A forgotten account key means a
//! new registration and a new set of rate limits; a forgotten certificate means
//! re-ordering every host at every start, which a CA will eventually refuse. So
//! unlike a container's published port, these are written down.
//!
//! The account is keyed by directory URL. Credentials issued by Let's Encrypt's
//! staging environment mean nothing to its production one, and a setup that
//! moves between them has to register with each — keeping both means moving
//! back is free.

use anyhow::{Context, Result};
use rusqlite::OptionalExtension;
use tracing::warn;

use super::Certificate;
use crate::state::Db;

/// The certificate tables, in the vocabulary of ordering and renewing.
#[derive(Debug, Clone)]
pub struct CertificateRepository {
    db: Db,
}

impl CertificateRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Remember the account spaceport registered with `directory`.
    ///
    /// `credentials` is instant-acme's own serialization, kept opaque on
    /// purpose: it holds the account key, and there is nothing spaceport could
    /// usefully do with the parts.
    pub async fn record_account(&self, directory: &str, credentials: &str) -> Result<()> {
        let directory = directory.to_owned();
        let credentials = credentials.to_owned();
        let created_at = crate::state::now();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "INSERT INTO acme_accounts (directory, credentials, created_at)
                         VALUES (?1, ?2, ?3)
                         ON CONFLICT(directory) DO UPDATE SET
                             credentials = excluded.credentials,
                             created_at  = excluded.created_at",
                        rusqlite::params![directory, credentials, created_at],
                    )
                    .context("recording the acme account")?;

                Ok(())
            })
            .await
    }

    /// The account registered with `directory`, if there is one.
    pub async fn account(&self, directory: &str) -> Result<Option<String>> {
        let directory = directory.to_owned();

        self.db
            .call(move |connection| {
                connection
                    .query_row(
                        "SELECT credentials FROM acme_accounts WHERE directory = ?1",
                        [directory],
                        |row| row.get(0),
                    )
                    .optional()
                    .context("reading the acme account")
            })
            .await
    }

    /// Remember `certificate` as what spaceport serves for its host.
    pub async fn record_issued(&self, certificate: &Certificate) -> Result<()> {
        let host = certificate.host.to_string();
        let chain = certificate.chain.clone();
        let private_key = certificate.private_key.clone();
        let issued_at = certificate.issued_at.clone();

        self.db
            .call(move |connection| {
                connection
                    .execute(
                        "INSERT INTO certificates (host, chain, private_key, issued_at)
                         VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(host) DO UPDATE SET
                             chain       = excluded.chain,
                             private_key = excluded.private_key,
                             issued_at   = excluded.issued_at",
                        rusqlite::params![host, chain, private_key, issued_at],
                    )
                    .context("recording an issued certificate")?;

                Ok(())
            })
            .await
    }

    /// Every certificate spaceport holds.
    ///
    /// A row whose host no longer parses is skipped with a warning rather than
    /// failing the read: one unusable certificate must not cost every other
    /// host its TLS.
    pub async fn all(&self) -> Result<Vec<Certificate>> {
        let rows: Vec<(String, String, String, String)> = self
            .db
            .call(|connection| {
                let mut statement = connection
                    .prepare(
                        "SELECT host, chain, private_key, issued_at FROM certificates ORDER BY host",
                    )
                    .context("preparing the certificates query")?;

                let rows = statement
                    .query_map([], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                    })
                    .context("reading the certificates")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .context("reading the certificates")?;

                Ok(rows)
            })
            .await?;

        Ok(rows
            .into_iter()
            .filter_map(|(host, chain, private_key, issued_at)| match host.parse() {
                Ok(host) => Some(Certificate::stored(host, chain, private_key, issued_at)),
                Err(error) => {
                    warn!(host, %error, "skipping a certificate whose host is not valid");
                    None
                }
            })
            .collect())
    }

    /// Drop the certificate for `host` — nothing spaceport serves needs it.
    ///
    /// Says whether there was one, so a caller can tell a cleanup that did
    /// something from one that had nothing to do.
    pub async fn forget(&self, host: &str) -> Result<bool> {
        let host = host.to_owned();

        self.db
            .call(move |connection| {
                let forgotten = connection
                    .execute("DELETE FROM certificates WHERE host = ?1", [host])
                    .context("forgetting a certificate")?;

                Ok(forgotten > 0)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::certificate::tests::certificate;

    fn repository() -> CertificateRepository {
        CertificateRepository::new(Db::in_memory().unwrap())
    }

    #[tokio::test]
    async fn holds_no_certificates_to_begin_with() {
        let repository = repository();

        assert!(repository.all().await.unwrap().is_empty());
        assert!(
            repository
                .account("https://acme.test/dir")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn remembers_an_account_per_directory() {
        let repository = repository();
        repository
            .record_account("https://staging.test/dir", "staging-credentials")
            .await
            .unwrap();
        repository
            .record_account("https://production.test/dir", "production-credentials")
            .await
            .unwrap();

        assert_eq!(
            repository
                .account("https://staging.test/dir")
                .await
                .unwrap(),
            Some("staging-credentials".to_owned())
        );
        assert_eq!(
            repository
                .account("https://production.test/dir")
                .await
                .unwrap(),
            Some("production-credentials".to_owned())
        );
    }

    #[tokio::test]
    async fn replaces_the_account_when_it_is_registered_again() {
        let repository = repository();
        repository
            .record_account("https://acme.test/dir", "old")
            .await
            .unwrap();
        repository
            .record_account("https://acme.test/dir", "new")
            .await
            .unwrap();

        assert_eq!(
            repository.account("https://acme.test/dir").await.unwrap(),
            Some("new".to_owned())
        );
    }

    #[tokio::test]
    async fn remembers_an_issued_certificate() {
        let repository = repository();
        let issued = certificate("alpha.test");
        repository.record_issued(&issued).await.unwrap();

        let stored = repository.all().await.unwrap();
        assert_eq!(stored, [issued]);
    }

    /// A renewal replaces the certificate for its host rather than adding one:
    /// the resolver only ever serves one per host.
    #[tokio::test]
    async fn a_renewal_replaces_what_was_there() {
        let repository = repository();
        repository
            .record_issued(&certificate("alpha.test"))
            .await
            .unwrap();
        let renewed = certificate("alpha.test");
        repository.record_issued(&renewed).await.unwrap();

        assert_eq!(repository.all().await.unwrap(), [renewed]);
    }

    #[tokio::test]
    async fn lists_certificates_in_a_stable_order() {
        let repository = repository();
        for host in ["zulu.test", "alpha.test", "mike.test"] {
            repository.record_issued(&certificate(host)).await.unwrap();
        }

        let hosts: Vec<String> = repository
            .all()
            .await
            .unwrap()
            .iter()
            .map(|certificate| certificate.host.to_string())
            .collect();
        assert_eq!(hosts, ["alpha.test", "mike.test", "zulu.test"]);
    }

    #[tokio::test]
    async fn forgets_a_certificate() {
        let repository = repository();
        repository
            .record_issued(&certificate("alpha.test"))
            .await
            .unwrap();

        assert!(repository.forget("alpha.test").await.unwrap());
        assert!(!repository.forget("alpha.test").await.unwrap());
        assert!(repository.all().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn skips_a_certificate_whose_host_is_not_valid() {
        let repository = repository();
        repository
            .record_issued(&certificate("alpha.test"))
            .await
            .unwrap();
        repository
            .db
            .call(|connection| {
                connection
                    .execute(
                        "INSERT INTO certificates (host, chain, private_key, issued_at)
                         VALUES ('not a host', '', '', '2026-01-01T00:00:00Z')",
                        [],
                    )
                    .context("inserting a broken record")?;

                Ok(())
            })
            .await
            .unwrap();

        let stored = repository.all().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].host.as_str(), "alpha.test");
    }
}

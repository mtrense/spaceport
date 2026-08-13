//! Talking to an ACME CA: the account, and the orders placed under it.
//!
//! This is the only file that knows RFC 8555 exists. What it turns that into is
//! a [`CertificateAuthority`] — "ask for a host, get a certificate" — and
//! everything else in spaceport works against that.
//!
//! The account is registered once and then kept: the key in it is the identity
//! the CA knows spaceport by, along with whatever rate limit budget that
//! identity has earned. Losing it means starting over as a stranger.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, AuthorizationStatus, ChallengeType, HttpClient,
    Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use tracing::{debug, info};

use super::{Certificate, CertificateAuthority, CertificateRepository, Challenges};
use crate::app::manifest::Host;
use crate::config;

/// How long to wait for a CA to validate a challenge before giving up on this
/// attempt. Generous, because the CA decides when it gets round to it; not
/// unbounded, because a pass that never returns is a pass that never renews
/// anything else either.
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for the certificate itself once the order is ready. Signing
/// is quick; this is only there for a CA having a slow minute.
const ISSUANCE_TIMEOUT: Duration = Duration::from_secs(60);

/// How the ACME client reaches the CA.
///
/// [`Transport::Supplied`] is the seam the order flow is tested through: a
/// directory answered in-process, so the challenge wiring — the part spaceport
/// actually owns — is exercised without a CA, a socket, or a certificate that
/// anything has to trust.
pub enum Transport {
    /// Over the network, verifying the CA against the host's trust store.
    Network,
    /// Through HTTP clients the caller makes.
    Supplied(Box<dyn Fn() -> Box<dyn HttpClient> + Send + Sync>),
}

impl Transport {
    /// A fresh account builder. One per call, because instant-acme takes the
    /// client by value and a registration may need a second attempt.
    fn builder(&self) -> Result<AccountBuilder> {
        match self {
            Self::Network => Account::builder().context("preparing the acme client"),
            Self::Supplied(client) => Ok(Account::builder_with_http(client())),
        }
    }
}

/// An ACME CA spaceport has an account with.
pub struct AcmeCa {
    account: Account,
    directory: String,
    /// Where an in-flight order publishes what the CA is about to come and ask
    /// for. The edge answers out of the same store.
    challenges: Arc<Challenges>,
}

impl AcmeCa {
    /// Pick up the account spaceport has with this CA, registering one if this
    /// is the first time it has ordered from it.
    pub async fn connect(
        acme: &config::Acme,
        repository: &CertificateRepository,
        challenges: Arc<Challenges>,
        transport: &Transport,
    ) -> Result<Self> {
        let directory = acme.directory.url().to_owned();

        let account = match repository.account(&directory).await? {
            Some(stored) => {
                let credentials: AccountCredentials = serde_json::from_str(&stored)
                    .context("reading the stored acme account credentials")?;

                let account = transport
                    .builder()?
                    .from_credentials(credentials)
                    .await
                    .with_context(|| format!("using the acme account at `{directory}`"))?;
                debug!(
                    directory,
                    id = account.id(),
                    "using the stored acme account"
                );

                account
            }
            None => Self::register(acme, &directory, repository, transport).await?,
        };

        Ok(Self {
            account,
            directory,
            challenges,
        })
    }

    /// Register with the CA and write the credentials down before doing
    /// anything else with them. An account that exists at the CA but not in the
    /// state store is one nobody can ever use again.
    async fn register(
        acme: &config::Acme,
        directory: &str,
        repository: &CertificateRepository,
        transport: &Transport,
    ) -> Result<Account> {
        let contact: Vec<&str> = acme.contact.iter().map(String::as_str).collect();
        let (account, credentials) = transport
            .builder()?
            .create(
                &NewAccount {
                    contact: &contact,
                    terms_of_service_agreed: acme.terms_of_service_agreed,
                    only_return_existing: false,
                },
                directory.to_owned(),
                None,
            )
            .await
            .with_context(|| format!("registering an acme account at `{directory}`"))?;

        repository
            .record_account(
                directory,
                &serde_json::to_string(&credentials)
                    .context("serializing the acme account credentials")?,
            )
            .await
            .context("storing the acme account credentials")?;

        info!(directory, id = account.id(), "registered an acme account");

        Ok(account)
    }
}

#[async_trait]
impl CertificateAuthority for AcmeCa {
    /// One order, for one host, start to finish.
    ///
    /// The shape is RFC 8555's: place an order, answer every authorization it
    /// comes back with, tell the CA to go and check, then finalize. The answers
    /// stay published for exactly as long as the order is in flight — the
    /// guards in `pending` see to that, including when this returns early with
    /// an error.
    async fn issue(&self, host: &Host) -> Result<Certificate> {
        let identifiers = [Identifier::Dns(host.to_string())];
        let mut order = self
            .account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .with_context(|| format!("ordering a certificate for `{host}`"))?;

        let mut pending = Vec::new();
        {
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization =
                    authorization.with_context(|| format!("reading the order for `{host}`"))?;

                // An authorization the CA already considers settled — from an
                // earlier order for the same host — needs no challenge, and
                // answering one it did not ask for would be an error.
                if authorization.status == AuthorizationStatus::Valid {
                    debug!(%host, "the ca already considers this host authorized");
                    continue;
                }

                let mut challenge = authorization
                    .challenge(ChallengeType::Http01)
                    .with_context(|| format!("`{host}` was offered no http-01 challenge"))?;

                // Published *before* the CA is told to come and look, or it
                // may arrive to find spaceport answering `404`.
                pending.push(self.challenges.expect(
                    challenge.token.clone(),
                    challenge.key_authorization().as_str().to_owned(),
                ));

                challenge
                    .set_ready()
                    .await
                    .with_context(|| format!("asking the ca to validate `{host}`"))?;
            }
        }

        let status = order
            .poll_ready(&RetryPolicy::default().timeout(VALIDATION_TIMEOUT))
            .await
            .with_context(|| format!("waiting for the ca to validate `{host}`"))?;
        if status != OrderStatus::Ready {
            bail!("the ca left the order for `{host}` {status:?} rather than ready");
        }

        // instant-acme generates the key and the CSR. The key never leaves this
        // process; what comes back from the CA is only ever the certificate.
        let private_key = order
            .finalize()
            .await
            .with_context(|| format!("asking the ca to issue for `{host}`"))?;
        let chain = order
            .poll_certificate(&RetryPolicy::default().timeout(ISSUANCE_TIMEOUT))
            .await
            .with_context(|| format!("collecting the certificate for `{host}`"))?;

        Certificate::issued(host.clone(), chain, private_key)
    }

    fn describe(&self) -> String {
        self.directory.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Db;

    mod fake_ca;
    use fake_ca::FakeDirectory;

    fn config(directory: &str) -> config::Acme {
        config::Acme {
            directory: config::Directory::Url(directory.to_owned()),
            contact: vec!["mailto:ops@example.test".to_owned()],
            terms_of_service_agreed: true,
        }
    }

    /// A CA, an empty state store and an empty challenge store, wired to each
    /// other the way `spaceport run` wires them.
    fn setup() -> (Arc<FakeDirectory>, CertificateRepository, Arc<Challenges>) {
        let challenges = Arc::new(Challenges::new());

        (
            FakeDirectory::new(challenges.clone()),
            CertificateRepository::new(Db::in_memory().unwrap()),
            challenges,
        )
    }

    async fn connect(
        ca: &Arc<FakeDirectory>,
        repository: &CertificateRepository,
        challenges: &Arc<Challenges>,
    ) -> Result<AcmeCa> {
        AcmeCa::connect(
            &config(FakeDirectory::URL),
            repository,
            challenges.clone(),
            &ca.transport(),
        )
        .await
    }

    fn host(host: &str) -> Host {
        host.parse().unwrap()
    }

    #[tokio::test]
    async fn registers_an_account_and_remembers_it() {
        let (ca, repository, challenges) = setup();

        connect(&ca, &repository, &challenges).await.unwrap();

        assert_eq!(ca.registrations(), 1);
        assert_eq!(ca.contacts(), [["mailto:ops@example.test"]]);
        assert!(
            repository
                .account(FakeDirectory::URL)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// The account key is the identity a CA's rate limits are counted against.
    /// A restart that registered again would spend a new one every time.
    #[tokio::test]
    async fn a_restart_uses_the_account_it_already_has() {
        let (ca, repository, challenges) = setup();
        connect(&ca, &repository, &challenges).await.unwrap();

        connect(&ca, &repository, &challenges).await.unwrap();

        assert_eq!(ca.registrations(), 1);
    }

    /// The whole flow: order, publish the answer, let the CA come and read it
    /// off the edge, and end up with a certificate for the host that was asked
    /// for.
    #[tokio::test]
    async fn orders_a_certificate_by_answering_the_challenge() {
        let (ca, repository, challenges) = setup();
        let acme = connect(&ca, &repository, &challenges).await.unwrap();

        let certificate = acme.issue(&host("alpha.test")).await.unwrap();

        assert_eq!(certificate.host, host("alpha.test"));
        assert!(certificate.validity().unwrap().not_after > time::OffsetDateTime::now_utc());
        assert_eq!(ca.validated(), ["alpha.test"]);
    }

    /// A token spaceport is still answering is a token it would answer for
    /// anybody. The moment the order is done it must be gone.
    #[tokio::test]
    async fn stops_answering_once_the_order_is_finished() {
        let (ca, repository, challenges) = setup();
        let acme = connect(&ca, &repository, &challenges).await.unwrap();

        acme.issue(&host("alpha.test")).await.unwrap();

        assert!(challenges.is_empty());
    }

    /// The usual failure: the host's DNS does not point here, so the CA reads
    /// somebody else's server — or nothing — and refuses.
    #[tokio::test]
    async fn reports_a_challenge_the_ca_would_not_accept() {
        let (ca, repository, challenges) = setup();
        ca.refuse_validation();
        let acme = connect(&ca, &repository, &challenges).await.unwrap();

        let err = format!("{:#}", acme.issue(&host("alpha.test")).await.unwrap_err());

        assert!(err.contains("alpha.test"), "{err}");
        // And nothing is left published for the next order to trip over.
        assert!(challenges.is_empty());
    }

    /// A CA that only offers challenges spaceport cannot answer is a CA
    /// spaceport cannot use, and saying so beats waiting for a timeout.
    #[tokio::test]
    async fn reports_a_ca_that_offers_no_http_challenge() {
        let (ca, repository, challenges) = setup();
        ca.offer_only_dns();
        let acme = connect(&ca, &repository, &challenges).await.unwrap();

        let err = format!("{:#}", acme.issue(&host("alpha.test")).await.unwrap_err());

        assert!(err.contains("http-01"), "{err}");
    }
}

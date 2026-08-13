//! Certificates: getting them, keeping them, and serving them.
//!
//! Spaceport gets certificates the way RFC 8555 says: it registers an account
//! with a CA, and for each host it serves, proves control of that host by
//! answering an `HTTP-01` challenge on port 80. That is why the plaintext
//! listener exists at all, and why [`crate::edge::service`] claims
//! `/.well-known/acme-challenge/` ahead of every proxy route — an app that
//! served that path itself could otherwise take renewal down.
//!
//! The parts, and why they are separate:
//!
//! - [`CertificateAuthority`] is *where certificates come from*. The ACME
//!   implementation is one of them; a test double is another. Everything above
//!   this line — when to order, what to do when an order fails, what to serve
//!   in the meantime — is spaceport's, and is tested without a CA.
//! - [`Certificate`] is one issued certificate, which answers questions about
//!   itself by reading itself rather than by being told.
//! - [`CertificateRepository`] is what survives a restart.
//! - [`Resolver`] is what a handshake consults.
//! - [`Challenges`] is what an in-flight order publishes.
//!
//! One order per host, never a single certificate covering all of them. A SAN
//! certificate would be one order instead of many, but it would also mean one
//! host whose DNS is not pointing here yet costing every other host its
//! certificate — and hosts arrive one at a time, so that case is the normal
//! one, not the exception.

pub mod account;
pub mod certificate;
pub mod challenge;
pub mod repository;
pub mod resolver;

pub use certificate::Certificate;
pub use challenge::Challenges;
pub use repository::CertificateRepository;
pub use resolver::Resolver;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::app::AppStore;
use crate::app::manifest::Host;

/// How long to wait before trying again after an order failed.
///
/// Short enough that a host whose DNS has just started pointing here gets its
/// certificate within the hour, long enough that a host whose DNS never will
/// is not hammering a CA that answers with rate limits.
const RETRY_AFTER_FAILURE: Duration = Duration::minutes(5);

/// Longest spaceport will sleep between passes, however far away the next
/// renewal is. A wall clock that jumps, or a certificate revoked out from
/// under it, should cost hours rather than weeks.
const LONGEST_SLEEP: Duration = Duration::hours(6);

/// Where certificates come from.
///
/// Exists so that everything spaceport decides — when to order, what to do
/// when an order fails, what to serve while one is in flight — can be exercised
/// without a CA, and so that a second way of getting certificates can be added
/// without touching any of it.
#[async_trait]
pub trait CertificateAuthority: Send + Sync {
    /// Prove control of `host` and come back with a certificate for it.
    ///
    /// Takes as long as it takes: the CA decides when it has finished
    /// validating, and this returns when it has.
    async fn issue(&self, host: &Host) -> Result<Certificate>;

    /// What to call this CA in a log line.
    fn describe(&self) -> String;
}

/// The certificates spaceport holds, and the machinery that keeps them current.
pub struct Certificates {
    ca: Arc<dyn CertificateAuthority>,
    repository: CertificateRepository,
    resolver: Arc<Resolver>,
    /// Everything spaceport has, by host. The resolver holds the same set,
    /// parsed and ready to serve; this one is the record it is rebuilt from.
    held: Mutex<BTreeMap<Host, Certificate>>,
}

/// What one pass over the wanted hosts did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pass {
    /// Hosts that got a certificate they did not have.
    pub issued: Vec<Host>,
    /// Hosts whose certificate was replaced before it expired.
    pub renewed: Vec<Host>,
    /// Hosts an order was attempted and failed for.
    pub failed: Vec<Host>,
}

impl Pass {
    pub fn is_empty(&self) -> bool {
        self.issued.is_empty() && self.renewed.is_empty() && self.failed.is_empty()
    }
}

impl Certificates {
    /// Take up the certificates already in the state store.
    ///
    /// A restart serves what it had from the first handshake on, without
    /// waiting for — or asking a CA for — anything.
    pub async fn load(
        ca: Arc<dyn CertificateAuthority>,
        repository: CertificateRepository,
        resolver: Arc<Resolver>,
    ) -> Result<Self> {
        let held: BTreeMap<Host, Certificate> = repository
            .all()
            .await?
            .into_iter()
            .map(|certificate| (certificate.host.clone(), certificate))
            .collect();

        resolver.install(&held.values().cloned().collect::<Vec<_>>());
        if !held.is_empty() {
            info!(certificates = held.len(), "took up the stored certificates");
        }

        Ok(Self {
            ca,
            repository,
            resolver,
            held: Mutex::new(held),
        })
    }

    /// The resolver the edge serves from.
    pub fn resolver(&self) -> &Arc<Resolver> {
        &self.resolver
    }

    /// Order what is missing, renew what is due, and say when to come back.
    ///
    /// Hosts that are no longer served keep their certificates — they cost a
    /// round trip and a slice of a CA's rate limit to obtain, and an app that
    /// comes back tomorrow should not pay for that twice — but they are not
    /// renewed. Only hosts something is actually serving are worth an order.
    pub async fn reconcile(
        &self,
        wanted: &BTreeSet<Host>,
        now: OffsetDateTime,
    ) -> (Pass, Duration) {
        let mut pass = Pass::default();
        let mut sleep = LONGEST_SLEEP;

        for host in wanted {
            let existing = self.held.lock().await.get(host).cloned();
            let renewal = match &existing {
                Some(certificate) if !certificate.is_due_for_renewal(now) => {
                    sleep = sleep.min(certificate.until_renewal(now));
                    continue;
                }
                Some(_) => true,
                None => false,
            };

            match self.ca.issue(host).await {
                Ok(certificate) => {
                    self.take(certificate).await;
                    if renewal {
                        info!(%host, "renewed the certificate");
                        pass.renewed.push(host.clone());
                    } else {
                        info!(%host, "got a certificate");
                        pass.issued.push(host.clone());
                    }
                }
                // Almost always a host whose DNS does not point here yet, which
                // is the operator's to fix and spaceport's to keep retrying.
                Err(error) => {
                    warn!(%host, error = %format!("{error:#}"), "could not get a certificate");
                    pass.failed.push(host.clone());
                    sleep = sleep.min(RETRY_AFTER_FAILURE);
                }
            }
        }

        // A pass that changed nothing and has nothing outstanding can sleep
        // until the first certificate is due, and no longer.
        if let Some(shortest) = self.shortest_wait(wanted, now).await {
            sleep = sleep.min(shortest);
        }

        (pass, sleep.max(Duration::ZERO))
    }

    /// Record `certificate`, and start serving it.
    ///
    /// Written down before it is served: a certificate served but not stored
    /// would be re-ordered at the next restart, and re-ordering is the thing a
    /// CA's rate limits punish.
    async fn take(&self, certificate: Certificate) {
        if let Err(error) = self.repository.record_issued(&certificate).await {
            warn!(
                host = %certificate.host,
                %error,
                "could not store the certificate, it will be ordered again after a restart",
            );
        }

        let mut held = self.held.lock().await;
        held.insert(certificate.host.clone(), certificate);
        self.resolver
            .install(&held.values().cloned().collect::<Vec<_>>());
    }

    /// How long until the soonest renewal among `wanted`.
    async fn shortest_wait(
        &self,
        wanted: &BTreeSet<Host>,
        now: OffsetDateTime,
    ) -> Option<Duration> {
        let held = self.held.lock().await;

        wanted
            .iter()
            .filter_map(|host| held.get(host))
            .map(|certificate| certificate.until_renewal(now))
            .min()
    }

    /// The hosts this holds a certificate for.
    pub async fn hosts(&self) -> Vec<Host> {
        self.held.lock().await.keys().cloned().collect()
    }
}

/// Keep the certificates for whatever `apps` is serving current, until
/// `shutdown` is cancelled.
///
/// Wakes on three things: a change to what is being served, so a newly applied
/// app gets its certificate in seconds rather than at the next tick; the
/// deadline the last pass asked for; and shutdown.
pub async fn maintain(
    certificates: Arc<Certificates>,
    apps: Arc<AppStore>,
    shutdown: CancellationToken,
) {
    info!(
        ca = certificates.ca.describe(),
        "keeping certificates current"
    );
    let mut changed = apps.changed();

    loop {
        let wanted = apps.routes().hosts();
        let (pass, sleep) = certificates
            .reconcile(&wanted, OffsetDateTime::now_utc())
            .await;

        if !pass.is_empty() {
            info!(
                issued = pass.issued.len(),
                renewed = pass.renewed.len(),
                failed = pass.failed.len(),
                "certificates reconciled",
            );
        }
        debug!(seconds = sleep.whole_seconds(), "waiting for the next pass");

        // A negative or absurd duration cannot come out of `reconcile`, but
        // `unsigned_abs` means a clock that has done something strange costs a
        // busy loop at worst rather than a panic.
        let sleep = sleep.unsigned_abs();

        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(sleep) => {}
            // The apps changed: a host may have arrived that has no
            // certificate, or one may have gone that no longer needs renewing.
            result = changed.changed() => {
                if result.is_err() {
                    break;
                }
            }
        }
    }

    debug!("stopped keeping certificates current");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    use crate::acme::certificate::tests::certificate;
    use crate::state::Db;

    /// A CA that issues whatever it is asked for, and can be told to stop.
    #[derive(Default)]
    struct FakeCa {
        issued: StdMutex<Vec<Host>>,
        refuse: StdMutex<bool>,
    }

    #[async_trait]
    impl CertificateAuthority for FakeCa {
        async fn issue(&self, host: &Host) -> Result<Certificate> {
            self.issued.lock().unwrap().push(host.clone());
            if *self.refuse.lock().unwrap() {
                anyhow::bail!("the dns for `{host}` does not point here");
            }

            Ok(certificate(host.as_str()))
        }

        fn describe(&self) -> String {
            "a fake ca".to_owned()
        }
    }

    impl FakeCa {
        fn orders(&self) -> Vec<String> {
            self.issued
                .lock()
                .unwrap()
                .iter()
                .map(ToString::to_string)
                .collect()
        }
    }

    fn resolver() -> Arc<Resolver> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let fallback = certificate("fallback.test")
            .certified_key(&provider)
            .unwrap();

        Arc::new(Resolver::new(provider, fallback))
    }

    async fn certificates() -> (Arc<Certificates>, Arc<FakeCa>, CertificateRepository) {
        let ca = Arc::new(FakeCa::default());
        let repository = CertificateRepository::new(Db::in_memory().unwrap());
        let certificates = Certificates::load(ca.clone(), repository.clone(), resolver())
            .await
            .unwrap();

        (Arc::new(certificates), ca, repository)
    }

    fn hosts(hosts: &[&str]) -> BTreeSet<Host> {
        hosts.iter().map(|host| host.parse().unwrap()).collect()
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    #[tokio::test]
    async fn orders_a_certificate_for_a_host_that_has_none() {
        let (certificates, ca, repository) = certificates().await;

        let (pass, _) = certificates.reconcile(&hosts(&["alpha.test"]), now()).await;

        assert_eq!(pass.issued.len(), 1);
        assert!(pass.failed.is_empty());
        assert_eq!(ca.orders(), ["alpha.test"]);
        // Stored, and being served.
        assert_eq!(repository.all().await.unwrap().len(), 1);
        assert!(certificates.resolver().has("alpha.test"));
    }

    /// The expensive mistake this whole module is arranged to avoid: ordering
    /// again for a host that already has a perfectly good certificate.
    #[tokio::test]
    async fn does_not_order_again_for_a_host_that_is_covered() {
        let (certificates, ca, _) = certificates().await;
        let wanted = hosts(&["alpha.test"]);
        certificates.reconcile(&wanted, now()).await;

        let (pass, sleep) = certificates.reconcile(&wanted, now()).await;

        assert!(pass.is_empty());
        assert_eq!(ca.orders().len(), 1);
        // And it comes back when that certificate is due, not before.
        assert!(sleep > Duration::ZERO);
    }

    #[tokio::test]
    async fn renews_a_certificate_that_is_due() {
        let (certificates, ca, _) = certificates().await;
        let wanted = hosts(&["alpha.test"]);
        certificates.reconcile(&wanted, now()).await;

        // Past two thirds of the certificate's lifetime, so it is due.
        let later = now() + certificate::tests::LIFETIME;
        let (pass, _) = certificates.reconcile(&wanted, later).await;

        assert_eq!(pass.renewed, ["alpha.test".parse::<Host>().unwrap()]);
        assert!(pass.issued.is_empty());
        assert_eq!(ca.orders().len(), 2);
    }

    #[tokio::test]
    async fn a_failed_order_is_retried_soon() {
        let (certificates, ca, repository) = certificates().await;
        *ca.refuse.lock().unwrap() = true;

        let (pass, sleep) = certificates.reconcile(&hosts(&["alpha.test"]), now()).await;

        assert_eq!(pass.failed.len(), 1);
        assert_eq!(sleep, RETRY_AFTER_FAILURE);
        assert!(repository.all().await.unwrap().is_empty());
        assert!(!certificates.resolver().has("alpha.test"));
    }

    /// One host whose DNS is not ready must not stop the hosts whose is.
    #[tokio::test]
    async fn one_hosts_failure_does_not_cost_the_others() {
        let (certificates, ca, _) = certificates().await;
        certificates.reconcile(&hosts(&["alpha.test"]), now()).await;
        *ca.refuse.lock().unwrap() = true;

        let (pass, _) = certificates
            .reconcile(&hosts(&["alpha.test", "beta.test"]), now())
            .await;

        assert_eq!(pass.failed, ["beta.test".parse::<Host>().unwrap()]);
        assert!(certificates.resolver().has("alpha.test"));
    }

    /// A restart must serve what it had, and must not re-order any of it.
    #[tokio::test]
    async fn takes_up_the_stored_certificates_without_ordering() {
        let (certificates, _, repository) = certificates().await;
        let wanted = hosts(&["alpha.test", "beta.test"]);
        certificates.reconcile(&wanted, now()).await;

        let ca = Arc::new(FakeCa::default());
        let restarted = Certificates::load(ca.clone(), repository, resolver())
            .await
            .unwrap();

        assert_eq!(restarted.hosts().await.len(), 2);
        assert!(restarted.resolver().has("alpha.test"));
        let (pass, _) = restarted.reconcile(&wanted, now()).await;
        assert!(pass.is_empty());
        assert!(ca.orders().is_empty());
    }

    /// A certificate costs a slice of a CA's rate limit. An app that is
    /// destroyed and re-applied should not spend a second one.
    #[tokio::test]
    async fn keeps_the_certificate_of_a_host_that_is_no_longer_served() {
        let (certificates, ca, _) = certificates().await;
        certificates.reconcile(&hosts(&["alpha.test"]), now()).await;

        let (pass, _) = certificates.reconcile(&BTreeSet::new(), now()).await;

        assert!(pass.is_empty());
        assert_eq!(certificates.hosts().await.len(), 1);
        assert!(certificates.resolver().has("alpha.test"));
        assert_eq!(ca.orders().len(), 1);
    }

    /// Nothing to serve, nothing to renew: sleep until something happens.
    #[tokio::test]
    async fn sleeps_when_there_is_nothing_to_do() {
        let (certificates, _, _) = certificates().await;

        let (pass, sleep) = certificates.reconcile(&BTreeSet::new(), now()).await;

        assert!(pass.is_empty());
        assert_eq!(sleep, LONGEST_SLEEP);
    }

    /// The loop has to come back before the certificate it is holding expires.
    #[tokio::test]
    async fn sleeps_no_longer_than_the_soonest_renewal() {
        let (certificates, _, _) = certificates().await;
        let wanted = hosts(&["alpha.test"]);

        let (_, sleep) = certificates.reconcile(&wanted, now()).await;

        let held = certificates.held.lock().await;
        let until = held["alpha.test"].until_renewal(now());
        assert!(sleep <= until, "{sleep} > {until}");
    }

    #[tokio::test]
    async fn the_loop_stops_when_it_is_shut_down() {
        let (certificates, ca, _) = certificates().await;
        let apps = Arc::new(AppStore::new());
        let shutdown = CancellationToken::new();

        let running = tokio::spawn(maintain(certificates, apps, shutdown.clone()));
        // Nothing is served, so the first pass has nothing to order.
        tokio::task::yield_now().await;
        shutdown.cancel();

        running.await.unwrap();
        assert!(ca.orders().is_empty());
    }
}

//! What this spaceport is, asked at the moment somebody wants to know.
//!
//! `spaceport apps list` answers "what is running?"; this answers the question
//! before it — "is this instance the one I deployed, is it listening where I
//! think, and are the three things everything else depends on still there?".
//! Those three are the container engine, the state store and the certificates:
//! each of them can fail quietly and leave an otherwise healthy-looking
//! spaceport serving nothing.
//!
//! Nothing here fails as a whole. A status report that refuses to answer
//! because the docker socket has gone is a report that withholds the one thing
//! the operator is looking for, so every part that can fail carries its own
//! error and the rest of the report is gathered anyway.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::acme::{CertificateRepository, Certificates};
use crate::app::reconcile::Report;
use crate::app::{AppId, Applier, health};
use crate::build::repository::BuildRepository;
use crate::config::{Config, TlsProvider};
use crate::connections::github::{self, ConnectionRepository, TrackingRepository};
use crate::operator::OperatorEndpoint;
use crate::state::Db;

/// Everything the running process would have to be asked for to answer
/// [`Instance::snapshot`].
///
/// Assembled once at startup and held by the operator interface: the parts a
/// status report is made of are scattered across a spaceport that otherwise
/// has no reason to know about each other, and this is the one place they meet.
pub struct Instance {
    /// The version of the binary that is running, which is what an operator
    /// checking a deployment is really asking about.
    pub version: String,
    /// When this process started, in UTC.
    pub started_at: OffsetDateTime,
    /// The config file it read, and what it read from it.
    pub config_path: PathBuf,
    pub config: Config,
    /// Where this very interface is listening.
    pub operator: OperatorEndpoint,
    pub applier: Arc<Applier>,
    pub db: Db,
    /// The GitHub Apps this spaceport has registered as itself. Held here
    /// rather than made on demand so that every handler which needs one gets
    /// the same one, over the same database.
    pub connections: Arc<ConnectionRepository>,
    /// Which repository each app is built from. Held beside `connections` and
    /// over the same database, for the same reason: a handler that points an
    /// app at a branch must be looking at the same rows as the edge that will
    /// be told about the pushes to it. Nothing reads it yet.
    pub tracking: Arc<TrackingRepository>,
    /// What became of the revisions those trackings named. Held beside them
    /// because that is the question an operator asks straight after "what is
    /// this app built from" — and the same rows the worker writes are the ones
    /// a report has to read, or a failed build would be invisible here.
    pub builds: Arc<BuildRepository>,
    /// How anything that has to ask GitHub something reaches it. One for the
    /// whole process, so every connection shares the connection pool rather
    /// than opening a TLS session per operator command.
    pub github: Arc<dyn github::Transport>,
    /// The App Manifest registrations an operator has begun and not yet
    /// finished. Held here because the two halves of that flow arrive at two
    /// different listeners — the operator socket issues the state, the edge
    /// answers for it — and this is the only thing both of them can see.
    pub attempts: Arc<github::Attempts>,
    /// How a handler tells the reconciler that what it has cached is stale.
    /// The same one the edge and the reconciliation loop hold: connecting an
    /// App on this socket is one of the things that makes it so.
    pub nudge: github::Nudge,
    /// How a handler tells the build worker that there is a revision to build.
    /// The same one the worker itself and the edge that hears the pushes hold,
    /// and deliberately not [`Instance::nudge`]: that one sends spaceport to
    /// ask GitHub where its App is installed, which is a round trip per
    /// connection and nothing a tracking has any use for.
    pub building: github::Nudge,
    /// How a handler tells the deploying worker to go and look at what has been
    /// built. The same one the builder shoves when an image exists, because
    /// there is one loop and it reads the rows either way.
    ///
    /// What an operator does on this socket can make a built revision
    /// deployable without anything being built: resuming an app that was
    /// suspended when its build finished, or arming one whose image was made
    /// while it deployed nothing on its own. Both leave a row saying "not
    /// deployed yet" that the next pass would find — in up to
    /// [`crate::app::deploy::Policy::interval`], which is five minutes of an
    /// operator watching a commit they can see was built go nowhere. The shove
    /// is what makes it seconds, and it decides only *when* the loop looks.
    pub deploying: github::Nudge,
    /// Absent when tls is self-signed: then nothing ever orders a certificate.
    pub certificates: Option<Arc<Certificates>>,
    /// What the reconciliation at startup did. Kept because it is the only
    /// account of why an app that was recorded is not running now.
    pub reconciled: Report,
}

impl Instance {
    /// Look at everything, now.
    pub async fn snapshot(&self) -> Status {
        let now = OffsetDateTime::now_utc();
        let apps = self.applier.store().apps();
        let routed_hosts = self.applier.store().routes().hosts();

        Status {
            version: self.version.clone(),
            started_at: self.started_at,
            uptime_seconds: (now - self.started_at)
                .whole_seconds()
                .max(0)
                .unsigned_abs(),
            config: self.config_path.display().to_string(),
            state: self.state().await,
            edge: Edge {
                hostname: self.config.edge.hostname.as_ref().map(ToString::to_string),
                http: self.config.edge.listen.http,
                https: self.config.edge.listen.https,
                routed_hosts: routed_hosts.len(),
            },
            tls: self.tls(),
            operator: self.operator.to_string(),
            engine: self.engine().await,
            apps: self.apps(&apps).await,
            certificates: self
                .certificates(
                    &routed_hosts
                        .iter()
                        .map(|host| host.to_string())
                        .collect::<Vec<_>>(),
                    now,
                )
                .await,
            reconcile: Reconcile {
                restored: self.reconciled.restored.len(),
                adopted: self.reconciled.adopted,
                failed: self.reconciled.failed.len(),
                swept: self.reconciled.swept,
            },
            // A count and no more: which apps they are is `spaceport connect
            // list`, and a status that named them would be repeating it.
            // Unreadable connections count as none rather than failing the
            // report, which is what every other part of this does.
            connections: self.connections.all().await.map_or(0, |all| all.len()),
        }
    }

    async fn state(&self) -> State {
        let path = Db::path_in(&self.config.state.directory)
            .display()
            .to_string();

        match self.db.schema_version().await {
            Ok(version) => State {
                path,
                schema_version: Some(version),
                error: None,
            },
            Err(error) => State {
                path,
                schema_version: None,
                error: Some(format!("{error:#}")),
            },
        }
    }

    fn tls(&self) -> Tls {
        match (&self.config.edge.tls.provider, &self.config.edge.tls.acme) {
            (TlsProvider::Acme, Some(acme)) => Tls {
                provider: "acme".to_owned(),
                directory: Some(acme.directory.url().to_owned()),
            },
            // Everything else serves the throwaway certificate, whatever the
            // config meant to say.
            _ => Tls {
                provider: "self-signed".to_owned(),
                directory: None,
            },
        }
    }

    /// Ask the engine what it is, which is also how we find out it is still
    /// answering — a daemon that has gone away is the failure this line exists
    /// to catch.
    async fn engine(&self) -> Engine {
        match self.applier.runtime().engine().await {
            Ok(description) => Engine {
                reachable: true,
                description,
            },
            Err(error) => Engine {
                reachable: false,
                description: format!("{error:#}"),
            },
        }
    }

    /// What is running, against what was asked for.
    ///
    /// The gap between the two is the interesting part: an app that is recorded
    /// and not running is one an operator asked for and is not getting, and
    /// nothing else in spaceport reports it after the startup log line has
    /// scrolled away.
    async fn apps(&self, running: &[Arc<crate::app::App>]) -> Apps {
        let ready = health::probe_all(running).await;
        let unreachable: Vec<AppId> = running
            .iter()
            .zip(&ready)
            .filter(|(_, ready)| !**ready)
            .map(|(app, _)| app.id.clone())
            .collect();

        // Why each app that is not running is not running, so a `down` app can
        // say more than that it is down.
        //
        // The store first and the startup report second. The store is what the
        // supervisor keeps current — an app that died an hour after boot, or
        // that spaceport has given up restarting, is only in there — and the
        // report is the fallback for the one case the store cannot hold: an app
        // whose recorded manifest this build cannot parse, which never got as
        // far as claiming a host.
        let mut reasons: BTreeMap<AppId, String> = self
            .reconciled
            .failed
            .iter()
            .map(|(id, reason)| (id.clone(), reason.clone()))
            .collect();
        for down in self.applier.store().down_apps() {
            reasons.insert(down.id, down.reason);
        }

        // Not running, and not a fault: an app is in here because somebody said
        // so, and it must not be counted among the ones that failed.
        let suspended: Vec<AppId> = self
            .applier
            .store()
            .suspended_apps()
            .into_iter()
            .map(|app| app.id)
            .collect();

        let (recorded, down, error) = match self.applier.repository().desired().await {
            Ok(records) => {
                let down = records
                    .iter()
                    .filter(|record| !running.iter().any(|app| app.id == record.id))
                    .filter(|record| !suspended.contains(&record.id))
                    .map(|record| Down {
                        id: record.id.clone(),
                        reason: reasons.get(&record.id).cloned(),
                    })
                    .collect();

                (records.len(), down, None)
            }
            Err(error) => (0, Vec::new(), Some(format!("{error:#}"))),
        };

        Apps {
            running: running.len(),
            ready: ready.iter().filter(|ready| **ready).count(),
            unreachable,
            recorded,
            suspended,
            down,
            error,
        }
    }

    /// The certificates spaceport holds, read from the store rather than from
    /// the resolver: the store is what survives a restart, and a certificate
    /// that is in one and not the other is worth the report saying so.
    async fn certificates(&self, routed: &[String], now: OffsetDateTime) -> CertificateStatus {
        let held = match CertificateRepository::new(self.db.clone()).all().await {
            Ok(held) => held,
            Err(error) => {
                return CertificateStatus {
                    error: Some(format!("{error:#}")),
                    ..CertificateStatus::default()
                };
            }
        };

        let mut next: Option<Renewal> = None;
        let mut unreadable = Vec::new();
        for certificate in &held {
            let host = certificate.host.to_string();
            // A certificate that will not parse is one the edge is not serving
            // either, so it is named rather than counted.
            let Ok(validity) = certificate.validity() else {
                unreadable.push(host);
                continue;
            };

            let at = validity.renew_at();
            if next.as_ref().is_none_or(|soonest| at < soonest.at) {
                next = Some(Renewal {
                    host,
                    at,
                    expires_at: validity.not_after,
                    in_seconds: (at - now).whole_seconds(),
                });
            }
        }

        // Only meaningful where something orders certificates: with a
        // self-signed edge every host is uncertified and saying so would be
        // noise on every single status.
        let uncertified = match self.certificates {
            Some(_) => routed
                .iter()
                .filter(|host| {
                    !held
                        .iter()
                        .any(|certificate| certificate.host.as_str() == host.as_str())
                })
                .cloned()
                .collect(),
            None => Vec::new(),
        };

        CertificateStatus {
            held: held.len(),
            next_renewal: next,
            uncertified,
            unreadable,
            error: None,
        }
    }
}

/// One spaceport, as it was at the moment it was asked.
///
/// Serialised whole over the operator interface: rendering it for a person is
/// the client's business, because only the client knows whether a person is
/// reading it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    pub uptime_seconds: u64,
    /// The config file this instance was started with.
    pub config: String,
    pub state: State,
    pub edge: Edge,
    pub tls: Tls,
    /// The endpoint this answer came over.
    pub operator: String,
    pub engine: Engine,
    pub apps: Apps,
    pub certificates: CertificateStatus,
    pub reconcile: Reconcile,
    /// How many GitHub Apps this spaceport is connected as.
    ///
    /// Defaulted rather than required, so a status from a spaceport that
    /// predates connections still reads.
    #[serde(default)]
    pub connections: usize,
}

/// Where spaceport keeps what it must not forget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Where client traffic comes in, and how much of it is claimed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    /// The host spaceport answers to as itself, if it was given one. What an
    /// operator needs when they are about to hand an outside service an address
    /// to call back on, and the first thing to check when one cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub http: SocketAddr,
    pub https: SocketAddr,
    /// How many hosts an app answers for.
    pub routed_hosts: usize,
}

/// Where the https listener's certificates come from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tls {
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
}

/// The container engine, and whether it is still there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Engine {
    pub reachable: bool,
    /// What it said it was, or why it did not say.
    pub description: String,
}

/// What is running, and what was asked for but is not.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Apps {
    pub running: usize,
    /// How many of the running ones answered a check just now.
    pub ready: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreachable: Vec<AppId>,
    /// How many apps are recorded as wanted, running or not.
    pub recorded: usize,
    /// Apps that are deliberately not running.
    ///
    /// Reported apart from `down` because they are the opposite of it: an app
    /// in here is doing exactly what it was told to, and a status that counted
    /// it as down would have an operator looking for a fault that is a
    /// decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suspended: Vec<AppId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub down: Vec<Down>,
    /// Why the records could not be read, if they could not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// An app spaceport was told to run and is not running.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Down {
    pub id: AppId,
    /// What went wrong the last time spaceport tried, when it was this
    /// spaceport that tried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The certificates spaceport holds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertificateStatus {
    pub held: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_renewal: Option<Renewal>,
    /// Hosts something is routed to that no certificate covers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uncertified: Vec<String>,
    /// Hosts whose stored certificate will not parse, and which the edge is
    /// therefore not serving either.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreadable: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The certificate due for renewal soonest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Renewal {
    pub host: String,
    /// When spaceport will start trying to replace it.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// When it stops being valid, which is the deadline that actually matters.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// How long until then. Negative for a renewal that is already overdue,
    /// which is the case worth noticing.
    pub in_seconds: i64,
}

/// What the reconciliation at startup did.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Reconcile {
    pub restored: usize,
    pub adopted: usize,
    pub failed: usize,
    pub swept: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{AppRepository, AppStore};
    use crate::runtime::{Container, ContainerId, ContainerRuntime, Managed};
    use anyhow::Result;
    use async_trait::async_trait;

    /// A runtime that starts things but is not there when asked what it is.
    struct Absent;

    #[async_trait]
    impl ContainerRuntime for Absent {
        async fn launch(&self, app: &AppId, _manifest: &crate::AppManifest) -> Result<Container> {
            Ok(Container {
                id: ContainerId::new(format!("{app}0123456789ab")),
                upstream: SocketAddr::from(([127, 0, 0, 1], 9000)),
            })
        }

        async fn remove(&self, _id: &ContainerId) -> Result<()> {
            Ok(())
        }

        async fn stop(&self, _id: &ContainerId) -> Result<()> {
            Ok(())
        }

        async fn start(
            &self,
            id: &ContainerId,
            _manifest: &crate::AppManifest,
        ) -> Result<Container> {
            Ok(Container {
                id: id.clone(),
                upstream: SocketAddr::from(([127, 0, 0, 1], 9000)),
            })
        }

        async fn managed(&self) -> Result<Vec<Managed>> {
            Ok(Vec::new())
        }

        async fn engine(&self) -> Result<String> {
            anyhow::bail!("no engine answered")
        }
    }

    const CONFIG: &str = "schema_version: 1
edge:
  listen:
    http: 0.0.0.0:8080
    https: 0.0.0.0:8443
";

    const MANIFEST: &str = "schema_version: 1
source:
  type: image
  image: strm/helloworld-http:latest
routing:
  hosts: [alpha.test]
container:
  health:
    readiness:
      type: none
";

    fn instance(db: Db, applier: Arc<Applier>, reconciled: Report) -> Instance {
        Instance {
            version: "9.9.9".to_owned(),
            started_at: OffsetDateTime::now_utc() - time::Duration::minutes(5),
            config_path: PathBuf::from("/etc/spaceport/spaceport.yaml"),
            config: Config::parse(CONFIG).unwrap(),
            operator: "/run/spaceport.sock".parse().unwrap(),
            applier,
            connections: Arc::new(ConnectionRepository::new(db.clone())),
            tracking: Arc::new(TrackingRepository::new(db.clone())),
            builds: Arc::new(BuildRepository::new(db.clone())),
            github: github::api::testing::FakeGitHub::new(),
            attempts: Arc::new(github::Attempts::new()),
            nudge: github::Nudge::new(),
            building: github::Nudge::new(),
            deploying: github::Nudge::new(),
            db,
            certificates: None,
            reconciled,
        }
    }

    fn empty() -> (Db, Arc<Applier>) {
        let db = Db::in_memory().unwrap();
        let applier = Arc::new(Applier::new(
            Arc::new(AppStore::new()),
            Arc::new(Absent),
            AppRepository::new(db.clone()),
            BuildRepository::new(db.clone()),
        ));

        (db, applier)
    }

    #[tokio::test]
    async fn reports_what_this_instance_is() {
        let (db, applier) = empty();
        let status = instance(db, applier, Report::default()).snapshot().await;

        assert_eq!(status.version, "9.9.9");
        assert!(status.uptime_seconds >= 300, "{}", status.uptime_seconds);
        assert_eq!(status.edge.http.port(), 8080);
        assert_eq!(status.edge.https.port(), 8443);
        assert_eq!(status.tls.provider, "self-signed");
        assert_eq!(status.operator, "unix:/run/spaceport.sock");
        // Which migration it is on is the store's business; that the status
        // could ask it at all is this one's.
        assert!(status.state.schema_version.is_some(), "{status:?}");
    }

    /// The engine is asked rather than assumed, so one that has gone away
    /// shows up as gone rather than as nothing at all.
    #[tokio::test]
    async fn says_when_the_engine_does_not_answer() {
        let (db, applier) = empty();
        let status = instance(db, applier, Report::default()).snapshot().await;

        assert!(!status.engine.reachable);
        assert!(
            status.engine.description.contains("no engine"),
            "{status:?}"
        );
    }

    /// The gap between what was asked for and what is running is the whole
    /// point of the section.
    #[tokio::test]
    async fn names_an_app_that_is_recorded_and_not_running() {
        let (db, applier) = empty();
        applier
            .repository()
            .record_applied(&"ghost".parse().unwrap(), MANIFEST, None, false)
            .await
            .unwrap();

        let reconciled = Report {
            failed: vec![("ghost".parse().unwrap(), "no image `x:1`".to_owned())],
            ..Report::default()
        };
        let status = instance(db, applier, reconciled).snapshot().await;

        assert_eq!(status.apps.running, 0);
        assert_eq!(status.apps.recorded, 1);
        assert_eq!(status.apps.down.len(), 1);
        assert_eq!(status.apps.down[0].id.as_str(), "ghost");
        assert_eq!(
            status.apps.down[0].reason.as_deref(),
            Some("no image `x:1`")
        );
        assert_eq!(status.reconcile.failed, 1);
    }

    /// An app that is running but not answering is named, because the count
    /// alone does not say which one to go and look at.
    #[tokio::test]
    async fn names_a_running_app_that_does_not_answer() {
        let (db, applier) = empty();
        applier
            .apply(
                "alpha".parse().unwrap(),
                crate::AppManifest::parse(MANIFEST).unwrap(),
                false,
            )
            .await
            .unwrap();

        let status = instance(db, applier, Report::default()).snapshot().await;

        assert_eq!(status.apps.running, 1);
        assert_eq!(status.apps.ready, 0);
        assert_eq!(status.apps.unreachable[0].as_str(), "alpha");
        assert!(status.apps.down.is_empty(), "{:?}", status.apps.down);
        assert_eq!(status.edge.routed_hosts, 1);
    }

    /// Without a CA nothing will ever order a certificate, so a routed host
    /// having none is the arrangement rather than a problem.
    #[tokio::test]
    async fn does_not_call_hosts_uncertified_when_nothing_orders_certificates() {
        let (db, applier) = empty();
        applier
            .apply(
                "alpha".parse().unwrap(),
                crate::AppManifest::parse(MANIFEST).unwrap(),
                false,
            )
            .await
            .unwrap();

        let status = instance(db, applier, Report::default()).snapshot().await;

        assert_eq!(status.certificates.held, 0);
        assert!(status.certificates.uncertified.is_empty());
    }

    /// A spaceport is connected as nothing until somebody connects it, and the
    /// count is what says which of the two it is.
    #[tokio::test]
    async fn counts_the_github_apps_this_spaceport_is_connected_as() {
        let (db, applier) = empty();
        let instance = instance(db, applier, Report::default());
        assert_eq!(instance.snapshot().await.connections, 0);

        crate::connections::github::connect(
            &instance.connections,
            instance.github.clone(),
            serde_json::from_value(serde_json::json!({
                // The slug and id the fixture github answers as.
                "slug": "spaceport-for-acme",
                "app_id": 42,
                "name": "Spaceport for Acme",
                "owner": "an-organisation",
                "client_id": "Iv1.0123456789abcdef",
                "client_secret": "a-client-secret",
                "webhook_secret": "a-webhook-secret",
                "private_key": crate::connections::github::key::testing::PKCS1,
            }))
            .unwrap(),
            &instance.nudge,
        )
        .await
        .unwrap();

        assert_eq!(instance.snapshot().await.connections, 1);
    }
}

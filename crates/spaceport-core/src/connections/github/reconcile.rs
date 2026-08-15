//! Asking GitHub what is true, on a timer, because webhooks are not enough.
//!
//! A webhook is the fast path: an App installed on an organisation at eleven
//! o'clock is known about at eleven o'clock, and nothing here can beat that.
//! What a webhook is not is reliable. A delivery sent while this spaceport was
//! restarting arrives at a closed port; a hook GitHub has disabled after a run
//! of failures sends nothing at all until somebody re-enables it by hand; two
//! deliveries about the same installation can arrive in the order they were sent
//! and be applied in the other one. Every one of those leaves a cache that is
//! quietly wrong, and a cache that is quietly wrong is worse than no cache,
//! because nothing ever contradicts it.
//!
//! So this is the slow path, and it is always right. It asks GitHub outright
//! where the App is installed and what each installation grants, and replaces
//! the cached rows with the answer — a full replacement rather than a merge,
//! because GitHub's list is the whole truth and anything spaceport is still
//! holding that is not in it has gone. Webhooks make spaceport quick;
//! reconciliation makes it correct, and a system with only one of the two is
//! either slow or wrong.
//!
//! The rejected alternative was reconciling only what a delivery pointed at —
//! cheaper, and useless for exactly the case this exists for, since the
//! deliveries that go missing are the ones nothing would then point at.
//!
//! What it deliberately does not do is act on what it finds. Discovering that an
//! App has been installed on a repository is where this stops; deploying
//! anything from that repository is a later step and lives nowhere yet.
//!
//! The two paths meet at [`Nudge`]. A webhook that says the installations
//! changed, and connecting an App, both know something the cache does not, and
//! an hour is a long time to sit on that: an operator who connects an App and
//! immediately runs `spaceport connect show` should be told what GitHub says,
//! not `not yet`. So the loop sleeps on its interval *or* until something shoves
//! it, and the shove starts a pass that is the same pass the timer would have
//! run — the fast path decides *when* to ask GitHub, never *what* to believe.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::api::{Client, Transport};
use super::repository::{Connection, ConnectionRepository, Installation};

/// How often spaceport asks GitHub what is true, and how long it keeps the
/// evidence that a delivery has already been seen.
///
/// One struct rather than three constants for the reason the supervisor's is
/// one: the numbers are an argument about time that only makes sense read
/// together, and a test that had to sit out the real ones would take an hour to
/// find out what it already knows.
#[derive(Debug, Clone)]
pub struct Policy {
    /// How long between passes.
    ///
    /// This is the outer bound on how long a missed webhook stays missed, and an
    /// hour is right because installations change on a human timescale: an App
    /// is installed or removed by a person clicking a button in a browser, not
    /// by anything that happens per request. A shorter interval would spend rate
    /// limit — one listing plus one call per installation, every pass, for every
    /// connection — to notice sooner something that nobody is waiting on.
    pub interval: Duration,

    /// How long to wait before trying again after a pass had failures.
    ///
    /// The same five minutes [`crate::acme`] waits, for the same reason: GitHub
    /// being briefly unreachable, or rate limiting this App for a few minutes,
    /// should cost a few minutes rather than a whole interval.
    pub retry_after_failure: Duration,

    /// How long a delivery id is worth remembering.
    ///
    /// GitHub gives up retrying a delivery long before a day is out, so an id
    /// older than this can no longer arrive again — keeping it would be keeping
    /// a row that can never match anything. A day is comfortably past the last
    /// retry and short enough that the table stays a window rather than a log.
    pub delivery_retention: Duration,

    /// How long to let a nudge settle before acting on it.
    ///
    /// GitHub sends bursts: enabling two repositories on an installation
    /// produces an `installation_repositories` `added` and a `removed` delivery
    /// inside the same second, and each of them would otherwise be a pass. A
    /// short wait turns a burst into one pass, and costs only that wait — the
    /// pass reads the whole truth from GitHub either way, so the later delivery
    /// of a burst is answered by the pass the earlier one started.
    ///
    /// Two seconds because the deadline is human: an operator who has just
    /// connected an App types `spaceport connect show` in rather longer than
    /// that, and the reconciled answer has to be there when they do.
    pub settle: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            interval: Duration::hours(1),
            retry_after_failure: Duration::minutes(5),
            delivery_retention: Duration::hours(24),
            settle: Duration::seconds(2),
        }
    }
}

/// A shove that says the cached installations are stale.
///
/// Cheap to clone, and every clone is the same signal: the webhook handler, the
/// two places an App is connected, and the loop that acts on it are in four
/// different parts of the process, and each holds one of these rather than a
/// channel of its own. Two `Nudge`s would be two signals nobody is listening to
/// half of, which nothing would ever fail loudly about — so there is one, built
/// at startup and handed out.
///
/// The channel is a [`watch`], and that is the whole design: a `watch`
/// *coalesces*. Ten nudges arriving while a pass is running are one wake-up and
/// not ten queued passes, which is exactly right, because a pass reads the whole
/// truth from GitHub anyway — running it a second time immediately would learn
/// nothing the first did not, at the price of another round trip per connection.
#[derive(Debug, Clone)]
pub struct Nudge {
    /// Bumped by whoever learned something. The value is a counter and means
    /// nothing on its own; what matters is that it moved, and that the loop
    /// then goes and asks GitHub what it moved to.
    generation: Arc<watch::Sender<u64>>,
}

impl Default for Nudge {
    fn default() -> Self {
        Self::new()
    }
}

impl Nudge {
    pub fn new() -> Self {
        Self {
            generation: Arc::new(watch::Sender::new(0)),
        }
    }

    /// Say that what GitHub would answer is no longer what is cached.
    ///
    /// Never fails and never blocks: a `watch` with no receiver — a spaceport
    /// whose loop has already stopped for shutdown — takes the send and drops
    /// it, which is the right outcome for a signal nobody is waiting on.
    pub fn nudge(&self) {
        self.generation.send_modify(|generation| *generation += 1);
    }

    /// A handle that resolves whenever something has been learned.
    pub fn changed(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }
}

/// What one pass over every connection did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pass {
    /// Connections GitHub answered for, and whose cache was replaced.
    pub connections: usize,
    /// Installations GitHub reports that the cache did not have.
    pub discovered: usize,
    /// Installations the cache had that GitHub no longer reports.
    pub forgotten: usize,
    /// Repositories seen across every installation of every connection.
    pub repositories: usize,
    /// Delivery ids that had aged out and were dropped.
    pub pruned: usize,
    /// The slugs of connections GitHub could not be asked about.
    pub failed: Vec<String>,
}

impl Pass {
    /// Whether the pass changed nothing, and so is not worth a line.
    ///
    /// [`Self::connections`] and [`Self::repositories`] are what the pass
    /// *looked at* rather than what it changed, so they are not part of the
    /// answer: a steady state reconciles the same connections and sees the same
    /// repositories every hour, and a spaceport nobody is touching should say
    /// nothing all week.
    pub fn is_empty(&self) -> bool {
        self.discovered == 0 && self.forgotten == 0 && self.pruned == 0 && self.failed.is_empty()
    }
}

/// Ask GitHub about every connection, replace what is cached, and drop the
/// delivery ids that can no longer arrive.
///
/// `now` is a parameter rather than read here so that a test can decide what
/// counts as old without waiting a day for it to become true.
pub async fn reconcile(
    connections: &ConnectionRepository,
    transport: Arc<dyn Transport>,
    policy: &Policy,
    now: OffsetDateTime,
) -> Pass {
    let mut pass = Pass::default();

    let held = match connections.all().await {
        Ok(held) => held,
        // The state store, not GitHub. Nothing in a pass can be done without
        // it, and coming back sooner would not make it readable.
        Err(error) => {
            warn!(error = %format!("{error:#}"), "could not read the connections to reconcile");

            return pass;
        }
    };

    for connection in &held {
        match refresh(connections, connection, transport.clone()).await {
            Ok(change) => {
                pass.connections += 1;
                pass.discovered += change.discovered;
                pass.forgotten += change.forgotten;
                pass.repositories += change.repositories;
            }
            // One connection's App may have had its key rotated, or its
            // installation revoked, or simply be the one GitHub is rate
            // limiting. None of that is a reason to leave the others stale.
            Err(error) => {
                warn!(
                    slug = %connection.slug,
                    error = %format!("{error:#}"),
                    "could not reconcile a connection with github",
                );
                pass.failed.push(connection.slug.clone());
            }
        }
    }

    // Once per pass rather than once per connection: the table is pruned by age
    // and not by App, so doing it per connection would be the same `DELETE`
    // repeated with nothing left to find.
    pass.pruned = prune(connections, now - policy.delivery_retention).await;

    pass
}

/// What one connection's pass changed.
struct Change {
    discovered: usize,
    forgotten: usize,
    repositories: usize,
}

/// Replace one connection's cache with what GitHub says, and say what moved.
async fn refresh(
    connections: &ConnectionRepository,
    connection: &Connection,
    transport: Arc<dyn Transport>,
) -> Result<Change> {
    let client = Client::new(connection, transport)
        .with_context(|| format!("acting as the app `{}`", connection.slug))?;

    // Read before the replacement, because the replacement is what destroys the
    // evidence of what was there — and what was there is the only way to tell a
    // newly granted repository from one that has been granted all along.
    let cached = connections
        .installations(connection.app_id)
        .await
        .with_context(|| format!("reading what is cached for `{}`", connection.slug))?;

    let mut fetched = Vec::new();
    for record in client.installations().await? {
        let repositories = client.repositories(record.id).await?;

        fetched.push(Installation {
            installation_id: record.id,
            account: record.account,
            account_type: record.account_type,
            repositories,
        });
    }

    connections
        .record_installations(connection.app_id, &fetched)
        .await
        .with_context(|| format!("caching what github says about `{}`", connection.slug))?;

    Ok(compare(&connection.slug, &cached, &fetched))
}

/// What changed between the cache and GitHub's answer, said out loud.
///
/// Each discovery and each loss is worth a line of its own: an App newly
/// installed on an account is the thing an operator who has just clicked
/// "install" is watching `spaceport stream` for, and a count of one in an hourly
/// summary is not that.
fn compare(slug: &str, cached: &[Installation], fetched: &[Installation]) -> Change {
    let before: BTreeMap<i64, &Installation> = cached
        .iter()
        .map(|installation| (installation.installation_id, installation))
        .collect();
    let after: BTreeMap<i64, &Installation> = fetched
        .iter()
        .map(|installation| (installation.installation_id, installation))
        .collect();

    let mut change = Change {
        discovered: 0,
        forgotten: 0,
        repositories: fetched
            .iter()
            .map(|installation| installation.repositories.len())
            .sum(),
    };

    for (id, installation) in &after {
        if before.contains_key(id) {
            continue;
        }

        info!(
            %slug,
            installation = id,
            account = %installation.account,
            repositories = installation.repositories.len(),
            "github says the app is installed here",
        );
        change.discovered += 1;
    }

    for (id, installation) in &before {
        if after.contains_key(id) {
            continue;
        }

        info!(
            %slug,
            installation = id,
            account = %installation.account,
            "github no longer says the app is installed here",
        );
        change.forgotten += 1;
    }

    change
}

/// Drop every delivery id received before `cutoff`, and say how many.
async fn prune(connections: &ConnectionRepository, cutoff: OffsetDateTime) -> usize {
    // The stored column is the text [`crate::state::now`] writes, so the cutoff
    // has to be written the same way for the comparison to mean anything.
    let cutoff = match cutoff.format(&Rfc3339) {
        Ok(cutoff) => cutoff,
        // Unreachable: `Rfc3339` renders every valid timestamp. Saying so beats
        // pruning against a string nobody chose.
        Err(error) => {
            warn!(%error, "could not say how old a delivery has to be to be dropped");

            return 0;
        }
    };

    match connections.prune_deliveries(&cutoff).await {
        Ok(pruned) => pruned,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "could not drop the deliveries that have aged out");

            0
        }
    }
}

/// Keep asking GitHub what is true, until `shutdown` is cancelled.
///
/// Wakes on three things — the interval, a [`Nudge`], and shutdown. The interval
/// is what makes the cache eventually right whatever was missed; the nudge is
/// what makes it right in seconds when something did reach this spaceport, which
/// is nearly always. Nothing here treats the two differently once it is awake:
/// both run the same pass, because the pass is the only thing that knows
/// anything, and a wake-up that acted on what it was told would be believing a
/// webhook.
pub async fn maintain(
    connections: Arc<ConnectionRepository>,
    transport: Arc<dyn Transport>,
    policy: Policy,
    nudge: Nudge,
    shutdown: CancellationToken,
) {
    debug!(
        minutes = policy.interval.whole_minutes(),
        "keeping what github says current"
    );
    let mut changed = nudge.changed();

    loop {
        // Everything learned up to this point is what this pass is about to go
        // and see for itself, so it is not also a reason to run again. Anything
        // that arrives from here on is — it may have happened after GitHub
        // answered, and this pass would not have it.
        changed.mark_unchanged();

        let pass = reconcile(
            &connections,
            transport.clone(),
            &policy,
            OffsetDateTime::now_utc(),
        )
        .await;

        if !pass.is_empty() {
            info!(
                connections = pass.connections,
                discovered = pass.discovered,
                forgotten = pass.forgotten,
                repositories = pass.repositories,
                pruned = pass.pruned,
                failed = pass.failed.len(),
                "reconciled with github",
            );
        }

        let sleep = if pass.failed.is_empty() {
            policy.interval
        } else {
            policy.retry_after_failure
        };
        debug!(
            seconds = sleep.whole_seconds(),
            "waiting for the next pass over the connections"
        );

        tokio::select! {
            () = shutdown.cancelled() => break,
            // `unsigned_abs` for the same reason the acme loop uses it: a
            // policy or a clock that has done something strange should cost a
            // busy loop at worst rather than a panic.
            () = tokio::time::sleep(sleep.unsigned_abs()) => {}
            // Something learned that the cache is stale: a webhook that said
            // the installations changed, or an App connected a moment ago.
            result = changed.changed() => {
                // Every sender has gone, so nothing can ever say so again. The
                // acme loop stops for the same reason: a wake-up that can no
                // longer happen is not worth a task.
                if result.is_err() {
                    break;
                }

                // Only on this arm. A burst is a property of what GitHub sends,
                // and the interval has nothing to settle. Interruptible,
                // because a settle that outlived a shutdown would be a
                // shutdown that waits for it.
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(policy.settle.unsigned_abs()) => {}
                }
            }
        }
    }

    debug!("stopped keeping what github says current");
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::api::testing::FakeGitHub;
    use super::super::key;
    use crate::connections::Secret;
    use crate::state::Db;

    /// A connection as one is read back out of the state store, with the
    /// fixture key so a client can be built from it and can sign.
    fn connection(slug: &str, app_id: i64) -> Connection {
        Connection {
            slug: slug.to_owned(),
            app_id,
            name: "Spaceport for Acme".to_owned(),
            owner: "an-organisation".to_owned(),
            client_id: "Iv1.0123456789abcdef".to_owned(),
            client_secret: Secret::new("a-client-secret"),
            webhook_secret: Secret::new("a-webhook-secret"),
            private_key: Secret::new(key::testing::PKCS1),
            connected_at: String::new(),
        }
    }

    /// A store holding the connections named, and a GitHub to answer for them.
    async fn connected(slugs: &[(&str, i64)]) -> (ConnectionRepository, Arc<FakeGitHub>) {
        let connections = ConnectionRepository::new(Db::in_memory().unwrap());
        for (slug, app_id) in slugs {
            connections
                .record(&connection(slug, *app_id))
                .await
                .unwrap();
        }

        (connections, FakeGitHub::new())
    }

    async fn pass(connections: &ConnectionRepository, github: &Arc<FakeGitHub>) -> Pass {
        reconcile(
            connections,
            github.clone(),
            &Policy::default(),
            OffsetDateTime::now_utc(),
        )
        .await
    }

    #[tokio::test]
    async fn records_the_installations_github_reports() {
        let (connections, github) = connected(&[("spaceport-for-acme", 42)]).await;

        let pass = pass(&connections, &github).await;

        assert_eq!(pass.connections, 1);
        assert_eq!(pass.discovered, 1);
        assert_eq!(pass.repositories, 1);
        assert!(pass.failed.is_empty());
        let installations = connections.installations(42).await.unwrap();
        assert_eq!(installations.len(), 1);
        assert_eq!(installations[0].installation_id, 7);
        assert_eq!(installations[0].account, "an-organisation");
        assert_eq!(installations[0].repositories, ["an-organisation/site"]);
    }

    /// The case a webhook is most likely to have missed: an App uninstalled
    /// while this spaceport was not listening. The cached row would otherwise
    /// stay for ever, and nothing would ever contradict it.
    #[tokio::test]
    async fn forgets_an_installation_github_no_longer_reports() {
        let (connections, github) = connected(&[("spaceport-for-acme", 42)]).await;
        connections
            .record_installations(
                42,
                &[Installation {
                    installation_id: 99,
                    account: "a-former-organisation".to_owned(),
                    account_type: "Organization".to_owned(),
                    repositories: vec!["a-former-organisation/site".to_owned()],
                }],
            )
            .await
            .unwrap();

        let pass = pass(&connections, &github).await;

        assert_eq!(pass.forgotten, 1);
        assert_eq!(pass.discovered, 1);
        let installations = connections.installations(42).await.unwrap();
        assert_eq!(installations.len(), 1);
        assert_eq!(installations[0].installation_id, 7);
    }

    #[tokio::test]
    async fn picks_up_a_repository_added_to_an_installation() {
        let (connections, github) = connected(&[("spaceport-for-acme", 42)]).await;
        pass(&connections, &github).await;
        github.repositories_in_pages(&[&["an-organisation/site", "an-organisation/api"]]);

        let pass = pass(&connections, &github).await;

        // The installation is not new, so nothing is discovered — the change is
        // inside it.
        assert_eq!(pass.discovered, 0);
        assert_eq!(pass.repositories, 2);
        let installations = connections.installations(42).await.unwrap();
        assert_eq!(
            installations[0].repositories,
            ["an-organisation/api", "an-organisation/site"]
        );
    }

    /// One App whose credentials GitHub has stopped accepting must not leave
    /// every other connection on this host stale.
    #[tokio::test]
    async fn one_connections_failure_does_not_cost_the_others() {
        let (connections, github) = connected(&[("alpha", 42), ("beta", 43)]).await;
        github.refuses_the_app(42);

        let pass = pass(&connections, &github).await;

        assert_eq!(pass.failed, ["alpha"]);
        assert_eq!(pass.connections, 1);
        assert!(connections.installations(42).await.unwrap().is_empty());
        assert_eq!(connections.installations(43).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_pass_over_no_connections_does_nothing() {
        let (connections, github) = connected(&[]).await;

        let pass = pass(&connections, &github).await;

        assert!(pass.is_empty());
        assert_eq!(pass, Pass::default());
        assert!(github.requests().is_empty());
    }

    /// The quiet-pass rule: a spaceport nobody is touching reconciles the same
    /// connection every hour, and must not say so every hour.
    #[tokio::test]
    async fn a_pass_that_changed_nothing_reports_as_empty() {
        let (connections, github) = connected(&[("spaceport-for-acme", 42)]).await;
        assert!(!pass(&connections, &github).await.is_empty());

        let pass = pass(&connections, &github).await;

        assert!(pass.is_empty(), "{pass:?}");
        // And it still looked: what it saw is simply not what makes it worth a
        // line.
        assert_eq!(pass.connections, 1);
        assert_eq!(pass.repositories, 1);
    }

    /// A delivery id is a window, not a log: it is worth keeping exactly as long
    /// as GitHub might still send that delivery again.
    #[tokio::test]
    async fn prunes_the_deliveries_that_can_no_longer_arrive() {
        let (connections, github) = connected(&[("spaceport-for-acme", 42)]).await;
        connections
            .record_delivery("delivery-1", 42, "push")
            .await
            .unwrap();
        let policy = Policy::default();

        // A pass now: the delivery arrived a moment ago and is well inside the
        // retention.
        let kept = reconcile(
            &connections,
            github.clone(),
            &policy,
            OffsetDateTime::now_utc(),
        )
        .await;
        assert_eq!(kept.pruned, 0);
        assert!(
            !connections
                .record_delivery("delivery-1", 42, "push")
                .await
                .unwrap(),
            "the delivery is still remembered"
        );

        // And a pass two days later, by which time GitHub has long stopped
        // retrying it.
        let pruned = reconcile(
            &connections,
            github.clone(),
            &policy,
            OffsetDateTime::now_utc() + Duration::days(2),
        )
        .await;

        assert_eq!(pruned.pruned, 1);
        assert!(
            connections
                .record_delivery("delivery-1", 42, "push")
                .await
                .unwrap(),
            "the delivery id is new again"
        );
    }

    #[tokio::test]
    async fn the_loop_stops_when_it_is_shut_down() {
        let (connections, github) = connected(&[("spaceport-for-acme", 42)]).await;
        let shutdown = CancellationToken::new();

        let running = tokio::spawn(maintain(
            Arc::new(connections),
            github.clone(),
            Policy::default(),
            Nudge::new(),
            shutdown.clone(),
        ));
        // Cancelled while the first pass is sleeping off the interval, which is
        // an hour away: without the select arm this would never return.
        tokio::task::yield_now().await;
        shutdown.cancel();

        running.await.unwrap();
        assert!(!github.requests().is_empty(), "the first pass ran");
    }

    /// How many passes have run, counted by the one request every pass over a
    /// connection makes before any other.
    fn passes(github: &Arc<FakeGitHub>) -> usize {
        github
            .requests()
            .iter()
            .filter(|request| request.path == "/app/installations")
            .count()
    }

    /// Wait until `expected` passes have run, without letting the clock move.
    ///
    /// Yields rather than sleeps on purpose: the clock in these tests is paused
    /// and only advances when nothing is ready to run, so a test that slept
    /// would be a test that let the hourly interval elapse behind its own back —
    /// which is the very thing the nudge is supposed to make unnecessary.
    async fn until_passes(github: &Arc<FakeGitHub>, expected: usize) {
        for _ in 0..10_000 {
            if passes(github) >= expected {
                return;
            }

            tokio::task::yield_now().await;
        }

        panic!("{} passes ran, and {expected} were wanted", passes(github));
    }

    /// Give the loop enough turns to have acted on what it has been told,
    /// without moving the clock: a nudge wakes a task, and a task that has not
    /// been polled yet has not started settling on it.
    async fn let_the_loop_run() {
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
    }

    /// The whole point: spaceport is told, and acts on being told, instead of
    /// sitting on what it knows until the hour is up.
    #[tokio::test(start_paused = true)]
    async fn a_nudge_wakes_a_pass_the_interval_would_have_left_an_hour_away() {
        let (connections, github) = connected(&[("spaceport-for-acme", 42)]).await;
        let policy = Policy::default();
        let nudge = Nudge::new();
        let shutdown = CancellationToken::new();
        let running = tokio::spawn(maintain(
            Arc::new(connections),
            github.clone(),
            policy.clone(),
            nudge.clone(),
            shutdown.clone(),
        ));
        until_passes(&github, 1).await;

        let woken = tokio::time::Instant::now();
        nudge.nudge();
        let_the_loop_run().await;
        tokio::time::advance(policy.settle.unsigned_abs()).await;
        until_passes(&github, 2).await;

        assert!(
            woken.elapsed() < policy.interval.unsigned_abs(),
            "the second pass waited out the interval"
        );
        shutdown.cancel();
        running.await.unwrap();
    }

    /// Enabling two repositories sends an `added` and a `removed` inside the
    /// same second. Both say the same thing — go and look — and one look is what
    /// they are worth.
    #[tokio::test(start_paused = true)]
    async fn a_burst_of_nudges_during_the_settle_costs_one_pass() {
        let (connections, github) = connected(&[("spaceport-for-acme", 42)]).await;
        let policy = Policy::default();
        let nudge = Nudge::new();
        let shutdown = CancellationToken::new();
        let running = tokio::spawn(maintain(
            Arc::new(connections),
            github.clone(),
            policy.clone(),
            nudge.clone(),
            shutdown.clone(),
        ));
        until_passes(&github, 1).await;

        nudge.nudge();
        let_the_loop_run().await;
        // Halfway through the settle, and then twice more — a burst as GitHub
        // sends one, all of it inside the wait the first shove started.
        tokio::time::advance(Duration::milliseconds(500).unsigned_abs()).await;
        nudge.nudge();
        nudge.nudge();
        tokio::time::advance(policy.settle.unsigned_abs()).await;
        until_passes(&github, 2).await;
        // And nothing follows it: the loop is back on its interval rather than
        // working through a queue of shoves.
        let_the_loop_run().await;

        assert_eq!(passes(&github), 2);
        shutdown.cancel();
        running.await.unwrap();
    }

    /// A settle that outlived a shutdown would be a shutdown that waits for it,
    /// and every process stopping this spaceport is holding a stopwatch.
    #[tokio::test(start_paused = true)]
    async fn a_shutdown_during_the_settle_does_not_wait_it_out() {
        let (connections, github) = connected(&[("spaceport-for-acme", 42)]).await;
        let policy = Policy::default();
        let nudge = Nudge::new();
        let shutdown = CancellationToken::new();
        let running = tokio::spawn(maintain(
            Arc::new(connections),
            github.clone(),
            policy.clone(),
            nudge.clone(),
            shutdown.clone(),
        ));
        until_passes(&github, 1).await;

        nudge.nudge();
        // The loop has taken the nudge and started settling on it, and the
        // clock has not moved, so it is still settling.
        let_the_loop_run().await;
        let cancelled = tokio::time::Instant::now();
        shutdown.cancel();
        running.await.unwrap();

        assert!(
            cancelled.elapsed() < policy.settle.unsigned_abs(),
            "the loop sat out the settle before stopping"
        );
        assert_eq!(passes(&github), 1, "the settling pass never ran");
    }
}

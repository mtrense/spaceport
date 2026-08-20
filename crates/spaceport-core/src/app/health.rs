//! Deciding whether an app is working.
//!
//! The same check, asked at three moments, which is why one [`Probe`] describes
//! all three. [`wait_until_ready`] asks "may traffic be routed here yet?" once,
//! during an apply, at the one moment spaceport is in a position to wait for
//! the answer. [`probe`] asks "is it answering right now?" for a listing, and
//! waits for nobody. [`watch`] asks "is it still working?" over and over for as
//! long as the app is routed, and hands the answer to the supervisor.
//!
//! The difference between the first and the last is only which way the streak
//! runs. An apply is waiting for `success_threshold` checks to pass and gives
//! up once `failure_threshold` have failed; a watch has already seen it pass
//! and is waiting for `failure_threshold` to fail. Neither reacts to a single
//! check, because one check catches a garbage-collection pause as readily as a
//! broken app.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How long a tcp check waits to see whether a connection it just made is
/// going to survive. Not configurable: it is a property of how the container
/// engine publishes ports, not of the app.
const SETTLE: Duration = Duration::from_millis(100);

/// The longest a readiness wait may run, however patient the probe asks it to
/// be.
///
/// A backstop against the manifest rather than a tuning knob. `interval: 3600s`
/// with `failure_threshold: 3600` is a legal probe worth about a hundred and
/// fifty days of waiting, and the cost of that is not paid by the app that
/// wrote it: [`wait_until_ready`] is awaited holding the app's working lock,
/// and the automatic deployer walks armed apps one at a time and awaits each,
/// so one app can keep every other app on the host from deploying at all.
///
/// Half an hour is longer than any honest readiness check — an app that has not
/// answered a single probe in that time is not warming up — and short enough
/// that the operator finds out on the same day they applied.
const MAX_READINESS_WAIT: Duration = Duration::from_secs(30 * 60);

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::Empty;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tracing::debug;

use super::manifest::{Check, Probe};

/// Wait until the app at `addr` passes its readiness check.
///
/// Returns as soon as it does. Gives up once `failure_threshold` checks in a
/// row have failed, and says what the last failure was — that message is the
/// only thing the operator will have to go on.
///
/// Gives up on the clock as well, and has to. The two streaks are *consecutive*
/// counts and each resets the other, so an app that fails, passes, fails,
/// passes keeps both of them at one for ever — and this function is awaited
/// holding the app's working lock, which makes "for ever" the supervisor
/// ignoring that app and the automatic deployer never reaching the next one.
/// Alternating is not an exotic failure either: it is what a container that
/// crashes and is restarted by its engine does, and what an app under a load it
/// half survives does. [`budget`] is what the probe's own numbers say the wait
/// is worth; passing it means the app is not becoming ready, it is oscillating.
pub async fn wait_until_ready(addr: SocketAddr, host: &str, readiness: &Probe) -> Result<()> {
    if readiness.kind == Check::None {
        return Ok(());
    }

    let started = Instant::now();
    let budget = budget(readiness);
    sleep(readiness.initial_delay).await;

    let (mut passed, mut failed) = (0, 0);
    let mut last = anyhow!("no check had finished yet");
    loop {
        match check(addr, host, readiness).await {
            Ok(()) => {
                failed = 0;
                passed += 1;
                if passed >= readiness.success_threshold {
                    return Ok(());
                }
            }
            Err(error) => {
                passed = 0;
                failed += 1;
                debug!(%addr, %error, failed, "readiness check failed");

                if failed >= readiness.failure_threshold {
                    bail!(
                        "the app was not ready after {failed} {} checks over {:.0?}: {error:#}",
                        readiness.kind.as_str(),
                        started.elapsed(),
                    );
                }
                last = error;
            }
        }

        // Checked here rather than around the whole loop, so that the refusal
        // can still say what the app last did wrong. A `timeout` wrapping this
        // would drop that on the floor, and it is the only thing the operator
        // gets to go on.
        if started.elapsed() >= budget {
            bail!(
                "the app never held a {} check long enough to be ready, and was still flapping after {:.0?}: {last:#}",
                readiness.kind.as_str(),
                started.elapsed(),
            );
        }

        sleep(readiness.interval).await;
    }
}

/// How long [`wait_until_ready`] will wait on a probe before calling it a day.
///
/// Derived from the probe rather than fixed, so that a slow app is still given
/// exactly the patience its manifest asked for: `initial_delay`, plus every
/// check the failure threshold entitles it to, each costing a whole `timeout`
/// and the `interval` after it. A wait that runs longer than this has not been
/// waiting for an app to start — a run of plain failures would have hit
/// `failure_threshold` and stopped by now, so the only way to still be here is
/// a pass in between resetting the count.
///
/// Saturating throughout, and capped by [`MAX_READINESS_WAIT`], because these
/// are manifest numbers: `failure_threshold` is a `u32` an operator types, and
/// multiplying an hour by four billion of them is not an arithmetic this wants
/// to be exact about.
fn budget(readiness: &Probe) -> Duration {
    let per_check = readiness.timeout.saturating_add(readiness.interval);

    readiness
        .initial_delay
        .saturating_add(per_check.saturating_mul(readiness.failure_threshold))
        .min(MAX_READINESS_WAIT)
}

/// Watch the app at `addr` until it stops working, and say what went wrong.
///
/// Returns only on failure — `failure_threshold` checks in a row — so a caller
/// awaiting this is asking "tell me when this app needs restarting" and
/// nothing else. An app that stays up keeps this pending forever, which is why
/// the caller is expected to drop the future when the app is replaced,
/// suspended or destroyed rather than to wait for it to say so.
///
/// A single failure is not enough and is not even reported. An app is allowed
/// to miss a check — a slow request, a pause, a moment of load — and a
/// supervisor that restarted it for that would be a worse fault than the one it
/// was watching for. `initial_delay` is the grace after a start: the app has
/// already passed its readiness check by the time this runs, but an app can be
/// ready and still be warming up.
pub async fn watch(addr: SocketAddr, host: &str, liveness: &Probe) -> String {
    if liveness.kind == Check::None {
        // Nothing to watch for. Pending forever is the honest answer: this app
        // will never be found broken by a check, only by its container going.
        std::future::pending::<()>().await;
    }

    sleep(liveness.initial_delay).await;

    let mut failed = 0;
    loop {
        match check(addr, host, liveness).await {
            Ok(()) => failed = 0,
            Err(error) => {
                failed += 1;
                debug!(%addr, %error, failed, "liveness check failed");

                if failed >= liveness.failure_threshold {
                    return format!(
                        "it failed {failed} {} checks in a row: {error:#}",
                        liveness.kind.as_str(),
                    );
                }
            }
        }

        sleep(liveness.interval).await;
    }
}

/// One look at an app that is already running, for reporting rather than
/// gating: does it answer right now?
///
/// Uses the app's own check where there is one, and a tcp check where the
/// manifest asked for none — `none` means "route it without waiting", not
/// "there is no way to tell". Its own short timeout, because whoever asked is
/// waiting on a listing and a dead app must not hold it up for the length of
/// an apply's patience.
pub async fn probe(addr: SocketAddr, host: &str, readiness: &Probe) -> Result<()> {
    let readiness = Probe {
        kind: match readiness.kind {
            Check::None => Check::Tcp,
            kind => kind,
        },
        timeout: PROBE_TIMEOUT,
        ..readiness.clone()
    };

    check(addr, host, &readiness).await
}

/// How long [`probe`] waits for an app to answer.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// [`probe`] every app at once, answering in the order they were given.
///
/// Concurrent because the answer is one round trip per app, and neither a
/// listing nor a status report should take as long as the slowest dead app in
/// it. A check that panicked counts as a failed one: an operator can do nothing
/// different about the two.
pub async fn probe_all(apps: &[std::sync::Arc<super::App>]) -> Vec<bool> {
    let checks: Vec<_> = apps
        .iter()
        .cloned()
        .map(|app| {
            tokio::spawn(async move {
                // Any host of the app's own will do; the check is addressed to
                // the upstream either way.
                let host = app.hosts()[0].as_str();
                let readiness = &app.manifest.container.health.readiness;

                probe(app.upstream, host, readiness).await
            })
        })
        .collect();

    let mut ready = Vec::with_capacity(checks.len());
    for check in checks {
        ready.push(matches!(check.await, Ok(Ok(()))));
    }

    ready
}

/// One check, given `timeout` to finish.
async fn check(addr: SocketAddr, host: &str, readiness: &Probe) -> Result<()> {
    let attempt = async {
        match readiness.kind {
            Check::Tcp => tcp(addr).await,
            // Validation guarantees the path; this keeps the guarantee local.
            Check::Http => {
                let path = readiness
                    .path
                    .as_deref()
                    .ok_or_else(|| anyhow!("no path to request"))?;

                http(addr, host, path).await
            }
            Check::None => Ok(()),
        }
    };

    match timeout(readiness.timeout, attempt).await {
        Ok(result) => result,
        Err(_) => bail!("no answer within {:?}", readiness.timeout),
    }
}

/// Ready when the app accepts a connection *and keeps it*.
///
/// Connecting is not enough. Docker publishes a container's port by listening
/// on the host itself and forwarding, so the host port accepts from the moment
/// the container starts, long before anything inside it listens — and then
/// closes the connection it just accepted. A check that stopped at `connect`
/// would pass instantly for every app, which is exactly the gap readiness
/// gating exists to close.
async fn tcp(addr: SocketAddr) -> Result<()> {
    let stream = TcpStream::connect(addr).await.context("connecting")?;

    // Nothing is expected to arrive; the connection staying open is the
    // answer, and a closed one arrives much faster than this.
    let Ok(readable) = timeout(SETTLE, stream.readable()).await else {
        return Ok(());
    };
    readable.context("waiting on the connection")?;

    let mut byte = [0_u8; 1];
    match stream.try_read(&mut byte) {
        // Closed the instant it was opened: the port is published but the app
        // behind it is not listening yet.
        Ok(0) => bail!("the connection was closed as soon as it was made"),
        // An app that greets its clients — unusual over http, but it is up.
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
            bail!("the connection was reset as soon as it was made")
        }
        Err(error) => Err(error).context("reading from the connection"),
    }
}

/// Ready when the app answers `path` without an error status.
///
/// The connection is made fresh every time and dropped after: a pooled one
/// would let a check pass against a connection the app opened before it broke.
async fn http(addr: SocketAddr, host: &str, path: &str) -> Result<()> {
    let stream = TcpStream::connect(addr).await.context("connecting")?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .context("starting an http conversation")?;
    let driver = tokio::spawn(connection);

    let request = Request::builder()
        .uri(path)
        // Sent as the app's own hostname, so an app that serves by virtual
        // host recognises the check as traffic for itself.
        .header(http::header::HOST, host)
        .body(Empty::<Bytes>::new())?;

    let status = sender
        .send_request(request)
        .await
        .with_context(|| format!("requesting {path}"))?
        .status();
    driver.abort();

    // Anything that is not an error is ready enough: an app answering a
    // redirect or a 404 for its health path is up, whatever else is wrong.
    if status >= StatusCode::INTERNAL_SERVER_ERROR {
        bail!("{path} answered {status}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::get;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;
    use tokio::net::TcpListener;

    fn quick(kind: Check) -> Probe {
        Probe {
            kind,
            initial_delay: Duration::ZERO,
            interval: Duration::from_millis(10),
            timeout: Duration::from_millis(500),
            failure_threshold: 5,
            ..Probe::default()
        }
    }

    /// An address nothing is listening on, and nothing will be.
    async fn dead_address() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        addr
    }

    #[tokio::test]
    async fn a_listening_app_is_ready() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        wait_until_ready(addr, "alpha.test", &quick(Check::Tcp))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn gives_up_on_an_app_that_never_listens() {
        let addr = dead_address().await;

        let err = wait_until_ready(addr, "alpha.test", &quick(Check::Tcp))
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("not ready after 5 tcp checks"), "{err}");
    }

    #[tokio::test]
    async fn waits_for_an_app_that_starts_late() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        // Rebound after a delay, the way a container's app starts after its
        // port is published.
        tokio::spawn(async move {
            sleep(Duration::from_millis(80)).await;
            let listener = TcpListener::bind(addr).await.unwrap();
            // Hold it open for the rest of the test.
            sleep(Duration::from_secs(30)).await;
            drop(listener);
        });

        let readiness = Probe {
            failure_threshold: 100,
            ..quick(Check::Tcp)
        };
        wait_until_ready(addr, "alpha.test", &readiness)
            .await
            .unwrap();
    }

    /// What docker's published port does before the app inside is listening:
    /// accept, then immediately close. The reason a tcp check cannot stop at
    /// `connect`.
    #[tokio::test]
    async fn an_app_whose_connection_is_dropped_at_once_is_not_ready() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                drop(stream);
            }
        });

        let err = wait_until_ready(addr, "alpha.test", &quick(Check::Tcp))
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("closed as soon as it was made"), "{err}");
    }

    #[tokio::test]
    async fn skips_the_check_entirely_when_asked_to() {
        let addr = dead_address().await;

        wait_until_ready(addr, "alpha.test", &quick(Check::None))
            .await
            .unwrap();
    }

    /// An app that answers 503 until it has warmed up, which is the whole
    /// reason to prefer an http check to a tcp one.
    async fn flaky_http(failures: u32) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(AtomicU32::new(0));

        let router = Router::new().route(
            "/healthz",
            get(move || {
                let seen = seen.clone();
                async move {
                    if seen.fetch_add(1, Ordering::SeqCst) < failures {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::OK
                    }
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        addr
    }

    fn http_readiness() -> Probe {
        Probe {
            path: Some("/healthz".to_owned()),
            ..quick(Check::Http)
        }
    }

    /// An app that never answers twice the same way — a container crash-looping
    /// under its engine's restart policy, seen from out here.
    async fn alternating_http() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(AtomicU32::new(0));

        let router = Router::new().route(
            "/healthz",
            get(move || {
                let seen = seen.clone();
                async move {
                    if seen.fetch_add(1, Ordering::SeqCst).is_multiple_of(2) {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::OK
                    }
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        addr
    }

    /// The wait that used to have no end. Neither streak ever reaches its
    /// threshold, because each reset the other — and this is awaited holding
    /// the app's working lock, so "no end" was the supervisor losing the app
    /// and the automatic deployer losing every app behind it.
    #[tokio::test]
    async fn gives_up_on_an_app_that_flaps_for_ever() {
        let addr = alternating_http().await;
        let readiness = Probe {
            // Never two passes in a row from a server that alternates, so the
            // only way out is the clock.
            success_threshold: 2,
            failure_threshold: 5,
            timeout: Duration::from_millis(50),
            ..http_readiness()
        };

        let started = Instant::now();
        let err = wait_until_ready(addr, "alpha.test", &readiness)
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("still flapping"), "{err}");
        // It gave up on the budget, not on a streak, and did it near the
        // budget rather than an iteration or two either side of forever.
        assert!(
            started.elapsed() < budget(&readiness) * 3,
            "{:?}",
            started.elapsed()
        );
    }

    /// The budget is the probe's own patience, not a number this module picked
    /// — a manifest that asks to wait longer is waited on longer.
    #[test]
    fn the_budget_is_what_the_probe_asked_for() {
        let readiness = Probe {
            initial_delay: Duration::from_secs(5),
            interval: Duration::from_secs(2),
            timeout: Duration::from_secs(1),
            failure_threshold: 10,
            ..quick(Check::Tcp)
        };

        assert_eq!(budget(&readiness), Duration::from_secs(5 + 10 * 3));
    }

    /// Until it asks for something no apply can afford. A legal manifest can
    /// spell a hundred and fifty days, and the app that wrote it is not the one
    /// that pays for the wait.
    #[test]
    fn an_absurd_probe_is_capped_rather_than_honoured() {
        let readiness = Probe {
            interval: Duration::from_secs(3600),
            failure_threshold: 3600,
            ..quick(Check::Tcp)
        };

        assert_eq!(budget(&readiness), MAX_READINESS_WAIT);
    }

    /// Saturating rather than panicking or wrapping: these are numbers an
    /// operator types, and `u32::MAX` of them is a manifest, not an attack.
    #[test]
    fn the_widest_probe_a_manifest_can_spell_still_has_a_budget() {
        let readiness = Probe {
            initial_delay: Duration::MAX,
            interval: Duration::MAX,
            timeout: Duration::MAX,
            failure_threshold: u32::MAX,
            ..quick(Check::Tcp)
        };

        assert_eq!(budget(&readiness), MAX_READINESS_WAIT);
    }

    #[tokio::test]
    async fn an_app_answering_its_health_path_is_ready() {
        let addr = flaky_http(0).await;

        wait_until_ready(addr, "alpha.test", &http_readiness())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn waits_out_an_app_that_answers_503_first() {
        let addr = flaky_http(3).await;

        wait_until_ready(addr, "alpha.test", &http_readiness())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn gives_up_on_an_app_that_only_ever_errors() {
        let addr = flaky_http(u32::MAX).await;

        let err = wait_until_ready(addr, "alpha.test", &http_readiness())
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("503"), "{err}");
    }

    /// A 404 means the app is answering, which is what a readiness check is
    /// asking about — a wrong path is a manifest bug, not a broken app.
    #[tokio::test]
    async fn a_missing_health_path_still_counts_as_answering() {
        let addr = flaky_http(0).await;
        let readiness = Probe {
            path: Some("/nope".to_owned()),
            ..quick(Check::Http)
        };

        wait_until_ready(addr, "alpha.test", &readiness)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn requires_a_success_streak_when_asked_to() {
        let addr = flaky_http(0).await;
        let readiness = Probe {
            success_threshold: 3,
            ..http_readiness()
        };

        // Nothing to assert beyond finishing: with a 10ms interval the streak
        // is quick, and failing to require it would finish too.
        wait_until_ready(addr, "alpha.test", &readiness)
            .await
            .unwrap();
    }

    /// The whole point of watching: an app that passed its readiness check and
    /// was routed to has since stopped answering, and only a standing check
    /// notices — the container is still running, so the engine says nothing.
    #[tokio::test]
    async fn notices_an_app_that_stops_answering() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let watching =
            tokio::spawn(async move { watch(addr, "alpha.test", &quick(Check::Tcp)).await });

        // Let it pass a few checks first, so what it reports is a working app
        // going away rather than one that was never there.
        sleep(Duration::from_millis(50)).await;
        drop(listener);

        let reason = timeout(Duration::from_secs(10), watching)
            .await
            .expect("watch should have given up by now")
            .unwrap();

        assert!(reason.contains("failed 5 tcp checks in a row"), "{reason}");
    }

    /// A supervisor that restarted an app for one missed check would be a
    /// worse fault than the one it was watching for: a slow request or a
    /// garbage-collection pause looks exactly like a broken app for one check.
    #[tokio::test]
    async fn does_not_give_up_on_a_single_failed_check() {
        let addr = flaky_http(1).await;

        let liveness = http_readiness();
        let watching = watch(addr, "alpha.test", &liveness);

        assert!(
            timeout(Duration::from_millis(200), watching).await.is_err(),
            "watch gave up over one failed check"
        );
    }

    /// `none` says never restart this app for failing a check, so the watch
    /// has nothing to report and must not report anything.
    #[tokio::test]
    async fn never_gives_up_on_an_app_it_was_told_not_to_check() {
        let addr = dead_address().await;

        let liveness = quick(Check::None);
        let watching = watch(addr, "alpha.test", &liveness);

        assert!(timeout(Duration::from_millis(100), watching).await.is_err());
    }

    /// The reason is handed to the supervisor and from there to the operator,
    /// who was not watching: it has to say how many checks failed and what the
    /// app actually said the last time.
    #[tokio::test]
    async fn says_how_many_checks_failed_and_what_the_last_one_said() {
        let addr = flaky_http(u32::MAX).await;
        let liveness = http_readiness();

        let reason = timeout(
            Duration::from_secs(10),
            watch(addr, "alpha.test", &liveness),
        )
        .await
        .expect("watch should have given up by now");

        assert!(reason.contains("failed 5 http checks in a row"), "{reason}");
        assert!(reason.contains("503"), "{reason}");
    }
}

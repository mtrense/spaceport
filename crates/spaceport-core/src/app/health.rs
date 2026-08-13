//! Deciding whether an app is working.
//!
//! Readiness only, for now, and only during an apply: the question this
//! answers is "may traffic be routed here yet?", asked once, at the one moment
//! spaceport is in a position to wait for the answer. Watching an app that has
//! *stopped* being ready is a supervisor's job, and there is no supervisor.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How long a tcp check waits to see whether a connection it just made is
/// going to survive. Not configurable: it is a property of how the container
/// engine publishes ports, not of the app.
const SETTLE: Duration = Duration::from_millis(100);

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::Empty;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tracing::debug;

use super::manifest::{Check, Readiness};

/// Wait until the app at `addr` passes its readiness check.
///
/// Returns as soon as it does. Gives up once `failure_threshold` checks in a
/// row have failed, and says what the last failure was — that message is the
/// only thing the operator will have to go on.
pub async fn wait_until_ready(addr: SocketAddr, host: &str, readiness: &Readiness) -> Result<()> {
    if readiness.kind == Check::None {
        return Ok(());
    }

    let started = Instant::now();
    sleep(readiness.initial_delay).await;

    let (mut passed, mut failed) = (0, 0);
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
            }
        }

        sleep(readiness.interval).await;
    }
}

/// One check, given `timeout` to finish.
async fn check(addr: SocketAddr, host: &str, readiness: &Readiness) -> Result<()> {
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

    fn quick(kind: Check) -> Readiness {
        Readiness {
            kind,
            initial_delay: Duration::ZERO,
            interval: Duration::from_millis(10),
            timeout: Duration::from_millis(500),
            failure_threshold: 5,
            ..Readiness::default()
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

        let readiness = Readiness {
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

    fn http_readiness() -> Readiness {
        Readiness {
            path: Some("/healthz".to_owned()),
            ..quick(Check::Http)
        }
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
        let readiness = Readiness {
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
        let readiness = Readiness {
            success_threshold: 3,
            ..http_readiness()
        };

        // Nothing to assert beyond finishing: with a 10ms interval the streak
        // is quick, and failing to require it would finish too.
        wait_until_ready(addr, "alpha.test", &readiness)
            .await
            .unwrap();
    }
}

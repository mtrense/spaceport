//! The edge: where client traffic enters spaceport.
//!
//! Two accept loops, one per listener, both feeding the same request chain.
//! Everything past the TCP accept happens in a per-connection task, including
//! the TLS handshake, so a slow or hostile client can never stall the loop
//! that is admitting everyone else.
//!
//! That alone is not enough. A task that never stalls the loop can still
//! outlive its usefulness, and enough of them will exhaust the process's file
//! descriptors just as effectively as a blocked accept would. So every stage a
//! client can drag out is bounded — the TLS handshake by
//! [`TLS_HANDSHAKE_TIMEOUT`], the silence before a client says anything at all
//! by [`FIRST_WORD_TIMEOUT`], the request headers by [`HEADER_READ_TIMEOUT`],
//! an idle HTTP/2 connection by its keep-alive ping — and the number of
//! connections alive at once is capped, across *both* listeners together, by
//! [`MAX_CONNECTIONS`]. The cap follows a connection past an upgrade too: a
//! WebSocket tunnel keeps the [`ConnectionSlot`] its handshake was admitted on,
//! because a tunnel is the longest-lived thing here and a cap that let go of it
//! would bound everything except what matters.

mod gate;
pub(crate) mod home;
pub(crate) mod proxy;
pub(crate) mod routes;
mod service;
pub mod tls;
mod websocket;

pub use home::{Home, LoginAttempts, LoginThrottle};
pub use service::{ConnInfo, Scheme};

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::Sleep;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::Config;
use crate::acme::Challenges;
use crate::app::AppStore;
use service::EdgeService;

/// How many connections may be alive at once, both listeners together.
///
/// Every connection costs a file descriptor and a task, and the two listeners
/// share one budget on purpose: the plaintext listener is the cheap one to
/// flood — no handshake, no certificate — and giving it a budget of its own
/// would let it exhaust the process's descriptors while the https listener,
/// nominally still within its own limit, could no longer accept anything.
///
/// Ten thousand is far above what a host proxying a handful of apps sees, and
/// it is under the descriptor limit spaceport actually runs with rather than
/// under one hoped for: nothing raises `RLIMIT_NOFILE` by itself, and Linux's
/// default soft limit of 1024 would have the process failing in `accept()`
/// long before this cap bound anything. So the unit `spaceport setup` writes
/// raises the limit to match — see
/// [`crate::setup::systemd::FILE_DESCRIPTOR_LIMIT`], which is derived from this
/// number and leaves room for the upstream socket each connection may open in
/// turn. Run outside that unit, on a host that has not been told otherwise, the
/// descriptor limit binds first and this cap is the looser of the two.
pub(crate) const MAX_CONNECTIONS: usize = 10_000;

/// How long a client has, after the TCP connection is up, to get through the
/// TLS handshake.
///
/// A connection that completes the three-way handshake and then says nothing
/// costs a descriptor and a task for as long as it is left alone, and it costs
/// the attacker one packet. Ten seconds is generous for a handshake on a slow
/// mobile link — the round trips are few and the computation is milliseconds —
/// and short enough that holding descriptors this way needs a real flood.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a client has, once its connection is ready to carry HTTP, to send
/// the first byte of anything at all.
///
/// This is the gap [`HEADER_READ_TIMEOUT`] cannot cover. Before hyper can start
/// a header timeout it has to know which protocol it is timing: `auto::Builder`
/// reads up to the length of the HTTP/2 preface to tell a preface from a
/// request line, and only then constructs the HTTP/1.1 connection the header
/// timeout belongs to. That first read has no deadline of its own, so a client
/// that connects and sends nothing — on the plaintext listener directly, or on
/// the https listener by completing a perfectly good handshake and stopping —
/// would hold a task, a slot and a descriptor for ever, at a cost to itself of
/// one packet. [`FirstWord`] puts a deadline on it.
///
/// Ten seconds, matching [`TLS_HANDSHAKE_TIMEOUT`] rather than the header
/// budget, because it is the same question that timeout asks — is anybody
/// there? — and not the more forgiving one [`HEADER_READ_TIMEOUT`] asks, which
/// is how slowly a client that has shown itself may finish its sentence.
const FIRST_WORD_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a client has to deliver a complete set of HTTP/1.1 request headers.
///
/// This is hyper's own default, set explicitly for two reasons: it only takes
/// effect once a timer is installed on the builder, so writing it out is a
/// reminder that the [`TokioTimer`] beside it is load-bearing rather than
/// decorative; and a reader deserves to see the number that decides how long a
/// slowloris gets to dribble a header line.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How often an idle HTTP/2 connection is pinged.
///
/// hyper ships keep-alive pings off, and turning them on is deliberate: the
/// HTTP/1.1 header timeout has no HTTP/2 equivalent, so a client can open a
/// connection, open streams on it and then simply stop, and nothing in the
/// protocol times that out. The ping is what makes that attack cost the
/// attacker a live, answering peer instead of a forgotten socket, and it is the
/// only thing here that reaps an HTTP/2 connection whose other end has gone
/// away without a FIN.
///
/// A minute between pings, rather than something tighter, because the trade is
/// asymmetric: the cost of pinging is a wakeup per idle connection per interval
/// — paid on every quiet connection, of which a proxy has many — while the cost
/// of pinging rarely is only that a dead socket is noticed a minute later than
/// it might have been. How long the answer may take is hyper's own twenty
/// seconds, left alone: a shorter window would be won by ordinary TCP
/// retransmission backoff on a lossy mobile link, and would cost a live client
/// a reconnect and a TLS handshake at the worst possible moment.
const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(60);

/// The three deadlines a connection is held to, carried together so the two
/// internal functions that need them can be handed one value rather than three.
///
/// It exists because the numbers have to be injectable. The consts above are
/// the production answer and [`serve`] passes exactly them, but a test that
/// wants to prove a timeout fires cannot wait ten seconds for it, and the
/// alternative — pausing the clock while real sockets talk over loopback — is
/// not sound: a paused clock auto-advances to the earliest pending timer the
/// moment the runtime idles, so whichever timer happened to be armed first
/// wins, which is a race and not a measurement. Short real durations on a clock
/// nobody is touching are the honest way to assert on these, and this is what
/// lets a test choose them. It is deliberately not a config surface: nothing
/// outside this module can name the type or the fields.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timeouts {
    /// See [`TLS_HANDSHAKE_TIMEOUT`].
    tls_handshake: Duration,
    /// See [`FIRST_WORD_TIMEOUT`].
    first_word: Duration,
    /// See [`HEADER_READ_TIMEOUT`].
    header_read: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            tls_handshake: TLS_HANDSHAKE_TIMEOUT,
            first_word: FIRST_WORD_TIMEOUT,
            header_read: HEADER_READ_TIMEOUT,
        }
    }
}

/// A connection's place in the two things that count connections: its slot
/// under [`MAX_CONNECTIONS`], and the tally [`serve`] waits out before it
/// returns. It also carries the token that says spaceport is stopping, since
/// whoever holds the first two is exactly who needs to hear the third.
///
/// It is a handle rather than a guard the connection task simply keeps, because
/// one kind of connection outlives that task. hyper's HTTP/1.1 connection
/// future *completes* at an upgrade — it hands the raw socket to the pending
/// `Upgraded` and returns `Ok(())` — so a WebSocket handshake ends the task
/// that admitted it while the tunnel it opened runs on, in a task of its own,
/// holding a client socket and an upstream socket for the whole session.
/// Letting the slot go there would mean the cap bounded every connection except
/// the long-lived ones, and `serve` returned while tunnels were still shovelling
/// bytes. So the handle is clonable, rides every request's extensions, and
/// [`websocket::tunnel`] takes a clone into the tunnel task.
#[derive(Clone)]
pub(crate) struct ConnectionSlot(Arc<Slot>);

/// What a [`ConnectionSlot`] is holding on everyone's behalf. Both fields do
/// their work by being dropped, which happens when the last clone goes.
struct Slot {
    /// Returned to the semaphore, freeing the slot for the next client.
    _permit: OwnedSemaphorePermit,
    /// The last of these to be dropped is what closes the channel [`serve`] is
    /// waiting on.
    _alive: mpsc::Sender<()>,
    /// Cancelled when spaceport is shutting down.
    shutdown: CancellationToken,
}

impl ConnectionSlot {
    fn new(
        permit: OwnedSemaphorePermit,
        alive: mpsc::Sender<()>,
        shutdown: CancellationToken,
    ) -> Self {
        Self(Arc::new(Slot {
            _permit: permit,
            _alive: alive,
            shutdown,
        }))
    }

    /// The token cancelled when spaceport is stopping. Anything that means to
    /// outlive its connection task has to watch this itself: nothing else will
    /// interrupt it, and [`serve`] cannot return until it lets the slot go.
    pub(crate) fn shutdown(&self) -> &CancellationToken {
        &self.0.shutdown
    }

    /// A slot attached to nothing, for tests that serve a connection without an
    /// accept loop behind it: a semaphore of its own to hold a permit in, a
    /// channel nobody is waiting on, and a token nobody cancels.
    #[cfg(test)]
    pub(crate) fn detached() -> Self {
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let (alive, _drained) = mpsc::channel::<()>(1);

        Self::new(permit, alive, CancellationToken::new())
    }
}

/// What every connection shares. Cheap to clone behind an `Arc`; nothing in
/// here is touched on the proxy path except the two scalars.
pub struct EdgeState {
    /// The routes spaceport answers itself, on every host.
    pub router: Router,
    /// The app spaceport serves on its own hostname, if it was given one. Kept
    /// whether or not there is a hostname: which host reaches it is the routing
    /// table's business, and the edge only needs the thing to hand it to.
    pub home: Router,
    /// The apps traffic is forwarded to.
    pub apps: Arc<AppStore>,
    /// The connection pool traffic is forwarded through.
    pub upstreams: proxy::Upstreams,
    /// The sessions the gate checks app cookies against, per request on gated
    /// apps — the same repository the login page and the callback write, or a
    /// cookie one listener minted would be one another refuses.
    pub sessions: Arc<crate::auth::SessionRepository>,
    /// What each user may reach, for the intersection a minted JWT's `roles`
    /// carries. The same repository the exchange checks entitlements through,
    /// because both are reading the same access question at different moments.
    pub entitlements: Arc<crate::auth::EntitlementRepository>,
    /// Who each user is at their connections, for the `name` and `email` a
    /// minted JWT carries. Read per mint beside the entitlements, and by the
    /// same argument: what an IdP last said about a person can have changed
    /// since the session began, and the token is the thing that has to be
    /// current.
    pub identities: Arc<crate::auth::IdentityRepository>,
    /// The key the gate signs JWTs with — the same signer whose JWKS the home
    /// router serves, or a token minted here would fail against the document
    /// apps verify with.
    pub signer: Arc<crate::auth::JwtSigner>,
    /// The four-minute JWT cache: the gate's hot path, and the very instance
    /// the auth repositories purge on the operator side. Shared through
    /// [`Home`], exactly as `sessions` is.
    pub jwt_cache: Arc<crate::auth::JwtCache>,
    /// Spaceport's own hostname, for building the exchange URL a gated app
    /// bounces strangers to. Absent when the config named none, in which case
    /// gated apps can only refuse.
    pub hostname: Option<String>,
    /// Port plaintext clients are redirected to.
    pub https_port: u16,
}

/// Serve both listeners until `shutdown` is cancelled.
///
/// `acceptor` decides which certificate each TLS connection is served, and
/// `challenges` is what the plaintext listener answers an ACME CA out of. Both
/// are built by the caller: what certificates spaceport has is not the edge's
/// business, and serving them is not [`crate::acme`]'s. `home` is the same
/// arrangement for the pages spaceport serves as itself — the state store and
/// the way out to GitHub belong to the process, not to the edge.
///
/// Returns once every in-flight connection has finished, so the caller can
/// treat a normal return as "nothing is still being served".
pub async fn serve(
    config: &Config,
    apps: Arc<AppStore>,
    home: Arc<home::Home>,
    acceptor: TlsAcceptor,
    challenges: Arc<Challenges>,
    shutdown: CancellationToken,
) -> Result<()> {
    let listen = &config.edge.listen;

    // The pieces the every-host routes and the gate share with the home
    // router, copied out before `home` is consumed into its router: they are
    // the same repositories on purpose — the callback redeems what the login
    // page minted — and this is where that sameness is wired.
    let sessions = home.sessions.clone();
    let entitlements = home.entitlements.clone();
    let identities = home.identities.clone();
    let signer = home.signer.clone();
    let jwt_cache = home.jwt_cache.clone();
    let hostname = home.hostname.clone();

    let state = Arc::new(EdgeState {
        router: routes::router(routes::SpaceportRoutes {
            challenges,
            apps: apps.clone(),
            sessions: sessions.clone(),
            hostname: hostname.clone(),
            https_port: listen.https.port(),
        }),
        home: home::router(home),
        apps,
        upstreams: proxy::Upstreams::new(),
        sessions,
        entitlements,
        identities,
        signer,
        jwt_cache,
        hostname,
        https_port: listen.https.port(),
    });

    // Bind both before serving either: a half-up edge is worse than a clean
    // failure to start.
    let http = TcpListener::bind(listen.http)
        .await
        .with_context(|| format!("binding the http listener to {}", listen.http))?;
    let https = TcpListener::bind(listen.https)
        .await
        .with_context(|| format!("binding the https listener to {}", listen.https))?;

    info!(addr = %listen.http, "listening for http, redirecting to https");
    info!(addr = %listen.https, "listening for https");

    // Every connection task holds a clone of `alive`. Once the accept loops
    // are done and this end is dropped, the receiver resolves as soon as the
    // last connection lets go of its clone.
    let (alive, mut drained) = mpsc::channel::<()>(1);

    // One budget for both listeners, for the reason [`MAX_CONNECTIONS`] gives.
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    tokio::join!(
        accept_loop(
            http,
            None,
            state.clone(),
            shutdown.clone(),
            alive.clone(),
            limit.clone(),
            Timeouts::default()
        ),
        accept_loop(
            https,
            Some(acceptor),
            state,
            shutdown.clone(),
            alive.clone(),
            limit,
            Timeouts::default()
        ),
    );

    drop(alive);
    let _ = drained.recv().await;
    info!("edge stopped");

    Ok(())
}

/// Admit connections until cancelled, handing each one to its own task.
async fn accept_loop(
    listener: TcpListener,
    acceptor: Option<TlsAcceptor>,
    state: Arc<EdgeState>,
    shutdown: CancellationToken,
    alive: mpsc::Sender<()>,
    limit: Arc<Semaphore>,
    timeouts: Timeouts,
) {
    let scheme = if acceptor.is_some() {
        Scheme::Https
    } else {
        Scheme::Http
    };

    // Whether this listener is currently turning clients away. Refusals come in
    // floods by their nature, and a line per refused connection would bury the
    // one line that matters; this makes it a line per outage instead.
    let mut refusing = false;

    loop {
        let (stream, peer) = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                // Per-connection errors (fd limits, a client gone between
                // SYN and accept) must not take the listener down.
                Err(error) => {
                    warn!(%error, scheme = scheme.as_str(), "accept failed");
                    continue;
                }
            },
        };

        // Take the slot before spawning, and refuse rather than wait. Waiting
        // for a permit would put the accept loop itself behind a full
        // connection table, which is precisely the stall this module promises
        // never to have — one client's slow handshake would delay everybody's
        // admission. Closing the connection immediately is honest backpressure
        // instead: the client learns at once, rather than sitting in a socket
        // that looks established and is being served by nobody.
        //
        // Loudly, but once. This is the single condition under which spaceport
        // stops serving people who have done nothing wrong, so an operator
        // reading a normal log level has to see it — and a flood is exactly
        // when a line per refusal would drown out everything else, including
        // this one. So the transition is what is logged, and the way back out
        // of it too, which together say how long the outage lasted.
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            if !refusing {
                refusing = true;
                warn!(
                    %peer,
                    scheme = scheme.as_str(),
                    limit = MAX_CONNECTIONS,
                    "refusing connections, the table is full"
                );
            }
            continue;
        };
        if refusing {
            refusing = false;
            info!(
                scheme = scheme.as_str(),
                "admitting connections again, the table has room"
            );
        }

        // Latency over throughput: this is a proxy, responses are small and
        // waiting to coalesce them only adds delay.
        if let Err(error) = stream.set_nodelay(true) {
            debug!(%peer, %error, "could not set TCP_NODELAY");
        }

        let conn = ConnInfo { peer, scheme };
        // The slot the connection is admitted on, handed to the service so that
        // whatever the connection turns into can keep hold of it. This task
        // keeps a clone of its own, so an ordinary connection — one that never
        // upgrades and whose requests are long since dropped — still holds its
        // slot until the task ends.
        let slot = ConnectionSlot::new(permit, alive.clone(), shutdown.clone());
        let service = TowerToHyperService::new(EdgeService::new(state.clone(), conn, slot.clone()));
        let acceptor = acceptor.clone();
        let shutdown = shutdown.clone();

        tokio::spawn(async move {
            let _slot = slot;
            match acceptor {
                // The handshake happens here, inside the connection's own
                // task, rather than in the accept loop.
                Some(acceptor) => {
                    match tokio::time::timeout(timeouts.tls_handshake, acceptor.accept(stream))
                        .await
                    {
                        Ok(Ok(stream)) => {
                            serve_connection(stream, service, shutdown, timeouts).await;
                        }
                        Ok(Err(error)) => debug!(%peer, %error, "tls handshake failed"),
                        // Distinct from a failure: nothing went wrong on the
                        // wire, the client simply never got round to speaking.
                        Err(_) => debug!(
                            %peer,
                            timeout = ?timeouts.tls_handshake,
                            "tls handshake timed out"
                        ),
                    }
                }
                None => serve_connection(stream, service, shutdown, timeouts).await,
            }
        });
    }

    debug!(scheme = scheme.as_str(), "stopped accepting");
}

/// Drive one connection, negotiating HTTP/1.1 or HTTP/2 by ALPN or preface.
async fn serve_connection<I>(
    io: I,
    service: TowerToHyperService<EdgeService>,
    shutdown: CancellationToken,
    timeouts: Timeouts,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = Builder::new(TokioExecutor::new());

    // The timer is what makes the rest of this real. hyper carries defaults for
    // these timeouts, but it drops any of them on the floor unless a timer is
    // installed, so a builder without one has a header read timeout on paper
    // and none in fact.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(timeouts.header_read);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(HTTP2_KEEP_ALIVE_INTERVAL);

    // Wrapped rather than handed over bare: everything above times a stage of a
    // conversation that has started, and this is what bounds the silence before
    // one does.
    let io = FirstWord::new(io, timeouts.first_word);

    let connection = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    tokio::pin!(connection);

    let result = tokio::select! {
        result = connection.as_mut() => result,
        () = shutdown.cancelled() => {
            // Stop accepting new requests on this connection, then let the
            // one in flight finish.
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    };

    // A client hanging up mid-request is routine, not something to log loudly.
    if let Err(error) = result {
        debug!(%error, "connection closed with an error");
    }
}

/// IO that insists on hearing something. Until the first read comes back, a
/// deadline runs; if it expires first the read fails and the connection with
/// it. After that this is the wrapped IO and nothing else.
///
/// It exists because the one stage of a connection hyper cannot time is the
/// stage before it knows what it is timing — see [`FIRST_WORD_TIMEOUT`] — and
/// it wraps the IO rather than racing the connection future because the failure
/// has to look like what it is: a read that did not happen, reported where the
/// read was asked for, leaving hyper to tear the connection down its own way.
///
/// Being on the hot path is the whole design constraint. Every byte of every
/// request and every response passes through here for the life of the
/// connection, so once the deadline has done its work it is dropped, and what
/// remains between hyper and the socket is one `Option` check per call.
struct FirstWord<I> {
    io: I,
    /// `Some` only until the first read returns. The timer is boxed so this
    /// type stays [`Unpin`], which is what lets every method here reach the
    /// wrapped IO without a projection.
    deadline: Option<Pin<Box<Sleep>>>,
}

impl<I> FirstWord<I> {
    fn new(io: I, within: Duration) -> Self {
        Self {
            io,
            deadline: Some(Box::pin(tokio::time::sleep(within))),
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for FirstWord<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        let Some(deadline) = this.deadline.as_mut() else {
            return Pin::new(&mut this.io).poll_read(cx, buf);
        };

        match Pin::new(&mut this.io).poll_read(cx, buf) {
            // The client has spoken — or hung up, which is a read that
            // completed just as much and ends the connection by itself. Either
            // way there is nothing left to wait for, and dropping the timer
            // here is what makes the rest of this connection free.
            Poll::Ready(Ok(())) => {
                this.deadline = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            // Nothing yet, so the socket has registered its waker and the timer
            // registers ours: whichever comes first wakes this task.
            Poll::Pending => {
                if deadline.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }

                // The error is terminal for the connection, so the timer has no
                // second question to ask.
                this.deadline = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the client sent nothing at all",
                )))
            }
        }
    }
}

/// Writes are none of this wrapper's business — the deadline is on the client's
/// first word, and spaceport does not speak first — so every method is the
/// wrapped IO's, vectored writes included, which hyper asks about and would
/// otherwise be told a flat no.
impl<I: AsyncWrite + Unpin> AsyncWrite for FirstWord<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// How long a test waits for something it expects to happen at once.
    ///
    /// Nothing here is asserting on this number — it is a guard, not a
    /// measurement. Without it a regression in any of the refusals below would
    /// leave a socket admitted and unanswered, the read would block for ever,
    /// and `cargo test` — which has no per-test timeout — would hang CI rather
    /// than tell anyone which behaviour broke.
    const PATIENCE: Duration = Duration::from_secs(30);

    /// The value a timeout under test is set to.
    ///
    /// Two orders of magnitude under [`PATIENCE`], which is what makes the
    /// tests below sound: on an unmanipulated clock the timer being asserted on
    /// is the only one that can plausibly fire inside the guard, so a
    /// connection that closes in time closed because of it. Long enough, too,
    /// that a loopback connection and a TLS handshake finish well inside it on
    /// any machine that can run the suite at all.
    const BRIEF: Duration = Duration::from_millis(100);

    /// Enough of an edge to run an accept loop against. Nothing here is what
    /// the connection tests are looking at — they assert on what happens to
    /// the socket before a request is ever routed — but the loop builds a
    /// service per connection and the service wants a state.
    fn state() -> Arc<EdgeState> {
        let db = crate::state::Db::in_memory().unwrap();
        let apps = Arc::new(AppStore::new());
        let jwt_cache = Arc::new(crate::auth::JwtCache::new());
        let sessions = Arc::new(crate::auth::SessionRepository::with_jwt_cache(
            db.clone(),
            jwt_cache.clone(),
        ));
        let entitlements = Arc::new(crate::auth::EntitlementRepository::with_jwt_cache(
            db.clone(),
            jwt_cache.clone(),
        ));

        Arc::new(EdgeState {
            router: routes::router(routes::SpaceportRoutes {
                challenges: Arc::new(Challenges::new()),
                apps: apps.clone(),
                sessions: sessions.clone(),
                hostname: None,
                https_port: 443,
            }),
            home: Router::new(),
            apps,
            upstreams: proxy::Upstreams::new(),
            sessions,
            entitlements,
            identities: Arc::new(crate::auth::IdentityRepository::new(db.clone())),
            signer: Arc::new(crate::auth::JwtSigner::new(db)),
            jwt_cache,
            hostname: None,
            https_port: 443,
        })
    }

    /// An accept loop on a loopback port, with a budget and a set of deadlines
    /// the test chooses. Returns the address to knock on and the token that
    /// stops it.
    ///
    /// The deadlines are a parameter because a test asserting on one of them
    /// has to shorten that one and leave the others alone — see [`Timeouts`]
    /// for why shortening beats stopping the clock.
    async fn edge(
        acceptor: Option<TlsAcceptor>,
        permits: usize,
        timeouts: Timeouts,
    ) -> (std::net::SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let (alive, _drained) = mpsc::channel::<()>(1);
        let limit = Arc::new(Semaphore::new(permits));

        tokio::spawn(accept_loop(
            listener,
            acceptor,
            state(),
            shutdown.clone(),
            alive,
            limit,
            timeouts,
        ));

        (addr, shutdown)
    }

    /// The cap is on connections alive at once, so a client that is being
    /// served holds its slot and the next one along is turned away — closed
    /// at once rather than parked in a socket nobody is reading.
    ///
    /// Production deadlines throughout, and deliberately so: this test needs
    /// the first connection to still be holding its slot when the second one
    /// knocks, so every timeout that could reap it — the header read timeout,
    /// once the answer is delivered and hyper is waiting on the next request —
    /// has to stay far longer than the test takes.
    #[tokio::test]
    async fn refuses_a_connection_once_the_table_is_full() {
        let (addr, shutdown) = edge(None, 1, Timeouts::default()).await;

        // A whole request and its answer, so the first connection is provably
        // admitted and — keep-alive being the default — provably still alive,
        // holding the only slot there is, when the second one knocks.
        let mut served = TcpStream::connect(addr).await.unwrap();
        served
            .write_all(b"GET / HTTP/1.1\r\nHost: nobody.test\r\n\r\n")
            .await
            .unwrap();
        let mut answer = [0u8; 12];
        tokio::time::timeout(PATIENCE, served.read_exact(&mut answer))
            .await
            .expect("the first connection was never answered")
            .unwrap();
        assert!(
            answer.starts_with(b"HTTP/1.1 "),
            "expected a response, got {:?}",
            String::from_utf8_lossy(&answer)
        );

        let mut refused = TcpStream::connect(addr).await.unwrap();
        // A whole request on this one too, so what is being asserted is that
        // nobody served it. A connection that said nothing would also read back
        // nothing — [`FIRST_WORD_TIMEOUT`] would see to that — and would prove
        // only that the silence timeout works, which is another test's job.
        // Writing may fail outright if the close has already landed, which is
        // the refusal arriving early rather than a problem.
        let _ = refused
            .write_all(b"GET / HTTP/1.1\r\nHost: nobody.test\r\n\r\n")
            .await;
        // Reading to the end rather than expecting a particular error: the
        // refusal is a close, and what a close looks like from here depends on
        // whether the request above beat it. A socket closed with bytes still
        // unread resets rather than ending cleanly, so both endings are the
        // same refusal — and neither of them is a response, which is what the
        // emptiness below is for.
        let mut refusal = Vec::new();
        let read = tokio::time::timeout(PATIENCE, refused.read_to_end(&mut refusal)).await;

        let read = read.expect("the connection was neither served nor closed, it was left open");
        if let Err(error) = read {
            assert_eq!(
                error.kind(),
                io::ErrorKind::ConnectionReset,
                "expected the connection to be closed, not to fail: {error}"
            );
        }
        assert!(
            refusal.is_empty(),
            "expected the connection to be dropped unserved, got {:?}",
            String::from_utf8_lossy(&refusal)
        );

        shutdown.cancel();
    }

    /// And the slot comes back: the refused connection above was not a
    /// permanent loss of capacity, so once the connection holding the slot
    /// hangs up the next client is admitted normally.
    ///
    /// Production deadlines again: the slot has to come back because the
    /// connection ended, and a short timeout would end connections for it and
    /// let the test pass without the release path working at all.
    #[tokio::test]
    async fn gives_the_slot_back_when_the_connection_ends() {
        let (addr, shutdown) = edge(None, 1, Timeouts::default()).await;

        let mut served = TcpStream::connect(addr).await.unwrap();
        served
            .write_all(b"GET / HTTP/1.1\r\nHost: nobody.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(PATIENCE, served.read_to_end(&mut answer))
            .await
            .expect("the first connection was never answered or closed")
            .unwrap();
        drop(served);

        // The connection task releases its permit as it ends, which may be a
        // moment after the client saw the close, so this is the one place the
        // test has to wait for something rather than observe it.
        let mut next = None;
        for _ in 0..100 {
            let mut candidate = TcpStream::connect(addr).await.unwrap();
            candidate
                .write_all(b"GET / HTTP/1.1\r\nHost: nobody.test\r\n\r\n")
                .await
                .unwrap();
            let mut answer = [0u8; 12];
            // A refused candidate reads back an immediate end of stream, so the
            // bound is only there in case one is admitted and then left unread.
            if matches!(
                tokio::time::timeout(PATIENCE, candidate.read_exact(&mut answer)).await,
                Ok(Ok(_))
            ) {
                next = Some(answer);
                break;
            }
            tokio::task::yield_now().await;
        }

        assert!(
            next.is_some_and(|answer| answer.starts_with(b"HTTP/1.1 ")),
            "the slot never came back"
        );

        shutdown.cancel();
    }

    /// A client that opens a TCP connection to the https listener and then
    /// says nothing is dropped rather than held forever.
    ///
    /// The handshake deadline is injected as [`BRIEF`] rather than waited out
    /// at its production ten seconds, and the clock is left alone. Injecting is
    /// the honest way round: what is being asserted is that spaceport arms a
    /// handshake deadline and drops the connection when it expires, which is
    /// true of any value, and a hundred milliseconds proves it in a hundred
    /// milliseconds. Pausing the clock instead would assert nothing — a paused
    /// clock jumps to whichever timer is armed first the moment the runtime
    /// idles, and over a real socket that can be this test's own guard, firing
    /// before the server has armed anything.
    ///
    /// So the two assertions bracket the real elapsed time: the close arrived
    /// inside [`PATIENCE`], which only the deadline under test is short enough
    /// to cause, and no sooner than the deadline itself, which rules out the
    /// connection having been dropped for some other reason entirely.
    #[tokio::test]
    async fn drops_a_tls_client_that_never_starts_the_handshake() {
        let acceptor = tls::acceptor(tls::resolver().unwrap()).unwrap();
        let (addr, shutdown) = edge(
            Some(acceptor),
            1,
            Timeouts {
                tls_handshake: BRIEF,
                ..Timeouts::default()
            },
        )
        .await;

        // Started before the connection, so it cannot overstate how long the
        // server took: the server can only arm its deadline after this.
        let knocked = Instant::now();
        let mut silent = TcpStream::connect(addr).await.unwrap();
        let mut nothing = Vec::new();
        let closed = tokio::time::timeout(PATIENCE, silent.read_to_end(&mut nothing)).await;
        let waited = knocked.elapsed();

        assert!(closed.is_ok(), "the silent connection was never dropped");
        assert!(
            waited >= BRIEF,
            "the connection went away in {waited:?}, sooner than the {BRIEF:?} handshake deadline, \
             so something other than the deadline closed it"
        );
        assert!(nothing.is_empty());

        shutdown.cancel();
    }

    /// The hole [`FIRST_WORD_TIMEOUT`] closes, on the listener where it is
    /// cheapest to exploit: a client that completes the TCP handshake and then
    /// sends nothing at all. Nothing in hyper times this — the protocol sniff
    /// that precedes both connection types reads without a deadline, and the
    /// header timeout belongs to a connection that does not exist yet — so
    /// what is being asserted here is entirely [`FirstWord`]'s doing.
    ///
    /// The silence deadline is injected as [`BRIEF`] and the clock is left
    /// alone, for the reason the handshake test above gives: a real deadline of
    /// a hundred milliseconds on a clock nobody is manipulating is the only way
    /// to know that what closed this connection was the deadline and not the
    /// test's own guard racing it.
    #[tokio::test]
    async fn drops_a_plaintext_client_that_never_sends_a_byte() {
        let (addr, shutdown) = edge(
            None,
            1,
            Timeouts {
                first_word: BRIEF,
                ..Timeouts::default()
            },
        )
        .await;

        let knocked = Instant::now();
        let mut silent = TcpStream::connect(addr).await.unwrap();
        let mut nothing = Vec::new();
        let closed = tokio::time::timeout(PATIENCE, silent.read_to_end(&mut nothing)).await;
        let waited = knocked.elapsed();

        assert!(closed.is_ok(), "the silent connection was never dropped");
        assert!(
            waited >= BRIEF,
            "the connection went away in {waited:?}, sooner than the {BRIEF:?} silence deadline, \
             so something other than the deadline closed it"
        );
        assert!(nothing.is_empty());

        shutdown.cancel();
    }

    /// And the same client on the https listener, which is the interesting
    /// case: it does everything right up to the point where it would say
    /// something. The TLS handshake completes, so [`TLS_HANDSHAKE_TIMEOUT`] is
    /// satisfied and disarmed, and the connection is a real one holding a
    /// descriptor, a task and a slot — with nothing but the silence timeout
    /// left to end it.
    ///
    /// Only the silence deadline is shortened; the handshake deadline keeps its
    /// production value. That separation is the point of injecting rather than
    /// pausing the clock. This test has two of spaceport's timers armed in
    /// succession over a real socket, and it needs the second one to be what
    /// ends the connection — so the first is left so long it cannot plausibly
    /// fire, the second is made short enough to observe, and the clock they
    /// both run on is the ordinary one. A paused clock offers no such control:
    /// it advances to the earliest armed timer whenever the runtime idles,
    /// which over loopback is between packets, and would happily expire a
    /// handshake that is merely in flight.
    #[tokio::test]
    async fn drops_a_tls_client_that_says_nothing_after_the_handshake() {
        let acceptor = tls::acceptor(tls::resolver().unwrap()).unwrap();
        let (addr, shutdown) = edge(
            Some(acceptor),
            1,
            Timeouts {
                first_word: BRIEF,
                ..Timeouts::default()
            },
        )
        .await;

        let stream = TcpStream::connect(addr).await.unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config()));
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut silent = connector.connect(name, stream).await.unwrap();

        // After the handshake, because that is when the deadline being measured
        // is armed.
        let handshaked = Instant::now();
        let mut nothing = Vec::new();
        let closed = tokio::time::timeout(PATIENCE, silent.read_to_end(&mut nothing)).await;
        let waited = handshaked.elapsed();

        assert!(
            closed.is_ok(),
            "a handshaked connection that sent nothing was held open"
        );
        assert!(
            waited >= BRIEF,
            "the connection went away in {waited:?}, sooner than the {BRIEF:?} silence deadline, \
             so something other than the deadline closed it"
        );
        assert!(nothing.is_empty());

        shutdown.cancel();
    }

    /// A client that will speak TLS to spaceport's self-signed certificate
    /// without an opinion about who signed it. The test is about what happens
    /// after the handshake, not about the handshake.
    fn client_config() -> rustls::ClientConfig {
        #[derive(Debug)]
        struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

        impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &rustls::pki_types::CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                rustls::crypto::verify_tls12_signature(
                    message,
                    cert,
                    dss,
                    &self.0.signature_verification_algorithms,
                )
            }

            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &rustls::pki_types::CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                rustls::crypto::verify_tls13_signature(
                    message,
                    cert,
                    dss,
                    &self.0.signature_verification_algorithms,
                )
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                self.0.signature_verification_algorithms.supported_schemes()
            }
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        config
    }
}

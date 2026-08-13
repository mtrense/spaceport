//! The edge: where client traffic enters spaceport.
//!
//! Two accept loops, one per listener, both feeding the same request chain.
//! Everything past the TCP accept happens in a per-connection task, including
//! the TLS handshake, so a slow or hostile client can never stall the loop
//! that is admitting everyone else.

pub(crate) mod proxy;
mod routes;
mod service;
mod tls;

pub use service::{ConnInfo, Scheme};

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::Config;
use crate::app::AppStore;
use service::EdgeService;

/// What every connection shares. Cheap to clone behind an `Arc`; nothing in
/// here is touched on the proxy path except the two scalars.
pub struct EdgeState {
    /// The routes spaceport answers itself.
    pub router: Router,
    /// The apps traffic is forwarded to.
    pub apps: Arc<AppStore>,
    /// The connection pool traffic is forwarded through.
    pub upstreams: proxy::Upstreams,
    /// Port plaintext clients are redirected to.
    pub https_port: u16,
}

/// Serve both listeners until `shutdown` is cancelled.
///
/// Returns once every in-flight connection has finished, so the caller can
/// treat a normal return as "nothing is still being served".
pub async fn serve(
    config: &Config,
    apps: Arc<AppStore>,
    shutdown: CancellationToken,
) -> Result<()> {
    let listen = &config.edge.listen;

    let state = Arc::new(EdgeState {
        router: routes::router(),
        apps,
        upstreams: proxy::Upstreams::new(),
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
    let acceptor = tls::acceptor(&config.edge.tls)?;

    info!(addr = %listen.http, "listening for http, redirecting to https");
    info!(addr = %listen.https, "listening for https");

    // Every connection task holds a clone of `alive`. Once the accept loops
    // are done and this end is dropped, the receiver resolves as soon as the
    // last connection lets go of its clone.
    let (alive, mut drained) = mpsc::channel::<()>(1);

    tokio::join!(
        accept_loop(http, None, state.clone(), shutdown.clone(), alive.clone()),
        accept_loop(
            https,
            Some(acceptor),
            state,
            shutdown.clone(),
            alive.clone()
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
) {
    let scheme = if acceptor.is_some() {
        Scheme::Https
    } else {
        Scheme::Http
    };

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

        // Latency over throughput: this is a proxy, responses are small and
        // waiting to coalesce them only adds delay.
        if let Err(error) = stream.set_nodelay(true) {
            debug!(%peer, %error, "could not set TCP_NODELAY");
        }

        let conn = ConnInfo { peer, scheme };
        let service = TowerToHyperService::new(EdgeService::new(state.clone(), conn));
        let acceptor = acceptor.clone();
        let shutdown = shutdown.clone();
        let alive = alive.clone();

        tokio::spawn(async move {
            let _alive = alive;
            match acceptor {
                // The handshake happens here, inside the connection's own
                // task, rather than in the accept loop.
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(stream) => serve_connection(stream, service, shutdown).await,
                    Err(error) => debug!(%peer, %error, "tls handshake failed"),
                },
                None => serve_connection(stream, service, shutdown).await,
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
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let builder = Builder::new(TokioExecutor::new());
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

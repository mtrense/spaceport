//! The routes spaceport answers itself, on every host.
//!
//! An ordinary [`axum::Router`], reached only for paths under the prefixes
//! claimed in [`super::service`] — which is what makes `/.spaceport/*`
//! spaceport's reserved path space on every host it serves, gated apps
//! included. The ACME `HTTP-01` responder, the exchange callback that sets an
//! app's session cookie, and the health check all hang off here.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use super::gate;
use crate::acme::Challenges;
use crate::app::AppStore;
use crate::auth::SessionRepository;

/// What the every-host routes are served out of. One struct, in the shape of
/// [`super::home::Home`] and for its reason: everything here lives for the
/// process, and the alternative is threading each `Arc` through `edge::serve`
/// separately.
#[derive(Clone)]
pub struct SpaceportRoutes {
    /// What the ACME responder answers a CA out of.
    pub challenges: Arc<Challenges>,
    /// How the exchange callback finds which app serves the host it arrived
    /// at — the binding that makes a nonce good for one domain only.
    pub apps: Arc<AppStore>,
    /// The sessions the callback redeems nonces against and mints app
    /// sessions into: the same repository the login page writes, because the
    /// nonce's parent has to be a row that page created.
    pub sessions: Arc<SessionRepository>,
    /// Spaceport's own hostname, for restarting a failed exchange. Absent when
    /// the config named none — in which case no exchange ever started, and a
    /// callback reached anyway says so instead of building a URL from nothing.
    pub hostname: Option<String>,
    /// Named in restart URLs when it is not 443, exactly as the plaintext
    /// redirect names it.
    pub https_port: u16,
}

pub fn router(state: SpaceportRoutes) -> Router {
    Router::new()
        .route("/.spaceport/health", get(health))
        .route("/.spaceport/callback", get(gate::callback))
        .route("/.well-known/acme-challenge/{token}", get(acme_challenge))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok\n"
}

/// Prove to a CA that spaceport controls this host.
///
/// The CA asks for a token it handed out moments ago, over plaintext, at a
/// path RFC 8555 pins. Spaceport answers only tokens it is expecting: a token
/// nobody is waiting on is a `404`, the same as any other path — there is no
/// question to answer, and inventing one would be answering a stranger.
async fn acme_challenge(
    State(state): State<SpaceportRoutes>,
    Path(token): Path<String>,
) -> Response {
    match state.challenges.answer(&token) {
        // RFC 8555 §8.3: the response body is the key authorization and
        // nothing else, served as `application/octet-stream`.
        Some(answer) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            answer,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// The status and body of a `GET` for `path`.
    async fn get_path(challenges: Arc<Challenges>, path: &str) -> (StatusCode, String) {
        let state = SpaceportRoutes {
            challenges,
            apps: Arc::new(AppStore::new()),
            sessions: Arc::new(SessionRepository::new(
                crate::state::Db::in_memory().unwrap(),
            )),
            hostname: None,
            https_port: 443,
        };
        let response = router(state)
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();

        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    fn challenges() -> Arc<Challenges> {
        Arc::new(Challenges::new())
    }

    #[tokio::test]
    async fn serves_health() {
        let (status, _) = get_path(challenges(), "/.spaceport/health").await;

        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_spaceport_paths_are_not_found() {
        let (status, _) = get_path(challenges(), "/.spaceport/nope").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn answers_a_challenge_it_is_expecting() {
        let challenges = challenges();
        let _pending = challenges.expect("tok3n".to_owned(), "tok3n.thumbprint".to_owned());

        let (status, body) = get_path(challenges, "/.well-known/acme-challenge/tok3n").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "tok3n.thumbprint");
    }

    /// Anyone can ask. Only a CA that has just handed out a token gets an
    /// answer, and only for that token.
    #[tokio::test]
    async fn a_token_nobody_is_waiting_on_is_not_found() {
        let challenges = challenges();
        let _pending = challenges.expect("tok3n".to_owned(), "answer".to_owned());

        let (status, _) = get_path(challenges, "/.well-known/acme-challenge/guessed").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn answers_no_challenges_when_no_order_is_in_flight() {
        let (status, _) = get_path(challenges(), "/.well-known/acme-challenge/tok3n").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

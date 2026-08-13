//! The routes spaceport answers itself.
//!
//! An ordinary [`axum::Router`], reached only for paths under the prefixes
//! claimed in [`super::service`]. The ACME `HTTP-01` responder, auth provider
//! callbacks and the admin API all hang off here.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::acme::Challenges;

pub fn router(challenges: Arc<Challenges>) -> Router {
    Router::new()
        .route("/.spaceport/health", get(health))
        .route("/.well-known/acme-challenge/{token}", get(acme_challenge))
        .with_state(challenges)
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
    State(challenges): State<Arc<Challenges>>,
    Path(token): Path<String>,
) -> Response {
    match challenges.answer(&token) {
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
        let response = router(challenges)
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

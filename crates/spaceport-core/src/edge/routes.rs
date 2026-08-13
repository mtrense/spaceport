//! The routes spaceport answers itself.
//!
//! An ordinary [`axum::Router`], reached only for paths under the prefixes
//! claimed in [`super::service`]. The ACME `HTTP-01` responder, auth provider
//! callbacks and the admin API all hang off here.

use axum::Router;
use axum::routing::get;

pub fn router() -> Router {
    Router::new().route("/.spaceport/health", get(health))
}

async fn health() -> &'static str {
    "ok\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn serves_health() {
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/.spaceport/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_spaceport_paths_are_not_found() {
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/.spaceport/nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

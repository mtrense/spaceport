//! The app spaceport serves on its own hostname.
//!
//! Distinct from [`super::routes`], which spaceport answers on *every* host
//! because it has to: an ACME challenge is asked for at the name being
//! certified, whichever app that name belongs to. Nothing here is like that.
//! These are pages and endpoints that are spaceport's own, and they are reached
//! at the one address that is spaceport's own — which is what lets them own
//! their paths, instead of living under a prefix chosen to stay out of the way
//! of every app that will ever be applied.
//!
//! An outside service integrating with spaceport — a forge posting a webhook,
//! an identity provider returning from a login — is given a URL under this
//! host, and hangs off this router.

use axum::Router;
use axum::routing::get;

pub fn router() -> Router {
    Router::new().route("/", get(index))
}

/// Enough to tell an operator that the address resolves here, that TLS
/// terminated, and which build answered — the three things that are in doubt
/// the first time a new hostname is pointed at a host.
async fn index() -> String {
    format!("spaceport {}\n", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn get_path(path: &str) -> (StatusCode, String) {
        let response = router()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();

        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn says_which_spaceport_answered() {
        let (status, body) = get_path("/").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with("spaceport "), "{body}");
    }

    /// The host is spaceport's, but only the paths it serves are: a path
    /// nothing is mounted at is a 404, not a page.
    #[tokio::test]
    async fn serves_nothing_it_has_no_route_for() {
        let (status, _) = get_path("/nope").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

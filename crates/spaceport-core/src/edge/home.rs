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
//!
//! The first of those is GitHub's App Manifest flow, and it is the reason this
//! router now has state at all: two pages, one holding the form a browser posts
//! to github.com and one catching the redirect back. Both answer in HTML rather
//! than in the plain text the operator interface uses, because what is looking
//! at them is a browser with an operator behind it — an error here has to be a
//! sentence on a page, not a status code somebody has to go and look up.
//!
//! Every page is written inline, with no stylesheet, no script that matters and
//! nothing fetched from anywhere. A spaceport whose own pages depend on an asset
//! is a spaceport that renders a broken page on exactly the host that is being
//! set up for the first time.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use serde::Deserialize;
use time::OffsetDateTime;
use tracing::warn;

use crate::connections::github::manifest::{self, Attempts, Manifest};
use crate::connections::github::{
    ConnectionRepository, Nudge, TrackingRepository, Transport, register, webhook,
};

/// What the pages on spaceport's own host are served out of.
///
/// One struct rather than an extractor apiece, because everything in here is
/// held for the life of the process and the alternative is threading every one
/// of the `Arc`s through `edge::serve` separately.
pub struct Home {
    /// The registrations an operator has started and not yet finished.
    pub attempts: Arc<Attempts>,
    pub connections: Arc<ConnectionRepository>,
    /// What each app is built from, over the same database as `connections`.
    /// Held here because a push arrives at this router and nowhere else, and
    /// the handler that decides what one means has to be able to ask.
    pub tracking: Arc<TrackingRepository>,
    /// How the callback reaches GitHub to exchange the code it was handed.
    pub github: Arc<dyn Transport>,
    /// How both handlers here tell the reconciler that what it has cached is
    /// no longer what GitHub would say — a delivery about an installation, or
    /// an App this spaceport has just been handed.
    pub nudge: Nudge,
    /// The host these pages are being served on, which is also the host every
    /// url in the manifest is built from. Absent when the config named none —
    /// in which case nothing should ever have issued an attempt, and a page
    /// that was reached anyway says so rather than building a url from a
    /// hostname it does not have.
    pub hostname: Option<String>,
}

pub fn router(home: Arc<Home>) -> Router {
    Router::new()
        .route("/", get(index))
        .route(&format!("{}/{{state}}", manifest::SETUP_PATH), get(setup))
        .route(
            &format!("{}/{{state}}/callback", manifest::SETUP_PATH),
            get(callback),
        )
        .route(manifest::WEBHOOK_PATH, post(deliver))
        .with_state(home)
}

/// Enough to tell an operator that the address resolves here, that TLS
/// terminated, and which build answered — the three things that are in doubt
/// the first time a new hostname is pointed at a host.
async fn index() -> String {
    format!("spaceport {}\n", env!("CARGO_PKG_VERSION"))
}

/// `GET /connections/github/setup/{state}`: the form that creates the App.
///
/// A form and not a redirect: GitHub takes the manifest as a `POST` body from a
/// logged-in browser, and there is no url that carries one. The button is real
/// and visible, and the script below it only presses it — an operator whose
/// browser runs no scripts gets the same flow one click slower, and one that
/// silently did nothing would be the worst of both.
///
/// The attempt is read and not consumed. A page is fetched more than once —
/// reloads, a browser that prefetches, a back button — and every one of those
/// has to render the form.
async fn setup(State(home): State<Arc<Home>>, Path(state): Path<String>) -> Response {
    let Some(hostname) = home.hostname.clone() else {
        return problem(
            StatusCode::NOT_FOUND,
            "This spaceport has no hostname",
            "Set `edge.hostname` in its config, restart it, and run `spaceport connect github --auto` again.",
        );
    };

    let Some(attempt) = home.attempts.peek(&state, OffsetDateTime::now_utc()) else {
        return expired();
    };

    let manifest = match Manifest::new(&hostname, &attempt.name, &state).to_json() {
        Ok(manifest) => manifest,
        Err(error) => {
            warn!(%error, "could not write the github app manifest");

            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Spaceport could not describe the app",
                "Nothing was created on GitHub. Run `spaceport connect github --auto` again.",
            );
        }
    };

    let owner = match &attempt.org {
        Some(org) => format!("the <code>{}</code> organisation", escape(org)),
        None => "your own GitHub account".to_owned(),
    };

    page(
        StatusCode::OK,
        "Create a GitHub App",
        &format!(
            r#"<h1>Create a GitHub App</h1>
<p>GitHub will create an app called <strong>{name}</strong> on {owner}, and hand
this spaceport its credentials. Nothing is recorded until it does.</p>
<form id="manifest" method="post" action="{action}">
  <input type="hidden" name="manifest" value="{manifest}">
  <button type="submit">Create it on GitHub</button>
</form>
<p class="quiet">If nothing happens, press the button.</p>
<script>document.getElementById("manifest").submit();</script>"#,
            name = escape(&attempt.name),
            action = escape(&manifest::new_app_url(attempt.org.as_deref(), &state)),
            manifest = escape(&manifest),
        ),
    )
}

/// `GET /connections/github/setup/{state}/callback?code=…`: GitHub has created
/// the App.
///
/// This is where the attempt is spent. The code is exchanged for the App's
/// credentials, and those are recorded exactly as a hand-registered app is —
/// through [`register::connect`], which asks GitHub to confirm them first. That
/// round trip is redundant here, since GitHub has just said what they are, and
/// it is kept anyway: it is the one check that the key which arrived can
/// actually sign, and this is the last moment anybody is watching.
async fn callback(
    State(home): State<Arc<Home>>,
    Path(state): Path<String>,
    Query(query): Query<Callback>,
) -> Response {
    let Some(code) = query.code.filter(|code| !code.is_empty()) else {
        return problem(
            StatusCode::BAD_REQUEST,
            "GitHub sent no code",
            "Only GitHub can complete a registration, and it did not. Run `spaceport connect github --auto` again and open the new link.",
        );
    };

    let Some(_attempt) = home.attempts.take(&state, OffsetDateTime::now_utc()) else {
        return expired();
    };

    let registration = match manifest::convert(home.github.as_ref(), &code).await {
        Ok(registration) => registration,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "a github app manifest conversion failed");

            return problem(
                StatusCode::BAD_GATEWAY,
                "GitHub would not hand over the app",
                &format!("{error:#}"),
            );
        }
    };

    let connection = match register::connect(
        &home.connections,
        home.github.clone(),
        registration,
        &home.nudge,
    )
    .await
    {
        Ok(connection) => connection,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "recording a github app spaceport created failed");

            return problem(
                StatusCode::BAD_GATEWAY,
                "The app exists on GitHub and this spaceport could not record it",
                &format!(
                    "{error:#} — the app was created, so delete it on GitHub before trying again."
                ),
            );
        }
    };

    let install = format!(
        "https://github.com/apps/{}/installations/new",
        connection.slug
    );

    page(
        StatusCode::OK,
        "The app is connected",
        &format!(
            r#"<h1>{name} is connected</h1>
<p>GitHub created app <code>{app_id}</code> as <code>{slug}</code>, owned by
<code>{owner}</code>, and this spaceport has recorded its credentials.</p>
<p>It can see nothing until it is installed somewhere.</p>
<p><a href="{install}">Install it on an account</a></p>"#,
            name = escape(&connection.name),
            app_id = connection.app_id,
            slug = escape(&connection.slug),
            owner = escape(&connection.owner),
            install = escape(&install),
        ),
    )
}

/// `POST /connections/github/webhooks`: GitHub has something to say.
///
/// The body arrives as [`Bytes`] and not through axum's `Json` extractor, and
/// that is the whole reason this handler is three lines rather than one. The
/// signature is an HMAC over the exact bytes GitHub sent, so any extractor that
/// parses and re-serialises them — reordering a key, dropping a space, changing
/// how a number is spelled — hands the verifier a body that never existed and
/// turns every genuine delivery into a refused one. The parsing that does
/// happen happens after the signature has been checked.
///
/// The answer is a status and no body: what is reading it is GitHub's delivery
/// machinery, which records the status and nothing else.
async fn deliver(State(home): State<Arc<Home>>, headers: HeaderMap, body: Bytes) -> Response {
    match webhook::receive(
        &home.connections,
        &home.tracking,
        &home.nudge,
        &headers,
        &body,
    )
    .await
    {
        Ok(outcome) => outcome.status().into_response(),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "a github webhook delivery could not be handled");

            // A 500 rather than a refusal, because this is spaceport's fault
            // and a retry is exactly what should happen.
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct Callback {
    /// GitHub's one-time code. Optional because a browser can arrive here with
    /// anything in the query string, and a missing code is a sentence rather
    /// than a rejected request nobody can read.
    code: Option<String>,
}

/// What a state nobody is waiting on is told.
///
/// The same page whether the state expired, was already spent, or was never
/// issued at all: telling those apart would be telling whoever asked which
/// states this spaceport has issued, and the answer an operator needs is the
/// same in all three cases.
fn expired() -> Response {
    problem(
        StatusCode::NOT_FOUND,
        "This link has expired",
        "It was never issued by this spaceport, or it has already been used, or it is more than half an hour old. Run `spaceport connect github --auto` again and open the new link.",
    )
}

/// A page that says what went wrong, since a browser is what is reading it.
///
/// Both halves are escaped here rather than at the call sites: a detail is
/// sometimes an error message, an error message sometimes quotes something that
/// came off a url, and a helper that escaped only what it was told to would be
/// one call site away from a page that did not.
fn problem(status: StatusCode, title: &str, detail: &str) -> Response {
    page(
        status,
        title,
        &format!("<h1>{}</h1>\n<p>{}</p>", escape(title), escape(detail)),
    )
}

/// One whole HTML document. `body` is trusted; everything interpolated into it
/// has already been through [`escape`].
fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let document = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — spaceport</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 4rem auto; max-width: 34rem; line-height: 1.5; }}
button {{ font: inherit; padding: 0.5rem 1rem; }}
.quiet {{ color: #666; font-size: 0.9rem; }}
</style>
</head>
<body>
{body}
</body>
</html>
"#,
        title = escape(title),
    );

    (status, Html(document)).into_response()
}

/// `value`, safe to put anywhere in a document or an attribute.
///
/// Every one of these five matters somewhere: the angle brackets end an
/// element, the quotes end an attribute, and the ampersand is what would let an
/// entity be smuggled through the other four. The manifest is JSON full of
/// quotes and goes in an attribute; the state comes off a url and is under
/// nobody's control at all.
fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }

    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::Secret;
    use crate::connections::github::Connection;
    use crate::connections::github::api::testing::FakeGitHub;
    use crate::state::Db;
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use ring::hmac;
    use tower::ServiceExt;

    const HOSTNAME: &str = "spaceport.example.com";

    /// A home as the daemon assembles one, with a GitHub that will convert a
    /// manifest into the fixture app.
    fn home() -> (Arc<Home>, Arc<FakeGitHub>) {
        let github = FakeGitHub::new();
        github.converts_manifests_into(42, "spaceport-for-acme", "Spaceport for Acme");

        let db = Db::in_memory().unwrap();
        let home = Arc::new(Home {
            attempts: Arc::new(Attempts::new()),
            connections: Arc::new(ConnectionRepository::new(db.clone())),
            tracking: Arc::new(TrackingRepository::new(db)),
            github: github.clone(),
            nudge: Nudge::new(),
            hostname: Some(HOSTNAME.to_owned()),
        });

        (home, github)
    }

    /// A home for the tests that only fetch a page, with a fake nothing asks
    /// anything of.
    fn plain_home() -> Arc<Home> {
        home().0
    }

    async fn get_path(home: Arc<Home>, path: &str) -> (StatusCode, String) {
        let response = router(home)
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();

        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    /// An attempt as the operator interface would have begun one.
    fn begin(home: &Home, org: Option<&str>) -> String {
        home.attempts
            .begin(
                org.map(ToOwned::to_owned),
                "Spaceport for Acme".to_owned(),
                OffsetDateTime::now_utc(),
            )
            .unwrap()
    }

    #[tokio::test]
    async fn says_which_spaceport_answered() {
        let (status, body) = get_path(plain_home(), "/").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with("spaceport "), "{body}");
    }

    /// The host is spaceport's, but only the paths it serves are: a path
    /// nothing is mounted at is a 404, not a page.
    #[tokio::test]
    async fn serves_nothing_it_has_no_route_for() {
        let (status, _) = get_path(plain_home(), "/nope").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_setup_page_posts_the_manifest_to_the_organisations_page() {
        let home = plain_home();
        let state = begin(&home, Some("an-organisation"));

        let (status, body) = get_path(home, &format!("/connections/github/setup/{state}")).await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains(&format!(
                r#"action="https://github.com/organizations/an-organisation/settings/apps/new?state={state}""#
            )),
            "{body}"
        );
        // A real button, so a browser running no scripts still works.
        assert!(body.contains("<button type=\"submit\">"), "{body}");
    }

    /// Without an organisation the app belongs to whoever is logged in, and
    /// that is a different page on github.com.
    #[tokio::test]
    async fn the_setup_page_posts_to_the_personal_account_page_without_an_organisation() {
        let home = plain_home();
        let state = begin(&home, None);

        let (_, body) = get_path(home, &format!("/connections/github/setup/{state}")).await;

        assert!(
            body.contains(&format!(
                r#"action="https://github.com/settings/apps/new?state={state}""#
            )),
            "{body}"
        );
    }

    /// The manifest is the whole of what GitHub is being asked for, and it
    /// travels in this one field.
    #[tokio::test]
    async fn the_setup_page_carries_the_manifest_in_a_hidden_field() {
        let home = plain_home();
        let state = begin(&home, Some("an-organisation"));

        let (_, body) = get_path(home, &format!("/connections/github/setup/{state}")).await;

        assert!(
            body.contains(r#"<input type="hidden" name="manifest""#),
            "{body}"
        );
        // Escaped into the attribute, which is what makes it a value rather
        // than the end of the tag.
        assert!(body.contains("&quot;default_permissions&quot;"), "{body}");
        assert!(
            body.contains(&format!(
                "https://{HOSTNAME}/connections/github/setup/{state}/callback"
            )),
            "{body}"
        );
    }

    #[tokio::test]
    async fn a_state_this_spaceport_never_issued_is_not_found() {
        let (status, body) = get_path(
            plain_home(),
            "/connections/github/setup/not-a-state-anybody-issued",
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("expired"), "{body}");
        assert!(body.contains("--auto"), "{body}");
    }

    #[tokio::test]
    async fn the_callback_records_the_app_and_says_where_to_install_it() {
        let (home, _) = home();
        let state = begin(&home, Some("an-organisation"));
        let changed = home.nudge.changed();

        let (status, body) = get_path(
            home.clone(),
            &format!("/connections/github/setup/{state}/callback?code=a-one-time-code"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Spaceport for Acme"), "{body}");
        assert!(
            body.contains("https://github.com/apps/spaceport-for-acme/installations/new"),
            "{body}"
        );
        let recorded = home
            .connections
            .by_slug("spaceport-for-acme")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recorded.app_id, 42);
        // And the reconciler has been told, which is what makes the app an
        // operator has just installed show up in seconds.
        assert!(changed.has_changed().unwrap());
    }

    /// Only GitHub completes a registration, and it always sends a code.
    #[tokio::test]
    async fn a_callback_without_a_code_is_refused() {
        let (home, _) = home();
        let state = begin(&home, None);

        let (status, body) = get_path(
            home.clone(),
            &format!("/connections/github/setup/{state}/callback"),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("no code"), "{body}");
        // And the attempt is still there, because nothing has been answered.
        assert!(
            home.attempts
                .peek(&state, OffsetDateTime::now_utc())
                .is_some()
        );
    }

    /// A callback that arrives twice — a reload, a prefetch, a link somebody
    /// kept — must create one app and not two.
    #[tokio::test]
    async fn a_state_cannot_be_answered_twice() {
        let (home, _) = home();
        let state = begin(&home, None);
        let path = format!("/connections/github/setup/{state}/callback?code=a-one-time-code");

        let (first, _) = get_path(home.clone(), &path).await;
        let (second, body) = get_path(home, &path).await;

        assert_eq!(first, StatusCode::OK);
        assert_eq!(second, StatusCode::NOT_FOUND);
        assert!(body.contains("already been used"), "{body}");
    }

    /// The state comes off a url and is under nobody's control, so a page that
    /// puts one anywhere near a tag has to escape it — and the page for a state
    /// nobody is waiting on does not echo it at all, which is the stronger
    /// version of the same rule.
    #[tokio::test]
    async fn a_state_off_the_url_never_reaches_the_page_as_markup() {
        let hostile = "%22%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E";

        let (status, body) = get_path(
            plain_home(),
            &format!("/connections/github/setup/{hostile}"),
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!body.contains("<script>alert"), "{body}");
        assert!(!body.contains("alert(1)"), "{body}");
    }

    /// The escaping itself, since the pages above only ever hand it values a
    /// test cannot make hostile.
    #[test]
    fn escapes_a_state_that_would_close_the_attribute_it_lands_in() {
        let hostile = r#""><script>alert(1)</script>"#;

        let escaped = escape(&manifest::new_app_url(None, hostile));

        assert!(!escaped.contains("<script>"), "{escaped}");
        assert!(escaped.contains("&lt;script&gt;"), "{escaped}");
        assert!(escaped.contains("&quot;&gt;"), "{escaped}");
    }

    /// A connection as an operator would have registered one, with a webhook
    /// secret the tests can sign with.
    async fn connect(home: &Home, slug: &str, app_id: i64, webhook_secret: &str) {
        home.connections
            .record(&Connection {
                slug: slug.to_owned(),
                app_id,
                name: "Spaceport for Acme".to_owned(),
                owner: "an-organisation".to_owned(),
                client_id: "Iv1.0123456789abcdef".to_owned(),
                client_secret: Secret::new("a-client-secret"),
                webhook_secret: Secret::new(webhook_secret),
                private_key: Secret::new("-----BEGIN RSA PRIVATE KEY-----"),
                connected_at: String::new(),
            })
            .await
            .unwrap();
    }

    /// The signature GitHub would have sent, computed rather than pasted.
    fn signed(secret: &str, body: &str) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let tag = hmac::sign(&key, body.as_bytes());
        let hex: String = tag.as_ref().iter().map(|byte| format!("{byte:02x}")).fold(
            String::new(),
            |mut all, digits| {
                all.push_str(&digits);
                all
            },
        );

        format!("sha256={hex}")
    }

    /// One delivery, posted at the real route through the real router.
    async fn deliver_headers(
        home: Arc<Home>,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (StatusCode, String) {
        let mut request = Request::builder()
            .method("POST")
            .uri("/connections/github/webhooks");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }

        let response = router(home)
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();

        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    /// A delivery of `event` for `app_id`, signed with `secret`.
    async fn deliver(
        home: Arc<Home>,
        app_id: i64,
        secret: &str,
        event: &str,
        delivery_id: &str,
        body: &str,
    ) -> StatusCode {
        deliver_headers(
            home,
            &[
                ("x-github-event", event),
                ("x-github-delivery", delivery_id),
                ("x-github-hook-installation-target-type", "integration"),
                ("x-github-hook-installation-target-id", &app_id.to_string()),
                ("x-hub-signature-256", &signed(secret, body)),
            ],
            body,
        )
        .await
        .0
    }

    const PUSH: &str =
        r#"{"repository":{"full_name":"an-organisation/site"},"installation":{"id":7}}"#;

    /// Accepted and not merely `200`: nothing acts on a delivery yet, which is
    /// what `202` says.
    #[tokio::test]
    async fn a_properly_signed_delivery_is_accepted() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;

        let status = deliver(home, 42, "a-webhook-secret", "push", "delivery-1", PUSH).await;

        assert_eq!(status, StatusCode::ACCEPTED);
    }

    /// GitHub retries what it did not get a 2xx for, so the same delivery id
    /// arrives more than once and must be observed exactly once.
    #[tokio::test]
    async fn the_same_delivery_twice_is_recorded_once() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;

        let first = deliver(
            home.clone(),
            42,
            "a-webhook-secret",
            "push",
            "delivery-1",
            PUSH,
        )
        .await;
        let second = deliver(
            home.clone(),
            42,
            "a-webhook-secret",
            "push",
            "delivery-1",
            PUSH,
        )
        .await;

        assert_eq!(first, StatusCode::ACCEPTED);
        assert_eq!(second, StatusCode::OK);
        // And the row is still the first one's, rather than having been written
        // twice — asking again says it is known.
        assert!(
            !home
                .connections
                .record_delivery("delivery-1", 42, "push")
                .await
                .unwrap()
        );
    }

    /// The signature is the only thing that says a delivery is GitHub's, so a
    /// delivery without one is a stranger's.
    #[tokio::test]
    async fn an_unsigned_delivery_is_refused() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;

        let (status, _) = deliver_headers(
            home,
            &[
                ("x-github-event", "push"),
                ("x-github-delivery", "delivery-1"),
                ("x-github-hook-installation-target-type", "integration"),
                ("x-github-hook-installation-target-id", "42"),
            ],
            PUSH,
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_delivery_signed_with_the_wrong_secret_is_refused() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;

        let status = deliver(
            home,
            42,
            "another-webhook-secret",
            "push",
            "delivery-1",
            PUSH,
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// A hook for an App this spaceport does not hold ought to be disabled
    /// rather than retried forever, and `404` is what tells GitHub so.
    #[tokio::test]
    async fn a_delivery_for_an_app_nothing_connects_to_is_not_found() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;

        let status = deliver(home, 99, "a-webhook-secret", "push", "delivery-1", PUSH).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// An App's own hook is the only hook spaceport registers; a repository
    /// hook somebody pointed at this url is not one of its deliveries.
    #[tokio::test]
    async fn a_delivery_from_a_hook_that_is_not_an_apps_own_is_not_found() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;

        let (status, _) = deliver_headers(
            home,
            &[
                ("x-github-event", "push"),
                ("x-github-delivery", "delivery-1"),
                ("x-github-hook-installation-target-type", "repository"),
                ("x-github-hook-installation-target-id", "42"),
                ("x-hub-signature-256", &signed("a-webhook-secret", PUSH)),
            ],
            PUSH,
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// Without an id there is nothing to deduplicate on, and a retry could not
    /// be told from a new delivery.
    #[tokio::test]
    async fn a_delivery_without_an_id_is_refused() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;

        let (status, _) = deliver_headers(
            home,
            &[
                ("x-github-event", "push"),
                ("x-github-hook-installation-target-type", "integration"),
                ("x-github-hook-installation-target-id", "42"),
                ("x-hub-signature-256", &signed("a-webhook-secret", PUSH)),
            ],
            PUSH,
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// GitHub sends a `ping` the moment a hook is created, and it is the first
    /// delivery any App ever makes — handled like every other event, with no
    /// case of its own.
    #[tokio::test]
    async fn a_ping_is_accepted_like_anything_else() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;

        let status = deliver(
            home,
            42,
            "a-webhook-secret",
            "ping",
            "delivery-ping",
            r#"{"zen":"Design for failure."}"#,
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
    }

    /// The signature says the delivery is genuine; whether spaceport can read
    /// the body is a separate question and not one GitHub can fix.
    #[tokio::test]
    async fn a_signed_delivery_whose_body_is_not_json_is_still_accepted() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;

        let status = deliver(
            home,
            42,
            "a-webhook-secret",
            "push",
            "delivery-1",
            "not json at all",
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
    }

    /// The multi-app invariant, and the one that matters most: a spaceport
    /// holding several connections verifies each delivery against the secret of
    /// the App that header names, and against no other. A spaceport that tried
    /// every secret in turn would pass every assertion but the last two.
    #[tokio::test]
    async fn two_connections_verify_their_own_deliveries_and_nobody_elses() {
        let home = plain_home();
        connect(&home, "alpha", 1, "alphas-secret").await;
        connect(&home, "beta", 2, "betas-secret").await;

        assert_eq!(
            deliver(home.clone(), 1, "alphas-secret", "push", "alpha-1", PUSH).await,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            deliver(home.clone(), 2, "betas-secret", "push", "beta-1", PUSH).await,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            deliver(home.clone(), 1, "betas-secret", "push", "alpha-2", PUSH).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            deliver(home, 2, "alphas-secret", "push", "beta-2", PUSH).await,
            StatusCode::UNAUTHORIZED
        );
    }

    const INSTALLATION: &str = r#"{"action":"created","installation":{"id":7}}"#;

    /// The event the whole fast path exists for: an App installed on an
    /// account, which is precisely what the cache is a copy of.
    #[tokio::test]
    async fn a_verified_installation_delivery_nudges_the_reconciler() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;
        let changed = home.nudge.changed();

        let status = deliver(
            home.clone(),
            42,
            "a-webhook-secret",
            "installation",
            "delivery-1",
            INSTALLATION,
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(changed.has_changed().unwrap());
    }

    /// A repository added to or removed from an installation changes what the
    /// App can see without changing where it is installed, and the cache holds
    /// both halves.
    #[tokio::test]
    async fn a_verified_installation_repositories_delivery_nudges_the_reconciler() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;
        let changed = home.nudge.changed();

        let status = deliver(
            home.clone(),
            42,
            "a-webhook-secret",
            "installation_repositories",
            "delivery-1",
            r#"{"action":"added","installation":{"id":7}}"#,
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(changed.has_changed().unwrap());
    }

    /// A commit says nothing about where the App is installed, and a busy
    /// organisation pushes all day — a pass apiece would be a GitHub round trip
    /// per connection per commit, asking a question whose answer has not moved.
    #[tokio::test]
    async fn a_verified_push_delivery_nudges_nothing() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;
        let changed = home.nudge.changed();

        let status = deliver(
            home.clone(),
            42,
            "a-webhook-secret",
            "push",
            "delivery-1",
            PUSH,
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(!changed.has_changed().unwrap());
    }

    /// The amplification guard, and the reason the nudge happens after
    /// verification rather than before it: this endpoint is open to whoever can
    /// find the hostname, and a delivery that proves nothing must never be able
    /// to make spaceport call GitHub.
    #[tokio::test]
    async fn a_delivery_that_did_not_verify_nudges_nothing() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;
        let changed = home.nudge.changed();

        let (unsigned, _) = deliver_headers(
            home.clone(),
            &[
                ("x-github-event", "installation"),
                ("x-github-delivery", "delivery-1"),
                ("x-github-hook-installation-target-type", "integration"),
                ("x-github-hook-installation-target-id", "42"),
            ],
            INSTALLATION,
        )
        .await;
        let wrongly_signed = deliver(
            home.clone(),
            42,
            "another-webhook-secret",
            "installation",
            "delivery-2",
            INSTALLATION,
        )
        .await;

        assert_eq!(unsigned, StatusCode::UNAUTHORIZED);
        assert_eq!(wrongly_signed, StatusCode::UNAUTHORIZED);
        assert!(!changed.has_changed().unwrap());
    }

    /// GitHub retries, and an operator redelivers by hand. The first delivery
    /// already started the pass that read the whole truth, so the copy is not
    /// news and must not cost a second one.
    #[tokio::test]
    async fn a_redelivery_nudges_nothing() {
        let home = plain_home();
        connect(&home, "spaceport-for-acme", 42, "a-webhook-secret").await;

        let first = deliver(
            home.clone(),
            42,
            "a-webhook-secret",
            "installation",
            "delivery-1",
            INSTALLATION,
        )
        .await;
        // Everything the first delivery said is now seen, so what the second
        // one adds is all that is being measured.
        let changed = home.nudge.changed();
        let second = deliver(
            home.clone(),
            42,
            "a-webhook-secret",
            "installation",
            "delivery-1",
            INSTALLATION,
        )
        .await;

        assert_eq!(first, StatusCode::ACCEPTED);
        assert_eq!(second, StatusCode::OK);
        assert!(!changed.has_changed().unwrap());
    }

    #[test]
    fn escapes_every_character_that_could_end_a_tag_or_an_attribute() {
        assert_eq!(
            escape(r#"<a href="x">&'"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
        assert_eq!(escape("nothing to do"), "nothing to do");
    }
}

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
use http::{HeaderMap, HeaderValue, StatusCode};
use serde::Deserialize;
use time::OffsetDateTime;
use tracing::warn;

use crate::auth::{RedeemError, SessionRepository};
use crate::connections::github::manifest::{self, Attempts, Manifest};
use crate::connections::github::{
    ConnectionRepository, Nudge, TrackingRepository, Transport, register, webhook,
};
use crate::secret::Secret;

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
    /// How a push that moved a tracked branch tells the build worker to go and
    /// look. A second instance of the same type as `nudge` and never the same
    /// one: waking the reconciler costs a GitHub round trip per connection, and
    /// waking the builder costs a read of this host's own database — see
    /// [`webhook::receive`].
    pub builds: Nudge,
    /// The host these pages are being served on, which is also the host every
    /// url in the manifest is built from. Absent when the config named none —
    /// in which case nothing should ever have issued an attempt, and a page
    /// that was reached anyway says so rather than building a url from a
    /// hostname it does not have.
    pub hostname: Option<String>,
    /// The sessions and one-time codes the login page reads and writes. Held
    /// here because `/login` and `/logout` live on this host and nowhere else:
    /// the cookie they manage is scoped to spaceport's own name, which is what
    /// keeps it out of every app's cookie jar.
    pub sessions: Arc<SessionRepository>,
}

/// The session cookie's name. The `__Host-` prefix is a promise the browser
/// enforces — `Secure`, `Path=/`, no `Domain` — so a cookie under this name
/// cannot be planted by a subdomain or ride to one. Spaceport can afford the
/// prefix unconditionally because the edge terminates TLS even in development
/// (`tls.provider: self-signed` is the floor, not an option to skip) and the
/// plaintext listener never serves this page — it answers everything but ACME
/// challenges with a redirect to https, so the login form is only ever
/// submitted over a connection the `Secure` attribute is satisfied by.
pub(crate) const SESSION_COOKIE: &str = "__Host-spaceport-session";

pub fn router(home: Arc<Home>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/login", get(login_page).post(login))
        .route("/logout", get(logout_page).post(logout))
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

/// `GET /login`: the form that turns a one-time code into a session.
///
/// A `?next=` names where to go after — carried through the form in a hidden
/// field, and only ever a path this host serves: [`safe_next`] is the gate,
/// applied on the way out rather than here, so a hostile value ends up as `/`
/// instead of an error page that teaches nothing.
async fn login_page(Query(query): Query<LoginQuery>) -> Response {
    login_form(StatusCode::OK, None, query.next.as_deref())
}

/// `POST /login`: redeem the code, set the cookie, go where `next` says.
///
/// Every refusal renders the same sentence, whatever went wrong underneath —
/// an unknown code, a spent one, an expired one, a suspended user. The
/// repository already collapses them into one error precisely so this handler
/// *cannot* tell them apart; anything more specific would be an oracle for
/// whoever is guessing codes.
async fn login(State(home): State<Arc<Home>>, body: String) -> Response {
    let next = form_value(&body, "next");
    let next = next.as_deref();
    let Some(code) = form_value(&body, "code").filter(|code| !code.is_empty()) else {
        return login_form(StatusCode::BAD_REQUEST, Some("Enter the code."), next);
    };

    match home.sessions.redeem(&Secret::new(code)).await {
        Ok(fresh) => {
            let mut response = Response::new(axum::body::Body::empty());
            // 303, so the redirect is fetched with GET whatever this was.
            *response.status_mut() = StatusCode::SEE_OTHER;
            response.headers_mut().insert(
                http::header::LOCATION,
                HeaderValue::from_str(safe_next(next)).expect("a vetted path is a header value"),
            );
            match HeaderValue::from_str(&session_cookie(&fresh)) {
                Ok(cookie) => {
                    response
                        .headers_mut()
                        .insert(http::header::SET_COOKIE, cookie);

                    response
                }
                // A token that will not fit in a header was never minted by
                // this build; refuse rather than redirect to a page that will
                // only bounce back here.
                Err(error) => {
                    warn!(%error, "could not render the session cookie");

                    problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Spaceport could not set the session cookie",
                        "The login itself worked; sign in again with a fresh code.",
                    )
                }
            }
        }
        Err(RedeemError::Refused) => login_form(
            StatusCode::UNAUTHORIZED,
            Some("That code did not work. Check it, or ask for a new one."),
            next,
        ),
        Err(RedeemError::Failed(error)) => {
            warn!(error = %format!("{error:#}"), "a login could not be answered");

            problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Spaceport could not check the code",
                "Nothing about the code was decided. Try again.",
            )
        }
    }
}

/// `GET /logout`: a confirm form, and deliberately not a logout.
///
/// A `GET` that dropped the session would let any page log a user out with an
/// `<img src>` — the small cousin of every CSRF. The form is the whole page:
/// the browser only ever sends the `POST` because somebody pressed the button.
async fn logout_page() -> Response {
    page(
        StatusCode::OK,
        "Sign out",
        r#"<h1>Sign out</h1>
<form method="post" action="/logout">
  <button type="submit">Sign out</button>
</form>"#,
    )
}

/// `POST /logout`: drop the session and clear the cookie.
///
/// The answer is the same page whether the cookie named a live session, a dead
/// one or nothing at all: the user asked to be signed out, and after this they
/// are. Derived app sessions are dropped inside
/// [`SessionRepository::logout`]'s transaction when that milestone lands — see
/// the hook there — so this handler will not change shape for it.
async fn logout(State(home): State<Arc<Home>>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_value(&headers, SESSION_COOKIE)
        && let Err(error) = home.sessions.logout(&Secret::new(token)).await
    {
        warn!(error = %format!("{error:#}"), "a logout could not be answered");

        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Spaceport could not sign the session out",
            "The session may still be live. Try again.",
        );
    }

    let mut response = page(
        StatusCode::OK,
        "Signed out",
        r#"<h1>Signed out</h1>
<p><a href="/login">Sign in again</a></p>"#,
    );
    // Max-Age=0 is the deletion; the attributes must match the ones the cookie
    // was set with, or the browser treats it as a different cookie and keeps
    // the original.
    response.headers_mut().insert(
        http::header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{SESSION_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax"
        ))
        .expect("a literal cookie is a header value"),
    );

    response
}

#[derive(Debug, Deserialize)]
struct LoginQuery {
    /// Where to land after the login, when the request that bounced here says.
    next: Option<String>,
}

/// The login form, with `error` above it when the last attempt failed and
/// `next` carried through a hidden field. The code input turns autocomplete
/// and its relatives off because a one-time code is the one value a browser
/// must not helpfully remember.
fn login_form(status: StatusCode, error: Option<&str>, next: Option<&str>) -> Response {
    let error = match error {
        Some(error) => format!("<p class=\"error\">{}</p>\n", escape(error)),
        None => String::new(),
    };
    let next = match safe_next(next) {
        "/" => String::new(),
        next => format!(
            "  <input type=\"hidden\" name=\"next\" value=\"{}\">\n",
            escape(next)
        ),
    };

    page(
        status,
        "Sign in",
        &format!(
            r#"<h1>Sign in</h1>
<p>Enter the one-time code you were given.</p>
{error}<form method="post" action="/login">
{next}  <input name="code" autofocus autocomplete="off" autocapitalize="off" spellcheck="false">
  <button type="submit">Sign in</button>
</form>"#
        ),
    )
}

/// Where a finished login may be sent: `next` when it is a plain absolute path
/// on this host, `/` otherwise.
///
/// The rules are deny-by-shape rather than a parse: it must start with `/`,
/// must not start with `//` (which a browser reads as scheme-relative and
/// sends to another host), and must not contain `\` (which some browsers
/// normalise into `/` and turn `/\evil.example` back into the previous case).
/// Anything with a scheme fails the leading-`/` test already. The fallback is
/// `/` and never an error, because the value arrives on urls users share and
/// a broken link should still land them somewhere signed in.
fn safe_next(next: Option<&str>) -> &str {
    match next {
        Some(next) if next.starts_with('/') && !next.starts_with("//") && !next.contains('\\') => {
            next
        }
        _ => "/",
    }
}

/// The `Set-Cookie` value a fresh session travels out as.
///
/// `HttpOnly` keeps scripts out of it, `SameSite=Lax` keeps cross-site `POST`s
/// from riding it, and `Secure` plus the [`SESSION_COOKIE`] `__Host-` prefix
/// pin it to this exact https host. `Max-Age` mirrors the row's expiry so the
/// browser forgets the token about when the database stops honouring it — the
/// database stays the authority either way, so a clock two machines disagree
/// on costs a re-login, never access.
fn session_cookie(fresh: &crate::auth::FreshSession) -> String {
    let max_age = time::OffsetDateTime::parse(
        &fresh.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map(|expires| {
        (expires - time::OffsetDateTime::now_utc())
            .whole_seconds()
            .max(0)
    });

    let mut cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Lax",
        fresh.token.expose()
    );
    if let Ok(max_age) = max_age {
        cookie.push_str(&format!("; Max-Age={max_age}"));
    }

    cookie
}

/// The value of the cookie `name`, out of however many `Cookie` headers the
/// request carries.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| header.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(cookie, _)| *cookie == name)
        .map(|(_, value)| value.to_owned())
}

/// The value of `name` in an `application/x-www-form-urlencoded` body.
///
/// Parsed by hand because it is ten lines and the alternative is a dependency:
/// split on `&`, split on `=`, undo `+` and `%XX`. A `%` that is not an escape
/// is kept as it came — the value it garbles is one the form never produces,
/// and a code mangled either way simply fails to redeem.
fn form_value(body: &str, name: &str) -> Option<String> {
    body.split('&')
        .filter_map(|pair| pair.split_once('=').or(Some((pair, ""))))
        .find(|(key, _)| form_decode(key) == name)
        .map(|(_, value)| form_decode(value))
}

/// Undo form encoding: `+` is a space, `%XX` is the byte it spells.
fn form_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' if index + 2 < bytes.len()
                && bytes[index + 1].is_ascii_hexdigit()
                && bytes[index + 2].is_ascii_hexdigit() =>
            {
                let hex = std::str::from_utf8(&bytes[index + 1..=index + 2])
                    .expect("two ascii hex digits are utf-8");
                decoded.push(u8::from_str_radix(hex, 16).expect("two hex digits are a byte"));
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }

    String::from_utf8_lossy(&decoded).into_owned()
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
        &home.builds,
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
    use crate::connections::github::Connection;
    use crate::connections::github::api::testing::FakeGitHub;
    use crate::secret::Secret;
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
            tracking: Arc::new(TrackingRepository::new(db.clone())),
            github: github.clone(),
            nudge: Nudge::new(),
            builds: Nudge::new(),
            hostname: Some(HOSTNAME.to_owned()),
            sessions: Arc::new(SessionRepository::new(db)),
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

    /// A home whose database the test can also reach, for planting the user
    /// and the code a login needs.
    fn auth_home() -> (Arc<Home>, crate::auth::UserRepository) {
        let db = Db::in_memory().unwrap();
        let home = Arc::new(Home {
            attempts: Arc::new(Attempts::new()),
            connections: Arc::new(ConnectionRepository::new(db.clone())),
            tracking: Arc::new(TrackingRepository::new(db.clone())),
            github: FakeGitHub::new(),
            nudge: Nudge::new(),
            builds: Nudge::new(),
            hostname: Some(HOSTNAME.to_owned()),
            sessions: Arc::new(SessionRepository::new(db.clone())),
        });

        (home, crate::auth::UserRepository::new(db))
    }

    /// A code as the operator socket would have minted one, exposed for the
    /// form to type.
    async fn minted_code(home: &Home, users: &crate::auth::UserRepository, slug: &str) -> String {
        users.create(&slug.parse().unwrap(), None).await.unwrap();

        home.sessions
            .mint_code(
                &crate::auth::UserRef::Slug(slug.parse().unwrap()),
                crate::auth::DEFAULT_SESSION_LIFETIME,
            )
            .await
            .unwrap()
            .code
            .expose()
            .to_owned()
    }

    /// One form submission at `path`, as a browser would send it.
    async fn post_form(home: Arc<Home>, path: &str, body: &str) -> http::Response<Body> {
        router(home)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn the_login_page_renders_the_code_form() {
        let (status, body) = get_path(auth_home().0, "/login").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#"<input name="code""#), "{body}");
        assert!(body.contains(r#"action="/login""#), "{body}");
    }

    /// The whole point of the page: a good code becomes a cookie with every
    /// attribute the spec asks for, and a bounce to `/`.
    #[tokio::test]
    async fn a_good_code_sets_the_session_cookie_and_redirects_home() {
        let (home, users) = auth_home();
        let code = minted_code(&home, &users, "alice").await;

        let response = post_form(home, "/login", &format!("code={code}")).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[http::header::LOCATION], "/");
        let cookie = response.headers()[http::header::SET_COOKIE]
            .to_str()
            .unwrap();
        assert!(cookie.starts_with("__Host-spaceport-session="), "{cookie}");
        for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/", "Max-Age="] {
            assert!(cookie.contains(attribute), "{cookie}");
        }
    }

    #[tokio::test]
    async fn a_safe_next_path_is_honoured() {
        let (home, users) = auth_home();
        let code = minted_code(&home, &users, "alice").await;

        let response =
            post_form(home, "/login", &format!("code={code}&next=%2Fwiki%3Fq%3D1")).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[http::header::LOCATION], "/wiki?q=1");
    }

    /// The open-redirect gate: anything that is not a plain absolute path on
    /// this host lands at `/`, never on somebody else's origin.
    #[tokio::test]
    async fn a_hostile_next_falls_back_to_the_root() {
        for hostile in [
            "https://evil.example/",
            "//evil.example/",
            "/%5Cevil.example",
            "javascript:alert(1)",
            "wiki",
        ] {
            let (home, users) = auth_home();
            let code = minted_code(&home, &users, "alice").await;

            let response = post_form(home, "/login", &format!("code={code}&next={hostile}")).await;

            assert_eq!(response.status(), StatusCode::SEE_OTHER, "{hostile}");
            assert_eq!(response.headers()[http::header::LOCATION], "/", "{hostile}");
        }
    }

    /// One sentence for every kind of bad code — and no cookie, which is the
    /// half a test can prove.
    #[tokio::test]
    async fn a_bad_code_rerenders_the_form_with_a_neutral_error() {
        let (home, _) = auth_home();

        let response = post_form(home, "/login", "code=wrongcod").await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(http::header::SET_COOKIE).is_none());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("did not work"), "{body}");
        assert!(body.contains(r#"<input name="code""#), "{body}");
    }

    /// A suspended user's code is exactly as refused as one that never
    /// existed: same status, same sentence.
    #[tokio::test]
    async fn a_suspended_users_code_is_refused_like_an_unknown_one() {
        let (home, users) = auth_home();
        let code = minted_code(&home, &users, "alice").await;
        users
            .suspend(&crate::auth::UserRef::Slug("alice".parse().unwrap()))
            .await
            .unwrap();

        let response = post_form(home, "/login", &format!("code={code}")).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            String::from_utf8(body.to_vec())
                .unwrap()
                .contains("did not work")
        );
    }

    /// CSRF hygiene: fetching `/logout` must not log anybody out — it renders
    /// the form whose `POST` does.
    #[tokio::test]
    async fn get_logout_confirms_rather_than_logging_out() {
        let (home, users) = auth_home();
        let code = minted_code(&home, &users, "alice").await;
        post_form(home.clone(), "/login", &format!("code={code}")).await;

        let (status, body) = get_path(home.clone(), "/logout").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#"method="post""#), "{body}");
        // And the session is still there.
        let (_, listed) = home
            .sessions
            .list(&crate::auth::UserRef::Slug("alice".parse().unwrap()))
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
    }

    #[tokio::test]
    async fn post_logout_drops_the_session_and_clears_the_cookie() {
        let (home, users) = auth_home();
        let code = minted_code(&home, &users, "alice").await;
        let login = post_form(home.clone(), "/login", &format!("code={code}")).await;
        let cookie = login.headers()[http::header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        let response = router(home.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .header(http::header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let cleared = response.headers()[http::header::SET_COOKIE]
            .to_str()
            .unwrap();
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
        let (_, listed) = home
            .sessions
            .list(&crate::auth::UserRef::Slug("alice".parse().unwrap()))
            .await
            .unwrap();
        assert!(listed.is_empty());
    }

    /// Signing out while holding no session is a success too: the user asked
    /// to be signed out, and they are.
    #[tokio::test]
    async fn post_logout_without_a_session_still_answers_signed_out() {
        let (home, _) = auth_home();

        let response = post_form(home, "/logout", "").await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn form_values_decode_the_way_a_browser_encodes() {
        assert_eq!(
            form_value("code=abc23456&next=%2Fa%20b", "next").as_deref(),
            Some("/a b")
        );
        assert_eq!(form_value("a=1&code=x+y", "code").as_deref(), Some("x y"));
        assert_eq!(form_value("a=1", "code"), None);
        // A stray percent is carried as it came rather than panicking.
        assert_eq!(form_value("code=1%GG", "code").as_deref(), Some("1%GG"));
    }
}

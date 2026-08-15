//! Having GitHub create the App, instead of an operator filling in a form.
//!
//! The other half of [`super::register`]. Registering by hand means an operator
//! on github.com clicking through a settings page with a dozen permission
//! dropdowns on it, generating a key, generating a client secret, and typing
//! seven values back into a terminal without transposing a digit. GitHub's App
//! Manifest flow exists to replace all of that: spaceport writes down what the
//! App should be, GitHub creates it exactly so, and hands the secrets back once.
//!
//! What it cannot do is create the App on its own. GitHub requires the manifest
//! to arrive as a form POST from a browser that is logged in as somebody with
//! the right to create an App on that account — which is a person, and a person
//! spaceport has no session for. So the flow is a URL handed to an operator, a
//! page served on spaceport's own hostname holding that form, and a redirect
//! back with a one-time code. That shape is not a workaround; it is the only
//! shape there is.
//!
//! Two things live here and nothing else does. The manifest document itself,
//! which is the security surface of every installation this App will ever have,
//! and the attempts in flight — a nonce spaceport issued, remembered only long
//! enough for one trip through a browser. The attempts are in memory on purpose:
//! an attempt that does not survive a restart is an operator running one command
//! again, and writing a half-finished registration to the state store would mean
//! a row nothing ever cleans up.
//!
//! The rejected alternative was having spaceport post the manifest itself with
//! an operator's personal access token. That works, and it means asking for a
//! token with `admin:org` on it — a credential far stronger than the App being
//! created, held for the length of one command, to save a click.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::Method;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use super::api::{self, Transport};
use super::register::Registration;
use crate::connections::Secret;

/// Where GitHub takes a browser to create an App on an organisation.
///
/// GitHub's own path, and the `organizations/{org}` in it is what decides who
/// owns the App — there is no field in the manifest that says so.
const NEW_ORGANISATION_APP: &str = "https://github.com/organizations";

/// Where GitHub takes a browser to create an App on the operator's own account.
///
/// A different path rather than the same one with an empty owner, because
/// GitHub has no notion of a personal account's "organisation" — an App with no
/// organisation belongs to whoever is logged in.
const NEW_PERSONAL_APP: &str = "https://github.com/settings/apps/new";

/// The path spaceport serves the manifest form at, under its own hostname.
///
/// The state is the last segment, which is why it is rendered as base64 with a
/// url-safe alphabet: it goes in a path, not in a query string.
pub const SETUP_PATH: &str = "/connections/github/setup";

/// The path GitHub is told to deliver this App's webhooks to.
///
/// Served by [`super::webhook`], through the edge's home router. It is declared
/// here because the manifest is the only chance to declare it: changing the
/// webhook url afterwards is an edit on the App's settings page, done by hand,
/// on every App this flow has ever created.
pub const WEBHOOK_PATH: &str = "/connections/github/webhooks";

/// What the App may do, and nothing beyond it.
///
/// The fewest permissions a thing which watches repositories and reports on
/// commits can be given: read the metadata that says a repository exists, read
/// the code, write the checks and statuses that appear against a commit, write
/// the deployments that record where that commit went, and read the pull
/// requests those checks belong to. Nothing writes to a repository's contents,
/// and nothing reads an organisation's members or its secrets.
///
/// Starting narrow is the point. Widening this later is not a deployment — it
/// is a permission change every account that has installed the App has to
/// approve by hand, and until each of them does, the App keeps the permissions
/// it had. Anything added here is therefore added once and forever, so it is
/// added only when something actually cannot work without it.
const PERMISSIONS: [(&str, &str); 6] = [
    ("metadata", "read"),
    ("contents", "read"),
    ("checks", "write"),
    ("statuses", "write"),
    ("deployments", "write"),
    ("pull_requests", "read"),
];

/// What GitHub is asked to tell spaceport about.
///
/// The same argument as [`PERMISSIONS`], and the same consequence: an event
/// spaceport does not subscribe to at creation is one an operator has to tick
/// on the settings page of every App this flow has ever made. These five are
/// what it takes to know what an App can see and what has happened to the code
/// inside — and no more than that. Nothing here asks for issues, comments, or
/// anything else about the people using a repository.
///
/// `installation` and `installation_repositories` are conspicuously absent, and
/// spaceport receives them anyway. GitHub sends an App the events about its own
/// installation whether it asked or not — there is nothing to subscribe to —
/// and naming them here is not a harmless duplicate but a refusal: a manifest
/// listing them is rejected outright as invalid, with "default events
/// unsupported". So the two events the webhook receiver most needs are the two
/// this list must not mention.
const EVENTS: [&str; 5] = [
    "push",
    "repository",
    "check_suite",
    "pull_request",
    "deployment",
];

/// How many bytes of randomness a `state` nonce is made of.
///
/// The nonce has one job: an answer arriving at the callback must be an answer
/// to a question this spaceport asked, and it only has to be unguessable for
/// the half hour an attempt lives. 128 bits is far past what that needs — it is
/// the same figure a session identifier uses, for a value that lives for weeks
/// rather than for one trip through a browser form.
const STATE_BYTES: usize = 16;

/// How long an attempt is worth remembering.
///
/// It spans one operator's trip through a browser form: open the page, read it,
/// press the button, approve on github.com, come back. Half an hour is generous
/// for that and short enough that a link pasted into a chat window is dead
/// before anybody scrolls past it. GitHub's own conversion code is good for an
/// hour, so the attempt is deliberately the shorter of the two — spaceport
/// forgets first, and the failure is spaceport's own sentence rather than
/// GitHub's.
pub const LIFETIME: Duration = Duration::minutes(30);

/// The document GitHub creates an App from.
///
/// Serialised into a hidden form field and posted by a browser, so every field
/// here is a decision that cannot be revised without creating another App.
#[derive(Debug, Serialize)]
pub struct Manifest {
    /// The App's display name, which GitHub turns into the slug everything
    /// afterwards knows it by.
    name: String,
    /// Where a human who found the App on github.com should be sent. This
    /// spaceport, because this spaceport is what the App is for.
    url: String,
    /// Where deliveries go, and whether GitHub sends them at all.
    hook_attributes: Hook,
    /// Where GitHub returns the browser once the App exists.
    redirect_url: String,
    /// Never public. A public App can be installed by anybody who finds it, and
    /// this one exists to serve the accounts one operator runs.
    public: bool,
    default_permissions: BTreeMap<&'static str, &'static str>,
    default_events: [&'static str; EVENTS.len()],
}

/// Where the App's deliveries are sent.
#[derive(Debug, Serialize)]
struct Hook {
    url: String,
    /// On from the start. An App created with deliveries switched off looks
    /// perfectly healthy and silently reports nothing, which is the hardest
    /// kind of misconfiguration to notice.
    active: bool,
}

impl Manifest {
    /// The manifest for an App called `name`, serving this `hostname`, answering
    /// the attempt `state` identifies.
    pub fn new(hostname: &str, name: &str, state: &str) -> Self {
        Self {
            name: name.to_owned(),
            url: format!("https://{hostname}"),
            hook_attributes: Hook {
                url: format!("https://{hostname}{WEBHOOK_PATH}"),
                active: true,
            },
            redirect_url: callback_url(hostname, state),
            public: false,
            default_permissions: PERMISSIONS.into_iter().collect(),
            default_events: EVENTS,
        }
    }

    /// The manifest as the form field carries it.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).context("writing the github app manifest")
    }
}

/// Where an operator opens the form that creates the App.
pub fn setup_url(hostname: &str, state: &str) -> String {
    format!("https://{hostname}{SETUP_PATH}/{state}")
}

/// Where GitHub returns the browser once it has created the App.
fn callback_url(hostname: &str, state: &str) -> String {
    format!("{}/callback", setup_url(hostname, state))
}

/// Where the form posts to: GitHub's own "create an app" page, told which
/// attempt the answer belongs to.
///
/// Without an `org` the App belongs to whichever account the operator is logged
/// in as, which is the right answer for a spaceport one person runs.
pub fn new_app_url(org: Option<&str>, state: &str) -> String {
    match org {
        Some(org) => format!("{NEW_ORGANISATION_APP}/{org}/settings/apps/new?state={state}"),
        None => format!("{NEW_PERSONAL_APP}?state={state}"),
    }
}

/// One trip through the browser form, as spaceport remembers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The organisation the App is to belong to, or none for the operator's own
    /// account.
    pub org: Option<String>,
    /// The display name the App is to be created with.
    pub name: String,
    pub created_at: OffsetDateTime,
}

impl Attempt {
    fn expired(&self, now: OffsetDateTime) -> bool {
        now - self.created_at >= LIFETIME
    }
}

/// The attempts this spaceport has issued a state for and not yet finished.
///
/// Held behind one lock rather than one per entry: an operator registers an App
/// occasionally and by hand, so there is no contention to design around, and a
/// map small enough to fit in a sentence does not want a concurrent structure.
#[derive(Debug, Default)]
pub struct Attempts {
    pending: Mutex<HashMap<String, Attempt>>,
}

impl Attempts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember an attempt and hand back the state that names it.
    pub fn begin(&self, org: Option<String>, name: String, now: OffsetDateTime) -> Result<String> {
        let state = nonce()?;

        self.pending
            .lock()
            .expect("the pending attempts are never held across a panic")
            .insert(
                state.clone(),
                Attempt {
                    org,
                    name,
                    created_at: now,
                },
            );

        Ok(state)
    }

    /// What `state` was issued for, if it is still worth answering.
    ///
    /// Reading without consuming, because the form page is a page: an operator
    /// who reloads it, or whose browser fetches it twice, must get the form both
    /// times. Only the callback consumes.
    pub fn peek(&self, state: &str, now: OffsetDateTime) -> Option<Attempt> {
        self.pending
            .lock()
            .expect("the pending attempts are never held across a panic")
            .get(state)
            .filter(|attempt| !attempt.expired(now))
            .cloned()
    }

    /// Consume `state`, if it names an attempt that has not expired.
    ///
    /// One-time, so a callback that arrives twice — a reload, a browser
    /// prefetch, a link somebody kept — creates one App and not two. A state
    /// that does not match one spaceport issued is not an answer to a question
    /// spaceport asked, and there is nothing to do with it but refuse it.
    ///
    /// Expired attempts are dropped on the way past, which is the only sweeping
    /// there is: without it a spaceport whose operator abandons a registration
    /// keeps that attempt for as long as the process runs, and the map grows
    /// with every one of them.
    pub fn take(&self, state: &str, now: OffsetDateTime) -> Option<Attempt> {
        let mut pending = self
            .pending
            .lock()
            .expect("the pending attempts are never held across a panic");

        pending.retain(|_, attempt| !attempt.expired(now));

        pending.remove(state)
    }
}

/// A state nonce: [`STATE_BYTES`] of randomness, in an alphabet a url path
/// carries as it is.
fn nonce() -> Result<String> {
    let mut bytes = [0_u8; STATE_BYTES];

    SystemRandom::new()
        .fill(&mut bytes)
        // ring's own error says nothing; what an operator can act on is that
        // the host's randomness is what failed.
        .map_err(|_| anyhow::anyhow!("this host would not produce random bytes"))?;

    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// What GitHub answers a conversion with.
///
/// No `deny_unknown_fields`, the same stance as the rest of GitHub's wire
/// shapes: a field GitHub adds on a Tuesday must not be the reason an operator
/// cannot register an App.
#[derive(Deserialize)]
struct Converted {
    id: i64,
    slug: String,
    name: String,
    owner: Owner,
    client_id: String,
    client_secret: Secret,
    webhook_secret: Secret,
    /// GitHub's name for the private key, which arrives as PEM in the body —
    /// the one and only time it is ever sent.
    pem: Secret,
}

#[derive(Deserialize)]
struct Owner {
    login: String,
}

/// Turn the code GitHub sent back into the App it created.
///
/// Unauthenticated, and that is not an oversight: the code *is* the credential.
/// It is single-use and good for an hour, and the response is the only time
/// GitHub will ever say what this App's private key and secrets are.
pub async fn convert(transport: &dyn Transport, code: &str) -> Result<Registration> {
    let url = format!("{}/app-manifests/{code}/conversions", api::API);
    let response = api::request(transport, Method::POST, &url, None)
        .await
        .context("asking github for the app it just created")?;

    if !response.status().is_success() {
        // Nothing here is worth telling apart. A code can be exchanged once and
        // expires after an hour, so every refusal means the same thing to the
        // operator standing there: this attempt is over, make another.
        bail!(
            "github would not hand over the app it created ({}) — the one-time code has already been used or has expired, so run `spaceport connect github --auto` again and open the new link",
            response.status()
        );
    }

    let converted: Converted = serde_json::from_slice(response.body())
        .context("github's answer about the app it just created is not what spaceport expected")?;

    Ok(Registration {
        slug: converted.slug,
        app_id: converted.id,
        name: converted.name,
        owner: converted.owner.login,
        client_id: converted.client_id,
        client_secret: converted.client_secret,
        webhook_secret: converted.webhook_secret,
        private_key: converted.pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::github::api::testing::FakeGitHub;
    use crate::connections::github::key;
    use http::StatusCode;
    use serde_json::Value;

    const HOSTNAME: &str = "spaceport.example.com";

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn manifest() -> Value {
        serde_json::from_str(
            &Manifest::new(HOSTNAME, "Spaceport for Acme", "a-state")
                .to_json()
                .unwrap(),
        )
        .unwrap()
    }

    /// The permissions are the whole security surface of every installation
    /// this App will ever have, so the assertion is the exact set — a test that
    /// checked only that `contents` was there would pass just as happily for an
    /// App that could also write to it.
    #[test]
    fn the_manifest_asks_for_exactly_six_permissions() {
        let permissions = manifest()["default_permissions"].clone();

        assert_eq!(
            permissions,
            serde_json::json!({
                "metadata": "read",
                "contents": "read",
                "checks": "write",
                "statuses": "write",
                "deployments": "write",
                "pull_requests": "read",
            })
        );
    }

    /// Subscribing to an event nobody needs is the same mistake as asking for a
    /// permission nobody needs, and just as hard to take back.
    #[test]
    fn the_manifest_subscribes_to_exactly_five_events() {
        assert_eq!(
            sorted_events(),
            [
                "check_suite",
                "deployment",
                "pull_request",
                "push",
                "repository",
            ]
        );
    }

    /// GitHub delivers an App its own installation events whether it asked or
    /// not, and rejects the whole manifest as invalid for naming them — so the
    /// list must leave out the two events the webhook receiver most depends on.
    /// This test is the only thing standing between that reasoning and somebody
    /// helpfully adding them back.
    #[test]
    fn the_manifest_does_not_ask_for_the_events_github_sends_regardless() {
        let events = sorted_events();

        assert!(!events.contains(&"installation".to_owned()), "{events:?}");
        assert!(
            !events.contains(&"installation_repositories".to_owned()),
            "{events:?}"
        );
    }

    /// The events the manifest asks for, in a stable order.
    fn sorted_events() -> Vec<String> {
        let mut events: Vec<String> = manifest()["default_events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event.as_str().unwrap().to_owned())
            .collect();
        events.sort();

        events
    }

    #[test]
    fn the_manifest_points_github_back_at_this_spaceport() {
        let manifest = manifest();

        assert_eq!(manifest["url"], "https://spaceport.example.com");
        assert_eq!(
            manifest["hook_attributes"]["url"],
            "https://spaceport.example.com/connections/github/webhooks"
        );
        assert_eq!(manifest["hook_attributes"]["active"], true);
        assert_eq!(
            manifest["redirect_url"],
            "https://spaceport.example.com/connections/github/setup/a-state/callback"
        );
    }

    /// A public app is one anybody who finds it can install, and this one is
    /// for the accounts of whoever runs the spaceport.
    #[test]
    fn the_manifest_never_asks_for_a_public_app() {
        assert_eq!(manifest()["public"], false);
    }

    #[test]
    fn the_form_posts_to_the_organisation_github_should_own_the_app() {
        assert_eq!(
            new_app_url(Some("an-organisation"), "a-state"),
            "https://github.com/organizations/an-organisation/settings/apps/new?state=a-state"
        );
    }

    /// Without an organisation the App belongs to whoever is logged in, which
    /// is a different page on github.com rather than the same one with a blank.
    #[test]
    fn the_form_posts_to_the_personal_account_page_when_there_is_no_organisation() {
        assert_eq!(
            new_app_url(None, "a-state"),
            "https://github.com/settings/apps/new?state=a-state"
        );
    }

    #[test]
    fn issues_a_state_and_answers_for_it_once() {
        let attempts = Attempts::new();
        let state = attempts
            .begin(Some("an-organisation".to_owned()), "Sp".to_owned(), now())
            .unwrap();

        let taken = attempts.take(&state, now()).unwrap();

        assert_eq!(taken.org.as_deref(), Some("an-organisation"));
        assert_eq!(taken.name, "Sp");
        assert!(attempts.take(&state, now()).is_none());
    }

    /// The page is read as many times as a browser feels like fetching it, so
    /// only the callback may consume the attempt.
    #[test]
    fn reading_an_attempt_does_not_use_it_up() {
        let attempts = Attempts::new();
        let state = attempts.begin(None, "Sp".to_owned(), now()).unwrap();

        assert!(attempts.peek(&state, now()).is_some());
        assert!(attempts.peek(&state, now()).is_some());
        assert!(attempts.take(&state, now()).is_some());
    }

    #[test]
    fn an_attempt_older_than_its_lifetime_is_not_answered() {
        let attempts = Attempts::new();
        let started = now();
        let state = attempts.begin(None, "Sp".to_owned(), started).unwrap();

        let later = started + LIFETIME + Duration::seconds(1);

        assert!(attempts.peek(&state, later).is_none());
        assert!(attempts.take(&state, later).is_none());
    }

    /// An operator who abandons a registration leaves an attempt behind, and
    /// without this the map keeps every one of them for the life of the
    /// process.
    #[test]
    fn taking_one_attempt_drops_the_others_that_have_expired() {
        let attempts = Attempts::new();
        let started = now();
        let abandoned = attempts
            .begin(None, "Abandoned".to_owned(), started)
            .unwrap();
        let later = started + LIFETIME + Duration::seconds(1);
        let fresh = attempts.begin(None, "Fresh".to_owned(), later).unwrap();

        attempts.take(&fresh, later).unwrap();

        assert!(attempts.pending.lock().unwrap().get(&abandoned).is_none());
        assert!(attempts.pending.lock().unwrap().is_empty());
    }

    /// Two attempts must not be able to answer for each other, which is the
    /// entire job of the nonce.
    #[test]
    fn two_states_are_never_the_same_state() {
        let attempts = Attempts::new();

        let one = attempts.begin(None, "Sp".to_owned(), now()).unwrap();
        let another = attempts.begin(None, "Sp".to_owned(), now()).unwrap();

        assert_ne!(one, another);
        // And it is a value a url path carries without escaping anything.
        assert!(
            one.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{one}"
        );
    }

    #[tokio::test]
    async fn reads_the_app_github_says_it_created() {
        let github = FakeGitHub::new();
        github.converts_manifests_into(42, "spaceport-for-acme", "Spaceport for Acme");

        let registration = convert(github.as_ref(), "a-one-time-code").await.unwrap();

        assert_eq!(registration.app_id, 42);
        assert_eq!(registration.slug, "spaceport-for-acme");
        assert_eq!(registration.name, "Spaceport for Acme");
        assert_eq!(registration.owner, "an-organisation");
        assert_eq!(registration.client_id, "Iv1.0123456789abcdef");
        assert_eq!(registration.client_secret, Secret::new("a-client-secret"));
        assert_eq!(registration.webhook_secret, Secret::new("a-webhook-secret"));
        assert_eq!(registration.private_key, Secret::new(key::testing::PKCS1));
        // Everything the conversion hands back has to be good enough to record.
        registration.validate().unwrap();
    }

    /// The conversion is unauthenticated because the code is the credential,
    /// and presenting one of the App's own credentials would be presenting a
    /// credential for an App that does not exist yet.
    #[tokio::test]
    async fn the_conversion_presents_no_credential_at_all() {
        use crate::connections::github::api::testing::Authorization;

        let github = FakeGitHub::new();
        github.converts_manifests_into(42, "spaceport-for-acme", "Spaceport for Acme");

        convert(github.as_ref(), "a-one-time-code").await.unwrap();

        let requests = github.requests();
        assert_eq!(
            requests[0].path,
            "/app-manifests/a-one-time-code/conversions"
        );
        assert_eq!(requests[0].authorization, Authorization::None);
    }

    /// A code is single-use and lasts an hour, so a refusal always means the
    /// same thing: this attempt is over.
    #[tokio::test]
    async fn a_refused_conversion_says_to_start_again() {
        let github = FakeGitHub::new();
        github.refuse_with(StatusCode::NOT_FOUND, "Not Found");

        let error = format!(
            "{:#}",
            convert(github.as_ref(), "a-spent-code").await.unwrap_err()
        );

        assert!(
            error.contains("already been used or has expired"),
            "{error}"
        );
        assert!(error.contains("--auto"), "{error}");
    }
}

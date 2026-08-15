//! What spaceport does with a delivery GitHub posts to it.
//!
//! A webhook is the only way GitHub tells a spaceport anything without being
//! asked, and it arrives over the open internet at a url anybody can find.
//! Nothing about the request says who sent it except the signature, so the
//! signature is not a formality — it is the single thing that makes a delivery
//! evidence of anything at all. A body that verifies against the webhook secret
//! GitHub issued when the App was created came from GitHub; a body that does
//! not is a stranger's, whatever its headers claim.
//!
//! What this module does with a delivery is observe it, and — for the two
//! events that say the installations are not what they were — shove the
//! reconciler. It never applies what a delivery claims. A body is a story about
//! the past that may arrive twice, late, or out of order, and the answer to all
//! three is to go and ask GitHub outright; the delivery only decides *when* that
//! happens. No app is deployed, no container is touched.
//!
//! The shove happens after verification and after deduplication, and that
//! ordering is a security property rather than a tidiness one. This endpoint is
//! reachable by anybody who can find the hostname, so a nudge a stranger could
//! send would make an unauthenticated request into a GitHub API round trip per
//! connection — an amplifier, and one that spends a rate limit spaceport needs.
//!
//! The rejected alternative was verifying a delivery against every secret this
//! spaceport holds until one matched. That works, and it turns each stranger's
//! request into one HMAC per connection while quietly making the connections
//! interchangeable. GitHub names the App in a header of its own, so a delivery
//! is attributed first and verified once, against that App's secret only.
//!
//! Deduplication is the other half. GitHub retries a delivery it did not get a
//! 2xx for, and a redelivery an operator triggers by hand carries the same id,
//! so the delivery id is remembered and a repeat is answered without being
//! observed twice.

use anyhow::{Context, Result, anyhow, bail};
use http::{HeaderMap, StatusCode};
use ring::hmac;
use serde_json::Value;
use tracing::{debug, info, warn};

use super::reconcile::Nudge;
use super::repository::ConnectionRepository;
use crate::connections::Secret;

/// The header naming what happened — `push`, `installation`, `ping`.
///
/// GitHub's own header, and the only place the event name appears: the body
/// describes what happened without ever saying which event it is.
pub const EVENT_HEADER: &str = "x-github-event";

/// The header carrying GitHub's unique id for this delivery.
///
/// The deduplication key, and GitHub's guarantee rather than spaceport's: a
/// retry and a hand-triggered redelivery both carry the id of the delivery they
/// repeat, which is what makes remembering it enough.
pub const DELIVERY_HEADER: &str = "x-github-delivery";

/// The header carrying the signature over the body.
///
/// `sha256=<hex>`, an HMAC-SHA256 of the exact request body under the App's
/// webhook secret. GitHub also sends a legacy `X-Hub-Signature` holding a SHA-1
/// of the same body; that header is not read here, and SHA-1 is not accepted —
/// a delivery signed only that way is refused rather than falling back.
pub const SIGNATURE_HEADER: &str = "x-hub-signature-256";

/// The header saying what kind of thing the hook is attached to.
///
/// `integration` is GitHub's word for a GitHub App's own hook, which is the
/// only hook spaceport ever registers. A `repository` or `organization` hook
/// somebody pointed at this url is not something spaceport asked for.
pub const TARGET_TYPE_HEADER: &str = "x-github-hook-installation-target-type";

/// The header carrying the numeric id of the App the hook belongs to.
///
/// How a delivery is attributed. One spaceport may hold several connections,
/// each with a secret of its own, and this is the only field that says which of
/// them a delivery is supposed to be from.
pub const TARGET_ID_HEADER: &str = "x-github-hook-installation-target-id";

/// The target type spaceport's own hook always has.
const APP_TARGET_TYPE: &str = "integration";

/// What every signature GitHub sends begins with.
///
/// The prefix names the algorithm, so it is checked rather than skipped: a
/// signature spelled any other way is one this module cannot say it verified.
const SIGNATURE_PREFIX: &str = "sha256=";

/// The events that mean the cached installations are stale.
///
/// `installation` is an App installed, uninstalled, suspended or unsuspended on
/// an account; `installation_repositories` is a repository added to or removed
/// from one. Between them they are every way the answer to "where is this App,
/// and what can it see" changes, which is exactly what the cache holds.
///
/// Nothing else belongs here, and the discrimination is the point. A `push`
/// says a commit happened and says nothing whatever about where the App is
/// installed — waking the reconciler for one would spend a GitHub round trip
/// per connection for every commit an organisation pushes, on a question whose
/// answer has not moved. The same goes for `check_suite`, `pull_request` and
/// every other event a busy repository generates all day.
pub const EVENTS_THAT_STALE_THE_CACHE: [&str; 2] = ["installation", "installation_repositories"];

/// What spaceport made of a delivery.
///
/// A status code is chosen from this rather than returned from the handling,
/// because the choice needs saying out loud. GitHub retries a delivery that
/// failed and eventually disables a hook that keeps failing, so a non-2xx has
/// to be reserved for a delivery that is genuinely wrong — not for one this
/// spaceport merely has nothing to do with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Verified, new, and observed.
    Accepted,
    /// Verified, and seen before.
    Redelivery,
    /// No connection holds this app id, or the hook is not an App's own.
    Unattributed,
    /// The signature is missing, malformed, or not this app's.
    Unverified,
    /// A header GitHub always sends is missing or unreadable.
    Malformed,
}

impl Outcome {
    /// The status GitHub is answered with.
    pub fn status(self) -> StatusCode {
        match self {
            // Nothing acts on the delivery yet, and "accepted, not acted on" is
            // exactly what 202 means. It is also what this will keep meaning
            // once the reconciler does act, since acting will be a background
            // pass rather than something finished before the response.
            Self::Accepted => StatusCode::ACCEPTED,
            // Plain 200: the work was already done, and repeating it is not
            // something GitHub should be told about.
            Self::Redelivery => StatusCode::OK,
            // 404, because from GitHub's side there is genuinely no hook here
            // for that App — and a hook whose App has been disconnected ought
            // to be disabled rather than retried forever.
            Self::Unattributed => StatusCode::NOT_FOUND,
            // 401 and not 403: the request failed to prove who it is from,
            // which is exactly the distinction between the two.
            Self::Unverified => StatusCode::UNAUTHORIZED,
            // 400, because a retry of the same malformed request will fail the
            // same way — nothing about it is worth GitHub sending again.
            Self::Malformed => StatusCode::BAD_REQUEST,
        }
    }
}

/// Whether `signature` is what `secret` makes of `body`.
///
/// The comparison is `ring`'s rather than `==` because `ring`'s is constant
/// time. Comparing two signatures with `==` leaks through how long the failure
/// takes: a mismatch in the first byte returns sooner than one in the last, and
/// an attacker who can send a few million deliveries can walk a valid signature
/// out of that difference one byte at a time.
pub fn verify(secret: &Secret, signature: &str, body: &[u8]) -> Result<()> {
    let Some(hex) = signature.strip_prefix(SIGNATURE_PREFIX) else {
        bail!("a webhook signature must be `{SIGNATURE_PREFIX}<hex>`");
    };

    let expected = decode_hex(hex).context("reading a webhook signature")?;

    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose().as_bytes());

    hmac::verify(&key, body, &expected)
        // `ring`'s error says nothing at all, and there is nothing to add: the
        // signature is not this secret's over these bytes, and which of the two
        // is wrong is not something spaceport can know.
        .map_err(|_| anyhow!("the webhook signature is not this app's over this body"))
}

/// Take in one delivery, and say what became of it.
///
/// `body` is the bytes as they arrived. Nothing here may reparse or
/// re-serialise them before verifying, because the signature is over exactly
/// those bytes.
///
/// The `Err` case is reserved for the state store failing — everything a
/// delivery itself can get wrong is an [`Outcome`], because it is an answer to
/// GitHub rather than a fault of this spaceport's.
pub async fn receive(
    connections: &ConnectionRepository,
    nudge: &Nudge,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Outcome> {
    let Some(app_id) = header(headers, TARGET_ID_HEADER).and_then(parse_app_id) else {
        warn!("a webhook delivery named no app id");

        return Ok(Outcome::Malformed);
    };

    // Absent is tolerated and wrong is not: the header is one GitHub added
    // later, and a delivery that says it is a repository's hook is saying it is
    // not spaceport's.
    if let Some(target_type) = header(headers, TARGET_TYPE_HEADER)
        && !target_type.eq_ignore_ascii_case(APP_TARGET_TYPE)
    {
        warn!(
            target_type,
            app_id, "a webhook delivery was not an app's own"
        );

        return Ok(Outcome::Unattributed);
    }

    let Some(connection) = connections
        .by_app_id(app_id)
        .await
        .context("looking up the connection a webhook delivery names")?
    else {
        warn!(
            app_id,
            "a webhook delivery named an app nothing connects to"
        );

        return Ok(Outcome::Unattributed);
    };

    let Some(signature) = header(headers, SIGNATURE_HEADER) else {
        warn!(app_id, "a webhook delivery carried no signature");

        return Ok(Outcome::Unverified);
    };

    if let Err(error) = verify(&connection.webhook_secret, signature, body) {
        // The error, never the signature and never the secret.
        warn!(app_id, %error, "a webhook delivery did not verify");

        return Ok(Outcome::Unverified);
    }

    let Some(delivery_id) = header(headers, DELIVERY_HEADER) else {
        warn!(app_id, "a verified webhook delivery carried no id");

        return Ok(Outcome::Malformed);
    };

    // Unnamed deliveries do not exist, but an event GitHub has invented since
    // this was written does, and it is worth observing under whatever it calls
    // itself.
    let event = header(headers, EVENT_HEADER).unwrap_or("unknown");

    // Nothing prunes the delivery window here. The reconciliation loop calls
    // `prune_deliveries`, because pruning belongs to something that runs on a
    // timer rather than to something that runs once per delivery.
    if !connections
        .record_delivery(delivery_id, app_id, event)
        .await
        .context("recording a webhook delivery")?
    {
        debug!(
            event,
            delivery_id, app_id, "github sent a webhook delivery again"
        );

        return Ok(Outcome::Redelivery);
    }

    let payload = Payload::read(body);

    info!(
        event,
        delivery_id,
        connection = connection.slug,
        app_id,
        action = payload.action,
        repository = payload.repository,
        installation = payload.installation,
        "a github webhook delivery arrived"
    );

    // Here and nowhere earlier. Every return above this point is a delivery
    // that did not prove it came from GitHub, or one that has already been
    // acted on, and neither may make spaceport call GitHub: an endpoint a
    // stranger can turn into an API request is an amplifier, and this one is
    // open to the internet.
    if EVENTS_THAT_STALE_THE_CACHE.contains(&event) {
        debug!(
            event,
            delivery_id, app_id, "github says where this app is installed has changed"
        );
        nudge.nudge();
    }

    Ok(Outcome::Accepted)
}

/// The few things worth lifting out of a delivery's body.
///
/// Everything is optional because the body is GitHub's and differs per event —
/// a `push` has no `action`, an `installation` has no `repository`. A field
/// that is missing, or a body that is not JSON at all, must never fail a
/// delivery whose signature was good: the signature is what says the delivery
/// is genuine, and nothing spaceport failed to understand can take that back.
#[derive(Debug, Default)]
struct Payload {
    /// What was done — `opened`, `created`, `synchronize`.
    action: Option<String>,
    /// The repository it happened in, as `owner/name`.
    repository: Option<String>,
    /// The installation it came through, which is what a token is minted
    /// against.
    installation: Option<i64>,
}

impl Payload {
    /// What can be read out of `body`, and nothing more.
    ///
    /// The payload itself never becomes a field. A `push` body runs to hundreds
    /// of kilobytes, and an event stream that carried them would be a copy of
    /// GitHub rather than a record of what spaceport heard.
    fn read(body: &[u8]) -> Self {
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            warn!("a verified webhook delivery was not json");

            return Self::default();
        };

        Self {
            action: text(&value["action"]),
            repository: text(&value["repository"]["full_name"]),
            installation: value["installation"]["id"].as_i64(),
        }
    }
}

/// `value` as a string, when it is one.
fn text(value: &Value) -> Option<String> {
    value.as_str().map(ToOwned::to_owned)
}

/// The value of `name`, when it is present and is text.
///
/// A header whose bytes are not ASCII is treated as absent rather than as an
/// error: nothing GitHub sends is anything else, so the only sender it can come
/// from is one whose delivery was going to be refused anyway.
fn header<'headers>(headers: &'headers HeaderMap, name: &str) -> Option<&'headers str> {
    headers.get(name)?.to_str().ok()
}

/// The app id a target-id header names, when it names one at all.
///
/// Positive because GitHub's ids are, and a `0` or a negative would be a value
/// that could never match a row — refusing it outright says so, rather than
/// looking it up and reporting an app nothing connects to.
fn parse_app_id(value: &str) -> Option<i64> {
    value.parse::<i64>().ok().filter(|id| *id > 0)
}

/// The bytes `hex` spells.
///
/// Sixteen lines rather than a dependency: a crate earns its place in this
/// workspace by doing something that is easy to get wrong, and this is a pair
/// of nibbles and a shift. Odd lengths and non-hex digits are refused rather
/// than skipped, because a signature spaceport had to guess at is one it cannot
/// say it verified.
fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        bail!(
            "a hex value has an even number of digits, and this one has {}",
            hex.len()
        );
    }

    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = digit(pair[0])?;
            let low = digit(pair[1])?;

            Ok(high << 4 | low)
        })
        .collect()
}

/// The value of one hex digit, upper or lower case.
fn digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("`{}` is not a hex digit", byte as char),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "a-webhook-secret";
    const BODY: &[u8] = br#"{"action":"opened"}"#;

    /// A signature exactly as GitHub would have computed it, written with
    /// `ring::hmac::sign` rather than pasted as hex so the test says what it
    /// means.
    fn signature(secret: &str, body: &[u8]) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let tag = hmac::sign(&key, body);

        let mut hex = String::new();
        for byte in tag.as_ref() {
            hex.push_str(&format!("{byte:02x}"));
        }

        format!("{SIGNATURE_PREFIX}{hex}")
    }

    #[test]
    fn a_signature_github_would_have_sent_verifies() {
        verify(&Secret::new(SECRET), &signature(SECRET, BODY), BODY).unwrap();
    }

    #[test]
    fn a_signature_made_with_another_secret_does_not_verify() {
        let signature = signature("another-webhook-secret", BODY);

        assert!(verify(&Secret::new(SECRET), &signature, BODY).is_err());
    }

    /// The point of signing the body rather than the headers: a delivery
    /// somebody edited on the way is not the delivery GitHub signed.
    #[test]
    fn a_signature_over_a_different_body_does_not_verify() {
        let signature = signature(SECRET, BODY);

        assert!(verify(&Secret::new(SECRET), &signature, br#"{"action":"closed"}"#).is_err());
    }

    /// The prefix names the algorithm, and a bare hex string — or GitHub's
    /// legacy `sha1=` — is not a SHA-256 signature spaceport may accept.
    #[test]
    fn a_signature_without_the_algorithm_prefix_is_refused() {
        let signed = signature(SECRET, BODY);
        let bare = signed.strip_prefix(SIGNATURE_PREFIX).unwrap();

        assert!(verify(&Secret::new(SECRET), bare, BODY).is_err());
        assert!(verify(&Secret::new(SECRET), &format!("sha1={bare}"), BODY).is_err());
    }

    #[test]
    fn a_signature_of_an_odd_number_of_digits_is_refused() {
        assert!(verify(&Secret::new(SECRET), "sha256=abc", BODY).is_err());
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn a_signature_that_is_not_hex_at_all_is_refused() {
        assert!(verify(&Secret::new(SECRET), "sha256=zz", BODY).is_err());
        assert!(decode_hex("ag").is_err());
        assert!(decode_hex("  ").is_err());
    }

    #[test]
    fn the_hex_decoder_reads_back_what_hex_spells() {
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode_hex("00ff107a").unwrap(), [0x00, 0xff, 0x10, 0x7a]);
        // Either case, since nothing says which GitHub sends.
        assert_eq!(decode_hex("DEADBEEF").unwrap(), [0xde, 0xad, 0xbe, 0xef]);
    }

    /// The signature the tests build has to be the one the verifier reads, or
    /// every test above passes against a bug in both halves.
    #[test]
    fn the_test_signature_is_sixty_four_hex_digits_of_sha_256() {
        let signed = signature(SECRET, BODY);
        let hex = signed.strip_prefix(SIGNATURE_PREFIX).unwrap();

        assert_eq!(hex.len(), 64);
        assert_eq!(decode_hex(hex).unwrap().len(), 32);
    }

    #[test]
    fn an_app_id_is_a_positive_number_and_nothing_else() {
        assert_eq!(parse_app_id("42"), Some(42));
        assert_eq!(parse_app_id("0"), None);
        assert_eq!(parse_app_id("-1"), None);
        assert_eq!(parse_app_id("forty-two"), None);
        assert_eq!(parse_app_id(""), None);
    }

    /// A body spaceport cannot read is still a delivery GitHub signed, so
    /// reading it gives up on the fields rather than on the delivery.
    #[test]
    fn a_body_that_is_not_json_yields_no_fields_and_no_error() {
        let payload = Payload::read(b"not json at all");

        assert_eq!(payload.action, None);
        assert_eq!(payload.repository, None);
        assert_eq!(payload.installation, None);
    }

    #[test]
    fn reads_the_few_fields_worth_recording_out_of_a_body() {
        let payload = Payload::read(
            br#"{"action":"opened",
                 "repository":{"full_name":"an-organisation/site"},
                 "installation":{"id":7}}"#,
        );

        assert_eq!(payload.action.as_deref(), Some("opened"));
        assert_eq!(payload.repository.as_deref(), Some("an-organisation/site"));
        assert_eq!(payload.installation, Some(7));
    }

    /// A `push` has no `action` and an `installation` has no `repository`, so
    /// missing fields are the normal case rather than an error.
    #[test]
    fn a_body_missing_the_fields_is_read_without_complaint() {
        let payload = Payload::read(br#"{"zen":"Design for failure."}"#);

        assert_eq!(payload.action, None);
        assert_eq!(payload.repository, None);
        assert_eq!(payload.installation, None);
    }

    /// The status codes are the whole of what GitHub sees, and getting one
    /// wrong means either a hook that is disabled for working or a delivery
    /// that is retried forever.
    #[test]
    fn each_outcome_answers_github_with_the_status_it_can_act_on() {
        assert_eq!(Outcome::Accepted.status(), StatusCode::ACCEPTED);
        assert_eq!(Outcome::Redelivery.status(), StatusCode::OK);
        assert_eq!(Outcome::Unattributed.status(), StatusCode::NOT_FOUND);
        assert_eq!(Outcome::Unverified.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(Outcome::Malformed.status(), StatusCode::BAD_REQUEST);
    }
}

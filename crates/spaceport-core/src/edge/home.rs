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

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Extension, Path, Query, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};
use tracing::{debug, warn};

use super::service::ConnInfo;
use crate::app::manifest::Host;
use crate::app::{AppId, AppStore, Auth};
use crate::auth::{
    AuthLogRepository, EntitlementRepository, RedeemError, SessionRepository, SsoLogin, SsoOutcome,
    SsoRepository, UserRef, WEB_ORIGIN,
};
use crate::connections::github::manifest::{self, Attempts, Manifest};
use crate::connections::github::{
    Client, ConnectionRepository, Nudge, TrackingRepository, Transport, api, register, webhook,
};
use crate::secret::Secret;
use crate::uri::query_encode;

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
    /// What each user may reach, for the access check the exchange makes
    /// before it mints anything: a nonce is a promise the callback will keep,
    /// so the entitlement question has to be answered before one exists.
    pub entitlements: Arc<EntitlementRepository>,
    /// Who each user is at their connections. On the `Home` for the wiring's
    /// sake, exactly as `jwt_cache` is: nothing on this host reads it, but
    /// `edge::serve` copies it out for [`super::EdgeState`], where every mint
    /// asks it what to call the person it is vouching for.
    pub identities: Arc<crate::auth::IdentityRepository>,
    /// Where the exchange records an access denial. The one auth event a page
    /// here writes outside a mutation's transaction, because a denial *is* no
    /// mutation — see [`AuthLogRepository::record`].
    pub auth_log: Arc<AuthLogRepository>,
    /// The routing table, for the exchange to re-derive an app's hosts and
    /// manifest from: nothing about where a user is sent is taken from the
    /// request that sent them here.
    pub apps: Arc<AppStore>,
    /// The key that signs the JWTs gated apps receive, held here because the
    /// JWKS that verifies them is served on this host — the spec pins it to
    /// `https://<edge.hostname>/.well-known/jwks.json` — and the gate signs
    /// with the same key through [`super::EdgeState`], or a token minted at
    /// one listener would fail at the document the other serves.
    pub signer: Arc<crate::auth::JwtSigner>,
    /// The JWT cache the gate mints into. On the `Home` for the wiring's sake:
    /// `edge::serve` copies it out for [`super::EdgeState`] exactly as it does
    /// `sessions`, and the operator side purges the same instance through the
    /// auth repositories.
    pub jwt_cache: Arc<crate::auth::JwtCache>,
    /// Named in the callback URLs the exchange builds when it is not 443,
    /// exactly as the plaintext redirect names it.
    pub https_port: u16,
    /// The SSO logins this spaceport has sent to GitHub and not yet seen come
    /// back — the state nonce's memory, in-process for the reason `attempts`
    /// is: a login that does not survive a restart is one more click on the
    /// login page.
    pub logins: Arc<LoginAttempts>,
    /// What bounds guessing at one-time codes. Held here rather than inside the
    /// session repository because it is the *edge's* memory of who has been
    /// knocking — one process, one window, no database — and `POST /login` is
    /// the only door it stands in front of.
    pub throttle: Arc<LoginThrottle>,
    /// The transaction a finished GitHub bounce lands in: resolve the user,
    /// snapshot the identity, re-sync the mapped entitlements, mint the
    /// session — one commit, over the same tables the operator socket reads.
    pub sso: Arc<SsoRepository>,
}

/// How long a login's state nonce is worth remembering.
///
/// It spans one trip through GitHub's authorize page — usually non-interactive
/// and over in a second, occasionally a password and a 2FA prompt. Ten minutes
/// covers the slow case with room to spare and matches the one-time code's
/// window, which answers the same question: how long is an invitation to sign
/// in allowed to sit unused.
const LOGIN_STATE_LIFETIME: Duration = Duration::minutes(10);

/// How many unfinished logins this spaceport will hold at once.
///
/// A ceiling rather than a tuning knob. The route that fills this map is
/// unauthenticated by design — a sign-in button is a link anyone may follow —
/// so without a number here the map's size is whatever request rate somebody
/// points at it, and the edge is the one process on the host that must not be
/// the one that runs out of memory. Four thousand is orders of magnitude more
/// logins than a spaceport has genuinely in flight in a ten-minute window, so
/// the number is only ever reached by a spaceport under attack.
const MAX_PENDING_LOGINS: usize = 4096;

/// How many unfinished logins one client address may hold at once.
///
/// The number that makes [`MAX_PENDING_LOGINS`] safe to have. A ceiling on the
/// map alone says nothing about *who* filled it, and a map filled by one
/// address is the whole lockout: four thousand requests from a single client —
/// an `<img src>` on any page will do, since this is a `GET` — and every other
/// user is refused for as long as the burst takes to expire.
///
/// Charging the map per address is [`MAX_THROTTLED_CLIENTS`]' argument reached
/// from the other end. That map could evict, because it is keyed by address and
/// so an eviction only ever spends the evicting client's own budget. This one
/// is keyed by an opaque state, so eviction has no idea whose entry it is
/// taking — and the entries it would take first are the *oldest*, which are
/// precisely the real logins sitting on GitHub's consent screen. So the quota
/// goes at the front instead: a flood now fills its own eight slots and stops,
/// and the four thousand behind them stay free for everybody else.
///
/// Eight rather than one, because a person with three tabs open, a stale button
/// they clicked twice and a bounce that never came back is holding several
/// perfectly honest entries, and none of them is worth a refusal.
const MAX_PENDING_LOGINS_PER_CLIENT: usize = 8;

/// One login in flight: which connection it went out through, and where the
/// finished login should land.
#[derive(Debug, Clone)]
struct LoginAttempt {
    connection: String,
    /// Already through [`safe_next`] when it was stored, so the value that
    /// comes back out is a path this host serves and nothing else.
    next: String,
    created_at: OffsetDateTime,
    /// Who asked for it, so the map can be charged per address rather than in
    /// one pool anybody may drain. Never read back out into a login — it exists
    /// for [`MAX_PENDING_LOGINS_PER_CLIENT`] and for the eviction that backs it.
    client: IpAddr,
}

/// The SSO logins this spaceport has issued a state for and not yet finished.
///
/// The same shape as [`Attempts`] and deliberately so — one lock, an
/// expiry-on-the-way-past sweep, and a strictly single-use `take`, because the
/// state's whole job is that an answer arriving at the callback is an answer
/// to a question this spaceport asked, exactly once. Unlike the setup flow
/// there is no `peek`: nothing between the redirect and the callback ever
/// needs to read an attempt without spending it.
///
/// What the setup flow does not have to reckon with is who fills the map. This
/// one is filled by `GET /auth/github/{slug}`, which is a link on a public
/// login page and answers anybody — so the sweep runs on the way in as well as
/// on the way out, and [`MAX_PENDING_LOGINS`] is the size this map has, rather
/// than the size somebody else's request rate gives it.
#[derive(Debug, Default)]
pub struct LoginAttempts {
    pending: Mutex<HashMap<String, LoginAttempt>>,
}

impl LoginAttempts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember that a login left `client` through `connection` aiming at
    /// `next`, and hand back the state that names it — or `None` when `client`
    /// is already holding [`MAX_PENDING_LOGINS_PER_CLIENT`] of them.
    ///
    /// A refusal is only ever a client's own doing. That is the point of the
    /// per-address quota: the previous rule refused on the *map* being full, so
    /// four thousand requests from one address bought a ten-minute lockout of
    /// every other user on the spaceport. Now a flood exhausts its own eight
    /// slots and every address that has not spent theirs is as welcome as it
    /// ever was — the same shape [`LoginThrottle::permits`] settled on, and for
    /// the same reason.
    ///
    /// The map's own ceiling still stands behind the quota, because five
    /// hundred addresses could reach it honestly enough. Reaching it takes an
    /// eviction rather than a refusal, and the one evicted is the oldest entry
    /// belonging to whichever address is holding the most — so the eviction
    /// lands on the biggest contributor to the problem, and a user holding a
    /// single login is untouchable while anybody is holding two.
    fn begin(
        &self,
        client: IpAddr,
        connection: String,
        next: String,
        now: OffsetDateTime,
    ) -> anyhow::Result<Option<String>> {
        let state = manifest::nonce()?;

        let mut pending = self
            .pending
            .lock()
            .expect("the pending logins are never held across a panic");

        sweep(&mut pending, now);

        if held_by(&pending, client) >= MAX_PENDING_LOGINS_PER_CLIENT {
            return Ok(None);
        }

        if pending.len() >= MAX_PENDING_LOGINS {
            evict_from_the_greediest(&mut pending);
        }

        pending.insert(
            state.clone(),
            LoginAttempt {
                connection,
                next,
                created_at: now,
                client,
            },
        );

        Ok(Some(state))
    }

    /// Consume `state`, if it names a login that has not expired — sweeping
    /// abandoned attempts on the way past, for [`Attempts::take`]'s reason.
    fn take(&self, state: &str, now: OffsetDateTime) -> Option<LoginAttempt> {
        let mut pending = self
            .pending
            .lock()
            .expect("the pending logins are never held across a panic");

        sweep(&mut pending, now);

        pending.remove(state)
    }
}

/// Drop every login too old to still be answered.
///
/// On both paths rather than only on the callback's: a spaceport that starts
/// logins and never sees one come back — which is every spaceport whose login
/// page somebody is walking past — would otherwise never sweep at all. Bounded
/// by [`MAX_PENDING_LOGINS`], so the scan under the lock costs a constant and
/// a real login is never queued behind an arbitrarily long one.
fn sweep(pending: &mut HashMap<String, LoginAttempt>, now: OffsetDateTime) {
    pending.retain(|_, attempt| now - attempt.created_at < LOGIN_STATE_LIFETIME);
}

/// How many unfinished logins `client` is holding.
///
/// A scan rather than a second map keyed by address. The map is bounded by
/// [`MAX_PENDING_LOGINS`], so this costs a constant under a lock that is only
/// ever held across arithmetic — and a second map would have to be kept
/// truthful by both the sweep and every `take`, which is two more places for
/// the two to disagree about what is in flight.
fn held_by(pending: &HashMap<String, LoginAttempt>, client: IpAddr) -> usize {
    pending
        .values()
        .filter(|attempt| attempt.client == client)
        .count()
}

/// Make room by dropping the oldest login belonging to whichever address holds
/// the most of them.
///
/// Only ever called on a map the sweep has already been over, so every entry in
/// it is still live and one of them has to go. Which one is the whole question:
/// the oldest entry outright would be a real login sitting on GitHub's consent
/// screen, which is the entry likeliest to be honest and likeliest to be spent
/// within the second. The address holding the most is the one whose next entry
/// nobody will miss, and inside it the oldest is the one with the least of its
/// ten minutes left to be worth anything.
///
/// A tie goes to whoever the iteration reaches first, deliberately: at the
/// point where several addresses are tied for the most entries in a full map,
/// there is nothing left to choose between them that is worth an allocation.
fn evict_from_the_greediest(pending: &mut HashMap<String, LoginAttempt>) {
    let mut counts: HashMap<IpAddr, usize> = HashMap::new();
    for attempt in pending.values() {
        *counts.entry(attempt.client).or_default() += 1;
    }

    let Some(greediest) = counts
        .into_iter()
        .max_by_key(|(_, held)| *held)
        .map(|(client, _)| client)
    else {
        return;
    };

    let oldest = pending
        .iter()
        .filter(|(_, attempt)| attempt.client == greediest)
        .min_by_key(|(_, attempt)| attempt.created_at)
        .map(|(state, _)| state.clone());

    if let Some(oldest) = oldest {
        pending.remove(&oldest);
    }
}

/// How long a failed redemption is held against whoever sent it.
///
/// The same ten minutes a code lives, because that is the unit the budget is
/// really about: whatever somebody can try inside one code's lifetime is what
/// they get to try against that code. It is also short enough that a client
/// who has spent its budget — including a whole office behind one address — is
/// working again within one coffee, without an operator being called.
const LOGIN_FAILURE_WINDOW: Duration = Duration::minutes(10);

/// How many failed redemptions one client address may spend in a window.
///
/// Sized for the office NAT rather than for the attacker, because the attacker
/// is hopeless at any of these numbers: twenty guesses per ten minutes against
/// a forty-bit code space is one expected hit every four hundred thousand
/// years, so the only question left is whether the number is generous enough
/// for real people. A single user cannot fail more than
/// `MAX_CODE_ATTEMPTS` times at their own code before it dies of its own
/// accord, so twenty is four users mistyping their way through an entire code
/// each, from one address, inside ten minutes.
const MAX_FAILURES_PER_CLIENT: u32 = 20;

/// How many client addresses the throttle will remember at once.
///
/// [`MAX_PENDING_LOGINS`]' argument, applied to a map an unauthenticated `POST`
/// fills: the size is a number this build chose, never one somebody else's
/// request rate chose.
///
/// Unlike the pending logins, a full map here *evicts* rather than refuses, and
/// the difference matters enough to spell out. Refusing an address the map has
/// no room for would hand any attacker the lockout this whole change exists to
/// remove: fill the map from four thousand addresses and every user whose
/// address is not already in it is refused. Evicting the window closest to
/// turning over costs almost nothing instead — the evicted address gets its
/// budget back early, and buying that back for one address means pushing four
/// thousand others through first, which is far more work than the twenty
/// guesses it returns.
const MAX_THROTTLED_CLIENTS: usize = 4096;

/// What one client has spent inside one window.
#[derive(Debug, Clone, Copy)]
struct Spent {
    failures: u32,
    /// When the window opened — at the client's first failure in it, so the
    /// window is forgotten whole rather than decaying guess by guess. Cheaper
    /// than a timestamp per failure, and the difference only ever shows up as
    /// a client getting its next budget slightly sooner.
    opened_at: OffsetDateTime,
}

impl Default for Spent {
    fn default() -> Self {
        Self {
            failures: 0,
            opened_at: OffsetDateTime::UNIX_EPOCH,
        }
    }
}

/// The failed one-time-code redemptions this spaceport has answered lately.
///
/// The other half of the code's five attempts, and the half that has to live
/// out here. A code's counter can only count guesses that hit it; somebody
/// working through the code space hits nothing, so the table never sees them
/// coming — see [`crate::auth::SessionRepository::redeem`]. This does: it
/// counts refusals per client address and, once a budget is spent, answers the
/// next one without the database being asked at all, which is the point. A
/// refusal has to be cheaper for spaceport than the guess was for whoever sent
/// it, or the throttle is itself the denial of service.
///
/// In memory and per process, like [`LoginAttempts`] and for the same reason:
/// what it holds is worth exactly one window, and a restart that forgets it
/// costs an attacker one window's budget. Bounded by
/// [`MAX_THROTTLED_CLIENTS`], swept on the way past.
#[derive(Debug, Default)]
pub struct LoginThrottle {
    spent: Mutex<Ledger>,
}

/// The throttle's whole state, behind one lock: the per-address budgets and the
/// global one. One lock rather than two, because every path reads both and a
/// pair of locks would only be a pair of chances to take them in the wrong
/// order.
#[derive(Debug, Default)]
struct Ledger {
    clients: HashMap<IpAddr, Spent>,
}

impl Ledger {
    /// Forget every window that has turned over.
    fn sweep(&mut self, now: OffsetDateTime) {
        self.clients
            .retain(|_, spent| now - spent.opened_at < LOGIN_FAILURE_WINDOW);
    }

    /// Forget the window closest to turning over, to make room for one more.
    ///
    /// Only ever called on a map the sweep has already been over, so every
    /// window in it is live and one of them has to go: the oldest is the one
    /// with the least of its budget left to give back.
    fn evict_oldest(&mut self) {
        let oldest = self
            .clients
            .iter()
            .min_by_key(|(_, spent)| spent.opened_at)
            .map(|(client, _)| *client);

        if let Some(oldest) = oldest {
            self.clients.remove(&oldest);
        }
    }
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a redemption from `client` is worth asking the database about.
    ///
    /// Asked before the code is looked at, so a client past its budget costs a
    /// lock and a hash lookup and nothing else. It is deliberately not the same
    /// call as [`LoginThrottle::charge`]: a redemption that *succeeds* must not
    /// be charged, and only the repository knows which it was. Two calls means
    /// two lock acquisitions and so a handful of concurrent requests can spend
    /// the last of a budget together — an overshoot of however many are in
    /// flight at once, against budgets in the hundreds, which is not worth
    /// holding a lock across a database call to avoid.
    fn permits(&self, client: IpAddr, now: OffsetDateTime) -> bool {
        let mut spent = self
            .spent
            .lock()
            .expect("the login throttle is never held across a panic");

        spent.sweep(now);

        match spent.clients.get(&client) {
            Some(client) => client.failures < MAX_FAILURES_PER_CLIENT,
            // An address that has not failed inside this window is owed the
            // benefit of the doubt, whatever else the map is holding. There is
            // no ceiling across addresses on purpose: one would be a lever any
            // stranger could pull to refuse everybody, which is the shape of
            // the bug this replaced. The per-address budget is enough on its
            // own — twenty guesses per address per window against a forty-bit
            // space stays hopeless however many addresses are brought to it.
            None => true,
        }
    }

    /// Charge one failed redemption to `client`.
    ///
    /// Only failures are counted, and a success neither counts nor clears: the
    /// window is short enough to forgive a real user's typos on its own, where
    /// clearing on success would hand anybody holding one working code a way to
    /// reset the budget between guesses at the next one.
    fn charge(&self, client: IpAddr, now: OffsetDateTime) {
        let mut spent = self
            .spent
            .lock()
            .expect("the login throttle is never held across a panic");

        spent.sweep(now);

        match spent.clients.get_mut(&client) {
            // Saturating, because a client that keeps knocking after its
            // budget is spent keeps being counted, and how high that goes is
            // nobody here's decision — every number past the budget means the
            // same thing.
            Some(client) => client.failures = client.failures.saturating_add(1),
            None => {
                if spent.clients.len() >= MAX_THROTTLED_CLIENTS {
                    spent.evict_oldest();
                }
                spent.clients.insert(
                    client,
                    Spent {
                        failures: 1,
                        opened_at: now,
                    },
                );
            }
        }
    }
}

/// Which client a login post is charged to: the peer address the connection
/// arrived from.
///
/// [`ConnInfo`] is attached to every request the edge's own listeners accept,
/// so the only requests without one are the ones that never crossed a socket —
/// this module's tests, today. Those are bucketed together under the
/// unspecified address rather than exempted, because "no address" must not be
/// the one way past the budget.
fn client_of(conn: Option<&ConnInfo>) -> IpAddr {
    conn.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |conn| conn.peer.ip())
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
        .route("/auth/exchange", get(exchange))
        // The literal `callback` segment outranks the `{slug}` capture in the
        // router, which is what lets the two share a prefix — the one slug a
        // connection can never start a login under is `callback`, and a GitHub
        // App could only hold that slug by being named it on github.com.
        .route("/auth/github/{slug}", get(github_start))
        .route(manifest::LOGIN_CALLBACK_PATH, get(github_callback))
        .route("/.well-known/jwks.json", get(jwks))
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

/// `GET /login`: the form that turns a one-time code into a session, and — one
/// button per GitHub connection — the way in that needs no code at all.
///
/// A `?next=` names where to go after — carried through the form in a hidden
/// field, and only ever a path this host serves: [`safe_next`] is the gate,
/// applied on the way out rather than here, so a hostile value ends up as `/`
/// instead of an error page that teaches nothing.
async fn login_page(State(home): State<Arc<Home>>, Query(query): Query<LoginQuery>) -> Response {
    let buttons = sso_buttons(&home, query.next.as_deref()).await;

    login_form(StatusCode::OK, None, query.next.as_deref(), &buttons)
}

/// The "Sign in with GitHub" buttons, one per connection, already escaped —
/// or an empty string when there are none, which leaves the page exactly the
/// page it was before SSO existed.
///
/// Each is a `GET` form to the start route with `next` in a hidden field: a
/// form so the buttons match the code form beside them, `GET` because starting
/// a login mutates nothing on this host — the state nonce is spaceport's own
/// bookkeeping, and a prefetch that spends one costs a click, not an account.
/// A connections read that fails costs the buttons and not the page: the code
/// form is a working way in, and refusing it because SSO is having trouble
/// would be the wrong door to close.
async fn sso_buttons(home: &Home, next: Option<&str>) -> String {
    let connections = match home.connections.all().await {
        Ok(connections) => connections,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "the login page could not list connections");

            return String::new();
        }
    };

    let next = match safe_next(next) {
        "/" => String::new(),
        next => format!(
            "  <input type=\"hidden\" name=\"next\" value=\"{}\">\n",
            escape(next)
        ),
    };
    // The connection's display name only when there is a choice to make: one
    // App is "GitHub" to the person clicking, two are two doors that need
    // labels.
    let named = connections.len() > 1;

    connections
        .iter()
        .map(|connection| {
            let label = match named {
                true => format!("Sign in with GitHub ({})", escape(&connection.name)),
                false => "Sign in with GitHub".to_owned(),
            };

            format!(
                "<form method=\"get\" action=\"/auth/github/{slug}\">\n{next}  \
                 <button type=\"submit\">{label}</button>\n</form>\n",
                slug = escape(&connection.slug),
            )
        })
        .collect()
}

/// `POST /login`: redeem the code, set the cookie, go where `next` says.
///
/// Every refusal renders the same sentence, whatever went wrong underneath —
/// an unknown code, a spent one, an expired one, a suspended user. The
/// repository already collapses them into one error precisely so this handler
/// *cannot* tell them apart; anything more specific would be an oracle for
/// whoever is guessing codes.
///
/// The CSRF gate stands in front, held to the same rules as the apps' — not
/// because a forged login steals a session, but because it plants one: a
/// cross-site form that signs the victim into the attacker's account makes
/// everything they then do the attacker's to read.
///
/// And [`LoginThrottle`] stands in front of the database. A code's five
/// attempts only bound guesses that hit a real code; this bounds the ones that
/// hit nothing, which is every guess an attacker working through the code space
/// makes. Past the budget the answer is assembled here and the redemption's
/// write transaction never runs — the refusal has to cost spaceport less than
/// the request cost whoever sent it.
async fn login(
    State(home): State<Arc<Home>>,
    conn: Option<Extension<ConnInfo>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Some(refusal) = super::gate::csrf_refusal(
        &http::Method::POST,
        &headers,
        home.hostname.as_deref(),
        home.https_port,
    ) {
        return refusal;
    }

    let next = form_value(&body, "next");
    let next = next.as_deref();
    let Some(code) = form_value(&body, "code").filter(|code| !code.is_empty()) else {
        let buttons = sso_buttons(&home, next).await;

        return login_form(
            StatusCode::BAD_REQUEST,
            Some("Enter the code."),
            next,
            &buttons,
        );
    };

    let client = client_of(conn.as_ref().map(|Extension(conn)| conn));
    let now = OffsetDateTime::now_utc();
    let outcome = match home.throttle.permits(client, now) {
        true => home.sessions.redeem(&Secret::new(code)).await,
        // Out of budget: the same refusal the repository would have produced,
        // produced without asking it. `debug` and not `warn`, because how
        // often this line is written is decided by whoever is knocking, and a
        // log an attacker can fill is a second denial of service.
        false => {
            debug!(%client, "a login was refused without the code being looked at");

            Err(RedeemError::Refused)
        }
    };

    match outcome {
        Ok(fresh) => session_response(&fresh, next),
        Err(RedeemError::Refused) => {
            // One refusal, whichever side it came from, all the way down to
            // the sentence: an attacker who could tell "wrong code" from "out
            // of budget" would know exactly when to stop and come back. The
            // page's SSO buttons are rendered for the same reason, so the two
            // answers are the same bytes — that read is a single indexed
            // `SELECT` with no commit behind it, which leaves the asymmetry
            // this throttle exists for intact.
            home.throttle.charge(client, now);
            let buttons = sso_buttons(&home, next).await;

            login_form(
                StatusCode::UNAUTHORIZED,
                Some("That code did not work. Check it, or ask for a new one."),
                next,
                &buttons,
            )
        }
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

/// The response every successful login travels out as, whichever door it came
/// through: the cookie set with every attribute the spec asks for, and a 303
/// to wherever `next` safely says. One function for the code redemption and
/// the SSO callback, so the two ways in cannot drift into two cookies.
fn session_response(fresh: &crate::auth::FreshSession, next: Option<&str>) -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    // 303, so the redirect is fetched with GET whatever this was.
    *response.status_mut() = StatusCode::SEE_OTHER;
    response.headers_mut().insert(
        http::header::LOCATION,
        HeaderValue::from_str(safe_next(next)).expect("a vetted path is a header value"),
    );
    match HeaderValue::from_str(&session_cookie(fresh)) {
        Ok(cookie) => {
            response
                .headers_mut()
                .insert(http::header::SET_COOKIE, cookie);

            response
        }
        // A token that will not fit in a header was never minted by this
        // build; refuse rather than redirect to a page that will only bounce
        // back here.
        Err(error) => {
            warn!(%error, "could not render the session cookie");

            problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Spaceport could not set the session cookie",
                "The login itself worked; sign in again.",
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
///
/// The CSRF gate stands in front for the same reason the confirm form does:
/// this is a cookie-authenticated POST, and a page that could sign a user out
/// cross-site is the small cousin the form already refused to be.
async fn logout(State(home): State<Arc<Home>>, headers: HeaderMap) -> Response {
    if let Some(refusal) = super::gate::csrf_refusal(
        &http::Method::POST,
        &headers,
        home.hostname.as_deref(),
        home.https_port,
    ) {
        return refusal;
    }

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
struct ExchangeQuery {
    /// Which app the exchange is for — the id, which the routing table turns
    /// back into a manifest nothing in this request can forge.
    app: Option<String>,
    /// The host the user was knocking on. Honoured only if the app's manifest
    /// lists it; anything else falls back to the manifest's first host, so
    /// this parameter can steer between an app's own domains and nowhere else.
    host: Option<String>,
    /// The path and query to land on afterwards, held to [`safe_next`]'s
    /// shape on the way out.
    next: Option<String>,
}

/// `GET /auth/exchange?app=…&host=…&next=…`: the edge-side hop of the app
/// sign-in dance.
///
/// The order of questions is the security argument. Which app, from the
/// routing table — so everything after speaks about a manifest, not about
/// request values. Who is asking, from the global session — no session means
/// the login form, with this very URL as its `next`, so finishing the login
/// resumes the exchange. Whether they may enter, from entitlements against the
/// deployed manifest's declared roles — an empty intersection is a plain "no
/// access" page and an `access.denied` event, never a nonce. Only then is the
/// nonce minted and the browser bounced to the app's own domain to redeem it.
async fn exchange(
    State(home): State<Arc<Home>>,
    headers: HeaderMap,
    Query(query): Query<ExchangeQuery>,
) -> Response {
    let Some(app_id) = query
        .app
        .as_deref()
        .and_then(|app| app.parse::<AppId>().ok())
    else {
        return problem(
            StatusCode::BAD_REQUEST,
            "This sign-in link names no app",
            "The link is incomplete. Go back to the app you were opening and try again.",
        );
    };

    // The app, from the table rather than the request. Only a *running* app
    // can finish the exchange — a suspended or down one could not serve the
    // page the user is after anyway, and the honest answer is the same one
    // its own domain would give.
    let Some(app) = home.apps.get(&app_id) else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "This app is not being served",
            "It may be suspended or down. Try again later, or ask its operator.",
        );
    };

    // The host to send the user to: theirs if the manifest lists it, the
    // manifest's first host otherwise. Either way the redirect target is a
    // name the app's own document claims — the allowlist the spec asks for.
    let host = query
        .host
        .as_deref()
        .and_then(|asked| {
            app.manifest
                .routing
                .hosts
                .iter()
                .find(|host| host.as_str() == asked)
        })
        .or_else(|| app.manifest.routing.hosts.first())
        .map(Host::as_str)
        .unwrap_or_default()
        .to_owned();
    let next = safe_next(query.next.as_deref()).to_owned();

    // An open app has no session to mint: whatever brought someone here, the
    // app's own domain answers as itself.
    let Auth::Edge { roles, .. } = &app.manifest.auth else {
        return see_other(&format!(
            "https://{}{next}",
            super::gate::authority(&host, home.https_port)
        ));
    };

    // Who is asking — the database's answer, not a cookie's.
    let session = match cookie_value(&headers, SESSION_COOKIE) {
        Some(token) => match home.sessions.session_of(&Secret::new(token)).await {
            Ok(session) => session,
            Err(error) => {
                warn!(error = %format!("{error:#}"), "the exchange could not check a session");

                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Spaceport could not check the session",
                    "Nothing was decided. Try again.",
                );
            }
        },
        None => None,
    };
    let Some((session, user)) = session else {
        // Not signed in on the edge either: the login form, with this very
        // exchange as its `next`, so the login's last redirect resumes here.
        let resume = format!(
            "/auth/exchange?app={}&host={}&next={}",
            query_encode(app_id.as_str()),
            query_encode(&host),
            query_encode(&next),
        );

        return see_other(&format!("/login?next={}", query_encode(&resume)));
    };

    // The access check: at least one entitlement for a role the *deployed*
    // manifest declares. An entitlement for a role the app never heard of is
    // stored, warned about at grant — and worth exactly nothing here.
    let held = match home.entitlements.audit(&UserRef::Id(user.clone())).await {
        Ok((_, held)) => held,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "the exchange could not read entitlements");

            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Spaceport could not check your access",
                "Nothing was decided. Try again.",
            );
        }
    };
    let entitled = held
        .iter()
        .any(|entitlement| entitlement.app == app_id && roles.contains(&entitlement.role));
    if !entitled {
        // Recorded, because a denial is the event an auditor goes looking
        // for; a plain page rather than a redirect, because there is nowhere
        // sending them that would change the answer.
        if let Err(error) = home
            .auth_log
            .record(
                "access.denied",
                Some(&user),
                WEB_ORIGIN,
                Some(&format!("no entitled role at app `{app_id}`")),
            )
            .await
        {
            warn!(error = %format!("{error:#}"), "an access denial could not be recorded");
        }

        return problem(
            StatusCode::FORBIDDEN,
            "No access",
            &format!(
                "You are signed in, and your account has no access to `{app_id}`. An operator can grant it."
            ),
        );
    }

    let nonce = match home.sessions.mint_nonce(&user, &app_id, &session).await {
        Ok(nonce) => nonce,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "the exchange could not mint a nonce");

            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Spaceport could not complete the sign-in",
                "Nothing was minted. Try again.",
            );
        }
    };

    see_other(&format!(
        "https://{}/.spaceport/callback?nonce={}&next={}",
        super::gate::authority(&host, home.https_port),
        query_encode(nonce.expose()),
        query_encode(&next),
    ))
}

/// `GET /.well-known/jwks.json`: the public keys that verify spaceport's JWTs.
///
/// Served on spaceport's own hostname only — the path the spec pins, on the
/// origin `SPACEPORT_ISSUER` names, which is what lets an app's middleware
/// derive this URL from the issuer alone. The document holds every key a
/// token in flight might carry, `kid`-disambiguated, so key rotation is
/// invisible to a verifier that re-fetches on an unknown `kid`.
///
/// `max-age=60`: JWKS reads are one per app process plus re-fetches, so the
/// cache buys almost nothing in load — what it costs is rotation latency,
/// since a verifier holding a stale document misses a brand-new key for up to
/// the max-age. A minute keeps that window smaller than any human rotation
/// runbook notices, where the five minutes a JWT lives would have made
/// rotation's first minutes a stream of refusals.
async fn jwks(State(home): State<Arc<Home>>) -> Response {
    match home.signer.jwks().await {
        Ok(document) => (
            StatusCode::OK,
            [
                (http::header::CONTENT_TYPE, "application/jwk-set+json"),
                (http::header::CACHE_CONTROL, "public, max-age=60"),
            ],
            document,
        )
            .into_response(),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "the jwks could not be served");

            // Plain text rather than a page: what is reading this is an app's
            // JWT middleware, not a person with a browser.
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "spaceport could not read its signing keys\n",
            )
                .into_response()
        }
    }
}

/// `GET /auth/github/{slug}?next=…`: start a login through the connection
/// `slug` names.
///
/// All this does on spaceport's side is remember: a state nonce binding the
/// connection and the sanitized `next`, so the callback can trust both without
/// reading either off GitHub's redirect. The browser then goes to GitHub's
/// authorize page — the written-out [`api::AUTHORIZE_ENDPOINT`], never a value
/// anything could steer — with the App's client id and the callback url the
/// manifest declared. When GitHub's own session is live the whole round trip
/// is non-interactive, which is what makes an expired spaceport session slide:
/// the bounce lands back here, mints a fresh 12h session, and the user never
/// saw a page.
async fn github_start(
    State(home): State<Arc<Home>>,
    conn: Option<Extension<ConnInfo>>,
    Path(slug): Path<String>,
    Query(query): Query<LoginQuery>,
) -> Response {
    let Some(hostname) = home.hostname.clone() else {
        return problem(
            StatusCode::NOT_FOUND,
            "This spaceport has no hostname",
            "Set `edge.hostname` in its config and restart it — without one, GitHub has no address to send a login back to.",
        );
    };

    let connection = match home.connections.by_slug(&slug).await {
        Ok(Some(connection)) => connection,
        Ok(None) => {
            return problem(
                StatusCode::NOT_FOUND,
                "This sign-in button leads nowhere",
                "No GitHub connection answers to it — it may have been disconnected. Go back to the login page and try again.",
            );
        }
        Err(error) => {
            warn!(error = %format!("{error:#}"), "a login start could not read its connection");

            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Spaceport could not start the sign-in",
                "Nothing was started. Try again.",
            );
        }
    };

    let state = match home.logins.begin(
        client_of(conn.as_deref()),
        connection.slug.clone(),
        safe_next(query.next.as_deref()).to_owned(),
        OffsetDateTime::now_utc(),
    ) {
        Ok(Some(state)) => state,
        Ok(None) => {
            // `debug!`, not `warn!`: this is an unauthenticated route, so a
            // refusal is a line anybody may ask spaceport to write, and the
            // event ring holds a few hundred. A stranger who can fill it
            // decides what an operator is still able to see, which is the same
            // argument the throttle's own refusal makes.
            debug!(
                limit = MAX_PENDING_LOGINS_PER_CLIENT,
                "a login start was refused because this client has too many in flight"
            );

            return problem(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many sign-ins are already in flight",
                "This spaceport is holding as many unfinished sign-ins for you as it will. Nothing was started. Finish one, or wait a few minutes and try again.",
            );
        }
        Err(error) => {
            warn!(error = %format!("{error:#}"), "a login start could not mint a state");

            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Spaceport could not start the sign-in",
                "Nothing was started. Try again.",
            );
        }
    };

    // The redirect_uri repeats what the manifest declared as the App's
    // callback — hostname, no port — because GitHub matches the two strings,
    // and a spaceport on an odd https port registered the portless spelling.
    see_other(&format!(
        "{}?client_id={}&redirect_uri={}&state={}",
        api::AUTHORIZE_ENDPOINT,
        query_encode(&connection.client_id),
        query_encode(&format!(
            "https://{hostname}{}",
            manifest::LOGIN_CALLBACK_PATH
        )),
        query_encode(&state),
    ))
}

#[derive(Debug, Deserialize)]
struct GithubCallback {
    /// GitHub's one-time authorization code. Optional for [`Callback`]'s
    /// reason: a browser can arrive with anything, and a missing code should
    /// be a sentence.
    code: Option<String>,
    /// The nonce this spaceport issued at the start route.
    state: Option<String>,
    /// What GitHub sends instead of a code when the person said no.
    error: Option<String>,
}

/// `GET /auth/github/callback?code=…&state=…`: GitHub has sent the person
/// back.
///
/// The state is spent before anything else is believed: it is the one proof
/// this answer belongs to a question this spaceport asked, and it carries the
/// connection and the `next` so neither is ever read off the request. Then the
/// connection's own client turns the code into a token and the token into who
/// the person is — and everything from there is [`SsoRepository::login`]'s one
/// transaction. A GitHub account no mapping rule matches is turned away here
/// without a user being made, so an unknown arrival leaves the log entry and
/// nothing else. Every refusal on the way is a sentence with the login page a
/// click away, because the person standing here is a user mid-sign-in, not an
/// operator reading a terminal.
async fn github_callback(
    State(home): State<Arc<Home>>,
    Query(query): Query<GithubCallback>,
) -> Response {
    // The state is consumed whatever else the query says — a denied login's
    // nonce is as spent as a finished one's.
    let attempt = query
        .state
        .as_deref()
        .and_then(|state| home.logins.take(state, OffsetDateTime::now_utc()));

    // The person told GitHub no. Their decision, delivered as prose rather
    // than a 500 — nothing failed, somebody declined.
    if let Some(error) = query.error.as_deref() {
        warn!(error, "a github login came back declined");

        return page(
            StatusCode::OK,
            "Sign-in cancelled",
            r#"<h1>Sign-in cancelled</h1>
<p>GitHub did not authorize the sign-in — usually because you declined it.</p>
<p><a href="/login">Back to the login page</a></p>"#,
        );
    }

    let Some(attempt) = attempt else {
        // Unknown, expired and replayed states get one answer, for
        // [`expired`]'s reason: telling them apart would be telling whoever
        // asked which states this spaceport issued.
        return problem(
            StatusCode::NOT_FOUND,
            "This sign-in attempt has expired",
            "It was never started here, has already finished, or sat for more than ten minutes. Start again from the login page at /login.",
        );
    };
    let Some(code) = query.code.filter(|code| !code.is_empty()) else {
        return problem(
            StatusCode::BAD_REQUEST,
            "GitHub sent no code",
            "Only GitHub can finish a sign-in, and it did not. Start again from the login page at /login.",
        );
    };

    let connection = match home.connections.by_slug(&attempt.connection).await {
        Ok(Some(connection)) => connection,
        Ok(None) => {
            return problem(
                StatusCode::NOT_FOUND,
                "This connection is gone",
                "The GitHub App this sign-in went out through has been disconnected. Start again from the login page at /login.",
            );
        }
        Err(error) => {
            warn!(error = %format!("{error:#}"), "a login callback could not read its connection");

            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Spaceport could not finish the sign-in",
                "Nothing was decided. Start again from the login page at /login.",
            );
        }
    };
    let client = match Client::new(&connection, home.github.clone()) {
        Ok(client) => client,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "a login callback could not build its client");

            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Spaceport could not finish the sign-in",
                "The connection's credentials would not load. An operator can check `spaceport connect list`.",
            );
        }
    };

    // The whole conversation with GitHub, as one fallible piece: the code
    // becomes a token, the token becomes who the person is and what they
    // belong to. One failure sentence for all of it, because to the person
    // standing here every variant means the same thing — start again.
    let asked = async {
        let token = client.exchange_user_code(&code).await?;
        let user = client.user(&token).await?;
        let orgs = client.user_orgs(&token).await?;
        let teams = client.user_teams(&token).await?;

        anyhow::Ok((token, user, orgs, teams))
    }
    .await;
    let (token, user, orgs, teams) = match asked {
        Ok(answers) => answers,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "a github login could not be read back");

            return problem(
                StatusCode::BAD_GATEWAY,
                "GitHub would not finish the sign-in",
                "The code may have expired or already been used. Start again from the login page at /login.",
            );
        }
    };

    // The snapshot the mapping rules are judged against. Teams land twice on
    // purpose: bare (`authors`) because that is the spelling the spec's
    // `team=authors` example writes, and qualified (`acme-corp/authors`) so an
    // operator whose organisations reuse a slug can disambiguate — containment
    // matching means both rules find their value in the same list.
    let mut attributes = crate::auth::Attributes::new();
    attributes.insert("login".to_owned(), vec![user.login.clone()]);
    if !orgs.is_empty() {
        attributes.insert("org".to_owned(), orgs);
    }
    if !teams.is_empty() {
        let mut values: Vec<String> = teams
            .iter()
            .map(|team| format!("{}/{}", team.org, team.slug))
            .collect();
        for team in &teams {
            if !values.contains(&team.slug) {
                values.push(team.slug.clone());
            }
        }
        attributes.insert("team".to_owned(), values);
    }

    // What GitHub calls this person, which is a different question from who
    // they are and is answered separately on purpose. The addresses are read
    // here — `/user/emails`, under the App's `emails: read` — and what is taken
    // from them is the primary *verified* one and nothing else. That is not the
    // resolution-by-email this flow used to do: nothing below looks a user up
    // by this address, `users.email` is not written from it, and no mapping
    // rule can be aimed at it. It is stored against the identity as a claim
    // GitHub made, so that the next slice can hand an app a name to greet
    // somebody by.
    //
    // Outside the block above, and failing softly, because a profile is not
    // worth a sign-in. GitHub having a bad minute on this one endpoint, or an
    // installation whose email permission an operator narrowed after the fact,
    // must leave the person signed in with no profile rather than staring at a
    // bad-gateway page — the identity, the entitlements and the session do not
    // depend on it. The warning is what an operator reads if the profiles
    // stopped arriving.
    let profile = crate::auth::IdpProfile {
        name: user.name.clone(),
        email: match client.user_emails(&token).await {
            Ok(emails) => {
                crate::connections::github::api::primary_verified(&emails).map(str::to_owned)
            }
            Err(error) => {
                warn!(
                    error = %format!("{error:#}"),
                    login = %user.login,
                    "a github login's addresses would not read; signing in without a profile address"
                );

                None
            }
        },
    };

    let outcome = home
        .sso
        .login(SsoLogin {
            connection: connection.slug,
            external_id: user.id.to_string(),
            external_login: user.login,
            attributes,
            profile,
        })
        .await;

    match outcome {
        Ok(SsoOutcome::SignedIn(fresh)) => session_response(&fresh, Some(&attempt.next)),
        Ok(SsoOutcome::Suspended(user)) => problem(
            StatusCode::FORBIDDEN,
            "This account is suspended",
            &format!(
                "GitHub signed you in, and the spaceport account `{}` it belongs to is suspended. An operator can resume it.",
                user.slug
            ),
        ),
        Ok(SsoOutcome::Unmapped) => problem(
            StatusCode::FORBIDDEN,
            "This spaceport has no account for you",
            "GitHub confirmed who you are, but there is no account here for you and no mapping rule that would make one. An operator has to add a mapping rule that matches you, or create the account, before you can sign in. Once they have, start again from the login page at /login.",
        ),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "an sso login could not be recorded");

            problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Spaceport could not finish the sign-in",
                "GitHub answered and this spaceport could not record the login. Nothing was decided; start again from the login page at /login.",
            )
        }
    }
}

/// A 303 to `location`: fetched with GET whatever this was.
fn see_other(location: &str) -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(http::header::LOCATION, value);
    }

    response
}

#[derive(Debug, Deserialize)]
struct LoginQuery {
    /// Where to land after the login, when the request that bounced here says.
    next: Option<String>,
}

/// The login form, with `error` above it when the last attempt failed, `next`
/// carried through a hidden field, and `buttons` — the pre-rendered, already
/// escaped SSO forms from [`sso_buttons`], or nothing — below it. The code
/// input turns autocomplete and its relatives off because a one-time code is
/// the one value a browser must not helpfully remember.
fn login_form(
    status: StatusCode,
    error: Option<&str>,
    next: Option<&str>,
    buttons: &str,
) -> Response {
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
</form>
{buttons}"#
        ),
    )
}

/// The longest `next` worth carrying.
///
/// Part of the shape and not a separate concern: a `next` is remembered in
/// [`LoginAttempts`], which an unauthenticated request writes to, so its length
/// is the size of an entry somebody else chooses. Half a kilobyte is a roomy
/// path and query for any app spaceport fronts and keeps a full map's worst
/// case in the low megabytes.
const MAX_NEXT: usize = 512;

/// Where a finished login may be sent: `next` when it is a plain absolute path
/// on this host, `/` otherwise.
///
/// The rules are deny-by-shape rather than a parse: it must start with `/`,
/// must not start with `//` (which a browser reads as scheme-relative and
/// sends to another host), must not contain `\` (which some browsers
/// normalise into `/` and turn `/\evil.example` back into the previous case),
/// and must fit in [`MAX_NEXT`]. Anything with a scheme fails the leading-`/`
/// test already. The fallback is `/` and never an error, because the value
/// arrives on urls users share and a broken link should still land them
/// somewhere signed in.
pub(super) fn safe_next(next: Option<&str>) -> &str {
    match next {
        Some(next)
            if next.starts_with('/')
                && !next.starts_with("//")
                && !next.contains('\\')
                && next.len() <= MAX_NEXT =>
        {
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
pub(super) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
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
            sessions: Arc::new(SessionRepository::new(db.clone())),
            entitlements: Arc::new(EntitlementRepository::new(db.clone())),
            auth_log: Arc::new(AuthLogRepository::new(db.clone())),
            apps: Arc::new(AppStore::new()),
            signer: Arc::new(crate::auth::JwtSigner::new(db.clone())),
            jwt_cache: Arc::new(crate::auth::JwtCache::new()),
            https_port: 443,
            logins: Arc::new(LoginAttempts::new()),
            throttle: Arc::new(LoginThrottle::new()),
            sso: Arc::new(SsoRepository::new(db.clone())),
            identities: Arc::new(crate::auth::IdentityRepository::new(db)),
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

    /// The JWKS is served where the spec pins it — the well-known path on
    /// spaceport's own host — in the JWK Set media type, cacheable for the
    /// minute the handler's rotation-latency comment argues, and holding the
    /// OKP key an app verifies with.
    #[tokio::test]
    async fn serves_the_jwks_on_the_well_known_path() {
        let response = router(plain_home())
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["content-type"],
            "application/jwk-set+json"
        );
        assert_eq!(response.headers()["cache-control"], "public, max-age=60");

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let key = &jwks["keys"][0];
        assert_eq!(key["kty"], "OKP");
        assert_eq!(key["crv"], "Ed25519");
        assert!(key["kid"].as_str().unwrap().contains('-'), "{jwks}");
        assert!(!key["x"].as_str().unwrap().is_empty(), "{jwks}");
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
        let (home, users, _) = exchange_home(Arc::new(AppStore::new()));

        (home, users)
    }

    /// The same, over a routing table the test controls — what the exchange
    /// tests steer apps into — with the entitlement repository to grant with.
    fn exchange_home(
        apps: Arc<AppStore>,
    ) -> (
        Arc<Home>,
        crate::auth::UserRepository,
        Arc<EntitlementRepository>,
    ) {
        let db = Db::in_memory().unwrap();
        let entitlements = Arc::new(EntitlementRepository::new(db.clone()));
        let home = Arc::new(Home {
            attempts: Arc::new(Attempts::new()),
            connections: Arc::new(ConnectionRepository::new(db.clone())),
            tracking: Arc::new(TrackingRepository::new(db.clone())),
            github: FakeGitHub::new(),
            nudge: Nudge::new(),
            builds: Nudge::new(),
            hostname: Some(HOSTNAME.to_owned()),
            sessions: Arc::new(SessionRepository::new(db.clone())),
            entitlements: entitlements.clone(),
            auth_log: Arc::new(AuthLogRepository::new(db.clone())),
            apps,
            signer: Arc::new(crate::auth::JwtSigner::new(db.clone())),
            jwt_cache: Arc::new(crate::auth::JwtCache::new()),
            https_port: 443,
            logins: Arc::new(LoginAttempts::new()),
            throttle: Arc::new(LoginThrottle::new()),
            sso: Arc::new(SsoRepository::new(db.clone())),
            identities: Arc::new(crate::auth::IdentityRepository::new(db.clone())),
        });

        (home, crate::auth::UserRepository::new(db), entitlements)
    }

    /// A code as the operator socket would have minted one, exposed for the
    /// form to type.
    async fn minted_code(home: &Home, users: &crate::auth::UserRepository, slug: &str) -> String {
        users
            .create(&slug.parse().unwrap(), None, None)
            .await
            .unwrap();

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

    /// One form submission at `path`, as a browser would send it — fetch
    /// metadata included, since a browser posting its own page's form always
    /// says `same-origin` and the CSRF gate now insists on hearing it.
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
                    .header("sec-fetch-site", "same-origin")
                    .body(Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// The same submission, from a named client address — what the edge's
    /// listeners attach to every request they accept, and what the throttle
    /// counts against.
    async fn post_form_from(
        home: Arc<Home>,
        path: &str,
        body: &str,
        peer: &str,
    ) -> http::Response<Body> {
        router(home)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .header("sec-fetch-site", "same-origin")
                    .extension(ConnInfo {
                        peer: peer.parse().unwrap(),
                        scheme: crate::edge::Scheme::Https,
                    })
                    .body(Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Every wrong guess one client is allowed, so the next request from it
    /// meets the throttle rather than the database.
    async fn spend_the_budget(home: &Arc<Home>, peer: &str) {
        for _ in 0..MAX_FAILURES_PER_CLIENT {
            let response = post_form_from(home.clone(), "/login", "code=wrongcod", peer).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
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

    /// Past its budget a client is refused without the code being looked at —
    /// which the *good* code proves: it is submitted, it is refused, and it is
    /// still sitting unspent in the table afterwards, so nothing about it was
    /// read or written. That is the property the throttle exists for; a
    /// refusal that still cost a transaction and an fsync would be no defence.
    #[tokio::test]
    async fn a_client_past_its_budget_is_refused_without_the_code_being_checked() {
        let (home, users) = auth_home();
        let code = minted_code(&home, &users, "alice").await;
        spend_the_budget(&home, "203.0.113.7:54321").await;

        let response = post_form_from(
            home.clone(),
            "/login",
            &format!("code={code}"),
            "203.0.113.7:9",
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(http::header::SET_COOKIE).is_none());
        // Untouched: the repository, asked directly, still redeems it.
        assert!(home.sessions.redeem(&Secret::new(code)).await.is_ok());
    }

    /// And the refusal says nothing about which refusal it was. An attacker who
    /// could tell "wrong code" from "out of budget" would know exactly when to
    /// stop and come back.
    #[tokio::test]
    async fn a_refusal_past_the_budget_reads_like_any_other_refusal() {
        let (home, _) = auth_home();
        let ordinary =
            post_form_from(home.clone(), "/login", "code=wrongcod", "203.0.113.7:1").await;
        let ordinary = (
            ordinary.status(),
            ordinary.into_body().collect().await.unwrap().to_bytes(),
        );

        spend_the_budget(&home, "203.0.113.7:2").await;
        let throttled =
            post_form_from(home.clone(), "/login", "code=wrongcod", "203.0.113.7:3").await;
        let throttled = (
            throttled.status(),
            throttled.into_body().collect().await.unwrap().to_bytes(),
        );

        assert_eq!(throttled, ordinary);
    }

    /// The budget is per address, so somebody else's guessing is not a user's
    /// problem: a good code from a client that has failed nothing still signs
    /// in, however much the neighbour has been knocking.
    #[tokio::test]
    async fn a_good_code_still_works_after_another_clients_failures() {
        let (home, users) = auth_home();
        let code = minted_code(&home, &users, "alice").await;
        spend_the_budget(&home, "203.0.113.7:54321").await;

        let response =
            post_form_from(home, "/login", &format!("code={code}"), "198.51.100.4:443").await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(
            response.headers()[http::header::SET_COOKIE]
                .to_str()
                .unwrap()
                .starts_with("__Host-spaceport-session=")
        );
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
        let (_, listed, _) = home
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
                    .header("sec-fetch-site", "same-origin")
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
        let (_, listed, _) = home
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

    /// The edge's own forms are held to the same CSRF rules as the apps':
    /// another site's POST to `/login` would plant the attacker's session,
    /// and to `/logout` would sign the victim out — both die at the gate,
    /// whether the browser said `cross-site` or said nothing at all.
    #[tokio::test]
    async fn a_cross_site_post_to_login_or_logout_is_refused() {
        for path in ["/login", "/logout"] {
            for hostile in [
                &[("sec-fetch-site", "cross-site")][..],
                &[("origin", "https://evil.example")][..],
                &[][..],
            ] {
                let (home, users) = auth_home();
                let code = minted_code(&home, &users, "alice").await;

                let mut request = Request::builder().method("POST").uri(path).header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                );
                for (name, value) in hostile {
                    request = request.header(*name, *value);
                }
                let response = router(home.clone())
                    .oneshot(request.body(Body::from(format!("code={code}"))).unwrap())
                    .await
                    .unwrap();

                assert_eq!(
                    response.status(),
                    StatusCode::FORBIDDEN,
                    "{path} {hostile:?}"
                );
                // And the code is still unspent: nothing was redeemed on the
                // way to the refusal.
                assert!(
                    post_form(home, "/login", &format!("code={code}"))
                        .await
                        .status()
                        .is_redirection(),
                    "{path} {hostile:?}"
                );
            }
        }
    }

    /// The fallback for clients without fetch metadata: an `Origin` naming
    /// this very host passes the form through.
    #[tokio::test]
    async fn a_login_post_with_a_matching_origin_and_no_fetch_metadata_passes() {
        let (home, users) = auth_home();
        let code = minted_code(&home, &users, "alice").await;

        let response = router(home)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .header(http::header::ORIGIN, format!("https://{HOSTNAME}"))
                    .body(Body::from(format!("code={code}")))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    /// A gated app for the routing table, in the shape the proxy tests use.
    fn gated_app(id: &str, hosts: &str, roles: &str) -> crate::app::App {
        crate::app::App {
            id: id.parse().unwrap(),
            manifest: crate::AppManifest::parse(&format!(
                "schema_version: 1\nsource:\n  type: image\n  image: x\nrouting:\n  hosts: [{hosts}]\nauth:\n  gating: edge\n  roles: [{roles}]\n"
            ))
            .unwrap(),
            container: crate::runtime::ContainerId::new("test-container"),
            upstream: "127.0.0.1:1".parse().unwrap(),
        }
    }

    /// A signed-in browser's cookie header, made the way the login page makes
    /// one.
    async fn session_cookie_for(home: &Arc<Home>, users: &crate::auth::UserRepository) -> String {
        let code = minted_code(home, users, "alice").await;
        let login = post_form(home.clone(), "/login", &format!("code={code}")).await;

        login.headers()[http::header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    async fn get_exchange(home: Arc<Home>, path: &str, cookie: Option<&str>) -> Response {
        let mut request = Request::builder().uri(path);
        if let Some(cookie) = cookie {
            request = request.header(http::header::COOKIE, cookie);
        }

        router(home)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    const EXCHANGE: &str = "/auth/exchange?app=blog&host=alpha.test&next=%2Fposts%3Fq%3D1";

    /// Without a global session the exchange is a login form away, and the
    /// form's `next` is the exchange itself — finishing the login resumes it.
    #[tokio::test]
    async fn the_exchange_sends_a_stranger_to_login_and_completes_after_it() {
        let apps = Arc::new(AppStore::new());
        apps.insert(gated_app("blog", "alpha.test", "reader"))
            .unwrap();
        let (home, users, entitlements) = exchange_home(apps);
        users
            .create(&"alice".parse().unwrap(), None, None)
            .await
            .unwrap();
        entitlements
            .grant(
                &crate::auth::UserRef::Slug("alice".parse().unwrap()),
                &"reader@blog".parse().unwrap(),
            )
            .await
            .unwrap();

        let response = get_exchange(home.clone(), EXCHANGE, None).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let login = response.headers()[http::header::LOCATION].to_str().unwrap();
        assert!(login.starts_with("/login?next="), "{login}");

        // The login form carries that next through, and redeeming a code
        // lands back on the exchange...
        let code = home
            .sessions
            .mint_code(
                &crate::auth::UserRef::Slug("alice".parse().unwrap()),
                crate::auth::DEFAULT_SESSION_LIFETIME,
            )
            .await
            .unwrap();
        // The hidden field travels back form-encoded, as a browser would send
        // it — which is what keeps the nested encoding intact.
        let next = form_decode(login.strip_prefix("/login?next=").unwrap());
        let login = post_form(
            home.clone(),
            "/login",
            &format!("code={}&next={}", code.code.expose(), query_encode(&next)),
        )
        .await;
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let resumed = login.headers()[http::header::LOCATION].to_str().unwrap();
        assert!(resumed.starts_with("/auth/exchange?app=blog"), "{resumed}");
        let cookie = login.headers()[http::header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        // ...which, now signed in, bounces to the app's own callback with a
        // nonce and the original path and query intact.
        let response = get_exchange(home, resumed, Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let callback = response.headers()[http::header::LOCATION].to_str().unwrap();
        assert!(
            callback.starts_with("https://alpha.test/.spaceport/callback?nonce="),
            "{callback}"
        );
        assert!(callback.ends_with("&next=%2Fposts%3Fq%3D1"), "{callback}");
    }

    /// Signed in and not entitled is a page, not a redirect: nowhere the
    /// browser could be sent would change the answer — and the denial is the
    /// event an auditor goes looking for, so it is in the log.
    #[tokio::test]
    async fn the_exchange_refuses_a_user_with_no_entitlement_and_records_it() {
        let apps = Arc::new(AppStore::new());
        apps.insert(gated_app("blog", "alpha.test", "reader"))
            .unwrap();
        let (home, users, _) = exchange_home(apps);
        let cookie = session_cookie_for(&home, &users).await;

        let response = get_exchange(home.clone(), EXCHANGE, Some(&cookie)).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            String::from_utf8(body.to_vec())
                .unwrap()
                .contains("No access")
        );
        let entries = home.auth_log.entries(None).await.unwrap();
        assert!(entries.iter().any(|entry| entry.kind == "access.denied"
            && entry.detail.as_deref() == Some("no entitled role at app `blog`")),);
    }

    /// An entitlement the manifest does not declare opens nothing: the spec
    /// stores it, warns at grant, and the exchange values it at exactly zero.
    #[tokio::test]
    async fn an_entitlement_for_an_undeclared_role_grants_no_access() {
        let apps = Arc::new(AppStore::new());
        apps.insert(gated_app("blog", "alpha.test", "reader"))
            .unwrap();
        let (home, users, entitlements) = exchange_home(apps);
        let cookie = session_cookie_for(&home, &users).await;
        entitlements
            .grant(
                &crate::auth::UserRef::Slug("alice".parse().unwrap()),
                &"editor@blog".parse().unwrap(),
            )
            .await
            .unwrap();

        let response = get_exchange(home, EXCHANGE, Some(&cookie)).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// The redirect target is allowlisted to the app's manifest: a host the
    /// manifest never claimed falls back to one it did, and the path is held
    /// to the same shape a login `next` is.
    #[tokio::test]
    async fn the_exchange_only_redirects_to_hosts_the_manifest_claims() {
        let apps = Arc::new(AppStore::new());
        apps.insert(gated_app("blog", "alpha.test", "reader"))
            .unwrap();
        let (home, users, entitlements) = exchange_home(apps);
        let cookie = session_cookie_for(&home, &users).await;
        entitlements
            .grant(
                &crate::auth::UserRef::Slug("alice".parse().unwrap()),
                &"reader@blog".parse().unwrap(),
            )
            .await
            .unwrap();

        let response = get_exchange(
            home,
            "/auth/exchange?app=blog&host=evil.example&next=%2F%2Fevil.example",
            Some(&cookie),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[http::header::LOCATION].to_str().unwrap();
        assert!(
            location.starts_with("https://alpha.test/.spaceport/callback?nonce="),
            "{location}"
        );
        // The scheme-relative `next` was replaced by the fallback `/`.
        assert!(location.ends_with("&next=%2F"), "{location}");
    }

    /// An open app has no session to mint, whoever asks: the exchange simply
    /// hands the browser back to the app's own domain.
    #[tokio::test]
    async fn the_exchange_sends_an_open_apps_visitor_straight_back() {
        let apps = Arc::new(AppStore::new());
        apps.insert(crate::app::App {
            id: "blog".parse().unwrap(),
            manifest: crate::AppManifest::parse(
                "schema_version: 1\nsource:\n  type: image\n  image: x\nrouting:\n  hosts: [alpha.test]\nauth:\n  gating: open\n",
            )
            .unwrap(),
            container: crate::runtime::ContainerId::new("test-container"),
            upstream: "127.0.0.1:1".parse().unwrap(),
        })
        .unwrap();
        let (home, _, _) = exchange_home(apps);

        let response = get_exchange(home, EXCHANGE, None).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[http::header::LOCATION],
            "https://alpha.test/posts?q=1"
        );
    }

    /// An app nothing serves cannot finish an exchange, and the page says why
    /// in the words its own domain would use.
    #[tokio::test]
    async fn the_exchange_answers_for_an_app_that_is_not_served() {
        let (home, _, _) = exchange_home(Arc::new(AppStore::new()));

        let response = get_exchange(home, EXCHANGE, None).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
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

    /// A home whose GitHub can sign the scripted person in, with every
    /// repository the SSO assertions read handed back over the same database.
    fn sso_home() -> (Arc<Home>, Arc<FakeGitHub>, Db) {
        let github = FakeGitHub::new();
        let db = Db::in_memory().unwrap();
        let home = Arc::new(Home {
            attempts: Arc::new(Attempts::new()),
            connections: Arc::new(ConnectionRepository::new(db.clone())),
            tracking: Arc::new(TrackingRepository::new(db.clone())),
            github: github.clone(),
            nudge: Nudge::new(),
            builds: Nudge::new(),
            hostname: Some(HOSTNAME.to_owned()),
            sessions: Arc::new(SessionRepository::new(db.clone())),
            entitlements: Arc::new(EntitlementRepository::new(db.clone())),
            auth_log: Arc::new(AuthLogRepository::new(db.clone())),
            apps: Arc::new(AppStore::new()),
            signer: Arc::new(crate::auth::JwtSigner::new(db.clone())),
            jwt_cache: Arc::new(crate::auth::JwtCache::new()),
            https_port: 443,
            logins: Arc::new(LoginAttempts::new()),
            throttle: Arc::new(LoginThrottle::new()),
            sso: Arc::new(SsoRepository::new(db.clone())),
            identities: Arc::new(crate::auth::IdentityRepository::new(db.clone())),
        });

        (home, github, db)
    }

    /// A connection whose key can actually sign, unlike [`connect`]'s fixture
    /// PEM: the login callback builds a real [`Client`] out of the row, and a
    /// key that will not parse would fail the flow before GitHub was asked
    /// anything.
    async fn connect_for_login(home: &Home) {
        home.connections
            .record(&Connection {
                slug: "spaceport-for-acme".to_owned(),
                app_id: 42,
                name: "Spaceport for Acme".to_owned(),
                owner: "an-organisation".to_owned(),
                // The OAuth client the fake's code exchange verifies against.
                client_id: "Iv1.0123456789abcdef".to_owned(),
                client_secret: Secret::new("a-client-secret"),
                webhook_secret: Secret::new("a-webhook-secret"),
                private_key: Secret::new(crate::connections::github::key::testing::PKCS1),
                connected_at: String::new(),
            })
            .await
            .unwrap();
    }

    /// Walk the start route and hand back the state GitHub would echo, read
    /// out of the authorize redirect the way GitHub reads it.
    async fn started(home: Arc<Home>, path: &str) -> String {
        let response = router(home)
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[http::header::LOCATION]
            .to_str()
            .unwrap()
            .to_owned();

        location
            .rsplit_once("state=")
            .expect("the authorize url carries a state")
            .1
            .to_owned()
    }

    /// One callback fetch, as GitHub's redirect would make it.
    async fn callback_with(home: Arc<Home>, query: &str) -> http::Response<Body> {
        router(home)
            .oneshot(
                Request::builder()
                    .uri(format!("{}?{query}", manifest::LOGIN_CALLBACK_PATH))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Zero connections leave the login page exactly the page it was — no
    /// button, no mention of GitHub at all.
    #[tokio::test]
    async fn the_login_page_offers_no_github_without_a_connection() {
        let (status, body) = get_path(auth_home().0, "/login").await;

        assert_eq!(status, StatusCode::OK);
        assert!(!body.to_lowercase().contains("github"), "{body}");
    }

    /// One connection is one button, posting nowhere but the start route —
    /// with the code form still beside it, untouched.
    #[tokio::test]
    async fn the_login_page_offers_github_per_connection() {
        let (home, _, _) = sso_home();
        connect_for_login(&home).await;

        let (status, body) = get_path(home, "/login?next=%2Fwiki").await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains(r#"action="/auth/github/spaceport-for-acme""#),
            "{body}"
        );
        assert!(body.contains("Sign in with GitHub"), "{body}");
        // The `next` rides along in the button's form too.
        assert!(
            body.contains(r#"<input type="hidden" name="next" value="/wiki">"#),
            "{body}"
        );
        // And the code form is exactly as it was.
        assert!(body.contains(r#"<input name="code""#), "{body}");
    }

    /// The start route's whole job: remember, then hand the browser to the
    /// written-out authorize endpoint with the App's client id, the callback
    /// the manifest declared, and a state — never anything read off the
    /// request.
    #[tokio::test]
    async fn starting_a_login_redirects_to_githubs_authorize_page() {
        let (home, _, _) = sso_home();
        connect_for_login(&home).await;

        let response = router(home)
            .oneshot(
                Request::builder()
                    .uri("/auth/github/spaceport-for-acme?next=%2Fwiki")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[http::header::LOCATION].to_str().unwrap();
        assert!(
            location.starts_with(
                "https://github.com/login/oauth/authorize?client_id=Iv1.0123456789abcdef"
            ),
            "{location}"
        );
        assert!(
            location.contains(&format!(
                "redirect_uri=https%3A%2F%2F{HOSTNAME}%2Fauth%2Fgithub%2Fcallback"
            )),
            "{location}"
        );
        assert!(location.contains("&state="), "{location}");
    }

    /// A start aimed at no connection is a sentence, not a bounce to GitHub
    /// with credentials that belong to nobody.
    #[tokio::test]
    async fn starting_a_login_through_an_unknown_connection_is_refused() {
        let (home, _, _) = sso_home();

        let (status, body) = get_path(home, "/auth/github/ghost").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("No GitHub connection"), "{body}");
    }

    /// The happy path, end to end through the real router: the button leads to
    /// GitHub, the callback finds the operator-made user by the GitHub account
    /// bound to it, records the snapshot, re-syncs the mapped entitlement, sets
    /// the session cookie exactly as the code form does, and lands on `next`.
    #[tokio::test]
    async fn a_github_login_reaches_its_linked_user_and_lands_signed_in() {
        let (home, github, db) = sso_home();
        connect_for_login(&home).await;
        github.signs_in("a-login-code", "ghu_a-user-token", 1001, "octocat");
        github.user_belongs_to_orgs(&["acme-corp"]);
        github.user_belongs_to_teams(&[("acme-corp", "authors")]);
        github.user_is_called("Mona Lisa");
        // Three addresses, of which exactly one is both primary and verified —
        // so a profile that picked by either flag alone would pick a different
        // one and this test would say so.
        github.user_emails_in_pages(&[&[
            ("old@example.com", true, false),
            ("mona@acme.example", true, true),
            ("typo@example.com", false, false),
        ]]);
        let users = crate::auth::UserRepository::new(db.clone());
        let alice = users
            .create(&"alice".parse().unwrap(), None, None)
            .await
            .unwrap();
        crate::auth::IdentityRepository::new(db.clone())
            .record(
                &alice.id,
                "spaceport-for-acme",
                "1001",
                "octocat",
                &Default::default(),
                &Default::default(),
            )
            .await
            .unwrap();
        // A rule matched through the *bare* team spelling, which is the spec's
        // own `team=authors` example.
        let mappings = crate::auth::MappingRepository::new(db.clone());
        let rule = mappings
            .add(
                "spaceport-for-acme",
                &"reader@blog".parse().unwrap(),
                &["team=authors".parse().unwrap()],
            )
            .await
            .unwrap();

        let state = started(
            home.clone(),
            "/auth/github/spaceport-for-acme?next=%2Fwiki%3Fq%3D1",
        )
        .await;
        let response =
            callback_with(home.clone(), &format!("code=a-login-code&state={state}")).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[http::header::LOCATION], "/wiki?q=1");
        let cookie = response.headers()[http::header::SET_COOKIE]
            .to_str()
            .unwrap();
        assert!(cookie.starts_with("__Host-spaceport-session="), "{cookie}");
        for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/", "Max-Age="] {
            assert!(cookie.contains(attribute), "{cookie}");
        }
        // No second user was made: the bound account named alice, whose
        // snapshot now carries the login, the org, and the team both ways.
        assert_eq!(users.list(None).await.unwrap().len(), 1);
        let identities = crate::auth::IdentityRepository::new(db.clone());
        let held = identities.for_user(&alice.id).await.unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].external_id, "1001");
        assert_eq!(held[0].attributes["login"], ["octocat"]);
        assert_eq!(held[0].attributes["org"], ["acme-corp"]);
        assert_eq!(held[0].attributes["team"], ["acme-corp/authors", "authors"]);
        // And what github calls her, beside the identity that asserted it: the
        // display name, and the one address that was primary *and* verified.
        assert_eq!(held[0].profile.name.as_deref(), Some("Mona Lisa"));
        assert_eq!(held[0].profile.email.as_deref(), Some("mona@acme.example"));
        // Which is emphatically not her credential: `users.email` is what the
        // email connection signs somebody in by, and a github login does not
        // get to mint one.
        assert_eq!(users.list(None).await.unwrap()[0].email, None);
        // Nor is it something a mapping rule could ever be aimed at.
        assert!(!held[0].attributes.contains_key("email"), "");
        // The mapped entitlement arrived, tagged with its rule.
        let (_, entitled) = home
            .entitlements
            .audit(&UserRef::Id(alice.id.clone()))
            .await
            .unwrap();
        assert_eq!(entitled.len(), 1);
        assert_eq!(entitled[0].role.as_str(), "reader");
        assert_eq!(
            entitled[0].mapped_rule.as_deref(),
            Some(rule.rule_id.as_str())
        );
        // And the login is in the log with the connection as its origin.
        let entries = home.auth_log.entries(None).await.unwrap();
        assert!(
            entries.iter().any(
                |entry| entry.kind == "login.succeeded" && entry.origin == "spaceport-for-acme"
            ),
            "{entries:?}"
        );
    }

    /// Through the router, the rule that replaced email linking: an address
    /// GitHub asserts as *verified* — the strongest thing it can say about a
    /// mailbox — still reaches nobody. The login makes a fresh `github:` user
    /// rather than handing over the account recorded under that address, and
    /// the address is not copied onto the new record either, because the
    /// mailbox is the email connection's credential and this login proved
    /// nothing about it.
    #[tokio::test]
    async fn a_verified_email_creates_a_user_rather_than_linking() {
        let (home, github, db) = sso_home();
        connect_for_login(&home).await;
        github.signs_in("a-login-code", "ghu_a-user-token", 1001, "octocat");
        github.user_emails_in_pages(&[&[("octocat@acme.example", true, true)]]);
        let users = crate::auth::UserRepository::new(db.clone());
        let alice = users
            .create(
                &"alice".parse().unwrap(),
                Some("octocat@acme.example"),
                None,
            )
            .await
            .unwrap();
        // Auto-creation is gated on a rule matching, so a test about what the
        // email does has to get past that gate first: the login attribute the
        // callback always plants is the cheapest thing to match on.
        crate::auth::MappingRepository::new(db.clone())
            .add(
                "spaceport-for-acme",
                &"reader@blog".parse().unwrap(),
                &["login=octocat".parse().unwrap()],
            )
            .await
            .unwrap();

        let state = started(home.clone(), "/auth/github/spaceport-for-acme").await;
        let response =
            callback_with(home.clone(), &format!("code=a-login-code&state={state}")).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let listed = users.list(None).await.unwrap();
        assert_eq!(listed.len(), 2);
        let minted = listed.iter().find(|user| user.id != alice.id).unwrap();
        assert_eq!(minted.slug.as_str(), "github:octocat");
        // The address was not stored either: a record carrying it would hand
        // this account a way in through the email connection that spaceport
        // never verified and GitHub cannot revoke.
        assert_eq!(minted.email, None);
        // Alice keeps hers, unlinked and untouched.
        assert_eq!(
            listed
                .iter()
                .find(|user| user.id == alice.id)
                .unwrap()
                .email,
            Some("octocat@acme.example".to_owned())
        );
        // The callback did read the addresses — a profile needs one — and what
        // it did with the answer is the whole point: the same address that is
        // alice's *credential* is, over here, a claim recorded against the new
        // user's github identity and nothing more. It resolved nobody.
        let asked: Vec<String> = github
            .requests()
            .into_iter()
            .map(|request| request.path)
            .collect();
        assert!(
            asked.iter().any(|path| path.contains("/user/emails")),
            "{asked:?}"
        );
        let held = crate::auth::IdentityRepository::new(db)
            .for_user(&minted.id)
            .await
            .unwrap();
        assert_eq!(
            held[0].profile.email.as_deref(),
            Some("octocat@acme.example")
        );
    }

    /// The returning-identity rule through the router: a recorded identity
    /// names its user even when somebody else now holds the matching email.
    #[tokio::test]
    async fn a_returning_identity_wins_over_a_matching_email() {
        let (home, github, db) = sso_home();
        connect_for_login(&home).await;
        github.signs_in("a-login-code", "ghu_a-user-token", 1001, "octocat");
        let users = crate::auth::UserRepository::new(db.clone());
        let carol = users
            .create(&"carol".parse().unwrap(), None, None)
            .await
            .unwrap();
        crate::auth::IdentityRepository::new(db.clone())
            .record(
                &carol.id,
                "spaceport-for-acme",
                "1001",
                "octocat",
                &Default::default(),
                &Default::default(),
            )
            .await
            .unwrap();
        users
            .create(&"eve".parse().unwrap(), Some("octocat@acme.example"), None)
            .await
            .unwrap();

        let state = started(home.clone(), "/auth/github/spaceport-for-acme").await;
        callback_with(home.clone(), &format!("code=a-login-code&state={state}")).await;

        // Carol holds the fresh session; eve holds nothing.
        let (_, carols, _) = home
            .sessions
            .list(&UserRef::Id(carol.id.clone()))
            .await
            .unwrap();
        assert_eq!(carols.len(), 1);
        let (_, eves, _) = home
            .sessions
            .list(&UserRef::Slug("eve".parse().unwrap()))
            .await
            .unwrap();
        assert!(eves.is_empty());
    }

    /// A suspended user's bounce comes back as refusal prose and a logged
    /// denial — no session, no cookie, no snapshot movement.
    #[tokio::test]
    async fn a_suspended_users_github_login_is_refused_and_logged() {
        let (home, github, db) = sso_home();
        connect_for_login(&home).await;
        github.signs_in("a-login-code", "ghu_a-user-token", 1001, "octocat");
        let users = crate::auth::UserRepository::new(db.clone());
        let alice = users
            .create(&"alice".parse().unwrap(), None, None)
            .await
            .unwrap();
        crate::auth::IdentityRepository::new(db.clone())
            .record(
                &alice.id,
                "spaceport-for-acme",
                "1001",
                "octocat",
                &Default::default(),
                &Default::default(),
            )
            .await
            .unwrap();
        users
            .suspend(&UserRef::Slug("alice".parse().unwrap()))
            .await
            .unwrap();

        let state = started(home.clone(), "/auth/github/spaceport-for-acme").await;
        let response =
            callback_with(home.clone(), &format!("code=a-login-code&state={state}")).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get(http::header::SET_COOKIE).is_none());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            String::from_utf8(body.to_vec())
                .unwrap()
                .contains("suspended")
        );
        let entries = home.auth_log.entries(None).await.unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| entry.kind == "login.failed" && entry.origin == "spaceport-for-acme"),
            "{entries:?}"
        );
    }

    /// The create-gate end to end through the router: a stranger no rule
    /// matches is turned away, and nothing is made for them — no user, no
    /// session, and no `user.created` or `login.succeeded` in the log that an
    /// operator would later have to read past.
    #[tokio::test]
    async fn a_github_login_matching_no_mapping_rule_creates_nothing() {
        let (home, github, db) = sso_home();
        connect_for_login(&home).await;
        github.signs_in("a-login-code", "ghu_a-user-token", 1001, "octocat");
        github.user_belongs_to_orgs(&["acme-corp"]);
        // A rule that exists and does not match: an empty table would refuse
        // this login for the wrong reason.
        crate::auth::MappingRepository::new(db.clone())
            .add(
                "spaceport-for-acme",
                &"reader@blog".parse().unwrap(),
                &["org=other-corp".parse().unwrap()],
            )
            .await
            .unwrap();

        let state = started(home.clone(), "/auth/github/spaceport-for-acme").await;
        let response =
            callback_with(home.clone(), &format!("code=a-login-code&state={state}")).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get(http::header::SET_COOKIE).is_none());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("mapping rule"), "{body}");
        assert!(body.contains("/login"), "{body}");
        // Nobody was made, and the log carries no trace of one.
        let users = crate::auth::UserRepository::new(db.clone());
        assert!(users.list(None).await.unwrap().is_empty());
        let entries = home.auth_log.entries(None).await.unwrap();
        assert!(
            !entries
                .iter()
                .any(|entry| entry.kind == "user.created" || entry.kind == "login.succeeded"),
            "{entries:?}"
        );
    }

    /// The state is single-use and must be spaceport's own: garbage is
    /// refused, and the same state answered twice signs in once.
    #[tokio::test]
    async fn a_bad_or_replayed_state_is_refused() {
        let (home, github, db) = sso_home();
        connect_for_login(&home).await;
        github.signs_in("a-login-code", "ghu_a-user-token", 1001, "octocat");
        // Auto-creation is gated on a rule matching, and the replay half only
        // means something if the first callback really signs in — so this test
        // about state has to get past that gate first.
        crate::auth::MappingRepository::new(db.clone())
            .add(
                "spaceport-for-acme",
                &"reader@blog".parse().unwrap(),
                &["login=octocat".parse().unwrap()],
            )
            .await
            .unwrap();

        let (status, body) = get_path(
            home.clone(),
            &format!(
                "{}?code=a-login-code&state=nobody-issued-this",
                manifest::LOGIN_CALLBACK_PATH
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("expired"), "{body}");
        assert!(body.contains("/login"), "{body}");

        let state = started(home.clone(), "/auth/github/spaceport-for-acme").await;
        let first = callback_with(home.clone(), &format!("code=a-login-code&state={state}")).await;
        let replay = callback_with(home.clone(), &format!("code=a-login-code&state={state}")).await;
        assert_eq!(first.status(), StatusCode::SEE_OTHER);
        assert_eq!(replay.status(), StatusCode::NOT_FOUND);
    }

    /// Somebody pressing "cancel" on github.com is not an error in anything:
    /// prose, a way back to the login page, and no 500.
    #[tokio::test]
    async fn a_declined_authorization_is_prose_rather_than_a_failure() {
        let (home, _, _) = sso_home();
        connect_for_login(&home).await;
        let state = started(home.clone(), "/auth/github/spaceport-for-acme").await;

        let response =
            callback_with(home.clone(), &format!("error=access_denied&state={state}")).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("cancelled"), "{body}");
        assert!(body.contains("/login"), "{body}");
        // And the decline spent the state: it cannot be replayed with a code.
        let retry = callback_with(home, &format!("code=a-login-code&state={state}")).await;
        assert_eq!(retry.status(), StatusCode::NOT_FOUND);
    }

    /// The spec's re-sync, driven twice through the router: membership that
    /// went away takes its mapped entitlement along on the next login, and the
    /// manual grant beside it never moves.
    #[tokio::test]
    async fn a_second_login_drops_a_stale_mapped_entitlement_and_keeps_the_manual_grant() {
        let (home, github, db) = sso_home();
        connect_for_login(&home).await;
        github.signs_in("a-login-code", "ghu_a-user-token", 1001, "octocat");
        github.user_belongs_to_orgs(&["acme-corp"]);
        crate::auth::MappingRepository::new(db.clone())
            .add(
                "spaceport-for-acme",
                &"reader@blog".parse().unwrap(),
                &["org=acme-corp".parse().unwrap()],
            )
            .await
            .unwrap();

        // First login: the rule matches and maps.
        let state = started(home.clone(), "/auth/github/spaceport-for-acme").await;
        callback_with(home.clone(), &format!("code=a-login-code&state={state}")).await;
        let minted = crate::auth::UserRepository::new(db.clone())
            .list(None)
            .await
            .unwrap()
            .remove(0);
        home.entitlements
            .grant(
                &UserRef::Id(minted.id.clone()),
                &"editor@blog".parse().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            home.entitlements
                .audit(&UserRef::Id(minted.id.clone()))
                .await
                .unwrap()
                .1
                .len(),
            2
        );

        // Thrown out of the organisation, GitHub answers the next login bare.
        github.user_belongs_to_orgs(&[]);
        github.signs_in("another-code", "ghu_a-user-token", 1001, "octocat");
        let state = started(home.clone(), "/auth/github/spaceport-for-acme").await;
        callback_with(home.clone(), &format!("code=another-code&state={state}")).await;

        let (_, held) = home
            .entitlements
            .audit(&UserRef::Id(minted.id))
            .await
            .unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].role.as_str(), "editor");
        assert_eq!(held[0].mapped_rule, None);
    }

    /// One login remembered from one address, with an explicit clock the tests
    /// can move.
    fn begin_from(logins: &LoginAttempts, client: IpAddr, now: OffsetDateTime) -> Option<String> {
        logins
            .begin(client, "spaceport-for-acme".to_owned(), "/".to_owned(), now)
            .unwrap()
    }

    /// A burst from `count` distinct addresses, each spending its whole quota —
    /// the cheapest way for a test to fill the map legitimately.
    ///
    /// Never [`STRANGER`], so that a test can hold a login of its own and know
    /// the flood is somebody else's traffic rather than more of its own. The
    /// quota is per address, so a burst that included the caller's would be
    /// entitled to evict the caller's login and the test would be asserting
    /// nothing.
    fn flood(logins: &LoginAttempts, count: u32, now: OffsetDateTime) {
        for index in 0..count {
            for _ in 0..MAX_PENDING_LOGINS_PER_CLIENT {
                begin_from(logins, client(index + 1), now);
            }
        }
    }

    /// The address a test signs in from when the flood is meant to be other
    /// people. Outside every range [`flood`] uses.
    const STRANGER: u32 = 0;

    fn held(logins: &LoginAttempts) -> usize {
        logins.pending.lock().unwrap().len()
    }

    /// The quota, which is the whole point: an unauthenticated `GET` may be
    /// walked as often as somebody likes and what they fill is their own eight
    /// slots.
    #[test]
    fn one_address_may_only_hold_its_own_quota() {
        let logins = LoginAttempts::new();
        let now = OffsetDateTime::now_utc();
        for _ in 0..MAX_PENDING_LOGINS_PER_CLIENT {
            assert!(begin_from(&logins, client(1), now).is_some());
        }

        assert!(begin_from(&logins, client(1), now).is_none());
        assert_eq!(held(&logins), MAX_PENDING_LOGINS_PER_CLIENT);
    }

    /// The lockout this quota exists to remove. One address hammering the route
    /// used to fill the map and refuse everybody; now it fills its eight and
    /// the next user signs in as if nothing were happening.
    #[test]
    fn a_flood_from_one_address_locks_nobody_else_out() {
        let logins = LoginAttempts::new();
        let now = OffsetDateTime::now_utc();
        for _ in 0..MAX_PENDING_LOGINS * 2 {
            begin_from(&logins, client(1), now);
        }

        assert_eq!(held(&logins), MAX_PENDING_LOGINS_PER_CLIENT);
        assert!(begin_from(&logins, client(2), now).is_some());
    }

    /// A login already in flight when the flood arrives still finishes — the
    /// promise the old refuse-when-full rule was protecting, kept by the quota
    /// instead and without the lockout that came with it.
    #[test]
    fn a_flood_does_not_spend_a_login_already_in_flight() {
        let logins = LoginAttempts::new();
        let now = OffsetDateTime::now_utc();
        let mine = begin_from(&logins, client(STRANGER), now).unwrap();

        // Enough distinct addresses to fill the map several times over, so the
        // eviction path runs and runs.
        flood(
            &logins,
            (MAX_PENDING_LOGINS * 2 / MAX_PENDING_LOGINS_PER_CLIENT) as u32,
            now,
        );

        assert!(logins.take(&mine, now).is_some());
    }

    /// The map's own ceiling still stands behind the quota, for the five
    /// hundred addresses that could reach it honestly.
    #[test]
    fn the_map_stops_growing_however_many_addresses_arrive() {
        let logins = LoginAttempts::new();
        let now = OffsetDateTime::now_utc();

        flood(
            &logins,
            (MAX_PENDING_LOGINS * 2 / MAX_PENDING_LOGINS_PER_CLIENT) as u32,
            now,
        );

        assert_eq!(held(&logins), MAX_PENDING_LOGINS);
    }

    /// Which entry an eviction takes. A user holding one login is untouchable
    /// while anybody is holding more than one, so filling the map costs the
    /// address that filled it and nobody else.
    #[test]
    fn an_eviction_lands_on_the_address_holding_the_most() {
        let mut pending = HashMap::new();
        let now = OffsetDateTime::now_utc();
        let mut remember = |state: &str, client: IpAddr, age: i64| {
            pending.insert(
                state.to_owned(),
                LoginAttempt {
                    connection: "spaceport-for-acme".to_owned(),
                    next: "/".to_owned(),
                    created_at: now - Duration::seconds(age),
                    client,
                },
            );
        };

        // The quiet user's is by far the oldest, so an oldest-first eviction
        // would take it. The greedy address holds more.
        remember("quiet", client(1), 300);
        remember("greedy-old", client(2), 200);
        remember("greedy-new", client(2), 10);

        evict_from_the_greediest(&mut pending);

        assert!(pending.contains_key("quiet"));
        assert!(pending.contains_key("greedy-new"));
        assert!(!pending.contains_key("greedy-old"));
    }

    /// The sweep runs on the way in, so a spaceport nobody ever completes a
    /// login at still forgets the abandoned ones — and a map filled by a burst
    /// takes new logins again once that burst is past its lifetime.
    #[test]
    fn beginning_a_login_sweeps_the_expired_ones() {
        let logins = LoginAttempts::new();
        let started = OffsetDateTime::now_utc();
        for _ in 0..MAX_PENDING_LOGINS_PER_CLIENT {
            begin_from(&logins, client(1), started);
        }
        assert!(begin_from(&logins, client(1), started).is_none());

        let later = started + LOGIN_STATE_LIFETIME + Duration::seconds(1);

        assert!(begin_from(&logins, client(1), later).is_some());
        // Every one of the burst's entries went, and only the fresh one is
        // left — no callback traffic involved.
        assert_eq!(held(&logins), 1);
    }

    /// The `index`th client address — as many distinct ones as a test needs to
    /// pretend to be a botnet with.
    fn client(index: u32) -> IpAddr {
        IpAddr::from([10, (index >> 16) as u8, (index >> 8) as u8, index as u8])
    }

    fn tracked(throttle: &LoginThrottle) -> usize {
        throttle.spent.lock().unwrap().clients.len()
    }

    /// The per-address budget: twenty failures and the twenty-first request is
    /// refused before anything is looked at — and a second address is still as
    /// welcome as it ever was, which is the difference between a throttle and
    /// the global charge this replaced.
    #[test]
    fn a_client_that_spends_its_budget_is_refused_and_its_neighbour_is_not() {
        let throttle = LoginThrottle::new();
        let now = OffsetDateTime::now_utc();

        for _ in 0..MAX_FAILURES_PER_CLIENT {
            assert!(throttle.permits(client(1), now));
            throttle.charge(client(1), now);
        }

        assert!(!throttle.permits(client(1), now));
        assert!(throttle.permits(client(2), now));
    }

    /// A budget is a window's worth, not a lifetime's: the client that spent
    /// its twenty is trying again ten minutes later, with no operator involved.
    #[test]
    fn a_spent_budget_comes_back_when_the_window_turns_over() {
        let throttle = LoginThrottle::new();
        let now = OffsetDateTime::now_utc();
        for _ in 0..MAX_FAILURES_PER_CLIENT {
            throttle.charge(client(1), now);
        }
        assert!(!throttle.permits(client(1), now));

        let later = now + LOGIN_FAILURE_WINDOW + Duration::seconds(1);

        assert!(throttle.permits(client(1), later));
    }

    /// The property that makes this a throttle and not a lockout lever: no
    /// number of guessing addresses can make the spaceport refuse an address
    /// that has not guessed. Somebody else's flood is never a stranger's
    /// problem, however large it gets — which is exactly what the global charge
    /// this replaced got wrong, and what a ceiling across addresses would have
    /// got wrong again.
    #[test]
    fn a_flood_from_other_addresses_never_refuses_an_innocent_one() {
        let throttle = LoginThrottle::new();
        let now = OffsetDateTime::now_utc();

        // Twice as many addresses as the map holds, so it is full and evicting
        // throughout, and one of them spending its whole budget for good
        // measure — neither shape is a stranger's problem.
        for guesser in 0..(MAX_THROTTLED_CLIENTS as u32) * 2 {
            throttle.charge(client(guesser), now);
        }
        for _ in 0..MAX_FAILURES_PER_CLIENT {
            throttle.charge(client(1), now);
        }

        assert!(throttle.permits(client(u32::MAX), now));
    }

    /// The bound, [`a_full_map_refuses_rather_than_grows`]' argument applied to
    /// the map an unauthenticated `POST` fills — except that this map evicts
    /// where the pending logins refuse, because refusing here would be the
    /// lockout the test above exists to rule out.
    #[test]
    fn the_throttle_forgets_addresses_rather_than_growing_without_bound() {
        let throttle = LoginThrottle::new();
        let now = OffsetDateTime::now_utc();

        for index in 0..(MAX_THROTTLED_CLIENTS as u32) * 2 {
            throttle.charge(client(index), now);
        }

        assert_eq!(tracked(&throttle), MAX_THROTTLED_CLIENTS);

        // And full is not a state it stays in: a window later the whole burst
        // is forgotten and one fresh address is all that is held.
        let later = now + LOGIN_FAILURE_WINDOW + Duration::seconds(1);
        throttle.charge(client(0), later);

        assert_eq!(tracked(&throttle), 1);
    }

    /// Eviction is by age, so the address whose window is closest to turning
    /// over is the one that goes: the newcomer is remembered, and the budget
    /// handed back is the one that had least of itself left to spend.
    #[test]
    fn a_full_throttle_evicts_the_window_nearest_its_end() {
        let throttle = LoginThrottle::new();
        let now = OffsetDateTime::now_utc();

        // The oldest window, then a full map's worth a minute newer.
        throttle.charge(client(0), now);
        let newer = now + Duration::minutes(1);
        for index in 1..MAX_THROTTLED_CLIENTS as u32 {
            throttle.charge(client(index), newer);
        }
        assert_eq!(tracked(&throttle), MAX_THROTTLED_CLIENTS);

        throttle.charge(client(u32::MAX), newer);

        assert_eq!(tracked(&throttle), MAX_THROTTLED_CLIENTS);
        let spent = throttle.spent.lock().unwrap();
        assert!(!spent.clients.contains_key(&client(0)), "the oldest stayed");
        assert!(spent.clients.contains_key(&client(u32::MAX)));
    }

    /// A `next` too long to be a path this host serves is a hostile shape like
    /// any other: it lands at `/`, and what gets remembered is one byte rather
    /// than however many somebody sent.
    #[test]
    fn an_overlong_next_falls_back_to_the_root() {
        let longest = format!("/{}", "a".repeat(MAX_NEXT - 1));
        assert_eq!(safe_next(Some(&longest)), longest);

        let overlong = format!("/{}", "a".repeat(MAX_NEXT));
        assert_eq!(safe_next(Some(&overlong)), "/");
    }

    /// And through the router: the start route stores the sanitized value, so
    /// the size of an entry is spaceport's to decide.
    #[tokio::test]
    async fn starting_a_login_with_an_overlong_next_remembers_the_root() {
        let (home, _, _) = sso_home();
        connect_for_login(&home).await;

        let state = started(
            home.clone(),
            &format!(
                "/auth/github/spaceport-for-acme?next=%2F{}",
                "a".repeat(MAX_NEXT)
            ),
        )
        .await;

        let attempt = home.logins.take(&state, OffsetDateTime::now_utc()).unwrap();
        assert_eq!(attempt.next, "/");
    }

    /// A client past its own quota gets a sentence and a 429, not a bounce to
    /// GitHub for a state this spaceport did not keep.
    ///
    /// A request that never crossed a socket is charged to the unspecified
    /// address, so that is the quota this test has to spend.
    #[tokio::test]
    async fn starting_a_login_past_the_clients_quota_is_refused() {
        let (home, _, _) = sso_home();
        connect_for_login(&home).await;
        let now = OffsetDateTime::now_utc();
        for _ in 0..MAX_PENDING_LOGINS_PER_CLIENT {
            begin_from(&home.logins, client_of(None), now);
        }

        let (status, body) = get_path(home, "/auth/github/spaceport-for-acme").await;

        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(body.contains("Nothing was started"), "{body}");
    }

    /// The other half of that, and the reason the quota is per address: a
    /// stranger who has spent theirs has not spent anybody else's, so the route
    /// still answers a user the flood never touched.
    #[tokio::test]
    async fn a_client_past_its_quota_does_not_refuse_the_next_one() {
        let (home, _, _) = sso_home();
        connect_for_login(&home).await;
        let now = OffsetDateTime::now_utc();
        for _ in 0..MAX_PENDING_LOGINS * 2 {
            begin_from(&home.logins, client(1), now);
        }

        let (status, _) = get_path(home, "/auth/github/spaceport-for-acme").await;

        assert_eq!(status, StatusCode::SEE_OTHER);
    }
}

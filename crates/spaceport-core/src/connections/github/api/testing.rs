//! GitHub's API, answered in this process.
//!
//! Enough of it for everything [`super::Client`] asks: the App record,
//! the installations of an App — over as many pages as a test wants — the
//! repositories of an installation, one repository read by name, the commit a
//! branch of it is at, and the mint
//! that turns an installation into a token — and, since the App became the way
//! people sign in, one scripted person: the code exchange that turns their
//! authorization code into a token, and the `/user` family that token opens.
//! Requests never leave the process; the client is handed this as
//! its [`Transport`] and there is no socket anywhere.
//!
//! What makes it worth having is the recording. Every request is kept with the
//! method, the path and — the part the tests are really about — which
//! credential was presented, because "the App signed this", "an installation
//! token was used" and "the person's own token was used" are the distinction
//! that decides whether a call works at all, and it is invisible in a response.
//!
//! What it deliberately does not do is check the JWT. Verifying the signature
//! here would test [`super::super::jwt`] a second time, and that module
//! verifies its own against the public key already. All this looks at is the
//! scheme in front of the token.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use super::Transport;

/// How long a minted token says it is good for, unless a test says otherwise.
///
/// GitHub's own figure for an installation token, so a test that says nothing
/// about expiry gets the behaviour production has.
const TOKEN_LIFETIME: Duration = Duration::hours(1);

/// The commit the fixture repository's `main` is at.
///
/// A whole sha rather than a short one, because everything that reads a head
/// abbreviates it for a person and a fixture that was already short would hide
/// whether it did.
pub(crate) const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";

/// The permissions `/app` reports unless a test says otherwise: what the
/// manifest asks for, so the fixture App and one the manifest flow would
/// create are the same App. Kept as one expression rather than eight setter
/// calls, because the tests that care are the ones taking permissions *away*.
fn default_permissions() -> Value {
    json!({
        "metadata": "read",
        "contents": "read",
        "checks": "write",
        "statuses": "write",
        "deployments": "write",
        "pull_requests": "read",
        "members": "read",
        "emails": "read",
    })
}

/// Which credential a request presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Authorization {
    /// `Bearer …` — a JWT the App signed for itself.
    Jwt,
    /// `token …` — one GitHub minted for an installation.
    Token,
    /// `Bearer …` holding the scripted person's token — a user-to-server call.
    ///
    /// Told apart from [`Self::Jwt`] by value rather than by scheme, because on
    /// the wire they *are* the same scheme — which is exactly why the tests
    /// need the recording to say which one was really sent.
    User,
    /// Nothing at all, which is what the unauthenticated calls look like.
    None,
}

/// One request this was asked, as much of it as a test ever asserts on.
#[derive(Debug, Clone)]
pub(crate) struct Recorded {
    #[expect(
        dead_code,
        reason = "kept so a failing assertion prints the whole request"
    )]
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) authorization: Authorization,
    pub(crate) accept: Option<String>,
    pub(crate) api_version: Option<String>,
    pub(crate) user_agent: Option<String>,
}

/// A GitHub that answers whatever it has been told to answer.
pub(crate) struct FakeGitHub {
    state: Mutex<State>,
}

struct State {
    /// The apps registered on this GitHub. `/app` answers with whichever of
    /// them the presented JWT claims to be, which is what makes a test that
    /// connects two different apps possible at all.
    apps: Vec<Value>,
    /// Pages of `/app/installations`, each a JSON array.
    installations: Vec<Value>,
    /// Pages of `/installation/repositories`, each a JSON array.
    repositories: Vec<Value>,
    /// The default branch of each repository `/repos/{owner}/{name}` knows, by
    /// full name. Kept apart from the listing pages because the two answer
    /// different questions — a repository can be granted to an installation and
    /// still be one no test ever said anything about the branches of.
    default_branches: HashMap<String, String>,
    /// The commit each branch `/repos/{owner}/{name}/branches/{branch}` knows
    /// is at, by full name and branch. Seeded with the fixture repository's
    /// `main`, because a tracking now resolves a head and a test that says
    /// nothing about branches should still get the ordinary case; a branch
    /// nothing has said this about is one this GitHub answers `404` for, which
    /// is what a mistyped `--branch` really gets.
    heads: HashMap<(String, String), String>,
    /// Where `/repos/{owner}/{name}/tarball/{revision}` redirects to, by full
    /// name and revision. Empty to begin with, because a redirect to nowhere is
    /// not a useful default and a test that cares about the download says so.
    archives: HashMap<(String, String), String>,
    token_lifetime: Duration,
    minted: usize,
    /// Answer every request with this status and body instead.
    refusal: Option<(StatusCode, String)>,
    /// Refuse only what this app signs for, whoever else is being answered.
    refused_app: Option<i64>,
    /// Headers added to a refusal, for the rate limit's sake.
    refusal_headers: Vec<(String, String)>,
    /// Offer a next page for ever, however many have been served.
    endless: bool,
    /// The app a manifest conversion hands back, for the tests that create one
    /// the way GitHub's manifest flow does.
    converted: Option<Value>,
    /// The one person this GitHub will sign in, once a test scripts them.
    ///
    /// None to begin with, because a code exchange nothing has been said about
    /// should fail the way a stale or mistyped code really does — as GitHub's
    /// `200`-with-`error` answer, not as a path the fake forgot.
    user: Option<ScriptedUser>,
    requests: Vec<Recorded>,
}

/// A person a test has told this GitHub about: the code that signs them in,
/// the token that acts as them, and everything the `/user` family answers.
struct ScriptedUser {
    code: String,
    token: String,
    id: i64,
    login: String,
    /// Pages of `/user/emails`, each a JSON array — pages rather than a flat
    /// list so a test can make GitHub paginate the way it really does.
    email_pages: Vec<Value>,
    /// Pages of `/user/orgs`, each a JSON array.
    org_pages: Vec<Value>,
    /// Pages of `/user/teams`, each a JSON array.
    team_pages: Vec<Value>,
}

impl FakeGitHub {
    /// A GitHub holding the app the tests connect, one installation and one
    /// repository whose default branch is `main` — the shape everything starts
    /// from.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                apps: vec![json!({
                    "id": 42,
                    "slug": "spaceport-for-acme",
                    "name": "Spaceport for Acme",
                    "owner": {"login": "an-organisation", "type": "Organization"},
                    // What the manifest asks for, so a test that says nothing
                    // about permissions gets an App the manifest flow made.
                    "permissions": default_permissions(),
                    // A field spaceport does not know, present on purpose: a
                    // response that grows one must still parse.
                    "html_url": "https://github.com/apps/spaceport-for-acme",
                })],
                installations: vec![
                    json!([{"id": 7, "account": {"login": "an-organisation", "type": "Organization"}}]),
                ],
                repositories: vec![json!([{"full_name": "an-organisation/site"}])],
                default_branches: HashMap::from([(
                    "an-organisation/site".to_owned(),
                    "main".to_owned(),
                )]),
                heads: HashMap::from([(
                    ("an-organisation/site".to_owned(), "main".to_owned()),
                    HEAD.to_owned(),
                )]),
                archives: HashMap::new(),
                token_lifetime: TOKEN_LIFETIME,
                minted: 0,
                refusal: None,
                refused_app: None,
                refusal_headers: Vec::new(),
                endless: false,
                converted: None,
                user: None,
                requests: Vec::new(),
            }),
        })
    }

    /// Answer `/app` with this app and no other, whoever signed the request —
    /// the shape of a key and an app id taken from two different apps.
    pub(crate) fn app_is(&self, id: i64, slug: &str, name: &str, owner: &str) {
        self.state.lock().unwrap().apps = vec![app(id, slug, name, owner)];
    }

    /// Answer `/app` saying every app registered here holds exactly these
    /// permissions — the shape of an App created before the manifest widened,
    /// which GitHub keeps at what its owner once approved.
    pub(crate) fn app_permissions(&self, permissions: &[(&str, &str)]) {
        let permissions: Value = permissions
            .iter()
            .map(|(name, level)| ((*name).to_owned(), json!(level)))
            .collect::<serde_json::Map<String, Value>>()
            .into();

        for app in &mut self.state.lock().unwrap().apps {
            app["permissions"] = permissions.clone();
        }
    }

    /// Register another app here, so that a test can connect two.
    pub(crate) fn also_hosts(&self, id: i64, slug: &str, name: &str, owner: &str) {
        self.state
            .lock()
            .unwrap()
            .apps
            .push(app(id, slug, name, owner));
    }

    /// Serve the installations over these pages, in this order.
    pub(crate) fn installations_in_pages(&self, pages: &[&[(i64, &str, &str)]]) {
        self.state.lock().unwrap().installations = pages
            .iter()
            .map(|page| {
                page.iter()
                    .map(|(id, account, account_type)| {
                        json!({"id": id, "account": {"login": account, "type": account_type}})
                    })
                    .collect()
            })
            .collect();
    }

    /// Serve the repositories over these pages, in this order.
    pub(crate) fn repositories_in_pages(&self, pages: &[&[&str]]) {
        self.state.lock().unwrap().repositories = pages
            .iter()
            .map(|page| {
                page.iter()
                    .map(|full_name| json!({"full_name": full_name}))
                    .collect()
            })
            .collect();
    }

    /// Say that `/repos/{full_name}` exists and that this is its default
    /// branch.
    ///
    /// Separate from [`Self::repositories_in_pages`] on purpose: a test about
    /// what an installation can see and a test about which branch an app tracks
    /// are different tests, and making one script the other would tie them
    /// together for no reason. A repository nobody has said this about is one
    /// this GitHub answers `404` for.
    pub(crate) fn repository_defaults_to(&self, full_name: &str, branch: &str) {
        self.state
            .lock()
            .unwrap()
            .default_branches
            .insert(full_name.to_owned(), branch.to_owned());
    }

    /// Say that `branch` of `full_name` exists and is at this commit.
    ///
    /// Apart from [`Self::repository_defaults_to`] for the reason that one is
    /// apart from the listing: which branch an app tracks and where that branch
    /// has got to are different facts, and a test about one should not have to
    /// state the other.
    pub(crate) fn branch_is_at(&self, full_name: &str, branch: &str, sha: &str) {
        self.state
            .lock()
            .unwrap()
            .heads
            .insert((full_name.to_owned(), branch.to_owned()), sha.to_owned());
    }

    /// Say that the tarball of `revision` is downloadable from `location`.
    ///
    /// Answered as GitHub answers it: a `302` and a `Location`, never the bytes.
    /// A revision nothing has been said about is a `404`, which is the same
    /// answer a repository this installation was never granted would get — see
    /// [`Self::repository_defaults_to`] for why GitHub does not distinguish.
    pub(crate) fn archives_at(&self, full_name: &str, revision: &str, location: &str) {
        self.state.lock().unwrap().archives.insert(
            (full_name.to_owned(), revision.to_owned()),
            location.to_owned(),
        );
    }

    /// Mint tokens that are good for this long — negative for one that has
    /// already expired by the time it arrives.
    pub(crate) fn tokens_expiring_in(&self, lifetime: Duration) {
        self.state.lock().unwrap().token_lifetime = lifetime;
    }

    /// Answer everything with this status and body.
    pub(crate) fn refuse_with(&self, status: StatusCode, body: &str) {
        self.state.lock().unwrap().refusal = Some((status, body.to_owned()));
    }

    /// Stop accepting the credentials of the app `app_id`, and go on answering
    /// for every other app registered here.
    ///
    /// The shape of one connection of several being broken — a key rotated on
    /// the settings page, an app deleted on github.com — which is the case a
    /// pass over many connections has to survive. Matched on the `iss` claim,
    /// so a call made as an installation of that app is refused at the mint.
    pub(crate) fn refuses_the_app(&self, app_id: i64) {
        self.state.lock().unwrap().refused_app = Some(app_id);
    }

    /// Say that this app has no requests left until `reset`, a unix timestamp.
    pub(crate) fn exhaust_the_rate_limit(&self, reset: i64) {
        self.state.lock().unwrap().refusal_headers = vec![
            ("x-ratelimit-remaining".to_owned(), "0".to_owned()),
            ("x-ratelimit-reset".to_owned(), reset.to_string()),
        ];
    }

    /// Create this app out of any manifest conversion, and answer `/app` as it
    /// from then on — which is what GitHub does, since the app now exists.
    ///
    /// The secrets are the fixture ones every other test uses, so a connection
    /// made this way and one registered by hand are the same connection.
    pub(crate) fn converts_manifests_into(&self, id: i64, slug: &str, name: &str) {
        let mut state = self.state.lock().unwrap();

        state.converted = Some(json!({
            "id": id,
            "slug": slug,
            "name": name,
            "owner": {"login": "an-organisation", "type": "Organization"},
            "client_id": "Iv1.0123456789abcdef",
            "client_secret": "a-client-secret",
            "webhook_secret": "a-webhook-secret",
            "pem": super::super::key::testing::PKCS1,
            // A field spaceport does not know, for the same reason `/app`
            // carries one.
            "html_url": format!("https://github.com/apps/{slug}"),
        }));
        state.apps = vec![app(id, slug, name, "an-organisation")];
    }

    /// Script the person this GitHub signs in: `code` is what the login
    /// callback will bring back, `token` is what the exchange answers with and
    /// what every `/user` call must then present.
    ///
    /// Any other code gets GitHub's real refusal — a `200` carrying
    /// `bad_verification_code` — so a test about the error path needs no setter
    /// of its own: it just exchanges a code nobody scripted.
    ///
    /// The person starts with no emails, organisations or teams; the setters
    /// below add those separately, because who a person is and what they belong
    /// to are different facts and a test about one should not have to state the
    /// other.
    pub(crate) fn signs_in(&self, code: &str, token: &str, id: i64, login: &str) {
        self.state.lock().unwrap().user = Some(ScriptedUser {
            code: code.to_owned(),
            token: token.to_owned(),
            id,
            login: login.to_owned(),
            email_pages: Vec::new(),
            org_pages: Vec::new(),
            team_pages: Vec::new(),
        });
    }

    /// Serve the signed-in person's emails over these pages, in this order —
    /// each email as `(address, verified, primary)`.
    pub(crate) fn user_emails_in_pages(&self, pages: &[&[(&str, bool, bool)]]) {
        self.script(|user| {
            user.email_pages = pages
                .iter()
                .map(|page| {
                    page.iter()
                        .map(|(email, verified, primary)| {
                            json!({"email": email, "verified": verified, "primary": primary})
                        })
                        .collect()
                })
                .collect();
        });
    }

    /// Say which organisations the signed-in person belongs to, on one page.
    pub(crate) fn user_belongs_to_orgs(&self, orgs: &[&str]) {
        self.script(|user| {
            user.org_pages = vec![orgs.iter().map(|login| json!({"login": login})).collect()];
        });
    }

    /// Say which teams the signed-in person is on, each as `(org, slug)`, on
    /// one page.
    pub(crate) fn user_belongs_to_teams(&self, teams: &[(&str, &str)]) {
        self.script(|user| {
            user.team_pages = vec![
                teams
                    .iter()
                    .map(|(org, slug)| json!({"slug": slug, "organization": {"login": org}}))
                    .collect(),
            ];
        });
    }

    /// Change the scripted person, for the setters that fill them in.
    fn script(&self, change: impl FnOnce(&mut ScriptedUser)) {
        change(
            self.state
                .lock()
                .unwrap()
                .user
                .as_mut()
                .expect("a test says who signs in before saying what they belong to"),
        );
    }

    /// Offer a next page for ever — a `Link` header that points at itself.
    pub(crate) fn paginate_endlessly(&self) {
        self.state.lock().unwrap().endless = true;
    }

    pub(crate) fn requests(&self) -> Vec<Recorded> {
        self.state.lock().unwrap().requests.clone()
    }

    /// How many installation tokens have been minted here.
    pub(crate) fn minted(&self) -> usize {
        self.state.lock().unwrap().minted
    }

    fn handle(&self, request: &Request<Bytes>) -> Response<Bytes> {
        let path = request.uri().path().to_owned();
        let page = page_number(request.uri().query());
        let signed_by = issuer(request);
        let mut state = self.state.lock().unwrap();

        let user_token = state.user.as_ref().map(|user| user.token.clone());
        state
            .requests
            .push(recorded(request, user_token.as_deref()));

        if state.refused_app.is_some() && state.refused_app == signed_by {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Bytes::from_static(br#"{"message":"Bad credentials"}"#))
                .unwrap();
        }

        if let Some((status, body)) = state.refusal.clone() {
            let mut response = Response::builder().status(status);
            for (name, value) in &state.refusal_headers {
                response = response.header(name, value);
            }

            return response.body(Bytes::from(body)).unwrap();
        }

        match path.split('/').collect::<Vec<_>>().as_slice() {
            // GitHub answers `/app` for whoever signed the request, so this
            // reads the `iss` claim off the token — without verifying it, for
            // the reason the module docs give.
            ["", "app"] => {
                let issuer = issuer(request);
                let app = state
                    .apps
                    .iter()
                    .find(|app| app["id"].as_i64() == issuer)
                    // Falling back to the first is what makes `app_is` mean
                    // "answer as this whatever was asked for".
                    .or_else(|| state.apps.first())
                    .cloned()
                    .unwrap_or(Value::Null);

                ok(app, None)
            }
            ["", "app", "installations"] => {
                let (body, next) = paged(&state, &state.installations, &path, page);

                ok(body, next)
            }
            ["", "installation", "repositories"] => {
                let (repositories, next) = paged(&state, &state.repositories, &path, page);

                ok(
                    json!({
                        "total_count": repositories.as_array().map_or(0, Vec::len),
                        "repositories": repositories,
                    }),
                    next,
                )
            }
            // One repository by name. The name is the path tail as it arrived,
            // so a test that asks for `owner/name` is asking exactly what the
            // client put on the wire.
            ["", "repos", owner, name] => {
                let full_name = format!("{owner}/{name}");

                match state.default_branches.get(&full_name) {
                    Some(default_branch) => ok(
                        json!({
                            "full_name": full_name,
                            "default_branch": default_branch,
                            // A field spaceport does not know, for the same
                            // reason `/app` carries one.
                            "html_url": format!("https://github.com/{full_name}"),
                        }),
                        None,
                    ),
                    // GitHub answers `404` rather than `403` for a repository an
                    // installation may not see, so that a token cannot be used
                    // to find out what exists.
                    None => Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Bytes::from_static(br#"{"message":"Not Found"}"#))
                        .unwrap(),
                }
            }
            // One branch by name, which is where the commit a tracking is built
            // from comes from. The branch is the rest of the path joined back
            // up, for the reason the tarball's revision is.
            ["", "repos", owner, name, "branches", branch @ ..] => {
                let full_name = format!("{owner}/{name}");
                let branch = branch.join("/");

                match state.heads.get(&(full_name.clone(), branch.clone())) {
                    Some(sha) => ok(
                        json!({
                            "name": branch,
                            "commit": {
                                "sha": sha,
                                // A field spaceport does not know, for the same
                                // reason `/app` carries one.
                                "url": format!("https://api.github.com/repos/{full_name}/commits/{sha}"),
                            },
                        }),
                        None,
                    ),
                    // A branch this GitHub has never been told about, which is
                    // what a mistyped `--branch` arrives as.
                    None => Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Bytes::from_static(br#"{"message":"Branch not found"}"#))
                        .unwrap(),
                }
            }
            // The tarball, which is a redirect and never a body. The revision
            // is the rest of the path joined back up, since a branch name is
            // allowed to have slashes in it and the client sends it unescaped.
            ["", "repos", owner, name, "tarball", revision @ ..] => {
                let full_name = format!("{owner}/{name}");
                let revision = revision.join("/");

                match state.archives.get(&(full_name, revision)) {
                    Some(location) => Response::builder()
                        .status(StatusCode::FOUND)
                        .header(header::LOCATION, location)
                        .body(Bytes::new())
                        .unwrap(),
                    None => Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Bytes::from_static(br#"{"message":"Not Found"}"#))
                        .unwrap(),
                }
            }
            ["", "app", "installations", installation, "access_tokens"] => {
                state.minted += 1;
                let expires_at = (OffsetDateTime::now_utc() + state.token_lifetime)
                    .format(&Rfc3339)
                    .unwrap();

                ok(
                    json!({
                        // Unguessable in reality; here only distinct, so a test
                        // can tell a reused token from a re-minted one.
                        "token": format!("ghs-token-{installation}-{}", state.minted),
                        "expires_at": expires_at,
                    }),
                    None,
                )
            }
            // The code exchange, which really lives on github.com rather than
            // the API host — the fake dispatches on path alone, and this path
            // exists nowhere else, so the distinction costs nothing here.
            // Answered the way GitHub answers it: a `200` whatever happened,
            // with the complaint in the body when there is one.
            ["", "login", "oauth", "access_token"] => {
                let body: Value = serde_json::from_slice(request.body()).unwrap_or(Value::Null);
                let field = |name: &str| {
                    body.get(name)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                // The credentials are checked before the code, as GitHub does:
                // a wrong client secret is its own refusal however good the
                // code is — and checking it here is what makes the happy-path
                // test prove the secret was actually sent.
                let answer = if field("client_id") != "Iv1.0123456789abcdef"
                    || field("client_secret") != "a-client-secret"
                {
                    json!({
                        "error": "incorrect_client_credentials",
                        "error_description": "The client_id and/or client_secret passed are incorrect.",
                    })
                } else {
                    match &state.user {
                        Some(user) if field("code") == user.code => json!({
                            "access_token": user.token,
                            "token_type": "bearer",
                            "scope": "",
                        }),
                        // A code nobody scripted is what a stale, replayed or
                        // mistyped one really gets.
                        _ => json!({
                            "error": "bad_verification_code",
                            "error_description": "The code passed is incorrect or expired.",
                        }),
                    }
                };

                ok(answer, None)
            }
            ["", "user"] => match signed_in(&state, request) {
                Some(user) => ok(json!({"id": user.id, "login": user.login}), None),
                None => unauthorized(),
            },
            ["", "user", "emails"] => match signed_in(&state, request) {
                Some(user) => {
                    let (body, next) = paged(&state, &user.email_pages, &path, page);

                    ok(body, next)
                }
                None => unauthorized(),
            },
            ["", "user", "orgs"] => match signed_in(&state, request) {
                Some(user) => {
                    let (body, next) = paged(&state, &user.org_pages, &path, page);

                    ok(body, next)
                }
                None => unauthorized(),
            },
            ["", "user", "teams"] => match signed_in(&state, request) {
                Some(user) => {
                    let (body, next) = paged(&state, &user.team_pages, &path, page);

                    ok(body, next)
                }
                None => unauthorized(),
            },
            // The manifest conversion, which carries no credential at all: the
            // one-time code in the path is the whole of it.
            ["", "app-manifests", _code, "conversions"] => match state.converted.clone() {
                Some(converted) => ok(converted, None),
                None => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Bytes::from_static(br#"{"message":"Not Found"}"#))
                    .unwrap(),
            },
            _ => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Bytes::from_static(br#"{"message":"Not Found"}"#))
                .unwrap(),
        }
    }
}

/// One app's `/app` response.
fn app(id: i64, slug: &str, name: &str, owner: &str) -> Value {
    json!({
        "id": id,
        "slug": slug,
        "name": name,
        "owner": {"login": owner, "type": "Organization"},
        "permissions": default_permissions(),
    })
}

/// The app id a request's JWT claims to be, read out of the `iss` claim.
///
/// The signature is not checked — see the module docs. What is being modelled
/// is GitHub answering as whoever signed, not GitHub deciding whether they did.
fn issuer(request: &Request<Bytes>) -> Option<i64> {
    use base64::Engine;

    let token = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.split('.').nth(1)?)
        .ok()?;

    serde_json::from_slice::<Value>(&claims)
        .ok()?
        .get("iss")?
        .as_str()?
        .parse()
        .ok()
}

/// The scripted person, if the request presents their token — anything else
/// gets [`unauthorized`] from the `/user` family.
///
/// The check is by value rather than by scheme, because scheme is all the App's
/// own JWT differs by on the wire: a fake that only looked for `Bearer` would
/// wave through exactly the wrong-credential mistake these endpoints exist to
/// catch.
fn signed_in<'a>(state: &'a State, request: &Request<Bytes>) -> Option<&'a ScriptedUser> {
    state.user.as_ref().filter(|user| {
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            == Some(format!("Bearer {}", user.token).as_str())
    })
}

/// GitHub's `401`, which is what a wrong or missing user token gets.
fn unauthorized() -> Response<Bytes> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Bytes::from_static(br#"{"message":"Bad credentials"}"#))
        .unwrap()
}

/// The page a request asked for, counting from one as GitHub does.
fn page_number(query: Option<&str>) -> usize {
    query
        .unwrap_or_default()
        .split('&')
        .find_map(|pair| pair.strip_prefix("page="))
        .and_then(|page| page.parse().ok())
        .unwrap_or(1)
}

/// One page of a listing, and the url of the next if there is one.
fn paged(state: &State, pages: &[Value], path: &str, page: usize) -> (Value, Option<String>) {
    let body = pages.get(page - 1).cloned().unwrap_or_else(|| json!([]));
    let next = (state.endless || page < pages.len()).then(|| {
        format!(
            "https://api.github.com{path}?per_page=100&page={}",
            page + 1
        )
    });

    (body, next)
}

fn ok(body: Value, next: Option<String>) -> Response<Bytes> {
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json");

    if let Some(next) = next {
        // GitHub sends `prev` and `last` alongside, so the parsing has to pick
        // its relation out of a list rather than read the whole header.
        response = response.header(
            header::LINK,
            format!(r#"<{next}>; rel="next", <{next}>; rel="last""#),
        );
    }

    response.body(Bytes::from(body.to_string())).unwrap()
}

fn recorded(request: &Request<Bytes>, user_token: Option<&str>) -> Recorded {
    let text = |name: header::HeaderName| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
    };
    let authorization = match text(header::AUTHORIZATION) {
        // The scripted person's token first, because it arrives as `Bearer`
        // too and the arm below would swallow it as the App's JWT.
        Some(value) if user_token.is_some_and(|token| value == format!("Bearer {token}")) => {
            Authorization::User
        }
        Some(value) if value.starts_with("Bearer ") => Authorization::Jwt,
        Some(value) if value.starts_with("token ") => Authorization::Token,
        _ => Authorization::None,
    };

    Recorded {
        method: request.method().clone(),
        path: request.uri().path().to_owned(),
        authorization,
        accept: text(header::ACCEPT),
        api_version: text(header::HeaderName::from_static("x-github-api-version")),
        user_agent: text(header::USER_AGENT),
    }
}

#[async_trait]
impl Transport for FakeGitHub {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
        Ok(self.handle(&request))
    }
}

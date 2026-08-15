//! GitHub's API, answered in this process.
//!
//! Enough of it for everything [`super::Client`] asks: the App record,
//! the installations of an App — over as many pages as a test wants — the
//! repositories of an installation, one repository read by name, and the mint
//! that turns an installation into a token. Requests never leave the process; the client is handed this as
//! its [`Transport`] and there is no socket anywhere.
//!
//! What makes it worth having is the recording. Every request is kept with the
//! method, the path and — the part the tests are really about — which of the
//! two credentials was presented, because "the App signed this" and "an
//! installation token was used" are the distinction that decides whether a call
//! works at all, and it is invisible in a response.
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

/// Which credential a request presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Authorization {
    /// `Bearer …` — a JWT the App signed for itself.
    Jwt,
    /// `token …` — one GitHub minted for an installation.
    Token,
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
    requests: Vec<Recorded>,
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
                archives: HashMap::new(),
                token_lifetime: TOKEN_LIFETIME,
                minted: 0,
                refusal: None,
                refused_app: None,
                refusal_headers: Vec::new(),
                endless: false,
                converted: None,
                requests: Vec::new(),
            }),
        })
    }

    /// Answer `/app` with this app and no other, whoever signed the request —
    /// the shape of a key and an app id taken from two different apps.
    pub(crate) fn app_is(&self, id: i64, slug: &str, name: &str, owner: &str) {
        self.state.lock().unwrap().apps = vec![app(id, slug, name, owner)];
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

        state.requests.push(recorded(request));

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

fn recorded(request: &Request<Bytes>) -> Recorded {
    let text = |name: header::HeaderName| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
    };
    let authorization = match text(header::AUTHORIZATION) {
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

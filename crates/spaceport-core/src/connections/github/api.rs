//! Asking GitHub things, as the App an operator connected.
//!
//! This is the only file in spaceport that makes an outbound request to
//! something that is not on this host. What it offers is the five questions a
//! connection is actually for: what does GitHub say this App is, where has it
//! been installed, what can each installation see, what does one of those
//! repositories look like, and — the one everything else is built on — a token
//! that acts as an installation for the next hour. Since the App became the
//! way people sign in, it also asks the questions a login turns on: who GitHub
//! says a person is, which of their emails GitHub has verified, and which
//! organisations and teams they belong to — each asked with a token minted
//! from the code GitHub hands the login callback. One question is asked as
//! whichever installation can see the answer — which account, if any, holds a
//! handle an operator typed — because the endpoint that answers it is public
//! but an enterprise may hide its members from anybody standing outside it.
//!
//! Every one of those goes through [`Transport`], which exists so the tests can
//! answer in-process. That seam is the same shape as the ACME one: a trait with
//! a single method, a real implementation that owns a connection pool, and a
//! fake that records what it was asked. Without it the only way to test the
//! error sentences an operator reads would be to make GitHub produce them.
//!
//! What this deliberately does not do is persist. An installation token lasts
//! an hour and can always be minted again from the private key, so writing one
//! to the state database would be storing a credential in order to save a
//! single request. The cache lives in the client, the client lives as long as
//! the piece of work that made it, and both go away together.
//!
//! Nor does it retry, rate-limit itself, or hold a registry of clients. A
//! caller that gets "worth trying again" is a caller with a reconciliation loop
//! that will come round anyway, and inventing a backoff here would be inventing
//! a second schedule that disagrees with that one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, Method, Request, Response, StatusCode, header};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use super::jwt;
use super::key;
use super::repository::Connection;
use crate::secret::Secret;

/// Where GitHub's REST API lives.
///
/// The public one, and only the public one: GitHub Enterprise Server answers on
/// an operator's own host under a different path, and supporting it is a field
/// on the connection and a migration, not a constant. Written out rather than
/// configurable so that nothing can point spaceport's credentials at another
/// host by editing a config file.
pub(super) const API: &str = "https://api.github.com";

/// Where a user's authorization code is exchanged for a token.
///
/// On `github.com` and not on [`API`], because GitHub keeps its OAuth machinery
/// on the website rather than the REST API — this is the one call in the module
/// that does not live under the API base. Written out whole for the reason
/// [`API`] is: nothing may point the App's client secret at another host by
/// editing a config file.
const USER_TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";

/// Where a browser is sent to authorize as themselves, before GitHub bounces
/// them back to the login callback with a code.
///
/// Written out whole for the family's reason, and here it matters most of all:
/// this is a url a *user's browser* is redirected to, and a base that could be
/// bent by a config edit or a request value would be a login page whoever bent
/// it controls. `pub` rather than module-private because the redirect is
/// issued by the edge's login flow, while the exchange the code comes back to
/// lives here — one constant, so the two ends of the trip cannot disagree
/// about the host.
pub const AUTHORIZE_ENDPOINT: &str = "https://github.com/login/oauth/authorize";

/// The media type that selects GitHub's current REST responses.
///
/// GitHub's rule, not a choice: `application/json` still works but is
/// documented as the older behaviour, and the `+json` form is what every
/// current endpoint is specified against.
const ACCEPT: &str = "application/vnd.github+json";

/// The header naming which dated version of the API to answer with.
const API_VERSION_HEADER: HeaderName = HeaderName::from_static("x-github-api-version");

/// The dated API version spaceport is written against.
///
/// Pinned rather than omitted on purpose. Leaving it out means GitHub picks,
/// and GitHub picking means a breaking change to a response arrives on a day
/// nobody deployed anything. This value moves when somebody has read the
/// changelog for the version they are moving to.
const API_VERSION: &str = "2022-11-28";

/// What spaceport calls itself to GitHub.
///
/// GitHub requires a user agent and refuses requests without one. The version
/// is in it because the first question about a misbehaving client is which one
/// it is.
const USER_AGENT: &str = concat!("spaceport/", env!("CARGO_PKG_VERSION"));

/// How many items to ask for per page.
///
/// GitHub's maximum, so this is the fewest round trips a listing can take. A
/// smaller page would only mean more requests against the same rate limit.
const PER_PAGE: usize = 100;

/// How many pages a listing may run to before spaceport gives up on it.
///
/// At [`PER_PAGE`] this is fifty thousand repositories under one App, which is
/// past anything an operator is running a spaceport for. The cap is not really
/// about size, though: a `Link` header that points at the page it came from is
/// a loop, and a loop inside a reconciliation pass is a spaceport that never
/// reconciles anything again. Failing loudly at some number beats that.
const PAGE_LIMIT: usize = 500;

/// How long before a token expires to mint a new one instead of reusing it.
///
/// Two reasons, and the same five minutes covers both. A request that starts
/// just before expiry may well arrive after it, and GitHub's clock is not this
/// host's — so a token that looks good for another thirty seconds here may be
/// already dead there. An hour's token spent five minutes early costs nothing.
const REFRESH_BEFORE: Duration = Duration::minutes(5);

/// How much of an unrecognised error body to put in the message.
///
/// Enough for GitHub's `message` field, which is the part worth reading, and
/// not enough for an HTML error page. A whole body in a log line is a denial of
/// service on whoever has to read the log.
const BODY_LIMIT: usize = 400;

/// How long a github handle is allowed to be.
///
/// GitHub's own limit, written down here because [`handle`] is a gate on
/// operator input rather than a guess at a reasonable length: a bound that was
/// merely generous would be a bound that let something through.
const HANDLE_LIMIT: usize = 39;

/// How spaceport reaches GitHub.
///
/// One method, because one method is all the API needs: every call is a request
/// with no body or an empty one, and a response small enough to hold whole.
/// Streaming would matter for downloading a tarball, and downloading a tarball
/// is not something this module does.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>>;
}

/// The transport that actually goes out to the internet.
///
/// This is the first outbound HTTPS spaceport has ever made — the edge
/// *terminates* TLS and the proxy speaks plaintext to containers on loopback,
/// so until GitHub there was nothing on the other side of this host to talk to.
/// The trust anchors are the host's own, because the host already maintains a
/// set and a second one compiled into spaceport could only ever disagree with
/// it: an operator behind a corporate root, or one whose distribution has
/// distrusted a CA this morning, is right and spaceport would be wrong.
///
/// Held so the connection pool is reused. A reconciliation pass makes one call
/// per installation and a fresh TLS handshake for each of them is a handshake
/// spent on nothing.
pub struct Network {
    client: hyper_util::client::legacy::Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        http_body_util::Full<Bytes>,
    >,
}

impl Network {
    pub fn new() -> Result<Self> {
        // rustls needs a process-wide crypto provider, and a spaceport that
        // serves TLS has already installed one. Losing that race is not an
        // error: both calls install the same provider.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .context(
                "reading this host's certificate authorities, which github is verified against",
            )?
            // Plaintext to api.github.com is a request that has handed the
            // App's credentials to whoever answered.
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();

        Ok(Self {
            client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build(connector),
        })
    }
}

#[async_trait]
impl Transport for Network {
    /// One request, one response, and no redirect ever followed.
    ///
    /// hyper's client does not follow redirects and nothing here adds it.
    /// GitHub's API does not redirect any of the calls made from this module,
    /// and a client that quietly follows one is a client that can be pointed
    /// somewhere else — by anybody who can answer as `api.github.com` for one
    /// response, with the App's credentials replayed to wherever they said.
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
        use http_body_util::BodyExt;

        let (parts, body) = request.into_parts();
        let request = Request::from_parts(parts, http_body_util::Full::new(body));

        let response = self
            .client
            .request(request)
            .await
            .context("github could not be reached")?;

        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .context("reading github's answer")?
            .to_bytes();

        Ok(Response::from_parts(parts, body))
    }
}

/// What GitHub says the App is.
///
/// `owner` is flattened out of the response's `owner.login`, because the only
/// thing spaceport wants from that object is the name an operator would
/// recognise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRecord {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub owner: String,
    /// What GitHub says the App may do, permission by permission — `members`
    /// to `read`, say. Carried whole rather than as the one or two flags a
    /// caller checks today, because the questions asked of it are prose for an
    /// operator ("this App lacks…") and the map is GitHub's own vocabulary. A
    /// `BTreeMap` so anything that ever prints it prints it in one order.
    pub permissions: std::collections::BTreeMap<String, String>,
}

/// One place the App is installed, as GitHub reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationRecord {
    pub id: i64,
    /// The user or organisation that installed the App.
    pub account: String,
    /// `User` or `Organization`, in GitHub's own spelling — see
    /// [`super::Installation`] for why it is not an enum.
    pub account_type: String,
}

/// What spaceport needs of a repository, which is its default branch and
/// nothing else.
///
/// The rest of GitHub's repository object — the description, the topics, the
/// counts, the dozens of urls — is left on the wire for the same reason the
/// listing hands back bare `Vec<String>` full names: spaceport would be keeping
/// a copy of somebody else's record, one that is stale the moment anybody
/// touches the repository on github.com, and every field of it would be a field
/// some later code was tempted to trust. What is lifted out here is what a
/// tracked app is *decided* by, and it is lifted out once, at track time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryRecord {
    pub default_branch: String,
    /// GitHub's own spelling of `owner/name`, which is not necessarily the
    /// spelling that was asked for — the API resolves a renamed repository to
    /// its current name.
    pub full_name: String,
}

/// Who GitHub says a signed-in person is.
///
/// One GitHub account, in the three registers spaceport reads it in.
///
/// The id and the login answer different questions and both are asked: the id
/// is what an identity is *keyed* by — logins are renameable and reassignable,
/// and a link made on one would follow the name to whoever holds it next — and
/// the login is what a person and the mapping rules recognise.
///
/// `name` is a third kind of thing again, and the distinction is the whole
/// reason it is a separate field rather than a better login: it is display
/// text, free-form, absent on most accounts and never unique. Nothing resolves,
/// keys or authorises on it. It is carried because the person behind the
/// account is eventually shown to an app, and `octo-alice` is not what she is
/// called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    pub id: i64,
    pub login: String,
    /// GitHub's free-text display name, when the account has bothered to set
    /// one. `None` and the empty string mean the same thing here and both
    /// arrive as `None` — an account with a blank name has no name.
    pub name: Option<String>,
}

/// One email address GitHub holds for a signed-in person.
///
/// `verified` is the field the login flow is really after: linking an IdP
/// identity to an existing user goes through an email the IdP *asserts*, and an
/// unverified address is a string anybody can type into their GitHub settings.
/// `primary` rides along so the flow can prefer the address a person actually
/// reads when it records one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailRecord {
    pub email: String,
    pub verified: bool,
    pub primary: bool,
}

/// GitHub's display name, with the empty string folded into the absence it
/// actually is.
///
/// A trimmed-to-nothing name is an account that set a name and then took it
/// back, and storing `""` would make a profile that reads as having a name
/// nobody can see. One place rather than at each of the two reads, so the two
/// cannot come to differ about what a blank name means.
fn display_name(name: Option<String>) -> Option<String> {
    name.map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
}

/// The one address of a signed-in person worth recording: the primary, and
/// only if GitHub has verified it.
///
/// Primary because it is the address the person actually reads — the listing
/// carries every address they ever added, and picking any other one would put a
/// long-abandoned forwarding address in front of an app. Verified because an
/// unverified address is a string somebody typed into their settings, and a
/// profile that carried one would let an app that trusted it be told anything.
///
/// `None` when GitHub has no address that is both, which is an ordinary answer
/// and not a failure: it means this identity's profile has no address, and the
/// column stays NULL.
///
/// Note what this address is *not*, because the distinction is the one the
/// whole login flow is built around: it is a claim GitHub makes about a mailbox,
/// stored beside the identity that made it. It is never `users.email` — that is
/// the email connection's credential, proven by a code that has to arrive
/// today — and nothing resolves a user by it.
pub fn primary_verified(emails: &[EmailRecord]) -> Option<&str> {
    emails
        .iter()
        .find(|email| email.primary && email.verified)
        .map(|email| email.email.as_str())
}

/// One team a signed-in person is on, with the organisation it belongs to
/// flattened to its login the way [`AppRecord`] flattens its owner.
///
/// Both halves are kept because a team slug alone is ambiguous: `platform` in
/// two organisations is two different teams, and a mapping rule that matched on
/// the slug alone would grant across a boundary nobody drew.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamRecord {
    pub slug: String,
    pub org: String,
}

/// The wire shapes GitHub answers with.
///
/// None of these carries `deny_unknown_fields`, which is the deliberate
/// opposite of the rule the config and registration structs follow. There, an
/// unknown field is an operator's typo and a secret that silently did not
/// arrive. Here it is GitHub shipping something on a Tuesday, and a spaceport
/// that refused to parse a response because it grew a field would stop
/// reconciling for a reason that has nothing to do with this host.
mod wire {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub(super) struct App {
        pub(super) id: i64,
        pub(super) slug: String,
        pub(super) name: String,
        pub(super) owner: Account,
        /// Defaulted rather than required for the reason nothing here denies
        /// unknown fields: GitHub sends the map today, and a response that
        /// stopped carrying it should read as an App with no permissions to
        /// speak of rather than as a spaceport that cannot ask who it is.
        #[serde(default)]
        pub(super) permissions: std::collections::BTreeMap<String, String>,
    }

    #[derive(Deserialize)]
    pub(super) struct Account {
        pub(super) login: String,
        #[serde(rename = "type")]
        pub(super) account_type: String,
    }

    #[derive(Deserialize)]
    pub(super) struct Installation {
        pub(super) id: i64,
        pub(super) account: Account,
    }

    /// `GET /installation/repositories` wraps its page in an object, unlike
    /// every other listing here, which is why it needs a type of its own.
    #[derive(Deserialize)]
    pub(super) struct RepositoryPage {
        pub(super) repositories: Vec<Repository>,
    }

    #[derive(Deserialize)]
    pub(super) struct Repository {
        pub(super) full_name: String,
    }

    /// One repository asked for by name, which carries fields a listing does
    /// not promise — hence a shape of its own rather than an `Option` bolted on
    /// to [`Repository`], where a missing branch would be indistinguishable
    /// from a listing spaceport forgot to ask the right endpoint for.
    #[derive(Deserialize)]
    pub(super) struct RepositoryDetail {
        pub(super) full_name: String,
        pub(super) default_branch: String,
    }

    /// One branch, of which spaceport reads exactly one thing: the commit it is
    /// at. The rest of GitHub's branch object — the protection rules, the
    /// commit's author, its tree — is left on the wire for the reason
    /// [`RepositoryDetail`] leaves the repository's fields there.
    #[derive(Deserialize)]
    pub(super) struct Branch {
        pub(super) commit: Commit,
    }

    #[derive(Deserialize)]
    pub(super) struct Commit {
        pub(super) sha: String,
    }

    /// What the code exchange answers, which is a token or a complaint — never
    /// both, and GitHub's OAuth endpoint reports the complaint as a `200` with
    /// an `error` field rather than as a status. One shape with options rather
    /// than an untagged enum, because untagged deserialisation swallows the
    /// reason a variant did not match, and this is a response worth reading the
    /// failure of.
    #[derive(Deserialize)]
    pub(super) struct UserToken {
        pub(super) access_token: Option<crate::secret::Secret>,
        pub(super) error: Option<String>,
        pub(super) error_description: Option<String>,
    }

    #[derive(Deserialize)]
    pub(super) struct User {
        pub(super) id: i64,
        pub(super) login: String,
        /// Explicitly nullable *and* defaulted: GitHub sends `"name": null`
        /// for an account that never set one, and the public read of a hidden
        /// account has been known to omit the field outright. Both mean the
        /// same absence, and neither is a reason to fail a sign-in.
        #[serde(default)]
        pub(super) name: Option<String>,
    }

    #[derive(Deserialize)]
    pub(super) struct Email {
        pub(super) email: String,
        pub(super) verified: bool,
        pub(super) primary: bool,
    }

    /// An organisation as the membership listings carry it — its login is the
    /// only field read, so it is the only field named. Not [`Account`], which
    /// requires a `type` these listings do not promise to send.
    #[derive(Deserialize)]
    pub(super) struct Organization {
        pub(super) login: String,
    }

    #[derive(Deserialize)]
    pub(super) struct Team {
        pub(super) slug: String,
        pub(super) organization: Organization,
    }
}

/// A freshly minted installation token, and when it stops working.
#[derive(Deserialize)]
struct MintedToken {
    token: Secret,
    /// RFC 3339, and GitHub's word on the matter — never computed from this
    /// host's clock plus an hour.
    expires_at: String,
}

/// How a request says who is making it.
///
/// The three levels of a GitHub App's authentication, and the distinction
/// matters at every call site: the App itself may read `/app` and mint tokens
/// and nothing else, an installation may read the repositories it was granted
/// and knows nothing about the App, and a user token sees GitHub as the person
/// who signed in — filtered down to what they granted the App. Presenting the
/// wrong one is a `403` with a message about permissions, which is a confusing
/// thing to read.
pub(super) enum Credential {
    /// A JWT the App signed, presented as `Bearer`.
    App(String),
    /// A token GitHub minted for one installation, presented as `token`.
    Installation(Secret),
    /// A token minted from a user's authorization code, presented as `Bearer`.
    ///
    /// GitHub accepts `token` and `Bearer` interchangeably for these; `Bearer`
    /// is the one chosen because it is the OAuth 2.0 scheme the token was
    /// issued under and the spelling GitHub's own documentation shows for
    /// user-to-server calls, so it is the form anybody debugging against the
    /// docs will expect to see on the wire.
    User(Secret),
}

impl Credential {
    fn header(&self) -> String {
        match self {
            Self::App(token) => format!("Bearer {token}"),
            Self::Installation(token) => format!("token {}", token.expose()),
            Self::User(token) => format!("Bearer {}", token.expose()),
        }
    }
}

#[cfg(test)]
impl std::fmt::Debug for Credential {
    /// Only ever formatted by the test that proves a credential cannot give
    /// its token away — the production paths never print one at all.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::App(_) => f.write_str("Credential::App(…)"),
            Self::Installation(token) => write!(f, "Credential::Installation({token:?})"),
            Self::User(token) => write!(f, "Credential::User({token:?})"),
        }
    }
}

/// A conversation with GitHub as one connected App.
///
/// Made for a piece of work — a registration, a reconciliation pass — and
/// dropped when it is done. There is deliberately no registry of clients kept
/// across requests: the only thing a shared one would save is the token
/// minting, and with reconciliation an hour apart and tokens good for an hour,
/// that is one request per installation per hour. A cache with a lifetime, an
/// eviction rule and a lock that outlives every caller does not pay for that.
pub struct Client {
    app_id: i64,
    /// Parsed once here rather than at every signature, so a connection holding
    /// a key that cannot sign fails when the client is made rather than in the
    /// middle of a pass.
    key: ring::signature::RsaKeyPair,
    /// The OAuth client the App is, which is what a login speaks as: the code
    /// exchange authenticates with these rather than with the private key.
    client_id: String,
    client_secret: Secret,
    transport: Arc<dyn Transport>,
    /// Installation tokens, by installation id, with the moment GitHub said
    /// each stops working.
    tokens: Mutex<HashMap<i64, (Secret, OffsetDateTime)>>,
}

impl Client {
    pub fn new(connection: &Connection, transport: Arc<dyn Transport>) -> Result<Self> {
        Ok(Self {
            app_id: connection.app_id,
            key: key::parse(connection.private_key.expose())
                .with_context(|| format!("the private key of `{}`", connection.slug))?,
            client_id: connection.client_id.clone(),
            client_secret: connection.client_secret.clone(),
            transport,
            tokens: Mutex::new(HashMap::new()),
        })
    }

    /// What GitHub says this App is.
    ///
    /// The cheapest question there is, and the one that answers "are these
    /// credentials real": nothing but the App's own key gets an answer.
    pub async fn app(&self) -> Result<AppRecord> {
        let app: wire::App = self
            .fetch("/app", &self.app_credential()?, "app with that id")
            .await?;

        Ok(AppRecord {
            id: app.id,
            slug: app.slug,
            name: app.name,
            owner: app.owner.login,
            permissions: app.permissions,
        })
    }

    /// Every account this App has been installed on.
    pub async fn installations(&self) -> Result<Vec<InstallationRecord>> {
        let pages: Vec<Vec<wire::Installation>> = self
            .paginate(
                "/app/installations",
                &self.app_credential()?,
                "installations of that app",
            )
            .await?;

        Ok(pages
            .into_iter()
            .flatten()
            .map(|installation| InstallationRecord {
                id: installation.id,
                account: installation.account.login,
                account_type: installation.account.account_type,
            })
            .collect())
    }

    /// The repositories an installation grants, as `owner/name`.
    ///
    /// Asked as the installation rather than as the App: the App may know that
    /// an installation exists, and only the installation may see what is in it.
    pub async fn repositories(&self, installation_id: i64) -> Result<Vec<String>> {
        let token = self.installation_token(installation_id).await?;
        let pages: Vec<wire::RepositoryPage> = self
            .paginate(
                "/installation/repositories",
                &Credential::Installation(token),
                &format!("repositories of installation {installation_id}"),
            )
            .await?;

        Ok(pages
            .into_iter()
            .flat_map(|page| page.repositories)
            .map(|repository| repository.full_name)
            .collect())
    }

    /// One repository, as GitHub has it now.
    ///
    /// Asked as the installation, like the listing and for the same reason, and
    /// through [`Self::installation_token`] rather than a mint of its own, so
    /// that tracking several apps in one pass costs one token and not one per
    /// repository.
    ///
    /// Not paginated, because it is one object: there is no `Link` header to
    /// follow and nothing to cap.
    pub async fn repository(
        &self,
        installation_id: i64,
        full_name: &str,
    ) -> Result<RepositoryRecord> {
        let token = self.installation_token(installation_id).await?;
        // `full_name` is already `owner/name`, which is exactly the tail of the
        // path — splitting it here only to join it again would be a chance to
        // get it wrong.
        let repository: wire::RepositoryDetail = self
            .fetch(
                &format!("/repos/{full_name}"),
                &Credential::Installation(token),
                &format!("repository `{full_name}`"),
            )
            .await?;

        Ok(RepositoryRecord {
            default_branch: repository.default_branch,
            full_name: repository.full_name,
        })
    }

    /// The commit a branch is at, as GitHub has it now.
    ///
    /// The question `spaceport apps track` has no other way of answering. A
    /// tracking is built from the revision written down beside it, and a
    /// repository whose last push is older than the tracking will never produce
    /// a delivery to write one — so the head is asked for at the moment the
    /// branch is settled rather than waited for.
    ///
    /// Asked as the installation and through [`Self::installation_token`], like
    /// every other repository call. The branch goes onto the path as it was
    /// given, for the reason a revision does in [`Self::archive_location`]: a
    /// branch may hold slashes, and those slashes are the path's.
    ///
    /// Not paginated, like [`Self::repository`] and for the same reason.
    ///
    /// A branch GitHub does not have comes back as `None` rather than as an
    /// error, which is the one call here that steps around [`refusal`]'s `404`.
    /// That sentence refuses to say whether a thing is missing or ungranted
    /// because GitHub refuses to, and for a repository that is honest. Here it
    /// is not: the repository was settled before this was asked, and what is in
    /// doubt is a branch somebody typed. Handing the case back lets the caller
    /// say so, under a status that means it.
    pub async fn branch_head(
        &self,
        installation_id: i64,
        full_name: &str,
        branch: &str,
    ) -> Result<Option<String>> {
        let token = self.installation_token(installation_id).await?;
        let what = format!("branch `{branch}` of `{full_name}`");
        let response = self
            .send(
                Method::GET,
                &format!("{API}/repos/{full_name}/branches/{branch}"),
                Some(&Credential::Installation(token)),
            )
            .await
            .with_context(|| format!("asking github about the {what}"))?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let branch: wire::Branch = decode(&response, &what)?;

        Ok(Some(branch.commit.sha))
    }

    /// Where GitHub says the tarball of `revision` may be downloaded from.
    ///
    /// The one call in this module that does not want a body. `GET
    /// /repos/{owner}/{repo}/tarball/{ref}` never answers with an archive: it
    /// answers `302` to `codeload.github.com` with a short-lived token in the
    /// query string, and codeload *refuses* a request that forwards the
    /// `Authorization` header this one carried. So the download is two requests
    /// by GitHub's design, and this is the first of them — the authenticated
    /// one, which reads the header and goes no further.
    ///
    /// Following the redirect here is exactly what [`Network::send`] refuses to
    /// do, and it is refused for this endpoint most of all: the whole value of
    /// not following is that an installation token is never replayed to
    /// whatever host answered. The second request is made by
    /// [`crate::build::archive`], to a host it pins, carrying no credential at
    /// all.
    ///
    /// The location is handed back exactly as GitHub wrote it. The token in the
    /// query string is the credential the download is authorised by, and any
    /// parsing, re-encoding or tidying of the url is a chance to break it.
    pub async fn archive_location(
        &self,
        installation_id: i64,
        full_name: &str,
        revision: &str,
    ) -> Result<String> {
        let token = self.installation_token(installation_id).await?;
        let what = format!("archive of `{full_name}` at `{revision}`");
        let response = self
            .send(
                Method::GET,
                &format!("{API}/repos/{full_name}/tarball/{revision}"),
                Some(&Credential::Installation(token)),
            )
            .await
            .with_context(|| format!("asking github for the {what}"))?;

        location(&response, &what)
    }

    /// A token that acts as the person who just authorized on github.com, in
    /// exchange for the code GitHub sent to the login callback.
    ///
    /// This is the one call in the module that leaves [`API`]: the exchange
    /// lives on `github.com` itself, so the request is built here rather than
    /// through [`request`] — that helper carries the REST API's accept and
    /// version headers, and this endpoint is not the REST API and answers
    /// form-encoded unless plain `application/json` is asked for. The
    /// parameters go in a JSON body rather than the query string GitHub also
    /// accepts, because a query string holding the client secret is a secret in
    /// every access log between here and GitHub.
    ///
    /// A refused code comes back as a `200` whose body carries `error` — that
    /// is GitHub's OAuth behaviour, not a quirk — so the body is read before
    /// the status is trusted to mean anything.
    ///
    /// No refresh token is asked for or kept: GitHub only issues them when the
    /// App opts into expiring user tokens, and spaceport spends this token on
    /// the handful of calls a login needs and then drops it. A credential worth
    /// refreshing would be a credential worth storing, which the module's whole
    /// design refuses to do.
    pub async fn exchange_user_code(&self, code: &str) -> Result<Secret> {
        let what = "user authorization code";
        // The one place the client secret leaves its wrapper: onto the wire, to
        // the host pinned above.
        let body = serde_json::json!({
            "client_id": self.client_id,
            "client_secret": self.client_secret.expose(),
            "code": code,
        });
        let request = Request::builder()
            .method(Method::POST)
            .uri(USER_TOKEN_ENDPOINT)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::USER_AGENT, USER_AGENT)
            .body(Bytes::from(body.to_string()))
            .context("preparing the code exchange request")?;
        let response = self
            .transport
            .send(request)
            .await
            .with_context(|| format!("asking github to exchange the {what}"))?;
        let answer: wire::UserToken = decode(&response, what)?;

        if let Some(error) = answer.error {
            let description = answer
                .error_description
                .unwrap_or_else(|| "github gave no further description".to_owned());
            bail!("github refused to exchange the {what} ({error}): {description}");
        }

        answer.access_token.ok_or_else(|| {
            anyhow!(
                "github's answer to the {what} exchange carried neither a token nor an error, which is not how that endpoint is documented to behave"
            )
        })
    }

    /// Who GitHub says the holder of a user token is.
    pub async fn user(&self, token: &Secret) -> Result<UserRecord> {
        let user: wire::User = self
            .fetch("/user", &Credential::User(token.clone()), "signed-in user")
            .await?;

        Ok(UserRecord {
            id: user.id,
            login: user.login,
            name: display_name(user.name),
        })
    }

    /// Every email GitHub holds for the signed-in person, verified or not.
    ///
    /// All of them rather than the verified ones pre-filtered, because which
    /// addresses count is the login flow's decision to make and to explain —
    /// a listing that silently dropped the unverified ones would leave that
    /// flow unable to say "GitHub has your address but has not verified it".
    /// Needs the App's `emails: read`, which the manifest asks for.
    pub async fn user_emails(&self, token: &Secret) -> Result<Vec<EmailRecord>> {
        let pages: Vec<Vec<wire::Email>> = self
            .paginate(
                "/user/emails",
                &Credential::User(token.clone()),
                "emails of the signed-in user",
            )
            .await?;

        Ok(pages
            .into_iter()
            .flatten()
            .map(|email| EmailRecord {
                email: email.email,
                verified: email.verified,
                primary: email.primary,
            })
            .collect())
    }

    /// The organisations the signed-in person belongs to, as their logins.
    ///
    /// Asked with a user token, this is *not* every organisation the person is
    /// in: GitHub only lists the ones where the App is installed and the person
    /// is a member. That is the right narrowing for mapping rules — an
    /// organisation that never installed the App is one no rule about this
    /// spaceport should be granting from — but anybody comparing the answer to
    /// the person's profile page will see fewer, and that is GitHub's doing.
    pub async fn user_orgs(&self, token: &Secret) -> Result<Vec<String>> {
        let pages: Vec<Vec<wire::Organization>> = self
            .paginate(
                "/user/orgs",
                &Credential::User(token.clone()),
                "organisations of the signed-in user",
            )
            .await?;

        Ok(pages
            .into_iter()
            .flatten()
            .map(|organization| organization.login)
            .collect())
    }

    /// The teams the signed-in person is on, each with its organisation.
    ///
    /// Narrowed the way [`Self::user_orgs`] is and for the same reason: only
    /// teams in organisations where the App is installed. Needs the App's
    /// `members: read`, which the manifest asks for.
    pub async fn user_teams(&self, token: &Secret) -> Result<Vec<TeamRecord>> {
        let pages: Vec<Vec<wire::Team>> = self
            .paginate(
                "/user/teams",
                &Credential::User(token.clone()),
                "teams of the signed-in user",
            )
            .await?;

        Ok(pages
            .into_iter()
            .flatten()
            .map(|team| TeamRecord {
                slug: team.slug,
                org: team.organization.login,
            })
            .collect())
    }

    /// Who GitHub says holds a handle, if anybody does.
    ///
    /// The question an operator asserting a binding creates: an identity is
    /// keyed by the numeric account id, and a handle typed at the unix socket
    /// has to be turned into one before anything is written down. Handles are
    /// renameable and reusable, so a binding stored by the name would follow it
    /// to whoever holds it next.
    ///
    /// Asked as an installation, and the credential is presented for what it
    /// lets spaceport *see* rather than for any authority it carries. `GET
    /// /users/{username}` is documented to accept user tokens, installation
    /// tokens and fine-grained PATs, and to require no permission of any of
    /// them — the App's own JWT is the one credential it does not accept, since
    /// a JWT is good only for the App's own endpoints, so [`Self::app_credential`]
    /// must never be reached for here. What an installation token buys is the
    /// enterprise case: an enterprise configured to hide its members answers
    /// `404` to a reader standing outside it, and a `404` is indistinguishable
    /// from "no such handle" — so an operator binding a colleague would be told
    /// the colleague does not exist. Presenting a token from inside makes the
    /// account visible and the answer true. The rate limit improves as a side
    /// effect, five thousand an hour per installation against sixty an hour per
    /// source address, but that is not what this is for: a command an operator
    /// types by hand never comes near either number.
    ///
    /// Every installation is tried, in turn, until one of them can see the
    /// handle. An App may be installed on several organisations and a member
    /// hidden from one enterprise's installation may be plainly visible to
    /// another's, so picking a single installation — the first, the one that
    /// happens to sort lowest — would report "github knows no such account" for
    /// an account that exists and is bindable, which is precisely the failure
    /// this is here to remove. The cost is a handful of requests on a command
    /// an operator types by hand, and only when the earlier installations
    /// cannot see the handle: the first that answers ends the walk.
    ///
    /// A connection with no installations at all falls back to asking with no
    /// credential. A spaceport whose App nobody has installed yet can still
    /// bind a public account, and refusing outright would make an operator
    /// assertion depend on an installation the feature does not otherwise need.
    ///
    /// A failure to *list* the installations is a failure of this call, not a
    /// reason to quietly go out unauthenticated instead. A network that is down
    /// or a key GitHub no longer accepts would then produce a `404` from the
    /// public read of a hidden account, and spaceport would tell the operator
    /// their colleague's handle does not exist — the same confusion this
    /// change removes, rebuilt one layer down. It is reported as what it is.
    ///
    /// A handle no installation can see comes back as `None` rather than as an
    /// error, the way [`Self::branch_head`] hands back a missing branch and for
    /// a stronger reason. [`refusal`]'s `404` refuses to say whether a thing is
    /// absent or ungranted because for a permission-filtered endpoint GitHub
    /// refuses to; this endpoint needs no permission, so once every installation
    /// has been asked its `404` means one thing, and the caller can say "no such
    /// account" under a status that means it.
    pub async fn user_by_login(&self, login: &str) -> Result<Option<UserRecord>> {
        // Checked before the value can reach the url, never escaped into it: an
        // escaped path is still a path spaceport did not mean to ask for, and
        // refusing everything that is not a handle is what makes a `..` segment
        // climbing to another endpoint, or a `?` appending parameters to this
        // one, impossible rather than merely encoded. Checked before the
        // installations are listed, too, so a handle that is not one costs no
        // request at all.
        if !handle(login) {
            bail!(
                "`{login}` is not a github handle — a handle is at most {HANDLE_LIMIT} characters of letters, digits and single hyphens, and never begins or ends with one, so check how the account is spelled on github.com"
            );
        }

        let installations = self.installations().await.with_context(|| {
            format!("finding an installation to read the github account `{login}` as")
        })?;

        if installations.is_empty() {
            return self.account(login, None).await;
        }

        for installation in installations {
            let token = self.installation_token(installation.id).await?;
            let seen = self
                .account(login, Some(&Credential::Installation(token)))
                .await?;

            if seen.is_some() {
                return Ok(seen);
            }
        }

        Ok(None)
    }

    /// One read of `GET /users/{login}` with whatever credential was chosen for
    /// it, where `404` is an answer rather than a refusal.
    ///
    /// Split out of [`Self::user_by_login`] because that call makes this same
    /// read once per installation and once more with nothing, and a loop body
    /// written twice is two places for the `404` to stop meaning "not visible
    /// from here". `login` has already passed [`handle`] — this is private, and
    /// its only caller is the gate.
    async fn account(
        &self,
        login: &str,
        credential: Option<&Credential>,
    ) -> Result<Option<UserRecord>> {
        let what = format!("github account `{login}`");
        let response = self
            .send(Method::GET, &format!("{API}/users/{login}"), credential)
            .await
            .with_context(|| format!("asking github about the {what}"))?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let user: wire::User = decode(&response, &what)?;

        Ok(Some(UserRecord {
            id: user.id,
            // GitHub's own spelling rather than the operator's, for the reason
            // [`RepositoryRecord::full_name`] keeps GitHub's: the API resolves
            // a handle case-insensitively, and the stored name should be the
            // one github.com shows.
            login: user.login,
            // Read because the endpoint sends it, and deliberately dropped on
            // the floor by this read's one caller: `auth user connect` asserts
            // who an account *is*, and a profile it recorded would be one
            // spaceport read over the person's shoulder rather than one they
            // signed in and handed over.
            name: display_name(user.name),
        }))
    }

    /// A token that acts as installation `installation_id`, minting one only if
    /// the one in hand is not good for long enough.
    pub async fn installation_token(&self, installation_id: i64) -> Result<Secret> {
        let now = OffsetDateTime::now_utc();
        if let Some(token) = self.cached(installation_id, now) {
            return Ok(token);
        }

        let minted: MintedToken = self
            .call(
                Method::POST,
                &format!("{API}/app/installations/{installation_id}/access_tokens"),
                Some(&self.app_credential()?),
                &format!("installation {installation_id}"),
            )
            .await?;
        let expires_at = OffsetDateTime::parse(&minted.expires_at, &Rfc3339).with_context(|| {
            format!(
                "github said installation {installation_id}'s token expires at `{}`, which is not a timestamp",
                minted.expires_at
            )
        })?;

        self.tokens
            .lock()
            .expect("the token cache is never held across a panic")
            .insert(installation_id, (minted.token.clone(), expires_at));

        Ok(minted.token)
    }

    /// The token in hand for `installation_id`, if it has more than
    /// [`REFRESH_BEFORE`] left on it.
    fn cached(&self, installation_id: i64, now: OffsetDateTime) -> Option<Secret> {
        let tokens = self
            .tokens
            .lock()
            .expect("the token cache is never held across a panic");
        let (token, expires_at) = tokens.get(&installation_id)?;

        (*expires_at - now > REFRESH_BEFORE).then(|| token.clone())
    }

    /// A JWT signed as this App, good for the next few minutes.
    fn app_credential(&self) -> Result<Credential> {
        jwt::app_jwt(self.app_id, &self.key, OffsetDateTime::now_utc()).map(Credential::App)
    }

    /// One `GET` under [`API`], decoded.
    async fn fetch<T: DeserializeOwned>(
        &self,
        path: &str,
        credential: &Credential,
        what: &str,
    ) -> Result<T> {
        self.call(Method::GET, &format!("{API}{path}"), Some(credential), what)
            .await
    }

    /// Every page of a listing, in order, each decoded whole.
    ///
    /// Pages come back as themselves rather than flattened because GitHub does
    /// not agree with itself about what a page is: a listing is usually a bare
    /// array and sometimes an object with the array inside it. Deciding which
    /// belongs to the caller who knows the endpoint.
    async fn paginate<T: DeserializeOwned>(
        &self,
        path: &str,
        credential: &Credential,
        what: &str,
    ) -> Result<Vec<T>> {
        let mut url = format!("{API}{path}?per_page={PER_PAGE}");
        let mut pages = Vec::new();

        loop {
            let response = self
                .send(Method::GET, &url, Some(credential))
                .await
                .with_context(|| format!("asking github for the {what}"))?;
            let next = next_page(&response);
            pages.push(decode(&response, what)?);

            let Some(next) = next else {
                return Ok(pages);
            };
            if pages.len() >= PAGE_LIMIT {
                bail!(
                    "github is still offering more pages of the {what} after {PAGE_LIMIT} of them, which is more than spaceport will follow — this is either an implausible number of them or a `link` header that points at itself"
                );
            }

            url = next;
        }
    }

    /// One request, decoded, with the status turned into a sentence first.
    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        url: &str,
        credential: Option<&Credential>,
        what: &str,
    ) -> Result<T> {
        let response = self
            .send(method, url, credential)
            .await
            .with_context(|| format!("asking github about the {what}"))?;

        decode(&response, what)
    }

    async fn send(
        &self,
        method: Method,
        url: &str,
        credential: Option<&Credential>,
    ) -> Result<Response<Bytes>> {
        request(self.transport.as_ref(), method, url, credential).await
    }
}

/// One request to GitHub, with the headers every call carries.
///
/// A free function taking the transport rather than a method on [`Client`],
/// because the calls that come before a connection exists — converting an App
/// manifest into an App, which has no credentials and no private key to make
/// one with — need the same headers and have no client to reach for.
pub(super) async fn request(
    transport: &dyn Transport,
    method: Method,
    url: &str,
    credential: Option<&Credential>,
) -> Result<Response<Bytes>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(url)
        .header(header::ACCEPT, ACCEPT)
        .header(API_VERSION_HEADER, API_VERSION)
        .header(header::USER_AGENT, USER_AGENT);

    if let Some(credential) = credential {
        builder = builder.header(header::AUTHORIZATION, credential.header());
    }

    // Never a request body: every call here says everything it has to say in
    // the method and the path.
    let request = builder
        .body(Bytes::new())
        .with_context(|| format!("preparing a request to `{url}`"))?;

    transport.send(request).await
}

/// Whether a string is shaped like a github handle.
///
/// GitHub's grammar, and the reason it is spelled out rather than trusted: the
/// only caller formats this straight into a request path, so this predicate —
/// and not an escaping pass — is what stands between an operator's typing and
/// the url spaceport asks for. ASCII letters and digits, single hyphens between
/// them and never at either end, at most [`HANDLE_LIMIT`] of them. Nothing in
/// that alphabet can be a path separator, a `..` segment or the start of a
/// query string, so those are ruled out by what is allowed rather than by a
/// list of what is not — a list being the thing somebody eventually finds a
/// gap in.
///
/// `len` rather than a count of characters is right here and only here: every
/// accepted byte is ASCII, so the two are the same number, and a string where
/// they differ has already failed the alphabet.
fn handle(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= HANDLE_LIMIT
        && !login.starts_with('-')
        && !login.ends_with('-')
        && !login.contains("--")
        && login
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Read a response as `T`, or say what GitHub answered instead.
fn decode<T: DeserializeOwned>(response: &Response<Bytes>, what: &str) -> Result<T> {
    if !response.status().is_success() {
        return Err(refusal(response, what));
    }

    serde_json::from_slice(response.body()).with_context(|| {
        format!("github's answer about the {what} is not what spaceport expected it to be")
    })
}

/// Read the `Location` of a response that is supposed to be a redirect.
///
/// The mirror image of [`decode`], and it needs its own path because it inverts
/// that function's rule: there every non-2xx is a refusal, and here the *only*
/// good answer is a `302`. A `200` is the case worth being explicit about — it
/// would mean GitHub had started answering this endpoint with the archive
/// itself, and a caller handed a body where it expected a url would go looking
/// for the fault anywhere but here.
///
/// Everything GitHub refuses with — the credentials, the rate limit, a
/// repository or a revision it will not show, its own bad afternoon — is left
/// to [`refusal`], so those read the way they read everywhere else.
fn location(response: &Response<Bytes>, what: &str) -> Result<String> {
    let status = response.status();

    if status.is_client_error() || status.is_server_error() {
        return Err(refusal(response, what));
    }
    if status != StatusCode::FOUND {
        bail!(
            "github answered {status} for the {what} rather than a download location, which is not how that endpoint is documented to behave — spaceport will not guess where the archive is"
        );
    }

    response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            anyhow!(
                "github redirected the {what} without saying where to, so it did not answer with a download location spaceport can fetch"
            )
        })
}

/// What to tell an operator about a status GitHub answered with.
///
/// Every arm is a sentence about what went wrong and what to do next, because
/// this is the text that ends up in the terminal of somebody who has just typed
/// `spaceport connect github`.
fn refusal(response: &Response<Bytes>, what: &str) -> anyhow::Error {
    let status = response.status();

    match status {
        StatusCode::UNAUTHORIZED => anyhow!(
            "github does not accept this app's credentials — the app id or the private key is wrong, so check the `App ID` on the app's settings page and generate a fresh key there"
        ),
        StatusCode::FORBIDDEN if exhausted(response) => anyhow!(
            "github is rate limiting this app and is refusing requests until {} — nothing is wrong with the connection, and the next pass will pick up where this one stopped",
            resets_at(response)
        ),
        // Said without naming which of the two it is, because GitHub does not
        // say either: a repository an installation was never granted is a `404`
        // and not a `403`, deliberately, so that a token cannot be used to find
        // out what exists. A sentence per caller was the alternative, and it
        // would have been several sentences all guessing at the same thing.
        StatusCode::NOT_FOUND => anyhow!(
            "github knows no {what} — it is either not there or not something this app has been granted, so check the `App ID` on the app's settings page and what the app was installed on"
        ),
        _ if status.is_server_error() => anyhow!(
            "github answered {status} when asked about the {what}, which is github's own trouble rather than this spaceport's — it is worth trying again"
        ),
        _ => anyhow!(
            "github answered {status} when asked about the {what}: {}",
            truncated(response.body())
        ),
    }
}

/// Whether a `403` is the rate limiter rather than a permission.
fn exhausted(response: &Response<Bytes>) -> bool {
    response
        .headers()
        .get("x-ratelimit-remaining")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|remaining| remaining.trim() == "0")
}

/// When GitHub says the rate limit refills, in words.
fn resets_at(response: &Response<Bytes>) -> String {
    response
        .headers()
        .get("x-ratelimit-reset")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<i64>().ok())
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .and_then(|moment| moment.format(&Rfc3339).ok())
        // GitHub always sends the header; if it has not, saying so beats
        // printing a moment nobody knows.
        .unwrap_or_else(|| "some point it did not say".to_owned())
}

/// The beginning of a response body, as much of it as is worth reading.
fn truncated(body: &Bytes) -> String {
    let text = String::from_utf8_lossy(body);
    let kept: String = text.chars().take(BODY_LIMIT).collect();

    if kept.chars().count() < text.chars().count() {
        format!("{kept}…")
    } else {
        kept
    }
}

/// The url of the next page of a listing, if GitHub offered one.
///
/// GitHub paginates by `Link` header rather than by a page number spaceport
/// counts up, and following the url it gives is the only way that stays correct
/// when the collection changes underneath the walk.
fn next_page(response: &Response<Bytes>) -> Option<String> {
    let link = response.headers().get(header::LINK)?.to_str().ok()?;

    link.split(',').find_map(|part| {
        let (url, relation) = part.split_once('>')?;

        relation
            .contains(r#"rel="next""#)
            .then(|| url.trim().trim_start_matches('<').to_owned())
    })
}

/// A GitHub the whole crate's tests can answer with.
///
/// Not private to this module's tests, because everything above it — the
/// registration flow, the operator handler that drives it — now has to hand a
/// transport down, and a second fake for each of them would be a second set of
/// canned responses to keep true to GitHub.
#[cfg(test)]
pub(crate) mod testing;

#[cfg(test)]
mod tests {
    use super::*;
    use testing::{Authorization, FakeGitHub};

    /// A connection as one is read back out of the state store, with the
    /// fixture key so the client can be built and can sign.
    fn connection() -> Connection {
        Connection {
            slug: "spaceport-for-acme".to_owned(),
            app_id: 42,
            name: "Spaceport for Acme".to_owned(),
            owner: "an-organisation".to_owned(),
            client_id: "Iv1.0123456789abcdef".to_owned(),
            client_secret: Secret::new("a-client-secret"),
            webhook_secret: Secret::new("a-webhook-secret"),
            private_key: Secret::new(key::testing::PKCS1),
            connected_at: String::new(),
        }
    }

    fn client(github: &Arc<FakeGitHub>) -> Client {
        Client::new(&connection(), github.clone()).unwrap()
    }

    #[tokio::test]
    async fn reads_the_app_github_says_this_is() {
        let github = FakeGitHub::new();

        let app = client(&github).app().await.unwrap();

        assert_eq!(app.id, 42);
        assert_eq!(app.slug, "spaceport-for-acme");
        assert_eq!(app.name, "Spaceport for Acme");
        assert_eq!(app.owner, "an-organisation");
        // The permissions ride along on the same answer — `members` is the one
        // the mapping handler asks after, so it is the one asserted by name.
        assert_eq!(
            app.permissions.get("members").map(String::as_str),
            Some("read")
        );
        assert_eq!(
            app.permissions.get("emails").map(String::as_str),
            Some("read")
        );
    }

    /// `/app` is about the App itself, so only the App's own signature opens
    /// it — an installation token is refused there.
    #[tokio::test]
    async fn reads_the_app_with_the_signed_token_rather_than_an_installation_one() {
        let github = FakeGitHub::new();

        client(&github).app().await.unwrap();

        let requests = github.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/app");
        assert_eq!(requests[0].authorization, Authorization::Jwt);
    }

    #[tokio::test]
    async fn lists_the_installations_across_every_page() {
        let github = FakeGitHub::new();
        github.installations_in_pages(&[&[(1, "alpha", "Organization")], &[(2, "beta", "User")]]);

        let installations = client(&github).installations().await.unwrap();

        assert_eq!(
            installations,
            [
                InstallationRecord {
                    id: 1,
                    account: "alpha".to_owned(),
                    account_type: "Organization".to_owned(),
                },
                InstallationRecord {
                    id: 2,
                    account: "beta".to_owned(),
                    account_type: "User".to_owned(),
                },
            ]
        );
        assert_eq!(github.requests().len(), 2);
    }

    /// The App may know an installation exists; only the installation may see
    /// what is in it. Presenting the wrong credential here is a `403` about
    /// permissions that reads like a misconfigured app.
    #[tokio::test]
    async fn reads_repositories_as_the_installation_and_not_as_the_app() {
        let github = FakeGitHub::new();
        github.repositories_in_pages(&[&["an-organisation/site"], &["an-organisation/api"]]);

        let repositories = client(&github).repositories(7).await.unwrap();

        assert_eq!(
            repositories,
            ["an-organisation/site", "an-organisation/api"]
        );
        let listings: Vec<Authorization> = github
            .requests()
            .into_iter()
            .filter(|request| request.path == "/installation/repositories")
            .map(|request| request.authorization)
            .collect();
        assert_eq!(listings, [Authorization::Token, Authorization::Token]);
        // And the mint itself is the App speaking, since an installation
        // cannot mint its own token.
        assert_eq!(github.requests()[0].authorization, Authorization::Jwt);
    }

    /// The branch a tracked app follows is resolved once, here, so this is the
    /// call that decides it — and it is asked as the installation, since the
    /// App itself may not read a repository.
    #[tokio::test]
    async fn asks_for_a_repository_with_an_installation_token() {
        let github = FakeGitHub::new();
        github.repository_defaults_to("an-organisation/site", "trunk");

        let repository = client(&github)
            .repository(7, "an-organisation/site")
            .await
            .unwrap();

        assert_eq!(
            repository,
            RepositoryRecord {
                default_branch: "trunk".to_owned(),
                full_name: "an-organisation/site".to_owned(),
            }
        );
        let read = github
            .requests()
            .into_iter()
            .find(|request| request.path == "/repos/an-organisation/site")
            .expect("the repository was read");
        assert_eq!(read.authorization, Authorization::Token);
    }

    /// Tracking several apps in one pass must not mint a token per repository:
    /// the same cache and the same refresh window as every other call.
    #[tokio::test]
    async fn reads_a_second_repository_with_the_token_already_in_hand() {
        let github = FakeGitHub::new();
        github.repository_defaults_to("an-organisation/api", "main");
        let client = client(&github);

        client.repository(7, "an-organisation/site").await.unwrap();
        client.repository(7, "an-organisation/api").await.unwrap();

        assert_eq!(github.minted(), 1);
    }

    #[tokio::test]
    async fn says_when_the_repository_is_one_github_will_not_show() {
        let github = FakeGitHub::new();

        let error = format!(
            "{:#}",
            client(&github)
                .repository(7, "an-organisation/nowhere")
                .await
                .unwrap_err()
        );

        assert!(
            error.contains("knows no repository `an-organisation/nowhere`"),
            "{error}"
        );
        assert!(error.contains("has been granted"), "{error}");
    }

    /// The head is what a tracking is built from, so this is the call that
    /// gives a freshly tracked app something to build — as the installation,
    /// since the App itself may not read a repository.
    #[tokio::test]
    async fn asks_what_commit_a_branch_is_at_with_an_installation_token() {
        let github = FakeGitHub::new();
        github.branch_is_at("an-organisation/site", "release/2026", "d34db33f");

        let head = client(&github)
            .branch_head(7, "an-organisation/site", "release/2026")
            .await
            .unwrap();

        assert_eq!(head.as_deref(), Some("d34db33f"));
        let read = github
            .requests()
            .into_iter()
            .find(|request| request.path == "/repos/an-organisation/site/branches/release/2026")
            .expect("the branch was read");
        assert_eq!(read.authorization, Authorization::Token);
    }

    /// A mistyped `--branch` is the likeliest way anybody reaches this, which
    /// is why it is not an error: the caller knows it asked about a branch, and
    /// can say so far better than a sentence written for repositories.
    #[tokio::test]
    async fn answers_with_nothing_for_a_branch_github_does_not_have() {
        let github = FakeGitHub::new();

        let head = client(&github)
            .branch_head(7, "an-organisation/site", "mian")
            .await
            .expect("a branch that is not there is an answer, not a failure");

        assert_eq!(head, None);
    }

    /// The archive is read as the installation like every other repository
    /// call, and through the same cache — a build is not a reason to mint a
    /// token of its own.
    #[tokio::test]
    async fn asks_where_a_revision_may_be_downloaded_from_with_an_installation_token() {
        let github = FakeGitHub::new();
        github.archives_at(
            "an-organisation/site",
            "d34db33f",
            "https://codeload.github.com/an-organisation/site/legacy.tar.gz/d34db33f",
        );

        client(&github)
            .archive_location(7, "an-organisation/site", "d34db33f")
            .await
            .unwrap();

        let asked = github
            .requests()
            .into_iter()
            .find(|request| request.path == "/repos/an-organisation/site/tarball/d34db33f")
            .expect("the archive location was asked for");
        assert_eq!(asked.authorization, Authorization::Token);
    }

    /// The token in the query string is what authorises the download, so the
    /// location has to come back byte for byte — anything that parses and
    /// rebuilds the url is a chance to drop it.
    #[tokio::test]
    async fn hands_back_the_location_github_gave_including_its_token() {
        let github = FakeGitHub::new();
        let location = "https://codeload.github.com/an-organisation/site/legacy.tar.gz/d34db33f?token=ABCDEF%2F123";
        github.archives_at("an-organisation/site", "d34db33f", location);

        let answer = client(&github)
            .archive_location(7, "an-organisation/site", "d34db33f")
            .await
            .unwrap();

        assert_eq!(answer, location);
    }

    /// A `200` here would mean the archive itself had arrived on a path
    /// spaceport reads a header off, and a caller handed bytes where it wanted
    /// a url would look for the fault everywhere but here.
    #[tokio::test]
    async fn refuses_an_archive_answer_that_is_not_a_redirect() {
        let github = FakeGitHub::new();
        let client = client(&github);
        // Minted first, so that answering everything with `200` afterwards is
        // about the tarball call and not about the token.
        client.installation_token(7).await.unwrap();
        github.refuse_with(StatusCode::OK, "a tarball, apparently");

        let error = format!(
            "{:#}",
            client
                .archive_location(7, "an-organisation/site", "d34db33f")
                .await
                .unwrap_err()
        );

        assert!(error.contains("rather than a download location"), "{error}");
        assert!(error.contains("will not guess"), "{error}");
    }

    #[tokio::test]
    async fn says_when_the_revision_is_one_github_will_not_show() {
        let github = FakeGitHub::new();

        let error = format!(
            "{:#}",
            client(&github)
                .archive_location(7, "an-organisation/site", "d34db33f")
                .await
                .unwrap_err()
        );

        assert!(
            error.contains("knows no archive of `an-organisation/site` at `d34db33f`"),
            "{error}"
        );
        assert!(error.contains("has been granted"), "{error}");
    }

    #[tokio::test]
    async fn mints_a_token_once_and_uses_it_again() {
        let github = FakeGitHub::new();
        let client = client(&github);

        let first = client.installation_token(7).await.unwrap();
        let second = client.installation_token(7).await.unwrap();

        assert_eq!(first, second);
        assert_eq!(github.minted(), 1);
    }

    #[tokio::test]
    async fn mints_a_new_token_when_the_one_in_hand_has_expired() {
        let github = FakeGitHub::new();
        github.tokens_expiring_in(Duration::minutes(-1));
        let client = client(&github);

        client.installation_token(7).await.unwrap();
        client.installation_token(7).await.unwrap();

        assert_eq!(github.minted(), 2);
    }

    /// A token good for another two minutes is a token a request may well
    /// outlive, so it is spent rather than used.
    #[tokio::test]
    async fn mints_a_new_token_when_the_one_in_hand_is_about_to_expire() {
        let github = FakeGitHub::new();
        github.tokens_expiring_in(REFRESH_BEFORE - Duration::minutes(3));
        let client = client(&github);

        client.installation_token(7).await.unwrap();
        client.installation_token(7).await.unwrap();

        assert_eq!(github.minted(), 2);
    }

    #[tokio::test]
    async fn a_separate_installation_gets_a_token_of_its_own() {
        let github = FakeGitHub::new();
        let client = client(&github);

        let seven = client.installation_token(7).await.unwrap();
        let eight = client.installation_token(8).await.unwrap();

        assert_ne!(seven, eight);
        assert_eq!(github.minted(), 2);
    }

    #[tokio::test]
    async fn says_that_the_credentials_are_not_accepted() {
        let github = FakeGitHub::new();
        github.refuse_with(StatusCode::UNAUTHORIZED, "Bad credentials");

        let error = format!("{:#}", client(&github).app().await.unwrap_err());

        assert!(
            error.contains("does not accept this app's credentials"),
            "{error}"
        );
        assert!(error.contains("App ID"), "{error}");
    }

    #[tokio::test]
    async fn says_when_the_app_id_names_no_app() {
        let github = FakeGitHub::new();
        github.refuse_with(StatusCode::NOT_FOUND, "Not Found");

        let error = format!("{:#}", client(&github).app().await.unwrap_err());

        assert!(error.contains("knows no app with that id"), "{error}");
    }

    /// A `403` is a permission problem *unless* the rate limit headers say it
    /// is not, and the two want quite different reactions.
    #[tokio::test]
    async fn says_when_the_rate_limit_is_spent_and_when_it_refills() {
        let github = FakeGitHub::new();
        github.refuse_with(StatusCode::FORBIDDEN, "API rate limit exceeded");
        github.exhaust_the_rate_limit(1_800_000_000);

        let error = format!("{:#}", client(&github).app().await.unwrap_err());

        assert!(error.contains("rate limiting"), "{error}");
        assert!(error.contains("2027-01-15"), "{error}");
    }

    #[tokio::test]
    async fn says_that_a_server_error_is_githubs_own_trouble() {
        let github = FakeGitHub::new();
        github.refuse_with(StatusCode::BAD_GATEWAY, "<html>");

        let error = format!("{:#}", client(&github).app().await.unwrap_err());

        assert!(error.contains("github's own trouble"), "{error}");
        assert!(error.contains("worth trying again"), "{error}");
    }

    /// An unrecognised status has to carry the status and something of the
    /// body, and the body has to stop: a whole error page in a log line is a
    /// denial of service on whoever reads it.
    #[tokio::test]
    async fn reports_an_unknown_status_with_a_truncated_body() {
        let github = FakeGitHub::new();
        github.refuse_with(StatusCode::IM_A_TEAPOT, &"x".repeat(BODY_LIMIT * 3));

        let error = format!("{:#}", client(&github).app().await.unwrap_err());

        assert!(error.contains("418"), "{error}");
        assert!(error.contains('…'), "{error}");
        assert!(error.len() < BODY_LIMIT * 2, "{}", error.len());
    }

    /// A `Link` header that points at the page it came from is a loop, and a
    /// loop inside a reconciliation pass is a spaceport that never finishes
    /// one again.
    #[tokio::test]
    async fn refuses_to_follow_pages_for_ever() {
        let github = FakeGitHub::new();
        github.paginate_endlessly();

        let error = format!("{:#}", client(&github).installations().await.unwrap_err());

        assert!(error.contains("more than spaceport will follow"), "{error}");
        assert_eq!(github.requests().len(), PAGE_LIMIT);
    }

    /// GitHub requires the user agent and answers the wrong shape without the
    /// accept header, and neither failure would be obvious from the response.
    #[tokio::test]
    async fn every_request_says_what_it_accepts_which_version_and_who_it_is() {
        let github = FakeGitHub::new();
        let client = client(&github);
        client.app().await.unwrap();
        client.repositories(7).await.unwrap();

        let requests = github.requests();
        assert!(requests.len() >= 3);
        for request in requests {
            assert_eq!(request.accept.as_deref(), Some(ACCEPT), "{}", request.path);
            assert_eq!(
                request.api_version.as_deref(),
                Some(API_VERSION),
                "{}",
                request.path
            );
            assert_eq!(
                request.user_agent.as_deref(),
                Some(USER_AGENT),
                "{}",
                request.path
            );
        }
    }

    /// The exchange is what turns a login callback into somebody: the code
    /// GitHub sent comes back as a token, and both halves of the App's OAuth
    /// client have to be on the request — which the fake checks, so this test
    /// proves the secret was sent and not just that a token came back.
    #[tokio::test]
    async fn exchanges_a_login_code_for_a_user_token() {
        let github = FakeGitHub::new();
        github.signs_in("a-login-code", "ghu_a-user-token", 1001, "octocat");

        let token = client(&github)
            .exchange_user_code("a-login-code")
            .await
            .unwrap();

        assert_eq!(token.expose(), "ghu_a-user-token");
        let exchange = github
            .requests()
            .into_iter()
            .find(|request| request.path == "/login/oauth/access_token")
            .expect("the exchange was asked for");
        // No credential header: the client id and secret in the body are the
        // whole of the authentication.
        assert_eq!(exchange.authorization, Authorization::None);
        // Plain JSON asked for, because github.com's OAuth endpoint answers
        // form-encoded without it — this is not the REST API.
        assert_eq!(exchange.accept.as_deref(), Some("application/json"));
    }

    /// GitHub reports a refused code as a `200` whose body carries `error`, so
    /// a client that only read the status would hand a "token" that is really
    /// a complaint to the login flow. The description is the part a person
    /// debugging a broken login can act on, so it has to reach the message.
    #[tokio::test]
    async fn surfaces_githubs_oauth_error_with_its_description() {
        let github = FakeGitHub::new();

        let error = format!(
            "{:#}",
            client(&github)
                .exchange_user_code("a-code-nobody-issued")
                .await
                .unwrap_err()
        );

        assert!(error.contains("bad_verification_code"), "{error}");
        assert!(error.contains("incorrect or expired"), "{error}");
    }

    /// The id is what an identity is keyed by and the login is what a person
    /// recognises, and the call is made as the person — the fake refuses it
    /// under anything but their token, so the recorded credential is proof.
    /// The display name rides along as the third thing, for the profile.
    #[tokio::test]
    async fn reads_who_the_signed_in_person_is() {
        let github = FakeGitHub::new();
        github.signs_in("a-login-code", "ghu_a-user-token", 1001, "octocat");
        github.user_is_called("Mona Lisa");

        let user = client(&github)
            .user(&Secret::new("ghu_a-user-token"))
            .await
            .unwrap();

        assert_eq!(
            user,
            UserRecord {
                id: 1001,
                login: "octocat".to_owned(),
                name: Some("Mona Lisa".to_owned()),
            }
        );
        let read = github
            .requests()
            .into_iter()
            .find(|request| request.path == "/user")
            .expect("the user was read");
        assert_eq!(read.authorization, Authorization::User);
    }

    /// The emails are what verified-email linking reads, so the flags have to
    /// survive the trip — and GitHub paginates the listing, so a person with
    /// many addresses must not lose the ones past the first page.
    #[tokio::test]
    async fn reads_the_persons_emails_across_every_page() {
        let github = FakeGitHub::new();
        github.signs_in("a-login-code", "ghu_a-user-token", 1001, "octocat");
        github.user_emails_in_pages(&[
            &[("octocat@acme.example", true, true)],
            &[("octocat@example.com", false, false)],
        ]);

        let emails = client(&github)
            .user_emails(&Secret::new("ghu_a-user-token"))
            .await
            .unwrap();

        assert_eq!(
            emails,
            [
                EmailRecord {
                    email: "octocat@acme.example".to_owned(),
                    verified: true,
                    primary: true,
                },
                EmailRecord {
                    email: "octocat@example.com".to_owned(),
                    verified: false,
                    primary: false,
                },
            ]
        );
    }

    #[tokio::test]
    async fn reads_the_organisations_github_shows_the_signed_in_person() {
        let github = FakeGitHub::new();
        github.signs_in("a-login-code", "ghu_a-user-token", 1001, "octocat");
        github.user_belongs_to_orgs(&["acme-corp", "another-org"]);

        let orgs = client(&github)
            .user_orgs(&Secret::new("ghu_a-user-token"))
            .await
            .unwrap();

        assert_eq!(orgs, ["acme-corp", "another-org"]);
    }

    /// A team slug alone is ambiguous across organisations, which is why the
    /// record carries both halves — a mapping rule grants inside one org, not
    /// wherever a slug happens to repeat.
    #[tokio::test]
    async fn reads_the_persons_teams_with_the_organisation_each_belongs_to() {
        let github = FakeGitHub::new();
        github.signs_in("a-login-code", "ghu_a-user-token", 1001, "octocat");
        github.user_belongs_to_teams(&[("acme-corp", "platform"), ("another-org", "platform")]);

        let teams = client(&github)
            .user_teams(&Secret::new("ghu_a-user-token"))
            .await
            .unwrap();

        assert_eq!(
            teams,
            [
                TeamRecord {
                    slug: "platform".to_owned(),
                    org: "acme-corp".to_owned(),
                },
                TeamRecord {
                    slug: "platform".to_owned(),
                    org: "another-org".to_owned(),
                },
            ]
        );
    }

    /// The one address a profile may carry: primary *and* verified. Either flag
    /// alone picks a different address here, which is the point — an
    /// abandoned-but-verified forwarding address is not what the person reads,
    /// and an unverified primary is a string they typed into their settings.
    #[test]
    fn takes_the_primary_verified_address_and_no_other() {
        let emails = [
            ("old@example.com", true, false),
            ("typo@example.com", false, true),
            ("mona@acme.example", true, true),
        ]
        .map(|(email, verified, primary)| EmailRecord {
            email: email.to_owned(),
            verified,
            primary,
        });

        assert_eq!(primary_verified(&emails), Some("mona@acme.example"));
    }

    /// An account whose primary address github has not verified has no profile
    /// address at all — the column stays empty rather than taking the best
    /// available string.
    #[test]
    fn takes_no_address_at_all_when_none_is_both() {
        let emails = [EmailRecord {
            email: "typo@example.com".to_owned(),
            verified: false,
            primary: true,
        }];

        assert_eq!(primary_verified(&emails), None);
        assert_eq!(primary_verified(&[]), None);
    }

    /// A name github sends as null, as blank, or as spaces is the same absence
    /// three ways, and a profile that stored `""` would read as a name nobody
    /// can see.
    #[test]
    fn a_blank_display_name_is_no_display_name() {
        assert_eq!(display_name(None), None);
        assert_eq!(display_name(Some(String::new())), None);
        assert_eq!(display_name(Some("   ".to_owned())), None);
        assert_eq!(
            display_name(Some("  Mona Lisa  ".to_owned())),
            Some("Mona Lisa".to_owned())
        );
    }

    /// The user endpoints answer as the person the token is, so a token that is
    /// not theirs must be refused — a fake that waved any `Bearer` through
    /// would let the App's own JWT pass exactly where it must not.
    #[tokio::test]
    async fn refuses_a_user_call_that_presents_the_wrong_token() {
        let github = FakeGitHub::new();
        github.signs_in("a-login-code", "ghu_a-user-token", 1001, "octocat");

        let error = format!(
            "{:#}",
            client(&github)
                .user(&Secret::new("ghu_somebody-elses-token"))
                .await
                .unwrap_err()
        );

        assert!(error.contains("credentials"), "{error}");
    }

    /// The lookup a binding is built on: the operator types a handle and what
    /// gets written down is the numeric id, so the id has to survive the trip
    /// and the login has to come back as github spells it.
    #[tokio::test]
    async fn reads_which_account_holds_a_handle() {
        let github = FakeGitHub::new();
        github.hosts_account("octocat", 1001);

        let account = client(&github).user_by_login("octocat").await.unwrap();

        assert_eq!(
            account,
            Some(UserRecord {
                id: 1001,
                login: "octocat".to_owned(),
                // The public read carries a display name too; this account
                // simply has none, and the binding would not have stored one
                // either way.
                name: None,
            })
        );
    }

    /// The one assertion that catches somebody putting the app's own signature
    /// back on this call, or taking the credential off it again. `GET
    /// /users/{username}` does not accept an app JWT — a jwt here would be
    /// refused by real github while every other test in this file went on
    /// passing — and asking with nothing is what makes a hidden enterprise
    /// member read as an account that does not exist.
    #[tokio::test]
    async fn asks_who_holds_a_handle_as_an_installation_rather_than_as_the_app() {
        let github = FakeGitHub::new();
        github.hosts_account("octocat", 1001);

        client(&github).user_by_login("octocat").await.unwrap();

        let read = github
            .requests()
            .into_iter()
            .find(|request| request.path == "/users/octocat")
            .expect("the account was read");
        assert_eq!(read.authorization, Authorization::Token);
    }

    /// The enterprise case this credential exists for: an organisation with
    /// member privacy turned on denies its people to anybody reading from
    /// outside, so an account one installation cannot see may be plainly
    /// visible to another. Stopping at the first installation would tell an
    /// operator that a colleague they can see on github.com does not exist.
    #[tokio::test]
    async fn finds_an_account_only_the_second_installation_is_allowed_to_see() {
        let github = FakeGitHub::new();
        github.installations_in_pages(&[&[
            (7, "an-organisation", "Organization"),
            (8, "an-enterprise", "Organization"),
        ]]);
        github.hosts_account_visible_only_to("octocat", 1001, 8);

        let account = client(&github).user_by_login("octocat").await.unwrap();

        assert_eq!(
            account,
            Some(UserRecord {
                id: 1001,
                login: "octocat".to_owned(),
                // The public read carries a display name too; this account
                // simply has none, and the binding would not have stored one
                // either way.
                name: None,
            })
        );
        // Both installations were asked, in order — the first is the one that
        // could not see the account, and skipping it would make this pass for
        // the wrong reason.
        let mints: Vec<String> = github
            .requests()
            .into_iter()
            .filter(|request| request.path.ends_with("/access_tokens"))
            .map(|request| request.path)
            .collect();
        assert_eq!(
            mints,
            [
                "/app/installations/7/access_tokens",
                "/app/installations/8/access_tokens",
            ]
        );
        assert_eq!(
            github
                .requests()
                .into_iter()
                .filter(|request| request.path == "/users/octocat")
                .count(),
            2
        );
    }

    /// A handle nobody holds is the likeliest way anybody reaches this — the
    /// operator mistyped it. The endpoint needs no permission of the token it
    /// was asked with, so once every installation has answered `404` that `404`
    /// means one thing, and the caller may say so rather than repeating
    /// [`refusal`]'s hedge about grants.
    #[tokio::test]
    async fn answers_with_nothing_for_a_handle_no_installation_can_see() {
        let github = FakeGitHub::new();
        github.installations_in_pages(&[&[
            (7, "an-organisation", "Organization"),
            (8, "an-enterprise", "Organization"),
        ]]);

        let account = client(&github)
            .user_by_login("nobody-at-all")
            .await
            .expect("a handle that is not there is an answer, not a failure");

        assert_eq!(account, None);
        assert_eq!(
            github
                .requests()
                .into_iter()
                .filter(|request| request.path == "/users/nobody-at-all")
                .count(),
            2
        );
    }

    /// A spaceport whose app nobody has installed yet still has public accounts
    /// to bind, and refusing here would make an operator assertion wait on an
    /// installation the feature does not otherwise need.
    #[tokio::test]
    async fn reads_a_public_account_with_no_credential_when_nothing_has_installed_the_app() {
        let github = FakeGitHub::new();
        github.is_installed_nowhere();
        github.hosts_account("octocat", 1001);

        let account = client(&github).user_by_login("octocat").await.unwrap();

        assert_eq!(
            account,
            Some(UserRecord {
                id: 1001,
                login: "octocat".to_owned(),
                // The public read carries a display name too; this account
                // simply has none, and the binding would not have stored one
                // either way.
                name: None,
            })
        );
        let read = github
            .requests()
            .into_iter()
            .find(|request| request.path == "/users/octocat")
            .expect("the account was read");
        assert_eq!(read.authorization, Authorization::None);
        assert_eq!(github.minted(), 0);
    }

    /// Listing the installations failing must not degrade into the
    /// unauthenticated read, because that read would answer `404` for exactly
    /// the hidden account this call exists to find — and the operator would be
    /// told their colleague's handle is unknown rather than that github could
    /// not be reached.
    #[tokio::test]
    async fn fails_rather_than_falling_back_when_the_installations_cannot_be_listed() {
        let github = FakeGitHub::new();
        github.refuses_the_app(42);

        let error = format!(
            "{:#}",
            client(&github).user_by_login("octocat").await.unwrap_err()
        );

        assert!(error.contains("finding an installation"), "{error}");
        assert!(
            error.contains("does not accept this app's credentials"),
            "{error}"
        );
        assert!(!error.contains("knows no"), "{error}");
    }

    /// The handle is operator input formatted straight into a path, so anything
    /// that is not a handle has to be refused *before* a request exists — an
    /// escaped `../app` is still a request for another endpoint, and a `?` is
    /// still query parameters spaceport did not mean to send. The empty request
    /// log is the assertion that matters.
    #[tokio::test]
    async fn refuses_a_handle_that_is_not_one_without_asking_github_anything() {
        for login in [
            "../app",
            "foo/bar",
            "octocat?per_page=1",
            "-lead",
            "trail-",
            "double--hyphen",
            "octo cat",
            "",
            "a-handle-far-longer-than-github-ever-issues-x",
        ] {
            let github = FakeGitHub::new();

            let error = format!(
                "{:#}",
                client(&github).user_by_login(login).await.unwrap_err()
            );

            assert!(error.contains("not a github handle"), "{login}: {error}");
            assert!(
                github.requests().is_empty(),
                "`{login}` reached the transport"
            );
        }
    }

    /// The `Option` says "github has no such account" and must not quietly
    /// swallow anything else: github having a bad afternoon is trouble worth
    /// failing on, not an answer of "no".
    #[tokio::test]
    async fn still_fails_when_the_handle_lookup_goes_wrong_for_some_other_reason() {
        let github = FakeGitHub::new();
        // Only the account read is refused, so the failure under test is that
        // read's rather than the listing that now comes before it.
        github.refuse_path_with("/users/octocat", StatusCode::INTERNAL_SERVER_ERROR, "");

        let error = format!(
            "{:#}",
            client(&github).user_by_login("octocat").await.unwrap_err()
        );

        assert!(error.contains("github account `octocat`"), "{error}");
        assert!(error.contains("trying again"), "{error}");
    }

    /// The user token is a credential like the installation one, and the same
    /// rule holds: it must not survive a `Debug` format, however it got there.
    #[tokio::test]
    async fn never_puts_a_user_token_in_a_debug_line() {
        let credential = Credential::User(Secret::new("ghu_a-user-token"));

        assert!(!format!("{credential:?}").contains("ghu_a-user-token"));
    }

    /// The whole point of [`Secret`]: a token spaceport is holding must not
    /// reach an error message or a debug line, however the error was made.
    #[tokio::test]
    async fn never_puts_an_installation_token_in_an_error_or_a_debug_line() {
        let github = FakeGitHub::new();
        let client = client(&github);
        let token = client.installation_token(7).await.unwrap();
        let plaintext = token.expose().to_owned();
        assert!(!plaintext.is_empty());

        github.refuse_with(StatusCode::IM_A_TEAPOT, &plaintext);
        let error = format!("{:#}", client.repositories(7).await.unwrap_err());
        let cache = format!(
            "{:?}",
            client
                .tokens
                .lock()
                .expect("nothing else holds the cache")
                .get(&7)
        );

        // The body is echoed back, so the message may hold the plaintext GitHub
        // said — what must not appear is spaceport's own copy of it, which is
        // what the cache formats.
        assert!(!cache.contains(&plaintext), "{cache}");
        assert!(!format!("{:?}", Credential::Installation(token)).contains(&plaintext));
        assert!(error.contains("418"), "{error}");
    }
}

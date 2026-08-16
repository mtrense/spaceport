mod render;

use std::io::Read as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use render::Colour;
use spaceport_core::acme::account::{AcmeCa, Transport};
use spaceport_core::acme::{CertificateRepository, Certificates, Challenges};
use spaceport_core::app::{
    self, AppId, AppRepository, AppStore, Applier, DataDir, Pattern, SecretRepository, VarName,
    reconcile, supervise,
};
use spaceport_core::auth::{
    AuthLogRepository, EntitlementRepository, JwtCache, JwtSigner, RevokeScope, RoleAtApp,
    SessionId, SessionRepository, UserId, UserRef, UserRepository, UserSlug, jwt,
};
use spaceport_core::build;
use spaceport_core::build::dir::BuildDir;
use spaceport_core::build::repository::BuildRepository;
use spaceport_core::config::TlsProvider;
use spaceport_core::connections::github::{self, ConnectionRepository};
use spaceport_core::events::{self, Category, Event, EventBus, Level};
use spaceport_core::operator::client::Watch;
use spaceport_core::operator::{
    DEFAULT_OPERATOR_ENDPOINT, SecretOutcome, SecretSet, client, server,
};
use spaceport_core::runtime::DockerRuntime;
use spaceport_core::secret::Secret;
use spaceport_core::setup;
use spaceport_core::state::{self, Db, StateLock};
use spaceport_core::status::Instance;
use spaceport_core::{Config, OperatorEndpoint, acme, config::DEFAULT_CONFIG_PATH, edge};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// What goes to stdout, unless `RUST_LOG` says otherwise.
const DEFAULT_LOG_FILTER: &str = "spaceport=info,warn";

/// What `spaceport stream` carries, unless this names something else.
const STREAM_FILTER_VAR: &str = "SPACEPORT_STREAM";

/// Spaceport's own events, down to debug, and nothing else.
///
/// The crates underneath spaceport — the docker client, rustls, hyper — have a
/// great deal to say at debug level, and none of it is about what this
/// spaceport is doing. The prefix covers `spaceport` and `spaceport_core`
/// alike, which is every module that means anything to an operator.
const DEFAULT_STREAM_FILTER: &str = "spaceport=debug";

/// A reverse proxy for small and internal apps.
#[derive(Debug, Parser)]
#[command(name = "spaceport", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start spaceport in the foreground.
    Run(RunArgs),
    /// Install this spaceport on the host as a system service, or update the
    /// one that is already installed.
    Setup(SetupArgs),
    /// Check that spaceport is set up correctly.
    Check {
        #[command(subcommand)]
        command: CheckCommand,
    },
    /// Manage the apps a running spaceport serves.
    Apps {
        #[command(subcommand)]
        command: AppsCommand,
    },
    /// Manage who a running spaceport knows: the user pool, and the record of
    /// what happened to it.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Manage what a running spaceport is registered as, out on the internet.
    Connect {
        #[command(subcommand)]
        command: ConnectCommand,
    },
    /// Watch what a running spaceport is doing, as it does it.
    Stream(StreamArgs),
    /// Report what a running spaceport is and how it is doing.
    Status(StatusArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    #[command(flatten)]
    config: ConfigArgs,

    /// Expose the operator interface on a unix socket path or local address.
    #[arg(short, long, value_name = "SOCKET|ADDRESS")]
    operator: Option<OperatorEndpoint>,
}

#[derive(Debug, Args)]
struct SetupArgs {
    /// A config file to install at the config path. Without one, a host that
    /// has no config yet gets a reference one to edit.
    #[arg(short, long, value_name = "FILE")]
    initial_config: Option<PathBuf>,

    #[command(flatten)]
    config: ConfigArgs,

    /// Expose the operator interface on a unix socket path or local address.
    /// Leaving it out is what takes an installed one away again.
    #[arg(short, long, value_name = "SOCKET|ADDRESS")]
    operator: Option<OperatorEndpoint>,
}

#[derive(Debug, Subcommand)]
enum CheckCommand {
    /// Validate the config file.
    Config(ConfigArgs),
    /// Open the state store and report what it holds.
    State(ConfigArgs),
}

#[derive(Debug, Subcommand)]
enum AppsCommand {
    /// Run an app from a manifest, replacing it if it is already running.
    Apply(ApplyArgs),
    /// List the apps spaceport is running.
    List(ListArgs),
    /// Report everything spaceport knows about one app.
    Show(ShowArgs),
    /// Say which repository and branch an app's code lives on, so that the
    /// commit the branch is at now and every push to it after are built.
    ///
    /// The current head and not only the pushes to come: a repository whose
    /// last commit is older than the tracking would otherwise wait for a push
    /// that may never arrive.
    ///
    /// Built, and no more than that, unless `--deploy` says otherwise: what a
    /// build produces is an image, and running it is `spaceport apps deploy` —
    /// a step an operator takes when they are ready for it rather than one a
    /// push takes for them.
    Track(TrackArgs),
    /// Run what spaceport built from the app's repository.
    Deploy(DeployArgs),
    /// Stop serving an app, keeping everything about it.
    Suspend(SuspendArgs),
    /// Serve a suspended app again.
    Resume(ResumeArgs),
    /// Stop an app and remove it.
    Destroy(DestroyArgs),
    /// Set, list and remove the values an app's manifest names and never
    /// contains.
    ///
    /// A manifest declares which secrets its container needs and interpolates
    /// them into its environment; what they are is set here, because a manifest
    /// is a document that gets committed to a repository.
    Secret(SecretArgs),
}

#[derive(Debug, Args)]
struct SecretArgs {
    #[command(subcommand)]
    command: SecretCommand,
}

#[derive(Debug, Subcommand)]
enum SecretCommand {
    /// List the names of the secrets set for an app.
    ///
    /// Names only. There is no way to read a value back out of spaceport, on
    /// purpose: an operator who has lost one sets a new one.
    List(SecretListArgs),
    /// Set one of an app's secrets, and bring the app up to date with it.
    ///
    /// An app that was suspended waiting for this value starts serving; an app
    /// that was already running has its container replaced with one carrying
    /// the new value. Setting a secret to the value it already has does
    /// neither.
    Set(SecretSetArgs),
    /// Remove one of an app's secrets.
    ///
    /// Refused while the app's manifest still declares the name — the app could
    /// not be started again without it, so the manifest goes first.
    Delete(SecretDeleteArgs),
}

#[derive(Debug, Args)]
struct SecretListArgs {
    /// The app whose secrets to list.
    app_id: AppId,

    /// Only list secrets whose name matches, where `*` stands for any
    /// characters.
    pattern: Option<Pattern>,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct SecretSetArgs {
    /// The app the secret belongs to.
    app_id: AppId,

    /// The environment variable the app reads the value as.
    name: VarName,

    /// The value, or `-` to read it from standard input.
    ///
    /// `-` is what to use for anything that matters. A value typed on the
    /// command line is written to the shell's history file, which outlives the
    /// terminal and is rarely treated as a file holding credentials, and it is
    /// visible in `ps` to every user on the host for as long as the command
    /// runs. Neither is somewhere a database password belongs.
    value: String,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct SecretDeleteArgs {
    /// The app the secret belongs to.
    app_id: AppId,

    /// The name of the secret to remove.
    name: VarName,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Manage the global user pool.
    ///
    /// Users are the stable identities everything else will hang off:
    /// sessions, API keys and entitlements are later milestones, but the ids
    /// minted here are the ones they will name. Whoever can reach the operator
    /// socket is the admin — there is no separate in-band admin role.
    User(UserArgs),
    /// Grant a user a role at an app.
    ///
    /// An entitlement connects a user, an app and a role; only a user holding
    /// one for a role the app's manifest declares gets through the edge. A
    /// grant for a role the app does not declare — or an app spaceport does
    /// not run — is stored all the same, with a warning: granting ahead of the
    /// deploy is the ordinary order of operations.
    Grant(GrantArgs),
    /// Take entitlements away again: one role, one whole app, or everything.
    ///
    /// Only manual grants are the operator's to revoke. An entitlement mapped
    /// from SSO is refused with the rule that produced it — the next IdP login
    /// would put it straight back, and dropping the mapping is what removes it.
    Revoke(RevokeArgs),
    /// Manage the sessions that sign a user in on the web, and the API keys
    /// that sign a machine's requests.
    ///
    /// A session starts from a one-time code minted here and typed into the
    /// login page on the edge hostname; it ends when it expires, when the user
    /// signs out, or when an operator drops it. An API key is minted here too,
    /// grants exactly one role at one app, and ends when it expires or is
    /// revoked — `list` shows both, `drop` takes either.
    Session(SessionArgs),
    /// Report one user's whole standing: the record, the SSO connection, every
    /// entitlement with its origin, and the apps they actually reach.
    Audit(UserRefArgs),
    /// Manage the Ed25519 key that signs the JWTs handed down to apps.
    ///
    /// The key rotates by itself every ninety days; `rotate` is the manual
    /// lever for the day it is suspected compromised. Rotation breaks nothing:
    /// tokens signed before it verify against the retired key, which the JWKS
    /// keeps serving until every one of them has expired.
    Key(KeyArgs),
    /// Print the append-only auth event log.
    ///
    /// Every mutating auth command lands in it with a timestamp and where it
    /// came from, and it outlives the users it is about: after a drop, the log
    /// is the only record the user ever existed.
    Log(AuthLogArgs),
}

#[derive(Debug, Args)]
struct GrantArgs {
    /// The user, as a slug or a user id.
    ///
    /// The spec writes `<user-id>`; a slug is taken too, because every other
    /// command that names a user resolves both and a grant that insisted on
    /// the UUID would have operators copy-pasting what they already typed.
    user: UserRef,

    /// What to grant, as `<role>@<app-id>`.
    entitlement: RoleAtApp,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
// Exactly one of the two shapes, and clap holds the line: a scope names what
// goes, `--all` says everything does, and a revoke that said both — or
// neither — would be one nobody can be sure they meant.
#[command(group = clap::ArgGroup::new("what").args(["scope", "all"]).required(true))]
struct RevokeArgs {
    /// The user, as a slug or a user id.
    user: UserRef,

    /// What to revoke: one entitlement as `<role>@<app-id>`, or a bare
    /// `<app-id>` for every role the user holds there.
    scope: Option<RevokeScope>,

    /// Revoke every entitlement the user holds, across all apps.
    #[arg(long)]
    all: bool,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct UserArgs {
    #[command(subcommand)]
    command: UserCommand,
}

#[derive(Debug, Args)]
struct SessionArgs {
    #[command(subcommand)]
    command: SessionCommand,
}

#[derive(Debug, Args)]
struct KeyArgs {
    #[command(subcommand)]
    command: KeyCommand,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Retire the current signing key and mint a fresh one, immediately.
    ///
    /// For compromise response — the ninety-day rotation needs no command.
    /// In-flight JWTs stay valid until their own expiry; nothing an app holds
    /// breaks.
    Rotate(KeyServerArgs),
    /// List the signing keys still in the store: the current one, and any
    /// retired key the JWKS still serves.
    List(KeyServerArgs),
}

/// The shape both key commands share: nothing but the socket to ask.
#[derive(Debug, Args)]
struct KeyServerArgs {
    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    /// List a user's live sessions and API keys.
    List(UserRefArgs),
    /// Mint a one-time code that signs the user in on the login page.
    ///
    /// The code is printed once and stored only as a hash: there is no way to
    /// read it back, and losing it means minting another. It is good for ten
    /// minutes, a single use, and five failed attempts.
    Mint(SessionMintArgs),
    /// Mint an API key granting one role at one app.
    ///
    /// The key is printed once and stored only as a hash: there is no way to
    /// read it back, and losing it means minting another. A machine presents
    /// it as `Authorization: Bearer spk_…` and needs no cookie, session or
    /// CSRF ceremony; the app sees the same JWT a signed-in user's request
    /// carries, with the key's single role.
    ApiKey(SessionApiKeyArgs),
    /// Drop one session or revoke one API key by id, or drop every session
    /// and key the user holds.
    Drop(SessionDropArgs),
}

#[derive(Debug, Args)]
struct SessionMintArgs {
    /// The user, as a slug or a user id.
    user: UserRef,

    /// How long the session the code redeems into lives, as a duration like
    /// `12h`. Fixed now, at mint — redeeming the code later does not stretch
    /// it. Twelve hours when left out.
    #[arg(long, value_name = "DURATION")]
    expires: Option<String>,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct SessionApiKeyArgs {
    /// The user the key belongs to, as a slug or a user id.
    user: UserRef,

    /// What the key grants, as `<role>@<app-id>` — exactly that role, at
    /// exactly that app, whatever entitlements the user otherwise holds.
    grants: RoleAtApp,

    /// How long the key lives, as a duration like `90d`. Ninety days when
    /// left out.
    #[arg(long, value_name = "DURATION")]
    expires: Option<String>,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct SessionDropArgs {
    /// The user, as a slug or a user id.
    user: UserRef,

    /// The session to drop or the API key to revoke, as `spaceport auth
    /// session list` prints them. Leaving it out drops every session and
    /// key the user holds.
    session: Option<SessionId>,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Subcommand)]
enum UserCommand {
    /// List the users spaceport knows.
    List(UserListArgs),
    /// Create a user, minting the id it keeps for life.
    Create(UserCreateArgs),
    /// Suspend a user, keeping the record but letting nothing in.
    Suspend(UserRefArgs),
    /// Let a suspended user back in.
    Resume(UserRefArgs),
    /// Drop a user entirely. The slug can be created again — and names a
    /// different user then, because an id is never reused.
    Drop(UserRefArgs),
}

#[derive(Debug, Args)]
struct UserListArgs {
    /// Only list users whose slug matches, where `*` stands for any
    /// characters.
    pattern: Option<Pattern>,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct UserCreateArgs {
    /// The name the user answers to: a lowercase letter, then lowercase
    /// letters, digits and hyphens.
    slug: UserSlug,

    /// The user's email address. Optional, because a technical user has no
    /// reason to have one; later it is where one-time codes go and what an
    /// IdP login links through.
    #[arg(long, value_name = "ADDR")]
    email: Option<String>,

    #[command(flatten)]
    server: ServerArgs,
}

/// The shape `suspend`, `resume` and `drop` share: one user, named either way.
#[derive(Debug, Args)]
struct UserRefArgs {
    /// The user, as a slug or a user id.
    user: UserRef,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct AuthLogArgs {
    /// Only the entries about this user id.
    user: Option<UserId>,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Subcommand)]
enum ConnectCommand {
    /// Hold a GitHub App as this spaceport's own identity on github.com.
    Github(ConnectGithubArgs),
    /// List the GitHub Apps spaceport is connected as.
    List(ConnectListArgs),
    /// Report everything spaceport knows about one connection.
    Show(ConnectShowArgs),
    /// Forget a connection, and everything cached under it.
    Forget(ConnectForgetArgs),
}

#[derive(Debug, Args)]
// Exactly one of the two flows, and saying which is not optional: they need
// entirely different arguments, and a command that guessed would be guessing
// whether to create an app on github.com.
#[command(group = clap::ArgGroup::new("flow").args(["auto", "manual"]).required(true))]
struct ConnectGithubArgs {
    /// Have GitHub create the app, and print a link to open in a browser.
    ///
    /// Spaceport describes the app it wants and GitHub creates it, so there is
    /// nothing to copy off a settings page. GitHub only accepts that from a
    /// logged-in browser, which is why this prints a link rather than doing it.
    #[arg(long)]
    auto: bool,

    /// The organisation the app should belong to, with `--auto`.
    ///
    /// Without it the app belongs to whichever account the browser is signed
    /// in as, which is the right answer for a spaceport one person runs.
    #[arg(long, value_name = "ORG")]
    org: Option<String>,

    /// Register an app that was created by hand on github.com, with the
    /// details from its settings page.
    #[arg(long)]
    manual: bool,

    /// The `App ID` on the app's settings page.
    #[arg(long, value_name = "ID")]
    app_id: Option<i64>,

    /// The name in the app's url on github.com, which is what spaceport knows
    /// it by from here on.
    #[arg(long)]
    slug: Option<String>,

    /// The app's display name.
    ///
    /// With `--auto`, optional: spaceport names the app after its own hostname,
    /// which is the one thing about it that is already unique across
    /// github.com — where an app's name has to be.
    #[arg(long)]
    name: Option<String>,

    /// The user or organisation the app belongs to.
    #[arg(long)]
    owner: Option<String>,

    /// The `Client ID` on the app's settings page.
    #[arg(long, value_name = "ID")]
    client_id: Option<String>,

    /// A client secret generated on the app's settings page.
    ///
    /// The environment variable is there so a secret does not end up in shell
    /// history, which is a file that outlives the terminal and is rarely
    /// treated as one that holds credentials.
    #[arg(long, value_name = "SECRET", env = "SPACEPORT_GITHUB_CLIENT_SECRET")]
    client_secret: Option<String>,

    /// The webhook secret set on the app's settings page.
    ///
    /// The environment variable exists for the same reason as
    /// `--client-secret`'s: a value pasted on a command line is written to
    /// shell history and stays there.
    #[arg(long, value_name = "SECRET", env = "SPACEPORT_GITHUB_WEBHOOK_SECRET")]
    webhook_secret: Option<String>,

    /// Path to the `.pem` file GitHub downloaded when the private key was
    /// generated.
    ///
    /// A path rather than the key itself, because a path is what an operator
    /// has after clicking "generate a private key" — the file is in their
    /// downloads and nobody wants to paste it.
    #[arg(long, value_name = "FILE", env = "SPACEPORT_GITHUB_PRIVATE_KEY")]
    private_key: Option<PathBuf>,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct ConnectListArgs {
    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct ConnectShowArgs {
    /// The slug of the connection to report on.
    slug: String,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct ConnectForgetArgs {
    /// The slug of the connection to forget.
    slug: String,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct ApplyArgs {
    /// The name to run the app under.
    app_id: AppId,

    /// Path to the app manifest.
    manifest: PathBuf,

    /// Record the app and claim its hosts without starting it.
    ///
    /// Certificates for its hosts are acquired and renewed all the same, so
    /// `spaceport apps resume` starts serving immediately. Applying to an app
    /// that is already suspended leaves it suspended whether or not this is
    /// given.
    #[arg(long)]
    suspended: bool,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct SuspendArgs {
    /// The app to stop serving.
    app_id: AppId,

    /// Stop its container too, and keep it.
    ///
    /// Without this the container is left running and only stops receiving
    /// traffic, which is what makes resuming instant.
    #[arg(long)]
    stop_container: bool,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct ResumeArgs {
    /// The app to serve again.
    app_id: AppId,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct ListArgs {
    /// Only list apps whose name matches, where `*` stands for any characters.
    pattern: Option<Pattern>,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct ShowArgs {
    /// The app to report on.
    app_id: AppId,

    /// Print the manifest it was applied with, verbatim and on its own.
    ///
    /// What comes out is what went in, so it can be written to a file and
    /// applied again.
    #[arg(long)]
    manifest: bool,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct TrackArgs {
    /// The app whose code this is.
    app_id: AppId,

    /// The repository the app is built from, as `owner/name`.
    repository: String,

    /// The connection that reaches the repository.
    ///
    /// Named rather than worked out, because a repository can be reachable
    /// through more than one of them — a spaceport connected to an
    /// organisation's app and to somebody's personal one can see the same
    /// repository as either. Which identity acts on a push decides what it may
    /// read and what shows up in the repository's audit log, and that is not
    /// something to settle by picking whichever connection was found first.
    #[arg(long, value_name = "SLUG")]
    connection: String,

    /// The branch a push has to be on to be about this app.
    ///
    /// Without it, spaceport asks GitHub what the repository's default branch is
    /// and records the name it answers. The name and not "the default": a
    /// default branch is a setting somebody may change on github.com months from
    /// now, and an app that followed it would quietly start building from
    /// somewhere nobody pointed it at.
    #[arg(short, long, value_name = "BRANCH")]
    branch: Option<String>,

    /// Where the app's manifest is in the repository, as a path from its root.
    ///
    /// A monorepo holding one of these per app is the reason it is an option at
    /// all: several apps track the same repository and branch, and the manifest
    /// path is the only thing that tells their builds apart.
    #[arg(short, long, value_name = "FILE", default_value = "spaceport.yaml")]
    manifest_path: String,

    /// Run every build of this app as soon as it succeeds, without anybody
    /// typing `spaceport apps deploy`.
    ///
    /// Every commit on the branch reaches production on its own from then on,
    /// replacing whatever manifest the app was applied with — which is what
    /// makes it a thing to ask for rather than the default. A suspended app is
    /// left suspended, and a deployment that fails puts the app back on the
    /// revision it was running.
    #[arg(long, conflicts_with = "no_deploy")]
    deploy: bool,

    /// Stop running this app's builds on their own, leaving `spaceport apps
    /// deploy` as the only thing that puts one in front of the traffic.
    ///
    /// There is no `spaceport apps autodeploy`, so re-tracking with this is how
    /// an armed app is disarmed. Mentioning neither flag leaves the switch
    /// exactly as it was, so correcting a branch or a manifest path never
    /// silently stops an app deploying itself.
    #[arg(long)]
    no_deploy: bool,

    #[command(flatten)]
    server: ServerArgs,
}

impl TrackArgs {
    /// Whether the operator said anything about automatic deployment, and what.
    ///
    /// `None` is the answer that matters: the two flags are the only way the
    /// switch is set, and a re-track that mentions neither is not an answer to
    /// the question at all — so the spaceport is told nothing rather than told
    /// `false`, and leaves the app as armed as it already was.
    fn deploy(&self) -> Option<bool> {
        match (self.deploy, self.no_deploy) {
            (true, _) => Some(true),
            (_, true) => Some(false),
            _ => None,
        }
    }
}

#[derive(Debug, Args)]
struct DeployArgs {
    /// The app to deploy.
    app_id: AppId,

    /// The commit to run, in full or abbreviated to anything that names one
    /// build of this app.
    ///
    /// Without it, spaceport runs the newest image it has finished building —
    /// which is what somebody who has just pushed is asking for. Naming one is
    /// how a deploy is repeated on another host, and how an app is put back on
    /// the revision it was running before the last one.
    ///
    /// The manifest that comes with it is the one that commit carried, so the
    /// app is configured as its repository says at that revision rather than as
    /// it says today.
    #[arg(short, long, value_name = "SHA")]
    revision: Option<String>,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct DestroyArgs {
    /// The app to stop and remove.
    app_id: AppId,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct StreamArgs {
    /// Only events about apps whose name matches, where `*` stands for any
    /// characters. Excludes the events that are about no app at all.
    #[arg(short, long, value_name = "PATTERN")]
    app: Option<Pattern>,

    /// Only events in this category, or in one below it: `app` selects
    /// `app.apply` and `app.reconcile` alike.
    #[arg(short, long)]
    category: Option<Category>,

    /// The least severe events worth seeing.
    #[arg(short, long, default_value = "debug")]
    level: Level,

    /// How many events from before now to show first.
    #[arg(long, default_value_t = 20, value_name = "COUNT")]
    history: usize,

    /// Colour the events, even when this is not writing to a terminal.
    /// Without it, colour is used when a terminal is there to show it and
    /// `NO_COLOR` is not set.
    #[arg(short, long)]
    pretty: bool,

    /// Print the events as the JSON they arrive as, one per line. Never
    /// coloured: whatever reads this is not looking at it.
    #[arg(long, conflicts_with = "pretty")]
    json: bool,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct StatusArgs {
    /// Colour the report, even when this is not writing to a terminal.
    /// Without it, colour is used when a terminal is there to show it and
    /// `NO_COLOR` is not set.
    #[arg(short, long)]
    pretty: bool,

    /// Print the status as the JSON it arrives as. Never coloured: whatever
    /// reads this is not looking at it.
    #[arg(long, conflicts_with = "pretty")]
    json: bool,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Debug, Args)]
struct ServerArgs {
    /// The spaceport to talk to: an operator socket, or an address over the
    /// network.
    #[arg(
        short,
        long,
        value_name = "SOCKET|ADDRESS",
        env = "SPACEPORT_SERVER",
        default_value = DEFAULT_OPERATOR_ENDPOINT
    )]
    server: OperatorEndpoint,
}

#[derive(Debug, Args)]
struct ConfigArgs {
    /// Path to the config file.
    #[arg(short, long, value_name = "FILE", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Run(args) => run(args).await,
        Command::Setup(args) => setup(args),
        Command::Check { command } => match command {
            CheckCommand::Config(args) => check_config(args),
            CheckCommand::State(args) => check_state(args).await,
        },
        Command::Apps { command } => match command {
            AppsCommand::Apply(args) => apply(args).await,
            AppsCommand::List(args) => list(args).await,
            AppsCommand::Show(args) => show(args).await,
            AppsCommand::Track(args) => track(args).await,
            AppsCommand::Deploy(args) => deploy(args).await,
            AppsCommand::Suspend(args) => suspend(args).await,
            AppsCommand::Resume(args) => resume(args).await,
            AppsCommand::Destroy(args) => destroy(args).await,
            AppsCommand::Secret(args) => match args.command {
                SecretCommand::List(args) => secret_list(args).await,
                SecretCommand::Set(args) => secret_set(args).await,
                SecretCommand::Delete(args) => secret_delete(args).await,
            },
        },
        Command::Auth { command } => match command {
            AuthCommand::User(args) => match args.command {
                UserCommand::List(args) => user_list(args).await,
                UserCommand::Create(args) => user_create(args).await,
                UserCommand::Suspend(args) => user_suspend(args).await,
                UserCommand::Resume(args) => user_resume(args).await,
                UserCommand::Drop(args) => user_drop(args).await,
            },
            AuthCommand::Session(args) => match args.command {
                SessionCommand::List(args) => session_list(args).await,
                SessionCommand::Mint(args) => session_mint(args).await,
                SessionCommand::ApiKey(args) => session_api_key(args).await,
                SessionCommand::Drop(args) => session_drop(args).await,
            },
            AuthCommand::Grant(args) => grant(args).await,
            AuthCommand::Revoke(args) => revoke(args).await,
            AuthCommand::Audit(args) => audit(args).await,
            AuthCommand::Key(args) => match args.command {
                KeyCommand::Rotate(args) => auth_key_rotate(args).await,
                KeyCommand::List(args) => auth_key_list(args).await,
            },
            AuthCommand::Log(args) => auth_log(args).await,
        },
        Command::Connect { command } => match command {
            ConnectCommand::Github(args) => connect_github(args).await,
            ConnectCommand::List(args) => connections(args).await,
            ConnectCommand::Show(args) => connection(args).await,
            ConnectCommand::Forget(args) => forget_connection(args).await,
        },
        Command::Stream(args) => stream(args).await,
        Command::Status(args) => status(args).await,
    }
}

/// Ask a running spaceport what it is, and lay the answer out.
async fn status(args: StatusArgs) -> Result<()> {
    let status = client::status(&args.server.server).await?;

    if args.json {
        // What arrived, indented rather than reshaped: anything reading this
        // is reading the same fields the operator interface sent.
        println!("{}", serde_json::to_string_pretty(&status)?);

        return Ok(());
    }

    print!("{}", render::status(&status, Colour::detect(args.pretty)));

    Ok(())
}

async fn run(args: RunArgs) -> Result<()> {
    // Before anything is loaded or opened, so that the uptime a status reports
    // is how long this process has been alive rather than how long it has been
    // finished starting.
    let started_at = OffsetDateTime::now_utc();

    // Two consumers of the same events, each filtered for what it is: the log
    // this service writes, and the stream an operator watches — which can
    // afford the debug-level detail that would drown a log file, and cannot
    // afford anything at all from the crates underneath spaceport.
    let events = Arc::new(EventBus::new());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer().with_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| DEFAULT_LOG_FILTER.into()),
            ),
        )
        .with(
            events::layer(events.clone()).with_filter(
                tracing_subscriber::EnvFilter::try_from_env(STREAM_FILTER_VAR)
                    .unwrap_or_else(|_| DEFAULT_STREAM_FILTER.into()),
            ),
        )
        .init();

    let config = Config::load(&args.config.config)?;
    info!(path = %args.config.config.display(), "loaded config");

    // Before anything is started: two spaceports over one state directory
    // would spend their lives undoing each other's reconciliation.
    state::create_directory(&config.state.directory)?;
    let _lock = StateLock::acquire(&config.state.directory)?;
    let db = Db::open(&config.state.directory)?;
    info!(path = %Db::path_in(&config.state.directory).display(), "opened the state store");

    // Checked at startup rather than at the first apply: an unreachable
    // container engine is a broken host, and finding out about it while
    // starting is a great deal cheaper than finding out about it later.
    let data = DataDir::new(config.data.directory.clone());
    data.create()?;
    info!(path = %data.root().display(), "opened the app data directory");

    // Beside the data directory and emphatically not inside it: this is the one
    // directory spaceport deletes from, and it holds the source code of
    // somebody's app rather than the data an operator backs up.
    let builds = BuildDir::new(config.build.directory.clone());
    builds.create()?;
    info!(path = %builds.root().display(), "opened the build directory");

    // The issuer gated containers are told to expect JWTs from — one spelling
    // for the `iss` claim, the `SPACEPORT_ISSUER` variable and the JWKS URL,
    // absent exactly when the hostname is.
    let issuer = config
        .edge
        .hostname
        .as_ref()
        .map(|hostname| jwt::issuer(&hostname.to_string(), config.edge.listen.https.port()));

    let runtime = Arc::new(DockerRuntime::connect(data, issuer)?);
    runtime.ping().await?;

    // Spaceport's own host is claimed before the first app is restored, so
    // there is no window in which one could take it.
    let apps = Arc::new(AppStore::answering_to(config.edge.hostname.clone()));
    if let Some(hostname) = &config.edge.hostname {
        info!(%hostname, "answering to this host as spaceport itself");
    }

    // One JWT cache for the whole process, made before anything that mints
    // into it or purges it: the edge's gate fills it, and the auth
    // repositories and the applier empty it on every revocation lever — two
    // caches would be a purge that leaves the other one serving.
    let jwt_cache = Arc::new(JwtCache::new());

    // Cloned rather than moved: the same engine runs the containers and builds
    // the images, which is what [`spaceport_core::build::image::ImageBuilder`]
    // is implemented on `DockerRuntime` for.
    let applier = Arc::new(
        Applier::new(
            apps.clone(),
            runtime.clone(),
            AppRepository::new(db.clone()),
            BuildRepository::new(db.clone()),
            SecretRepository::new(db.clone()),
        )
        .with_jwt_cache(jwt_cache.clone()),
    );

    // Ahead of the listeners, so a restart does not answer 404 for apps it is
    // in the middle of bringing back.
    let report = reconcile(&applier).await?;
    if !report.is_empty() {
        info!(
            restored = report.restored.len(),
            adopted = report.adopted,
            failed = report.failed.len(),
            swept = report.swept,
            "reconciled with what was recorded",
        );
    }

    // The certificate machinery, before the listeners: the resolver has to
    // exist for the acceptor to be built from, and a restart should be serving
    // the certificates it already had from its very first handshake.
    let resolver = edge::tls::resolver()?;
    let challenges = Arc::new(Challenges::new());
    let certificates = match (&config.edge.tls.provider, &config.edge.tls.acme) {
        (TlsProvider::Acme, Some(acme)) => {
            let repository = CertificateRepository::new(db.clone());
            let ca = Arc::new(
                AcmeCa::connect(acme, &repository, challenges.clone(), &Transport::Network).await?,
            );

            Some(Arc::new(
                Certificates::load(ca, repository, resolver.clone()).await?,
            ))
        }
        // Without acme nothing ever puts a certificate in the resolver, and
        // every host is served the development one.
        _ => None,
    };
    let acceptor = edge::tls::acceptor(resolver)?;

    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => info!("shutting down"),
                Err(error) => tracing::error!(%error, "could not listen for ctrl-c"),
            }
            shutdown.cancel();
        }
    });

    // After reconciliation, which settles what should be running, and after the
    // shutdown token, which is the only thing that stops it. From here on, an
    // app that stops running is spaceport's problem rather than an operator's.
    tokio::spawn(supervise(applier.clone(), shutdown.clone()));

    // Without `--operator` there is no way to tell spaceport what to run, which
    // is a legitimate way to start it: the edge still serves, and still says so.
    // One for the whole process, so every command that asks GitHub something
    // reuses the same TLS connections rather than handshaking per request.
    let github = Arc::new(github::Network::new()?);
    let connections = Arc::new(ConnectionRepository::new(db.clone()));

    // What each app is built from. One for the whole process, so the operator
    // socket that records a tracking and the edge that hears the pushes about
    // it are looking at the same rows.
    let tracking = Arc::new(github::TrackingRepository::new(db.clone()));

    // One signal for the whole process, built here because everything that
    // shoves it and the one thing that listens for it are assembled below: the
    // reconciliation loop, the operator socket where an app is connected, and
    // the edge where GitHub's webhooks land. Two of these would be a spaceport
    // that reconciles on some of what it learns and silently not on the rest.
    let nudge = github::Nudge::new();

    // Whatever webhooks missed, healed on a timer. Started unconditionally,
    // even on a host with no connections at all: a connection can be made while
    // spaceport is running, and a loop that was not started because there were
    // none at startup would never notice the first one. A pass over zero
    // connections asks GitHub nothing and says nothing, so the cost of being
    // wrong that way is a task asleep for an hour.
    tokio::spawn(github::maintain(
        connections.clone(),
        github.clone(),
        github::reconcile::Policy::default(),
        nudge.clone(),
        shutdown.clone(),
    ));

    // The builder's own signal, and deliberately not the reconciler's. A push
    // wakes this one, which reads the trackings out of the database; waking the
    // reconciler for a push would make every commit an organisation makes into
    // a GitHub round trip per connection.
    let building = github::Nudge::new();

    // And the deploying loop's own signal, which is neither of the other two.
    // The builder shoves this one when an image exists; waking the builder
    // instead would put a finished build back through the queue it came out of,
    // and waking the reconciler would make every image into a GitHub round trip
    // per connection.
    let deploying = github::Nudge::new();

    // One store, cloned into the worker that writes the rows and held by the
    // operator interface that reads them back: `spaceport apps show` reports
    // what a build came to, and it has to be looking at the same table the
    // worker finished writing.
    let build_records = Arc::new(BuildRepository::new(db.clone()));

    // Started unconditionally, for the reason the reconciler is: an app can be
    // tracked while spaceport is running, and a loop that was not started
    // because nothing was tracked at startup would never build the first
    // commit. A pass over nothing is two local queries and no network at all.
    tokio::spawn(build::worker::maintain(
        Arc::new(build::worker::Worker {
            builds: (*build_records).clone(),
            trackings: tracking.clone(),
            connections: connections.clone(),
            github: github.clone(),
            archives: Arc::new(build::archive::Downloads::new()?),
            images: runtime,
            directory: builds,
            deploys: deploying.clone(),
        }),
        build::worker::Policy {
            max_archive_bytes: config.build.max_archive_bytes,
            keep: config.build.keep,
            ..build::worker::Policy::default()
        },
        building.clone(),
        shutdown.clone(),
    ));

    // What runs an image once there is one, for the apps whose operator armed
    // them. Started unconditionally, for the reason the two loops above are: an
    // app can be armed while spaceport is running, and a pass over no armed
    // trackings is one local query. It is also what makes a build recorded by a
    // spaceport that was then killed still reach production — the row it left
    // behind is the trigger, so the first pass after the restart finds it.
    tokio::spawn(app::deploy::maintain(
        Arc::new(app::deploy::Worker {
            applier: applier.clone(),
            trackings: tracking.clone(),
            builds: (*build_records).clone(),
        }),
        app::deploy::Policy::default(),
        deploying.clone(),
        shutdown.clone(),
    ));

    // Shared between the two listeners on purpose: `spaceport connect github
    // --auto` issues a state on the operator socket, and the browser that
    // answers for it arrives at the edge.
    let attempts = Arc::new(github::Attempts::new());

    // The pages spaceport serves as itself. Built whether or not a hostname was
    // configured — which host reaches them is the routing table's business, and
    // a page that is never reached costs nothing to have made.
    // One repository for the two listeners that touch sessions: the login page
    // on the edge writes the rows this socket lists and drops, and two
    // repositories would only be two handles to the same table pretending
    // otherwise.
    let sessions = Arc::new(SessionRepository::with_jwt_cache(
        db.clone(),
        jwt_cache.clone(),
    ));
    // Shared with the operator interface for the reason sessions are: the
    // exchange on the edge must be answering over the same rows a grant or a
    // denial audit reads on the socket.
    let entitlements = Arc::new(EntitlementRepository::with_jwt_cache(
        db.clone(),
        jwt_cache.clone(),
    ));
    let auth_log = Arc::new(AuthLogRepository::new(db.clone()));
    // The key the edge signs app JWTs with, and whose JWKS it serves —
    // generated on first need, persisted in the state store.
    let signer = Arc::new(JwtSigner::new(db.clone()));

    let home = Arc::new(edge::Home {
        attempts: attempts.clone(),
        connections: connections.clone(),
        tracking: tracking.clone(),
        github: github.clone(),
        nudge: nudge.clone(),
        builds: building.clone(),
        hostname: config.edge.hostname.as_ref().map(ToString::to_string),
        sessions: sessions.clone(),
        entitlements: entitlements.clone(),
        auth_log: auth_log.clone(),
        apps: apps.clone(),
        signer: signer.clone(),
        jwt_cache: jwt_cache.clone(),
        https_port: config.edge.listen.https.port(),
    });

    let operator = args.operator.map(|endpoint| {
        // Everything a status report is made of, gathered while the things it
        // is made of are still in scope.
        let instance = Arc::new(Instance {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            started_at,
            config_path: args.config.config.clone(),
            config: config.clone(),
            operator: endpoint.clone(),
            applier,
            connections,
            tracking,
            builds: build_records,
            github,
            attempts,
            nudge,
            // The operator socket shoves this one too: `spaceport apps track`
            // resolves the head of the branch it binds, and a commit written
            // down with nothing woken would wait out the builder's interval.
            building,
            // And this one, for the same kind of reason: resuming an app, or
            // arming one, can make an image that already exists deployable
            // without anything being built to wake the loop on its own.
            deploying,
            users: Arc::new(UserRepository::with_jwt_cache(db.clone(), jwt_cache)),
            auth_log,
            entitlements,
            sessions,
            // The very signer the edge signs with, so a rotation over this
            // socket retires the key the next request would have used.
            signer,
            db,
            certificates: certificates.clone(),
            reconciled: report,
        });

        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let result = server::serve(&endpoint, instance, events, shutdown.clone()).await;

            // An operator interface that never came up is a startup failure,
            // and one nobody would otherwise hear about until they tried to
            // use it. Take the edge down with it and report at the exit.
            if result.is_err() {
                shutdown.cancel();
            }

            result
        })
    });

    // Ordering and renewing runs alongside the edge rather than before it: the
    // challenges it publishes are answered by the listener it is waiting on.
    if let Some(certificates) = certificates {
        tokio::spawn(acme::maintain(certificates, apps.clone(), shutdown.clone()));
    }

    let served = edge::serve(&config, apps, home, acceptor, challenges, shutdown.clone()).await;

    // Whatever stopped the edge stops the operator interface too, so a failure
    // to bind one port does not leave the other half of spaceport running.
    shutdown.cancel();
    if let Some(operator) = operator {
        operator
            .await
            .context("the operator interface panicked")??;
    }

    served
}

/// Install this binary as the host's spaceport service, and start it.
fn setup(args: SetupArgs) -> Result<()> {
    let report = setup::install(&setup::Setup {
        config: args.config.config,
        initial_config: args.initial_config,
        operator: args.operator,
    })?;

    println!("{report}");
    println!("{}: enabled and restarted", setup::systemd::UNIT_NAME);

    Ok(())
}

async fn apply(args: ApplyArgs) -> Result<()> {
    let manifest = std::fs::read_to_string(&args.manifest)
        .with_context(|| format!("reading app manifest `{}`", args.manifest.display()))?;

    print!(
        "{}",
        client::apply(&args.server.server, &args.app_id, manifest, args.suspended).await?
    );

    Ok(())
}

async fn list(args: ListArgs) -> Result<()> {
    print!(
        "{}",
        client::list(&args.server.server, args.pattern.as_ref()).await?
    );

    Ok(())
}

async fn show(args: ShowArgs) -> Result<()> {
    print!(
        "{}",
        client::show(&args.server.server, &args.app_id, args.manifest).await?
    );

    Ok(())
}

async fn track(args: TrackArgs) -> Result<()> {
    print!(
        "{}",
        client::track(
            &args.server.server,
            &args.app_id,
            &args.repository,
            &args.connection,
            args.branch.as_deref(),
            Some(&args.manifest_path),
            args.deploy(),
        )
        .await?
    );

    Ok(())
}

async fn deploy(args: DeployArgs) -> Result<()> {
    print!(
        "{}",
        client::deploy(&args.server.server, &args.app_id, args.revision.as_deref()).await?
    );

    Ok(())
}

async fn suspend(args: SuspendArgs) -> Result<()> {
    print!(
        "{}",
        client::suspend(&args.server.server, &args.app_id, args.stop_container).await?
    );

    Ok(())
}

async fn resume(args: ResumeArgs) -> Result<()> {
    print!(
        "{}",
        client::resume(&args.server.server, &args.app_id).await?
    );

    Ok(())
}

/// Print the names of an app's secrets, one per line.
///
/// Nothing at all when the app has none, where `spaceport apps list` says "no
/// apps are running". They differ because their readers do: an app table is
/// read by a person, and this is the one listing meant to be read by a loop —
/// `for name in $(spaceport apps secret list web)` — where a sentence would be
/// three secrets named `no`, `secrets` and `are`. Still an exit code of 0: an
/// app with no secrets is an answer, not a failure.
async fn secret_list(args: SecretListArgs) -> Result<()> {
    print!(
        "{}",
        client::secrets(&args.server.server, &args.app_id, args.pattern.as_ref()).await?
    );

    Ok(())
}

async fn secret_set(args: SecretSetArgs) -> Result<()> {
    let value = value_of(&args.value)?;
    let set = client::set_secret(&args.server.server, &args.app_id, &args.name, &value).await?;

    println!("{}", set_line(&args.app_id, &args.name, &set));

    Ok(())
}

async fn secret_delete(args: SecretDeleteArgs) -> Result<()> {
    print!(
        "{}",
        client::delete_secret(&args.server.server, &args.app_id, &args.name).await?
    );

    Ok(())
}

async fn user_list(args: UserListArgs) -> Result<()> {
    print!(
        "{}",
        client::auth_user_list(&args.server.server, args.pattern.as_ref()).await?
    );

    Ok(())
}

async fn user_create(args: UserCreateArgs) -> Result<()> {
    print!(
        "{}",
        client::auth_user_create(&args.server.server, &args.slug, args.email.as_deref()).await?
    );

    Ok(())
}

async fn user_suspend(args: UserRefArgs) -> Result<()> {
    print!(
        "{}",
        client::auth_user_suspend(&args.server.server, &args.user).await?
    );

    Ok(())
}

async fn user_resume(args: UserRefArgs) -> Result<()> {
    print!(
        "{}",
        client::auth_user_resume(&args.server.server, &args.user).await?
    );

    Ok(())
}

async fn user_drop(args: UserRefArgs) -> Result<()> {
    print!(
        "{}",
        client::auth_user_drop(&args.server.server, &args.user).await?
    );

    Ok(())
}

async fn session_list(args: UserRefArgs) -> Result<()> {
    print!(
        "{}",
        client::auth_session_list(&args.server.server, &args.user).await?
    );

    Ok(())
}

/// The duration is validated here as well as at the far end, so a typo is a
/// refusal before anything crosses the socket — but what travels is the
/// operator's own spelling, and the server's parser stays the authority.
async fn session_mint(args: SessionMintArgs) -> Result<()> {
    if let Some(expires) = args.expires.as_deref() {
        spaceport_core::duration::parse(expires)?;
    }

    print!(
        "{}",
        client::auth_session_mint(&args.server.server, &args.user, args.expires.as_deref()).await?
    );

    Ok(())
}

/// The duration is validated here as well as at the far end, for
/// [`session_mint`]'s reason: a typo is a refusal before anything crosses the
/// socket, and the server's parser stays the authority.
async fn session_api_key(args: SessionApiKeyArgs) -> Result<()> {
    if let Some(expires) = args.expires.as_deref() {
        spaceport_core::duration::parse(expires)?;
    }

    print!(
        "{}",
        client::auth_api_key_mint(
            &args.server.server,
            &args.user,
            &args.grants,
            args.expires.as_deref()
        )
        .await?
    );

    Ok(())
}

async fn session_drop(args: SessionDropArgs) -> Result<()> {
    print!(
        "{}",
        client::auth_session_drop(&args.server.server, &args.user, args.session.as_ref()).await?
    );

    Ok(())
}

async fn grant(args: GrantArgs) -> Result<()> {
    print!(
        "{}",
        client::auth_grant(&args.server.server, &args.user, &args.entitlement).await?
    );

    Ok(())
}

/// Clap has already enforced that exactly one of `scope` and `--all` was
/// given, so an absent scope *is* `--all` by the time it gets here.
async fn revoke(args: RevokeArgs) -> Result<()> {
    print!(
        "{}",
        client::auth_revoke(&args.server.server, &args.user, args.scope.as_ref()).await?
    );

    Ok(())
}

async fn audit(args: UserRefArgs) -> Result<()> {
    print!(
        "{}",
        client::auth_audit(&args.server.server, &args.user).await?
    );

    Ok(())
}

async fn auth_log(args: AuthLogArgs) -> Result<()> {
    print!(
        "{}",
        client::auth_log(&args.server.server, args.user.as_ref()).await?
    );

    Ok(())
}

async fn auth_key_rotate(args: KeyServerArgs) -> Result<()> {
    print!("{}", client::auth_key_rotate(&args.server.server).await?);

    Ok(())
}

async fn auth_key_list(args: KeyServerArgs) -> Result<()> {
    print!("{}", client::auth_key_list(&args.server.server).await?);

    Ok(())
}

/// What the operator wants stored: the argument itself, or whatever was piped
/// in when they said `-`.
///
/// The only thing in this CLI that reads standard input, and it exists so that
/// a value never has to be typed. An argument on the command line is written to
/// the shell's history file, which outlives the terminal, and it is visible in
/// `ps` to every user on the host for as long as the command runs — so
/// `spaceport apps secret set web DB_PASSWORD hunter2` leaks the password twice
/// before it has finished running.
fn value_of(value: &str) -> Result<Secret> {
    if value != STDIN {
        return Ok(Secret::new(value.to_owned()));
    }

    let mut piped = String::new();
    std::io::stdin()
        .read_to_string(&mut piped)
        .context("reading the secret's value from standard input")?;

    read(piped)
}

/// The argument that means "the value is on standard input".
const STDIN: &str = "-";

/// What was piped in, as the value it is meant to be.
///
/// Exactly one trailing newline is taken off and nothing else is touched.
/// `echo hunter2 |` and `printf hunter2 |` have to set the same secret, and the
/// newline `echo` adds is the shell's rather than the operator's. Every other
/// byte stays: leading spaces, tabs, a second trailing newline and a `\r` are
/// all bytes a generated key can genuinely end in, and a token stored without
/// one it arrived with fails to authenticate for a reason nobody can see by
/// looking.
///
/// Nothing at all is a refusal rather than an empty secret. A pipe that
/// produced nothing is a command that failed further up the line, and storing
/// the empty string would answer that by starting the app with an empty
/// password.
fn read(mut piped: String) -> Result<Secret> {
    if piped.ends_with('\n') {
        piped.pop();
    }

    if piped.is_empty() {
        anyhow::bail!(
            "nothing arrived on standard input — `-` reads the value from there, and a secret with no value is not one"
        );
    }

    Ok(Secret::new(piped))
}

/// What setting a secret did, as one line for the person who typed it.
///
/// Composed here rather than by the spaceport because the outcomes differ in
/// what the operator does next — nothing, set the other secrets, or go and look
/// at an app that should now be up — and because this side is the one that
/// knows a person is reading. Never a value: there is not one in [`SecretSet`]
/// to print.
fn set_line(id: &AppId, name: &VarName, set: &SecretSet) -> String {
    let what = match set.created {
        true => "set",
        false => "replaced",
    };

    match &set.outcome {
        SecretOutcome::Unchanged => {
            format!("secret `{name}` of app `{id}` already had that value — nothing was restarted")
        }
        SecretOutcome::Stored => format!(
            "secret `{name}` {what} for app `{id}` — nothing here is waiting on it, so nothing was started"
        ),
        SecretOutcome::Missing { secrets } => format!(
            "secret `{name}` {what} for app `{id}` — it is still waiting for {}",
            secrets
                .iter()
                .map(|secret| format!("`{secret}`"))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        SecretOutcome::Resumed => format!(
            "secret `{name}` {what} for app `{id}` — it has every secret it declares, and is serving again"
        ),
        SecretOutcome::Redeployed => format!(
            "secret `{name}` {what} for app `{id}` — its container was replaced with one carrying the new value"
        ),
        SecretOutcome::Started => format!(
            "secret `{name}` {what} for app `{id}` — it was not running, and it has been started on the new value"
        ),
    }
}

/// Print what spaceport is doing until the operator has seen enough.
///
/// Ends on ctrl-c, which is the only way it ends while spaceport is up — and
/// that is not a failure, so it says nothing about it.
async fn stream(args: StreamArgs) -> Result<()> {
    let watch = Watch {
        app: args.app,
        category: args.category,
        level: Some(args.level),
        history: args.history,
    };
    let colour = Colour::detect(args.pretty);

    let print = |event: Event| {
        if args.json {
            // The event as it arrived, for anything that is not a person —
            // which is also why it is never coloured.
            match serde_json::to_string(&event) {
                Ok(line) => println!("{line}"),
                Err(error) => eprintln!("could not print an event: {error}"),
            }
        } else {
            println!("{}", render::line(&event, colour));
        }
    };

    tokio::select! {
        result = client::stream(&args.server.server, &watch, print) => result,
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

/// Hand a running spaceport a GitHub App an operator created by hand.
///
/// The private key is read here rather than sent as a path: the spaceport being
/// talked to may be on another host, where the file an operator just downloaded
/// does not exist.
async fn connect_github(args: ConnectGithubArgs) -> Result<()> {
    if args.auto {
        let request = client::GithubAppRequest {
            org: args.org,
            name: args.name,
        };

        print!(
            "{}",
            client::register_github(&args.server.server, &request).await?
        );

        // No polling: what happens next is a person opening a link, and a
        // command that sat waiting on that would be holding a terminal open for
        // minutes to report something `spaceport connect list` says anyway.
        return Ok(());
    }

    let private_key = required(args.private_key, "--private-key")?;
    let registration = client::GithubRegistration {
        slug: required(args.slug, "--slug")?,
        app_id: required(args.app_id, "--app-id")?,
        name: required(args.name, "--name")?,
        owner: required(args.owner, "--owner")?,
        client_id: required(args.client_id, "--client-id")?,
        client_secret: required(args.client_secret, "--client-secret")?,
        webhook_secret: required(args.webhook_secret, "--webhook-secret")?,
        private_key: std::fs::read_to_string(&private_key).with_context(|| {
            format!(
                "reading the app's private key `{}` — it is the `.pem` github downloaded",
                private_key.display()
            )
        })?,
    };

    print!(
        "{}",
        client::connect_github(&args.server.server, &registration).await?
    );

    Ok(())
}

/// The value of an option `--manual` cannot do without.
///
/// Optional to clap and required here, because what has to be given depends on
/// which half of the flow was asked for — and a missing one is worth a sentence
/// naming the flag rather than a panic.
fn required<T>(value: Option<T>, flag: &str) -> Result<T> {
    value.with_context(|| format!("`{flag}` is required with `--manual`"))
}

async fn connections(args: ConnectListArgs) -> Result<()> {
    print!("{}", client::connections(&args.server.server).await?);

    Ok(())
}

async fn connection(args: ConnectShowArgs) -> Result<()> {
    print!(
        "{}",
        client::connection(&args.server.server, &args.slug).await?
    );

    Ok(())
}

async fn forget_connection(args: ConnectForgetArgs) -> Result<()> {
    print!(
        "{}",
        client::forget_connection(&args.server.server, &args.slug).await?
    );

    Ok(())
}

async fn destroy(args: DestroyArgs) -> Result<()> {
    print!(
        "{}",
        client::destroy(&args.server.server, &args.app_id).await?
    );

    Ok(())
}

/// Open the state store the way `run` would, and say what is in it.
///
/// Deliberately does not take the lock: this is a question, and asking it
/// while spaceport is running is exactly when the answer is interesting.
async fn check_state(args: ConfigArgs) -> Result<()> {
    let config = Config::load(&args.config)?;
    let directory = &config.state.directory;
    let db = Db::open(directory)?;

    println!("{}: ok", Db::path_in(directory).display());
    println!("  schema version {}", db.schema_version().await?);

    let desired = AppRepository::new(db.clone()).desired().await?;
    if desired.is_empty() {
        println!("  no apps recorded");
    }
    for record in desired {
        println!("  app {} applied {}", record.id, record.applied_at);
    }

    let certificates = CertificateRepository::new(db).all().await?;
    if certificates.is_empty() {
        println!("  no certificates held");
    }
    for certificate in certificates {
        // A certificate whose validity will not parse is worth naming rather
        // than hiding: it is one the edge is not serving either.
        match certificate.validity() {
            Ok(validity) => println!(
                "  certificate for {} expires {}",
                certificate.host, validity.not_after
            ),
            Err(error) => println!(
                "  certificate for {}: unreadable ({error:#})",
                certificate.host
            ),
        }
    }

    Ok(())
}

fn check_config(args: ConfigArgs) -> Result<()> {
    let config = Config::load(&args.config)?;

    println!("{}: ok", args.config.display());
    // Ahead of the listeners: this is the name the config *means*, and the
    // addresses below are only where it is answered. Echoed back normalised, so
    // a hostname that was typed in mixed case is confirmed as it will be routed.
    match &config.edge.hostname {
        Some(hostname) => println!("  edge answers to {hostname} as spaceport itself"),
        None => println!("  edge answers to no host of its own"),
    }
    for (proto, addr) in listeners(&config) {
        println!("  edge listens for {proto} on {addr}");
    }
    match (&config.edge.tls.provider, &config.edge.tls.acme) {
        (TlsProvider::Acme, Some(acme)) => {
            println!("  edge orders certificates from {}", acme.directory.url())
        }
        _ => println!("  edge serves a self-signed certificate, trusted by nothing"),
    }
    println!("  state lives in {}", config.state.directory.display());
    // Named even when nothing uses one yet: it is where an operator's backups
    // have to point, and finding that out after the first volume is written is
    // too late.
    println!(
        "  apps keep their volumes in {}",
        config.data.directory.display()
    );

    Ok(())
}

/// The configured edge listeners, in protocol order.
fn listeners(config: &Config) -> impl Iterator<Item = (&'static str, SocketAddr)> {
    let listen = &config.edge.listen;
    [("http", listen.http), ("https", listen.https)].into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `echo hunter2 | spaceport apps secret set …` is how a secret is set by
    /// anybody who has read the help, and the newline `echo` adds is the
    /// shell's rather than part of the password. A value stored with it would
    /// be a password that fails to authenticate and looks identical to the one
    /// that works everywhere it is printed.
    #[test]
    fn takes_the_newline_a_pipe_added_off_a_value() {
        assert_eq!(read("hunter2\n".to_owned()).unwrap().expose(), "hunter2");
    }

    /// And exactly one of them. A key really can end in a blank line — a `.pem`
    /// does — and trimming until there was nothing left to trim would quietly
    /// store something the app cannot use.
    #[test]
    fn takes_only_one_newline_off_a_value() {
        assert_eq!(read("a key\n\n".to_owned()).unwrap().expose(), "a key\n");
    }

    /// Nothing else is touched either. Every one of these is a byte somebody's
    /// generated token can genuinely carry, and a value stored without one it
    /// arrived with fails for a reason nobody can see by looking at it.
    #[test]
    fn keeps_every_other_byte_of_a_value() {
        assert_eq!(
            read("  spaced \tand\ttabbed\r\n".to_owned())
                .unwrap()
                .expose(),
            "  spaced \tand\ttabbed\r",
        );
    }

    /// A pipe that produced nothing is a command that failed further up the
    /// line — `pass show db | spaceport apps secret set …` with the wrong
    /// name — and storing the empty string would answer that by starting the
    /// app with an empty password.
    #[test]
    fn refuses_a_value_that_is_not_there() {
        assert!(read(String::new()).is_err());
        assert!(read("\n".to_owned()).is_err());
    }

    /// The other half of the argument: a value that is not `-` is the value,
    /// untouched, newline and all.
    #[test]
    fn takes_a_value_off_the_command_line_as_it_is() {
        assert_eq!(value_of("hunter2").unwrap().expose(), "hunter2");
    }

    fn app() -> AppId {
        "web".parse().unwrap()
    }

    fn name() -> VarName {
        "DB_PASSWORD".parse().unwrap()
    }

    /// The outcomes an operator acts on differently have to read differently,
    /// and none of them may name a value — which is why there is no value in
    /// [`SecretSet`] to name.
    #[test]
    fn says_which_of_the_things_setting_a_secret_did() {
        let line = |created, outcome| set_line(&app(), &name(), &SecretSet { created, outcome });

        assert!(
            line(false, SecretOutcome::Unchanged).contains("already had that value"),
            "{}",
            line(false, SecretOutcome::Unchanged),
        );
        assert!(line(true, SecretOutcome::Stored).contains("nothing here is waiting on it"));
        assert!(
            line(
                true,
                SecretOutcome::Missing {
                    secrets: vec!["API_KEY".to_owned()],
                },
            )
            .contains("`API_KEY`")
        );
        assert!(line(false, SecretOutcome::Resumed).contains("serving again"));
        assert!(line(false, SecretOutcome::Redeployed).contains("container was replaced"));
        // And the app that had no container to replace, which must not be told
        // that one was.
        let started = line(false, SecretOutcome::Started);
        assert!(started.contains("it was not running"), "{started}");
        assert!(!started.contains("replaced with"), "{started}");
    }

    /// Created and replaced are the two things an operator is told apart,
    /// because one of them means they have just overwritten something.
    #[test]
    fn says_whether_a_secret_was_new() {
        assert!(
            set_line(
                &app(),
                &name(),
                &SecretSet {
                    created: true,
                    outcome: SecretOutcome::Stored,
                }
            )
            .contains("set for app")
        );
        assert!(
            set_line(
                &app(),
                &name(),
                &SecretSet {
                    created: false,
                    outcome: SecretOutcome::Stored,
                }
            )
            .contains("replaced for app")
        );
    }
}

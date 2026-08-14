mod render;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use render::Colour;
use spaceport_core::acme::account::{AcmeCa, Transport};
use spaceport_core::acme::{CertificateRepository, Certificates, Challenges};
use spaceport_core::app::{
    AppId, AppRepository, AppStore, Applier, DataDir, Pattern, reconcile, supervise,
};
use spaceport_core::config::TlsProvider;
use spaceport_core::events::{self, Category, Event, EventBus, Level};
use spaceport_core::operator::client::Watch;
use spaceport_core::operator::{DEFAULT_OPERATOR_ENDPOINT, client, server};
use spaceport_core::runtime::DockerRuntime;
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
    /// Stop serving an app, keeping everything about it.
    Suspend(SuspendArgs),
    /// Serve a suspended app again.
    Resume(ResumeArgs),
    /// Stop an app and remove it.
    Destroy(DestroyArgs),
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
            AppsCommand::Suspend(args) => suspend(args).await,
            AppsCommand::Resume(args) => resume(args).await,
            AppsCommand::Destroy(args) => destroy(args).await,
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

    let runtime = Arc::new(DockerRuntime::connect(data)?);
    runtime.ping().await?;

    let apps = Arc::new(AppStore::new());
    let applier = Arc::new(Applier::new(
        apps.clone(),
        runtime,
        AppRepository::new(db.clone()),
    ));

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

    let served = edge::serve(&config, apps, acceptor, challenges, shutdown.clone()).await;

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

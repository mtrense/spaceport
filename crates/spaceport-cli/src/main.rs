use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use spaceport_core::acme::account::{AcmeCa, Transport};
use spaceport_core::acme::{CertificateRepository, Certificates, Challenges};
use spaceport_core::app::{AppId, AppRepository, AppStore, Applier, Pattern, reconcile};
use spaceport_core::config::TlsProvider;
use spaceport_core::operator::{DEFAULT_OPERATOR_ENDPOINT, client, server};
use spaceport_core::runtime::DockerRuntime;
use spaceport_core::setup;
use spaceport_core::state::{self, Db, StateLock};
use spaceport_core::{Config, OperatorEndpoint, acme, config::DEFAULT_CONFIG_PATH, edge};
use tokio_util::sync::CancellationToken;
use tracing::info;

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
    /// Stop an app and remove it.
    Destroy(DestroyArgs),
}

#[derive(Debug, Args)]
struct ApplyArgs {
    /// The name to run the app under.
    app_id: AppId,

    /// Path to the app manifest.
    manifest: PathBuf,

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
struct DestroyArgs {
    /// The app to stop and remove.
    app_id: AppId,

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
            AppsCommand::Destroy(args) => destroy(args).await,
        },
    }
}

async fn run(args: RunArgs) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "spaceport=info,warn".into()),
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
    let runtime = Arc::new(DockerRuntime::connect()?);
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

    // Without `--operator` there is no way to tell spaceport what to run, which
    // is a legitimate way to start it: the edge still serves, and still says so.
    let operator = args.operator.map(|endpoint| {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let result = server::serve(&endpoint, applier, shutdown.clone()).await;

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
        client::apply(&args.server.server, &args.app_id, manifest).await?
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

    Ok(())
}

/// The configured edge listeners, in protocol order.
fn listeners(config: &Config) -> impl Iterator<Item = (&'static str, SocketAddr)> {
    let listen = &config.edge.listen;
    [("http", listen.http), ("https", listen.https)].into_iter()
}

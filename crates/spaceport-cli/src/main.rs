use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use spaceport_core::{Config, OperatorEndpoint, config::DEFAULT_CONFIG_PATH, edge};
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
    /// Check that spaceport is set up correctly.
    Check {
        #[command(subcommand)]
        command: CheckCommand,
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

#[derive(Debug, Subcommand)]
enum CheckCommand {
    /// Validate the config file.
    Config(ConfigArgs),
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
        Command::Check {
            command: CheckCommand::Config(args),
        } => check_config(args),
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

    // TODO: start the operator interface if one was requested.
    if let Some(operator) = &args.operator {
        info!(%operator, "operator interface not implemented yet");
    }

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

    edge::serve(&config, shutdown).await
}

fn check_config(args: ConfigArgs) -> Result<()> {
    let config = Config::load(&args.config)?;

    println!("{}: ok", args.config.display());
    for (proto, addr) in listeners(&config) {
        println!("  edge listens for {proto} on {addr}");
    }

    Ok(())
}

/// The configured edge listeners, in protocol order.
fn listeners(config: &Config) -> impl Iterator<Item = (&'static str, SocketAddr)> {
    let listen = &config.edge.listen;
    [("http", listen.http), ("https", listen.https)].into_iter()
}

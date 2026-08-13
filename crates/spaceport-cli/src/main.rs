use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use spaceport_core::{Config, OperatorEndpoint, config::DEFAULT_CONFIG_PATH};

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
    /// Inspect and manage the configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
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
enum ConfigCommand {
    /// Validate the config file.
    Check(ConfigArgs),
}

#[derive(Debug, Args)]
struct ConfigArgs {
    /// Path to the config file.
    #[arg(short, long, value_name = "FILE", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Run(args) => run(args),
        Command::Config {
            command: ConfigCommand::Check(args),
        } => config_check(args),
    }
}

fn run(args: RunArgs) -> Result<()> {
    let config = Config::load(&args.config.config)?;

    // TODO: start the proxy, and the operator interface if one was requested.
    println!("loaded config from {}", args.config.config.display());
    if let Some(operator) = &args.operator {
        println!("operator interface would listen on {operator}");
    }
    let _ = config;

    Ok(())
}

fn config_check(args: ConfigArgs) -> Result<()> {
    Config::load(&args.config)?;
    println!("{}: ok", args.config.display());
    Ok(())
}

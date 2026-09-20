//! `cred-swap`: replace secrets and personal data in text with consistent
//! stand-ins, then put the originals back.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

mod cli;
mod commands;
mod config;
mod output;
mod session;

use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::Parser as _;

use cli::{Cli, Command};
use config::Config;

/// Exit status for a command that could not run at all.
const EXIT_ERROR: u8 = 2;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("CRED_SWAP_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .without_time()
        .init();

    match run() {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(EXIT_ERROR)),
        Err(error) => {
            report(&error);
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run() -> Result<i32> {
    let cli = Cli::parse();

    // `init` writes the config rather than reading it, so it must not fail
    // because the config it is about to create does not parse.
    if let Command::Init(args) = &cli.command {
        return commands::init(args);
    }

    let config = load_config(&cli)?;
    let resolved = config::resolve(&config, &cli.global)?;

    match &cli.command {
        Command::Scrub(args) => commands::scrub(args, &cli.global, &resolved),
        Command::Restore(args) => commands::restore(args, &cli.global, &resolved),
        Command::Detect(args) => commands::detect(args, &cli.global, &resolved),
        Command::Vault(command) => commands::vault(command, &cli.global, &resolved),
        Command::Kinds => commands::kinds(&cli.global, &resolved),
        Command::Proxy(args) => commands::proxy(args, &cli.global, &resolved),
        Command::Init(_) => unreachable!("handled above"),
    }
}

/// Read the config file.
///
/// An explicit `--config` that does not exist is an error, because the user
/// named a file and expects its rules to apply. A missing default config is
/// not: it just means nothing has been configured yet.
fn load_config(cli: &Cli) -> Result<Config> {
    if let Some(path) = &cli.global.config {
        return Config::load(path)
            .with_context(|| format!("--config {} could not be used", path.display()));
    }
    let default = session::config_path()?;
    if default.exists() {
        Config::load(&default)
    } else {
        Ok(Config::default())
    }
}

/// Print an error and everything that caused it, one cause per line.
fn report(error: &anyhow::Error) {
    eprintln!("cred-swap: {error}");
    for cause in error.chain().skip(1) {
        eprintln!("  caused by: {cause}");
    }
}

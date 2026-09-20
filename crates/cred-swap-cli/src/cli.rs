//! Command line surface.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Replace secrets and personal data in text with consistent stand-ins, then
/// put the originals back.
#[derive(Debug, Parser)]
#[command(
    name = "cred-swap",
    version,
    about,
    long_about = "cred-swap rewrites text so it can be sent to a hosted model without \
                  sending the secrets in it.\n\n\
                  Every detected value is replaced by a stand-in of the same shape, so the \
                  model still sees a valid-looking card number or hostname and answers the \
                  question you actually asked. Stand-ins are stable within a session, so the \
                  same value always becomes the same substitute. They are also reversible: \
                  pipe the model's answer back through `restore` to get your real values back.",
    after_help = "Run `cred-swap init` to write a starter config, or `cred-swap kinds` to see \
                  everything it knows how to find."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    #[command(flatten)]
    pub global: GlobalArgs,
}

/// Flags that apply to more than one subcommand.
#[derive(Debug, Args, Clone)]
pub struct GlobalArgs {
    /// Session to use. Sessions keep their own vault, so stand-ins stay
    /// consistent within one and independent between them.
    #[arg(
        long,
        short = 's',
        default_value = "default",
        global = true,
        value_name = "NAME"
    )]
    pub session: String,

    /// Use this vault file instead of the session's default location.
    #[arg(long, global = true, value_name = "PATH", conflicts_with = "session")]
    pub vault: Option<PathBuf>,

    /// Config file to read. Defaults to the per-user config if it exists.
    #[arg(long, short = 'c', global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Which starting set of rules to use.
    #[arg(long, short = 'p', global = true, value_enum)]
    pub policy: Option<PolicyPreset>,

    /// Also detect these kinds. Repeatable, or comma-separated.
    #[arg(long, global = true, value_name = "KIND", value_delimiter = ',')]
    pub enable: Vec<String>,

    /// Do not detect these kinds. Repeatable, or comma-separated.
    #[arg(long, global = true, value_name = "KIND", value_delimiter = ',')]
    pub disable: Vec<String>,

    /// Never replace this exact string. Repeatable.
    #[arg(long, global = true, value_name = "TEXT")]
    pub allow: Vec<String>,

    /// What stand-ins should look like.
    #[arg(long, global = true, value_enum)]
    pub style: Option<StyleArg>,

    /// Print machine-readable JSON instead of a human-readable report.
    #[arg(long, global = true)]
    pub json: bool,

    /// Say nothing on stderr beyond errors.
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,
}

/// A named starting set of detection rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum PolicyPreset {
    /// Credentials and personal data, skipping the rules that fire on ordinary
    /// prose. This is the default.
    Standard,
    /// Credentials only. Leaves names, addresses and cards in place, which is
    /// usually what you want when the text is source code.
    Secrets,
    /// Every rule, including bare URLs, UUIDs and unlabelled high-entropy
    /// strings. Catches more and misfires more.
    Aggressive,
    /// Nothing. Build up from here with `--enable`.
    None,
}

/// How stand-ins should read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum StyleArg {
    /// A plausible value of the same shape, such as `avery.ashford@globex.example`.
    Realistic,
    /// An obvious marker, such as `[[EMAIL_ADDRESS_1]]`.
    Tagged,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Replace sensitive values with stand-ins.
    ///
    /// Reads a file or standard input and writes the rewritten text to
    /// standard output, so it drops straight into a pipe. The summary of what
    /// changed goes to standard error.
    Scrub(ScrubArgs),

    /// Put the real values back wherever a stand-in appears.
    ///
    /// The reverse of `scrub`, against the same session's vault. Pipe a model's
    /// answer through this to get a usable answer back.
    Restore(RestoreArgs),

    /// Report what would be replaced, without changing anything.
    Detect(DetectArgs),

    /// Inspect and manage a session's vault.
    #[command(subcommand)]
    Vault(VaultCommand),

    /// List every kind of value cred-swap can find.
    Kinds,

    /// Write a starter config file.
    Init(InitArgs),

    /// Run a local proxy that scrubs requests and restores responses.
    Proxy(ProxyArgs),
}

#[derive(Debug, Args)]
pub struct ScrubArgs {
    /// File to read. Reads standard input when omitted or `-`.
    #[arg(value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// Write to this file instead of standard output.
    #[arg(long, short = 'o', value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Leave these kinds in place. Secrets are replaced regardless: a
    /// credential left in outgoing text is not a tradeoff worth offering.
    #[arg(long, value_name = "KIND", value_delimiter = ',')]
    pub keep: Vec<String>,

    /// Do not record the substitutions, so they cannot be reversed later.
    ///
    /// Use this for one-way redaction, such as scrubbing a log before
    /// attaching it to a ticket.
    #[arg(long)]
    pub no_save: bool,
}

#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// File to read. Reads standard input when omitted or `-`.
    #[arg(value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// Write to this file instead of standard output.
    #[arg(long, short = 'o', value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct DetectArgs {
    /// File to read. Reads standard input when omitted or `-`.
    #[arg(value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// Print the matched values in full instead of masking secrets.
    #[arg(long)]
    pub show_values: bool,

    /// Exit with status 1 when anything is found, for use in a pre-commit
    /// hook or a CI check.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// List the substitutions in the session.
    List {
        /// Print real values in full instead of masking secrets.
        #[arg(long)]
        show_values: bool,
    },
    /// Print the path to the session's vault file.
    Path,
    /// Generate a new stand-in for one real value.
    ///
    /// Use this when a stand-in happens to collide with something in your text
    /// or reads confusingly. Substitutions already sent to a model keep their
    /// old stand-in in that conversation.
    Reroll {
        /// The real value to give a new stand-in.
        #[arg(value_name = "VALUE")]
        value: String,
    },
    /// Delete every substitution in the session.
    ///
    /// The seed survives, so a value seen again gets the stand-in it had
    /// before. Use `--new-seed` to break that link as well.
    Clear {
        /// Also draw a new seed, so past stand-ins can never be regenerated.
        #[arg(long)]
        new_seed: bool,
        /// Do not ask for confirmation.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Write here instead of the per-user config location.
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Overwrite an existing file.
    #[arg(long, short = 'f')]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// Address to listen on.
    #[arg(
        long,
        short = 'l',
        default_value = "127.0.0.1:8787",
        value_name = "ADDR"
    )]
    pub listen: String,

    /// Where to forward requests.
    #[arg(long, short = 'u', value_name = "URL")]
    pub upstream: String,

    /// Do not restore real values in responses, only scrub requests.
    #[arg(long)]
    pub no_restore: bool,

    /// Write the vault to disk after each request, rather than on shutdown.
    ///
    /// Slower, but a crash cannot then strand stand-ins that a model has
    /// already seen.
    #[arg(long)]
    pub sync_vault: bool,
}

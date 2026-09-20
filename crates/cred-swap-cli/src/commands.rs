//! What each subcommand actually does.

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use cred_swap_core::{Cloak, Decision, EntityKind, Finding, Surrogates, Vault};

use crate::cli::{
    DetectArgs, GlobalArgs, InitArgs, ProxyArgs, RestoreArgs, ScrubArgs, VaultCommand,
};
use crate::config::{self, Resolved};
use crate::output;

/// Exit status meaning "the command ran and found something".
///
/// Separate from a failure status so a pre-commit hook can tell "there is a
/// secret in this diff" apart from "cred-swap could not run".
pub const EXIT_FOUND: i32 = 1;

/// A session opened for use: its vault, its rules, and where it came from.
pub struct Session {
    /// Detection, substitution and restoration for this session.
    pub cloak: Cloak,
    /// Where the vault is stored.
    pub path: PathBuf,
}

impl Session {
    /// Write the vault back to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save(&self) -> Result<()> {
        self.cloak
            .vault()
            .save(&self.path)
            .with_context(|| format!("cannot save session to {}", self.path.display()))
    }
}

/// Open the session named by the arguments, creating it if it does not exist.
///
/// # Errors
///
/// Returns an error if the vault exists but cannot be read, or the policy
/// contains a pattern that does not compile.
pub fn open_session(resolved: &Resolved, args: &GlobalArgs) -> Result<Session> {
    let path = crate::session::resolve_vault(args.vault.as_deref(), &resolved.session)?;
    let vault = Vault::load_or_new(&path, Surrogates::random(resolved.style))
        .with_context(|| format!("cannot open the session at {}", path.display()))?;

    // An existing session's style is a property of the stand-ins already in
    // it. Honouring a conflicting flag would produce a vault with two
    // incompatible naming schemes in it, so the stored style wins and the
    // disagreement is reported.
    if !vault.is_empty() && args.style.is_some() && vault.surrogates().style() != resolved.style {
        warn(
            args,
            &format!(
                "session `{}` already uses the {:?} style; ignoring --style",
                resolved.session,
                vault.surrogates().style()
            ),
        );
    }

    let cloak = Cloak::resume(resolved.policy.clone(), vault)?;
    Ok(Session { cloak, path })
}

/// `cred-swap scrub`
///
/// # Errors
///
/// Returns an error if input or output cannot be accessed, or a `--keep` kind
/// is unknown or is a credential.
pub fn scrub(args: &ScrubArgs, global: &GlobalArgs, resolved: &Resolved) -> Result<i32> {
    let keep = parse_keep(&args.keep)?;
    let text = read_input(args.input.as_deref())?;
    let mut session = open_session(resolved, global)?;

    let scrubbed = session.cloak.scrub_with(&text, |finding: &Finding| {
        if keep.contains(&finding.kind) {
            Decision::Keep
        } else {
            Decision::Replace
        }
    });

    write_output(args.output.as_deref(), &scrubbed.text)?;

    if !args.no_save {
        session.save()?;
    }

    if global.json {
        let report = serde_json::json!({
            "replacements": scrubbed.replacements,
            "kept": scrubbed.kept,
            "vault": session.path,
            "saved": !args.no_save,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !global.quiet {
        let mut stderr = std::io::stderr().lock();
        output::write_scrub_summary(&mut stderr, &scrubbed)?;
        if args.no_save {
            writeln!(stderr, "Not recorded: this scrub cannot be reversed.")?;
        }
    }

    Ok(0)
}

/// `cred-swap restore`
///
/// # Errors
///
/// Returns an error if input or output cannot be accessed, or the session
/// vault cannot be read.
pub fn restore(args: &RestoreArgs, global: &GlobalArgs, resolved: &Resolved) -> Result<i32> {
    let text = read_input(args.input.as_deref())?;
    let mut session = open_session(resolved, global)?;

    if session.cloak.vault().is_empty() {
        warn(
            global,
            &format!(
                "session `{}` has no substitutions, so nothing can be restored",
                resolved.session
            ),
        );
    }

    let count = session.cloak.vault_mut().count_restorable(&text);
    let restored = session.cloak.restore(&text);
    write_output(args.output.as_deref(), &restored)?;

    if global.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "restored": count,
                "vault": session.path,
            }))?
        );
    } else if !global.quiet {
        eprintln!(
            "{} restored.",
            if count == 1 {
                "1 stand-in".to_owned()
            } else {
                format!("{count} stand-ins")
            }
        );
    }

    Ok(0)
}

/// `cred-swap detect`
///
/// # Errors
///
/// Returns an error if input cannot be read or the policy does not compile.
pub fn detect(args: &DetectArgs, global: &GlobalArgs, resolved: &Resolved) -> Result<i32> {
    let text = read_input(args.input.as_deref())?;
    // Detection reads nothing from the vault and writes nothing to it, so this
    // never creates a session file as a side effect of looking.
    let cloak = Cloak::new(resolved.policy.clone(), Surrogates::random(resolved.style))?;
    let findings = cloak.inspect(&text);

    if global.json {
        let rows = output::finding_rows(&text, &findings, args.show_values);
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        let mut stdout = std::io::stdout().lock();
        output::write_findings(&mut stdout, &text, &findings, args.show_values)?;
    }

    Ok(if args.strict && !findings.is_empty() {
        EXIT_FOUND
    } else {
        0
    })
}

/// `cred-swap vault ...`
///
/// # Errors
///
/// Returns an error if the vault cannot be read or written, or a confirmation
/// is needed and cannot be asked for.
pub fn vault(command: &VaultCommand, global: &GlobalArgs, resolved: &Resolved) -> Result<i32> {
    match command {
        VaultCommand::Path => {
            let path = crate::session::resolve_vault(global.vault.as_deref(), &resolved.session)?;
            println!("{}", path.display());
            Ok(0)
        }

        VaultCommand::List { show_values } => {
            let session = open_session(resolved, global)?;
            let entries = session.cloak.vault().entries();
            if global.json {
                println!("{}", serde_json::to_string_pretty(entries)?);
            } else {
                let mut stdout = std::io::stdout().lock();
                output::write_entries(&mut stdout, entries, *show_values)?;
            }
            Ok(0)
        }

        VaultCommand::Reroll { value } => {
            let mut session = open_session(resolved, global)?;
            let Some(entry) = session.cloak.vault_mut().reroll(value) else {
                bail!(
                    "`{value}` has not been substituted in session `{}`. \
                     Run `cred-swap vault list` to see what has.",
                    resolved.session
                );
            };
            session.save()?;
            if global.json {
                println!("{}", serde_json::to_string_pretty(&entry)?);
            } else {
                println!("{} is now {}", entry.kind, entry.fake);
                if !global.quiet {
                    eprintln!("Text already sent using the old stand-in will no longer restore.");
                }
            }
            Ok(0)
        }

        VaultCommand::Clear { new_seed, yes } => {
            let mut session = open_session(resolved, global)?;
            let count = session.cloak.vault().len();
            if count == 0 && !*new_seed {
                if !global.quiet {
                    eprintln!("Session `{}` is already empty.", resolved.session);
                }
                return Ok(0);
            }

            if !*yes {
                let detail = if *new_seed {
                    "and draw a new seed, so those stand-ins can never be regenerated"
                } else {
                    "keeping the seed, so the same values would get the same stand-ins again"
                };
                confirm(&format!(
                    "Delete {count} substitution(s) from session `{}` {detail}?",
                    resolved.session
                ))?;
            }

            if *new_seed {
                let style = session.cloak.vault().surrogates().style();
                *session.cloak.vault_mut() = Vault::new(Surrogates::random(style));
            } else {
                session.cloak.vault_mut().clear();
            }
            session.save()?;

            if !global.quiet {
                eprintln!("Cleared {count} substitution(s).");
            }
            Ok(0)
        }
    }
}

/// `cred-swap kinds`
///
/// # Errors
///
/// Returns an error if stdout cannot be written to.
pub fn kinds(global: &GlobalArgs, resolved: &Resolved) -> Result<i32> {
    if global.json {
        let rows: Vec<_> = EntityKind::BUILTIN
            .iter()
            .map(|kind| {
                serde_json::json!({
                    "kind": kind.as_str(),
                    "category": kind.category().as_str(),
                    "secret": kind.is_secret(),
                    "enabled": resolved.policy.is_enabled(kind),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(0);
    }

    let width = EntityKind::BUILTIN
        .iter()
        .map(|kind| kind.as_str().len())
        .max()
        .unwrap_or(24);

    let mut current = None;
    for kind in EntityKind::BUILTIN {
        let category = kind.category();
        if current != Some(category) {
            if current.is_some() {
                println!();
            }
            println!("{}:", category.as_str().to_uppercase());
            current = Some(category);
        }
        let mark = if resolved.policy.is_enabled(kind) {
            "on "
        } else {
            "off"
        };
        println!("  {mark}  {:<width$}", kind.as_str());
    }
    println!();
    println!(
        "`on` and `off` reflect the current policy. Change it with --policy, --enable and --disable."
    );
    Ok(0)
}

/// `cred-swap init`
///
/// # Errors
///
/// Returns an error if the file already exists without `--force`, or cannot
/// be written.
pub fn init(args: &InitArgs) -> Result<i32> {
    let path = match &args.path {
        Some(path) => path.clone(),
        None => crate::session::config_path()?,
    };

    if path.exists() && !args.force {
        bail!(
            "{} already exists. Pass --force to overwrite it.",
            path.display()
        );
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    std::fs::write(&path, config::TEMPLATE)
        .with_context(|| format!("cannot write {}", path.display()))?;

    println!("Wrote {}", path.display());
    Ok(0)
}

/// `cred-swap proxy`
///
/// # Errors
///
/// Returns an error if the listen address is unusable, the upstream URL is
/// malformed, or the server stops unexpectedly.
pub fn proxy(args: &ProxyArgs, global: &GlobalArgs, resolved: &Resolved) -> Result<i32> {
    use std::sync::{Arc, Mutex};

    let session = open_session(resolved, global)?;
    let vault_path = session.path.clone();
    let cloak = Arc::new(Mutex::new(session.cloak));

    let settings = cred_swap_proxy::Settings {
        listen: args
            .listen
            .parse()
            .with_context(|| format!("`{}` is not a host:port address", args.listen))?,
        upstream: args.upstream.clone(),
        restore_responses: !args.no_restore,
        vault_path: args.sync_vault.then(|| vault_path.clone()),
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;

    let result = runtime.block_on(cred_swap_proxy::serve(settings, Arc::clone(&cloak)));

    // Persist whatever was substituted before reporting a failure: losing the
    // vault would strand every stand-in already sent upstream.
    if let Ok(guard) = cloak.lock() {
        guard.vault().save(&vault_path)?;
    }
    result?;
    Ok(0)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn parse_keep(names: &[String]) -> Result<Vec<EntityKind>> {
    let mut kinds = Vec::with_capacity(names.len());
    for name in names {
        let kind: EntityKind = name.parse().map_err(|_| {
            anyhow::anyhow!("unknown kind `{name}`. Run `cred-swap kinds` for the list.")
        })?;
        if kind.is_secret() {
            bail!(
                "--keep {name} would leave a credential in the outgoing text. \
                 If you really mean to send it, use --policy none --enable <other kinds>."
            );
        }
        kinds.push(kind);
    }
    Ok(kinds)
}

fn read_input(path: Option<&Path>) -> Result<String> {
    match path {
        None => read_stdin(),
        Some(path) if path.as_os_str() == "-" => read_stdin(),
        Some(path) => {
            std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))
        }
    }
}

fn read_stdin() -> Result<String> {
    let mut buffer = String::new();
    std::io::stdin()
        .lock()
        .read_to_string(&mut buffer)
        .context("cannot read standard input")?;
    Ok(buffer)
}

fn write_output(path: Option<&Path>, text: &str) -> Result<()> {
    if let Some(path) = path {
        std::fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))?;
    } else {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(text.as_bytes())?;
        stdout.flush()?;
    }
    Ok(())
}

fn warn(args: &GlobalArgs, message: &str) {
    if !args.quiet {
        eprintln!("cred-swap: {message}");
    }
}

/// Ask before doing something irreversible.
///
/// Refuses rather than assuming yes when there is no terminal to ask at, so a
/// script that pipes input cannot silently destroy a vault.
fn confirm(question: &str) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        bail!("{question} Pass --yes to confirm; refusing to assume when not run from a terminal.");
    }
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;

    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("cannot read the answer")?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        bail!("Cancelled.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_accepts_ordinary_kinds() {
        let kinds = parse_keep(&["email-address".into(), "ip_v4".into()]).unwrap();
        assert_eq!(kinds, vec![EntityKind::EmailAddress, EntityKind::IpV4]);
    }

    #[test]
    fn keep_refuses_credentials_and_says_why() {
        let error = parse_keep(&["github-token".into()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("credential"), "{error}");
    }

    #[test]
    fn keep_rejects_an_unknown_kind() {
        assert!(parse_keep(&["nonsense".into()]).is_err());
    }

    #[test]
    fn reading_a_missing_file_names_it() {
        let error = read_input(Some(Path::new("/nope/missing.txt")))
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing.txt"), "{error}");
    }
}

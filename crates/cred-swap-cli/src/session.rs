//! Where sessions and config live on disk.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

/// Environment variable that overrides the whole data directory.
///
/// Set this to keep sessions inside a project, or to point at an encrypted
/// volume. Vault files contain every real value alongside its stand-in, so
/// where they live is a decision worth being able to make.
pub const HOME_VAR: &str = "CRED_SWAP_HOME";

/// The directory holding config and sessions.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn home() -> Result<PathBuf> {
    if let Some(override_path) = std::env::var_os(HOME_VAR) {
        let path = PathBuf::from(override_path);
        if path.as_os_str().is_empty() {
            bail!("{HOME_VAR} is set but empty");
        }
        return Ok(path);
    }
    let dirs = directories::ProjectDirs::from("", "", "cred-swap").context(
        "cannot locate a home directory for the session store; set {HOME_VAR} to choose one",
    )?;
    Ok(dirs.data_local_dir().to_path_buf())
}

/// The vault file for a named session.
///
/// # Errors
///
/// Returns an error if the name is not usable as a filename, or if no home
/// directory can be determined.
pub fn vault_path(session: &str) -> Result<PathBuf> {
    validate_session_name(session)?;
    Ok(home()?.join("sessions").join(format!("{session}.json")))
}

/// The default config file location.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn config_path() -> Result<PathBuf> {
    Ok(home()?.join("config.toml"))
}

/// Reject session names that would escape the session directory.
///
/// A session name reaches the filesystem directly, so `../../.ssh/id_rsa` has
/// to be refused here rather than trusted to the caller.
fn validate_session_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("session name is empty");
    }
    if name.len() > 64 {
        bail!("session name is longer than 64 characters");
    }
    let acceptable = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !acceptable || name.starts_with('.') {
        bail!(
            "session name `{name}` is not usable as a filename; \
             use letters, digits, dashes and underscores"
        );
    }
    Ok(())
}

/// Resolve the vault path from an explicit override or a session name.
///
/// # Errors
///
/// Returns an error if the session name is unusable or no home directory can
/// be determined.
pub fn resolve_vault(explicit: Option<&Path>, session: &str) -> Result<PathBuf> {
    match explicit {
        Some(path) => Ok(path.to_path_buf()),
        None => vault_path(session),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_session_names_are_accepted() {
        for name in ["default", "work", "incident-4821", "a_b.c"] {
            validate_session_name(name).unwrap_or_else(|e| panic!("{name} rejected: {e}"));
        }
    }

    #[test]
    fn traversal_and_separators_are_refused() {
        for name in ["../escape", "a/b", "a\\b", "", ".hidden", "with space"] {
            assert!(
                validate_session_name(name).is_err(),
                "{name:?} should not be a valid session name"
            );
        }
    }

    #[test]
    fn an_explicit_path_bypasses_the_session_store() {
        let explicit = Path::new("/tmp/somewhere/vault.json");
        assert_eq!(
            resolve_vault(Some(explicit), "default").unwrap(),
            explicit.to_path_buf()
        );
    }
}

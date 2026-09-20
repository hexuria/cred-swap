//! Runs the built binary the way a user would.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_cred-swap");

/// A throwaway `CRED_SWAP_HOME`, removed when the test ends.
struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = format!(
            "cred-swap-cli-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&path).expect("cannot create the sandbox");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Run `cred-swap` with these arguments and this standard input.
    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(BIN)
            .args(args)
            .env("CRED_SWAP_HOME", &self.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("cannot start cred-swap");
        child
            .stdin
            .as_mut()
            .expect("stdin was piped")
            .write_all(stdin.as_bytes())
            .expect("cannot write to cred-swap");
        child.wait_with_output().expect("cred-swap did not finish")
    }

    /// Run and return standard output, asserting the command succeeded.
    fn stdout(&self, args: &[&str], stdin: &str) -> String {
        let output = self.run(args, stdin);
        assert!(
            output.status.success(),
            "`cred-swap {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("output was not UTF-8")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn scrub_then_restore_returns_the_original_text() {
    let sandbox = Sandbox::new();
    let original = "Email dana@corp.com or call +1 415 867 5309.";

    let scrubbed = sandbox.stdout(&["scrub"], original);
    assert!(!scrubbed.contains("dana@corp.com"), "{scrubbed}");

    let restored = sandbox.stdout(&["restore"], &scrubbed);
    assert_eq!(restored, original);
}

#[test]
fn the_summary_goes_to_stderr_so_stdout_stays_pipeable() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["scrub"], "mail dana@corp.com");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains("replaced"),
        "summary leaked into stdout: {stdout}"
    );
    assert!(stderr.contains("1 value replaced"), "{stderr}");
}

#[test]
fn detect_signals_findings_through_its_exit_status() {
    let sandbox = Sandbox::new();
    assert_eq!(
        sandbox
            .run(&["detect", "--strict"], "nothing here")
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        sandbox
            .run(&["detect", "--strict"], "mail dana@corp.com")
            .status
            .code(),
        Some(1)
    );
}

#[test]
fn detect_does_not_create_a_session() {
    let sandbox = Sandbox::new();
    sandbox.stdout(&["detect"], "mail dana@corp.com");
    assert!(
        !sandbox.path().join("sessions").exists(),
        "looking at text should not start a session"
    );
}

#[test]
fn separate_sessions_do_not_share_stand_ins() {
    let sandbox = Sandbox::new();
    let text = "mail dana@corp.com";

    let work = sandbox.stdout(&["--session", "work", "scrub"], text);
    let home = sandbox.stdout(&["--session", "home", "scrub"], text);
    assert_ne!(work, home, "two sessions produced the same stand-in");

    // A stand-in from one session means nothing in the other.
    let crossed = sandbox.stdout(&["--session", "home", "restore"], &work);
    assert_eq!(crossed, work);
}

#[test]
fn a_session_keeps_its_stand_ins_across_invocations() {
    let sandbox = Sandbox::new();
    let first = sandbox.stdout(&["scrub"], "mail dana@corp.com today");
    let second = sandbox.stdout(&["scrub"], "mail dana@corp.com tomorrow");

    let stand_in = first
        .split_whitespace()
        .nth(1)
        .expect("the scrubbed line has a second word");
    assert!(
        second.contains(stand_in),
        "the second run used a different stand-in: {first} vs {second}"
    );
}

#[cfg(unix)]
#[test]
fn the_session_file_is_not_readable_by_other_users() {
    use std::os::unix::fs::PermissionsExt as _;

    let sandbox = Sandbox::new();
    sandbox.stdout(&["scrub"], "mail dana@corp.com");

    let path = sandbox.path().join("sessions").join("default.json");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "the vault is readable by other users");
}

#[test]
fn no_save_leaves_no_trace_and_cannot_be_reversed() {
    let sandbox = Sandbox::new();
    let scrubbed = sandbox.stdout(&["scrub", "--no-save"], "mail dana@corp.com");
    assert!(!scrubbed.contains("dana@corp.com"));

    let restored = sandbox.stdout(&["restore"], &scrubbed);
    assert_eq!(
        restored, scrubbed,
        "a --no-save scrub should not be reversible"
    );
}

#[test]
fn keep_refuses_to_pass_a_credential_through() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["scrub", "--keep", "github-token"], "");
    assert_eq!(output.status.code(), Some(2));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("credential"), "{stderr}");
}

#[test]
fn keep_leaves_the_named_kind_alone() {
    let sandbox = Sandbox::new();
    let text = "mail dana@corp.com from 203.0.113.9";
    let scrubbed = sandbox.stdout(&["scrub", "--keep", "email-address"], text);
    assert!(scrubbed.contains("dana@corp.com"), "{scrubbed}");
    assert!(!scrubbed.contains("203.0.113.9"), "{scrubbed}");
}

#[test]
fn tagged_style_produces_readable_markers() {
    let sandbox = Sandbox::new();
    let scrubbed = sandbox.stdout(&["--style", "tagged", "scrub"], "mail dana@corp.com");
    assert!(scrubbed.contains("[[EMAIL_ADDRESS_1]]"), "{scrubbed}");
    assert_eq!(
        sandbox.stdout(&["restore"], &scrubbed),
        "mail dana@corp.com"
    );
}

#[test]
fn the_secrets_policy_leaves_ordinary_personal_data_in_place() {
    let sandbox = Sandbox::new();
    let text = "Dana's address is dana@corp.com";
    let scrubbed = sandbox.stdout(&["--policy", "secrets", "scrub"], text);
    assert_eq!(scrubbed, text);
}

#[test]
fn init_writes_a_config_and_refuses_to_clobber_it() {
    let sandbox = Sandbox::new();
    let path = sandbox.path().join("config.toml");

    sandbox.stdout(&["init", path.to_str().unwrap()], "");
    assert!(path.exists());

    let again = sandbox.run(&["init", path.to_str().unwrap()], "");
    assert_eq!(again.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("--force"),
        "the error should say how to overwrite"
    );

    sandbox.stdout(&["init", "--force", path.to_str().unwrap()], "");
}

#[test]
fn a_config_file_adds_its_own_terms_and_patterns() {
    let sandbox = Sandbox::new();
    let config = sandbox.path().join("custom.toml");
    std::fs::write(
        &config,
        r#"
policy = "none"

[[term]]
literal = "Project Halcyon"
kind = "custom:codename"

[[pattern]]
label = "ticket"
regex = '\bACME-\d{4}\b'
group = 0
"#,
    )
    .unwrap();

    let scrubbed = sandbox.stdout(
        &["--config", config.to_str().unwrap(), "scrub"],
        "Project Halcyon is tracked in ACME-1234, ask dana@corp.com",
    );

    assert!(!scrubbed.contains("Project Halcyon"), "{scrubbed}");
    assert!(!scrubbed.contains("ACME-1234"), "{scrubbed}");
    // `policy = "none"` was asked for, so the email is out of scope.
    assert!(scrubbed.contains("dana@corp.com"), "{scrubbed}");
}

#[test]
fn a_missing_named_config_is_an_error_rather_than_a_silent_default() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["--config", "/nope/missing.toml", "detect"], "");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing.toml"));
}

#[test]
fn clearing_a_vault_needs_confirmation_when_there_is_no_terminal() {
    let sandbox = Sandbox::new();
    sandbox.stdout(&["scrub"], "mail dana@corp.com");

    let output = sandbox.run(&["vault", "clear"], "");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--yes"));

    sandbox.run(&["vault", "clear", "--yes"], "");
    let listing = sandbox.stdout(&["vault", "list"], "");
    assert!(listing.contains("no substitutions"), "{listing}");
}

#[test]
fn a_session_name_cannot_escape_the_session_directory() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["--session", "../../escape", "scrub"], "hello");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not usable as a filename"));
}

#[test]
fn kinds_lists_every_rule_with_its_state() {
    let sandbox = Sandbox::new();
    let listing = sandbox.stdout(&["kinds"], "");
    assert!(listing.contains("aws-access-key-id"));
    assert!(listing.contains("CREDENTIAL:"));
    // `url` is off under the standard policy.
    assert!(
        listing
            .lines()
            .any(|line| line.contains("off") && line.contains("url")),
        "{listing}"
    );
}

#[test]
fn json_output_is_valid_json() {
    let sandbox = Sandbox::new();
    let out = sandbox.stdout(&["--json", "detect"], "mail dana@corp.com");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("not valid JSON");
    assert_eq!(parsed[0]["kind"], "email-address");
}

#[test]
fn scrubbing_already_scrubbed_text_is_a_no_op() {
    let sandbox = Sandbox::new();
    let once = sandbox.stdout(&["scrub"], "mail dana@corp.com");
    let twice = sandbox.stdout(&["scrub"], &once);
    assert_eq!(once, twice);
}

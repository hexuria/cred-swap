//! The config file, and how it combines with command line flags.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use cred_swap_core::{CustomPattern, EntityKind, Policy, Style, Term};
use serde::Deserialize;

use crate::cli::{GlobalArgs, PolicyPreset, StyleArg};

/// The starter file written by `cred-swap init`.
pub const TEMPLATE: &str = include_str!("../template.toml");

/// A parsed config file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Which preset to start from: `standard`, `secrets`, `aggressive`, `none`.
    pub policy: Option<String>,
    /// `realistic` or `tagged`.
    pub style: Option<String>,
    /// Default session name.
    pub session: Option<String>,
    /// Extra kinds to detect.
    #[serde(default)]
    pub enable: Vec<String>,
    /// Kinds not to detect.
    #[serde(default)]
    pub disable: Vec<String>,
    /// Exact strings never to replace.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Literal strings always to replace.
    #[serde(default, rename = "term")]
    pub terms: Vec<TermSpec>,
    /// User-defined regex rules.
    #[serde(default, rename = "pattern")]
    pub patterns: Vec<PatternSpec>,
}

/// A literal string the user always wants replaced.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermSpec {
    /// The string to look for.
    pub literal: String,
    /// What to treat it as. Use `custom:<label>` for your own category.
    pub kind: String,
}

/// A user-defined regex rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternSpec {
    /// Name for this rule, shown in reports.
    pub label: String,
    /// The pattern.
    pub regex: String,
    /// Capture group holding the value to replace. 0 means the whole match.
    #[serde(default)]
    pub group: usize,
}

impl Config {
    /// Read and parse a config file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or is not valid TOML.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config at {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("config at {} is not valid", path.display()))
    }
}

/// Everything the flags and the config file agreed on.
#[derive(Debug)]
pub struct Resolved {
    /// The rules to apply.
    pub policy: Policy,
    /// What stand-ins should look like.
    pub style: Style,
    /// Which session to use.
    pub session: String,
}

/// Combine a config file with command line flags.
///
/// Flags win over the file, and the file wins over the built-in defaults. The
/// one exception is `--allow` and `disable`, which are additive: a flag cannot
/// un-exempt something the config exempted, because that would make a
/// carefully written config silently weaker on the command line.
///
/// # Errors
///
/// Returns an error if any kind name is not recognised.
pub fn resolve(config: &Config, args: &GlobalArgs) -> Result<Resolved> {
    let mut policy = match args.policy {
        Some(PolicyPreset::Standard) => Policy::default(),
        Some(PolicyPreset::Secrets) => Policy::secrets_only(),
        Some(PolicyPreset::Aggressive) => Policy::aggressive(),
        Some(PolicyPreset::None) => Policy::empty(),
        // The preset names in a config file are the same vocabulary the
        // browser build uses, so core owns them.
        None => match config.policy.as_deref() {
            None => Policy::default(),
            Some(name) => Policy::from_preset(name)
                .map_err(|error| anyhow::anyhow!("config sets policy = \"{name}\": {error}"))?,
        },
    };

    for name in config.enable.iter().chain(args.enable.iter()) {
        policy = policy.enable(parse_kind(name)?);
    }
    for name in config.disable.iter().chain(args.disable.iter()) {
        policy = policy.disable(&parse_kind(name)?);
    }
    for literal in config.allow.iter().chain(args.allow.iter()) {
        policy = policy.allow(literal.clone());
    }
    for term in &config.terms {
        policy.terms.push(Term {
            literal: term.literal.clone(),
            kind: parse_kind(&term.kind)?,
        });
    }
    for pattern in &config.patterns {
        policy.custom_patterns.push(CustomPattern {
            label: pattern.label.clone(),
            pattern: pattern.regex.clone(),
            group: pattern.group,
        });
    }

    let style = match args.style {
        Some(StyleArg::Realistic) => Style::Realistic,
        Some(StyleArg::Tagged) => Style::Tagged,
        None => match config.style.as_deref() {
            None | Some("realistic") => Style::Realistic,
            Some("tagged") => Style::Tagged,
            Some(other) => {
                bail!("config sets style = \"{other}\", expected realistic or tagged")
            }
        },
    };

    // `--session` has a default value, so it cannot be distinguished from
    // being unset; treat the literal default as "unset" and let the config win.
    let session = if args.session == "default" {
        config
            .session
            .clone()
            .unwrap_or_else(|| "default".to_owned())
    } else {
        args.session.clone()
    };

    Ok(Resolved {
        policy,
        style,
        session,
    })
}

fn parse_kind(name: &str) -> Result<EntityKind> {
    name.parse::<EntityKind>().map_err(|_| {
        anyhow::anyhow!(
            "unknown kind `{name}`. Run `cred-swap kinds` for the list, \
             or use `custom:<label>` for your own."
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> GlobalArgs {
        GlobalArgs {
            session: "default".into(),
            vault: None,
            config: None,
            policy: None,
            enable: Vec::new(),
            disable: Vec::new(),
            allow: Vec::new(),
            style: None,
            json: false,
            quiet: false,
        }
    }

    #[test]
    fn the_shipped_template_parses() {
        let config: Config = toml::from_str(TEMPLATE).expect("template is valid TOML");
        let resolved = resolve(&config, &args()).expect("template resolves");
        assert!(resolved.policy.is_enabled(&EntityKind::AwsAccessKeyId));
    }

    #[test]
    fn flags_override_the_config_preset() {
        let config = Config {
            policy: Some("aggressive".into()),
            ..Config::default()
        };
        let mut args = args();
        args.policy = Some(PolicyPreset::Secrets);
        let resolved = resolve(&config, &args).unwrap();
        assert!(!resolved.policy.is_enabled(&EntityKind::EmailAddress));
    }

    #[test]
    fn config_and_flag_exemptions_both_apply() {
        let config = Config {
            allow: vec!["from-config".into()],
            ..Config::default()
        };
        let mut args = args();
        args.allow = vec!["from-flag".into()];
        let resolved = resolve(&config, &args).unwrap();
        assert!(resolved.policy.is_allowed("from-config"));
        assert!(resolved.policy.is_allowed("from-flag"));
    }

    #[test]
    fn disable_wins_over_enable_for_the_same_kind() {
        let mut args = args();
        args.enable = vec!["url".into()];
        args.disable = vec!["url".into()];
        let resolved = resolve(&Config::default(), &args).unwrap();
        assert!(!resolved.policy.is_enabled(&EntityKind::Url));
    }

    #[test]
    fn an_unknown_kind_names_itself_in_the_error() {
        let mut args = args();
        args.enable = vec!["emial".into()];
        let error = resolve(&Config::default(), &args).unwrap_err().to_string();
        assert!(error.contains("emial"), "{error}");
        assert!(error.contains("cred-swap kinds"), "{error}");
    }

    #[test]
    fn a_bad_preset_name_is_rejected_with_the_options() {
        let config = Config {
            policy: Some("paranoid".into()),
            ..Config::default()
        };
        let error = resolve(&config, &args()).unwrap_err().to_string();
        assert!(error.contains("paranoid"), "{error}");
        assert!(error.contains("aggressive"), "{error}");
    }

    #[test]
    fn an_unknown_config_key_is_reported_rather_than_ignored() {
        let error = toml::from_str::<Config>("polcy = \"secrets\"")
            .unwrap_err()
            .to_string();
        assert!(error.contains("polcy"), "{error}");
    }

    #[test]
    fn custom_kinds_are_accepted_in_terms() {
        let config = Config {
            terms: vec![TermSpec {
                literal: "Halcyon".into(),
                kind: "custom:codename".into(),
            }],
            ..Config::default()
        };
        let resolved = resolve(&config, &args()).unwrap();
        assert_eq!(
            resolved.policy.terms[0].kind,
            EntityKind::Custom("codename".into())
        );
    }
}

//! What to look for, and what to leave alone.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::detect::patterns::RULES;
use crate::entity::EntityKind;

/// Returned when a preset name is not recognised.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown policy `{0}`, expected standard, secrets, aggressive or none")]
pub struct UnknownPreset(pub String);

/// A literal string the user always wants replaced, regardless of shape.
///
/// This is how a team masks its own codenames, internal hostnames or customer
/// names, which no general pattern could know about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Term {
    /// The literal to look for. Matched case-insensitively on word boundaries.
    pub literal: String,
    /// What to treat it as, which decides the shape of its replacement.
    pub kind: EntityKind,
}

/// A user-supplied regex rule from the config file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomPattern {
    /// Label for the entity, surfaced as `EntityKind::Custom`.
    pub label: String,
    /// The regex source.
    pub pattern: String,
    /// Capture group holding the value to replace. Defaults to the whole match.
    #[serde(default)]
    pub group: usize,
}

/// The set of decisions that shape a scrub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Entity kinds to detect.
    pub enabled: BTreeSet<EntityKind>,
    /// Literal strings never replaced, even when a rule matches them.
    ///
    /// Compared case-insensitively. This is the escape hatch for a public
    /// address or a demo key that the reader needs to see verbatim.
    pub allowlist: BTreeSet<String>,
    /// Literal strings always replaced.
    pub terms: Vec<Term>,
    /// Extra regex rules.
    pub custom_patterns: Vec<CustomPattern>,
}

impl Default for Policy {
    /// Everything the built-in table marks as on by default.
    ///
    /// The rules left off are the ones that fire constantly on ordinary text:
    /// bare URLs, UUIDs, and the entropy-only secret sweep.
    fn default() -> Self {
        Self {
            enabled: RULES
                .iter()
                .filter(|rule| rule.default_on)
                .map(|rule| rule.kind.clone())
                .collect(),
            allowlist: BTreeSet::new(),
            terms: Vec::new(),
            custom_patterns: Vec::new(),
        }
    }
}

impl Policy {
    /// Detect nothing. Build up from here with [`Policy::enable`].
    #[must_use]
    pub fn empty() -> Self {
        Self {
            enabled: BTreeSet::new(),
            allowlist: BTreeSet::new(),
            terms: Vec::new(),
            custom_patterns: Vec::new(),
        }
    }

    /// Credentials only: the smallest policy that still prevents a leak.
    ///
    /// Useful when piping source code, where masking every name and address
    /// would destroy the snippet but leaking a key would end the day.
    #[must_use]
    pub fn secrets_only() -> Self {
        Self {
            // Built from the rule table rather than from the kind list, so a
            // kind whose only rule is off by default stays off. Otherwise
            // asking for "credentials" would quietly switch on the unlabelled
            // entropy sweep, which in source code fires on every checksum and
            // alphabet constant in the tree.
            enabled: RULES
                .iter()
                .filter(|rule| rule.default_on && rule.kind.is_secret())
                .map(|rule| rule.kind.clone())
                .collect(),
            ..Self::empty()
        }
    }

    /// Build a policy from a preset name.
    ///
    /// The names are the shared vocabulary between the command line, the
    /// config file and the browser build, so they live here rather than in any
    /// one of them.
    ///
    /// # Errors
    ///
    /// Returns the list of valid names if `name` is not one of them.
    pub fn from_preset(name: &str) -> Result<Self, UnknownPreset> {
        match name.trim().to_ascii_lowercase().as_str() {
            "standard" | "default" => Ok(Self::default()),
            "secrets" => Ok(Self::secrets_only()),
            "aggressive" => Ok(Self::aggressive()),
            "none" => Ok(Self::empty()),
            _ => Err(UnknownPreset(name.to_owned())),
        }
    }

    /// Every built-in kind, including the noisy ones.
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            enabled: EntityKind::BUILTIN.iter().cloned().collect(),
            ..Self::empty()
        }
    }

    /// Turn a kind on.
    #[must_use]
    pub fn enable(mut self, kind: EntityKind) -> Self {
        self.enabled.insert(kind);
        self
    }

    /// Turn a kind off.
    #[must_use]
    pub fn disable(mut self, kind: &EntityKind) -> Self {
        self.enabled.remove(kind);
        self
    }

    /// Exempt a literal string from replacement.
    #[must_use]
    pub fn allow(mut self, literal: impl Into<String>) -> Self {
        self.allowlist.insert(literal.into().to_ascii_lowercase());
        self
    }

    /// Always replace a literal string.
    #[must_use]
    pub fn term(mut self, literal: impl Into<String>, kind: EntityKind) -> Self {
        self.terms.push(Term {
            literal: literal.into(),
            kind,
        });
        self
    }

    /// Whether a kind is in scope.
    #[must_use]
    pub fn is_enabled(&self, kind: &EntityKind) -> bool {
        self.enabled.contains(kind)
    }

    /// Whether a matched string is exempt.
    #[must_use]
    pub fn is_allowed(&self, text: &str) -> bool {
        if self.allowlist.is_empty() {
            return false;
        }
        self.allowlist.contains(&text.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_covers_credentials_but_not_bare_urls() {
        let policy = Policy::default();
        assert!(policy.is_enabled(&EntityKind::AwsAccessKeyId));
        assert!(policy.is_enabled(&EntityKind::EmailAddress));
        assert!(!policy.is_enabled(&EntityKind::Url));
        assert!(!policy.is_enabled(&EntityKind::Uuid));
    }

    #[test]
    fn secrets_only_excludes_personal_data() {
        let policy = Policy::secrets_only();
        assert!(policy.is_enabled(&EntityKind::GithubToken));
        assert!(policy.is_enabled(&EntityKind::DatabaseUrl));
        assert!(!policy.is_enabled(&EntityKind::EmailAddress));
        assert!(
            !policy.is_enabled(&EntityKind::HighEntropyString),
            "asking for credentials should not turn on the entropy sweep"
        );
        assert!(!policy.is_enabled(&EntityKind::CreditCard));
    }

    #[test]
    fn preset_names_map_to_the_right_policies() {
        assert!(
            Policy::from_preset("standard")
                .unwrap()
                .is_enabled(&EntityKind::EmailAddress)
        );
        assert!(
            !Policy::from_preset("secrets")
                .unwrap()
                .is_enabled(&EntityKind::EmailAddress)
        );
        assert!(
            Policy::from_preset("aggressive")
                .unwrap()
                .is_enabled(&EntityKind::Url)
        );
        assert!(Policy::from_preset("none").unwrap().enabled.is_empty());
        assert!(
            Policy::from_preset("Standard").is_ok(),
            "names are case-insensitive"
        );

        let error = Policy::from_preset("paranoid").unwrap_err().to_string();
        assert!(error.contains("paranoid"), "{error}");
        assert!(error.contains("aggressive"), "{error}");
    }

    #[test]
    fn allowlist_is_case_insensitive() {
        let policy = Policy::default().allow("Support@Example.com");
        assert!(policy.is_allowed("support@example.com"));
        assert!(policy.is_allowed("SUPPORT@EXAMPLE.COM"));
        assert!(!policy.is_allowed("other@example.com"));
    }

    #[test]
    fn policy_round_trips_through_json() {
        let policy = Policy::default()
            .allow("example.com")
            .term("Project Halcyon", EntityKind::Custom("codename".into()));
        let encoded = serde_json::to_string(&policy).unwrap();
        let decoded: Policy = serde_json::from_str(&encoded).unwrap();
        assert_eq!(policy, decoded);
    }
}

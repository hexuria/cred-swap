//! The built-in rule table.
//!
//! Each rule pairs a regex with the span it actually wants to replace and an
//! optional structural check. Rules that would otherwise fire on every second
//! line of a code snippet are keyword-gated: they only match when the text
//! itself says what the value is (`api_key = ...`), which is what keeps the
//! output reviewable.

use regex::Regex;

use crate::entity::EntityKind;

use super::validate;

/// A compiled detection rule.
pub struct Rule {
    /// What a match of this rule means.
    pub kind: EntityKind,
    /// The compiled pattern.
    pub regex: Regex,
    /// Which capture group holds the value to replace.
    ///
    /// Group 0 is the whole match. Keyword-gated rules use group 1 so the
    /// keyword itself (`password = `) survives into the scrubbed text.
    pub group: usize,
    /// Structural check applied to the captured text.
    pub validate: Option<fn(&str) -> bool>,
    /// Whether the default policy enables this rule.
    pub default_on: bool,
}

/// Substrings that mark a value as a stand-in for a secret rather than one.
const DEAD_GIVEAWAYS: &[&str] = &[
    "your",
    "my-",
    "changeme",
    "change_me",
    "placeholder",
    "example",
    "redacted",
    "todo",
    "fixme",
    "insert",
    "replace",
    "dummy",
    "sample",
    "test-key",
    "notreal",
    "secret_here",
    "key_here",
    "value_here",
    "none",
    "null",
    "undefined",
];

/// Strings that look like a secret's shape but carry no secret.
///
/// Scrubbing these is worse than useless: it trains the reader to ignore the
/// report, and it burns a vault entry that can never be restored usefully.
fn is_placeholder(value: &str) -> bool {
    let lowered = value
        .trim()
        .trim_matches(['"', '\'', '`'])
        .to_ascii_lowercase();
    if lowered.len() < 6 {
        return true;
    }
    if lowered.starts_with('<') || lowered.starts_with('$') || lowered.starts_with('{') {
        return true;
    }
    if lowered.contains("***") || lowered.contains("xxxx") {
        return true;
    }
    // A single repeated character is a mask, not a value.
    let first = lowered.as_bytes()[0];
    if lowered.bytes().all(|b| b == first) {
        return true;
    }
    DEAD_GIVEAWAYS.iter().any(|needle| lowered.contains(needle))
}

/// Values that are the gating keyword said back, not a secret.
///
/// `Credential => "credential"` and `"secret": isSecret` are ordinary lines of
/// code that happen to sit next to the word a keyword-gated rule looks for.
const KEYWORD_ECHOES: &[&str] = &[
    "secret",
    "secrets",
    "credential",
    "credentials",
    "password",
    "passwords",
    "passwd",
    "pwd",
    "passphrase",
    "token",
    "tokens",
    "apikey",
    "api_key",
    "key",
    "keys",
    "value",
    "string",
    "text",
    "true",
    "false",
    "default",
    "enabled",
    "disabled",
    "required",
    "optional",
];

/// Reject a capture that is a fragment of source code rather than a value.
///
/// Keyword-gated rules read `name = value`, which is also the shape of half
/// the lines in any program. Without this, scanning a codebase reports
/// `secrets = findings.iter().filter(|f| ...` as a leaked credential, and a
/// report full of those is a report nobody reads.
fn looks_like_code(value: &str) -> bool {
    value.contains("::")
        || value.contains("()")
        || value.contains("=>")
        || value.contains('|')
        || value.contains("${")
        || value.contains("&&")
        || value.ends_with('(')
        || value.ends_with('.')
        || value.ends_with("--")
}

/// Reject a capture that is a bare identifier.
///
/// `secret: isSecret` and `password: userPassword` are how code passes a
/// value around, not how it writes one down. A real passphrase of this length
/// almost always carries a digit or a separator; an identifier does not.
fn looks_like_identifier(value: &str) -> bool {
    value.len() < 20 && value.bytes().all(|byte| byte.is_ascii_alphabetic())
}

/// Shared gate for every keyword-gated rule.
fn is_credible_value(value: &str) -> bool {
    !is_placeholder(value)
        && !looks_like_code(value)
        && !looks_like_identifier(value)
        && !KEYWORD_ECHOES.contains(&value.trim().to_ascii_lowercase().as_str())
}

/// A keyword-gated secret: real enough to be worth replacing.
fn is_real_secret(value: &str) -> bool {
    is_credible_value(value) && value.len() >= 8
}

/// A generic key: keyword-gated, so entropy is a tiebreak rather than a gate.
fn is_real_key(value: &str) -> bool {
    is_credible_value(value) && value.len() >= 12
}

/// A US Social Security Number that the SSA would actually issue.
fn is_issuable_ssn(value: &str) -> bool {
    let digits: Vec<u8> = value.bytes().filter(u8::is_ascii_digit).collect();
    if digits.len() != 9 {
        return false;
    }
    let area = &value[..3];
    let group = &digits[3..5];
    let serial = &digits[5..];
    if matches!(area, "000" | "666") || area.starts_with('9') {
        return false;
    }
    if group.iter().all(|&b| b == b'0') || serial.iter().all(|&b| b == b'0') {
        return false;
    }
    true
}

/// A run of digits long enough to be a dialable number.
fn is_dialable(value: &str) -> bool {
    let digits = value.bytes().filter(u8::is_ascii_digit).count();
    (10..=15).contains(&digits)
}

fn is_valid_card(value: &str) -> bool {
    validate::luhn(value)
}

fn is_valid_iban(value: &str) -> bool {
    validate::iban_mod97(value)
}

fn is_valid_routing(value: &str) -> bool {
    validate::aba_routing(value)
}

fn is_maskable_ipv4(value: &str) -> bool {
    validate::parse_ipv4(value).is_some_and(validate::is_meaningful_ipv4)
}

fn is_random_enough(value: &str) -> bool {
    validate::looks_random(value)
}

/// Build the rule table. Called once, behind [`RULES`].
///
/// A malformed pattern here is a bug in this file, not a runtime condition, so
/// compilation failure panics with the offending pattern named.
#[expect(
    clippy::too_many_lines,
    reason = "the rule table reads as a table; splitting it hides the ordering that decides precedence"
)]
fn build() -> Vec<Rule> {
    fn rule(
        kind: EntityKind,
        pattern: &str,
        group: usize,
        validate: Option<fn(&str) -> bool>,
        default_on: bool,
    ) -> Rule {
        let regex = Regex::new(pattern)
            .unwrap_or_else(|err| panic!("built-in pattern for {kind} is invalid: {err}"));
        assert!(
            group < regex.captures_len(),
            "built-in pattern for {kind} has no capture group {group}"
        );
        Rule {
            kind,
            regex,
            group,
            validate,
            default_on,
        }
    }

    vec![
        // ---------------------------------------------------------------
        // Private key material. Matched first and never restored.
        // ---------------------------------------------------------------
        rule(
            EntityKind::SshPrivateKey,
            r"(?s)-----BEGIN OPENSSH PRIVATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::PrivateKeyBlock,
            r"(?s)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----",
            0,
            None,
            true,
        ),
        // ---------------------------------------------------------------
        // Vendor credentials. High confidence: the prefixes are unambiguous.
        // ---------------------------------------------------------------
        rule(
            EntityKind::AwsAccessKeyId,
            r"\b(?:AKIA|ASIA|ABIA|ACCA|AIDA|AGPA|AROA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::AwsSecretAccessKey,
            r#"(?i)aws_?secret_?access_?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})"#,
            1,
            None,
            true,
        ),
        rule(
            EntityKind::GithubToken,
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::GitlabToken,
            r"\bglpat-[A-Za-z0-9_\-]{20,}\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::SlackToken,
            r"\bxox[abprse]-[A-Za-z0-9\-]{10,}\b|https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::StripeKey,
            r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::AnthropicKey,
            r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::OpenAiKey,
            r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::GoogleApiKey,
            r"\bAIza[0-9A-Za-z_\-]{35}\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::SendgridKey,
            r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::TwilioKey,
            r"\b(?:SK|AC)[0-9a-fA-F]{32}\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::NpmToken,
            r"\bnpm_[A-Za-z0-9]{36}\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::JwtToken,
            r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
            0,
            None,
            true,
        ),
        // ---------------------------------------------------------------
        // Connection strings, which leak a host and a password together.
        // ---------------------------------------------------------------
        rule(
            EntityKind::DatabaseUrl,
            r#"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqps?|mssql|clickhouse)://[^\s"'<>]+"#,
            0,
            None,
            true,
        ),
        rule(
            EntityKind::BasicAuth,
            r"(?i)\bbasic\s+([A-Za-z0-9+/]{16,}={0,2})",
            1,
            Some(is_real_secret),
            true,
        ),
        rule(
            EntityKind::BearerToken,
            r"(?i)\bbearer\s+([A-Za-z0-9._\-+/]{16,}={0,2})",
            1,
            Some(is_real_secret),
            true,
        ),
        // ---------------------------------------------------------------
        // Keyword-gated generics. Deliberately last among credentials.
        // ---------------------------------------------------------------
        rule(
            EntityKind::GenericApiKey,
            r#"(?i)\b(?:api[_\-]?key|apikey|api[_\-]?token|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|refresh[_\-]?token)\b["']?\s*[:=]>?\s*["']?([A-Za-z0-9._\-+/]{12,}={0,2})"#,
            1,
            Some(is_real_key),
            true,
        ),
        rule(
            EntityKind::GenericSecret,
            r#"(?i)\b(?:secret|credential|private[_\-]?key|session[_\-]?key|signing[_\-]?key)s?\b["']?\s*[:=]>?\s*["']?([^\s"'`,;]{8,})"#,
            1,
            Some(is_real_secret),
            true,
        ),
        rule(
            EntityKind::PasswordAssignment,
            r#"(?i)(?:password|passwd|pwd|passphrase)\b["']?\s*[:=]>?\s*["']?([^\s"'`,;]{6,})"#,
            1,
            Some(is_real_secret),
            true,
        ),
        // ---------------------------------------------------------------
        // Financial.
        // ---------------------------------------------------------------
        rule(
            EntityKind::CreditCard,
            r"\b\d(?:[ \-]?\d){11,18}\b",
            0,
            Some(is_valid_card),
            true,
        ),
        rule(
            EntityKind::Iban,
            r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b",
            0,
            Some(is_valid_iban),
            true,
        ),
        rule(
            EntityKind::BankRouting,
            r"(?i)\b(?:routing|aba|transit)(?:[ _\-]?number)?\b\s*[:=]?\s*(\d{9})\b",
            1,
            Some(is_valid_routing),
            true,
        ),
        rule(
            EntityKind::SwiftBic,
            r"(?i)\b(?:swift|bic)(?:[ _\-]?code)?\b\s*[:=]?\s*([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b",
            1,
            None,
            true,
        ),
        rule(
            EntityKind::CryptoAddress,
            r"\bbc1[ac-hj-np-z02-9]{11,71}\b|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b",
            0,
            None,
            true,
        ),
        // ---------------------------------------------------------------
        // People.
        // ---------------------------------------------------------------
        rule(
            EntityKind::EmailAddress,
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,24}\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::PhoneNumber,
            r"(?:\+\d{1,3}[ .\-]?)?(?:\(\d{2,4}\)[ .\-]?|\d{2,4}[ .\-])\d{2,4}[ .\-]?\d{2,4}(?:[ .\-]?\d{2,4})?",
            0,
            Some(is_dialable),
            true,
        ),
        rule(
            EntityKind::NationalId,
            r"\b\d{3}-\d{2}-\d{4}\b",
            0,
            Some(is_issuable_ssn),
            true,
        ),
        // Two separate rules rather than one alternation: each branch needs its
        // own capture group, and the honorific or the `name:` label has to stay
        // in the scrubbed text for the sentence to still read.
        rule(
            EntityKind::PersonName,
            r"\b(?:Mr|Mrs|Ms|Mx|Dr|Prof)\.?\s+([A-Z][a-z'\-]{1,20}(?:\s+[A-Z][a-z'\-]{1,20}){0,2})",
            1,
            None,
            true,
        ),
        rule(
            EntityKind::PersonName,
            r"(?i)\b(?:full[ _\-]?name|first[ _\-]?name|last[ _\-]?name|name)\s*[:=]\s*([A-Z][a-z'\-]{1,20}(?:\s+[A-Z][a-z'\-]{1,20}){0,2})",
            1,
            None,
            true,
        ),
        rule(
            EntityKind::StreetAddress,
            r"\b\d{1,6}[A-Za-z]?\s+(?:[A-Z][A-Za-z'\-]{1,15}\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir|Way|Terrace|Ter|Place|Pl|Parkway|Pkwy|Highway|Hwy)\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::DateOfBirth,
            r"(?i)\b(?:date[ _\-]?of[ _\-]?birth|d\.?o\.?b\.?|birth[ _\-]?date|born(?:\s+on)?)\b\s*[:=]?\s*(\d{1,4}[/\-.]\d{1,2}[/\-.]\d{1,4}|[A-Z][a-z]{2,8}\s+\d{1,2},?\s+\d{4})",
            1,
            None,
            true,
        ),
        rule(
            EntityKind::PassportNumber,
            r"(?i)\bpassport(?:[ _\-]?(?:no|number|#))?\b\s*[:=]?\s*([A-Z0-9]{6,9})\b",
            1,
            None,
            true,
        ),
        rule(
            EntityKind::DriversLicense,
            r"(?i)\b(?:driver'?s?[ _\-]?licen[cs]e|dl)(?:[ _\-]?(?:no|number|#))?\b\s*[:=]?\s*([A-Z0-9]{5,20})\b",
            1,
            None,
            true,
        ),
        // ---------------------------------------------------------------
        // Infrastructure.
        // ---------------------------------------------------------------
        rule(
            EntityKind::S3Uri,
            r#"\bs3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9](?:/[^\s"'<>]*)?"#,
            0,
            None,
            true,
        ),
        rule(
            EntityKind::Url,
            r#"\bhttps?://[^\s"'<>`\]\)]+"#,
            0,
            None,
            false,
        ),
        rule(
            EntityKind::IpV4,
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            0,
            Some(is_maskable_ipv4),
            true,
        ),
        rule(
            EntityKind::IpV6,
            r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::MacAddress,
            r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::Uuid,
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
            0,
            None,
            false,
        ),
        rule(
            EntityKind::Hostname,
            r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:internal|local|lan|corp|intranet|vpc)\b",
            0,
            None,
            true,
        ),
        // ---------------------------------------------------------------
        // Last resort: a high-entropy blob with no keyword at all.
        // Off by default; `--aggressive` turns it on.
        // ---------------------------------------------------------------
        rule(
            EntityKind::HighEntropyString,
            r"\b[A-Za-z0-9+/]{32,}={0,2}\b",
            0,
            Some(is_random_enough),
            false,
        ),
    ]
}

/// The built-in rule table, compiled on first use.
pub static RULES: std::sync::LazyLock<Vec<Rule>> = std::sync::LazyLock::new(build);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    /// Find the first rule for a kind that matches, and return the captured span.
    fn capture(kind: &EntityKind, haystack: &str) -> Option<String> {
        RULES
            .iter()
            .filter(|rule| &rule.kind == kind)
            .find_map(|rule| {
                let captures = rule.regex.captures(haystack)?;
                let matched = captures.get(rule.group).or_else(|| captures.get(0))?;
                let text = matched.as_str();
                match rule.validate {
                    Some(check) if !check(text) => None,
                    _ => Some(text.to_owned()),
                }
            })
    }

    #[test]
    fn rule_table_compiles() {
        assert!(RULES.len() > 30);
    }

    #[test]
    fn vendor_keys_are_recognised() {
        assert_eq!(
            capture(
                &EntityKind::AwsAccessKeyId,
                &format!("key {} here", fixtures::AWS_ACCESS_KEY_ID)
            )
            .as_deref(),
            Some(fixtures::AWS_ACCESS_KEY_ID)
        );
        assert!(capture(&EntityKind::GithubToken, &fixtures::github_token()).is_some());
        assert!(capture(&EntityKind::StripeKey, &fixtures::stripe_live_key()).is_some());
        assert!(capture(&EntityKind::GoogleApiKey, &fixtures::google_api_key()).is_some());
    }

    #[test]
    fn keyword_gated_rules_capture_only_the_value() {
        assert_eq!(
            capture(
                &EntityKind::PasswordAssignment,
                r#"password = "hunter2swordfish""#
            )
            .as_deref(),
            Some("hunter2swordfish")
        );
        assert_eq!(
            capture(&EntityKind::GenericApiKey, "api_key: 8fj2Kd93ldMzQ01x").as_deref(),
            Some("8fj2Kd93ldMzQ01x")
        );
    }

    #[test]
    fn placeholders_are_left_alone() {
        assert!(
            capture(
                &EntityKind::PasswordAssignment,
                "password = <your-password>"
            )
            .is_none()
        );
        assert!(capture(&EntityKind::GenericApiKey, "api_key = YOUR_API_KEY_HERE").is_none());
        assert!(capture(&EntityKind::PasswordAssignment, "password: ********").is_none());
    }

    #[test]
    fn source_code_is_not_mistaken_for_a_secret() {
        // Every one of these is a real line from this repository that an
        // earlier version of the rules reported as a leaked credential.
        for line in [
            r#""secret": kind.is_secret(),"#,
            r#""secret": isSecret,"#,
            r"password: userPassword,",
            r"let secrets = findings.iter().filter(|f| f.kind.is_secret()).count();",
            r#"Self::Credential => "credential","#,
            r#""secrets" => Ok(Self::secrets_only()),"#,
            r"password: self.config.password.clone(),",
        ] {
            for kind in [
                EntityKind::GenericSecret,
                EntityKind::GenericApiKey,
                EntityKind::PasswordAssignment,
            ] {
                assert!(
                    capture(&kind, line).is_none(),
                    "{kind} fired on source code: {line}"
                );
            }
        }
    }

    #[test]
    fn real_assignments_are_still_caught() {
        assert!(
            capture(
                &EntityKind::PasswordAssignment,
                r#"password = "hunter2swordfish""#
            )
            .is_some()
        );
        // `client_secret` has no word boundary before `secret`, so it is the
        // API-key rule that owns it, not the generic-secret rule.
        assert!(
            capture(
                &EntityKind::GenericApiKey,
                "client_secret: aG7xQ92mZk1pLw83"
            )
            .is_some()
        );
        assert!(capture(&EntityKind::GenericSecret, "secret = aG7xQ92mZk1pLw83").is_some());
        assert!(
            capture(
                &EntityKind::PasswordAssignment,
                "PGPASSWORD=tr0ub4dor-and-3"
            )
            .is_some()
        );
    }

    #[test]
    fn card_numbers_need_a_valid_check_digit() {
        assert!(
            capture(
                &EntityKind::CreditCard,
                &format!("card {}", fixtures::TEST_CARD_SPACED)
            )
            .is_some()
        );
        assert!(capture(&EntityKind::CreditCard, "order 1234 5678 9012 3456").is_none());
    }

    #[test]
    fn loopback_addresses_are_not_masked() {
        assert!(capture(&EntityKind::IpV4, "bind 127.0.0.1").is_none());
        assert!(capture(&EntityKind::IpV4, "peer 203.0.113.7").is_some());
    }

    #[test]
    fn ssn_area_rules_are_enforced() {
        assert!(capture(&EntityKind::NationalId, "ssn 123-45-6789").is_some());
        assert!(capture(&EntityKind::NationalId, "ssn 000-45-6789").is_none());
        assert!(capture(&EntityKind::NationalId, "ssn 900-45-6789").is_none());
        assert!(capture(&EntityKind::NationalId, "ssn 123-00-6789").is_none());
    }

    #[test]
    fn private_key_blocks_match_across_lines() {
        let block = fixtures::private_key_block();
        assert_eq!(
            capture(&EntityKind::PrivateKeyBlock, &block).as_deref(),
            Some(block.as_str())
        );
    }
}

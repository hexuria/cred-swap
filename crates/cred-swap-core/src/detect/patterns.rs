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

fn is_valid_sin(value: &str) -> bool {
    validate::canadian_sin(value)
}

fn is_valid_cpf(value: &str) -> bool {
    validate::cpf(value)
}

fn is_valid_abn(value: &str) -> bool {
    validate::abn(value)
}

fn is_valid_nric(value: &str) -> bool {
    validate::nric(value)
}

fn is_valid_aadhaar(value: &str) -> bool {
    let digits = value.bytes().filter(u8::is_ascii_digit).count();
    digits == 12 && validate::verhoeff(value)
}

/// Prefix pairs the National Insurance office never issues.
const NINO_NEVER_ISSUED: &[&[u8; 2]] = &[b"BG", b"GB", b"NK", b"KN", b"TN", b"NT", b"ZZ"];

/// A UK National Insurance number the office would actually issue.
///
/// The prefix rules are what make this precise: several letter pairs are
/// administrative and never issued, and without excluding them the pattern
/// matches ordinary six-digit references with letters either side.
fn is_issuable_nino(value: &str) -> bool {
    let compact: Vec<u8> = value
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if compact.len() != 9 {
        return false;
    }
    NINO_NEVER_ISSUED
        .iter()
        .all(|pair| pair.as_slice() != &compact[..2])
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
            EntityKind::AwsSecretAccessKey,
            r#"(?i)aws_?session_?token\s*[:=]\s*["']?([A-Za-z0-9/+=]{100,})"#,
            1,
            None,
            true,
        ),
        rule(
            // The id on its own is twelve bare digits, which is a quantity as
            // often as it is an account, so it needs the word beside it.
            EntityKind::AwsAccessKeyId,
            r"(?i)\baws[ _\-]?account(?:[ _\-]?id)?\b\s*[:=#]?\s*(\d{12})\b",
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
        // The long tail of vendor tokens. Each prefix is unambiguous, so
        // these need no keyword and no entropy check.
        // ---------------------------------------------------------------
        rule(
            EntityKind::VendorApiToken,
            concat!(
                // Model providers.
                r"\bgsk_[A-Za-z0-9]{40,}\b",
                r"|\bfw_[A-Za-z0-9]{24,}\b",
                r"|\bhf_[A-Za-z0-9]{30,}\b",
                r"|\br8_[A-Za-z0-9]{35,}\b",
                r"|\bpplx-[A-Za-z0-9]{30,}\b",
                r"|\bxai-[A-Za-z0-9]{70,}\b",
                r"|\bnvapi-[A-Za-z0-9_\-]{60,}\b",
                r"|\bsk-or-v1-[a-f0-9]{60,}\b",
            ),
            0,
            None,
            true,
        ),
        rule(
            EntityKind::VendorApiToken,
            concat!(
                // Cloud and infrastructure.
                r"\bdo[oprt]_v1_[a-f0-9]{60,}\b",
                r"|\bdapi[a-f0-9]{32}\b",
                r"|\bsbp_[a-f0-9]{40}\b",
                r"|\bdckr_pat_[A-Za-z0-9_\-]{25,}\b",
                r"|\bglsa_[A-Za-z0-9]{32}_[a-f0-9]{8}\b",
                r"|\bdp\.pt\.[A-Za-z0-9]{40,}\b",
                r"|\b[a-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}\b",
            ),
            0,
            None,
            true,
        ),
        rule(
            EntityKind::VendorApiToken,
            concat!(
                // Commerce and payments.
                r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b",
                r"|\bsq0(?:atp|csp)-[A-Za-z0-9_\-]{20,}\b",
                r"|\bkey-[a-f0-9]{32}\b",
                r"|\b[a-f0-9]{32}-us\d{1,2}\b",
            ),
            0,
            None,
            true,
        ),
        rule(
            EntityKind::VendorApiToken,
            concat!(
                // Developer tools and observability.
                r"\bsntrys_[A-Za-z0-9_=+/]{40,}\b",
                r"|\bNRAK-[A-Z0-9]{25,}\b",
                r"|\blin_api_[A-Za-z0-9]{35,}\b",
                r"|\bntn_[A-Za-z0-9]{35,}\b",
                r"|\bfigd_[A-Za-z0-9_\-]{35,}\b",
                r"|\bATATT3[A-Za-z0-9_\-=]{100,}\b",
                r"|\brubygems_[a-f0-9]{48}\b",
                r"|\bcio[A-Za-z0-9]{32}\b",
                r"|\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b",
                r"|\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b",
            ),
            0,
            None,
            true,
        ),
        rule(
            EntityKind::VendorApiToken,
            concat!(
                // Google's own two shapes, and the chat platforms.
                r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b",
                r"|\b\d{10,}-[a-z0-9]{32}\.apps\.googleusercontent\.com\b",
                r"|\b[MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b",
                r"|\b\d{8,10}:AA[A-Za-z0-9_\-]{32,}\b",
            ),
            0,
            None,
            true,
        ),
        // ---------------------------------------------------------------
        // Taxpayer and national identifiers.
        // ---------------------------------------------------------------
        rule(
            // Philippine TIN, which carries a branch code: 000-000-000-00000.
            EntityKind::TaxId,
            r"\b\d{3}-\d{3}-\d{3}-\d{3,5}\b",
            0,
            None,
            true,
        ),
        rule(
            // The bare nine-digit form is also a Canadian SIN and half a phone
            // number, so it needs the word next to it.
            EntityKind::TaxId,
            r"(?i)\b(?:tin|t\.i\.n\.|tax[ _\-]?(?:id|identification)(?:[ _\-]?(?:no|number|#))?)\b\s*[:#=]?\s*(\d{3}-?\d{3}-?\d{3}(?:-?\d{3,5})?)\b",
            1,
            None,
            true,
        ),
        rule(
            // A US ITIN: always 9xx, with the group in the ranges the IRS uses.
            EntityKind::TaxId,
            r"\b9\d{2}-(?:5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])-\d{4}\b",
            0,
            None,
            true,
        ),
        rule(
            EntityKind::TaxId,
            r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b",
            0,
            Some(is_valid_cpf),
            true,
        ),
        rule(
            EntityKind::TaxId,
            r"(?i)\b(?:abn|australian business number)\b\s*[:#=]?\s*(\d{2}\s?\d{3}\s?\d{3}\s?\d{3})\b",
            1,
            Some(is_valid_abn),
            true,
        ),
        rule(
            EntityKind::TaxId,
            r"(?i)\b(?:pan|permanent account number)\b\s*[:#=]?\s*([A-Z]{5}\d{4}[A-Z])\b",
            1,
            None,
            true,
        ),
        rule(
            EntityKind::TaxId,
            r"(?i)\bvat(?:[ _\-]?(?:no|number|id|reg))?\b\s*[:#=]?\s*((?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|GB|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[A-Z0-9]{8,12})\b",
            1,
            None,
            true,
        ),
        rule(
            EntityKind::NationalId,
            r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
            0,
            Some(is_issuable_nino),
            true,
        ),
        rule(
            EntityKind::NationalId,
            r"\b[STFG]\d{7}[A-Z]\b",
            0,
            Some(is_valid_nric),
            true,
        ),
        rule(
            EntityKind::NationalId,
            r"(?i)\b(?:sin|social insurance(?:[ _\-]?number)?)\b\s*[:#=]?\s*(\d{3}[- ]?\d{3}[- ]?\d{3})\b",
            1,
            Some(is_valid_sin),
            true,
        ),
        rule(
            EntityKind::NationalId,
            r"(?i)\b(?:aadhaar|aadhar|uidai)\b\s*[:#=]?\s*(\d{4}\s?\d{4}\s?\d{4})\b",
            1,
            Some(is_valid_aadhaar),
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

    /// Build a token from parts, so no credential-shaped literal sits in the
    /// source. See `crate::fixtures` for why.
    fn tok(prefix: &str, body: &str, times: usize) -> String {
        format!("{prefix}{}", body.repeat(times))
    }

    #[test]
    fn vendor_tokens_are_recognised_by_their_prefix() {
        let cases: Vec<(String, &str)> = vec![
            (tok(concat!("gsk", "_"), "a", 52), "Groq"),
            (tok(concat!("hf", "_"), "b", 34), "Hugging Face"),
            (tok(concat!("r8", "_"), "c", 37), "Replicate"),
            (tok(concat!("pplx", "-"), "d", 32), "Perplexity"),
            (tok(concat!("xai", "-"), "e", 80), "xAI"),
            (tok(concat!("sk-or-", "v1-"), "f", 64), "OpenRouter"),
            (tok(concat!("dop", "_v1_"), "0", 64), "DigitalOcean"),
            (tok("dapi", "a", 32), "Databricks"),
            (tok(concat!("sbp", "_"), "1", 40), "Supabase"),
            (tok(concat!("shpat", "_"), "9", 32), "Shopify"),
            (tok(concat!("sntrys", "_"), "g", 50), "Sentry"),
            (tok(concat!("NRAK", "-"), "H", 27), "New Relic"),
            (tok(concat!("lin_api", "_"), "h", 40), "Linear"),
            (tok(concat!("ntn", "_"), "i", 40), "Notion"),
            (tok(concat!("figd", "_"), "j", 40), "Figma"),
            (tok(concat!("dckr_pat", "_"), "k", 30), "Docker Hub"),
            (tok(concat!("rubygems", "_"), "2", 48), "RubyGems"),
            (tok("cio", "l", 32), "crates.io"),
            (tok(concat!("GOCSPX", "-"), "m", 28), "Google OAuth"),
            (tok(concat!("dp.pt", "."), "n", 44), "Doppler"),
        ];

        for (value, vendor) in cases {
            assert!(
                capture(&EntityKind::VendorApiToken, &value).is_some(),
                "{vendor} token was not recognised"
            );
        }
    }

    /// Every rule the whole table would apply, the way a real scrub does.
    ///
    /// The per-kind `capture` helper asks one rule in isolation, so it cannot
    /// see two rules claiming the same span. That is how an `OpenRouter` token
    /// came to be reported as an `OpenAI` key: both matched, both at the same
    /// precedence, and declaration order quietly decided.
    fn scanned(text: &str) -> Vec<EntityKind> {
        use crate::detect::Detector;
        use crate::policy::Policy;

        Detector::new(Policy::aggressive())
            .expect("the aggressive policy compiles")
            .scan(text)
            .into_iter()
            .map(|finding| finding.kind)
            .collect()
    }

    #[test]
    fn a_prefixed_vendor_token_is_not_claimed_by_a_broader_rule() {
        // `sk-or-v1-...` is also a valid `sk-...`, so the generic OpenAI rule
        // matches the identical span. The more specific rule has to win.
        let openrouter = tok(concat!("sk-or-", "v1-"), "a", 64);
        assert_eq!(
            scanned(&openrouter),
            vec![EntityKind::VendorApiToken],
            "a vendor token was claimed by a broader rule"
        );

        // And the two neighbours it sits between still resolve correctly.
        assert_eq!(
            scanned(&fixtures::anthropic_key()),
            vec![EntityKind::AnthropicKey]
        );
        assert_eq!(
            scanned(&fixtures::openai_key()),
            vec![EntityKind::OpenAiKey]
        );
    }

    #[test]
    fn aws_has_the_shapes_beyond_the_access_key() {
        assert!(
            capture(
                &EntityKind::AwsSecretAccessKey,
                &format!("aws_session_token = {}", "A".repeat(120))
            )
            .is_some()
        );
        assert_eq!(
            capture(&EntityKind::AwsAccessKeyId, "aws_account_id: 123456789012").as_deref(),
            Some("123456789012")
        );
        // Twelve bare digits are a quantity far more often than an account.
        assert!(
            capture(
                &EntityKind::AwsAccessKeyId,
                "we processed 123456789012 rows"
            )
            .is_none()
        );
    }

    #[test]
    fn the_remaining_vendor_prefixes_are_recognised() {
        let cases: Vec<(String, &str)> = vec![
            (tok(concat!("key", "-"), "a", 32), "Mailgun"),
            (format!("{}-us12", "b".repeat(32)), "Mailchimp"),
            (tok(concat!("sq0atp", "-"), "c", 22), "Square"),
            (tok(concat!("glsa", "_"), "d", 32) + "_abcdef01", "Grafana"),
            (
                format!("{}.atlasv1.{}", "e".repeat(14), "f".repeat(64)),
                "Terraform Cloud",
            ),
            (tok(concat!("ATATT", "3"), "g", 120), "Atlassian"),
            (tok(concat!("pypi-AgEIcHlwaS5", "vcmc"), "h", 60), "PyPI"),
            (
                format!("pat{}.{}", "i".repeat(14), "0".repeat(64)),
                "Airtable",
            ),
            (
                format!(
                    "{}.{}.{}",
                    "M".to_string() + &"j".repeat(24),
                    "k".repeat(6),
                    "l".repeat(30)
                ),
                "Discord",
            ),
            (format!("123456789:AA{}", "m".repeat(33)), "Telegram"),
            (
                format!(
                    "{}-{}.apps.googleusercontent.com",
                    "1".repeat(12),
                    "n".repeat(32)
                ),
                "Google OAuth client",
            ),
            (tok(concat!("nvapi", "-"), "o", 64), "NVIDIA"),
            (tok(concat!("fw", "_"), "p", 26), "Fireworks"),
        ];
        for (value, vendor) in cases {
            assert!(
                capture(&EntityKind::VendorApiToken, &value).is_some(),
                "{vendor} token was not recognised: {value}"
            );
        }
    }

    #[test]
    fn a_bare_hash_is_not_mistaken_for_a_vendor_token() {
        // The riskiest new shapes are bare hex. A commit SHA, an md5 and a
        // content hash all live in ordinary logs and must not fire.
        for line in [
            "commit 0e5c3b1a9f4d2e8c7b6a5f4e3d2c1b0a9f8e7d6c",
            "md5 d41d8cd98f00b204e9800998ecf8427e",
            "integrity sha256-47DEQpj8HBSaTImW1jbXbdcB9wLpvhxaEr5r",
            "the cache key is stale",
        ] {
            assert!(
                capture(&EntityKind::VendorApiToken, line).is_none(),
                "fired on: {line}"
            );
        }
    }

    #[test]
    fn an_aadhaar_with_a_valid_checksum_is_caught() {
        // 2345 6789 0123 fails Verhoeff, so an earlier negative-only test
        // passed for a reason that had nothing to do with the keyword gate.
        assert_eq!(
            capture(&EntityKind::NationalId, "aadhaar 2994 1234 5678").as_deref(),
            Some("2994 1234 5678")
        );
        // A wrong check digit is refused.
        assert!(capture(&EntityKind::NationalId, "aadhaar 2994 1234 5679").is_none());
        // And the keyword really is required.
        assert!(capture(&EntityKind::NationalId, "batch 2994 1234 5678 shipped").is_none());
    }

    #[test]
    fn an_itin_covers_every_group_the_irs_issues() {
        for group in ["50", "65", "70", "88", "90", "92", "94", "99"] {
            let value = format!("912-{group}-1234");
            assert!(
                capture(&EntityKind::TaxId, &value).is_some(),
                "{value} is an issued ITIN group"
            );
        }
        for group in ["49", "66", "89", "93"] {
            let value = format!("912-{group}-1234");
            assert!(
                capture(&EntityKind::TaxId, &value).is_none(),
                "{value} is not an issued ITIN group"
            );
        }
    }

    #[test]
    fn ordinary_words_are_not_vendor_tokens() {
        for line in [
            "let key = compute_key(input);",
            "the patch is ready for review",
            "cio is the crates.io registry",
            "dapi returns a handle",
            "https://example.com/path/to/a/page",
        ] {
            assert!(
                capture(&EntityKind::VendorApiToken, line).is_none(),
                "fired on: {line}"
            );
        }
    }

    #[test]
    fn a_philippine_tin_is_recognised_with_and_without_its_branch_code() {
        assert_eq!(
            capture(&EntityKind::TaxId, "TIN 123-456-789-00001").as_deref(),
            Some("123-456-789-00001")
        );
        assert_eq!(
            capture(&EntityKind::TaxId, "tax id: 123-456-789").as_deref(),
            Some("123-456-789")
        );
        // The bare nine-digit form needs the word, or it matches half the
        // reference numbers in any document.
        assert!(capture(&EntityKind::TaxId, "order 123-456-789 shipped").is_none());
    }

    #[test]
    fn an_itin_is_told_apart_from_a_social_security_number() {
        // 9xx is never an SSN and always an ITIN.
        assert!(capture(&EntityKind::TaxId, "itin 912-78-1234").is_some());
        assert!(capture(&EntityKind::NationalId, "ssn 912-78-1234").is_none());
        // And the reverse.
        assert!(capture(&EntityKind::NationalId, "ssn 123-45-6789").is_some());
        assert!(capture(&EntityKind::TaxId, "123-45-6789").is_none());
    }

    #[test]
    fn checksummed_identifiers_need_their_checksum() {
        assert!(capture(&EntityKind::TaxId, "cpf 529.982.247-25").is_some());
        assert!(capture(&EntityKind::TaxId, "cpf 529.982.247-26").is_none());

        assert!(capture(&EntityKind::TaxId, "ABN 51 824 753 556").is_some());
        assert!(capture(&EntityKind::TaxId, "ABN 51 824 753 557").is_none());

        assert!(capture(&EntityKind::NationalId, "NRIC S1234567D").is_some());
        assert!(capture(&EntityKind::NationalId, "NRIC S1234567A").is_none());

        assert!(capture(&EntityKind::NationalId, "SIN: 046 454 286").is_some());
        assert!(capture(&EntityKind::NationalId, "SIN: 046 454 287").is_none());
    }

    #[test]
    fn a_nino_excludes_the_prefixes_that_are_never_issued() {
        // D, F, I, Q, U and V are never used as prefix letters, so the pattern
        // excludes them; AB is an ordinary issued prefix.
        assert!(capture(&EntityKind::NationalId, "NI AB 12 34 56 C").is_some());
        assert!(capture(&EntityKind::NationalId, "QQ 12 34 56 C").is_none());
        for never in ["BG123456C", "GB123456C", "NK123456C", "ZZ123456C"] {
            assert!(
                capture(&EntityKind::NationalId, never).is_none(),
                "{never} is not issued"
            );
        }
    }

    #[test]
    fn keyword_gated_identifiers_need_their_keyword() {
        assert!(capture(&EntityKind::TaxId, "PAN ABCDE1234F").is_some());
        assert!(capture(&EntityKind::TaxId, "ABCDE1234F").is_none());

        assert!(capture(&EntityKind::TaxId, "VAT no GB123456789").is_some());
        assert!(capture(&EntityKind::TaxId, "GB123456789").is_none());

        // Aadhaar's own gate is covered by `an_aadhaar_with_a_valid_checksum_is_caught`.
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

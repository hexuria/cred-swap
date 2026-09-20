//! The taxonomy of things `cred-swap` knows how to recognise and replace.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Broad grouping used for policy decisions and reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// Personally identifiable information about a human being.
    Pii,
    /// Financial instruments and account identifiers.
    Financial,
    /// Machine or network identifiers.
    Infrastructure,
    /// Secrets that grant access to a system.
    Credential,
}

impl Category {
    /// The stable kebab-case identifier for this category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pii => "pii",
            Self::Financial => "financial",
            Self::Infrastructure => "infrastructure",
            Self::Credential => "credential",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A kind of sensitive value.
///
/// Variants are stable identifiers: they are used as vault keys and appear in
/// the JSON session file, so renaming one is a breaking change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntityKind {
    // --- people ---
    /// A human name, found after an honorific or a `name:` label.
    PersonName,
    /// An email address.
    EmailAddress,
    /// A phone number with enough digits to be dialable.
    PhoneNumber,
    /// A street address line, number through street suffix.
    StreetAddress,
    /// A date labelled as someone's date of birth.
    DateOfBirth,
    /// A national identity number: US SSN, UK NINO, Canadian SIN,
    /// Singapore NRIC or FIN, Indian Aadhaar.
    NationalId,
    /// A taxpayer identifier: Philippine TIN, US ITIN, Indian PAN,
    /// Brazilian CPF, Australian ABN, EU VAT number.
    TaxId,
    /// A passport number, found after a `passport` label.
    PassportNumber,
    /// A driving licence number, found after a licence label.
    DriversLicense,

    // --- financial ---
    /// A payment card number that passes the Luhn check.
    CreditCard,
    /// An international bank account number that passes the mod-97 check.
    Iban,
    /// A US ABA routing number that passes its weighted checksum.
    BankRouting,
    /// A SWIFT or BIC bank identifier, found after a label.
    SwiftBic,
    /// A Bitcoin or Ethereum address.
    CryptoAddress,

    // --- infrastructure ---
    /// An IPv4 address outside the loopback and link-local ranges.
    IpV4,
    /// An IPv6 address.
    IpV6,
    /// A hardware MAC address.
    MacAddress,
    /// A host under a private suffix such as `.internal` or `.corp`.
    Hostname,
    /// An HTTP or HTTPS URL. Off by default: too common in ordinary text.
    Url,
    /// A version 1-8 UUID. Off by default: usually not sensitive.
    Uuid,
    /// An `s3://` bucket URI.
    S3Uri,
    /// A database connection string. Classed as a credential, not as
    /// infrastructure, because it usually carries a password inside it.
    DatabaseUrl,

    // --- credentials ---
    /// An AWS access key id, such as one beginning `AKIA`.
    AwsAccessKeyId,
    /// An AWS secret access key, found after its usual variable name.
    AwsSecretAccessKey,
    /// A GitHub personal access, OAuth, or app token.
    GithubToken,
    /// A GitLab personal access token.
    GitlabToken,
    /// A Slack API token or incoming webhook URL.
    SlackToken,
    /// A Stripe secret, publishable, or restricted key.
    StripeKey,
    /// An `OpenAI` API key.
    OpenAiKey,
    /// An Anthropic API key.
    AnthropicKey,
    /// A Google API key.
    GoogleApiKey,
    /// A `SendGrid` API key.
    SendgridKey,
    /// A Twilio account SID or API key SID.
    TwilioKey,
    /// An npm access token.
    NpmToken,
    /// A JSON Web Token.
    JwtToken,
    /// A PEM-armoured private key of any type.
    PrivateKeyBlock,
    /// An OpenSSH-format private key.
    SshPrivateKey,
    /// The credential part of an HTTP `Authorization: Bearer` header.
    BearerToken,
    /// The credential part of an HTTP `Authorization: Basic` header.
    BasicAuth,
    /// A value assigned to something named like an API key.
    GenericApiKey,
    /// A value assigned to something named like a secret.
    GenericSecret,
    /// A value assigned to something named like a password.
    PasswordAssignment,
    /// A token from a service whose prefix names it: `gsk_`, `shpat_`,
    /// `dop_v1_` and the rest of the long tail.
    ///
    /// One kind rather than forty, because the useful part is the same for all
    /// of them: the prefix says what it is, and the stand-in keeps it.
    VendorApiToken,
    /// A long random-looking string with nothing nearby to say what it is.
    ///
    /// Off in every preset but `aggressive`: in source code this fires on
    /// checksums, encoded assets and alphabet constants. It is a separate kind
    /// from [`EntityKind::GenericSecret`] precisely so that enabling
    /// keyword-gated secrets does not drag the entropy sweep along with it.
    HighEntropyString,

    /// A user-defined rule from the config file.
    Custom(String),
}

impl EntityKind {
    /// Every built-in kind, in declaration order.
    pub const BUILTIN: &'static [Self] = &[
        Self::PersonName,
        Self::EmailAddress,
        Self::PhoneNumber,
        Self::StreetAddress,
        Self::DateOfBirth,
        Self::NationalId,
        Self::TaxId,
        Self::PassportNumber,
        Self::DriversLicense,
        Self::CreditCard,
        Self::Iban,
        Self::BankRouting,
        Self::SwiftBic,
        Self::CryptoAddress,
        Self::IpV4,
        Self::IpV6,
        Self::MacAddress,
        Self::Hostname,
        Self::Url,
        Self::Uuid,
        Self::S3Uri,
        Self::DatabaseUrl,
        Self::AwsAccessKeyId,
        Self::AwsSecretAccessKey,
        Self::GithubToken,
        Self::GitlabToken,
        Self::SlackToken,
        Self::StripeKey,
        Self::OpenAiKey,
        Self::AnthropicKey,
        Self::GoogleApiKey,
        Self::SendgridKey,
        Self::TwilioKey,
        Self::NpmToken,
        Self::JwtToken,
        Self::PrivateKeyBlock,
        Self::SshPrivateKey,
        Self::BearerToken,
        Self::BasicAuth,
        Self::GenericApiKey,
        Self::GenericSecret,
        Self::PasswordAssignment,
        Self::VendorApiToken,
        Self::HighEntropyString,
    ];

    /// Stable kebab-case identifier, matching the serde representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::PersonName => "person-name",
            Self::EmailAddress => "email-address",
            Self::PhoneNumber => "phone-number",
            Self::StreetAddress => "street-address",
            Self::DateOfBirth => "date-of-birth",
            Self::NationalId => "national-id",
            Self::TaxId => "tax-id",
            Self::PassportNumber => "passport-number",
            Self::DriversLicense => "drivers-license",
            Self::CreditCard => "credit-card",
            Self::Iban => "iban",
            Self::BankRouting => "bank-routing",
            Self::SwiftBic => "swift-bic",
            Self::CryptoAddress => "crypto-address",
            Self::IpV4 => "ip-v4",
            Self::IpV6 => "ip-v6",
            Self::MacAddress => "mac-address",
            Self::Hostname => "hostname",
            Self::Url => "url",
            Self::Uuid => "uuid",
            Self::S3Uri => "s3-uri",
            Self::DatabaseUrl => "database-url",
            Self::AwsAccessKeyId => "aws-access-key-id",
            Self::AwsSecretAccessKey => "aws-secret-access-key",
            Self::GithubToken => "github-token",
            Self::GitlabToken => "gitlab-token",
            Self::SlackToken => "slack-token",
            Self::StripeKey => "stripe-key",
            Self::OpenAiKey => "openai-key",
            Self::AnthropicKey => "anthropic-key",
            Self::GoogleApiKey => "google-api-key",
            Self::SendgridKey => "sendgrid-key",
            Self::TwilioKey => "twilio-key",
            Self::NpmToken => "npm-token",
            Self::JwtToken => "jwt-token",
            Self::PrivateKeyBlock => "private-key-block",
            Self::SshPrivateKey => "ssh-private-key",
            Self::BearerToken => "bearer-token",
            Self::BasicAuth => "basic-auth",
            Self::GenericApiKey => "generic-api-key",
            Self::GenericSecret => "generic-secret",
            Self::PasswordAssignment => "password-assignment",
            Self::VendorApiToken => "vendor-api-token",
            Self::HighEntropyString => "high-entropy-string",
            Self::Custom(label) => label.as_str(),
        }
    }

    /// The name [`FromStr`] accepts, which for a custom kind carries the
    /// `custom:` prefix that tells it apart from a built-in.
    ///
    /// Use this wherever a kind crosses a boundary and has to come back:
    /// JSON, a command line flag, a JavaScript object. [`EntityKind::as_str`]
    /// is for display, and is ambiguous for custom kinds.
    #[must_use]
    pub fn qualified_name(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::Custom(label) => std::borrow::Cow::Owned(format!("custom:{label}")),
            other => std::borrow::Cow::Borrowed(other.as_str()),
        }
    }

    /// Which broad group this kind belongs to.
    #[must_use]
    pub const fn category(&self) -> Category {
        match self {
            Self::PersonName
            | Self::EmailAddress
            | Self::PhoneNumber
            | Self::StreetAddress
            | Self::DateOfBirth
            | Self::NationalId
            | Self::TaxId
            | Self::PassportNumber
            | Self::DriversLicense => Category::Pii,

            Self::CreditCard
            | Self::Iban
            | Self::BankRouting
            | Self::SwiftBic
            | Self::CryptoAddress => Category::Financial,

            Self::IpV4
            | Self::IpV6
            | Self::MacAddress
            | Self::Hostname
            | Self::Url
            | Self::Uuid
            | Self::S3Uri => Category::Infrastructure,

            _ => Category::Credential,
        }
    }

    /// True when leaking this value hands someone else access to a system.
    ///
    /// Callers use this to decide what a human is allowed to wave through. The
    /// CLI refuses to leave a secret in place even when the user unticks it,
    /// because the cost of being wrong is not symmetric with a masked name.
    #[must_use]
    pub const fn is_secret(&self) -> bool {
        matches!(self.category(), Category::Credential)
    }

    /// Tie-break weight when two detectors claim overlapping spans.
    ///
    /// Higher wins. Specific vendor patterns outrank the generic fallbacks so
    /// that, say, `sk-ant-...` is reported as an Anthropic key rather than a
    /// generic secret.
    #[must_use]
    pub const fn precedence(&self) -> u8 {
        match self {
            Self::SshPrivateKey => 105,
            Self::PrivateKeyBlock => 100,
            Self::AnthropicKey => 95,
            Self::AwsAccessKeyId
            | Self::AwsSecretAccessKey
            | Self::GithubToken
            | Self::GitlabToken
            | Self::SlackToken
            | Self::StripeKey
            | Self::OpenAiKey
            | Self::GoogleApiKey
            | Self::SendgridKey
            | Self::TwilioKey
            | Self::NpmToken
            | Self::VendorApiToken => 90,
            Self::JwtToken | Self::DatabaseUrl => 85,
            Self::Custom(_) => 80,
            Self::CreditCard | Self::Iban | Self::NationalId | Self::TaxId => 70,
            // Above `PhoneNumber`: a dotted quad such as 198.51.100.44 has ten
            // digits and dot separators, so it satisfies the phone rule too.
            // The IPv4 rule is the far stricter of the two — four groups of at
            // most three digits, each validated to be in range — so where both
            // match, it is the one that is right.
            Self::IpV4 => 65,
            Self::EmailAddress | Self::PhoneNumber | Self::CryptoAddress => 60,
            Self::S3Uri | Self::Url => 50,
            Self::IpV6 | Self::MacAddress | Self::Uuid => 40,
            Self::BearerToken | Self::BasicAuth | Self::PasswordAssignment => 35,
            Self::GenericApiKey | Self::GenericSecret => 20,
            Self::Hostname => 15,
            // Lowest of all: anything with a label beats a guess from shape.
            Self::HighEntropyString => 10,
            _ => 30,
        }
    }
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returned when a kind name in a config file or CLI flag is not recognised.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown entity kind `{0}`")]
pub struct UnknownEntityKind(pub String);

impl FromStr for EntityKind {
    type Err = UnknownEntityKind;

    /// Accepts kebab-case, `snake_case` or spaced names, and `custom:<label>`
    /// for a rule defined in a config file.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if let Some(label) = trimmed.strip_prefix("custom:") {
            return if label.is_empty() {
                Err(UnknownEntityKind(s.to_owned()))
            } else {
                Ok(Self::Custom(label.to_owned()))
            };
        }
        let normalized = trimmed.to_ascii_lowercase().replace(['_', ' '], "-");
        Self::BUILTIN
            .iter()
            .find(|kind| kind.as_str() == normalized)
            .cloned()
            .ok_or_else(|| UnknownEntityKind(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_list_covers_every_named_variant() {
        // Guards against adding a variant and forgetting to register it.
        let mut names: Vec<&str> = EntityKind::BUILTIN.iter().map(EntityKind::as_str).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate entity kind identifier");
        assert_eq!(before, 44);
    }

    #[test]
    fn from_str_accepts_snake_and_kebab() {
        assert_eq!(
            "aws_access_key_id".parse::<EntityKind>().unwrap(),
            EntityKind::AwsAccessKeyId
        );
        assert_eq!(
            "Email-Address".parse::<EntityKind>().unwrap(),
            EntityKind::EmailAddress
        );
        assert!("not-a-thing".parse::<EntityKind>().is_err());
    }

    #[test]
    fn from_str_understands_custom_labels() {
        assert_eq!(
            "custom:codename".parse::<EntityKind>().unwrap(),
            EntityKind::Custom("codename".into())
        );
        assert!("custom:".parse::<EntityKind>().is_err());
    }

    #[test]
    fn every_qualified_name_parses_back_to_its_kind() {
        for kind in EntityKind::BUILTIN {
            let name = kind.qualified_name();
            assert_eq!(&name.parse::<EntityKind>().unwrap(), kind, "{name}");
        }
        let custom = EntityKind::Custom("codename".into());
        assert_eq!(custom.qualified_name(), "custom:codename");
        assert_eq!(
            custom.qualified_name().parse::<EntityKind>().unwrap(),
            custom
        );
    }

    #[test]
    fn credentials_are_marked_secret() {
        assert!(EntityKind::GithubToken.is_secret());
        assert!(EntityKind::Custom("internal".into()).is_secret());
        // A connection string carries a password, so it is a credential even
        // though it looks like infrastructure.
        assert!(EntityKind::DatabaseUrl.is_secret());
        assert!(!EntityKind::EmailAddress.is_secret());
        assert!(!EntityKind::CreditCard.is_secret());
        assert!(!EntityKind::Url.is_secret());
    }
}

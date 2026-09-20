//! Turning a real value into a stand-in.
//!
//! Two properties matter and they pull against each other. The stand-in has to
//! be *shaped* like the original, or the model answers a different question
//! than the one asked: a masked card number still has to have sixteen digits
//! and a valid check digit for a payments question to make sense. And it has
//! to be *inert*: every generated host sits under a reserved domain, every
//! generated IP sits in a documentation range, every generated phone number
//! sits in the fictional 555-01xx block. Nothing that leaves here can reach a
//! real person or a real machine.

pub mod data;

use hmac::{Hmac, Mac};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::entity::{Category, EntityKind};

type HmacSha256 = Hmac<Sha256>;

/// How a stand-in should look.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Style {
    /// A plausible value of the same shape, such as `avery.sinclair@globex.example`.
    ///
    /// Reads naturally, so the model reasons about it the way it would about
    /// the original. The cost is that a reader skimming the output cannot tell
    /// at a glance which values were substituted.
    #[default]
    Realistic,
    /// An obvious marker, such as `[[EMAIL_ADDRESS_1]]`.
    ///
    /// Unmistakable in a diff and trivially reversible, at the cost of telling
    /// the model that a value was withheld.
    Tagged,
}

/// Generates stand-ins deterministically from a seed.
///
/// The same seed and the same real value always produce the same stand-in,
/// across processes and across runs. That is what lets a long conversation
/// stay coherent: the third mention of a colleague's email gets the same
/// substitute as the first, without the two sides having to share state.
#[derive(Clone)]
pub struct Surrogates {
    seed: [u8; 32],
    style: Style,
}

impl std::fmt::Debug for Surrogates {
    /// Never prints the seed: it is the key that links stand-ins to originals.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Surrogates")
            .field("seed", &"<redacted>")
            .field("style", &self.style)
            .finish()
    }
}

impl Surrogates {
    /// Use a raw 32-byte seed.
    #[must_use]
    pub const fn from_seed(seed: [u8; 32], style: Style) -> Self {
        Self { seed, style }
    }

    /// Derive a seed from arbitrary secret material, such as a passphrase.
    #[must_use]
    pub fn from_secret(secret: &[u8], style: Style) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"cred-swap/surrogate-seed/v1");
        hasher.update(secret);
        Self {
            seed: hasher.finalize().into(),
            style,
        }
    }

    /// Draw a fresh seed from the operating system.
    ///
    /// Requires the `os-rng` feature, which is on by default. A build without
    /// it — a browser build, say — has no OS entropy to draw on and must get
    /// its seed from the host instead, through [`Surrogates::from_seed`] or
    /// [`Surrogates::from_secret`].
    #[cfg(feature = "os-rng")]
    #[must_use]
    pub fn random(style: Style) -> Self {
        let mut seed = [0u8; 32];
        rand::rng().fill(&mut seed);
        Self { seed, style }
    }

    /// The seed, for persisting a session.
    #[must_use]
    pub const fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Derive an independent generator for one conversation or tenant.
    ///
    /// The derived seed is a one-way function of this one and `label`, so the
    /// same label always yields the same generator, and no derived generator
    /// reveals anything about its parent or its siblings.
    ///
    /// This is what keeps two conversations from leaking to each other. A
    /// server that scrubs many conversations against a single generator gives
    /// the same stand-in to the same value everywhere, which means a stand-in
    /// seen in one tenant's transcript identifies that value in another's.
    /// Deriving per conversation removes that link while keeping each
    /// conversation internally consistent.
    ///
    /// # Panics
    ///
    /// Panics if the HMAC rejects the key. The key is always 32 bytes, so it
    /// does not.
    #[must_use]
    pub fn derive(&self, label: &str) -> Self {
        let mut mac = HmacSha256::new_from_slice(&self.seed).expect("HMAC accepts a 32-byte key");
        mac.update(b"cred-swap/derive/v1");
        mac.update(&[0]);
        mac.update(label.as_bytes());
        Self {
            seed: mac.finalize().into_bytes().into(),
            style: self.style,
        }
    }

    /// The configured style.
    #[must_use]
    pub const fn style(&self) -> Style {
        self.style
    }

    /// Produce a stand-in for one real value.
    ///
    /// `ordinal` is the 1-based index of this value among others of the same
    /// kind, used only by [`Style::Tagged`]. `attempt` is bumped by the vault
    /// when a generated value collided with one already in use, which reseeds
    /// the generator rather than looping forever on the same output.
    #[must_use]
    pub fn generate(&self, kind: &EntityKind, real: &str, ordinal: u32, attempt: u32) -> String {
        if self.style == Style::Tagged {
            return tagged(kind, ordinal, attempt);
        }
        let mut rng = self.rng(kind, real, attempt);
        realistic(kind, real, &mut rng)
    }

    /// Derive a per-value generator.
    ///
    /// Keying on the real value is what makes the mapping consistent. Keying
    /// on the seed is what stops anyone who sees only the stand-ins from
    /// recovering the originals by regenerating them.
    fn rng(&self, kind: &EntityKind, real: &str, attempt: u32) -> ChaCha12Rng {
        let mut mac = HmacSha256::new_from_slice(&self.seed).expect("HMAC accepts a 32-byte key");
        mac.update(kind.as_str().as_bytes());
        mac.update(&[0]);
        mac.update(real.as_bytes());
        mac.update(&[0]);
        mac.update(&attempt.to_le_bytes());
        ChaCha12Rng::from_seed(mac.finalize().into_bytes().into())
    }
}

/// `[[EMAIL_ADDRESS_1]]`, with the attempt count appended only on a collision.
fn tagged(kind: &EntityKind, ordinal: u32, attempt: u32) -> String {
    let label = kind.as_str().to_ascii_uppercase().replace('-', "_");
    if attempt == 0 {
        format!("[[{label}_{ordinal}]]")
    } else {
        format!("[[{label}_{ordinal}_{attempt}]]")
    }
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

fn pick<'a>(rng: &mut ChaCha12Rng, options: &[&'a str]) -> &'a str {
    options[rng.random_range(0..options.len())]
}

fn token(rng: &mut ChaCha12Rng, alphabet: &[u8], len: usize) -> String {
    (0..len)
        .map(|_| char::from(alphabet[rng.random_range(0..alphabet.len())]))
        .collect()
}

fn digits(rng: &mut ChaCha12Rng, len: usize) -> String {
    (0..len)
        .map(|_| char::from(b'0' + u8::try_from(rng.random_range(0..10u32)).unwrap_or(0)))
        .collect()
}

/// A reserved domain such as `globex.example`.
fn domain(rng: &mut ChaCha12Rng) -> String {
    format!(
        "{}.{}",
        pick(rng, data::DOMAIN_LABELS),
        pick(rng, data::RESERVED_TLDS)
    )
}

/// Count characters, not bytes, so a multi-byte original keeps its visual size.
fn char_len(value: &str) -> usize {
    value.chars().count()
}

/// The separator the original used between number groups, if any.
fn separator_of(value: &str) -> Option<char> {
    value.chars().find(|c| matches!(*c, '-' | '.' | ' '))
}

// ---------------------------------------------------------------------------
// Format-preserving builders
// ---------------------------------------------------------------------------

/// A card number with the original's length and brand digit, and a real
/// Luhn check digit, so downstream validation still behaves the same way.
fn card_like(real: &str, rng: &mut ChaCha12Rng) -> String {
    let real_digits: Vec<char> = real.chars().filter(char::is_ascii_digit).collect();
    let len = real_digits.len().clamp(13, 19);
    let brand = real_digits.first().copied().unwrap_or('4');

    let mut body = String::with_capacity(len);
    body.push(brand);
    body.push_str(&digits(rng, len - 2));
    body.push(luhn_check_digit(&body));

    // Reproduce the original's grouping so the value still reads as a card.
    match separator_of(real) {
        Some(sep) => body
            .as_bytes()
            .chunks(4)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join(&sep.to_string()),
        None => body,
    }
}

/// The digit that makes `partial` plus one more digit satisfy Luhn.
fn luhn_check_digit(partial: &str) -> char {
    let sum: u32 = partial
        .chars()
        .filter_map(|c| c.to_digit(10))
        .rev()
        .enumerate()
        .map(|(index, digit)| {
            // The appended check digit shifts every position by one, so the
            // doubling parity here is the opposite of a plain Luhn sum.
            if index % 2 == 0 {
                let doubled = digit * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                digit
            }
        })
        .sum();
    let check = (10 - (sum % 10)) % 10;
    char::from_digit(check, 10).unwrap_or('0')
}

/// An IBAN with the original's country and length and correct check digits.
fn iban_like(real: &str, rng: &mut ChaCha12Rng) -> String {
    let compact: String = real
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let country = if compact.len() >= 2 {
        &compact[..2]
    } else {
        "GB"
    };
    let bban_len = compact.len().clamp(15, 34) - 4;

    let bban = token(rng, data::UPPER_ALNUM, bban_len);
    let check = iban_check_digits(country, &bban);
    format!("{country}{check:02}{bban}")
}

/// The two digits that make `country` + `bban` pass the mod-97 test.
fn iban_check_digits(country: &str, bban: &str) -> u32 {
    let rearranged = format!("{bban}{country}00");
    let mut remainder = 0u32;
    for ch in rearranged.chars() {
        let value = if ch.is_ascii_digit() {
            ch as u32 - '0' as u32
        } else {
            ch as u32 - 'A' as u32 + 10
        };
        remainder = if value > 9 {
            (remainder * 100 + value) % 97
        } else {
            (remainder * 10 + value) % 97
        };
    }
    98 - remainder
}

/// Nine digits that satisfy the ABA weighted checksum.
fn routing_like(rng: &mut ChaCha12Rng) -> String {
    let weights = [3u32, 7, 1, 3, 7, 1, 3, 7];
    let head = digits(rng, 8);
    let sum: u32 = head
        .chars()
        .filter_map(|c| c.to_digit(10))
        .zip(weights)
        .map(|(digit, weight)| digit * weight)
        .sum();
    let last = (10 - (sum % 10)) % 10;
    format!("{head}{last}")
}

/// Real area codes, so a stand-in number still parses as a US number.
const AREA_CODES: &[&str] = &["201", "310", "415", "512", "617", "720", "919"];

/// A number in the NANP block reserved for fiction.
fn phone_like(real: &str, rng: &mut ChaCha12Rng) -> String {
    // 555-0100 through 555-0199 is set aside for use in fiction, so a
    // surrogate can never ring a real handset.
    let line = rng.random_range(100..200u32);
    let area = pick(rng, AREA_CODES);
    let sep = separator_of(real).unwrap_or('-');

    if real.trim_start().starts_with('+') {
        format!("+1{sep}{area}{sep}555{sep}0{line}")
    } else {
        format!("({area}){sep}555{sep}0{line}")
    }
}

/// An address in the TEST-NET-3 documentation range.
fn ipv4_like(rng: &mut ChaCha12Rng) -> String {
    // 203.0.113.0/24 is reserved by RFC 5737 for documentation.
    format!("203.0.113.{}", rng.random_range(1..255u32))
}

/// An address in the RFC 3849 documentation prefix.
fn ipv6_like(rng: &mut ChaCha12Rng) -> String {
    format!(
        "2001:db8:{}:{}::{}",
        token(rng, data::HEX_LOWER, 4),
        token(rng, data::HEX_LOWER, 4),
        token(rng, data::HEX_LOWER, 4)
    )
}

/// A locally-administered MAC, which no manufacturer can have assigned.
fn mac_like(real: &str, rng: &mut ChaCha12Rng) -> String {
    let sep = if real.contains('-') { '-' } else { ':' };
    let octets: Vec<String> = (0..5).map(|_| token(rng, data::HEX_LOWER, 2)).collect();
    // The second-least-significant bit of the first octet marks a local address.
    format!("02{sep}{}", octets.join(&sep.to_string()))
}

fn date_like(real: &str, rng: &mut ChaCha12Rng) -> String {
    const MONTHS: &[&str] = &[
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let year = rng.random_range(1955..2001u32);
    let month = rng.random_range(1..13u32);
    let day = rng.random_range(1..29u32);

    if real.contains('/') {
        format!("{month:02}/{day:02}/{year}")
    } else if real.chars().any(char::is_alphabetic) {
        let name = MONTHS[(month - 1) as usize];
        format!("{name} {day}, {year}")
    } else {
        format!("{year}-{month:02}-{day:02}")
    }
}

fn crypto_like(real: &str, rng: &mut ChaCha12Rng) -> String {
    let len = char_len(real);
    if real.starts_with("0x") || real.starts_with("0X") {
        format!("0x{}", token(rng, data::HEX_LOWER, 40))
    } else if real.starts_with("bc1") {
        format!(
            "bc1{}",
            token(rng, data::BECH32, len.saturating_sub(3).max(11))
        )
    } else {
        let lead = real.chars().next().unwrap_or('1');
        format!(
            "{lead}{}",
            token(rng, data::BASE58, len.saturating_sub(1).max(25))
        )
    }
}

/// Rebuild a URL over a reserved domain, keeping the scheme and path depth.
fn url_like(real: &str, rng: &mut ChaCha12Rng) -> String {
    let scheme = real.split("://").next().unwrap_or("https");
    let after_scheme = real.split_once("://").map_or("", |(_, rest)| rest);
    let path_depth = after_scheme.matches('/').count();
    let mut out = format!("{scheme}://{}", domain(rng));
    for _ in 0..path_depth.min(4) {
        out.push('/');
        out.push_str(&pick(rng, data::STREET_NAMES).to_ascii_lowercase());
    }
    out
}

/// Rebuild a connection string, keeping the scheme, port and database name shape.
fn database_url_like(real: &str, rng: &mut ChaCha12Rng) -> String {
    let scheme = real.split("://").next().unwrap_or("postgresql");
    let port = real
        .rsplit(':')
        .next()
        .and_then(|tail| tail.split('/').next())
        .and_then(|candidate| candidate.parse::<u16>().ok())
        .unwrap_or(5432);
    format!(
        "{scheme}://{}:{}@db.{}:{port}/{}",
        pick(rng, data::GIVEN_NAMES).to_ascii_lowercase(),
        token(rng, data::ALNUM, 16),
        domain(rng),
        pick(rng, data::STREET_NAMES).to_ascii_lowercase()
    )
}

/// Rebuild a vendor token, keeping the prefix that names the service.
///
/// `shpat_`, `dop_v1_`, `NRAK-`: the part before the last separator near the
/// front is what tells a reader, a scanner and the service itself what this
/// is, so it survives. The rest is regenerated at the same length over the
/// same alphabet, so a stand-in still looks like what it replaced.
fn vendor_token_like(real: &str, rng: &mut ChaCha12Rng) -> String {
    let head: String = real.chars().take(12).collect();
    let split = head.rfind(['_', '-']).map_or_else(
        || {
            // No separator: keep a short leading run of letters, which is
            // how `dapi`, `cio` and `figd` style prefixes are shaped.
            real.chars()
                .take_while(char::is_ascii_alphabetic)
                .count()
                .min(5)
        },
        |index| index + 1,
    );

    let (prefix, tail) = real.split_at(split.min(real.len()));
    let alphabet = if tail.is_empty() {
        data::ALNUM
    } else if tail
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        data::HEX_LOWER
    } else if tail
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        data::UPPER_ALNUM
    } else if tail.bytes().any(|b| matches!(b, b'-' | b'_')) {
        data::BASE64_URL
    } else {
        data::ALNUM
    };

    format!("{prefix}{}", token(rng, alphabet, char_len(tail).max(8)))
}

/// Rebuild an identifier, keeping its digit-and-separator layout.
///
/// A taxpayer number is recognised by its shape as much as its value, so
/// `123-456-789-00001` has to come back as five groups in the same places.
fn layout_like(real: &str, rng: &mut ChaCha12Rng) -> String {
    real.chars()
        .map(|character| {
            if character.is_ascii_digit() {
                char::from(b'0' + u8::try_from(rng.random_range(0..10u32)).unwrap_or(0))
            } else if character.is_ascii_alphabetic() {
                char::from(data::UPPER_ALNUM[rng.random_range(0..26)])
            } else {
                character
            }
        })
        .collect()
}

/// A Brazilian CPF with correct check digits, in the layout it was written in.
fn cpf_like(real: &str, rng: &mut ChaCha12Rng) -> String {
    let mut digits: Vec<u32> = (0..9).map(|_| rng.random_range(0..10u32)).collect();
    for length in [9usize, 10] {
        let sum: u32 = digits[..length]
            .iter()
            .enumerate()
            .map(|(index, digit)| digit * u32::try_from(length + 1 - index).unwrap_or(0))
            .sum();
        let remainder = sum % 11;
        digits.push(if remainder < 2 { 0 } else { 11 - remainder });
    }

    let mut rendered = digits.iter().map(ToString::to_string).collect::<String>();
    if real.contains('.') {
        rendered = format!(
            "{}.{}.{}-{}",
            &rendered[0..3],
            &rendered[3..6],
            &rendered[6..9],
            &rendered[9..11]
        );
    }
    rendered
}

// ---------------------------------------------------------------------------
// The kind-to-shape table
// ---------------------------------------------------------------------------

#[expect(
    clippy::too_many_lines,
    reason = "one arm per entity kind; splitting it hides the mapping"
)]
fn realistic(kind: &EntityKind, real: &str, rng: &mut ChaCha12Rng) -> String {
    match kind {
        EntityKind::PersonName => {
            // A single-word original gets a single-word stand-in, so
            // "Dr. Chen" does not become "Dr. Avery Sinclair".
            let given = pick(rng, data::GIVEN_NAMES);
            if real.split_whitespace().count() <= 1 {
                given.to_owned()
            } else {
                format!("{given} {}", pick(rng, data::FAMILY_NAMES))
            }
        }
        EntityKind::EmailAddress => format!(
            "{}.{}@{}",
            pick(rng, data::GIVEN_NAMES).to_ascii_lowercase(),
            pick(rng, data::FAMILY_NAMES).to_ascii_lowercase(),
            domain(rng)
        ),
        EntityKind::PhoneNumber => phone_like(real, rng),
        EntityKind::StreetAddress => format!(
            "{} {} {}",
            rng.random_range(100..9000u32),
            pick(rng, data::STREET_NAMES),
            pick(rng, data::STREET_SUFFIXES)
        ),
        EntityKind::DateOfBirth => date_like(real, rng),
        // The 900 block is never issued, so this cannot collide with a real SSN.
        EntityKind::NationalId => {
            format!("9{}-{}-{}", digits(rng, 2), digits(rng, 2), digits(rng, 4))
        }
        EntityKind::TaxId => {
            if crate::detect::validate::cpf(real) {
                cpf_like(real, rng)
            } else {
                layout_like(real, rng)
            }
        }
        EntityKind::VendorApiToken => vendor_token_like(real, rng),
        EntityKind::PassportNumber => {
            format!(
                "X{}",
                digits(rng, char_len(real).saturating_sub(1).clamp(5, 8))
            )
        }
        EntityKind::DriversLicense => token(rng, data::UPPER_ALNUM, char_len(real).clamp(5, 20)),

        EntityKind::CreditCard => card_like(real, rng),
        EntityKind::Iban => iban_like(real, rng),
        EntityKind::BankRouting => routing_like(rng),
        EntityKind::SwiftBic => {
            let len = if char_len(real) >= 11 { 11 } else { 8 };
            token(rng, data::UPPER_ALNUM, len)
        }
        EntityKind::CryptoAddress => crypto_like(real, rng),

        EntityKind::IpV4 => ipv4_like(rng),
        EntityKind::IpV6 => ipv6_like(rng),
        EntityKind::MacAddress => mac_like(real, rng),
        EntityKind::Hostname => format!(
            "{}{}.internal",
            pick(rng, data::STREET_NAMES).to_ascii_lowercase(),
            rng.random_range(1..100u32)
        ),
        EntityKind::Url => url_like(real, rng),
        EntityKind::Uuid => format!(
            "{}-{}-4{}-{}{}-{}",
            token(rng, data::HEX_LOWER, 8),
            token(rng, data::HEX_LOWER, 4),
            token(rng, data::HEX_LOWER, 3),
            pick(rng, &["8", "9", "a", "b"]),
            token(rng, data::HEX_LOWER, 3),
            token(rng, data::HEX_LOWER, 12)
        ),
        EntityKind::S3Uri => {
            let tail = real.split_once("s3://").map_or("", |(_, rest)| rest);
            let depth = tail.matches('/').count();
            let mut out = format!("s3://{}-bucket", pick(rng, data::DOMAIN_LABELS));
            for _ in 0..depth.min(4) {
                out.push('/');
                out.push_str(&pick(rng, data::STREET_NAMES).to_ascii_lowercase());
            }
            out
        }
        EntityKind::DatabaseUrl => database_url_like(real, rng),

        EntityKind::AwsAccessKeyId => {
            let prefix = real.get(..4).unwrap_or("AKIA");
            format!("{prefix}{}", token(rng, data::UPPER_ALNUM, 16))
        }
        EntityKind::AwsSecretAccessKey => token(rng, data::BASE64_STD, 40),
        EntityKind::GithubToken => {
            let prefix = real.split_once('_').map_or("ghp", |(head, _)| head);
            format!("{prefix}_{}", token(rng, data::ALNUM, 36))
        }
        EntityKind::GitlabToken => format!("glpat-{}", token(rng, data::ALNUM, 20)),
        EntityKind::SlackToken => {
            let prefix = real.get(..4).unwrap_or("xoxb");
            format!(
                "{prefix}-{}-{}",
                digits(rng, 12),
                token(rng, data::ALNUM, 24)
            )
        }
        EntityKind::StripeKey => {
            // Always route the stand-in to the test mode prefix: if it ever
            // reaches a real API it fails loudly instead of moving money.
            let kind_prefix = real.get(..2).unwrap_or("sk");
            format!("{kind_prefix}_test_{}", token(rng, data::ALNUM, 24))
        }
        EntityKind::OpenAiKey => format!("sk-{}", token(rng, data::ALNUM, 45)),
        EntityKind::AnthropicKey => {
            format!(
                concat!("sk-", "ant-api03-{}"),
                token(rng, data::BASE64_URL, 95)
            )
        }
        EntityKind::GoogleApiKey => format!("AIza{}", token(rng, data::BASE64_URL, 35)),
        EntityKind::SendgridKey => format!(
            "SG.{}.{}",
            token(rng, data::BASE64_URL, 22),
            token(rng, data::BASE64_URL, 43)
        ),
        EntityKind::TwilioKey => {
            let prefix = real.get(..2).unwrap_or("SK");
            format!("{prefix}{}", token(rng, data::HEX_LOWER, 32))
        }
        EntityKind::NpmToken => format!("npm_{}", token(rng, data::ALNUM, 36)),
        EntityKind::JwtToken => format!(
            "{}.{}.{}",
            token(rng, data::BASE64_URL, 36),
            token(rng, data::BASE64_URL, 64),
            token(rng, data::BASE64_URL, 43)
        ),
        EntityKind::PrivateKeyBlock | EntityKind::SshPrivateKey => {
            let label = if matches!(kind, EntityKind::SshPrivateKey) {
                "OPENSSH"
            } else {
                "RSA"
            };
            let body: Vec<String> = (0..4).map(|_| token(rng, data::BASE64_STD, 64)).collect();
            format!(
                "-----BEGIN {label} PRIVATE KEY-----\n{}\n-----END {label} PRIVATE KEY-----",
                body.join("\n")
            )
        }
        EntityKind::BearerToken | EntityKind::BasicAuth => {
            token(rng, data::BASE64_URL, char_len(real).clamp(24, 64))
        }
        EntityKind::GenericApiKey => token(rng, data::ALNUM, char_len(real).clamp(16, 48)),
        EntityKind::GenericSecret | EntityKind::HighEntropyString => {
            token(rng, data::BASE64_URL, char_len(real).clamp(16, 48))
        }
        EntityKind::PasswordAssignment => format!(
            "{}-{}-{}",
            pick(rng, data::STREET_NAMES).to_ascii_lowercase(),
            pick(rng, data::CITIES).to_ascii_lowercase(),
            digits(rng, 4)
        ),
        EntityKind::Custom(_) => {
            // Nothing is known about the shape, so the only safe default is to
            // preserve size: a secret-sized blob for a secret, a word otherwise.
            if kind.category() == Category::Credential && char_len(real) >= 16 {
                token(rng, data::ALNUM, char_len(real))
            } else {
                format!(
                    "{}-{}",
                    pick(rng, data::DOMAIN_LABELS),
                    rng.random_range(1000..9999u32)
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::validate;
    use crate::fixtures;

    fn surrogates() -> Surrogates {
        Surrogates::from_secret(b"test seed", Style::Realistic)
    }

    fn make(kind: &EntityKind, real: &str) -> String {
        surrogates().generate(kind, real, 1, 0)
    }

    #[test]
    fn generation_is_deterministic_across_instances() {
        let first = Surrogates::from_secret(b"same", Style::Realistic);
        let second = Surrogates::from_secret(b"same", Style::Realistic);
        assert_eq!(
            first.generate(&EntityKind::EmailAddress, "a@b.com", 1, 0),
            second.generate(&EntityKind::EmailAddress, "a@b.com", 1, 0)
        );
    }

    #[test]
    fn derived_generators_are_stable_and_independent() {
        let root = Surrogates::from_secret(b"root", Style::Realistic);
        let left = root.derive("conversation-a");
        let right = root.derive("conversation-b");

        // Same label, same generator, every time.
        assert_eq!(left.seed(), root.derive("conversation-a").seed());
        // Different labels cannot see each other.
        assert_ne!(left.seed(), right.seed());
        // And none of them is the parent.
        assert_ne!(left.seed(), root.seed());

        assert_ne!(
            left.generate(&EntityKind::EmailAddress, "dana@corp.com", 1, 0),
            right.generate(&EntityKind::EmailAddress, "dana@corp.com", 1, 0),
            "two conversations gave the same value the same stand-in"
        );
    }

    #[test]
    fn derivation_keeps_the_style() {
        let root = Surrogates::from_secret(b"root", Style::Tagged);
        assert_eq!(root.derive("x").style(), Style::Tagged);
    }

    #[test]
    fn a_different_seed_gives_a_different_stand_in() {
        let first = Surrogates::from_secret(b"one", Style::Realistic);
        let second = Surrogates::from_secret(b"two", Style::Realistic);
        assert_ne!(
            first.generate(&EntityKind::EmailAddress, "a@b.com", 1, 0),
            second.generate(&EntityKind::EmailAddress, "a@b.com", 1, 0)
        );
    }

    #[test]
    fn bumping_the_attempt_changes_the_output() {
        let s = surrogates();
        assert_ne!(
            s.generate(&EntityKind::EmailAddress, "a@b.com", 1, 0),
            s.generate(&EntityKind::EmailAddress, "a@b.com", 1, 1)
        );
    }

    #[test]
    fn generated_cards_pass_luhn_and_keep_their_length() {
        for real in [
            fixtures::TEST_CARD,
            "5555 5555 5555 4444",
            "378282246310005",
        ] {
            let fake = make(&EntityKind::CreditCard, real);
            assert!(validate::luhn(&fake), "{fake} is not a valid card number");
            let real_digits = real.chars().filter(char::is_ascii_digit).count();
            let fake_digits = fake.chars().filter(char::is_ascii_digit).count();
            assert_eq!(real_digits, fake_digits, "length changed for {real}");
        }
    }

    #[test]
    fn generated_ibans_pass_mod97_and_keep_their_country() {
        let fake = make(&EntityKind::Iban, fixtures::TEST_IBAN);
        assert!(fake.starts_with("GB"), "{fake}");
        assert!(validate::iban_mod97(&fake), "{fake} fails the checksum");
    }

    #[test]
    fn generated_routing_numbers_pass_the_aba_checksum() {
        let fake = make(&EntityKind::BankRouting, "021000021");
        assert!(validate::aba_routing(&fake), "{fake}");
    }

    #[test]
    fn generated_addresses_stay_in_reserved_ranges() {
        let ip = make(&EntityKind::IpV4, "8.8.8.8");
        assert!(ip.starts_with("203.0.113."), "{ip} escaped the doc range");
        let ip6 = make(&EntityKind::IpV6, "2606:4700::1111");
        assert!(ip6.starts_with("2001:db8:"), "{ip6} escaped the doc range");
    }

    #[test]
    fn generated_emails_land_on_a_reserved_tld() {
        let email = make(&EntityKind::EmailAddress, "real.person@bigcorp.com");
        let tld = email.rsplit('.').next().unwrap();
        assert!(
            data::RESERVED_TLDS.contains(&tld),
            "{email} could reach a real mailbox"
        );
    }

    #[test]
    fn generated_phone_numbers_stay_in_the_fiction_block() {
        let phone = make(&EntityKind::PhoneNumber, "+1 415 867 5309");
        assert!(phone.contains("555"), "{phone}");
        assert!(phone.starts_with('+'), "{phone} dropped the country code");
    }

    #[test]
    fn stripe_stand_ins_are_always_test_mode() {
        let fake = make(&EntityKind::StripeKey, &fixtures::stripe_live_key());
        assert!(fake.starts_with("sk_test_"), "{fake} is a live-mode key");
    }

    #[test]
    fn stand_ins_are_detected_as_the_same_kind_they_replace() {
        use crate::detect::Detector;
        use crate::policy::Policy;

        let detector = Detector::new(Policy::aggressive()).unwrap();
        for (kind, real) in [
            (EntityKind::EmailAddress, "real@bigcorp.com"),
            (EntityKind::CreditCard, fixtures::TEST_CARD),
            (EntityKind::AwsAccessKeyId, fixtures::AWS_ACCESS_KEY_ID),
            (EntityKind::IpV4, "8.8.8.8"),
            (EntityKind::Iban, "GB82WEST12345698765432"),
            (EntityKind::TaxId, "123-456-789-00001"),
        ] {
            let fake = make(&kind, real);
            let found = detector.scan(&fake);
            assert!(
                found.iter().any(|finding| finding.kind == kind),
                "stand-in {fake} for {kind} is not recognised as a {kind}"
            );
        }
    }

    #[test]
    fn a_vendor_stand_in_keeps_the_prefix_that_names_the_service() {
        for (real, prefix) in [
            (
                format!("{}{}", concat!("shpat", "_"), "9".repeat(32)),
                concat!("shpat", "_"),
            ),
            (
                format!("{}{}", concat!("dop", "_v1_"), "0".repeat(64)),
                concat!("dop", "_v1_"),
            ),
            (
                format!("{}{}", concat!("NRAK", "-"), "H".repeat(27)),
                concat!("NRAK", "-"),
            ),
            (format!("dapi{}", "a".repeat(32)), "dapi"),
        ] {
            let fake = make(&EntityKind::VendorApiToken, &real);
            assert!(fake.starts_with(prefix), "{fake} lost the {prefix} prefix");
            assert_ne!(fake, real);
            assert_eq!(fake.len(), real.len(), "{fake} changed length");
        }
    }

    #[test]
    fn a_tax_id_stand_in_keeps_its_layout() {
        let fake = make(&EntityKind::TaxId, "123-456-789-00001");
        assert_ne!(fake, "123-456-789-00001");
        let layout = |value: &str| {
            value
                .chars()
                .map(|c| if c.is_ascii_digit() { 'd' } else { c })
                .collect::<String>()
        };
        assert_eq!(layout(&fake), layout("123-456-789-00001"));
    }

    #[test]
    fn a_cpf_stand_in_passes_its_own_checksum() {
        let fake = make(&EntityKind::TaxId, "529.982.247-25");
        assert!(validate::cpf(&fake), "{fake} is not a valid CPF");
        assert!(fake.contains('.'), "{fake} lost its layout");
    }

    #[test]
    fn tagged_style_is_readable_and_unique_per_ordinal() {
        let s = Surrogates::from_secret(b"seed", Style::Tagged);
        assert_eq!(
            s.generate(&EntityKind::EmailAddress, "a@b.com", 1, 0),
            "[[EMAIL_ADDRESS_1]]"
        );
        assert_eq!(
            s.generate(&EntityKind::EmailAddress, "c@d.com", 2, 0),
            "[[EMAIL_ADDRESS_2]]"
        );
    }

    #[test]
    fn debug_output_never_prints_the_seed() {
        let rendered = format!("{:?}", surrogates());
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("115"), "{rendered}");
    }
}

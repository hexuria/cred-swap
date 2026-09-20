//! Synthetic credential strings for tests and examples.
//!
//! Every value here is fabricated or is a vendor's own published example. None
//! of them grants access to anything.
//!
//! They are assembled from fragments rather than written as literals, on
//! purpose. A project whose test corpus is, by definition, a pile of
//! credential-shaped strings will trip every secret scanner it is ever run
//! through: pre-commit hooks, CI scanners, repository push protection. Keeping
//! the literals out of the source means those tools stay useful — a hit in
//! this repository is then a real finding rather than one more entry in a list
//! everybody has learned to scroll past.
//!
//! Enable the `fixtures` feature to use these from another crate's tests.

/// AWS's own documentation example access key id.
pub const AWS_ACCESS_KEY_ID: &str = concat!("AKIA", "IOSFODNN7EXAMPLE");

/// AWS's own documentation example secret access key.
pub const AWS_SECRET_ACCESS_KEY: &str = concat!("wJalrXUtnFEMI/", "K7MDENG/bPxRfiCYEXAMPLEKEY");

/// A payment card number from the published test range.
pub const TEST_CARD: &str = "4242424242424242";

/// The same card number written with the grouping a human would type.
pub const TEST_CARD_SPACED: &str = "4242 4242 4242 4242";

/// A well-formed IBAN from the ISO 13616 documentation.
pub const TEST_IBAN: &str = "GB82 WEST 1234 5698 7654 32";

/// A GitHub personal access token of the right shape.
#[must_use]
pub fn github_token() -> String {
    format!("{}{}", concat!("ghp", "_"), "a".repeat(36))
}

/// An Anthropic API key of the right shape.
#[must_use]
pub fn anthropic_key() -> String {
    format!("{}{}", concat!("sk-", "ant-api03-"), "b".repeat(85))
}

/// An `OpenAI` API key of the right shape.
#[must_use]
pub fn openai_key() -> String {
    format!("{}{}", concat!("sk", "-"), "c".repeat(45))
}

/// A Stripe live-mode secret key of the right shape.
#[must_use]
pub fn stripe_live_key() -> String {
    format!("{}{}", concat!("sk", "_live_"), "d".repeat(24))
}

/// A Google API key of the right shape.
#[must_use]
pub fn google_api_key() -> String {
    format!("{}{}", concat!("AI", "za"), "E".repeat(35))
}

/// A PEM-armoured private key block.
#[must_use]
pub fn private_key_block() -> String {
    format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{}\n{}\n-----END RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEA",
        "f".repeat(64)
    )
}

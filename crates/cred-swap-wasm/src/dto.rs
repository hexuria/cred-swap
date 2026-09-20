//! The shapes that cross into JavaScript.
//!
//! These exist rather than serializing the core types directly, for one
//! reason: an [`EntityKind`](cred_swap_core::EntityKind) serializes a custom rule as `{"custom": "label"}`,
//! which is awkward to switch on from JavaScript. Here every kind is the flat
//! string the rest of the tool uses — `"email-address"`, `"custom:codename"` —
//! so a caller can compare it, store it and hand it back without knowing
//! anything about how Rust enums are encoded.

use cred_swap_core::{Entry, Finding, Replacement, Scrubbed};
use serde::Serialize;

/// A value found in the text, and what it would be replaced with.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsFinding {
    /// The kind of value, as `email-address` or `custom:codename`.
    pub kind: String,
    /// One of `pii`, `financial`, `infrastructure` or `credential`.
    pub category: String,
    /// Whether leaking this would hand someone access to a system.
    ///
    /// A review interface should not offer to let one of these through.
    pub secret: bool,
    /// Byte offset of the value in the text that was scanned.
    pub start: usize,
    /// Byte offset one past the value.
    pub end: usize,
    /// The matched text.
    pub value: String,
}

impl From<&Finding> for JsFinding {
    fn from(finding: &Finding) -> Self {
        Self {
            kind: finding.kind.qualified_name().into_owned(),
            category: finding.kind.category().as_str().to_owned(),
            secret: finding.kind.is_secret(),
            start: finding.start,
            end: finding.end,
            value: finding.text.clone(),
        }
    }
}

/// A substitution that was made.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsReplacement {
    /// The kind of value.
    pub kind: String,
    /// The value's category.
    pub category: String,
    /// Whether it is a credential.
    pub secret: bool,
    /// The original text.
    pub real: String,
    /// What went out in its place.
    pub fake: String,
    /// Byte offset of the value in the original text.
    pub start: usize,
    /// Byte offset one past the value in the original text.
    pub end: usize,
}

impl From<&Replacement> for JsReplacement {
    fn from(replacement: &Replacement) -> Self {
        Self {
            kind: replacement.kind.qualified_name().into_owned(),
            category: replacement.kind.category().as_str().to_owned(),
            secret: replacement.kind.is_secret(),
            real: replacement.real.clone(),
            fake: replacement.fake.clone(),
            start: replacement.source_start,
            end: replacement.source_end,
        }
    }
}

/// The result of a scrub.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsScrubbed {
    /// The text as it should now be sent.
    pub text: String,
    /// Every substitution made, in document order.
    pub replacements: Vec<JsReplacement>,
    /// Findings left in place at the caller's request.
    pub kept: Vec<JsFinding>,
}

impl From<&Scrubbed> for JsScrubbed {
    fn from(scrubbed: &Scrubbed) -> Self {
        Self {
            text: scrubbed.text.clone(),
            replacements: scrubbed.replacements.iter().map(Into::into).collect(),
            kept: scrubbed.kept.iter().map(Into::into).collect(),
        }
    }
}

/// One row of the vault.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsEntry {
    /// The kind of value.
    pub kind: String,
    /// Whether it is a credential.
    pub secret: bool,
    /// The original text, as first seen.
    pub real: String,
    /// The stand-in that replaces it.
    pub fake: String,
    /// How many times it has been substituted.
    pub hits: u64,
}

impl From<&Entry> for JsEntry {
    fn from(entry: &Entry) -> Self {
        Self {
            kind: entry.kind.qualified_name().into_owned(),
            secret: entry.kind.is_secret(),
            real: entry.real.clone(),
            fake: entry.fake.clone(),
            hits: entry.hits,
        }
    }
}

/// One rule, for building a settings interface.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsKind {
    /// The kind's name.
    pub kind: String,
    /// Its category.
    pub category: String,
    /// Whether it is a credential.
    pub secret: bool,
    /// Whether the current policy has it switched on.
    pub enabled: bool,
}

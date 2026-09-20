//! `cred-swap` in the browser.
//!
//! Compiles the detection rules, the stand-in generator and the vault to
//! WebAssembly so an extension can mask a prompt in the composer before it is
//! sent, and put the real values back in the reply. It is the same rule table
//! the command line uses: one implementation, one set of tests, two hosts.
//!
//! # Entropy and the seed
//!
//! Stand-ins are derived from a seed. The same seed and the same real value
//! always give the same stand-in, which is what keeps a long conversation
//! coherent — and what makes persisting the seed the single thing an extension
//! must get right. Lose it and every stand-in in every stored conversation
//! becomes unrestorable.
//!
//! This build has no operating system to ask for entropy, so [`new_seed`]
//! reads the Web Crypto API, and the seed travels inside the exported vault.
//! Save what [`Cloak::export_vault`] returns; hand it to [`Cloak::from_vault`] next
//! time.
//!
//! ```js
//! import init, { Cloak, kinds } from "./pkg/cred_swap_wasm.js";
//! await init();
//!
//! const stored = await browser.storage.local.get("vault");
//! const cloak = stored.vault
//!   ? Cloak.fromVault(stored.vault)
//!   : Cloak.create();
//!
//! const { text, replacements } = cloak.scrub(composer.value);
//! composer.value = text;                       // what the model will see
//! await browser.storage.local.set({ vault: cloak.export() });
//!
//! reply.textContent = cloak.restore(reply.textContent);
//! ```
//!
//! # What crosses the boundary
//!
//! Nothing leaves the page. There is no network access in this crate and no
//! way to reach one: the vault is handed to the caller as a string and the
//! caller decides where it goes.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

mod dto;

use cred_swap_core::{
    Cloak as CoreCloak, CustomPattern, Decision, EntityKind, Finding, Policy, Style, Surrogates,
    Term, Vault,
};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use dto::{JsEntry, JsFinding, JsKind, JsScrubbed};

/// How many bytes of seed the generator takes.
const SEED_LEN: usize = 32;

/// Settings accepted by [`Cloak::create`] and [`Cloak::from_vault`].
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
struct Options {
    /// `standard`, `secrets`, `aggressive` or `none`.
    policy: Option<String>,
    /// `realistic` or `tagged`. Ignored by [`Cloak::from_vault`], which keeps
    /// the style the stored stand-ins were made in.
    style: Option<String>,
    /// Extra kinds to detect.
    enable: Vec<String>,
    /// Kinds not to detect.
    disable: Vec<String>,
    /// Exact strings never to replace.
    allow: Vec<String>,
    /// Literal strings always to replace.
    terms: Vec<TermSpec>,
    /// Caller-supplied regex rules.
    patterns: Vec<PatternSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TermSpec {
    literal: String,
    kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PatternSpec {
    label: String,
    regex: String,
    #[serde(default)]
    group: usize,
}

/// Every key [`Options`] understands.
///
/// Checked by hand rather than left to `deny_unknown_fields`, which the
/// JavaScript deserializer does not enforce. Without this a typo would be
/// silently ignored, and an extension user who wrote `polcy` would get the
/// default rules while believing they had chosen otherwise.
const OPTION_KEYS: &[&str] = &[
    "policy", "style", "enable", "disable", "allow", "terms", "patterns",
];

impl Options {
    /// Read the options object, treating `undefined` and `null` as "defaults".
    fn parse(value: &JsValue) -> Result<Self, JsError> {
        if value.is_undefined() || value.is_null() {
            return Ok(Self::default());
        }
        reject_unknown_keys(value)?;
        serde_wasm_bindgen::from_value(value.clone())
            .map_err(|error| JsError::new(&format!("invalid options: {error}")))
    }

    fn into_policy(self) -> Result<(Policy, Style), JsError> {
        let mut policy = match &self.policy {
            None => Policy::default(),
            Some(name) => Policy::from_preset(name).map_err(to_js_error)?,
        };
        for name in &self.enable {
            policy = policy.enable(parse_kind(name)?);
        }
        for name in &self.disable {
            policy = policy.disable(&parse_kind(name)?);
        }
        for literal in self.allow {
            policy = policy.allow(literal);
        }
        for term in self.terms {
            let kind = parse_kind(&term.kind)?;
            policy.terms.push(Term {
                literal: term.literal,
                kind,
            });
        }
        for pattern in self.patterns {
            policy.custom_patterns.push(CustomPattern {
                label: pattern.label,
                pattern: pattern.regex,
                group: pattern.group,
            });
        }

        let style = match self.style.as_deref() {
            None | Some("realistic") => Style::Realistic,
            Some("tagged") => Style::Tagged,
            Some(other) => {
                return Err(JsError::new(&format!(
                    "unknown style `{other}`, expected realistic or tagged"
                )));
            }
        };
        Ok((policy, style))
    }
}

/// Fail on any option key that is not one of [`OPTION_KEYS`].
fn reject_unknown_keys(value: &JsValue) -> Result<(), JsError> {
    let Some(object) = value.dyn_ref::<js_sys::Object>() else {
        return Err(JsError::new("options must be an object"));
    };
    for key in js_sys::Object::keys(object).iter() {
        let Some(name) = key.as_string() else {
            continue;
        };
        if !OPTION_KEYS.contains(&name.as_str()) {
            return Err(JsError::new(&format!(
                "unknown option `{name}`. Valid options are: {}.",
                OPTION_KEYS.join(", ")
            )));
        }
    }
    Ok(())
}

fn parse_kind(name: &str) -> Result<EntityKind, JsError> {
    name.parse::<EntityKind>().map_err(|_| {
        JsError::new(&format!(
            "unknown kind `{name}`. Call kinds() for the list, or use `custom:<label>`."
        ))
    })
}

fn to_js_error(error: impl std::fmt::Display) -> JsError {
    JsError::new(&error.to_string())
}

fn to_js_value<T: serde::Serialize>(value: &T) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(value)
        .map_err(|error| JsError::new(&format!("cannot convert result: {error}")))
}

/// Draw 32 random bytes from the Web Crypto API.
///
/// Reached through the global object rather than through `window`, so it works
/// the same in a page, a worker and an extension service worker.
///
/// # Errors
///
/// Returns an error if the host has no Web Crypto implementation. There is no
/// fallback on purpose: a predictable seed would make every stand-in
/// reversible by anyone who guessed it.
///
/// # Panics
///
/// Panics if the seed length does not fit in a `u32`, which it always does.
#[wasm_bindgen(js_name = newSeed)]
pub fn new_seed() -> Result<Vec<u8>, JsError> {
    let global = js_sys::global();
    let crypto = js_sys::Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|_| JsError::new("no Web Crypto API on the global object"))?;
    let function = js_sys::Reflect::get(&crypto, &JsValue::from_str("getRandomValues"))
        .ok()
        .and_then(|value| value.dyn_into::<js_sys::Function>().ok())
        .ok_or_else(|| JsError::new("crypto.getRandomValues is unavailable"))?;

    let buffer = js_sys::Uint8Array::new_with_length(
        u32::try_from(SEED_LEN).expect("the seed length fits in a u32"),
    );
    function
        .call1(&crypto, &buffer)
        .map_err(|_| JsError::new("crypto.getRandomValues failed"))?;

    Ok(buffer.to_vec())
}

/// Every rule, and whether the given options switch it on.
///
/// Use it to build a settings screen without hard-coding the list.
///
/// # Errors
///
/// Returns an error if the options are invalid.
#[wasm_bindgen]
pub fn kinds(options: &JsValue) -> Result<JsValue, JsError> {
    let (policy, _) = Options::parse(options)?.into_policy()?;
    let rows: Vec<JsKind> = EntityKind::BUILTIN
        .iter()
        .map(|kind| JsKind {
            kind: kind.qualified_name().into_owned(),
            category: kind.category().as_str().to_owned(),
            secret: kind.is_secret(),
            enabled: policy.is_enabled(kind),
        })
        .collect();
    to_js_value(&rows)
}

/// The version of `cred-swap` this build came from.
#[wasm_bindgen]
#[must_use]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Detection, substitution and restoration for one conversation.
#[wasm_bindgen]
pub struct Cloak {
    inner: CoreCloak,
}

#[wasm_bindgen]
impl Cloak {
    /// Start a new session with a seed drawn from the Web Crypto API.
    ///
    /// Persist [`Cloak::export_vault`] afterwards, or every stand-in this session
    /// hands out becomes unrestorable when the page goes away.
    ///
    /// # Errors
    ///
    /// Returns an error if the options are invalid or the host has no Web
    /// Crypto API.
    pub fn create(options: &JsValue) -> Result<Self, JsError> {
        let (policy, style) = Options::parse(options)?.into_policy()?;
        let seed = new_seed()?;
        let surrogates = Surrogates::from_seed(to_seed(&seed)?, style);
        Ok(Self {
            inner: CoreCloak::new(policy, surrogates).map_err(to_js_error)?,
        })
    }

    /// Start a session from a seed you already hold.
    ///
    /// Two hosts given the same seed produce the same stand-ins for the same
    /// values without exchanging anything else, which is how a browser and a
    /// command line can share one set of substitutions.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed is not 32 bytes, or the options are
    /// invalid.
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &[u8], options: &JsValue) -> Result<Self, JsError> {
        let (policy, style) = Options::parse(options)?.into_policy()?;
        let surrogates = Surrogates::from_seed(to_seed(seed)?, style);
        Ok(Self {
            inner: CoreCloak::new(policy, surrogates).map_err(to_js_error)?,
        })
    }

    /// Resume a session from [`Cloak::export_vault`] output.
    ///
    /// The stored style wins over any `style` in the options: the stand-ins
    /// already in the vault were made one way, and mixing two naming schemes
    /// in one conversation helps nobody.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault is not readable, or the options are
    /// invalid.
    #[wasm_bindgen(js_name = fromVault)]
    pub fn from_vault(vault: &str, options: &JsValue) -> Result<Self, JsError> {
        let (policy, _) = Options::parse(options)?.into_policy()?;
        let vault = Vault::from_json(vault).map_err(to_js_error)?;
        Ok(Self {
            inner: CoreCloak::resume(policy, vault).map_err(to_js_error)?,
        })
    }

    /// Report what would be replaced, changing nothing.
    ///
    /// This is what a review card shows before the user presses send. Nothing
    /// is written to the vault, so a user who backs out leaves no trace.
    ///
    /// # Errors
    ///
    /// Returns an error if the findings cannot be converted for JavaScript.
    pub fn detect(&self, text: &str) -> Result<JsValue, JsError> {
        let findings: Vec<JsFinding> = self.inner.inspect(text).iter().map(Into::into).collect();
        to_js_value(&findings)
    }

    /// Replace every detected value with its stand-in.
    ///
    /// # Errors
    ///
    /// Returns an error if the result cannot be converted for JavaScript.
    pub fn scrub(&mut self, text: &str) -> Result<JsValue, JsError> {
        let scrubbed = self.inner.scrub(text);
        to_js_value(&JsScrubbed::from(&scrubbed))
    }

    /// Replace every detected value except the ones at the given offsets.
    ///
    /// `keep` holds the `start` offsets of findings the user unticked. A
    /// credential is replaced whether or not it appears there: leaving one in
    /// outgoing text is not a choice worth offering, and a review interface
    /// should not present it as one.
    ///
    /// # Errors
    ///
    /// Returns an error if the result cannot be converted for JavaScript.
    #[wasm_bindgen(js_name = scrubExcept)]
    pub fn scrub_except(&mut self, text: &str, keep: Vec<usize>) -> Result<JsValue, JsError> {
        let keep: std::collections::HashSet<usize> = keep.into_iter().collect();
        let scrubbed = self.inner.scrub_with(text, |finding: &Finding| {
            if !finding.kind.is_secret() && keep.contains(&finding.start) {
                Decision::Keep
            } else {
                Decision::Replace
            }
        });
        to_js_value(&JsScrubbed::from(&scrubbed))
    }

    /// Put the real values back wherever a stand-in appears.
    ///
    /// Safe to call on any text: one with no stand-ins in it comes back
    /// unchanged, so an extension can run it over a whole reply as it streams.
    pub fn restore(&mut self, text: &str) -> String {
        self.inner.restore(text)
    }

    /// Restore a growing buffer, holding back what might still be incomplete.
    ///
    /// Returns `[restoredText, bytesConsumed]`. Keep the unconsumed tail and
    /// prepend it to the next chunk. Use this when a reply arrives a few
    /// characters at a time, where restoring eagerly would cut a stand-in in
    /// half and leave both halves unrestorable.
    ///
    /// # Errors
    ///
    /// Returns an error if the result cannot be converted for JavaScript.
    #[wasm_bindgen(js_name = restoreStreaming)]
    pub fn restore_streaming(&mut self, text: &str) -> Result<JsValue, JsError> {
        let (restored, consumed) = self.inner.restore_streaming(text);
        to_js_value(&(restored, consumed))
    }

    /// Give an already-substituted value a different stand-in.
    ///
    /// Returns the updated row, or `undefined` if the value was never
    /// substituted. Text already sent using the old stand-in will no longer
    /// restore, so this is for use before anything has gone anywhere.
    ///
    /// # Errors
    ///
    /// Returns an error if the result cannot be converted for JavaScript.
    pub fn reroll(&mut self, value: &str) -> Result<JsValue, JsError> {
        match self.inner.vault_mut().reroll(value) {
            Some(entry) => to_js_value(&JsEntry::from(&entry)),
            None => Ok(JsValue::UNDEFINED),
        }
    }

    /// Every substitution made so far, in the order it was first made.
    ///
    /// # Errors
    ///
    /// Returns an error if the result cannot be converted for JavaScript.
    pub fn entries(&self) -> Result<JsValue, JsError> {
        let rows: Vec<JsEntry> = self
            .inner
            .vault()
            .entries()
            .iter()
            .map(Into::into)
            .collect();
        to_js_value(&rows)
    }

    /// Serialize the session for storage.
    ///
    /// The result holds every real value next to its stand-in, and the seed
    /// that links them. In an extension it belongs in `storage.local`, which
    /// other sites cannot read — never in a page's own `localStorage`, which
    /// they can.
    #[wasm_bindgen(js_name = export)]
    #[must_use]
    pub fn export_vault(&self) -> String {
        self.inner.vault().to_json()
    }

    /// How many distinct values have been substituted.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn size(&self) -> usize {
        self.inner.vault().len()
    }

    /// Forget every substitution, keeping the seed.
    ///
    /// A value seen again gets the stand-in it had before. To break that link
    /// as well, build a fresh session with [`Cloak::create`].
    pub fn clear(&mut self) {
        self.inner.vault_mut().clear();
    }
}

fn to_seed(bytes: &[u8]) -> Result<[u8; SEED_LEN], JsError> {
    <[u8; SEED_LEN]>::try_from(bytes).map_err(|_| {
        JsError::new(&format!(
            "seed must be {SEED_LEN} bytes, got {}",
            bytes.len()
        ))
    })
}

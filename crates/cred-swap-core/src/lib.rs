//! Detect sensitive values in text, replace them with consistent stand-ins,
//! and put the originals back afterwards.
//!
//! The problem this solves: you want to ask a hosted model about a real
//! production incident, a real customer record, a real config file. The useful
//! version of that question contains details you cannot send. The sendable
//! version is too vague to get a useful answer.
//!
//! `cred-swap` rewrites the question instead of weakening it. Every sensitive
//! value is replaced by a stand-in of the same shape, so the model still sees a
//! sixteen-digit card number and a routable-looking host and reasons normally.
//! Every stand-in is stable, so the fourth mention of a colleague is still the
//! same person as the first. And every stand-in is reversible, so the model's
//! answer comes back with your real values in it.
//!
//! ```
//! use cred_swap_core::{Cloak, Policy, Style, Surrogates};
//!
//! let mut cloak = Cloak::new(
//!     Policy::default(),
//!     Surrogates::from_secret(b"a secret only this machine knows", Style::Realistic),
//! )?;
//!
//! let scrubbed = cloak.scrub("Email dana@acme.com, card 4242 4242 4242 4242.");
//! assert!(!scrubbed.text.contains("dana@acme.com"));
//! assert!(!scrubbed.text.contains("4242 4242 4242 4242"));
//! assert_eq!(scrubbed.replacements.len(), 2);
//!
//! // Whatever comes back referring to the stand-ins is mapped home again.
//! let answer = format!("I would email {} first.", scrubbed.replacements[0].fake);
//! assert_eq!(cloak.restore(&answer), "I would email dana@acme.com first.");
//! # Ok::<(), cred_swap_core::DetectorError>(())
//! ```
//!
//! # Layout
//!
//! - [`detect`] finds sensitive spans. [`policy`] decides which ones count.
//! - [`fake`] turns a real value into a stand-in of the same shape.
//! - [`vault`] remembers the pairing, on disk if asked.
//! - [`engine`] is the three of them wired together, and is what most callers
//!   want.
//! - [`json`] runs the same thing over a JSON document, for a provider request
//!   body or a tool call's arguments.
//! - [`session`] keeps one [`Cloak`] per conversation, safely shared across
//!   threads, which is what a server needs.
//!
//! # What this is not
//!
//! Detection is pattern-based. It is very good at things with a defined shape
//! (keys, cards, addresses) and much weaker at free-form personal data: an
//! unannounced person's name in the middle of a sentence will be missed.
//! Treat the output as a large reduction in exposure, not as a guarantee, and
//! review it when the stakes call for it.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod detect;
pub mod engine;
pub mod entity;
pub mod fake;
pub mod json;
pub mod policy;
pub mod session;
pub mod vault;

#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;

pub use detect::{Detector, DetectorError, Finding};
pub use engine::{Cloak, Decision, Replacement, Scrubbed};
pub use entity::{Category, EntityKind};
pub use fake::{Style, Surrogates};
pub use json::Changes;
pub use policy::{CustomPattern, Policy, Term, UnknownPreset};
pub use session::{Session, SessionError, SessionStore};
pub use vault::{Entry, Vault, VaultError};

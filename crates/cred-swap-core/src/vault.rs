//! The record of which stand-in replaced which real value.
//!
//! The vault is what makes a scrub reversible and a conversation coherent. It
//! is also, by construction, the most sensitive file the tool touches: it holds
//! every original next to its substitute. [`Vault::save`] writes it owner-only
//! and nothing in this crate ever logs its contents.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use aho_corasick::{AhoCorasick, MatchKind};
use serde::{Deserialize, Serialize};

use crate::entity::EntityKind;
use crate::fake::{Style, Surrogates};

/// The on-disk format version. Bumped when the layout changes incompatibly.
const FORMAT_VERSION: u32 = 1;

/// How many times to reseed the generator when a stand-in collides.
///
/// A collision needs two 20-plus character random values to coincide, so in
/// practice this loop runs once. The bound exists so a pathological policy
/// (a custom rule generating from a two-element alphabet, say) fails fast
/// instead of hanging.
const MAX_GENERATION_ATTEMPTS: u32 = 64;

/// One real-to-stand-in substitution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// What kind of value this is.
    pub kind: EntityKind,
    /// The original text, exactly as first seen.
    pub real: String,
    /// The substitute that goes out in its place.
    pub fake: String,
    /// How many times this value has been substituted.
    pub hits: u64,
}

/// Something went wrong reading or writing the vault file.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The file could not be read or written.
    #[error("cannot access vault at {path}")]
    Io {
        /// The path involved.
        path: String,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// The file is not valid JSON, or not a vault.
    #[error("vault at {path} is corrupt or not a cred-swap vault")]
    Malformed {
        /// The path involved.
        path: String,
        /// The parse failure.
        #[source]
        source: serde_json::Error,
    },
    /// The file was written by an incompatible version.
    #[error("vault at {path} uses format version {found}, this build understands {FORMAT_VERSION}")]
    UnsupportedVersion {
        /// The path involved.
        path: String,
        /// The version found in the file.
        found: u32,
    },
}

/// A bidirectional, order-stable map between real values and their stand-ins.
pub struct Vault {
    surrogates: Surrogates,
    entries: Vec<Entry>,
    by_real: HashMap<(EntityKind, String), usize>,
    by_fake: HashMap<String, usize>,
    ordinals: HashMap<EntityKind, u32>,
    /// Rebuilt lazily; dropped whenever an entry is added.
    restorer: Option<AhoCorasick>,
}

impl std::fmt::Debug for Vault {
    /// Prints counts only. The contents are the thing being protected.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("entries", &self.entries.len())
            .field("style", &self.surrogates.style())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// An empty vault that generates stand-ins with `surrogates`.
    #[must_use]
    pub fn new(surrogates: Surrogates) -> Self {
        Self {
            surrogates,
            entries: Vec::new(),
            by_real: HashMap::new(),
            by_fake: HashMap::new(),
            ordinals: HashMap::new(),
            restorer: None,
        }
    }

    /// The stand-in for a real value, creating it on first sight.
    ///
    /// Calling this twice with the same value returns the same stand-in and
    /// increments the hit count. That is the whole contract: the second
    /// mention of a colleague in a conversation has to reach the model as the
    /// same person as the first.
    pub fn substitute(&mut self, kind: &EntityKind, real: &str) -> String {
        let key = (kind.clone(), normalize(kind, real));
        if let Some(&index) = self.by_real.get(&key) {
            self.entries[index].hits += 1;
            return self.entries[index].fake.clone();
        }

        let ordinal = {
            let counter = self.ordinals.entry(kind.clone()).or_insert(0);
            *counter += 1;
            *counter
        };
        let fake = self.mint(kind, real, ordinal);

        let index = self.entries.len();
        self.entries.push(Entry {
            kind: kind.clone(),
            real: real.to_owned(),
            fake: fake.clone(),
            hits: 1,
        });
        self.by_real.insert(key, index);
        self.by_fake.insert(fake.clone(), index);
        self.restorer = None;
        fake
    }

    /// Generate a stand-in that is not already spoken for.
    ///
    /// Three things disqualify a candidate: it is already another value's
    /// stand-in, it is itself a real value in the vault, or it equals the value
    /// it is meant to hide. The first two would make restoration ambiguous;
    /// the third would silently leak.
    fn mint(&self, kind: &EntityKind, real: &str, ordinal: u32) -> String {
        self.mint_from(kind, real, ordinal, 0, None)
    }

    /// As [`Vault::mint`], starting at `start` and refusing `avoid`.
    ///
    /// Rerolling needs both: it must not hand back the stand-in it was asked
    /// to replace, and it must not start from the attempt that produced it.
    fn mint_from(
        &self,
        kind: &EntityKind,
        real: &str,
        ordinal: u32,
        start: u32,
        avoid: Option<&str>,
    ) -> String {
        for attempt in start..start.saturating_add(MAX_GENERATION_ATTEMPTS) {
            let candidate = self.surrogates.generate(kind, real, ordinal, attempt);
            let collides = candidate == real
                || Some(candidate.as_str()) == avoid
                || self.by_fake.contains_key(&candidate)
                || self
                    .by_real
                    .contains_key(&(kind.clone(), normalize(kind, &candidate)));
            if !collides {
                return candidate;
            }
        }
        // Unreachable with any sane rule set, but a wrong answer here would be
        // a silent leak, so make it a loud, unique, obviously-synthetic value.
        format!(
            "[[{}_{ordinal}_EXHAUSTED]]",
            kind.as_str().to_ascii_uppercase()
        )
    }

    /// The entry a stand-in came from, if this vault minted it.
    #[must_use]
    pub fn lookup(&self, fake: &str) -> Option<&Entry> {
        self.by_fake.get(fake).map(|&index| &self.entries[index])
    }

    /// Give an already-substituted value a different stand-in.
    ///
    /// Returns the updated entry, or `None` if the value was never
    /// substituted. Matching follows the same normalization as
    /// [`Vault::substitute`], so the spelling given here does not have to be
    /// the spelling first seen.
    ///
    /// Text already sent to a model still contains the old stand-in, and
    /// restoring it will no longer work. That is the tradeoff a reroll makes:
    /// it exists for the case where a stand-in reads badly or collides with
    /// something in the surrounding text, before the text has gone anywhere.
    pub fn reroll(&mut self, real: &str) -> Option<Entry> {
        let index = self.entries.iter().position(|entry| {
            entry.real == real
                || normalize(&entry.kind, &entry.real) == normalize(&entry.kind, real)
        })?;

        let (kind, seen_as, old_fake) = {
            let entry = &self.entries[index];
            (entry.kind.clone(), entry.real.clone(), entry.fake.clone())
        };

        self.by_fake.remove(&old_fake);
        let ordinal = {
            let counter = self.ordinals.entry(kind.clone()).or_insert(0);
            *counter += 1;
            *counter
        };
        let fresh = self.mint_from(&kind, &seen_as, ordinal, 1, Some(&old_fake));

        self.entries[index].fake.clone_from(&fresh);
        self.by_fake.insert(fresh, index);
        self.restorer = None;
        Some(self.entries[index].clone())
    }

    /// Replace every known stand-in in `text` with the value it replaced.
    ///
    /// Longest match wins, so a stand-in that happens to be a prefix of another
    /// cannot eat it. Text containing no stand-ins comes back untouched.
    ///
    /// # Panics
    ///
    /// Panics if the stand-in matcher cannot be built. The stand-ins are plain
    /// literal strings, so this cannot happen short of an allocation failure.
    pub fn restore(&mut self, text: &str) -> String {
        if self.entries.is_empty() {
            return text.to_owned();
        }
        self.ensure_restorer();
        let automaton = self.restorer.as_ref().expect("just built");

        let mut out = String::with_capacity(text.len());
        let mut last = 0usize;
        for hit in automaton.find_iter(text) {
            out.push_str(&text[last..hit.start()]);
            out.push_str(&self.entries[hit.pattern().as_usize()].real);
            last = hit.end();
        }
        out.push_str(&text[last..]);
        out
    }

    /// Restore a growing buffer, holding back what might still be incomplete.
    ///
    /// Returns the restored text to emit and how many bytes of `text` it
    /// consumed. The caller keeps `text[consumed..]` and prepends it to the
    /// next chunk.
    ///
    /// This exists because a stream delivers a stand-in a few characters at a
    /// time. Emitting eagerly would cut a stand-in in half and leave both
    /// halves unrestorable forever. Holding back a fixed number of bytes is
    /// not enough either: the cut can still land in the middle of a stand-in
    /// that has already fully arrived. So the decision is made from the actual
    /// match positions — everything up to the last point where a *future*
    /// match could still begin is safe to emit, and nothing before it is held.
    ///
    /// On an empty vault this consumes everything and restores nothing, so a
    /// caller with no substitutions pays no latency.
    ///
    /// # Panics
    ///
    /// Panics if the stand-in matcher cannot be built. The stand-ins are plain
    /// literal strings, so this cannot happen short of an allocation failure.
    pub fn restore_streaming(&mut self, text: &str) -> (String, usize) {
        if self.entries.is_empty() {
            return (text.to_owned(), text.len());
        }
        // A match that has not fully arrived must start within the last
        // `longest - 1` bytes, so everything before that is settled.
        let hold = self.longest_surrogate().saturating_sub(1);
        if text.len() <= hold {
            return (String::new(), 0);
        }
        let limit = text.len() - hold;

        self.ensure_restorer();
        let automaton = self.restorer.as_ref().expect("just built");

        let mut out = String::with_capacity(limit);
        let mut last = 0usize;
        for hit in automaton.find_iter(text) {
            if hit.start() >= limit {
                // Close enough to the end that a longer stand-in starting here
                // might still be arriving. Leave it for the next chunk.
                break;
            }
            out.push_str(&text[last..hit.start()]);
            out.push_str(&self.entries[hit.pattern().as_usize()].real);
            last = hit.end();
        }

        // No match starts between `last` and `limit`, or the loop would have
        // returned it, so that stretch is safe to emit verbatim.
        let mut consumed = limit.max(last);
        while consumed > last && !text.is_char_boundary(consumed) {
            consumed -= 1;
        }
        out.push_str(&text[last..consumed]);
        (out, consumed)
    }

    /// How many stand-ins would be replaced in `text`, without rewriting it.
    ///
    /// # Panics
    ///
    /// Panics if the stand-in matcher cannot be built. The stand-ins are plain
    /// literal strings, so this cannot happen short of an allocation failure.
    pub fn count_restorable(&mut self, text: &str) -> usize {
        if self.entries.is_empty() {
            return 0;
        }
        self.ensure_restorer();
        self.restorer
            .as_ref()
            .expect("just built")
            .find_iter(text)
            .count()
    }

    /// Build the stand-in matcher if an entry has been added since the last one.
    fn ensure_restorer(&mut self) {
        if self.restorer.is_some() {
            return;
        }
        self.restorer = Some(
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(self.entries.iter().map(|entry| entry.fake.as_str()))
                .expect("stand-ins are a plain literal set"),
        );
    }

    /// Every substitution made, in the order it was first made.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Number of distinct values substituted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Length in bytes of the longest stand-in in the vault.
    ///
    /// A streaming consumer needs this: to restore a stand-in that arrives
    /// split across two chunks, it has to hold back one byte less than this
    /// before emitting anything.
    #[must_use]
    pub fn longest_surrogate(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| entry.fake.len())
            .max()
            .unwrap_or(0)
    }

    /// Whether this exact string is a stand-in this vault minted.
    #[must_use]
    pub fn is_surrogate(&self, text: &str) -> bool {
        self.by_fake.contains_key(text)
    }

    /// Whether anything has been substituted yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The generator, for reuse across vaults sharing a seed.
    #[must_use]
    pub const fn surrogates(&self) -> &Surrogates {
        &self.surrogates
    }

    /// Discard every substitution, keeping the seed.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.by_real.clear();
        self.by_fake.clear();
        self.ordinals.clear();
        self.restorer = None;
    }

    /// Write the vault to disk, readable only by its owner.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created or the file
    /// cannot be written.
    ///
    /// # Panics
    ///
    /// Panics if the vault cannot be serialized. Its contents are strings and
    /// integers, so this cannot happen.
    pub fn save(&self, path: &Path) -> Result<(), VaultError> {
        let io_err = |source: io::Error| VaultError::Io {
            path: path.display().to_string(),
            source,
        };

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(io_err)?;
        }

        let file = VaultFile {
            version: FORMAT_VERSION,
            seed: to_hex(self.surrogates.seed()),
            style: self.surrogates.style(),
            entries: self.entries.clone(),
        };
        let encoded = serde_json::to_vec_pretty(&file)
            .expect("vault contents are plain strings and always serialize");

        // Create the file with restrictive permissions before any bytes land
        // in it, rather than writing first and tightening afterwards.
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut handle = options.open(path).map_err(io_err)?;
        io::Write::write_all(&mut handle, &encoded).map_err(io_err)?;
        io::Write::flush(&mut handle).map_err(io_err)
    }

    /// Read a vault back from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file is missing, unreadable, malformed, or
    /// written by an incompatible version.
    pub fn load(path: &Path) -> Result<Self, VaultError> {
        let bytes = fs::read(path).map_err(|source| VaultError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let file: VaultFile =
            serde_json::from_slice(&bytes).map_err(|source| VaultError::Malformed {
                path: path.display().to_string(),
                source,
            })?;
        if file.version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion {
                path: path.display().to_string(),
                found: file.version,
            });
        }

        let seed = from_hex(&file.seed).ok_or_else(|| VaultError::Malformed {
            path: path.display().to_string(),
            source: <serde_json::Error as serde::de::Error>::custom(
                "seed is not 32 hex-encoded bytes",
            ),
        })?;

        let mut vault = Self::new(Surrogates::from_seed(seed, file.style));
        for entry in file.entries {
            let index = vault.entries.len();
            let ordinal = vault.ordinals.entry(entry.kind.clone()).or_insert(0);
            *ordinal += 1;
            vault.by_real.insert(
                (entry.kind.clone(), normalize(&entry.kind, &entry.real)),
                index,
            );
            vault.by_fake.insert(entry.fake.clone(), index);
            vault.entries.push(entry);
        }
        Ok(vault)
    }

    /// Load the vault at `path`, or start an empty one if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error for any failure other than the file being absent. A
    /// corrupt vault is reported rather than silently replaced, because
    /// discarding it would strand every stand-in already sent to a model.
    pub fn load_or_new(path: &Path, surrogates: Surrogates) -> Result<Self, VaultError> {
        match Self::load(path) {
            Ok(vault) => Ok(vault),
            Err(VaultError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                Ok(Self::new(surrogates))
            }
            Err(other) => Err(other),
        }
    }
}

/// The key under which two spellings of the same value are treated as one.
///
/// Case for anything addressable, punctuation for anything numeric. The entry
/// still stores the original spelling, so restoring a stand-in gives back the
/// form it was first seen in, not the normalized one.
fn normalize(kind: &EntityKind, value: &str) -> String {
    match kind {
        EntityKind::EmailAddress
        | EntityKind::Hostname
        | EntityKind::Url
        | EntityKind::S3Uri
        | EntityKind::DatabaseUrl
        | EntityKind::MacAddress
        | EntityKind::IpV6 => value.to_ascii_lowercase(),

        EntityKind::CreditCard
        | EntityKind::PhoneNumber
        | EntityKind::Iban
        | EntityKind::BankRouting
        | EntityKind::NationalId => value
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_uppercase())
            .collect(),

        _ => value.to_owned(),
    }
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    seed: String,
    #[serde(default)]
    style: Style,
    entries: Vec<Entry>,
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn from_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let hex = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(hex, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    fn vault() -> Vault {
        Vault::new(Surrogates::from_secret(b"vault test", Style::Realistic))
    }

    #[test]
    fn the_same_value_always_gets_the_same_stand_in() {
        let mut vault = vault();
        let first = vault.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        let second = vault.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        assert_eq!(first, second);
        assert_eq!(vault.len(), 1);
        assert_eq!(vault.entries()[0].hits, 2);
    }

    #[test]
    fn different_values_get_different_stand_ins() {
        let mut vault = vault();
        let a = vault.substitute(&EntityKind::EmailAddress, "a@corp.com");
        let b = vault.substitute(&EntityKind::EmailAddress, "b@corp.com");
        assert_ne!(a, b);
        assert_eq!(vault.len(), 2);
    }

    #[test]
    fn case_differences_collapse_for_addressable_kinds() {
        let mut vault = vault();
        let lower = vault.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        let upper = vault.substitute(&EntityKind::EmailAddress, "DANA@CORP.COM");
        assert_eq!(lower, upper);
        assert_eq!(vault.len(), 1);
    }

    #[test]
    fn punctuation_differences_collapse_for_numeric_kinds() {
        let mut vault = vault();
        let spaced = vault.substitute(&EntityKind::CreditCard, fixtures::TEST_CARD_SPACED);
        let tight = vault.substitute(&EntityKind::CreditCard, fixtures::TEST_CARD);
        assert_eq!(spaced, tight);
    }

    #[test]
    fn case_matters_for_passwords() {
        let mut vault = vault();
        let lower = vault.substitute(&EntityKind::PasswordAssignment, "hunter2swordfish");
        let upper = vault.substitute(&EntityKind::PasswordAssignment, "Hunter2Swordfish");
        assert_ne!(
            lower, upper,
            "a password differing only in case is a different password"
        );
    }

    #[test]
    fn restore_reverses_substitute() {
        let mut vault = vault();
        let fake = vault.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        let scrubbed = format!("mail {fake} about the invoice");
        assert_eq!(
            vault.restore(&scrubbed),
            "mail dana@corp.com about the invoice"
        );
    }

    #[test]
    fn restore_leaves_unknown_text_alone() {
        let mut vault = vault();
        vault.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        let text = "nothing here was ever substituted";
        assert_eq!(vault.restore(text), text);
    }

    #[test]
    fn restore_handles_repeated_and_adjacent_stand_ins() {
        let mut vault = vault();
        let a = vault.substitute(&EntityKind::EmailAddress, "a@corp.com");
        let b = vault.substitute(&EntityKind::EmailAddress, "b@corp.com");
        let text = format!("{a} {b} {a}");
        assert_eq!(vault.restore(&text), "a@corp.com b@corp.com a@corp.com");
    }

    #[test]
    fn an_entry_added_after_a_restore_is_still_restored() {
        let mut vault = vault();
        let first = vault.substitute(&EntityKind::EmailAddress, "a@corp.com");
        assert_eq!(vault.restore(&first), "a@corp.com");
        let second = vault.substitute(&EntityKind::EmailAddress, "b@corp.com");
        assert_eq!(vault.restore(&second), "b@corp.com");
    }

    #[test]
    fn a_stand_in_never_equals_the_value_it_hides() {
        let mut vault = vault();
        for real in ["203.0.113.9", "avery.sinclair@globex.example"] {
            let kind = if real.contains('@') {
                EntityKind::EmailAddress
            } else {
                EntityKind::IpV4
            };
            let fake = vault.substitute(&kind, real);
            assert_ne!(fake, real);
        }
    }

    #[test]
    fn round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("cred-swap-vault-{}", std::process::id()));
        let path = dir.join("session.json");
        let mut original = vault();
        let fake = original.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        original.substitute(&EntityKind::AwsAccessKeyId, fixtures::AWS_ACCESS_KEY_ID);
        original.save(&path).unwrap();

        let mut reloaded = Vault::load(&path).unwrap();
        assert_eq!(reloaded.len(), 2);
        assert_eq!(reloaded.restore(&fake), "dana@corp.com");
        // The seed survives, so a value seen only after reloading still gets
        // the stand-in it would have got in the original session.
        assert_eq!(
            reloaded.substitute(&EntityKind::EmailAddress, "new@corp.com"),
            original.substitute(&EntityKind::EmailAddress, "new@corp.com")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("cred-swap-perm-{}", std::process::id()));
        let path = dir.join("session.json");
        let mut v = vault();
        v.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        v.save(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "vault is readable by others");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_starts_an_empty_session() {
        let path = std::env::temp_dir().join("cred-swap-does-not-exist-xyz/session.json");
        let vault =
            Vault::load_or_new(&path, Surrogates::from_secret(b"s", Style::Realistic)).unwrap();
        assert!(vault.is_empty());
    }

    #[test]
    fn a_corrupt_file_is_reported_not_discarded() {
        let dir = std::env::temp_dir().join(format!("cred-swap-corrupt-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.json");
        fs::write(&path, b"{ not json").unwrap();
        let error =
            Vault::load_or_new(&path, Surrogates::from_secret(b"s", Style::Realistic)).unwrap_err();
        assert!(matches!(error, VaultError::Malformed { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn debug_output_does_not_leak_contents() {
        let mut vault = vault();
        vault.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        let rendered = format!("{vault:?}");
        assert!(!rendered.contains("dana"), "{rendered}");
    }

    #[test]
    fn reroll_changes_the_stand_in_and_keeps_the_original() {
        let mut vault = vault();
        let first = vault.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        let entry = vault
            .reroll("dana@corp.com")
            .expect("value is in the vault");
        assert_ne!(entry.fake, first);
        assert_eq!(entry.real, "dana@corp.com");
        assert_eq!(vault.len(), 1);
    }

    #[test]
    fn a_rerolled_stand_in_restores_and_the_old_one_no_longer_does() {
        let mut vault = vault();
        let old = vault.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        let new = vault.reroll("dana@corp.com").unwrap().fake;
        assert_eq!(vault.restore(&new), "dana@corp.com");
        assert_eq!(
            vault.restore(&old),
            old,
            "the retired stand-in still resolved"
        );
    }

    #[test]
    fn rerolling_matches_a_differently_spelled_original() {
        let mut vault = vault();
        vault.substitute(&EntityKind::EmailAddress, "Dana@Corp.com");
        assert!(vault.reroll("dana@corp.com").is_some());
    }

    #[test]
    fn rerolling_an_unknown_value_reports_it() {
        let mut vault = vault();
        assert!(vault.reroll("never-seen@corp.com").is_none());
    }

    /// Feed `text` through `restore_streaming` one byte at a time.
    fn drip(vault: &mut Vault, text: &str) -> String {
        let mut buffer = String::new();
        let mut out = String::new();
        for byte in text.as_bytes() {
            buffer.push(*byte as char);
            let (emitted, consumed) = vault.restore_streaming(&buffer);
            out.push_str(&emitted);
            buffer.drain(..consumed);
        }
        let (tail, ()) = (vault.restore(&buffer), ());
        out.push_str(&tail);
        out
    }

    #[test]
    fn streaming_restores_a_stand_in_delivered_one_byte_at_a_time() {
        let mut vault = vault();
        let fake = vault.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        let stream = format!("please email {fake} about it");
        assert_eq!(
            drip(&mut vault, &stream),
            "please email dana@corp.com about it"
        );
    }

    #[test]
    fn streaming_handles_a_stand_in_at_the_very_end() {
        let mut vault = vault();
        let fake = vault.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        let stream = format!("write to {fake}");
        assert_eq!(drip(&mut vault, &stream), "write to dana@corp.com");
    }

    #[test]
    fn streaming_handles_back_to_back_stand_ins() {
        let mut vault = vault();
        let a = vault.substitute(&EntityKind::EmailAddress, "a@corp.com");
        let b = vault.substitute(&EntityKind::EmailAddress, "b@corp.com");
        let stream = format!("{a} {b}");
        assert_eq!(drip(&mut vault, &stream), "a@corp.com b@corp.com");
    }

    #[test]
    fn streaming_never_emits_a_partial_stand_in() {
        let mut vault = vault();
        let fake = vault.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        let stream = format!("to {fake} now");

        let mut buffer = String::new();
        let mut emitted = String::new();
        for byte in stream.as_bytes() {
            buffer.push(*byte as char);
            let (chunk, consumed) = vault.restore_streaming(&buffer);
            emitted.push_str(&chunk);
            buffer.drain(..consumed);
            // At no point may a fragment of the stand-in reach the output.
            for length in 4..fake.len() {
                assert!(
                    !emitted.contains(&fake[..length]),
                    "leaked the first {length} characters of the stand-in"
                );
            }
        }
    }

    #[test]
    fn streaming_on_an_empty_vault_consumes_everything() {
        let mut vault = vault();
        let (out, consumed) = vault.restore_streaming("nothing to do here");
        assert_eq!(out, "nothing to do here");
        assert_eq!(consumed, "nothing to do here".len());
    }

    #[test]
    fn streaming_does_not_split_a_multibyte_character() {
        let mut vault = vault();
        vault.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        let text = "café — naïve, 🙂 and more text besides to push past the hold";
        let (out, consumed) = vault.restore_streaming(text);
        assert!(text.is_char_boundary(consumed));
        assert!(text.starts_with(&out));
    }

    #[test]
    fn longest_surrogate_tracks_the_widest_entry() {
        let mut vault = vault();
        assert_eq!(vault.longest_surrogate(), 0);
        let fake = vault.substitute(&EntityKind::EmailAddress, "dana@corp.com");
        assert_eq!(vault.longest_surrogate(), fake.len());
        let key = vault.substitute(&EntityKind::AnthropicKey, &fixtures::anthropic_key());
        assert_eq!(vault.longest_surrogate(), key.len().max(fake.len()));
        assert!(vault.is_surrogate(&key));
        assert!(!vault.is_surrogate("something else"));
    }

    #[test]
    fn hex_round_trips() {
        let seed = [0xabu8; 32];
        assert_eq!(from_hex(&to_hex(&seed)), Some(seed));
        assert_eq!(from_hex("nope"), None);
    }
}

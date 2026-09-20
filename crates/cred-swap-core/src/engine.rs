//! Scrubbing text and putting it back.

use serde::{Deserialize, Serialize};

use crate::detect::{Detector, DetectorError, Finding};
use crate::entity::EntityKind;
use crate::fake::Surrogates;
use crate::policy::Policy;
use crate::vault::Vault;

/// What the caller decided about one finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Substitute a stand-in for it.
    Replace,
    /// Leave the original text in place.
    Keep,
}

/// One substitution that was actually made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replacement {
    /// What kind of value it was.
    pub kind: EntityKind,
    /// The original text.
    pub real: String,
    /// What went out in its place.
    pub fake: String,
    /// Byte offset of the value in the *original* text.
    pub source_start: usize,
    /// Byte offset one past the value in the *original* text.
    pub source_end: usize,
}

/// The result of a scrub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scrubbed {
    /// The text as it should now be sent.
    pub text: String,
    /// Every substitution made, in document order.
    pub replacements: Vec<Replacement>,
    /// Findings the caller chose to leave in place.
    pub kept: Vec<Finding>,
    /// Findings dropped because they overlapped one already applied.
    ///
    /// Always empty for [`Cloak::scrub`] and [`Cloak::scrub_with`], whose
    /// findings come from the detector and cannot overlap. Non-empty only when
    /// a caller hands [`Cloak::scrub_findings`] a list that does, and then it
    /// is the answer to "why is that still in the text".
    pub skipped: Vec<Finding>,
}

impl Scrubbed {
    /// Whether anything was changed.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.replacements.is_empty()
    }

    /// Distinct kinds substituted, in document order of first appearance.
    #[must_use]
    pub fn kinds(&self) -> Vec<EntityKind> {
        let mut seen = Vec::new();
        for replacement in &self.replacements {
            if !seen.contains(&replacement.kind) {
                seen.push(replacement.kind.clone());
            }
        }
        seen
    }
}

/// Detection, substitution and restoration wired together.
///
/// This is the type an application holds for the life of a conversation. It
/// owns the vault, so every scrub it performs is consistent with every scrub
/// before it, and every response it restores maps back to the right originals.
pub struct Cloak {
    detector: Detector,
    vault: Vault,
}

impl std::fmt::Debug for Cloak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cloak")
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

impl Cloak {
    /// Build a cloak from a policy and a stand-in generator.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy contains a custom pattern that does not
    /// compile.
    pub fn new(policy: Policy, surrogates: Surrogates) -> Result<Self, DetectorError> {
        Ok(Self {
            detector: Detector::new(policy)?,
            vault: Vault::new(surrogates),
        })
    }

    /// Build a cloak around an existing vault, resuming its session.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy contains a custom pattern that does not
    /// compile.
    pub fn resume(policy: Policy, vault: Vault) -> Result<Self, DetectorError> {
        Ok(Self {
            detector: Detector::new(policy)?,
            vault,
        })
    }

    /// Report what would be substituted, changing nothing.
    ///
    /// This is what a review step shows the user before anything is sent.
    #[must_use]
    pub fn inspect(&self, text: &str) -> Vec<Finding> {
        self.detector.scan(text)
    }

    /// Replace every detected value with its stand-in.
    pub fn scrub(&mut self, text: &str) -> Scrubbed {
        self.scrub_with(text, |_| Decision::Replace)
    }

    /// Replace detected values, asking `decide` about each one.
    ///
    /// Findings are visited in document order, which is the order a reviewer
    /// reads them in.
    ///
    /// A finding whose text is already a stand-in this vault minted is passed
    /// through untouched and `decide` is not consulted about it. This matters
    /// more than it sounds: in a multi-turn conversation the earlier turns come
    /// back in every request, already scrubbed. Without this, a stand-in email
    /// address would be detected as an email address and replaced by a second
    /// stand-in on the next turn, and a third on the turn after, until nothing
    /// could be restored and the model lost track of who it was talking about.
    pub fn scrub_with(&mut self, text: &str, decide: impl FnMut(&Finding) -> Decision) -> Scrubbed {
        let findings = self.detector.scan(text);
        debug_assert!(
            findings.windows(2).all(|pair| pair[0].end <= pair[1].start),
            "the detector returned overlapping or unordered spans"
        );
        self.apply(text, findings, decide)
    }

    /// Rewrite `text` according to `findings`, which must be ordered and
    /// non-overlapping.
    fn apply(
        &mut self,
        text: &str,
        findings: Vec<Finding>,
        mut decide: impl FnMut(&Finding) -> Decision,
    ) -> Scrubbed {
        let mut out = String::with_capacity(text.len());
        let mut replacements = Vec::new();
        let mut kept = Vec::new();
        let mut skipped = Vec::new();
        let mut cursor = 0usize;

        for finding in findings {
            // A monotonic cursor is all this needs, so a span that starts
            // behind the cursor is dropped rather than sliced backwards. There
            // is no assertion here on purpose: `scrub_findings` takes a list
            // the caller assembled, where an overlap is bad input rather than
            // a broken invariant, and panicking half way through a rewrite
            // leaves them unable to tell how much was already replaced. The
            // invariant is asserted in `scrub_with`, where it really is one.
            if finding.start < cursor {
                skipped.push(finding);
                continue;
            }
            out.push_str(&text[cursor..finding.start]);
            cursor = finding.end;

            if self.vault.lookup(&finding.text).is_some() {
                out.push_str(&finding.text);
                continue;
            }

            match decide(&finding) {
                Decision::Replace => {
                    let fake = self.vault.substitute(&finding.kind, &finding.text);
                    out.push_str(&fake);
                    replacements.push(Replacement {
                        kind: finding.kind,
                        real: finding.text,
                        fake,
                        source_start: finding.start,
                        source_end: finding.end,
                    });
                }
                Decision::Keep => {
                    out.push_str(&finding.text);
                    kept.push(finding);
                }
            }
        }
        out.push_str(&text[cursor..]);

        Scrubbed {
            text: out,
            replacements,
            kept,
            skipped,
        }
    }

    /// Scrub using a finding list the caller assembled.
    ///
    /// This is the seam for anything the rules cannot do on their own. Take
    /// [`Cloak::inspect`], put the spans a judge should see through
    /// [`candidates`], fold the verdicts back in with [`merge`], and hand the
    /// result here. The vault, the stand-ins and the restore path are the same
    /// ones the rules use, so a judged finding restores exactly like any other.
    ///
    /// `findings` should not overlap and should be in document order, which is
    /// what [`merge`] guarantees. A span that overlaps one already applied is
    /// dropped and reported in [`Scrubbed::skipped`], rather than panicking
    /// half way through a rewrite the caller cannot then inspect.
    ///
    /// [`candidates`]: crate::detect::candidates::candidates
    /// [`merge`]: crate::detect::merge
    pub fn scrub_findings(
        &mut self,
        text: &str,
        findings: Vec<Finding>,
        decide: impl FnMut(&Finding) -> Decision,
    ) -> Scrubbed {
        self.apply(text, findings, decide)
    }

    /// Put the real values back wherever a stand-in appears.
    pub fn restore(&mut self, text: &str) -> String {
        self.vault.restore(text)
    }

    /// Restore a growing buffer, holding back what might still be incomplete.
    ///
    /// See [`Vault::restore_streaming`] for the contract. Use this when text
    /// arrives in pieces, such as a streamed model response.
    ///
    /// [`Vault::restore_streaming`]: crate::vault::Vault::restore_streaming
    pub fn restore_streaming(&mut self, text: &str) -> (String, usize) {
        self.vault.restore_streaming(text)
    }

    /// The vault backing this session.
    #[must_use]
    pub const fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Mutable access to the vault, for saving or clearing it.
    pub const fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }

    /// The policy in force.
    #[must_use]
    pub const fn policy(&self) -> &Policy {
        self.detector.policy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::Style;
    use crate::fixtures;

    fn cloak() -> Cloak {
        Cloak::new(
            Policy::default(),
            Surrogates::from_secret(b"engine test", Style::Realistic),
        )
        .unwrap()
    }

    #[test]
    fn scrub_then_restore_is_the_identity() {
        let mut cloak = cloak();
        let original = format!(
            "Email dana@corp.com or call +1 415 867 5309. Key: {}",
            fixtures::AWS_ACCESS_KEY_ID
        );
        let scrubbed = cloak.scrub(&original);
        assert_ne!(scrubbed.text, original);
        assert_eq!(cloak.restore(&scrubbed.text), original);
    }

    #[test]
    fn text_with_nothing_sensitive_passes_through_unchanged() {
        let mut cloak = cloak();
        let original = "Rewrite this loop to avoid the intermediate allocation.";
        let scrubbed = cloak.scrub(original);
        assert_eq!(scrubbed.text, original);
        assert!(scrubbed.is_clean());
    }

    #[test]
    fn the_same_value_twice_in_one_message_gets_one_stand_in() {
        let mut cloak = cloak();
        let scrubbed = cloak.scrub("from dana@corp.com to dana@corp.com");
        assert_eq!(scrubbed.replacements.len(), 2);
        assert_eq!(scrubbed.replacements[0].fake, scrubbed.replacements[1].fake);
        assert_eq!(cloak.vault().len(), 1);
    }

    #[test]
    fn stand_ins_persist_across_separate_messages() {
        let mut cloak = cloak();
        let first = cloak.scrub("ping dana@corp.com");
        let second = cloak.scrub("dana@corp.com replied");
        assert_eq!(first.replacements[0].fake, second.replacements[0].fake);
    }

    #[test]
    fn kept_findings_survive_verbatim() {
        let mut cloak = cloak();
        let scrubbed = cloak.scrub_with("mail dana@corp.com now", |finding| {
            if finding.kind == EntityKind::EmailAddress {
                Decision::Keep
            } else {
                Decision::Replace
            }
        });
        assert_eq!(scrubbed.text, "mail dana@corp.com now");
        assert_eq!(scrubbed.kept.len(), 1);
        assert!(scrubbed.replacements.is_empty());
    }

    #[test]
    fn offsets_point_into_the_original_text() {
        let mut cloak = cloak();
        let original = "reach dana@corp.com today";
        let scrubbed = cloak.scrub(original);
        let replacement = &scrubbed.replacements[0];
        assert_eq!(
            &original[replacement.source_start..replacement.source_end],
            replacement.real
        );
    }

    #[test]
    fn multibyte_text_is_not_corrupted() {
        let mut cloak = cloak();
        let original = "Café — write to dana@corp.com 🙂 done";
        let scrubbed = cloak.scrub(original);
        assert!(scrubbed.text.starts_with("Café — write to "));
        assert!(scrubbed.text.ends_with(" 🙂 done"));
        assert_eq!(cloak.restore(&scrubbed.text), original);
    }

    #[test]
    fn a_scrub_leaves_nothing_sensitive_behind() {
        let mut cloak = cloak();
        let original = format!(
            "ssn 123-45-6789, card {}, key {}",
            fixtures::TEST_CARD_SPACED,
            fixtures::AWS_ACCESS_KEY_ID
        );
        let scrubbed = cloak.scrub(&original);
        for replacement in &scrubbed.replacements {
            assert!(
                !scrubbed.text.contains(&replacement.real),
                "original {} survived the scrub",
                replacement.real
            );
        }
    }

    #[test]
    fn kinds_lists_each_kind_once_in_order() {
        let mut cloak = cloak();
        let scrubbed = cloak.scrub(&format!(
            "a@x.com, b@x.com, {}",
            fixtures::AWS_ACCESS_KEY_ID
        ));
        assert_eq!(
            scrubbed.kinds(),
            vec![EntityKind::EmailAddress, EntityKind::AwsAccessKeyId]
        );
    }

    #[test]
    fn scrubbing_twice_changes_nothing_the_second_time() {
        let mut cloak = cloak();
        let once = cloak.scrub(&format!(
            "Email dana@corp.com about {}",
            fixtures::AWS_ACCESS_KEY_ID
        ));
        let twice = cloak.scrub(&once.text);
        assert_eq!(twice.text, once.text, "stand-ins were substituted again");
        assert!(twice.replacements.is_empty());
        assert_eq!(cloak.vault().len(), 2, "a second round minted new entries");
    }

    #[test]
    fn a_conversation_stays_reversible_across_many_turns() {
        let mut cloak = cloak();
        let mut transcript = String::new();
        for turn in 0..5 {
            use std::fmt::Write as _;
            let _ = write!(transcript, "\nturn {turn}: ping dana@corp.com");
            transcript = cloak.scrub(&transcript).text;
        }
        assert!(!transcript.contains("dana@corp.com"));
        let restored = cloak.restore(&transcript);
        assert_eq!(restored.matches("dana@corp.com").count(), 5);
        assert_eq!(cloak.vault().len(), 1);
    }

    #[test]
    fn overlapping_findings_are_skipped_rather_than_panicking() {
        let mut cloak = cloak();
        let text = "contact dana@corp.com now";

        // What a caller assembling their own list can produce: a rule finding
        // and a narrower judged one over the same span.
        let findings = vec![
            Finding {
                kind: EntityKind::EmailAddress,
                start: 8,
                end: 21,
                text: "dana@corp.com".into(),
            },
            Finding {
                kind: EntityKind::PersonName,
                start: 8,
                end: 12,
                text: "dana".into(),
            },
        ];

        let scrubbed = cloak.scrub_findings(text, findings, |_| Decision::Replace);
        assert_eq!(
            scrubbed.replacements.len(),
            1,
            "the contained span was not skipped"
        );
        assert_eq!(scrubbed.skipped.len(), 1, "the drop was silent");
        assert_eq!(scrubbed.skipped[0].text, "dana");
        assert!(
            !scrubbed.text.contains("dana@corp.com"),
            "{}",
            scrubbed.text
        );
        assert!(scrubbed.text.starts_with("contact "), "{}", scrubbed.text);
        assert!(scrubbed.text.ends_with(" now"), "{}", scrubbed.text);
        assert_eq!(cloak.restore(&scrubbed.text), text);
    }

    #[test]
    fn a_judged_finding_scrubs_and_restores_like_any_other() {
        use crate::detect::candidates::{Survey, candidates};
        use crate::detect::merge;

        let mut cloak = cloak();
        let original = "Avery Sinclair approved it; mail dana@corp.com to confirm.";

        // The rules find the address and miss the name, which is the whole
        // reason a second opinion is worth paying for.
        let rules = cloak.inspect(original);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].kind, EntityKind::EmailAddress);

        // A judge says one of the candidates is a person. Anything that can
        // answer that question works here; this stands in for one.
        let judged: Vec<Finding> = candidates(original, &rules, &Survey::default())
            .into_iter()
            .filter(|candidate| candidate.text == "Avery Sinclair")
            .map(|candidate| Finding {
                kind: EntityKind::PersonName,
                start: candidate.start,
                end: candidate.end,
                text: candidate.text,
            })
            .collect();
        assert_eq!(judged.len(), 1, "the name was not put forward");

        let merged = merge(rules, judged);
        assert_eq!(merged.displaced, 0);
        let scrubbed = cloak.scrub_findings(original, merged.findings, |_| Decision::Replace);

        assert_eq!(scrubbed.replacements.len(), 2);
        assert!(
            !scrubbed.text.contains("Avery Sinclair"),
            "{}",
            scrubbed.text
        );
        assert!(
            !scrubbed.text.contains("dana@corp.com"),
            "{}",
            scrubbed.text
        );
        // And the round trip holds, which is the point: a judged finding is
        // not a redaction, it is a substitution like the rest.
        assert_eq!(cloak.restore(&scrubbed.text), original);
    }

    #[test]
    fn a_resumed_session_reuses_its_stand_ins() {
        let mut first = cloak();
        let before = first.scrub("ping dana@corp.com");
        let vault = std::mem::replace(
            first.vault_mut(),
            crate::vault::Vault::new(Surrogates::from_secret(b"x", Style::Realistic)),
        );

        let mut second = Cloak::resume(Policy::default(), vault).unwrap();
        let after = second.scrub("dana@corp.com again");
        assert_eq!(before.replacements[0].fake, after.replacements[0].fake);
    }
}

//! Finding sensitive spans in text.

pub mod candidates;
pub mod patterns;
pub mod validate;

use aho_corasick::{AhoCorasick, MatchKind};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::entity::EntityKind;
use crate::policy::Policy;

use patterns::{RULES, Rule};

/// One sensitive span located in a piece of text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// What was found.
    pub kind: EntityKind,
    /// Byte offset of the first byte of the value.
    pub start: usize,
    /// Byte offset one past the last byte of the value.
    pub end: usize,
    /// The matched text itself.
    pub text: String,
}

impl Finding {
    /// The half-open byte range this finding occupies.
    #[must_use]
    pub const fn range(&self) -> std::ops::Range<usize> {
        self.start..self.end
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// A config file asked for something that could not be compiled.
#[derive(Debug, thiserror::Error)]
pub enum DetectorError {
    /// A custom pattern failed to compile.
    #[error("custom pattern `{label}` is not a valid regex: {source}")]
    BadPattern {
        /// The rule's label, so the user can find it in their config.
        label: String,
        /// The underlying regex error.
        #[source]
        source: Box<regex::Error>,
    },
    /// A custom pattern named a capture group it does not have.
    #[error("custom pattern `{label}` has no capture group {group}")]
    MissingGroup {
        /// The rule's label.
        label: String,
        /// The group index that was requested.
        group: usize,
    },
}

/// Scans text for everything a [`Policy`] asks for.
///
/// Building one compiles the policy's custom patterns and term list, so a
/// detector is worth keeping alive across many scans rather than rebuilding
/// per request.
pub struct Detector {
    policy: Policy,
    custom: Vec<Rule>,
    terms: Option<TermMatcher>,
}

impl std::fmt::Debug for Detector {
    /// Prints the shape of the detector, not the policy's literals, which may
    /// themselves be the sensitive strings a user asked to have masked.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detector")
            .field("enabled_kinds", &self.policy.enabled.len())
            .field("custom_patterns", &self.custom.len())
            .field("terms", &self.policy.terms.len())
            .finish()
    }
}

struct TermMatcher {
    automaton: AhoCorasick,
    kinds: Vec<EntityKind>,
}

impl Detector {
    /// Compile a detector for a policy.
    ///
    /// # Errors
    ///
    /// Returns an error when a custom pattern is not a valid regex or names a
    /// capture group it does not define.
    ///
    /// # Panics
    ///
    /// Panics if the term list cannot be compiled into a matcher. The terms
    /// are plain literal strings with no syntax to get wrong, so this cannot
    /// happen short of an allocation failure.
    pub fn new(mut policy: Policy) -> Result<Self, DetectorError> {
        // Writing a custom rule is itself the act of enabling it. Requiring the
        // user to also list its label under `enabled` would be a trap that
        // fails silently, which is the worst way for this tool to fail.
        for spec in &policy.custom_patterns {
            policy
                .enabled
                .insert(EntityKind::Custom(spec.label.clone()));
        }
        for term in &policy.terms {
            policy.enabled.insert(term.kind.clone());
        }

        let mut custom = Vec::with_capacity(policy.custom_patterns.len());
        for spec in &policy.custom_patterns {
            let regex = Regex::new(&spec.pattern).map_err(|source| DetectorError::BadPattern {
                label: spec.label.clone(),
                source: Box::new(source),
            })?;
            if spec.group >= regex.captures_len() {
                return Err(DetectorError::MissingGroup {
                    label: spec.label.clone(),
                    group: spec.group,
                });
            }
            custom.push(Rule {
                kind: EntityKind::Custom(spec.label.clone()),
                regex,
                group: spec.group,
                validate: None,
                default_on: true,
            });
        }

        let terms = if policy.terms.is_empty() {
            None
        } else {
            let automaton = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostLongest)
                .build(policy.terms.iter().map(|term| term.literal.as_str()))
                .expect("term list is a plain literal set");
            let kinds = policy.terms.iter().map(|term| term.kind.clone()).collect();
            Some(TermMatcher { automaton, kinds })
        };

        Ok(Self {
            policy,
            custom,
            terms,
        })
    }

    /// The policy this detector was built from.
    #[must_use]
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Locate every in-scope sensitive span, ordered by position.
    ///
    /// Overlapping candidates are resolved before returning: the returned
    /// findings never overlap, so a caller can replace them left to right.
    #[must_use]
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut candidates = Vec::new();

        for rule in RULES.iter().chain(self.custom.iter()) {
            if !self.policy.is_enabled(&rule.kind) {
                continue;
            }
            self.collect_rule(rule, text, &mut candidates);
        }

        if let Some(matcher) = &self.terms {
            self.collect_terms(matcher, text, &mut candidates);
        }

        resolve_overlaps(candidates)
    }

    fn collect_rule(&self, rule: &Rule, text: &str, out: &mut Vec<Finding>) {
        for captures in rule.regex.captures_iter(text) {
            // A branch of an alternation may not participate in the match, in
            // which case fall back to the whole match rather than dropping it.
            let Some(matched) = captures.get(rule.group).or_else(|| captures.get(0)) else {
                continue;
            };
            let value = matched.as_str();
            if let Some(check) = rule.validate
                && !check(value)
            {
                continue;
            }
            if self.policy.is_allowed(value) {
                continue;
            }
            out.push(Finding {
                kind: rule.kind.clone(),
                start: matched.start(),
                end: matched.end(),
                text: value.to_owned(),
            });
        }
    }

    fn collect_terms(&self, matcher: &TermMatcher, text: &str, out: &mut Vec<Finding>) {
        for hit in matcher.automaton.find_iter(text) {
            let value = &text[hit.start()..hit.end()];
            if self.policy.is_allowed(value) {
                continue;
            }
            if !has_word_boundaries(text, hit.start(), hit.end()) {
                continue;
            }
            out.push(Finding {
                kind: matcher.kinds[hit.pattern().as_usize()].clone(),
                start: hit.start(),
                end: hit.end(),
                text: value.to_owned(),
            });
        }
    }
}

/// Reject a literal term hit that sits inside a longer word.
///
/// Without this, a term like `ada` masks the middle of `adapter`.
fn has_word_boundaries(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    !before.is_some_and(is_word) && !after.is_some_and(is_word)
}

/// Combine findings from more than one source into one ordered, non-overlapping list.
///
/// Use it to fold a classifier's verdicts in beside the rules'. Precedence
/// decides who wins where two claim the same span, so a rule that knows
/// exactly what it found beats a judgement that something looked personal.
///
/// The result is safe to hand to [`crate::Cloak::scrub_findings`].
#[must_use]
pub fn merge(rules: Vec<Finding>, judged: Vec<Finding>) -> Vec<Finding> {
    let mut all = rules;
    all.extend(judged);
    resolve_overlaps(all)
}

/// Pick a non-overlapping subset of candidates and sort it by position.
///
/// Two rules routinely claim the same span: a vendor key is also a generic
/// secret, a card number is also a phone number. The winner is the most
/// specific rule, then the longest match, then the earliest.
fn resolve_overlaps(mut candidates: Vec<Finding>) -> Vec<Finding> {
    candidates.sort_by(|a, b| {
        b.kind
            .precedence()
            .cmp(&a.kind.precedence())
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
            .then_with(|| a.start.cmp(&b.start))
            .then_with(|| a.kind.cmp(&b.kind))
    });

    let mut accepted: Vec<Finding> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if accepted.iter().any(|kept| kept.overlaps(&candidate)) {
            continue;
        }
        accepted.push(candidate);
    }
    accepted.sort_by_key(|finding| finding.start);
    accepted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use crate::policy::Policy;

    fn scan(text: &str) -> Vec<Finding> {
        Detector::new(Policy::default()).unwrap().scan(text)
    }

    fn kinds(text: &str) -> Vec<EntityKind> {
        scan(text).into_iter().map(|finding| finding.kind).collect()
    }

    #[test]
    fn findings_come_back_in_document_order() {
        let text = "mail bob@example.com then call +1 415 555 0132";
        let found = scan(text);
        assert_eq!(found.len(), 2);
        assert!(found[0].start < found[1].start);
        assert_eq!(found[0].kind, EntityKind::EmailAddress);
        assert_eq!(found[1].kind, EntityKind::PhoneNumber);
    }

    #[test]
    fn findings_never_overlap() {
        let text = format!(
            "aws_secret_access_key = {} and {}",
            fixtures::AWS_SECRET_ACCESS_KEY,
            fixtures::AWS_ACCESS_KEY_ID
        );
        let found = scan(&text);
        for pair in found.windows(2) {
            assert!(pair[0].end <= pair[1].start, "overlap: {pair:?}");
        }
    }

    #[test]
    fn specific_vendor_rule_beats_the_generic_one() {
        let anthropic = fixtures::anthropic_key();
        assert_eq!(kinds(&anthropic), vec![EntityKind::AnthropicKey]);
    }

    #[test]
    fn a_dotted_quad_is_an_address_not_a_phone_number() {
        // 198.51.100.44 is ten digits separated by dots, which also satisfies
        // the phone rule. The address reading is the correct one.
        for text in ["198.51.100.44", "203.0.113.128", "192.168.100.200"] {
            assert_eq!(kinds(text), vec![EntityKind::IpV4], "{text}");
        }
    }

    #[test]
    fn a_dotted_phone_number_is_still_a_phone_number() {
        // Three groups, and a final group too long to be an octet, so the
        // address rule cannot claim it.
        assert_eq!(kinds("415.867.5309"), vec![EntityKind::PhoneNumber]);
    }

    #[test]
    fn offsets_index_the_original_text() {
        let text = "contact: alice@corp.dev";
        let found = scan(text);
        assert_eq!(&text[found[0].range()], "alice@corp.dev");
    }

    #[test]
    fn allowlisted_values_are_skipped() {
        let policy = Policy::default().allow("support@example.com");
        let detector = Detector::new(policy).unwrap();
        assert!(detector.scan("write to support@example.com").is_empty());
        assert_eq!(detector.scan("write to ceo@example.com").len(), 1);
    }

    #[test]
    fn custom_terms_respect_word_boundaries() {
        let policy = Policy::default().term("Ada", EntityKind::PersonName);
        let detector = Detector::new(policy).unwrap();
        assert_eq!(detector.scan("ask Ada about it").len(), 1);
        assert!(detector.scan("the adapter broke").is_empty());
    }

    #[test]
    fn custom_patterns_compile_or_report_which_one_failed() {
        let mut policy = Policy::default();
        policy.custom_patterns.push(crate::policy::CustomPattern {
            label: "ticket".into(),
            pattern: "ACME-[0-9".into(),
            group: 0,
        });
        let error = Detector::new(policy).unwrap_err();
        assert!(error.to_string().contains("ticket"));
    }

    #[test]
    fn custom_pattern_findings_carry_their_label() {
        let mut policy = Policy::default();
        policy.custom_patterns.push(crate::policy::CustomPattern {
            label: "ticket".into(),
            pattern: r"\bACME-\d{4}\b".into(),
            group: 0,
        });
        let detector = Detector::new(policy).unwrap();
        let found = detector.scan("see ACME-1234 for context");
        assert_eq!(found[0].kind, EntityKind::Custom("ticket".into()));
    }

    #[test]
    fn merging_lets_a_rule_win_over_a_judgement() {
        let rules = vec![Finding {
            kind: EntityKind::EmailAddress,
            start: 5,
            end: 18,
            text: "dana@corp.com".into(),
        }];
        // A judge that thought the same span was a person's name.
        let judged = vec![Finding {
            kind: EntityKind::PersonName,
            start: 5,
            end: 18,
            text: "dana@corp.com".into(),
        }];

        let merged = merge(rules, judged);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].kind, EntityKind::EmailAddress);
    }

    #[test]
    fn merging_keeps_both_when_they_do_not_collide() {
        let rules = vec![Finding {
            kind: EntityKind::EmailAddress,
            start: 0,
            end: 13,
            text: "dana@corp.com".into(),
        }];
        let judged = vec![Finding {
            kind: EntityKind::PersonName,
            start: 20,
            end: 34,
            text: "Avery Sinclair".into(),
        }];

        let merged = merge(rules, judged);
        assert_eq!(merged.len(), 2);
        assert!(merged[0].start < merged[1].start, "not in document order");
    }

    #[test]
    fn empty_text_finds_nothing() {
        assert!(scan("").is_empty());
    }

    #[test]
    fn prose_with_nothing_sensitive_stays_clean() {
        let found = scan("Refactor the parser so it stops allocating on every token.");
        assert!(found.is_empty(), "false positives: {found:?}");
    }
}

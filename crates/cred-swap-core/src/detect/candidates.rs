//! Spans worth asking someone else about.
//!
//! The rule table is precise and narrow. It is very good at things with a
//! defined shape and blind to a colleague's name in the middle of a sentence,
//! because no pattern can tell `Avery Sinclair` from `Bond Street` from
//! `Redis Cluster` without knowing what the sentence is about.
//!
//! A classifier can tell them apart, and cannot find them: a yes/no judge
//! answers questions, it does not return offsets. So the two halves fit
//! together the other way round from how it first looks. This module does the
//! finding — deliberately over-generously, casting far wider than the rules
//! ever would — and something with judgement does the deciding.
//!
//! Everything here is cheap and local. No network, no model, no async. The
//! expensive half belongs to the caller, which is also the only place that
//! knows what a false positive costs it.
//!
//! ```
//! use cred_swap_core::detect::candidates::{Survey, candidates};
//! use cred_swap_core::{Cloak, Policy, Style, Surrogates};
//!
//! let cloak = Cloak::new(Policy::default(), Surrogates::from_secret(b"s", Style::Realistic))?;
//! let text = "Avery Sinclair approved the Northwind migration on Tuesday.";
//!
//! let found = cloak.inspect(text);          // the rules find nothing here
//! let asking = candidates(text, &found, &Survey::default());
//! assert!(asking.iter().any(|c| c.text == "Avery Sinclair"));
//! # Ok::<(), cred_swap_core::DetectorError>(())
//! ```

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::Finding;

/// Why a span was put forward.
///
/// The shape is a hint for whoever judges, not a claim. It says what kind of
/// question is worth asking about this span, which is usually enough to pick
/// the right one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Shape {
    /// A run of capitalised words. A person, a company, a place, or the name
    /// of a piece of software, and only context tells them apart.
    ProperNoun,
    /// A value sitting after a label, as in `owner: ...` or `account = ...`.
    /// The label is the most useful thing a judge can be shown.
    LabelledValue,
    /// A long opaque run with no keyword anywhere near it. A key, a hash, a
    /// build id, or a base64 blob of something harmless.
    OpaqueToken,
    /// A long run of digits and separators that no checksum claimed.
    Numeric,
}

impl Shape {
    /// A stable name, for putting in a question.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProperNoun => "proper-noun",
            Self::LabelledValue => "labelled-value",
            Self::OpaqueToken => "opaque-token",
            Self::Numeric => "numeric",
        }
    }
}

/// A span put forward for judgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// The span itself.
    pub text: String,
    /// Byte offset of the span.
    pub start: usize,
    /// Byte offset one past the span.
    pub end: usize,
    /// What kind of span this is.
    pub shape: Shape,
    /// The span with the words either side of it.
    ///
    /// A judge shown `Avery` alone cannot answer. Shown
    /// `…approved by Avery Sinclair on Tuesday…` it can. This is the single
    /// most important field here, and the reason a candidate is not just an
    /// offset pair.
    pub context: String,
}

impl Candidate {
    /// The byte range this candidate occupies.
    #[must_use]
    pub const fn range(&self) -> std::ops::Range<usize> {
        self.start..self.end
    }

    fn overlaps_finding(&self, finding: &Finding) -> bool {
        self.start < finding.end && finding.start < self.end
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// How widely to cast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Survey {
    /// Most candidates to return.
    ///
    /// A bound, not a target. Judging costs money per candidate, so this is
    /// what stops one pasted log file from becoming a thousand questions.
    pub limit: usize,
    /// Characters of surrounding text to carry with each candidate.
    pub context: usize,
    /// Shapes to look for.
    pub shapes: Vec<Shape>,
}

impl Default for Survey {
    fn default() -> Self {
        Self {
            limit: 64,
            context: 72,
            shapes: vec![
                Shape::ProperNoun,
                Shape::LabelledValue,
                Shape::OpaqueToken,
                Shape::Numeric,
            ],
        }
    }
}

impl Survey {
    /// Look for one kind of span only.
    #[must_use]
    pub fn only(shape: Shape) -> Self {
        Self {
            shapes: vec![shape],
            ..Self::default()
        }
    }

    /// Return at most `limit` candidates.
    #[must_use]
    pub const fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
}

/// Two or more capitalised words in a row, or one that is not starting a
/// sentence. Apostrophes and hyphens are inside names; full stops are not.
static PROPER_NOUN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z][a-z'\u{2019}\-]{1,19}(?:\s+[A-Z][a-z'\u{2019}\-]{1,19}){0,3}\b")
        .unwrap_or_else(|error| unreachable!("proper-noun pattern is valid: {error}"))
});

/// `label: value` in any of the spellings a config file or a log line uses.
static LABELLED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)([A-Za-z][A-Za-z0-9 ._\-]{1,30})\s*[:=]\s*([^\s,;][^\n,;]{2,79})")
        .unwrap_or_else(|error| unreachable!("labelled-value pattern is valid: {error}"))
});

/// A long unbroken run that is not a word.
static OPAQUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z0-9_\-./+=]{16,}")
        .unwrap_or_else(|error| unreachable!("opaque-token pattern is valid: {error}"))
});

/// Eight or more digits, however they are grouped.
static NUMERIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\d[\d \-./]{6,}\d")
        .unwrap_or_else(|error| unreachable!("numeric pattern is valid: {error}"))
});

/// Words that begin a sentence far more often than they begin a name.
const SENTENCE_STARTERS: &[&str] = &[
    "The", "This", "That", "These", "Those", "There", "Then", "They", "We", "You", "It", "If",
    "And", "But", "For", "Not", "All", "Any", "Our", "Its", "His", "Her", "Their", "When", "While",
    "Where", "What", "Which", "Who", "How", "Why", "Also", "Once", "After", "Before", "Here",
    "Both", "Each", "Every", "Some", "Most", "Only", "Such", "Same", "Other", "Please", "Note",
    "See", "Use", "Run", "Add", "Set", "Get", "Try", "Let", "Make", "Now", "New", "One", "Two",
    "Yes", "No", "Ok", "Okay",
];

/// Put forward the spans worth asking about.
///
/// Anything already claimed by `found` is left out: the rules were sure, and
/// paying to ask about it again buys nothing. Candidates never overlap each
/// other, and come back in document order.
#[must_use]
pub fn candidates(text: &str, found: &[Finding], survey: &Survey) -> Vec<Candidate> {
    let mut raised = Vec::new();

    for shape in &survey.shapes {
        match shape {
            Shape::ProperNoun => raise_proper_nouns(text, &mut raised),
            Shape::LabelledValue => {
                raise_captured(text, &LABELLED, 2, Shape::LabelledValue, &mut raised);
            }
            Shape::OpaqueToken => raise_captured(text, &OPAQUE, 0, Shape::OpaqueToken, &mut raised),
            Shape::Numeric => raise_captured(text, &NUMERIC, 0, Shape::Numeric, &mut raised),
        }
    }

    // The rules already decided about these.
    raised.retain(|candidate| {
        !found
            .iter()
            .any(|finding| candidate.overlaps_finding(finding))
    });

    // A labelled value says more than the bare token inside it, and a full
    // name says more than either half, so longer wins where they collide.
    raised.sort_by(|a, b| {
        (b.end - b.start)
            .cmp(&(a.end - a.start))
            .then_with(|| a.start.cmp(&b.start))
    });

    let mut kept: Vec<Candidate> = Vec::new();
    for candidate in raised {
        if kept.len() >= survey.limit {
            break;
        }
        if kept.iter().any(|held| held.overlaps(&candidate)) {
            continue;
        }
        kept.push(candidate);
    }

    for candidate in &mut kept {
        candidate.context = window(text, candidate.start, candidate.end, survey.context);
    }
    kept.sort_by_key(|candidate| candidate.start);
    kept
}

fn raise_proper_nouns(text: &str, out: &mut Vec<Candidate>) {
    for matched in PROPER_NOUN.find_iter(text) {
        let span = matched.as_str();
        let words = span.split_whitespace().count();

        // One capitalised word is usually a sentence opening, a heading or an
        // ordinary noun. Only put it forward when something else suggests it
        // is a name: it is not a known opener, and not the first word of the
        // text or of a line.
        if words == 1 {
            if SENTENCE_STARTERS.contains(&span) {
                continue;
            }
            let opens_a_line = text[..matched.start()]
                .chars()
                .next_back()
                .is_none_or(|before| before == '\n');
            if opens_a_line {
                continue;
            }
        }

        out.push(Candidate {
            text: span.to_owned(),
            start: matched.start(),
            end: matched.end(),
            shape: Shape::ProperNoun,
            context: String::new(),
        });
    }
}

fn raise_captured(text: &str, regex: &Regex, group: usize, shape: Shape, out: &mut Vec<Candidate>) {
    for captures in regex.captures_iter(text) {
        let Some(matched) = captures.get(group).or_else(|| captures.get(0)) else {
            continue;
        };
        out.push(Candidate {
            text: matched.as_str().to_owned(),
            start: matched.start(),
            end: matched.end(),
            shape,
            context: String::new(),
        });
    }
}

/// The span plus the text around it, cut on character boundaries.
fn window(text: &str, start: usize, end: usize, width: usize) -> String {
    let mut from = start.saturating_sub(width);
    while from > 0 && !text.is_char_boundary(from) {
        from -= 1;
    }
    let mut to = (end + width).min(text.len());
    while to < text.len() && !text.is_char_boundary(to) {
        to += 1;
    }

    let mut out = String::with_capacity(to - from + 2);
    if from > 0 {
        out.push('…');
    }
    out.push_str(text[from..to].trim());
    if to < text.len() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cloak, Policy, Style, Surrogates};

    fn cloak() -> Cloak {
        Cloak::new(
            Policy::default(),
            Surrogates::from_secret(b"candidates", Style::Realistic),
        )
        .expect("the default policy compiles")
    }

    fn raise(text: &str) -> Vec<Candidate> {
        candidates(text, &cloak().inspect(text), &Survey::default())
    }

    fn texts(found: &[Candidate]) -> Vec<&str> {
        found.iter().map(|c| c.text.as_str()).collect()
    }

    #[test]
    fn a_name_the_rules_cannot_see_is_put_forward() {
        let text = "Avery Sinclair approved the migration on Tuesday.";
        assert!(
            cloak().inspect(text).is_empty(),
            "the rules should miss this"
        );
        assert!(texts(&raise(text)).contains(&"Avery Sinclair"));
    }

    #[test]
    fn a_sentence_opening_is_not_put_forward_as_a_name() {
        let raised = raise("The parser allocates on every token. This is the bug.");
        assert!(
            texts(&raised).is_empty(),
            "ordinary prose raised: {:?}",
            texts(&raised)
        );
    }

    #[test]
    fn what_the_rules_already_found_is_not_asked_about_again() {
        let text = "mail dana@corp.com about it";
        let found = cloak().inspect(text);
        assert_eq!(found.len(), 1);

        let raised = candidates(text, &found, &Survey::default());
        assert!(
            raised.iter().all(|c| !c.text.contains("dana@corp.com")),
            "{:?}",
            texts(&raised)
        );
    }

    #[test]
    fn candidates_carry_enough_context_to_judge() {
        let text = "The change was approved by Avery Sinclair on the second of June.";
        let raised = raise(text);
        let name = raised
            .iter()
            .find(|c| c.text == "Avery Sinclair")
            .expect("the name is a candidate");
        assert!(name.context.contains("approved by"), "{}", name.context);
        assert!(name.context.contains("on the second"), "{}", name.context);
    }

    #[test]
    fn a_labelled_value_beats_the_bare_token_inside_it() {
        let raised = raise("owner_reference = 8fj2Kd93ldMzQ01xPq");
        let covering = raised
            .iter()
            .find(|c| c.text.contains("8fj2Kd93ldMzQ01xPq"))
            .expect("the value is a candidate");
        assert_eq!(covering.shape, Shape::LabelledValue);
        assert_eq!(raised.len(), 1, "{:?}", texts(&raised));
    }

    #[test]
    fn candidates_never_overlap_and_arrive_in_order() {
        let raised = raise(
            "Avery Sinclair and Rowan Whitfield met at Northwind Logistics about 4029 8811 2233.",
        );
        for pair in raised.windows(2) {
            assert!(
                pair[0].end <= pair[1].start,
                "overlap: {:?} then {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn the_limit_is_a_hard_bound() {
        use std::fmt::Write as _;
        let mut text = String::new();
        for index in 0..200 {
            let _ = write!(text, "Avery Sinclair{index} wrote it. ");
        }
        let raised = candidates(&text, &[], &Survey::default().limit(10));
        assert_eq!(raised.len(), 10);
    }

    #[test]
    fn a_survey_can_ask_for_one_shape_only() {
        let text = "Avery Sinclair set token = aG7xQ92mZk1pLw83Tb";
        let raised = candidates(text, &[], &Survey::only(Shape::ProperNoun));
        assert!(raised.iter().all(|c| c.shape == Shape::ProperNoun));
        assert!(texts(&raised).contains(&"Avery Sinclair"));
    }

    #[test]
    fn offsets_index_the_original_text() {
        let text = "approved by Avery Sinclair today";
        for candidate in raise(text) {
            assert_eq!(&text[candidate.range()], candidate.text);
        }
    }

    #[test]
    fn multibyte_text_is_not_split() {
        let text = "Café — Avery Sinclair signed 🙂 on Tuesday";
        for candidate in raise(text) {
            assert_eq!(&text[candidate.range()], candidate.text);
            assert!(text.contains(candidate.context.trim_matches('…')));
        }
    }

    #[test]
    fn empty_text_raises_nothing() {
        assert!(raise("").is_empty());
    }
}

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
//! assert!(asking.candidates.iter().any(|c| c.text == "Avery Sinclair"));
//! assert!(!asking.truncated());
//! # Ok::<(), cred_swap_core::DetectorError>(())
//! ```

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::Finding;

/// Why a span was put forward.
///
/// The shape is a hint for whoever judges, not a claim. It says what kind of
/// question is worth asking about this span, which is usually enough to pick
/// the right one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
///
/// Carries raw text, and up to a couple of hundred characters of the text
/// around it, because that is what a judge needs to answer. It is therefore
/// exactly as sensitive as the message it came from: send it to a classifier,
/// do not send it to a log.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl fmt::Debug for Candidate {
    /// Shape and position, never the text.
    ///
    /// This struct's own doc says to send it to a classifier and not to a log,
    /// and a derived `Debug` is the easiest possible way to do the thing it
    /// warns against. `Vault` sets the precedent: print counts, not contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("shape", &self.shape)
            .field("at", &self.range())
            .field("chars", &self.text.chars().count())
            // `text` and `context` are withheld, which is the entire point, so
            // this is exhaustive in the only sense that matters here.
            .finish_non_exhaustive()
    }
}

impl Candidate {
    /// The byte range this candidate occupies.
    #[must_use]
    pub const fn range(&self) -> std::ops::Range<usize> {
        self.start..self.end
    }

    const fn span(&self) -> (usize, usize) {
        (self.start, self.end)
    }

    fn overlaps_finding(&self, finding: &Finding) -> bool {
        super::spans_overlap(self.span(), finding.span())
    }
}

/// How widely to cast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Survey {
    /// Most *distinct values* to put forward.
    ///
    /// A bound on questions, not on candidates. Every occurrence of an
    /// afforded value comes back, so the returned list is routinely longer
    /// than this: five mentions of one name cost one slot and return five
    /// candidates, because masking one and leaving four teaches the reader the
    /// name. Judging costs money per distinct value, so this is what stops one
    /// pasted log file from becoming a thousand questions.
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

    /// Spend the budget on at most `limit` distinct values.
    #[must_use]
    pub const fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Carry `width` characters of surrounding text with each candidate.
    #[must_use]
    pub const fn context(mut self, width: usize) -> Self {
        self.context = width;
        self
    }
}

/// What a survey turned up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Surveyed {
    /// The spans to ask about, in document order.
    pub candidates: Vec<Candidate>,
    /// Distinct values the budget could not afford.
    ///
    /// A bare `Vec` would make a clean survey and a truncated one look the
    /// same, which is the failure this whole feature exists to avoid: a caller
    /// would report "nothing else looked sensitive" when the honest answer is
    /// "I stopped looking". Non-zero means raise [`Survey::limit`], or accept
    /// that some of the message went unexamined and say so.
    pub dropped: usize,
}

impl Surveyed {
    /// Whether the budget ran out before the message did.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.dropped > 0
    }

    /// The candidates, in document order.
    pub fn iter(&self) -> std::slice::Iter<'_, Candidate> {
        self.candidates.iter()
    }
}

impl IntoIterator for Surveyed {
    type Item = Candidate;
    type IntoIter = std::vec::IntoIter<Candidate>;

    fn into_iter(self) -> Self::IntoIter {
        self.candidates.into_iter()
    }
}

impl<'a> IntoIterator for &'a Surveyed {
    type Item = &'a Candidate;
    type IntoIter = std::slice::Iter<'a, Candidate>;

    fn into_iter(self) -> Self::IntoIter {
        self.candidates.iter()
    }
}

/// A run of capitalised words. Unicode classes rather than `A-Z`, so that
/// `Müller`, `Étienne` and `Ægir` are seen at all: an ASCII class quietly
/// makes every non-English name invisible, which is the opposite of what a
/// recall pass is for. Apostrophes and hyphens live inside names; full stops
/// do not.
static PROPER_NOUN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\p{Lu}[\p{Ll}\p{Lm}\p{Lo}'\u{2019}\-]{1,19}(?:\s+\p{Lu}[\p{Ll}\p{Lm}\p{Lo}'\u{2019}\-]{1,19}){0,3}\b")
        .unwrap_or_else(|error| unreachable!("proper-noun pattern is valid: {error}"))
});

/// A run of script that has no case at all, such as CJK, and so can never be
/// caught by a capitalisation rule.
///
/// Deliberately crude: it raises the run and lets the judge decide, because
/// the alternative is that these languages are structurally invisible here.
static UNCASED_RUN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[\p{Han}\p{Hiragana}\p{Katakana}\p{Hangul}\p{Arabic}\p{Hebrew}\p{Thai}\p{Devanagari}]{2,24}")
        .unwrap_or_else(|error| unreachable!("uncased-run pattern is valid: {error}"))
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
///
/// The budget is spent on *distinct values*, taken round-robin across shapes.
/// Both halves of that matter. Spending per occurrence meant a name repeated
/// five times cost five slots and five identical questions; spending
/// longest-first meant the eighty-character labelled values were admitted
/// before any fourteen-character name, so the thing this exists to catch was
/// the first thing dropped.
#[must_use]
pub fn candidates(text: &str, found: &[Finding], survey: &Survey) -> Surveyed {
    let mut raised = Vec::new();

    for shape in &survey.shapes {
        match shape {
            Shape::ProperNoun => raise_proper_nouns(text, &mut raised),
            Shape::LabelledValue => {
                raise_captured(text, &LABELLED, 2, Shape::LabelledValue, &mut raised);
            }
            Shape::OpaqueToken => {
                raise_captured(text, &OPAQUE, 0, Shape::OpaqueToken, &mut raised);
                // A run of nothing but digits belongs to `Numeric`, so it
                // is dropped here to stop both shapes claiming the span and
                // the raise order deciding. Only when `Numeric` is also being
                // looked for, though: dropping it when nothing else will pick
                // it up loses the span altogether, which is what a survey
                // asked for this shape alone used to do.
                if survey.shapes.contains(&Shape::Numeric) {
                    raised.retain(|candidate| {
                        candidate.shape != Shape::OpaqueToken
                            || candidate.text.chars().any(char::is_alphabetic)
                    });
                }
            }
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
    let mut settled = super::pick_disjoint(raised, Candidate::span);
    settled.sort_by_key(|candidate| candidate.start);

    // Owned, so the borrow the budget takes on `settled` ends before the move.
    let (affordable, dropped) = {
        let (afforded, dropped) = afford(&settled, survey);
        let owned: HashSet<String> = afforded.into_iter().map(ToOwned::to_owned).collect();
        (owned, dropped)
    };
    let mut kept: Vec<Candidate> = settled
        .into_iter()
        .filter(|candidate| affordable.contains(&candidate.text))
        .collect();

    for candidate in &mut kept {
        candidate.context = window(text, candidate.start, candidate.end, survey.context);
    }
    Surveyed {
        candidates: kept,
        dropped,
    }
}

/// Choose which distinct values the budget stretches to.
///
/// Round-robin across the shapes present, each taking its next value in
/// document order, so no one shape can eat the whole allowance. Returns the
/// values that fit and how many distinct ones did not.
fn afford<'a>(settled: &'a [Candidate], survey: &Survey) -> (HashSet<&'a str>, usize) {
    // Distinct values per shape, in document order, first occurrence only.
    let mut queues: BTreeMap<Shape, VecDeque<&str>> = BTreeMap::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for candidate in settled {
        if seen.insert(candidate.text.as_str()) {
            queues
                .entry(candidate.shape)
                .or_default()
                .push_back(candidate.text.as_str());
        }
    }
    let distinct = seen.len();

    let mut afforded: HashSet<&str> = HashSet::with_capacity(survey.limit.min(distinct));
    while afforded.len() < survey.limit {
        let mut took_any = false;
        for queue in queues.values_mut() {
            if afforded.len() >= survey.limit {
                break;
            }
            if let Some(value) = queue.pop_front() {
                afforded.insert(value);
                took_any = true;
            }
        }
        if !took_any {
            break;
        }
    }

    let dropped = distinct - afforded.len();
    (afforded, dropped)
}

fn raise_proper_nouns(text: &str, out: &mut Vec<Candidate>) {
    for matched in PROPER_NOUN.find_iter(text) {
        let span = matched.as_str();
        let words = span.split_whitespace().count();

        // One capitalised word is often a sentence opening or a heading, so the
        // highest-frequency openers are skipped. Position is deliberately NOT
        // used: a name at the start of a line is the commonest shape in a
        // transcript, and skipping line openers made `Dana: the deploy failed`
        // impossible to mask, which is the exact case this exists for. The
        // cost is a few more questions, and a judge that answers them.
        if words == 1 && SENTENCE_STARTERS.contains(&span) {
            continue;
        }

        out.push(Candidate {
            text: span.to_owned(),
            start: matched.start(),
            end: matched.end(),
            shape: Shape::ProperNoun,
            context: String::new(),
        });
    }

    // Scripts with no upper case cannot be found by a capitalisation rule at
    // all, so they are raised wholesale and left to the judge.
    for matched in UNCASED_RUN.find_iter(text) {
        out.push(Candidate {
            text: matched.as_str().to_owned(),
            start: matched.start(),
            end: matched.end(),
            shape: Shape::ProperNoun,
            context: String::new(),
        });
    }
}

fn raise_captured(text: &str, regex: &Regex, group: usize, shape: Shape, out: &mut Vec<Candidate>) {
    for captures in regex.captures_iter(text) {
        // No fallback to group 0. Every rule here names a group that always
        // participates, so a miss would be a bug in the pattern, and quietly
        // widening to the whole match would hide it behind a bigger span.
        let Some(matched) = captures.get(group) else {
            debug_assert!(false, "pattern for {shape:?} has no group {group}");
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
    use crate::{Cloak, EntityKind, Policy, Style, Surrogates};

    fn cloak() -> Cloak {
        Cloak::new(
            Policy::default(),
            Surrogates::from_secret(b"candidates", Style::Realistic),
        )
        .expect("the default policy compiles")
    }

    fn raise(text: &str) -> Surveyed {
        candidates(text, &cloak().inspect(text), &Survey::default())
    }

    fn texts(found: &Surveyed) -> Vec<&str> {
        found.candidates.iter().map(|c| c.text.as_str()).collect()
    }

    fn shaped(found: &Surveyed, shape: Shape) -> Vec<&str> {
        found
            .candidates
            .iter()
            .filter(|c| c.shape == shape)
            .map(|c| c.text.as_str())
            .collect()
    }

    /// `count` distinct two-word names. Appending a digit does not work: a
    /// digit is not a lowercase letter, so `Avery Sinclair7` matches as
    /// `Avery` and every one of them collapses to the same value.
    fn distinct_names(count: usize) -> Vec<String> {
        const GIVEN: &[&str] = &[
            "Avery", "Rowan", "Quinn", "Harper", "Emerson", "Finley", "Sawyer", "Reese", "Marlow",
            "Ellis",
        ];
        const FAMILY: &[&str] = &[
            "Ashford",
            "Barlow",
            "Cartwright",
            "Ellington",
            "Granger",
            "Halloway",
            "Ingram",
            "Kingsley",
            "Lockhart",
            "Prescott",
        ];
        (0..count)
            .map(|index| {
                format!(
                    "{} {}",
                    GIVEN[index % GIVEN.len()],
                    FAMILY[(index / GIVEN.len()) % FAMILY.len()]
                )
            })
            .collect()
    }

    // ---------------------------------------------------------------
    // What each shape must catch, and what it must not.
    // ---------------------------------------------------------------

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
    fn a_name_that_opens_a_line_is_put_forward() {
        // The commonest shape in a transcript, and the case that an earlier
        // "skip line openers" rule made impossible to mask.
        let raised = raise("Dana: the deploy failed\nRowan: rolling back");
        let names = shaped(&raised, Shape::ProperNoun);
        assert!(names.contains(&"Dana"), "{names:?}");
        assert!(names.contains(&"Rowan"), "{names:?}");
    }

    #[test]
    fn a_sentence_opening_is_not_put_forward_as_a_name() {
        let raised = raise("The parser allocates on every token. This is the bug.");
        assert!(
            shaped(&raised, Shape::ProperNoun).is_empty(),
            "ordinary prose raised: {:?}",
            texts(&raised)
        );
    }

    #[test]
    fn non_english_names_are_visible() {
        // An ASCII-only class makes these structurally invisible, which is the
        // opposite of what a recall pass is for.
        for name in ["Müller", "Étienne Lefèvre", "Ægir Ólafsson"] {
            let text = format!("approved by {name} today");
            assert!(
                texts(&raise(&text))
                    .iter()
                    .any(|found| name.starts_with(found)),
                "{name} was not raised"
            );
        }
    }

    #[test]
    fn scripts_without_capitalisation_are_raised_wholesale() {
        let raised = raise("approved by 田中太郎 today");
        assert!(texts(&raised).contains(&"田中太郎"), "{:?}", texts(&raised));
    }

    #[test]
    fn a_labelled_value_is_raised_but_an_ordinary_sentence_is_not() {
        let raised = raise("owner_reference = 8fj2Kd93ldMzQ01xPq");
        assert_eq!(
            shaped(&raised, Shape::LabelledValue),
            vec!["8fj2Kd93ldMzQ01xPq"]
        );

        // Prose with no assignment in it must raise no labelled value at all.
        let prose = raise("we rewrote the loop and it got faster");
        assert!(
            shaped(&prose, Shape::LabelledValue).is_empty(),
            "{:?}",
            texts(&prose)
        );
    }

    #[test]
    fn an_opaque_token_is_raised_but_an_ordinary_word_is_not() {
        let raised = raise("the value aG7xQ92mZk1pLw83Tb5R came back");
        assert!(shaped(&raised, Shape::OpaqueToken).contains(&"aG7xQ92mZk1pLw83Tb5R"));

        // Nothing under sixteen characters, and no ordinary prose.
        let prose = raise("the configuration was reloaded successfully");
        assert!(
            shaped(&prose, Shape::OpaqueToken).is_empty(),
            "{:?}",
            texts(&prose)
        );
    }

    #[test]
    fn a_long_digit_run_is_raised_but_a_short_one_is_not() {
        // Twenty digits: too long for a card, and with no separators the phone
        // rule cannot claim it either, so it reaches the survey.
        let raised = raise("reference 12345678901234567890 for the claim");
        assert_eq!(
            shaped(&raised, Shape::Numeric),
            vec!["12345678901234567890"],
            "{:?}",
            texts(&raised)
        );

        let short = raise("we saw 42 retries in 2 hours");
        assert!(
            shaped(&short, Shape::Numeric).is_empty(),
            "{:?}",
            texts(&short)
        );
    }

    // ---------------------------------------------------------------
    // The budget.
    // ---------------------------------------------------------------

    #[test]
    fn the_budget_is_spent_on_distinct_values_not_occurrences() {
        let text = "Avery Sinclair wrote it. Avery Sinclair shipped it. Avery Sinclair broke it.";
        let raised = candidates(text, &[], &Survey::default().limit(1));

        assert!(
            !raised.truncated(),
            "one value should cost one slot, {:?}",
            raised.dropped
        );
        assert_eq!(
            texts(&raised).len(),
            3,
            "every occurrence must come back, or only one of them can be masked"
        );
    }

    #[test]
    fn the_budget_is_shared_between_shapes_rather_than_taken_longest_first() {
        // Labelled values are far longer than names, so a longest-first budget
        // admitted all of them and none of the names.
        use std::collections::BTreeSet;

        use std::fmt::Write as _;

        let mut text = String::new();
        for index in 0..20 {
            let _ = writeln!(
                text,
                "setting_number_{index} = a-fairly-long-configuration-value-{index}"
            );
        }
        for name in distinct_names(20) {
            let _ = writeln!(text, "approved by {name} today");
        }

        let raised = candidates(&text, &[], &Survey::default().limit(10));
        let names: BTreeSet<&str> = shaped(&raised, Shape::ProperNoun).into_iter().collect();
        let values: BTreeSet<&str> = shaped(&raised, Shape::LabelledValue).into_iter().collect();

        assert!(
            names.len() >= 3,
            "names were crowded out by longer values: {} names, {} values",
            names.len(),
            values.len()
        );
        assert!(
            values.len() >= 3,
            "values were crowded out: {} names, {} values",
            names.len(),
            values.len()
        );
    }

    #[test]
    fn truncation_is_reported_rather_than_silent() {
        use std::fmt::Write as _;

        let mut text = String::new();
        for name in distinct_names(50) {
            let _ = write!(text, "approved by {name} today. ");
        }

        let raised = candidates(&text, &[], &Survey::default().limit(10));
        assert!(
            raised.truncated(),
            "a caller could not tell it was truncated"
        );
        assert_eq!(raised.dropped, 40, "{} raised", raised.candidates.len());
    }

    #[test]
    fn a_survey_that_fits_reports_nothing_dropped() {
        let raised = raise("Avery Sinclair approved it.");
        assert!(!raised.truncated());
        assert_eq!(raised.dropped, 0);
    }

    // ---------------------------------------------------------------
    // Shared behaviour.
    // ---------------------------------------------------------------

    #[test]
    fn what_the_rules_already_found_is_not_asked_about_again() {
        let text = "mail dana@corp.com about it";
        let found = cloak().inspect(text);
        assert_eq!(found.len(), 1);

        let raised = candidates(text, &found, &Survey::default());
        assert!(
            raised
                .candidates
                .iter()
                .all(|c| !c.text.contains("dana@corp.com")),
            "{:?}",
            texts(&raised)
        );
    }

    #[test]
    fn candidates_carry_enough_context_to_judge() {
        let text = "The change was approved by Avery Sinclair on the second of June.";
        let raised = raise(text);
        let name = raised
            .candidates
            .iter()
            .find(|c| c.text == "Avery Sinclair")
            .expect("the name is a candidate");
        assert!(name.context.contains("approved by"), "{}", name.context);
        assert!(name.context.contains("on the second"), "{}", name.context);
    }

    #[test]
    fn candidates_never_overlap_and_arrive_in_order() {
        let raised = raise(
            "Avery Sinclair and Rowan Whitfield met at Northwind Logistics about 4029 8811 2233.",
        );
        for pair in raised.candidates.windows(2) {
            assert!(
                pair[0].end <= pair[1].start,
                "overlap: {:?} then {:?}",
                pair[0].text,
                pair[1].text
            );
        }
    }

    #[test]
    fn asking_for_opaque_tokens_alone_does_not_lose_digit_runs() {
        // A pure digit run belongs to `Numeric`, so it is dropped from the
        // opaque shape to stop both claiming the span. Dropping it when
        // `Numeric` is not being looked for lost it altogether.
        let text = "reference 12345678901234567890 for the claim";
        let alone = candidates(text, &[], &Survey::only(Shape::OpaqueToken));
        assert_eq!(
            texts(&alone),
            vec!["12345678901234567890"],
            "the span was dropped by a shape that was not even asked for"
        );

        // With both shapes asked for, `Numeric` still wins it.
        let both = raise(text);
        assert_eq!(shaped(&both, Shape::Numeric), vec!["12345678901234567890"]);
        assert!(shaped(&both, Shape::OpaqueToken).is_empty());
    }

    #[test]
    fn debug_output_does_not_print_the_span_or_its_context() {
        let raised = raise("approved by Avery Sinclair today");
        let candidate = raised
            .candidates
            .iter()
            .find(|c| c.text == "Avery Sinclair")
            .expect("the name is a candidate");

        let rendered = format!("{candidate:?}");
        assert!(!rendered.contains("Avery"), "{rendered}");
        assert!(!rendered.contains("approved"), "{rendered}");
        assert!(rendered.contains("chars"), "{rendered}");
    }

    #[test]
    fn a_survey_can_ask_for_one_shape_only() {
        let text = "Avery Sinclair set token = aG7xQ92mZk1pLw83Tb";
        let raised = candidates(text, &[], &Survey::only(Shape::ProperNoun));
        assert!(
            raised
                .candidates
                .iter()
                .all(|c| c.shape == Shape::ProperNoun)
        );
        assert!(texts(&raised).contains(&"Avery Sinclair"));
    }

    #[test]
    fn offsets_index_the_original_text() {
        let text = "approved by Avery Sinclair today";
        for candidate in &raise(text).candidates {
            assert_eq!(&text[candidate.range()], candidate.text);
        }
    }

    #[test]
    fn multibyte_text_is_not_split() {
        let text = "Café — Avery Sinclair signed 🙂 on Tuesday";
        for candidate in &raise(text).candidates {
            assert_eq!(&text[candidate.range()], candidate.text);
            assert!(text.contains(candidate.context.trim_matches('…')));
        }
    }

    #[test]
    fn empty_text_raises_nothing() {
        let raised = raise("");
        assert!(raised.candidates.is_empty());
        assert_eq!(raised.dropped, 0);
    }

    #[test]
    fn a_judged_candidate_can_be_scrubbed_and_restored() {
        let mut cloak = cloak();
        let text = "Avery Sinclair approved it.";
        let raised = candidates(text, &[], &Survey::default());

        let judged: Vec<Finding> = raised
            .candidates
            .iter()
            .filter(|c| c.text == "Avery Sinclair")
            .map(|c| Finding {
                kind: EntityKind::PersonName,
                start: c.start,
                end: c.end,
                text: c.text.clone(),
            })
            .collect();
        assert_eq!(judged.len(), 1);

        let merged = super::super::merge(Vec::new(), judged);
        let scrubbed = cloak.scrub_findings(text, merged.findings, |_| crate::Decision::Replace);
        assert!(!scrubbed.text.contains("Avery Sinclair"));
        assert_eq!(cloak.restore(&scrubbed.text), text);
    }

    #[test]
    fn the_shape_name_matches_what_serde_writes() {
        // Two tables would drift; this is the one that notices.
        for shape in [
            Shape::ProperNoun,
            Shape::LabelledValue,
            Shape::OpaqueToken,
            Shape::Numeric,
        ] {
            let encoded = serde_json::to_string(&shape).expect("a unit variant serializes");
            assert_eq!(encoded.trim_matches('"'), shape.as_str());
        }
    }
}

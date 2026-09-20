//! Turning results into something worth reading.

use std::io::Write;

use cred_swap_core::{EntityKind, Entry, Finding, Scrubbed};
use serde::Serialize;

/// Abbreviate a value for display.
///
/// A report that prints every secret in full turns the terminal scrollback
/// into the thing the user was trying to protect. Credentials are shown as
/// enough of a fingerprint to identify which one it was, and no more.
/// Everything else is shown as-is: the user wrote it and is looking at it.
#[must_use]
pub fn mask(kind: &EntityKind, value: &str, show_values: bool) -> String {
    if show_values || !kind.is_secret() {
        return single_line(value);
    }
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return format!("<{} chars hidden>", chars.len());
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars
        .iter()
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail} ({} chars)", chars.len())
}

/// Collapse a multi-line value onto one line so a table stays a table.
fn single_line(value: &str) -> String {
    if !value.contains(['\n', '\r']) {
        return value.to_owned();
    }
    let first = value.lines().next().unwrap_or_default();
    format!("{first} …({} lines)", value.lines().count())
}

/// The 1-based line and column of a byte offset.
#[must_use]
pub fn position(text: &str, offset: usize) -> (usize, usize) {
    let head = &text[..offset.min(text.len())];
    let line = head.matches('\n').count() + 1;
    let column = head.rfind('\n').map_or_else(
        || head.chars().count(),
        |start| head[start + 1..].chars().count(),
    ) + 1;
    (line, column)
}

/// One row of the `detect` report, for `--json`.
#[derive(Serialize)]
pub struct FindingRow<'a> {
    /// The kind of value found.
    pub kind: &'a str,
    /// 1-based line number.
    pub line: usize,
    /// 1-based column number, in characters.
    pub column: usize,
    /// Byte offset of the value.
    pub start: usize,
    /// Byte offset one past the value.
    pub end: usize,
    /// The matched text, masked unless `--show-values` was given.
    pub value: String,
}

/// Build the JSON rows for a set of findings.
#[must_use]
pub fn finding_rows<'a>(
    text: &str,
    findings: &'a [Finding],
    show_values: bool,
) -> Vec<FindingRow<'a>> {
    findings
        .iter()
        .map(|finding| {
            let (line, column) = position(text, finding.start);
            FindingRow {
                kind: finding.kind.as_str(),
                line,
                column,
                start: finding.start,
                end: finding.end,
                value: mask(&finding.kind, &finding.text, show_values),
            }
        })
        .collect()
}

/// Print findings as an aligned table.
///
/// # Errors
///
/// Returns an error if the stream cannot be written to.
pub fn write_findings(
    out: &mut impl Write,
    text: &str,
    findings: &[Finding],
    show_values: bool,
) -> std::io::Result<()> {
    if findings.is_empty() {
        return writeln!(out, "Nothing found.");
    }

    let rows = finding_rows(text, findings, show_values);
    let where_width = rows
        .iter()
        .map(|row| format!("{}:{}", row.line, row.column).len())
        .max()
        .unwrap_or(5)
        .max(5);
    let kind_width = rows
        .iter()
        .map(|row| row.kind.len())
        .max()
        .unwrap_or(4)
        .max(4);

    writeln!(
        out,
        "{:<where_width$}  {:<kind_width$}  VALUE",
        "WHERE", "KIND"
    )?;
    for row in &rows {
        let at = format!("{}:{}", row.line, row.column);
        writeln!(
            out,
            "{at:<where_width$}  {:<kind_width$}  {}",
            row.kind, row.value
        )?;
    }

    let secrets = findings.iter().filter(|f| f.kind.is_secret()).count();
    writeln!(out)?;
    writeln!(
        out,
        "{} found{}.",
        plural(findings.len(), "value", "values"),
        if secrets > 0 {
            format!(", {secrets} of them credentials")
        } else {
            String::new()
        }
    )
}

/// Print a one-line-per-kind summary of what a scrub changed.
///
/// # Errors
///
/// Returns an error if the stream cannot be written to.
pub fn write_scrub_summary(out: &mut impl Write, scrubbed: &Scrubbed) -> std::io::Result<()> {
    if scrubbed.is_clean() && scrubbed.kept.is_empty() {
        return writeln!(out, "Nothing to replace.");
    }

    for kind in scrubbed.kinds() {
        let count = scrubbed
            .replacements
            .iter()
            .filter(|replacement| replacement.kind == kind)
            .count();
        writeln!(out, "  {count:>3} × {kind}")?;
    }
    writeln!(
        out,
        "{} replaced.",
        plural(scrubbed.replacements.len(), "value", "values")
    )?;
    if !scrubbed.kept.is_empty() {
        writeln!(
            out,
            "{} left in place by --keep.",
            plural(scrubbed.kept.len(), "value", "values")
        )?;
    }
    Ok(())
}

/// Print the contents of a vault.
///
/// # Errors
///
/// Returns an error if the stream cannot be written to.
pub fn write_entries(
    out: &mut impl Write,
    entries: &[Entry],
    show_values: bool,
) -> std::io::Result<()> {
    if entries.is_empty() {
        return writeln!(out, "This session has no substitutions yet.");
    }

    let kind_width = entries
        .iter()
        .map(|entry| entry.kind.as_str().len())
        .max()
        .unwrap_or(4)
        .max(4);
    let real_width = entries
        .iter()
        .map(|entry| mask(&entry.kind, &entry.real, show_values).chars().count())
        .max()
        .unwrap_or(8)
        .clamp(8, 48);

    writeln!(
        out,
        "{:<kind_width$}  {:<real_width$}  STAND-IN",
        "KIND", "ORIGINAL"
    )?;
    for entry in entries {
        writeln!(
            out,
            "{:<kind_width$}  {:<real_width$}  {}",
            entry.kind.as_str(),
            mask(&entry.kind, &entry.real, show_values),
            single_line(&entry.fake)
        )?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "{}.",
        plural(entries.len(), "substitution", "substitutions")
    )
}

fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's published example key id, assembled so the literal is not in the
    /// source. See `cred_swap_core::fixtures` for why.
    const AWS_KEY: &str = concat!("AKIA", "IOSFODNN7EXAMPLE");

    #[test]
    fn credentials_are_masked_by_default() {
        let masked = mask(&EntityKind::AwsAccessKeyId, AWS_KEY, false);
        assert!(masked.starts_with("AKIA"), "{masked}");
        assert!(!masked.contains("IOSFODNN7EXAM"), "{masked}");
        assert!(masked.contains("20 chars"), "{masked}");
    }

    #[test]
    fn short_credentials_reveal_nothing_at_all() {
        let masked = mask(&EntityKind::GenericSecret, "abc123", false);
        assert_eq!(masked, "<6 chars hidden>");
    }

    #[test]
    fn non_credentials_are_shown_in_full() {
        assert_eq!(
            mask(&EntityKind::EmailAddress, "dana@corp.com", false),
            "dana@corp.com"
        );
    }

    #[test]
    fn show_values_unmasks_credentials() {
        assert_eq!(mask(&EntityKind::AwsAccessKeyId, AWS_KEY, true), AWS_KEY);
    }

    #[test]
    fn multiline_values_are_collapsed_for_the_table() {
        let block = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----";
        let shown = mask(&EntityKind::PrivateKeyBlock, block, true);
        assert!(!shown.contains('\n'), "{shown}");
        assert!(shown.contains("3 lines"), "{shown}");
    }

    #[test]
    fn positions_are_one_based_and_count_characters() {
        let text = "first\nsécond line\nthird";
        assert_eq!(position(text, 0), (1, 1));
        let offset = text.find("line").unwrap();
        assert_eq!(position(text, offset), (2, 8));
    }

    #[test]
    fn an_empty_result_says_so_rather_than_printing_a_header() {
        let mut out = Vec::new();
        write_findings(&mut out, "clean text", &[], false).unwrap();
        assert_eq!(String::from_utf8(out).unwrap().trim(), "Nothing found.");
    }

    #[test]
    fn the_table_counts_credentials_separately() {
        let findings = vec![
            Finding {
                kind: EntityKind::EmailAddress,
                start: 0,
                end: 5,
                text: "a@b.c".into(),
            },
            Finding {
                kind: EntityKind::AwsAccessKeyId,
                start: 6,
                end: 26,
                text: AWS_KEY.into(),
            },
        ];
        let mut out = Vec::new();
        write_findings(&mut out, &format!("a@b.c {AWS_KEY}"), &findings, false).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("2 values found, 1 of them credentials"),
            "{rendered}"
        );
    }
}

//! Rewriting the strings inside a JSON document.
//!
//! A model API request is a JSON document whose interesting content is spread
//! across nested message arrays, system prompts and tool results, and every
//! provider arranges them differently. Rather than learn each schema, this
//! walks every string in the document and lets the detector decide. Detection
//! is conservative enough that structural values — model names, role strings,
//! tool names, identifiers — go through untouched.
//!
//! The same walk runs in reverse on the way back, which is what makes a tool
//! call usable: a model handed a stand-in hostname will emit a tool call
//! containing that stand-in, and [`restore_value`] puts the real host back
//! before the tool runs.

use crate::engine::{Cloak, Replacement, Scrubbed};
use serde_json::Value;

/// What a walk over one body changed.
#[derive(Debug, Default)]
pub struct Changes {
    /// Substitutions made, across every string in the document.
    pub replacements: Vec<Replacement>,
}

impl Changes {
    /// Whether the body came out identical to the way it went in.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.replacements.is_empty()
    }
}

/// Replace sensitive values in every string in a JSON document.
pub fn scrub_value(cloak: &mut Cloak, value: &mut Value, changes: &mut Changes) {
    match value {
        Value::String(text) => {
            let Scrubbed {
                text: rewritten,
                mut replacements,
                ..
            } = cloak.scrub(text);
            if !replacements.is_empty() {
                *text = rewritten;
                changes.replacements.append(&mut replacements);
            }
        }
        Value::Array(items) => {
            for item in items {
                scrub_value(cloak, item, changes);
            }
        }
        Value::Object(fields) => {
            for (_, field) in fields.iter_mut() {
                scrub_value(cloak, field, changes);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Put real values back in every string in a JSON document.
pub fn restore_value(cloak: &mut Cloak, value: &mut Value) {
    match value {
        Value::String(text) => {
            let restored = cloak.restore(text);
            if restored != *text {
                *text = restored;
            }
        }
        Value::Array(items) => {
            for item in items {
                restore_value(cloak, item);
            }
        }
        Value::Object(fields) => {
            for (_, field) in fields.iter_mut() {
                restore_value(cloak, field);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Scrub a body, returning the rewritten bytes.
///
/// A body that is not JSON is treated as plain text, which covers form posts
/// and the occasional plain-text endpoint. A body that is neither valid JSON
/// nor valid UTF-8 is passed through untouched: rewriting bytes whose meaning
/// is unknown would corrupt them.
pub fn scrub_body(cloak: &mut Cloak, body: &[u8], is_json: bool) -> (Vec<u8>, Changes) {
    let mut changes = Changes::default();

    if is_json && let Ok(mut value) = serde_json::from_slice::<Value>(body) {
        scrub_value(cloak, &mut value, &mut changes);
        if changes.is_empty() {
            return (body.to_vec(), changes);
        }
        return match serde_json::to_vec(&value) {
            Ok(bytes) => (bytes, changes),
            // Re-serializing a value that was just deserialized cannot fail in
            // practice; if it somehow does, sending the original is wrong, so
            // report no changes and let the caller decide.
            Err(_) => (body.to_vec(), Changes::default()),
        };
    }

    match std::str::from_utf8(body) {
        Ok(text) => {
            let scrubbed = cloak.scrub(text);
            changes.replacements = scrubbed.replacements;
            (scrubbed.text.into_bytes(), changes)
        }
        Err(_) => (body.to_vec(), changes),
    }
}

/// Restore a body, returning the rewritten bytes.
pub fn restore_body(cloak: &mut Cloak, body: &[u8], is_json: bool) -> Vec<u8> {
    if is_json && let Ok(mut value) = serde_json::from_slice::<Value>(body) {
        restore_value(cloak, &mut value);
        if let Ok(bytes) = serde_json::to_vec(&value) {
            return bytes;
        }
    }
    match std::str::from_utf8(body) {
        Ok(text) => cloak.restore(text).into_bytes(),
        Err(_) => body.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use crate::{Policy, Style, Surrogates};

    fn cloak() -> Cloak {
        Cloak::new(
            Policy::default(),
            Surrogates::from_secret(b"proxy json test", Style::Realistic),
        )
        .unwrap()
    }

    #[test]
    fn nested_message_content_is_scrubbed() {
        let mut cloak = cloak();
        let body = br#"{"model":"claude-fable-5-1","messages":[
            {"role":"user","content":[{"type":"text","text":"mail dana@corp.com"}]}
        ]}"#;
        let (out, changes) = scrub_body(&mut cloak, body, true);
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("dana@corp.com"));
        assert_eq!(changes.replacements.len(), 1);
    }

    #[test]
    fn structural_fields_are_left_alone() {
        let mut cloak = cloak();
        let body = br#"{"model":"claude-fable-5-1","max_tokens":1024,"stream":true,
            "messages":[{"role":"user","content":"refactor this loop"}]}"#;
        let (out, changes) = scrub_body(&mut cloak, body, true);
        assert!(changes.is_empty());
        let value: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["model"], "claude-fable-5-1");
        assert_eq!(value["messages"][0]["role"], "user");
    }

    #[test]
    fn a_body_round_trips_through_scrub_and_restore() {
        let mut cloak = cloak();
        let content = format!("key {}", fixtures::AWS_ACCESS_KEY_ID);
        let body = serde_json::to_vec(&serde_json::json!({
            "messages": [{"role": "user", "content": content}]
        }))
        .unwrap();

        let (scrubbed, _) = scrub_body(&mut cloak, &body, true);
        assert!(!String::from_utf8_lossy(&scrubbed).contains(fixtures::AWS_ACCESS_KEY_ID));

        let restored = restore_body(&mut cloak, &scrubbed, true);
        let value: Value = serde_json::from_slice(&restored).unwrap();
        assert_eq!(value["messages"][0]["content"], content);
    }

    #[test]
    fn plain_text_bodies_are_handled() {
        let mut cloak = cloak();
        let (out, changes) = scrub_body(&mut cloak, b"contact dana@corp.com", false);
        assert!(!String::from_utf8_lossy(&out).contains("dana@corp.com"));
        assert_eq!(changes.replacements.len(), 1);
    }

    #[test]
    fn binary_bodies_pass_through_unchanged() {
        let mut cloak = cloak();
        let body = &[0xffu8, 0xfe, 0x00, 0x01];
        let (out, changes) = scrub_body(&mut cloak, body, false);
        assert_eq!(out, body);
        assert!(changes.is_empty());
    }

    #[test]
    fn malformed_json_falls_back_to_text() {
        let mut cloak = cloak();
        let (out, changes) = scrub_body(&mut cloak, b"{ mail dana@corp.com", true);
        assert!(!String::from_utf8_lossy(&out).contains("dana@corp.com"));
        assert_eq!(changes.replacements.len(), 1);
    }

    #[test]
    fn an_earlier_turns_stand_in_is_not_substituted_again() {
        let mut cloak = cloak();
        let first = br#"{"messages":[{"role":"user","content":"mail dana@corp.com"}]}"#;
        let (once, _) = scrub_body(&mut cloak, first, true);
        let (twice, changes) = scrub_body(&mut cloak, &once, true);
        assert!(changes.is_empty(), "{:?}", changes.replacements);
        assert_eq!(once, twice);
    }
}

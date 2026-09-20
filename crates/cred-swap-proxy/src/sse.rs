//! Restoring real values in a streaming response.
//!
//! Restoring a stream is harder than restoring a document, because a stand-in
//! almost never arrives in one piece. A model streams `avery`, then `.ash`,
//! then `ford@globex.example`, each inside its own JSON event. Matching on the
//! raw bytes as they arrive would never see the whole stand-in, so nothing
//! would ever be restored.
//!
//! So this works on the decoded text instead. It reassembles the text deltas
//! into a running buffer, holds back the last few bytes — one less than the
//! longest stand-in in the vault, which is the most that could turn out to be
//! the start of one — and emits the rest with the originals put back. When
//! anything other than a text delta arrives, or the stream ends, the held-back
//! text is flushed first, so nothing is ever lost.
//!
//! The cost is latency: the client sees each token once the following few
//! bytes have arrived. In exchange the answer it displays contains the user's
//! real values rather than the stand-ins the model was given.

use std::sync::{Arc, Mutex};

use cred_swap_core::Cloak;
use serde_json::Value;

/// Where a provider puts the streamed text in its event payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// `{"delta": {"text": "..."}}`, as Anthropic's Messages API streams.
    DeltaText,
    /// `{"delta": {"content": "..."}}`.
    DeltaContent,
    /// `{"choices": [{"delta": {"content": "..."}}]}`, as `OpenAI`'s chat API streams.
    ChoiceDelta,
    /// `{"type": "response.output_text.delta", "delta": "..."}`.
    OutputTextDelta,
}

impl Shape {
    /// Recognise the payload shape, if this event carries streamed text at all.
    fn of(value: &Value) -> Option<Self> {
        if let Some(delta) = value.get("delta") {
            if delta.get("text").is_some_and(Value::is_string) {
                return Some(Self::DeltaText);
            }
            if delta.get("content").is_some_and(Value::is_string) {
                return Some(Self::DeltaContent);
            }
            if delta.is_string()
                && value
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind.ends_with("text.delta"))
            {
                return Some(Self::OutputTextDelta);
            }
        }
        let choice_content = value
            .get("choices")
            .and_then(|choices| choices.get(0))
            .and_then(|choice| choice.get("delta"))
            .and_then(|delta| delta.get("content"));
        if choice_content.is_some_and(Value::is_string) {
            return Some(Self::ChoiceDelta);
        }
        None
    }

    /// The text this event carries.
    fn read(self, value: &Value) -> &str {
        let found = match self {
            Self::DeltaText => value.pointer("/delta/text"),
            Self::DeltaContent => value.pointer("/delta/content"),
            Self::ChoiceDelta => value.pointer("/choices/0/delta/content"),
            Self::OutputTextDelta => value.pointer("/delta"),
        };
        found.and_then(Value::as_str).unwrap_or_default()
    }

    /// Overwrite the text this event carries.
    fn write(self, value: &mut Value, text: String) {
        let slot = match self {
            Self::DeltaText => value.pointer_mut("/delta/text"),
            Self::DeltaContent => value.pointer_mut("/delta/content"),
            Self::ChoiceDelta => value.pointer_mut("/choices/0/delta/content"),
            Self::OutputTextDelta => value.pointer_mut("/delta"),
        };
        if let Some(slot) = slot {
            *slot = Value::String(text);
        }
    }
}

/// A text-delta event kept so held-back text can be flushed in the same shape.
struct Template {
    block: String,
    shape: Shape,
}

/// Rewrites a server-sent event stream, putting real values back as it goes.
pub struct Restorer {
    cloak: Arc<Mutex<Cloak>>,
    /// Bytes received but not yet forming a complete event.
    raw: Vec<u8>,
    /// Decoded text emitted by the model but not yet passed on.
    pending: String,
    /// The most recent text-delta event, used to shape a flush.
    template: Option<Template>,
    /// Whether the vault was empty when the stream began.
    noop: bool,
}

impl Restorer {
    /// Start restoring a stream against a vault.
    #[must_use]
    pub fn new(cloak: Arc<Mutex<Cloak>>) -> Self {
        let noop = cloak.lock().is_ok_and(|guard| guard.vault().is_empty());
        Self {
            cloak,
            raw: Vec::new(),
            pending: String::new(),
            template: None,
            noop,
        }
    }

    /// Whether this stream needs rewriting at all.
    ///
    /// An empty vault has nothing to restore, so the proxy can hand the
    /// upstream body straight through without the buffering delay.
    #[must_use]
    pub const fn is_noop(&self) -> bool {
        self.noop
    }

    /// Feed in the next chunk of the upstream response.
    ///
    /// Returns the bytes to send on, which may be empty while an event is
    /// still incomplete.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.raw.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some((end, _)) = next_boundary(&self.raw) {
            let block: Vec<u8> = self.raw.drain(..end).collect();
            out.extend_from_slice(&self.process(&block));
        }
        out
    }

    /// Finish the stream, emitting everything held back.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.raw.is_empty() {
            let trailing: Vec<u8> = std::mem::take(&mut self.raw);
            out.extend_from_slice(&self.process(&trailing));
        }
        out.extend_from_slice(&self.flush());
        out
    }

    /// Handle one complete event block.
    fn process(&mut self, block: &[u8]) -> Vec<u8> {
        let Ok(text) = std::str::from_utf8(block) else {
            // Not text. Nothing here can be a stand-in, so pass it through
            // rather than risk corrupting it.
            return block.to_vec();
        };

        let Some(payload) = data_payload(text) else {
            return self.flush_then(block);
        };
        let Ok(mut value) = serde_json::from_str::<Value>(&payload) else {
            // `data: [DONE]` and other non-JSON sentinels land here.
            return self.flush_then(block);
        };
        let Some(shape) = Shape::of(&value) else {
            return self.flush_then(block);
        };

        self.pending.push_str(shape.read(&value));
        let restored = self.release();

        shape.write(&mut value, restored);
        let rendered = render(text, &value);
        self.template = Some(Template {
            block: text.to_owned(),
            shape,
        });
        rendered.into_bytes()
    }

    /// Emit everything held back, then the given block unchanged.
    fn flush_then(&mut self, block: &[u8]) -> Vec<u8> {
        let mut out = self.flush();
        out.extend_from_slice(block);
        out
    }

    /// Emit the held-back text as one more event in the last delta's shape.
    fn flush(&mut self) -> Vec<u8> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let remaining = std::mem::take(&mut self.pending);
        let restored = self.restore_all(&remaining);

        let Some(template) = &self.template else {
            // Text accumulated without any delta event having been seen, which
            // cannot happen: `pending` is only ever written from one.
            return Vec::new();
        };
        let Ok(mut value) =
            serde_json::from_str::<Value>(&data_payload(&template.block).unwrap_or_default())
        else {
            return Vec::new();
        };
        template.shape.write(&mut value, restored);
        render(&template.block, &value).into_bytes()
    }

    /// Emit whatever part of the buffer is settled, with originals restored.
    ///
    /// The vault decides how much that is, because only it knows where the
    /// stand-ins actually begin and end.
    fn release(&mut self) -> String {
        if self.pending.is_empty() {
            return String::new();
        }
        let Ok(mut guard) = self.cloak.lock() else {
            // The vault is unusable. Passing the text through unrestored is the
            // only option that does not lose the model's answer.
            return std::mem::take(&mut self.pending);
        };
        let (restored, consumed) = guard.restore_streaming(&self.pending);
        drop(guard);
        self.pending.drain(..consumed);
        restored
    }

    /// Restore a complete piece of text, holding nothing back.
    fn restore_all(&self, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }
        self.cloak
            .lock()
            .map_or_else(|_| text.to_owned(), |mut guard| guard.restore(text))
    }
}

/// The end offset of the first complete event in `buffer`, and its separator.
fn next_boundary(buffer: &[u8]) -> Option<(usize, usize)> {
    let crlf = find(buffer, b"\r\n\r\n");
    let lf = find(buffer, b"\n\n");
    match (crlf, lf) {
        (Some(c), Some(l)) if c <= l => Some((c + 4, 4)),
        (_, Some(l)) => Some((l + 2, 2)),
        (Some(c), None) => Some((c + 4, 4)),
        (None, None) => None,
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Concatenate an event's `data:` lines, the way the SSE spec defines it.
fn data_payload(block: &str) -> Option<String> {
    let mut parts = Vec::new();
    for line in block.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            parts.push(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

/// Rebuild an event block with a new payload, keeping its other fields.
///
/// The `event:` and `id:` lines matter to the client, so they survive
/// verbatim. Only the data is replaced, and multi-line data collapses to a
/// single line, which is equivalent under the SSE spec.
fn render(block: &str, value: &Value) -> String {
    let ending = if block.contains("\r\n") { "\r\n" } else { "\n" };
    let payload = serde_json::to_string(value).unwrap_or_default();

    let mut out = String::with_capacity(block.len() + payload.len());
    let mut wrote_data = false;
    for line in block.lines() {
        if line.starts_with("data:") {
            if !wrote_data {
                out.push_str("data: ");
                out.push_str(&payload);
                out.push_str(ending);
                wrote_data = true;
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        out.push_str(line);
        out.push_str(ending);
    }
    out.push_str(ending);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cred_swap_core::{Policy, Style, Surrogates};

    /// A cloak that has already substituted `dana@corp.com`, plus that stand-in.
    fn prepared() -> (Arc<Mutex<Cloak>>, String) {
        let mut cloak = Cloak::new(
            Policy::default(),
            Surrogates::from_secret(b"sse test", Style::Realistic),
        )
        .unwrap();
        let scrubbed = cloak.scrub("mail dana@corp.com");
        let fake = scrubbed.replacements[0].fake.clone();
        (Arc::new(Mutex::new(cloak)), fake)
    }

    fn anthropic_delta(text: &str) -> String {
        format!(
            "event: content_block_delta\ndata: {}\n\n",
            serde_json::json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": text}
            })
        )
    }

    /// Run a whole stream through and collect the decoded text deltas.
    fn drive(restorer: &mut Restorer, chunks: &[&str]) -> String {
        let mut raw = Vec::new();
        for chunk in chunks {
            raw.extend_from_slice(&restorer.push(chunk.as_bytes()));
        }
        raw.extend_from_slice(&restorer.finish());

        let rendered = String::from_utf8(raw).unwrap();
        let mut text = String::new();
        for block in rendered.split("\n\n") {
            if let Some(payload) = data_payload(block)
                && let Ok(value) = serde_json::from_str::<Value>(&payload)
                && let Some(shape) = Shape::of(&value)
            {
                text.push_str(shape.read(&value));
            }
        }
        text
    }

    #[test]
    fn a_stand_in_split_across_events_is_still_restored() {
        let (cloak, fake) = prepared();
        let mut restorer = Restorer::new(Arc::clone(&cloak));

        // Break the stand-in into single-character deltas, the worst case.
        let mut chunks: Vec<String> = vec![anthropic_delta("I would email ")];
        chunks.extend(fake.chars().map(|c| anthropic_delta(&c.to_string())));
        chunks.push(anthropic_delta(" first."));
        let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();

        assert_eq!(
            drive(&mut restorer, &refs),
            "I would email dana@corp.com first."
        );
    }

    #[test]
    fn a_stand_in_split_across_byte_chunks_is_still_restored() {
        let (cloak, fake) = prepared();
        let mut restorer = Restorer::new(Arc::clone(&cloak));

        // One event, delivered one byte at a time.
        let event = anthropic_delta(&format!("email {fake} first"));
        let chunks: Vec<String> = event
            .as_bytes()
            .chunks(1)
            .map(|b| String::from_utf8(b.to_vec()).unwrap())
            .collect();
        let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();

        assert_eq!(drive(&mut restorer, &refs), "email dana@corp.com first");
    }

    #[test]
    fn text_with_no_stand_ins_arrives_unchanged() {
        let (cloak, _) = prepared();
        let mut restorer = Restorer::new(cloak);
        let events: Vec<String> = ["Refactor ", "the ", "parser."]
            .iter()
            .map(|t| anthropic_delta(t))
            .collect();
        let refs: Vec<&str> = events.iter().map(String::as_str).collect();
        assert_eq!(drive(&mut restorer, &refs), "Refactor the parser.");
    }

    #[test]
    fn held_back_text_is_flushed_before_a_non_delta_event() {
        let (cloak, _) = prepared();
        let mut restorer = Restorer::new(cloak);
        let mut raw = Vec::new();
        raw.extend_from_slice(&restorer.push(anthropic_delta("tail text").as_bytes()));
        raw.extend_from_slice(
            &restorer.push(b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"),
        );
        let rendered = String::from_utf8(raw).unwrap();

        let stop = rendered.find("message_stop").unwrap();
        let tail = rendered.find("tail text").unwrap();
        assert!(
            tail < stop,
            "the held-back text came out after the stop event"
        );
    }

    #[test]
    fn the_done_sentinel_passes_through() {
        let (cloak, _) = prepared();
        let mut restorer = Restorer::new(cloak);
        let mut raw = Vec::new();
        raw.extend_from_slice(&restorer.push(anthropic_delta("hello").as_bytes()));
        raw.extend_from_slice(&restorer.push(b"data: [DONE]\n\n"));
        raw.extend_from_slice(&restorer.finish());
        let rendered = String::from_utf8(raw).unwrap();
        assert!(rendered.contains("[DONE]"), "{rendered}");
        assert!(rendered.contains("hello"), "{rendered}");
    }

    #[test]
    fn the_openai_chat_shape_is_understood() {
        let (cloak, fake) = prepared();
        let mut restorer = Restorer::new(cloak);
        let events: Vec<String> = ["ask ", &fake, " today"]
            .iter()
            .map(|text| {
                format!(
                    "data: {}\n\n",
                    serde_json::json!({"choices":[{"delta":{"content": text},"index":0}]})
                )
            })
            .collect();
        let refs: Vec<&str> = events.iter().map(String::as_str).collect();
        assert_eq!(drive(&mut restorer, &refs), "ask dana@corp.com today");
    }

    #[test]
    fn event_names_survive_the_rewrite() {
        let (cloak, _) = prepared();
        let mut restorer = Restorer::new(cloak);
        let mut raw = Vec::new();
        raw.extend_from_slice(
            &restorer.push(anthropic_delta("some fairly long text here").as_bytes()),
        );
        raw.extend_from_slice(&restorer.finish());
        let rendered = String::from_utf8(raw).unwrap();
        assert!(
            rendered.contains("event: content_block_delta"),
            "{rendered}"
        );
    }

    #[test]
    fn an_empty_vault_needs_no_buffering() {
        let cloak = Arc::new(Mutex::new(
            Cloak::new(
                Policy::default(),
                Surrogates::from_secret(b"empty", Style::Realistic),
            )
            .unwrap(),
        ));
        assert!(Restorer::new(cloak).is_noop());
    }

    #[test]
    fn carriage_returns_are_preserved() {
        let (cloak, _) = prepared();
        let mut restorer = Restorer::new(cloak);
        let mut raw = Vec::new();
        raw.extend_from_slice(&restorer.push(
            b"event: content_block_delta\r\ndata: {\"delta\":{\"text\":\"hi there everyone\"}}\r\n\r\n",
        ));
        raw.extend_from_slice(&restorer.finish());
        let rendered = String::from_utf8(raw).unwrap();
        assert!(rendered.contains("\r\n"), "{rendered:?}");
    }
}

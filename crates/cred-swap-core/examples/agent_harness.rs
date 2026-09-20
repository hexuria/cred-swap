//! Wiring cred-swap into an agent harness.
//!
//! Run it: `cargo run -p cred-swap-core --example agent_harness`
//!
//! A chat client needs two hooks — scrub what goes out, restore what comes
//! back. An agent harness needs four, because the model does not just talk
//! about your infrastructure, it asks you to act on it:
//!
//! 1. **Outbound request.** Scrub the whole request body. The model sees
//!    stand-ins.
//! 2. **Tool call arguments.** Restore them *before the tool runs*. The model
//!    was shown `northfield12.internal`, so it asks you to connect to
//!    `northfield12.internal`. Skip this hook and the agent dutifully tries,
//!    and fails, against a host that does not exist. This is the hook people
//!    forget, and it is the one that breaks the agent rather than leaking.
//! 3. **Tool result.** Scrub it on the way back. A file read or a command's
//!    output is where secrets actually enter a transcript.
//! 4. **Final answer.** Restore it, so the human reads real values.
//!
//! The same [`Session`] handles all four, so every hook agrees about which
//! stand-in means what.

use cred_swap_core::session::{Session, SessionStore};
use cred_swap_core::{Policy, Style};
use serde_json::{Value, json};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Built once at startup. The secret belongs wherever the deployment keeps
    // its other secrets; the directory makes sessions survive a restart.
    let store = SessionStore::builder()
        .policy(Policy::default())
        .style(Style::Realistic)
        .secret(b"a stable per-deployment secret")
        .build()?;

    // One handle per conversation. Any stable id will do.
    let session = store.session("run:8f21c4")?;

    let transcript = turn(&session)?;
    println!("{transcript}");
    Ok(())
}

fn turn(session: &Session) -> Result<String, Box<dyn std::error::Error>> {
    let mut report = String::new();

    // ---------------------------------------------------------------
    // Hook 1: the outbound request.
    // ---------------------------------------------------------------
    let mut request = json!({
        "model": "claude-fable-5-1",
        "max_tokens": 2048,
        "system": "You are a site reliability coworker.",
        "messages": [{
            "role": "user",
            "content": [{
                "type": "text",
                "text": "Checkout is erroring. Tail the app log on db.prod.internal \
                         and mail dana.reyes@northwind-logistics.com what you find."
            }]
        }]
    });

    let replaced = session.scrub_json(&mut request)?;
    report.push_str("1. OUTBOUND REQUEST\n");
    for replacement in &replaced {
        report.push_str(&format!(
            "     {:<14} {} -> {}\n",
            replacement.kind, replacement.real, replacement.fake
        ));
    }
    // Structural fields are untouched: the model name still routes correctly.
    assert_eq!(request["model"], "claude-fable-5-1");

    // ---------------------------------------------------------------
    // Hook 2: the tool call the model sends back.
    // ---------------------------------------------------------------
    // The provider saw a stand-in host, so it asks us to act on the stand-in.
    let stand_in_host = replaced
        .iter()
        .find(|replacement| replacement.real == "db.prod.internal")
        .map_or_else(String::new, |replacement| replacement.fake.clone());

    let mut tool_call = json!({
        "name": "ssh_run",
        "input": {"host": stand_in_host, "command": "tail -n 20 /var/log/app.log"}
    });

    report.push_str("\n2. TOOL CALL, as the model sent it\n");
    report.push_str(&format!("     host: {}\n", tool_call["input"]["host"]));

    session.restore_json(&mut tool_call)?;

    report.push_str("   TOOL CALL, as it will actually run\n");
    report.push_str(&format!("     host: {}\n", tool_call["input"]["host"]));
    assert_eq!(tool_call["input"]["host"], "db.prod.internal");
    assert_eq!(
        tool_call["name"], "ssh_run",
        "the tool name is not a secret"
    );

    // ---------------------------------------------------------------
    // Hook 3: the tool's output.
    // ---------------------------------------------------------------
    let raw_output = run_tool(&tool_call);
    let scrubbed_output = session.scrub(&raw_output)?;

    report.push_str("\n3. TOOL RESULT\n");
    report.push_str(&format!(
        "   as the box produced it:\n{}\n",
        indent(&raw_output)
    ));
    report.push_str(&format!(
        "   as the model will see it:\n{}\n",
        indent(&scrubbed_output.text)
    ));
    for replacement in &scrubbed_output.replacements {
        assert!(
            !scrubbed_output.text.contains(&replacement.real),
            "a real value survived into the tool result"
        );
    }

    // ---------------------------------------------------------------
    // Hook 4: the answer the human reads.
    // ---------------------------------------------------------------
    // A streamed reply arrives in pieces, so restore it the streaming way: a
    // stand-in split across two chunks still has to come back whole.
    let reply_chunks = [
        "The pool is exhausted. Connection string ",
        &scrubbed_output
            .replacements
            .iter()
            .find(|r| r.kind.as_str() == "database-url")
            .map_or_else(String::new, |r| r.fake.clone()),
        " is capped at 5. I would mail ",
        &replaced
            .iter()
            .find(|r| r.real.contains('@'))
            .map_or_else(String::new, |r| r.fake.clone()),
        " to confirm the window.",
    ];

    let mut pending = String::new();
    let mut shown = String::new();
    for chunk in reply_chunks {
        pending.push_str(chunk);
        let (emit, consumed) = session.restore_streaming(&pending)?;
        pending.drain(..consumed);
        shown.push_str(&emit);
    }
    shown.push_str(&session.restore(&pending)?);

    report.push_str("\n4. FINAL ANSWER, restored for the human\n");
    report.push_str(&format!("{}\n", indent(&shown)));
    assert!(shown.contains("db.prod.internal"));
    assert!(shown.contains("dana.reyes@northwind-logistics.com"));

    report.push_str(&format!(
        "\nVault now holds {} substitution(s) for this conversation.\n",
        session.entries()?.len()
    ));
    Ok(report)
}

/// Stands in for the box actually running the command.
fn run_tool(_call: &Value) -> String {
    "2026-09-20T05:12:44Z ERROR pool exhausted\n\
     2026-09-20T05:12:44Z  url=postgresql://appuser:s3cr3t-p4ssw0rd@db.prod.internal:5432/orders\n\
     2026-09-20T05:12:45Z  retry from 198.51.100.44 failed"
        .to_owned()
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|line| format!("     {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

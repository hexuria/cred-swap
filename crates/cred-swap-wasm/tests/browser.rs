//! Exercises the bindings in a real JavaScript runtime.
//!
//! The core crate's tests cover the rules. These cover the boundary: that the
//! seed really comes from Web Crypto, that results arrive as JavaScript
//! objects with the field names the documentation promises, and that a session
//! survives the export-and-reload round trip an extension depends on.
//!
//! Run with `wasm-pack test --node crates/cred-swap-wasm`.

#![cfg(target_arch = "wasm32")]

use cred_swap_wasm::{Cloak, kinds, new_seed};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

/// Read a string property off a JavaScript object.
fn get_string(value: &JsValue, key: &str) -> String {
    js_sys::Reflect::get(value, &JsValue::from_str(key))
        .ok()
        .and_then(|found| found.as_string())
        .unwrap_or_else(|| panic!("`{key}` is missing or not a string"))
}

fn get_array(value: &JsValue, key: &str) -> js_sys::Array {
    js_sys::Reflect::get(value, &JsValue::from_str(key))
        .ok()
        .and_then(|found| found.dyn_into::<js_sys::Array>().ok())
        .unwrap_or_else(|| panic!("`{key}` is missing or not an array"))
}

use wasm_bindgen::JsCast as _;

/// A synthetic GitHub token, assembled rather than written out.
///
/// See `cred_swap_core::fixtures` for why: a repository whose tests are made
/// of credential-shaped strings trips every secret scanner it is run through,
/// and a scanner nobody trusts is a scanner nobody reads.
fn github_token() -> String {
    format!("{}{}", concat!("ghp", "_"), "a".repeat(36))
}

#[wasm_bindgen_test]
fn the_seed_comes_from_web_crypto_and_is_not_constant() {
    let first = new_seed().expect("Web Crypto should be available");
    let second = new_seed().expect("Web Crypto should be available");
    assert_eq!(first.len(), 32);
    assert_ne!(
        first, second,
        "the seed generator returned the same bytes twice"
    );
    assert!(
        first.iter().any(|byte| *byte != 0),
        "the seed was all zeroes"
    );
}

#[wasm_bindgen_test]
fn scrub_returns_an_object_with_the_documented_fields() {
    let mut cloak = Cloak::create(&JsValue::UNDEFINED).expect("cloak should be created");
    let result = cloak
        .scrub("email dana@corp.com about it")
        .expect("scrub should succeed");

    let text = get_string(&result, "text");
    assert!(!text.contains("dana@corp.com"), "{text}");

    let replacements = get_array(&result, "replacements");
    assert_eq!(replacements.length(), 1);

    let first = replacements.get(0);
    assert_eq!(get_string(&first, "kind"), "email-address");
    assert_eq!(get_string(&first, "category"), "pii");
    assert_eq!(get_string(&first, "real"), "dana@corp.com");
    assert!(!get_string(&first, "fake").is_empty());
}

#[wasm_bindgen_test]
fn detect_reports_without_recording_anything() {
    let cloak = Cloak::create(&JsValue::UNDEFINED).expect("cloak should be created");
    let findings = cloak
        .detect("card 4242 4242 4242 4242")
        .expect("detect should succeed")
        .dyn_into::<js_sys::Array>()
        .expect("detect returns an array");

    assert_eq!(findings.length(), 1);
    assert_eq!(get_string(&findings.get(0), "kind"), "credit-card");
    assert_eq!(cloak.size(), 0, "looking at text should not fill the vault");
}

#[wasm_bindgen_test]
fn a_session_survives_export_and_reload() {
    let mut first = Cloak::create(&JsValue::UNDEFINED).expect("cloak should be created");
    let scrubbed = first
        .scrub("ping dana@corp.com")
        .expect("scrub should succeed");
    let sent = get_string(&scrubbed, "text");
    let exported = first.export_vault();

    let mut second =
        Cloak::from_vault(&exported, &JsValue::UNDEFINED).expect("vault should reload");
    assert_eq!(second.size(), 1);
    assert_eq!(second.restore(&sent), "ping dana@corp.com");

    // The seed survived, so a value first seen after reloading gets the same
    // stand-in it would have got before.
    let after = second
        .scrub("and new@corp.com")
        .expect("scrub should succeed");
    let before = first
        .scrub("and new@corp.com")
        .expect("scrub should succeed");
    assert_eq!(get_string(&after, "text"), get_string(&before, "text"));
}

#[wasm_bindgen_test]
fn two_sessions_with_the_same_seed_agree() {
    let seed = new_seed().expect("Web Crypto should be available");
    let mut left = Cloak::from_seed(&seed, &JsValue::UNDEFINED).expect("cloak should be created");
    let mut right = Cloak::from_seed(&seed, &JsValue::UNDEFINED).expect("cloak should be created");

    let a = left
        .scrub("mail dana@corp.com")
        .expect("scrub should succeed");
    let b = right
        .scrub("mail dana@corp.com")
        .expect("scrub should succeed");
    assert_eq!(get_string(&a, "text"), get_string(&b, "text"));
}

#[wasm_bindgen_test]
fn scrub_except_honours_the_users_choices_but_not_for_secrets() {
    let mut cloak = Cloak::create(&JsValue::UNDEFINED).expect("cloak should be created");
    let text = &format!("mail dana@corp.com with {}", github_token());

    let findings = cloak
        .detect(text)
        .expect("detect should succeed")
        .dyn_into::<js_sys::Array>()
        .expect("detect returns an array");

    // Untick everything, the way a user clicking every chip would.
    let mut keep = Vec::new();
    for index in 0..findings.length() {
        let finding = findings.get(index);
        let start = js_sys::Reflect::get(&finding, &JsValue::from_str("start"))
            .ok()
            .and_then(|value| value.as_f64())
            .expect("start is a number");
        keep.push(start as usize);
    }

    let result = cloak
        .scrub_except(text, keep)
        .expect("scrub should succeed");
    let out = get_string(&result, "text");

    assert!(
        out.contains("dana@corp.com"),
        "the unticked email was replaced anyway"
    );
    assert!(
        !out.contains(&github_token()),
        "a credential was left in place: {out}"
    );
}

#[wasm_bindgen_test]
fn streaming_restore_reassembles_a_split_stand_in() {
    let mut cloak = Cloak::create(&JsValue::UNDEFINED).expect("cloak should be created");
    let scrubbed = cloak
        .scrub("mail dana@corp.com")
        .expect("scrub should succeed");
    let fake = get_string(&get_array(&scrubbed, "replacements").get(0), "fake");

    let stream = format!("please write to {fake} today");
    let mut buffer = String::new();
    let mut assembled = String::new();

    for character in stream.chars() {
        buffer.push(character);
        let result = cloak
            .restore_streaming(&buffer)
            .expect("streaming restore should succeed")
            .dyn_into::<js_sys::Array>()
            .expect("restoreStreaming returns a pair");

        let emitted = result
            .get(0)
            .as_string()
            .expect("first element is a string");
        let consumed = result.get(1).as_f64().expect("second element is a number") as usize;

        assembled.push_str(&emitted);
        buffer.drain(..consumed);
    }
    assembled.push_str(&cloak.restore(&buffer));

    assert_eq!(assembled, "please write to dana@corp.com today");
}

#[wasm_bindgen_test]
fn options_shape_the_policy() {
    let options = js_sys::JSON::parse(r#"{"policy":"secrets"}"#).expect("valid JSON");
    let cloak = Cloak::create(&options).expect("cloak should be created");

    let findings = cloak
        .detect("mail dana@corp.com")
        .expect("detect should succeed")
        .dyn_into::<js_sys::Array>()
        .expect("detect returns an array");
    assert_eq!(
        findings.length(),
        0,
        "the secrets policy should skip an email"
    );
}

#[wasm_bindgen_test]
fn a_custom_pattern_reports_its_label() {
    let options = js_sys::JSON::parse(
        r#"{"policy":"none","patterns":[{"label":"ticket","regex":"\\bACME-\\d{4}\\b"}]}"#,
    )
    .expect("valid JSON");
    let cloak = Cloak::create(&options).expect("cloak should be created");

    let findings = cloak
        .detect("see ACME-1234")
        .expect("detect should succeed")
        .dyn_into::<js_sys::Array>()
        .expect("detect returns an array");

    assert_eq!(findings.length(), 1);
    assert_eq!(get_string(&findings.get(0), "kind"), "custom:ticket");
}

#[wasm_bindgen_test]
fn a_bad_option_is_reported_rather_than_ignored() {
    let options = js_sys::JSON::parse(r#"{"policy":"paranoid"}"#).expect("valid JSON");
    assert!(Cloak::create(&options).is_err());

    let options = js_sys::JSON::parse(r#"{"enable":["emial"]}"#).expect("valid JSON");
    assert!(Cloak::create(&options).is_err());

    let options = js_sys::JSON::parse(r#"{"polcy":"secrets"}"#).expect("valid JSON");
    assert!(
        Cloak::create(&options).is_err(),
        "a misspelled key should not be ignored"
    );
}

#[wasm_bindgen_test]
fn kinds_lists_every_rule_with_its_state() {
    let rows = kinds(&JsValue::UNDEFINED)
        .expect("kinds should succeed")
        .dyn_into::<js_sys::Array>()
        .expect("kinds returns an array");

    assert_eq!(rows.length(), 44);

    let mut saw_enabled_email = false;
    for index in 0..rows.length() {
        let row = rows.get(index);
        if get_string(&row, "kind") == "email-address" {
            saw_enabled_email = js_sys::Reflect::get(&row, &JsValue::from_str("enabled"))
                .ok()
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
        }
    }
    assert!(saw_enabled_email, "email-address should be on by default");
}

#[wasm_bindgen_test]
fn rerolling_an_unknown_value_returns_undefined() {
    let mut cloak = Cloak::create(&JsValue::UNDEFINED).expect("cloak should be created");
    assert!(cloak.reroll("never-seen@corp.com").unwrap().is_undefined());

    cloak
        .scrub("mail dana@corp.com")
        .expect("scrub should succeed");
    let entry = cloak
        .reroll("dana@corp.com")
        .expect("reroll should succeed");
    assert_eq!(get_string(&entry, "real"), "dana@corp.com");
}

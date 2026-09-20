//! Drives real HTTP through the proxy against a stub upstream.
//!
//! The unit tests check the pieces. These check the thing the user actually
//! relies on: that the provider never sees the real value, and that the client
//! does.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::post;
use cred_swap_core::{Cloak, Policy, Style, Surrogates};
use cred_swap_proxy::{Settings, serve};

/// What the stub upstream received, so a test can assert on it.
#[derive(Default)]
struct Seen {
    body: String,
    api_key: String,
}

type Recorder = Arc<Mutex<Seen>>;

/// Echo the received message content back as a non-streaming reply.
async fn echo(State(seen): State<Recorder>, body: axum::body::Bytes) -> impl IntoResponse {
    let text = String::from_utf8_lossy(&body).into_owned();
    let content = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|value| {
            value["messages"][0]["content"]
                .as_str()
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default();

    seen.lock().unwrap().body = text;

    axum::Json(serde_json::json!({
        "content": [{"type": "text", "text": format!("You said: {content}")}]
    }))
}

/// Stream the received content back one character per event, which is the
/// case that byte-window buffering gets wrong.
async fn echo_stream(State(seen): State<Recorder>, body: axum::body::Bytes) -> impl IntoResponse {
    let text = String::from_utf8_lossy(&body).into_owned();
    let content = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|value| {
            value["messages"][0]["content"]
                .as_str()
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default();

    seen.lock().unwrap().body = text;

    let mut out = String::new();
    for character in content.chars() {
        out.push_str(&format!(
            "event: content_block_delta\ndata: {}\n\n",
            serde_json::json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": character.to_string()}
            })
        ));
    }
    out.push_str("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");

    ([("content-type", "text/event-stream")], out)
}

async fn record_key(State(seen): State<Recorder>, headers: axum::http::HeaderMap) -> String {
    seen.lock().unwrap().api_key = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    "ok".into()
}

/// Start the stub upstream on an ephemeral port.
async fn start_upstream() -> (SocketAddr, Recorder) {
    let seen: Recorder = Arc::new(Mutex::new(Seen::default()));
    let app = Router::new()
        .route("/v1/messages", post(echo))
        .route("/v1/stream", post(echo_stream))
        .route("/v1/key", post(record_key))
        .with_state(Arc::clone(&seen));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, seen)
}

/// Start the proxy in front of `upstream`, returning its address.
async fn start_proxy(upstream: SocketAddr, cloak: Arc<Mutex<Cloak>>) -> SocketAddr {
    // Bind first so the test knows the port before the server takes ownership.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let settings = Settings {
        listen: addr,
        upstream: format!("http://{upstream}"),
        restore_responses: true,
        vault_path: None,
    };
    tokio::spawn(async move {
        let _ = serve(settings, cloak).await;
    });

    // Wait for the listener to come up rather than sleeping a fixed amount.
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return addr;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("proxy did not start listening on {addr}");
}

fn cloak() -> Arc<Mutex<Cloak>> {
    Arc::new(Mutex::new(
        Cloak::new(
            Policy::default(),
            Surrogates::from_secret(b"end to end", Style::Realistic),
        )
        .unwrap(),
    ))
}

#[tokio::test]
async fn the_upstream_never_sees_the_real_value_and_the_client_gets_it_back() {
    let (upstream, seen) = start_upstream().await;
    let proxy = start_proxy(upstream, cloak()).await;

    let response = reqwest::Client::new()
        .post(format!("http://{proxy}/v1/messages"))
        .json(&serde_json::json!({
            "model": "claude-fable-5-1",
            "messages": [{"role": "user", "content": "email dana@corp.com about the invoice"}]
        }))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
    let reply: serde_json::Value = response.json().await.unwrap();

    let received = seen.lock().unwrap().body.clone();
    assert!(
        !received.contains("dana@corp.com"),
        "the real address reached the upstream: {received}"
    );
    assert!(
        received.contains("@"),
        "a stand-in address should have reached the upstream: {received}"
    );

    let text = reply["content"][0]["text"].as_str().unwrap();
    assert_eq!(text, "You said: email dana@corp.com about the invoice");
}

#[tokio::test]
async fn the_path_and_query_reach_the_upstream_unchanged() {
    let (upstream, _) = start_upstream().await;
    let proxy = start_proxy(upstream, cloak()).await;

    let response = reqwest::Client::new()
        .post(format!("http://{proxy}/v1/nope?beta=true"))
        .body("{}")
        .send()
        .await
        .unwrap();

    // The stub has no such route, so a 404 proves the path was forwarded
    // rather than swallowed or rewritten by the proxy.
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn the_clients_own_api_key_is_forwarded_untouched() {
    let (upstream, seen) = start_upstream().await;
    let proxy = start_proxy(upstream, cloak()).await;

    reqwest::Client::new()
        .post(format!("http://{proxy}/v1/key"))
        .header("x-api-key", "the-users-real-provider-key")
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(
        seen.lock().unwrap().api_key,
        "the-users-real-provider-key",
        "the proxy must not scrub the credential the provider needs"
    );
}

#[tokio::test]
async fn a_stand_in_streamed_one_character_at_a_time_is_restored() {
    let (upstream, seen) = start_upstream().await;
    let proxy = start_proxy(upstream, cloak()).await;

    let response = reqwest::Client::new()
        .post(format!("http://{proxy}/v1/stream"))
        .json(&serde_json::json!({
            "messages": [{"role": "user", "content": "ping dana@corp.com now"}],
            "stream": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
        "text/event-stream"
    );

    let received = seen.lock().unwrap().body.clone();
    assert!(
        !received.contains("dana@corp.com"),
        "the real address reached the upstream: {received}"
    );

    // Reassemble the streamed deltas the way a client would.
    let raw = response.text().await.unwrap();
    let mut assembled = String::new();
    for block in raw.split("\n\n") {
        for line in block.lines() {
            let Some(payload) = line.strip_prefix("data: ") else {
                continue;
            };
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(payload)
                && let Some(text) = value["delta"]["text"].as_str()
            {
                assembled.push_str(text);
            }
        }
    }

    assert_eq!(assembled, "ping dana@corp.com now");
}

#[tokio::test]
async fn a_multi_turn_conversation_keeps_one_stand_in_per_value() {
    let (upstream, seen) = start_upstream().await;
    let shared = cloak();
    let proxy = start_proxy(upstream, Arc::clone(&shared)).await;
    let client = reqwest::Client::new();

    let mut transcript = String::from("ping dana@corp.com");
    for _ in 0..3 {
        let response = client
            .post(format!("http://{proxy}/v1/messages"))
            .json(&serde_json::json!({
                "messages": [{"role": "user", "content": transcript}]
            }))
            .send()
            .await
            .unwrap();
        let reply: serde_json::Value = response.json().await.unwrap();
        transcript = reply["content"][0]["text"].as_str().unwrap().to_owned();
    }

    let received = seen.lock().unwrap().body.clone();
    assert!(!received.contains("dana@corp.com"), "{received}");
    assert!(transcript.contains("dana@corp.com"), "{transcript}");
    assert_eq!(
        shared.lock().unwrap().vault().len(),
        1,
        "each turn minted a new stand-in instead of reusing the first"
    );
}

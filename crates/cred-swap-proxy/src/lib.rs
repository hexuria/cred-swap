//! A local reverse proxy that scrubs what you send to a model and restores
//! what comes back.
//!
//! Point any client at it instead of the provider — change one base URL — and
//! every request body is rewritten on the way out and every response body on
//! the way back. Nothing about the client changes: it sends its own API key in
//! its own headers, which this never touches, and it receives an answer
//! containing its own real values.
//!
//! ```no_run
//! use std::sync::{Arc, Mutex};
//! use cred_swap_core::{Cloak, Policy, Style, Surrogates};
//! use cred_swap_proxy::{Settings, serve};
//!
//! # async fn run() -> anyhow::Result<()> {
//! let cloak = Cloak::new(Policy::default(), Surrogates::random(Style::Realistic))?;
//! let settings = Settings {
//!     listen: "127.0.0.1:8787".parse()?,
//!     upstream: "https://api.anthropic.com".into(),
//!     restore_responses: true,
//!     vault_path: None,
//! };
//! serve(settings, Arc::new(Mutex::new(cloak))).await
//! # }
//! ```
//!
//! # What it does not protect against
//!
//! The proxy sees only what passes through it. A value the detector does not
//! recognise goes upstream unchanged. Request bodies are rewritten, headers
//! are not, which is deliberate: the client's own credential has to reach the
//! provider for the call to work at all.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod json;
pub mod sse;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result};
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use cred_swap_core::Cloak;
use futures_util::StreamExt as _;

/// Largest request or response body the proxy will buffer, in bytes.
///
/// Model API payloads are text, and a request larger than this is not a
/// conversation. Refusing it is better than letting a malformed or hostile
/// client exhaust memory.
const MAX_BODY: usize = 64 * 1024 * 1024;

/// Headers that describe a specific hop and must not be forwarded.
///
/// `accept-encoding` is dropped on purpose: a compressed body cannot be
/// rewritten without decompressing it, so the proxy asks upstream for plain
/// bytes rather than silently passing secrets through untouched.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "accept-encoding",
    "content-encoding",
];

/// How the proxy should behave.
pub struct Settings {
    /// Address to listen on. Bind to loopback unless you mean otherwise: the
    /// vault behind this proxy holds every real value it has seen.
    pub listen: SocketAddr,
    /// Base URL to forward to, such as `https://api.anthropic.com`.
    pub upstream: String,
    /// Whether to put real values back in responses.
    pub restore_responses: bool,
    /// Where to write the vault after each request.
    ///
    /// `None` keeps it in memory and leaves saving to the caller, which is
    /// faster; `Some` survives a crash.
    pub vault_path: Option<PathBuf>,
}

struct Shared {
    client: reqwest::Client,
    upstream: String,
    restore_responses: bool,
    vault_path: Option<PathBuf>,
    cloak: Arc<Mutex<Cloak>>,
}

/// Run the proxy until interrupted.
///
/// # Errors
///
/// Returns an error if the listen address cannot be bound or the server stops
/// with a failure.
pub async fn serve(settings: Settings, cloak: Arc<Mutex<Cloak>>) -> Result<()> {
    let upstream = settings.upstream.trim_end_matches('/').to_owned();
    if !upstream.starts_with("http://") && !upstream.starts_with("https://") {
        anyhow::bail!("upstream `{upstream}` must start with http:// or https://");
    }

    let shared = Arc::new(Shared {
        client: reqwest::Client::builder()
            .build()
            .context("cannot build the upstream HTTP client")?,
        upstream: upstream.clone(),
        restore_responses: settings.restore_responses,
        vault_path: settings.vault_path,
        cloak,
    });

    let app = Router::new().fallback(handle).with_state(shared);

    let listener = tokio::net::TcpListener::bind(settings.listen)
        .await
        .with_context(|| format!("cannot listen on {}", settings.listen))?;

    let bound = listener.local_addr().unwrap_or(settings.listen);
    tracing::info!(%bound, %upstream, "cred-swap proxy listening");
    eprintln!("cred-swap: proxying http://{bound} -> {upstream}");
    eprintln!("cred-swap: point your client's base URL at http://{bound}");

    axum::serve(listener, app)
        .with_graceful_shutdown(interrupted())
        .await
        .context("proxy stopped unexpectedly")
}

async fn interrupted() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!();
    eprintln!("cred-swap: shutting down");
}

/// Anything that stopped a request from being proxied.
struct ProxyError(anyhow::Error);

impl From<anyhow::Error> for ProxyError {
    fn from(error: anyhow::Error) -> Self {
        Self(error)
    }
}

impl IntoResponse for ProxyError {
    /// Report the failure as a JSON body, so a client that only parses JSON
    /// still gets something it can print.
    fn into_response(self) -> Response {
        tracing::error!(error = %self.0, "request failed");
        let body = serde_json::json!({
            "error": {
                "type": "cred_swap_proxy_error",
                "message": self.0.to_string(),
            }
        });
        (StatusCode::BAD_GATEWAY, axum::Json(body)).into_response()
    }
}

async fn handle(
    State(shared): State<Arc<Shared>>,
    request: axum::extract::Request,
) -> Result<Response, ProxyError> {
    let (parts, body) = request.into_parts();

    let body = axum::body::to_bytes(body, MAX_BODY)
        .await
        .map_err(|error| anyhow::anyhow!("request body could not be read: {error}"))?;

    let is_json = mentions(&parts.headers, "content-type", "json");
    let (scrubbed, changes) = {
        let mut guard = shared.cloak.lock().map_err(poisoned)?;
        json::scrub_body(&mut guard, &body, is_json)
    };

    if !changes.is_empty() {
        let mut kinds: Vec<&str> = changes
            .replacements
            .iter()
            .map(|replacement| replacement.kind.as_str())
            .collect();
        kinds.sort_unstable();
        kinds.dedup();
        tracing::info!(
            path = %parts.uri.path(),
            replaced = changes.replacements.len(),
            kinds = kinds.join(","),
            "scrubbed request"
        );
    }

    let target = format!(
        "{}{}",
        shared.upstream,
        parts
            .uri
            .path_and_query()
            .map_or_else(|| parts.uri.path().to_owned(), ToString::to_string)
    );

    let response = shared
        .client
        .request(parts.method.clone(), &target)
        .headers(forwardable(&parts.headers))
        .body(scrubbed)
        .send()
        .await
        .with_context(|| format!("upstream request to {target} failed"))?;

    if let Some(path) = &shared.vault_path {
        let guard = shared.cloak.lock().map_err(poisoned)?;
        guard
            .vault()
            .save(path)
            .with_context(|| format!("cannot save the vault to {}", path.display()))?;
    }

    build_response(&shared, response).await
}

async fn build_response(
    shared: &Arc<Shared>,
    response: reqwest::Response,
) -> Result<Response, ProxyError> {
    let status = response.status();
    let headers = forwardable(response.headers());
    let streaming = mentions(response.headers(), "content-type", "event-stream");
    let is_json = mentions(response.headers(), "content-type", "json");

    let mut out = Response::builder().status(status);
    if let Some(slot) = out.headers_mut() {
        *slot = headers;
    }

    if !shared.restore_responses {
        return finish(out, passthrough(response));
    }

    if streaming {
        let restorer = sse::Restorer::new(Arc::clone(&shared.cloak));
        if restorer.is_noop() {
            // Nothing has been substituted yet, so there is nothing to put
            // back and no reason to make the client wait for a buffer.
            return finish(out, passthrough(response));
        }
        return finish(out, restoring_stream(response, restorer));
    }

    let body = response
        .bytes()
        .await
        .context("upstream response body could not be read")?;
    let restored = {
        let mut guard = shared.cloak.lock().map_err(poisoned)?;
        json::restore_body(&mut guard, &body, is_json)
    };
    finish(out, Body::from(restored))
}

fn finish(builder: http::response::Builder, body: Body) -> Result<Response, ProxyError> {
    builder
        .body(body)
        .context("cannot assemble the response")
        .map_err(ProxyError::from)
}

/// Forward the upstream body byte for byte.
fn passthrough(response: reqwest::Response) -> Body {
    Body::from_stream(response.bytes_stream())
}

/// Forward the upstream body through the streaming restorer.
fn restoring_stream(response: reqwest::Response, restorer: sse::Restorer) -> Body {
    let upstream = Box::pin(response.bytes_stream());

    let stream = futures_util::stream::unfold(
        (upstream, restorer, false),
        |(mut upstream, mut restorer, done)| async move {
            if done {
                return None;
            }
            match upstream.next().await {
                Some(Ok(chunk)) => {
                    let out = restorer.push(&chunk);
                    Some((Ok(Bytes::from(out)), (upstream, restorer, false)))
                }
                Some(Err(error)) => Some((
                    Err(std::io::Error::other(error)),
                    (upstream, restorer, true),
                )),
                None => {
                    let out = restorer.finish();
                    Some((Ok(Bytes::from(out)), (upstream, restorer, true)))
                }
            }
        },
    );

    Body::from_stream(stream)
}

/// Copy the headers that belong to the message rather than the connection.
fn forwardable(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        out.insert(name.clone(), value.clone());
    }
    // Ask upstream not to compress, since a compressed body cannot be
    // rewritten on the way back.
    out.insert(
        HeaderName::from_static("accept-encoding"),
        HeaderValue::from_static("identity"),
    );
    out
}

fn mentions(headers: &HeaderMap, name: &str, needle: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains(needle))
}

/// The vault mutex was poisoned by a panic in another request.
///
/// Continuing would mean scrubbing against a half-updated vault, which could
/// send a real value upstream, so every later request fails loudly instead.
fn poisoned<T>(_: std::sync::PoisonError<T>) -> ProxyError {
    ProxyError(anyhow::anyhow!(
        "the vault was left in an unknown state by an earlier failure; restart the proxy"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_headers_are_dropped_and_encoding_is_forced() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:8787"));
        headers.insert("content-length", HeaderValue::from_static("42"));
        headers.insert("accept-encoding", HeaderValue::from_static("gzip"));
        headers.insert("x-api-key", HeaderValue::from_static("secret-key"));
        headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));

        let out = forwardable(&headers);
        assert!(!out.contains_key("host"));
        assert!(!out.contains_key("content-length"));
        assert_eq!(out["accept-encoding"], "identity");
        // The client's own credential has to survive, or nothing works.
        assert_eq!(out["x-api-key"], "secret-key");
        assert_eq!(out["anthropic-version"], "2023-06-01");
    }

    #[test]
    fn content_type_matching_ignores_case_and_parameters() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("Application/JSON; charset=utf-8"),
        );
        assert!(mentions(&headers, "content-type", "json"));
        assert!(!mentions(&headers, "content-type", "event-stream"));
    }
}

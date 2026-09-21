//! Per-RPC trace-ID layer.
//!
//! Wraps every incoming gRPC request in a tracing span with a
//! `request_id` field populated from either the caller-supplied
//! `x-request-id` metadata or a freshly-generated UUID. All
//! `tracing` events emitted inside the handler inherit the
//! request_id, so JSON log lines can be correlated end-to-end.
//!
//! Threading: span is captured per request (each call gets its own
//! span); the layer is `Clone` and `Send` to satisfy tower's
//! contract with multiple worker threads.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{HeaderValue, Request, Response};
use tower_layer::Layer;
use tower_service::Service;
use tracing::Instrument;

const REQUEST_ID_HEADER: &str = "x-request-id";

/// Maximum caller-supplied `x-request-id` bytes recorded in spans and
/// logs (W1-C3-25). HTTP/2 already caps header size on the wire; this
/// keeps log lines bounded when a caller sends a maximal header.
/// Generated UUIDs (36 chars) are always under the cap.
const MAX_REQUEST_ID_LEN: usize = 128;

/// Marker appended when a caller-supplied id is truncated.
const TRUNCATED_MARKER: &str = "[truncated]";

/// Bound a caller-supplied request id: verbatim when it fits, truncated
/// with a marker when it does not. Truncation respects char boundaries
/// and the result never exceeds [`MAX_REQUEST_ID_LEN`].
fn bound_request_id(id: &str) -> String {
    if id.len() <= MAX_REQUEST_ID_LEN {
        return id.to_string();
    }
    let mut end = MAX_REQUEST_ID_LEN - TRUNCATED_MARKER.len();
    while !id.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{TRUNCATED_MARKER}", &id[..end])
}

#[derive(Clone, Default)]
pub struct TraceIdLayer;

impl<S> Layer<S> for TraceIdLayer {
    type Service = TraceIdService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceIdService { inner }
    }
}

#[derive(Clone)]
pub struct TraceIdService<S> {
    inner: S,
}

impl<S, ReqBody, RespBody> Service<Request<ReqBody>> for TraceIdService<S>
where
    S: Service<Request<ReqBody>, Response = Response<RespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let request_id = req
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(bound_request_id)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // Make the ID available to handler-side logic too, even though
        // most handlers will read it only via the tracing context.
        if !req.headers().contains_key(REQUEST_ID_HEADER)
            && let Ok(val) = HeaderValue::from_str(&request_id)
        {
            req.headers_mut().insert(REQUEST_ID_HEADER, val);
        }
        let method = req.uri().path().to_owned();
        let span = tracing::info_span!(
            "rpc",
            request_id = %request_id,
            method = %method,
        );

        // Inner future inherits the span; nested tracing events will
        // automatically include `request_id` as a field.
        // W1-C3-18: clone-only; the old replace-then-restore was a no-op.
        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await }.instrument(span))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // W1-C3-25: ordinary caller ids (and exactly-at-cap ids) are
    // recorded verbatim.
    #[test]
    fn normal_request_id_verbatim() {
        assert_eq!(bound_request_id("abc-123"), "abc-123");
        assert_eq!(bound_request_id(""), "");
        let at_cap = "x".repeat(MAX_REQUEST_ID_LEN);
        assert_eq!(bound_request_id(&at_cap), at_cap);
    }

    // W1-C3-25: overlong caller ids are truncated with a marker and
    // never exceed the cap.
    #[test]
    fn overlong_request_id_truncated_with_marker() {
        let long = "y".repeat(MAX_REQUEST_ID_LEN + 1);
        let bounded = bound_request_id(&long);
        assert!(bounded.ends_with(TRUNCATED_MARKER), "{bounded}");
        assert!(bounded.len() <= MAX_REQUEST_ID_LEN, "{bounded}");
        assert!(bounded.starts_with(&"y".repeat(MAX_REQUEST_ID_LEN - TRUNCATED_MARKER.len())));
    }

    // W1-C3-25: truncation must respect char boundaries (multi-byte
    // chars near the cut point must not panic or split).
    #[test]
    fn truncation_respects_char_boundaries() {
        let long = format!("{}éééé", "z".repeat(MAX_REQUEST_ID_LEN));
        let bounded = bound_request_id(&long);
        assert!(bounded.ends_with(TRUNCATED_MARKER), "{bounded}");
        assert!(bounded.len() <= MAX_REQUEST_ID_LEN, "{bounded}");
    }
}

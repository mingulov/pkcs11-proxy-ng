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
            .map(String::from)
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
        let mut inner = self.inner.clone();
        let std_inner = std::mem::replace(&mut self.inner, inner.clone());
        self.inner = std_inner;
        Box::pin(async move { inner.call(req).await }.instrument(span))
    }
}

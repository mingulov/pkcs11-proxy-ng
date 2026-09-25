//! Per-RPC client-side deadline (W1-C10-01).
//!
//! Every RPC the client issues passes through [`RpcDeadline`], a thin tower
//! layer over the tonic `Channel` that bounds each call — including lazy
//! connection establishment — by [`Pkcs11Client::rpc_timeout`]. A wedged
//! daemon that answers TCP (or nothing at all) can therefore never hang a
//! caller past the deadline; expiry surfaces as
//! `Code::DeadlineExceeded`, which the client's transport mapping already
//! turns into `CKR_FUNCTION_FAILED` (in every entry point's
//! spec-permitted set).
//!
//! Why a client-crate layer instead of `Endpoint::timeout`: the tonic
//! endpoint timeout cannot be applied to a pre-built `Channel`
//! (`Pkcs11Client::from_channel`), and tonic maps its own timeout expiry
//! to `Code::Cancelled` (client-visible `CKR_FUNCTION_CANCELED`), which
//! misdescribes a timeout. This layer yields a real `DeadlineExceeded`
//! status on every construction path and is reconfigurable at runtime via
//! [`Pkcs11Client::set_rpc_timeout`].

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// Default per-RPC deadline (W1-C10-01): 60 seconds.
///
/// Bounds a wedged daemon without tripping slow-but-healthy operations
/// (HSM key generation and attestation can take tens of seconds).
/// Override per client with [`Pkcs11Client::set_rpc_timeout`][crate::client::Pkcs11Client::set_rpc_timeout].
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(60);

/// Tower layer bounding each gRPC call (and lazy connect) by `timeout`.
///
/// Expiry is reported as a tonic `DeadlineExceeded` status so the
/// downstream `grpc_status_to_ck_rv*` mapping classifies it exactly like a
/// wire deadline: `CKR_FUNCTION_FAILED`, plus the transport-failure hook
/// (a deadline trip means the daemon is wedged — the channel SHOULD be
/// recycled, same as any transport failure).
/// Local twin of tonic's (private) `BoxError`: `Box<dyn Error + Send +
/// Sync>`. Identical type, so the blanket `GrpcService` impl's
/// `Into<BoxError>` bound is satisfied by reflexivity.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone)]
pub(crate) struct RpcDeadline<S> {
    inner: S,
    timeout: Duration,
}

impl<S> RpcDeadline<S> {
    pub(crate) fn new(inner: S, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl<S, ReqBody, ResBody> tower::Service<http::Request<ReqBody>> for RpcDeadline<S>
where
    S: tower::Service<http::Request<ReqBody>, Response = http::Response<ResBody>>,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = http::Response<ResBody>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: http::Request<ReqBody>) -> Self::Future {
        let call = self.inner.call(request);
        let timeout = self.timeout;
        Box::pin(async move {
            match tokio::time::timeout(timeout, call).await {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(error)) => Err(error.into()),
                Err(_) => Err(tonic::Status::deadline_exceeded(
                    "pkcs11-proxy-ng client RPC deadline exceeded",
                )
                .into()),
            }
        })
    }
}

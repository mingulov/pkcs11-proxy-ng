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
//!
//! Operator knob (D6): `PKCS11_PROXY_RPC_TIMEOUT_SECS` overrides the
//! 60-second default at client construction. A trimmed positive integer
//! is taken as seconds; unset, unparseable, or zero values fall back to
//! [`DEFAULT_RPC_TIMEOUT`] (a set-but-ignored value logs a warning — the
//! shim's `PKCS11_PROXY_CONNECT_*` tolerance style). The shim inherits
//! the knob because it builds its client through these constructors.
//!
//! Raising this deadline only helps if the server is raised to match:
//! the daemon independently abandons a backend call at its own
//! `proxy.request_timeout_secs` (default 60s as well), so an operation
//! longer than the server timeout still fails there no matter how long
//! the client is willing to wait. The effective bound is the smaller
//! of the two; raise both together.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// Default per-RPC deadline (W1-C10-01): 60 seconds.
///
/// Bounds a wedged daemon without tripping slow-but-healthy operations
/// (HSM key generation and attestation can take tens of seconds).
/// Operators override it at client construction with
/// `PKCS11_PROXY_RPC_TIMEOUT_SECS` (see [`default_rpc_timeout`]), or per
/// client with [`Pkcs11Client::set_rpc_timeout`][crate::client::Pkcs11Client::set_rpc_timeout].
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(60);

/// Env var overriding the per-RPC deadline at client construction (D6).
const RPC_TIMEOUT_ENV_VAR: &str = "PKCS11_PROXY_RPC_TIMEOUT_SECS";

/// Resolve the effective default deadline from a raw env value: a
/// trimmed positive integer is taken as seconds; unset, unparseable, or
/// zero falls back to [`DEFAULT_RPC_TIMEOUT`]. Pure so the parse matrix
/// is unit-tested without mutating process-global env (the shim's
/// `connect_attempts_from_value` pattern).
pub(crate) fn rpc_timeout_from_value(raw: Option<&str>) -> Duration {
    raw.and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_RPC_TIMEOUT)
}

/// Loud warning when `PKCS11_PROXY_RPC_TIMEOUT_SECS` is set but will be
/// ignored. The predicate matches [`rpc_timeout_from_value`] exactly
/// (trimmed positive `u64`), so the warning fires exactly when the
/// default engages despite a set value — never silently.
pub(crate) fn rpc_timeout_warning(raw: Option<&str>) -> Option<String> {
    match raw {
        None => None,
        Some(value) => match value.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => None,
            _ => Some(format!(
                "{RPC_TIMEOUT_ENV_VAR}={value:?} is not a valid positive number of seconds; \
                 using default {}",
                DEFAULT_RPC_TIMEOUT.as_secs()
            )),
        },
    }
}

/// The deadline a freshly constructed client starts with:
/// `PKCS11_PROXY_RPC_TIMEOUT_SECS` when set to a positive integer,
/// [`DEFAULT_RPC_TIMEOUT`] otherwise.
pub(crate) fn default_rpc_timeout() -> Duration {
    let raw = std::env::var(RPC_TIMEOUT_ENV_VAR).ok();
    if let Some(warning) = rpc_timeout_warning(raw.as_deref()) {
        tracing::warn!("{warning}");
    }
    rpc_timeout_from_value(raw.as_deref())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    // D6: `PKCS11_PROXY_RPC_TIMEOUT_SECS` resolves through the pure
    // parser, so the matrix below needs no process-global env mutation
    // (the shim's `connect_attempts_from_value` pattern).
    #[test]
    fn rpc_timeout_unset_falls_back_to_sixty_seconds() {
        assert_eq!(rpc_timeout_from_value(None), Duration::from_secs(60));
        assert_eq!(rpc_timeout_from_value(None), DEFAULT_RPC_TIMEOUT);
    }

    #[test]
    fn rpc_timeout_valid_value_is_used() {
        assert_eq!(rpc_timeout_from_value(Some("120")), Duration::from_secs(120));
        assert_eq!(rpc_timeout_from_value(Some("1")), Duration::from_secs(1));
        // Neighbouring parsers trim before parsing.
        assert_eq!(rpc_timeout_from_value(Some(" 30 ")), Duration::from_secs(30));
    }

    #[test]
    fn rpc_timeout_invalid_and_zero_fall_back_to_sixty_seconds() {
        for raw in ["junk", "", "0", "-5", "1.5"] {
            assert_eq!(
                rpc_timeout_from_value(Some(raw)),
                Duration::from_secs(60),
                "{raw:?} must fall back to the 60s default"
            );
        }
    }

    #[test]
    fn rpc_timeout_warning_fires_exactly_when_a_set_value_is_ignored() {
        assert_eq!(rpc_timeout_warning(None), None);
        assert_eq!(rpc_timeout_warning(Some("120")), None);
        for raw in ["junk", "0"] {
            let warning = rpc_timeout_warning(Some(raw)).expect("ignored value must warn");
            assert!(
                warning.contains("PKCS11_PROXY_RPC_TIMEOUT_SECS") && warning.contains(raw),
                "warning must name the var and the value: {warning}"
            );
        }
    }
}

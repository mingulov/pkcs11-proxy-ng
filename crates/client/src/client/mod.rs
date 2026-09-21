use pkcs11_proxy_ng_proto::Pkcs11ProxyClient as GrpcClient;
use pkcs11_proxy_ng_types::*;

use crate::error::MessageCallError;

macro_rules! pkcs11_template {
    ($template:expr) => {{ $template.iter().map(pkcs11_proxy_ng_proto::Attribute::from).collect::<Vec<_>>() }};
}

macro_rules! pkcs11_unary_call {
    ($call:expr, $is_session_scoped:expr) => {{ $crate::client::unary_prologue($call, $is_session_scoped, |response| response.ck_rv).await? }};
}

macro_rules! pkcs11_unary_map {
    ($call:expr, $is_session_scoped:expr, $resp:ident => $body:expr) => {{
        let $resp =
            $crate::client::unary_prologue($call, $is_session_scoped, |response| response.ck_rv)
                .await?;
        Ok($body)
    }};
}

macro_rules! pkcs11_unary_ok {
    ($call:expr, $is_session_scoped:expr) => {{
        $crate::client::unary_prologue($call, $is_session_scoped, |response| response.ck_rv)
            .await?;
        Ok::<(), CkRv>(())
    }};
}

/// Shared await/map/`into_inner`/RV-check prologue for the `pkcs11_unary_*`
/// macros (W1-L11-04): one definition of the transport-error mapping and the
/// backend-`ck_rv` early return. The macros differ only in how they shape the
/// success value (raw response, mapped body, unit). `ck_rv_of` extracts the
/// `ck_rv` field every unary response carries.
pub(crate) async fn unary_prologue<Fut, Resp>(
    call: Fut,
    is_session_scoped: bool,
    ck_rv_of: impl FnOnce(&Resp) -> u64,
) -> CkResult<Resp>
where
    Fut: std::future::Future<Output = Result<tonic::Response<Resp>, tonic::Status>>,
{
    let response = call
        .await
        .map_err(|status| crate::error::grpc_status_to_ck_rv(status.code(), is_session_scoped))?
        .into_inner();
    let rv = CkRv(ck_rv_of(&response));
    if rv.is_err() {
        return Err(rv);
    }
    Ok(response)
}

/// Generic core for stateful unit (`ck_rv`-only) session calls (W1-L11-08):
/// one definition of the transport-error mapping and the backend-`ck_rv`
/// decode, shared by `close_session_stateful` and `session_cancel_stateful`.
/// Parameterized by the already-built gRPC call future (which fixes the
/// request type and method); `ck_rv_of` extracts the `ck_rv` field the
/// response carries. Session-scoped mapping, matching both callers.
pub(crate) async fn stateful_unit_call<Fut, Resp>(
    call: Fut,
    ck_rv_of: impl FnOnce(&Resp) -> u64,
) -> Result<(), MessageCallError>
where
    Fut: std::future::Future<Output = Result<tonic::Response<Resp>, tonic::Status>>,
{
    let response = call
        .await
        .map_err(|status| {
            MessageCallError::transport(crate::error::grpc_status_to_ck_rv(status.code(), true))
        })?
        .into_inner();
    let rv = CkRv(ck_rv_of(&response));
    if rv.is_ok() { Ok(()) } else { Err(MessageCallError::backend(rv)) }
}

mod async_ops;
mod crypto;
mod discovery;
mod kem;
mod key_ops;
mod lifecycle;
mod object;
mod raw_output;
mod session;
mod session_3x;

/// Tracks how the gRPC channel was established so `reconnect` knows whether
/// it can re-dial.
#[derive(Clone)]
enum ConnectionSource {
    /// Created via `connect(endpoint)` or `connect_with_tls_files(...)` — reconnectable.
    Endpoint { endpoint: String, tls_files: Option<crate::tls::ClientTlsFiles> },
    /// Injected via `from_channel` — reconnection not possible.
    SharedChannel,
}

/// High-level PKCS#11 client that wraps a gRPC transport to the proxy daemon.
///
/// All methods are `async` because they perform gRPC calls. The shim layer
/// (pkcs11-proxy-shim) bridges async to sync via `tokio::runtime::Runtime::block_on`.
///
/// `Clone` is cheap: the underlying tonic `Channel` is `Arc`'d, the
/// `context_id` is a short `String`, and `ConnectionSource` is plain
/// data. Cloning lets multiple concurrent shim calls each hold an
/// owned `Pkcs11Client` and multiplex over the same HTTP/2 connection
/// instead of serializing on a `Mutex`.
#[derive(Clone)]
pub struct Pkcs11Client {
    exact_effects_version: std::sync::Arc<std::sync::atomic::AtomicU32>,
    grpc: GrpcClient<tonic::transport::Channel>,
    context_id: Option<String>,
    source: ConnectionSource,
}

impl Pkcs11Client {
    fn proto_template(template: &[CkAttribute]) -> Vec<pkcs11_proxy_ng_proto::Attribute> {
        pkcs11_template!(template)
    }

    fn proto_mechanism(mechanism: &CkMechanism) -> CkResult<pkcs11_proxy_ng_proto::Mechanism> {
        pkcs11_proxy_ng_proto::Mechanism::try_from(mechanism)
    }

    /// Returns the stored context_id or `CKR_CRYPTOKI_NOT_INITIALIZED`.
    fn context_id(&self) -> CkResult<String> {
        self.context_id.clone().ok_or(CkRv::CRYPTOKI_NOT_INITIALIZED)
    }

    /// The stored logical-context id, if this client initialized one.
    /// Used to preserve the session across a transport reconnect: the new
    /// channel serves the SAME server-side context (W1-L6-29).
    pub fn context_id_opt(&self) -> Option<String> {
        self.context_id.clone()
    }

    /// Restore a logical-context id after a transport reconnect
    /// (W1-L6-29). The replacement channel serves the same server-side
    /// context, so sessions and handles stay valid; a mid-session
    /// reconnect that dropped the id would orphan the server context
    /// (later calls, including `finalize`, would short-circuit locally
    /// and never reach the daemon).
    pub fn restore_context_id(&mut self, context_id: Option<String>) {
        self.context_id = context_id;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal stand-in for the prost response types: the macros only touch
    /// the `ck_rv` field after `into_inner()`.
    #[derive(Debug)]
    struct FakeUnaryResponse {
        ck_rv: u64,
    }

    fn ok_call(
        ck_rv: u64,
    ) -> impl std::future::Future<Output = Result<tonic::Response<FakeUnaryResponse>, tonic::Status>>
    {
        async move { Ok(tonic::Response::new(FakeUnaryResponse { ck_rv })) }
    }

    fn err_call(
        code: tonic::Code,
    ) -> impl std::future::Future<Output = Result<tonic::Response<FakeUnaryResponse>, tonic::Status>>
    {
        async move {
            Err::<tonic::Response<FakeUnaryResponse>, tonic::Status>(tonic::Status::new(
                code, "boom",
            ))
        }
    }

    // W1-L11-04 characterization: pin each macro's ok / backend-RV /
    // transport-error behavior. Must pass before AND after the prologue DRY.

    #[tokio::test]
    async fn t7_unary_call_returns_response_on_ok() {
        async fn run() -> CkResult<FakeUnaryResponse> {
            let response = pkcs11_unary_call!(ok_call(CkRv::OK.0), true);
            Ok(response)
        }
        assert_eq!(run().await.unwrap().ck_rv, CkRv::OK.0);
    }

    #[tokio::test]
    async fn t7_unary_call_returns_backend_rv_early() {
        async fn run() -> CkResult<FakeUnaryResponse> {
            let response = pkcs11_unary_call!(ok_call(CkRv::SESSION_HANDLE_INVALID.0), true);
            Ok(response)
        }
        assert_eq!(run().await.unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
    }

    #[tokio::test]
    async fn t7_unary_call_maps_transport_by_scope_flag() {
        async fn run_scoped() -> CkResult<FakeUnaryResponse> {
            let response = pkcs11_unary_call!(err_call(tonic::Code::Unavailable), true);
            Ok(response)
        }
        async fn run_unscoped() -> CkResult<FakeUnaryResponse> {
            let response = pkcs11_unary_call!(err_call(tonic::Code::Unavailable), false);
            Ok(response)
        }
        assert_eq!(run_scoped().await.unwrap_err(), CkRv::DEVICE_ERROR);
        assert_eq!(run_unscoped().await.unwrap_err(), CkRv::TOKEN_NOT_PRESENT);
    }

    #[tokio::test]
    async fn t7_unary_map_returns_mapped_body_on_ok() {
        async fn run() -> CkResult<u64> {
            pkcs11_unary_map!(ok_call(CkRv::OK.0), true, resp => resp.ck_rv + 1)
        }
        assert_eq!(run().await.unwrap(), CkRv::OK.0 + 1);
    }

    #[tokio::test]
    async fn t7_unary_map_returns_backend_rv() {
        async fn run() -> CkResult<u64> {
            pkcs11_unary_map!(ok_call(CkRv::PIN_INCORRECT.0), true, resp => resp.ck_rv)
        }
        assert_eq!(run().await.unwrap_err(), CkRv::PIN_INCORRECT);
    }

    #[tokio::test]
    async fn t7_unary_map_maps_transport_error() {
        async fn run() -> CkResult<u64> {
            pkcs11_unary_map!(err_call(tonic::Code::Unavailable), true, resp => resp.ck_rv)
        }
        assert_eq!(run().await.unwrap_err(), CkRv::DEVICE_ERROR);
    }

    #[tokio::test]
    async fn t7_unary_ok_returns_unit_on_ok() {
        async fn run() -> CkResult<()> {
            pkcs11_unary_ok!(ok_call(CkRv::OK.0), true)
        }
        assert!(run().await.is_ok());
    }

    #[tokio::test]
    async fn t7_unary_ok_returns_backend_rv_early() {
        async fn run() -> CkResult<()> {
            pkcs11_unary_ok!(ok_call(CkRv::USER_NOT_LOGGED_IN.0), true)
        }
        assert_eq!(run().await.unwrap_err(), CkRv::USER_NOT_LOGGED_IN);
    }

    #[tokio::test]
    async fn t7_unary_ok_maps_transport_error() {
        async fn run() -> CkResult<()> {
            pkcs11_unary_ok!(err_call(tonic::Code::Unavailable), true)
        }
        assert_eq!(run().await.unwrap_err(), CkRv::DEVICE_ERROR);
    }
}

use pkcs11_proxy_ng_proto::Pkcs11ProxyClient as GrpcClient;
use pkcs11_proxy_ng_types::*;

use crate::error::MessageCallError;

pub use deadline::DEFAULT_RPC_TIMEOUT;
use deadline::RpcDeadline;
// W1-C10-06: downstream crates name these from the crate root.
pub use key_ops::DeriveKeyMechanismOutResult;
pub use lifecycle::{BackendProbe, ConnectError};

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
pub(crate) mod deadline;
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct Pkcs11Client {
    exact_effects_version: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Cached `pointer_safe_authenticated_parameters` capability (W1-C10-03):
    /// 0 = unknown (probe), 1 = no, 2 = yes. Shared across clones; every
    /// fresh probe overwrites it and reconnect resets it to unknown.
    typed_auth_capability: std::sync::Arc<std::sync::atomic::AtomicU8>,
    grpc: GrpcClient<RpcDeadline<tonic::transport::Channel>>,
    /// The channel wrapped by `grpc`, kept so [`Pkcs11Client::set_rpc_timeout`]
    /// and [`reconnect`][Pkcs11Client::reconnect] can rebuild the gRPC client
    /// around the same connection (tonic 0.14 generated clients expose no
    /// inner-service accessor). Cheap to clone (`Channel` is `Arc`d).
    channel: tonic::transport::Channel,
    context_id: Option<String>,
    source: ConnectionSource,
    rpc_timeout: std::time::Duration,
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

    async fn ok_call(ck_rv: u64) -> Result<tonic::Response<FakeUnaryResponse>, tonic::Status> {
        Ok(tonic::Response::new(FakeUnaryResponse { ck_rv }))
    }

    async fn err_call(
        code: tonic::Code,
    ) -> Result<tonic::Response<FakeUnaryResponse>, tonic::Status> {
        Err::<tonic::Response<FakeUnaryResponse>, tonic::Status>(tonic::Status::new(code, "boom"))
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

    // W1-C10-04: transport-error scope-flag taxonomy over EVERY
    // `pkcs11_unary_*` call site in the crate (see `RpcKind` in error.rs):
    // `true` (session-scoped → DEVICE_ERROR) everywhere except the
    // slot/token family, which passes `false` (→ TOKEN_NOT_PRESENT).
    // `open_session` is session-scoped (`RpcKind::Session` names
    // `C_OpenSession`); `close_all_sessions` stays slot-scoped (takes a
    // slot id, no session); `wait_for_slot_event` keeps its pre-existing
    // `true` (changing the C_WaitForSlotEvent transport RV is out of
    // scope for this item). Every prod macro invocation carries its flag
    // on the invocation line, so the scan is exact per line.
    #[test]
    fn scope_flags_match_session_taxonomy() {
        const SOURCES: &[(&str, &str)] = &[
            ("async_ops.rs", include_str!("async_ops.rs")),
            ("deadline.rs", include_str!("deadline.rs")),
            ("discovery.rs", include_str!("discovery.rs")),
            ("kem.rs", include_str!("kem.rs")),
            ("key_ops.rs", include_str!("key_ops.rs")),
            ("lifecycle.rs", include_str!("lifecycle.rs")),
            ("mod.rs", include_str!("mod.rs")),
            ("object.rs", include_str!("object.rs")),
            ("raw_output.rs", include_str!("raw_output.rs")),
            ("session.rs", include_str!("session.rs")),
            ("session_3x.rs", include_str!("session_3x.rs")),
            ("crypto/authenticated_typed.rs", include_str!("crypto/authenticated_typed.rs")),
            ("crypto/authenticated_wrap.rs", include_str!("crypto/authenticated_wrap.rs")),
            ("crypto/combined.rs", include_str!("crypto/combined.rs")),
            ("crypto/digest_cipher.rs", include_str!("crypto/digest_cipher.rs")),
            ("crypto/message_crypto.rs", include_str!("crypto/message_crypto.rs")),
            ("crypto/mod.rs", include_str!("crypto/mod.rs")),
            ("crypto/sign_verify.rs", include_str!("crypto/sign_verify.rs")),
            ("crypto/verify_signature.rs", include_str!("crypto/verify_signature.rs")),
        ];
        // The only methods allowed a `false` (slot/token-scoped) flag.
        const FALSE_FAMILY: &[&str] = &[
            "get_info",
            "get_slot_list",
            "get_slot_info",
            "get_token_info",
            "get_mechanism_list",
            "get_mechanism_info",
            "close_all_sessions",
        ];
        let mut sites = 0;
        let mut false_seen = vec![];
        for (name, source) in SOURCES {
            let prod = source.split("#[cfg(test)]").next().unwrap_or(source);
            for (lineno, line) in prod.lines().enumerate() {
                if !(line.contains("pkcs11_unary_") && line.contains("self.grpc.")) {
                    continue;
                }
                let after = line.split("self.grpc.").nth(1).unwrap();
                let method = after.split('(').next().unwrap();
                let flag = if line.contains(", true)") || line.contains(", true,") {
                    true
                } else if line.contains(", false)") || line.contains(", false,") {
                    false
                } else {
                    panic!("{name}:{}: scope flag not on invocation line: {line}", lineno + 1);
                };
                sites += 1;
                if method == "open_session" {
                    assert!(
                        flag,
                        "{name}:{}: open_session must be session-scoped (true)",
                        lineno + 1
                    );
                } else if FALSE_FAMILY.contains(&method) {
                    assert!(!flag, "{name}:{lineno}: {method} must be slot-scoped (false)");
                    if !false_seen.contains(&method) {
                        false_seen.push(method);
                    }
                } else {
                    assert!(flag, "{name}:{}: {method} must be session-scoped (true)", lineno + 1);
                }
            }
        }
        assert!(sites > 50, "taxonomy scan must see the whole crate, saw {sites} sites");
        for method in FALSE_FAMILY {
            assert!(false_seen.contains(method), "slot-scoped pin for {method} must be exercised");
        }
    }

    // W1-L3-06: a backend-RETURNED DEVICE_ERROR must still pass through
    // distinctly — only the absent-info mapping moves to
    // FUNCTION_NOT_SUPPORTED. Guards against over-correction.
    #[tokio::test]
    async fn unary_call_passes_backend_device_error_through() {
        async fn run() -> CkResult<FakeUnaryResponse> {
            let response = pkcs11_unary_call!(ok_call(CkRv::DEVICE_ERROR.0), false);
            Ok(response)
        }
        assert_eq!(run().await.unwrap_err(), CkRv::DEVICE_ERROR);
    }
}

use pkcs11_proxy_ng_proto::Pkcs11ProxyClient as GrpcClient;
use pkcs11_proxy_ng_types::*;

macro_rules! pkcs11_template {
    ($template:expr) => {{ $template.iter().map(pkcs11_proxy_ng_proto::Attribute::from).collect::<Vec<_>>() }};
}

macro_rules! pkcs11_unary_call {
    ($call:expr, $is_session_scoped:expr) => {{
        let response = $call
            .await
            .map_err(|status| {
                crate::error::grpc_status_to_ck_rv(status.code(), $is_session_scoped)
            })?
            .into_inner();
        let rv = CkRv(response.ck_rv);
        if !rv.is_ok() {
            return Err(rv);
        }
        response
    }};
}

macro_rules! pkcs11_unary_map {
    ($call:expr, $is_session_scoped:expr, $resp:ident => $body:expr) => {{
        let response = $call
            .await
            .map_err(|status| {
                crate::error::grpc_status_to_ck_rv(status.code(), $is_session_scoped)
            })?
            .into_inner();
        let rv = CkRv(response.ck_rv);
        if rv.is_ok() {
            let $resp = response;
            Ok($body)
        } else {
            Err(rv)
        }
    }};
}

macro_rules! pkcs11_unary_ok {
    ($call:expr, $is_session_scoped:expr) => {{
        let response = $call
            .await
            .map_err(|status| {
                crate::error::grpc_status_to_ck_rv(status.code(), $is_session_scoped)
            })?
            .into_inner();
        let rv = CkRv(response.ck_rv);
        if !rv.is_ok() {
            return Err(rv);
        }
        Ok::<(), CkRv>(())
    }};
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
pub struct Pkcs11Client {
    grpc: GrpcClient<tonic::transport::Channel>,
    context_id: Option<String>,
    source: ConnectionSource,
}

impl Pkcs11Client {
    fn proto_template(template: &[CkAttribute]) -> Vec<pkcs11_proxy_ng_proto::Attribute> {
        pkcs11_template!(template)
    }

    fn proto_mechanism(mechanism: &CkMechanism) -> pkcs11_proxy_ng_proto::Mechanism {
        pkcs11_proxy_ng_proto::Mechanism::from(mechanism)
    }

    /// Returns the stored context_id or `CKR_CRYPTOKI_NOT_INITIALIZED`.
    fn context_id(&self) -> CkResult<String> {
        self.context_id.clone().ok_or(CkRv::CRYPTOKI_NOT_INITIALIZED)
    }
}

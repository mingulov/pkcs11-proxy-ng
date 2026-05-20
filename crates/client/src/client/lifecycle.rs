use pkcs11_proxy_ng_proto::{MechanismRegistryPayload, Pkcs11ProxyClient as GrpcClient};
use pkcs11_proxy_ng_types::*;
use tonic::transport::Channel;

use super::{ConnectionSource, Pkcs11Client};
use crate::error::{RpcKind, grpc_status_to_ck_rv_kind};

/// Result of a `get_backend_interfaces` probe — the backend's interface
/// capabilities plus the server's mechanism registry payload (absent on
/// older daemons predating the field).
#[derive(Debug, Clone)]
pub struct BackendProbe {
    pub interfaces: Vec<(u8, u8, Vec<String>)>,
    pub mechanism_registry: Option<MechanismRegistryPayload>,
}

// TODO R2-FOLLOWUP-slow-backend: scenario 5 (slow backend) in the R2
// resilience fixture is only able to inject latency on the network
// path between shim and daemon (via toxiproxy). A true "backend-slow"
// test requires a mock backend module (.so) that intentionally
// sleeps in C_Sign so the daemon's spawn_backend timeout fires.
// Track that mock under tests/r2_resilience/mock-backend/ when
// implementing R5 (PKCS#11 compatibility audit).

async fn connect_channel(
    endpoint: &str,
    tls_files: Option<crate::tls::ClientTlsFiles>,
) -> Result<Channel, String> {
    let mut builder = tonic::transport::Endpoint::from_shared(endpoint.to_owned())
        .map_err(|e| format!("invalid endpoint: {e}"))?;
    if let Some(tls_files) = tls_files {
        builder = builder
            .tls_config(tls_files.into_tonic_config()?)
            .map_err(|e| format!("invalid TLS config: {e}"))?;
    }

    builder
        .connect_timeout(std::time::Duration::from_secs(5))
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(std::time::Duration::from_secs(10))
        .keep_alive_timeout(std::time::Duration::from_secs(5))
        .connect()
        .await
        .map_err(|e| format!("gRPC connect failed: {e}"))
}

impl Pkcs11Client {
    /// Connect to the proxy daemon at `endpoint` (e.g. `"http://127.0.0.1:50051"`).
    pub async fn connect(endpoint: &str) -> Result<Self, String> {
        let channel = connect_channel(endpoint, None).await?;
        let grpc = GrpcClient::new(channel);
        Ok(Self {
            grpc,
            context_id: None,
            source: ConnectionSource::Endpoint { endpoint: endpoint.to_owned(), tls_files: None },
        })
    }

    /// Connect to the proxy daemon using mTLS credentials from files.
    pub async fn connect_with_tls_files(
        endpoint: &str,
        tls_files: crate::tls::ClientTlsFiles,
    ) -> Result<Self, String> {
        let channel = connect_channel(endpoint, Some(tls_files.clone())).await?;
        let grpc = GrpcClient::new(channel);
        Ok(Self {
            grpc,
            context_id: None,
            source: ConnectionSource::Endpoint {
                endpoint: endpoint.to_owned(),
                tls_files: Some(tls_files),
            },
        })
    }

    /// Build a client from an already-established channel (e.g. for tests or
    /// channel sharing). Reconnection will not be available.
    pub fn from_channel(channel: tonic::transport::Channel) -> Self {
        Self {
            grpc: GrpcClient::new(channel),
            context_id: None,
            source: ConnectionSource::SharedChannel,
        }
    }

    /// Call `C_Initialize` on the proxy. Stores the returned `context_id` for
    /// use in all subsequent requests.
    ///
    /// Transport errors are mapped via `RpcKind::Lifecycle` because
    /// `C_Initialize` has a stricter spec-permitted CK_RV set than the
    /// session-scoped RPCs (PKCS#11 v3.0 §5.4): `CKR_TOKEN_NOT_PRESENT`
    /// is NOT in that set, so a daemon-unreachable failure surfaces as
    /// `CKR_GENERAL_ERROR` instead.
    pub async fn initialize(&mut self) -> CkResult<()> {
        let req = pkcs11_proxy_ng_proto::InitializeRequest { client_context_id: String::new() };
        let response = self
            .grpc
            .initialize(req)
            .await
            .map_err(|status| grpc_status_to_ck_rv_kind(status.code(), RpcKind::Lifecycle))?
            .into_inner();
        let rv = CkRv(response.ck_rv);
        if !rv.is_ok() {
            return Err(rv);
        }
        self.context_id = Some(response.client_context_id);
        Ok(())
    }

    /// Call `C_Finalize` on the proxy. Clears the stored `context_id`.
    ///
    /// Like `initialize`, uses `RpcKind::Lifecycle` for transport-error
    /// mapping per PKCS#11 v3.0 §5.5.
    pub async fn finalize(&mut self) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::FinalizeRequest { client_context_id: ctx };
        let response = self
            .grpc
            .finalize(req)
            .await
            .map_err(|status| grpc_status_to_ck_rv_kind(status.code(), RpcKind::Lifecycle))?
            .into_inner();
        let rv = CkRv(response.ck_rv);
        if !rv.is_ok() {
            return Err(rv);
        }
        self.context_id = None;
        Ok(())
    }

    /// Query the daemon for the backend's interface capabilities. Also
    /// pulls the server-published mechanism registry payload when the
    /// daemon includes it (older daemons predate the field and the
    /// caller must fall back to its embedded default).
    ///
    /// Context-free (no `C_Initialize` required); safe to call before
    /// `initialize()`.
    pub async fn get_backend_interfaces(&mut self) -> Result<BackendProbe, String> {
        let req = pkcs11_proxy_ng_proto::GetBackendInterfacesRequest {};
        let resp = self
            .grpc
            .get_backend_interfaces(req)
            .await
            .map_err(|e| format!("GetBackendInterfaces failed: {e}"))?
            .into_inner();

        let interfaces = resp
            .interfaces
            .into_iter()
            .map(|info| (info.version_major as u8, info.version_minor as u8, info.null_functions))
            .collect();

        Ok(BackendProbe { interfaces, mechanism_registry: resp.mechanism_registry })
    }

    /// Re-dial the endpoint (if it was created via `connect`) and probe the
    /// connection by calling `GetSlotList`.
    pub async fn reconnect(&mut self) -> CkResult<()> {
        match &self.source {
            ConnectionSource::Endpoint { endpoint, tls_files } => {
                let channel = connect_channel(endpoint, tls_files.clone())
                    .await
                    .map_err(|_| CkRv::DEVICE_ERROR)?;
                self.grpc = GrpcClient::new(channel);
                if let Some(ref ctx) = self.context_id {
                    let req = pkcs11_proxy_ng_proto::GetSlotListRequest {
                        client_context_id: ctx.clone(),
                        token_present: false,
                    };
                    pkcs11_unary_ok!(self.grpc.get_slot_list(req), false)?;
                }
                Ok(())
            }
            ConnectionSource::SharedChannel => Err(CkRv::GENERAL_ERROR),
        }
    }
}

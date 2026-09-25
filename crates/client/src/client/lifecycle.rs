use pkcs11_proxy_ng_proto::{MechanismRegistryPayload, Pkcs11ProxyClient as GrpcClient};
use pkcs11_proxy_ng_types::*;
use tonic::transport::Channel;

use super::{ConnectionSource, Pkcs11Client};
use crate::error::{RpcKind, grpc_status_to_ck_rv_kind};

/// Per-call message size cap (64 MiB), matching the server's
/// `proxy.max_message_bytes` ceiling defined in `crates/server/src/config.rs`.
///
/// Tonic's default decode limit is 4 MiB, so without this an operator
/// who raises the server's `max_message_bytes` (e.g. for large
/// `C_Decrypt` plaintexts or wrapped-key blobs) would silently get a
/// `CKR_GENERAL_ERROR` on the client side from the decode-too-large
/// status. Keep the client cap aligned with the server's cap so large
/// payloads succeed end-to-end and oversized payloads fail at the
/// server (where the operator can configure the bound) rather than
/// invisibly at the client.
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

fn new_grpc_client(channel: Channel) -> GrpcClient<Channel> {
    GrpcClient::new(channel)
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES)
}

/// Result of a `get_backend_interfaces` probe — the backend's interface
/// capabilities plus the server's mechanism registry payload (absent on
/// older daemons predating the field).
#[derive(Debug, Clone)]
pub struct BackendProbe {
    pub interfaces: Vec<(u8, u8, Vec<String>)>,
    pub mechanism_registry: Option<MechanismRegistryPayload>,
    /// Backend `sizeof(CK_ULONG)` in bytes (4 or 8), advertised for the width
    /// bridge (ADR-0011 D2). `None` against an older daemon that predates the
    /// field — the caller falls back to 8 with a warning (D9).
    pub backend_ulong_size: Option<u32>,
    /// Backend `CK_ULONG` byte order (1 = little, 2 = big; ADR-0011 D6).
    /// `None` against an older daemon.
    pub backend_byte_order: Option<u32>,
    /// The backend's native sizeof(CK_ATTRIBUTE) (D2 extension), if advertised.
    pub backend_attribute_stride: Option<u32>,
}

async fn connect_channel(
    endpoint: &str,
    tls_files: Option<crate::tls::ClientTlsFiles>,
) -> Result<Channel, String> {
    // Unix-domain-socket endpoint (`unix:/abs/path` or `unix:///abs/path`):
    // dial the local socket. No TLS — a Unix socket carries no network to
    // secure; the daemon authenticates the peer via SO_PEERCRED. Intended for
    // local-user / ssh-forwarded use. Windows has no UDS peer-cred path, so a
    // Windows client is tcp/mTLS-only (ADR-0011 Bucket 3, client side).
    if let Some(path) = endpoint.strip_prefix("unix:") {
        #[cfg(unix)]
        {
            if tls_files.is_some() {
                tracing::debug!(
                    "TLS configuration ignored for unix-socket endpoint (peer-cred auth)"
                );
            }
            return connect_unix_channel(path).await;
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err("unix-domain-socket endpoints are not supported on this platform; \
                        use a tcp/mTLS endpoint such as https://host:port"
                .to_string());
        }
    }

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

/// Connect a gRPC channel over a Unix-domain socket at `raw_path`.
#[cfg(unix)]
async fn connect_unix_channel(raw_path: &str) -> Result<Channel, String> {
    // Tolerate the authority form `unix://<path>` by dropping a leading "//".
    let path = raw_path.strip_prefix("//").unwrap_or(raw_path).to_owned();
    if path.is_empty() {
        return Err("unix endpoint has an empty socket path".to_string());
    }

    // The HTTP/2 `:authority` is unused for a UDS connector, but tonic still
    // needs a syntactically valid Endpoint to carry the connection settings.
    tonic::transport::Endpoint::try_from("http://pkcs11-proxy-ng.local")
        .map_err(|e| format!("invalid unix endpoint base: {e}"))?
        .connect_timeout(std::time::Duration::from_secs(5))
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(std::time::Duration::from_secs(10))
        .keep_alive_timeout(std::time::Duration::from_secs(5))
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .map_err(|e| format!("unix gRPC connect failed: {e}"))
}

impl Pkcs11Client {
    /// Connect to the proxy daemon at `endpoint` (e.g. `"http://127.0.0.1:50051"`).
    pub async fn connect(endpoint: &str) -> Result<Self, String> {
        let channel = connect_channel(endpoint, None).await?;
        let grpc = new_grpc_client(channel);
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
        let grpc = new_grpc_client(channel);
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
            grpc: new_grpc_client(channel),
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
        if rv.is_err() {
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
        if rv.is_err() {
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

        Ok(BackendProbe {
            interfaces,
            mechanism_registry: resp.mechanism_registry,
            backend_ulong_size: resp.backend_ulong_size,
            backend_byte_order: resp.backend_byte_order,
            backend_attribute_stride: resp.backend_attribute_stride,
        })
    }

    /// Re-dial the endpoint (if it was created via `connect`) and probe the
    /// connection by calling `GetSlotList`.
    pub async fn reconnect(&mut self) -> CkResult<()> {
        match &self.source {
            ConnectionSource::Endpoint { endpoint, tls_files } => {
                let channel = connect_channel(endpoint, tls_files.clone())
                    .await
                    .map_err(|_| CkRv::DEVICE_ERROR)?;
                self.grpc = new_grpc_client(channel);
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

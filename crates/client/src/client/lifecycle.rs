use pkcs11_proxy_ng_proto::Pkcs11ProxyClient as GrpcClient;
use pkcs11_proxy_ng_types::*;
use tonic::transport::Channel;

use super::{ConnectionSource, Pkcs11Client};

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
    pub async fn initialize(&mut self) -> CkResult<()> {
        let req = pkcs11_proxy_ng_proto::InitializeRequest { client_context_id: String::new() };
        let resp = pkcs11_unary_call!(self.grpc.initialize(req), false);
        self.context_id = Some(resp.client_context_id);
        Ok(())
    }

    /// Call `C_Finalize` on the proxy. Clears the stored `context_id`.
    pub async fn finalize(&mut self) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::FinalizeRequest { client_context_id: ctx };
        pkcs11_unary_ok!(self.grpc.finalize(req), false)?;
        self.context_id = None;
        Ok(())
    }

    /// Query the daemon for the backend's interface capabilities.
    ///
    /// This is context-free (no `C_Initialize` required) and can be called
    /// before `initialize()`. Used by the shim to dynamically build
    /// function lists matching the backend.
    pub async fn get_backend_interfaces(&mut self) -> Result<Vec<(u8, u8, Vec<String>)>, String> {
        let req = pkcs11_proxy_ng_proto::GetBackendInterfacesRequest {};
        let resp = self
            .grpc
            .get_backend_interfaces(req)
            .await
            .map_err(|e| format!("GetBackendInterfaces failed: {e}"))?
            .into_inner();

        Ok(resp
            .interfaces
            .into_iter()
            .map(|info| (info.version_major as u8, info.version_minor as u8, info.null_functions))
            .collect())
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

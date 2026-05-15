use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;

use super::super::super::context_manager::ContextManager;
use super::super::service_utils::spawn_backend;

/// Handler for GetBackendInterfaces RPC.
///
/// Context-free: no client_context_id required.
/// Returns the backend's interface capabilities (which versions are
/// supported and which function pointers are NULL).
pub(super) async fn get_backend_interfaces(
    _ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    _request: Request<pkcs11_proxy_ng_proto::GetBackendInterfacesRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetBackendInterfacesResponse>, Status> {
    let backend = backend_ref.clone();
    let result = spawn_backend(move || Ok(backend.get_interface_capabilities())).await?;

    let caps = match result {
        Ok(caps) => caps,
        Err(_) => {
            // Should not happen since get_interface_capabilities() does not fail,
            // but handle gracefully.
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetBackendInterfacesResponse {
                interfaces: vec![],
            }));
        }
    };

    let interfaces = caps
        .interfaces
        .into_iter()
        .map(|info| pkcs11_proxy_ng_proto::InterfaceInfo {
            version_major: info.version_major as u32,
            version_minor: info.version_minor as u32,
            null_functions: info.null_functions,
        })
        .collect();

    Ok(Response::new(pkcs11_proxy_ng_proto::GetBackendInterfacesResponse { interfaces }))
}

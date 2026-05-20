use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;

use crate::mechanism_registry_source::MechanismRegistrySource;
use crate::server::rate_limit;

use super::super::super::context_manager::ContextManager;
use super::super::service_utils::spawn_backend;

/// Handler for GetBackendInterfaces RPC.
///
/// Context-free: no client_context_id required.
/// Returns the backend's interface capabilities (which versions are
/// supported and which function pointers are NULL) plus the daemon's
/// current mechanism registry payload so shims can refresh their
/// param-shape / parameterless data without restarting.
///
/// Rate-limited per peer IP (R3-FOLLOWUP-rate-limit). Disabled by
/// default — see `proxy.rate_limit_get_backend_interfaces` in
/// proxy.toml.
pub(super) async fn get_backend_interfaces(
    _ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    registry_source: &MechanismRegistrySource,
    request: Request<pkcs11_proxy_ng_proto::GetBackendInterfacesRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetBackendInterfacesResponse>, Status> {
    if let Some(peer) = request.remote_addr()
        && let Err(retry_after) = rate_limit::check(peer.ip())
    {
        return Err(Status::resource_exhausted(format!(
            "rate limit exceeded; retry after {} ms",
            retry_after.as_millis()
        )));
    }
    let _request = request;
    let backend = backend_ref.clone();
    let result = spawn_backend(move || Ok(backend.get_interface_capabilities())).await?;

    // Take a snapshot of the registry payload up-front so we can include
    // it in either the success or fallback response without an extra
    // RwLock acquisition.
    let registry_payload = registry_source.current();

    let caps = match result {
        Ok(caps) => caps,
        Err(_) => {
            // Should not happen since get_interface_capabilities() does not fail,
            // but handle gracefully.
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetBackendInterfacesResponse {
                interfaces: vec![],
                mechanism_registry: Some((*registry_payload).clone()),
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

    Ok(Response::new(pkcs11_proxy_ng_proto::GetBackendInterfacesResponse {
        interfaces,
        mechanism_registry: Some((*registry_payload).clone()),
    }))
}

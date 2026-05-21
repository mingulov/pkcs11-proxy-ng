use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;

use crate::mechanism_registry_source::MechanismRegistrySource;
use crate::server::rate_limit;

use super::super::super::context_manager::ContextManager;

/// Handler for GetBackendInterfaces RPC.
///
/// Context-free: no client_context_id required.
/// Returns the backend's interface capabilities (which versions are
/// supported and which function pointers are NULL) plus the daemon's
/// current mechanism registry payload so shims can refresh their
/// param-shape / parameterless data without restarting.
///
/// Rate-limited per peer IP (FOLLOWUP-rate-limit). Disabled by
/// default — see `proxy.rate_limit_get_backend_interfaces` in
/// proxy.toml.
pub(super) async fn get_backend_interfaces(
    _ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    registry_source: &MechanismRegistrySource,
    request: Request<pkcs11_proxy_ng_proto::GetBackendInterfacesRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetBackendInterfacesResponse>, Status> {
    if let Some(peer) = request.remote_addr() {
        if let Err(retry_after) = rate_limit::check(peer.ip()) {
            return Err(Status::resource_exhausted(format!(
                "rate limit exceeded; retry after {} ms",
                retry_after.as_millis()
            )));
        }
    }
    let _request = request;
    // NOTE: get_interface_capabilities is pure metadata (reads the .so's
    // function-list NULL pointers — no PKCS#11 call into the backend).
    // We deliberately do NOT route it through spawn_backend, because
    // that path emits Success events to the backend-health gate. The
    // chaos scenario 2 needs the gate to see only real backend-call outcomes;
    // routing this metadata read through spawn_backend would emit
    // spurious Successes interleaved with the actual failing C_Sign
    // events and reset the consecutive-failure counter.
    let backend = backend_ref.clone();
    let caps_result: pkcs11_proxy_ng_types::CkResult<_> = Ok(backend.get_interface_capabilities());

    // Take a snapshot of the registry payload up-front so we can include
    // it in either the success or fallback response without an extra
    // RwLock acquisition.
    let registry_payload = registry_source.current();

    let caps = match caps_result {
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

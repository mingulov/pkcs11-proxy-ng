use crate::server::slot_map::BackendSlotId;
use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::CkRv;

use super::super::super::auth::policy::TokenPolicy;
use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::authorization::slot_is_authorized;
use super::super::service_utils::spawn_backend;

fn no_event() -> Response<pkcs11_proxy_ng_proto::WaitForSlotEventResponse> {
    Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
        ck_rv: CkRv::NO_EVENT.0,
        slot_id: 0,
    })
}

pub(super) async fn wait_for_slot_event(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::WaitForSlotEventRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::WaitForSlotEventResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let context: Option<()> = ctx_mgr.get_context(&ctx_id, |_| ()).await;
    if context.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            slot_id: 0,
        }));
    }

    let flags = req.flags;
    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.wait_for_slot_event(flags)).await?;

    let backend_slot = match result {
        Ok(backend_slot) => backend_slot,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
                ck_rv: error.0,
                slot_id: 0,
            }));
        }
    };

    // Never leak the raw backend slot id: an event for a slot this client has
    // no virtual mapping for is reported as no-event (M13).
    let Some(virtual_slot) = ctx_mgr.to_virtual_slot(backend_slot).await else {
        return Ok(no_event());
    };

    // Suppress events for tokens this client is not authorized to see, so the
    // insertion/removal of a token outside its policy is not disclosed (M13).
    // An unauthenticated context bypasses the policy (slot_is_authorized → true),
    // preserving prior behavior; any policy denial or token-info error fails
    // closed to no-event rather than leaking the slot.
    match slot_is_authorized(ctx_mgr, backend_ref, token_policy, &ctx_id, backend_slot).await? {
        Ok(true) => Ok(Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
            ck_rv: CkRv::OK.0,
            slot_id: virtual_slot.0,
        })),
        _ => Ok(no_event()),
    }
}

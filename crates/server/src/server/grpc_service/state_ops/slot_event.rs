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

    match result {
        Ok(backend_slot) => match ctx_mgr.to_virtual_slot(backend_slot).await {
            Some(virtual_slot) => {
                Ok(Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
                    ck_rv: CkRv::OK.0,
                    slot_id: virtual_slot.0,
                }))
            }
            // No virtual mapping for this client: never leak the raw backend
            // slot id. Report no event rather than disclosing an unmapped slot.
            // (TODO M13 follow-up: also run slot_is_authorized to suppress
            // events for mapped-but-unauthorized tokens.)
            None => Ok(Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
                ck_rv: CkRv::NO_EVENT.0,
                slot_id: 0,
            })),
        },
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
            ck_rv: error.0,
            slot_id: 0,
        })),
    }
}

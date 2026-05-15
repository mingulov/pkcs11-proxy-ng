use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::{CkRv, CkSlotId};

use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::service_utils::spawn_backend;

pub(super) async fn wait_for_slot_event(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
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
        Ok(backend_slot) => {
            let backend_slot: CkSlotId = backend_slot;
            Ok(Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
                ck_rv: CkRv::OK.0,
                slot_id: ctx_mgr.to_virtual_slot(backend_slot).await.unwrap_or(backend_slot).0,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
            ck_rv: error.0,
            slot_id: 0,
        })),
    }
}

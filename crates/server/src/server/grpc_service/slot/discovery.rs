use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::auth::policy::TokenPolicy;
use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::authorization;
use super::super::service_utils::{context_exists, resolve_slot, spawn_backend};

pub(super) async fn get_slot_list(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::GetSlotListRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetSlotListResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotListResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            slot_ids: vec![],
        }));
    }

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.get_slot_list(req.token_present)).await?;

    match result {
        Ok(backend_slots) => {
            let mut slot_ids = Vec::with_capacity(backend_slots.len());
            for backend_slot in backend_slots {
                match authorization::slot_is_authorized(
                    ctx_mgr,
                    backend_ref,
                    token_policy,
                    &ctx_id,
                    backend_slot,
                )
                .await?
                {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(error) => {
                        return Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotListResponse {
                            ck_rv: error.0,
                            slot_ids: vec![],
                        }));
                    }
                }

                if let Some(virtual_slot) = ctx_mgr.to_virtual_slot(backend_slot).await {
                    slot_ids.push(virtual_slot.0);
                    continue;
                }
                ctx_mgr.register_slot(backend_slot).await;
                if let Some(virtual_slot) = ctx_mgr.to_virtual_slot(backend_slot).await {
                    slot_ids.push(virtual_slot.0);
                }
            }
            Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotListResponse {
                ck_rv: CkRv::OK.0,
                slot_ids,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotListResponse {
            ck_rv: error.0,
            slot_ids: vec![],
        })),
    }
}

pub(super) async fn get_slot_info(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::GetSlotInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetSlotInfoResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotInfoResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            info: None,
        }));
    }

    let backend_slot = match resolve_slot(ctx_mgr, req.slot_id).await {
        Ok(slot) => slot,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotInfoResponse {
                ck_rv: error.0,
                info: None,
            }));
        }
    };

    match authorization::slot_is_authorized(
        ctx_mgr,
        backend_ref,
        token_policy,
        &ctx_id,
        backend_slot,
    )
    .await?
    {
        Ok(true) => {}
        Ok(false) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotInfoResponse {
                ck_rv: CkRv::SLOT_ID_INVALID.0,
                info: None,
            }));
        }
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotInfoResponse {
                ck_rv: error.0,
                info: None,
            }));
        }
    }

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.get_slot_info(backend_slot)).await?;
    let (ck_rv, info) = match result {
        Ok(info) => (CkRv::OK.0, Some(pkcs11_proxy_ng_proto::SlotInfo::from(&info))),
        Err(error) => (error.0, None),
    };
    Ok(Response::new(pkcs11_proxy_ng_proto::GetSlotInfoResponse { ck_rv, info }))
}

pub(super) async fn get_token_info(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::GetTokenInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetTokenInfoResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetTokenInfoResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            info: None,
        }));
    }

    let backend_slot = match resolve_slot(ctx_mgr, req.slot_id).await {
        Ok(slot) => slot,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetTokenInfoResponse {
                ck_rv: error.0,
                info: None,
            }));
        }
    };

    match authorization::slot_is_authorized(
        ctx_mgr,
        backend_ref,
        token_policy,
        &ctx_id,
        backend_slot,
    )
    .await?
    {
        Ok(true) => {}
        Ok(false) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetTokenInfoResponse {
                ck_rv: CkRv::SLOT_ID_INVALID.0,
                info: None,
            }));
        }
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetTokenInfoResponse {
                ck_rv: error.0,
                info: None,
            }));
        }
    }

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.get_token_info(backend_slot)).await?;
    let (ck_rv, info) = match result {
        Ok(info) => (CkRv::OK.0, Some(pkcs11_proxy_ng_proto::TokenInfo::from(&info))),
        Err(error) => (error.0, None),
    };
    Ok(Response::new(pkcs11_proxy_ng_proto::GetTokenInfoResponse { ck_rv, info }))
}

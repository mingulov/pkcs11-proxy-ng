use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::auth::policy::TokenPolicy;
use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::authorization;
use super::super::service_utils::{context_exists, resolve_slot, spawn_backend};

pub(super) async fn get_mechanism_list(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::GetMechanismListRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetMechanismListResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetMechanismListResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            mechanism_types: vec![],
        }));
    }

    let backend_slot = match resolve_slot(ctx_mgr, req.slot_id).await {
        Ok(slot) => slot,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetMechanismListResponse {
                ck_rv: error.0,
                mechanism_types: vec![],
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
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetMechanismListResponse {
                ck_rv: CkRv::SLOT_ID_INVALID.0,
                mechanism_types: vec![],
            }));
        }
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetMechanismListResponse {
                ck_rv: error.0,
                mechanism_types: vec![],
            }));
        }
    }

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.get_mechanism_list(backend_slot)).await?;
    match result {
        Ok(mechanisms) => {
            let mechanism_types = mechanisms.iter().map(|mech| mech.0).collect();
            Ok(Response::new(pkcs11_proxy_ng_proto::GetMechanismListResponse {
                ck_rv: CkRv::OK.0,
                mechanism_types,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::GetMechanismListResponse {
            ck_rv: error.0,
            mechanism_types: vec![],
        })),
    }
}

pub(super) async fn get_mechanism_info(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::GetMechanismInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetMechanismInfoResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetMechanismInfoResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            info: None,
        }));
    }

    let backend_slot = match resolve_slot(ctx_mgr, req.slot_id).await {
        Ok(slot) => slot,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetMechanismInfoResponse {
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
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetMechanismInfoResponse {
                ck_rv: CkRv::SLOT_ID_INVALID.0,
                info: None,
            }));
        }
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetMechanismInfoResponse {
                ck_rv: error.0,
                info: None,
            }));
        }
    }

    let mechanism_type = CkMechanismType(req.mechanism_type);
    let backend = backend_ref.clone();
    let result =
        spawn_backend(move || backend.get_mechanism_info(backend_slot, mechanism_type)).await?;
    let (ck_rv, info) = match result {
        Ok(info) => (
            CkRv::OK.0,
            Some(pkcs11_proxy_ng_proto::MechanismInfo {
                min_key_size: info.min_key_size,
                max_key_size: info.max_key_size,
                flags: info.flags.0,
            }),
        ),
        Err(error) => (error.0, None),
    };
    Ok(Response::new(pkcs11_proxy_ng_proto::GetMechanismInfoResponse { ck_rv, info }))
}

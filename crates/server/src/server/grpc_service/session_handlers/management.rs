use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{info, warn};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::auth::policy::TokenPolicy;
use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::authorization;
use super::super::service_utils::{context_exists, resolve_session, resolve_slot, spawn_backend};

pub(super) async fn init_token(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::InitTokenRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::InitTokenResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::InitTokenResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
        }));
    }

    let backend_slot = match resolve_slot(ctx_mgr, req.slot_id).await {
        Ok(slot) => slot,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::InitTokenResponse { ck_rv: error.0 }));
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
            return Ok(Response::new(pkcs11_proxy_ng_proto::InitTokenResponse {
                ck_rv: CkRv::SLOT_ID_INVALID.0,
            }));
        }
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::InitTokenResponse { ck_rv: error.0 }));
        }
    }

    let so_pin = req.so_pin;
    let label_for_log = req.label.clone();
    let label = req.label;
    let backend = backend_ref.clone();
    let result =
        spawn_backend(move || backend.init_token(backend_slot, so_pin.as_deref(), &label)).await?;

    let ck_rv = match &result {
        Ok(()) => {
            info!(context_id = %ctx_id.0, label = %label_for_log, "Token initialized");
            CkRv::OK.0
        }
        Err(error) => {
            warn!(context_id = %ctx_id.0, rv = error.0, "InitToken failed");
            error.0
        }
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::InitTokenResponse { ck_rv }))
}

pub(super) async fn init_pin(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::InitPinRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::InitPinResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::InitPinResponse { ck_rv: error.0 }));
        }
    };

    let pin = req.pin;
    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.init_pin(session, pin.as_deref())).await?;

    let ck_rv = match &result {
        Ok(()) => {
            info!(context_id = %ctx_id.0, "InitPIN succeeded");
            CkRv::OK.0
        }
        Err(error) => {
            warn!(context_id = %ctx_id.0, rv = error.0, "InitPIN failed");
            error.0
        }
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::InitPinResponse { ck_rv }))
}

pub(super) async fn set_pin(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SetPinRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SetPinResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SetPinResponse { ck_rv: error.0 }));
        }
    };

    let old_pin = req.old_pin;
    let new_pin = req.new_pin;
    let backend = backend_ref.clone();
    let result =
        spawn_backend(move || backend.set_pin(session, old_pin.as_deref(), new_pin.as_deref()))
            .await?;

    let ck_rv = match &result {
        Ok(()) => {
            info!(context_id = %ctx_id.0, "SetPIN succeeded");
            CkRv::OK.0
        }
        Err(error) => {
            warn!(context_id = %ctx_id.0, rv = error.0, "SetPIN failed");
            error.0
        }
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::SetPinResponse { ck_rv }))
}

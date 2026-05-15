//! Handlers for PKCS#11 3.0/3.2 session extension RPCs (Wave 1).
//!
//! Replaces the stub handlers from `pkcs11_3x_stubs.rs` for:
//! - `C_LoginUser`
//! - `C_SessionCancel`
//! - `C_GetSessionValidationFlags`

use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{info, warn};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::context_manager::{ClientContextId, ContextManager};
use super::service_utils::{resolve_session, spawn_backend};

pub(super) async fn login_user(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::LoginUserRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::LoginUserResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse { ck_rv: error.0 }));
        }
    };

    let user_type = match CkUserType::from_raw(req.user_type) {
        Some(user_type) => user_type,
        None => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse {
                ck_rv: CkRv::USER_TYPE_INVALID.0,
            }));
        }
    };

    let user_type_raw = req.user_type;
    // Security: DO NOT log pin or username at any tracing level.
    let pin = req.pin;
    let username = req.username;
    let backend = backend_ref.clone();
    let result =
        spawn_backend(move || backend.login_user(session, user_type, &username, &pin)).await?;

    let ck_rv = match &result {
        Ok(()) => {
            info!(context_id = %ctx_id.0, user_type = user_type_raw, "LoginUser succeeded");
            CkRv::OK.0
        }
        Err(error) => {
            warn!(context_id = %ctx_id.0, user_type = user_type_raw, rv = error.0, "LoginUser failed");
            error.0
        }
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse { ck_rv }))
}

pub(super) async fn session_cancel(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SessionCancelRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SessionCancelResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SessionCancelResponse {
                ck_rv: error.0,
            }));
        }
    };

    let flags = CkFlags(req.flags);
    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.session_cancel(session, flags)).await?;

    let ck_rv = match &result {
        Ok(()) => {
            info!(context_id = %ctx_id.0, "SessionCancel succeeded");
            CkRv::OK.0
        }
        Err(error) => {
            warn!(context_id = %ctx_id.0, rv = error.0, "SessionCancel failed");
            error.0
        }
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::SessionCancelResponse { ck_rv }))
}

pub(super) async fn get_session_validation_flags(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetSessionValidationFlagsRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetSessionValidationFlagsResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetSessionValidationFlagsResponse {
                ck_rv: error.0,
                flags: 0,
            }));
        }
    };

    let flags_type = req.flags_type;
    let backend = backend_ref.clone();
    let result =
        spawn_backend(move || backend.get_session_validation_flags(session, flags_type)).await?;

    let (ck_rv, flags) = match result {
        Ok(flags) => (CkRv::OK.0, flags),
        Err(error) => (error.0, 0),
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::GetSessionValidationFlagsResponse { ck_rv, flags }))
}

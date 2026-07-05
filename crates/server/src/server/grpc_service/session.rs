use std::sync::Arc;
use std::time::Instant;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_audit::EventClass;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::auth::policy::TokenPolicy;
use super::super::context_manager::{ClientContextId, ContextManager};
use super::super::handle_map::VirtualHandle;
use super::audit_events::emit_auth_event;
#[path = "session_handlers/auth.rs"]
mod auth;
#[path = "session_handlers/lifecycle.rs"]
mod lifecycle;
#[path = "session_handlers/management.rs"]
mod management;

use crate::server::grpc_service::HandlerContext;

/// Open a session, emit a fail-closed `Auth` audit record after the result is
/// known.  Used by the main dispatch path (receives the full `HandlerContext`
/// from `mod.rs`).
pub(super) async fn open_session_with_policy(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::OpenSessionRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::OpenSessionResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let slot_for_audit = Some(request.get_ref().slot_id as u64);

    let response = lifecycle::open_session(
        &ctx.context_manager,
        &ctx.backend,
        ctx.token_policy.as_ref(),
        request,
    )
    .await?;

    let ck_rv = response.get_ref().ck_rv;
    // Record the returned virtual session handle on success so the record is
    // queryable by session as well as slot.
    let session_for_audit =
        if ck_rv == CkRv::OK.0 { Some(response.get_ref().session_handle) } else { None };

    if emit_auth_event(
        ctx,
        &ctx_id,
        "C_OpenSession",
        EventClass::Auth,
        slot_for_audit,
        session_for_audit,
        ck_rv,
        started,
    )
    .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::OpenSessionResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
            session_handle: 0,
        }));
    }

    Ok(response)
}

/// Test-only shim: wraps `open_session_with_policy` with a default token
/// policy and a `HandlerContext` built from the raw manager + backend.
/// Production paths call `open_session_with_policy` directly via `mod.rs`.
#[cfg(test)]
pub(super) async fn open_session(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::OpenSessionRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::OpenSessionResponse>, Status> {
    let ctx = HandlerContext::for_test(ctx_mgr, backend_ref);
    open_session_with_policy(&ctx, request).await
}

pub(super) async fn close_session(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::CloseSessionRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CloseSessionResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    // Look up the slot BEFORE the inner handler removes the session mapping.
    let vh = VirtualHandle(request.get_ref().session_handle);
    let slot_for_audit = ctx
        .context_manager
        .get_context(&ctx_id, |c| c.session_slots.get(&vh).copied())
        .await
        .flatten()
        .map(|s| s.0);

    let response = lifecycle::close_session(&ctx.context_manager, &ctx.backend, request).await?;
    let ck_rv = response.get_ref().ck_rv;

    if emit_auth_event(
        ctx,
        &ctx_id,
        "C_CloseSession",
        EventClass::Auth,
        slot_for_audit,
        session_for_audit,
        ck_rv,
        started,
    )
    .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
        }));
    }

    Ok(response)
}

#[allow(dead_code)]
pub(super) async fn close_all_sessions(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::CloseAllSessionsRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CloseAllSessionsResponse>, Status> {
    let token_policy =
        TokenPolicy::from_config(&crate::config::AuthConfig::default()).expect("default policy");
    close_all_sessions_with_policy(ctx_mgr, backend_ref, &token_policy, request).await
}

pub(super) async fn close_all_sessions_with_policy(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::CloseAllSessionsRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CloseAllSessionsResponse>, Status> {
    lifecycle::close_all_sessions(ctx_mgr, backend_ref, token_policy, request).await
}

pub(super) async fn get_session_info(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetSessionInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetSessionInfoResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    lifecycle::get_session_info(ctx_mgr, backend_ref, request).await
}

pub(super) async fn login(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::LoginRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::LoginResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    // Look up the owning slot before handing the request to the inner handler.
    // This is a cheap DashMap read (no .await); the inner handler re-resolves
    // it anyway as part of its session-slot lookup.
    let vh = VirtualHandle(request.get_ref().session_handle);
    let slot_for_audit = ctx
        .context_manager
        .get_context(&ctx_id, |c| c.session_slots.get(&vh).copied())
        .await
        .flatten()
        .map(|s| s.0);

    let response = auth::login(&ctx.context_manager, &ctx.backend, request).await?;
    let ck_rv = response.get_ref().ck_rv;

    if emit_auth_event(
        ctx,
        &ctx_id,
        "C_Login",
        EventClass::Auth,
        slot_for_audit,
        session_for_audit,
        ck_rv,
        started,
    )
    .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
        }));
    }

    Ok(response)
}

pub(super) async fn logout(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::LogoutRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::LogoutResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    let vh = VirtualHandle(request.get_ref().session_handle);
    let slot_for_audit = ctx
        .context_manager
        .get_context(&ctx_id, |c| c.session_slots.get(&vh).copied())
        .await
        .flatten()
        .map(|s| s.0);

    let response = auth::logout(&ctx.context_manager, &ctx.backend, request).await?;
    let ck_rv = response.get_ref().ck_rv;

    if emit_auth_event(
        ctx,
        &ctx_id,
        "C_Logout",
        EventClass::Auth,
        slot_for_audit,
        session_for_audit,
        ck_rv,
        started,
    )
    .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::LogoutResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
        }));
    }

    Ok(response)
}

/// Init token, emit a fail-closed `KeyMgmt` audit record.
pub(super) async fn init_token_with_policy(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::InitTokenRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::InitTokenResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let slot_for_audit = Some(request.get_ref().slot_id as u64);

    let response = management::init_token(
        &ctx.context_manager,
        &ctx.backend,
        ctx.token_policy.as_ref(),
        request,
    )
    .await?;
    let ck_rv = response.get_ref().ck_rv;

    if emit_auth_event(
        ctx,
        &ctx_id,
        "C_InitToken",
        EventClass::KeyMgmt,
        slot_for_audit,
        None,
        ck_rv,
        started,
    )
    .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::InitTokenResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
        }));
    }

    Ok(response)
}

/// Test-only shim for `init_token` with default policy and no HandlerContext.
#[cfg(test)]
pub(super) async fn init_token(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::InitTokenRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::InitTokenResponse>, Status> {
    let ctx = HandlerContext::for_test(ctx_mgr, backend_ref);
    init_token_with_policy(&ctx, request).await
}

pub(super) async fn init_pin(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::InitPinRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::InitPinResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    let vh = VirtualHandle(request.get_ref().session_handle);
    let slot_for_audit = ctx
        .context_manager
        .get_context(&ctx_id, |c| c.session_slots.get(&vh).copied())
        .await
        .flatten()
        .map(|s| s.0);

    let response = management::init_pin(&ctx.context_manager, &ctx.backend, request).await?;
    let ck_rv = response.get_ref().ck_rv;

    if emit_auth_event(
        ctx,
        &ctx_id,
        "C_InitPIN",
        EventClass::KeyMgmt,
        slot_for_audit,
        session_for_audit,
        ck_rv,
        started,
    )
    .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::InitPinResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
        }));
    }

    Ok(response)
}

pub(super) async fn set_pin(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SetPinRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SetPinResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    let vh = VirtualHandle(request.get_ref().session_handle);
    let slot_for_audit = ctx
        .context_manager
        .get_context(&ctx_id, |c| c.session_slots.get(&vh).copied())
        .await
        .flatten()
        .map(|s| s.0);

    let response = management::set_pin(&ctx.context_manager, &ctx.backend, request).await?;
    let ck_rv = response.get_ref().ck_rv;

    if emit_auth_event(
        ctx,
        &ctx_id,
        "C_SetPIN",
        EventClass::KeyMgmt,
        slot_for_audit,
        session_for_audit,
        ck_rv,
        started,
    )
    .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SetPinResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
        }));
    }

    Ok(response)
}

pub(super) async fn get_function_status(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetFunctionStatusRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetFunctionStatusResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    lifecycle::get_function_status(ctx_mgr, backend_ref, request).await
}

pub(super) async fn cancel_function(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::CancelFunctionRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CancelFunctionResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    lifecycle::cancel_function(ctx_mgr, backend_ref, request).await
}

#[cfg(test)]
mod tests;

use crate::server::slot_map::BackendSlotId;
use std::sync::Arc;
use std::time::Duration;

use tonic::{Request, Response, Status};
use tracing::debug;

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::auth::policy::TokenPolicy;
use super::super::super::context_manager::{
    ClientContextId, CloseSessionBeginError, ContextManager,
};
use super::super::super::handle_map::VirtualHandle;
use super::super::authorization;
use super::super::service_utils::{
    ck_rv_only, context_exists, current_context_operation_guard, register_session_handle,
    resolve_session, resolve_slot, spawn_backend, spawn_backend_with_optional_timeout,
};

pub(super) async fn open_session(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::OpenSessionRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::OpenSessionResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::OpenSessionResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            session_handle: 0,
        }));
    }

    let backend_slot = match resolve_slot(ctx_mgr, req.slot_id).await {
        Ok(slot) => slot,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::OpenSessionResponse {
                ck_rv: error.0,
                session_handle: 0,
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
            return Ok(Response::new(pkcs11_proxy_ng_proto::OpenSessionResponse {
                ck_rv: CkRv::SLOT_ID_INVALID.0,
                session_handle: 0,
            }));
        }
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::OpenSessionResponse {
                ck_rv: error.0,
                session_handle: 0,
            }));
        }
    }

    // G2-PR3: per-principal session quota (opt-in; zero-cost when unset).
    // principal_key is derived only when the quota is active to avoid an
    // unconditional DashMap lookup + String clone on every open_session call
    // in the common (limit-unset) path.
    if let Some(max) = crate::server::rate_quota::per_principal_max_sessions() {
        let principal_key = ctx_mgr.context_identity(&ctx_id).unwrap_or_else(|| ctx_id.0.clone());
        if ctx_mgr.session_count_for_principal(&principal_key) >= max {
            crate::server::resilience::record_session_quota_rejected();
            return Ok(Response::new(pkcs11_proxy_ng_proto::OpenSessionResponse {
                ck_rv: CkRv::SESSION_COUNT.0,
                session_handle: 0,
            }));
        }
    }

    let flags = CkSessionFlags(req.flags as u64);
    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.open_session(backend_slot.0, flags)).await?;

    match result {
        Ok(backend_session) => {
            match register_session_handle(ctx_mgr, &ctx_id, backend_session, backend_slot).await {
                Some(virtual_handle) => {
                    debug!(
                        context_id = %ctx_id.0,
                        slot = req.slot_id,
                        virtual_handle,
                        "Session opened"
                    );
                    Ok(Response::new(pkcs11_proxy_ng_proto::OpenSessionResponse {
                        ck_rv: CkRv::OK.0,
                        session_handle: virtual_handle,
                    }))
                }
                None => {
                    let backend = backend_ref.clone();
                    let _ = spawn_backend(move || backend.close_session(backend_session)).await;
                    Ok(Response::new(pkcs11_proxy_ng_proto::OpenSessionResponse {
                        ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
                        session_handle: 0,
                    }))
                }
            }
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::OpenSessionResponse {
            ck_rv: error.0,
            session_handle: 0,
        })),
    }
}

pub(super) async fn close_session(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::CloseSessionRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CloseSessionResponse>, Status> {
    close_session_with_timeout(ctx_mgr, backend_ref, request, None).await
}

pub(super) async fn close_session_with_timeout(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::CloseSessionRequest>,
    timeout_override: Option<Duration>,
) -> Result<Response<pkcs11_proxy_ng_proto::CloseSessionResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let vh = VirtualHandle(req.session_handle);
    let mut transition = match ctx_mgr.begin_close_session_with_guard(
        &ctx_id,
        vh,
        current_context_operation_guard(),
    ) {
        Ok(transition) => transition,
        Err(CloseSessionBeginError::ContextMissing) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse {
                ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            }));
        }
        Err(CloseSessionBeginError::SessionMissing) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse {
                ck_rv: CkRv::SESSION_HANDLE_INVALID.0,
            }));
        }
    };

    let session = CkSessionHandle(transition.backend_handle().0);
    let backend = backend_ref.clone();
    let operation = move || {
        transition.mark_started();
        let result = backend.close_session(session);
        transition.settle(&result);
        result
    };
    let result = spawn_backend_with_optional_timeout(timeout_override, operation).await?;

    let ck_rv = ck_rv_only(result);
    if ck_rv == CkRv::OK.0 {
        debug!(context_id = %ctx_id.0, virtual_handle = req.session_handle, "Session closed");
    }
    Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse { ck_rv }))
}

pub(super) async fn close_all_sessions(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::CloseAllSessionsRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CloseAllSessionsResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::CloseAllSessionsResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
        }));
    }

    // Validate the slot ID (maps virtual→backend).
    let backend_slot = match resolve_slot(ctx_mgr, req.slot_id).await {
        Ok(slot) => slot,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CloseAllSessionsResponse {
                ck_rv: error.0,
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
            return Ok(Response::new(pkcs11_proxy_ng_proto::CloseAllSessionsResponse {
                ck_rv: CkRv::SLOT_ID_INVALID.0,
            }));
        }
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CloseAllSessionsResponse {
                ck_rv: error.0,
            }));
        }
    }

    // ADR-0002 §7: close only THIS client's sessions for the target slot.
    // We MUST NOT call backend.close_all_sessions() — that would close
    // sessions belonging to other logical client instances.
    let backend_sessions = ctx_mgr
        .get_context(&ctx_id, |ctx| ctx.remove_sessions_for_slot(backend_slot))
        .await
        .unwrap_or_default();

    // m-5: attempt the last-holder logout BEFORE the batch close, using one
    // of the closing sessions as the preferred carrier (ADR-0002 §7: the
    // logout rides a still-open session and runs before the departing
    // context's backend sessions close). The logical login is already
    // removed above, so the last-holder check observes only other live
    // contexts. No routine WARN on the ordinary logged-in close-all.
    if held_login && let Some(carrier) = backend_sessions.first() {
        ctx_mgr
            .backend_logout_if_last_holder_out(backend_ref, backend_slot, Some(carrier.0 as u64))
            .await;
    }

    let count = backend_sessions.len();
    let ck_rv = if backend_sessions.is_empty() {
        CkRv::OK.0
    } else {
        // Single spawn_backend call to close all sessions in batch.
        let sessions: Vec<CkSessionHandle> =
            backend_sessions.iter().map(|bh| CkSessionHandle(bh.0 as u64)).collect();
        let backend = backend_ref.clone();
        let result = spawn_backend(move || backend.close_sessions(&sessions)).await?;
        match result {
            Ok(()) => CkRv::OK.0,
            Err(rv) => rv.0,
        }
    };
    // D6(2): post-close fallback for the race where a held login lost its
    // last own session to a concurrent close between the snapshot and the
    // removal above (login implies a session, so this is normally
    // unreachable): retry via any live session, as before.
    if held_login && backend_sessions.is_empty() {
        ctx_mgr.backend_logout_if_last_holder_out(backend_ref, backend_slot, None).await;
    }

    debug!(
        context_id = %ctx_id.0,
        slot = req.slot_id,
        closed = count,
        "CloseAllSessions completed"
    );

    Ok(Response::new(pkcs11_proxy_ng_proto::CloseAllSessionsResponse { ck_rv }))
}

pub(super) async fn get_session_info(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetSessionInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetSessionInfoResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetSessionInfoResponse {
                ck_rv: error.0,
                info: None,
            }));
        }
    };

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.get_session_info(session)).await?;

    match result {
        Ok(mut info) => {
            let reported_slot = BackendSlotId(info.slot_id);
            let owner = ctx_mgr.slot_for_session(&ctx_id, VirtualHandle(req.session_handle)).await;
            let virtual_slot = ctx_mgr.to_virtual_slot(reported_slot).await;
            if owner != Some(reported_slot) || virtual_slot.is_none() {
                return Ok(Response::new(pkcs11_proxy_ng_proto::GetSessionInfoResponse {
                    ck_rv: CkRv::DEVICE_ERROR.0,
                    info: None,
                }));
            }
            info.slot_id = CkSlotId(virtual_slot.expect("mapping checked above").0);
            Ok(Response::new(pkcs11_proxy_ng_proto::GetSessionInfoResponse {
                ck_rv: CkRv::OK.0,
                info: Some(pkcs11_proxy_ng_proto::SessionInfo::from(&info)),
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::GetSessionInfoResponse {
            ck_rv: error.0,
            info: None,
        })),
    }
}

pub(super) async fn get_function_status(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetFunctionStatusRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetFunctionStatusResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetFunctionStatusResponse {
                ck_rv: error.0,
            }));
        }
    };

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.get_function_status(session)).await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::GetFunctionStatusResponse {
        ck_rv: ck_rv_only(result),
    }))
}

pub(super) async fn cancel_function(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::CancelFunctionRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CancelFunctionResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CancelFunctionResponse {
                ck_rv: error.0,
            }));
        }
    };

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.cancel_function(session)).await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::CancelFunctionResponse { ck_rv: ck_rv_only(result) }))
}

use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::debug;

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::auth::policy::TokenPolicy;
use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::super::handle_map::VirtualHandle;
use super::super::authorization;
use super::super::service_utils::{
    ck_rv_only, context_exists, register_session_handle, resolve_session, resolve_slot,
    spawn_backend,
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

    // G2-PR3: per-principal session quota (opt-in; no-op when unset).
    // Derive the principal key exactly as the dispatch seam does:
    // authenticated_identity when bound, ctx_id string otherwise.
    // The derived count is leak-proof — it reads live session_slots bookkeeping
    // rather than a separate reserve/release counter.
    let principal_key = ctx_mgr.context_identity(&ctx_id).unwrap_or_else(|| ctx_id.0.clone());
    if let Some(max) = crate::server::rate_quota::per_principal_max_sessions()
        && ctx_mgr.session_count_for_principal(&principal_key) >= max
    {
        crate::server::resilience::record_session_quota_rejected();
        return Ok(Response::new(pkcs11_proxy_ng_proto::OpenSessionResponse {
            ck_rv: CkRv::SESSION_COUNT.0,
            session_handle: 0,
        }));
    }

    let flags = CkSessionFlags(req.flags as u64);
    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.open_session(backend_slot, flags)).await?;

    match result {
        Ok(backend_session) => {
            let slot_id = CkSlotId(req.slot_id as u64);
            match register_session_handle(ctx_mgr, &ctx_id, backend_session, slot_id).await {
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
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let vh = VirtualHandle(req.session_handle);
    // Resolve WITHOUT removing the mapping: removing it before the backend close
    // (as the old code did) orphans the backend session if the close fails — the
    // virtual handle is gone, so the client can neither retry nor reach it (M3).
    let resolved = ctx_mgr.get_context(&ctx_id, |ctx| ctx.session_handles.resolve(vh)).await;

    let backend_handle = match resolved {
        None => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse {
                ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            }));
        }
        Some(None) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse {
                ck_rv: CkRv::SESSION_HANDLE_INVALID.0,
            }));
        }
        Some(Some(backend_handle)) => backend_handle,
    };

    let session = CkSessionHandle(backend_handle.0 as u64);
    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.close_session(session)).await?;

    // Drop the virtual handle (and its session-scoped state — B2 eviction, login
    // state) only on a TERMINAL result: a clean close, or the backend reporting
    // the session already gone. A transient backend failure keeps the mapping so
    // the client can retry and the backend session is not orphaned (M3).
    let ck_rv = match result {
        Ok(()) => {
            let _ = ctx_mgr.get_context(&ctx_id, |ctx| ctx.remove_session(vh)).await;
            debug!(context_id = %ctx_id.0, virtual_handle = req.session_handle, "Session closed");
            CkRv::OK.0
        }
        Err(error) if error == CkRv::SESSION_HANDLE_INVALID || error == CkRv::SESSION_CLOSED => {
            let _ = ctx_mgr.get_context(&ctx_id, |ctx| ctx.remove_session(vh)).await;
            error.0
        }
        Err(error) => error.0,
    };
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
    let _backend_slot = match resolve_slot(ctx_mgr, req.slot_id).await {
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
        _backend_slot,
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
    let slot_id = CkSlotId(req.slot_id as u64);
    let backend_sessions = ctx_mgr
        .get_context(&ctx_id, |ctx| ctx.remove_sessions_for_slot(slot_id))
        .await
        .unwrap_or_default();

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
            if let Some(virtual_slot) = ctx_mgr.to_virtual_slot(info.slot_id).await {
                info.slot_id = virtual_slot;
            }
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

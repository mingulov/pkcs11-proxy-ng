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

    let flags = CkSessionFlags(req.flags);
    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.open_session(backend_slot, flags)).await?;

    match result {
        Ok(backend_session) => {
            let slot_id = CkSlotId(req.slot_id);
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

    let resolved = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            let vh = VirtualHandle(req.session_handle);
            ctx.session_slots.remove(&vh);
            ctx.session_handles.remove(vh)
        })
        .await;

    match resolved {
        None => Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
        })),
        Some(None) => Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse {
            ck_rv: CkRv::SESSION_HANDLE_INVALID.0,
        })),
        Some(Some(backend_handle)) => {
            let session = CkSessionHandle(backend_handle.0);
            let backend = backend_ref.clone();
            let result = spawn_backend(move || backend.close_session(session)).await?;
            let ck_rv = match result {
                Ok(()) => {
                    debug!(context_id = %ctx_id.0, virtual_handle = req.session_handle, "Session closed");
                    CkRv::OK.0
                }
                Err(error) => error.0,
            };
            Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse { ck_rv }))
        }
    }
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
    let slot_id = CkSlotId(req.slot_id);
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
            backend_sessions.iter().map(|bh| CkSessionHandle(bh.0)).collect();
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

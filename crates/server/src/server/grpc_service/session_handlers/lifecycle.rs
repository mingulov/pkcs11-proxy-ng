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
use super::super::super::handle_map::{BackendHandle, VirtualHandle};
use super::super::authorization;
use super::super::service_utils::{
    ck_rv_only, context_exists, current_context_operation_guard, current_peer, login_lock_timeout,
    principal_quota_key, register_session_handle, resolve_session, resolve_slot, spawn_backend,
    spawn_backend_with_optional_timeout,
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
    // W1-L6-04: the check-and-reserve is atomic under the quota mutex, and
    // the reservation counts toward the cap until the session registers
    // (released on every failure path by drop), so concurrent opens cannot
    // exceed the cap.
    let quota_reservation =
        if let Some(max) = crate::server::rate_quota::per_principal_max_sessions() {
            // W1-L7-02: shared key with the in-flight guard — unauthenticated
            // contexts key on the peer IP, not the context id.
            let principal_key = principal_quota_key(ctx_mgr, &ctx_id);
            // Bind a peer-keyed context to its peer BEFORE reserving, so the
            // live-session counter attributes this context's sessions to the
            // shared key. Identity-bound and peerless contexts record
            // nothing — their counting is unchanged.
            if ctx_mgr.context_identity(&ctx_id).is_none()
                && let Some(peer) = current_peer()
            {
                let ip = peer.ip();
                ctx_mgr.get_context(&ctx_id, |ctx| ctx.last_peer_ip = Some(ip)).await;
            }
            match ctx_mgr.try_reserve_session_for_principal(&principal_key, max) {
                Some(reservation) => Some(reservation),
                None => {
                    crate::server::resilience::record_session_quota_rejected();
                    return Ok(Response::new(pkcs11_proxy_ng_proto::OpenSessionResponse {
                        ck_rv: CkRv::SESSION_COUNT.0,
                        session_handle: 0,
                    }));
                }
            }
        } else {
            None
        };

    let flags = CkSessionFlags(req.flags as u64);
    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.open_session(backend_slot.0, flags)).await?;

    match result {
        Ok(backend_session) => {
            match register_session_handle(ctx_mgr, &ctx_id, backend_session, backend_slot).await {
                Some(virtual_handle) => {
                    // W1-L6-04: the live count now covers this session —
                    // release the reservation (failure paths below release
                    // by drop at return).
                    drop(quota_reservation);
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

    // W1-L6-25: close takes the per-slot login lock around the D6(2) snapshot
    // + suspend, so login's re-resolve-under-lock and this suspend are
    // mutually exclusive — a login can no longer drive the backend with a
    // handle this close already suspended.
    //
    // Lock ordering (Task 3 order, shared with login/logout/login_user):
    // per-slot login tokio Mutex OUTER; while holding it, take only
    // TRANSIENT contexts-DashMap guards (the snapshot + begin below). Never
    // acquire the slot lock while holding a contexts guard.
    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
        }));
    }
    let Some(slot) = ctx_mgr.slot_for_session(&ctx_id, vh).await else {
        return Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse {
            ck_rv: CkRv::SESSION_HANDLE_INVALID.0,
        }));
    };
    // Bounded acquisition (G2/V11): refuse with CKR_GENERAL_ERROR (W1-L3-01:
    // proxy serialization refusal, same as login/logout/login_user) rather
    // than queue unboundedly when a slow/wedged backend pins the lock.
    // Nothing is mutated yet, so early return is safe.
    let login_guard = ctx_mgr.slot_login_lock(slot);
    let _login_lock = match tokio::time::timeout(login_lock_timeout(), login_guard.lock()).await {
        Ok(guard) => guard,
        Err(_elapsed) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse {
                ck_rv: CkRv::GENERAL_ERROR.0,
            }));
        }
    };

    // D6(2) snapshot: when this close drops the context's last logical login
    // for its slot, the backend login must be released too (last-context-out)
    // so a later login PIN-verifies against a logged-out token.
    let held_login_slot = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            ctx.session_slots.get(&vh).copied().filter(|slot| ctx.login_state.contains_key(slot))
        })
        .await
        .flatten();
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

    // Release the slot lock before the backend calls. Suspend (above) is the
    // step that races login's resolve, and both are now under the lock — the
    // backend close needs no slot serialization once the mapping is suspended.
    // The D6(2) last-holder helpers below take this same lock via try_lock, so
    // holding it across them would skip the logout.
    drop(_login_lock);

    let session = CkSessionHandle(transition.backend_handle().0);
    // T5F: attempt the last-holder logout BEFORE the backend close, using
    // the closing session as the preferred carrier (singular-path analogue
    // of the m-5 close-all ordering, ADR-0002 §7: the logout rides a
    // still-open session). Runs only when this close drops the context's
    // last own session for a held-login slot; the excluding-self check
    // observes only other live contexts. Own login stays held across the
    // close so transient failures retain it (transition semantics). No
    // routine WARN on the ordinary logged-in singular close.
    let pre_close_logout_done = match held_login_slot {
        Some(slot)
            if ctx_mgr
                .get_context(&ctx_id, |ctx| {
                    !ctx.session_slots.iter().any(|(other, s)| *s == slot && *other != vh)
                })
                .await
                .unwrap_or(false) =>
        {
            ctx_mgr
                .backend_logout_if_last_holder_out_excluding(
                    backend_ref,
                    slot,
                    Some(transition.backend_handle().0),
                    &ctx_id,
                )
                .await
        }
        _ => false,
    };
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
    // D6(2): release the backend login when this close dropped the last
    // logical login for the slot. Best-effort and self-guarded: no-ops when
    // the close failed transiently (login retained), when sibling sessions
    // keep the login, or when another live context holds it. Skipped when
    // the pre-close attempt already released the login — a second backend
    // logout would answer USER_NOT_LOGGED_IN and WARN.
    if let Some(slot) = held_login_slot
        && !pre_close_logout_done
    {
        ctx_mgr.backend_logout_if_last_holder_out(backend_ref, slot, None).await;
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
    // W1-L6-03: suspend-then-close (mirror of the singular suspend path):
    // mappings stay until the backend close confirms, and a transient
    // failure reactivates them instead of leaking live backend sessions
    // with no mappings. The logical login is likewise dropped only when
    // the closes settle terminal.
    // D6(2): snapshot the held login first; the last-holder logout below
    // excludes this context (T5F analogue of the singular pre-close path)
    // because the own login is still held across the batch close.
    let held_login = ctx_mgr
        .get_context(&ctx_id, |ctx| ctx.login_state.contains_key(&backend_slot))
        .await
        .unwrap_or(false);
    let virtual_sessions: Vec<VirtualHandle> = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            ctx.session_slots
                .iter()
                .filter(|(_, slot)| **slot == backend_slot)
                .map(|(vh, _)| *vh)
                .collect()
        })
        .await
        .unwrap_or_default();
    let mut transitions = Vec::with_capacity(virtual_sessions.len());
    for vh in virtual_sessions {
        match ctx_mgr.begin_close_session_with_guard(&ctx_id, vh, None) {
            Ok(transition) => transitions.push(transition),
            Err(CloseSessionBeginError::ContextMissing) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::CloseAllSessionsResponse {
                    ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
                }));
            }
            Err(CloseSessionBeginError::SessionMissing) => {
                // Already suspended by a concurrent singular close, which
                // owns its completion — skip it here.
            }
        }
    }
    let backend_sessions: Vec<BackendHandle> =
        transitions.iter().map(|t| t.backend_handle()).collect();

    // m-5: attempt the last-holder logout BEFORE the batch close, using one
    // of the closing sessions as the preferred carrier (ADR-0002 §7: the
    // logout rides a still-open session and runs before the departing
    // context's backend sessions close). The own login is still held, so
    // the excluding variant keeps the last-holder check exact (T5F). No
    // routine WARN on the ordinary logged-in close-all.
    if held_login && let Some(carrier) = backend_sessions.first() {
        ctx_mgr
            .backend_logout_if_last_holder_out_excluding(
                backend_ref,
                backend_slot,
                Some(carrier.0 as u64),
                &ctx_id,
            )
            .await;
    }

    let count = backend_sessions.len();
    let ck_rv = if backend_sessions.is_empty() {
        CkRv::OK.0
    } else {
        // Single spawn_backend call to close all sessions in batch. The
        // transitions move into the blocking closure (singular-path
        // discipline): a timeout/cancellation cannot strand or prematurely
        // reactivate the suspended handles, and every transition settles
        // against the one batch outcome.
        let sessions: Vec<CkSessionHandle> =
            backend_sessions.iter().map(|bh| CkSessionHandle(bh.0 as u64)).collect();
        let backend = backend_ref.clone();
        let result = spawn_backend(move || {
            let mut transitions = transitions;
            for transition in &mut transitions {
                transition.mark_started();
            }
            let result = backend.close_sessions(&sessions);
            for transition in &mut transitions {
                transition.settle(&result);
            }
            result
        })
        .await?;
        match result {
            Ok(()) => CkRv::OK.0,
            Err(rv) => rv.0,
        }
    };
    // D6(2): post-close fallback for the race where a held login lost its
    // last own session to a concurrent close between the snapshot and the
    // suspend above (login implies a session, so this is normally
    // unreachable): retry via any live session, excluding self as above.
    if held_login && backend_sessions.is_empty() {
        ctx_mgr
            .backend_logout_if_last_holder_out_excluding(backend_ref, backend_slot, None, &ctx_id)
            .await;
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

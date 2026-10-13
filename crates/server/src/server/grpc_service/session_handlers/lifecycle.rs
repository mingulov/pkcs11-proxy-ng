use crate::server::slot_map::BackendSlotId;
use std::future::Future;
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
    principal_quota_key, register_session_handle, resolve_session, resolve_slot,
    scope_context_operation, scope_peer_admission, spawn_backend,
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
            // Deferred T30 M3: record-before-reserve is deliberate — even a
            // REJECTED open re-keys `last_peer_ip`. Zero-sum at the moment:
            // the rewrite moves this context's live sessions from the old
            // key to the new key (total live unchanged; freed capacity
            // under the old key is exactly the capacity consumed under the
            // new key, which may read over max — conservative, fail-closed
            // there). Absent attribution changes every key holds at most
            // max and live total stays within k*max for k source IPs; a
            // re-key frees the old key (re-admittable) while charging the
            // new key, so repeated cross-IP re-keys can push total live
            // past k*max — inherent to last-peer attribution. The rejected
            // open itself creates no session and holds no slot. Pinned by
            // `open_session_quota_rejected_open_rekeys_without_creating_quota`.
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

/// Run close completion (worker await + post-settle logout) detached from
/// handler cancellation (F1): the spawned task owns the whole sequence to
/// true completion, so dropping the handler future (tonic timeout, client
/// disconnect) cannot skip the last-holder logout. The handler still awaits
/// the task for its response — RV and `Status` semantics are unchanged;
/// only a cancellation detaches, and the self-guarded logout then still
/// runs. The request task-locals (peer, operation guard) are re-published
/// inside so breaker admission and context pinning match the direct path.
async fn await_close_completion_detached<R, F>(completion: F) -> Result<Response<R>, Status>
where
    R: Send + 'static,
    F: Future<Output = Result<Response<R>, Status>> + Send + 'static,
{
    let peer = current_peer();
    let guard = current_context_operation_guard();
    let task = tokio::spawn(async move {
        scope_peer_admission(peer, scope_context_operation(guard, completion)).await
    });
    match task.await {
        Ok(outcome) => outcome,
        Err(error) => Err(Status::internal(format!("close completion task failed: {error}"))),
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
    // so a later login PIN-verifies against a logged-out token. The login
    // VALUE travels with the snapshot so the transient carrier opens with
    // SO-aware flags (Q01-P1).
    let held_login_slot = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            ctx.session_slots
                .get(&vh)
                .copied()
                .and_then(|slot| ctx.login_state.get(&slot).copied().map(|login| (slot, login)))
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
            // F2: the live mapping is missing, but the slot lookup above
            // proved `session_slots` still names this handle — it is
            // suspended under an in-flight close (or settled terminally
            // in between). Answer outcome-ambiguous FUNCTION_FAILED
            // while a suspended entry exists so a racing close does not
            // evict a member the owner may reactivate; only a
            // proven-gone handle answers SESSION_HANDLE_INVALID.
            let suspended = ctx_mgr
                .get_context(&ctx_id, |ctx| ctx.session_handles.suspended_backend(vh).is_some())
                .await
                .unwrap_or(false);
            let ck_rv =
                if suspended { CkRv::FUNCTION_FAILED.0 } else { CkRv::SESSION_HANDLE_INVALID.0 };
            return Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse { ck_rv }));
        }
    };

    // Release the slot lock before the backend calls. Suspend (above) is the
    // step that races login's resolve, and both are now under the lock — the
    // backend close needs no slot serialization once the mapping is suspended.
    // The D6(2) last-holder helpers below take this same lock via try_lock, so
    // holding it across them would skip the logout.
    drop(_login_lock);

    let session = CkSessionHandle(transition.backend_handle().0);
    // Q01: no logout runs before the backend close. A pre-close logout
    // would strand the native login when the close then fails transiently
    // (the transition reactivates the mapping and the logical login, but
    // no PIN replay may restore the native one) — the last-holder release
    // below runs only after the close settles.
    let backend = backend_ref.clone();
    let operation = move || {
        transition.mark_started();
        let result = backend.close_session(session);
        transition.settle(&result);
        result
    };
    // F1: the worker await and the post-settle logout run as one detached
    // completion — a handler cancellation detaches the await but not the
    // task, so the logout still runs after the late settlement.
    let ctx_mgr_task = Arc::clone(ctx_mgr);
    let backend_task = Arc::clone(backend_ref);
    let ctx_id_owned = ctx_id.0.clone();
    let vh_raw = req.session_handle;
    await_close_completion_detached(async move {
        let result = spawn_backend_with_optional_timeout(timeout_override, operation).await?;

        let ck_rv = ck_rv_only(result);
        if ck_rv == CkRv::OK.0 {
            debug!(context_id = %ctx_id_owned, virtual_handle = vh_raw, "Session closed");
        }
        // D6(2): release the backend login when this close dropped the last
        // logical login for the slot. Best-effort and self-guarded: no-ops when
        // the close failed transiently (login retained), when sibling sessions
        // keep the login, or when another live context holds it — the native
        // login always survives with a retained logical login.
        if let Some((slot, login)) = held_login_slot {
            ctx_mgr_task.backend_logout_if_last_holder_out(&backend_task, slot, None, login).await;
        }
        Ok(Response::new(pkcs11_proxy_ng_proto::CloseSessionResponse { ck_rv }))
    })
    .await
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
    // D6(2): snapshot the held login first; the last-holder logout runs
    // after the batch settles (Q01), when a retained login still no-ops
    // it — never before the outcome is known. The login VALUE travels
    // with the snapshot so the transient carrier opens with SO-aware
    // flags (Q01-P1).
    let held_login = ctx_mgr
        .get_context(&ctx_id, |ctx| ctx.login_state.get(&backend_slot).copied())
        .await
        .flatten();
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
    let mut skipped_suspended = 0usize;
    for vh in virtual_sessions {
        match ctx_mgr.begin_close_session_with_guard(&ctx_id, vh, None) {
            Ok(transition) => transitions.push(transition),
            Err(CloseSessionBeginError::ContextMissing) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::CloseAllSessionsResponse {
                    ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
                }));
            }
            Err(CloseSessionBeginError::SessionMissing) => {
                // The member was suspended by an in-flight singular
                // close (which owns its completion) or already gone.
                // Count it ambiguous unless PROVEN gone: a member that
                // settles-transient between this begin-fail and the
                // check below reactivates live, and claiming OK for it
                // would evict shim state for a server-live session.
                // Absent mappings stay absent (only a suspended owner
                // can settle one, and it holds the suspended entry),
                // so proven-gone is stable and OK stays honest (Q01).
                let gone = ctx_mgr
                    .get_context(&ctx_id, |ctx| {
                        ctx.session_handles.resolve(vh).is_none()
                            && ctx.session_handles.suspended_backend(vh).is_none()
                    })
                    .await
                    .unwrap_or(false);
                if !gone {
                    skipped_suspended += 1;
                }
            }
        }
    }
    let backend_sessions: Vec<BackendHandle> =
        transitions.iter().map(|t| t.backend_handle()).collect();

    let count = backend_sessions.len();
    // F1: the batch await and the post-settle logout run as one detached
    // completion (singular-path discipline) — a handler cancellation
    // detaches the await but not the task, so the logout still runs after
    // the late settlement.
    let ctx_mgr_task = Arc::clone(ctx_mgr);
    let backend_task = Arc::clone(backend_ref);
    let ctx_id_owned = ctx_id.0.clone();
    let slot_id_raw = req.slot_id;
    await_close_completion_detached(async move {
        let ck_rv = if backend_sessions.is_empty() {
            if skipped_suspended > 0 {
                // Every member is owned by an in-flight singular close.
                // Claiming OK would evict shim state an owner may still
                // reactivate (a server-live session unreachable from the
                // shim); answer the same outcome-ambiguous FUNCTION_FAILED
                // as a timed-out singular close instead, so the shim
                // retains and the next call reports the owners' true
                // settlement.
                CkRv::FUNCTION_FAILED.0
            } else {
                CkRv::OK.0
            }
        } else {
            // Single spawn_backend call to close all sessions in batch. The
            // transitions move into the blocking closure (singular-path
            // discipline): a timeout/cancellation cannot strand or prematurely
            // reactivate the suspended handles. Q01: each transition settles
            // against its own per-session outcome — a partial batch drops the
            // sessions that actually closed and reactivates the survivors —
            // while the aggregate keeps the historical last-error CK_RV.
            let sessions: Vec<CkSessionHandle> =
                backend_sessions.iter().map(|bh| CkSessionHandle(bh.0 as u64)).collect();
            let backend = backend_task.clone();
            let result = spawn_backend(move || {
                let mut transitions = transitions;
                let mut last_error = None;
                for (transition, session) in transitions.iter_mut().zip(sessions.iter()) {
                    transition.mark_started();
                    let outcome = backend.close_session(*session);
                    transition.settle(&outcome);
                    if let Err(rv) = outcome {
                        last_error = Some(rv);
                    }
                }
                match last_error {
                    Some(rv) => Err(rv),
                    None => Ok(()),
                }
            })
            .await?;
            // A suspended member skipped above has an unknown fate owned
            // elsewhere: the batch cannot honestly claim OK for it (same
            // ambiguity as the empty-skipped batch — the shim must retain
            // until the owner settles). A real per-member failure keeps its
            // own aggregate.
            let mut batch_rv = match result {
                Ok(()) => CkRv::OK.0,
                Err(rv) => rv.0,
            };
            if skipped_suspended > 0 && batch_rv == CkRv::OK.0 {
                batch_rv = CkRv::FUNCTION_FAILED.0;
            }
            batch_rv
        };
        // D6(2): release the backend login when the batch dropped the last
        // logical login for the slot (Q01: only after the closes settle — a
        // retained login after a transient or partial failure no-ops the
        // helper, so the native login survives with it; this also covers the
        // race where a concurrent close took the last own session mid-batch).
        if let Some(login) = held_login {
            ctx_mgr_task
                .backend_logout_if_last_holder_out(&backend_task, backend_slot, None, login)
                .await;
        }

        debug!(
            context_id = %ctx_id_owned,
            slot = slot_id_raw,
            closed = count,
            skipped_suspended,
            "CloseAllSessions completed"
        );

        Ok(Response::new(pkcs11_proxy_ng_proto::CloseAllSessionsResponse { ck_rv }))
    })
    .await
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

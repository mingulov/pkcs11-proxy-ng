use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{info, warn};
use zeroize::Zeroizing;

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::context_manager::{ClientContextId, ContextManager, LoginState};
use super::super::super::handle_map::VirtualHandle;
use super::super::service_utils::spawn_backend;

fn login_state_for_user_type(user_type: CkUserType) -> Option<LoginState> {
    match user_type {
        CkUserType::So => Some(LoginState::So),
        CkUserType::User => Some(LoginState::User),
        CkUserType::ContextSpecific => None,
    }
}

fn already_logged_in_rv(current: LoginState, requested: LoginState) -> CkRv {
    if current == requested {
        CkRv::USER_ALREADY_LOGGED_IN
    } else {
        CkRv::USER_ANOTHER_ALREADY_LOGGED_IN
    }
}

/// Resolve a virtual session to its backend session, owning slot, and current
/// login state in a single context-locked read (shared by login/logout — M7).
/// Returns the CK_RV the caller should surface when the context is gone
/// (`CRYPTOKI_NOT_INITIALIZED`) or the session handle is unknown
/// (`SESSION_HANDLE_INVALID`).
async fn resolve_session_slot_login(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    session_handle: u64,
) -> Result<(CkSessionHandle, CkSlotId, Option<LoginState>), CkRv> {
    let resolved = ctx_mgr
        .get_context(ctx_id, |ctx| {
            let virtual_session = VirtualHandle(session_handle);
            let backend_session = ctx.session_handles.resolve(virtual_session);
            let slot = ctx.session_slots.get(&virtual_session).copied();
            let current_login_state = slot.and_then(|slot| ctx.login_state.get(&slot).copied());
            (backend_session, slot, current_login_state)
        })
        .await;

    match resolved {
        None => Err(CkRv::CRYPTOKI_NOT_INITIALIZED),
        Some((Some(backend_session), Some(slot), current_login_state)) => {
            Ok((CkSessionHandle(backend_session.0 as u64), slot, current_login_state))
        }
        Some(_) => Err(CkRv::SESSION_HANDLE_INVALID),
    }
}

pub(super) async fn login(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::LoginRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::LoginResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let user_type = match CkUserType::from_raw(req.user_type) {
        Some(user_type) => user_type,
        None => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse {
                ck_rv: CkRv::USER_TYPE_INVALID.0,
            }));
        }
    };
    let requested_login_state = login_state_for_user_type(user_type);

    let (session, slot, current_login_state) =
        match resolve_session_slot_login(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(resolved) => resolved,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse { ck_rv: rv.0 }));
            }
        };

    // Serialize login on this slot (M5): hold the per-slot lock across the
    // cross-context login-state scan, the backend C_Login, and the login_state
    // insert. Otherwise two clients racing the first login on the shared token
    // both see "no other login" and both take the real-login path, and the
    // second is answered USER_ALREADY_LOGGED_IN instead of the logical OK.
    let login_guard = ctx_mgr.slot_login_lock(slot);
    let _login_lock = login_guard.lock().await;

    // Wrap PIN bytes in `Zeroizing` so the backing buffer is overwritten when
    // dropped. Read it up-front and pre-hash it so the logical-login path can
    // validate the PIN and the verifier can be stored after the PIN is moved
    // into the backend call.
    let pin = req.pin.map(Zeroizing::new);
    let pin_hash = ctx_mgr.hash_pin(pin.as_deref().map(Vec::as_slice));

    if current_login_state.is_none()
        && let Some(requested) = requested_login_state
        && let Some(other_login_state) = ctx_mgr.first_login_state_for_slot_excluding(slot, &ctx_id)
    {
        if other_login_state == requested {
            // The shared backend token is already logged in (another logical
            // client holds this state), so a second backend C_Login would
            // answer USER_ALREADY_LOGGED_IN WITHOUT checking the PIN. Validate
            // against the verifier captured at the first successful login so a
            // wrong PIN is rejected rather than synthesized OK (A1; ADR-0008).
            match ctx_mgr.verify_pin_hash(slot, requested, &pin_hash) {
                Some(true) => {
                    let _ = ctx_mgr
                        .get_context(&ctx_id, |ctx| {
                            ctx.login_state.insert(slot, requested);
                        })
                        .await;
                    info!(
                        context_id = %ctx_id.0,
                        user_type = req.user_type,
                        "Login completed logically"
                    );
                    return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse {
                        ck_rv: CkRv::OK.0,
                    }));
                }
                Some(false) => {
                    warn!(
                        context_id = %ctx_id.0,
                        user_type = req.user_type,
                        "Logical login rejected: PIN does not match"
                    );
                    return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse {
                        ck_rv: CkRv::PIN_INCORRECT.0,
                    }));
                }
                // No verifier recorded (e.g. the original login used the
                // protected-auth path): cannot validate, so fall through to a
                // real backend login rather than synthesize an unvalidated OK.
                None => {}
            }
        } else {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse {
                ck_rv: already_logged_in_rv(other_login_state, requested).0,
            }));
        }
    }

    let user_type_raw = req.user_type;
    let backend = backend_ref.clone();
    let result =
        spawn_backend(move || backend.login(session, user_type, pin.as_deref().map(Vec::as_slice)))
            .await?;

    let ck_rv = match &result {
        Ok(()) => {
            if let Some(login_state) = requested_login_state {
                // Capture the verifier so co-located logical clients can be
                // PIN-validated (A1) without a second backend login.
                ctx_mgr.store_pin_verifier_hash(slot, login_state, pin_hash);
                let _ = ctx_mgr
                    .get_context(&ctx_id, |ctx| {
                        ctx.login_state.insert(slot, login_state);
                    })
                    .await;
            }
            info!(context_id = %ctx_id.0, user_type = user_type_raw, "Login succeeded");
            CkRv::OK.0
        }
        Err(error) => {
            warn!(context_id = %ctx_id.0, user_type = user_type_raw, rv = error.0, "Login failed");
            error.0
        }
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse { ck_rv }))
}

pub(super) async fn logout(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::LogoutRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::LogoutResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, slot, current_login_state) =
        match resolve_session_slot_login(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(resolved) => resolved,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::LogoutResponse { ck_rv: rv.0 }));
            }
        };

    // Serialize logout against concurrent login/logout on the same slot (M5),
    // so the cross-context scan and the login_state removal stay atomic.
    let login_guard = ctx_mgr.slot_login_lock(slot);
    let _login_lock = login_guard.lock().await;

    let other_login_state = ctx_mgr.first_login_state_for_slot_excluding(slot, &ctx_id);

    if current_login_state.is_none() && other_login_state.is_some() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::LogoutResponse {
            ck_rv: CkRv::USER_NOT_LOGGED_IN.0,
        }));
    }

    if current_login_state.is_some() && other_login_state.is_some() {
        let _ = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.login_state.remove(&slot);
            })
            .await;
        info!(context_id = %ctx_id.0, "Logout completed logically");
        return Ok(Response::new(pkcs11_proxy_ng_proto::LogoutResponse { ck_rv: CkRv::OK.0 }));
    }

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.logout(session)).await?;

    let ck_rv = match result {
        Ok(()) => {
            // Last holder logged out: the shared token is now logged out, so
            // drop the per-slot PIN verifier (a fresh login re-captures it).
            if let Some(state) = current_login_state {
                ctx_mgr.clear_pin_verifier(slot, state);
            }
            let _ = ctx_mgr
                .get_context(&ctx_id, |ctx| {
                    ctx.login_state.remove(&slot);
                })
                .await;
            info!(context_id = %ctx_id.0, "Logout succeeded");
            CkRv::OK.0
        }
        Err(error) => error.0,
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::LogoutResponse { ck_rv }))
}

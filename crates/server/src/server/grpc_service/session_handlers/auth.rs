use crate::server::slot_map::BackendSlotId;
use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{info, warn};
use zeroize::Zeroizing;

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::context_manager::{ClientContextId, ContextManager, LoginState};
use super::super::super::handle_map::VirtualHandle;
use super::super::service_utils::{login_lock_timeout, spawn_backend};

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
    //
    // Bounded acquisition (G2/V11): refuse rather than queue unboundedly when
    // a slow/wedged backend C_Login pins the lock. CKR_DEVICE_ERROR signals a
    // transient token-serialization failure the client can retry.
    let login_guard = ctx_mgr.slot_login_lock(slot);
    let _login_lock = match tokio::time::timeout(login_lock_timeout(), login_guard.lock()).await {
        Ok(guard) => guard,
        Err(_elapsed) => {
            // Another tenant holds the per-slot login lock past the configured
            // bound (slow/wedged backend login on the shared token). Refuse
            // rather than queue unboundedly; CKR_DEVICE_ERROR is a transient
            // token-serialization failure the client can retry.
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse {
                ck_rv: CkRv::DEVICE_ERROR.0,
            }));
        }
    };

    // G2-PR3: per-slot aggregate failed-login budget. Fast-reject during the
    // cooldown window without touching the backend — the proxy stops feeding
    // the backend's shared PIN-lockout counter. Inert (always false) when
    // `per_slot_failed_login_budget` is unset → byte-identical to today.
    // Indistinguishable from the lock-timeout DEVICE_ERROR above; the app
    // already handles transient DEVICE_ERROR as a retriable failure.
    if crate::server::rate_quota::login_slot_in_cooldown(slot) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse {
            ck_rv: CkRv::DEVICE_ERROR.0,
        }));
    }

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
            // G2-PR3: backend accepted the PIN → reset the slot's failure counter
            // so the budget window starts fresh on the next wrong-PIN attempt.
            crate::server::rate_quota::record_login_success(slot);
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
            // G2-PR3: count PIN-wrong RVs toward the per-slot aggregate budget.
            // PIN_LOCKED is the backend's own lockout — counting it would be
            // redundant. PIN_EXPIRED is not a wrong-PIN attempt. Other RVs
            // (SESSION_HANDLE_INVALID, DEVICE_ERROR, …) are not PIN failures.
            // The trip metric (login_budget_tripped_total) is recorded exactly
            // once per trip inside record_login_failure → record_failure_on.
            if *error == CkRv::PIN_INCORRECT
                || *error == CkRv::PIN_INVALID
                || *error == CkRv::PIN_LEN_RANGE
            {
                crate::server::rate_quota::record_login_failure(slot);
            }
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
    //
    // Bounded acquisition (G2/V11): same cross-tenant DoS bound as login.
    let login_guard = ctx_mgr.slot_login_lock(slot);
    let _login_lock = match tokio::time::timeout(login_lock_timeout(), login_guard.lock()).await {
        Ok(guard) => guard,
        Err(_elapsed) => {
            // Another tenant holds the per-slot login lock past the configured
            // bound (slow/wedged backend login on the shared token). Refuse
            // rather than queue unboundedly; CKR_DEVICE_ERROR is a transient
            // token-serialization failure the client can retry.
            return Ok(Response::new(pkcs11_proxy_ng_proto::LogoutResponse {
                ck_rv: CkRv::DEVICE_ERROR.0,
            }));
        }
    };

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
        // C1: per PKCS#11 §11.6, C_Logout invalidates the application's handles to
        // private objects. The coalescer must not serve cached attributes of those
        // handles after logout. Evicting the entire cache is conservative + correct;
        // over-invalidating public entries is only a performance miss, not a bug.
        ctx_mgr.attr_cache_clear(&ctx_id).await;
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
            // C1: per PKCS#11 §11.6, C_Logout invalidates the application's handles to
            // private objects. The coalescer must not serve cached attributes of those
            // handles after logout. Evicting the entire cache is conservative + correct;
            // over-invalidating public entries is only a performance miss, not a bug.
            ctx_mgr.attr_cache_clear(&ctx_id).await;
            info!(context_id = %ctx_id.0, "Logout succeeded");
            CkRv::OK.0
        }
        Err(error) => error.0,
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::LogoutResponse { ck_rv }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tonic::Request;

    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_types::*;

    use crate::server::context_manager::{CachedAttr, ClientContextId, ContextManager, LoginState};
    use crate::server::handle_map::BackendHandle;

    // Ensure the coalescer is on for C1 tests. The OnceLock is set once per
    // process; the first call wins — subsequent calls are no-ops.
    fn enable_coalesce() {
        crate::server::resilience::configure(None, true);
    }

    /// C1: a successful C_Logout must clear the calling context's attr_cache so
    /// the coalescer cannot serve cached private-object attributes after the token
    /// has been logged out (post-logout transparency divergence fix).
    #[tokio::test]
    async fn logout_clears_attr_cache_on_success() {
        enable_coalesce();
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();

        // Open a real backend session and log in so the mock accepts C_Logout.
        let backend_session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        mock.login(backend_session, CkUserType::User, None).unwrap();

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(CkSlotId(0)).await;
        let virtual_slot = ctx_mgr.to_virtual_slot(CkSlotId(0)).await.unwrap();
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        // Register the real backend session in the context and record logged-in state.
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                let vh = ctx.register_session(BackendHandle(backend_session.0), virtual_slot);
                ctx.login_state.insert(virtual_slot, LoginState::User);
                vh
            })
            .await
            .unwrap();

        // Pre-populate attr_cache to simulate a coalescer entry cached after login.
        ctx_mgr
            .attr_cache_put(
                &ctx_id,
                42,
                CkAttributeType::ID,
                CachedAttr { value: b"cached-id".to_vec(), ck_rv: CkRv::OK.0 },
            )
            .await;
        assert!(
            ctx_mgr.attr_cache_get(&ctx_id, 42, CkAttributeType::ID).await.is_some(),
            "attr_cache must be populated before logout"
        );

        // Call the real logout handler.
        let resp = super::logout(
            &ctx_mgr,
            &backend,
            Request::new(pkcs11_proxy_ng_proto::LogoutRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session_vh.0,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(resp.ck_rv, CkRv::OK.0, "logout must succeed");
        assert!(
            ctx_mgr.attr_cache_get(&ctx_id, 42, CkAttributeType::ID).await.is_none(),
            "attr_cache must be empty after C_Logout (C1 fix: post-logout transparency)"
        );
    }

    /// C1 logical path: a logical logout (another context still holds the token)
    /// must also clear the calling context's attr_cache.
    #[tokio::test]
    async fn logical_logout_clears_attr_cache() {
        enable_coalesce();
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();

        // Open a real backend session and log in.
        let backend_session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        mock.login(backend_session, CkUserType::User, None).unwrap();

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(CkSlotId(0)).await;
        let virtual_slot = ctx_mgr.to_virtual_slot(CkSlotId(0)).await.unwrap();

        // Two contexts on the same slot — ctx_a will attempt logout; ctx_b stays logged in,
        // forcing the logical-logout path (backend NOT called).
        let ctx_a = ctx_mgr.create_context(None).await.unwrap();
        let ctx_b = ctx_mgr.create_context(None).await.unwrap();

        let session_a_vh = ctx_mgr
            .get_context(&ctx_a, |ctx| {
                let vh = ctx.register_session(BackendHandle(backend_session.0), virtual_slot);
                ctx.login_state.insert(virtual_slot, LoginState::User);
                vh
            })
            .await
            .unwrap();

        // ctx_b is also logged in for the same slot (makes first_login_state_for_slot_excluding
        // return Some, so ctx_a's logout takes the logical path).
        ctx_mgr
            .get_context(&ctx_b, |ctx| {
                ctx.login_state.insert(virtual_slot, LoginState::User);
            })
            .await;

        // Pre-populate attr_cache for ctx_a.
        ctx_mgr
            .attr_cache_put(
                &ctx_a,
                7,
                CkAttributeType::LABEL,
                CachedAttr { value: b"my-label".to_vec(), ck_rv: CkRv::OK.0 },
            )
            .await;
        assert!(
            ctx_mgr.attr_cache_get(&ctx_a, 7, CkAttributeType::LABEL).await.is_some(),
            "attr_cache must be populated before logical logout"
        );

        // Logical logout for ctx_a (backend NOT called because ctx_b is still logged in).
        let resp = super::logout(
            &ctx_mgr,
            &backend,
            Request::new(pkcs11_proxy_ng_proto::LogoutRequest {
                client_context_id: ctx_a.0.clone(),
                session_handle: session_a_vh.0,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(resp.ck_rv, CkRv::OK.0, "logical logout must succeed");
        assert!(
            ctx_mgr.attr_cache_get(&ctx_a, 7, CkAttributeType::LABEL).await.is_none(),
            "attr_cache must be empty after logical C_Logout (C1 fix)"
        );

        // ctx_b's cache must be untouched.
        ctx_mgr
            .attr_cache_put(
                &ctx_b,
                7,
                CkAttributeType::LABEL,
                CachedAttr { value: b"other".to_vec(), ck_rv: CkRv::OK.0 },
            )
            .await;
        assert!(
            ctx_mgr.attr_cache_get(&ctx_b, 7, CkAttributeType::LABEL).await.is_some(),
            "ctx_b's attr_cache must be unaffected by ctx_a's logout"
        );
    }

    /// C1 negative: a failed logout must NOT clear the attr_cache.
    #[tokio::test]
    async fn failed_logout_does_not_clear_attr_cache() {
        enable_coalesce();
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();

        // Open a session but do NOT login — backend will return USER_NOT_LOGGED_IN.
        let backend_session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(CkSlotId(0)).await;
        let virtual_slot = ctx_mgr.to_virtual_slot(CkSlotId(0)).await.unwrap();
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        // Session not logged in from the ContextManager's perspective either.
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(BackendHandle(backend_session.0), virtual_slot)
            })
            .await
            .unwrap();

        // Pre-populate attr_cache.
        ctx_mgr
            .attr_cache_put(
                &ctx_id,
                5,
                CkAttributeType::TOKEN,
                CachedAttr { value: vec![0x01], ck_rv: CkRv::OK.0 },
            )
            .await;

        // Logout should fail with USER_NOT_LOGGED_IN (context not logged in).
        let resp = super::logout(
            &ctx_mgr,
            &backend,
            Request::new(pkcs11_proxy_ng_proto::LogoutRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session_vh.0,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(
            resp.ck_rv,
            CkRv::USER_NOT_LOGGED_IN.0,
            "logout with no login must return USER_NOT_LOGGED_IN"
        );
        // Cache must be intact — no successful logout occurred.
        assert!(
            ctx_mgr.attr_cache_get(&ctx_id, 5, CkAttributeType::TOKEN).await.is_some(),
            "attr_cache must be intact after a failed logout"
        );
    }

    /// Context-ID invariant: attr_cache_clear by ID is used in the
    /// ContextManager-level test (context_manager/tests.rs); this test
    /// validates that a non-existent ClientContextId is a silent no-op
    /// (matches the contract of all other get_context-based accessors).
    #[tokio::test]
    async fn attr_cache_clear_noop_for_missing_context() {
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        let gone = ClientContextId("nonexistent".into());
        ctx_mgr.attr_cache_clear(&gone).await; // must not panic
    }
}

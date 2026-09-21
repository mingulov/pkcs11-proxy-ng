use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{info, warn};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::context_manager::{ClientContextId, ContextManager, LoginState};
use super::super::service_utils::{
    acquire_slot_login_lock, resolve_session_slot_login, spawn_backend,
};

pub(crate) fn login_state_for_user_type(user_type: CkUserType) -> Option<LoginState> {
    match user_type {
        CkUserType::So => Some(LoginState::So),
        CkUserType::User => Some(LoginState::User),
        CkUserType::ContextSpecific => None,
    }
}

pub(crate) fn already_logged_in_rv(current: LoginState, requested: LoginState) -> CkRv {
    if current == requested {
        CkRv::USER_ALREADY_LOGGED_IN
    } else {
        CkRv::USER_ANOTHER_ALREADY_LOGGED_IN
    }
}

pub(super) async fn login(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::LoginRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::LoginResponse>, Status> {
    // W1-C8-11: `LoginRequest` is `ZeroizeOnDrop`; take owned fields out
    // with `mem::take` instead of moving them.
    let mut req = request.into_inner();
    let ctx_id = ClientContextId(std::mem::take(&mut req.client_context_id));

    let user_type = match CkUserType::from_raw(req.user_type) {
        Some(user_type) => user_type,
        None => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse {
                ck_rv: CkRv::USER_TYPE_INVALID.0,
            }));
        }
    };
    let requested_login_state = login_state_for_user_type(user_type);

    // Pre-resolve with transient contexts-DashMap guards (released before
    // locking) to discover the owning slot for lock selection. The handle and
    // login state from this read are NOT used: the authoritative resolve
    // happens under the slot lock below (W1-L6-25).
    let slot = match resolve_session_slot_login(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok((_, slot, _)) => slot,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse { ck_rv: rv.0 }));
        }
    };

    // Serialize login on this slot (M5): hold the per-slot lock across the
    // cross-context login-state scan, the backend C_Login, and the login_state
    // insert. Otherwise two clients racing the first login on the shared token
    // both see "no other login" and both take the real-login path, and the
    // second is answered USER_ALREADY_LOGGED_IN instead of the logical OK.
    let _login_lock = match acquire_slot_login_lock(ctx_mgr, slot).await {
        Ok(guard) => guard,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse { ck_rv: rv.0 }));
        }
    };

    // W1-L6-25: authoritative resolve UNDER the slot lock. Close takes the
    // same lock around suspend, so a session closed between the pre-resolve
    // and here now resolves to None — fail cleanly instead of driving the
    // backend with a stale handle.
    //
    // Lock ordering (Task 3 order, shared with login/logout/login_user/
    // close): per-slot login tokio Mutex OUTER; while holding it, take only
    // TRANSIENT contexts-DashMap guards. Never acquire the slot lock while
    // holding a contexts guard.
    let (session, current_login_state) =
        match resolve_session_slot_login(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok((session, resolved_slot, login_state)) if resolved_slot == slot => {
                (session, login_state)
            }
            Ok(_) => {
                // Slot rebound under a live virtual id: unreachable while vh
                // ids are monotonic, but fail closed — the held lock covers
                // the pre-resolved slot only.
                return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse {
                    ck_rv: CkRv::SESSION_HANDLE_INVALID.0,
                }));
            }
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse { ck_rv: rv.0 }));
            }
        };

    // G2-PR3: per-slot aggregate failed-login budget. Fast-reject during the
    // cooldown window without touching the backend — the proxy stops feeding
    // the backend's shared PIN-lockout counter. Inert (always false) when
    // `per_slot_failed_login_budget` is unset → byte-identical to today.
    // Caller-visible CKR_PIN_LOCKED (W1-L3-01): the proxy refuses to forward
    // further PIN attempts for now — the app must stop trying PINs, the same
    // action a backend lockout demands. Distinct from the GENERAL_ERROR
    // lock-timeout above.
    if crate::server::rate_quota::login_slot_in_cooldown(slot) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse {
            ck_rv: CkRv::PIN_LOCKED.0,
        }));
    }

    // Hold PIN bytes in `SecretBytes`: the backing buffer is overwritten
    // when dropped, and Debug redacts the secret (audit/log safety net).
    let pin = std::mem::take(&mut req.pin).map(SecretBytes::new);

    // W1-L13-11 + W1-L7-15 (one edit): same-context re-login
    // short-circuit. This context already holds a logical login on the
    // slot, so the shared backend token is logged in and a physical
    // C_Login could only answer ALREADY (without even checking the PIN)
    // — answer locally with no backend call. Context-specific logins
    // (requested `None`) never mint token state and always fall through
    // to the backend, as before.
    if let Some(current) = current_login_state
        && let Some(requested) = requested_login_state
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse {
            ck_rv: already_logged_in_rv(current, requested).0,
        }));
    }

    // D6(3) reconciliation (Wave 3.5 tenancy ruling; supersedes ADR-0008): when
    // another live context already holds a login on this slot, the shared
    // backend token is logged in and would answer a second backend C_Login
    // with USER_ALREADY_LOGGED_IN *without* checking the PIN. The daemon
    // therefore cannot PIN-verify this login against the token, so it returns
    // the backend's answer faithfully and mints NO logical login — never a
    // login on an unverified PIN. The caller retries after the holder releases
    // the slot (last-context-out backend logout, D6(2), bounds the window).
    if current_login_state.is_none()
        && let Some(requested) = requested_login_state
        && let Some(other_login_state) = ctx_mgr.first_login_state_for_slot_excluding(slot, &ctx_id)
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::LoginResponse {
            ck_rv: already_logged_in_rv(other_login_state, requested).0,
        }));
    }

    let user_type_raw = req.user_type;
    // A second wiping copy for a possible F-01 reconcile retry below; both
    // copies are wiped on drop.
    let pin_retry = pin.clone();
    let backend = backend_ref.clone();
    let result = spawn_backend(move || {
        // Transfer into a wiping owner for the FFI boundary; the moved
        // `SecretBytes` (and this transfer) are wiped on drop.
        let pin = pin.map(SecretBytes::into_zeroizing);
        backend.login(session, user_type, pin.as_deref().map(Vec::as_slice))
    })
    .await?;

    // F-01 reconcile-on-ALREADY: the backend answers ALREADY but — rechecked
    // under the already-held slot lock — NO live context holds this slot, so
    // the backend login is orphaned (a best-effort last-holder logout was
    // skipped or failed). Without this the slot bricks: every future login
    // gets ALREADY with no state minted, and no path ever logs out. Reconcile
    // with one backend logout through this session, then retry the login
    // exactly once so the PIN verifies against a logged-out token.
    let result = match result {
        Err(rv)
            if (rv == CkRv::USER_ALREADY_LOGGED_IN
                || rv == CkRv::USER_ANOTHER_ALREADY_LOGGED_IN)
                && !ctx_mgr.any_login_state_for_slot(slot) =>
        {
            warn!(
                context_id = %ctx_id.0,
                user_type = user_type_raw,
                "Login reconciling holderless-but-logged-in backend"
            );
            let backend = backend_ref.clone();
            if let Err(rv) = spawn_backend(move || backend.logout(session)).await? {
                warn!(
                    context_id = %ctx_id.0,
                    rv = rv.0,
                    "Login reconcile logout failed; retrying login once anyway"
                );
            }
            let backend = backend_ref.clone();
            spawn_backend(move || {
                let pin = pin_retry.map(SecretBytes::into_zeroizing);
                backend.login(session, user_type, pin.as_deref().map(Vec::as_slice))
            })
            .await?
        }
        other => other,
    };

    let ck_rv = match &result {
        Ok(()) => {
            // W1-L6-25 post-call generation verify, still under the slot
            // lock: lock-free mapping removers (close-all, eviction) may have
            // dropped/recycled the mapping mid-call. Mint nothing for a
            // handle we no longer track — the backend login landed, but no
            // LoginState may reference an untracked session.
            match resolve_session_slot_login(ctx_mgr, &ctx_id, req.session_handle).await {
                Ok((fresh_session, fresh_slot, _))
                    if fresh_session == session && fresh_slot == slot =>
                {
                    // G2-PR3: backend accepted the PIN → reset the slot's failure counter
                    // so the budget window starts fresh on the next wrong-PIN attempt.
                    crate::server::rate_quota::record_login_success(slot);
                    if let Some(login_state) = requested_login_state {
                        let inserted = ctx_mgr
                            .get_context(&ctx_id, |ctx| {
                                ctx.login_state.insert(slot, login_state);
                            })
                            .await
                            .is_some();
                        if inserted {
                            // W1-L13-17: sync the holder index with the mint.
                            ctx_mgr.note_login_acquired(&ctx_id, slot);
                        }
                    }
                    info!(context_id = %ctx_id.0, user_type = user_type_raw, "Login succeeded");
                    CkRv::OK.0
                }
                _ => CkRv::SESSION_HANDLE_INVALID.0,
            }
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

    // Pre-resolve with transient contexts-DashMap guards (released before
    // locking) to discover the owning slot for lock selection. The handle and
    // login state from this read are NOT used: the authoritative resolve
    // happens under the slot lock below (W1-L6-25).
    let slot = match resolve_session_slot_login(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok((_, slot, _)) => slot,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LogoutResponse { ck_rv: rv.0 }));
        }
    };

    // Serialize logout against concurrent login/logout on the same slot (M5),
    // so the cross-context scan and the login_state removal stay atomic.
    // Same cross-tenant DoS bound as login (shared acquisition helper).
    let _login_lock = match acquire_slot_login_lock(ctx_mgr, slot).await {
        Ok(guard) => guard,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LogoutResponse { ck_rv: rv.0 }));
        }
    };

    // W1-L6-25: authoritative resolve UNDER the slot lock, same as login.
    // Close takes the same lock around suspend, so a session closed between
    // the pre-resolve and here now resolves to None — fail cleanly instead
    // of driving the backend with a stale handle. (No post-call verify: this
    // path only REMOVES login state, never mints it.)
    //
    // Lock ordering (Task 3 order, shared with login/logout/login_user/
    // close): per-slot login tokio Mutex OUTER; while holding it, take only
    // TRANSIENT contexts-DashMap guards. Never acquire the slot lock while
    // holding a contexts guard.
    let (session, current_login_state) =
        match resolve_session_slot_login(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok((session, resolved_slot, login_state)) if resolved_slot == slot => {
                (session, login_state)
            }
            Ok(_) => {
                // Slot rebound under a live virtual id: unreachable while vh
                // ids are monotonic, but fail closed — the held lock covers
                // the pre-resolved slot only.
                return Ok(Response::new(pkcs11_proxy_ng_proto::LogoutResponse {
                    ck_rv: CkRv::SESSION_HANDLE_INVALID.0,
                }));
            }
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::LogoutResponse { ck_rv: rv.0 }));
            }
        };

    // W1-L13-17: logout needs the authoritative scan — a missed holder
    // here would take the backend path instead of the logical one.
    let other_login_state =
        ctx_mgr.first_login_state_for_slot_excluding_authoritative(slot, &ctx_id);

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
        // W1-L13-17: sync the holder index with the release.
        ctx_mgr.note_login_released(&ctx_id, slot);
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
            let _ = ctx_mgr
                .get_context(&ctx_id, |ctx| {
                    ctx.login_state.remove(&slot);
                })
                .await;
            // W1-L13-17: sync the holder index with the release.
            ctx_mgr.note_login_released(&ctx_id, slot);
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
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let backend_slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        // Register the real backend session in the context and record logged-in state.
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                let vh = ctx.register_session(BackendHandle(backend_session.0), backend_slot);
                ctx.login_state.insert(backend_slot, LoginState::User);
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
                CachedAttr { value: SecretBytes::new(b"cached-id".to_vec()), ck_rv: CkRv::OK.0 },
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
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let backend_slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));

        // Two contexts on the same slot — ctx_a will attempt logout; ctx_b stays logged in,
        // forcing the logical-logout path (backend NOT called).
        let ctx_a = ctx_mgr.create_context(None).await.unwrap();
        let ctx_b = ctx_mgr.create_context(None).await.unwrap();

        let session_a_vh = ctx_mgr
            .get_context(&ctx_a, |ctx| {
                let vh = ctx.register_session(BackendHandle(backend_session.0), backend_slot);
                ctx.login_state.insert(backend_slot, LoginState::User);
                vh
            })
            .await
            .unwrap();

        // ctx_b is also logged in for the same slot (makes first_login_state_for_slot_excluding
        // return Some, so ctx_a's logout takes the logical path).
        ctx_mgr
            .get_context(&ctx_b, |ctx| {
                ctx.login_state.insert(backend_slot, LoginState::User);
            })
            .await;

        // Pre-populate attr_cache for ctx_a.
        ctx_mgr
            .attr_cache_put(
                &ctx_a,
                7,
                CkAttributeType::LABEL,
                CachedAttr { value: SecretBytes::new(b"my-label".to_vec()), ck_rv: CkRv::OK.0 },
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
                CachedAttr { value: SecretBytes::new(b"other".to_vec()), ck_rv: CkRv::OK.0 },
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
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let backend_slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        // Session not logged in from the ContextManager's perspective either.
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(BackendHandle(backend_session.0), backend_slot)
            })
            .await
            .unwrap();

        // Pre-populate attr_cache.
        ctx_mgr
            .attr_cache_put(
                &ctx_id,
                5,
                CkAttributeType::TOKEN,
                CachedAttr { value: SecretBytes::new(vec![0x01]), ck_rv: CkRv::OK.0 },
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

    /// The login handler's PIN holder must redact secrets in Debug: any
    /// future log line capturing the holder (or its container) must not
    /// leak PIN bytes. Mirrors the holder construction in `login`.
    ///
    /// NOTE: `Vec<u8>` renders in Debug as decimal byte values (`[83,
    /// 117, ...]`), never as a string — so the assertion scans for every
    /// PIN byte's decimal rendering, not the PIN text.
    #[test]
    fn pin_holder_debug_redacts_secret() {
        let pin_bytes = b"SuperSecretPIN!42";
        let pin = Some(SecretBytes::new(pin_bytes.to_vec()));
        let rendered = format!("{pin:?}");
        for byte in pin_bytes {
            assert!(
                !rendered.contains(&byte.to_string()),
                "PIN holder leaks secret byte {byte} via Debug: {rendered}"
            );
        }
    }

    /// W1-L11-07 characterization: login and logout must refuse identically
    /// (W1-L3-01: CKR_GENERAL_ERROR, was CKR_DEVICE_ERROR) when the per-slot
    /// lock is held past the bound. Paused time fast-forwards the
    /// (seconds-long) acquisition timeout.
    #[tokio::test]
    async fn t7_login_and_logout_refuse_general_error_when_slot_lock_held() {
        tokio::time::pause();
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let backend_session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let backend_slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(BackendHandle(backend_session.0), backend_slot)
            })
            .await
            .unwrap();

        // Wedge the per-slot login lock; both handlers must time out on it.
        let slot_lock = ctx_mgr.slot_login_lock(backend_slot);
        let _held = slot_lock.lock().await;

        let login_rv = super::login(
            &ctx_mgr,
            &backend,
            Request::new(pkcs11_proxy_ng_proto::LoginRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session_vh.0,
                user_type: CkUserType::User as u64,
                pin: None,
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
        assert_eq!(login_rv, CkRv::GENERAL_ERROR.0, "login must refuse with GENERAL_ERROR");

        let logout_rv = super::logout(
            &ctx_mgr,
            &backend,
            Request::new(pkcs11_proxy_ng_proto::LogoutRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session_vh.0,
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
        assert_eq!(logout_rv, CkRv::GENERAL_ERROR.0, "logout must refuse with GENERAL_ERROR");
    }

    /// W1-L13-11 + W1-L7-15 (one edit): a same-context re-login must
    /// short-circuit locally with ALREADY and issue NO backend C_Login.
    /// The backend is reset to logged-out between the calls, so only the
    /// short-circuit can answer ALREADY — a backend round-trip would
    /// succeed with OK instead.
    #[tokio::test]
    async fn l13_11_same_context_relogin_short_circuits_without_backend_call() {
        let slot = CkSlotId(41);
        let mock = Arc::new(MockBackend::new(vec![slot], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let backend_session = mock.open_session(slot, CkSessionFlags::default()).unwrap();

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(slot)).await;
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(slot),
                )
            })
            .await
            .unwrap();

        let login_req = || pkcs11_proxy_ng_proto::LoginRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session_vh.0,
            user_type: CkUserType::User as u64,
            pin: None,
        };
        let first =
            super::login(&ctx_mgr, &backend, Request::new(login_req())).await.unwrap().into_inner();
        assert_eq!(first.ck_rv, CkRv::OK.0, "first login must succeed");
        assert_eq!(mock.login_call_count(), 1);

        // Reset the BACKEND to logged-out; the logical login stays held.
        mock.logout(backend_session).unwrap();

        let second =
            super::login(&ctx_mgr, &backend, Request::new(login_req())).await.unwrap().into_inner();
        assert_eq!(
            second.ck_rv,
            CkRv::USER_ALREADY_LOGGED_IN.0,
            "same-context re-login must answer ALREADY locally"
        );
        assert_eq!(mock.login_call_count(), 1, "re-login must not issue a backend C_Login");
        // The backend is still logged out — no call reached it.
        assert_eq!(mock.logout(backend_session).unwrap_err(), CkRv::USER_NOT_LOGGED_IN);
    }

    /// W1-L7-15: same-context re-login for the OTHER user type answers
    /// USER_ANOTHER_ALREADY_LOGGED_IN locally (the backend would only
    /// ever answer the same-type ALREADY here).
    #[tokio::test]
    async fn l7_15_same_context_other_user_type_answers_another_already() {
        let slot = CkSlotId(42);
        let mock = Arc::new(MockBackend::new(vec![slot], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let backend_session = mock.open_session(slot, CkSessionFlags::default()).unwrap();

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(slot)).await;
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(slot),
                )
            })
            .await
            .unwrap();

        let login_as = |user_type: CkUserType| pkcs11_proxy_ng_proto::LoginRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session_vh.0,
            user_type: user_type as u64,
            pin: None,
        };
        let first = super::login(&ctx_mgr, &backend, Request::new(login_as(CkUserType::User)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(first.ck_rv, CkRv::OK.0, "first login must succeed");

        let second = super::login(&ctx_mgr, &backend, Request::new(login_as(CkUserType::So)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            second.ck_rv,
            CkRv::USER_ANOTHER_ALREADY_LOGGED_IN.0,
            "other-type re-login must answer ANOTHER locally"
        );
        assert_eq!(
            mock.login_call_count(),
            1,
            "other-type re-login must not issue a backend C_Login"
        );
    }

    /// Pin: context-specific logins never mint token state, so they must
    /// keep reaching the backend even when this context holds a login.
    #[tokio::test]
    async fn l13_11_context_specific_relogin_still_reaches_backend() {
        let slot = CkSlotId(43);
        let mock = Arc::new(MockBackend::new(vec![slot], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let backend_session = mock.open_session(slot, CkSessionFlags::default()).unwrap();

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(slot)).await;
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(slot),
                )
            })
            .await
            .unwrap();

        let login_as = |user_type: CkUserType| pkcs11_proxy_ng_proto::LoginRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session_vh.0,
            user_type: user_type as u64,
            pin: None,
        };
        let first = super::login(&ctx_mgr, &backend, Request::new(login_as(CkUserType::User)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(first.ck_rv, CkRv::OK.0, "first login must succeed");
        let before = mock.login_call_count();

        let second =
            super::login(&ctx_mgr, &backend, Request::new(login_as(CkUserType::ContextSpecific)))
                .await
                .unwrap()
                .into_inner();
        // The mock token is logged in, so the backend answers ALREADY —
        // the point is the backend WAS reached (no short-circuit).
        assert_eq!(second.ck_rv, CkRv::USER_ALREADY_LOGGED_IN.0);
        assert_eq!(
            mock.login_call_count(),
            before + 1,
            "context-specific login must still reach the backend"
        );
    }
}

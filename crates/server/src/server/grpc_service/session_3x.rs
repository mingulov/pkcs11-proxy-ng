//! Handlers for PKCS#11 3.0/3.2 session extension RPCs (Wave 1).
//!
//! Replaces the stub handlers from `pkcs11_3x_stubs.rs` for:
//! - `C_LoginUser`
//! - `C_SessionCancel`
//! - `C_GetSessionValidationFlags`

use std::time::Duration;

use tonic::{Request, Response, Status};
use tracing::{info, warn};

use pkcs11_proxy_ng_types::*;

use super::super::context_manager::{ClientContextId, MessageOperation};
use super::super::handle_map::VirtualHandle;
use super::service_utils::{
    login_lock_timeout, resolve_session, spawn_backend, spawn_backend_with_optional_timeout,
};

use crate::server::grpc_service::HandlerContext;

const CKF_MESSAGE_ENCRYPT: u64 = 0x0000_0002;
const CKF_MESSAGE_DECRYPT: u64 = 0x0000_0004;
const CKF_MESSAGE_SIGN: u64 = 0x0000_0008;
const CKF_MESSAGE_VERIFY: u64 = 0x0000_0010;

fn cancelled_message_operations(flags: u64) -> Vec<MessageOperation> {
    [
        (CKF_MESSAGE_ENCRYPT, MessageOperation::Encrypt),
        (CKF_MESSAGE_DECRYPT, MessageOperation::Decrypt),
        (CKF_MESSAGE_SIGN, MessageOperation::Sign),
        (CKF_MESSAGE_VERIFY, MessageOperation::Verify),
    ]
    .into_iter()
    .filter_map(|(flag, operation)| (flags & flag != 0).then_some(operation))
    .collect()
}

pub(super) async fn login_user(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::LoginUserRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::LoginUserResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // Gate order mirrors `session::auth::login` exactly (W1-C1-02, W1-L7-01):
    // user-type → pre-resolve → slot lock → re-resolve → cooldown → D6(3) →
    // call → post-call verify → record/mint. Keep the two paths in sync.

    let user_type = match CkUserType::from_raw(req.user_type) {
        Some(user_type) => user_type,
        None => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse {
                ck_rv: CkRv::USER_TYPE_INVALID.0,
            }));
        }
    };
    let requested_login_state = super::session::auth::login_state_for_user_type(user_type);

    // Pre-resolve with transient contexts-DashMap guards (released before
    // locking) to discover the owning slot for lock selection. The handle and
    // login state from this read are NOT used: the authoritative resolve
    // happens under the slot lock below (W1-L6-25).
    let slot = match super::session::auth::resolve_session_slot_login(
        ctx_mgr,
        &ctx_id,
        req.session_handle,
    )
    .await
    {
        Ok((_, slot, _)) => slot,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse { ck_rv: rv.0 }));
        }
    };

    // Serialize login_user on this slot (M5), same as `C_Login`: hold the
    // per-slot lock across the cross-context login-state scan, the backend
    // C_LoginUser, and the login_state insert, so two clients racing the
    // first login cannot both take the real-login path.
    //
    // Lock ordering (shared with login/logout — Task 6 must match): acquire
    // the per-slot login tokio Mutex; while holding it, take only TRANSIENT
    // contexts-DashMap guards (cross-context scan, login_state insert).
    // Never acquire the slot lock while holding a contexts guard.
    //
    // Bounded acquisition (G2/V11): refuse with CKR_DEVICE_ERROR rather than
    // queue unboundedly when a slow/wedged backend pins the lock.
    let login_guard = ctx_mgr.slot_login_lock(slot);
    let _login_lock = match tokio::time::timeout(login_lock_timeout(), login_guard.lock()).await {
        Ok(guard) => guard,
        Err(_elapsed) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse {
                ck_rv: CkRv::DEVICE_ERROR.0,
            }));
        }
    };

    // W1-L6-25: authoritative resolve UNDER the slot lock, same as `C_Login`.
    // Close takes the same lock around suspend, so a session closed between
    // the pre-resolve and here now resolves to None — fail cleanly instead
    // of driving the backend with a stale handle.
    let (session, current_login_state) = match super::session::auth::resolve_session_slot_login(
        ctx_mgr,
        &ctx_id,
        req.session_handle,
    )
    .await
    {
        Ok((session, resolved_slot, login_state)) if resolved_slot == slot => {
            (session, login_state)
        }
        Ok(_) => {
            // Slot rebound under a live virtual id: unreachable while vh
            // ids are monotonic, but fail closed — the held lock covers
            // the pre-resolved slot only.
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse {
                ck_rv: CkRv::SESSION_HANDLE_INVALID.0,
            }));
        }
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse { ck_rv: rv.0 }));
        }
    };

    // G2-PR3: per-slot aggregate failed-login budget. Fast-reject during the
    // cooldown window without touching the backend (same DEVICE_ERROR as
    // `C_Login`, indistinguishable from the lock-timeout above).
    if crate::server::rate_quota::login_slot_in_cooldown(slot) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse {
            ck_rv: CkRv::DEVICE_ERROR.0,
        }));
    }

    // D6(3) reconciliation, same as `C_Login`: when another live context
    // already holds a login on this slot, the shared backend token is logged
    // in and would answer a second backend login with USER_ALREADY_LOGGED_IN
    // *without* checking the PIN — so return the backend's answer faithfully
    // and mint NO logical login, never a login on an unverified PIN.
    if current_login_state.is_none()
        && let Some(requested) = requested_login_state
        && let Some(other_login_state) = ctx_mgr.first_login_state_for_slot_excluding(slot, &ctx_id)
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse {
            ck_rv: super::session::auth::already_logged_in_rv(other_login_state, requested).0,
        }));
    }

    let user_type_raw = req.user_type;
    // Hold the PIN and username in `SecretBytes`: wiped on drop and redacted
    // in Debug. DO NOT log pin or username at any tracing level.
    // (build.rs flags LoginUserRequest.username secret-bearing.)
    let pin = SecretBytes::new(req.pin);
    let username = SecretBytes::new(req.username);
    let backend = backend_ref.clone();
    let result = spawn_backend(move || {
        let pin = pin.into_zeroizing();
        let username = username.into_zeroizing();
        backend.login_user(session, user_type, &username, &pin)
    })
    .await?;

    let ck_rv = match &result {
        Ok(()) => {
            // W1-L6-25 post-call generation verify, still under the slot
            // lock, same as `C_Login`: lock-free mapping removers (close-all,
            // eviction) may have dropped/recycled the mapping mid-call. Mint
            // nothing for a handle we no longer track.
            match super::session::auth::resolve_session_slot_login(
                ctx_mgr,
                &ctx_id,
                req.session_handle,
            )
            .await
            {
                Ok((fresh_session, fresh_slot, _))
                    if fresh_session == session && fresh_slot == slot =>
                {
                    // G2-PR3: backend accepted the PIN → reset the slot's failure
                    // counter so the budget window starts fresh.
                    crate::server::rate_quota::record_login_success(slot);
                    if let Some(login_state) = requested_login_state {
                        let _ = ctx_mgr
                            .get_context(&ctx_id, |ctx| {
                                ctx.login_state.insert(slot, login_state);
                            })
                            .await;
                    }
                    info!(context_id = %ctx_id.0, user_type = user_type_raw, "LoginUser succeeded");
                    CkRv::OK.0
                }
                _ => CkRv::SESSION_HANDLE_INVALID.0,
            }
        }
        Err(error) => {
            warn!(context_id = %ctx_id.0, user_type = user_type_raw, rv = error.0, "LoginUser failed");
            // G2-PR3: count PIN-wrong RVs toward the per-slot aggregate
            // budget — the same RV set as `C_Login`.
            if *error == CkRv::PIN_INCORRECT
                || *error == CkRv::PIN_INVALID
                || *error == CkRv::PIN_LEN_RANGE
            {
                crate::server::rate_quota::record_login_failure(slot);
            }
            error.0
        }
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse { ck_rv }))
}

pub(super) async fn session_cancel(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SessionCancelRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SessionCancelResponse>, Status> {
    session_cancel_with_timeout(ctx, request, None).await
}

async fn session_cancel_with_timeout(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SessionCancelRequest>,
    timeout_override: Option<Duration>,
) -> Result<Response<pkcs11_proxy_ng_proto::SessionCancelResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
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

    let flags = CkFlags(req.flags as u64);
    let operations = cancelled_message_operations(flags.0);
    let mut transitions = match ctx_mgr
        .begin_message_operation_transitions(
            &ctx_id,
            VirtualHandle(req.session_handle),
            &operations,
        )
        .await
    {
        Ok(transitions) => transitions,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SessionCancelResponse {
                ck_rv: error.0,
            }));
        }
    };
    let backend = backend_ref.clone();
    let result = spawn_backend_with_optional_timeout(timeout_override, move || {
        for transition in &mut transitions {
            transition.mark_started();
        }
        let result = backend.session_cancel(session, flags);
        for transition in &mut transitions {
            transition.settle(&result, None);
        }
        result
    })
    .await?;

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
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetSessionValidationFlagsRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetSessionValidationFlagsResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend, mock::MockMessageLifecycleAction};
    use pkcs11_proxy_ng_proto::convert::message_params::MessageParameterShape;

    use crate::server::context_manager::ContextManager;
    use crate::server::handle_map::BackendHandle;

    async fn setup_message_shapes() -> (
        Arc<ContextManager>,
        Arc<MockBackend>,
        Arc<dyn Pkcs11Backend>,
        ClientContextId,
        VirtualHandle,
    ) {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(1)], vec![]));
        mock.initialize().unwrap();
        let backend_session = mock.open_session(CkSlotId(1), CkSessionFlags::default()).unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(1)),
                )
            })
            .await
            .unwrap();
        for operation in [
            MessageOperation::Encrypt,
            MessageOperation::Decrypt,
            MessageOperation::Sign,
            MessageOperation::Verify,
        ] {
            ctx_mgr
                .message_operation_lock(&ctx_id, virtual_session, operation)
                .await
                .unwrap()
                .lock()
                .await
                .shape = Some(MessageParameterShape::Unmodeled);
        }
        (ctx_mgr, mock, backend, ctx_id, virtual_session)
    }

    async fn message_shapes(
        ctx_mgr: &ContextManager,
        ctx_id: &ClientContextId,
        session: VirtualHandle,
    ) -> Vec<Option<MessageParameterShape>> {
        let mut shapes = Vec::new();
        for operation in [
            MessageOperation::Encrypt,
            MessageOperation::Decrypt,
            MessageOperation::Sign,
            MessageOperation::Verify,
        ] {
            shapes.push(
                ctx_mgr
                    .message_operation_lock(ctx_id, session, operation)
                    .await
                    .unwrap()
                    .lock()
                    .await
                    .shape,
            );
        }
        shapes
    }

    #[test]
    fn cancel_operation_selection_is_fixed_order_and_bit_selective() {
        assert!(cancelled_message_operations(0).is_empty());
        assert_eq!(
            cancelled_message_operations(CKF_MESSAGE_VERIFY | CKF_MESSAGE_ENCRYPT),
            vec![MessageOperation::Encrypt, MessageOperation::Verify],
        );
        assert_eq!(
            cancelled_message_operations(
                CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_DECRYPT | CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY,
            ),
            vec![
                MessageOperation::Encrypt,
                MessageOperation::Decrypt,
                MessageOperation::Sign,
                MessageOperation::Verify,
            ],
        );
    }

    #[tokio::test]
    async fn successful_cancel_clears_only_selected_server_shapes() {
        let (ctx_mgr, mock, backend, ctx_id, virtual_session) = setup_message_shapes().await;
        let handler = HandlerContext::for_test(&ctx_mgr, &backend);

        let calls_before = mock.message_lifecycle_call_count();
        let zero = session_cancel(
            &handler,
            Request::new(pkcs11_proxy_ng_proto::SessionCancelRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: virtual_session.0,
                flags: 0,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(zero.ck_rv, CkRv::OK.0);
        assert_eq!(mock.message_lifecycle_call_count(), calls_before + 1);
        assert_eq!(
            message_shapes(&ctx_mgr, &ctx_id, virtual_session).await,
            vec![Some(MessageParameterShape::Unmodeled); 4],
        );

        let selected = session_cancel(
            &handler,
            Request::new(pkcs11_proxy_ng_proto::SessionCancelRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: virtual_session.0,
                flags: CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_SIGN,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(selected.ck_rv, CkRv::OK.0);
        assert_eq!(mock.message_lifecycle_call_count(), calls_before + 2);
        assert_eq!(
            message_shapes(&ctx_mgr, &ctx_id, virtual_session).await,
            vec![
                None,
                Some(MessageParameterShape::Unmodeled),
                None,
                Some(MessageParameterShape::Unmodeled),
            ],
        );
    }

    #[tokio::test]
    async fn cancel_outcomes_settle_only_selected_server_shapes() {
        for (action, timeout, expected_rv, selected_shape) in [
            (
                MockMessageLifecycleAction::Return(CkRv::FUNCTION_FAILED),
                None,
                Some(CkRv::FUNCTION_FAILED),
                Some(MessageParameterShape::Unmodeled),
            ),
            (
                MockMessageLifecycleAction::Return(CkRv::DEVICE_ERROR),
                None,
                Some(CkRv::DEVICE_ERROR),
                None,
            ),
            (
                MockMessageLifecycleAction::Delay(std::time::Duration::from_millis(60), CkRv::OK),
                Some(std::time::Duration::from_millis(5)),
                Some(CkRv::DEVICE_ERROR),
                None,
            ),
            (
                MockMessageLifecycleAction::Delay(
                    std::time::Duration::from_millis(60),
                    CkRv::FUNCTION_FAILED,
                ),
                Some(std::time::Duration::from_millis(5)),
                Some(CkRv::DEVICE_ERROR),
                Some(MessageParameterShape::Unmodeled),
            ),
            (MockMessageLifecycleAction::Panic, None, None, None),
        ] {
            let (ctx_mgr, mock, backend, ctx_id, virtual_session) = setup_message_shapes().await;
            let handler = HandlerContext::for_test(&ctx_mgr, &backend);
            let calls_before = mock.message_lifecycle_call_count();
            mock.set_next_message_lifecycle_action(action);
            let response = session_cancel_with_timeout(
                &handler,
                Request::new(pkcs11_proxy_ng_proto::SessionCancelRequest {
                    client_context_id: ctx_id.0.clone(),
                    session_handle: virtual_session.0,
                    flags: CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_SIGN,
                }),
                timeout,
            )
            .await;
            match expected_rv {
                Some(expected) => {
                    assert_eq!(response.unwrap().into_inner().ck_rv, expected.0, "{action:?}",)
                }
                None => assert!(response.is_err(), "panic must be a transport error"),
            }
            let shapes = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                message_shapes(&ctx_mgr, &ctx_id, virtual_session),
            )
            .await
            .expect("provider transition must settle");
            assert_eq!(
                shapes,
                vec![
                    selected_shape,
                    Some(MessageParameterShape::Unmodeled),
                    selected_shape,
                    Some(MessageParameterShape::Unmodeled),
                ],
                "{action:?}",
            );
            assert_eq!(mock.message_lifecycle_call_count(), calls_before + 1);
        }
    }

    /// `login_user` must not leak the PIN or username into audit logs
    /// (both holders are `SecretBytes`, and the handler logs only IDs and
    /// RVs). Uses a wrong PIN so the mock takes the failure path; both
    /// paths share the same holder and logging code.
    #[tokio::test]
    async fn login_user_produces_audit_log_without_secrets() {
        let (ctx_mgr, _mock, backend, ctx_id, virtual_session) = setup_message_shapes().await;
        let pin = b"WrongPin!999".to_vec();
        let username = b"operator-7".to_vec();

        let output = super::super::session::tests::capture_logs(|| async {
            let _ = login_user(
                &HandlerContext::for_test(&ctx_mgr, &backend),
                Request::new(pkcs11_proxy_ng_proto::LoginUserRequest {
                    client_context_id: ctx_id.0.clone(),
                    session_handle: virtual_session.0,
                    user_type: 1,
                    pin: pin.clone(),
                    username: username.clone(),
                }),
            )
            .await;
        })
        .await;

        assert!(
            output.contains("LoginUser succeeded") || output.contains("LoginUser failed"),
            "login_user audit output missing expected event: {output:?}"
        );
        assert!(!output.contains("WrongPin"), "PIN must never appear in log output: {output}");
        assert!(
            !output.contains("operator-7"),
            "username must never appear in log output: {output}"
        );
    }

    /// Set up two client contexts sharing one backend slot, each with one
    /// registered virtual session. Returns the context manager, mock,
    /// backend trait object, both context ids, both virtual sessions, and
    /// the shared slot id.
    async fn setup_login_user() -> (
        Arc<ContextManager>,
        Arc<MockBackend>,
        Arc<dyn Pkcs11Backend>,
        ClientContextId,
        ClientContextId,
        VirtualHandle,
        VirtualHandle,
        crate::server::slot_map::BackendSlotId,
    ) {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(1)], vec![]));
        mock.initialize().unwrap();
        let backend_session_a = mock.open_session(CkSlotId(1), CkSessionFlags::default()).unwrap();
        let backend_session_b = mock.open_session(CkSlotId(1), CkSessionFlags::default()).unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        let slot = crate::server::slot_map::BackendSlotId(CkSlotId(1));
        let ctx_a = ctx_mgr.create_context(None).await.unwrap();
        let ctx_b = ctx_mgr.create_context(None).await.unwrap();
        let session_a = ctx_mgr
            .get_context(&ctx_a, |ctx| {
                ctx.register_session(BackendHandle(backend_session_a.0), slot)
            })
            .await
            .unwrap();
        let session_b = ctx_mgr
            .get_context(&ctx_b, |ctx| {
                ctx.register_session(BackendHandle(backend_session_b.0), slot)
            })
            .await
            .unwrap();
        (ctx_mgr, mock, backend, ctx_a, ctx_b, session_a, session_b, slot)
    }

    fn login_user_request(
        ctx_id: &ClientContextId,
        session: VirtualHandle,
        user_type: u64,
        pin: &[u8],
    ) -> Request<pkcs11_proxy_ng_proto::LoginUserRequest> {
        Request::new(pkcs11_proxy_ng_proto::LoginUserRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session.0,
            user_type,
            pin: pin.to_vec(),
            username: b"operator".to_vec(),
        })
    }

    async fn login_user_rv(
        ctx_mgr: &Arc<ContextManager>,
        backend: &Arc<dyn Pkcs11Backend>,
        ctx_id: &ClientContextId,
        session: VirtualHandle,
        user_type: u64,
        pin: &[u8],
    ) -> u64 {
        login_user(
            &HandlerContext::for_test(ctx_mgr, backend),
            login_user_request(ctx_id, session, user_type, pin),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv
    }

    /// W1-C1-02: a successful `C_LoginUser` must mint `LoginState` exactly
    /// like `C_Login` does (User → User, SO → SO, ContextSpecific → none).
    #[tokio::test]
    async fn login_user_mints_login_state_per_user_type() {
        for (user_type, expected) in [
            (CkUserType::User, Some(crate::server::context_manager::LoginState::User)),
            (CkUserType::So, Some(crate::server::context_manager::LoginState::So)),
            (CkUserType::ContextSpecific, None),
        ] {
            let (ctx_mgr, _mock, backend, ctx_a, _ctx_b, session_a, _session_b, slot) =
                setup_login_user().await;
            let rv =
                login_user_rv(&ctx_mgr, &backend, &ctx_a, session_a, user_type as u64, b"1234")
                    .await;
            assert_eq!(rv, CkRv::OK.0, "login_user({user_type:?}) must succeed");
            let minted = ctx_mgr
                .get_context(&ctx_a, |ctx| ctx.login_state.get(&slot).copied())
                .await
                .unwrap();
            assert_eq!(
                minted, expected,
                "login_user({user_type:?}) must mint {expected:?} (W1-C1-02)"
            );
        }
    }

    /// W1-C1-02 (D6(3)): when another live context already holds a login on
    /// the slot, `C_LoginUser` must return the backend's ALREADY answer
    /// faithfully and mint NO logical login — without touching the backend
    /// (the token would answer ALREADY without checking the PIN).
    #[tokio::test]
    async fn login_user_second_context_gets_faithful_already() {
        let (ctx_mgr, mock, backend, ctx_a, ctx_b, session_a, session_b, slot) =
            setup_login_user().await;
        let rv_a =
            login_user_rv(&ctx_mgr, &backend, &ctx_a, session_a, CkUserType::User as u64, b"1234")
                .await;
        assert_eq!(rv_a, CkRv::OK.0, "first login_user must succeed");
        assert_eq!(mock.login_user_call_count(), 1, "first login must reach the backend once");

        let rv_b =
            login_user_rv(&ctx_mgr, &backend, &ctx_b, session_b, CkUserType::User as u64, b"1234")
                .await;
        assert_eq!(
            rv_b,
            CkRv::USER_ALREADY_LOGGED_IN.0,
            "second-context login_user must be a faithful ALREADY (D6(3)), not a minted login"
        );
        assert_eq!(mock.login_user_call_count(), 1, "D6(3) refusal must not reach the backend");
        let b_state =
            ctx_mgr.get_context(&ctx_b, |ctx| ctx.login_state.get(&slot).copied()).await.unwrap();
        assert_eq!(b_state, None, "D6(3) refusal must mint no LoginState");
    }

    /// W1-C1-02 (M5): two clients racing the FIRST `C_LoginUser` on the same
    /// shared token must not both take the real-login path. Mirrors
    /// `concurrent_first_login_serializes_to_one_backend_login`: the first
    /// does the real backend login and the second — after blocking on the
    /// per-slot lock and seeing A's state — takes the faithful-ALREADY path.
    /// Exactly one backend `C_LoginUser`.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_first_login_user_serializes_to_one_backend_login() {
        let (ctx_mgr, mock, backend, ctx_a, ctx_b, session_a, session_b, _slot) =
            setup_login_user().await;

        // Gate: each real backend login_user signals `entered`, then blocks.
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let proceed = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        mock.set_login_user_gate(entered_tx, proceed.clone());

        // Client A starts and blocks inside the real backend login_user (still
        // holding the per-slot login lock).
        let a = {
            let (ctx_mgr, backend) = (ctx_mgr.clone(), backend.clone());
            let req = login_user_request(&ctx_a, session_a, CkUserType::User as u64, b"1234");
            tokio::spawn(async move {
                login_user(&HandlerContext::for_test(&ctx_mgr, &backend), req)
                    .await
                    .unwrap()
                    .into_inner()
                    .ck_rv
            })
        };
        // Wait (off the executor) until A is actually inside the backend call.
        tokio::task::spawn_blocking(move || entered_rx.recv().unwrap()).await.unwrap();

        // Client B now races: with serialization it must block on the lock.
        let b = {
            let (ctx_mgr, backend) = (ctx_mgr.clone(), backend.clone());
            let req = login_user_request(&ctx_b, session_b, CkUserType::User as u64, b"1234");
            tokio::spawn(async move {
                login_user(&HandlerContext::for_test(&ctx_mgr, &backend), req)
                    .await
                    .unwrap()
                    .into_inner()
                    .ck_rv
            })
        };

        // Release A; it finishes the real login, mints its login state, and
        // drops the lock; B then sees A's login state and answers ALREADY.
        {
            let (lock, cv) = &*proceed;
            *lock.lock().unwrap() = true;
            cv.notify_all();
        }

        let rv_a = a.await.unwrap();
        let rv_b = b.await.unwrap();

        assert_eq!(rv_a, CkRv::OK.0, "the first login_user should succeed");
        assert_eq!(
            rv_b,
            CkRv::USER_ALREADY_LOGGED_IN.0,
            "the raced second login_user must be a faithful ALREADY (D6(3))"
        );
        assert_eq!(
            mock.login_user_call_count(),
            1,
            "per-slot serialization must yield exactly one real backend C_LoginUser"
        );
    }

    /// Sibling parity: like `C_Login`, `C_LoginUser` validates the user type
    /// BEFORE resolving the session, so an invalid user type wins over an
    /// unknown session handle.
    #[tokio::test]
    async fn login_user_rejects_invalid_user_type_before_resolve() {
        let (ctx_mgr, _mock, backend, ctx_a, _ctx_b, _session_a, _session_b, _slot) =
            setup_login_user().await;
        let rv = login_user_rv(&ctx_mgr, &backend, &ctx_a, VirtualHandle(9999), 999, b"1234").await;
        assert_eq!(
            rv,
            CkRv::USER_TYPE_INVALID.0,
            "invalid user type must precede session resolution (sibling parity)"
        );
    }

    /// The `login_user` handler's PIN/username holders must redact secrets
    /// in Debug (build.rs flags the username secret-bearing; the handler
    /// must never log either). Mirrors the holder construction in
    /// `login_user`. Byte-wise assertion: `Vec<u8>` Debug renders decimal
    /// byte values, never the original text.
    #[test]
    fn login_user_holders_debug_redact_secrets() {
        let pin_bytes = b"SuperSecretPIN!42";
        let user_bytes = b"secret-operator-7";
        let pin = SecretBytes::new(pin_bytes.to_vec());
        let username = SecretBytes::new(user_bytes.to_vec());
        let rendered = format!("{pin:?} {username:?}");
        for byte in pin_bytes.iter().chain(user_bytes.iter()) {
            assert!(
                !rendered.contains(&byte.to_string()),
                "login_user holder leaks secret byte {byte} via Debug: {rendered}"
            );
        }
    }
}

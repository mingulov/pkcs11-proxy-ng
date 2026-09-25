//! Handlers for PKCS#11 3.0/3.2 session extension RPCs (Wave 1).
//!
//! Replaces the stub handlers from `pkcs11_3x_stubs.rs` for:
//! - `C_LoginUser`
//! - `C_SessionCancel`
//! - `C_GetSessionValidationFlags`

use std::time::Duration;

use tonic::{Request, Response, Status};
use tracing::{info, warn};
use zeroize::Zeroizing;

use pkcs11_proxy_ng_types::*;

use super::super::context_manager::{ClientContextId, MessageOperation};
use super::super::handle_map::VirtualHandle;
use super::service_utils::{resolve_session, spawn_backend, spawn_backend_with_optional_timeout};

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
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    _sanitize_inputs: bool,
    request: Request<pkcs11_proxy_ng_proto::LoginUserRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::LoginUserResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse { ck_rv: error.0 }));
        }
    };

    let user_type = match CkUserType::from_raw(req.user_type) {
        Some(user_type) => user_type,
        None => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse {
                ck_rv: CkRv::USER_TYPE_INVALID.0,
            }));
        }
    };

    let user_type_raw = req.user_type;
    // PIN bytes are zeroized when the closure drops.
    // DO NOT log pin or username at any tracing level.
    let pin = Zeroizing::new(req.pin);
    // Usernames can be sensitive account identifiers tied to the PIN
    // (build.rs flags LoginUserRequest.username secret-bearing); wipe on drop.
    let username = Zeroizing::new(req.username);
    let backend = backend_ref.clone();
    let result = spawn_backend(move || {
        let pin = pin.into_zeroizing();
        let username = username.into_zeroizing();
        backend.login_user(session, user_type, &username, &pin)
    })
    .await?;

    let ck_rv = match &result {
        Ok(()) => {
            info!(context_id = %ctx_id.0, user_type = user_type_raw, "LoginUser succeeded");
            CkRv::OK.0
        }
        Err(error) => {
            warn!(context_id = %ctx_id.0, user_type = user_type_raw, rv = error.0, "LoginUser failed");
            error.0
        }
    };

    Ok(Response::new(pkcs11_proxy_ng_proto::LoginUserResponse { ck_rv }))
}

pub(super) async fn session_cancel(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    _sanitize_inputs: bool,
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
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    _sanitize_inputs: bool,
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

// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use std::sync::Arc;
use std::time::Duration;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::{CkObjectHandle, CkRv, CkSessionHandle, SecretBytes};

use super::super::super::context_manager::{ClientContextId, ContextManager, MessageOperation};
use super::super::super::handle_map::{BackendHandle, VirtualHandle};
use super::super::ck_result_to_rv;
use super::super::service_utils::{
    check_sanitize, ck_rv_only, gate_object_handle, input_from_wire, spawn_backend,
};
use crate::server::grpc_service::HandlerContext;

async fn resolve_state_handles(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    session_handle: u64,
    encryption_key_handle: u64,
    authentication_key_handle: u64,
) -> Result<(CkSessionHandle, CkObjectHandle, CkObjectHandle), CkRv> {
    let resolved: Option<(Option<BackendHandle>, Option<BackendHandle>, Option<BackendHandle>)> =
        ctx_mgr
            .get_context(ctx_id, |ctx| {
                (
                    ctx.session_handles.resolve(VirtualHandle(session_handle)),
                    ctx.object_handles.resolve(VirtualHandle(encryption_key_handle)),
                    ctx.object_handles.resolve(VirtualHandle(authentication_key_handle)),
                )
            })
            .await;

    let Some((session, encryption_key, authentication_key)) = resolved else {
        return Err(CkRv::CRYPTOKI_NOT_INITIALIZED);
    };

    let backend_session = session.ok_or(CkRv::SESSION_HANDLE_INVALID)?;
    let encryption_key =
        encryption_key.map_or(CkObjectHandle(0), |handle| CkObjectHandle(handle.0 as u64));
    let authentication_key =
        authentication_key.map_or(CkObjectHandle(0), |handle| CkObjectHandle(handle.0 as u64));

    Ok((CkSessionHandle(backend_session.0 as u64), encryption_key, authentication_key))
}

pub(super) async fn get_operation_state(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetOperationStateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetOperationStateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session =
        match super::super::service_utils::resolve_session(ctx_mgr, &ctx_id, req.session_handle)
            .await
        {
            Ok(session) => session,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::GetOperationStateResponse {
                    ck_rv: error.0,
                    operation_state: vec![],
                }));
            }
        };

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.get_operation_state(session)).await?;
    let (ck_rv, operation_state) = ck_result_to_rv(result);

    Ok(Response::new(pkcs11_proxy_ng_proto::GetOperationStateResponse {
        ck_rv,
        operation_state: secret_to_plain(&operation_state.unwrap_or_default()),
    }))
}

pub(super) async fn set_operation_state(
    ctx: &HandlerContext,
    sanitize_inputs: bool,
    request: Request<pkcs11_proxy_ng_proto::SetOperationStateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SetOperationStateResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, mut encryption_key, mut authentication_key) = match resolve_state_handles(
        ctx_mgr,
        &ctx_id,
        req.session_handle,
        req.encryption_key_handle,
        req.authentication_key_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SetOperationStateResponse {
                ck_rv: error.0,
            }));
        }
    };

    // Gate embedded key handles through per-object authz if active (C1).
    if ctx.token_policy.per_object_active() {
        let backend_session = BackendHandle(session.0);
        if encryption_key.0 != 0 {
            encryption_key = gate_object_handle(
                ctx,
                &ctx_id,
                req.session_handle,
                req.encryption_key_handle,
                backend_session,
                encryption_key,
            )
            .await;
        }
        if authentication_key.0 != 0 {
            authentication_key = gate_object_handle(
                ctx,
                &ctx_id,
                req.session_handle,
                req.authentication_key_handle,
                backend_session,
                authentication_key,
            )
            .await;
        }
    }

    let operation_state = req.operation_state;
    let operation_state_null_len = req.operation_state_null_len;
    // ADR-0010 sanitize_inputs: validate NULL operation_state pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, operation_state_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SetOperationStateResponse { ck_rv: rv.0 }));
    }
    let backend = backend_ref.clone();
    let result = spawn_backend(move || {
        backend.set_operation_state(
            session,
            input_from_wire(&operation_state, operation_state_null_len),
            encryption_key,
            authentication_key,
        )
    })
    .await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::SetOperationStateResponse {
        ck_rv: ck_rv_only(result),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_proxy_ng_backend::{MockBackend, mock::MockMessageLifecycleAction};
    use pkcs11_proxy_ng_proto::convert::message_params::MessageParameterShape;
    use pkcs11_proxy_ng_types::{CkMechanismType, CkSessionFlags, CkSlotId};

    async fn setup_message_shapes() -> (
        Arc<ContextManager>,
        Arc<MockBackend>,
        Arc<dyn Pkcs11Backend>,
        ClientContextId,
        VirtualHandle,
    ) {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(1)], vec![CkMechanismType::RSA_PKCS]));
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

    #[tokio::test]
    async fn successful_restore_clears_every_server_message_shape() {
        let (ctx_mgr, _mock, backend, ctx_id, virtual_session) = setup_message_shapes().await;
        let handler = HandlerContext::for_test(&ctx_mgr, &backend);

        let response = set_operation_state(
            &handler,
            false,
            Request::new(pkcs11_proxy_ng_proto::SetOperationStateRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: virtual_session.0,
                operation_state: vec![0xC9, 0xEA, 2],
                encryption_key_handle: 0,
                authentication_key_handle: 0,
                operation_state_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(response.ck_rv, CkRv::OK.0);
        assert_eq!(message_shapes(&ctx_mgr, &ctx_id, virtual_session).await, vec![None; 4],);
    }

    #[tokio::test]
    async fn explicit_failed_restore_preserves_every_server_message_shape() {
        let (ctx_mgr, _mock, backend, ctx_id, virtual_session) = setup_message_shapes().await;
        let handler = HandlerContext::for_test(&ctx_mgr, &backend);

        let response = set_operation_state(
            &handler,
            false,
            Request::new(pkcs11_proxy_ng_proto::SetOperationStateRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: virtual_session.0,
                operation_state: vec![0xFF],
                encryption_key_handle: 0,
                authentication_key_handle: 0,
                operation_state_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(response.ck_rv, CkRv::SAVED_STATE_INVALID.0);
        assert_eq!(
            message_shapes(&ctx_mgr, &ctx_id, virtual_session).await,
            vec![Some(MessageParameterShape::Unmodeled); 4],
        );
    }

    #[tokio::test]
    async fn restore_outcomes_settle_every_server_message_shape() {
        for (action, timeout, expected_rv, expected_shape) in [
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
            let response = set_operation_state_with_timeout(
                &handler,
                false,
                Request::new(pkcs11_proxy_ng_proto::SetOperationStateRequest {
                    client_context_id: ctx_id.0.clone(),
                    session_handle: virtual_session.0,
                    operation_state: vec![0xC9, 0xEA, 2],
                    encryption_key_handle: 0,
                    authentication_key_handle: 0,
                    operation_state_null_len: None,
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
            assert_eq!(shapes, vec![expected_shape; 4], "{action:?}");
            assert_eq!(mock.message_lifecycle_call_count(), calls_before + 1);
        }
    }
}

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_proto::convert::output::byte_output_function_from_i32;
use pkcs11_proxy_ng_proto::version::{
    exact_effects_version_rejected, exact_output_effects_version_supported,
};
use pkcs11_proxy_ng_types::{
    ByteOutputFunction, CkInBuf, CkOutputBufferResult, CkOutputBufferSpec, CkResult, CkRv,
    SecretBytes,
};

use super::super::context_manager::ClientContextId;
use super::service_utils::{
    ExactCompletion, check_sanitize, input_from_wire, mechanism_output_to_proto, resolve_session,
    spawn_backend_exact,
};

use crate::server::grpc_service::HandlerContext;

pub(super) async fn byte_output_exact(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::ByteOutputExactRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::ByteOutputExactResponse>, Status> {
    let started = std::time::Instant::now();
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    // W1-L5-04: compatibility-range gate, never an equality literal.
    if !exact_output_effects_version_supported(req.exact_output_effects_version) {
        return Err(exact_effects_version_rejected(req.exact_output_effects_version));
    }
    let ctx_id = ClientContextId(req.client_context_id);

    // Parse the function discriminator
    let function = match byte_output_function_from_i32(req.function) {
        Some(f) => f,
        None => {
            // W1-C1-10: an unknown function id must still carry an explicit
            // CK_RV — never a result-less response the shim cannot interpret.
            return Ok(Response::new(error_response(CkRv::FUNCTION_NOT_SUPPORTED)));
        }
    };

    fn error_response(error: CkRv) -> pkcs11_proxy_ng_proto::ByteOutputExactResponse {
        pkcs11_proxy_ng_proto::ByteOutputExactResponse {
            result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                apply_returned_len: Some(false),
                ck_rv: error.0,
                returned_len: 0,
                value: None,
            }),
            mechanism_out: None,
        }
    }

    // Build the output buffer spec
    let spec =
        req.output_spec.as_ref().map(CkOutputBufferSpec::from).unwrap_or(CkOutputBufferSpec {
            buffer_present: false,
            buffer_len: 0,
            length_pointer_null: false,
        });

    let input_data = SecretBytes::new(req.input_data);
    let input_data_null_len = req.input_data_null_len;

    match function {
        // Shape: (session, mechanism, wrapping_key, key, spec) -> wrap_key_exact
        ByteOutputFunction::WrapKey => {
            let outcome = async {
                let p = match super::key_ops::wrap_preparation::prepare_wrap(
                    ctx,
                    &ctx_id,
                    req.session_handle,
                    req.wrapping_key_handle,
                    req.key_handle,
                    req.mechanism,
                )
                .await?
                {
                    Ok(p) => p,
                    Err(rv) => return Ok(Err(rv)),
                };
                let backend = ctx.backend.clone();
                spawn_backend_exact(move || {
                    ExactCompletion::capture(backend.wrap_key_exact_with_output(
                        p.session,
                        &p.mechanism,
                        p.wrapping_key,
                        p.key,
                        &spec,
                    ))
                })
                .await
            }
            .await;
            let result = super::audit_events::audit_key_outcome(
                ctx,
                &ctx_id,
                "C_WrapKey",
                req.session_handle,
                started,
                outcome,
                |(output, _)| output.ck_rv,
            )?;
            let (wrap_result, mechanism_out) = match result {
                Ok((output, mech_out)) => (Ok(output), mech_out),
                Err(error) => (Err(error), None),
            };
            Ok(Response::new(pkcs11_proxy_ng_proto::ByteOutputExactResponse {
                result: Some(result_to_proto(wrap_result)),
                mechanism_out: mechanism_out.and_then(mechanism_output_to_proto),
            }))
        }

        // Shape: (session, spec) -> *_final_exact / get_operation_state_exact
        ByteOutputFunction::SignFinal
        | ByteOutputFunction::DigestFinal
        | ByteOutputFunction::EncryptFinal
        | ByteOutputFunction::DecryptFinal
        | ByteOutputFunction::GetOperationState => {
            let session =
                match resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
                    Ok(s) => s,
                    Err(error) => return Ok(Response::new(error_response(error))),
                };

            let backend = ctx.backend.clone();
            let result = spawn_backend_exact(move || {
                ExactCompletion::capture(dispatch_session_only(function, &*backend, session, &spec))
            })
            .await?;

            Ok(Response::new(pkcs11_proxy_ng_proto::ByteOutputExactResponse {
                result: Some(result_to_proto(result)),
                mechanism_out: None,
            }))
        }

        // Shape: (session, data, spec) -> all remaining functions
        _ => {
            let session =
                match resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
                    Ok(s) => s,
                    Err(error) => return Ok(Response::new(error_response(error))),
                };

            // ADR-0010 sanitize_inputs: validate NULL data pointer before backend call.
            if let Err(rv) = check_sanitize(sanitize_inputs, input_data_null_len) {
                return Ok(Response::new(error_response(rv)));
            }

            let backend = ctx.backend.clone();
            let (result, mechanism_out) = if function == ByteOutputFunction::Encrypt {
                let result = spawn_backend_exact(move || {
                    input_data.expose(|raw| {
                        let buf = input_from_wire(raw, input_data_null_len);
                        ExactCompletion::capture(
                            backend.encrypt_exact_with_output(session, buf, &spec),
                        )
                    })
                })
                .await?;
                match result {
                    Ok((output, mechanism_out)) => (Ok(output), mechanism_out),
                    Err(error) => (Err(error), None),
                }
            } else {
                let result = spawn_backend_exact(move || {
                    input_data.expose(|raw| {
                        let buf = input_from_wire(raw, input_data_null_len);
                        ExactCompletion::capture(dispatch_session_data(
                            function, &*backend, session, buf, &spec,
                        ))
                    })
                })
                .await?;
                (result, None)
            };

            Ok(Response::new(pkcs11_proxy_ng_proto::ByteOutputExactResponse {
                result: Some(result_to_proto(result)),
                mechanism_out: mechanism_out.and_then(mechanism_output_to_proto),
            }))
        }
    }
}

fn dispatch_session_only(
    function: ByteOutputFunction,
    backend: &dyn Pkcs11Backend,
    session: pkcs11_proxy_ng_types::CkSessionHandle,
    spec: &CkOutputBufferSpec,
) -> pkcs11_proxy_ng_types::CkResult<pkcs11_proxy_ng_types::CkOutputBufferResult> {
    match function {
        ByteOutputFunction::SignFinal => backend.sign_final_exact(session, spec),
        ByteOutputFunction::DigestFinal => backend.digest_final_exact(session, spec),
        ByteOutputFunction::EncryptFinal => backend.encrypt_final_exact(session, spec),
        ByteOutputFunction::DecryptFinal => backend.decrypt_final_exact(session, spec),
        ByteOutputFunction::GetOperationState => backend.get_operation_state_exact(session, spec),
        // Defensive: the parent match dispatched only session-only variants
        // here, but a future variant added without updating the parent would
        // otherwise silently `unreachable!()`-panic across the gRPC handler.
        // Return CKR_FUNCTION_NOT_SUPPORTED instead so a panic across the
        // tonic boundary becomes a clean client-visible error.
        _ => Err(pkcs11_proxy_ng_types::CkRv::FUNCTION_NOT_SUPPORTED),
    }
}

fn dispatch_session_data(
    function: ByteOutputFunction,
    backend: &dyn Pkcs11Backend,
    session: pkcs11_proxy_ng_types::CkSessionHandle,
    buf: CkInBuf<'_>,
    spec: &CkOutputBufferSpec,
) -> pkcs11_proxy_ng_types::CkResult<pkcs11_proxy_ng_types::CkOutputBufferResult> {
    match function {
        ByteOutputFunction::Sign => backend.sign_exact(session, buf, spec),
        ByteOutputFunction::SignRecover => backend.sign_recover_exact(session, buf, spec),
        ByteOutputFunction::VerifyRecover => backend.verify_recover_exact(session, buf, spec),
        ByteOutputFunction::Digest => backend.digest_exact(session, buf, spec),
        ByteOutputFunction::Encrypt => backend.encrypt_exact(session, buf, spec),
        ByteOutputFunction::EncryptUpdate => backend.encrypt_update_exact(session, buf, spec),
        ByteOutputFunction::Decrypt => backend.decrypt_exact(session, buf, spec),
        ByteOutputFunction::DecryptUpdate => backend.decrypt_update_exact(session, buf, spec),
        ByteOutputFunction::DigestEncryptUpdate => {
            backend.digest_encrypt_update_exact(session, buf, spec)
        }
        ByteOutputFunction::DecryptDigestUpdate => {
            backend.decrypt_digest_update_exact(session, buf, spec)
        }
        ByteOutputFunction::SignEncryptUpdate => {
            backend.sign_encrypt_update_exact(session, buf, spec)
        }
        ByteOutputFunction::DecryptVerifyUpdate => {
            backend.decrypt_verify_update_exact(session, buf, spec)
        }
        // See `dispatch_session_only` for the rationale: conservative
        // CKR_FUNCTION_NOT_SUPPORTED instead of a panic across gRPC.
        _ => Err(pkcs11_proxy_ng_types::CkRv::FUNCTION_NOT_SUPPORTED),
    }
}

fn result_to_proto(
    result: CkResult<CkOutputBufferResult>,
) -> pkcs11_proxy_ng_proto::OutputBufferResult {
    match result {
        Ok(r) => pkcs11_proxy_ng_proto::OutputBufferResult::from(&r),
        Err(error) => pkcs11_proxy_ng_proto::OutputBufferResult {
            apply_returned_len: Some(false),
            ck_rv: error.0,
            returned_len: 0,
            value: None,
        },
    }
}

// `mechanism_output_to_proto` has moved to `service_utils` so the
// simple Encrypt/Decrypt handlers can share the same conversion.

#[cfg(test)]
mod sanitize_inputs_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_types::*;
    use tonic::Request;

    /// W1-L5-04: every server-side exact-effects version gate (6 sites in
    /// 5 files) must delegate to the compatibility-range helper — no
    /// equality literal may remain. Expected helper-name occurrences per
    /// file: one import + one call per gate.
    #[test]
    fn exact_effects_gates_use_the_compatibility_range() {
        // Concat-built so the patterns cannot match their own source text.
        let pats = [["!= ", "1"].concat(), ["== ", "1"].concat()];
        let helper = ["exact_output_effects_version_", "supported"].concat();
        let files = [
            ("byte_output_exact.rs", include_str!("byte_output_exact.rs"), 2usize),
            ("parameter_output_exact.rs", include_str!("parameter_output_exact.rs"), 2),
            ("object/attributes.rs", include_str!("object/attributes.rs"), 2),
            ("key_ops/kem.rs", include_str!("key_ops/kem.rs"), 2),
            ("message_crypto/mod.rs", include_str!("message_crypto/mod.rs"), 3),
        ];
        for (name, src, expected_uses) in files {
            for (index, line) in src.lines().enumerate() {
                if line.contains("effects_version") && !line.trim_start().starts_with("//") {
                    for pat in &pats {
                        assert!(
                            !line.contains(pat),
                            "{name} line {}: gate must use the range helper, not `{pat}`: {line}",
                            index + 1
                        );
                    }
                }
            }
            assert_eq!(
                src.matches(&helper).count(),
                expected_uses,
                "{name}: expected one import + one range-helper call per gate"
            );
        }
    }

    use super::super::digest_cipher::{decrypt_init, encrypt_init};
    use super::byte_output_exact;
    use crate::server::context_manager::{ClientContextId, ContextManager};
    use crate::server::grpc_service::{HandlerContext, Pkcs11ProxyService, session::open_session};

    // -----------------------------------------------------------------------
    // Fixture helpers
    // -----------------------------------------------------------------------

    async fn setup_mock_session() -> (Arc<ContextManager>, Arc<MockBackend>, ClientContextId, u64) {
        let mock = Arc::new(MockBackend::default_test());
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let virtual_slot = ctx_mgr.virtual_slots().await[0];

        let resp = open_session(
            &ctx_mgr,
            &backend,
            Request::new(pkcs11_proxy_ng_proto::OpenSessionRequest {
                client_context_id: ctx_id.0.clone(),
                slot_id: virtual_slot.0,
                flags: CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(resp.ck_rv, CkRv::OK.0, "setup: open_session failed");
        (ctx_mgr, mock, ctx_id, resp.session_handle)
    }

    /// Do a decrypt_init so the session has an active decrypt operation.
    async fn setup_decrypt(
        ctx_mgr: &Arc<ContextManager>,
        backend: &Arc<dyn Pkcs11Backend>,
        ctx_id: &ClientContextId,
        session: u64,
    ) {
        // Generate a key first so we have a valid key handle.
        let key_resp = crate::server::grpc_service::key_ops::generate_key(
            &HandlerContext::for_test(ctx_mgr, backend),
            Request::new(pkcs11_proxy_ng_proto::GenerateKeyRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                    mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN.0,
                    params: None,
                }),
                template: vec![],

                template_null: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        // Ignore the RV — just init decrypt with key_handle=0 (mock ignores key validity for
        // decrypt_init) and any mechanism that the mock supports.
        let _ = decrypt_init(
            &HandlerContext::for_test(ctx_mgr, backend),
            Request::new(pkcs11_proxy_ng_proto::DecryptInitRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                key_handle: key_resp.key_handle,
                mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                    mechanism_type: CkMechanismType::RSA_PKCS.0,
                    params: None,
                }),
            }),
        )
        .await
        .unwrap();
    }

    fn make_service_sanitize_off(
        ctx_mgr: Arc<ContextManager>,
        backend: Arc<dyn Pkcs11Backend>,
    ) -> Pkcs11ProxyService {
        Pkcs11ProxyService::insecure_for_tests(ctx_mgr, backend)
    }

    fn make_service_sanitize_on(
        ctx_mgr: Arc<ContextManager>,
        backend: Arc<dyn Pkcs11Backend>,
    ) -> Pkcs11ProxyService {
        Pkcs11ProxyService::insecure_for_tests(ctx_mgr, backend).with_sanitize_inputs()
    }

    // -----------------------------------------------------------------------
    // Test 1: sanitize ON + NULL data pointer (len>0) → CKR_ARGUMENTS_BAD,
    //         backend NOT called for the data operation.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn sanitize_on_null_input_rejected_before_backend() {
        let (ctx_mgr, mock, ctx_id, session) = setup_mock_session().await;
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        setup_decrypt(&ctx_mgr, &backend, &ctx_id, session).await;

        let before = mock.data_op_call_count();
        let service = make_service_sanitize_on(ctx_mgr.clone(), backend.clone());

        let resp = byte_output_exact(
            &service.ctx,
            Request::new(pkcs11_proxy_ng_proto::ByteOutputExactRequest {
                exact_output_effects_version: 1,
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                function: pkcs11_proxy_ng_proto::ByteOutputFunction::Decrypt as i32,
                // NULL pointer with len=16: spec-invalid input
                input_data: vec![],
                input_data_null_len: Some(16),
                output_spec: Some(pkcs11_proxy_ng_proto::OutputBufferSpec {
                    buffer_present: true,
                    buffer_len: 64,
                    length_pointer_null: false,
                }),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner();

        let result = resp.result.expect("result must be present");
        assert_eq!(
            result.ck_rv,
            CkRv::ARGUMENTS_BAD.0,
            "sanitize ON: NULL data with len>0 must return CKR_ARGUMENTS_BAD"
        );
        assert_eq!(
            mock.data_op_call_count(),
            before,
            "sanitize ON: backend must NOT be called for the data operation"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2: sanitize OFF (default) + NULL data pointer → reaches backend
    //         (backend itself returns ARGUMENTS_BAD as a strict token, so we
    //         confirm by checking that the backend call count increased).
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn sanitize_off_null_input_reaches_backend() {
        let (ctx_mgr, mock, ctx_id, session) = setup_mock_session().await;
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        setup_decrypt(&ctx_mgr, &backend, &ctx_id, session).await;

        let before = mock.data_op_call_count();
        let service = make_service_sanitize_off(ctx_mgr.clone(), backend.clone());

        let _resp = byte_output_exact(
            &service.ctx,
            Request::new(pkcs11_proxy_ng_proto::ByteOutputExactRequest {
                exact_output_effects_version: 1,
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                function: pkcs11_proxy_ng_proto::ByteOutputFunction::Decrypt as i32,
                input_data: vec![],
                input_data_null_len: Some(16),
                output_spec: Some(pkcs11_proxy_ng_proto::OutputBufferSpec {
                    buffer_present: true,
                    buffer_len: 64,
                    length_pointer_null: false,
                }),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        assert!(
            mock.data_op_call_count() > before,
            "sanitize OFF: backend must be called even for NULL input (transparent forwarding)"
        );
    }

    #[tokio::test]
    async fn missing_output_length_is_forwarded_to_byte_output_backend_once() {
        let (ctx_mgr, mock, ctx_id, session) = setup_mock_session().await;
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        setup_decrypt(&ctx_mgr, &backend, &ctx_id, session).await;
        let before = mock.data_op_call_count();

        let response = byte_output_exact(
            &HandlerContext::for_test(&ctx_mgr, &backend),
            Request::new(pkcs11_proxy_ng_proto::ByteOutputExactRequest {
                exact_output_effects_version: 1,
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                function: pkcs11_proxy_ng_proto::ByteOutputFunction::Decrypt as i32,
                input_data: b"data".to_vec(),
                output_spec: Some(pkcs11_proxy_ng_proto::OutputBufferSpec {
                    buffer_present: true,
                    buffer_len: 0,
                    length_pointer_null: true,
                }),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();

        assert_eq!(response.ck_rv, CkRv::ARGUMENTS_BAD.0);
        assert_eq!(response.returned_len, 0);
        assert_eq!(response.value, None);
        assert_eq!(mock.data_op_call_count(), before + 1);
    }

    // -----------------------------------------------------------------------
    // Test 3a: sanitize ON + NULL mechanism on encrypt_init → ARGUMENTS_BAD
    //          without dispatching to backend.
    // Test 3b: sanitize OFF + NULL mechanism on encrypt_init → forwarded
    //          (existing Scope-1 behavior: encrypt_init_cancel is called).
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn sanitize_on_null_mechanism_init_rejected() {
        let (ctx_mgr, mock, ctx_id, session) = setup_mock_session().await;
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let before = mock.data_op_call_count();

        let service = make_service_sanitize_on(ctx_mgr.clone(), backend.clone());

        let resp = encrypt_init(
            &service.ctx,
            Request::new(pkcs11_proxy_ng_proto::EncryptInitRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                key_handle: 0,
                mechanism: None, // NULL mechanism
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(
            resp.ck_rv,
            CkRv::ARGUMENTS_BAD.0,
            "sanitize ON: NULL mechanism on encrypt_init must return CKR_ARGUMENTS_BAD"
        );
        // Primary evidence: ARGUMENTS_BAD confirms the init cancel was never dispatched.
        // Supplementary: data_op_call_count is unchanged (no data op reached the backend).
        assert_eq!(
            mock.data_op_call_count(),
            before,
            "sanitize ON: no data op should have been called"
        );
    }

    #[tokio::test]
    async fn sanitize_off_null_mechanism_init_forwarded() {
        let (ctx_mgr, _mock, ctx_id, session) = setup_mock_session().await;
        let backend: Arc<dyn Pkcs11Backend> = _mock.clone();

        let service = make_service_sanitize_off(ctx_mgr.clone(), backend.clone());

        let resp = encrypt_init(
            &service.ctx,
            Request::new(pkcs11_proxy_ng_proto::EncryptInitRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                key_handle: 0,
                mechanism: None, // NULL mechanism — forwarded as cancel
            }),
        )
        .await
        .unwrap()
        .into_inner();

        // The mock backend returns OK on encrypt_init_cancel.
        assert_ne!(
            resp.ck_rv,
            CkRv::ARGUMENTS_BAD.0,
            "sanitize OFF: NULL mechanism must be forwarded (not rejected with ARGUMENTS_BAD)"
        );
    }

    // -----------------------------------------------------------------------
    // Test 4: sanitize ON rejects NULL data on sign handler (per-op, not ByteOutputExact).
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn sanitize_on_null_data_sign_rejected() {
        let (ctx_mgr, mock, ctx_id, session) = setup_mock_session().await;
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let before = mock.data_op_call_count();
        let service = make_service_sanitize_on(ctx_mgr.clone(), backend.clone());

        let resp = super::super::sign_verify::sign(
            &service.ctx,
            Request::new(pkcs11_proxy_ng_proto::SignRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                data: vec![],
                data_null_len: Some(16),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(
            resp.ck_rv,
            CkRv::ARGUMENTS_BAD.0,
            "sanitize ON: NULL data on sign must return CKR_ARGUMENTS_BAD"
        );
        assert_eq!(mock.data_op_call_count(), before, "sanitize ON: backend must not be called");
    }

    // -----------------------------------------------------------------------
    // Test 5: sanitize ON rejects NULL signature (SECOND field) on verify.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn sanitize_on_null_signature_verify_rejected() {
        let (ctx_mgr, mock, ctx_id, session) = setup_mock_session().await;
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let before = mock.data_op_call_count();
        let service = make_service_sanitize_on(ctx_mgr.clone(), backend.clone());

        // data is valid (non-null), signature_null_len makes the second field NULL
        let resp = super::super::sign_verify::verify(
            &service.ctx,
            Request::new(pkcs11_proxy_ng_proto::VerifyRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                data: vec![0x01, 0x02, 0x03],
                data_null_len: None, // valid data
                signature: vec![],
                signature_null_len: Some(16), // NULL signature
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(
            resp.ck_rv,
            CkRv::ARGUMENTS_BAD.0,
            "sanitize ON: NULL signature (2nd field) on verify must return CKR_ARGUMENTS_BAD"
        );
        assert_eq!(mock.data_op_call_count(), before, "sanitize ON: backend must not be called");
    }

    // -----------------------------------------------------------------------
    // Test 6: sanitize ON rejects NULL mechanism on sign_init.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn sanitize_on_null_mechanism_sign_init_rejected() {
        let (ctx_mgr, mock, ctx_id, session) = setup_mock_session().await;
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let before = mock.data_op_call_count();
        let service = make_service_sanitize_on(ctx_mgr.clone(), backend.clone());

        let resp = super::super::sign_verify::sign_init(
            &service.ctx,
            Request::new(pkcs11_proxy_ng_proto::SignInitRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                key_handle: 0,
                mechanism: None,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(
            resp.ck_rv,
            CkRv::ARGUMENTS_BAD.0,
            "sanitize ON: NULL mechanism on sign_init must return CKR_ARGUMENTS_BAD"
        );
        assert_eq!(mock.data_op_call_count(), before, "sanitize ON: backend must not be called");
    }

    // -----------------------------------------------------------------------
    // Test 7: sanitize OFF forwards NULL mechanism on sign_init to backend.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn sanitize_off_null_mechanism_sign_init_forwarded() {
        let (ctx_mgr, _mock, ctx_id, session) = setup_mock_session().await;
        let backend: Arc<dyn Pkcs11Backend> = _mock.clone();
        let service = make_service_sanitize_off(ctx_mgr.clone(), backend.clone());

        let resp = super::super::sign_verify::sign_init(
            &service.ctx,
            Request::new(pkcs11_proxy_ng_proto::SignInitRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                key_handle: 0,
                mechanism: None,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_ne!(
            resp.ck_rv,
            CkRv::ARGUMENTS_BAD.0,
            "sanitize OFF: NULL mechanism must be forwarded (not rejected)"
        );
    }

    /// W1-C1-10: an unknown exact-output function id must yield a response
    /// carrying an explicit CK_RV — never a result-less response.
    #[tokio::test]
    async fn unknown_function_returns_explicit_ck_rv() {
        let mock = Arc::new(MockBackend::default_test());
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));

        let resp = byte_output_exact(
            &HandlerContext::for_test(&ctx_mgr, &backend),
            Request::new(pkcs11_proxy_ng_proto::ByteOutputExactRequest {
                exact_output_effects_version: 1,
                function: 9999,
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner();

        let result = resp.result.expect("unknown function must still carry a ck_rv");
        assert_eq!(result.ck_rv, CkRv::FUNCTION_NOT_SUPPORTED.0);
    }
}

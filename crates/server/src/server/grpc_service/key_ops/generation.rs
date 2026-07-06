use std::sync::Arc;
use std::time::Instant;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_audit::EventClass;
use pkcs11_proxy_ng_types::{CkMechanismParams, CkObjectHandle, CkRv, Sp800108DerivedKey};

use super::super::convert_template;
use super::super::mechanism_handles::remap_mechanism_handles;
use super::super::service_utils::{
    gate_object_handle, parse_mechanism, register_object_handle, register_session_object_handle,
    register_session_object_pair, resolve_session, resolve_session_and_object, spawn_backend,
    template_declares_token_object,
};
use crate::server::context_manager::{ClientContextId, ContextManager};
use crate::server::grpc_service::audit_events::emit_auth_event;
use crate::server::handle_map::{BackendHandle, VirtualHandle};

const CK_SP800_108_KEY_HANDLE: u64 = 0x0000_0005;

use crate::server::grpc_service::HandlerContext;

/// Emit a fail-closed `KeyMgmt` audit record after the operation completes.
/// On audit sink failure, returns `CKR_FUNCTION_FAILED` instead of the real
/// response (ADR-0012 fail-closed contract).
macro_rules! audit_key_mgmt {
    ($ctx:expr, $ctx_id:expr, $method:expr, $session:expr, $response:expr, $started:expr, $fail_response:expr) => {{
        let ck_rv = $response.get_ref().ck_rv;
        if emit_auth_event(
            $ctx,
            $ctx_id,
            $method,
            EventClass::KeyMgmt,
            None,
            $session,
            ck_rv,
            $started,
        )
        .is_err()
        {
            return Ok(Response::new($fail_response));
        }
        Ok($response)
    }};
}

/// Outer dispatcher: captures timing + identity, delegates to the impl, then
/// emits a fail-closed `KeyMgmt` audit record.
pub(crate) async fn generate_key_pair(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GenerateKeyPairRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GenerateKeyPairResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    let response = generate_key_pair_impl(ctx, request).await?;
    audit_key_mgmt!(
        ctx,
        &ctx_id,
        "C_GenerateKeyPair",
        session_for_audit,
        response,
        started,
        pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
            public_key_handle: 0,
            private_key_handle: 0,
        }
    )
}

async fn generate_key_pair_impl(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GenerateKeyPairRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GenerateKeyPairResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                ck_rv: rv.0,
                public_key_handle: 0,
                private_key_handle: 0,
            }));
        }
    };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                ck_rv: rv.0,
                public_key_handle: 0,
                private_key_handle: 0,
            }));
        }
    };

    let public_key_template = match convert_template(&req.public_key_template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                ck_rv: rv,
                public_key_handle: 0,
                private_key_handle: 0,
            }));
        }
    };

    let private_key_template = match convert_template(&req.private_key_template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                ck_rv: rv,
                public_key_handle: 0,
                private_key_handle: 0,
            }));
        }
    };

    // Each generated key is a session object unless its template marks
    // CKA_TOKEN; classify before the templates move into the backend call (B2).
    let public_is_token = template_declares_token_object(&public_key_template);
    let private_is_token = template_declares_token_object(&private_key_template);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.generate_key_pair(session, &mechanism, &public_key_template, &private_key_template)
    })
    .await?;

    match result {
        Ok((public_key, private_key)) => {
            let virtual_handles = register_session_object_pair(
                ctx_mgr,
                &ctx_id,
                virtual_session,
                CkObjectHandle(public_key.0 as u64),
                public_is_token,
                CkObjectHandle(private_key.0 as u64),
                private_is_token,
            )
            .await;
            match virtual_handles {
                Some((public_key_handle, private_key_handle)) => {
                    Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                        ck_rv: CkRv::OK.0,
                        public_key_handle,
                        private_key_handle,
                    }))
                }
                None => Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                    ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
                    public_key_handle: 0,
                    private_key_handle: 0,
                })),
            }
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
            ck_rv: error.0,
            public_key_handle: 0,
            private_key_handle: 0,
        })),
    }
}

/// Outer dispatcher: captures timing + identity, delegates to the impl, then
/// emits a fail-closed `KeyMgmt` audit record.
pub(crate) async fn generate_key(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GenerateKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GenerateKeyResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    let response = generate_key_impl(ctx, request).await?;
    audit_key_mgmt!(
        ctx,
        &ctx_id,
        "C_GenerateKey",
        session_for_audit,
        response,
        started,
        pkcs11_proxy_ng_proto::GenerateKeyResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
            key_handle: 0,
            mechanism_out: None,
        }
    )
}

async fn generate_key_impl(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GenerateKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GenerateKeyResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
                mechanism_out: None,
            }));
        }
    };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
                mechanism_out: None,
            }));
        }
    };

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
                ck_rv: rv,
                key_handle: 0,
                mechanism_out: None,
            }));
        }
    };

    let mechanism_type = mechanism.mechanism_type;
    // A generated key is a session object unless its template marks CKA_TOKEN;
    // classify before the template moves into the backend call (B2).
    let is_token = template_declares_token_object(&template);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.generate_key_with_output(session, &mechanism, &template))
            .await?;

    match result {
        Ok((object, mechanism_out_params)) => {
            let key_handle = register_session_object_handle(
                ctx_mgr,
                &ctx_id,
                virtual_session,
                CkObjectHandle(object.0 as u64),
                is_token,
            )
            .await;
            let mechanism_out = mechanism_out_params.map(|params| {
                pkcs11_proxy_ng_proto::Mechanism::from(&pkcs11_proxy_ng_types::CkMechanism {
                    mechanism_type,
                    params: Some(params),
                })
            });
            Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
                ck_rv: CkRv::OK.0,
                key_handle,
                mechanism_out,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
            ck_rv: error.0,
            key_handle: 0,
            mechanism_out: None,
        })),
    }
}

/// Outer dispatcher: captures timing + identity, delegates to the impl, then
/// emits a fail-closed `KeyMgmt` audit record.
pub(crate) async fn derive_key(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DeriveKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DeriveKeyResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    let response = derive_key_impl(ctx, request).await?;
    audit_key_mgmt!(
        ctx,
        &ctx_id,
        "C_DeriveKey",
        session_for_audit,
        response,
        started,
        pkcs11_proxy_ng_proto::DeriveKeyResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
            key_handle: 0,
            mechanism_out: None,
        }
    )
}

async fn derive_key_impl(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DeriveKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DeriveKeyResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, base_key) =
        match resolve_session_and_object(ctx, &ctx_id, req.session_handle, req.base_key_handle)
            .await
        {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                    ck_rv: rv.0,
                    key_handle: 0,
                    mechanism_out: None,
                }));
            }
        };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
                mechanism_out: None,
            }));
        }
    };

    // Translate every embedded object handle carried inside the mechanism
    // parameters (HKDF salt key, ECDH/MQV private-data keys, TLS key-material
    // secrets, CKM_CONCATENATE_BASE_AND_KEY handle, …) from the caller's
    // virtual handle space to the backend's, gating through per-object authz
    // when active (B1 + C1). SP800-108's byte-encoded input key handles are
    // handled separately just below.
    if let Err(rv) =
        remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
            mechanism_out: None,
        }));
    }

    if let Some(ref mut params) = mechanism.params
        && let Err(rv) =
            resolve_sp800_108_key_handle_data_params(ctx, &ctx_id, req.session_handle, params).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
            mechanism_out: None,
        }));
    }

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                ck_rv: rv,
                key_handle: 0,
                mechanism_out: None,
            }));
        }
    };

    let mechanism_type = mechanism.mechanism_type;
    // A derived key is a session object unless CKA_TOKEN is set (B2).
    let is_token = template_declares_token_object(&template);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.derive_key_with_output_result(session, &mechanism, base_key, &template)
    })
    .await?;

    match result {
        Ok(mut derive_result) => {
            let key_handle = if derive_result.rv.is_ok() {
                match derive_result.key_handle {
                    Some(object) => {
                        register_session_object_handle(
                            ctx_mgr,
                            &ctx_id,
                            virtual_session,
                            object,
                            is_token,
                        )
                        .await
                    }
                    None => 0,
                }
            } else {
                0
            };
            if derive_result.rv.is_ok()
                && let Some(ref mut params) = derive_result.mechanism_out
            {
                virtualize_sp800_108_additional_handles(ctx_mgr, &ctx_id, params).await;
            }
            let mechanism_out = derive_result.mechanism_out.map(|params| {
                pkcs11_proxy_ng_proto::Mechanism::from(&pkcs11_proxy_ng_types::CkMechanism {
                    mechanism_type,
                    params: Some(params),
                })
            });
            Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                ck_rv: derive_result.rv.0,
                key_handle,
                mechanism_out,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
            ck_rv: error.0,
            key_handle: 0,
            mechanism_out: None,
        })),
    }
}

/// Resolve SP800-108 byte-encoded key handles in KDF params, gating each
/// through per-object authz when active (C1).
async fn resolve_sp800_108_key_handle_data_params(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    virtual_session_handle: u64,
    params: &mut CkMechanismParams,
) -> Result<(), CkRv> {
    match params {
        CkMechanismParams::Sp800108Kdf(params) => {
            resolve_sp800_108_key_handle_data_param_list(
                ctx,
                ctx_id,
                virtual_session_handle,
                &mut params.data_params,
            )
            .await
        }
        CkMechanismParams::Sp800108FeedbackKdf(params) => {
            resolve_sp800_108_key_handle_data_param_list(
                ctx,
                ctx_id,
                virtual_session_handle,
                &mut params.data_params,
            )
            .await
        }
        _ => Ok(()),
    }
}

async fn resolve_sp800_108_key_handle_data_param_list(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    virtual_session_handle: u64,
    data_params: &mut [pkcs11_proxy_ng_types::PrfDataParam],
) -> Result<(), CkRv> {
    for data_param in data_params {
        if data_param.type_ != CK_SP800_108_KEY_HANDLE {
            continue;
        }

        let (virtual_handle, width) = read_sp800_108_key_handle_value(&data_param.value)?;
        let backend_handle = ctx
            .context_manager
            .get_context(ctx_id, |lci| lci.object_handles.resolve(VirtualHandle(virtual_handle)))
            .await
            .and_then(|resolved| resolved)
            .ok_or(CkRv::OBJECT_HANDLE_INVALID)?;

        // Gate the resolved handle through per-object authz if active (C1).
        let final_handle = if ctx.token_policy.per_object_active() && backend_handle.0 != 0 {
            gate_object_handle(
                ctx,
                ctx_id,
                virtual_session_handle,
                virtual_handle,
                BackendHandle(backend_handle.0),
                CkObjectHandle(backend_handle.0),
            )
            .await
        } else {
            CkObjectHandle(backend_handle.0)
        };

        data_param.value = write_sp800_108_key_handle_value(final_handle.0, width)?;
    }
    Ok(())
}

fn read_sp800_108_key_handle_value(value: &[u8]) -> Result<(u64, usize), CkRv> {
    match value.len() {
        8 => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(value);
            Ok((u64::from_ne_bytes(bytes), 8))
        }
        4 => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(value);
            Ok((u32::from_ne_bytes(bytes) as u64, 4))
        }
        _ => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

fn write_sp800_108_key_handle_value(handle: u64, width: usize) -> Result<Vec<u8>, CkRv> {
    match width {
        8 => Ok(handle.to_ne_bytes().to_vec()),
        4 => Ok(u32::try_from(handle)
            .map_err(|_| CkRv::OBJECT_HANDLE_INVALID)?
            .to_ne_bytes()
            .to_vec()),
        _ => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

async fn virtualize_sp800_108_additional_handles(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    params: &mut CkMechanismParams,
) {
    match params {
        CkMechanismParams::Sp800108Kdf(params) => {
            virtualize_derived_key_handles(ctx_mgr, ctx_id, &mut params.additional_derived_keys)
                .await;
        }
        CkMechanismParams::Sp800108FeedbackKdf(params) => {
            virtualize_derived_key_handles(ctx_mgr, ctx_id, &mut params.additional_derived_keys)
                .await;
        }
        _ => {}
    }
}

async fn virtualize_derived_key_handles(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    derived_keys: &mut [Sp800108DerivedKey],
) {
    for derived_key in derived_keys {
        if derived_key.key_handle != 0 {
            derived_key.key_handle = register_object_handle(
                ctx_mgr,
                ctx_id,
                CkObjectHandle(derived_key.key_handle as u64),
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::server::grpc_service::HandlerContext;
    use crate::server::handle_map::BackendHandle;
    use pkcs11_proxy_ng_backend::MockBackend;
    use pkcs11_proxy_ng_types::{
        CkMechanismType, CkSlotId, PrfDataParam, Sp800108FeedbackKdfParams, Sp800108KdfParams,
    };

    /// Build a minimal `HandlerContext` with no per-object policy (fast path for
    /// SP800-108 unit tests that only care about handle resolution, not gating).
    fn make_ctx(ctx_mgr: &Arc<ContextManager>) -> HandlerContext {
        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> =
            Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        HandlerContext::for_test(ctx_mgr, &backend)
    }

    #[tokio::test]
    async fn resolves_sp800_108_key_handle_data_param_to_backend_handle_bytes() {
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 16));
        let ctx = make_ctx(&ctx_mgr);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let backend_key = BackendHandle(0xABCD_0102);
        let virtual_key =
            ctx_mgr.get_context(&ctx_id, |c| c.object_handles.insert(backend_key)).await.unwrap();
        let mut params = CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
            prf_type: CkMechanismType::SHA256.0,
            data_params: vec![PrfDataParam {
                type_: CK_SP800_108_KEY_HANDLE,
                value: virtual_key.0.to_ne_bytes().to_vec(),
            }],
            iv: vec![0xA5; 16],
            additional_derived_keys: Vec::new(),
        });

        // Virtual session handle = 0 is fine; per_object_active() is false so it
        // is not used for gate lookup.
        resolve_sp800_108_key_handle_data_params(&ctx, &ctx_id, 0, &mut params).await.unwrap();

        let CkMechanismParams::Sp800108FeedbackKdf(params) = params else {
            panic!("expected SP800-108 feedback KDF params");
        };
        assert_eq!(params.data_params[0].value, backend_key.0.to_ne_bytes().to_vec());
    }

    #[tokio::test]
    async fn rejects_malformed_sp800_108_key_handle_data_param_width() {
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 16));
        let ctx = make_ctx(&ctx_mgr);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let mut params = CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CkMechanismType::SHA256.0,
            data_params: vec![PrfDataParam {
                type_: CK_SP800_108_KEY_HANDLE,
                value: vec![1, 2, 3],
            }],
            additional_derived_keys: Vec::new(),
        });

        let err = resolve_sp800_108_key_handle_data_params(&ctx, &ctx_id, 0, &mut params)
            .await
            .unwrap_err();

        assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
    }
}

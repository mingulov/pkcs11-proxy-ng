use std::sync::Arc;
use std::time::Instant;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_audit::EventClass;
use pkcs11_proxy_ng_types::{
    CkMechanismParams, CkObjectClass, CkObjectHandle, CkRv, CkSessionHandle, Sp800108DerivedKey,
};

use super::super::authorization::{class_mint_permitted, mechanism_permitted};
use super::super::convert_template_opt;
use super::super::mechanism_handles::remap_mechanism_handles;
use super::super::service_utils::{
    ensure_private_mint_allowed, ensure_private_use_allowed, gate_object_handle, parse_mechanism,
    register_session_object_handle, register_session_object_pair, resolve_session,
    resolve_session_and_object, spawn_backend, template_declares_private_object,
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

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                ck_rv: rv.0,
                public_key_handle: 0,
                private_key_handle: 0,
            }));
        }
    };

    // Mechanism policy gate (G3-PR3 Task 3): deny before backend call when the
    // principal's grant does not include this key-generation mechanism.
    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
            ck_rv: CkRv::MECHANISM_INVALID.0,
            public_key_handle: 0,
            private_key_handle: 0,
        }));
    }

    if let Err(rv) =
        remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
            ck_rv: rv.0,
            public_key_handle: 0,
            private_key_handle: 0,
        }));
    }

    let public_key_template =
        match convert_template_opt(&req.public_key_template, req.public_template_null) {
            Ok(template) => template,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                    ck_rv: rv,
                    public_key_handle: 0,
                    private_key_handle: 0,
                }));
            }
        };

    let private_key_template =
        match convert_template_opt(&req.private_key_template, req.private_template_null) {
            Ok(template) => template,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                    ck_rv: rv,
                    public_key_handle: 0,
                    private_key_handle: 0,
                }));
            }
        };

    // NULL templates carry no attributes; classification treats them as empty.
    let public_view = public_key_template.as_deref().unwrap_or(&[]);
    let private_view = private_key_template.as_deref().unwrap_or(&[]);

    // D6(1): refuse minting a private object while logically logged out.
    for template in [public_view, private_view] {
        if let Err(rv) =
            ensure_private_mint_allowed(ctx_mgr, &ctx_id, req.session_handle, template).await
        {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                ck_rv: rv.0,
                public_key_handle: 0,
                private_key_handle: 0,
            }));
        }
    }

    // W1-L7-05: mint-time class gate per template (implied PUBLIC_KEY /
    // PRIVATE_KEY when CKA_CLASS is omitted). Either half denied denies
    // the whole mint, before the backend runs.
    for (template, default) in
        [(public_view, CkObjectClass::PUBLIC_KEY), (private_view, CkObjectClass::PRIVATE_KEY)]
    {
        if !class_mint_permitted(ctx, &ctx_id, req.session_handle, template, Some(default)).await {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                ck_rv: CkRv::ATTRIBUTE_VALUE_INVALID.0,
                public_key_handle: 0,
                private_key_handle: 0,
            }));
        }
    }

    // Each generated key is a session object unless its template marks
    // CKA_TOKEN; classify before the templates move into the backend call (B2).
    // Privacy bits are recorded alongside for the D6(1) USE enforcement.
    let public_is_token = template_declares_token_object(public_view);
    let private_is_token = template_declares_token_object(private_view);
    let public_is_private = template_declares_private_object(public_view);
    let private_is_private = template_declares_private_object(private_view);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.generate_key_pair(
            session,
            &mechanism,
            public_key_template.as_deref(),
            private_key_template.as_deref(),
        )
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
                public_is_private,
                CkObjectHandle(private_key.0 as u64),
                private_is_token,
                private_is_private,
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

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
                mechanism_out: None,
            }));
        }
    };

    // Mechanism policy gate (G3-PR3 Task 3): deny before backend call when the
    // principal's grant does not include this key-generation mechanism.
    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
            ck_rv: CkRv::MECHANISM_INVALID.0,
            key_handle: 0,
            mechanism_out: None,
        }));
    }

    if let Err(rv) =
        remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
            mechanism_out: None,
        }));
    }

    let template = match convert_template_opt(&req.template, req.template_null) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
                ck_rv: rv,
                key_handle: 0,
                mechanism_out: None,
            }));
        }
    };

    // A NULL template carries no attributes; classification treats it as empty.
    let template_view = template.as_deref().unwrap_or(&[]);

    // D6(1): refuse minting a private object while logically logged out.
    if let Err(rv) =
        ensure_private_mint_allowed(ctx_mgr, &ctx_id, req.session_handle, template_view).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
            mechanism_out: None,
        }));
    }

    // W1-L7-05: mint-time class gate (implied SECRET_KEY when CKA_CLASS is
    // omitted), before the backend runs.
    if !class_mint_permitted(
        ctx,
        &ctx_id,
        req.session_handle,
        template_view,
        Some(CkObjectClass::SECRET_KEY),
    )
    .await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
            ck_rv: CkRv::ATTRIBUTE_VALUE_INVALID.0,
            key_handle: 0,
            mechanism_out: None,
        }));
    }

    let mechanism_type = mechanism.mechanism_type;
    // A generated key is a session object unless its template marks CKA_TOKEN;
    // classify before the template moves into the backend call (B2). The
    // privacy bit is recorded for the D6(1) USE enforcement.
    let is_token = template_declares_token_object(template_view);
    let is_private = template_declares_private_object(template_view);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.generate_key_with_output(session, &mechanism, template.as_deref())
    })
    .await?;

    match result {
        Ok((object, mechanism_out_params)) => {
            let key_handle = register_session_object_handle(
                ctx_mgr,
                &ctx_id,
                virtual_session,
                CkObjectHandle(object.0 as u64),
                is_token,
                Some(is_private),
            )
            .await;
            let mechanism_out = match mechanism_out_params
                .map(|params| {
                    pkcs11_proxy_ng_proto::Mechanism::try_from(
                        &pkcs11_proxy_ng_types::CkMechanism {
                            mechanism_type,
                            params: Some(params),
                        },
                    )
                })
                .transpose()
            {
                Ok(mechanism_out) => mechanism_out,
                // The backend returned output params the wire cannot
                // represent (e.g. a nested template, W1-C8-01): fail
                // loudly rather than report success with silently
                // dropped output. Shape matches the backend-error arm.
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
                        ck_rv: rv.0,
                        key_handle: 0,
                        mechanism_out: None,
                    }));
                }
            };
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

    // Mechanism policy gate (G3-PR3 Task 3): deny before backend call when the
    // principal's grant does not include this derive mechanism.
    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
            ck_rv: CkRv::MECHANISM_INVALID.0,
            key_handle: 0,
            mechanism_out: None,
        }));
    }

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
        && let Err(rv) = resolve_sp800_108_key_handle_data_params(
            ctx,
            &ctx_id,
            req.session_handle,
            session,
            params,
        )
        .await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
            mechanism_out: None,
        }));
    }

    let template = match convert_template_opt(&req.template, req.template_null) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                ck_rv: rv,
                key_handle: 0,
                mechanism_out: None,
            }));
        }
    };

    // A NULL template carries no attributes; classification treats it as empty.
    let template_view = template.as_deref().unwrap_or(&[]);

    // D6(1): refuse minting a private object while logically logged out.
    // (The private base key itself is refused by the USE check inside
    // resolve_session_and_object above.)
    if let Err(rv) =
        ensure_private_mint_allowed(ctx_mgr, &ctx_id, req.session_handle, template_view).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
            mechanism_out: None,
        }));
    }

    // W1-L7-05: mint-time class gate (implied SECRET_KEY when CKA_CLASS is
    // omitted), before the backend runs.
    if !class_mint_permitted(
        ctx,
        &ctx_id,
        req.session_handle,
        template_view,
        Some(CkObjectClass::SECRET_KEY),
    )
    .await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
            ck_rv: CkRv::ATTRIBUTE_VALUE_INVALID.0,
            key_handle: 0,
            mechanism_out: None,
        }));
    }

    let mechanism_type = mechanism.mechanism_type;
    // A derived key is a session object unless CKA_TOKEN is set (B2). The
    // privacy bit is recorded for the D6(1) USE enforcement.
    let is_token = template_declares_token_object(template_view);
    let is_private = template_declares_private_object(template_view);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.derive_key_with_output_result(session, &mechanism, base_key, template.as_deref())
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
                            Some(is_private),
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
                virtualize_sp800_108_additional_handles(ctx_mgr, &ctx_id, virtual_session, params)
                    .await;
                virtualize_key_mat_out_handles(ctx_mgr, &ctx_id, virtual_session, is_token, params)
                    .await;
            }
            let mechanism_out = match derive_result
                .mechanism_out
                .map(|params| {
                    pkcs11_proxy_ng_proto::Mechanism::try_from(
                        &pkcs11_proxy_ng_types::CkMechanism {
                            mechanism_type,
                            params: Some(params),
                        },
                    )
                })
                .transpose()
            {
                Ok(mechanism_out) => mechanism_out,
                // The backend returned output params the wire cannot
                // represent (e.g. a nested template, W1-C8-01): fail
                // loudly rather than report success with silently
                // dropped output. Shape matches the backend-error arm.
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                        ck_rv: rv.0,
                        key_handle: 0,
                        mechanism_out: None,
                    }));
                }
            };
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
/// through object/class authorization when active. The native session is kept
/// separate from the embedded object, since metadata reads require both.
async fn resolve_sp800_108_key_handle_data_params(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    virtual_session_handle: u64,
    backend_session: CkSessionHandle,
    params: &mut CkMechanismParams,
) -> Result<(), CkRv> {
    match params {
        CkMechanismParams::Sp800108Kdf(params) => {
            resolve_sp800_108_key_handle_data_param_list(
                ctx,
                ctx_id,
                virtual_session_handle,
                backend_session,
                &mut params.data_params,
            )
            .await
        }
        CkMechanismParams::Sp800108FeedbackKdf(params) => {
            resolve_sp800_108_key_handle_data_param_list(
                ctx,
                ctx_id,
                virtual_session_handle,
                backend_session,
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
    backend_session: CkSessionHandle,
    data_params: &mut [pkcs11_proxy_ng_types::PrfDataParam],
) -> Result<(), CkRv> {
    for data_param in data_params {
        if data_param.type_ != CK_SP800_108_KEY_HANDLE {
            continue;
        }

        let (virtual_handle, width) = data_param.value.expose(read_sp800_108_key_handle_value)?;
        let backend_handle = ctx
            .context_manager
            .get_context(ctx_id, |lci| lci.object_handles.resolve(VirtualHandle(virtual_handle)))
            .await
            .and_then(|resolved| resolved)
            .ok_or(CkRv::OBJECT_HANDLE_INVALID)?;

        // D6(1): the byte-encoded input key is a USE of the embedded key —
        // refuse while the caller is logically logged out (before the
        // per-object gate below, like the primary-handle chokepoints).
        if backend_handle.0 != 0 {
            ensure_private_use_allowed(
                ctx,
                ctx_id,
                virtual_session_handle,
                virtual_handle,
                backend_session,
                CkObjectHandle(backend_handle.0),
            )
            .await?;
        }

        let final_handle = if (ctx.token_policy.per_object_active()
            || ctx.token_policy.per_class_active())
            && backend_handle.0 != 0
        {
            gate_object_handle(
                ctx,
                ctx_id,
                virtual_session_handle,
                virtual_handle,
                BackendHandle(backend_session.0),
                CkObjectHandle(backend_handle.0),
            )
            .await
        } else {
            CkObjectHandle(backend_handle.0)
        };

        // A denied nonzero key must not become a different parameter (zero).
        // Match shared embedded-handle denial before any provider dispatch.
        if virtual_handle != 0 && final_handle.0 == 0 {
            return Err(CkRv::OBJECT_HANDLE_INVALID);
        }
        data_param.value = write_sp800_108_key_handle_value(final_handle.0, width)?.into();
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
    virtual_session: VirtualHandle,
    params: &mut CkMechanismParams,
) {
    match params {
        CkMechanismParams::Sp800108Kdf(params) => {
            virtualize_derived_key_handles(
                ctx_mgr,
                ctx_id,
                virtual_session,
                &mut params.additional_derived_keys,
            )
            .await;
        }
        CkMechanismParams::Sp800108FeedbackKdf(params) => {
            virtualize_derived_key_handles(
                ctx_mgr,
                ctx_id,
                virtual_session,
                &mut params.additional_derived_keys,
            )
            .await;
        }
        _ => {}
    }
}

async fn virtualize_derived_key_handles(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    virtual_session: VirtualHandle,
    derived_keys: &mut [Sp800108DerivedKey],
) {
    for derived_key in derived_keys {
        if derived_key.key_handle != 0 {
            // m-1: derived keys are always private secret keys. Each key is
            // bound to the derive session per its own template (B2), so a
            // session additional key evicts — mapping and privacy bit — when
            // the owner session closes instead of lingering as a stale
            // mapping that over-refuses with CKR_USER_NOT_LOGGED_IN.
            derived_key.key_handle = register_session_object_handle(
                ctx_mgr,
                ctx_id,
                virtual_session,
                CkObjectHandle(derived_key.key_handle as u64),
                template_declares_token_object(&derived_key.template),
                Some(true),
            )
            .await;
        }
    }
}

/// Register + rewrite each non-zero OUT handle in SSL3/TLS/WTLS key-material
/// `mechanism_out` (F6/D4). Without this the key-mat handles flow back native
/// and unresolvable (`CKR_OBJECT_HANDLE_INVALID` on readback). Mirrors
/// [`virtualize_sp800_108_additional_handles`]; `Ssl3KeyMatParams` covers the
/// TLS12 layout as well.
async fn virtualize_key_mat_out_handles(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    virtual_session: VirtualHandle,
    is_token_object: bool,
    params: &mut CkMechanismParams,
) {
    let handles: &mut [&mut u64] = match params {
        CkMechanismParams::Ssl3KeyMat(p) => &mut [
            &mut p.client_mac_secret_handle,
            &mut p.server_mac_secret_handle,
            &mut p.client_key_handle,
            &mut p.server_key_handle,
        ],
        CkMechanismParams::WtlsKeyMat(p) => &mut [&mut p.mac_secret_handle, &mut p.key_handle],
        _ => return,
    };
    for handle in handles {
        if **handle != 0 {
            // m-1: key-mat OUT handles are always private secret keys. Key-mat
            // params carry no per-key template, so the outputs inherit the
            // derive template's token classification (like the primary
            // derived key) and bind to the derive session (B2): a session
            // output's mapping and privacy bit evict on owner-session close.
            **handle = register_session_object_handle(
                ctx_mgr,
                ctx_id,
                virtual_session,
                CkObjectHandle(**handle),
                is_token_object,
                Some(true),
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
                value: virtual_key.0.to_ne_bytes().to_vec().into(),
            }],
            iv: vec![0xA5; 16],
            additional_derived_keys: Vec::new(),
        });

        // Virtual session handle = 0 is fine; per_object_active() is false so it
        // is not used for gate lookup.
        resolve_sp800_108_key_handle_data_params(&ctx, &ctx_id, 0, CkSessionHandle(0), &mut params)
            .await
            .unwrap();

        let CkMechanismParams::Sp800108FeedbackKdf(params) = params else {
            panic!("expected SP800-108 feedback KDF params");
        };
        assert_eq!(params.data_params[0].value, backend_key.0.to_ne_bytes().to_vec().into());
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
                value: vec![1, 2, 3].into(),
            }],
            additional_derived_keys: Vec::new(),
        });

        let err = resolve_sp800_108_key_handle_data_params(
            &ctx,
            &ctx_id,
            0,
            CkSessionHandle(0),
            &mut params,
        )
        .await
        .unwrap_err();

        assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
    }

    #[tokio::test]
    async fn rejects_sp800_108_backend_handle_that_cannot_fit_encoded_width() {
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 16));
        let ctx = make_ctx(&ctx_mgr);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let virtual_key = ctx_mgr
            .get_context(&ctx_id, |c| c.object_handles.insert(BackendHandle(u32::MAX as u64 + 1)))
            .await
            .unwrap();
        let input = (virtual_key.0 as u32).to_ne_bytes().to_vec();
        let mut params = CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: cryptoki_sys::CKM_SHA256_HMAC as u64,
            data_params: vec![PrfDataParam {
                type_: CK_SP800_108_KEY_HANDLE,
                value: input.clone().into(),
            }],
            additional_derived_keys: vec![],
        });
        assert_eq!(
            resolve_sp800_108_key_handle_data_params(
                &ctx,
                &ctx_id,
                0,
                CkSessionHandle(0),
                &mut params,
            )
            .await,
            Err(CkRv::OBJECT_HANDLE_INVALID)
        );
        let CkMechanismParams::Sp800108Kdf(params) = params else { unreachable!() };
        assert_eq!(
            params.data_params[0].value,
            input.into(),
            "failure must not serialize a truncated handle"
        );
    }

    /// F-02: the SP800-108 byte-encoded input key handle is a USE of the
    /// embedded key — refused with `CKR_USER_NOT_LOGGED_IN` while the caller
    /// is logically logged out, resolved normally once logged in.
    #[tokio::test]
    async fn sp800_108_private_embedded_key_use_while_logged_out_is_refused() {
        use crate::server::context_manager::LoginState;
        use crate::server::slot_map::BackendSlotId;

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 16));
        let ctx = make_ctx(&ctx_mgr);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let slot = BackendSlotId(CkSlotId(0));
        let backend_key = BackendHandle(0xABCD_0102);
        // A session on the slot (logged out: no login_state entry) plus a
        // mint-recorded-private embedded key.
        let (virtual_session, virtual_key) = ctx_mgr
            .get_context(&ctx_id, |c| {
                let vs = c.register_session(BackendHandle(77), slot);
                let vk = c.object_handles.insert(backend_key);
                c.object_private.insert(vk, true);
                (vs, vk)
            })
            .await
            .unwrap();
        let mut params = CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CkMechanismType::SHA256.0,
            data_params: vec![PrfDataParam {
                type_: CK_SP800_108_KEY_HANDLE,
                value: virtual_key.0.to_ne_bytes().to_vec().into(),
            }],
            additional_derived_keys: Vec::new(),
        });

        // Logged out → refused.
        assert_eq!(
            resolve_sp800_108_key_handle_data_params(
                &ctx,
                &ctx_id,
                virtual_session.0,
                CkSessionHandle(77),
                &mut params,
            )
            .await,
            Err(CkRv::USER_NOT_LOGGED_IN)
        );

        // Logged in → resolves to the backend handle bytes.
        ctx_mgr.get_context(&ctx_id, |c| c.login_state.insert(slot, LoginState::User)).await;
        resolve_sp800_108_key_handle_data_params(
            &ctx,
            &ctx_id,
            virtual_session.0,
            CkSessionHandle(77),
            &mut params,
        )
        .await
        .unwrap();
        let CkMechanismParams::Sp800108Kdf(params) = params else { unreachable!() };
        assert_eq!(params.data_params[0].value, backend_key.0.to_ne_bytes().to_vec().into());
    }

    /// F6: key-mat OUT handles in a successful derive's `mechanism_out` must
    /// come back virtualized (registered + rewritten); zero handles are left
    /// alone and non-key-mat params pass through untouched.
    #[tokio::test]
    async fn virtualizes_key_mat_out_handles_and_leaves_zeros_alone() {
        use pkcs11_proxy_ng_types::{
            Ssl3KeyMatParams, SslRandomData, WtlsKeyMatParams, WtlsRandomData,
        };

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 16));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(77),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();

        let mut ssl3 = CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
            mac_size_bits: 128,
            key_size_bits: 128,
            iv_size_bits: 0,
            is_export: false,
            random_info: SslRandomData { client_random: vec![1; 32], server_random: vec![2; 32] },
            prf_hash_mechanism: 0,
            client_mac_secret_handle: 0xA1,
            server_mac_secret_handle: 0,
            client_key_handle: 0xA2,
            server_key_handle: 0xA3,
            client_iv: Vec::new().into(),
            server_iv: Vec::new().into(),
        });
        virtualize_key_mat_out_handles(&ctx_mgr, &ctx_id, virtual_session, false, &mut ssl3).await;
        let CkMechanismParams::Ssl3KeyMat(ssl3) = &ssl3 else { unreachable!() };
        assert_eq!(ssl3.server_mac_secret_handle, 0, "zero OUT handles stay zero");
        for (rewritten, backend) in [
            (ssl3.client_mac_secret_handle, 0xA1),
            (ssl3.client_key_handle, 0xA2),
            (ssl3.server_key_handle, 0xA3),
        ] {
            assert_ne!(rewritten, backend, "non-zero OUT handle must be rewritten");
            let resolved = ctx_mgr
                .get_context(&ctx_id, |c| {
                    c.object_handles.resolve(crate::server::handle_map::VirtualHandle(rewritten))
                })
                .await
                .unwrap();
            assert_eq!(resolved, Some(BackendHandle(backend)));
        }

        let mut wtls = CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
            digest_mechanism: 0x220,
            mac_size_bits: 128,
            key_size_bits: 128,
            iv_size_bits: 0,
            sequence_number: 0,
            is_export: false,
            random_info: WtlsRandomData { client_random: vec![3; 16], server_random: vec![4; 16] },
            mac_secret_handle: 0xB1,
            key_handle: 0,
            iv: Vec::new(),
        });
        virtualize_key_mat_out_handles(&ctx_mgr, &ctx_id, virtual_session, false, &mut wtls).await;
        let CkMechanismParams::WtlsKeyMat(wtls) = &wtls else { unreachable!() };
        assert_eq!(wtls.key_handle, 0);
        assert_ne!(wtls.mac_secret_handle, 0xB1);
        let resolved = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.object_handles
                    .resolve(crate::server::handle_map::VirtualHandle(wtls.mac_secret_handle))
            })
            .await
            .unwrap();
        assert_eq!(resolved, Some(BackendHandle(0xB1)));

        // Non-key-mat params are untouched.
        let mut other = CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CkMechanismType::SHA256.0,
            data_params: Vec::new(),
            additional_derived_keys: Vec::new(),
        });
        virtualize_key_mat_out_handles(&ctx_mgr, &ctx_id, virtual_session, false, &mut other).await;
        assert!(matches!(other, CkMechanismParams::Sp800108Kdf(_)));
    }

    /// m-1: virtualized key-mat / SP800-108 OUT handles are always private
    /// secret keys, so registration records `object_private=true` and
    /// logged-out USE refuses even when the backend `CKA_PRIVATE` probe
    /// fails. (Pre-fix the bit was unknown and the probe failure failed
    /// open to the backend verdict.)
    #[tokio::test]
    async fn virtualized_out_handles_recorded_private_refuse_logged_out_use() {
        use crate::server::slot_map::BackendSlotId;
        use pkcs11_proxy_ng_types::{CkSlotId, Ssl3KeyMatParams, SslRandomData};

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 16));
        let ctx = make_ctx(&ctx_mgr);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let slot = BackendSlotId(CkSlotId(0));
        // Logged-out session (no login_state entry). Backend session 77 does
        // not exist in the mock, so any CKA_PRIVATE probe fails.
        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| c.register_session(BackendHandle(77), slot))
            .await
            .unwrap();

        // Key-mat OUT handle unknown to the mock backend.
        let mut ssl3 = CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
            mac_size_bits: 128,
            key_size_bits: 128,
            iv_size_bits: 0,
            is_export: false,
            random_info: SslRandomData { client_random: vec![1; 32], server_random: vec![2; 32] },
            prf_hash_mechanism: 0,
            client_mac_secret_handle: 0,
            server_mac_secret_handle: 0,
            client_key_handle: 0xA2,
            server_key_handle: 0,
            client_iv: Vec::new().into(),
            server_iv: Vec::new().into(),
        });
        virtualize_key_mat_out_handles(&ctx_mgr, &ctx_id, virtual_session, false, &mut ssl3).await;
        let CkMechanismParams::Ssl3KeyMat(ssl3) = &ssl3 else { unreachable!() };
        let v_key_mat = ssl3.client_key_handle;

        // SP800-108 additional derived-key handle unknown to the mock backend.
        let mut kdf = CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CkMechanismType::SHA256.0,
            data_params: Vec::new(),
            additional_derived_keys: vec![Sp800108DerivedKey {
                template: Vec::new(),
                key_handle: 0xC1,
            }],
        });
        virtualize_sp800_108_additional_handles(&ctx_mgr, &ctx_id, virtual_session, &mut kdf).await;
        let CkMechanismParams::Sp800108Kdf(kdf) = &kdf else { unreachable!() };
        let v_kdf = kdf.additional_derived_keys[0].key_handle;

        for (name, virtual_handle, backend_handle) in
            [("key-mat", v_key_mat, 0xA2), ("sp800-108", v_kdf, 0xC1)]
        {
            let recorded = ctx_mgr
                .get_context(&ctx_id, |c| {
                    c.object_private
                        .get(&crate::server::handle_map::VirtualHandle(virtual_handle))
                        .copied()
                })
                .await
                .unwrap();
            assert_eq!(
                recorded,
                Some(true),
                "{name}: virtualized OUT handle must be recorded private at registration"
            );
            assert_eq!(
                ensure_private_use_allowed(
                    &ctx,
                    &ctx_id,
                    virtual_session.0,
                    virtual_handle,
                    CkSessionHandle(77),
                    CkObjectHandle(backend_handle),
                )
                .await,
                Err(CkRv::USER_NOT_LOGGED_IN),
                "{name}: logged-out USE with a failing backend probe must still refuse"
            );
        }
    }

    /// T5-m1-followup: virtualized SP800-108/key-mat OUT handles are bound
    /// to the derive session (B2), so owner-session close evicts the mapping
    /// AND the m-1 privacy bit. A post-close USE from a fresh logged-out
    /// session then resolves unknown — skipping the privacy gate instead of
    /// over-refusing 257 — and the backend verdict (130) decides. A
    /// token-template SP800-108 additional key survives the close with its
    /// privacy bit intact and still refuses logged-out USE.
    #[tokio::test]
    async fn virtualized_out_handles_evict_on_owner_session_close() {
        use crate::server::slot_map::BackendSlotId;
        use pkcs11_proxy_ng_types::{
            CkAttribute, CkAttributeType, CkAttributeValue, Ssl3KeyMatParams, SslRandomData,
        };

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 16));
        let ctx = make_ctx(&ctx_mgr);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let slot = BackendSlotId(CkSlotId(0));
        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| c.register_session(BackendHandle(77), slot))
            .await
            .unwrap();

        let mut kdf = CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CkMechanismType::SHA256.0,
            data_params: Vec::new(),
            additional_derived_keys: vec![
                Sp800108DerivedKey { template: Vec::new(), key_handle: 0xC1 },
                Sp800108DerivedKey {
                    template: vec![CkAttribute {
                        attr_type: CkAttributeType::TOKEN,
                        value: Some(CkAttributeValue::Bool(true)),
                    }],
                    key_handle: 0xC2,
                },
            ],
        });
        virtualize_sp800_108_additional_handles(&ctx_mgr, &ctx_id, virtual_session, &mut kdf).await;
        let CkMechanismParams::Sp800108Kdf(kdf) = &kdf else { unreachable!() };
        let v_session_key = kdf.additional_derived_keys[0].key_handle;
        let v_token_key = kdf.additional_derived_keys[1].key_handle;

        let mut ssl3 = CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
            mac_size_bits: 128,
            key_size_bits: 128,
            iv_size_bits: 0,
            is_export: false,
            random_info: SslRandomData { client_random: vec![1; 32], server_random: vec![2; 32] },
            prf_hash_mechanism: 0,
            client_mac_secret_handle: 0,
            server_mac_secret_handle: 0,
            client_key_handle: 0xA2,
            server_key_handle: 0,
            client_iv: Vec::new().into(),
            server_iv: Vec::new().into(),
        });
        virtualize_key_mat_out_handles(&ctx_mgr, &ctx_id, virtual_session, false, &mut ssl3).await;
        let CkMechanismParams::Ssl3KeyMat(ssl3) = &ssl3 else { unreachable!() };
        let v_key_mat = ssl3.client_key_handle;

        // While the owner session lives, all three resolve and are recorded
        // private (m-1).
        for (name, virtual_handle) in [
            ("session sp800-108", v_session_key),
            ("token sp800-108", v_token_key),
            ("key-mat", v_key_mat),
        ] {
            let (resolved, recorded) = ctx_mgr
                .get_context(&ctx_id, |c| {
                    (
                        c.object_handles.resolve(VirtualHandle(virtual_handle)),
                        c.object_private.get(&VirtualHandle(virtual_handle)).copied(),
                    )
                })
                .await
                .unwrap();
            assert!(resolved.is_some(), "{name}: must resolve while the owner session lives");
            assert_eq!(recorded, Some(true), "{name}: must be recorded private (m-1)");
        }

        // Owner session closes: session OUT handles evict, the token key
        // survives with its privacy bit.
        ctx_mgr.get_context(&ctx_id, |c| c.remove_session(virtual_session)).await;
        for (name, virtual_handle, survives) in [
            ("session sp800-108", v_session_key, false),
            ("token sp800-108", v_token_key, true),
            ("key-mat", v_key_mat, false),
        ] {
            let (resolved, recorded) = ctx_mgr
                .get_context(&ctx_id, |c| {
                    (
                        c.object_handles.resolve(VirtualHandle(virtual_handle)),
                        c.object_private.get(&VirtualHandle(virtual_handle)).copied(),
                    )
                })
                .await
                .unwrap();
            assert_eq!(
                resolved.is_some(),
                survives,
                "{name}: post-close mapping presence must follow token classification"
            );
            assert_eq!(
                recorded,
                survives.then_some(true),
                "{name}: post-close privacy bit must evict with the mapping"
            );
        }

        // Post-close USE from a fresh logged-out session: the evicted handle
        // resolves unknown (forwarded as 0, so the backend verdict decides)
        // instead of tripping the stale-mapping 257 gate ...
        let fresh_session = ctx_mgr
            .get_context(&ctx_id, |c| c.register_session(BackendHandle(78), slot))
            .await
            .unwrap();
        let (_, backend_object) =
            resolve_session_and_object(&ctx, &ctx_id, fresh_session.0, v_session_key)
                .await
                .unwrap();
        assert_eq!(
            backend_object,
            CkObjectHandle(0),
            "evicted OUT handle must resolve unknown so the backend verdict decides"
        );
        // ... while the surviving private token key still refuses.
        assert_eq!(
            resolve_session_and_object(&ctx, &ctx_id, fresh_session.0, v_token_key).await,
            Err(CkRv::USER_NOT_LOGGED_IN),
            "surviving private token key must still refuse logged-out USE"
        );
    }
}

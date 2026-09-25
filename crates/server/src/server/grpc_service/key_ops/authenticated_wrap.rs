//! gRPC handlers for PKCS#11 3.2 authenticated wrap/unwrap operations (Wave 5).
//!
//! - `C_WrapKeyAuthenticated`
//! - `C_UnwrapKeyAuthenticated`

use std::sync::Arc;
use std::time::Instant;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_audit::EventClass;
use pkcs11_proxy_ng_types::{CkObjectHandle, CkRv};

use super::super::authorization::{extract_is_permitted, mechanism_permitted};
use super::super::convert_template;
use super::super::service_utils::{
    check_sanitize, input_from_wire, parse_mechanism, register_session_object_handle,
    resolve_session_and_two_objects, spawn_backend, template_declares_token_object,
};
use crate::server::context_manager::ClientContextId;
use crate::server::grpc_service::audit_events::emit_auth_event;
use crate::server::handle_map::VirtualHandle;

use crate::server::grpc_service::HandlerContext;

/// Outer dispatcher: captures timing + identity, delegates to the impl, then
/// emits a fail-closed `KeyMgmt` audit record (mirrors the C_WrapKey pattern).
pub(crate) async fn wrap_key_authenticated(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::WrapKeyAuthenticatedRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    let response = wrap_key_authenticated_impl(ctx, request).await?;
    let ck_rv = response.get_ref().ck_rv;
    if emit_auth_event(
        ctx,
        &ctx_id,
        "C_WrapKeyAuthenticated",
        EventClass::KeyMgmt,
        None,
        session_for_audit,
        ck_rv,
        started,
    )
    .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
            wrapped_key: Vec::new(),
            mechanism_parameter_out: Vec::new(),
        }));
    }
    Ok(response)
}

async fn wrap_key_authenticated_impl(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::WrapKeyAuthenticatedRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse>, Status> {
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, wrapping_key, key) = match resolve_session_and_two_objects(
        ctx,
        &ctx_id,
        req.session_handle,
        req.wrapping_key_handle,
        req.key_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse {
                ck_rv: rv.0,
                wrapped_key: Vec::new(),
                mechanism_parameter_out: Vec::new(),
            }));
        }
    };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse {
                ck_rv: rv.0,
                wrapped_key: Vec::new(),
                mechanism_parameter_out: Vec::new(),
            }));
        }
    };

    let aad = req.associated_data;
    let aad_null_len = req.associated_data_null_len;
    // ADR-0010 sanitize_inputs: validate NULL aad pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, aad_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse {
            ck_rv: rv.0,
            wrapped_key: Vec::new(),
            mechanism_parameter_out: Vec::new(),
        }));
    }

    // Mechanism policy gate (G3-PR3 Task 3): deny before backend call when the
    // principal's grant does not include this wrapping mechanism.
    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse {
            ck_rv: CkRv::MECHANISM_INVALID.0,
            wrapped_key: Vec::new(),
            mechanism_parameter_out: Vec::new(),
        }));
    }

    // Extract-deny gate (G2-PR2): wrapping a key exports its material; if the
    // principal's grant for this token has extract=Deny, reject before calling
    // the backend. The outer dispatcher emits a KeyMgmt audit record for both
    // successful authenticated-wrap and this denied attempt (ck_rv =
    // KEY_FUNCTION_NOT_PERMITTED). Mirrors the C_WrapKey gate in wrapping.rs.
    if !extract_is_permitted(ctx, &ctx_id, req.session_handle, req.key_handle).await? {
        return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse {
            ck_rv: CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            wrapped_key: Vec::new(),
            mechanism_parameter_out: Vec::new(),
        }));
    }

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.wrap_key_authenticated(
            session,
            &mechanism,
            wrapping_key,
            key,
            input_from_wire(&aad, aad_null_len),
        )
    })
    .await?;

    match result {
        Ok((wrapped_key, mechanism_parameter_out)) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse {
                ck_rv: CkRv::OK.0,
                wrapped_key,
                mechanism_parameter_out,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse {
            ck_rv: error.0,
            wrapped_key: Vec::new(),
            mechanism_parameter_out: Vec::new(),
        })),
    }
}

pub(crate) async fn unwrap_key_authenticated(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, unwrapping_key) = match super::super::service_utils::resolve_session_and_object(
        ctx,
        &ctx_id,
        req.session_handle,
        req.unwrapping_key_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse {
                ck_rv: rv.0,
                key_handle: 0,
                mechanism_parameter_out: Vec::new(),
            }));
        }
    };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse {
                ck_rv: rv.0,
                key_handle: 0,
                mechanism_parameter_out: Vec::new(),
            }));
        }
    };

    // Mechanism policy gate (G3-PR3 Task 3): deny before backend call when the
    // principal's grant does not include this unwrapping mechanism.
    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse {
            ck_rv: CkRv::MECHANISM_INVALID.0,
            key_handle: 0,
            mechanism_parameter_out: Vec::new(),
        }));
    }

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse {
                ck_rv: rv,
                key_handle: 0,
                mechanism_parameter_out: Vec::new(),
            }));
        }
    };

    let wrapped_key = req.wrapped_key;
    let wrapped_key_null_len = req.wrapped_key_null_len;
    let aad = req.associated_data;
    let aad_null_len = req.associated_data_null_len;
    // ADR-0010 sanitize_inputs: validate NULL wrapped_key/aad pointers before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, wrapped_key_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse {
            ck_rv: rv.0,
            key_handle: 0,
            mechanism_parameter_out: Vec::new(),
        }));
    }
    if let Err(rv) = check_sanitize(sanitize_inputs, aad_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse {
            ck_rv: rv.0,
            key_handle: 0,
            mechanism_parameter_out: Vec::new(),
        }));
    }
    // An authenticated-unwrapped key is a session object unless CKA_TOKEN is set (B2).
    let is_token = template_declares_token_object(&template);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.unwrap_key_authenticated(
            session,
            &mechanism,
            unwrapping_key,
            input_from_wire(&wrapped_key, wrapped_key_null_len),
            &template,
            input_from_wire(&aad, aad_null_len),
        )
    })
    .await?;

    match result {
        Ok((key, mechanism_parameter_out)) => {
            let key_handle = register_session_object_handle(
                ctx_mgr,
                &ctx_id,
                virtual_session,
                CkObjectHandle(key.0 as u64),
                is_token,
            )
            .await;
            Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse {
                ck_rv: CkRv::OK.0,
                key_handle,
                mechanism_parameter_out,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse {
            ck_rv: error.0,
            key_handle: 0,
            mechanism_parameter_out: Vec::new(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tonic::Request;

    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_types::*;

    use crate::config::{
        AuthConfig, ExtractPolicyConfig, GrantSpec, PolicyEntry, RichGrantConfig, TokenAccessSpec,
    };
    use crate::server::auth::policy::TokenPolicy;
    use crate::server::context_manager::{ClientContextId, ContextManager};
    use crate::server::grpc_service::HandlerContext;
    use crate::server::handle_map::BackendHandle;

    const MTLS_IDENTITY: &str = "x509:issuer=CN=Root CA;subject=CN=client";

    fn deny_policy() -> TokenPolicy {
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: MTLS_IDENTITY.into(),
                tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                    token: "label:MockToken".into(),
                    classes: None,
                    mechanisms: None,
                    extract: ExtractPolicyConfig::Deny,
                    objects: None,
                })]),
            }],
        })
        .unwrap()
    }

    fn allow_policy() -> TokenPolicy {
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: MTLS_IDENTITY.into(),
                tokens: TokenAccessSpec::Specific(vec![GrantSpec::Bare("label:MockToken".into())]),
            }],
        })
        .unwrap()
    }

    async fn setup(
        policy: TokenPolicy,
        identity: Option<String>,
    ) -> (HandlerContext, ClientContextId, u64) {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(CkSlotId(0)).await;
        let ctx_id = ctx_mgr.create_context(identity).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| ctx.register_session(BackendHandle(1), CkSlotId(0)))
            .await
            .unwrap();
        ctx_mgr.cache_token_info(CkSlotId(0), "MockToken".into(), "0001".into());

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = Arc::new(policy);
        (ctx, ctx_id, session_vh.0)
    }

    fn wrap_auth_request(
        ctx_id: &ClientContextId,
        session_handle: u64,
    ) -> pkcs11_proxy_ng_proto::WrapKeyAuthenticatedRequest {
        pkcs11_proxy_ng_proto::WrapKeyAuthenticatedRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                mechanism_type: CkMechanismType::RSA_PKCS.0,
                params: None,
            }),
            wrapping_key_handle: 0,
            key_handle: 0,
            associated_data: Vec::new(),
            associated_data_null_len: None,
        }
    }

    #[tokio::test]
    async fn wrap_key_authenticated_denied_with_extract_deny_grant() {
        // C1: C_WrapKeyAuthenticated must be blocked for a principal whose grant
        // has extract=Deny — the same extract-deny gate that guards C_WrapKey.
        let (ctx, ctx_id, session_handle) = setup(deny_policy(), Some(MTLS_IDENTITY.into())).await;

        let response = super::wrap_key_authenticated(
            &ctx,
            Request::new(wrap_auth_request(&ctx_id, session_handle)),
        )
        .await
        .unwrap();

        assert_eq!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "C_WrapKeyAuthenticated with extract=Deny must return KEY_FUNCTION_NOT_PERMITTED"
        );
    }

    #[tokio::test]
    async fn wrap_key_authenticated_proceeds_with_extract_allow_grant() {
        let (ctx, ctx_id, session_handle) = setup(allow_policy(), Some(MTLS_IDENTITY.into())).await;

        let response = super::wrap_key_authenticated(
            &ctx,
            Request::new(wrap_auth_request(&ctx_id, session_handle)),
        )
        .await
        .unwrap();

        // MockBackend will fail (no real objects) but must NOT return
        // KEY_FUNCTION_NOT_PERMITTED — the extract gate must not block an allowed principal.
        assert_ne!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "C_WrapKeyAuthenticated with extract=Allow must reach the backend"
        );
    }

    #[tokio::test]
    async fn wrap_key_authenticated_unauthenticated_proceeds() {
        // No identity → unauthenticated; extract-deny is opt-in so must pass through.
        let (ctx, ctx_id, session_handle) = setup(deny_policy(), None).await;

        let response = super::wrap_key_authenticated(
            &ctx,
            Request::new(wrap_auth_request(&ctx_id, session_handle)),
        )
        .await
        .unwrap();

        assert_ne!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "unauthenticated peer must not be blocked by extract-deny"
        );
    }
}

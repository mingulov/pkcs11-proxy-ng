use std::sync::Arc;
use std::time::Instant;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_audit::EventClass;
use pkcs11_proxy_ng_types::{CkObjectHandle, CkRv};

use super::super::authorization::extract_is_permitted;
use super::super::ck_result_to_rv;
use super::super::convert_template;
use super::super::mechanism_handles::remap_mechanism_handles;
use super::super::service_utils::{
    check_sanitize, input_from_wire, parse_mechanism, register_session_object_handle,
    resolve_session_and_object, resolve_session_and_two_objects, spawn_backend,
    template_declares_token_object,
};
use crate::server::context_manager::ClientContextId;
use crate::server::grpc_service::audit_events::emit_auth_event;
use crate::server::handle_map::VirtualHandle;

use crate::server::grpc_service::HandlerContext;

/// Outer dispatcher: captures timing + identity, delegates to the impl, then
/// emits a fail-closed `KeyMgmt` audit record.
pub(crate) async fn wrap_key(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::WrapKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::WrapKeyResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    let response = wrap_key_impl(ctx, request).await?;
    let ck_rv = response.get_ref().ck_rv;
    if emit_auth_event(
        ctx,
        &ctx_id,
        "C_WrapKey",
        EventClass::KeyMgmt,
        None,
        session_for_audit,
        ck_rv,
        started,
    )
    .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
            wrapped_key: Vec::new(),
        }));
    }
    Ok(response)
}

async fn wrap_key_impl(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::WrapKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::WrapKeyResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, wrapping_key, key) = match resolve_session_and_two_objects(
        ctx_mgr,
        &ctx_id,
        req.session_handle,
        req.wrapping_key_handle,
        req.key_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyResponse {
                ck_rv: rv.0,
                wrapped_key: Vec::new(),
            }));
        }
    };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyResponse {
                ck_rv: rv.0,
                wrapped_key: Vec::new(),
            }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters.
    if let Err(rv) = remap_mechanism_handles(ctx_mgr, &ctx_id, &mut mechanism).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyResponse {
            ck_rv: rv.0,
            wrapped_key: Vec::new(),
        }));
    }

    // Extract-deny gate (G2-PR2): wrapping a key exports its material; if the
    // principal's grant for this token has extract=Deny, reject before calling
    // the backend. The outer `wrap_key` dispatcher will still emit a KeyMgmt
    // audit record for this denied attempt (ck_rv is KEY_FUNCTION_NOT_PERMITTED).
    if !extract_is_permitted(ctx, &ctx_id, req.session_handle).await? {
        return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyResponse {
            ck_rv: CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            wrapped_key: Vec::new(),
        }));
    }

    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.wrap_key(session, &mechanism, wrapping_key, key)).await?;
    let (ck_rv, wrapped_key) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyResponse {
        ck_rv,
        wrapped_key: wrapped_key.unwrap_or_default(),
    }))
}

/// Outer dispatcher: captures timing + identity, delegates to the impl, then
/// emits a fail-closed `KeyMgmt` audit record.
pub(crate) async fn unwrap_key(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::UnwrapKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::UnwrapKeyResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());
    let session_for_audit = Some(request.get_ref().session_handle);
    let response = unwrap_key_impl(ctx, request).await?;
    let ck_rv = response.get_ref().ck_rv;
    if emit_auth_event(
        ctx,
        &ctx_id,
        "C_UnwrapKey",
        EventClass::KeyMgmt,
        None,
        session_for_audit,
        ck_rv,
        started,
    )
    .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
            key_handle: 0,
        }));
    }
    Ok(response)
}

async fn unwrap_key_impl(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::UnwrapKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::UnwrapKeyResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, unwrapping_key) = match resolve_session_and_object(
        ctx_mgr,
        &ctx_id,
        req.session_handle,
        req.unwrapping_key_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
            }));
        }
    };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
            }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters.
    if let Err(rv) = remap_mechanism_handles(ctx_mgr, &ctx_id, &mut mechanism).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
        }));
    }

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
                ck_rv: rv,
                key_handle: 0,
            }));
        }
    };

    // An unwrapped key is a session object unless CKA_TOKEN is set (B2).
    let is_token = template_declares_token_object(&template);
    let virtual_session = VirtualHandle(req.session_handle);
    let wrapped_key = req.wrapped_key;
    let wrapped_key_null_len = req.wrapped_key_null_len;
    // ADR-0010 sanitize_inputs: validate NULL wrapped_key pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, wrapped_key_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.unwrap_key(
            session,
            &mechanism,
            unwrapping_key,
            input_from_wire(&wrapped_key, wrapped_key_null_len),
            &template,
        )
    })
    .await?;

    match result {
        Ok(object) => {
            let key_handle = register_session_object_handle(
                ctx_mgr,
                &ctx_id,
                virtual_session,
                CkObjectHandle(object.0 as u64),
                is_token,
            )
            .await;
            Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
                ck_rv: CkRv::OK.0,
                key_handle,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
            ck_rv: error.0,
            key_handle: 0,
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

    fn wrap_request(
        ctx_id: &ClientContextId,
        session_handle: u64,
    ) -> pkcs11_proxy_ng_proto::WrapKeyRequest {
        pkcs11_proxy_ng_proto::WrapKeyRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                mechanism_type: CkMechanismType::RSA_PKCS.0,
                params: None,
            }),
            wrapping_key_handle: 0,
            key_handle: 0,
        }
    }

    #[tokio::test]
    async fn wrap_key_denied_with_extract_deny_grant() {
        let (ctx, ctx_id, session_handle) = setup(deny_policy(), Some(MTLS_IDENTITY.into())).await;

        let response = super::wrap_key(&ctx, Request::new(wrap_request(&ctx_id, session_handle)))
            .await
            .unwrap();

        assert_eq!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "C_WrapKey with extract=Deny must return KEY_FUNCTION_NOT_PERMITTED"
        );
    }

    #[tokio::test]
    async fn wrap_key_proceeds_with_extract_allow_grant() {
        let (ctx, ctx_id, session_handle) = setup(allow_policy(), Some(MTLS_IDENTITY.into())).await;

        let response = super::wrap_key(&ctx, Request::new(wrap_request(&ctx_id, session_handle)))
            .await
            .unwrap();

        // The MockBackend will fail (no real objects), but it must NOT be
        // KEY_FUNCTION_NOT_PERMITTED — the gate must not block an allowed principal.
        assert_ne!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "C_WrapKey with extract=Allow must reach the backend"
        );
    }

    #[tokio::test]
    async fn wrap_key_unauthenticated_proceeds() {
        // No identity → unauthenticated; extract-deny is opt-in so must pass through.
        let policy = deny_policy();
        let (ctx, ctx_id, session_handle) = setup(policy, None).await;

        let response = super::wrap_key(&ctx, Request::new(wrap_request(&ctx_id, session_handle)))
            .await
            .unwrap();

        assert_ne!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "unauthenticated peer must not be blocked by extract-deny"
        );
    }
}

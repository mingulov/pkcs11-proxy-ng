// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use std::sync::Arc;
use std::time::Instant;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_audit::EventClass;
use pkcs11_proxy_ng_types::{CkObjectHandle, CkRv, SecretBytes};

use super::super::authorization::mechanism_permitted;
use super::super::ck_result_to_rv;
use super::super::convert_template_opt;
use super::super::mechanism_handles::remap_mechanism_handles;
use super::super::service_utils::{
    check_sanitize, ensure_private_mint_allowed, input_from_wire, parse_mechanism,
    register_session_object_handle, resolve_session_and_object, spawn_backend,
    template_declares_private_object, template_declares_token_object,
};
use crate::server::context_manager::ClientContextId;
use crate::server::grpc_service::audit_events::emit_auth_event;
use crate::server::handle_map::VirtualHandle;

use crate::server::grpc_service::HandlerContext;

/// Share preparation and outcome auditing with both exact wrapping adapters.
pub(crate) async fn wrap_key(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::WrapKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::WrapKeyResponse>, Status> {
    let started = Instant::now();
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    let outcome = async {
        let p = match super::wrap_preparation::prepare_wrap(
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
        let backend = Arc::clone(&ctx.backend);
        spawn_backend(move || backend.wrap_key(p.session, &p.mechanism, p.wrapping_key, p.key))
            .await
    }
    .await;
    let result = super::super::audit_events::audit_key_outcome(
        ctx,
        &ctx_id,
        "C_WrapKey",
        req.session_handle,
        started,
        outcome,
        |_| CkRv::OK,
    )?;
    let (ck_rv, wrapped_key) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyResponse {
        ck_rv,
        wrapped_key: secret_to_plain(&wrapped_key.unwrap_or_default()),
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
        ctx,
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

    // B1: remap object handles embedded in the mechanism parameters;
    // gate each through per-object authz when active (C1).
    if let Err(rv) =
        remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
        }));
    }

    // Mechanism policy gate (G3-PR3 Task 3): deny before backend call when the
    // principal's grant does not include this unwrapping mechanism.
    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
            ck_rv: CkRv::MECHANISM_INVALID.0,
            key_handle: 0,
        }));
    }

    let template = match convert_template_opt(&req.template, req.template_null) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
                ck_rv: rv,
                key_handle: 0,
            }));
        }
    };

    // A NULL template carries no attributes; classification treats it as empty.
    let template_view = template.as_deref().unwrap_or(&[]);

    // D6(1): refuse minting a private object while logically logged out.
    // (The private unwrapping key itself is refused by the USE check inside
    // resolve_session_and_object above.)
    if let Err(rv) =
        ensure_private_mint_allowed(ctx_mgr, &ctx_id, req.session_handle, template_view).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
        }));
    }

    // An unwrapped key is a session object unless CKA_TOKEN is set (B2). The
    // privacy bit is recorded for the D6(1) USE enforcement.
    let is_token = template_declares_token_object(template_view);
    let is_private = template_declares_private_object(template_view);
    let virtual_session = VirtualHandle(req.session_handle);
    let wrapped_key = SecretBytes::new(req.wrapped_key);
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
        wrapped_key.expose(|raw| {
            backend.unwrap_key(
                session,
                &mechanism,
                unwrapping_key,
                input_from_wire(raw, wrapped_key_null_len),
                template.as_deref(),
            )
        })
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
                Some(is_private),
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
        AuthConfig, ExtractPolicyConfig, GrantSpec, ObjectAclRichConfig, ObjectAclSpec,
        PolicyEntry, RichGrantConfig, TokenAccessSpec,
    };
    use crate::server::auth::policy::TokenPolicy;
    use crate::server::context_manager::{ClientContextId, ContextManager, ObjectMetadata};
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
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(identity).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(
                    BackendHandle(1),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );

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

    // -----------------------------------------------------------------------
    // Per-object extract override tests (Task 4)
    // -----------------------------------------------------------------------

    /// Build a policy where the grant's extract is `grant_extract` and the
    /// object at `object_uid_hex` has a per-object extract override of
    /// `per_object_extract`.
    fn per_object_policy(
        grant_extract: ExtractPolicyConfig,
        object_uid_hex: &str,
        per_object_extract: Option<ExtractPolicyConfig>,
    ) -> TokenPolicy {
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: MTLS_IDENTITY.into(),
                tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                    token: "label:MockToken".into(),
                    classes: None,
                    mechanisms: None,
                    extract: grant_extract,
                    objects: Some(vec![ObjectAclSpec::Rich(ObjectAclRichConfig {
                        id: object_uid_hex.into(),
                        extract: per_object_extract,
                    })]),
                })]),
            }],
        })
        .unwrap()
    }

    /// Setup helper that also registers an object handle and pre-populates the
    /// metadata cache for it. Returns `(ctx, ctx_id, session_vh.0, object_vh.0)`.
    async fn setup_with_object(
        policy: TokenPolicy,
        identity: Option<String>,
        object_uid: Vec<u8>,
    ) -> (HandlerContext, ClientContextId, u64, u64) {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(identity).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(
                    BackendHandle(1),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );

        // Register a virtual object handle and cache its metadata so
        // `resolve_uid_for_extract` can resolve it without a backend round-trip.
        let object_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| ctx.object_handles.insert(BackendHandle(2)))
            .await
            .unwrap();
        ctx_mgr
            .cache_object_metadata(
                &ctx_id,
                object_vh.0,
                ObjectMetadata {
                    unique_id: object_uid.into(),
                    class: Some(CkObjectClass::SECRET_KEY),
                    is_token: false,
                },
            )
            .await;

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = Arc::new(policy);
        (ctx, ctx_id, session_vh.0, object_vh.0)
    }

    /// Build a WrapKeyRequest that targets a specific key handle.
    fn wrap_request_with_key(
        ctx_id: &ClientContextId,
        session_handle: u64,
        key_handle: u64,
    ) -> pkcs11_proxy_ng_proto::WrapKeyRequest {
        pkcs11_proxy_ng_proto::WrapKeyRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                mechanism_type: CkMechanismType::RSA_PKCS.0,
                params: None,
            }),
            wrapping_key_handle: 0,
            key_handle,
        }
    }

    #[tokio::test]
    async fn wrap_key_per_object_deny_blocks_when_grant_allows() {
        // Grant-level extract=Allow, but the specific key object has a per-object
        // Deny override → must be rejected.
        const OBJ_UID_HEX: &str = "aabbcc";
        let uid = hex::decode(OBJ_UID_HEX).unwrap();
        let policy = per_object_policy(
            ExtractPolicyConfig::Allow,
            OBJ_UID_HEX,
            Some(ExtractPolicyConfig::Deny),
        );
        let (ctx, ctx_id, session_handle, key_handle) =
            setup_with_object(policy, Some(MTLS_IDENTITY.into()), uid).await;

        let response = super::wrap_key(
            &ctx,
            Request::new(wrap_request_with_key(&ctx_id, session_handle, key_handle)),
        )
        .await
        .unwrap();

        assert_eq!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "per-object Deny override must block wrap even when grant-level allows"
        );
    }

    #[tokio::test]
    async fn wrap_key_per_object_allow_overrides_grant_deny() {
        // Grant-level extract=Deny, but the specific key object has a per-object
        // Allow override → must be permitted (reaches the backend).
        const OBJ_UID_HEX: &str = "112233";
        let uid = hex::decode(OBJ_UID_HEX).unwrap();
        let policy = per_object_policy(
            ExtractPolicyConfig::Deny,
            OBJ_UID_HEX,
            Some(ExtractPolicyConfig::Allow),
        );
        let (ctx, ctx_id, session_handle, key_handle) =
            setup_with_object(policy, Some(MTLS_IDENTITY.into()), uid).await;

        let response = super::wrap_key(
            &ctx,
            Request::new(wrap_request_with_key(&ctx_id, session_handle, key_handle)),
        )
        .await
        .unwrap();

        assert_ne!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "per-object Allow override must permit wrap even when grant-level denies"
        );
    }

    #[tokio::test]
    async fn wrap_key_per_object_none_inherits_grant_deny() {
        // Object in the list with extract=None → inherits grant-level Deny → blocked.
        const OBJ_UID_HEX: &str = "deadbe";
        let uid = hex::decode(OBJ_UID_HEX).unwrap();
        let policy = per_object_policy(ExtractPolicyConfig::Deny, OBJ_UID_HEX, None);
        let (ctx, ctx_id, session_handle, key_handle) =
            setup_with_object(policy, Some(MTLS_IDENTITY.into()), uid).await;

        let response = super::wrap_key(
            &ctx,
            Request::new(wrap_request_with_key(&ctx_id, session_handle, key_handle)),
        )
        .await
        .unwrap();

        assert_eq!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "per-object None override must inherit grant-level Deny"
        );
    }

    #[tokio::test]
    async fn wrap_key_per_object_none_inherits_grant_allow() {
        // Object in the list with extract=None → inherits grant-level Allow → permitted.
        const OBJ_UID_HEX: &str = "cafebb";
        let uid = hex::decode(OBJ_UID_HEX).unwrap();
        let policy = per_object_policy(ExtractPolicyConfig::Allow, OBJ_UID_HEX, None);
        let (ctx, ctx_id, session_handle, key_handle) =
            setup_with_object(policy, Some(MTLS_IDENTITY.into()), uid).await;

        let response = super::wrap_key(
            &ctx,
            Request::new(wrap_request_with_key(&ctx_id, session_handle, key_handle)),
        )
        .await
        .unwrap();

        assert_ne!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "per-object None override must inherit grant-level Allow"
        );
    }

    #[tokio::test]
    async fn wrap_key_unauthenticated_bypasses_per_object_deny() {
        // Unauthenticated peer: per-object deny is irrelevant; must pass through.
        const OBJ_UID_HEX: &str = "ff0011";
        let uid = hex::decode(OBJ_UID_HEX).unwrap();
        let policy = per_object_policy(
            ExtractPolicyConfig::Deny,
            OBJ_UID_HEX,
            Some(ExtractPolicyConfig::Deny),
        );
        // No identity → unauthenticated; per-object extract is opt-in for
        // authenticated identities only.
        let (ctx, ctx_id, session_handle, key_handle) = setup_with_object(policy, None, uid).await;

        let response = super::wrap_key(
            &ctx,
            Request::new(wrap_request_with_key(&ctx_id, session_handle, key_handle)),
        )
        .await
        .unwrap();

        assert_ne!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "unauthenticated peer must bypass per-object extract deny"
        );
    }
}

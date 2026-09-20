// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use std::sync::Arc;
use std::time::Instant;

use pkcs11_proxy_ng_audit::EventClass;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::{CkInBuf, CkMechanism, CkRv, SecretBytes};
use tonic::{Request, Response, Status};

use super::super::authorization::mechanism_permitted;
use super::super::ck_result_to_rv;
use super::super::mechanism_handles::remap_mechanism_handles;
use super::super::service_utils::{
    ck_rv_only, mechanism_output_to_proto, parse_mechanism, resolve_session,
    resolve_session_and_key, spawn_backend,
};
use crate::server::context_manager::ClientContextId;
use crate::server::grpc_service::audit_events::emit_auth_event;

use crate::server::grpc_service::HandlerContext;
pub(crate) async fn encrypt_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::EncryptInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptInitResponse {
            ck_rv: CkRv::ARGUMENTS_BAD.0,
            mechanism_out: None,
        }));
    }

    if req.mechanism.is_none() {
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(session) => session,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptInitResponse {
                    ck_rv: rv.0,
                    mechanism_out: None,
                }));
            }
        };
        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || backend.encrypt_init_cancel(session)).await?;
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptInitResponse {
            ck_rv: ck_rv_only(result),
            mechanism_out: None,
        }));
    }

    let (session, key) =
        match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptInitResponse {
                    ck_rv: rv.0,
                    mechanism_out: None,
                }));
            }
        };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptInitResponse {
                ck_rv: rv.0,
                mechanism_out: None,
            }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters;
    // gate each through per-object authz when active (C1).
    if let Err(rv) =
        remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptInitResponse {
            ck_rv: rv.0,
            mechanism_out: None,
        }));
    }

    let mechanism_type = mechanism.mechanism_type;
    // Mechanism policy gate (G3-PR3 Task 3): deny before backend call when the
    // principal's grant does not include this mechanism type. Transparent (zero
    // overhead) when per_mechanism_active() is false.
    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
            mechanism_out: None,
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.encrypt_init(session, &mechanism, key)).await?;
    let (ck_rv, params) = ck_result_to_rv(result);
    let mechanism_out = match params
        .flatten()
        .map(|params| {
            pkcs11_proxy_ng_proto::Mechanism::try_from(&CkMechanism {
                mechanism_type,
                params: Some(params),
            })
        })
        .transpose()
    {
        Ok(mechanism_out) => mechanism_out,
        // The backend returned output params the wire cannot represent
        // (e.g. a nested template, W1-C8-01): fail loudly rather than
        // report success with silently dropped output.
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptInitResponse {
                ck_rv: rv.0,
                mechanism_out: None,
            }));
        }
    };
    Ok(Response::new(pkcs11_proxy_ng_proto::EncryptInitResponse { ck_rv, mechanism_out }))
}

// NOTE: legacy per-op RPC — not used by the shim; NULL-input class not forwarded (ADR-0010 Scope 2 covers the *_exact paths).
pub(crate) async fn encrypt(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::EncryptRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptResponse>, Status> {
    let started = Instant::now();
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptResponse {
                ck_rv: rv.0,
                encrypted_data: Vec::new(),
                mechanism_out: None,
            }));
        }
    };

    let data = SecretBytes::new(req.data);
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || data.expose(|raw| backend.encrypt(session, CkInBuf::Bytes(raw))))
            .await?;
    let (ck_rv, encrypted_data) = ck_result_to_rv(result);
    let mechanism_out = session_mechanism_out_if_ok(backend_ref, session, ck_rv);
    // Opt-in data-plane audit: emit fail-open; never reject the op on a dropped record.
    if ctx.audit.as_ref().is_some_and(|a| a.data_plane_enabled()) {
        let _ = emit_auth_event(
            ctx,
            &ctx_id,
            "C_Encrypt",
            EventClass::DataPlane,
            None,
            Some(req.session_handle),
            ck_rv,
            started,
        );
    }
    Ok(Response::new(pkcs11_proxy_ng_proto::EncryptResponse {
        ck_rv,
        encrypted_data: secret_to_plain(&encrypted_data.unwrap_or_default()),
        mechanism_out,
    }))
}

// NOTE: legacy per-op RPC — not used by the shim; NULL-input class not forwarded (ADR-0010 Scope 2 covers the *_exact paths).
pub(crate) async fn encrypt_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::EncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptUpdateResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptUpdateResponse {
                ck_rv: rv.0,
                encrypted_part: Vec::new(),
                mechanism_out: None,
            }));
        }
    };

    let part = SecretBytes::new(req.part);
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        part.expose(|raw| backend.encrypt_update(session, CkInBuf::Bytes(raw)))
    })
    .await?;
    let (ck_rv, encrypted_part) = ck_result_to_rv(result);
    let mechanism_out = session_mechanism_out_if_ok(backend_ref, session, ck_rv);
    Ok(Response::new(pkcs11_proxy_ng_proto::EncryptUpdateResponse {
        ck_rv,
        encrypted_part: secret_to_plain(&encrypted_part.unwrap_or_default()),
        mechanism_out,
    }))
}

pub(crate) async fn encrypt_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::EncryptFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptFinalResponse>, Status> {
    let started = Instant::now();
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptFinalResponse {
                ck_rv: rv.0,
                last_encrypted_part: Vec::new(),
                mechanism_out: None,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.encrypt_final(session)).await?;
    let (ck_rv, last_encrypted_part) = ck_result_to_rv(result);
    let mechanism_out = session_mechanism_out_if_ok(backend_ref, session, ck_rv);
    // Opt-in data-plane audit: emit fail-open; never reject the op on a dropped record.
    if ctx.audit.as_ref().is_some_and(|a| a.data_plane_enabled()) {
        let _ = emit_auth_event(
            ctx,
            &ctx_id,
            "C_Encrypt",
            EventClass::DataPlane,
            None,
            Some(req.session_handle),
            ck_rv,
            started,
        );
    }
    Ok(Response::new(pkcs11_proxy_ng_proto::EncryptFinalResponse {
        ck_rv,
        last_encrypted_part: secret_to_plain(&last_encrypted_part.unwrap_or_default()),
        mechanism_out,
    }))
}

pub(crate) async fn decrypt_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecryptInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptInitResponse {
            ck_rv: CkRv::ARGUMENTS_BAD.0,
            mechanism_out: None,
        }));
    }

    if req.mechanism.is_none() {
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(session) => session,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptInitResponse {
                    ck_rv: rv.0,
                    mechanism_out: None,
                }));
            }
        };
        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || backend.decrypt_init_cancel(session)).await?;
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptInitResponse {
            ck_rv: ck_rv_only(result),
            mechanism_out: None,
        }));
    }

    let (session, key) =
        match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptInitResponse {
                    ck_rv: rv.0,
                    mechanism_out: None,
                }));
            }
        };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptInitResponse {
                ck_rv: rv.0,
                mechanism_out: None,
            }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters;
    // gate each through per-object authz when active (C1).
    if let Err(rv) =
        remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptInitResponse {
            ck_rv: rv.0,
            mechanism_out: None,
        }));
    }

    let mechanism_type = mechanism.mechanism_type;
    // Mechanism policy gate (G3-PR3 Task 3): deny before backend call when the
    // principal's grant does not include this mechanism type.
    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
            mechanism_out: None,
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.decrypt_init(session, &mechanism, key)).await?;
    let (ck_rv, params) = ck_result_to_rv(result);
    let mechanism_out = match params
        .flatten()
        .map(|params| {
            pkcs11_proxy_ng_proto::Mechanism::try_from(&CkMechanism {
                mechanism_type,
                params: Some(params),
            })
        })
        .transpose()
    {
        Ok(mechanism_out) => mechanism_out,
        // The backend returned output params the wire cannot represent
        // (e.g. a nested template, W1-C8-01): fail loudly rather than
        // report success with silently dropped output.
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptInitResponse {
                ck_rv: rv.0,
                mechanism_out: None,
            }));
        }
    };
    Ok(Response::new(pkcs11_proxy_ng_proto::DecryptInitResponse { ck_rv, mechanism_out }))
}

// NOTE: legacy per-op RPC — not used by the shim; NULL-input class not forwarded (ADR-0010 Scope 2 covers the *_exact paths).
pub(crate) async fn decrypt(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecryptRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptResponse>, Status> {
    let started = Instant::now();
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptResponse {
                ck_rv: rv.0,
                data: Vec::new(),
                mechanism_out: None,
            }));
        }
    };

    let encrypted_data = req.encrypted_data;
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.decrypt(session, CkInBuf::Bytes(&encrypted_data))).await?;
    let (ck_rv, data) = ck_result_to_rv(result);
    let mechanism_out = session_mechanism_out_if_ok(backend_ref, session, ck_rv);
    // Opt-in data-plane audit: emit fail-open; never reject the op on a dropped record.
    if ctx.audit.as_ref().is_some_and(|a| a.data_plane_enabled()) {
        let _ = emit_auth_event(
            ctx,
            &ctx_id,
            "C_Decrypt",
            EventClass::DataPlane,
            None,
            Some(req.session_handle),
            ck_rv,
            started,
        );
    }
    Ok(Response::new(pkcs11_proxy_ng_proto::DecryptResponse {
        ck_rv,
        data: secret_to_plain(&data.unwrap_or_default()),
        mechanism_out,
    }))
}

// NOTE: legacy per-op RPC — not used by the shim; NULL-input class not forwarded (ADR-0010 Scope 2 covers the *_exact paths).
pub(crate) async fn decrypt_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptUpdateResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptUpdateResponse {
                ck_rv: rv.0,
                part: Vec::new(),
                mechanism_out: None,
            }));
        }
    };

    let encrypted_part = req.encrypted_part;
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.decrypt_update(session, CkInBuf::Bytes(&encrypted_part)))
            .await?;
    let (ck_rv, part) = ck_result_to_rv(result);
    let mechanism_out = session_mechanism_out_if_ok(backend_ref, session, ck_rv);
    Ok(Response::new(pkcs11_proxy_ng_proto::DecryptUpdateResponse {
        ck_rv,
        part: secret_to_plain(&part.unwrap_or_default()),
        mechanism_out,
    }))
}

pub(crate) async fn decrypt_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecryptFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptFinalResponse>, Status> {
    let started = Instant::now();
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptFinalResponse {
                ck_rv: rv.0,
                last_part: Vec::new(),
                mechanism_out: None,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.decrypt_final(session)).await?;
    let (ck_rv, last_part) = ck_result_to_rv(result);
    let mechanism_out = session_mechanism_out_if_ok(backend_ref, session, ck_rv);
    // Opt-in data-plane audit: emit fail-open; never reject the op on a dropped record.
    if ctx.audit.as_ref().is_some_and(|a| a.data_plane_enabled()) {
        let _ = emit_auth_event(
            ctx,
            &ctx_id,
            "C_Decrypt",
            EventClass::DataPlane,
            None,
            Some(req.session_handle),
            ck_rv,
            started,
        );
    }
    Ok(Response::new(pkcs11_proxy_ng_proto::DecryptFinalResponse {
        ck_rv,
        last_part: secret_to_plain(&last_part.unwrap_or_default()),
        mechanism_out,
    }))
}

/// Read the cached mechanism's `output_params()` from the backend for a
/// session, but only when the preceding op returned `CKR_OK`. Used by
/// the simple Encrypt/Decrypt + Update/Final handlers to surface HSM
/// mutations (e.g. AES-GCM IV) without locally re-deriving them.
fn session_mechanism_out_if_ok(
    backend: &Arc<dyn Pkcs11Backend>,
    session: pkcs11_proxy_ng_types::CkSessionHandle,
    ck_rv: u64,
) -> Option<pkcs11_proxy_ng_proto::Mechanism> {
    if ck_rv != pkcs11_proxy_ng_types::CkRv::OK.0 {
        return None;
    }
    backend.session_output_mechanism_params(session).and_then(mechanism_output_to_proto)
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

    const PEER_IDENTITY: &str = "uid=1000";

    fn mechanism_grant_policy(allowed_mechs: Vec<String>) -> TokenPolicy {
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: PEER_IDENTITY.into(),
                tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                    token: "label:MockToken".into(),
                    classes: None,
                    mechanisms: Some(allowed_mechs),
                    extract: ExtractPolicyConfig::Allow,
                    objects: None,
                })]),
            }],
        })
        .unwrap()
    }

    fn no_mechanism_grant_policy() -> TokenPolicy {
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: PEER_IDENTITY.into(),
                tokens: TokenAccessSpec::Specific(vec![GrantSpec::Bare("label:MockToken".into())]),
            }],
        })
        .unwrap()
    }

    async fn setup(
        policy: TokenPolicy,
        identity: Option<String>,
    ) -> (HandlerContext, ClientContextId, u64) {
        let mock = Arc::new(MockBackend::new(
            vec![CkSlotId(0)],
            vec![CkMechanismType::AES_GCM, CkMechanismType::RSA_PKCS],
        ));
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

    fn encrypt_init_request(
        ctx_id: &ClientContextId,
        session_handle: u64,
        mech_type: CkMechanismType,
    ) -> pkcs11_proxy_ng_proto::EncryptInitRequest {
        pkcs11_proxy_ng_proto::EncryptInitRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                mechanism_type: mech_type.0,
                params: None,
            }),
            key_handle: 0,
        }
    }

    #[tokio::test]
    async fn encrypt_init_allowed_mechanism_proceeds() {
        // A principal with mechanisms=["CKM_RSA_PKCS"] may use RSA_PKCS.
        let (ctx, ctx_id, session) =
            setup(mechanism_grant_policy(vec!["CKM_RSA_PKCS".into()]), Some(PEER_IDENTITY.into()))
                .await;
        let resp = super::encrypt_init(
            &ctx,
            Request::new(encrypt_init_request(&ctx_id, session, CkMechanismType::RSA_PKCS)),
        )
        .await
        .unwrap();
        assert_ne!(
            resp.into_inner().ck_rv,
            CkRv::MECHANISM_INVALID.0,
            "allowed mechanism must NOT return CKR_MECHANISM_INVALID"
        );
    }

    #[tokio::test]
    async fn encrypt_init_unlisted_mechanism_returns_mechanism_invalid() {
        // A principal with mechanisms=["CKM_RSA_PKCS"] must be denied for AES_GCM.
        let (ctx, ctx_id, session) =
            setup(mechanism_grant_policy(vec!["CKM_RSA_PKCS".into()]), Some(PEER_IDENTITY.into()))
                .await;
        let resp = super::encrypt_init(
            &ctx,
            Request::new(encrypt_init_request(&ctx_id, session, CkMechanismType::AES_GCM)),
        )
        .await
        .unwrap();
        assert_eq!(
            resp.into_inner().ck_rv,
            CkRv::MECHANISM_INVALID.0,
            "mechanism not in grant list must return CKR_MECHANISM_INVALID without a backend call"
        );
    }

    #[tokio::test]
    async fn encrypt_init_no_mechanism_grant_any_mechanism_allowed() {
        // A principal with mechanisms=None (absent) → any mechanism permitted (transparent).
        let policy = no_mechanism_grant_policy();
        assert!(!policy.per_mechanism_active(), "no mechanisms list → gate must be inactive");
        let (ctx, ctx_id, session) = setup(policy, Some(PEER_IDENTITY.into())).await;
        // AES_GCM is not in RSA_PKCS list but there is no restriction
        let resp = super::encrypt_init(
            &ctx,
            Request::new(encrypt_init_request(&ctx_id, session, CkMechanismType::AES_GCM)),
        )
        .await
        .unwrap();
        assert_ne!(
            resp.into_inner().ck_rv,
            CkRv::MECHANISM_INVALID.0,
            "no mechanism grant → gate must be transparent (any mechanism allowed)"
        );
    }

    // -----------------------------------------------------------------------
    // Data-plane audit tests (Task 2)
    // -----------------------------------------------------------------------

    use std::path::PathBuf;

    use crate::config::AuditConfig;
    use crate::server::audit::{AuditSink, spawn_audit_sink};

    fn dp_temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("cipher-dp-{}-{}", std::process::id(), tag))
    }

    fn dp_make_audit_dir(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn dp_make_sink(dir: &std::path::Path, data_plane: bool) -> AuditSink {
        let cfg = AuditConfig { dir: Some(dir.to_path_buf()), data_plane, ..Default::default() };
        spawn_audit_sink(&cfg).unwrap().expect("sink")
    }

    fn dp_parse_records(dir: &std::path::Path) -> Vec<pkcs11_proxy_ng_audit::AuditRecord> {
        let content = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap_or_default();
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| pkcs11_proxy_ng_audit::record::from_jsonl(l).expect("parse"))
            .collect()
    }

    /// With `data_plane=true`, a C_Encrypt completion writes a DataPlane record
    /// with method="C_Encrypt" and the op's real ck_rv.
    #[tokio::test]
    async fn encrypt_data_plane_true_produces_record() {
        let dir = dp_temp_dir("enc-on");
        dp_make_audit_dir(&dir);
        let sink = dp_make_sink(&dir, true);

        let (mut ctx, ctx_id, session) =
            setup(no_mechanism_grant_policy(), Some(PEER_IDENTITY.into())).await;
        ctx.audit = Some(sink.clone());

        let req = pkcs11_proxy_ng_proto::EncryptRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            data: vec![0u8; 4],
            data_null_len: None,
        };
        let resp = super::encrypt(&ctx, Request::new(req)).await.unwrap();
        let ck_rv = resp.into_inner().ck_rv;

        sink.flush().await.unwrap();

        let records = dp_parse_records(&dir);
        let dp = records.iter().find(|r| r.class == pkcs11_proxy_ng_audit::EventClass::DataPlane);
        assert!(dp.is_some(), "DataPlane record must be written when data_plane=true");
        let dp = dp.unwrap();
        assert_eq!(dp.method, "C_Encrypt");
        assert_eq!(dp.ck_rv, ck_rv, "record must carry the real ck_rv");

        let report = pkcs11_proxy_ng_audit::verify::verify_dir(&dir, None).unwrap();
        assert!(report.chain_ok, "chain must verify: {report:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// With `data_plane=false`, C_Encrypt must NOT write any DataPlane records.
    #[tokio::test]
    async fn encrypt_data_plane_false_no_record() {
        let dir = dp_temp_dir("enc-off");
        dp_make_audit_dir(&dir);
        let sink = dp_make_sink(&dir, false);

        let (mut ctx, ctx_id, session) =
            setup(no_mechanism_grant_policy(), Some(PEER_IDENTITY.into())).await;
        ctx.audit = Some(sink.clone());

        let req = pkcs11_proxy_ng_proto::EncryptRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            data: vec![0u8; 4],
            data_null_len: None,
        };
        let _ = super::encrypt(&ctx, Request::new(req)).await.unwrap();
        sink.flush().await.unwrap();

        let records = dp_parse_records(&dir);
        let has_dp =
            records.iter().any(|r| r.class == pkcs11_proxy_ng_audit::EventClass::DataPlane);
        assert!(!has_dp, "no DataPlane records must appear when data_plane=false");

        std::fs::remove_dir_all(&dir).ok();
    }
}

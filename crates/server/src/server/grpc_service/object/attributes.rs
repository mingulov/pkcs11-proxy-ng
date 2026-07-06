use std::time::Instant;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_audit::EventClass;
use pkcs11_proxy_ng_types::attribute::is_value_bearing_secret;
use pkcs11_proxy_ng_types::{CkAttributeQuery, CkAttributeType, CkRv};

use super::super::super::context_manager::ClientContextId;
use super::super::HandlerContext;
use super::super::audit_events::emit_auth_event;
use super::super::authorization::extract_is_permitted;
use super::super::service_utils::{
    ck_rv_only, resolve_session_and_object, spawn_backend, spawn_task,
};
use super::super::{ck_result_to_rv, convert_template};
use super::attribute_results;

fn validate_exact_attribute_results(
    query_types: &[CkAttributeType],
    results: &[pkcs11_proxy_ng_types::CkAttributeQueryResult],
) -> Result<(), Status> {
    if results.len() != query_types.len() {
        return Err(Status::internal(
            "backend returned mismatched GetAttributeValueExact result count",
        ));
    }

    for (&query_type, result) in query_types.iter().zip(results.iter()) {
        if result.attr_type != query_type {
            return Err(Status::internal(
                "backend returned misaligned GetAttributeValueExact results",
            ));
        }
    }

    Ok(())
}

pub(super) async fn get_attribute_value(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetAttributeValueRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetAttributeValueResponse>, Status> {
    let started = Instant::now();
    crate::server::resilience::record_get_attribute_value();
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) =
        match resolve_session_and_object(ctx, &ctx_id, req.session_handle, req.object_handle).await
        {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueResponse {
                    ck_rv: error.0,
                    results: vec![],
                }));
            }
        };

    let mut template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueResponse {
                ck_rv: error,
                results: vec![],
            }));
        }
    };

    // Extract-deny gate (G2-PR2): if any queried attribute is value-bearing-
    // secret AND the principal's grant denies extraction, return
    // KEY_FUNCTION_NOT_PERMITTED without calling the backend. Public attributes
    // such as CKA_MODULUS are unaffected (is_value_bearing_secret returns false
    // for them). Unauthenticated / no-policy / no-extract-deny → passes through.
    // I3: emit a KeyMgmt audit record for the denial so monitoring can detect
    // extraction attempts; do NOT audit the allowed path (data-plane volume).
    let has_secret_attr = template.iter().any(|attr| is_value_bearing_secret(attr.attr_type));
    if has_secret_attr && !extract_is_permitted(ctx, &ctx_id, req.session_handle).await? {
        if emit_auth_event(
            ctx,
            &ctx_id,
            "C_GetAttributeValue",
            EventClass::KeyMgmt,
            None,
            Some(req.session_handle),
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            started,
        )
        .is_err()
        {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueResponse {
                ck_rv: CkRv::FUNCTION_FAILED.0,
                results: vec![],
            }));
        }
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueResponse {
            ck_rv: CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            results: vec![],
        }));
    }

    let backend = ctx.backend.clone();
    let (result, template) = spawn_task(move || {
        let rv = backend.get_attribute_value(session, object, &mut template);
        (rv, template)
    })
    .await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueResponse {
        ck_rv: ck_rv_only(result),
        results: attribute_results(template),
    }))
}

pub(super) async fn get_attribute_value_exact(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetAttributeValueExactRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetAttributeValueExactResponse>, Status> {
    let started = Instant::now();
    crate::server::resilience::record_get_attribute_value();
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) =
        match resolve_session_and_object(ctx, &ctx_id, req.session_handle, req.object_handle).await
        {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
                    ck_rv: error.0,
                    results: vec![],
                }));
            }
        };

    let queries = req.queries.iter().map(CkAttributeQuery::from).collect::<Vec<_>>();
    // Keep only the (Copy) attribute types for post-call alignment validation,
    // then move the full query vector into the backend call — avoids cloning the
    // whole query vector on this hot read path (M8).
    let query_types: Vec<CkAttributeType> = queries.iter().map(|q| q.attr_type).collect();

    // Extract-deny gate (G2-PR2): same semantics as get_attribute_value above.
    // I3: emit a KeyMgmt audit record for the denial; do NOT audit the allowed
    // path (data-plane volume). No secret/attribute values in the record.
    let has_secret_attr = query_types.iter().any(|&t| is_value_bearing_secret(t));
    if has_secret_attr && !extract_is_permitted(ctx, &ctx_id, req.session_handle).await? {
        if emit_auth_event(
            ctx,
            &ctx_id,
            "C_GetAttributeValueExact",
            EventClass::KeyMgmt,
            None,
            Some(req.session_handle),
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            started,
        )
        .is_err()
        {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
                ck_rv: CkRv::FUNCTION_FAILED.0,
                results: vec![],
            }));
        }
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
            ck_rv: CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            results: vec![],
        }));
    }

    let backend = ctx.backend.clone();
    let result =
        spawn_backend(move || backend.get_attribute_value_exact(session, object, &queries)).await?;

    match result {
        Ok((ck_rv, results)) => {
            validate_exact_attribute_results(&query_types, &results)?;
            Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
                ck_rv: ck_rv.0,
                // Consume `results` by value so each attribute's owned
                // `Vec<u8>` moves directly into the proto buffer (mirrors
                // the `attribute_results` optimization for the
                // non-exact path).
                results: results
                    .into_iter()
                    .map(pkcs11_proxy_ng_proto::AttributeQueryResult::from)
                    .collect(),
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::GetAttributeValueExactResponse {
            ck_rv: error.0,
            results: vec![],
        })),
    }
}

pub(super) async fn set_attribute_value(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SetAttributeValueRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SetAttributeValueResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) =
        match resolve_session_and_object(ctx, &ctx_id, req.session_handle, req.object_handle).await
        {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SetAttributeValueResponse {
                    ck_rv: error.0,
                }));
            }
        };

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SetAttributeValueResponse {
                ck_rv: error,
            }));
        }
    };

    let backend = ctx.backend.clone();
    let result =
        spawn_backend(move || backend.set_attribute_value(session, object, &template)).await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::SetAttributeValueResponse {
        ck_rv: ck_rv_only(result),
    }))
}

pub(super) async fn get_object_size(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetObjectSizeRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetObjectSizeResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) =
        match resolve_session_and_object(ctx, &ctx_id, req.session_handle, req.object_handle).await
        {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::GetObjectSizeResponse {
                    ck_rv: error.0,
                    size: 0,
                }));
            }
        };

    let backend = ctx.backend.clone();
    let result = spawn_backend(move || backend.get_object_size(session, object)).await?;
    let (ck_rv, size) = ck_result_to_rv(result);

    Ok(Response::new(pkcs11_proxy_ng_proto::GetObjectSizeResponse {
        ck_rv,
        size: size.unwrap_or(0),
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tonic::Request;

    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_types::*;

    use super::validate_exact_attribute_results;
    use crate::config::{
        AuthConfig, ExtractPolicyConfig, GrantSpec, PolicyEntry, RichGrantConfig, TokenAccessSpec,
    };
    use crate::server::auth::policy::TokenPolicy;
    use crate::server::context_manager::{ClientContextId, ContextManager};
    use crate::server::grpc_service::HandlerContext;
    use crate::server::handle_map::BackendHandle;
    use tonic::Code;

    // --- existing alignment tests ---

    #[test]
    fn exact_result_validation_rejects_result_count_mismatch() {
        let status = validate_exact_attribute_results(&[CkAttributeType::LABEL], &[])
            .expect_err("expected count mismatch");

        assert_eq!(status.code(), Code::Internal);
    }

    #[test]
    fn exact_result_validation_rejects_attr_type_mismatch() {
        let status = validate_exact_attribute_results(
            &[CkAttributeType::LABEL],
            &[CkAttributeQueryResult {
                attr_type: CkAttributeType::VALUE,
                returned_len: 0,
                value: None,
                ck_rv: None,
                nested: None,
            }],
        )
        .expect_err("expected attr_type mismatch");

        assert_eq!(status.code(), Code::Internal);
    }

    #[test]
    fn exact_result_validation_accepts_aligned_results() {
        validate_exact_attribute_results(
            &[CkAttributeType::LABEL],
            &[CkAttributeQueryResult {
                attr_type: CkAttributeType::LABEL,
                returned_len: 3,
                value: Some(b"key".to_vec()),
                ck_rv: None,
                nested: None,
            }],
        )
        .expect("aligned results");
    }

    // --- extract-deny gate tests ---

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

    /// Build a test HandlerContext with a given policy and a session registered
    /// on slot 0, with token info pre-cached. Returns `(ctx, ctx_id, session_handle)`.
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

    #[tokio::test]
    async fn get_attribute_value_denies_secret_attr_when_extract_denied() {
        let (ctx, ctx_id, session_handle) = setup(deny_policy(), Some(MTLS_IDENTITY.into())).await;

        let response = super::get_attribute_value(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::GetAttributeValueRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle,
                object_handle: 0,
                // CKA_VALUE is a secret attribute.
                template: vec![pkcs11_proxy_ng_proto::Attribute {
                    attr_type: CkAttributeType::VALUE.0,
                    value: None,
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "querying CKA_VALUE with extract=Deny must return KEY_FUNCTION_NOT_PERMITTED"
        );
    }

    #[tokio::test]
    async fn get_attribute_value_allows_public_attr_when_extract_denied() {
        let (ctx, ctx_id, session_handle) = setup(deny_policy(), Some(MTLS_IDENTITY.into())).await;

        let response = super::get_attribute_value(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::GetAttributeValueRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle,
                object_handle: 0,
                // CKA_MODULUS is a public attribute — not value-bearing-secret.
                template: vec![pkcs11_proxy_ng_proto::Attribute {
                    attr_type: CkAttributeType::MODULUS.0,
                    value: None,
                }],
            }),
        )
        .await
        .unwrap();

        // The backend (MockBackend) will handle the call. It may return any
        // CK_RV, but it must NOT be KEY_FUNCTION_NOT_PERMITTED — that would
        // mean the gate incorrectly blocked a public attribute.
        assert_ne!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "querying CKA_MODULUS with extract=Deny must reach the backend unchanged"
        );
    }

    #[tokio::test]
    async fn get_attribute_value_allows_secret_attr_when_extract_allowed() {
        let (ctx, ctx_id, session_handle) = setup(allow_policy(), Some(MTLS_IDENTITY.into())).await;

        let response = super::get_attribute_value(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::GetAttributeValueRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle,
                object_handle: 0,
                template: vec![pkcs11_proxy_ng_proto::Attribute {
                    attr_type: CkAttributeType::VALUE.0,
                    value: None,
                }],
            }),
        )
        .await
        .unwrap();

        assert_ne!(
            response.into_inner().ck_rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0,
            "CKA_VALUE query with extract=Allow must reach the backend unchanged"
        );
    }
}

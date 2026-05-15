use std::str::FromStr;
use std::sync::Arc;

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;
use tonic::Status;

use super::super::auth::identity::AuthenticatedIdentity;
use super::super::auth::policy::TokenPolicy;
use super::super::context_manager::{ClientContextId, ContextManager};
use super::service_utils::{context_exists, spawn_backend};

pub(super) async fn context_identity(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
) -> CkResult<AuthenticatedIdentity> {
    if !context_exists(ctx_mgr, ctx_id).await {
        return Err(CkRv::CRYPTOKI_NOT_INITIALIZED);
    }

    let Some(identity) = ctx_mgr.context_identity(ctx_id).await else {
        return Ok(AuthenticatedIdentity::Unauthenticated);
    };

    AuthenticatedIdentity::from_str(&identity).map_err(|_| CkRv::GENERAL_ERROR)
}

pub(super) async fn slot_is_authorized(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    ctx_id: &ClientContextId,
    backend_slot: CkSlotId,
) -> Result<CkResult<bool>, Status> {
    let identity = match context_identity(ctx_mgr, ctx_id).await {
        Ok(identity) => identity,
        Err(error) => return Ok(Err(error)),
    };

    if matches!(identity, AuthenticatedIdentity::Unauthenticated) {
        return Ok(Ok(true));
    }

    let backend = backend_ref.clone();
    match spawn_backend(move || backend.get_token_info(backend_slot)).await? {
        Ok(info) => Ok(Ok(token_policy.allows(&identity, &info.label, &info.serial_number))),
        Err(CkRv::TOKEN_NOT_PRESENT) => Ok(Ok(false)),
        Err(error) => Ok(Err(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, PolicyEntry, TokenAccessSpec};
    use pkcs11_proxy_ng_backend::MockBackend;

    const MTLS_IDENTITY: &str = "x509:issuer=CN=Root CA;subject=CN=client";

    fn backend() -> Arc<dyn Pkcs11Backend> {
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]))
    }

    fn policy_for_identity(identity: &str) -> TokenPolicy {
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            policy: vec![PolicyEntry {
                identity: identity.into(),
                tokens: TokenAccessSpec::Specific(vec!["label:MockToken".into()]),
            }],
        })
        .unwrap()
    }

    #[tokio::test]
    async fn unauthenticated_context_bypasses_token_policy() {
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let policy = TokenPolicy::from_config(&AuthConfig::default()).unwrap();

        let authorized = slot_is_authorized(&ctx_mgr, &backend(), &policy, &ctx_id, CkSlotId(999))
            .await
            .unwrap()
            .unwrap();

        assert!(authorized);
    }

    #[tokio::test]
    async fn authenticated_context_without_matching_rule_is_denied() {
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        let ctx_id = ctx_mgr.create_context(Some(MTLS_IDENTITY.into())).await.unwrap();
        let policy = TokenPolicy::from_config(&AuthConfig::default()).unwrap();

        let authorized = slot_is_authorized(&ctx_mgr, &backend(), &policy, &ctx_id, CkSlotId(0))
            .await
            .unwrap()
            .unwrap();

        assert!(!authorized);
    }

    #[tokio::test]
    async fn authenticated_context_with_matching_selector_is_allowed() {
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        let ctx_id = ctx_mgr.create_context(Some(MTLS_IDENTITY.into())).await.unwrap();
        let policy = policy_for_identity(MTLS_IDENTITY);

        let authorized = slot_is_authorized(&ctx_mgr, &backend(), &policy, &ctx_id, CkSlotId(0))
            .await
            .unwrap()
            .unwrap();

        assert!(authorized);
    }
}

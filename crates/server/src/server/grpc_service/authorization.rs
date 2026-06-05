use std::str::FromStr;
use std::sync::Arc;

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;
use tonic::Status;

use crate::config::{TcpAuthMode, UnixAuthMode};

use super::super::auth::identity::AuthenticatedIdentity;
use super::super::auth::policy::TokenPolicy;
use super::super::auth::request_identity::identity_from_request;
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

/// A2 ownership gate (pure core): decide whether a request bearing a
/// `client_context_id` may proceed, given the identity captured for that
/// context at C_Initialize (`stored`; `None` when no such context is recorded)
/// and the caller's live transport identity (`live`).
///
/// The `client_context_id` is an unauthenticated bearer token on the wire;
/// without this check a co-located peer that learned another client's id could
/// drive that client's context. A `None` `stored` is allowed here on purpose —
/// the absence of the context is surfaced by the handler as the proper PKCS#11
/// error, not masked as a permission failure.
pub(super) fn context_owner_allowed(stored: Option<&str>, live: &AuthenticatedIdentity) -> bool {
    match stored {
        None => true,
        Some(expected) => expected == live.to_string(),
    }
}

/// Enforce A2 context ownership for a request that carries `client_context_id`.
/// Re-derives the caller's transport identity on every call and rejects with
/// `permission_denied` when it does not match the identity bound to the context
/// at C_Initialize. A context that does not exist (or carries no recorded
/// identity) passes here and is reported by the handler as the proper CK_RV.
pub(super) async fn enforce_context_owner<T>(
    ctx_mgr: &Arc<ContextManager>,
    request: &tonic::Request<T>,
    ctx_id: &ClientContextId,
    tcp_auth: TcpAuthMode,
    unix_auth: UnixAuthMode,
) -> Result<(), Status> {
    let stored = ctx_mgr.context_identity(ctx_id).await;
    let live = identity_from_request(request, tcp_auth, unix_auth)?;
    if context_owner_allowed(stored.as_deref(), &live) {
        Ok(())
    } else {
        tracing::warn!(
            context_id = %ctx_id.0,
            "rejected request: client_context_id presented by a different transport identity"
        );
        Err(Status::permission_denied(
            "client_context_id does not belong to the calling transport identity",
        ))
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

    // --- A2: per-request context-ownership gate (the pure decision core) ---

    #[test]
    fn owner_check_allows_when_no_context_recorded() {
        // A missing context is not an ownership failure: the handler maps it to
        // the proper CK_RV (CRYPTOKI_NOT_INITIALIZED). The gate must not turn
        // that into a permission failure.
        assert!(context_owner_allowed(None, &AuthenticatedIdentity::PeerCred { uid: 1000 }));
    }

    #[test]
    fn owner_check_allows_matching_peer_cred() {
        assert!(context_owner_allowed(
            Some("uid=1000"),
            &AuthenticatedIdentity::PeerCred { uid: 1000 }
        ));
    }

    #[test]
    fn owner_check_rejects_mismatched_peer_cred() {
        // The bearer-token attack: a different uid presenting another client's
        // client_context_id must be rejected.
        assert!(!context_owner_allowed(
            Some("uid=1000"),
            &AuthenticatedIdentity::PeerCred { uid: 2000 }
        ));
    }

    #[test]
    fn owner_check_rejects_unauthenticated_caller_claiming_authenticated_context() {
        assert!(!context_owner_allowed(Some("uid=1000"), &AuthenticatedIdentity::Unauthenticated));
    }

    #[test]
    fn owner_check_allows_matching_unauthenticated() {
        assert!(context_owner_allowed(
            Some("unauthenticated"),
            &AuthenticatedIdentity::Unauthenticated
        ));
    }

    #[test]
    fn owner_check_matches_mtls_identity_exactly() {
        let owner = AuthenticatedIdentity::Mtls {
            issuer: "CN=Root CA".into(),
            subject: "CN=client".into(),
        };
        assert!(context_owner_allowed(Some(MTLS_IDENTITY), &owner));

        let impostor = AuthenticatedIdentity::Mtls {
            issuer: "CN=Root CA".into(),
            subject: "CN=attacker".into(),
        };
        assert!(!context_owner_allowed(Some(MTLS_IDENTITY), &impostor));
    }
}

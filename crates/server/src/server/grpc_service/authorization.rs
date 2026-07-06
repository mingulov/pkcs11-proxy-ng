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
use super::super::handle_map::VirtualHandle;
use super::HandlerContext;
use super::service_utils::{context_exists, spawn_backend};

pub(super) async fn context_identity(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
) -> CkResult<AuthenticatedIdentity> {
    if !context_exists(ctx_mgr, ctx_id).await {
        return Err(CkRv::CRYPTOKI_NOT_INITIALIZED);
    }

    let Some(identity) = ctx_mgr.context_identity(ctx_id) else {
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

    // Unauthenticated peers route through the SAME deny-default decision as
    // `TokenPolicy::allows` (the single G2-PR2 flip-point); short-circuit here so
    // an identity-independent answer does not trigger a token-info fetch.
    if matches!(identity, AuthenticatedIdentity::Unauthenticated) {
        return Ok(Ok(token_policy.allows_unauthenticated()));
    }

    // Serve the token (label, serial) from the per-slot cache when fresh, so a
    // burst of authorization checks (discovery, open) does not issue a blocking
    // C_GetTokenInfo each time (M9). A cache miss reads the backend and records
    // the result; TOKEN_NOT_PRESENT and other errors are not cached.
    let (label, serial) = match ctx_mgr.cached_token_info(backend_slot) {
        Some(cached) => cached,
        None => {
            let backend = backend_ref.clone();
            match spawn_backend(move || backend.get_token_info(backend_slot)).await? {
                Ok(info) => {
                    ctx_mgr.cache_token_info(
                        backend_slot,
                        info.label.clone(),
                        info.serial_number.clone(),
                    );
                    (info.label, info.serial_number)
                }
                Err(CkRv::TOKEN_NOT_PRESENT) => return Ok(Ok(false)),
                Err(error) => return Ok(Err(error)),
            }
        }
    };
    Ok(Ok(token_policy.allows(&identity, &label, &serial)))
}

/// Returns `true` if the calling principal may extract key material from the
/// token that owns `virtual_session`.
///
/// `false` only when the principal has an explicit `extract = "deny"` grant for
/// the matched token AND the token info is already in the cache. On any
/// resolution failure (unknown context, session not in `session_slots`, cache
/// miss) the function returns `true` so that the opt-in extract-deny gate
/// never denies due to incomplete state.
pub(super) async fn extract_is_permitted(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    virtual_session: u64,
) -> Result<bool, Status> {
    let identity = match context_identity(&ctx.context_manager, ctx_id).await {
        Ok(identity) => identity,
        Err(_) => return Ok(true), // context gone → permissive
    };

    // Unauthenticated peers: extract_allowed always returns true; skip
    // session/slot lookup.
    if matches!(identity, AuthenticatedIdentity::Unauthenticated) {
        return Ok(true);
    }

    let Some(backend_slot) =
        ctx.context_manager.slot_for_session(ctx_id, VirtualHandle(virtual_session)).await
    else {
        return Ok(true); // session not registered → permissive
    };

    let (label, serial) = match ctx.context_manager.cached_token_info(backend_slot) {
        Some(info) => info,
        // Cache miss: rather than blocking on a backend call just for the
        // extract gate, be permissive — extract-deny is opt-in.
        None => return Ok(true),
    };

    Ok(ctx.token_policy.extract_allowed(&identity, &label, &serial))
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
    let stored = ctx_mgr.context_identity(ctx_id);
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
    use crate::config::{
        AuthConfig, ExtractPolicyConfig, GrantSpec, PolicyEntry, RichGrantConfig, TokenAccessSpec,
    };
    use crate::server::grpc_service::HandlerContext;
    use crate::server::handle_map::BackendHandle;
    use pkcs11_proxy_ng_backend::MockBackend;

    const MTLS_IDENTITY: &str = "x509:issuer=CN=Root CA;subject=CN=client";

    fn backend() -> Arc<dyn Pkcs11Backend> {
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]))
    }

    fn policy_for_identity(identity: &str) -> TokenPolicy {
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: identity.into(),
                tokens: TokenAccessSpec::Specific(vec![GrantSpec::Bare("label:MockToken".into())]),
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

    #[tokio::test]
    async fn token_info_is_cached_across_authorization_checks() {
        // M9: repeated authorization checks for the same slot reuse the cached
        // (label, serial) instead of issuing a blocking C_GetTokenInfo each
        // time; a slot re-registration invalidates the cache.
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        let ctx_id = ctx_mgr.create_context(Some(MTLS_IDENTITY.into())).await.unwrap();
        let policy = policy_for_identity(MTLS_IDENTITY);

        for _ in 0..3 {
            slot_is_authorized(&ctx_mgr, &backend, &policy, &ctx_id, CkSlotId(0))
                .await
                .unwrap()
                .unwrap();
        }
        assert_eq!(mock.token_info_call_count(), 1, "repeat checks must hit the cache");

        ctx_mgr.register_slot(CkSlotId(0)).await; // invalidates the cached token info
        slot_is_authorized(&ctx_mgr, &backend, &policy, &ctx_id, CkSlotId(0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mock.token_info_call_count(), 2, "re-registration must re-read token info");
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
            spki_sha256: "".into(),
        };
        assert!(context_owner_allowed(Some(MTLS_IDENTITY), &owner));

        let impostor = AuthenticatedIdentity::Mtls {
            issuer: "CN=Root CA".into(),
            subject: "CN=attacker".into(),
            spki_sha256: "".into(),
        };
        assert!(!context_owner_allowed(Some(MTLS_IDENTITY), &impostor));
    }

    // --- extract_is_permitted ---

    fn policy_with_extract_deny(identity: &str) -> TokenPolicy {
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: identity.into(),
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

    /// Helper: build a HandlerContext with a given policy, register a session on
    /// slot 0 in the context, and pre-populate the token-info cache so
    /// `extract_is_permitted` can see the token without a backend round-trip.
    /// Returns `(ctx, ctx_id, session_handle)`.
    async fn setup_extract_test(
        policy: TokenPolicy,
        identity: Option<String>,
    ) -> (HandlerContext, ClientContextId, u64) {
        let backend = backend();
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        ctx_mgr.register_slot(CkSlotId(0)).await;
        let ctx_id = ctx_mgr.create_context(identity).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| ctx.register_session(BackendHandle(1), CkSlotId(0)))
            .await
            .unwrap();
        // Prime the token-info cache so extract_is_permitted can resolve without
        // a backend call.
        ctx_mgr.cache_token_info(CkSlotId(0), "MockToken".into(), "0001".into());

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = Arc::new(policy);
        (ctx, ctx_id, session_vh.0)
    }

    #[tokio::test]
    async fn extract_permitted_for_deny_grant_returns_false() {
        let policy = policy_with_extract_deny(MTLS_IDENTITY);
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        let permitted = extract_is_permitted(&ctx, &ctx_id, session).await.unwrap();
        assert!(!permitted, "extract must be denied for principal with extract=Deny grant");
    }

    #[tokio::test]
    async fn extract_permitted_for_allow_grant_returns_true() {
        let policy = policy_for_identity(MTLS_IDENTITY);
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        let permitted = extract_is_permitted(&ctx, &ctx_id, session).await.unwrap();
        assert!(permitted, "extract must be allowed for principal with default (allow) grant");
    }

    #[tokio::test]
    async fn extract_permitted_for_unauthenticated_returns_true() {
        // No policy configured for unauthenticated; extract-deny is opt-in.
        let policy = policy_with_extract_deny(MTLS_IDENTITY);
        let (ctx, ctx_id, session) = setup_extract_test(policy, None).await;
        let permitted = extract_is_permitted(&ctx, &ctx_id, session).await.unwrap();
        assert!(
            permitted,
            "unauthenticated peer must always be permitted (extract-deny is opt-in)"
        );
    }

    #[tokio::test]
    async fn extract_permitted_for_no_policy_returns_true() {
        // Default (empty) policy: no grants at all → extract permitted.
        let policy = TokenPolicy::from_config(&AuthConfig::default()).unwrap();
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        let permitted = extract_is_permitted(&ctx, &ctx_id, session).await.unwrap();
        assert!(permitted, "principal with no matching grant must be permitted by default");
    }

    #[tokio::test]
    async fn extract_permitted_on_cache_miss_returns_true() {
        // When the token-info cache is empty (no prime step), the function
        // returns true (permissive on cache miss — extract-deny is opt-in).
        let policy = policy_with_extract_deny(MTLS_IDENTITY);
        let backend = backend();
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        ctx_mgr.register_slot(CkSlotId(0)).await;
        let ctx_id = ctx_mgr.create_context(Some(MTLS_IDENTITY.into())).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| ctx.register_session(BackendHandle(1), CkSlotId(0)))
            .await
            .unwrap();
        // No cache_token_info call — intentional cache miss.
        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = Arc::new(policy);

        let permitted = extract_is_permitted(&ctx, &ctx_id, session_vh.0).await.unwrap();
        assert!(permitted, "cache miss must be permissive");
    }
}

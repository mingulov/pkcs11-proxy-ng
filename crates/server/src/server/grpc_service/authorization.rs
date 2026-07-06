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
/// Returns `false` when the principal has an explicit `extract = "deny"` grant
/// for the matched token. On a cache miss for an authenticated principal the
/// function fetches the token info from the backend and caches it, mirroring
/// `slot_is_authorized`'s resolution strategy (M9) — a stale/expired cache
/// must not silently disarm the extract gate. Returns `true` (permissive) on
/// unknown context or unregistered session. Returns `false` (fail-closed) when
/// the backend reports `TOKEN_NOT_PRESENT` or another error — consistent with
/// `slot_is_authorized`'s "do not silently permit" contract. Unauthenticated
/// principals always return `true` (extract-deny is opt-in for authenticated
/// identities only).
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

    // Resolve the token (label, serial) from cache when available. On a miss,
    // fetch from the backend and cache the result so a TTL-expired cache cannot
    // silently disarm the extract gate. Mirrors slot_is_authorized (M9).
    let (label, serial) = match ctx.context_manager.cached_token_info(backend_slot) {
        Some(info) => info,
        None => {
            let backend = ctx.backend.clone();
            match spawn_backend(move || backend.get_token_info(backend_slot)).await? {
                Ok(info) => {
                    ctx.context_manager.cache_token_info(
                        backend_slot,
                        info.label.clone(),
                        info.serial_number.clone(),
                    );
                    (info.label, info.serial_number)
                }
                // No token at this slot → fail closed (consistent with
                // slot_is_authorized returning false for TOKEN_NOT_PRESENT).
                Err(CkRv::TOKEN_NOT_PRESENT) => return Ok(false),
                // Backend error → fail closed; do not silently permit.
                Err(_) => return Ok(false),
            }
        }
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

/// Fetch `CKA_UNIQUE_ID` bytes from the backend for the given backend-level
/// object handle.
///
/// Implements the PKCS#11 two-call `C_GetAttributeValue` pattern using a
/// one-element `CkAttribute` template:
///
/// - **Call 1** (`value = None`, i.e. `pValue = NULL` at the FFI edge):
///   For mock-style backends that fill attribute values directly, this call
///   already returns the bytes.  For real FFI backends the backend writes
///   `ulValueLen` into the raw `CK_ATTRIBUTE` struct, but the Rust mapping
///   discards it (the size has nowhere to go since `CkAttribute.value` is
///   `Option<CkAttributeValue>` with no separate length field).
/// - **Call 2** (pre-allocated 256-byte buffer, `value = Some(Bytes(...))`):
///   For FFI backends that did not fill a value in call 1, this call
///   provides a sized buffer so the backend can write actual bytes.
///   `CKA_UNIQUE_ID` is a UUID-like byte string (16–36 bytes in practice);
///   256 bytes is generous for any conforming provider.
///
/// Returns `Some(bytes)` when the attribute is present and non-empty; `None`
/// on any error, absent attribute (`CKR_ATTRIBUTE_TYPE_INVALID`), sensitive
/// attribute, or empty value.  The value is **not** logged.  Buggy-backend
/// quirks (`CKR_BUFFER_TOO_SMALL`, etc.) collapse to `None`.
///
/// # Note
/// Called by the per-object gate in `service_utils::gate_object_handle`.
pub(super) async fn fetch_object_unique_id(
    ctx: &HandlerContext,
    session: CkSessionHandle,
    object: CkObjectHandle,
) -> Option<Vec<u8>> {
    let backend = ctx.backend.clone();
    let result = spawn_backend(move || -> CkResult<Option<Vec<u8>>> {
        // --- Call 1: size-query (value=None → pValue=NULL at the FFI edge) ---
        let mut template = [CkAttribute { attr_type: CkAttributeType::UNIQUE_ID, value: None }];
        match backend.get_attribute_value(session, object, &mut template) {
            Ok(()) => {}
            // Attribute absent, sensitive, or invalid handle — not available.
            Err(
                CkRv::ATTRIBUTE_TYPE_INVALID
                | CkRv::ATTRIBUTE_SENSITIVE
                | CkRv::OBJECT_HANDLE_INVALID
                | CkRv::SESSION_HANDLE_INVALID,
            ) => return Ok(None),
            // Other backend errors propagate so the caller can collapse them.
            Err(rv) => return Err(rv),
        }
        // Mock-style backends fill `value` directly on the size-query call.
        // If we already have non-empty bytes, we are done.
        if let Some(CkAttributeValue::Bytes(bytes)) = template[0].value.take()
            && !bytes.is_empty()
        {
            return Ok(Some(bytes));
        }
        // --- Call 2: data-query with a pre-allocated buffer ---
        // FFI backends need a sized buffer; use 256 bytes (generous for UUID strings).
        template[0].value = Some(CkAttributeValue::Bytes(vec![0u8; 256]));
        match backend.get_attribute_value(session, object, &mut template) {
            Ok(()) => {}
            Err(
                CkRv::ATTRIBUTE_TYPE_INVALID
                | CkRv::ATTRIBUTE_SENSITIVE
                | CkRv::BUFFER_TOO_SMALL
                | CkRv::OBJECT_HANDLE_INVALID
                | CkRv::SESSION_HANDLE_INVALID,
            ) => return Ok(None),
            Err(rv) => return Err(rv),
        }
        match template[0].value.take() {
            Some(CkAttributeValue::Bytes(bytes)) if !bytes.is_empty() => Ok(Some(bytes)),
            _ => Ok(None),
        }
    })
    .await;
    // Collapse any transport/timeout error or backend CkRv error to None;
    // the gate in Task 3 treats a missing unique-id as a deny decision.
    match result {
        Ok(Ok(opt)) => opt,
        _ => None,
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
                    objects: None,
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
    async fn extract_denied_on_cache_miss_for_authenticated_identity() {
        // I1 fix: for an authenticated identity with extract=Deny, a cache miss
        // must NOT silently permit. The function fetches token info from the
        // backend, caches it, and then evaluates the grant — yielding a denial
        // when the policy says extract=Deny.
        let policy = policy_with_extract_deny(MTLS_IDENTITY);
        let backend = backend();
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        ctx_mgr.register_slot(CkSlotId(0)).await;
        let ctx_id = ctx_mgr.create_context(Some(MTLS_IDENTITY.into())).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| ctx.register_session(BackendHandle(1), CkSlotId(0)))
            .await
            .unwrap();
        // No cache_token_info call — intentional cache miss; backend fetch is
        // expected (MockBackend returns label "MockToken" which matches the policy).
        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = Arc::new(policy);

        let permitted = extract_is_permitted(&ctx, &ctx_id, session_vh.0).await.unwrap();
        assert!(
            !permitted,
            "cache miss for authenticated identity with extract=Deny must resolve from backend and deny"
        );
    }

    // --- fetch_object_unique_id ---

    mod fetch_unique_id {
        use super::*;
        use pkcs11_proxy_ng_backend::mock::MockAttributeSlot;

        /// Open a real backend session and create a live object on the mock so
        /// `get_attribute_value_impl` can validate both the session and the object.
        fn mock_with_session_and_object() -> (Arc<MockBackend>, CkSessionHandle, CkObjectHandle) {
            let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
            mock.initialize().unwrap();
            let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
            let session = mock.open_session(CkSlotId(0), flags).unwrap();
            let object = mock.create_object(session, &[]).unwrap();
            (mock, session, object)
        }

        fn make_ctx(mock: Arc<MockBackend>) -> HandlerContext {
            let backend: Arc<dyn Pkcs11Backend> = mock;
            let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
            HandlerContext::for_test(&ctx_mgr, &backend)
        }

        #[tokio::test]
        async fn returns_uid_bytes_when_backend_has_attr() {
            let (mock, session, object) = mock_with_session_and_object();
            let uid = b"d41d8cd9-8f00-3204-a980-0998ecf8427e".to_vec();
            mock.set_attribute(
                object,
                CkAttributeType::UNIQUE_ID,
                MockAttributeSlot::Value(CkAttributeValue::Bytes(uid.clone())),
            );
            let ctx = make_ctx(mock);
            let result = fetch_object_unique_id(&ctx, session, object).await;
            assert_eq!(result, Some(uid), "must return the uid bytes registered on the mock");
        }

        #[tokio::test]
        async fn returns_none_when_attr_type_invalid() {
            let (mock, session, object) = mock_with_session_and_object();
            mock.set_attribute(object, CkAttributeType::UNIQUE_ID, MockAttributeSlot::InvalidType);
            let ctx = make_ctx(mock);
            let result = fetch_object_unique_id(&ctx, session, object).await;
            assert_eq!(result, None, "CKR_ATTRIBUTE_TYPE_INVALID must map to None");
        }

        #[tokio::test]
        async fn returns_none_when_attr_sensitive() {
            let (mock, session, object) = mock_with_session_and_object();
            mock.set_attribute(object, CkAttributeType::UNIQUE_ID, MockAttributeSlot::Sensitive);
            let ctx = make_ctx(mock);
            let result = fetch_object_unique_id(&ctx, session, object).await;
            assert_eq!(result, None, "CKR_ATTRIBUTE_SENSITIVE must map to None");
        }
    }
}

use crate::server::slot_map::BackendSlotId;
use std::str::FromStr;
use std::sync::Arc;

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;
use tonic::Status;

use crate::config::{TcpAuthMode, UnixAuthMode};

use super::super::auth::identity::AuthenticatedIdentity;
use super::super::auth::policy::TokenPolicy;
use super::super::auth::request_identity::identity_from_request;
use super::super::context_manager::{ClientContextId, ContextManager, ObjectMetadata};
use super::super::handle_map::VirtualHandle;
use super::HandlerContext;
use super::service_utils::{
    context_exists, resolve_object_authz_context, spawn_backend, template_declared_class,
};

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
    backend_slot: BackendSlotId,
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
            match spawn_backend(move || backend.get_token_info(backend_slot.0)).await? {
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
/// token that owns `virtual_session`, taking into account any per-object
/// extract-policy override for `virtual_object`.
///
/// **Grant-level gate:** Returns `false` when the principal has an explicit
/// `extract = "deny"` grant for the matched token. On a cache miss for an
/// authenticated principal the function fetches token info from the backend
/// and caches it, mirroring `slot_is_authorized`'s strategy (M9).
///
/// **Per-object gate (when `per_object_active()` is true):** If any grant in
/// the policy has an `objects` list, the gate also checks for a per-object
/// extract override for `virtual_object`. The object's `CKA_UNIQUE_ID` is
/// resolved from the metadata cache (`object_metadata` — session objects
/// per-handle, token objects gated by the authz generation) when available,
/// otherwise fetched from the backend and cached.
///
/// On uid-resolution failure (I1 fix — fail-closed when overrides exist):
/// - If the principal has ANY per-object extract override (`extract.is_some()`)
///   on the matched token → DENY (fail-closed: we cannot rule out this object
///   being covered by a per-object extract=Deny).
/// - If the principal has NO per-object extract overrides → fall through to the
///   grant-level `extract_allowed` decision (an unconfined principal must NOT
///   be over-denied on a transient uid-fetch failure).
///
/// Returns `false` (fail-closed) on unknown context or unregistered
/// session (W1-C1-15): a close racing an attribute read must deny
/// instead of skipping an extract-deny via a permissive default.
/// Returns `false` (fail-closed) when the backend reports `TOKEN_NOT_PRESENT`
/// or another error. Unauthenticated principals always return `true`
/// (extract-deny is opt-in for authenticated identities only).
pub(super) async fn extract_is_permitted(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    virtual_session: u64,
    virtual_object: u64,
) -> Result<bool, Status> {
    let identity = match context_identity(&ctx.context_manager, ctx_id).await {
        Ok(identity) => identity,
        Err(_) => return Ok(false), // context gone → deny (W1-C1-15)
    };

    // Unauthenticated peers: extract_allowed always returns true; skip
    // session/slot lookup.
    if matches!(identity, AuthenticatedIdentity::Unauthenticated) {
        return Ok(true);
    }

    let Some(backend_slot) =
        ctx.context_manager.slot_for_session(ctx_id, VirtualHandle(virtual_session)).await
    else {
        return Ok(false); // session not registered → deny (W1-C1-15)
    };

    // Resolve the token (label, serial) from cache when available. On a miss,
    // fetch from the backend and cache the result so a TTL-expired cache cannot
    // silently disarm the extract gate. Mirrors slot_is_authorized (M9).
    let (label, serial) = match ctx.context_manager.cached_token_info(backend_slot) {
        Some(info) => info,
        None => {
            let backend = ctx.backend.clone();
            match spawn_backend(move || backend.get_token_info(backend_slot.0)).await? {
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

    // Fast path: when no grant has an objects list, per-object extract overrides
    // are inactive; skip uid resolution entirely (transparent, M1).
    if !ctx.token_policy.per_object_active() {
        return Ok(ctx.token_policy.extract_allowed(&identity, &label, &serial));
    }

    // Per-object active: resolve the object's CKA_UNIQUE_ID so we can check
    // for a per-object extract override.
    //
    // On uid-resolution failure (I1 fix):
    // - If the principal has ANY per-object extract override on this token: DENY
    //   (fail-closed — we can't rule out this object being covered by extract=Deny).
    // - If the principal has NO per-object extract overrides: fall through to the
    //   grant-level decision (an unconfined principal must NOT be over-denied on a
    //   transient uid-fetch failure).
    match resolve_uid_for_extract(ctx, ctx_id, virtual_session, virtual_object).await {
        Some(uid) => Ok(uid.expose(|raw| {
            ctx.token_policy.extract_allowed_for_object(&identity, &label, &serial, raw)
        })),
        None => {
            if ctx.token_policy.has_object_extract_override(&identity, &label, &serial) {
                Ok(false) // I1 fix: fail-closed when per-object extract overrides exist
            } else {
                Ok(ctx.token_policy.extract_allowed(&identity, &label, &serial))
            }
        }
    }
}

/// Resolve the `CKA_UNIQUE_ID` of `virtual_object` for the extract gate.
///
/// Fast path: returns the cached `ObjectMetadata::unique_id` when already
/// present in the metadata cache (populated by `gate_object_handle`
/// earlier in the same request). On a cache miss, resolves the backend
/// session and object handles in one context-lock and calls
/// `fetch_object_metadata` — the result is cached for subsequent calls.
///
/// Returns `None` when:
/// - The context is gone.
/// - Either handle (session or object) cannot be resolved.
/// - `fetch_object_metadata` returns `None` (uid absent/sensitive/error).
///
/// `None` is the fail-safe fallback; callers fall back to grant-level policy.
async fn resolve_uid_for_extract(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    virtual_session: u64,
    virtual_object: u64,
) -> Option<SecretBytes> {
    // Fast path: metadata already in cache — session objects per-handle,
    // token objects while their authz generation is current (W1-L13-18).
    if let Some(cached) = ctx.context_manager.object_metadata(ctx_id, virtual_object).await {
        return Some(cached.unique_id);
    }

    // Cache miss: resolve backend handles in one context lock.
    let (bs_opt, bo_opt) = ctx
        .context_manager
        .get_context(ctx_id, |c| {
            (
                c.session_handles.resolve(VirtualHandle(virtual_session)),
                c.object_handles.resolve(VirtualHandle(virtual_object)),
            )
        })
        .await?;

    let backend_session = CkSessionHandle(bs_opt?.0 as u64);
    let backend_object_bh = bo_opt?;
    let backend_object = CkObjectHandle(backend_object_bh.0 as u64);

    let fetched = fetch_object_metadata(ctx, backend_session, backend_object).await;
    if let Some(ref m) = fetched {
        ctx.context_manager.cache_object_metadata(ctx_id, virtual_object, m.clone()).await;
    }
    fetched.map(|m| m.unique_id)
}

/// Per-mechanism authorization gate (G3-PR3 Task 3, ADR-0012).
///
/// Called at every crypto-init RPC that BINDS a mechanism (e.g.
/// `encrypt_init`, `sign_init`, `generate_key`, `wrap_key`, …). Returns
/// `true` when the calling principal is allowed to use `mech` on the token
/// that owns `virtual_session`.
///
/// **Transparent when off:** when no grant in any policy rule has a
/// `mechanisms` list (`per_mechanism_active() == false`), returns `true`
/// immediately with zero resolution work, preserving byte-identical behaviour
/// for all existing deployments.
///
/// **Fail-closed:** if the identity or token info cannot be resolved (context
/// gone, slot unknown, backend error), returns `false` — the operation is
/// denied rather than silently permitted.
///
/// **Unauthenticated peers:** `allows_mechanism` short-circuits to `true` for
/// `Unauthenticated` identities, so this function is always transparent for
/// unauthenticated peers regardless of the configured mechanism grants.
///
/// On denial the caller returns `CKR_MECHANISM_INVALID` (0x70) — a
/// spec-native rejection that is NOT an existence oracle (unlike handle-based
/// denials which use the invisible-denial contract).
pub(super) async fn mechanism_permitted(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    virtual_session: u64,
    mech: CkMechanismType,
) -> bool {
    if !ctx.token_policy.per_mechanism_active() {
        return true; // transparent when no mechanism grants configured
    }
    let Some((identity, label, serial)) =
        resolve_object_authz_context(ctx, ctx_id, virtual_session).await
    else {
        return false; // fail-closed: context/slot/token unavailable
    };
    ctx.token_policy.allows_mechanism(&identity, &label, &serial, mech)
}

/// Whether the principal may MINT an object of the template's class
/// (W1-L7-05): the mint-time companion to the USE-time class gate in
/// `gate_object_handle`, closing the "persist a denied-class token
/// object, use it never" hole.
///
/// `template` is the mint template view; `default_class` is the
/// operation's implied class when its templates conventionally omit
/// `CKA_CLASS` (`generate_key`/`derive_key` → `SECRET_KEY`;
/// `generate_key_pair` checks each template with `PUBLIC_KEY` /
/// `PRIVATE_KEY`). `create`/`copy` pass `None`: a copy without a class
/// override inherits its (USE-allowed) source's class, and a create
/// without `CKA_CLASS` is rejected by the backend itself
/// (`CKR_TEMPLATE_INCOMPLETE`) — nothing persists either way, so an
/// unknowable class falls through to the backend verdict instead of
/// inventing a refusal (transparency; the USE-time gate fail-closes on
/// unknown class regardless).
pub(super) async fn class_mint_permitted(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    virtual_session: u64,
    template: &[CkAttribute],
    default_class: Option<CkObjectClass>,
) -> bool {
    if !ctx.token_policy.per_class_active() {
        return true; // transparent when no class grants configured
    }
    let Some(class) = template_declared_class(template).or(default_class) else {
        return true; // unknowable class: backend decides (see above)
    };
    let Some((identity, label, serial)) =
        resolve_object_authz_context(ctx, ctx_id, virtual_session).await
    else {
        return false; // fail-closed: context/slot/token unavailable
    };
    ctx.token_policy.allows_class(&identity, &label, &serial, class)
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

/// Fetch object metadata (`CKA_UNIQUE_ID`, `CKA_CLASS`, `CKA_TOKEN`) from the
/// backend in a single `C_GetAttributeValue` round-trip.
///
/// Uses a 3-element template. `CKA_CLASS` (always 8 bytes on 64-bit) and
/// `CKA_TOKEN` (always 1 byte — `CK_BBOOL`) have known fixed sizes and are
/// pre-allocated so real FFI backends fill them in the first call.
/// `CKA_UNIQUE_ID` is variable-length and may require a second call if the
/// first call (size-probe) does not fill it (FFI backends); mock-style backends
/// fill it directly.
///
/// Returns `None` (fail-closed) when:
/// - The backend call fails with a non-transient error.
/// - `CKA_UNIQUE_ID` is absent, sensitive, or empty.
/// - Transport or timeout error.
///
/// `CKA_CLASS` absence or parse failure does NOT cause `None` (M2): the returned
/// `ObjectMetadata.class` is `None` in that case. Class-confined gates treat
/// a `None` class as fail-closed (deny); uid-only deployments are unaffected.
///
/// The unique-id bytes are **not** logged.
///
/// Called by the per-object / per-class gate in `service_utils::gate_object_handle`
/// and the enumeration filter in `object/search.rs`.
pub(super) async fn fetch_object_metadata(
    ctx: &HandlerContext,
    session: CkSessionHandle,
    object: CkObjectHandle,
) -> Option<ObjectMetadata> {
    let backend = ctx.backend.clone();
    let result = spawn_backend(move || -> CkResult<Option<ObjectMetadata>> {
        // One 3-element template: UNIQUE_ID (size-probe/None), CLASS (pre-alloc
        // Ulong), TOKEN (pre-alloc 1-byte Bytes). CLASS and TOKEN have known
        // sizes and will be filled in this first call by all conforming backends.
        let mut template = [
            CkAttribute { attr_type: CkAttributeType::UNIQUE_ID, value: None },
            CkAttribute {
                attr_type: CkAttributeType::CLASS,
                value: Some(CkAttributeValue::Ulong(0)),
            },
            CkAttribute {
                attr_type: CkAttributeType::TOKEN,
                value: Some(CkAttributeValue::Bytes(vec![0u8; 1].into())),
            },
        ];

        match backend.get_attribute_value(session, object, &mut template) {
            Ok(()) => {}
            // Any of the three attributes being absent/sensitive, or invalid
            // session/object handle — not usable; fail-closed.
            Err(
                CkRv::ATTRIBUTE_TYPE_INVALID
                | CkRv::ATTRIBUTE_SENSITIVE
                | CkRv::OBJECT_HANDLE_INVALID
                | CkRv::SESSION_HANDLE_INVALID,
            ) => return Ok(None),
            Err(rv) => return Err(rv),
        }

        // Parse CLASS — tolerate absent/unparseable (M2): uid-only deployments must not
        // fail on a missing class attribute. Class-confined gates treat None as fail-closed.
        let class: Option<CkObjectClass> = match template[1].value.take() {
            Some(CkAttributeValue::Ulong(u)) => Some(CkObjectClass(u)),
            Some(CkAttributeValue::Bytes(ref bytes)) if bytes.len() == 8 => {
                let arr: [u8; 8] = bytes.expose(|raw| raw[..8].try_into().unwrap());
                Some(CkObjectClass(u64::from_ne_bytes(arr)))
            }
            Some(CkAttributeValue::Bytes(ref bytes)) if bytes.len() == 4 => {
                let arr: [u8; 4] = bytes.expose(|raw| raw[..4].try_into().unwrap());
                Some(CkObjectClass(u32::from_ne_bytes(arr) as u64))
            }
            _ => None, // M2: CLASS absent or unrecognised → None, not fail-closed here
        };

        // Parse TOKEN (absent → session object; any non-zero byte → token object).
        let is_token = match template[2].value.take() {
            Some(CkAttributeValue::Bool(b)) => b,
            Some(CkAttributeValue::Bytes(bytes)) => {
                bytes.expose(|raw| raw.first().is_some_and(|&b| b != 0))
            }
            Some(CkAttributeValue::Ulong(u)) => u != 0,
            // String/NestedTemplate don't encode a boolean — treat as absent (session).
            None | Some(_) => false,
        };

        // UNIQUE_ID: mock-style backends fill it in the first call; FFI backends
        // need a pre-allocated buffer (Call 2).
        if let Some(CkAttributeValue::Bytes(bytes)) = template[0].value.take()
            && !bytes.is_empty()
        {
            return Ok(Some(ObjectMetadata { unique_id: bytes, class, is_token }));
        }

        // Call 2: provide a pre-allocated 256-byte buffer for UNIQUE_ID.
        let mut uid_template = [CkAttribute {
            attr_type: CkAttributeType::UNIQUE_ID,
            value: Some(CkAttributeValue::Bytes(vec![0u8; 256].into())),
        }];
        match backend.get_attribute_value(session, object, &mut uid_template) {
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
        match uid_template[0].value.take() {
            Some(CkAttributeValue::Bytes(bytes)) if !bytes.is_empty() => {
                Ok(Some(ObjectMetadata { unique_id: bytes, class, is_token }))
            }
            _ => Ok(None),
        }
    })
    .await;
    // Collapse transport/timeout errors to None (fail-closed).
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

        let authorized = slot_is_authorized(
            &ctx_mgr,
            &backend(),
            &policy,
            &ctx_id,
            crate::server::slot_map::BackendSlotId(CkSlotId(999)),
        )
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

        let authorized = slot_is_authorized(
            &ctx_mgr,
            &backend(),
            &policy,
            &ctx_id,
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        )
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

        let authorized = slot_is_authorized(
            &ctx_mgr,
            &backend(),
            &policy,
            &ctx_id,
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        )
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
            slot_is_authorized(
                &ctx_mgr,
                &backend,
                &policy,
                &ctx_id,
                crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            )
            .await
            .unwrap()
            .unwrap();
        }
        assert_eq!(mock.token_info_call_count(), 1, "repeat checks must hit the cache");

        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await; // invalidates the cached token info
        slot_is_authorized(
            &ctx_mgr,
            &backend,
            &policy,
            &ctx_id,
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        )
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
        // Prime the token-info cache so extract_is_permitted can resolve without
        // a backend call.
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = Arc::new(policy);
        (ctx, ctx_id, session_vh.0)
    }

    #[tokio::test]
    async fn extract_permitted_for_deny_grant_returns_false() {
        let policy = policy_with_extract_deny(MTLS_IDENTITY);
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        let permitted = extract_is_permitted(&ctx, &ctx_id, session, 0).await.unwrap();
        assert!(!permitted, "extract must be denied for principal with extract=Deny grant");
    }

    #[tokio::test]
    async fn extract_permitted_for_allow_grant_returns_true() {
        let policy = policy_for_identity(MTLS_IDENTITY);
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        let permitted = extract_is_permitted(&ctx, &ctx_id, session, 0).await.unwrap();
        assert!(permitted, "extract must be allowed for principal with default (allow) grant");
    }

    #[tokio::test]
    async fn extract_permitted_for_unauthenticated_returns_true() {
        // No policy configured for unauthenticated; extract-deny is opt-in.
        let policy = policy_with_extract_deny(MTLS_IDENTITY);
        let (ctx, ctx_id, session) = setup_extract_test(policy, None).await;
        let permitted = extract_is_permitted(&ctx, &ctx_id, session, 0).await.unwrap();
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
        let permitted = extract_is_permitted(&ctx, &ctx_id, session, 0).await.unwrap();
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
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(Some(MTLS_IDENTITY.into())).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(
                    BackendHandle(1),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();
        // No cache_token_info call — intentional cache miss; backend fetch is
        // expected (MockBackend returns label "MockToken" which matches the policy).
        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = Arc::new(policy);

        let permitted = extract_is_permitted(&ctx, &ctx_id, session_vh.0, 0).await.unwrap();
        assert!(
            !permitted,
            "cache miss for authenticated identity with extract=Deny must resolve from backend and deny"
        );
    }

    // --- I1: fail-closed extract override on uid-fetch failure ---

    /// Build a policy where `identity` has `extract=Allow` at grant level
    /// PLUS a per-object `extract=Deny` for object id "a1".
    fn policy_with_per_object_extract_deny(identity: &str) -> TokenPolicy {
        use crate::config::{ObjectAclRichConfig, ObjectAclSpec};
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: identity.into(),
                tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                    token: "label:MockToken".into(),
                    classes: None,
                    mechanisms: None,
                    extract: ExtractPolicyConfig::Allow, // grant-level: allow
                    objects: Some(vec![ObjectAclSpec::Rich(ObjectAclRichConfig {
                        id: "a1".into(), // per-object deny
                        extract: Some(ExtractPolicyConfig::Deny),
                    })]),
                })]),
            }],
        })
        .unwrap()
    }

    #[tokio::test]
    async fn i1_extract_denied_when_override_exists_and_uid_fetch_fails() {
        // I1 fix: grant extract=Allow + objects=[{id="a1",extract="deny"}].
        // When the uid fetch fails (MockBackend returns ATTRIBUTE_SENSITIVE for
        // CKA_UNIQUE_ID), the gate must DENY (fail-closed — cannot rule out this
        // object being the per-object-deny entry "a1").
        use pkcs11_proxy_ng_backend::mock::MockAttributeSlot;
        let policy = policy_with_per_object_extract_deny(MTLS_IDENTITY);
        assert!(
            policy.per_object_active(),
            "policy with objects list must have per_object_active==true"
        );

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();
        // Make UNIQUE_ID ATTRIBUTE_SENSITIVE so uid resolution returns None.
        mock.set_attribute(
            backend_object,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Sensitive,
        );

        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(Some(MTLS_IDENTITY.into())).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(
                    BackendHandle(backend_session.0),
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

        // Register the object virtual handle.
        let object_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| ctx.object_handles.insert(BackendHandle(backend_object.0)))
            .await
            .unwrap();

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = Arc::new(policy);

        let permitted =
            extract_is_permitted(&ctx, &ctx_id, session_vh.0, object_vh.0).await.unwrap();
        assert!(
            !permitted,
            "I1: uid-fetch failure with per-object override must be DENIED (fail-closed)"
        );
    }

    #[tokio::test]
    async fn i1_extract_allowed_unconfined_principal_on_uid_fetch_failure() {
        // I1 fix: an unconfined principal (objects:None, grant extract=Allow) must
        // still be ALLOWED when uid fetch fails — no per-object overrides exist, so
        // the grant-level allow should not be over-denied on a transient failure.
        let policy = policy_for_identity(MTLS_IDENTITY); // bare grant, no objects list
        assert!(
            !policy.per_object_active(),
            "bare grant (no objects list) must have per_object_active==false"
        );
        // With per_object_active==false the fast path is taken (no uid resolution),
        // so this test confirms grant-level allow is returned without uid fetch.
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        let permitted = extract_is_permitted(&ctx, &ctx_id, session, 0).await.unwrap();
        assert!(
            permitted,
            "I1: unconfined principal (no per-object overrides) must remain ALLOWED on uid-fetch failure"
        );
    }

    #[tokio::test]
    async fn i1_extract_denied_per_object_override_present_no_uid_resolution() {
        // I1 fix (second coverage): has_object_extract_override returns true even
        // when the uid cache is empty (no object virtual handle registered), so
        // per-object-override detection is independent of uid resolution.
        let policy = policy_with_per_object_extract_deny(MTLS_IDENTITY);
        let backend = backend();
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(Some(MTLS_IDENTITY.into())).await.unwrap();
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

        // virtual_object=999 is not registered → uid resolution returns None via
        // cache miss AND handle-resolve-miss. The gate must still DENY because
        // has_object_extract_override is true for this principal on MockToken.
        let permitted = extract_is_permitted(&ctx, &ctx_id, session_vh.0, 999).await.unwrap();
        assert!(
            !permitted,
            "I1: unresolvable object handle with per-object extract override must be DENIED"
        );
    }

    // --- mechanism_permitted ---

    fn policy_with_mechanism_grant(identity: &str, mechanisms: Vec<String>) -> TokenPolicy {
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: identity.into(),
                tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                    token: "label:MockToken".into(),
                    classes: None,
                    mechanisms: Some(mechanisms),
                    extract: ExtractPolicyConfig::Allow,
                    objects: None,
                })]),
            }],
        })
        .unwrap()
    }

    #[tokio::test]
    async fn mechanism_permitted_transparent_when_no_mechanism_grant() {
        // A grant with mechanisms=None → per_mechanism_active is false → any
        // mechanism is permitted (transparent, zero resolution work).
        let policy = policy_for_identity(MTLS_IDENTITY);
        assert!(
            !policy.per_mechanism_active(),
            "no mechanism list → per_mechanism_active must be false"
        );
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        // Both allowed and "disallowed" mechanisms must pass when gate is off.
        assert!(mechanism_permitted(&ctx, &ctx_id, session, CkMechanismType::RSA_PKCS).await);
        assert!(mechanism_permitted(&ctx, &ctx_id, session, CkMechanismType::AES_GCM).await);
    }

    #[tokio::test]
    async fn mechanism_permitted_allows_listed_mechanism() {
        let policy = policy_with_mechanism_grant(MTLS_IDENTITY, vec!["CKM_RSA_PKCS".into()]);
        assert!(
            policy.per_mechanism_active(),
            "mechanism list → per_mechanism_active must be true"
        );
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        assert!(
            mechanism_permitted(&ctx, &ctx_id, session, CkMechanismType::RSA_PKCS).await,
            "listed mechanism must be permitted"
        );
    }

    #[tokio::test]
    async fn mechanism_permitted_denies_unlisted_mechanism() {
        let policy = policy_with_mechanism_grant(MTLS_IDENTITY, vec!["CKM_RSA_PKCS".into()]);
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        assert!(
            !mechanism_permitted(&ctx, &ctx_id, session, CkMechanismType::AES_GCM).await,
            "mechanism not in the list must be denied"
        );
    }

    #[tokio::test]
    async fn mechanism_permitted_unauthenticated_always_true() {
        // Unauthenticated peer: allows_mechanism returns true unconditionally,
        // even when per_mechanism_active() is true and the mechanism list is narrow.
        let policy = policy_with_mechanism_grant(MTLS_IDENTITY, vec!["CKM_RSA_PKCS".into()]);
        assert!(policy.per_mechanism_active());
        // No identity → unauthenticated
        let (ctx, ctx_id, session) = setup_extract_test(policy, None).await;
        assert!(
            mechanism_permitted(&ctx, &ctx_id, session, CkMechanismType::AES_GCM).await,
            "unauthenticated peer must always be permitted (mechanism-grant is opt-in)"
        );
    }

    #[tokio::test]
    async fn mechanism_permitted_no_policy_returns_true() {
        // Empty policy (no grants): per_mechanism_active is false → transparent.
        let policy = TokenPolicy::from_config(&AuthConfig::default()).unwrap();
        assert!(!policy.per_mechanism_active());
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        assert!(mechanism_permitted(&ctx, &ctx_id, session, CkMechanismType::AES_GCM).await);
    }

    // --- class_mint_permitted (W1-L7-05) ---

    fn policy_with_class_grant(identity: &str, classes: Vec<String>) -> TokenPolicy {
        TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: identity.into(),
                tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                    token: "label:MockToken".into(),
                    classes: Some(classes),
                    mechanisms: None,
                    extract: ExtractPolicyConfig::Allow,
                    objects: None,
                })]),
            }],
        })
        .unwrap()
    }

    fn class_template(class: CkObjectClass) -> Vec<CkAttribute> {
        vec![CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(class.0)),
        }]
    }

    #[tokio::test]
    async fn class_mint_permitted_denies_unlisted_class() {
        let policy = policy_with_class_grant(MTLS_IDENTITY, vec!["secret_key".into()]);
        assert!(policy.per_class_active());
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        assert!(
            !class_mint_permitted(
                &ctx,
                &ctx_id,
                session,
                &class_template(CkObjectClass::DATA),
                None
            )
            .await,
            "class outside the grant must be denied at mint"
        );
    }

    #[tokio::test]
    async fn class_mint_permitted_allows_listed_class() {
        let policy = policy_with_class_grant(MTLS_IDENTITY, vec!["secret_key".into()]);
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        assert!(
            class_mint_permitted(
                &ctx,
                &ctx_id,
                session,
                &class_template(CkObjectClass::SECRET_KEY),
                None
            )
            .await,
            "listed class must be permitted at mint"
        );
    }

    #[tokio::test]
    async fn class_mint_permitted_uses_default_when_template_has_no_class() {
        // Generate/derive templates often omit CKA_CLASS; the operation's
        // implied class (the default) is checked instead.
        let policy = policy_with_class_grant(MTLS_IDENTITY, vec!["secret_key".into()]);
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        assert!(
            class_mint_permitted(&ctx, &ctx_id, session, &[], Some(CkObjectClass::SECRET_KEY))
                .await,
            "allowed default class must be permitted"
        );
        assert!(
            !class_mint_permitted(&ctx, &ctx_id, session, &[], Some(CkObjectClass::PRIVATE_KEY))
                .await,
            "denied default class must be refused"
        );
    }

    #[tokio::test]
    async fn class_mint_permitted_no_class_no_default_allows_backend_to_decide() {
        // No knowable class (e.g. create without CKA_CLASS): the backend
        // rejects the malformed mint itself (nothing persists), so the
        // gate stays transparent instead of inventing its own refusal.
        let policy = policy_with_class_grant(MTLS_IDENTITY, vec!["secret_key".into()]);
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        assert!(
            class_mint_permitted(&ctx, &ctx_id, session, &[], None).await,
            "unknowable class must fall through to the backend verdict"
        );
    }

    #[tokio::test]
    async fn class_mint_permitted_transparent_when_gate_off() {
        let policy = TokenPolicy::from_config(&AuthConfig::default()).unwrap();
        assert!(!policy.per_class_active());
        let (ctx, ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        assert!(
            class_mint_permitted(
                &ctx,
                &ctx_id,
                session,
                &class_template(CkObjectClass::DATA),
                None
            )
            .await,
            "gate off must permit any class"
        );
    }

    #[tokio::test]
    async fn class_mint_permitted_unauthenticated_always_true() {
        let policy = policy_with_class_grant(MTLS_IDENTITY, vec!["secret_key".into()]);
        assert!(policy.per_class_active());
        let (ctx, ctx_id, session) = setup_extract_test(policy, None).await;
        assert!(
            class_mint_permitted(
                &ctx,
                &ctx_id,
                session,
                &class_template(CkObjectClass::DATA),
                None
            )
            .await,
            "unauthenticated peer must always be permitted (class grants are opt-in)"
        );
    }

    /// W1-C1-15: a context that vanishes mid-request (close racing an
    /// attribute read) must DENY extraction, not skip the extract-deny
    /// via a permissive default.
    #[tokio::test]
    async fn c1_15_extract_denies_when_context_vanished() {
        let policy = policy_for_identity(MTLS_IDENTITY);
        let (ctx, _ctx_id, session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        let gone = ClientContextId("c1-15-vanished-context".into());
        let permitted = extract_is_permitted(&ctx, &gone, session, 0).await.unwrap();
        assert!(!permitted, "vanished context must deny extraction (fail-closed), not permit");
    }

    /// W1-C1-15: a session that vanishes mid-request must DENY extraction.
    #[tokio::test]
    async fn c1_15_extract_denies_when_session_vanished() {
        let policy = policy_for_identity(MTLS_IDENTITY);
        let (ctx, ctx_id, _session) = setup_extract_test(policy, Some(MTLS_IDENTITY.into())).await;
        let permitted = extract_is_permitted(&ctx, &ctx_id, 0xDEAD_BEEF, 0).await.unwrap();
        assert!(!permitted, "vanished session must deny extraction (fail-closed), not permit");
    }

    // --- fetch_object_metadata ---

    mod fetch_object_metadata_tests {
        use super::*;
        use pkcs11_proxy_ng_backend::mock::MockAttributeSlot;

        /// Open a real backend session and create a live object on the mock, then
        /// set the required CLASS and TOKEN attributes (required by conformant backends
        /// and by `fetch_object_metadata`'s fail-closed CONTRACT).
        fn mock_with_session_and_object() -> (Arc<MockBackend>, CkSessionHandle, CkObjectHandle) {
            let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
            mock.initialize().unwrap();
            let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
            let session = mock.open_session(CkSlotId(0), flags).unwrap();
            let object = mock.create_object(session, Some(&[])).unwrap();
            // CLASS and TOKEN are mandatory in conformant backends; set them so the
            // 3-element template does not fail with ATTRIBUTE_TYPE_INVALID.
            mock.set_attribute(
                object,
                CkAttributeType::CLASS,
                MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
            );
            mock.set_attribute(
                object,
                CkAttributeType::TOKEN,
                MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
            );
            (mock, session, object)
        }

        fn make_ctx(mock: Arc<MockBackend>) -> HandlerContext {
            let backend: Arc<dyn Pkcs11Backend> = mock;
            let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
            HandlerContext::for_test(&ctx_mgr, &backend)
        }

        #[tokio::test]
        async fn returns_metadata_when_backend_has_all_attrs() {
            let (mock, session, object) = mock_with_session_and_object();
            let uid = b"d41d8cd9-8f00-3204-a980-0998ecf8427e".to_vec();
            mock.set_attribute(
                object,
                CkAttributeType::UNIQUE_ID,
                MockAttributeSlot::Value(CkAttributeValue::Bytes(uid.clone().into())),
            );
            let ctx = make_ctx(mock);
            let result = fetch_object_metadata(&ctx, session, object).await;
            let meta = result.expect("must return metadata when all attrs present");
            assert_eq!(
                meta.unique_id,
                SecretBytes::new(uid),
                "uid must match the registered value"
            );
            assert_eq!(meta.class, Some(CkObjectClass::SECRET_KEY), "class must be SECRET_KEY");
            assert!(!meta.is_token, "is_token must be false for a session object");
        }

        #[tokio::test]
        async fn returns_none_when_uid_attr_type_invalid() {
            let (mock, session, object) = mock_with_session_and_object();
            mock.set_attribute(object, CkAttributeType::UNIQUE_ID, MockAttributeSlot::InvalidType);
            let ctx = make_ctx(mock);
            let result = fetch_object_metadata(&ctx, session, object).await;
            assert!(result.is_none(), "CKR_ATTRIBUTE_TYPE_INVALID must map to None");
        }

        #[tokio::test]
        async fn returns_none_when_uid_attr_sensitive() {
            let (mock, session, object) = mock_with_session_and_object();
            mock.set_attribute(object, CkAttributeType::UNIQUE_ID, MockAttributeSlot::Sensitive);
            let ctx = make_ctx(mock);
            let result = fetch_object_metadata(&ctx, session, object).await;
            assert!(result.is_none(), "CKR_ATTRIBUTE_SENSITIVE must map to None");
        }

        #[tokio::test]
        async fn token_object_is_token_true() {
            let (mock, session, object) = mock_with_session_and_object();
            // Override TOKEN to true.
            mock.set_attribute(
                object,
                CkAttributeType::TOKEN,
                MockAttributeSlot::Value(CkAttributeValue::Bool(true)),
            );
            let uid = b"token-obj-uid".to_vec();
            mock.set_attribute(
                object,
                CkAttributeType::UNIQUE_ID,
                MockAttributeSlot::Value(CkAttributeValue::Bytes(uid.clone().into())),
            );
            let ctx = make_ctx(mock);
            let meta = fetch_object_metadata(&ctx, session, object).await.unwrap();
            assert!(meta.is_token, "CKA_TOKEN=true must parse as is_token=true");
        }

        #[tokio::test]
        async fn session_object_metadata_is_cached_token_object_is_gated() {
            // W1-L13-18: a session object (is_token=false) caches per-handle,
            // while a token object (is_token=true) caches gated by the authz
            // generation — revocation invalidates the token entry only.
            use crate::server::context_manager::ContextManager;

            let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
            let ctx_id = ctx_mgr.create_context(None).await.unwrap();

            let session_meta = ObjectMetadata {
                unique_id: b"ses-uid".to_vec().into(),
                class: Some(CkObjectClass::SECRET_KEY),
                is_token: false,
            };
            ctx_mgr.cache_object_metadata(&ctx_id, 1, session_meta.clone()).await;
            let cached = ctx_mgr.object_metadata(&ctx_id, 1).await;
            assert!(cached.is_some(), "session object metadata must be cached");

            let token_meta = ObjectMetadata {
                unique_id: b"tok-uid".to_vec().into(),
                class: Some(CkObjectClass::SECRET_KEY),
                is_token: true,
            };
            ctx_mgr.cache_object_metadata(&ctx_id, 2, token_meta).await;
            let cached_token = ctx_mgr.object_metadata(&ctx_id, 2).await;
            assert!(
                cached_token.is_some(),
                "token object metadata must be cached within the generation"
            );

            ctx_mgr.revoke_authz_generation();
            assert!(
                ctx_mgr.object_metadata(&ctx_id, 2).await.is_none(),
                "revocation must invalidate cached token metadata"
            );
            assert!(
                ctx_mgr.object_metadata(&ctx_id, 1).await.is_some(),
                "revocation must not evict session-object entries"
            );
        }

        #[tokio::test]
        async fn token_object_refetched_after_revocation() {
            // W1-L13-18 proof via mock call count: a token object (is_token=true)
            // is cached within the authz generation (repeated gated uses issue
            // one backend fetch) and re-fetched after revocation. We verify by
            // counting get_attribute_value calls against the mock backend.
            // This is tested in service_utils::tests as
            // per_object_gate_token_object_cached_until_revoked.
        }

        // --- M2: unrecognised CLASS format yields class=None, not fail-closed ---

        #[tokio::test]
        async fn m2_unrecognised_class_format_returns_metadata_with_none_class() {
            // M2: a CLASS value that is present but in an unrecognised byte-width
            // (not 4 or 8 bytes) must NOT cause fetch_object_metadata to return None.
            // Previously the `_ => return Ok(None)` branch was fail-closed for ALL
            // unrecognised CLASS encodings, breaking uid-only deployments when
            // backends emit unusual class widths.
            //
            // After M2: class parsing failure → class=None in ObjectMetadata.
            // The call still returns Some — uid-only deployments remain functional.
            let (mock, session, object) = mock_with_session_and_object();
            // Override CLASS with a 3-byte value: present but unrecognisable size
            // (valid sizes are 4 and 8 bytes). The backend call succeeds (no error
            // code from mock) so parsing is reached.
            mock.set_attribute(
                object,
                CkAttributeType::CLASS,
                MockAttributeSlot::Value(CkAttributeValue::Bytes(vec![0x00, 0x00, 0x03].into())),
            );
            let uid = b"uid-odd-class".to_vec();
            mock.set_attribute(
                object,
                CkAttributeType::UNIQUE_ID,
                MockAttributeSlot::Value(CkAttributeValue::Bytes(uid.clone().into())),
            );
            let ctx = make_ctx(mock);
            let result = fetch_object_metadata(&ctx, session, object).await;
            // M2: must return Some (not None) even though CLASS cannot be parsed.
            let meta = result.expect("M2: unrecognised CLASS format must NOT fail the fetch");
            assert_eq!(
                meta.unique_id,
                SecretBytes::new(uid),
                "uid must still be populated when CLASS unrecognised"
            );
            assert!(
                meta.class.is_none(),
                "M2: unrecognised CLASS encoding must map to class=None in metadata"
            );
        }

        #[tokio::test]
        async fn m2_present_class_returns_metadata_with_some_class() {
            // Regression guard: a normally-present CLASS is still parsed into Some(class).
            let (mock, session, object) = mock_with_session_and_object();
            let uid = b"uid-with-class".to_vec();
            mock.set_attribute(
                object,
                CkAttributeType::UNIQUE_ID,
                MockAttributeSlot::Value(CkAttributeValue::Bytes(uid.clone().into())),
            );
            let ctx = make_ctx(mock);
            let meta = fetch_object_metadata(&ctx, session, object).await.unwrap();
            assert_eq!(
                meta.class,
                Some(CkObjectClass::SECRET_KEY),
                "M2: normally-present CLASS must parse into Some(class)"
            );
        }
    }
}

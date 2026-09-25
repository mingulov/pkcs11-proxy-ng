use std::future::Future;
use std::sync::Arc;

use crate::config::{AuthConfig, TcpAuthMode, UnixAuthMode};
use crate::mechanism_registry_source::MechanismRegistrySource;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_proto::Pkcs11Proxy;
use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use pkcs11_proxy_ng_types::*;
use tonic::{Request, Response, Status};

use super::audit::AuditSink;
use super::auth::policy::TokenPolicy;
use super::context_manager::ContextManager;

mod async_ops;
mod audit_events;
mod authorization;
mod byte_output_exact;
mod combined;
mod context;
mod digest_cipher;
mod general;
mod key_ops;
mod mechanism_handles;
mod message_crypto;
mod object;
mod parameter_output_exact;
pub mod service_utils;
mod session;
mod session_3x;
mod sign_verify;
mod slot;
mod state_ops;

pub(crate) use context::HandlerContext;

/// The gRPC service implementation for all PKCS#11 proxy RPCs (ADR-0003).
///
/// Every RPC returns `Ok(Response)` with `ck_rv` in the body. gRPC `Status::Ok`
/// is used whenever a valid `ck_rv` can be returned; transport-level errors use
/// gRPC error codes only for truly unrecoverable situations (e.g. spawn_blocking
/// panic).
#[derive(Clone)]
pub struct Pkcs11ProxyService {
    /// All cross-cutting, request-independent handler state (context manager,
    /// backend, token policy, mechanism registry, transport auth modes,
    /// `sanitize_inputs`, audit sink). Aggregated so a new gateway concern is a
    /// field on `HandlerContext`, not another positional parameter threaded
    /// through every dispatched handler.
    pub(super) ctx: HandlerContext,
}

impl Pkcs11ProxyService {
    pub fn new(
        context_manager: Arc<ContextManager>,
        backend: Arc<dyn Pkcs11Backend>,
        tcp_auth_mode: TcpAuthMode,
        unix_auth_mode: UnixAuthMode,
        token_policy: Arc<TokenPolicy>,
        mechanism_registry_source: MechanismRegistrySource,
        audit: Option<AuditSink>,
    ) -> Self {
        Self {
            ctx: HandlerContext {
                object_cleanup: Arc::default(),
                context_manager,
                backend,
                tcp_auth_mode,
                unix_auth_mode,
                token_policy,
                mechanism_registry_source,
                sanitize_inputs: false,
                audit,
            },
        }
    }

    /// Enable sanitize_inputs mode for tests that need daemon-side input rejection.
    pub fn with_sanitize_inputs(mut self) -> Self {
        self.ctx.sanitize_inputs = true;
        self
    }

    pub fn insecure_for_tests(
        context_manager: Arc<ContextManager>,
        backend: Arc<dyn Pkcs11Backend>,
    ) -> Self {
        let token_policy =
            Arc::new(TokenPolicy::from_config(&AuthConfig::default()).expect("default policy"));
        let registry = MechanismRegistrySource::load(None)
            .expect("embedded mechanism registry must always load");
        Self::new(
            context_manager,
            backend,
            TcpAuthMode::None,
            UnixAuthMode::None,
            token_policy,
            registry,
            None, // audit: tests that need emission will pass a sink explicitly
        )
        // sanitize_inputs defaults to false — transparent forwarding (ADR-0010)
    }

    /// A2: reject any request whose live transport identity does not own the
    /// `client_context_id` it presents. The id is an unauthenticated bearer
    /// token, so it is re-bound to the caller's identity on every RPC (the
    /// identity is captured once at C_Initialize). `raw_ctx_id` is the request's
    /// `client_context_id` field; an unknown context passes here and the handler
    /// returns the proper CK_RV.
    async fn check_context_owner<T>(
        &self,
        request: &Request<T>,
        raw_ctx_id: &str,
    ) -> Result<(), Status> {
        authorization::enforce_context_owner(
            &self.ctx.context_manager,
            request,
            &super::context_manager::ClientContextId(raw_ctx_id.to_owned()),
            self.ctx.tcp_auth_mode,
            self.ctx.unix_auth_mode,
        )
        .await
    }
}

pub(super) fn ck_result_to_rv<T>(r: CkResult<T>) -> (u64, Option<T>) {
    match r {
        Ok(v) => (CkRv::OK.0, Some(v)),
        Err(e) => (e.0, None),
    }
}

pub(super) fn convert_template(
    attrs: &[pkcs11_proxy_ng_proto::Attribute],
) -> Result<Vec<CkAttribute>, u64> {
    attrs.iter().map(|a| CkAttribute::try_from(a).map_err(|e| e.0)).collect()
}

/// `convert_template` with Wave 3.5 D2 NULL-template preservation: a set
/// `template_null` bit yields `None` (the caller's NULL template pointer),
/// which the FFI backend materializes as NULL instead of (ptr, 0). A NULL
/// bit with a non-empty attribute list is a malformed request.
pub(super) fn convert_template_opt(
    attrs: &[pkcs11_proxy_ng_proto::Attribute],
    template_null: bool,
) -> Result<Option<Vec<CkAttribute>>, u64> {
    if template_null {
        if !attrs.is_empty() {
            return Err(CkRv::ARGUMENTS_BAD.0);
        }
        Ok(None)
    } else {
        convert_template(attrs).map(Some)
    }
}

/// Encode a `CkAttributeValue` into the on-wire `bytes` representation
/// the proto uses for `AttributeResult.value`.
///
/// Consumes the value by move. The `Bytes`/`String` variants copy through
/// the [`secret_to_plain`] ADR-0013 §5 boundary (the owned `SecretBytes`
/// is dropped and wiped afterwards); the scalar variants (`Bool`, `Ulong`)
/// construct a fresh small `Vec`.
pub(super) fn attr_value_to_bytes(v: CkAttributeValue) -> Vec<u8> {
    match v {
        CkAttributeValue::Bool(b) => vec![u8::from(b)],
        // Native order (not LE): this path shares the attr_cache key space
        // with the exact path's raw backend bytes, so both encodings must
        // agree on every host order (see the M1 encoding notes).
        CkAttributeValue::Ulong(u) => u.to_ne_bytes().to_vec(),
        CkAttributeValue::Bytes(b) => secret_to_plain(&b),
        CkAttributeValue::String(s) => secret_to_plain(&s),
        // Nested templates never travel through AttributeResult's flat
        // bytes field — the exact path carries them structurally. Empty
        // rather than fabricated struct bytes.
        CkAttributeValue::NestedTemplate(_) => Vec::new(),
    }
}

/// Resolve the principal key for `client_context_id` and acquire one in-flight
/// slot from the per-principal cap (G2-PR3).
///
/// Returns `Ok(guard)` on success (the guard is a zero-cost no-op when
/// `per_principal_max_in_flight` is unset — byte-identical to having no rate
/// limiting). Returns `Err(Status::resource_exhausted)` when the principal is
/// at its cap; the rejection metric is incremented internally by the rate-quota
/// module.
///
/// Must be called AFTER `check_context_owner` so an unauthorized
/// `client_context_id` is rejected before consuming any rate-quota slot.
/// Never touches the backend — a rejection does NOT increment the backend-health
/// failure counter.
fn acquire_principal_op_guard(
    ctx: &HandlerContext,
    client_context_id: &str,
) -> Result<crate::server::rate_quota::PrincipalOpGuard, Status> {
    let ctx_id = super::context_manager::ClientContextId(client_context_id.to_owned());
    let principal = ctx
        .context_manager
        .context_identity(&ctx_id)
        .unwrap_or_else(|| client_context_id.to_owned());
    crate::server::rate_quota::try_begin_principal_op(&principal)
        .ok_or_else(|| Status::resource_exhausted("per-principal concurrency limit exceeded"))
}

/// Admit one context-scoped operation under the per-context in-flight cap
/// (M2) and run `fut` with the resulting guard scoped.
///
/// Shared by the macro-generated RPCs and the 9 hand-written RPCs (W1-L6-01)
/// so the admission order and rejection values cannot drift:
/// * at cap → `Err(Status::resource_exhausted("per-context concurrency limit
///   exceeded"))`, and `fut` is never polled;
/// * missing context → `Ok(None)` guard, `fut` still runs so the handler
///   returns the proper `CK_RV`;
/// * admitted → `fut` runs inside `scope_context_operation`, so the context
///   stays un-evictable for the whole handler AND backend tasks cloned from
///   the guard keep it alive past timeout/cancel.
///
/// `peer` is the caller's TCP address for per-connection admission
/// (W1-L7-28): published task-locally for the whole future so
/// `spawn_backend` admits each backend call under the peer budget.
/// `None` (UDS / unknown transport) runs unadmitted under the global
/// breaker only.
///
/// Callers must run `check_context_owner` BEFORE this (a rejected identity
/// must not consume a cap slot) and acquire the per-principal guard INSIDE
/// `fut`. Final order: owner → M2 → scope → peer → per-principal → handler.
async fn run_context_scoped<T, F>(
    ctx: &HandlerContext,
    client_context_id: &str,
    peer: Option<std::net::SocketAddr>,
    fut: F,
) -> Result<T, Status>
where
    F: Future<Output = Result<T, Status>>,
{
    // Hold the context un-evictable for the whole operation so a
    // long backend call (keygen/derive on a slow HSM, larger than
    // the lease) is never reaped MID-CALL, AND enforce the
    // per-context in-flight cap so one noisy client cannot drain
    // the shared backend-call budget and DEVICE_ERROR every tenant
    // (M2). A context that is already gone yields Ok(None) and the
    // handler returns the right CKR.
    let operation_guard = match ctx.context_manager.begin_operation_capped(
        &super::context_manager::ClientContextId(client_context_id.to_owned()),
        service_utils::per_context_max_in_flight() as i64,
    ) {
        Ok(guard) => guard,
        Err(()) => {
            return Err(Status::resource_exhausted("per-context concurrency limit exceeded"));
        }
    };
    service_utils::scope_context_operation(
        operation_guard,
        service_utils::scope_peer_admission(peer, fut),
    )
    .await
}

// ── Dispatch rate-quota tests (G2-PR3) ────────────────────────────────────────
//
// Placed BEFORE `macro_rules! impl_proxy_service!` so the consistency-check
// source scanner does not mistake the test `async fn` names for RPC handlers.
// The scanner activates on `impl Pkcs11Proxy for ` (which appears inside the
// macro body below) and then counts every subsequent `async fn` as a handler.
// Inserting the tests here keeps them before that trigger line.
//
// These tests verify the per-principal cap at the dispatch seam level.
// The core cap logic (at-limit, drop, principal independence) is tested
// exhaustively by `rate_quota::tests` using local RateQuota instances.
// The tests here focus on three properties:
//   1. The shared helper is inert (always Ok) when the global limit is
//      unconfigured — the default for all CI tests.
//   2. `open_session` and a macro-generated handler pass through end-to-end
//      with the limit unset (regression guard: no behaviour change when off).
//   3. The principal key falls back to `client_context_id` when no identity
//      is bound to the context (unauthenticated / no transport auth).
#[cfg(test)]
mod dispatch_rate_quota_tests {
    use super::*;
    use crate::server::context_manager::ContextManager;
    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use std::sync::Arc;
    use tonic::Request;

    fn make_ctx_mgr() -> Arc<ContextManager> {
        Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0))
    }

    fn make_backend() -> Arc<dyn Pkcs11Backend> {
        let mock = MockBackend::default_test();
        mock.initialize().unwrap();
        Arc::new(mock)
    }

    // ── Helper unit tests ─────────────────────────────────────────────────────

    /// With no `per_principal_max_in_flight` configured (the opt-in default),
    /// `acquire_principal_op_guard` must always return `Ok` — zero-cost no-op
    /// path that is byte-identical to having no rate limiting.
    #[tokio::test]
    async fn principal_guard_no_limit_always_ok() {
        let ctx_mgr = make_ctx_mgr();
        let backend = make_backend();
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        // Many guards from the same principal must all succeed.
        let guards: Vec<_> = (0..50)
            .map(|_| acquire_principal_op_guard(&ctx, &ctx_id.0))
            .collect::<Result<Vec<_>, _>>()
            .expect("all guards must succeed with no limit configured");
        drop(guards);
    }

    /// Without a configured limit, two different principals can hold guards
    /// simultaneously (independence property, no-op path).
    #[tokio::test]
    async fn principal_guard_no_limit_different_principals_ok() {
        let ctx_mgr = make_ctx_mgr();
        let backend = make_backend();
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        // Bind distinct identities so the helper sees two different principals.
        let ctx_a = ctx_mgr.create_context(Some("alice".into())).await.unwrap();
        let ctx_b = ctx_mgr.create_context(Some("bob".into())).await.unwrap();

        let g_a = acquire_principal_op_guard(&ctx, &ctx_a.0).expect("alice ok");
        let g_b = acquire_principal_op_guard(&ctx, &ctx_b.0).expect("bob ok (independent)");
        drop(g_a);
        drop(g_b);
    }

    /// An unauthenticated context (no stored identity) must have the helper
    /// fall back to the `client_context_id` string as the principal key.
    /// With no limit configured the guard is still Ok.
    #[tokio::test]
    async fn principal_guard_falls_back_to_ctx_id_when_no_identity() {
        let ctx_mgr = make_ctx_mgr();
        let backend = make_backend();
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        // create_context(None) stores no identity.
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        assert!(
            ctx_mgr.context_identity(&ctx_id).is_none(),
            "setup: context must have no identity"
        );

        let g = acquire_principal_op_guard(&ctx, &ctx_id.0)
            .expect("fallback to ctx_id as principal must succeed with no limit");
        drop(g);
    }

    // ── Integration tests through Pkcs11ProxyService ─────────────────────────

    /// `open_session` (hand-written handler) passes end-to-end with no
    /// per-principal limit configured — the guard is a no-op and existing
    /// behaviour is unchanged.
    #[tokio::test]
    async fn open_session_through_service_inert_with_no_limit() {
        let ctx_mgr = make_ctx_mgr();
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let backend = make_backend();
        let svc = Pkcs11ProxyService::insecure_for_tests(ctx_mgr.clone(), backend);

        // create_context(None) stores no identity → owner check passes for any
        // transport (context_owner_allowed(None, _) = true).
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let virtual_slot = ctx_mgr.virtual_slots().await[0];

        let resp = svc
            .open_session(Request::new(pkcs11_proxy_ng_proto::OpenSessionRequest {
                client_context_id: ctx_id.0.clone(),
                slot_id: virtual_slot.0,
                flags: CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            resp.ck_rv,
            CkRv::OK.0,
            "open_session must succeed when per-principal limit is unset"
        );
    }

    /// A macro-generated handler (`get_info`) passes end-to-end with no
    /// per-principal limit configured — the `_pguard` is a no-op and existing
    /// behaviour is unchanged.
    #[tokio::test]
    async fn macro_handler_get_info_inert_with_no_limit() {
        let ctx_mgr = make_ctx_mgr();
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let backend = make_backend();
        let svc = Pkcs11ProxyService::insecure_for_tests(ctx_mgr.clone(), backend);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        let resp = svc
            .get_info(Request::new(pkcs11_proxy_ng_proto::GetInfoRequest {
                client_context_id: ctx_id.0.clone(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            resp.ck_rv,
            CkRv::OK.0,
            "macro-generated get_info must succeed when per-principal limit is unset"
        );
    }

    /// Multiple concurrent `open_session` calls from the same principal all
    /// proceed when the limit is unset (transparency: no behaviour change).
    #[tokio::test(flavor = "multi_thread")]
    async fn open_session_many_concurrent_no_limit() {
        let ctx_mgr = make_ctx_mgr();
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let backend = make_backend();
        let svc = Arc::new(Pkcs11ProxyService::insecure_for_tests(ctx_mgr.clone(), backend));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let virtual_slot = ctx_mgr.virtual_slots().await[0];

        let handles: Vec<_> = (0..20)
            .map(|_| {
                let svc = Arc::clone(&svc);
                let cid = ctx_id.0.clone();
                tokio::spawn(async move {
                    svc.open_session(Request::new(pkcs11_proxy_ng_proto::OpenSessionRequest {
                        client_context_id: cid,
                        slot_id: virtual_slot.0,
                        flags: CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION,
                    }))
                    .await
                    .unwrap()
                    .into_inner()
                    .ck_rv
                })
            })
            .collect();

        for handle in handles {
            assert_eq!(
                handle.await.unwrap(),
                CkRv::OK.0,
                "all concurrent open_session calls must succeed with no limit"
            );
        }
    }
}

// ── Scope-guard + M2-cap routing tests (W1-L6-01) ──────────────────────────────
//
// The 9 hand-written RPCs in the trait impl below must route through the same
// per-context operation guard (M2 cap) + `scope_context_operation` wrapper as
// the macro-generated RPCs, with identical rejection values. `initialize` and
// `get_backend_interfaces` are intentionally NOT in this list: they carry no
// `client_context_id` (pre-context discovery RPCs) and are rate-limited by the
// per-IP layer instead (see their handler comments).
//
// Placed BEFORE `macro_rules! impl_proxy_service!` for the same source-scanner
// reason as `dispatch_rate_quota_tests` above.
#[cfg(test)]
mod scoped_dispatch_tests {
    use super::*;
    use crate::server::context_manager::{ClientContextId, ContextManager};
    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tonic::{Code, Request};

    /// The 9 hand-written RPCs that carry a `client_context_id` and must
    /// enforce the scope guard + M2 cap (W1-L6-01). Every test below iterates
    /// this list and asserts its length; `consistency_checks::
    /// hand_written_context_rpcs_match_test_enumeration` additionally pins
    /// this exact set against the trait impl, so adding or removing a
    /// hand-written RPC without updating the enumeration fails loudly instead
    /// of silently dropping coverage. Keep the entries bare `"name",`
    /// literals — the consistency scanner parses them.
    const HAND_WRITTEN_RPCS: &[&str] = &[
        "get_slot_list",
        "get_slot_info",
        "get_token_info",
        "get_mechanism_list",
        "get_mechanism_info",
        "wait_for_slot_event",
        "open_session",
        "close_all_sessions",
        "init_token",
    ];

    struct Fixture {
        svc: Pkcs11ProxyService,
        ctx_mgr: Arc<ContextManager>,
        ctx_id: ClientContextId,
        slot: u64,
    }

    async fn setup() -> Fixture {
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let mock = MockBackend::default_test();
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
        let svc = Pkcs11ProxyService::insecure_for_tests(ctx_mgr.clone(), backend);
        // No identity → the A2 owner check passes and the principal key falls
        // back to the context id (same setup as `dispatch_rate_quota_tests`).
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let slot = ctx_mgr.virtual_slots().await[0].0;
        Fixture { svc, ctx_mgr, ctx_id, slot }
    }

    /// Dispatch one hand-written RPC by name; returns the `ck_rv` body on
    /// gRPC-level success. Panics on unknown names so a typo in
    /// `HAND_WRITTEN_RPCS` fails loudly.
    async fn call_hand_written_rpc(
        svc: &Pkcs11ProxyService,
        name: &str,
        client_context_id: &str,
        slot: u64,
    ) -> Result<u64, Status> {
        match name {
            "get_slot_list" => svc
                .get_slot_list(Request::new(pkcs11_proxy_ng_proto::GetSlotListRequest {
                    client_context_id: client_context_id.to_owned(),
                    token_present: false,
                }))
                .await
                .map(|r| r.into_inner().ck_rv),
            "get_slot_info" => svc
                .get_slot_info(Request::new(pkcs11_proxy_ng_proto::GetSlotInfoRequest {
                    client_context_id: client_context_id.to_owned(),
                    slot_id: slot,
                }))
                .await
                .map(|r| r.into_inner().ck_rv),
            "get_token_info" => svc
                .get_token_info(Request::new(pkcs11_proxy_ng_proto::GetTokenInfoRequest {
                    client_context_id: client_context_id.to_owned(),
                    slot_id: slot,
                }))
                .await
                .map(|r| r.into_inner().ck_rv),
            "get_mechanism_list" => svc
                .get_mechanism_list(Request::new(pkcs11_proxy_ng_proto::GetMechanismListRequest {
                    client_context_id: client_context_id.to_owned(),
                    slot_id: slot,
                }))
                .await
                .map(|r| r.into_inner().ck_rv),
            "get_mechanism_info" => svc
                .get_mechanism_info(Request::new(pkcs11_proxy_ng_proto::GetMechanismInfoRequest {
                    client_context_id: client_context_id.to_owned(),
                    slot_id: slot,
                    mechanism_type: CkMechanismType::RSA_PKCS.0,
                }))
                .await
                .map(|r| r.into_inner().ck_rv),
            "wait_for_slot_event" => svc
                .wait_for_slot_event(Request::new(pkcs11_proxy_ng_proto::WaitForSlotEventRequest {
                    client_context_id: client_context_id.to_owned(),
                    flags: 1, // CKF_DONT_BLOCK — never parks the test
                }))
                .await
                .map(|r| r.into_inner().ck_rv),
            "open_session" => svc
                .open_session(Request::new(pkcs11_proxy_ng_proto::OpenSessionRequest {
                    client_context_id: client_context_id.to_owned(),
                    slot_id: slot,
                    flags: CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION,
                }))
                .await
                .map(|r| r.into_inner().ck_rv),
            "close_all_sessions" => svc
                .close_all_sessions(Request::new(pkcs11_proxy_ng_proto::CloseAllSessionsRequest {
                    client_context_id: client_context_id.to_owned(),
                    slot_id: slot,
                }))
                .await
                .map(|r| r.into_inner().ck_rv),
            "init_token" => svc
                .init_token(Request::new(pkcs11_proxy_ng_proto::InitTokenRequest {
                    client_context_id: client_context_id.to_owned(),
                    slot_id: slot,
                    so_pin: Some(b"w1-l6-01-so-pin".to_vec()),
                    label: "w1-l6-01-test".into(),
                }))
                .await
                .map(|r| r.into_inner().ck_rv),
            unknown => panic!("unknown hand-written RPC in test enumeration: {unknown}"),
        }
    }

    /// W1-L6-01 core: every hand-written RPC must reject with the exact M2
    /// error once its context is at the per-context in-flight cap — the same
    /// code + message a macro-generated RPC (`get_info`) produces.
    #[tokio::test]
    async fn hand_written_rpcs_reject_at_per_context_cap() {
        // The enumeration itself is the contract: exactly these 9.
        assert_eq!(
            HAND_WRITTEN_RPCS.len(),
            9,
            "hand-written RPC enumeration must cover exactly 9 RPCs"
        );
        let fix = setup().await;
        // Saturate this context to its M2 cap (read live: another test in this
        // binary may reconfigure the global backend-call budget first).
        let cap = service_utils::per_context_max_in_flight();
        let _held = (0..cap)
            .map(|_| {
                fix.ctx_mgr
                    .begin_operation_capped(&fix.ctx_id, cap as i64)
                    .expect("fill below cap")
                    .expect("context exists")
            })
            .collect::<Vec<_>>();

        // Macro-path reference error, obtained the same way.
        let macro_err = fix
            .svc
            .get_info(Request::new(pkcs11_proxy_ng_proto::GetInfoRequest {
                client_context_id: fix.ctx_id.0.clone(),
            }))
            .await
            .expect_err("macro RPC must reject at the per-context cap");
        assert_eq!(macro_err.code(), Code::ResourceExhausted);
        assert_eq!(macro_err.message(), "per-context concurrency limit exceeded");

        let mut tested = Vec::new();
        for &name in HAND_WRITTEN_RPCS {
            let err = call_hand_written_rpc(&fix.svc, name, &fix.ctx_id.0, fix.slot)
                .await
                .expect_err(name);
            assert_eq!(err.code(), macro_err.code(), "{name}: code must match macro path");
            assert_eq!(err.message(), macro_err.message(), "{name}: message must match macro path");
            tested.push(name);
        }
        assert_eq!(tested, HAND_WRITTEN_RPCS, "every enumerated RPC must be exercised");
    }

    /// The guard is inert when under the cap: every hand-written RPC still
    /// answers (gRPC-level Ok) on an idle context — routing through the guard
    /// must not change success-path behaviour.
    #[tokio::test]
    async fn hand_written_rpcs_succeed_under_cap() {
        assert_eq!(
            HAND_WRITTEN_RPCS.len(),
            9,
            "hand-written RPC enumeration must cover exactly 9 RPCs"
        );
        let fix = setup().await;
        for &name in HAND_WRITTEN_RPCS {
            let rv = call_hand_written_rpc(&fix.svc, name, &fix.ctx_id.0, fix.slot).await;
            assert!(rv.is_ok(), "{name} must succeed under the cap, got: {rv:?}");
        }
    }

    /// A missing context yields `Ok(None)` from the capped admission (never a
    /// cap rejection): every hand-written RPC must return a normal `ck_rv`
    /// body for an unknown context, exactly as the macro path does.
    #[tokio::test]
    async fn hand_written_rpcs_unknown_context_returns_ckr() {
        assert_eq!(
            HAND_WRITTEN_RPCS.len(),
            9,
            "hand-written RPC enumeration must cover exactly 9 RPCs"
        );
        let fix = setup().await;
        for &name in HAND_WRITTEN_RPCS {
            let rv = call_hand_written_rpc(&fix.svc, name, "no-such-context", fix.slot).await;
            assert!(rv.is_ok(), "{name} must return ck_rv for unknown context, got: {rv:?}");
        }
    }

    /// The shared helper publishes the admitted guard into the task-local
    /// scope for the whole future (so `spawn_backend` clones it into blocking
    /// tasks) and releases it afterwards.
    #[tokio::test]
    async fn scoped_helper_holds_guard_for_the_whole_future() {
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        let mock = MockBackend::default_test();
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        assert!(service_utils::current_context_operation_guard().is_none());

        let seen = run_context_scoped(&ctx, &ctx_id.0, None, async {
            Result::<bool, Status>::Ok(service_utils::current_context_operation_guard().is_some())
        })
        .await
        .expect("admitted under cap");
        assert!(seen, "guard must be visible inside the scoped future");
        assert!(
            service_utils::current_context_operation_guard().is_none(),
            "guard must release after the future completes"
        );
    }

    /// At the cap the helper rejects with the exact M2 error without polling
    /// the future at all.
    #[tokio::test]
    async fn scoped_helper_rejects_at_cap_without_polling_future() {
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        let mock = MockBackend::default_test();
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let cap = service_utils::per_context_max_in_flight();
        let _held = (0..cap)
            .map(|_| {
                ctx_mgr
                    .begin_operation_capped(&ctx_id, cap as i64)
                    .expect("fill below cap")
                    .expect("context exists")
            })
            .collect::<Vec<_>>();

        let polled = Arc::new(AtomicBool::new(false));
        let mark = Arc::clone(&polled);
        let err = run_context_scoped(&ctx, &ctx_id.0, None, async move {
            mark.store(true, Ordering::Relaxed);
            Result::<(), Status>::Ok(())
        })
        .await
        .expect_err("must reject at cap");
        assert_eq!(err.code(), Code::ResourceExhausted);
        assert_eq!(err.message(), "per-context concurrency limit exceeded");
        assert!(!polled.load(Ordering::Relaxed), "future must never be polled at cap");
    }

    /// A missing context is NOT a cap rejection: the helper runs the future
    /// (with a `None` guard) so the handler returns the proper CK_RV.
    #[tokio::test]
    async fn scoped_helper_missing_context_runs_future() {
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        let mock = MockBackend::default_test();
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);

        let ran_none = run_context_scoped(&ctx, "no-such-context", None, async {
            Result::<bool, Status>::Ok(service_utils::current_context_operation_guard().is_none())
        })
        .await
        .expect("missing context must run the future");
        assert!(ran_none, "missing context scopes a None guard");
    }

    /// W1-L7-28: `run_context_scoped` publishes the caller's peer address
    /// task-locally for the whole future (so `spawn_backend` can admit
    /// per-connection) and releases it afterwards. `None` (UDS / unknown
    /// transport) propagates as `None` (unadmitted, global breaker only).
    #[tokio::test]
    async fn scoped_helper_publishes_peer_for_spawn_admission() {
        use std::net::SocketAddr;

        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        let mock = MockBackend::default_test();
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        assert!(service_utils::current_peer().is_none());

        let peer: SocketAddr = "192.0.2.60:1234".parse().unwrap();
        let seen = run_context_scoped(&ctx, &ctx_id.0, Some(peer), async {
            Result::<Option<SocketAddr>, Status>::Ok(service_utils::current_peer())
        })
        .await
        .expect("admitted under cap");
        assert_eq!(seen, Some(peer), "peer must be visible inside the scoped future");

        let seen_none = run_context_scoped(&ctx, &ctx_id.0, None, async {
            Result::<Option<SocketAddr>, Status>::Ok(service_utils::current_peer())
        })
        .await
        .expect("admitted under cap");
        assert_eq!(seen_none, None, "None peer must propagate as None");
        assert!(
            service_utils::current_peer().is_none(),
            "peer scope must release after the future completes"
        );
    }
}

macro_rules! impl_proxy_service {
    ($(($name:ident, $request:ident, $response:ident, $module:path)),+ $(,)?) => {
        #[tonic::async_trait]
        impl Pkcs11Proxy for Pkcs11ProxyService {
            async fn initialize(
                &self,
                request: Request<pkcs11_proxy_ng_proto::InitializeRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::InitializeResponse>, Status> {
                // No per-principal guard here: `initialize` CREATES the context so
                // there is no context_identity to key on yet. Connection-rate
                // limiting for pre-context requests is the responsibility of the
                // per-IP `rate_limit.rs` layer (G2-PR3).
                general::initialize(
                    &self.ctx.context_manager,
                    &self.ctx.backend,
                    request,
                    self.ctx.tcp_auth_mode,
                    self.ctx.unix_auth_mode,
                )
                .await
            }

            async fn get_slot_list(
                &self,
                request: Request<pkcs11_proxy_ng_proto::GetSlotListRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::GetSlotListResponse>, Status> {
                self.check_context_owner(&request, &request.get_ref().client_context_id)
                    .await?;
                // W1-L6-01: same M2 admission + scope as the macro-generated
                // RPCs (order: owner → M2 → scope → per-principal → handler).
                let client_context_id = request.get_ref().client_context_id.clone();
                // W1-L7-28: publish the TCP peer for per-connection admission.
                let peer_addr = request.remote_addr();
                run_context_scoped(&self.ctx, &client_context_id, peer_addr, async {
                    // G2-PR3: per-principal in-flight cap (opt-in; no-op when unset).
                    let _pguard =
                        acquire_principal_op_guard(&self.ctx, &client_context_id)?;
                    slot::get_slot_list_with_policy(
                        &self.ctx.context_manager,
                        &self.ctx.backend,
                        self.ctx.token_policy.as_ref(),
                        request,
                    )
                    .await
                })
                .await
            }

            async fn get_slot_info(
                &self,
                request: Request<pkcs11_proxy_ng_proto::GetSlotInfoRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::GetSlotInfoResponse>, Status> {
                self.check_context_owner(&request, &request.get_ref().client_context_id)
                    .await?;
                // W1-L6-01: same M2 admission + scope as the macro-generated
                // RPCs (order: owner → M2 → scope → per-principal → handler).
                let client_context_id = request.get_ref().client_context_id.clone();
                // W1-L7-28: publish the TCP peer for per-connection admission.
                let peer_addr = request.remote_addr();
                run_context_scoped(&self.ctx, &client_context_id, peer_addr, async {
                    // G2-PR3: per-principal in-flight cap (opt-in; no-op when unset).
                    let _pguard =
                        acquire_principal_op_guard(&self.ctx, &client_context_id)?;
                    slot::get_slot_info_with_policy(
                        &self.ctx.context_manager,
                        &self.ctx.backend,
                        self.ctx.token_policy.as_ref(),
                        request,
                    )
                    .await
                })
                .await
            }

            async fn get_token_info(
                &self,
                request: Request<pkcs11_proxy_ng_proto::GetTokenInfoRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::GetTokenInfoResponse>, Status> {
                self.check_context_owner(&request, &request.get_ref().client_context_id)
                    .await?;
                // W1-L6-01: same M2 admission + scope as the macro-generated
                // RPCs (order: owner → M2 → scope → per-principal → handler).
                let client_context_id = request.get_ref().client_context_id.clone();
                // W1-L7-28: publish the TCP peer for per-connection admission.
                let peer_addr = request.remote_addr();
                run_context_scoped(&self.ctx, &client_context_id, peer_addr, async {
                    // G2-PR3: per-principal in-flight cap (opt-in; no-op when unset).
                    let _pguard =
                        acquire_principal_op_guard(&self.ctx, &client_context_id)?;
                    slot::get_token_info_with_policy(
                        &self.ctx.context_manager,
                        &self.ctx.backend,
                        self.ctx.token_policy.as_ref(),
                        request,
                    )
                    .await
                })
                .await
            }

            async fn get_mechanism_list(
                &self,
                request: Request<pkcs11_proxy_ng_proto::GetMechanismListRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::GetMechanismListResponse>, Status> {
                self.check_context_owner(&request, &request.get_ref().client_context_id)
                    .await?;
                // W1-L6-01: same M2 admission + scope as the macro-generated
                // RPCs (order: owner → M2 → scope → per-principal → handler).
                let client_context_id = request.get_ref().client_context_id.clone();
                // W1-L7-28: publish the TCP peer for per-connection admission.
                let peer_addr = request.remote_addr();
                run_context_scoped(&self.ctx, &client_context_id, peer_addr, async {
                    // G2-PR3: per-principal in-flight cap (opt-in; no-op when unset).
                    let _pguard =
                        acquire_principal_op_guard(&self.ctx, &client_context_id)?;
                    slot::get_mechanism_list_with_policy(
                        &self.ctx.context_manager,
                        &self.ctx.backend,
                        self.ctx.token_policy.as_ref(),
                        request,
                    )
                    .await
                })
                .await
            }

            async fn get_mechanism_info(
                &self,
                request: Request<pkcs11_proxy_ng_proto::GetMechanismInfoRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::GetMechanismInfoResponse>, Status> {
                self.check_context_owner(&request, &request.get_ref().client_context_id)
                    .await?;
                // W1-L6-01: same M2 admission + scope as the macro-generated
                // RPCs (order: owner → M2 → scope → per-principal → handler).
                let client_context_id = request.get_ref().client_context_id.clone();
                // W1-L7-28: publish the TCP peer for per-connection admission.
                let peer_addr = request.remote_addr();
                run_context_scoped(&self.ctx, &client_context_id, peer_addr, async {
                    // G2-PR3: per-principal in-flight cap (opt-in; no-op when unset).
                    let _pguard =
                        acquire_principal_op_guard(&self.ctx, &client_context_id)?;
                    slot::get_mechanism_info_with_policy(
                        &self.ctx.context_manager,
                        &self.ctx.backend,
                        self.ctx.token_policy.as_ref(),
                        request,
                    )
                    .await
                })
                .await
            }

            async fn get_backend_interfaces(
                &self,
                request: Request<pkcs11_proxy_ng_proto::GetBackendInterfacesRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::GetBackendInterfacesResponse>, Status> {
                // No per-principal guard here: GetBackendInterfaces carries no
                // client_context_id and requires no prior C_Initialize — it is
                // a discovery RPC akin to initialize. Connection-rate limiting
                // for such pre-context calls is the responsibility of the
                // per-IP `rate_limit.rs` layer (G2-PR3).
                general::get_backend_interfaces(
                    &self.ctx.context_manager,
                    &self.ctx.backend,
                    &self.ctx.mechanism_registry_source,
                    request,
                )
                .await
            }

            async fn wait_for_slot_event(
                &self,
                request: Request<pkcs11_proxy_ng_proto::WaitForSlotEventRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::WaitForSlotEventResponse>, Status> {
                // Hand-written (not via the dispatch macro) because it needs the
                // token policy to suppress events for unauthorized slots (M13).
                self.check_context_owner(&request, &request.get_ref().client_context_id)
                    .await?;
                // W1-L6-01: same M2 admission + scope as the macro-generated
                // RPCs (replacing the previous uncapped `begin_operation`) — a
                // blocking wait (CKF_DONT_BLOCK omitted) must not be reaped
                // mid-call.
                let client_context_id = request.get_ref().client_context_id.clone();
                // W1-L7-28: publish the TCP peer for per-connection admission.
                let peer_addr = request.remote_addr();
                run_context_scoped(&self.ctx, &client_context_id, peer_addr, async {
                    // G2-PR3: per-principal in-flight cap (opt-in; no-op when unset).
                    let _pguard =
                        acquire_principal_op_guard(&self.ctx, &client_context_id)?;
                    state_ops::wait_for_slot_event_with_policy(
                        &self.ctx.context_manager,
                        &self.ctx.backend,
                        self.ctx.token_policy.as_ref(),
                        request,
                    )
                    .await
                })
                .await
            }

            async fn open_session(
                &self,
                request: Request<pkcs11_proxy_ng_proto::OpenSessionRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::OpenSessionResponse>, Status> {
                self.check_context_owner(&request, &request.get_ref().client_context_id)
                    .await?;
                // W1-L6-01: same M2 admission + scope as the macro-generated
                // RPCs (order: owner → M2 → scope → per-principal → handler).
                let client_context_id = request.get_ref().client_context_id.clone();
                // W1-L7-28: publish the TCP peer for per-connection admission.
                let peer_addr = request.remote_addr();
                run_context_scoped(&self.ctx, &client_context_id, peer_addr, async {
                    // G2-PR3: per-principal in-flight cap (opt-in; no-op when unset).
                    let _pguard =
                        acquire_principal_op_guard(&self.ctx, &client_context_id)?;
                    session::open_session_with_policy(&self.ctx, request).await
                })
                .await
            }

            async fn close_all_sessions(
                &self,
                request: Request<pkcs11_proxy_ng_proto::CloseAllSessionsRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::CloseAllSessionsResponse>, Status> {
                self.check_context_owner(&request, &request.get_ref().client_context_id)
                    .await?;
                // W1-L6-01: same M2 admission + scope as the macro-generated
                // RPCs (order: owner → M2 → scope → per-principal → handler).
                let client_context_id = request.get_ref().client_context_id.clone();
                // W1-L7-28: publish the TCP peer for per-connection admission.
                let peer_addr = request.remote_addr();
                run_context_scoped(&self.ctx, &client_context_id, peer_addr, async {
                    // G2-PR3: per-principal in-flight cap (opt-in; no-op when unset).
                    let _pguard =
                        acquire_principal_op_guard(&self.ctx, &client_context_id)?;
                    session::close_all_sessions_with_policy(
                        &self.ctx.context_manager,
                        &self.ctx.backend,
                        self.ctx.token_policy.as_ref(),
                        request,
                    )
                    .await
                })
                .await
            }

            async fn init_token(
                &self,
                request: Request<pkcs11_proxy_ng_proto::InitTokenRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::InitTokenResponse>, Status> {
                self.check_context_owner(&request, &request.get_ref().client_context_id)
                    .await?;
                // W1-L6-01: same M2 admission + scope as the macro-generated
                // RPCs (order: owner → M2 → scope → per-principal → handler).
                let client_context_id = request.get_ref().client_context_id.clone();
                // W1-L7-28: publish the TCP peer for per-connection admission.
                let peer_addr = request.remote_addr();
                run_context_scoped(&self.ctx, &client_context_id, peer_addr, async {
                    // G2-PR3: per-principal in-flight cap (opt-in; no-op when unset).
                    let _pguard =
                        acquire_principal_op_guard(&self.ctx, &client_context_id)?;
                    session::init_token_with_policy(&self.ctx, request).await
                })
                .await
            }

            $(
                async fn $name(
                    &self,
                    request: Request<pkcs11_proxy_ng_proto::$request>,
                ) -> Result<Response<pkcs11_proxy_ng_proto::$response>, Status> {
                    // A2: bind the caller's transport identity to the context it
                    // claims before touching any state.
                    self.check_context_owner(
                        &request,
                        &request.get_ref().client_context_id,
                    )
                    .await?;
                    // M2 admission + operation scope, shared with the 9
                    // hand-written RPCs (W1-L6-01). Order: owner → M2 → scope →
                    // per-principal → handler.
                    let client_context_id = request.get_ref().client_context_id.clone();
                    // W1-L7-28: publish the TCP peer for per-connection admission.
                    let peer_addr = request.remote_addr();
                    run_context_scoped(&self.ctx, &client_context_id, peer_addr, async {
                        // G2-PR3: per-principal in-flight cap (opt-in; zero-cost
                        // no-op when per_principal_max_in_flight is unset →
                        // byte-identical to the pre-quota path). Acquired AFTER
                        // context-owner validation and the per-context cap.
                        // Never reaches the backend → rejection does NOT increment
                        // the backend-health failure counter.
                        let _pguard =
                            acquire_principal_op_guard(&self.ctx, &client_context_id)?;
                        $module(&self.ctx, request).await
                    })
                    .await
                }
            )+
        }
    };
}

impl_proxy_service!(
    (finalize, FinalizeRequest, FinalizeResponse, general::finalize),
    (get_info, GetInfoRequest, GetInfoResponse, general::get_info),
    (close_session, CloseSessionRequest, CloseSessionResponse, session::close_session),
    (get_session_info, GetSessionInfoRequest, GetSessionInfoResponse, session::get_session_info),
    (login, LoginRequest, LoginResponse, session::login),
    (logout, LogoutRequest, LogoutResponse, session::logout),
    (init_pin, InitPinRequest, InitPinResponse, session::init_pin),
    (set_pin, SetPinRequest, SetPinResponse, session::set_pin),
    // Legacy parallel function status (PKCS#11 2.40)
    (
        get_function_status,
        GetFunctionStatusRequest,
        GetFunctionStatusResponse,
        session::get_function_status
    ),
    (cancel_function, CancelFunctionRequest, CancelFunctionResponse, session::cancel_function),
    (find_objects_init, FindObjectsInitRequest, FindObjectsInitResponse, object::find_objects_init),
    (find_objects, FindObjectsRequest, FindObjectsResponse, object::find_objects),
    (
        find_objects_final,
        FindObjectsFinalRequest,
        FindObjectsFinalResponse,
        object::find_objects_final
    ),
    (
        get_attribute_value,
        GetAttributeValueRequest,
        GetAttributeValueResponse,
        object::get_attribute_value
    ),
    (
        get_attribute_value_exact,
        GetAttributeValueExactRequest,
        GetAttributeValueExactResponse,
        object::get_attribute_value_exact
    ),
    (create_object, CreateObjectRequest, CreateObjectResponse, object::create_object),
    (copy_object, CopyObjectRequest, CopyObjectResponse, object::copy_object),
    (destroy_object, DestroyObjectRequest, DestroyObjectResponse, object::destroy_object),
    (get_object_size, GetObjectSizeRequest, GetObjectSizeResponse, object::get_object_size),
    (
        set_attribute_value,
        SetAttributeValueRequest,
        SetAttributeValueResponse,
        object::set_attribute_value
    ),
    (sign_init, SignInitRequest, SignInitResponse, sign_verify::sign_init),
    (sign, SignRequest, SignResponse, sign_verify::sign),
    (sign_update, SignUpdateRequest, SignUpdateResponse, sign_verify::sign_update),
    (sign_final, SignFinalRequest, SignFinalResponse, sign_verify::sign_final),
    (verify_init, VerifyInitRequest, VerifyInitResponse, sign_verify::verify_init),
    (verify, VerifyRequest, VerifyResponse, sign_verify::verify),
    (verify_update, VerifyUpdateRequest, VerifyUpdateResponse, sign_verify::verify_update),
    (verify_final, VerifyFinalRequest, VerifyFinalResponse, sign_verify::verify_final),
    (
        sign_recover_init,
        SignRecoverInitRequest,
        SignRecoverInitResponse,
        sign_verify::sign_recover_init
    ),
    (sign_recover, SignRecoverRequest, SignRecoverResponse, sign_verify::sign_recover),
    (
        verify_recover_init,
        VerifyRecoverInitRequest,
        VerifyRecoverInitResponse,
        sign_verify::verify_recover_init
    ),
    (verify_recover, VerifyRecoverRequest, VerifyRecoverResponse, sign_verify::verify_recover),
    (digest_init, DigestInitRequest, DigestInitResponse, digest_cipher::digest_init),
    (digest, DigestRequest, DigestResponse, digest_cipher::digest),
    (digest_update, DigestUpdateRequest, DigestUpdateResponse, digest_cipher::digest_update),
    (digest_key, DigestKeyRequest, DigestKeyResponse, digest_cipher::digest_key),
    (digest_final, DigestFinalRequest, DigestFinalResponse, digest_cipher::digest_final),
    (encrypt_init, EncryptInitRequest, EncryptInitResponse, digest_cipher::encrypt_init),
    (encrypt, EncryptRequest, EncryptResponse, digest_cipher::encrypt),
    (encrypt_update, EncryptUpdateRequest, EncryptUpdateResponse, digest_cipher::encrypt_update),
    (encrypt_final, EncryptFinalRequest, EncryptFinalResponse, digest_cipher::encrypt_final),
    (decrypt_init, DecryptInitRequest, DecryptInitResponse, digest_cipher::decrypt_init),
    (decrypt, DecryptRequest, DecryptResponse, digest_cipher::decrypt),
    (decrypt_update, DecryptUpdateRequest, DecryptUpdateResponse, digest_cipher::decrypt_update),
    (decrypt_final, DecryptFinalRequest, DecryptFinalResponse, digest_cipher::decrypt_final),
    (
        generate_key_pair,
        GenerateKeyPairRequest,
        GenerateKeyPairResponse,
        key_ops::generate_key_pair
    ),
    (generate_key, GenerateKeyRequest, GenerateKeyResponse, key_ops::generate_key),
    (derive_key, DeriveKeyRequest, DeriveKeyResponse, key_ops::derive_key),
    (wrap_key, WrapKeyRequest, WrapKeyResponse, key_ops::wrap_key),
    (unwrap_key, UnwrapKeyRequest, UnwrapKeyResponse, key_ops::unwrap_key),
    (generate_random, GenerateRandomRequest, GenerateRandomResponse, state_ops::generate_random),
    (
        get_operation_state,
        GetOperationStateRequest,
        GetOperationStateResponse,
        state_ops::get_operation_state
    ),
    (
        set_operation_state,
        SetOperationStateRequest,
        SetOperationStateResponse,
        state_ops::set_operation_state
    ),
    (seed_random, SeedRandomRequest, SeedRandomResponse, state_ops::seed_random),
    (
        digest_encrypt_update,
        DigestEncryptUpdateRequest,
        DigestEncryptUpdateResponse,
        combined::digest_encrypt_update
    ),
    (
        decrypt_digest_update,
        DecryptDigestUpdateRequest,
        DecryptDigestUpdateResponse,
        combined::decrypt_digest_update
    ),
    (
        sign_encrypt_update,
        SignEncryptUpdateRequest,
        SignEncryptUpdateResponse,
        combined::sign_encrypt_update
    ),
    (
        decrypt_verify_update,
        DecryptVerifyUpdateRequest,
        DecryptVerifyUpdateResponse,
        combined::decrypt_verify_update
    ),
    // PKCS#11 3.0 — Session extensions
    (login_user, LoginUserRequest, LoginUserResponse, session_3x::login_user),
    (session_cancel, SessionCancelRequest, SessionCancelResponse, session_3x::session_cancel),
    // PKCS#11 3.0 — Message-based encryption
    (
        message_encrypt_init,
        MessageEncryptInitRequest,
        MessageEncryptInitResponse,
        message_crypto::message_encrypt_init
    ),
    (
        encrypt_message,
        EncryptMessageRequest,
        EncryptMessageResponse,
        message_crypto::encrypt_message
    ),
    (
        encrypt_message_begin,
        EncryptMessageBeginRequest,
        EncryptMessageBeginResponse,
        message_crypto::encrypt_message_begin
    ),
    (
        encrypt_message_next,
        EncryptMessageNextRequest,
        EncryptMessageNextResponse,
        message_crypto::encrypt_message_next
    ),
    (
        message_encrypt_final,
        MessageEncryptFinalRequest,
        MessageEncryptFinalResponse,
        message_crypto::message_encrypt_final
    ),
    // PKCS#11 3.0 — Message-based decryption
    (
        message_decrypt_init,
        MessageDecryptInitRequest,
        MessageDecryptInitResponse,
        message_crypto::message_decrypt_init
    ),
    (
        decrypt_message,
        DecryptMessageRequest,
        DecryptMessageResponse,
        message_crypto::decrypt_message
    ),
    (
        decrypt_message_begin,
        DecryptMessageBeginRequest,
        DecryptMessageBeginResponse,
        message_crypto::decrypt_message_begin
    ),
    (
        decrypt_message_next,
        DecryptMessageNextRequest,
        DecryptMessageNextResponse,
        message_crypto::decrypt_message_next
    ),
    (
        message_decrypt_final,
        MessageDecryptFinalRequest,
        MessageDecryptFinalResponse,
        message_crypto::message_decrypt_final
    ),
    // PKCS#11 3.0 — Message-based signing
    (
        message_sign_init,
        MessageSignInitRequest,
        MessageSignInitResponse,
        message_crypto::message_sign_init
    ),
    (sign_message, SignMessageRequest, SignMessageResponse, message_crypto::sign_message),
    (
        sign_message_begin,
        SignMessageBeginRequest,
        SignMessageBeginResponse,
        message_crypto::sign_message_begin
    ),
    (
        sign_message_next,
        SignMessageNextRequest,
        SignMessageNextResponse,
        message_crypto::sign_message_next
    ),
    (
        message_sign_final,
        MessageSignFinalRequest,
        MessageSignFinalResponse,
        message_crypto::message_sign_final
    ),
    // PKCS#11 3.0 — Message-based verification
    (
        message_verify_init,
        MessageVerifyInitRequest,
        MessageVerifyInitResponse,
        message_crypto::message_verify_init
    ),
    (verify_message, VerifyMessageRequest, VerifyMessageResponse, message_crypto::verify_message),
    (
        verify_message_begin,
        VerifyMessageBeginRequest,
        VerifyMessageBeginResponse,
        message_crypto::verify_message_begin
    ),
    (
        verify_message_next,
        VerifyMessageNextRequest,
        VerifyMessageNextResponse,
        message_crypto::verify_message_next
    ),
    (
        message_verify_final,
        MessageVerifyFinalRequest,
        MessageVerifyFinalResponse,
        message_crypto::message_verify_final
    ),
    // PKCS#11 3.2 — KEM
    (encapsulate_key, EncapsulateKeyRequest, EncapsulateKeyResponse, key_ops::encapsulate_key),
    (decapsulate_key, DecapsulateKeyRequest, DecapsulateKeyResponse, key_ops::decapsulate_key),
    // PKCS#11 3.2 — Verify signature
    (
        verify_signature_init,
        VerifySignatureInitRequest,
        VerifySignatureInitResponse,
        sign_verify::verify_signature_init
    ),
    (
        verify_signature,
        VerifySignatureRequest,
        VerifySignatureResponse,
        sign_verify::verify_signature
    ),
    (
        verify_signature_update,
        VerifySignatureUpdateRequest,
        VerifySignatureUpdateResponse,
        sign_verify::verify_signature_update
    ),
    (
        verify_signature_final,
        VerifySignatureFinalRequest,
        VerifySignatureFinalResponse,
        sign_verify::verify_signature_final
    ),
    // PKCS#11 3.2 — Authenticated wrap
    (
        wrap_key_authenticated,
        WrapKeyAuthenticatedRequest,
        WrapKeyAuthenticatedResponse,
        key_ops::wrap_key_authenticated
    ),
    (
        unwrap_key_authenticated,
        UnwrapKeyAuthenticatedRequest,
        UnwrapKeyAuthenticatedResponse,
        key_ops::unwrap_key_authenticated
    ),
    // PKCS#11 3.2 — Async
    (async_complete, AsyncCompleteRequest, AsyncCompleteResponse, async_ops::async_complete),
    (async_get_id, AsyncGetIdRequest, AsyncGetIdResponse, async_ops::async_get_id),
    (async_join, AsyncJoinRequest, AsyncJoinResponse, async_ops::async_join),
    // PKCS#11 3.2 — Validation
    (
        get_session_validation_flags,
        GetSessionValidationFlagsRequest,
        GetSessionValidationFlagsResponse,
        session_3x::get_session_validation_flags
    ),
    // Track B: Exact byte-output RPC
    (
        byte_output_exact,
        ByteOutputExactRequest,
        ByteOutputExactResponse,
        byte_output_exact::byte_output_exact
    ),
    // Track C: Exact parameter-output RPC
    (
        parameter_output_exact,
        ParameterOutputExactRequest,
        ParameterOutputExactResponse,
        parameter_output_exact::parameter_output_exact
    ),
    // Track C Task 2: Exact encapsulate-key RPC
    (
        encapsulate_key_exact,
        EncapsulateKeyExactRequest,
        EncapsulateKeyExactResponse,
        key_ops::encapsulate_key_exact
    ),
);

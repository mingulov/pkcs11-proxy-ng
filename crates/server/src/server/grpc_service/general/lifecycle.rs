use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{debug, warn};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_proto::version::{
    EXACT_OUTPUT_EFFECTS_VERSION_MAX, EXACT_OUTPUT_EFFECTS_VERSION_MIN, negotiate_effects_version,
};
use pkcs11_proxy_ng_types::*;

use super::super::super::auth::identity::AuthenticatedIdentity;
use super::super::super::context_manager::{ClientContextId, ContextManager, RemoveIfIdleOutcome};
use super::super::super::rate_limit;
use super::super::service_utils::current_context_operation_guard;

pub(super) async fn initialize(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::InitializeRequest>,
    tcp_auth_mode: crate::config::TcpAuthMode,
    unix_auth_mode: crate::config::UnixAuthMode,
) -> Result<Response<pkcs11_proxy_ng_proto::InitializeResponse>, Status> {
    let identity = crate::server::auth::request_identity::identity_from_request(
        &request,
        tcp_auth_mode,
        unix_auth_mode,
    )?;
    // W1-L7-03: throttle unauthenticated context creation per IP BEFORE
    // minting the context, so an unauthenticated peer cannot flood to the
    // max_contexts cap. Uses the dedicated always-on initialize budget
    // (decoupled from the opt-in discovery limiter).
    check_init_throttle(&identity, request.remote_addr().map(|addr| addr.ip()))?;
    // W1-L5-05: negotiate the effects range BEFORE minting. Disjoint ranges
    // fail fast here — loud FUNCTION_NOT_SUPPORTED with the daemon range
    // echoed for diagnosis — never per-RPC later. Absent bounds mean a
    // legacy v1 client. The throttle stays first so version-garbage floods
    // cannot bypass flood protection.
    let body = request.get_ref();
    // T29 M2: the agreed version is deliberately discarded (overlap check
    // only) — correct while v1 is the only version; the bump procedure in
    // `pkcs11_proxy_ng_proto::version` names this site for plumbing on the
    // first real bump.
    let _negotiated = negotiate_effects_version(
        EXACT_OUTPUT_EFFECTS_VERSION_MIN,
        EXACT_OUTPUT_EFFECTS_VERSION_MAX,
        body.client_effects_version_min,
        body.client_effects_version_max,
    );
    if _negotiated.is_none() {
        warn!(
            client_min = ?body.client_effects_version_min,
            client_max = ?body.client_effects_version_max,
            "Initialize rejected: disjoint exact-output effects version range"
        );
        return Ok(Response::new(pkcs11_proxy_ng_proto::InitializeResponse {
            ck_rv: CkRv::FUNCTION_NOT_SUPPORTED.0,
            client_context_id: String::new(),
            daemon_effects_version_min: Some(EXACT_OUTPUT_EFFECTS_VERSION_MIN),
            daemon_effects_version_max: Some(EXACT_OUTPUT_EFFECTS_VERSION_MAX),
        }));
    }
    // Same-identity orphan replacement: at the admission cap, an idle
    // context owned by THIS identity (e.g. left behind by a previous
    // process of the same logical client that exited without Finalize)
    // is replaced instead of wedging admission until lease expiry. A
    // different identity, or a busy context, keeps the HOST_MEMORY
    // refusal. Initialize passes Some(..) for every auth mode including
    // unauthenticated, where all peers share one identity string — that
    // no-isolation posture already lets any peer use any context, so
    // replacing an idle unauthenticated orphan grants nothing new (see
    // `create_context_replacing_idle_same_identity`).
    let (ctx_id, replaced) =
        match ctx_mgr.create_context_replacing_idle_same_identity(Some(identity.to_string())).await
        {
            Ok(admitted) => admitted,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::InitializeResponse {
                    ck_rv: rv.0,
                    client_context_id: String::new(),
                    daemon_effects_version_min: Some(EXACT_OUTPUT_EFFECTS_VERSION_MIN),
                    daemon_effects_version_max: Some(EXACT_OUTPUT_EFFECTS_VERSION_MAX),
                }));
            }
        };
    if let Some(mut replaced) = replaced {
        // D6(2)/D9 shared teardown path, exactly like finalize:
        // refcount-checked session reaping plus last-holder backend
        // logout (best-effort; never fails this Initialize and never
        // disturbs live tenants). The plan is computed after the new
        // context inserted, so its liveness probes observe only live
        // tenants, the new (empty) context included.
        let replaced_id = replaced.id.clone();
        let plan = ctx_mgr.plan_removed_context_teardown(&mut replaced);
        let session_count = plan.sessions_to_close.len();
        let logout_count = plan.slot_logouts.len();
        ctx_mgr.execute_teardown_plans(backend_ref, vec![plan]).await;
        debug!(
            context_id = %ctx_id.0,
            replaced_context_id = %replaced_id.0,
            sessions_closed = session_count,
            logouts = logout_count,
            "Initialize: replaced idle same-identity context at admission cap"
        );
    }
    debug!(context_id = %ctx_id.0, "Initialize: created context");
    Ok(Response::new(pkcs11_proxy_ng_proto::InitializeResponse {
        ck_rv: CkRv::OK.0,
        client_context_id: ctx_id.0,
        daemon_effects_version_min: Some(EXACT_OUTPUT_EFFECTS_VERSION_MIN),
        daemon_effects_version_max: Some(EXACT_OUTPUT_EFFECTS_VERSION_MAX),
    }))
}

/// W1-L7-03: per-IP admission for unauthenticated initialize.
/// Authenticated peers (mTLS/peer-cred) bypass — they already present a
/// strong identity — as do callers with no TCP peer address (local IPC).
/// Over-budget peers get a loud `RESOURCE_EXHAUSTED` (mirrors the
/// discovery path) before any context is minted.
fn check_init_throttle(
    identity: &AuthenticatedIdentity,
    peer: Option<std::net::IpAddr>,
) -> Result<(), Status> {
    if !matches!(identity, AuthenticatedIdentity::Unauthenticated) {
        return Ok(());
    }
    let Some(ip) = peer else {
        return Ok(());
    };
    match rate_limit::check_init(ip) {
        Ok(()) => Ok(()),
        Err(retry_after) => Err(Status::resource_exhausted(format!(
            "initialize rate limit exceeded for peer; retry after {} ms",
            retry_after.as_millis()
        ))),
    }
}

pub(super) async fn finalize(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::FinalizeRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FinalizeResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // W1-L6-02: honor in_flight — refuse busy instead of removing the
    // context from underneath a concurrent op's backend call. Dispatch
    // scopes exactly one guard for this finalize itself; only guards
    // beyond that one count as foreign.
    let own_guards =
        match current_context_operation_guard().filter(|g| g.belongs_to(ctx_mgr, &ctx_id)) {
            Some(_) => 1,
            None => 0,
        };
    let ck_rv = match ctx_mgr.remove_context_if_idle(&ctx_id, own_guards) {
        RemoveIfIdleOutcome::Removed(mut ctx) => {
            // D6(2)/D9 shared teardown path: refcount-checked session reaping
            // plus last-holder backend logout (best-effort; never fails the
            // Finalize itself and never disturbs live tenants).
            let plan = ctx_mgr.plan_removed_context_teardown(&mut ctx);
            let session_count = plan.sessions_to_close.len();
            let logout_count = plan.slot_logouts.len();
            ctx_mgr.execute_teardown_plans(backend_ref, vec![plan]).await;
            debug!(
                context_id = %ctx_id.0,
                sessions_closed = session_count,
                logouts = logout_count,
                "Finalize: context removed"
            );
            CkRv::OK.0
        }
        RemoveIfIdleOutcome::Busy => {
            // Transient and retryable (same class as the breaker trip and
            // the login-lock contention refusal): the concurrent op drains
            // and a retried finalize proceeds.
            debug!(context_id = %ctx_id.0, "Finalize refused: operations in flight");
            CkRv::DEVICE_ERROR.0
        }
        RemoveIfIdleOutcome::Missing => CkRv::CRYPTOKI_NOT_INITIALIZED.0,
    };
    Ok(Response::new(pkcs11_proxy_ng_proto::FinalizeResponse { ck_rv }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tonic::Request;

    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_types::*;

    use crate::server::context_manager::{ClientContextId, ContextManager};
    use crate::server::grpc_service::service_utils::scope_context_operation;

    fn test_ctx_mgr() -> Arc<ContextManager> {
        Arc::new(ContextManager::new(Duration::from_secs(300), 0))
    }

    fn test_backend() -> Arc<dyn Pkcs11Backend> {
        let mock = MockBackend::default_test();
        mock.initialize().unwrap();
        Arc::new(mock)
    }

    fn finalize_request(
        ctx_id: &ClientContextId,
    ) -> Request<pkcs11_proxy_ng_proto::FinalizeRequest> {
        Request::new(pkcs11_proxy_ng_proto::FinalizeRequest { client_context_id: ctx_id.0.clone() })
    }

    /// W1-L6-02: finalize must refuse (busy) when a foreign backend operation
    /// is in flight instead of removing the context from underneath it.
    #[tokio::test]
    async fn finalize_refuses_busy_context() {
        let ctx_mgr = test_ctx_mgr();
        let backend = test_backend();
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        // Simulate a concurrent op: an operation guard NOT owned by this
        // finalize (no task-local scope), so in_flight = 1 foreign.
        let _foreign_guard = Arc::clone(&ctx_mgr).begin_operation(&ctx_id).expect("context exists");

        let resp = super::finalize(&ctx_mgr, &backend, finalize_request(&ctx_id))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            resp.ck_rv,
            CkRv::DEVICE_ERROR.0,
            "finalize during a foreign in-flight op must refuse busy"
        );
        assert!(
            ctx_mgr.get_context(&ctx_id, |_| ()).await.is_some(),
            "refused finalize must leave the context in place"
        );
    }

    /// W1-L6-02: a refused-busy finalize succeeds on retry once the
    /// in-flight op drains (no latch).
    #[tokio::test]
    async fn finalize_busy_then_idle_retry_succeeds() {
        let ctx_mgr = test_ctx_mgr();
        let backend = test_backend();
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        let foreign_guard = Arc::clone(&ctx_mgr).begin_operation(&ctx_id).expect("context exists");
        let busy = super::finalize(&ctx_mgr, &backend, finalize_request(&ctx_id))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(busy.ck_rv, CkRv::DEVICE_ERROR.0);
        drop(foreign_guard);

        let retry = super::finalize(&ctx_mgr, &backend, finalize_request(&ctx_id))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(retry.ck_rv, CkRv::OK.0, "idle retry must finalize");
        assert!(
            ctx_mgr.get_context(&ctx_id, |_| ()).await.is_none(),
            "successful finalize must remove the context"
        );
    }

    /// W1-L6-02: finalize's OWN dispatch guard must not count as foreign —
    /// an otherwise-idle context finalizes normally through the scoped path.
    #[tokio::test]
    async fn finalize_with_only_own_dispatch_guard_succeeds() {
        let ctx_mgr = test_ctx_mgr();
        let backend = test_backend();
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        // Mirror dispatch: the scoped guard is finalize's own (in_flight = 1).
        let own_guard = Arc::clone(&ctx_mgr).begin_operation(&ctx_id).expect("context exists");
        let resp = scope_context_operation(Some(own_guard), async {
            super::finalize(&ctx_mgr, &backend, finalize_request(&ctx_id)).await
        })
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            resp.ck_rv,
            CkRv::OK.0,
            "finalize holding only its own dispatch guard must succeed"
        );
        assert!(ctx_mgr.get_context(&ctx_id, |_| ()).await.is_none());
    }

    /// W1-L6-02: own dispatch guard + one foreign op is still busy.
    #[tokio::test]
    async fn finalize_with_own_guard_plus_foreign_op_refuses() {
        let ctx_mgr = test_ctx_mgr();
        let backend = test_backend();
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        let _foreign_guard = Arc::clone(&ctx_mgr).begin_operation(&ctx_id).expect("context exists");
        let own_guard = Arc::clone(&ctx_mgr).begin_operation(&ctx_id).expect("context exists");
        let resp = scope_context_operation(Some(own_guard), async {
            super::finalize(&ctx_mgr, &backend, finalize_request(&ctx_id)).await
        })
        .await
        .unwrap()
        .into_inner();
        assert_eq!(resp.ck_rv, CkRv::DEVICE_ERROR.0);
        assert!(ctx_mgr.get_context(&ctx_id, |_| ()).await.is_some());
    }

    /// W1-L7-03 fix round: an unauthenticated peer flooding initialize
    /// from one IP is throttled before context creation (loud
    /// RESOURCE_EXHAUSTED, no context minted) under DEFAULT configuration
    /// — no explicit limiter setup. Uses a dedicated TEST-NET IP so the
    /// shared always-on budget cannot interact with other tests.
    #[tokio::test]
    async fn initialize_throttles_unauthenticated_flood_per_ip() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::server::auth::identity::AuthenticatedIdentity;

        // NOTE: no rate_limit::configure — this test pins default-config
        // behavior. The initialize budget is always on and decoupled
        // from the (opt-in) discovery limiter.
        let ctx_mgr = test_ctx_mgr();
        let backend = test_backend();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 46));
        let peer = SocketAddr::new(ip, 1234);
        let request = || {
            // Legacy-shaped request (no version fields): exercises the
            // unversioned-client path through the throttle checks.
            let mut req = Request::new(pkcs11_proxy_ng_proto::InitializeRequest {
                client_context_id: String::new(),
                client_effects_version_min: None,
                client_effects_version_max: None,
            });
            req.extensions_mut().insert(tonic::transport::server::TcpConnectInfo {
                local_addr: None,
                remote_addr: Some(peer),
            });
            req
        };

        // Legitimate initializes pass.
        for _ in 0..2 {
            let resp = super::initialize(
                &ctx_mgr,
                &backend,
                request(),
                crate::config::TcpAuthMode::None,
                crate::config::UnixAuthMode::None,
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(resp.ck_rv, CkRv::OK.0, "in-budget initializes must pass");
        }
        assert_eq!(ctx_mgr.context_count(), 2);
        // Fill the rest of the always-on budget directly (2 units were
        // consumed by the initializes above); the next check trips the
        // throttle — no explicit limiter setup anywhere in this path.
        for _ in 0..(crate::server::rate_limit::INIT_THROTTLE_MAX_PER_WINDOW - 2) {
            assert!(
                super::check_init_throttle(&AuthenticatedIdentity::Unauthenticated, Some(ip))
                    .is_ok(),
                "in-budget checks must pass"
            );
        }
        assert!(
            super::check_init_throttle(&AuthenticatedIdentity::Unauthenticated, Some(ip)).is_err(),
            "default-config flood must be throttled"
        );
        // …and a further initialize is loudly rejected without minting.
        let err = super::initialize(
            &ctx_mgr,
            &backend,
            request(),
            crate::config::TcpAuthMode::None,
            crate::config::UnixAuthMode::None,
        )
        .await
        .expect_err("over-budget initialize must be throttled");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(ctx_mgr.context_count(), 2, "throttled initialize must mint no context");
    }

    /// W1-L7-03: initializes without a TCP peer (local IPC) bypass the
    /// throttle — legitimate local initializes always pass.
    #[tokio::test]
    async fn initialize_without_peer_bypasses_throttle() {
        let ctx_mgr = test_ctx_mgr();
        let backend = test_backend();
        for _ in 0..5 {
            let resp = super::initialize(
                &ctx_mgr,
                &backend,
                Request::new(pkcs11_proxy_ng_proto::InitializeRequest {
                    client_context_id: String::new(),
                    client_effects_version_min: None,
                    client_effects_version_max: None,
                }),
                crate::config::TcpAuthMode::None,
                crate::config::UnixAuthMode::None,
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(resp.ck_rv, CkRv::OK.0);
        }
        assert_eq!(ctx_mgr.context_count(), 5);
    }

    /// W1-L7-03: authenticated peers bypass the initialize throttle (they
    /// already present a strong identity) however the limiter is configured.
    #[test]
    fn init_throttle_bypasses_authenticated_peer() {
        use crate::server::auth::identity::AuthenticatedIdentity;
        use std::net::{IpAddr, Ipv4Addr};

        let peer = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 45)));
        for identity in [
            AuthenticatedIdentity::PeerCred { uid: 1000 },
            AuthenticatedIdentity::Mtls {
                issuer: "CN=ca".into(),
                subject: "CN=client".into(),
                spki_sha256: String::new(),
            },
        ] {
            assert!(
                super::check_init_throttle(&identity, peer).is_ok(),
                "authenticated initialize must bypass the throttle"
            );
        }
        // …as does an unauthenticated caller with no peer address.
        assert!(super::check_init_throttle(&AuthenticatedIdentity::Unauthenticated, None).is_ok());
    }

    // --- W1-L5-05: init-time version negotiation ---

    fn versioned_init_request(
        min: Option<u32>,
        max: Option<u32>,
    ) -> Request<pkcs11_proxy_ng_proto::InitializeRequest> {
        Request::new(pkcs11_proxy_ng_proto::InitializeRequest {
            client_context_id: String::new(),
            client_effects_version_min: min,
            client_effects_version_max: max,
        })
    }

    /// A client whose range is disjoint from the daemon's must fail fast at
    /// init: loud FUNCTION_NOT_SUPPORTED, no context minted, and the daemon
    /// range echoed for diagnosis.
    #[tokio::test]
    async fn initialize_rejects_disjoint_version_range_without_minting() {
        let ctx_mgr = test_ctx_mgr();
        let backend = test_backend();
        let resp = super::initialize(
            &ctx_mgr,
            &backend,
            versioned_init_request(Some(99), Some(99)),
            crate::config::TcpAuthMode::None,
            crate::config::UnixAuthMode::None,
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            resp.ck_rv,
            CkRv::FUNCTION_NOT_SUPPORTED.0,
            "W1-L5-05: mixed versions must fail fast at init"
        );
        assert!(resp.client_context_id.is_empty(), "rejected init must mint no context id");
        assert_eq!(ctx_mgr.context_count(), 0, "rejected init must mint no context");
        assert_eq!(resp.daemon_effects_version_min, Some(1));
        assert_eq!(resp.daemon_effects_version_max, Some(1));
    }

    /// Legacy clients (no version fields) are v1: accepted, with the daemon
    /// range advertised in the response.
    #[tokio::test]
    async fn initialize_accepts_legacy_unversioned_client() {
        let ctx_mgr = test_ctx_mgr();
        let backend = test_backend();
        let resp = super::initialize(
            &ctx_mgr,
            &backend,
            versioned_init_request(None, None),
            crate::config::TcpAuthMode::None,
            crate::config::UnixAuthMode::None,
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(resp.ck_rv, CkRv::OK.0, "legacy unversioned client must be accepted as v1");
        assert!(!resp.client_context_id.is_empty());
        assert_eq!(ctx_mgr.context_count(), 1);
        assert_eq!(resp.daemon_effects_version_min, Some(1));
        assert_eq!(resp.daemon_effects_version_max, Some(1));
    }

    /// A matching [1,1] client negotiates v1 (characterization of the
    /// overlap path; structurally red until the fields exist).
    #[tokio::test]
    async fn initialize_accepts_matching_version_range() {
        let ctx_mgr = test_ctx_mgr();
        let backend = test_backend();
        let resp = super::initialize(
            &ctx_mgr,
            &backend,
            versioned_init_request(Some(1), Some(1)),
            crate::config::TcpAuthMode::None,
            crate::config::UnixAuthMode::None,
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(ctx_mgr.context_count(), 1);
    }

    /// Idle finalize is unchanged (characterization).
    #[tokio::test]
    async fn finalize_idle_context_unchanged() {
        let ctx_mgr = test_ctx_mgr();
        let backend = test_backend();
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        let resp = super::finalize(&ctx_mgr, &backend, finalize_request(&ctx_id))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert!(ctx_mgr.get_context(&ctx_id, |_| ()).await.is_none());

        // Second finalize on the gone context answers NOT_INITIALIZED.
        let again = super::finalize(&ctx_mgr, &backend, finalize_request(&ctx_id))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(again.ck_rv, CkRv::CRYPTOKI_NOT_INITIALIZED.0);
    }

    // --- Same-identity orphan replacement at the admission cap ---
    //
    // A client process that exits without Finalize (pkcs11-check's
    // per-file processes) leaves an orphaned context holding the single
    // cap-1 slot until lease/lifetime expiry. A later Initialize from the
    // SAME identity must replace that idle orphan (with full teardown)
    // instead of wedging on HOST_MEMORY; a DIFFERENT identity, or a busy
    // context, must still be refused.

    fn orphan_request() -> Request<pkcs11_proxy_ng_proto::InitializeRequest> {
        Request::new(pkcs11_proxy_ng_proto::InitializeRequest {
            client_context_id: String::new(),
            client_effects_version_min: None,
            client_effects_version_max: None,
        })
    }

    async fn initialize_ok(
        ctx_mgr: &Arc<ContextManager>,
        backend: &Arc<dyn Pkcs11Backend>,
    ) -> pkcs11_proxy_ng_proto::InitializeResponse {
        super::initialize(
            ctx_mgr,
            backend,
            orphan_request(),
            crate::config::TcpAuthMode::None,
            crate::config::UnixAuthMode::None,
        )
        .await
        .unwrap()
        .into_inner()
    }

    /// (a) At cap 1, a second Initialize with the SAME identity as an idle
    /// existing context succeeds by replacing it: the orphan's backend
    /// sessions are closed and its login released via the shared teardown
    /// path, and exactly the new context remains.
    #[tokio::test]
    async fn initialize_replaces_idle_same_identity_orphan_at_cap1_and_tears_it_down() {
        use crate::server::context_manager::LoginState;
        use crate::server::handle_map::BackendHandle;

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = Arc::clone(&mock) as _;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 1));
        let slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
        ctx_mgr.register_slot(slot).await;

        // First "process": Initialize, open a backend session, log in —
        // then vanish without Finalize (no finalize call below).
        let first = initialize_ok(&ctx_mgr, &backend).await;
        assert_eq!(first.ck_rv, CkRv::OK.0);
        let orphan_id = ClientContextId(first.client_context_id.clone());
        let session = mock.open_session(CkSlotId(0), CkSessionFlags::SERIAL_SESSION).unwrap();
        mock.login(session, CkUserType::User, Some(b"1234")).unwrap();
        ctx_mgr
            .get_context(&orphan_id, |ctx| {
                ctx.register_session(BackendHandle(session.0), slot);
                ctx.login_state.insert(slot, LoginState::User);
            })
            .await;
        ctx_mgr.note_login_acquired(&orphan_id, slot);
        assert_eq!(mock.open_session_count(), 1);
        assert!(ctx_mgr.any_login_state_for_slot(slot));

        // Second "process", same identity (unauthenticated): must be
        // admitted by replacing the idle orphan, not refused HOST_MEMORY.
        let second = initialize_ok(&ctx_mgr, &backend).await;
        assert_eq!(
            second.ck_rv,
            CkRv::OK.0,
            "same-identity Initialize at cap1 must replace the idle orphan"
        );
        assert_ne!(second.client_context_id, first.client_context_id);
        assert_eq!(ctx_mgr.context_count(), 1, "replacement must not exceed cap1");
        assert!(
            ctx_mgr.get_context(&orphan_id, |_| ()).await.is_none(),
            "the replaced orphan must be gone"
        );
        let new_id = ClientContextId(second.client_context_id);
        assert!(ctx_mgr.get_context(&new_id, |_| ()).await.is_some(), "the new context must live");
        // Teardown ran like finalize: backend session closed, login released.
        assert_eq!(mock.open_session_count(), 0, "orphan backend session must be closed");
        assert!(mock.close_session_call_count() >= 1, "teardown must close the backend session");
        assert!(
            !ctx_mgr.any_login_state_for_slot(slot),
            "orphan login must be released with the replaced context"
        );
    }

    /// (b) At cap 1, an Initialize whose identity DIFFERS from the idle
    /// holder's is still refused HOST_MEMORY; the holder stays intact.
    #[tokio::test]
    async fn initialize_at_cap1_refuses_different_identity() {
        let backend = test_backend();
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 1));
        // Seed the sole slot with a different identity than the
        // unauthenticated identity the request below derives.
        let holder = ctx_mgr.create_context(Some("uid=424242".into())).await.unwrap();

        let resp = initialize_ok(&ctx_mgr, &backend).await;
        assert_eq!(
            resp.ck_rv,
            CkRv::HOST_MEMORY.0,
            "a different identity at cap must still be refused"
        );
        assert!(resp.client_context_id.is_empty());
        assert_eq!(ctx_mgr.context_count(), 1);
        assert!(
            ctx_mgr.get_context(&holder, |_| ()).await.is_some(),
            "the different-identity holder must stay intact"
        );
    }

    /// (c) At cap 1, a same-identity context with a foreign in-flight
    /// operation is NOT replaced: Initialize is refused and the busy
    /// context remains intact.
    #[tokio::test]
    async fn initialize_at_cap1_does_not_replace_busy_same_identity_context() {
        let backend = test_backend();
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 1));

        let first = initialize_ok(&ctx_mgr, &backend).await;
        assert_eq!(first.ck_rv, CkRv::OK.0);
        let busy_id = ClientContextId(first.client_context_id);
        // Foreign op in flight on the holder (not initialize's own guard).
        let _foreign_guard =
            Arc::clone(&ctx_mgr).begin_operation(&busy_id).expect("context exists");

        let resp = initialize_ok(&ctx_mgr, &backend).await;
        assert_eq!(
            resp.ck_rv,
            CkRv::HOST_MEMORY.0,
            "a busy same-identity context must never be replaced"
        );
        assert!(resp.client_context_id.is_empty());
        assert_eq!(ctx_mgr.context_count(), 1);
        assert!(
            ctx_mgr.get_context(&busy_id, |_| ()).await.is_some(),
            "the busy context must remain intact"
        );
    }

    // --- Q18 (SEC-H2): atomic context guardrail ---

    fn init_request() -> Request<pkcs11_proxy_ng_proto::InitializeRequest> {
        // Peerless legacy-shaped request: bypasses the init throttle and
        // negotiates v1, so the race below exercises admission only.
        Request::new(pkcs11_proxy_ng_proto::InitializeRequest {
            client_context_id: String::new(),
            client_effects_version_min: None,
            client_effects_version_max: None,
        })
    }

    /// Race `tasks` Initialize calls past one barrier and collect their
    /// `ck_rv`s. The barrier aligns the tasks so their admission sequences
    /// genuinely overlap on the multi-thread runtime; any serialization
    /// comes only from the admission mechanism under test, never from this
    /// harness (no locks, no awaits between barrier release and Initialize).
    async fn race_initializes(
        ctx_mgr: Arc<ContextManager>,
        backend: Arc<dyn Pkcs11Backend>,
        tasks: usize,
    ) -> Vec<u64> {
        let barrier = Arc::new(tokio::sync::Barrier::new(tasks));
        let mut handles = Vec::with_capacity(tasks);
        for _ in 0..tasks {
            let ctx_mgr = Arc::clone(&ctx_mgr);
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                super::initialize(
                    &ctx_mgr,
                    &backend,
                    init_request(),
                    crate::config::TcpAuthMode::None,
                    crate::config::UnixAuthMode::None,
                )
                .await
                .unwrap()
                .into_inner()
                .ck_rv
            }));
        }
        let mut rvs = Vec::with_capacity(tasks);
        for handle in handles {
            rvs.push(handle.await.unwrap());
        }
        rvs
    }

    /// Q18 (SEC-H2): barrier-controlled concurrent Initialize at cap1
    /// never over-admits — exactly one context is live afterwards — and
    /// every racer answers OK or the existing cap-refusal RV
    /// (`CKR_HOST_MEMORY`, the admission refusal — looked up in
    /// `context_manager.rs`, not invented here). All racers here share
    /// one (unauthenticated) identity, so under same-identity orphan
    /// replacement a racer may legitimately win by replacing the
    /// previous racer's idle context: the Q18 invariant is the live
    /// count bound, not a single OK. Cross-identity refusal is pinned by
    /// `initialize_at_cap1_refuses_different_identity`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn q18_barrier_concurrent_initialize_at_cap1_never_exceeds_cap() {
        const TASKS: usize = 32;
        const ROUNDS: usize = 200;
        let backend = test_backend();
        for _ in 0..ROUNDS {
            let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 1));
            let rvs = race_initializes(Arc::clone(&ctx_mgr), Arc::clone(&backend), TASKS).await;
            let oks = rvs.iter().filter(|rv| **rv == CkRv::OK.0).count();
            for rv in &rvs {
                assert!(
                    *rv == CkRv::OK.0 || *rv == CkRv::HOST_MEMORY.0,
                    "Q18: raced Initialize must answer OK or the existing HOST_MEMORY refusal, got {rv:#x}"
                );
            }
            assert!(oks >= 1, "Q18: at least one Initialize must be admitted at cap1");
            assert_eq!(
                ctx_mgr.total_contexts_created(),
                oks as u64,
                "Q18: every OK minted exactly one context, no phantom admissions"
            );
            assert_eq!(ctx_mgr.context_count(), 1, "Q18: no over-admission past cap1");
        }
    }

    /// Q18 (SEC-H2): finalizing the cap1 holder releases admission capacity
    /// — a later Initialize is admitted — and the post-release race still
    /// never over-admits past cap1 (release reuse plus atomicity). The
    /// pre-finalize second Initialize shares the holder's identity, so
    /// under same-identity orphan replacement it is admitted by
    /// replacing the idle holder (the wedge fix) rather than refused;
    /// cross-identity refusal is pinned separately.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn q18_finalize_releases_capacity_for_later_initialize() {
        const TASKS: usize = 32;
        const ROUNDS: usize = 50;
        let backend = test_backend();
        for _ in 0..ROUNDS {
            let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 1));
            let first = super::initialize(
                &ctx_mgr,
                &backend,
                init_request(),
                crate::config::TcpAuthMode::None,
                crate::config::UnixAuthMode::None,
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(first.ck_rv, CkRv::OK.0);
            let first_id = ClientContextId(first.client_context_id.clone());
            let second = super::initialize(
                &ctx_mgr,
                &backend,
                init_request(),
                crate::config::TcpAuthMode::None,
                crate::config::UnixAuthMode::None,
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(
                second.ck_rv,
                CkRv::OK.0,
                "same-identity second Initialize at cap1 must replace the idle holder"
            );
            assert_ne!(second.client_context_id, first.client_context_id);
            assert_eq!(ctx_mgr.context_count(), 1, "Q18: replacement must not exceed cap1");
            assert!(
                ctx_mgr.get_context(&first_id, |_| ()).await.is_none(),
                "the replaced first context must be gone"
            );
            let finalized = super::finalize(
                &ctx_mgr,
                &backend,
                Request::new(pkcs11_proxy_ng_proto::FinalizeRequest {
                    client_context_id: second.client_context_id,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(finalized.ck_rv, CkRv::OK.0);
            assert_eq!(ctx_mgr.context_count(), 0, "Q18: finalize must empty the cap1 manager");
            let rvs = race_initializes(Arc::clone(&ctx_mgr), Arc::clone(&backend), TASKS).await;
            let oks = rvs.iter().filter(|rv| **rv == CkRv::OK.0).count();
            assert!(oks >= 1, "Q18: the released slot must admit a racing Initialize");
            assert_eq!(ctx_mgr.context_count(), 1, "Q18: no over-admission past cap1");
        }
    }
}

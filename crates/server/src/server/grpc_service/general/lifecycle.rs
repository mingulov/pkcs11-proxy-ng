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
    _backend_ref: &Arc<dyn Pkcs11Backend>,
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
    if negotiate_effects_version(
        EXACT_OUTPUT_EFFECTS_VERSION_MIN,
        EXACT_OUTPUT_EFFECTS_VERSION_MAX,
        body.client_effects_version_min,
        body.client_effects_version_max,
    )
    .is_none()
    {
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
    let ctx_id = match ctx_mgr.create_context(Some(identity.to_string())).await {
        Ok(id) => id,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::InitializeResponse {
                ck_rv: rv.0,
                client_context_id: String::new(),
                daemon_effects_version_min: Some(EXACT_OUTPUT_EFFECTS_VERSION_MIN),
                daemon_effects_version_max: Some(EXACT_OUTPUT_EFFECTS_VERSION_MAX),
            }));
        }
    };
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
}

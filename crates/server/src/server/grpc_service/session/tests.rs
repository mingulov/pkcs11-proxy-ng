use super::{
    close_all_sessions, close_session, init_pin, init_token, login, logout, open_session, set_pin,
};
use crate::server::context_manager::{
    ClientContextId, ContextManager, LoginState, MessageOperation,
};
use crate::server::grpc_service::{HandlerContext, Pkcs11ProxyService};
use crate::server::handle_map::VirtualHandle;
use pkcs11_proxy_ng_backend::{
    MockBackend, Pkcs11Backend,
    mock::{MockEmbeddedHandles, MockMechanismEntry, MockMessageLifecycleAction},
};
use pkcs11_proxy_ng_proto::Pkcs11Proxy;
use pkcs11_proxy_ng_proto::convert::message_params::MessageParameterShape;
use pkcs11_proxy_ng_types::*;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use tonic::Request;
use tracing_subscriber::fmt::MakeWriter;

/// Shared buffer that captures tracing output for assertions.
#[derive(Clone, Default)]
struct CapturedWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl CapturedWriter {
    fn output(&self) -> String {
        String::from_utf8_lossy(&self.buf.lock().unwrap()).to_string()
    }
}

impl io::Write for CapturedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapturedWriter {
    type Writer = CapturedWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

static LOG_CAPTURE_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

/// The single buffer that the global capture subscriber routes events into.
/// Only one capture runs at a time (serialized by `LOG_CAPTURE_LOCK`), so a
/// single slot is sufficient and avoids the thread-local/callsite-interest
/// races that made per-future subscribers flaky under full-suite parallelism.
static ACTIVE_CAPTURE: Mutex<Option<CapturedWriter>> = Mutex::new(None);

/// Writer installed on the process-global subscriber; forwards to whichever
/// capture is currently active and discards otherwise.
struct RoutingWriter;

impl io::Write for RoutingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(writer) = ACTIVE_CAPTURE.lock().unwrap().as_ref() {
            writer.buf.lock().unwrap().extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Install the global TRACE subscriber exactly once. Setting it globally (vs a
/// per-future thread-local) registers callsite interest permanently, so audit
/// events — including any emitted off the test's poll thread — are never cached
/// as disabled and then missed.
fn ensure_capture_subscriber() {
    static SUBSCRIBER_INIT: OnceLock<()> = OnceLock::new();
    SUBSCRIBER_INIT.get_or_init(|| {
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(|| RoutingWriter)
            .finish();
        // If another global default is already installed, capture falls back to
        // it; in this crate's test binary nothing else sets one.
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

async fn setup_session() -> (Arc<ContextManager>, Arc<dyn Pkcs11Backend>, ClientContextId, u64) {
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();

    let virtual_slot = ctx_mgr.virtual_slots().await[0];
    let open_resp = open_session(
        &ctx_mgr,
        &backend,
        Request::new(pkcs11_proxy_ng_proto::OpenSessionRequest {
            client_context_id: ctx_id.0.clone(),
            slot_id: virtual_slot.0,
            flags: (CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION).0,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(open_resp.ck_rv, CkRv::OK.0, "setup: open_session failed");

    (ctx_mgr, backend, ctx_id, open_resp.session_handle)
}

async fn open_test_session(
    ctx_mgr: &Arc<ContextManager>,
    backend: &Arc<dyn Pkcs11Backend>,
    ctx_id: &ClientContextId,
) -> u64 {
    let virtual_slot = ctx_mgr.virtual_slots().await[0];
    let response = open_session(
        ctx_mgr,
        backend,
        Request::new(pkcs11_proxy_ng_proto::OpenSessionRequest {
            client_context_id: ctx_id.0.clone(),
            slot_id: virtual_slot.0,
            flags: (CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION).0,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(response.ck_rv, CkRv::OK.0, "open_session failed");
    response.session_handle
}

async fn login_response(
    ctx_mgr: &Arc<ContextManager>,
    backend: &Arc<dyn Pkcs11Backend>,
    ctx_id: &ClientContextId,
    session: u64,
) -> u64 {
    login(
        &HandlerContext::for_test(ctx_mgr, backend),
        Request::new(pkcs11_proxy_ng_proto::LoginRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            user_type: CkUserType::User as u64,
            pin: Some(b"1234".to_vec()),
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv
}

async fn logout_response(
    ctx_mgr: &Arc<ContextManager>,
    backend: &Arc<dyn Pkcs11Backend>,
    ctx_id: &ClientContextId,
    session: u64,
) -> u64 {
    logout(
        &HandlerContext::for_test(ctx_mgr, backend),
        Request::new(pkcs11_proxy_ng_proto::LogoutRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv
}

#[tokio::test]
async fn second_context_login_returns_backend_already_faithfully_without_minting_login() {
    // D6(3): while one live context holds the slot login, the shared backend
    // token is logged in and would answer a second backend C_Login with
    // USER_ALREADY_LOGGED_IN without checking the PIN. The daemon cannot
    // PIN-verify such a login, so it returns ALREADY faithfully and mints NO
    // logical login for the second context — never a login on an unverified
    // PIN (Wave 3.5 tenancy ruling; supersedes the ADR-0008 verifier).
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();

    let session_a = open_test_session(&ctx_mgr, &backend, &ctx_a).await;
    let session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;

    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_a, session_a).await, CkRv::OK.0);
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_b, session_b).await,
        CkRv::USER_ALREADY_LOGGED_IN.0,
        "a second live context must see the backend's ALREADY faithfully, even with the correct PIN"
    );
    assert_eq!(
        mock.login_call_count(),
        1,
        "the refused second login must not reach the backend at all"
    );

    // No logical login may be minted for ctx_b.
    let b_login_state = ctx_mgr
        .get_context(&ctx_b, |ctx| {
            ctx.login_state.get(&crate::server::slot_map::BackendSlotId(CkSlotId(0))).copied()
        })
        .await
        .unwrap();
    assert_eq!(b_login_state, None, "no logical login may be minted on an unverified PIN");

    // ctx_b was never logged in, so its logout reports NOT_LOGGED_IN while
    // ctx_a's backend login is undisturbed.
    assert_eq!(
        logout_response(&ctx_mgr, &backend, &ctx_b, session_b).await,
        CkRv::USER_NOT_LOGGED_IN.0
    );
    let backend_session_a = ctx_mgr
        .get_context(&ctx_a, |ctx| ctx.session_handles.resolve(VirtualHandle(session_a)))
        .await
        .unwrap()
        .unwrap();
    let info = backend.get_session_info(CkSessionHandle(backend_session_a.0 as u64)).unwrap();
    assert_eq!(
        info.state,
        CkSessionState::RwUser,
        "refusing ctx_b must not disturb ctx_a's backend login"
    );

    // After ctx_a logs out (last holder → real backend logout), ctx_b can log
    // in normally.
    assert_eq!(logout_response(&ctx_mgr, &backend, &ctx_a, session_a).await, CkRv::OK.0);
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_b, session_b).await,
        CkRv::OK.0,
        "after the holder releases the slot the next login must succeed"
    );
}

/// W1-L13-11 + W1-L7-15: a same-client re-login short-circuits locally —
/// ALREADY with no redundant backend C_Login. (The old
/// backend-authoritative expectation — every re-login reaches the
/// provider — was challenged and rejected in adjudication; the re-login
/// RV itself is unchanged.)
#[tokio::test]
async fn repeated_login_in_same_logical_client_short_circuits_locally() {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();

    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_id, session).await, CkRv::OK.0);
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_id, session).await,
        CkRv::USER_ALREADY_LOGGED_IN.0
    );
    assert_eq!(
        mock.login_call_count(),
        1,
        "same-client re-login must short-circuit locally without a backend call (W1-L13-11)"
    );
}

#[tokio::test]
async fn closing_last_session_clears_logical_login_state_for_slot() {
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();

    let session_a = open_test_session(&ctx_mgr, &backend, &ctx_a).await;
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_a, session_a).await, CkRv::OK.0);

    let close_a = close_session(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx_a.0.clone(),
            session_handle: session_a,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(close_a.ck_rv, CkRv::OK.0);
    let stale_login_state = ctx_mgr
        .get_context(&ctx_a, |ctx| {
            ctx.login_state.get(&crate::server::slot_map::BackendSlotId(CkSlotId(0))).copied()
        })
        .await
        .unwrap();
    assert_eq!(
        stale_login_state, None,
        "closing the last logical session for a slot must clear that context's login state"
    );

    let session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_b, session_b).await,
        CkRv::OK.0,
        "a closed logical client's stale login state must not cause a logical-only login"
    );
}

#[tokio::test]
async fn close_all_sessions_clears_logical_login_state_for_slot() {
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let virtual_slot = ctx_mgr.virtual_slots().await[0];

    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_id, session).await, CkRv::OK.0);

    let close_all = close_all_sessions(
        &ctx_mgr,
        &backend,
        Request::new(pkcs11_proxy_ng_proto::CloseAllSessionsRequest {
            client_context_id: ctx_id.0.clone(),
            slot_id: virtual_slot.0,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(close_all.ck_rv, CkRv::OK.0);

    let stale_login_state = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            ctx.login_state.get(&crate::server::slot_map::BackendSlotId(CkSlotId(0))).copied()
        })
        .await
        .unwrap();
    assert_eq!(
        stale_login_state, None,
        "closing all logical sessions for a slot must clear that context's login state"
    );
}

#[tokio::test]
async fn close_all_sessions_releases_backend_login_before_close() {
    // m-5: an ordinary logged-in close-all must attempt the last-holder
    // backend logout BEFORE the batch close, using one of the closing
    // sessions as the preferred carrier (ADR-0002 §7: "the logout rides a
    // still-open session ... and runs before that context's backend
    // sessions close"). Pre-fix the logout ran after the closes, found no
    // carrier single-tenant, WARNed, and left the backend logged in.
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let virtual_slot = ctx_mgr.virtual_slots().await[0];

    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_id, session).await, CkRv::OK.0);

    // A spare backend session held outside the context manager: it keeps the
    // mock token from auto-logging-out on last close (so the test observes
    // the daemon's own logout, not the mock's), while staying invisible to
    // the daemon's carrier scan (which reads context maps only).
    let spare = mock
        .open_session(CkSlotId(0), CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
        .unwrap();

    let close_all = close_all_sessions(
        &ctx_mgr,
        &backend,
        Request::new(pkcs11_proxy_ng_proto::CloseAllSessionsRequest {
            client_context_id: ctx_id.0.clone(),
            slot_id: virtual_slot.0,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(close_all.ck_rv, CkRv::OK.0);

    // The backend token must be logged out: a logout on the spare answers
    // USER_NOT_LOGGED_IN. (Pre-fix the backend stayed logged in and this
    // logout succeeded.) The success path emits no WARN, so the routine
    // "logout skipped" warning is gone with it.
    assert_eq!(
        mock.logout(spare),
        Err(CkRv::USER_NOT_LOGGED_IN),
        "close-all must release the backend login via its own pre-close carrier"
    );
}

#[tokio::test]
async fn close_session_releases_backend_login_before_close() {
    // T5F (singular-path analogue of m-5): an ordinary logged-in singular
    // close of the last own session must attempt the last-holder backend
    // logout BEFORE the backend close, using the closing session as the
    // preferred carrier (ADR-0002 §7: "the logout rides a still-open
    // session"). Pre-fix the logout ran after the close, found no carrier
    // single-tenant, WARNed, and left the backend logged in.
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();

    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_id, session).await, CkRv::OK.0);

    // A spare backend session held outside the context manager: it keeps the
    // mock token from auto-logging-out on last close (so the test observes
    // the daemon's own logout, not the mock's), while staying invisible to
    // the daemon's carrier scan (which reads context maps only).
    let spare = mock
        .open_session(CkSlotId(0), CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
        .unwrap();

    let close = close_session(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(close.ck_rv, CkRv::OK.0);

    // The backend token must be logged out: a logout on the spare answers
    // USER_NOT_LOGGED_IN. (Pre-fix the backend stayed logged in and this
    // logout succeeded.) The success path emits no WARN, so the routine
    // "logout skipped" warning is gone with it — verified via an isolated
    // log-capture probe, not committed (shared-message captures flake under
    // suite parallelism, same as m-5).
    assert_eq!(
        mock.logout(spare),
        Err(CkRv::USER_NOT_LOGGED_IN),
        "singular close must release the backend login via its own pre-close carrier"
    );
}

#[tokio::test]
async fn failed_physical_logout_preserves_logical_login_state() {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;

    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_id, session).await, CkRv::OK.0);
    let backend_session = ctx_mgr
        .get_context(&ctx_id, |ctx| ctx.session_handles.resolve(VirtualHandle(session)))
        .await
        .unwrap()
        .unwrap();
    mock.close_session(CkSessionHandle(backend_session.0 as u64)).unwrap();

    assert_eq!(
        logout_response(&ctx_mgr, &backend, &ctx_id, session).await,
        CkRv::SESSION_HANDLE_INVALID.0
    );
    let login_state = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            ctx.login_state.get(&crate::server::slot_map::BackendSlotId(CkSlotId(0))).copied()
        })
        .await
        .unwrap();
    assert_eq!(
        login_state,
        Some(LoginState::User),
        "failed physical logout must not clear logical daemon login state"
    );
}

#[tokio::test]
async fn context_specific_login_logout_reaches_backend_without_logical_state() {
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;

    let context_login = login(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::LoginRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            user_type: CkUserType::ContextSpecific as u64,
            pin: Some(b"1234".to_vec()),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(context_login.ck_rv, CkRv::OK.0);

    let logical_login_state = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            ctx.login_state.get(&crate::server::slot_map::BackendSlotId(CkSlotId(0))).copied()
        })
        .await
        .unwrap();
    assert_eq!(
        logical_login_state, None,
        "CKU_CONTEXT_SPECIFIC must not be recorded as token-wide logical login state"
    );
    assert_eq!(
        logout_response(&ctx_mgr, &backend, &ctx_id, session).await,
        CkRv::OK.0,
        "without another logical client to protect, C_Logout must reach the backend"
    );
}

pub(crate) async fn capture_logs<F, Fut>(f: F) -> String
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let _capture_guard = LOG_CAPTURE_LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    ensure_capture_subscriber();
    let writer = CapturedWriter::default();
    *ACTIVE_CAPTURE.lock().unwrap() = Some(writer.clone());
    f().await;
    *ACTIVE_CAPTURE.lock().unwrap() = None;
    writer.output()
}

#[tokio::test]
async fn capture_logs_keeps_overlapping_captures_isolated() {
    let (first, second) = tokio::join!(
        capture_logs(|| async {
            tokio::task::yield_now().await;
            tracing::info!("first audit marker");
        }),
        capture_logs(|| async {
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
            tracing::info!("second audit marker");
        })
    );

    assert!(
        first.contains("first audit marker"),
        "first capture missed its own event; first={first:?} second={second:?}"
    );
    assert!(
        second.contains("second audit marker"),
        "second capture missed its own event; first={first:?} second={second:?}"
    );
    assert!(
        !first.contains("second audit marker"),
        "first capture included second event; first={first:?} second={second:?}"
    );
    assert!(
        !second.contains("first audit marker"),
        "second capture included first event; first={first:?} second={second:?}"
    );
}

#[tokio::test]
async fn login_produces_audit_log_without_pin() {
    let (ctx_mgr, backend, ctx_id, session) = setup_session().await;
    let pin = b"SuperSecretPIN!42".to_vec();

    let output = capture_logs(|| async {
        let _ = login(
            &HandlerContext::for_test(&ctx_mgr, &backend),
            Request::new(pkcs11_proxy_ng_proto::LoginRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                user_type: 1,
                pin: Some(pin.clone()),
            }),
        )
        .await;
    })
    .await;

    assert!(
        output.contains("Login succeeded") || output.contains("Login failed"),
        "login audit output missing expected event: {output:?}"
    );
    assert!(
        !output.contains("SuperSecretPIN"),
        "PIN data must never appear in log output: {output}"
    );
}

#[tokio::test]
async fn init_token_produces_audit_log_without_so_pin() {
    let (ctx_mgr, backend, ctx_id, _session) = setup_session().await;
    let so_pin = b"TopSecretSOPin99".to_vec();
    let virtual_slot = ctx_mgr.virtual_slots().await[0];

    let output = capture_logs(|| async {
        let _ = init_token(
            &ctx_mgr,
            &backend,
            Request::new(pkcs11_proxy_ng_proto::InitTokenRequest {
                client_context_id: ctx_id.0.clone(),
                slot_id: virtual_slot.0,
                so_pin: Some(so_pin.clone()),
                label: "test-token".into(),
            }),
        )
        .await;
    })
    .await;

    assert!(output.contains("Token initialized") || output.contains("InitToken failed"));
    assert!(!output.contains("TopSecretSOPin"), "SO PIN must never appear in log output: {output}");
}

#[tokio::test]
async fn init_pin_produces_audit_log_without_pin() {
    let (ctx_mgr, backend, ctx_id, session) = setup_session().await;
    let pin = b"NewUserPin!XYZ".to_vec();

    let output = capture_logs(|| async {
        let _ = init_pin(
            &HandlerContext::for_test(&ctx_mgr, &backend),
            Request::new(pkcs11_proxy_ng_proto::InitPinRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                pin: Some(pin.clone()),
            }),
        )
        .await;
    })
    .await;

    assert!(output.contains("InitPIN succeeded") || output.contains("InitPIN failed"));
    assert!(!output.contains("NewUserPin"), "PIN must never appear in log output: {output}");
}

#[tokio::test]
async fn set_pin_produces_audit_log_without_pins() {
    let (ctx_mgr, backend, ctx_id, session) = setup_session().await;
    let old_pin = b"OldPin!Secret77".to_vec();
    let new_pin = b"BrandNewPin!88".to_vec();

    let output = capture_logs(|| async {
        let _ = set_pin(
            &HandlerContext::for_test(&ctx_mgr, &backend),
            Request::new(pkcs11_proxy_ng_proto::SetPinRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                old_pin: Some(old_pin.clone()),
                new_pin: Some(new_pin.clone()),
            }),
        )
        .await;
    })
    .await;

    assert!(output.contains("SetPIN succeeded") || output.contains("SetPIN failed"));
    assert!(!output.contains("OldPin"), "old PIN must never appear in log output: {output}");
    assert!(!output.contains("BrandNewPin"), "new PIN must never appear in log output: {output}");
}

#[tokio::test]
async fn logout_produces_audit_log() {
    let (ctx_mgr, backend, ctx_id, session) = setup_session().await;
    let pin = b"LogoutSetupPin!123".to_vec();

    let output = capture_logs(|| async {
        let _ = login(
            &HandlerContext::for_test(&ctx_mgr, &backend),
            Request::new(pkcs11_proxy_ng_proto::LoginRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                user_type: 1,
                pin: Some(pin.clone()),
            }),
        )
        .await;
        let _ = logout(
            &HandlerContext::for_test(&ctx_mgr, &backend),
            Request::new(pkcs11_proxy_ng_proto::LogoutRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
            }),
        )
        .await;
    })
    .await;

    assert!(output.contains("Logout succeeded") || output.contains("Logout"));
    assert!(!output.contains("LogoutSetupPin"), "PIN must never appear in log output: {output}");
}

#[test]
fn proto_pin_requests_debug_redacts_data() {
    // ADR-0013 §7: secret-bearing wire messages print only
    // `TypeName([REDACTED])` — neither the PIN payload nor its field name.
    let login = pkcs11_proxy_ng_proto::LoginRequest {
        client_context_id: "ctx-test".into(),
        session_handle: 1,
        user_type: 1,
        pin: Some(b"secret-pin-data".to_vec()),
    };
    let debug_output = format!("{:?}", login);
    assert_eq!(debug_output, "LoginRequest([REDACTED])");
    assert!(!debug_output.contains("secret-pin-data"));
}

/// Secret identifiers whose VALUE must never be captured by a log macro.
const PIN_SECRET_IDENTS: &[&str] = &[
    "pin", "so_pin", "old_pin", "new_pin", "user_pin", "username", "password", "secret", "pin_hash",
];

/// Log macros whose invocation bodies are scanned for secret captures:
/// tracing levels plus print sinks. (`dbg!` is banned outright by the gate
/// below, so it needs no body scan.)
const PIN_SCANNED_MACROS: &[&str] =
    &["info", "warn", "debug", "error", "trace", "print", "eprint", "println", "eprintln"];

/// Every `.rs` file under `grpc_service/`, walked recursively from disk so a
/// new handler file cannot bypass the PIN gates (W1-L2-06, W1-L9-07).
fn grpc_service_rs_files() -> Vec<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server/grpc_service");
    let mut files = Vec::new();
    collect_rs_files(&root, &mut files);
    files.sort();
    files.into_iter().map(|path| path.display().to_string()).collect()
}

fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Secret-value captures in one file's log-macro bodies, as
/// `file:line: ...` violations (empty when clean). Each tracing/print-macro
/// invocation body (possibly multi-line) is checked for `ident =` fields
/// (on string-blanked text, so `"pin = {}"` labels cannot trip), `%`/`?`
/// sigils, and `{ident}` interpolation (on comments-only-stripped text, since
/// interpolation lives inside string literals) over every secret ident.
fn pin_log_violations(file: &str, src: &str) -> Vec<String> {
    use crate::consistency_checks::{strip_rust_code, strip_rust_comments_only};

    let stripped = strip_rust_code(src);
    let with_strings = strip_rust_comments_only(src);
    let mut violations = Vec::new();
    for (lineno, span) in log_macro_body_spans(&stripped) {
        let code_body = &stripped[span.clone()];
        let text_body = &with_strings[span];
        for ident in PIN_SECRET_IDENTS {
            if tracing_field_captures(code_body, ident) {
                violations.push(format!(
                    "{file}:{lineno}: log macro captures the value of secret '{ident}' \
                     (`{ident} =` field): {}",
                    first_line(text_body),
                ));
            } else if logs_secret_sigil(text_body, ident) {
                violations.push(format!(
                    "{file}:{lineno}: log macro captures the value of secret '{ident}' \
                     (%/?/{{}} form): {}",
                    first_line(text_body),
                ));
            }
        }
    }
    violations
}

/// `(invocation line, body span)` for every scanned log-macro call, located
/// on comment- and string-stripped `src`. Handles `tracing::info!`-qualified
/// and wrapped invocations; strings/comments cannot forge a match (already
/// blanked). Spans index any same-offset stripping of the same source.
fn log_macro_body_spans(src: &str) -> Vec<(usize, std::ops::Range<usize>)> {
    use crate::consistency_checks::{is_ident_char, skip_ws};

    let bytes = src.as_bytes();
    let mut bodies = Vec::new();
    for macro_name in PIN_SCANNED_MACROS {
        let mut cursor = 0;
        while let Some(rel) = src[cursor..].find(macro_name) {
            let idx = cursor + rel;
            cursor = idx + 1;
            // Whole ident, not `my_info`/`debug_assert`/`eprintln`-inside-...:
            // the char before must not extend the ident (start or `::` or
            // punctuation), and after the name (plus whitespace) must come `!`.
            if idx > 0 && is_ident_char(bytes[idx - 1]) {
                continue;
            }
            let bang = skip_ws(src, idx + macro_name.len());
            if bytes.get(bang) != Some(&b'!') {
                continue;
            }
            let open = skip_ws(src, bang + 1);
            if bytes.get(open) != Some(&b'(') {
                continue;
            }
            // Balanced body on stripped text (no strings/comments left).
            let mut depth = 0usize;
            let mut end = open;
            for (i, b) in bytes.iter().enumerate().skip(open) {
                if *b == b'(' {
                    depth += 1;
                } else if *b == b')' {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
            }
            if end == open {
                continue;
            }
            let lineno = src[..open].bytes().filter(|b| *b == b'\n').count() + 1;
            bodies.push((lineno, open + 1..end));
        }
    }
    bodies.sort_by_key(|(lineno, _)| *lineno);
    bodies
}

/// True when `body` assigns the secret's value to a tracing field
/// (`ident = value`), with `ident` as a whole token. Comparisons
/// (`ident == ...`), match arms (`ident => ...`), and local bindings
/// (`let [mut] ident = ...`) are not captures.
fn tracing_field_captures(body: &str, ident: &str) -> bool {
    use crate::consistency_checks::{is_ident_char, skip_ws};

    let bytes = body.as_bytes();
    let mut cursor = 0;
    while let Some(rel) = body[cursor..].find(ident) {
        let start = cursor + rel;
        cursor = start + 1;
        if start > 0 && is_ident_char(bytes[start - 1]) {
            continue;
        }
        let end = start + ident.len();
        if bytes.get(end).is_some_and(|b| is_ident_char(*b)) {
            continue;
        }
        let eq = skip_ws(body, end);
        if bytes.get(eq) != Some(&b'=') {
            continue;
        }
        // `==`, `=>`: comparison or match arm, not a field capture.
        if bytes.get(eq + 1).is_some_and(|b| *b == b'=' || *b == b'>') {
            continue;
        }
        // `let [mut] ident =`: a local binding inside a block argument.
        if preceded_by_let(body, start) {
            continue;
        }
        return true;
    }
    false
}

/// True when the ident at `start` is bound by a `let`/`let mut` immediately
/// before it (whitespace-separated).
fn preceded_by_let(body: &str, start: usize) -> bool {
    use crate::consistency_checks::is_ident_char;

    let bytes = body.as_bytes();
    let mut cursor = start;
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    // Optional `mut`.
    let mut word_end = cursor;
    let mut word_start = word_end;
    while word_start > 0 && is_ident_char(bytes[word_start - 1]) {
        word_start -= 1;
    }
    if &body[word_start..word_end] == "mut" {
        cursor = word_start;
        while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
            cursor -= 1;
        }
        word_end = cursor;
        word_start = word_end;
        while word_start > 0 && is_ident_char(bytes[word_start - 1]) {
            word_start -= 1;
        }
    }
    &body[word_start..word_end] == "let"
        && (word_start == 0 || !is_ident_char(bytes[word_start - 1]))
}

/// True when `body` captures the value of `ident` via a tracing sigil
/// (`?ident`, `%ident`) or interpolates it (`{ident}`, `{ident:?}`, or any
/// other `{ident:...}` format spec), with `ident` as a whole token.
/// (Same rule as the shim PIN gate's `logs_secret_sigil`.)
fn logs_secret_sigil(body: &str, ident: &str) -> bool {
    use crate::consistency_checks::is_ident_char;

    let bytes = body.as_bytes();
    for sigil in ['?', '%'] {
        let pat = format!("{sigil}{ident}");
        let mut from = 0;
        while let Some(rel) = body[from..].find(&pat) {
            let start = from + rel;
            let end = start + pat.len();
            if end >= bytes.len() || !is_ident_char(bytes[end]) {
                return true;
            }
            from = start + 1;
        }
    }
    // Inline-format interpolation, skipping `{{` escapes: `{{pin}}` prints a
    // literal and must not trip, while `{pin}` and `{pin:?...}` capture.
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if bytes.get(i + 1) == Some(&b'{') {
                i += 2;
                continue;
            }
            if body[i + 1..].starts_with(ident) {
                let after = i + 1 + ident.len();
                if bytes.get(after).is_some_and(|b| *b == b'}' || *b == b':') {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// First line of a macro body, for violation messages.
fn first_line(body: &str) -> String {
    body.lines().next().unwrap_or_default().trim().to_string()
}

#[test]
fn grpc_handlers_never_debug_format_requests() {
    // W1-L9-07: whole-tree walk (not a hardcoded file list) so a new handler
    // file cannot bypass the dbg! ban; comments/strings cannot forge a match.
    let files = grpc_service_rs_files();
    assert!(!files.is_empty(), "no grpc_service sources found");

    let dbg_pattern = concat!("dbg", "!(");
    for name in &files {
        let src =
            std::fs::read_to_string(name).unwrap_or_else(|e| panic!("cannot read {name}: {e}"));
        let stripped = crate::consistency_checks::strip_rust_code(&src);
        for (lineno, line) in stripped.lines().enumerate() {
            assert!(
                !line.contains(dbg_pattern),
                "{name} line {}: found debug macro that may leak secrets: {}",
                lineno + 1,
                line.trim(),
            );
        }
    }
}

#[test]
fn pin_gate_trips_on_every_secret_form() {
    // W1-L10-25 negative control: every (macro, secret, form) combination the
    // old gate missed — `trace!`, `user_pin`/`username`/`password` idents,
    // `%`/`?` sigils, `{ident}` interpolation — must trip.
    for (macro_name, line) in [
        ("trace", "trace!(pin = pin, \"login\")"),
        ("user_pin", "info!(user_pin = user_pin, \"login_user\")"),
        ("username", "info!(username = username, \"login_user\")"),
        ("password", "debug!(password = password, \"auth\")"),
        ("display-sigil", "info!(pin = %pin, \"login\")"),
        ("debug-sigil", "info!(pin = ?pin, \"login\")"),
        ("interpolation", "info!(\"pin={pin}\")"),
        ("debug-interpolation", "info!(\"pin={pin:?}\")"),
        ("bare-sigil", "warn!(?so_pin)"),
        ("multiline", "debug!(\n    old_pin = old_pin,\n    \"set_pin\"\n)"),
    ] {
        let violations = pin_log_violations("control.rs", line);
        assert!(
            !violations.is_empty(),
            "gate must trip on {macro_name} form: {line:?} (got no violations)"
        );
    }
}

#[test]
fn pin_gate_covers_new_handler_files() {
    // W1-L2-06 + W1-L9-07 negative control: the walk reaches the PIN-bearing
    // files the hardcoded lists omitted, and a planted PIN in any of them
    // trips the gate.
    let files = grpc_service_rs_files();
    for required in
        ["session_3x.rs", "byte_output_exact.rs", "parameter_output_exact.rs", "message_crypto"]
    {
        assert!(
            files.iter().any(|path| path.contains(required)),
            "PIN-gate walk must reach {required}"
        );
    }
    for name in ["session_3x.rs", "message_crypto/mod.rs", "byte_output_exact.rs", "key_ops/kem.rs"]
    {
        let planted =
            "fn login_user() {\n    let pin = take_pin();\n    info!(pin = pin, \"leak\");\n}\n";
        let violations = pin_log_violations(name, planted);
        assert!(
            violations.iter().any(|v| v.contains(name)),
            "planted PIN in {name} must trip the gate (got {violations:?})"
        );
    }
}

#[test]
fn pin_gate_ignores_comments_and_length_fields() {
    // Precision control: length/metadata handling that never captures a
    // secret value must pass — `pin_len` fields, comparisons, and commented
    // or string-literal mentions.
    let clean = r#"
fn login() {
    let pin = take_pin();
    info!(pin_len = pin.len(), "login attempt");
    info!(pin_ok = (pin == expected), "verify");
    // info!(pin = pin, "disabled");
    let _ = "info!(pin = pin)";
    info!(context_id = %ctx_id.0, "InitPIN succeeded");
    info!("pin = {}", pin.len());
    info!("{{pin}} literal = {}", pin.len());
}
"#;
    assert!(pin_log_violations("clean.rs", clean).is_empty());
}

#[test]
fn source_code_never_logs_pin_fields() {
    // W1-L10-25 + W1-L2-06 + W1-L9-07 (one coherent gate): whole-tree walk
    // over grpc_service (session_3x.rs, message_crypto/, byte_output_exact.rs
    // and every future handler included); every tracing/print-macro body must
    // not capture a secret value via `ident =` fields, `%`/`?` sigils, or
    // `{ident}` interpolation — at any level including `trace!`.
    let files = grpc_service_rs_files();
    assert!(!files.is_empty(), "no grpc_service sources found");

    let mut violations = Vec::new();
    for name in &files {
        let src =
            std::fs::read_to_string(name).unwrap_or_else(|e| panic!("cannot read {name}: {e}"));
        violations.extend(pin_log_violations(name, &src));
    }
    assert!(violations.is_empty(), "PIN logging violations:\n{}", violations.join("\n"));
}

#[tokio::test]
async fn closing_a_session_evicts_session_objects_not_token_objects() {
    // B2: a session object's virtual handle must be evicted when its session
    // closes (the backend destroys it, and a recycled backend object number
    // must not alias the stale handle). A token object's handle persists — it
    // is valid across the application's sessions.
    use crate::server::grpc_service::object::create_object;
    use crate::server::grpc_service::session::close_session;

    let (ctx_mgr, backend, ctx_id, session) = setup_session().await;

    let create = |template: Vec<pkcs11_proxy_ng_proto::Attribute>| {
        let ctx_mgr = ctx_mgr.clone();
        let backend = backend.clone();
        let ctx = ctx_id.0.clone();
        async move {
            create_object(
                &HandlerContext::for_test(&ctx_mgr, &backend),
                Request::new(pkcs11_proxy_ng_proto::CreateObjectRequest {
                    client_context_id: ctx,
                    session_handle: session,
                    template,

                    template_null: false,
                }),
            )
            .await
            .unwrap()
            .into_inner()
            .object_handle
        }
    };

    let session_obj = create(vec![]).await;
    let token_obj = create(vec![pkcs11_proxy_ng_proto::Attribute {
        attr_type: CkAttributeType::TOKEN.0,
        value: Some(pkcs11_proxy_ng_proto::attribute::Value::BoolValue(true)),
    }])
    .await;
    assert_ne!(session_obj, 0);
    assert_ne!(token_obj, 0);

    let resolves = |vobj: u64| {
        let ctx_mgr = ctx_mgr.clone();
        let ctx = ctx_id.clone();
        async move {
            ctx_mgr
                .get_context(&ctx, |c| c.object_handles.resolve(VirtualHandle(vobj)))
                .await
                .flatten()
                .is_some()
        }
    };
    assert!(resolves(session_obj).await, "setup: session object should resolve");
    assert!(resolves(token_obj).await, "setup: token object should resolve");

    let closed = close_session(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(closed.ck_rv, CkRv::OK.0, "close_session failed");

    assert!(
        !resolves(session_obj).await,
        "session object handle must be evicted when its session closes"
    );
    assert!(
        resolves(token_obj).await,
        "token object handle must persist across the application's sessions"
    );
}

#[tokio::test]
async fn destroy_object_evicts_the_virtual_handle() {
    use crate::server::grpc_service::object::{create_object, destroy_object};

    let (ctx_mgr, backend, ctx_id, session) = setup_session().await;

    // Create a live backend object so destroy has something to remove.
    let created = create_object(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::CreateObjectRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            template: vec![],

            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(created.ck_rv, CkRv::OK.0, "setup: create_object failed");
    let vobj = created.object_handle;
    assert_ne!(vobj, 0, "create_object must return a virtual handle");

    let before = ctx_mgr
        .get_context(&ctx_id, |ctx| ctx.object_handles.resolve(VirtualHandle(vobj)))
        .await
        .flatten();
    assert!(before.is_some(), "the virtual object handle should resolve before destroy");

    let destroyed = destroy_object(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::DestroyObjectRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            object_handle: vobj,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(destroyed.ck_rv, CkRv::OK.0, "destroy_object failed");

    // After a successful destroy the virtual->backend mapping must be gone, so
    // a recycled backend object number can never alias this stale handle.
    let after = ctx_mgr
        .get_context(&ctx_id, |ctx| ctx.object_handles.resolve(VirtualHandle(vobj)))
        .await
        .flatten();
    assert!(after.is_none(), "destroyed object handle must be evicted, found {after:?}");
}

#[tokio::test]
async fn object_handles_are_isolated_per_context() {
    // H4 (non-ignored regression guard for the A1/A2/B1/B2 isolation work):
    // an object created by one logical client must not be reachable through
    // another client's context. This is sharp because per-context virtual
    // handles BOTH start numbering at 1 — ctx_b creates no object, so ctx_a's
    // handle simply does not exist in ctx_b's map and must not alias anything.
    // Runs on MockBackend, so it guards isolation in CI without a real HSM.
    use crate::server::grpc_service::object::{create_object, get_attribute_value};

    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();
    let session_a = open_test_session(&ctx_mgr, &backend, &ctx_a).await;
    let session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;

    // ctx_a creates an object; ctx_b creates none (its handle map stays empty).
    let created = create_object(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::CreateObjectRequest {
            client_context_id: ctx_a.0.clone(),
            session_handle: session_a,
            template: vec![],

            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(created.ck_rv, CkRv::OK.0, "setup: create_object failed");
    let vobj = created.object_handle;
    assert_ne!(vobj, 0, "create_object must return a virtual handle");

    let get = |ctx: String, session: u64| {
        let ctx_mgr = ctx_mgr.clone();
        let backend = backend.clone();
        async move {
            get_attribute_value(
                &HandlerContext::for_test(&ctx_mgr, &backend),
                Request::new(pkcs11_proxy_ng_proto::GetAttributeValueRequest {
                    client_context_id: ctx,
                    session_handle: session,
                    object_handle: vobj,
                    template: vec![],
                }),
            )
            .await
            .unwrap()
            .into_inner()
            .ck_rv
        }
    };

    // ctx_b cannot reach ctx_a's object through the shared numeric handle value.
    assert_eq!(
        get(ctx_b.0.clone(), session_b).await,
        CkRv::OBJECT_HANDLE_INVALID.0,
        "a foreign context must not resolve another client's object handle"
    );
    // ctx_a still owns it.
    assert_eq!(
        get(ctx_a.0.clone(), session_a).await,
        CkRv::OK.0,
        "the owning context must still resolve its own object handle"
    );
}

#[tokio::test]
async fn wait_for_slot_event_does_not_leak_raw_backend_slot() {
    use crate::server::grpc_service::state_ops::wait_for_slot_event_with_policy;

    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    // An event for a backend slot the daemon never registered (no virtual map).
    mock.enqueue_slot_event(CkSlotId(99));
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await; // only slot 0 is mapped; 99 is not
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let policy = crate::server::auth::policy::TokenPolicy::from_config(
        &crate::config::AuthConfig::default(),
    )
    .unwrap();

    let resp = wait_for_slot_event_with_policy(
        &ctx_mgr,
        &backend,
        &policy,
        Request::new(pkcs11_proxy_ng_proto::WaitForSlotEventRequest {
            client_context_id: ctx_id.0.clone(),
            flags: 1, // CKF_DONT_BLOCK — return the queued event immediately
        }),
    )
    .await
    .unwrap()
    .into_inner();

    assert_ne!(resp.slot_id, 99, "must never surface the raw backend slot id for an unmapped slot");
}

#[tokio::test]
async fn wait_for_slot_event_suppresses_events_for_unauthorized_slots() {
    // M13: an authenticated client must not learn that a token it has no policy
    // access to had a slot event — that would disclose insertion/removal of
    // tokens outside its authorization. The event is reported as no-event.
    use crate::server::grpc_service::state_ops::wait_for_slot_event_with_policy;

    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    mock.enqueue_slot_event(CkSlotId(0)); // event for a MAPPED slot with a token
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    // An authenticated identity that the (empty, deny-by-default) policy denies.
    let ctx_id =
        ctx_mgr.create_context(Some("x509:issuer=CN=CA;subject=CN=denied".into())).await.unwrap();
    let policy =
        crate::server::auth::policy::TokenPolicy::from_config(&crate::config::AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![],
        })
        .unwrap();

    let resp = wait_for_slot_event_with_policy(
        &ctx_mgr,
        &backend,
        &policy,
        Request::new(pkcs11_proxy_ng_proto::WaitForSlotEventRequest {
            client_context_id: ctx_id.0.clone(),
            flags: 1,
        }),
    )
    .await
    .unwrap()
    .into_inner();

    assert_eq!(
        resp.ck_rv,
        CkRv::NO_EVENT.0,
        "an event for an unauthorized slot must be suppressed (no-event)"
    );
    assert_eq!(resp.slot_id, 0, "no slot id is surfaced when suppressed");
}

#[tokio::test]
async fn wait_for_slot_event_absent_context_never_enters_backend() {
    // TO26b group 2: absent logical context refuses before backend entry.
    use crate::server::grpc_service::state_ops::wait_for_slot_event_with_policy;

    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let policy = crate::server::auth::policy::TokenPolicy::from_config(
        &crate::config::AuthConfig::default(),
    )
    .unwrap();

    let resp = wait_for_slot_event_with_policy(
        &ctx_mgr,
        &backend,
        &policy,
        Request::new(pkcs11_proxy_ng_proto::WaitForSlotEventRequest {
            client_context_id: "no-such-context".to_string(),
            flags: 1,
        }),
    )
    .await
    .unwrap()
    .into_inner();

    assert_eq!(resp.ck_rv, CkRv::CRYPTOKI_NOT_INITIALIZED.0);
    assert_eq!(resp.slot_id, 0, "no slot output on refusal");
    assert_eq!(mock.wait_call_count(), 0, "zero backend wait attempts");
    assert_eq!(mock.token_info_call_count(), 0, "zero backend policy attempts");
}

#[tokio::test]
async fn wait_for_slot_event_backend_error_passes_through_with_zero_slot() {
    // TO26b group 2: backend wait errors (contention, sentinel RVs) pass
    // through verbatim with no slot output and no policy follow-up.
    use crate::server::grpc_service::state_ops::wait_for_slot_event_with_policy;

    for scripted in [CkRv::FUNCTION_FAILED, CkRv(0xDEAD_BEEF)] {
        let mock = Arc::new(MockBackend::default_test());
        mock.initialize().unwrap();
        mock.set_next_wait_outcome(Err(scripted));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();

        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let policy = crate::server::auth::policy::TokenPolicy::from_config(
            &crate::config::AuthConfig::default(),
        )
        .unwrap();

        let resp = wait_for_slot_event_with_policy(
            &ctx_mgr,
            &backend,
            &policy,
            Request::new(pkcs11_proxy_ng_proto::WaitForSlotEventRequest {
                client_context_id: ctx_id.0.clone(),
                flags: 1,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(resp.ck_rv, scripted.0, "backend error passes through verbatim");
        assert_eq!(resp.slot_id, 0, "no slot output on backend error");
        assert_eq!(mock.wait_call_count(), 1);
        assert_eq!(mock.token_info_call_count(), 0, "no policy query on backend error");
    }
}

#[tokio::test]
async fn wait_for_slot_event_policy_query_after_seal_returns_not_initialized() {
    // TO26b group 2: an otherwise successful wait whose policy follow-up
    // finds the backend sealed answers local NOT_INITIALIZED with no slot
    // output. The seal is simulated by an injected NOT_INIT on token-info
    // (the FFI layer refuses such a query at admission with zero native
    // attempts — see the backend seal test — so no policy query crosses
    // the seal either way); the wait itself ignores injected errors.
    use crate::server::grpc_service::state_ops::wait_for_slot_event_with_policy;

    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    mock.enqueue_slot_event(CkSlotId(0));
    mock.inject_error(CkRv::CRYPTOKI_NOT_INITIALIZED);
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    // Authenticated: an unauthenticated context short-circuits the policy
    // without the token-info fetch this test seals against.
    let ctx_id =
        ctx_mgr.create_context(Some("x509:issuer=CN=CA;subject=CN=allowed".into())).await.unwrap();
    let policy =
        crate::server::auth::policy::TokenPolicy::from_config(&crate::config::AuthConfig {
            allow_all_authenticated: true,
            anonymous_principal: None,
            policy: vec![],
        })
        .unwrap();

    let resp = wait_for_slot_event_with_policy(
        &ctx_mgr,
        &backend,
        &policy,
        Request::new(pkcs11_proxy_ng_proto::WaitForSlotEventRequest {
            client_context_id: ctx_id.0.clone(),
            flags: 1,
        }),
    )
    .await
    .unwrap()
    .into_inner();

    assert_eq!(
        resp.ck_rv,
        CkRv::CRYPTOKI_NOT_INITIALIZED.0,
        "sealed policy follow-up must answer NOT_INITIALIZED, not NO_EVENT"
    );
    assert_eq!(resp.slot_id, 0, "no slot output when the policy query seals");
    assert_eq!(mock.wait_call_count(), 1, "the wait itself succeeded");
    assert_eq!(mock.token_info_call_count(), 1, "the policy query ran and sealed");
}

#[tokio::test]
async fn wait_for_slot_event_token_not_present_suppresses_to_no_event() {
    // TO26b group 2 (existing-behavior pin): a token that left between
    // the wait and the policy follow-up suppresses to no-event.
    use crate::server::grpc_service::state_ops::wait_for_slot_event_with_policy;

    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    mock.enqueue_slot_event(CkSlotId(0));
    mock.set_token_present(CkSlotId(0), false);
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id =
        ctx_mgr.create_context(Some("x509:issuer=CN=CA;subject=CN=allowed".into())).await.unwrap();
    let policy =
        crate::server::auth::policy::TokenPolicy::from_config(&crate::config::AuthConfig {
            allow_all_authenticated: true,
            anonymous_principal: None,
            policy: vec![],
        })
        .unwrap();

    let resp = wait_for_slot_event_with_policy(
        &ctx_mgr,
        &backend,
        &policy,
        Request::new(pkcs11_proxy_ng_proto::WaitForSlotEventRequest {
            client_context_id: ctx_id.0.clone(),
            flags: 1,
        }),
    )
    .await
    .unwrap()
    .into_inner();

    assert_eq!(resp.ck_rv, CkRv::NO_EVENT.0);
    assert_eq!(resp.slot_id, 0);
    assert_eq!(mock.token_info_call_count(), 1, "the policy query ran");
}

#[tokio::test]
async fn wait_for_slot_event_authorized_event_maps_to_virtual_slot() {
    // TO26b group 2: an authorized event publishes OK with the mapped
    // virtual slot (never the raw backend id).
    use crate::server::grpc_service::state_ops::wait_for_slot_event_with_policy;

    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    mock.enqueue_slot_event(CkSlotId(0));
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id =
        ctx_mgr.create_context(Some("x509:issuer=CN=CA;subject=CN=allowed".into())).await.unwrap();
    let policy =
        crate::server::auth::policy::TokenPolicy::from_config(&crate::config::AuthConfig {
            allow_all_authenticated: true,
            anonymous_principal: None,
            policy: vec![],
        })
        .unwrap();

    let resp = wait_for_slot_event_with_policy(
        &ctx_mgr,
        &backend,
        &policy,
        Request::new(pkcs11_proxy_ng_proto::WaitForSlotEventRequest {
            client_context_id: ctx_id.0.clone(),
            flags: 1,
        }),
    )
    .await
    .unwrap()
    .into_inner();

    let expected_virtual = ctx_mgr
        .to_virtual_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0)))
        .await
        .expect("slot 0 is mapped")
        .0;
    assert_eq!(resp.ck_rv, CkRv::OK.0);
    assert_eq!(resp.slot_id, expected_virtual, "authorized event maps to its virtual slot");
}

#[tokio::test]
async fn slot_wait_server_abort_retains_ordinary_owner() {
    // C3M.6 row 14: aborting the gRPC waiter while the native call is
    // stuck must not strand or corrupt anything. The blocking worker
    // keeps its captured backend/context ownership through native
    // settlement; the aborted call delivers no response; the backend
    // stays usable afterwards.
    use crate::server::grpc_service::state_ops::wait_for_slot_event_with_policy;

    let mock = std::sync::Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    // Empty queue + blocking flags: the native call parks on the condvar.
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let mock_ref = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let policy = crate::server::auth::policy::TokenPolicy::from_config(
        &crate::config::AuthConfig::default(),
    )
    .unwrap();

    let waiter = tokio::spawn({
        let ctx_mgr = ctx_mgr.clone();
        let backend = backend.clone();
        let ctx = ctx_id.0.clone();
        async move {
            // Move ownership into the future so the waiter holds its own
            // policy through native settlement (Send, 'static).
            let policy = policy;
            wait_for_slot_event_with_policy(
                &ctx_mgr,
                &backend,
                &policy,
                Request::new(pkcs11_proxy_ng_proto::WaitForSlotEventRequest {
                    client_context_id: ctx,
                    flags: 0, // blocking: parks until an event arrives
                }),
            )
            .await
        }
    });
    // Let the native call enter (order-independent: an early event would
    // just queue, a late abort still precedes settlement either way).
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    waiter.abort();
    let aborted = waiter.await.unwrap_err();
    assert!(aborted.is_cancelled(), "the aborted waiter delivers no response");

    // Settle the native call after the abort: the retained worker must
    // complete crash-free with its captured ownership intact.
    mock_ref.enqueue_slot_event(CkSlotId(0));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // The backend serves a fresh waiter afterwards: no leak, no poison.
    // (The aborted worker consumed the settlement event while completing,
    // so a new event proves liveness rather than a stale queue entry.)
    mock_ref.enqueue_slot_event(CkSlotId(0));
    let policy = crate::server::auth::policy::TokenPolicy::from_config(
        &crate::config::AuthConfig::default(),
    )
    .unwrap();
    let resp = wait_for_slot_event_with_policy(
        &ctx_mgr,
        &backend,
        &policy,
        Request::new(pkcs11_proxy_ng_proto::WaitForSlotEventRequest {
            client_context_id: ctx_id.0.clone(),
            flags: 1, // DONT_BLOCK: dequeues the fresh event
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(resp.ck_rv, CkRv::OK.0, "backend usable after abort+settlement");
}

/// Backstop for injected slot-event hangs: clearing the hang on drop
/// (including unwinding after a test failure) so a parked backend
/// thread is always released. Without this, a failure before the
/// explicit release strands a parked blocking-pool thread, and the
/// tokio runtime shutdown joins it forever — wedging the whole suite
/// binary with no output.
struct SlotEventHangGuard {
    mock: std::sync::Arc<MockBackend>,
}

impl SlotEventHangGuard {
    fn inject(mock: &std::sync::Arc<MockBackend>) -> Self {
        mock.inject_slot_event_hang(true);
        Self { mock: mock.clone() }
    }
}

impl Drop for SlotEventHangGuard {
    fn drop(&mut self) {
        // Enqueue BEFORE clearing: both notifies then happen after the
        // push, so a woken waiter always finds the event (deterministic
        // Ok). Clearing first would let a waiter win the re-lock race,
        // re-check an empty queue with the flag already false, and take
        // the NO_EVENT path — harmless for release, but nondeterministic
        // for tests observing the outcome. The queue lock additionally
        // serializes the release against a waiter that has checked the
        // flag but not yet parked, so no wakeup is missed either way.
        self.mock.enqueue_slot_event(CkSlotId(0));
        self.mock.inject_slot_event_hang(false);
    }
}

#[tokio::test]
async fn slot_event_hang_guard_releases_parked_waiter_on_drop() {
    // A DONT_BLOCK waiter parked by the injected hang must answer once
    // the guard drops. The drop enqueues before clearing, so every
    // wakeup finds the event queued and every interleaving ends with
    // the waiter consuming it (no timing assumption beyond reaching
    // the park).
    use std::sync::mpsc;
    let mock = std::sync::Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let (tx, rx) = mpsc::channel();
    let guard = SlotEventHangGuard::inject(&mock);
    let _waiter = std::thread::spawn({
        let backend: std::sync::Arc<dyn Pkcs11Backend> = mock.clone();
        move || tx.send(backend.wait_for_slot_event(1)).unwrap()
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    drop(guard);
    let outcome = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("released waiter must answer promptly");
    assert_eq!(outcome.unwrap(), CkSlotId(0), "waiter consumes the wakeup event");
}

#[tokio::test]
async fn slot_wait_nonblocking_hang_abnormal_stop() {
    // C3M.6 row 14: a faulty provider that hangs even a DONT_BLOCK
    // waiter must hit the daemon timeout (independent stop) with no
    // cleanup/unload of the library. The stuck call settles exactly
    // once released, and the backend stays initialized and usable.
    use crate::server::grpc_service::service_utils::spawn_backend_with_counters;
    use std::sync::atomic::{AtomicUsize, Ordering};
    // Dedicated breaker/stuck counters: the global IN_FLIGHT/STUCK_CALLS
    // gauges move under concurrent suite tests, so an exact delta on the
    // globals is racy in-suite (and a failure there strands the parked
    // thread — see SlotEventHangGuard).
    static HANG_COUNTER: AtomicUsize = AtomicUsize::new(0);
    static HANG_GAUGE: AtomicUsize = AtomicUsize::new(0);

    let mock = std::sync::Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    // Backstop: clearing the injected hang on drop (including test
    // failure) so a parked backend thread can never strand the tokio
    // runtime shutdown and wedge the whole suite binary.
    let _hang_guard = SlotEventHangGuard::inject(&mock);
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let waiter = tokio::spawn({
        let backend = backend.clone();
        async move {
            spawn_backend_with_counters(
                &HANG_COUNTER,
                &HANG_GAUGE,
                std::time::Duration::from_millis(100),
                8,
                move || {
                    backend.wait_for_slot_event(1) // CKF_DONT_BLOCK — hangs anyway (faulty)
                },
            )
            .await
        }
    });
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
        .await
        .expect("hung waiter must hit the daemon timeout, not the test timeout")
        .expect("waiter task must not panic");
    assert_eq!(
        outcome.expect("no transport error").unwrap_err(),
        CkRv::FUNCTION_FAILED,
        "a hung waiter surfaces the timeout promptly (W1-L3-01)"
    );
    assert_eq!(HANG_GAUGE.load(Ordering::Relaxed), 1, "the still-parked call counts as stuck");

    // Independent stop performed no cleanup/unload: release the native
    // call and it settles; the library answers afterwards. Enqueue
    // before clearing (see SlotEventHangGuard::drop) so the waiter
    // deterministically consumes the wakeup event.
    mock.enqueue_slot_event(CkSlotId(0));
    mock.inject_slot_event_hang(false);
    for _ in 0..200 {
        if HANG_GAUGE.load(Ordering::Relaxed) == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(
        HANG_GAUGE.load(Ordering::Relaxed),
        0,
        "stuck gauge returns to zero once the native call settles"
    );
    assert_eq!(
        backend.wait_for_slot_event(1).unwrap_err(),
        CkRv::NO_EVENT,
        "empty queue after settlement means alive-and-initialized, not unloaded"
    );
}

async fn setup_session_with_mock() -> (Arc<ContextManager>, Arc<MockBackend>, ClientContextId, u64)
{
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;
    (ctx_mgr, mock, ctx_id, session)
}

#[tokio::test]
async fn close_session_keeps_mapping_on_transient_backend_failure() {
    // M3: a transient backend close failure must NOT orphan the backend session
    // behind a deleted virtual handle — the mapping is kept so the client can
    // retry (the old code removed it before the backend close).
    let (ctx_mgr, mock, ctx_id, session) = setup_session_with_mock().await;
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    mock.inject_close_error(CkRv::FUNCTION_FAILED);

    let rv = close_session(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(rv, CkRv::FUNCTION_FAILED.0);

    let still = ctx_mgr
        .get_context(&ctx_id, |c| c.session_handles.resolve(VirtualHandle(session)))
        .await
        .flatten();
    assert!(still.is_some(), "a transient close failure must keep the session mapping for retry");
}

#[tokio::test]
async fn close_session_quarantines_mapping_on_device_error() {
    let (ctx_mgr, mock, ctx_id, session) = setup_session_with_mock().await;
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    mock.inject_close_error(CkRv::DEVICE_ERROR);

    let rv = close_session(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(rv, CkRv::DEVICE_ERROR.0);

    let state = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            (
                ctx.session_handles.resolve(VirtualHandle(session)),
                ctx.session_handles.suspended_backend(VirtualHandle(session)),
            )
        })
        .await
        .unwrap();
    assert_eq!(state.0, None, "an ambiguous close must make the session unresolvable");
    assert!(state.1.is_some(), "teardown must retain the quarantined backend handle");
}

#[tokio::test]
async fn close_session_refuses_general_error_when_slot_lock_held() {
    // W1-L3-01 fix round: close takes the same per-slot login lock under the
    // same bound as login/logout/login_user, so a wedged lock must refuse
    // with the same CKR_GENERAL_ERROR (was CKR_DEVICE_ERROR). Mirrors
    // t7_login_and_logout_refuse_general_error_when_slot_lock_held: paused
    // time fast-forwards the (seconds-long) acquisition timeout.
    tokio::time::pause();
    let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let backend_session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let backend_slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
    ctx_mgr.register_slot(backend_slot).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session_vh = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            ctx.register_session(
                crate::server::handle_map::BackendHandle(backend_session.0),
                backend_slot,
            )
        })
        .await
        .unwrap();

    // Wedge the per-slot login lock; the close must time out on it.
    let slot_lock = ctx_mgr.slot_login_lock(backend_slot);
    let _held = slot_lock.lock().await;

    let rv = super::lifecycle::close_session(
        &ctx_mgr,
        &backend,
        Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session_vh.0,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(rv, CkRv::GENERAL_ERROR.0, "close must refuse with GENERAL_ERROR");

    // Nothing was mutated: the mapping is intact for a retry.
    let still = ctx_mgr
        .get_context(&ctx_id, |c| c.session_handles.resolve(VirtualHandle(session_vh.0)))
        .await
        .flatten();
    assert!(still.is_some(), "a refused close must keep the session mapping for retry");
}

#[tokio::test]
async fn timed_out_close_settles_terminal_completion_after_handler_returns() {
    let (ctx_mgr, mock, ctx_id, session) = setup_session_with_mock().await;
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let operation = ctx_mgr
        .message_operation_lock(&ctx_id, VirtualHandle(session), MessageOperation::Encrypt)
        .await
        .unwrap();
    operation.lock().await.shape = Some(MessageParameterShape::Gcm);
    mock.set_close_session_delay(std::time::Duration::from_millis(80));
    let calls_before = mock.close_session_call_count();

    let rv = super::lifecycle::close_session_with_timeout(
        &ctx_mgr,
        &backend,
        Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
        }),
        Some(std::time::Duration::from_millis(10)),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(
        rv,
        CkRv::FUNCTION_FAILED.0,
        "handler timeout is outcome-ambiguous (W1-L3-01: FUNCTION_FAILED, was DEVICE_ERROR)"
    );
    assert_eq!(mock.close_session_call_count(), calls_before + 1);

    let in_flight = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            (
                ctx.session_handles.resolve(VirtualHandle(session)),
                ctx.session_handles.suspended_backend(VirtualHandle(session)),
            )
        })
        .await
        .unwrap();
    assert_eq!(in_flight.0, None, "timed-out close must remain unresolvable");
    assert!(in_flight.1.is_some(), "completion token retains the quarantined handle");

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let settled = ctx_mgr
                .get_context(&ctx_id, |ctx| {
                    ctx.session_handles.suspended_backend(VirtualHandle(session)).is_none()
                        && !ctx
                            .message_operations
                            .keys()
                            .any(|(owned_session, _)| *owned_session == VirtualHandle(session))
                })
                .await
                .unwrap_or(true);
            if settled {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("delayed provider close must settle after the handler timeout");
    mock.clear_close_session_delay();

    assert_eq!(mock.close_session_call_count(), calls_before + 1, "provider called exactly once");
    let terminal = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            (
                ctx.session_handles.resolve(VirtualHandle(session)),
                ctx.session_handles.suspended_backend(VirtualHandle(session)),
                ctx.message_operations
                    .keys()
                    .any(|(owned_session, _)| *owned_session == VirtualHandle(session)),
            )
        })
        .await
        .unwrap();
    assert_eq!(terminal, (None, None, false));
}

#[tokio::test]
async fn timed_out_close_settles_transient_completion_after_handler_returns() {
    let (ctx_mgr, mock, ctx_id, session) = setup_session_with_mock().await;
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let operation = ctx_mgr
        .message_operation_lock(&ctx_id, VirtualHandle(session), MessageOperation::Encrypt)
        .await
        .unwrap();
    operation.lock().await.shape = Some(MessageParameterShape::Gcm);
    mock.set_close_session_delay(std::time::Duration::from_millis(80));
    mock.inject_close_error(CkRv::FUNCTION_FAILED);
    let calls_before = mock.close_session_call_count();

    let rv = super::lifecycle::close_session_with_timeout(
        &ctx_mgr,
        &backend,
        Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
        }),
        Some(std::time::Duration::from_millis(10)),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(
        rv,
        CkRv::FUNCTION_FAILED.0,
        "handler timeout is outcome-ambiguous (W1-L3-01: FUNCTION_FAILED, was DEVICE_ERROR)"
    );

    let settled = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let state = ctx_mgr
                .get_context(&ctx_id, |ctx| {
                    (
                        ctx.session_handles.resolve(VirtualHandle(session)),
                        ctx.session_handles.suspended_backend(VirtualHandle(session)),
                    )
                })
                .await
                .unwrap();
            if state.0.is_some() && state.1.is_none() {
                break state;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("delayed transient close must reactivate the mapping");
    assert!(settled.0.is_some());
    assert_eq!(settled.1, None);
    assert_eq!(operation.lock().await.shape, Some(MessageParameterShape::Gcm));
    assert_eq!(mock.close_session_call_count(), calls_before + 1);
    mock.clear_close_session_delay();
    mock.clear_close_error();
}

#[tokio::test]
async fn panicked_close_quarantines_mapping_and_clears_shapes() {
    let (ctx_mgr, mock, ctx_id, session) = setup_session_with_mock().await;
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let operation = ctx_mgr
        .message_operation_lock(&ctx_id, VirtualHandle(session), MessageOperation::Encrypt)
        .await
        .unwrap();
    operation.lock().await.shape = Some(MessageParameterShape::Gcm);
    let calls_before = mock.close_session_call_count();
    mock.set_next_message_lifecycle_action(MockMessageLifecycleAction::Panic);

    let response = close_session(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
        }),
    )
    .await;
    assert!(response.is_err(), "provider panic must be a transport error");
    assert_eq!(mock.close_session_call_count(), calls_before + 1);
    let state = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            (
                ctx.session_handles.resolve(VirtualHandle(session)),
                ctx.session_handles.suspended_backend(VirtualHandle(session)),
                ctx.message_operations
                    .keys()
                    .any(|(owned_session, _)| *owned_session == VirtualHandle(session)),
            )
        })
        .await
        .unwrap();
    assert_eq!(state.0, None, "panicked close must remain unresolvable");
    assert!(state.1.is_some(), "teardown must retain the quarantined backend handle");
    assert!(!state.2, "panicked close must clear message shapes");
}

#[tokio::test]
async fn timed_out_close_holds_context_in_flight_and_reaper_cannot_close_twice() {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::ZERO, 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;
    mock.set_close_session_delay(std::time::Duration::from_millis(80));
    let calls_before = mock.close_session_call_count();

    let rv = super::lifecycle::close_session_with_timeout(
        &ctx_mgr,
        &backend,
        Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
        }),
        Some(std::time::Duration::from_millis(5)),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(rv, CkRv::FUNCTION_FAILED.0, "handler timeout surfaces FUNCTION_FAILED (W1-L3-01)");

    let expired = ctx_mgr.evict_expired(&backend).await;
    assert!(
        expired.is_empty(),
        "the provider close closure must keep its context in flight after handler timeout",
    );

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if mock.close_session_call_count() == calls_before + 1
                && ctx_mgr
                    .get_context(&ctx_id, |ctx| {
                        ctx.session_handles.suspended_backend(VirtualHandle(session)).is_none()
                    })
                    .await
                    .unwrap_or(true)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the original close must settle");
    mock.clear_close_session_delay();
    assert_eq!(
        mock.close_session_call_count(),
        calls_before + 1,
        "provider C_CloseSession must be invoked exactly once",
    );
}

#[tokio::test]
async fn production_scoped_close_reuses_one_capped_context_guard() {
    use crate::server::grpc_service::service_utils::scope_context_operation;

    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::ZERO, 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;
    mock.set_close_session_delay(std::time::Duration::from_millis(80));
    let guard =
        ctx_mgr.begin_operation_capped(&ctx_id, 1).expect("under cap").expect("context exists");

    let rv = scope_context_operation(
        Some(guard),
        super::lifecycle::close_session_with_timeout(
            &ctx_mgr,
            &backend,
            Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
            }),
            Some(std::time::Duration::from_millis(5)),
        ),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(rv, CkRv::FUNCTION_FAILED.0, "handler timeout surfaces FUNCTION_FAILED (W1-L3-01)");
    assert_eq!(
        ctx_mgr
            .get_context(&ctx_id, |context| {
                context.in_flight.load(std::sync::atomic::Ordering::Relaxed)
            })
            .await,
        Some(1),
        "CloseSession must share the one admitted guard instead of consuming a second slot",
    );

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if ctx_mgr
                .get_context(&ctx_id, |context| {
                    context.in_flight.load(std::sync::atomic::Ordering::Relaxed)
                })
                .await
                == Some(0)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("provider completion must release the shared close guard");
    mock.clear_close_session_delay();
}

#[tokio::test]
async fn close_session_drops_mapping_for_every_terminal_already_gone_result() {
    // M3: a terminal result (backend says the session is already invalid) must
    // drop the stale mapping rather than leaving it to linger.
    for terminal_rv in [CkRv::SESSION_CLOSED, CkRv::SESSION_HANDLE_INVALID] {
        let (ctx_mgr, mock, ctx_id, session) = setup_session_with_mock().await;
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        mock.inject_close_error(terminal_rv);

        let rv = close_session(
            &HandlerContext::for_test(&ctx_mgr, &backend),
            Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
        assert_eq!(rv, terminal_rv.0);

        let gone = ctx_mgr
            .get_context(&ctx_id, |c| c.session_handles.resolve(VirtualHandle(session)))
            .await
            .flatten();
        assert!(gone.is_none(), "{terminal_rv:?} must drop the stale mapping");
    }
}

#[tokio::test]
async fn cross_client_login_while_slot_held_is_already_regardless_of_pin() {
    // D6(3): when a slot is held logged-in by another live context, the daemon
    // cannot PIN-verify a new login (the token would just answer ALREADY), so
    // the PIN is never evaluated: wrong and correct PINs alike get the
    // faithful USER_ALREADY_LOGGED_IN, and no logical login is minted either
    // way. (Supersedes the ADR-0008 verifier contract, which answered
    // PIN_INCORRECT/OK from a cached hash.)
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();
    let session_a = open_test_session(&ctx_mgr, &backend, &ctx_a).await;
    let session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;

    // ctx_a logs in with the correct PIN ("1234" per login_response).
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_a, session_a).await, CkRv::OK.0);

    // ctx_b attempts a login with a WRONG PIN.
    let wrong = login(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::LoginRequest {
            client_context_id: ctx_b.0.clone(),
            session_handle: session_b,
            user_type: CkUserType::User as u64,
            pin: Some(b"WRONG-PIN".to_vec()),
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(
        wrong,
        CkRv::USER_ALREADY_LOGGED_IN.0,
        "a held slot must answer ALREADY without evaluating the PIN"
    );

    // ctx_b with the CORRECT PIN gets the same faithful answer — no minting.
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_b, session_b).await,
        CkRv::USER_ALREADY_LOGGED_IN.0,
        "a held slot must answer ALREADY even for the correct PIN (no unverified logins)"
    );
    let b_login_state = ctx_mgr
        .get_context(&ctx_b, |ctx| {
            ctx.login_state.get(&crate::server::slot_map::BackendSlotId(CkSlotId(0))).copied()
        })
        .await
        .unwrap();
    assert_eq!(b_login_state, None, "no logical login may be minted while the slot is held");
}

#[tokio::test]
async fn login_reconciles_holderless_logged_in_backend() {
    // F-01: a holderless-but-logged-in backend (every best-effort
    // last-holder logout skipped or failed) must not brick slot logins: the
    // first login reconciles with one backend logout plus a single retry, so
    // the PIN verifies against a logged-out token. Pre-fix, the backend's
    // ALREADY was returned as-is with no state minted — every future login
    // on the slot bricked until daemon restart.
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;

    // The backend token is logged in behind the proxy's back: no logical
    // holder exists anywhere.
    let backend_session = ctx_mgr
        .get_context(&ctx_id, |ctx| ctx.session_handles.resolve(VirtualHandle(session)))
        .await
        .unwrap()
        .unwrap();
    mock.login(CkSessionHandle(backend_session.0), CkUserType::User, None).unwrap();
    assert!(
        !ctx_mgr.any_login_state_for_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))),
        "setup: no logical holder may exist"
    );

    // The proxy login reconciles and succeeds, minting the logical login.
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_id, session).await,
        CkRv::OK.0,
        "login must reconcile a holderless-but-logged-in backend"
    );
    let state = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            ctx.login_state.get(&crate::server::slot_map::BackendSlotId(CkSlotId(0))).copied()
        })
        .await
        .unwrap();
    assert_eq!(state, Some(LoginState::User), "reconciled login must mint logical state");
    // Exactly one retry: setup login + first attempt + reconcile retry.
    assert_eq!(mock.login_call_count(), 3, "reconcile must retry the backend login exactly once");
    // The backend is genuinely logged in again by the retried login.
    assert_eq!(
        mock.login(CkSessionHandle(backend_session.0), CkUserType::User, None).unwrap_err(),
        CkRv::USER_ALREADY_LOGGED_IN,
        "backend must be logged in after reconcile"
    );
}

// ---------------------------------------------------------------------------
// D6(1): object-path logical-login enforcement
// ---------------------------------------------------------------------------

/// A `CKA_PRIVATE=true` template attribute (proto encoding).
fn private_true_attr() -> pkcs11_proxy_ng_proto::Attribute {
    pkcs11_proxy_ng_proto::Attribute {
        attr_type: CkAttributeType::PRIVATE.0,
        value: Some(pkcs11_proxy_ng_proto::attribute::Value::BoolValue(true)),
    }
}

async fn create_object_outcome(
    ctx_mgr: &Arc<ContextManager>,
    backend: &Arc<dyn Pkcs11Backend>,
    ctx_id: &ClientContextId,
    session: u64,
    template: Vec<pkcs11_proxy_ng_proto::Attribute>,
) -> (u64, u64) {
    let resp = crate::server::grpc_service::object::create_object(
        &HandlerContext::for_test(ctx_mgr, backend),
        Request::new(pkcs11_proxy_ng_proto::CreateObjectRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            template,

            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    (resp.ck_rv, resp.object_handle)
}

async fn copy_object_outcome(
    ctx_mgr: &Arc<ContextManager>,
    backend: &Arc<dyn Pkcs11Backend>,
    ctx_id: &ClientContextId,
    session: u64,
    object: u64,
    template: Vec<pkcs11_proxy_ng_proto::Attribute>,
) -> (u64, u64) {
    let resp = crate::server::grpc_service::object::copy_object(
        &HandlerContext::for_test(ctx_mgr, backend),
        Request::new(pkcs11_proxy_ng_proto::CopyObjectRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            object_handle: object,
            template,

            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    (resp.ck_rv, resp.new_object_handle)
}

async fn sign_init_rv(
    ctx_mgr: &Arc<ContextManager>,
    backend: &Arc<dyn Pkcs11Backend>,
    ctx_id: &ClientContextId,
    session: u64,
    key: u64,
) -> u64 {
    crate::server::grpc_service::sign_verify::sign_init(
        &HandlerContext::for_test(ctx_mgr, backend),
        Request::new(pkcs11_proxy_ng_proto::SignInitRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                mechanism_type: CkMechanismType::RSA_PKCS.0,
                params: None,
            }),
            key_handle: key,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv
}

#[tokio::test]
async fn create_private_object_while_logged_out_is_refused_when_backend_held_logged_in() {
    // D6(1): the mock backend enforces NO login checks (like the kryoptic
    // backend held logged-in in F1), so without the proxy's logical-layer
    // refusal the private mint below would succeed.
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_holder = ctx_mgr.create_context(None).await.unwrap();
    let ctx_out = ctx_mgr.create_context(None).await.unwrap();
    let session_holder = open_test_session(&ctx_mgr, &backend, &ctx_holder).await;
    let session_out = open_test_session(&ctx_mgr, &backend, &ctx_out).await;

    // Holder logs in: the shared backend token is now logged in.
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_holder, session_holder).await, CkRv::OK.0);

    // Logged-out context minting a private object → refused.
    let (rv, handle) =
        create_object_outcome(&ctx_mgr, &backend, &ctx_out, session_out, vec![private_true_attr()])
            .await;
    assert_eq!(
        rv,
        CkRv::USER_NOT_LOGGED_IN.0,
        "private mint while logically logged out must be refused despite the logged-in backend"
    );
    assert_eq!(handle, 0);

    // Logged-out context minting a public object → fine.
    let (rv, handle) =
        create_object_outcome(&ctx_mgr, &backend, &ctx_out, session_out, vec![]).await;
    assert_eq!(rv, CkRv::OK.0, "public mint while logged out must still succeed");
    assert_ne!(handle, 0);

    // Logged-in holder minting a private object → fine.
    let (rv, handle) = create_object_outcome(
        &ctx_mgr,
        &backend,
        &ctx_holder,
        session_holder,
        vec![private_true_attr()],
    )
    .await;
    assert_eq!(rv, CkRv::OK.0, "private mint while logged in must still succeed");
    assert_ne!(handle, 0);
}

#[tokio::test]
async fn copy_object_to_private_after_logout_is_refused_kryoptic_shape() {
    // F1 repro shape (kryoptic `test_public_cannot_copy_to_private_object`):
    // C_Logout, then public-session C_CopyObject to CKA_PRIVATE=True. Under
    // the D6(3) contract the victim cannot hold a login while another tenant
    // does, so its logout is a no-op NOT_LOGGED_IN and the backend stays
    // logged in via the holder — exactly the window the F1 report observed
    // (logical-only logout, backend still logged in). The copy must be
    // refused; pre-fix it succeeded (direct/native: USER_NOT_LOGGED_IN).
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_holder = ctx_mgr.create_context(None).await.unwrap();
    let ctx_victim = ctx_mgr.create_context(None).await.unwrap();
    let session_holder = open_test_session(&ctx_mgr, &backend, &ctx_holder).await;
    let session_victim = open_test_session(&ctx_mgr, &backend, &ctx_victim).await;

    // Victim owns a public object; holder then logs the backend token in.
    let (rv, public_obj) =
        create_object_outcome(&ctx_mgr, &backend, &ctx_victim, session_victim, vec![]).await;
    assert_eq!(rv, CkRv::OK.0, "setup: public create must succeed");
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_holder, session_holder).await,
        CkRv::OK.0,
        "setup: holder login must succeed"
    );

    // Victim cannot log in (slot held) and its logout is a no-op.
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_victim, session_victim).await,
        CkRv::USER_ALREADY_LOGGED_IN.0
    );
    assert_eq!(
        logout_response(&ctx_mgr, &backend, &ctx_victim, session_victim).await,
        CkRv::USER_NOT_LOGGED_IN.0
    );

    // The kryoptic copy: public session, CKA_PRIVATE=True template → refused.
    let (rv, handle) = copy_object_outcome(
        &ctx_mgr,
        &backend,
        &ctx_victim,
        session_victim,
        public_obj,
        vec![private_true_attr()],
    )
    .await;
    assert_eq!(
        rv,
        CkRv::USER_NOT_LOGGED_IN.0,
        "copy to CKA_PRIVATE=True after logout must be refused (kryoptic F1 shape)"
    );
    assert_eq!(handle, 0);

    // Public-to-public copy while logged out → fine.
    let (rv, handle) =
        copy_object_outcome(&ctx_mgr, &backend, &ctx_victim, session_victim, public_obj, vec![])
            .await;
    assert_eq!(rv, CkRv::OK.0, "public copy while logged out must still succeed");
    assert_ne!(handle, 0);
}

#[tokio::test]
async fn private_object_use_after_logout_is_refused_while_backend_held_logged_in() {
    // Back-to-back tenants: B logs in, mints a private object, logs out (last
    // holder → real backend logout); H then logs in (backend logged in
    // again). B's handle to its private object must now be unusable — both
    // copy-from and crypto USE refuse with USER_NOT_LOGGED_IN. Pre-fix, the
    // logged-in backend accepted both.
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();
    let ctx_h = ctx_mgr.create_context(None).await.unwrap();
    let session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;
    let session_h = open_test_session(&ctx_mgr, &backend, &ctx_h).await;

    // B holds the login and mints a private key object.
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_b, session_b).await, CkRv::OK.0);
    let (rv, priv_key) =
        create_object_outcome(&ctx_mgr, &backend, &ctx_b, session_b, vec![private_true_attr()])
            .await;
    assert_eq!(rv, CkRv::OK.0, "setup: private mint while logged in must succeed");

    // While logged in, B can USE the key.
    assert_eq!(
        sign_init_rv(&ctx_mgr, &backend, &ctx_b, session_b, priv_key).await,
        CkRv::OK.0,
        "setup: key use while logged in must reach the backend"
    );

    // B logs out; H logs in (backend logged in again, B logically out).
    assert_eq!(logout_response(&ctx_mgr, &backend, &ctx_b, session_b).await, CkRv::OK.0);
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_h, session_h).await, CkRv::OK.0);

    // Copy FROM the private source while logged out → refused.
    let (rv, _) =
        copy_object_outcome(&ctx_mgr, &backend, &ctx_b, session_b, priv_key, vec![]).await;
    assert_eq!(
        rv,
        CkRv::USER_NOT_LOGGED_IN.0,
        "copy from a private source while logged out must be refused"
    );

    // Crypto USE of the private key while logged out → refused.
    assert_eq!(
        sign_init_rv(&ctx_mgr, &backend, &ctx_b, session_b, priv_key).await,
        CkRv::USER_NOT_LOGGED_IN.0,
        "private-key use while logged out must be refused despite the logged-in backend"
    );
}

#[tokio::test]
async fn generate_private_key_while_logged_out_is_refused() {
    // The create-family mint check covers key generation too: a logged-out
    // context must not generate a CKA_PRIVATE key through a held-logged-in
    // backend. (Refusal precedes the backend call, so the mock's mechanism
    // table is irrelevant on the refused path.)
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_holder = ctx_mgr.create_context(None).await.unwrap();
    let ctx_out = ctx_mgr.create_context(None).await.unwrap();
    let session_holder = open_test_session(&ctx_mgr, &backend, &ctx_holder).await;
    let session_out = open_test_session(&ctx_mgr, &backend, &ctx_out).await;
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_holder, session_holder).await,
        CkRv::OK.0,
        "setup: holder login must succeed"
    );

    let generate = |session: u64,
                    ctx_id: &ClientContextId,
                    template: Vec<pkcs11_proxy_ng_proto::Attribute>| {
        let (ctx_mgr, backend) = (ctx_mgr.clone(), backend.clone());
        let ctx_id = ctx_id.0.clone();
        async move {
            crate::server::grpc_service::key_ops::generate_key(
                &HandlerContext::for_test(&ctx_mgr, &backend),
                Request::new(pkcs11_proxy_ng_proto::GenerateKeyRequest {
                    client_context_id: ctx_id,
                    session_handle: session,
                    mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                        mechanism_type: CkMechanismType::AES_KEY_GEN.0,
                        params: None,
                    }),
                    template,

                    template_null: false,
                }),
            )
            .await
            .unwrap()
            .into_inner()
            .ck_rv
        }
    };

    assert_eq!(
        generate(session_out, &ctx_out, vec![private_true_attr()]).await,
        CkRv::USER_NOT_LOGGED_IN.0,
        "private GenerateKey while logged out must be refused"
    );
    // A public-template GenerateKey passes the enforcement (whatever the
    // backend then verdicts — the mock does not implement AES_KEY_GEN).
    assert_ne!(
        generate(session_out, &ctx_out, vec![]).await,
        CkRv::USER_NOT_LOGGED_IN.0,
        "public GenerateKey must pass the logical-login enforcement"
    );
}

/// HKDF-DERIVE proto mechanism carrying `salt_key` as the embedded salt key.
fn hkdf_derive_mechanism(salt_key: u64) -> pkcs11_proxy_ng_proto::Mechanism {
    pkcs11_proxy_ng_proto::Mechanism::try_from(&CkMechanism {
        mechanism_type: CkMechanismType::HKDF_DERIVE,
        params: Some(CkMechanismParams::Hkdf(HkdfParams {
            extract: true,
            expand: true,
            prf_hash_mechanism: CkMechanismType::SHA256,
            salt_type: cryptoki_sys::CKF_HKDF_SALT_KEY as u64,
            salt: Vec::new().into(),
            salt_key_handle: CkObjectHandle(salt_key),
            info: Vec::new().into(),
        })),
    })
    .unwrap()
}

async fn derive_key_rv(
    ctx_mgr: &Arc<ContextManager>,
    backend: &Arc<dyn Pkcs11Backend>,
    ctx_id: &ClientContextId,
    session: u64,
    base_key: u64,
    salt_key: u64,
) -> u64 {
    crate::server::grpc_service::key_ops::derive_key(
        &HandlerContext::for_test(ctx_mgr, backend),
        Request::new(pkcs11_proxy_ng_proto::DeriveKeyRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            mechanism: Some(hkdf_derive_mechanism(salt_key)),
            base_key_handle: base_key,
            template: vec![],
            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv
}

#[tokio::test]
async fn derive_with_private_embedded_key_while_logged_out_is_refused() {
    // F-02: D6(1) USE enforcement covers mechanism-embedded auxiliary
    // handles (the HKDF salt key here): a logged-out context must not USE a
    // private embedded key through a backend held logged-in by another
    // tenant. Pre-fix, embedded handles were remapped with no login check
    // and the derive reached the backend.
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_out = ctx_mgr.create_context(None).await.unwrap();
    let ctx_holder = ctx_mgr.create_context(None).await.unwrap();
    let session_out = open_test_session(&ctx_mgr, &backend, &ctx_out).await;
    let session_holder = open_test_session(&ctx_mgr, &backend, &ctx_holder).await;

    // ctx_out mints a public base key and a private salt key while logged in.
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_out, session_out).await, CkRv::OK.0);
    let (rv, base_key) =
        create_object_outcome(&ctx_mgr, &backend, &ctx_out, session_out, vec![]).await;
    assert_eq!(rv, CkRv::OK.0, "setup: public base key mint must succeed");
    let (rv, salt_key) =
        create_object_outcome(&ctx_mgr, &backend, &ctx_out, session_out, vec![private_true_attr()])
            .await;
    assert_eq!(rv, CkRv::OK.0, "setup: private salt key mint must succeed");
    let native_salt = ctx_mgr
        .get_context(&ctx_out, |ctx| ctx.object_handles.resolve(VirtualHandle(salt_key)))
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(logout_response(&ctx_mgr, &backend, &ctx_out, session_out).await, CkRv::OK.0);

    // The holder keeps the shared backend token logged in.
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_holder, session_holder).await,
        CkRv::OK.0,
        "setup: holder login must succeed"
    );

    // Logged-out derive USE-ing a private embedded salt key → refused, and
    // the backend is never reached.
    assert_eq!(
        derive_key_rv(&ctx_mgr, &backend, &ctx_out, session_out, base_key, salt_key).await,
        CkRv::USER_NOT_LOGGED_IN.0,
        "derive USE-ing a private embedded key while logged out must be refused"
    );
    assert_eq!(
        mock.mechanism_entry_count(MockMechanismEntry::DeriveKey),
        0,
        "refused derive must not reach the backend"
    );

    // Logged-in derive with the same keys → reaches the backend, salt remapped.
    assert_eq!(logout_response(&ctx_mgr, &backend, &ctx_holder, session_holder).await, CkRv::OK.0);
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_out, session_out).await, CkRv::OK.0);
    assert_ne!(
        derive_key_rv(&ctx_mgr, &backend, &ctx_out, session_out, base_key, salt_key).await,
        CkRv::USER_NOT_LOGGED_IN.0,
        "derive while logged in must pass the logical-login enforcement"
    );
    assert_eq!(
        mock.last_embedded_handles(MockMechanismEntry::DeriveKey),
        Some(MockEmbeddedHandles::HkdfSalt(native_salt)),
        "logged-in derive must reach the backend with the remapped salt handle"
    );
}

// ---------------------------------------------------------------------------
// D6(2)/D9-proxy: last-context-out backend logout + refcounted teardown
// ---------------------------------------------------------------------------

async fn finalize_rv(
    ctx_mgr: &Arc<ContextManager>,
    backend: &Arc<dyn Pkcs11Backend>,
    ctx_id: &ClientContextId,
) -> u64 {
    crate::server::grpc_service::general::finalize(
        &HandlerContext::for_test(ctx_mgr, backend),
        Request::new(pkcs11_proxy_ng_proto::FinalizeRequest {
            client_context_id: ctx_id.0.clone(),
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv
}

async fn close_session_rv(
    ctx_mgr: &Arc<ContextManager>,
    backend: &Arc<dyn Pkcs11Backend>,
    ctx_id: &ClientContextId,
    session: u64,
) -> u64 {
    close_session(
        &HandlerContext::for_test(ctx_mgr, backend),
        Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv
}

#[tokio::test]
async fn finalize_while_holding_login_releases_backend_login() {
    // D6(2): a context that tears down holding the last logical login must
    // release the shared backend login, so the next login PIN-verifies
    // against a logged-out token. Pre-fix, finalize closed sessions without
    // logging out: with another tenant's session keeping the token alive,
    // the backend stayed logged in and the next login got a spurious
    // USER_ALREADY_LOGGED_IN.
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();
    let session_a = open_test_session(&ctx_mgr, &backend, &ctx_a).await;
    // B holds a bare session so the backend token would stay logged in on a
    // logout-less teardown (no last-close auto-logout to mask the bug).
    let _session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;

    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_a, session_a).await, CkRv::OK.0);
    let backend_session_a = ctx_mgr
        .get_context(&ctx_a, |ctx| ctx.session_handles.resolve(VirtualHandle(session_a)))
        .await
        .unwrap()
        .unwrap()
        .0;

    // A finalizes WITHOUT logging out.
    assert_eq!(finalize_rv(&ctx_mgr, &backend, &ctx_a).await, CkRv::OK.0);

    // A's backend session is reaped...
    assert_eq!(
        backend.get_session_info(CkSessionHandle(backend_session_a)).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID,
        "departed context's backend session must be closed"
    );
    // ...and the backend login is released: a fresh login succeeds.
    let ctx_h = ctx_mgr.create_context(None).await.unwrap();
    let session_h = open_test_session(&ctx_mgr, &backend, &ctx_h).await;
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_h, session_h).await,
        CkRv::OK.0,
        "last-context-out teardown must release the backend login"
    );
}

#[tokio::test]
async fn close_last_session_while_holding_login_releases_backend_login() {
    // D6(2) via session close: closing the last session drops the context's
    // logical login (existing semantics); last-context-out must then release
    // the backend login too. B's bare session again blocks last-close
    // auto-logout so the test discriminates the fix.
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();
    let session_a = open_test_session(&ctx_mgr, &backend, &ctx_a).await;
    let _session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;

    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_a, session_a).await, CkRv::OK.0);
    assert_eq!(close_session_rv(&ctx_mgr, &backend, &ctx_a, session_a).await, CkRv::OK.0);

    let ctx_h = ctx_mgr.create_context(None).await.unwrap();
    let session_h = open_test_session(&ctx_mgr, &backend, &ctx_h).await;
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_h, session_h).await,
        CkRv::OK.0,
        "closing the last logged-in session must release the backend login"
    );
}

#[tokio::test]
async fn close_session_without_login_does_not_release_backend_login() {
    // Guard against over-eager logout: closing a session that holds no login
    // must leave another tenant's backend login undisturbed.
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();
    let session_a = open_test_session(&ctx_mgr, &backend, &ctx_a).await;
    let session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;

    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_a, session_a).await, CkRv::OK.0);
    assert_eq!(close_session_rv(&ctx_mgr, &backend, &ctx_b, session_b).await, CkRv::OK.0);

    let backend_session_a = ctx_mgr
        .get_context(&ctx_a, |ctx| ctx.session_handles.resolve(VirtualHandle(session_a)))
        .await
        .unwrap()
        .unwrap()
        .0;
    let info = backend.get_session_info(CkSessionHandle(backend_session_a)).unwrap();
    assert_eq!(
        info.state,
        CkSessionState::RwUser,
        "closing a logged-out session must not disturb the holder's backend login"
    );
}

#[tokio::test]
async fn evict_expired_context_holding_login_releases_backend_login() {
    // D9 lease-expiry path through the same shared teardown: an expired
    // context holding the last login releases the backend login on reap.
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_millis(20), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let session_a = open_test_session(&ctx_mgr, &backend, &ctx_a).await;
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_a, session_a).await, CkRv::OK.0);

    // Let A expire, then create B fresh (B stays live: its session blocks
    // last-close auto-logout so the test discriminates the fix).
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();
    let _session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;

    let evicted = ctx_mgr.evict_expired(&backend).await;
    assert!(evicted.contains(&ctx_a), "the expired holder must be reaped");
    assert!(!evicted.contains(&ctx_b), "the fresh context must survive");

    let ctx_h = ctx_mgr.create_context(None).await.unwrap();
    let session_h = open_test_session(&ctx_mgr, &backend, &ctx_h).await;
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_h, session_h).await,
        CkRv::OK.0,
        "reaping an expired holder must release the backend login"
    );
}

#[tokio::test]
async fn teardown_of_one_tenant_does_not_disturb_other_tenant() {
    // D9 two-tenant test: A holds the slot login; B lives beside it with a
    // session and objects but no login. A departs via finalize. B must
    // observe no state change: its context, sessions, and objects stay
    // intact, its backend sessions stay open, and it can take over the
    // released backend login and keep operating. Pre-fix, the backend login
    // leaked (B's fresh login got ALREADY).
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();
    let session_a = open_test_session(&ctx_mgr, &backend, &ctx_a).await;
    let session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;

    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_a, session_a).await, CkRv::OK.0);
    let (rv, object_b) = create_object_outcome(&ctx_mgr, &backend, &ctx_b, session_b, vec![]).await;
    assert_eq!(rv, CkRv::OK.0, "setup: B's public create must succeed");
    let backend_session_a = ctx_mgr
        .get_context(&ctx_a, |ctx| ctx.session_handles.resolve(VirtualHandle(session_a)))
        .await
        .unwrap()
        .unwrap()
        .0;
    let backend_session_b = ctx_mgr
        .get_context(&ctx_b, |ctx| ctx.session_handles.resolve(VirtualHandle(session_b)))
        .await
        .unwrap()
        .unwrap()
        .0;

    // A departs holding the login.
    assert_eq!(finalize_rv(&ctx_mgr, &backend, &ctx_a).await, CkRv::OK.0);

    // A's backend session is reaped; B's stays open and usable.
    assert_eq!(
        backend.get_session_info(CkSessionHandle(backend_session_a)).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID,
        "departed tenant's backend session must be closed"
    );
    backend
        .get_session_info(CkSessionHandle(backend_session_b))
        .expect("surviving tenant's backend session must stay open");
    // B's logical state is untouched.
    let b_intact = ctx_mgr
        .get_context(&ctx_b, |ctx| {
            ctx.session_handles.resolve(VirtualHandle(session_b)).is_some()
                && ctx.object_handles.resolve(VirtualHandle(object_b)).is_some()
        })
        .await
        .unwrap();
    assert!(b_intact, "surviving tenant's sessions and objects must stay mapped");
    // And B takes over the released backend login and keeps operating.
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_b, session_b).await,
        CkRv::OK.0,
        "surviving tenant must be able to log in after the holder departs"
    );
    let (rv, _) = create_object_outcome(&ctx_mgr, &backend, &ctx_b, session_b, vec![]).await;
    assert_eq!(rv, CkRv::OK.0, "surviving tenant must keep operating");
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_first_login_serializes_to_one_backend_login() {
    // M5: two clients racing the FIRST login on the same shared token must not
    // both take the real-login path. Per-slot login serialization makes the
    // first do the real C_Login and the second — after blocking on the lock and
    // seeing A's state — take the faithful-ALREADY path (D6(3)): exactly one
    // backend C_Login.
    //
    // Deterministic harness: a login gate holds client A inside the backend
    // C_Login (still holding the per-slot lock) while client B starts, so B is
    // guaranteed to race. Without the lock, B would scan "no other login" before
    // A inserts its state and issue a SECOND backend login (count == 2); with it,
    // B blocks on the lock, then sees A's state and answers ALREADY faithfully.
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();
    let session_a = open_test_session(&ctx_mgr, &backend, &ctx_a).await;
    let session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;

    // Gate: each real backend login signals `entered`, then blocks on `proceed`.
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let proceed = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    mock.set_login_gate(entered_tx, proceed.clone());

    let login_req = |ctx: &ClientContextId, session: u64| {
        Request::new(pkcs11_proxy_ng_proto::LoginRequest {
            client_context_id: ctx.0.clone(),
            session_handle: session,
            user_type: CkUserType::User as u64,
            pin: Some(b"1234".to_vec()), // the MockBackend default PIN
        })
    };

    // Client A starts and blocks inside the real backend C_Login holding the lock.
    let a = {
        let (ctx_mgr, backend, req) =
            (ctx_mgr.clone(), backend.clone(), login_req(&ctx_a, session_a));
        tokio::spawn(async move {
            login(&HandlerContext::for_test(&ctx_mgr, &backend), req)
                .await
                .unwrap()
                .into_inner()
                .ck_rv
        })
    };
    // Wait (off the executor) until A is actually inside the backend login.
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap()).await.unwrap();

    // Client B now races: with serialization it must block on the per-slot lock.
    let b = {
        let (ctx_mgr, backend, req) =
            (ctx_mgr.clone(), backend.clone(), login_req(&ctx_b, session_b));
        tokio::spawn(async move {
            login(&HandlerContext::for_test(&ctx_mgr, &backend), req)
                .await
                .unwrap()
                .into_inner()
                .ck_rv
        })
    };

    // Release A; it finishes the real login, records its login state, and drops
    // the lock; B then sees A's login state and answers ALREADY faithfully.
    {
        let (lock, cv) = &*proceed;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }

    let rv_a = a.await.unwrap();
    let rv_b = b.await.unwrap();

    assert_eq!(rv_a, CkRv::OK.0, "the first login should succeed");
    assert_eq!(
        rv_b,
        CkRv::USER_ALREADY_LOGGED_IN.0,
        "the raced second login must be a faithful ALREADY (D6(3)), not a minted login"
    );
    assert_eq!(
        mock.login_call_count(),
        1,
        "per-slot serialization must yield exactly one real backend C_Login"
    );
}

// ---------------------------------------------------------------------------
// W1-L6-25: resolve-vs-close race — resolve under the slot lock, close takes
// the login lock. A login that resolves its backend session before acquiring
// the per-slot lock races a concurrent close: the close suspends/removes the
// mapping, and the login then drives the backend with a stale handle and/or
// mints LoginState for an untracked session.
// ---------------------------------------------------------------------------

/// W1-L6-25 leg 1: a close racing an in-flight backend login must serialize
/// behind the per-slot login lock — it must NOT steal the session out from
/// under the gated login.
///
/// Deterministic harness: gate client A's backend C_Login (A holds the slot
/// lock inside the call), then race a close of the same session. Post-fix the
/// close pends on the lock until the login finishes (login OK, close OK);
/// pre-fix the close sails through (it takes no lock), the backend session is
/// gone when the gate opens, and the stale backend login fails.
#[tokio::test(flavor = "multi_thread")]
async fn w1_l6_25_close_waits_for_inflight_login() {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let proceed = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    mock.set_login_gate(entered_tx, proceed.clone());

    let login_task = {
        let (ctx_mgr, backend, ctx_id) = (ctx_mgr.clone(), backend.clone(), ctx_id.clone());
        tokio::spawn(async move {
            login(
                &HandlerContext::for_test(&ctx_mgr, &backend),
                Request::new(pkcs11_proxy_ng_proto::LoginRequest {
                    client_context_id: ctx_id.0.clone(),
                    session_handle: session,
                    user_type: CkUserType::User as u64,
                    pin: Some(b"1234".to_vec()),
                }),
            )
            .await
            .unwrap()
            .into_inner()
            .ck_rv
        })
    };
    // Wait (off the executor) until the login is inside the backend call,
    // holding the per-slot lock.
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap()).await.unwrap();

    // Close races the gated login. The gate being closed pins the login inside
    // the backend call (holding the slot lock) until the test opens it below;
    // the sleep lets a lock-ignoring (pre-fix) close run to completion first
    // so the stale-handle outcome is deterministic. Post-fix the close pends
    // on the slot lock regardless of this sleep.
    let close_task = {
        let (ctx_mgr, backend, ctx_id) = (ctx_mgr.clone(), backend.clone(), ctx_id.clone());
        tokio::spawn(async move {
            close_session(
                &HandlerContext::for_test(&ctx_mgr, &backend),
                Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
                    client_context_id: ctx_id.0.clone(),
                    session_handle: session,
                }),
            )
            .await
            .unwrap()
            .into_inner()
            .ck_rv
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    {
        let (lock, cv) = &*proceed;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }

    let (rv_login, rv_close) = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        (login_task.await.unwrap(), close_task.await.unwrap())
    })
    .await
    .expect("login+close must not deadlock on the slot lock");

    assert_eq!(
        rv_login,
        CkRv::OK.0,
        "login gated inside the backend call must succeed once close serializes behind it \
         (pre-fix: close stole the session mid-login, stale backend login failed)"
    );
    assert_eq!(rv_close, CkRv::OK.0, "close must succeed after the login releases the lock");
    assert_eq!(mock.login_call_count(), 1, "exactly one backend C_Login");
    // End state: session closed, and closing the last session cleared the
    // minted login state (no mint lingering for an untracked session).
    let held = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            ctx.login_state.contains_key(&crate::server::slot_map::BackendSlotId(CkSlotId(0)))
        })
        .await
        .unwrap();
    assert!(!held, "no login state may linger after the last session closed");
}

/// W1-L6-25 leg 2: a login that loses the race (session closed between its
/// pre-resolve and slot-lock acquisition) must fail cleanly with
/// SESSION_HANDLE_INVALID WITHOUT issuing a backend login on the dead
/// handle — the post-lock re-resolve catches it.
///
/// Deterministic harness modulo one generous scheduling sleep: the test holds
/// the slot lock, spawns the login (it pre-resolves, then pends on the held
/// lock), then races a close. Pre-fix the close ignores the held lock and
/// completes, and the login proceeds with its stale pre-resolve (backend call
/// on the closed handle). Post-fix both pend; whoever wins the lock after the
/// release, the loser observes the winner — never a stale handle.
#[tokio::test(flavor = "multi_thread")]
async fn w1_l6_25_login_short_circuits_when_close_won() {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
    ctx_mgr.register_slot(slot).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;

    // Hold the slot lock so the login is guaranteed to be parked between its
    // pre-resolve and its locked section while the close runs.
    let slot_lock = ctx_mgr.slot_login_lock(slot);
    let guard = slot_lock.lock().await;
    let login_task = {
        let (ctx_mgr, backend, ctx_id) = (ctx_mgr.clone(), backend.clone(), ctx_id.clone());
        tokio::spawn(async move {
            login(
                &HandlerContext::for_test(&ctx_mgr, &backend),
                Request::new(pkcs11_proxy_ng_proto::LoginRequest {
                    client_context_id: ctx_id.0.clone(),
                    session_handle: session,
                    user_type: CkUserType::User as u64,
                    pin: Some(b"1234".to_vec()),
                }),
            )
            .await
            .unwrap()
            .into_inner()
            .ck_rv
        })
    };
    // One-sided scheduling margin: the login only needs a DashMap pre-resolve
    // plus a mutex pend. If this margin ever proves too short on a loaded box,
    // the pre-fix run passes spuriously (close first, clean pre-resolve miss)
    // — the post-fix invariants below hold regardless of order.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let close_task = {
        let (ctx_mgr, backend, ctx_id) = (ctx_mgr.clone(), backend.clone(), ctx_id.clone());
        tokio::spawn(async move {
            close_session(
                &HandlerContext::for_test(&ctx_mgr, &backend),
                Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
                    client_context_id: ctx_id.0.clone(),
                    session_handle: session,
                }),
            )
            .await
            .unwrap()
            .into_inner()
            .ck_rv
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(guard);

    let (rv_login, rv_close) = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        (login_task.await.unwrap(), close_task.await.unwrap())
    })
    .await
    .expect("login+close must not deadlock on the slot lock");

    assert_eq!(rv_close, CkRv::OK.0, "close of the live session must succeed");
    assert!(
        rv_login == CkRv::OK.0 || rv_login == CkRv::SESSION_HANDLE_INVALID.0,
        "login must either win cleanly (OK) or short-circuit (SESSION_HANDLE_INVALID), got {rv_login:#x}"
    );
    // The crux: a short-circuited login must never have reached the backend.
    // Pre-fix the close won during the hold and the login still issued its
    // stale backend login (count == 1 with SESSION_HANDLE_INVALID).
    assert_eq!(
        mock.login_call_count(),
        usize::from(rv_login == CkRv::OK.0),
        "short-circuited login must not issue a backend login on a dead handle"
    );
}

/// W1-L6-25 leg 3 (post-call generation verify): lock-free mapping removers
/// (close-all, eviction) can drop the session mapping while the backend login
/// is in flight. The proxy must then mint NO LoginState for the untracked
/// handle and report SESSION_HANDLE_INVALID.
///
/// Deterministic harness: gate the backend login, remove ONLY the proxy-side
/// mapping (the backend session stays open so the backend call succeeds —
/// exactly the close-all remove-then-close window), open the gate.
#[tokio::test(flavor = "multi_thread")]
async fn w1_l6_25_login_mints_nothing_when_mapping_vanishes_mid_call() {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
    ctx_mgr.register_slot(slot).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let proceed = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    mock.set_login_gate(entered_tx, proceed.clone());

    let login_task = {
        let (ctx_mgr, backend, ctx_id) = (ctx_mgr.clone(), backend.clone(), ctx_id.clone());
        tokio::spawn(async move {
            login(
                &HandlerContext::for_test(&ctx_mgr, &backend),
                Request::new(pkcs11_proxy_ng_proto::LoginRequest {
                    client_context_id: ctx_id.0.clone(),
                    session_handle: session,
                    user_type: CkUserType::User as u64,
                    pin: Some(b"1234".to_vec()),
                }),
            )
            .await
            .unwrap()
            .into_inner()
            .ck_rv
        })
    };
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap()).await.unwrap();

    // Drop the proxy mapping while the backend call is in flight. The backend
    // session itself stays open, so the backend login will succeed.
    ctx_mgr.get_context(&ctx_id, |ctx| ctx.remove_session(VirtualHandle(session))).await.unwrap();
    {
        let (lock, cv) = &*proceed;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }

    let rv_login = tokio::time::timeout(std::time::Duration::from_secs(30), login_task)
        .await
        .expect("gated login must finish")
        .unwrap();

    assert_eq!(
        mock.login_call_count(),
        1,
        "backend must have been reached (else this exercises the pre-call path, not the post-call verify)"
    );
    assert_eq!(
        rv_login,
        CkRv::SESSION_HANDLE_INVALID.0,
        "mapping vanished mid-call → no mint (pre-fix: OK with LoginState minted for an unmapped session)"
    );
    let held =
        ctx_mgr.get_context(&ctx_id, |ctx| ctx.login_state.contains_key(&slot)).await.unwrap();
    assert!(!held, "no login state may be minted for an untracked session");
}

/// W1-L6-25 acceptance hammer: resolve racing close on every iteration. Each
/// iteration opens a fresh session, races a login against its close, and
/// asserts the race end-state invariants: close always wins-or-loses cleanly,
/// a short-circuited login never reached the backend, and nothing deadlocks.
#[tokio::test(flavor = "multi_thread")]
async fn w1_l6_25_login_close_hammer_never_uses_stale_handle() {
    const ITERS: usize = 50;

    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();

    for i in 0..ITERS {
        let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;
        let calls_before = mock.login_call_count();

        let login_task = {
            let (ctx_mgr, backend, ctx_id) = (ctx_mgr.clone(), backend.clone(), ctx_id.clone());
            tokio::spawn(async move {
                login(
                    &HandlerContext::for_test(&ctx_mgr, &backend),
                    Request::new(pkcs11_proxy_ng_proto::LoginRequest {
                        client_context_id: ctx_id.0.clone(),
                        session_handle: session,
                        user_type: CkUserType::User as u64,
                        pin: Some(b"1234".to_vec()),
                    }),
                )
                .await
                .unwrap()
                .into_inner()
                .ck_rv
            })
        };
        let close_task = {
            let (ctx_mgr, backend, ctx_id) = (ctx_mgr.clone(), backend.clone(), ctx_id.clone());
            tokio::spawn(async move {
                close_session(
                    &HandlerContext::for_test(&ctx_mgr, &backend),
                    Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
                        client_context_id: ctx_id.0.clone(),
                        session_handle: session,
                    }),
                )
                .await
                .unwrap()
                .into_inner()
                .ck_rv
            })
        };

        let (rv_login, rv_close) =
            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                (login_task.await.unwrap(), close_task.await.unwrap())
            })
            .await
            .unwrap_or_else(|_| panic!("iter {i}: login+close deadlocked on the slot lock"));

        assert_eq!(rv_close, CkRv::OK.0, "iter {i}: close of the live session must succeed");
        assert!(
            rv_login == CkRv::OK.0 || rv_login == CkRv::SESSION_HANDLE_INVALID.0,
            "iter {i}: login must be OK or SESSION_HANDLE_INVALID, got {rv_login:#x}"
        );
        let delta = mock.login_call_count() - calls_before;
        if rv_login == CkRv::OK.0 {
            // F-01 reconcile may legally retry the backend login once, so OK
            // implies >= 1 backend call, never exactly 1.
            assert!(delta >= 1, "iter {i}: successful login must have reached the backend");
        } else {
            assert_eq!(
                delta, 0,
                "iter {i}: short-circuited login must not issue a backend login on a dead handle"
            );
        }
    }
}

/// W1-L6-25 leg 5a (review I-1): the `login_user` re-resolve is a line-for-line
/// mirror of the `login` one — pin it with the same resolve-vs-close race.
/// Mirrors leg 2 exactly: the test holds the slot lock, spawns the login_user
/// (it pre-resolves, then pends on the held lock), then races a close. A
/// short-circuited login_user must fail with SESSION_HANDLE_INVALID WITHOUT
/// issuing a backend login on the dead handle.
#[tokio::test(flavor = "multi_thread")]
async fn w1_l6_25_login_user_short_circuits_when_close_won() {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
    ctx_mgr.register_slot(slot).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;

    // Hold the slot lock; spawn the close FIRST so it queues on the mutex
    // ahead of the login_user — after the release the close suspends first and
    // the login_user must observe the suspension via its re-resolve. (The
    // post-fix invariants below hold in either order; close-first is what
    // makes a reverted re-resolve fail deterministically.)
    let slot_lock = ctx_mgr.slot_login_lock(slot);
    let guard = slot_lock.lock().await;
    let close_task = {
        let (ctx_mgr, backend, ctx_id) = (ctx_mgr.clone(), backend.clone(), ctx_id.clone());
        tokio::spawn(async move {
            close_session(
                &HandlerContext::for_test(&ctx_mgr, &backend),
                Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
                    client_context_id: ctx_id.0.clone(),
                    session_handle: session,
                }),
            )
            .await
            .unwrap()
            .into_inner()
            .ck_rv
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let login_task = {
        let (ctx_mgr, backend, ctx_id) = (ctx_mgr.clone(), backend.clone(), ctx_id.clone());
        tokio::spawn(async move {
            crate::server::grpc_service::session_3x::login_user(
                &HandlerContext::for_test(&ctx_mgr, &backend),
                Request::new(pkcs11_proxy_ng_proto::LoginUserRequest {
                    client_context_id: ctx_id.0.clone(),
                    session_handle: session,
                    user_type: CkUserType::User as u64,
                    pin: Some(b"1234".to_vec()),
                    username: Some(b"operator-7".to_vec()),
                }),
            )
            .await
            .unwrap()
            .into_inner()
            .ck_rv
        })
    };
    // One-sided scheduling margin, same as leg 2: the login_user only needs a
    // DashMap pre-resolve plus a mutex pend before the release below.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    drop(guard);

    let (rv_login, rv_close) = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        (login_task.await.unwrap(), close_task.await.unwrap())
    })
    .await
    .expect("login_user+close must not deadlock on the slot lock");

    assert_eq!(rv_close, CkRv::OK.0, "close of the live session must succeed");
    assert!(
        rv_login == CkRv::OK.0 || rv_login == CkRv::SESSION_HANDLE_INVALID.0,
        "login_user must either win cleanly (OK) or short-circuit (SESSION_HANDLE_INVALID), got {rv_login:#x}"
    );
    // The crux: a short-circuited login_user must never have reached the
    // backend. (Mock login_user keeps no login state, so no F-01 retry can
    // inflate the OK-side count — exactly 1.)
    assert_eq!(
        mock.login_user_call_count(),
        usize::from(rv_login == CkRv::OK.0),
        "short-circuited login_user must not issue a backend login on a dead handle"
    );
}

/// W1-L6-25 leg 5b (review I-1): the `logout` re-resolve is the same mirror —
/// a logout that loses the race must short-circuit WITHOUT issuing a backend
/// logout.
///
/// Deterministic harness modulo one generous scheduling sleep (same one-sided
/// shape as leg 2): log in, hold the slot lock, spawn the logout (it
/// pre-resolves, then pends on the held lock), then drop ONLY the proxy-side
/// mapping — the backend session stays open and the mock token stays logged
/// in, so any backend logout the proxy issued would succeed and log the token
/// out. Post-fix the logout short-circuits (SESSION_HANDLE_INVALID) and the
/// mock token is provably still logged in; with the re-resolve reverted the
/// stale backend logout succeeds (OK) and logs the token out.
#[tokio::test(flavor = "multi_thread")]
async fn w1_l6_25_logout_short_circuits_without_backend_call() {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
    ctx_mgr.register_slot(slot).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_id, session).await,
        CkRv::OK.0,
        "setup: login must succeed"
    );

    let slot_lock = ctx_mgr.slot_login_lock(slot);
    let guard = slot_lock.lock().await;
    let logout_task = {
        let (ctx_mgr, backend, ctx_id) = (ctx_mgr.clone(), backend.clone(), ctx_id.clone());
        tokio::spawn(async move {
            logout(
                &HandlerContext::for_test(&ctx_mgr, &backend),
                Request::new(pkcs11_proxy_ng_proto::LogoutRequest {
                    client_context_id: ctx_id.0.clone(),
                    session_handle: session,
                }),
            )
            .await
            .unwrap()
            .into_inner()
            .ck_rv
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Drop the proxy mapping while the logout is parked on the held lock. The
    // backend session itself stays open and the mock token stays logged in.
    ctx_mgr.get_context(&ctx_id, |ctx| ctx.remove_session(VirtualHandle(session))).await.unwrap();
    drop(guard);

    let rv_logout = tokio::time::timeout(std::time::Duration::from_secs(30), logout_task)
        .await
        .expect("logout must not deadlock on the slot lock")
        .unwrap();

    assert_eq!(
        rv_logout,
        CkRv::SESSION_HANDLE_INVALID.0,
        "mapping vanished mid-logout → short-circuit (reverted: stale backend logout succeeds with OK)"
    );
    // Backend proof that no C_Logout was issued: the mock token is still
    // logged in — a fresh backend session observes USER_ALREADY_LOGGED_IN.
    let probe = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(
        mock.login(probe, CkUserType::User, None),
        Err(CkRv::USER_ALREADY_LOGGED_IN),
        "mock token must still be logged in (no backend logout may have been issued)"
    );
}

// ---------------------------------------------------------------------------
// G1-PR2: Audit emission integration tests
// ---------------------------------------------------------------------------

/// Build a `HandlerContext` with a live audit sink pointing at `dir`.
async fn make_audited_ctx(
    ctx_mgr: &Arc<ContextManager>,
    backend: &Arc<dyn Pkcs11Backend>,
    dir: &std::path::Path,
) -> (HandlerContext, crate::server::audit::AuditSink) {
    let cfg = crate::config::AuditConfig {
        dir: Some(dir.to_owned()),
        rotate_max_bytes: 1 << 20,
        rotate_keep_files: 10,
        ..Default::default()
    };
    let sink =
        crate::server::audit::spawn_audit_sink(&cfg).unwrap().expect("audit sink must spawn");
    let mut ctx = HandlerContext::for_test(ctx_mgr, backend);
    ctx.audit = Some(sink.clone());
    (ctx, sink)
}

/// Returns a path inside the system temp dir that is unique per test process + tag.
fn test_audit_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("pkcs11-proxy-audit-{}-{}", std::process::id(), tag))
}

/// G1-PR2 primary: login then logout produces two audit records with the
/// correct method names and ck_rv, the chain verifies, and the test PIN is
/// absent from every byte of every audit file.
#[tokio::test]
async fn audit_login_logout_records_chain_ok_and_no_pin() {
    let dir = test_audit_dir("login-logout");
    let _ = std::fs::remove_dir_all(&dir);

    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;

    let (ctx, sink) = make_audited_ctx(&ctx_mgr, &backend, &dir).await;

    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session_handle = open_test_session(&ctx_mgr, &backend, &ctx_id).await;

    // Use a distinctive PIN string so the grep below is a strong assertion.
    let test_pin = b"G1PR2-AuditTestPin-SENSITIVE!".to_vec();

    let login_rv = login(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::LoginRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            user_type: CkUserType::User as u64,
            pin: Some(test_pin.clone()),
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(login_rv, CkRv::OK.0, "login must succeed");

    let logout_rv = logout(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::LogoutRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(logout_rv, CkRv::OK.0, "logout must succeed");

    // Flush: ensures all records are durably written before we read the files.
    sink.flush().await.unwrap();

    // Verify the hash chain.
    let report = pkcs11_proxy_ng_audit::verify::verify_dir(&dir, None).unwrap();
    assert!(report.chain_ok, "audit chain must be valid after login+logout: {report:?}");
    assert!(report.records >= 2, "must have at least 2 audit records, got {}", report.records);
    assert!(report.gaps.is_empty(), "no sequence gaps: {:?}", report.gaps);

    // Verify the record content (method names and ck_rv).
    let jsonl = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(jsonl.contains("\"C_Login\""), "C_Login method must appear in audit file");
    assert!(jsonl.contains("\"C_Logout\""), "C_Logout method must appear in audit file");
    let records: Vec<serde_json::Value> =
        jsonl.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    for method in ["C_Login", "C_Logout"] {
        let record = records.iter().find(|record| record["method"] == method).unwrap();
        assert_eq!(record["slot"].as_u64(), Some(1), "audit slots remain virtual, not backend 0");
    }
    // ck_rv 0 == CKR_OK
    assert!(jsonl.contains("\"ck_rv\":0"), "successful operations must record ck_rv 0");

    // PIN-safety: the raw PIN bytes must not appear anywhere in the audit files.
    let pin_str = std::str::from_utf8(&test_pin).unwrap();
    let all_files_content = {
        let mut s = String::new();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
                s.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
            }
        }
        s
    };
    assert!(
        !all_files_content.contains(pin_str),
        "PIN MUST NOT appear in any audit JSONL file (PIN safety violation!)"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// G1-PR2 audit-off: when `ctx.audit` is `None` (no `[audit]` config),
/// the operation behaves byte-identically to pre-audit code.
#[tokio::test]
async fn audit_off_login_logout_byte_identical() {
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;

    // No audit sink: for_test leaves ctx.audit = None.
    let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session_handle = open_test_session(&ctx_mgr, &backend, &ctx_id).await;

    let login_rv = login(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::LoginRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            user_type: CkUserType::User as u64,
            pin: Some(b"1234".to_vec()),
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(login_rv, CkRv::OK.0, "login must succeed with audit off");

    let logout_rv = logout(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::LogoutRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(logout_rv, CkRv::OK.0, "logout must succeed with audit off");
}

// ---------------------------------------------------------------------------
// G1-PR3: key-lifecycle audit emission tests
// ---------------------------------------------------------------------------

/// G1-PR3: `C_GenerateKey` emits a `KeyMgmt` audit record with the
/// operation's `ck_rv` and a valid hash chain.  Uses a MockBackend configured
/// with `AES_KEY_GEN` (not in `default_test`) so the backend call succeeds.
#[tokio::test]
async fn audit_generate_key_emits_key_mgmt_record() {
    let dir = test_audit_dir("generate-key");
    let _ = std::fs::remove_dir_all(&dir);

    // Build a backend that advertises AES_KEY_GEN.
    let mock = pkcs11_proxy_ng_backend::MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::AES_KEY_GEN],
    );
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;

    let (ctx, sink) = make_audited_ctx(&ctx_mgr, &backend, &dir).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session_handle = open_test_session(&ctx_mgr, &backend, &ctx_id).await;

    use crate::server::grpc_service::key_ops::generate_key;
    let gen_rv = generate_key(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::GenerateKeyRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                mechanism_type: CkMechanismType::AES_KEY_GEN.0,
                params: None,
            }),
            template: vec![],

            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(gen_rv, CkRv::OK.0, "generate_key must succeed");

    sink.flush().await.unwrap();

    let report = pkcs11_proxy_ng_audit::verify::verify_dir(&dir, None).unwrap();
    assert!(report.chain_ok, "audit chain must be valid after C_GenerateKey: {report:?}");
    assert!(report.records >= 1, "must have at least one audit record, got {}", report.records);
    assert!(report.gaps.is_empty(), "no sequence gaps: {:?}", report.gaps);

    let jsonl = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert!(jsonl.contains("\"C_GenerateKey\""), "C_GenerateKey must appear in audit JSONL");
    assert!(jsonl.contains("\"ck_rv\":0"), "successful keygen must record ck_rv 0");

    std::fs::remove_dir_all(&dir).ok();
}

/// Fail-closed-after-side-effect (ADR-0012): with a saturated audit sink, a
/// `KeyMgmt` op that already committed on the backend must still report
/// `CKR_FUNCTION_FAILED` with zeroed outputs rather than confirm an unaudited
/// security action. Setup mirrors `audit_generate_key_emits_key_mgmt_record`;
/// the saturated sink mirrors `sign_fail_open_saturated_sink`.
#[tokio::test]
async fn fail_closed_generate_key_saturated_sink_reports_function_failed() {
    // Build a backend that advertises AES_KEY_GEN so the op commits.
    let mock = pkcs11_proxy_ng_backend::MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::AES_KEY_GEN],
    );
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;

    // Saturated sink: every fail-closed emit is rejected immediately.
    let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
    ctx.audit = Some(crate::server::audit::AuditSink::new_saturated_for_test());

    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session_handle = open_test_session(&ctx_mgr, &backend, &ctx_id).await;

    // Resolve the backend session so the committed side effect is observed
    // directly on the backend, independent of the (zeroed) handler response.
    let backend_session = ctx_mgr
        .get_context(&ctx_id, |ctx| ctx.session_handles.resolve(VirtualHandle(session_handle)))
        .await
        .unwrap()
        .unwrap();
    let backend_session = CkSessionHandle(backend_session.0 as u64);

    // Negative control: a fresh MockBackend allocates object handles from 1
    // and setup creates no objects, so handle 1 must be invalid before the call.
    let generated = CkObjectHandle(1);
    assert_eq!(
        backend.get_object_size(backend_session, generated),
        Err(CkRv::OBJECT_HANDLE_INVALID),
        "no key must exist before the call"
    );

    use crate::server::grpc_service::key_ops::generate_key;
    let resp = generate_key(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::GenerateKeyRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                mechanism_type: CkMechanismType::AES_KEY_GEN.0,
                params: None,
            }),
            template: vec![],

            template_null: false,
        }),
    )
    .await
    .expect("handler must return Ok(Response), never a Status error")
    .into_inner();
    assert_eq!(
        resp.ck_rv,
        CkRv::FUNCTION_FAILED.0,
        "saturated sink must fail the op closed with FUNCTION_FAILED"
    );
    assert_eq!(resp.key_handle, 0, "key handle must be zeroed on audit rejection");
    assert!(resp.mechanism_out.is_none(), "mechanism_out must be dropped on audit rejection");

    // Committed side effect persists: the backend op ran before emission, so
    // the key exists on the backend even though the client saw FUNCTION_FAILED.
    backend
        .get_object_size(backend_session, generated)
        .expect("fail-closed-after-side-effect: committed key must persist on the backend");
}

/// G1-PR3 audit-off: when `ctx.audit` is `None`, `generate_key` behaves
/// byte-identically to the pre-audit path (no panic, correct ck_rv).
#[tokio::test]
async fn audit_off_generate_key_byte_identical() {
    let mock = pkcs11_proxy_ng_backend::MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::AES_KEY_GEN],
    );
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;

    // No audit sink: for_test leaves ctx.audit = None.
    let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session_handle = open_test_session(&ctx_mgr, &backend, &ctx_id).await;

    use crate::server::grpc_service::key_ops::generate_key;
    let gen_rv = generate_key(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::GenerateKeyRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                mechanism_type: CkMechanismType::AES_KEY_GEN.0,
                params: None,
            }),
            template: vec![],

            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(gen_rv, CkRv::OK.0, "generate_key must succeed with audit off");
}

// ---------------------------------------------------------------------------
// G2-PR3 Task 3: per-principal session quota (derived leak-proof count)
// ---------------------------------------------------------------------------

/// Helper: configure a per-principal session quota via the rate-quota module.
/// Uses a thread-local override rather than `configure()` (which is
/// OnceLock-guarded and therefore not re-callable between tests).  Instead we
/// exercise the code path that calls `per_principal_max_sessions()` directly
/// by setting the OnceLock the first time it is needed in this process, so
/// only one test may set a non-None value — these tests are serialized by
/// `SESSION_QUOTA_INIT`.
static SESSION_QUOTA_INIT: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

fn quota_mutex() -> &'static tokio::sync::Mutex<()> {
    SESSION_QUOTA_INIT.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Call `open_session` through the `session.rs` test shim and return the raw
/// `OpenSessionResponse` (ck_rv + session_handle).
async fn try_open_session(
    ctx_mgr: &Arc<ContextManager>,
    backend: &Arc<dyn Pkcs11Backend>,
    ctx_id: &ClientContextId,
) -> pkcs11_proxy_ng_proto::OpenSessionResponse {
    let virtual_slot = ctx_mgr.virtual_slots().await[0];
    open_session(
        ctx_mgr,
        backend,
        Request::new(pkcs11_proxy_ng_proto::OpenSessionRequest {
            client_context_id: ctx_id.0.clone(),
            slot_id: virtual_slot.0,
            flags: (CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION).0,
        }),
    )
    .await
    .unwrap()
    .into_inner()
}

/// G2-PR3/T3: session_count_for_principal correctly sums session_slots across
/// all contexts whose principal key matches.
///
/// Uses manual session registration (via `register_session`) rather than the
/// full `open_session` handler so this is a pure unit test of the counting
/// function without token-policy / identity-format side effects.
///
/// Identity format note: the `slot_is_authorized` path in `open_session`
/// runs `AuthenticatedIdentity::from_str` on the stored identity string, which
/// expects "uid=N" or "x509:…" formats. This test uses `"uid=1"` / `"uid=2"`
/// for authenticated contexts and `None` for the unauthenticated one.
#[tokio::test]
async fn session_count_for_principal_aggregates_correctly() {
    use crate::server::handle_map::BackendHandle;

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));

    // Two contexts sharing the same identity → sessions aggregate.
    let ctx_a1 = ctx_mgr.create_context(Some("uid=1".into())).await.unwrap();
    let ctx_a2 = ctx_mgr.create_context(Some("uid=1".into())).await.unwrap();
    // A context with a different identity.
    let ctx_b = ctx_mgr.create_context(Some("uid=2".into())).await.unwrap();
    // An unauthenticated context: principal key = ctx_id string.
    let ctx_anon = ctx_mgr.create_context(None).await.unwrap();

    assert_eq!(ctx_mgr.session_count_for_principal("uid=1"), 0, "no sessions yet");

    // Register one session in ctx_a1.
    ctx_mgr
        .get_context(&ctx_a1, |ctx| {
            ctx.register_session(
                BackendHandle(1),
                crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            )
        })
        .await
        .expect("ctx_a1 must exist");
    assert_eq!(ctx_mgr.session_count_for_principal("uid=1"), 1, "one session in ctx_a1");

    // Register one session in ctx_a2 (same identity → aggregates).
    ctx_mgr
        .get_context(&ctx_a2, |ctx| {
            ctx.register_session(
                BackendHandle(2),
                crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            )
        })
        .await
        .expect("ctx_a2 must exist");
    assert_eq!(
        ctx_mgr.session_count_for_principal("uid=1"),
        2,
        "two sessions across ctx_a1 + ctx_a2"
    );

    // uid=2 is independent.
    ctx_mgr
        .get_context(&ctx_b, |ctx| {
            ctx.register_session(
                BackendHandle(3),
                crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            )
        })
        .await
        .expect("ctx_b must exist");
    assert_eq!(
        ctx_mgr.session_count_for_principal("uid=1"),
        2,
        "uid=2 session does not affect uid=1 count"
    );
    assert_eq!(ctx_mgr.session_count_for_principal("uid=2"), 1, "uid=2 has its own count");

    // Unauthenticated: principal key is the ctx_id string itself.
    ctx_mgr
        .get_context(&ctx_anon, |ctx| {
            ctx.register_session(
                BackendHandle(4),
                crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            )
        })
        .await
        .expect("ctx_anon must exist");
    assert_eq!(
        ctx_mgr.session_count_for_principal(&ctx_anon.0),
        1,
        "anon counted under its ctx_id key"
    );
    assert_eq!(ctx_mgr.session_count_for_principal("uid=1"), 2, "anon does not affect uid=1");
}

/// G2-PR3/T3: derived session count tracks open/close correctly — proves the
/// leak-proof property. Uses `create_context(None)` so the principal key
/// falls back to the ctx_id string and the open_session handler's
/// token-policy / identity-format checks do not interfere.
#[tokio::test]
async fn session_count_for_principal_tracks_close_session() {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;

    // No identity → principal key = ctx_id string (unauthenticated path).
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let principal_key = ctx_id.0.clone(); // derived key used in lifecycle.rs

    assert_eq!(ctx_mgr.session_count_for_principal(&principal_key), 0, "start at zero");

    let s1 = try_open_session(&ctx_mgr, &backend, &ctx_id).await;
    assert_eq!(s1.ck_rv, CkRv::OK.0, "1st open must succeed");
    let s2 = try_open_session(&ctx_mgr, &backend, &ctx_id).await;
    assert_eq!(s2.ck_rv, CkRv::OK.0, "2nd open must succeed");

    assert_eq!(ctx_mgr.session_count_for_principal(&principal_key), 2, "two sessions open");

    // Close one session → derived count drops (proves leak-proofness: no manual release needed).
    let close_rv = close_session(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: s1.session_handle,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(close_rv, CkRv::OK.0, "close must succeed");
    assert_eq!(ctx_mgr.session_count_for_principal(&principal_key), 1, "count drops after close");

    // A new open succeeds (derived count dropped below the hypothetical max of 2).
    let s3 = try_open_session(&ctx_mgr, &backend, &ctx_id).await;
    assert_eq!(s3.ck_rv, CkRv::OK.0, "open must succeed after count drops");
    assert_eq!(ctx_mgr.session_count_for_principal(&principal_key), 2, "back to two");
}

/// G2-PR3/T3 end-to-end: configure the session quota to 2, exercise through
/// `Pkcs11ProxyService` so the full dispatch path is covered.
///
/// Serialized via `quota_mutex()` because `rate_quota::configure` is
/// OnceLock-guarded and can only run once per process.  This test must be the
/// FIRST (and only) test to call `configure` with a non-None `max_sessions`
/// for the quota path to be active, so it takes the mutex to prevent races.
#[tokio::test]
async fn open_session_quota_enforced_end_to_end() {
    let _guard = quota_mutex().lock().await;

    // Configure the quota to 2 per principal. OnceLock: only the first call
    // to configure() in this process wins. If another test already configured
    // the global state, the OnceLock is set and this call is a no-op — in
    // that case the test may observe a different limit.  We always assert the
    // invariant against the configured value returned by per_principal_max_sessions().
    let cfg = crate::config::RateLimitConfig {
        per_principal_max_in_flight: None,
        per_principal_max_sessions: Some(2),
        per_slot_failed_login_budget: None,
        per_slot_failed_login_cooldown_secs: None,
    };
    crate::server::rate_quota::configure(&cfg);

    // If per_principal_max_sessions is NOT 2 after configure (another test
    // won the OnceLock race), skip rather than assert wrong invariants.
    let max = crate::server::rate_quota::per_principal_max_sessions();
    if max != Some(2) {
        // OnceLock already set by another caller — skip gracefully.
        return;
    }

    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;

    let svc = Pkcs11ProxyService::insecure_for_tests(ctx_mgr.clone(), backend.clone());

    // Use create_context(None) so:
    //   • The A2 owner check passes (stored=None → always allowed).
    //   • The principal key falls back to the ctx_id string (unauthenticated path).
    //   • Two contexts have DIFFERENT principal keys → are independently quota-limited.
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let virtual_slot = ctx_mgr.virtual_slots().await[0];

    let open = |cid: String| {
        let svc = svc.clone();
        let slot = virtual_slot.0;
        async move {
            svc.open_session(Request::new(pkcs11_proxy_ng_proto::OpenSessionRequest {
                client_context_id: cid,
                slot_id: slot,
                flags: (CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION).0,
            }))
            .await
            .unwrap()
            .into_inner()
        }
    };

    let r1 = open(ctx_id.0.clone()).await;
    assert_eq!(r1.ck_rv, CkRv::OK.0, "1st open must succeed");
    let r2 = open(ctx_id.0.clone()).await;
    assert_eq!(r2.ck_rv, CkRv::OK.0, "2nd open must succeed");

    // 3rd open must be rejected with CKR_SESSION_COUNT — no backend call.
    let r3 = open(ctx_id.0.clone()).await;
    assert_eq!(r3.ck_rv, CkRv::SESSION_COUNT.0, "3rd open must return CKR_SESSION_COUNT");
    assert_eq!(r3.session_handle, 0, "rejected open must return handle 0");

    // Close one session → derived count drops → next open succeeds
    // (proves leak-proofness: no manual release required).
    let close_rv = svc
        .close_session(Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: r1.session_handle,
        }))
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
    assert_eq!(close_rv, CkRv::OK.0, "close must succeed");

    let r4 = open(ctx_id.0.clone()).await;
    assert_eq!(r4.ck_rv, CkRv::OK.0, "open must succeed after count drops below max");

    // A completely different context (different principal key) is independent.
    let ctx_other = ctx_mgr.create_context(None).await.unwrap();
    let ro1 = open(ctx_other.0.clone()).await;
    assert_eq!(ro1.ck_rv, CkRv::OK.0, "other context 1st open must succeed");
    let ro2 = open(ctx_other.0.clone()).await;
    assert_eq!(ro2.ck_rv, CkRv::OK.0, "other context 2nd open must succeed");
    let ro3 = open(ctx_other.0.clone()).await;
    assert_eq!(ro3.ck_rv, CkRv::SESSION_COUNT.0, "other context hits own quota independently");
}

/// W1-L7-02 end-to-end: unauthenticated contexts from one TCP peer IP
/// share a single session quota — N contexts cannot multiply the cap.
/// Same `configure` values as `open_session_quota_enforced_end_to_end`
/// (identical cfg, same `quota_mutex`) so the two tests agree
/// whichever wins the OnceLock race.
#[tokio::test]
async fn open_session_quota_shared_per_peer_ip_for_unauthenticated() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let _guard = quota_mutex().lock().await;

    let cfg = crate::config::RateLimitConfig {
        per_principal_max_in_flight: None,
        per_principal_max_sessions: Some(2),
        per_slot_failed_login_budget: None,
        per_slot_failed_login_cooldown_secs: None,
    };
    crate::server::rate_quota::configure(&cfg);
    if crate::server::rate_quota::per_principal_max_sessions() != Some(2) {
        // OnceLock already set otherwise by another caller — skip gracefully.
        return;
    }

    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;

    let svc = Pkcs11ProxyService::insecure_for_tests(ctx_mgr.clone(), backend.clone());
    let virtual_slot = ctx_mgr.virtual_slots().await[0];

    let open_as = |cid: String, peer: SocketAddr| {
        let svc = svc.clone();
        let slot = virtual_slot.0;
        async move {
            let mut req = Request::new(pkcs11_proxy_ng_proto::OpenSessionRequest {
                client_context_id: cid,
                slot_id: slot,
                flags: (CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION).0,
            });
            req.extensions_mut().insert(tonic::transport::server::TcpConnectInfo {
                local_addr: None,
                remote_addr: Some(peer),
            });
            svc.open_session(req).await.unwrap().into_inner()
        }
    };

    // Two contexts from the SAME peer IP (different ports — the key is
    // IP-only) share one quota of 2.
    let peer_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 1111);
    let peer_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 2222);
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();

    let r1 = open_as(ctx_a.0.clone(), peer_a).await;
    assert_eq!(r1.ck_rv, CkRv::OK.0, "peer 1st open must succeed");
    let r2 = open_as(ctx_a.0.clone(), peer_b).await;
    assert_eq!(r2.ck_rv, CkRv::OK.0, "peer 2nd open must succeed");
    let r3 = open_as(ctx_b.0.clone(), peer_a).await;
    assert_eq!(
        r3.ck_rv,
        CkRv::SESSION_COUNT.0,
        "second context from the same peer IP must share the quota (3rd open rejected)"
    );
    assert_eq!(r3.session_handle, 0, "rejected open must return handle 0");

    // A different peer IP gets its own independent quota of 2.
    let peer_c = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)), 3333);
    let ctx_c = ctx_mgr.create_context(None).await.unwrap();
    let c1 = open_as(ctx_c.0.clone(), peer_c).await;
    assert_eq!(c1.ck_rv, CkRv::OK.0, "other peer 1st open must succeed");
    let c2 = open_as(ctx_c.0.clone(), peer_c).await;
    assert_eq!(c2.ck_rv, CkRv::OK.0, "other peer 2nd open must succeed");
    let c3 = open_as(ctx_c.0.clone(), peer_c).await;
    assert_eq!(c3.ck_rv, CkRv::SESSION_COUNT.0, "other peer hits own quota independently");
}

// ---------------------------------------------------------------------------
// G2-PR3: per-slot aggregate failed-login budget
// ---------------------------------------------------------------------------

/// G2-PR3: when `per_slot_failed_login_budget` is unset (or configured to
/// `None`), all failed-login attempts reach the backend transparently — no
/// fast-reject, no DEVICE_ERROR substitution.
///
/// This test is safe to run alongside `open_session_quota_enforced_end_to_end`
/// which configures the global rate-quota state with `budget = None`. In both
/// the "state not yet configured" and the "state configured with budget = None"
/// cases, `login_slot_in_cooldown` always returns false and
/// `record_login_failure` is always a no-op, so the login path is unchanged.
#[tokio::test]
async fn failed_login_budget_unset_all_reach_backend_transparently() {
    // Use quota_mutex so this test serializes against the quota configure test;
    // if that test has already set the budget to None, we're fine. If another
    // test (e.g. in an integration binary) has configured a non-None budget, we
    // detect it here and skip rather than assert incorrectly.
    let _guard = quota_mutex().lock().await;

    // If the global state is already configured with a non-None budget, skip
    // gracefully. Within this test binary, only the existing configure call
    // (budget = None) ever runs, so this path should not be taken.
    if crate::server::rate_quota::configured_login_budget().is_some() {
        // A different invocation set a non-None budget; unset semantics cannot
        // be verified in this process. Skip.
        return;
    }

    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    // Inject PIN_INCORRECT so every backend login fails with a PIN error.
    mock.inject_login_rv(CkRv::PIN_INCORRECT);
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let session = open_test_session(&ctx_mgr, &backend, &ctx_id).await;

    // 5 failed attempts must ALL reach the backend (no fast-reject).
    for i in 1_usize..=5 {
        let rv = login(
            &HandlerContext::for_test(&ctx_mgr, &backend),
            Request::new(pkcs11_proxy_ng_proto::LoginRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                user_type: CkUserType::User as u64,
                pin: Some(b"wrong".to_vec()),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
        assert_eq!(
            rv,
            CkRv::PIN_INCORRECT.0,
            "attempt {i}: must return transparent CKR_PIN_INCORRECT (no fast-reject)"
        );
        assert_eq!(
            mock.login_call_count(),
            i,
            "attempt {i}: backend must be called — no fast-reject when budget is unset"
        );
    }
}

/// W1-L6-03: close-all must suspend-then-close (singular-path semantics):
/// a transient backend failure keeps the mappings (reactivated) and the
/// logical login, leaking no live backend sessions; a retry then closes
/// everything. Pre-fix the mappings were dropped before the backend call,
/// so a failure leaked the still-open backend sessions with no mappings.
#[tokio::test]
async fn close_all_sessions_reactivates_mappings_on_transient_failure() {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let virtual_slot = ctx_mgr.virtual_slots().await[0];

    let s1 = open_test_session(&ctx_mgr, &backend, &ctx_id).await;
    let s2 = open_test_session(&ctx_mgr, &backend, &ctx_id).await;
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_id, s1).await, CkRv::OK.0);
    assert_eq!(mock.open_session_count(), 2, "setup: two backend sessions");

    // Transient failure (not terminal SESSION_HANDLE_INVALID, not ambiguous
    // DEVICE_ERROR): every close in the batch fails, nothing closes.
    mock.inject_close_error(CkRv::FUNCTION_FAILED);
    let failed = close_all_sessions(
        &ctx_mgr,
        &backend,
        Request::new(pkcs11_proxy_ng_proto::CloseAllSessionsRequest {
            client_context_id: ctx_id.0.clone(),
            slot_id: virtual_slot.0,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(failed.ck_rv, CkRv::FUNCTION_FAILED.0);

    // Mappings reactivated: both sessions still resolve…
    for s in [s1, s2] {
        assert!(
            ctx_mgr.slot_for_session(&ctx_id, VirtualHandle(s)).await.is_some(),
            "failed close-all must reactivate the mapping for session {s}"
        );
    }
    // …the logical login is retained…
    let login_state = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            ctx.login_state.get(&crate::server::slot_map::BackendSlotId(CkSlotId(0))).copied()
        })
        .await
        .unwrap();
    assert_eq!(login_state, Some(LoginState::User), "failed close-all must retain the login");
    // …and the backend sessions are still open (nothing leaked: a retry can
    // still close them through the reactivated mappings).
    assert_eq!(mock.open_session_count(), 2, "failed batch must close nothing");

    // Retry with a healthy backend closes everything exactly once.
    mock.clear_close_error();
    let retry = close_all_sessions(
        &ctx_mgr,
        &backend,
        Request::new(pkcs11_proxy_ng_proto::CloseAllSessionsRequest {
            client_context_id: ctx_id.0.clone(),
            slot_id: virtual_slot.0,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(retry.ck_rv, CkRv::OK.0);
    for s in [s1, s2] {
        assert!(
            ctx_mgr.slot_for_session(&ctx_id, VirtualHandle(s)).await.is_none(),
            "retry must remove the mapping for session {s}"
        );
    }
    assert_eq!(mock.open_session_count(), 0, "retry must close every backend session");
}

/// W1-L6-03 characterization: the multi-session success path is identical
/// (every suspended mapping settles terminal, login released).
#[tokio::test]
async fn close_all_sessions_multi_session_success_unchanged() {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let virtual_slot = ctx_mgr.virtual_slots().await[0];

    let s1 = open_test_session(&ctx_mgr, &backend, &ctx_id).await;
    let s2 = open_test_session(&ctx_mgr, &backend, &ctx_id).await;
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_id, s1).await, CkRv::OK.0);

    let close_all = close_all_sessions(
        &ctx_mgr,
        &backend,
        Request::new(pkcs11_proxy_ng_proto::CloseAllSessionsRequest {
            client_context_id: ctx_id.0.clone(),
            slot_id: virtual_slot.0,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(close_all.ck_rv, CkRv::OK.0);
    for s in [s1, s2] {
        assert!(ctx_mgr.slot_for_session(&ctx_id, VirtualHandle(s)).await.is_none());
    }
    assert_eq!(mock.open_session_count(), 0);
    let stale_login_state = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            ctx.login_state.get(&crate::server::slot_map::BackendSlotId(CkSlotId(0))).copied()
        })
        .await
        .unwrap();
    assert_eq!(stale_login_state, None);
}

/// W1-L6-10: a DONT_BLOCK wait must never block — even a faulty provider
/// that parks nonblocking waiters gets a bounded grace, then NO_EVENT
/// (no breaker slot burned, nothing stuck). Pre-fix the wait rode
/// spawn_backend to the 30s request timeout and answered DEVICE_ERROR.
#[tokio::test]
async fn wait_for_slot_event_dont_block_never_blocks_on_hung_backend() {
    use crate::server::grpc_service::state_ops::wait_for_slot_event_with_policy;

    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let policy = crate::server::auth::policy::TokenPolicy::from_config(
        &crate::config::AuthConfig::default(),
    )
    .unwrap();

    mock.inject_slot_event_hang(true);
    let start = std::time::Instant::now();
    // Test-side bound far under the 30s request timeout: pre-fix this
    // parks until the backend timeout (then DEVICE_ERROR).
    // The hang flag is cleared on EVERY path below (before any assert can
    // panic): a test panic that left the parked blocking thread stranded
    // hangs process teardown, masking the real failure.
    let timed = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        wait_for_slot_event_with_policy(
            &ctx_mgr,
            &backend,
            &policy,
            Request::new(pkcs11_proxy_ng_proto::WaitForSlotEventRequest {
                client_context_id: ctx_id.0.clone(),
                flags: 1, // CKF_DONT_BLOCK
            }),
        ),
    )
    .await;
    // Release the abandoned parked call (clearing wakes waiters to re-check).
    mock.inject_slot_event_hang(false);
    let resp = timed
        .expect("DONT_BLOCK wait must answer promptly even on a hung backend")
        .unwrap()
        .into_inner();
    assert_eq!(
        resp.ck_rv,
        CkRv::NO_EVENT.0,
        "an unanswerable nonblocking poll reports no-event, never blocks"
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(15),
        "took {:?}, must be bounded",
        start.elapsed()
    );
}

/// W1-L6-10 characterization: a blocking wait still delivers a queued
/// event (bypassing the breaker changes accounting, not outcomes).
#[tokio::test]
async fn wait_for_slot_event_blocking_delivers_queued_event() {
    use crate::server::grpc_service::state_ops::wait_for_slot_event_with_policy;

    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    mock.enqueue_slot_event(CkSlotId(0));
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let virtual_slot = ctx_mgr.virtual_slots().await[0];
    let policy = crate::server::auth::policy::TokenPolicy::from_config(
        &crate::config::AuthConfig::default(),
    )
    .unwrap();

    let resp = wait_for_slot_event_with_policy(
        &ctx_mgr,
        &backend,
        &policy,
        Request::new(pkcs11_proxy_ng_proto::WaitForSlotEventRequest {
            client_context_id: ctx_id.0.clone(),
            flags: 0, // blocking
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(resp.ck_rv, CkRv::OK.0);
    assert_eq!(resp.slot_id, virtual_slot.0);
}

/// W1-L6-10 characterization: a DONT_BLOCK wait on an empty queue
/// answers NO_EVENT immediately on a healthy backend.
#[tokio::test]
async fn wait_for_slot_event_dont_block_empty_queue_is_no_event() {
    use crate::server::grpc_service::state_ops::wait_for_slot_event_with_policy;

    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let policy = crate::server::auth::policy::TokenPolicy::from_config(
        &crate::config::AuthConfig::default(),
    )
    .unwrap();

    let start = std::time::Instant::now();
    let resp = wait_for_slot_event_with_policy(
        &ctx_mgr,
        &backend,
        &policy,
        Request::new(pkcs11_proxy_ng_proto::WaitForSlotEventRequest {
            client_context_id: ctx_id.0.clone(),
            flags: 1, // CKF_DONT_BLOCK
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(resp.ck_rv, CkRv::NO_EVENT.0);
    assert_eq!(resp.slot_id, 0);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "healthy nonblocking wait must be immediate, took {:?}",
        start.elapsed()
    );
}

// --- W1-L7-05: allows_class at mint (create/copy/generate/derive) ---

const MINT_MTLS_IDENTITY: &str = "x509:issuer=CN=Root CA;subject=CN=client";

fn mint_policy_with_classes(classes: Vec<String>) -> crate::server::auth::policy::TokenPolicy {
    crate::server::auth::policy::TokenPolicy::from_config(&crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: MINT_MTLS_IDENTITY.into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![crate::config::GrantSpec::Rich(
                crate::config::RichGrantConfig {
                    token: "label:MockToken".into(),
                    classes: Some(classes),
                    mechanisms: None,
                    extract: crate::config::ExtractPolicyConfig::Allow,
                    objects: None,
                },
            )]),
        }],
    })
    .unwrap()
}

fn mint_class_attr(class: CkObjectClass) -> pkcs11_proxy_ng_proto::Attribute {
    pkcs11_proxy_ng_proto::Attribute {
        attr_type: CkAttributeType::CLASS.0,
        value: Some(pkcs11_proxy_ng_proto::attribute::Value::UlongValue(class.0)),
    }
}

/// HandlerContext carrying a class-confined policy, over an identity-bound
/// context with one real session and a primed token cache. Returns
/// `(ctx, ctx_id, session, mock)`. The session is registered directly
/// (like `setup_extract_test`): the `open_session` handler path would
/// deny the test identity under its default policy before the mint gate
/// under test is ever reached.
async fn setup_mint_test(
    policy: crate::server::auth::policy::TokenPolicy,
) -> (HandlerContext, ClientContextId, u64, Arc<MockBackend>) {
    use crate::server::handle_map::BackendHandle;

    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let backend_slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
    ctx_mgr.register_slot(backend_slot).await;
    ctx_mgr.cache_token_info(backend_slot, "MockToken".into(), "0001".into());
    let ctx_id = ctx_mgr.create_context(Some(MINT_MTLS_IDENTITY.into())).await.unwrap();
    let backend_session = mock
        .open_session(CkSlotId(0), CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
        .unwrap();
    let session = ctx_mgr
        .get_context(&ctx_id, |ctx| {
            ctx.register_session(BackendHandle(backend_session.0), backend_slot)
        })
        .await
        .unwrap()
        .0;
    let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
    ctx.token_policy = Arc::new(policy);
    (ctx, ctx_id, session, mock)
}

fn mint_public_attr() -> pkcs11_proxy_ng_proto::Attribute {
    pkcs11_proxy_ng_proto::Attribute {
        attr_type: CkAttributeType::PRIVATE.0,
        value: Some(pkcs11_proxy_ng_proto::attribute::Value::BoolValue(false)),
    }
}

#[tokio::test]
async fn mint_gate_denies_create_object_of_denied_class() {
    use crate::server::grpc_service::object::create_object;

    // The L7-05 threat: a class-confined principal persisting a
    // denied-class TOKEN object. Pre-fix no mint check existed, so this
    // created the object.
    let policy = mint_policy_with_classes(vec!["data".into()]);
    assert!(policy.per_class_active());
    let (ctx, ctx_id, session, mock) = setup_mint_test(policy).await;

    let resp = create_object(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::CreateObjectRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            template: vec![
                mint_class_attr(CkObjectClass::SECRET_KEY),
                pkcs11_proxy_ng_proto::Attribute {
                    attr_type: CkAttributeType::TOKEN.0,
                    value: Some(pkcs11_proxy_ng_proto::attribute::Value::BoolValue(true)),
                },
            ],
            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(resp.ck_rv, CkRv::ATTRIBUTE_VALUE_INVALID.0);
    assert_eq!(resp.object_handle, 0);
    assert_eq!(mock.live_object_count(), 0, "denied mint must create nothing");
}

#[tokio::test]
async fn mint_gate_allows_create_object_of_listed_class() {
    use crate::server::grpc_service::object::create_object;

    let policy = mint_policy_with_classes(vec!["secret_key".into()]);
    let (ctx, ctx_id, session, mock) = setup_mint_test(policy).await;

    let resp = create_object(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::CreateObjectRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            template: vec![mint_class_attr(CkObjectClass::SECRET_KEY)],
            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(resp.ck_rv, CkRv::OK.0, "allowed mints are unchanged");
    assert_ne!(resp.object_handle, 0);
    assert_eq!(mock.live_object_count(), 1);
}

#[tokio::test]
async fn mint_gate_denies_copy_object_of_denied_class() {
    use crate::server::grpc_service::object::{copy_object, create_object};
    use pkcs11_proxy_ng_backend::mock::MockAttributeSlot;

    // Source of an allowed class (USE gate passes); the copy template
    // declares a denied class → mint denied before the backend runs.
    // Explicitly public so privacy checks cannot mask the mint gate.
    let policy = mint_policy_with_classes(vec!["secret_key".into()]);
    let (ctx, ctx_id, session, mock) = setup_mint_test(policy).await;

    let source = create_object(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::CreateObjectRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            template: vec![mint_class_attr(CkObjectClass::SECRET_KEY), mint_public_attr()],
            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .object_handle;
    assert_ne!(source, 0, "setup: allowed source mint must succeed");
    // The USE gate reads live metadata: stamp the source's class/token/uid.
    let backend_object = ctx
        .context_manager
        .get_context(&ctx_id, |c| c.object_handles.resolve(VirtualHandle(source)))
        .await
        .unwrap()
        .unwrap();
    mock.set_attribute(
        CkObjectHandle(backend_object.0 as u64),
        CkAttributeType::CLASS,
        MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
    );
    mock.set_attribute(
        CkObjectHandle(backend_object.0 as u64),
        CkAttributeType::TOKEN,
        MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
    );
    mock.set_attribute(
        CkObjectHandle(backend_object.0 as u64),
        CkAttributeType::UNIQUE_ID,
        MockAttributeSlot::Value(CkAttributeValue::Bytes(b"copy-src-uid".to_vec().into())),
    );

    let resp = copy_object(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::CopyObjectRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            object_handle: source,
            template: vec![mint_class_attr(CkObjectClass::DATA)],
            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(resp.ck_rv, CkRv::ATTRIBUTE_VALUE_INVALID.0);
    assert_eq!(resp.new_object_handle, 0);
    assert_eq!(mock.live_object_count(), 1, "denied copy must create nothing");
}

#[tokio::test]
async fn mint_gate_denies_generate_key_of_denied_class() {
    // Empty template → implied SECRET_KEY default → denied for a
    // data-only principal. Pre-fix the backend verdict came back instead.
    let policy = mint_policy_with_classes(vec!["data".into()]);
    let (ctx, ctx_id, session, _mock) = setup_mint_test(policy).await;

    let resp = crate::server::grpc_service::key_ops::generate_key(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::GenerateKeyRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                mechanism_type: CkMechanismType::AES_KEY_GEN.0,
                params: None,
            }),
            template: vec![],
            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(resp.ck_rv, CkRv::ATTRIBUTE_VALUE_INVALID.0);
    assert_eq!(resp.key_handle, 0);
}

#[tokio::test]
async fn mint_gate_allows_generate_when_class_listed() {
    // Allowed class passes the gate; whatever the backend then verdicts
    // (the mock does not implement AES_KEY_GEN) is not a policy denial.
    let policy = mint_policy_with_classes(vec!["secret_key".into()]);
    let (ctx, ctx_id, session, _mock) = setup_mint_test(policy).await;

    let resp = crate::server::grpc_service::key_ops::generate_key(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::GenerateKeyRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                mechanism_type: CkMechanismType::AES_KEY_GEN.0,
                params: None,
            }),
            template: vec![],
            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_ne!(
        resp.ck_rv,
        CkRv::ATTRIBUTE_VALUE_INVALID.0,
        "listed class must pass the mint gate to the backend verdict"
    );
}

#[tokio::test]
async fn mint_gate_denies_keypair_when_private_class_denied() {
    // Public template (implied PUBLIC_KEY) is allowed but the private
    // template (implied PRIVATE_KEY) is not → the whole mint is denied.
    let policy = mint_policy_with_classes(vec!["public_key".into()]);
    let (ctx, ctx_id, session, _mock) = setup_mint_test(policy).await;

    let resp = crate::server::grpc_service::key_ops::generate_key_pair(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::GenerateKeyPairRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN.0,
                params: None,
            }),
            public_key_template: vec![],
            public_template_null: false,
            private_key_template: vec![],
            private_template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(resp.ck_rv, CkRv::ATTRIBUTE_VALUE_INVALID.0);
    assert_eq!(resp.public_key_handle, 0);
    assert_eq!(resp.private_key_handle, 0);
}

#[tokio::test]
async fn mint_gate_denies_derive_key_of_denied_class() {
    use crate::server::grpc_service::object::create_object;
    use pkcs11_proxy_ng_backend::mock::MockAttributeSlot;

    // Base key of an allowed class (USE gate passes); the derived key's
    // implied SECRET_KEY class is denied → mint denied before derive runs.
    // Explicitly public so privacy checks cannot mask the mint gate.
    let policy = mint_policy_with_classes(vec!["data".into()]);
    let (ctx, ctx_id, session, mock) = setup_mint_test(policy).await;

    let base = create_object(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::CreateObjectRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            template: vec![mint_class_attr(CkObjectClass::DATA), mint_public_attr()],
            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .object_handle;
    assert_ne!(base, 0, "setup: allowed base mint must succeed");
    let backend_base = ctx
        .context_manager
        .get_context(&ctx_id, |c| c.object_handles.resolve(VirtualHandle(base)))
        .await
        .unwrap()
        .unwrap();
    for (attr, slot) in [
        (
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::DATA.0)),
        ),
        (CkAttributeType::TOKEN, MockAttributeSlot::Value(CkAttributeValue::Bool(false))),
        (
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(b"derive-base-uid".to_vec().into())),
        ),
    ] {
        mock.set_attribute(CkObjectHandle(backend_base.0 as u64), attr, slot);
    }

    let resp = crate::server::grpc_service::key_ops::derive_key(
        &ctx,
        Request::new(pkcs11_proxy_ng_proto::DeriveKeyRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle: session,
            mechanism: Some(hkdf_derive_mechanism(base)),
            base_key_handle: base,
            template: vec![],
            template_null: false,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(resp.ck_rv, CkRv::ATTRIBUTE_VALUE_INVALID.0);
    assert_eq!(resp.key_handle, 0);
}

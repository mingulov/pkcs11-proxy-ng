use super::{
    close_all_sessions, close_session, init_pin, init_token, login, logout, open_session, set_pin,
};
use crate::server::context_manager::{
    ClientContextId, ContextManager, LoginState, MessageOperation,
};
use crate::server::grpc_service::{HandlerContext, Pkcs11ProxyService};
use crate::server::handle_map::VirtualHandle;
use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend, mock::MockMessageLifecycleAction};
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
            flags: CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION,
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
            flags: CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION,
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

#[tokio::test]
async fn repeated_login_in_same_logical_client_reaches_backend() {
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
        2,
        "same logical client repeat login must preserve backend/provider behavior"
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

#[test]
fn grpc_handlers_never_debug_format_requests() {
    let handler_sources: &[(&str, &str)] = &[
        ("session_handlers/lifecycle.rs", include_str!("../session_handlers/lifecycle.rs")),
        ("session_handlers/auth.rs", include_str!("../session_handlers/auth.rs")),
        ("session_handlers/management.rs", include_str!("../session_handlers/management.rs")),
        ("key_ops/generation.rs", include_str!("../key_ops/generation.rs")),
        ("key_ops/wrapping.rs", include_str!("../key_ops/wrapping.rs")),
        ("object/search.rs", include_str!("../object/search.rs")),
        ("object/attributes.rs", include_str!("../object/attributes.rs")),
        ("object/lifecycle.rs", include_str!("../object/lifecycle.rs")),
        ("digest_cipher/digest.rs", include_str!("../digest_cipher/digest.rs")),
        ("digest_cipher/cipher.rs", include_str!("../digest_cipher/cipher.rs")),
        ("sign_verify/sign.rs", include_str!("../sign_verify/sign.rs")),
        ("sign_verify/verify.rs", include_str!("../sign_verify/verify.rs")),
        ("combined/sign_encrypt.rs", include_str!("../combined/sign_encrypt.rs")),
        ("combined/decrypt_digest.rs", include_str!("../combined/decrypt_digest.rs")),
        ("general/lifecycle.rs", include_str!("../general/lifecycle.rs")),
        ("general/info.rs", include_str!("../general/info.rs")),
        ("slot/discovery.rs", include_str!("../slot/discovery.rs")),
        ("slot/mechanisms.rs", include_str!("../slot/mechanisms.rs")),
        ("state_ops/random.rs", include_str!("../state_ops/random.rs")),
        ("state_ops/operation_state.rs", include_str!("../state_ops/operation_state.rs")),
        ("state_ops/slot_event.rs", include_str!("../state_ops/slot_event.rs")),
    ];

    let dbg_pattern = concat!("dbg", "!(");
    for (name, src) in handler_sources {
        for (lineno, line) in src.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !trimmed.contains(dbg_pattern),
                "{name} line {}: found debug macro that may leak secrets: {trimmed}",
                lineno + 1,
            );
        }
    }
}

#[test]
fn source_code_never_logs_pin_fields() {
    let session_sources: &[(&str, &str)] = &[
        ("session.rs", include_str!("../session.rs")),
        ("session_handlers/lifecycle.rs", include_str!("../session_handlers/lifecycle.rs")),
        ("session_handlers/auth.rs", include_str!("../session_handlers/auth.rs")),
        ("session_handlers/management.rs", include_str!("../session_handlers/management.rs")),
    ];

    for (name, source) in session_sources {
        for (lineno, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if !trimmed.contains("info!(")
                && !trimmed.contains("warn!(")
                && !trimmed.contains("debug!(")
                && !trimmed.contains("error!(")
            {
                continue;
            }
            if trimmed.starts_with("//")
                || trimmed.starts_with("assert")
                || trimmed.starts_with("let")
            {
                continue;
            }
            for forbidden in &["pin =", "so_pin =", "old_pin =", "new_pin =", "pin=", "so_pin="] {
                assert!(
                    !trimmed.contains(forbidden),
                    "{name} line {}: tracing macro must not log PIN data: {}",
                    lineno + 1,
                    trimmed
                );
            }
        }
    }
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
        CkRv::DEVICE_ERROR,
        "a hung waiter surfaces the timeout promptly"
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
    assert_eq!(rv, CkRv::DEVICE_ERROR.0, "handler timeout is outcome-ambiguous");
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
    assert_eq!(rv, CkRv::DEVICE_ERROR.0, "handler timeout is outcome-ambiguous");

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
    assert_eq!(rv, CkRv::DEVICE_ERROR.0);

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
    assert_eq!(rv, CkRv::DEVICE_ERROR.0);
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
            flags: CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION,
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
                flags: CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION,
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

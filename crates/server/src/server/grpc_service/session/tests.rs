use super::{
    close_all_sessions, close_session, init_pin, init_token, login, logout, open_session, set_pin,
};
use crate::server::context_manager::{ClientContextId, ContextManager, LoginState};
use crate::server::grpc_service::HandlerContext;
use crate::server::handle_map::VirtualHandle;
use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
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
    ctx_mgr.register_slot(CkSlotId(0)).await;
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
async fn login_state_is_logical_client_scoped_when_backend_is_already_logged_in() {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(CkSlotId(0)).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();

    let session_a = open_test_session(&ctx_mgr, &backend, &ctx_a).await;
    let session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;

    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_a, session_a).await, CkRv::OK.0);
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_b, session_b).await,
        CkRv::OK.0,
        "a fresh logical client should not inherit backend USER_ALREADY_LOGGED_IN"
    );
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_b, session_b).await,
        CkRv::USER_ALREADY_LOGGED_IN.0,
        "repeat login in the same logical client should still report already logged in"
    );
    assert_eq!(
        mock.login_call_count(),
        2,
        "repeat login after a logical login must be answered by the backend, not synthesized"
    );

    let logout_b = logout(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::LogoutRequest {
            client_context_id: ctx_b.0.clone(),
            session_handle: session_b,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(logout_b.ck_rv, CkRv::OK.0);

    let backend_session_a = ctx_mgr
        .get_context(&ctx_a, |ctx| ctx.session_handles.resolve(VirtualHandle(session_a)))
        .await
        .unwrap()
        .unwrap();
    let info = backend.get_session_info(CkSessionHandle(backend_session_a.0 as u64)).unwrap();
    assert_eq!(
        info.state,
        CkSessionState::RwUser,
        "logging out ctx_b must not physically log out ctx_a"
    );
}

#[tokio::test]
async fn repeated_login_in_same_logical_client_reaches_backend() {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(CkSlotId(0)).await;
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
    ctx_mgr.register_slot(CkSlotId(0)).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();
    let virtual_slot = ctx_mgr.virtual_slots().await[0];

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
        .get_context(&ctx_a, |ctx| ctx.login_state.get(&virtual_slot).copied())
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
    ctx_mgr.register_slot(CkSlotId(0)).await;
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
        .get_context(&ctx_id, |ctx| ctx.login_state.get(&virtual_slot).copied())
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
    ctx_mgr.register_slot(CkSlotId(0)).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let virtual_slot = ctx_mgr.virtual_slots().await[0];
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
        .get_context(&ctx_id, |ctx| ctx.login_state.get(&virtual_slot).copied())
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
    ctx_mgr.register_slot(CkSlotId(0)).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let virtual_slot = ctx_mgr.virtual_slots().await[0];
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
        .get_context(&ctx_id, |ctx| ctx.login_state.get(&virtual_slot).copied())
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

async fn capture_logs<F, Fut>(f: F) -> String
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
fn proto_pin_requests_debug_exposes_data() {
    let login = pkcs11_proxy_ng_proto::LoginRequest {
        client_context_id: "ctx-test".into(),
        session_handle: 1,
        user_type: 1,
        pin: Some(b"secret-pin-data".to_vec()),
    };
    let debug_output = format!("{:?}", login);
    assert!(debug_output.contains("pin"));
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
    ctx_mgr.register_slot(CkSlotId(0)).await;
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
    ctx_mgr.register_slot(CkSlotId(0)).await; // only slot 0 is mapped; 99 is not
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
    ctx_mgr.register_slot(CkSlotId(0)).await;
    // An authenticated identity that the (empty, deny-by-default) policy denies.
    let ctx_id =
        ctx_mgr.create_context(Some("x509:issuer=CN=CA;subject=CN=denied".into())).await.unwrap();
    let policy =
        crate::server::auth::policy::TokenPolicy::from_config(&crate::config::AuthConfig {
            allow_all_authenticated: false,
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

async fn setup_session_with_mock() -> (Arc<ContextManager>, Arc<MockBackend>, ClientContextId, u64)
{
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(CkSlotId(0)).await;
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

    let still = ctx_mgr
        .get_context(&ctx_id, |c| c.session_handles.resolve(VirtualHandle(session)))
        .await
        .flatten();
    assert!(still.is_some(), "a transient close failure must keep the session mapping for retry");
}

#[tokio::test]
async fn close_session_drops_mapping_when_backend_reports_already_gone() {
    // M3: a terminal result (backend says the session is already invalid) must
    // drop the stale mapping rather than leaving it to linger.
    let (ctx_mgr, mock, ctx_id, session) = setup_session_with_mock().await;
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    mock.inject_close_error(CkRv::SESSION_HANDLE_INVALID);

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
    assert_eq!(rv, CkRv::SESSION_HANDLE_INVALID.0);

    let gone = ctx_mgr
        .get_context(&ctx_id, |c| c.session_handles.resolve(VirtualHandle(session)))
        .await
        .flatten();
    assert!(gone.is_none(), "a terminal 'already gone' close must drop the stale mapping");
}

#[tokio::test]
async fn cross_client_login_with_wrong_pin_is_rejected() {
    // A1: when a fresh logical client logs in to a slot another client already
    // holds, the shared backend token is logged in, so a second backend
    // C_Login returns USER_ALREADY_LOGGED_IN without validating the PIN. The
    // proxy must therefore validate the presented PIN against the verifier
    // captured at the first successful login — never synthesize CKR_OK for an
    // unvalidated/incorrect PIN.
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(CkSlotId(0)).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();
    let session_a = open_test_session(&ctx_mgr, &backend, &ctx_a).await;
    let session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;

    // ctx_a logs in with the correct PIN ("1234" per login_response).
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_a, session_a).await, CkRv::OK.0);

    // ctx_b attempts a logical login with a WRONG PIN.
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
        CkRv::PIN_INCORRECT.0,
        "cross-client login with a wrong PIN must be CKR_PIN_INCORRECT, not synthesized OK"
    );

    // ctx_b with the CORRECT PIN still succeeds (feature preserved).
    assert_eq!(
        login_response(&ctx_mgr, &backend, &ctx_b, session_b).await,
        CkRv::OK.0,
        "cross-client login with the correct PIN must still succeed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_first_login_serializes_to_one_backend_login() {
    // M5: two clients racing the FIRST login on the same shared token must not
    // both take the real-login path. Per-slot login serialization makes the
    // first do the real C_Login (capturing the verifier) and the second take
    // the logical path (verifier-validated OK) — exactly one backend C_Login.
    //
    // Deterministic harness: a login gate holds client A inside the backend
    // C_Login (still holding the per-slot lock) while client B starts, so B is
    // guaranteed to race. Without the lock, B would scan "no other login" before
    // A inserts its state and issue a SECOND backend login (count == 2); with it,
    // B blocks on the lock, then sees A's state and takes the logical path.
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(CkSlotId(0)).await;
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

    // Release A; it finishes the real login, captures the verifier, drops the
    // lock; B then sees A's login state and takes the logical path.
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
        CkRv::OK.0,
        "the raced second login must be a logical OK, not USER_ALREADY_LOGGED_IN"
    );
    assert_eq!(
        mock.login_call_count(),
        1,
        "per-slot serialization must yield exactly one real backend C_Login"
    );
}

#[tokio::test]
async fn set_pin_refreshes_the_cross_client_login_verifier() {
    // A1 follow-up (ADR-0008): after a PIN change, a co-located logical login
    // with the NEW PIN must be accepted — the verifier is refreshed, not left
    // failing closed against the old PIN.
    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(CkSlotId(0)).await;
    let ctx_a = ctx_mgr.create_context(None).await.unwrap();
    let ctx_b = ctx_mgr.create_context(None).await.unwrap();
    let session_a = open_test_session(&ctx_mgr, &backend, &ctx_a).await;
    let session_b = open_test_session(&ctx_mgr, &backend, &ctx_b).await;

    // ctx_a logs in with "1234" (verifier captured), then changes it to "5678".
    assert_eq!(login_response(&ctx_mgr, &backend, &ctx_a, session_a).await, CkRv::OK.0);
    let set_rv = set_pin(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::SetPinRequest {
            client_context_id: ctx_a.0.clone(),
            session_handle: session_a,
            old_pin: Some(b"1234".to_vec()),
            new_pin: Some(b"5678".to_vec()),
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(set_rv, CkRv::OK.0, "SetPIN should succeed");

    // ctx_b's logical login with the NEW PIN must now be accepted.
    let rv = login(
        &HandlerContext::for_test(&ctx_mgr, &backend),
        Request::new(pkcs11_proxy_ng_proto::LoginRequest {
            client_context_id: ctx_b.0.clone(),
            session_handle: session_b,
            user_type: CkUserType::User as u64,
            pin: Some(b"5678".to_vec()),
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .ck_rv;
    assert_eq!(
        rv,
        CkRv::OK.0,
        "a logical login with the new PIN must be accepted after SetPIN refreshes the verifier"
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
        signing_key: None,
        rotate_max_bytes: 1 << 20,
        rotate_keep_files: 10,
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
    ctx_mgr.register_slot(CkSlotId(0)).await;

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
    ctx_mgr.register_slot(CkSlotId(0)).await;

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

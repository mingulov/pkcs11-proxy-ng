use super::{
    close_all_sessions, close_session, init_pin, init_token, login, logout, open_session, set_pin,
};
use crate::server::context_manager::{ClientContextId, ContextManager, LoginState};
use crate::server::handle_map::VirtualHandle;
use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
use pkcs11_proxy_ng_types::*;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use tonic::Request;
use tracing::instrument::WithSubscriber;
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
        ctx_mgr,
        backend,
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
        ctx_mgr,
        backend,
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
        &ctx_mgr,
        &backend,
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
    let info = backend.get_session_info(CkSessionHandle(backend_session_a.0)).unwrap();
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
        &ctx_mgr,
        &backend,
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
    mock.close_session(CkSessionHandle(backend_session.0)).unwrap();

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
        &ctx_mgr,
        &backend,
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
    let writer = CapturedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(writer.clone())
        .finish();

    f().with_subscriber(subscriber).await;
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
            &ctx_mgr,
            &backend,
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
            &ctx_mgr,
            &backend,
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
            &ctx_mgr,
            &backend,
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
            &ctx_mgr,
            &backend,
            Request::new(pkcs11_proxy_ng_proto::LoginRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                user_type: 1,
                pin: Some(pin.clone()),
            }),
        )
        .await;
        let _ = logout(
            &ctx_mgr,
            &backend,
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
async fn destroy_object_evicts_the_virtual_handle() {
    use crate::server::grpc_service::object::{create_object, destroy_object};

    let (ctx_mgr, backend, ctx_id, session) = setup_session().await;

    // Create a live backend object so destroy has something to remove.
    let created = create_object(
        &ctx_mgr,
        &backend,
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
        &ctx_mgr,
        &backend,
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
async fn wait_for_slot_event_does_not_leak_raw_backend_slot() {
    use crate::server::grpc_service::state_ops::wait_for_slot_event;

    let mock = MockBackend::default_test();
    mock.initialize().unwrap();
    // An event for a backend slot the daemon never registered (no virtual map).
    mock.enqueue_slot_event(CkSlotId(99));
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);

    let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    ctx_mgr.register_slot(CkSlotId(0)).await; // only slot 0 is mapped; 99 is not
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();

    let resp = wait_for_slot_event(
        &ctx_mgr,
        &backend,
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
        &ctx_mgr,
        &backend,
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
        &ctx_mgr,
        &backend,
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
        &ctx_mgr,
        &backend,
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

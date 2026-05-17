use super::{init_pin, init_token, login, logout, open_session, set_pin};
use crate::server::context_manager::{ClientContextId, ContextManager};
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

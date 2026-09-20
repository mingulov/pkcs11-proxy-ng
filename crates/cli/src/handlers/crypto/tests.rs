//! W1-C11-04: label-based key lookup for the four crypto ops must also
//! search SECRET_KEY objects.
//!
//! Each test spins an in-process mock daemon (client -> gRPC -> backend),
//! creates one key object of a fixed class with a known label, installs a
//! find-template gate so only searches for that class match (simulating a
//! real backend's template filtering), then runs the real CLI handler.
//!
//! - `*_resolves_secret_key_by_label`: the SECRET_KEY object is found even
//!   though each op's primary class differs (encrypt/verify search
//!   PUBLIC_KEY, decrypt/sign search PRIVATE_KEY). Fails before the fix with
//!   `No <class> found with label ...`.
//! - `primary_classes_still_resolve_without_fallback`: previously-resolving
//!   classes still resolve with exactly one search (primary first, no
//!   spurious SECRET_KEY search).

use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::super::CliResult;
use super::{decrypt, encrypt, sign, verify};

const SECRET_LABEL: &str = "w1-c11-04-key";
const PIN: &str = "1234";
const DATA_HEX: &str = "00112233445566778899aabbccddeeff";

/// The mock backend's one-shot `C_Verify` only accepts the deterministic
/// `echo("sign", data)` output (2 bytes, `MOCK_SIGN_LEN`) as the signature.
fn mock_signature_hex() -> String {
    let data = hex::decode(DATA_HEX).unwrap();
    hex::encode(pkcs11_proxy_ng_backend::mock::echo::echo_bytes("sign", &[&data], 2))
}

/// Spin up an in-process gRPC daemon backed by `backend`.
///
/// Returns the endpoint URL and a shutdown sender; the server stops when
/// the sender is dropped. Mirrors the server crate's `common_3x` harness.
async fn mock_daemon(backend: Arc<MockBackend>) -> (String, tokio::sync::watch::Sender<bool>) {
    use pkcs11_proxy_ng::server::context_manager::ContextManager;
    use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
    use pkcs11_proxy_ng_backend::Pkcs11Backend;

    backend.initialize().expect("initialize mock backend before serving");
    let ctx = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    let backend: Arc<dyn Pkcs11Backend> = backend;
    ctx.populate_slots(&backend).await.expect("populate_slots");
    let svc = Pkcs11ProxyService::insecure_for_tests(ctx, backend);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://127.0.0.1:{}", addr.port());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let _ = tonic::transport::Server::builder()
            .add_service(pkcs11_proxy_ng_proto::Pkcs11ProxyServer::new(svc))
            .serve_with_incoming_shutdown(incoming, async move {
                let mut rx = server_shutdown;
                let _ = rx.changed().await;
            })
            .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (endpoint, shutdown_tx)
}

fn template_has_class(template: &[CkAttribute], class: u64) -> bool {
    template.iter().any(|attr| {
        attr.attr_type == CkAttributeType::CLASS
            && matches!(&attr.value, Some(CkAttributeValue::Ulong(c)) if *c == class)
    })
}

struct Fixture {
    backend: Arc<MockBackend>,
    client: Pkcs11Client,
    slot: u64,
    _shutdown: tokio::sync::watch::Sender<bool>,
    /// Held open so the created session object stays live across the
    /// handler's own session.
    _setup_session: CkSessionHandle,
}

/// Create a daemon with a single `object_class` key labelled `label`, served
/// by find only when the search template asks for that class.
async fn fixture(object_class: CkObjectClass, label: &str) -> Fixture {
    let backend = Arc::new(MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::AES_ECB, CkMechanismType(0x0000_0251)],
    ));
    let (endpoint, shutdown) = mock_daemon(backend.clone()).await;
    let mut client = Pkcs11Client::connect(&endpoint).await.unwrap();
    client.initialize().await.unwrap();
    let slots = client.get_slot_list(false).await.unwrap();
    let setup_session = client
        .open_session(slots[0], CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
        .await
        .unwrap();
    let key = client
        .create_object(
            setup_session,
            Some(&[
                CkAttribute {
                    attr_type: CkAttributeType::CLASS,
                    value: Some(CkAttributeValue::Ulong(object_class.0)),
                },
                CkAttribute {
                    attr_type: CkAttributeType::LABEL,
                    value: Some(CkAttributeValue::String(label.to_string().into())),
                },
            ]),
        )
        .await
        .unwrap();
    backend.set_find_objects_result(vec![key]);
    backend.set_find_template_gate(move |t| template_has_class(t, object_class.0));
    Fixture {
        backend,
        client,
        slot: slots[0].0,
        _shutdown: shutdown,
        _setup_session: setup_session,
    }
}

/// The handler needed the SECRET_KEY fallback: primary-class search first,
/// then exactly one SECRET_KEY search.
fn assert_fallback_search_order(backend: &MockBackend, primary: CkObjectClass) {
    let templates = backend.take_find_init_templates();
    assert_eq!(
        templates.len(),
        2,
        "expected primary + SECRET_KEY fallback searches, got {}",
        templates.len()
    );
    assert!(
        template_has_class(&templates[0], primary.0),
        "first search must use the op's primary class 0x{0:08X}",
        primary.0
    );
    assert!(
        template_has_class(&templates[1], CkObjectClass::SECRET_KEY.0),
        "second search must fall back to SECRET_KEY"
    );
}

#[tokio::test]
async fn encrypt_resolves_secret_key_by_label() {
    let mut fx = fixture(CkObjectClass::SECRET_KEY, SECRET_LABEL).await;
    encrypt(
        &mut fx.client,
        fx.slot,
        PIN.to_string(),
        SECRET_LABEL.to_string(),
        "AES_ECB".to_string(),
        DATA_HEX.to_string(),
    )
    .await
    .expect("encrypt must resolve a SECRET_KEY object by label");
    assert_fallback_search_order(&fx.backend, CkObjectClass::PUBLIC_KEY);
}

#[tokio::test]
async fn decrypt_resolves_secret_key_by_label() {
    let mut fx = fixture(CkObjectClass::SECRET_KEY, SECRET_LABEL).await;
    decrypt(
        &mut fx.client,
        fx.slot,
        PIN.to_string(),
        SECRET_LABEL.to_string(),
        "AES_ECB".to_string(),
        DATA_HEX.to_string(),
    )
    .await
    .expect("decrypt must resolve a SECRET_KEY object by label");
    assert_fallback_search_order(&fx.backend, CkObjectClass::PRIVATE_KEY);
}

#[tokio::test]
async fn sign_resolves_secret_key_by_label() {
    let mut fx = fixture(CkObjectClass::SECRET_KEY, SECRET_LABEL).await;
    sign(
        &mut fx.client,
        fx.slot,
        PIN.to_string(),
        SECRET_LABEL.to_string(),
        "SHA256_HMAC".to_string(),
        DATA_HEX.to_string(),
    )
    .await
    .expect("sign must resolve a SECRET_KEY object by label");
    assert_fallback_search_order(&fx.backend, CkObjectClass::PRIVATE_KEY);
}

#[tokio::test]
async fn verify_resolves_secret_key_by_label() {
    let mut fx = fixture(CkObjectClass::SECRET_KEY, SECRET_LABEL).await;
    verify(
        &mut fx.client,
        fx.slot,
        Some(PIN.to_string()),
        SECRET_LABEL.to_string(),
        "SHA256_HMAC".to_string(),
        DATA_HEX.to_string(),
        mock_signature_hex(),
    )
    .await
    .expect("verify must resolve a SECRET_KEY object by label");
    assert_fallback_search_order(&fx.backend, CkObjectClass::PUBLIC_KEY);
}

#[derive(Clone, Copy)]
enum CryptoOp {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
}

async fn run_op(op: CryptoOp, client: &mut Pkcs11Client, slot: u64, label: &str) -> CliResult {
    match op {
        CryptoOp::Encrypt => {
            encrypt(
                client,
                slot,
                PIN.to_string(),
                label.to_string(),
                "AES_ECB".to_string(),
                DATA_HEX.to_string(),
            )
            .await
        }
        CryptoOp::Decrypt => {
            decrypt(
                client,
                slot,
                PIN.to_string(),
                label.to_string(),
                "AES_ECB".to_string(),
                DATA_HEX.to_string(),
            )
            .await
        }
        CryptoOp::Sign => {
            sign(
                client,
                slot,
                PIN.to_string(),
                label.to_string(),
                "SHA256_HMAC".to_string(),
                DATA_HEX.to_string(),
            )
            .await
        }
        CryptoOp::Verify => {
            verify(
                client,
                slot,
                Some(PIN.to_string()),
                label.to_string(),
                "SHA256_HMAC".to_string(),
                DATA_HEX.to_string(),
                mock_signature_hex(),
            )
            .await
        }
    }
}

#[tokio::test]
async fn primary_classes_still_resolve_without_fallback() {
    use CryptoOp::{Decrypt, Encrypt, Sign, Verify};
    for (op, primary) in [
        (Encrypt, CkObjectClass::PUBLIC_KEY),
        (Decrypt, CkObjectClass::PRIVATE_KEY),
        (Sign, CkObjectClass::PRIVATE_KEY),
        (Verify, CkObjectClass::PUBLIC_KEY),
    ] {
        let mut fx = fixture(primary, SECRET_LABEL).await;
        run_op(op, &mut fx.client, fx.slot, SECRET_LABEL)
            .await
            .expect("previously-resolving class must still resolve");
        let templates = fx.backend.take_find_init_templates();
        assert_eq!(
            templates.len(),
            1,
            "primary-class hit must not trigger a fallback search (class 0x{:08X})",
            primary.0
        );
        assert!(template_has_class(&templates[0], primary.0));
    }
}

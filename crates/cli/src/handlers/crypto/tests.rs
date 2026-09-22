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
    fixture_with_mechanisms(
        object_class,
        label,
        vec![CkMechanismType::AES_ECB, CkMechanismType(0x0000_0251)],
    )
    .await
}

/// `fixture` with `count` same-label keys (W1-C11-14: `count = 2`
/// exercises the duplicate-label ambiguity error).
async fn fixture_with_count(object_class: CkObjectClass, label: &str, count: usize) -> Fixture {
    let backend = Arc::new(MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::AES_ECB, CkMechanismType(0x0000_0251)],
    ));
    let (endpoint, shutdown) = mock_daemon(backend.clone()).await;
    let mut client = Pkcs11Client::connect(&endpoint).await.unwrap();
    client.initialize().await.unwrap();
    let slots = client.get_slot_list(false).await.unwrap();
    let setup_session =
        client.open_session(slots[0], CkSessionFlags::SERIAL_SESSION).await.unwrap();
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        keys.push(
            client
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
                .unwrap(),
        );
    }
    backend.set_find_objects_result(keys);
    backend.set_find_template_gate(move |t| template_has_class(t, object_class.0));
    Fixture {
        backend,
        client,
        slot: slots[0].0,
        _shutdown: shutdown,
        _setup_session: setup_session,
    }
}

/// `fixture` with an explicit advertised-mechanism list (W1-C11-08: the
/// mock rejects init for unadvertised mechanisms with MECHANISM_INVALID).
async fn fixture_with_mechanisms(
    object_class: CkObjectClass,
    label: &str,
    mechanisms: Vec<CkMechanismType>,
) -> Fixture {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], mechanisms));
    let (endpoint, shutdown) = mock_daemon(backend.clone()).await;
    let mut client = Pkcs11Client::connect(&endpoint).await.unwrap();
    client.initialize().await.unwrap();
    let slots = client.get_slot_list(false).await.unwrap();
    let setup_session =
        client.open_session(slots[0], CkSessionFlags::SERIAL_SESSION).await.unwrap();
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
        SecretBytes::from(PIN),
        SECRET_LABEL.to_string(),
        "AES_ECB".to_string(),
        None,
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
        SecretBytes::from(PIN),
        SECRET_LABEL.to_string(),
        "AES_ECB".to_string(),
        None,
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
        SecretBytes::from(PIN),
        SECRET_LABEL.to_string(),
        "SHA256_HMAC".to_string(),
        None,
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
        Some(SecretBytes::from(PIN)),
        SECRET_LABEL.to_string(),
        "SHA256_HMAC".to_string(),
        None,
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
                SecretBytes::from(PIN),
                label.to_string(),
                "AES_ECB".to_string(),
                None,
                DATA_HEX.to_string(),
            )
            .await
        }
        CryptoOp::Decrypt => {
            decrypt(
                client,
                slot,
                SecretBytes::from(PIN),
                label.to_string(),
                "AES_ECB".to_string(),
                None,
                DATA_HEX.to_string(),
            )
            .await
        }
        CryptoOp::Sign => {
            sign(
                client,
                slot,
                SecretBytes::from(PIN),
                label.to_string(),
                "SHA256_HMAC".to_string(),
                None,
                DATA_HEX.to_string(),
            )
            .await
        }
        CryptoOp::Verify => {
            verify(
                client,
                slot,
                Some(SecretBytes::from(PIN)),
                label.to_string(),
                "SHA256_HMAC".to_string(),
                None,
                DATA_HEX.to_string(),
                mock_signature_hex(),
            )
            .await
        }
    }
}

// W1-C11-08: bare AES_GCM must error with a CLI hint,
// not sail through parameterless to a bare backend CKR.
#[tokio::test]
async fn bare_gcm_encrypt_errors_with_cli_hint() {
    let mut fx = fixture(CkObjectClass::SECRET_KEY, SECRET_LABEL).await;
    let err = encrypt(
        &mut fx.client,
        fx.slot,
        SecretBytes::from(PIN),
        SECRET_LABEL.to_string(),
        "AES_GCM".to_string(),
        None,
        DATA_HEX.to_string(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires parameters"), "no hint: {err}");
    assert!(err.contains("--params-file"), "no hint: {err}");
}

// W1-C11-12: the INVALID path releases the session (logout+close)
// and returns the VerifyInvalid sentinel (which main maps to exit 2)
// instead of process::exit-ing past cleanup.
#[tokio::test]
async fn verify_invalid_releases_session() {
    let mut fx = fixture(CkObjectClass::SECRET_KEY, SECRET_LABEL).await;
    let baseline = fx.backend.open_session_count();
    let err = verify(
        &mut fx.client,
        fx.slot,
        Some(SecretBytes::from(PIN)),
        SECRET_LABEL.to_string(),
        "SHA256_HMAC".to_string(),
        None,
        DATA_HEX.to_string(),
        "00".to_string(),
    )
    .await
    .unwrap_err();
    assert!(
        err.downcast_ref::<super::super::VerifyInvalid>().is_some(),
        "INVALID must return the VerifyInvalid sentinel, got: {err}"
    );
    assert_eq!(
        fx.backend.open_session_count(),
        baseline,
        "INVALID path must close the session it opened"
    );
}

// W1-C11-08: a parameterized mechanism succeeds end to end (CLI ->
// gRPC -> backend) once a params file supplies the params.
#[tokio::test]
async fn encrypt_accepts_gcm_params_file() {
    let mut fx = fixture_with_mechanisms(
        CkObjectClass::SECRET_KEY,
        SECRET_LABEL,
        vec![CkMechanismType::AES_GCM],
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let params_path = dir.path().join("gcm.json");
    std::fs::write(
        &params_path,
        r#"{"iv_hex": "00112233445566778899aabb", "aad_hex": "aabb", "tag_bits": 128}"#,
    )
    .unwrap();
    encrypt(
        &mut fx.client,
        fx.slot,
        SecretBytes::from(PIN),
        SECRET_LABEL.to_string(),
        "AES_GCM".to_string(),
        Some(params_path),
        DATA_HEX.to_string(),
    )
    .await
    .expect("encrypt with AES_GCM + params file must succeed");
}

// W1-C11-14: duplicate labels error loudly, listing the matches,
// instead of silently resolving to an arbitrary key.
#[tokio::test]
async fn duplicate_label_errors_listing_matches() {
    let mut fx = fixture_with_count(CkObjectClass::SECRET_KEY, SECRET_LABEL, 2).await;
    let err = encrypt(
        &mut fx.client,
        fx.slot,
        SecretBytes::from(PIN),
        SECRET_LABEL.to_string(),
        "AES_ECB".to_string(),
        None,
        DATA_HEX.to_string(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("Multiple"), "must flag ambiguity: {err}");
    assert!(err.contains(SECRET_LABEL), "must name the label: {err}");
    assert!(err.contains("secret-key"), "must name the class: {err}");
    assert!(err.contains("handles:"), "must list matches: {err}");
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

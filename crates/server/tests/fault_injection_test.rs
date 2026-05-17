//! Fault injection tests using MockBackend (Item 96).
//!
//! These tests verify cleanup, error reporting, and recovery behavior
//! when the backend returns errors, connections break, or resources
//! are exhausted. All tests run without external PKCS#11 modules.

use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use tokio::net::TcpListener;
use tonic::transport::Server;

fn mock(slots: &[u64], mechs: &[u64]) -> MockBackend {
    MockBackend::new(
        slots.iter().copied().map(CkSlotId).collect(),
        mechs.iter().copied().map(CkMechanismType).collect(),
    )
}

/// Spin up a mock daemon on an ephemeral port.
async fn mock_daemon(backend: Arc<MockBackend>) -> (String, tokio::sync::watch::Sender<bool>) {
    mock_daemon_with_lease(backend, Duration::from_secs(300), Duration::from_millis(100)).await
}

async fn mock_daemon_with_lease(
    backend: Arc<MockBackend>,
    lease: Duration,
    eviction_interval: Duration,
) -> (String, tokio::sync::watch::Sender<bool>) {
    let backend_trait: Arc<dyn Pkcs11Backend> = backend.clone();
    let ctx = Arc::new(ContextManager::new(lease, 0));
    ctx.populate_slots(&backend_trait).await.expect("populate_slots");

    let svc = Pkcs11ProxyService::insecure_for_tests(ctx.clone(), backend_trait);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://127.0.0.1:{}", addr.port());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Eviction task
    let evict_ctx = ctx.clone();
    let evict_backend: Arc<dyn Pkcs11Backend> = backend;
    let mut evict_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(eviction_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    evict_ctx.evict_expired(&evict_backend).await;
                }
                _ = evict_shutdown.changed() => break,
            }
        }
    });

    // gRPC server
    let server_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let _ = Server::builder()
            .add_service(pkcs11_proxy_ng_proto::Pkcs11ProxyServer::new(svc))
            .serve_with_incoming_shutdown(incoming, async move {
                let mut rx = server_shutdown;
                let _ = rx.changed().await;
            })
            .await;
    });

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(50)).await;

    (endpoint, shutdown_tx)
}

async fn init_client(endpoint: &str) -> Pkcs11Client {
    let mut client = Pkcs11Client::connect(endpoint).await.unwrap();
    client.initialize().await.unwrap();
    client
}

const CKF_SERIAL: CkSessionFlags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);

// ────────────────────────────────────────────────────────────────────
// Backend error injection tests
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn injected_device_error_propagates_through_grpc() {
    let mock = Arc::new(mock(&[0], &[0x00000000]));
    let (endpoint, _shutdown) = mock_daemon(mock.clone()).await;
    let mut client = init_client(&endpoint).await;

    // Normal operation works
    let slots = client.get_slot_list(false).await.unwrap();
    assert!(!slots.is_empty());

    // Inject CKR_DEVICE_ERROR
    mock.inject_error(CkRv::DEVICE_ERROR);

    // Now slot info should return device error
    let err = client.get_slot_info(slots[0]).await.unwrap_err();
    assert_eq!(err, CkRv::DEVICE_ERROR, "CKR_DEVICE_ERROR should propagate");

    // Clear error — should recover
    mock.clear_error();
    let _info = client.get_slot_info(slots[0]).await.unwrap();
}

#[tokio::test]
async fn injected_token_not_present_on_open_session() {
    let mock = Arc::new(mock(&[0], &[0x00000000]));
    let (endpoint, _shutdown) = mock_daemon(mock.clone()).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();

    // Inject CKR_TOKEN_NOT_PRESENT
    mock.inject_error(CkRv::TOKEN_NOT_PRESENT);

    let err = client.open_session(slots[0], CKF_SERIAL).await.unwrap_err();
    assert_eq!(err, CkRv::TOKEN_NOT_PRESENT);
}

#[tokio::test]
async fn injected_error_during_sign_init() {
    let mock = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock.clone()).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Create an object so we have a valid key handle
    let key = client.create_object(session, &[]).await.unwrap();

    // Inject error for sign_init
    mock.inject_error(CkRv::DEVICE_ERROR);

    let mech = CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None };
    let err = client.sign_init(session, &mech, key).await.unwrap_err();
    assert_eq!(err, CkRv::DEVICE_ERROR);

    // Clear and verify session is still usable
    mock.clear_error();
    let _info = client.get_session_info(session).await.unwrap();
}

#[tokio::test]
async fn error_recovery_full_sign_workflow() {
    let mock = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock.clone()).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let key = client.create_object(session, &[]).await.unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None };

    // 1) Normal sign workflow
    client.sign_init(session, &mech, key).await.unwrap();
    let sig = client.sign(session, b"hello").await.unwrap();
    assert!(!sig.is_empty());

    // 2) Inject error mid-workflow: sign_init fails
    mock.inject_error(CkRv::DEVICE_ERROR);
    let err = client.sign_init(session, &mech, key).await.unwrap_err();
    assert_eq!(err, CkRv::DEVICE_ERROR);

    // 3) Clear error, retry — should succeed
    mock.clear_error();
    client.sign_init(session, &mech, key).await.unwrap();
    let sig = client.sign(session, b"hello").await.unwrap();
    assert!(!sig.is_empty(), "Signature should not be empty after recovery");
}

// ────────────────────────────────────────────────────────────────────
// Session quota exhaustion tests
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn session_quota_exhaustion_returns_session_count() {
    let mock = Arc::new(mock(&[0], &[0x00000000]).with_quotas(2, 0));
    let (endpoint, _shutdown) = mock_daemon(mock.clone()).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();

    // Open 2 sessions (at quota)
    let _s1 = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let _s2 = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Third session should hit quota
    let err = client.open_session(slots[0], CKF_SERIAL).await.unwrap_err();
    assert_eq!(err, CkRv::SESSION_COUNT);
}

#[tokio::test]
async fn session_quota_recovers_after_close() {
    let mock = Arc::new(mock(&[0], &[0x00000000]).with_quotas(1, 0));
    let (endpoint, _shutdown) = mock_daemon(mock.clone()).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();

    // Open one session (at quota)
    let s1 = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Can't open another
    let err = client.open_session(slots[0], CKF_SERIAL).await.unwrap_err();
    assert_eq!(err, CkRv::SESSION_COUNT);

    // Close session
    client.close_session(s1).await.unwrap();

    // Now can open again
    let _s2 = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
}

#[tokio::test]
async fn session_lifecycle_sequence_covers_login_logout_finalize_and_reinitialize() {
    let mock = Arc::new(mock(&[0], &[0x00000000]));
    let (endpoint, shutdown) = mock_daemon(mock).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let rw_flags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION | CkSessionFlags::RW_SESSION);

    let session = client.open_session(slots[0], rw_flags).await.unwrap();
    let info = client.get_session_info(session).await.unwrap();
    assert_eq!(info.state, CkSessionState::RwPublic);

    client.login(session, CkUserType::User, Some(b"1234")).await.unwrap();
    let info = client.get_session_info(session).await.unwrap();
    assert_eq!(info.state, CkSessionState::RwUser);

    client.logout(session).await.unwrap();
    let info = client.get_session_info(session).await.unwrap();
    assert_eq!(info.state, CkSessionState::RwPublic);

    client.close_session(session).await.unwrap();
    let stale_after_close = client.get_session_info(session).await.unwrap_err();
    assert_eq!(stale_after_close, CkRv::SESSION_HANDLE_INVALID);

    let session_before_finalize = client.open_session(slots[0], rw_flags).await.unwrap();
    client.login(session_before_finalize, CkUserType::User, Some(b"1234")).await.unwrap();
    client.finalize().await.unwrap();

    let stale_without_context = client.get_session_info(session_before_finalize).await.unwrap_err();
    assert_eq!(stale_without_context, CkRv::CRYPTOKI_NOT_INITIALIZED);

    client.initialize().await.unwrap();
    let stale_after_reinitialize =
        client.get_session_info(session_before_finalize).await.unwrap_err();
    assert_eq!(stale_after_reinitialize, CkRv::SESSION_HANDLE_INVALID);

    let fresh_session = client.open_session(slots[0], rw_flags).await.unwrap();
    let fresh_info = client.get_session_info(fresh_session).await.unwrap();
    assert_eq!(fresh_info.state, CkSessionState::RwPublic);
    client.close_session(fresh_session).await.unwrap();
    client.finalize().await.unwrap();
    let _ = shutdown.send(true);
}

#[tokio::test]
async fn slot_token_lifecycle_tracks_presence_mechanisms_and_slot_scoped_sessions() {
    let mock = Arc::new(mock(&[10, 20], &[0x00000001]));
    mock.set_slot_mechanisms(CkSlotId(10), vec![CkMechanismType::RSA_PKCS]);
    mock.set_slot_mechanisms(CkSlotId(20), vec![CkMechanismType::SHA256]);
    mock.set_token_present(CkSlotId(20), false);

    let (endpoint, _shutdown) = mock_daemon(mock.clone()).await;
    let mut client = init_client(&endpoint).await;

    let present_slots = client.get_slot_list(true).await.unwrap();
    assert_eq!(present_slots.len(), 1, "startup discovery should expose only present tokens");
    let slot_a = present_slots[0];

    let all_slots = client.get_slot_list(false).await.unwrap();
    assert_eq!(all_slots.len(), 2, "all-slot discovery should include empty token slots");
    assert_eq!(all_slots[0], slot_a, "virtual slot for an existing backend slot must be stable");
    let slot_b = all_slots[1];

    let absent_info = client.get_slot_info(slot_b).await.unwrap();
    assert!(
        !absent_info.flags.token_present(),
        "slot info should model token absence without hiding the slot"
    );
    assert_eq!(client.get_token_info(slot_b).await.unwrap_err(), CkRv::TOKEN_NOT_PRESENT);
    assert_eq!(client.get_mechanism_list(slot_b).await.unwrap_err(), CkRv::TOKEN_NOT_PRESENT);

    mock.set_token_present(CkSlotId(20), true);
    let present_after_insert = client.get_slot_list(true).await.unwrap();
    assert_eq!(present_after_insert, all_slots, "token insertion should keep virtual IDs stable");
    assert!(client.get_slot_info(slot_b).await.unwrap().flags.token_present());

    assert_eq!(client.get_mechanism_list(slot_a).await.unwrap(), vec![CkMechanismType::RSA_PKCS]);
    assert_eq!(client.get_mechanism_list(slot_b).await.unwrap(), vec![CkMechanismType::SHA256]);
    assert_eq!(
        client.get_mechanism_info(slot_a, CkMechanismType::SHA256).await.unwrap_err(),
        CkRv::MECHANISM_INVALID
    );
    assert!(client.get_mechanism_info(slot_b, CkMechanismType::SHA256).await.is_ok());

    let session_a = client.open_session(slot_a, CKF_SERIAL).await.unwrap();
    let session_b = client.open_session(slot_b, CKF_SERIAL).await.unwrap();
    assert_eq!(client.get_session_info(session_a).await.unwrap().slot_id, slot_a);
    assert_eq!(client.get_session_info(session_b).await.unwrap().slot_id, slot_b);

    client.close_all_sessions(slot_a).await.unwrap();
    assert_eq!(client.get_session_info(session_a).await.unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
    assert_eq!(client.get_session_info(session_b).await.unwrap().slot_id, slot_b);
}

// ────────────────────────────────────────────────────────────────────
// Context lease expiry under fault conditions
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn lease_expiry_with_mock_backend() {
    let mock = Arc::new(mock(&[0], &[0x00000000]));
    let (endpoint, _shutdown) =
        mock_daemon_with_lease(mock, Duration::from_millis(100), Duration::from_millis(20)).await;

    let mut client = init_client(&endpoint).await;

    // Verify working
    let _slots = client.get_slot_list(false).await.unwrap();

    // Wait for lease to expire
    tokio::time::sleep(Duration::from_millis(250)).await;

    // After lease expiry, context is evicted
    let err = client.get_slot_list(false).await.unwrap_err();
    assert_eq!(err, CkRv::CRYPTOKI_NOT_INITIALIZED);
}

#[tokio::test]
async fn reinitialize_after_lease_expiry() {
    let mock = Arc::new(mock(&[0], &[0x00000000]));
    let (endpoint, _shutdown) =
        mock_daemon_with_lease(mock, Duration::from_millis(100), Duration::from_millis(20)).await;

    let mut client = init_client(&endpoint).await;
    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Wait for lease to expire
    tokio::time::sleep(Duration::from_millis(250)).await;

    let stale_after_eviction = client.get_session_info(session).await.unwrap_err();
    assert_eq!(stale_after_eviction, CkRv::CRYPTOKI_NOT_INITIALIZED);

    // Re-initialize should succeed
    client.initialize().await.unwrap();

    let stale_after_reinitialize = client.get_session_info(session).await.unwrap_err();
    assert_eq!(stale_after_reinitialize, CkRv::SESSION_HANDLE_INVALID);

    // And operations should work again
    let slots = client.get_slot_list(false).await.unwrap();
    assert!(!slots.is_empty());
}

// ────────────────────────────────────────────────────────────────────
// Connection interruption tests
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn daemon_shutdown_causes_transport_error() {
    let mock = Arc::new(mock(&[0], &[0x00000000]));
    let (endpoint, shutdown) = mock_daemon(mock).await;
    let mut client = init_client(&endpoint).await;

    // Normal operation works
    let _slots = client.get_slot_list(false).await.unwrap();

    // Shut down daemon
    let _ = shutdown.send(true);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Calls should fail with transport error
    let result = client.get_slot_list(false).await;
    assert!(result.is_err(), "Should get error after daemon shutdown");
}

#[tokio::test]
async fn multiple_clients_independent_fault_isolation() {
    let mock = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock.clone()).await;

    let mut client_a = init_client(&endpoint).await;
    let mut client_b = init_client(&endpoint).await;

    let slots = client_a.get_slot_list(false).await.unwrap();

    // Both clients open sessions and create objects for key handles
    let session_a = client_a.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let key_a = client_a.create_object(session_a, &[]).await.unwrap();

    let slots_b = client_b.get_slot_list(false).await.unwrap();
    let session_b = client_b.open_session(slots_b[0], CKF_SERIAL).await.unwrap();
    let key_b = client_b.create_object(session_b, &[]).await.unwrap();

    let mech = CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None };

    // Client A starts a sign
    client_a.sign_init(session_a, &mech, key_a).await.unwrap();

    // Inject error — affects new backend calls
    mock.inject_error(CkRv::DEVICE_ERROR);

    // Client B's sign_init fails
    let err = client_b.sign_init(session_b, &mech, key_b).await.unwrap_err();
    assert_eq!(err, CkRv::DEVICE_ERROR);

    // Clear error — Client A's in-flight operation should complete
    mock.clear_error();
    let sig = client_a.sign(session_a, b"data").await.unwrap();
    assert!(!sig.is_empty());
}

// ────────────────────────────────────────────────────────────────────
// Cleanup after errors: sessions close cleanly
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn close_session_succeeds_after_backend_error_recovery() {
    let mock = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock.clone()).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let key = client.create_object(session, &[]).await.unwrap();

    // Inject error
    mock.inject_error(CkRv::DEVICE_ERROR);
    let mech = CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None };
    let _err = client.sign_init(session, &mech, key).await.unwrap_err();

    // Clear error — close_session should work
    mock.clear_error();
    client.close_session(session).await.unwrap();
}

#[tokio::test]
async fn close_all_sessions_cleans_up() {
    let mock = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock.clone()).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();

    // Open multiple sessions
    let _s1 = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let _s2 = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Close all
    client.close_all_sessions(slots[0]).await.unwrap();
}

#[tokio::test]
async fn client_finalize_does_not_finalize_backend_or_other_clients() {
    let mock = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock.clone()).await;
    let mut client_a = init_client(&endpoint).await;
    let mut client_b = init_client(&endpoint).await;

    let slots = client_a.get_slot_list(false).await.unwrap();
    let _session_a = client_a.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let session_b = client_b.open_session(slots[0], CKF_SERIAL).await.unwrap();

    client_a.finalize().await.unwrap();
    assert_eq!(client_a.get_info().await.unwrap_err(), CkRv::CRYPTOKI_NOT_INITIALIZED);

    let info_b = client_b.get_session_info(session_b).await.unwrap();
    assert_eq!(info_b.slot_id, slots[0]);

    client_b.close_session(session_b).await.unwrap();
    client_b.finalize().await.unwrap();
}

#[tokio::test]
async fn finalize_cleans_up_after_backend_errors() {
    let mock = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock.clone()).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let _session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    mock.inject_error(CkRv::DEVICE_ERROR);
    mock.clear_error();

    client.finalize().await.unwrap();
}

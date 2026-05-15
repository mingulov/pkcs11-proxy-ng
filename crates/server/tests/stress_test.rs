//! Stress, soak, and leak detection tests (Item 95).
//!
//! Multi-client workloads against MockBackend to detect leaked sessions,
//! handles, tasks, or file descriptors under sustained load. All tests
//! run without external PKCS#11 modules.

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

fn mock_backend(slots: &[u64], mechs: &[u64]) -> MockBackend {
    MockBackend::new(
        slots.iter().copied().map(CkSlotId).collect(),
        mechs.iter().copied().map(CkMechanismType).collect(),
    )
}

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
// Multi-client concurrent workload
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn concurrent_clients_sign_workload() {
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock).await;

    let mut handles = Vec::new();
    for _ in 0..8 {
        let ep = endpoint.clone();
        handles.push(tokio::spawn(async move {
            let mut client = init_client(&ep).await;
            let slots = client.get_slot_list(false).await.unwrap();
            let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
            let key = client.create_object(session, &[]).await.unwrap();
            let mech = CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None };

            for _ in 0..20 {
                client.sign_init(session, &mech, key).await.unwrap();
                let sig = client.sign(session, b"stress-data").await.unwrap();
                assert!(!sig.is_empty());
            }

            client.close_session(session).await.unwrap();
            client.finalize().await.unwrap();
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn concurrent_clients_encrypt_decrypt_workload() {
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock).await;

    let mut handles = Vec::new();
    for _ in 0..6 {
        let ep = endpoint.clone();
        handles.push(tokio::spawn(async move {
            let mut client = init_client(&ep).await;
            let slots = client.get_slot_list(false).await.unwrap();
            let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
            let key = client.create_object(session, &[]).await.unwrap();
            let mech = CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None };
            let plaintext = b"encrypt-me-please";

            for _ in 0..15 {
                client.encrypt_init(session, &mech, key).await.unwrap();
                let ciphertext = client.encrypt(session, plaintext).await.unwrap();
                assert!(!ciphertext.is_empty());

                client.decrypt_init(session, &mech, key).await.unwrap();
                let result = client.decrypt(session, &ciphertext).await.unwrap();
                assert_eq!(result, plaintext, "round-trip must match");
            }

            client.close_session(session).await.unwrap();
            client.finalize().await.unwrap();
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

// ────────────────────────────────────────────────────────────────────
// Session churn: rapid open/close to detect leaked sessions
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn session_churn_no_leaked_sessions() {
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let slot = slots[0];

    // Rapidly open and close 100 sessions
    for _ in 0..100 {
        let session = client.open_session(slot, CKF_SERIAL).await.unwrap();
        client.close_session(session).await.unwrap();
    }

    // Should still be able to open a new session (no leaked quota)
    let session = client.open_session(slot, CKF_SERIAL).await.unwrap();
    client.close_session(session).await.unwrap();
    client.finalize().await.unwrap();
}

#[tokio::test]
async fn close_all_sessions_churn() {
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let slot = slots[0];

    for _ in 0..50 {
        // Open several sessions, then close all at once
        let _s1 = client.open_session(slot, CKF_SERIAL).await.unwrap();
        let _s2 = client.open_session(slot, CKF_SERIAL).await.unwrap();
        let _s3 = client.open_session(slot, CKF_SERIAL).await.unwrap();
        client.close_all_sessions(slot).await.unwrap();
    }

    // Verify clean state
    let session = client.open_session(slot, CKF_SERIAL).await.unwrap();
    client.close_session(session).await.unwrap();
    client.finalize().await.unwrap();
}

// ────────────────────────────────────────────────────────────────────
// Object handle churn: create/destroy to detect leaked handles
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn object_handle_churn_no_leaked_handles() {
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Rapidly create and destroy 100 objects
    for _ in 0..100 {
        let obj = client.create_object(session, &[]).await.unwrap();
        client.destroy_object(session, obj).await.unwrap();
    }

    // Should still be able to create objects
    let obj = client.create_object(session, &[]).await.unwrap();
    client.destroy_object(session, obj).await.unwrap();

    client.close_session(session).await.unwrap();
    client.finalize().await.unwrap();
}

// ────────────────────────────────────────────────────────────────────
// Context churn: rapid initialize/finalize cycles
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn initialize_finalize_churn() {
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock).await;

    let mut client = Pkcs11Client::connect(&endpoint).await.unwrap();

    for _ in 0..50 {
        client.initialize().await.unwrap();
        let slots = client.get_slot_list(false).await.unwrap();
        assert!(!slots.is_empty());
        client.finalize().await.unwrap();
    }
}

// ────────────────────────────────────────────────────────────────────
// Lease expiry under concurrent load
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn concurrent_clients_with_lease_expiry() {
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) =
        mock_daemon_with_lease(mock, Duration::from_millis(200), Duration::from_millis(30)).await;

    let mut handles = Vec::new();
    for _ in 0..4 {
        let ep = endpoint.clone();
        handles.push(tokio::spawn(async move {
            let mut client = init_client(&ep).await;

            // Work for a bit
            for _ in 0..5 {
                let _ = client.get_slot_list(false).await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            // Wait for lease to expire
            tokio::time::sleep(Duration::from_millis(300)).await;

            // Should get CKR_CRYPTOKI_NOT_INITIALIZED
            let err = client.get_slot_list(false).await.unwrap_err();
            assert_eq!(err, CkRv::CRYPTOKI_NOT_INITIALIZED);

            // Re-initialize should work
            client.initialize().await.unwrap();
            let slots = client.get_slot_list(false).await.unwrap();
            assert!(!slots.is_empty());
            client.finalize().await.unwrap();
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

// ────────────────────────────────────────────────────────────────────
// Concurrent reconnect stress
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn concurrent_reconnect_stress() {
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock).await;

    // 10 clients each connecting, doing work, disconnecting, reconnecting
    let mut handles = Vec::new();
    for _ in 0..10 {
        let ep = endpoint.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..5 {
                let mut client = init_client(&ep).await;
                let slots = client.get_slot_list(false).await.unwrap();
                let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
                client.close_session(session).await.unwrap();
                client.finalize().await.unwrap();
                // Drop client, reconnect next iteration
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

// ────────────────────────────────────────────────────────────────────
// Mixed operations under concurrent load
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mixed_operations_concurrent() {
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(mock).await;

    let mut handles = Vec::new();

    // Sign workers
    for _ in 0..3 {
        let ep = endpoint.clone();
        handles.push(tokio::spawn(async move {
            let mut client = init_client(&ep).await;
            let slots = client.get_slot_list(false).await.unwrap();
            let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
            let key = client.create_object(session, &[]).await.unwrap();
            let mech = CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None };

            for _ in 0..10 {
                client.sign_init(session, &mech, key).await.unwrap();
                client.sign(session, b"data").await.unwrap();
            }
            client.close_session(session).await.unwrap();
            client.finalize().await.unwrap();
        }));
    }

    // Digest workers
    for _ in 0..3 {
        let ep = endpoint.clone();
        handles.push(tokio::spawn(async move {
            let mut client = init_client(&ep).await;
            let slots = client.get_slot_list(false).await.unwrap();
            let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
            let mech = CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None };

            for _ in 0..10 {
                client.digest_init(session, &mech).await.unwrap();
                client.digest(session, b"data").await.unwrap();
            }
            client.close_session(session).await.unwrap();
            client.finalize().await.unwrap();
        }));
    }

    // Random workers
    for _ in 0..2 {
        let ep = endpoint.clone();
        handles.push(tokio::spawn(async move {
            let mut client = init_client(&ep).await;
            let slots = client.get_slot_list(false).await.unwrap();
            let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

            for _ in 0..10 {
                let random = client.generate_random(session, 32).await.unwrap();
                assert_eq!(random.len(), 32);
            }
            client.close_session(session).await.unwrap();
            client.finalize().await.unwrap();
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

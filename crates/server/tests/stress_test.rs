//! Stress, soak, and leak detection tests (Item 95).
//!
//! Multi-client workloads against MockBackend to detect leaked sessions,
//! handles, or file descriptors under sustained load. All tests run
//! without external PKCS#11 modules.
//!
//! Leak accounting (W1-C2-07): each test snapshots backend session/object
//! gauges plus the process FD count before its workload and asserts they
//! return to baseline afterwards — liveness alone ("a new session still
//! opens") cannot catch slow leaks. Tokio task counts are not observable
//! on stable Rust (a task census needs `tokio_unstable` runtime metrics);
//! leaked tasks that pin blocking threads or sockets surface via the FD
//! gauge instead.

use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

mod common_3x;
use common_3x::{init_client, mock as mock_backend, mock_daemon_with_lease};

/// Spin up a mock daemon with this test file's default lease (300s) and
/// eviction interval (100ms). For non-default leases call
/// `common_3x::mock_daemon_with_lease` directly.
async fn mock_daemon(backend: Arc<MockBackend>) -> (String, tokio::sync::watch::Sender<bool>) {
    mock_daemon_with_lease(backend, Duration::from_secs(300), Duration::from_millis(100)).await
}

const CKF_SERIAL: CkSessionFlags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);

// ────────────────────────────────────────────────────────────────────
// Leak accounting (W1-C2-07)
// ────────────────────────────────────────────────────────────────────

/// Serializes FD-accounted tests: FD counts are process-global, so two
/// tests running on libtest threads at once would pollute each other's
/// baseline. Concurrency *within* a test is unaffected.
static LEAK_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Open file-descriptor count for this process (Linux only).
#[cfg(target_os = "linux")]
fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").map(|entries| entries.count()).unwrap_or(0)
}

/// Resource baseline captured before a workload.
struct LeakSnapshot {
    backend_sessions: usize,
    backend_objects: usize,
    #[cfg(target_os = "linux")]
    fds: usize,
}

impl LeakSnapshot {
    fn capture(mock: &MockBackend) -> Self {
        Self {
            backend_sessions: mock.open_session_count(),
            backend_objects: mock.live_object_count(),
            #[cfg(target_os = "linux")]
            fds: open_fd_count(),
        }
    }

    /// Backend gauges must return exactly to baseline (mock calls settle
    /// synchronously once their RPC completes). FDs close asynchronously
    /// after the client drops, so settle-poll before asserting.
    async fn assert_no_growth(&self, mock: &MockBackend, what: &str) {
        assert_eq!(
            mock.open_session_count(),
            self.backend_sessions,
            "{what}: leaked backend sessions (baseline {}, now {})",
            self.backend_sessions,
            mock.open_session_count()
        );
        assert_eq!(
            mock.live_object_count(),
            self.backend_objects,
            "{what}: leaked backend objects (baseline {}, now {})",
            self.backend_objects,
            mock.live_object_count()
        );
        #[cfg(target_os = "linux")]
        {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                let now = open_fd_count();
                if now <= self.fds || std::time::Instant::now() >= deadline {
                    assert!(
                        now <= self.fds,
                        "{what}: leaked file descriptors (baseline {}, now {now})",
                        self.fds
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Multi-client concurrent workload
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn concurrent_clients_sign_workload() {
    let _leak_guard = LEAK_GUARD.lock().await;
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(Arc::clone(&mock)).await;
    let baseline = LeakSnapshot::capture(&mock);

    let mut handles = Vec::new();
    for _ in 0..8 {
        let ep = endpoint.clone();
        handles.push(tokio::spawn(async move {
            let mut client = init_client(&ep).await;
            let slots = client.get_slot_list(false).await.unwrap();
            let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
            let key = client.create_object(session, Some(&[])).await.unwrap();
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
    baseline.assert_no_growth(&mock, "concurrent_sign").await;
}

#[tokio::test]
async fn concurrent_clients_encrypt_decrypt_workload() {
    let _leak_guard = LEAK_GUARD.lock().await;
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(Arc::clone(&mock)).await;
    let baseline = LeakSnapshot::capture(&mock);

    let mut handles = Vec::new();
    for _ in 0..6 {
        let ep = endpoint.clone();
        handles.push(tokio::spawn(async move {
            let mut client = init_client(&ep).await;
            let slots = client.get_slot_list(false).await.unwrap();
            let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
            let key = client.create_object(session, Some(&[])).await.unwrap();
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
    baseline.assert_no_growth(&mock, "concurrent_encrypt_decrypt").await;
}

// ────────────────────────────────────────────────────────────────────
// Session churn: rapid open/close to detect leaked sessions
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn session_churn_no_leaked_sessions() {
    let _leak_guard = LEAK_GUARD.lock().await;
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(Arc::clone(&mock)).await;
    let baseline = LeakSnapshot::capture(&mock);
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
    drop(client);
    baseline.assert_no_growth(&mock, "session_churn").await;
}

#[tokio::test]
async fn close_all_sessions_churn() {
    let _leak_guard = LEAK_GUARD.lock().await;
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(Arc::clone(&mock)).await;
    let baseline = LeakSnapshot::capture(&mock);
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
    drop(client);
    baseline.assert_no_growth(&mock, "close_all_churn").await;
}

// ────────────────────────────────────────────────────────────────────
// Object handle churn: create/destroy to detect leaked handles
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn object_handle_churn_no_leaked_handles() {
    let _leak_guard = LEAK_GUARD.lock().await;
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(Arc::clone(&mock)).await;
    let baseline = LeakSnapshot::capture(&mock);
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Rapidly create and destroy 100 objects
    for _ in 0..100 {
        let obj = client.create_object(session, Some(&[])).await.unwrap();
        client.destroy_object(session, obj).await.unwrap();
    }

    // Should still be able to create objects
    let obj = client.create_object(session, Some(&[])).await.unwrap();
    client.destroy_object(session, obj).await.unwrap();

    client.close_session(session).await.unwrap();
    client.finalize().await.unwrap();
    drop(client);
    baseline.assert_no_growth(&mock, "object_churn").await;
}

// ────────────────────────────────────────────────────────────────────
// Context churn: rapid initialize/finalize cycles
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn initialize_finalize_churn() {
    let _leak_guard = LEAK_GUARD.lock().await;
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(Arc::clone(&mock)).await;
    let baseline = LeakSnapshot::capture(&mock);

    let mut client = Pkcs11Client::connect(&endpoint).await.unwrap();

    for _ in 0..50 {
        client.initialize().await.unwrap();
        let slots = client.get_slot_list(false).await.unwrap();
        assert!(!slots.is_empty());
        client.finalize().await.unwrap();
    }
    drop(client);
    baseline.assert_no_growth(&mock, "init_finalize_churn").await;
}

// ────────────────────────────────────────────────────────────────────
// Lease expiry under concurrent load
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn concurrent_clients_with_lease_expiry() {
    let _leak_guard = LEAK_GUARD.lock().await;
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon_with_lease(
        Arc::clone(&mock),
        Duration::from_millis(200),
        Duration::from_millis(30),
    )
    .await;
    let baseline = LeakSnapshot::capture(&mock);

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
    baseline.assert_no_growth(&mock, "lease_expiry").await;
}

// ────────────────────────────────────────────────────────────────────
// Concurrent reconnect stress
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn concurrent_reconnect_stress() {
    let _leak_guard = LEAK_GUARD.lock().await;
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(Arc::clone(&mock)).await;
    let baseline = LeakSnapshot::capture(&mock);

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
    baseline.assert_no_growth(&mock, "reconnect").await;
}

// ────────────────────────────────────────────────────────────────────
// Mixed operations under concurrent load
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mixed_operations_concurrent() {
    let _leak_guard = LEAK_GUARD.lock().await;
    let mock = Arc::new(mock_backend(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(Arc::clone(&mock)).await;
    let baseline = LeakSnapshot::capture(&mock);

    let mut handles = Vec::new();

    // Sign workers
    for _ in 0..3 {
        let ep = endpoint.clone();
        handles.push(tokio::spawn(async move {
            let mut client = init_client(&ep).await;
            let slots = client.get_slot_list(false).await.unwrap();
            let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
            let key = client.create_object(session, Some(&[])).await.unwrap();
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
    baseline.assert_no_growth(&mock, "mixed").await;
}

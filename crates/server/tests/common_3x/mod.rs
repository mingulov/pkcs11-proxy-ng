//! Shared test harness for PKCS#11 3.0/3.2 integration tests.
//!
//! Provides `mock()`, `mock_daemon()`, and `init_client()` helpers used by
//! wave1, wave2, and wave6 test modules to avoid copy-pasting ~70 lines of
//! identical setup code.

#![allow(dead_code)]

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

/// Create a `MockBackend` with the given slot IDs and mechanism type IDs.
pub fn mock(slots: &[u64], mechs: &[u64]) -> MockBackend {
    MockBackend::new(
        slots.iter().copied().map(CkSlotId).collect(),
        mechs.iter().copied().map(CkMechanismType).collect(),
    )
}

/// Spin up a gRPC proxy daemon backed by the given `Pkcs11Backend`.
///
/// Returns the endpoint URL and a shutdown sender.  The server runs in a
/// spawned Tokio task and is stopped when the sender is dropped or signalled.
pub async fn mock_daemon(
    backend: Arc<dyn Pkcs11Backend>,
) -> (String, tokio::sync::watch::Sender<bool>) {
    let ctx = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    ctx.populate_slots(&backend).await.expect("populate_slots");

    let svc = Pkcs11ProxyService::insecure_for_tests(ctx, backend);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://127.0.0.1:{}", addr.port());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

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

/// Connect a `Pkcs11Client` and call `initialize()`.
pub async fn init_client(endpoint: &str) -> Pkcs11Client {
    let mut client = Pkcs11Client::connect(endpoint).await.unwrap();
    client.initialize().await.unwrap();
    client
}

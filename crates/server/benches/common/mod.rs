//! Shared daemon harness for the server benches (W1-C3-12).
//!
//! Included via `#[path = "common/mod.rs"]` from each bench file so the
//! ~40-line `start_daemon` setup (plus `mock_backend`) lives in exactly
//! one place instead of copy-pasted across three bench files.
//!
//! The shared `start_daemon` spawns no eviction task: contexts carry
//! 600 s leases that never expire during a bench run, so periodic
//! eviction is irrelevant to every measured path (one former copy had a
//! 60 s eviction ticker; dropping it does not change bench behavior).

use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_types::*;
use tokio::net::TcpListener;
use tonic::transport::Server;

pub fn mock_backend() -> MockBackend {
    MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType(0x00000001)])
}

/// Start an insecure in-process daemon over loopback TCP and return its
/// endpoint plus a shutdown sender. Backed by [`mock_backend`].
pub async fn start_daemon() -> (String, tokio::sync::watch::Sender<bool>) {
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock_backend());
    let ctx = Arc::new(ContextManager::new(Duration::from_secs(600), 0));
    ctx.populate_slots(&backend).await.unwrap();
    let svc = Pkcs11ProxyService::insecure_for_tests(ctx, backend);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://127.0.0.1:{}", addr.port());
    let (tx, rx) = tokio::sync::watch::channel(false);
    let rx2 = rx.clone();
    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let _ = Server::builder()
            .add_service(pkcs11_proxy_ng_proto::Pkcs11ProxyServer::new(svc))
            .serve_with_incoming_shutdown(incoming, async move {
                let mut rx = rx2;
                let _ = rx.changed().await;
            })
            .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _keep_alive_rx = rx;
    (endpoint, tx)
}

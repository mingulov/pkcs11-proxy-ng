//! W1-C11-13: `find-objects` must page past 100 handles.
//!
//! Each test spins an in-process mock daemon (client -> gRPC ->
//! backend), installs a fabricated find-result list, runs the real CLI
//! handler with `verbose = false` (no per-object fetch, so fabricated
//! handles are fine), and asserts on the backend-observed `find_objects`
//! call count.

use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::find_objects;

/// Spin up an in-process gRPC daemon backed by `backend`.
///
/// Returns the endpoint URL and a shutdown sender; the server stops when
/// the sender is dropped. Mirrors `handlers::crypto::tests::mock_daemon`.
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

struct Fixture {
    backend: Arc<MockBackend>,
    client: Pkcs11Client,
    slot: u64,
    _shutdown: tokio::sync::watch::Sender<bool>,
    /// Held open so the created session objects stay live (and visible
    /// to the same context) across the handler's own session.
    _setup_session: CkSessionHandle,
}

async fn fixture() -> Fixture {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
    let (endpoint, shutdown) = mock_daemon(backend.clone()).await;
    let mut client = Pkcs11Client::connect(&endpoint).await.unwrap();
    client.initialize().await.unwrap();
    let slots = client.get_slot_list(false).await.unwrap();
    let setup_session =
        client.open_session(slots[0], CkSessionFlags::SERIAL_SESSION).await.unwrap();
    Fixture {
        backend,
        client,
        slot: slots[0].0,
        _shutdown: shutdown,
        _setup_session: setup_session,
    }
}

/// Create `count` live session objects visible to the fixture context
/// and serve them from find (the mock has no real search; the override
/// list is the search result, and the server filters it by ownership,
/// so the handles must be live and same-context).
async fn seed_visible_objects(fx: &mut Fixture, count: usize) {
    let mut handles = Vec::with_capacity(count);
    for _ in 0..count {
        let handle = fx
            .client
            .create_object(
                fx._setup_session,
                Some(&[CkAttribute {
                    attr_type: CkAttributeType::CLASS,
                    value: Some(CkAttributeValue::Ulong(CkObjectClass::DATA.0)),
                }]),
            )
            .await
            .unwrap();
        handles.push(handle);
    }
    fx.backend.set_find_objects_result(handles);
}

// W1-C11-13: a 250-handle listing pages to exhaustion (100+100+50),
// not silently truncated at 100. Every backend batch is fully visible,
// so backend find calls equal handler find calls.
#[tokio::test]
async fn find_objects_pages_past_100_handles() {
    let mut fx = fixture().await;
    seed_visible_objects(&mut fx, 250).await;
    find_objects(&mut fx.client, fx.slot, Some(SecretBytes::from("1234")), None, false)
        .await
        .expect("find-objects must succeed");
    assert_eq!(
        fx.backend.find_objects_call_count(),
        3,
        "250 handles at page 100 need 3 find calls (100+100+50)"
    );
}

// W1-C11-13: small listings still complete in a single find call.
#[tokio::test]
async fn small_listing_uses_single_find_call() {
    let mut fx = fixture().await;
    seed_visible_objects(&mut fx, 2).await;
    find_objects(&mut fx.client, fx.slot, Some(SecretBytes::from("1234")), None, false)
        .await
        .expect("find-objects must succeed");
    assert_eq!(fx.backend.find_objects_call_count(), 1);
}

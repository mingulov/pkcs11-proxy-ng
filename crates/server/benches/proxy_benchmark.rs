//! Benchmark baselines for core proxy flows (Item 94).
//!
//! Measures end-to-end latency through the gRPC stack using MockBackend.
//! These benchmarks establish baselines; regressions can be caught by
//! comparing `cargo bench` output across commits.
//!
//! Run: `cargo bench --bench proxy_benchmark`

use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tonic::transport::Server;

fn mock_backend() -> MockBackend {
    MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType(0x00000001)])
}

async fn start_daemon(backend: Arc<MockBackend>) -> (String, tokio::sync::watch::Sender<bool>) {
    let backend_trait: Arc<dyn Pkcs11Backend> = backend.clone();
    let ctx = Arc::new(ContextManager::new(Duration::from_secs(600), 0));
    ctx.populate_slots(&backend_trait).await.unwrap();

    let svc = Pkcs11ProxyService::insecure_for_tests(ctx.clone(), backend_trait);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://127.0.0.1:{}", addr.port());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let evict_ctx = ctx;
    let evict_backend: Arc<dyn Pkcs11Backend> = backend;
    let mut evict_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => { evict_ctx.evict_expired(&evict_backend).await; }
                _ = evict_shutdown.changed() => break,
            }
        }
    });

    let server_shutdown = shutdown_rx;
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

const CKF_SERIAL: CkSessionFlags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);

fn bench_initialize_finalize(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(async { start_daemon(Arc::new(mock_backend())).await });

    c.bench_function("initialize_finalize", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut client = Pkcs11Client::connect(&endpoint).await.unwrap();
                client.initialize().await.unwrap();
                client.finalize().await.unwrap();
            });
        });
    });
}

fn bench_get_slot_list(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(async { start_daemon(Arc::new(mock_backend())).await });
    let client = rt.block_on(async {
        let mut c = Pkcs11Client::connect(&endpoint).await.unwrap();
        c.initialize().await.unwrap();
        Arc::new(Mutex::new(c))
    });

    c.bench_function("get_slot_list", |b| {
        b.iter(|| {
            rt.block_on(async {
                client.lock().await.get_slot_list(false).await.unwrap();
            });
        });
    });
}

fn bench_open_close_session(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(async { start_daemon(Arc::new(mock_backend())).await });
    let client = rt.block_on(async {
        let mut c = Pkcs11Client::connect(&endpoint).await.unwrap();
        c.initialize().await.unwrap();
        let slots = c.get_slot_list(false).await.unwrap();
        Arc::new(Mutex::new((c, slots[0])))
    });

    c.bench_function("open_close_session", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut guard = client.lock().await;
                let (ref mut c, slot) = *guard;
                let session = c.open_session(slot, CKF_SERIAL).await.unwrap();
                c.close_session(session).await.unwrap();
            });
        });
    });
}

fn bench_sign(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(async { start_daemon(Arc::new(mock_backend())).await });
    let state = rt.block_on(async {
        let mut c = Pkcs11Client::connect(&endpoint).await.unwrap();
        c.initialize().await.unwrap();
        let slots = c.get_slot_list(false).await.unwrap();
        let session = c.open_session(slots[0], CKF_SERIAL).await.unwrap();
        let key = c.create_object(session, &[]).await.unwrap();
        Arc::new(Mutex::new((c, session, key)))
    });
    let mech = CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None };

    c.bench_function("sign_init_sign", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut guard = state.lock().await;
                let (ref mut c, session, key) = *guard;
                c.sign_init(session, &mech, key).await.unwrap();
                c.sign(session, b"benchmark-data").await.unwrap();
            });
        });
    });
}

fn bench_encrypt_decrypt(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(async { start_daemon(Arc::new(mock_backend())).await });
    let state = rt.block_on(async {
        let mut c = Pkcs11Client::connect(&endpoint).await.unwrap();
        c.initialize().await.unwrap();
        let slots = c.get_slot_list(false).await.unwrap();
        let session = c.open_session(slots[0], CKF_SERIAL).await.unwrap();
        let key = c.create_object(session, &[]).await.unwrap();
        Arc::new(Mutex::new((c, session, key)))
    });
    let mech = CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None };

    c.bench_function("encrypt_decrypt_roundtrip", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut guard = state.lock().await;
                let (ref mut c, session, key) = *guard;
                c.encrypt_init(session, &mech, key).await.unwrap();
                let ct = c.encrypt(session, b"benchmark-data").await.unwrap();
                c.decrypt_init(session, &mech, key).await.unwrap();
                c.decrypt(session, &ct).await.unwrap();
            });
        });
    });
}

fn bench_generate_random(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(async { start_daemon(Arc::new(mock_backend())).await });
    let state = rt.block_on(async {
        let mut c = Pkcs11Client::connect(&endpoint).await.unwrap();
        c.initialize().await.unwrap();
        let slots = c.get_slot_list(false).await.unwrap();
        let session = c.open_session(slots[0], CKF_SERIAL).await.unwrap();
        Arc::new(Mutex::new((c, session)))
    });

    c.bench_function("generate_random_32", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut guard = state.lock().await;
                let (ref mut c, session) = *guard;
                c.generate_random(session, 32).await.unwrap();
            });
        });
    });
}

criterion_group!(
    benches,
    bench_initialize_finalize,
    bench_get_slot_list,
    bench_open_close_session,
    bench_sign,
    bench_encrypt_decrypt,
    bench_generate_random,
);
criterion_main!(benches);

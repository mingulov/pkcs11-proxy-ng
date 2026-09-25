//! Latency histogram for shim→daemon→shim overhead.
//!
//! Runs N C_Sign operations against a real gRPC daemon backed by
//! MockBackend over loopback, records each call's latency in a
//! HdrHistogram, and prints p50/p90/p99/p99.9.
//!
//! Uses MockBackend to keep the backend FFI time near-zero; this is
//! the "shim+daemon+gRPC overhead only" measurement. The
//! direct-SoftHSM2-subtraction measurement lives in
//! `scripts/perf/measure_softhsm_latency.sh`.
//!
//! Run: `cargo bench --bench proxy_latency_histogram -- 10000`
//! (positional arg = sample count; default 10_000).

use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;
use tokio::net::TcpListener;
use tonic::transport::Server;

fn mock_backend() -> MockBackend {
    MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType(0x00000001)])
}

async fn start_daemon() -> (String, tokio::sync::watch::Sender<bool>) {
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

fn main() {
    let n: u64 = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(10_000);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(start_daemon());

    // Hot path: each iteration does sign_init + sign over a session
    // that was set up once. This measures the per-call overhead of
    // the gRPC + service-layer path, not session setup.
    let state = rt.block_on(async {
        let mut c = Pkcs11Client::connect(&endpoint).await.unwrap();
        c.initialize().await.unwrap();
        let slots = c.get_slot_list(false).await.unwrap();
        let session =
            c.open_session(slots[0], CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await.unwrap();
        let key = c.create_object(session, &[]).await.unwrap();
        (c, session, key)
    });
    let mech = CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None };

    let payload = vec![0xABu8; 256];
    let mut hist: Histogram<u64> = Histogram::new(3).unwrap();

    // Single-threaded sequential driver: own the client directly (no Mutex) so
    // each block_on borrows it for the duration of one op and releases on return.
    let (mut client, session, key) = state;

    // Warmup: 100 ops, discarded.
    for _ in 0..100 {
        rt.block_on(async {
            client.sign_init(session, &mech, key).await.unwrap();
            let _ = client.sign(session, &payload).await.unwrap();
        });
    }
    let total_start = Instant::now();
    for _ in 0..n {
        rt.block_on(async {
            let t0 = Instant::now();
            client.sign_init(session, &mech, key).await.unwrap();
            let _sig = client.sign(session, &payload).await.unwrap();
            let elapsed = t0.elapsed().as_micros() as u64;
            hist.record(elapsed).unwrap();
        });
    }
    let total = total_start.elapsed();

    println!(
        "n={n} duration={:.2}s mean_throughput={:.1}ops/s",
        total.as_secs_f64(),
        n as f64 / total.as_secs_f64()
    );
    println!(
        "latency µs: p50={} p90={} p99={} p99.9={} max={}",
        hist.value_at_quantile(0.5),
        hist.value_at_quantile(0.9),
        hist.value_at_quantile(0.99),
        hist.value_at_quantile(0.999),
        hist.max(),
    );

    // Optional JSON dump for downstream graphing.
    if let Ok(path) = env::var("R6_HIST_OUT") {
        use std::io::Write;
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"{{"n":{n},"mean_ops_per_sec":{:.2},"p50_us":{},"p90_us":{},"p99_us":{},"p99_9_us":{},"max_us":{}}}"#,
            n as f64 / total.as_secs_f64(),
            hist.value_at_quantile(0.5),
            hist.value_at_quantile(0.9),
            hist.value_at_quantile(0.99),
            hist.value_at_quantile(0.999),
            hist.max(),
        ).unwrap();
        eprintln!("wrote summary JSON to {path}");
    }
}

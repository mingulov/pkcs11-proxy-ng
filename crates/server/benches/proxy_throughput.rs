//! R6 — throughput at varying queue depth.
//!
//! Drives sustained C_Sign load with N concurrent client tasks
//! (one shared connection per task) for 10 seconds. Reports ops/sec
//! and basic percentiles per QD.
//!
//! Run: `cargo bench --bench proxy_throughput`

use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;
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
    let _keep_alive = rx;
    (endpoint, tx)
}

async fn build_signing_state(endpoint: &str) -> (Pkcs11Client, CkSessionHandle, CkObjectHandle) {
    let mut c = Pkcs11Client::connect(endpoint).await.unwrap();
    c.initialize().await.unwrap();
    let slots = c.get_slot_list(false).await.unwrap();
    let session =
        c.open_session(slots[0], CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await.unwrap();
    let key = c.create_object(session, &[]).await.unwrap();
    (c, session, key)
}

async fn run_qd(endpoint: &str, qd: usize, duration: Duration) -> (u64, Histogram<u64>) {
    let mech = Arc::new(CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None });
    let counter = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let payload = Arc::new(vec![0xABu8; 256]);

    // hdr_histogram is not Send across awaits, so each task records
    // into its own and we merge at the end.
    let mut handles = Vec::with_capacity(qd);
    for _ in 0..qd {
        let endpoint = endpoint.to_owned();
        let mech = mech.clone();
        let payload = payload.clone();
        let counter = counter.clone();
        let stop = stop.clone();
        handles.push(tokio::spawn(async move {
            let (c, session, key) = build_signing_state(&endpoint).await;
            let c = AsyncMutex::new(c);
            let mut hist: Histogram<u64> = Histogram::new(3).unwrap();
            while !stop.load(Ordering::Relaxed) {
                let t0 = Instant::now();
                let mut guard = c.lock().await;
                guard.sign_init(session, &mech, key).await.unwrap();
                let _ = guard.sign(session, &payload).await.unwrap();
                drop(guard);
                hist.record(t0.elapsed().as_micros() as u64).unwrap();
                counter.fetch_add(1, Ordering::Relaxed);
            }
            hist
        }));
    }

    tokio::time::sleep(duration).await;
    stop.store(true, Ordering::Relaxed);

    let mut merged: Histogram<u64> = Histogram::new(3).unwrap();
    for h in handles {
        let task_hist = h.await.unwrap();
        merged.add(&task_hist).unwrap();
    }
    (counter.load(Ordering::Relaxed), merged)
}

fn main() {
    let runtime_secs: u64 = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    let duration = Duration::from_secs(runtime_secs);

    let rt =
        tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(8).build().unwrap();
    let (endpoint, _shutdown) = rt.block_on(start_daemon());

    println!("# proxy_throughput  duration_per_qd={runtime_secs}s");
    println!("# qd\tcount\tops_per_sec\tp50_us\tp99_us\tp99_9_us");

    for &qd in &[1usize, 10, 100] {
        // 1 second of warmup discarded.
        rt.block_on(async {
            let _ = run_qd(&endpoint, qd, Duration::from_secs(1)).await;
        });
        let (count, hist) = rt.block_on(run_qd(&endpoint, qd, duration));
        let ops = count as f64 / runtime_secs as f64;
        println!(
            "{qd}\t{count}\t{:.1}\t{}\t{}\t{}",
            ops,
            hist.value_at_quantile(0.5),
            hist.value_at_quantile(0.99),
            hist.value_at_quantile(0.999),
        );
        // Optional JSON line.
        if let Ok(path) = env::var("R6_THROUGHPUT_OUT") {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).unwrap();
            writeln!(f, r#"{{"qd":{qd},"count":{count},"ops_per_sec":{:.2},"p50_us":{},"p99_us":{},"p99_9_us":{}}}"#,
                ops,
                hist.value_at_quantile(0.5),
                hist.value_at_quantile(0.99),
                hist.value_at_quantile(0.999),
            ).unwrap();
        }
    }
}

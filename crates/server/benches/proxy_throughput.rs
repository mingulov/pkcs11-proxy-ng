// W1-L12-03: test/bench report lines go to stdout by design; the
// workspace lint table denies this sink elsewhere.
#![allow(clippy::print_stdout)]
//! Throughput at varying queue depth.
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
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;
use tokio::sync::Mutex as AsyncMutex;

// W1-C3-12: daemon harness shared with the sibling bench files.
#[path = "common/mod.rs"]
mod common;
use common::start_daemon;

async fn build_signing_state(endpoint: &str) -> (Pkcs11Client, CkSessionHandle, CkObjectHandle) {
    let mut c = Pkcs11Client::connect(endpoint).await.unwrap();
    c.initialize().await.unwrap();
    let slots = c.get_slot_list(false).await.unwrap();
    let session = c.open_session(slots[0], CkSessionFlags::SERIAL_SESSION).await.unwrap();
    let key = c.create_object(session, Some(&[])).await.unwrap();
    (c, session, key)
}

async fn run_qd(endpoint: &str, qd: usize, duration: Duration) -> (u64, Histogram<u64>) {
    let mech = Arc::new(CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None });
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

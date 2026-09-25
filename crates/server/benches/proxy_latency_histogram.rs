// W1-L12-03: report lines go to stdout/stderr by design; the workspace
// lint table denies these sinks elsewhere.
#![allow(clippy::print_stdout, clippy::print_stderr)]
//! Latency histogram for Rust client→daemon round trips.
//!
//! Runs N SignInit + Sign pairs against a real gRPC daemon backed by
//! MockBackend over loopback, records each pair's latency in a
//! HdrHistogram, and prints p50/p90/p99/p99.9.
//!
//! Uses the Rust client directly and MockBackend rather than a native provider.
//! The measurement includes the gRPC/service path and mock execution; it does
//! not load the shim or subtract a direct-provider timing baseline.
//!
//! Run: `cargo bench --bench proxy_latency_histogram -- 10000`
//! (positional arg = sample count; default 10_000).

use std::env;
use std::time::Instant;

use hdrhistogram::Histogram;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

// W1-C3-12: daemon harness shared with the sibling bench files.
#[path = "common/mod.rs"]
mod common;
use common::start_daemon;

fn main() {
    let n: u64 = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(10_000);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (endpoint, _shutdown) = rt.block_on(start_daemon());

    // Hot path: each iteration does sign_init + sign over a session
    // that was set up once. This measures the pair's overhead through
    // the gRPC + service-layer path, not session setup.
    let state = rt.block_on(async {
        let mut c = Pkcs11Client::connect(&endpoint).await.unwrap();
        c.initialize().await.unwrap();
        let slots = c.get_slot_list(false).await.unwrap();
        let session = c.open_session(slots[0], CkSessionFlags::SERIAL_SESSION).await.unwrap();
        let key = c.create_object(session, Some(&[])).await.unwrap();
        (c, session, key)
    });
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };

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

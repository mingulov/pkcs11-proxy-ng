// W1-L12-03: report lines go to stdout/stderr by design; the workspace
// lint table denies these sinks elsewhere.
#![allow(clippy::print_stdout, clippy::print_stderr)]
//! Latency histogram for SignInit + Sign pairs, proxied or direct.
//!
//! Default mode runs N pairs against a real gRPC daemon backed by
//! MockBackend over loopback, recording each pair's latency. `--direct`
//! runs the identical op sequence in-process against MockBackend with no
//! gRPC, giving the direct baseline leg for T1 comparison (same provider
//! and workload identity; only `mode`/`transport` differ).
//!
//! Uses MockBackend rather than a native provider; it does not load the
//! shim. T1 receipts compare direct-vs-proxied here, or baseline-proxy vs
//! candidate-proxy across builds (via `T1_BUILD_TAG`).
//!
//! Run: `cargo bench --bench proxy_latency_histogram -- [--direct] [N]`
//! (N = sample count; default 10_000).

use std::env;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

// W1-C3-12: daemon harness shared with the sibling bench files.
#[path = "common/mod.rs"]
mod common;
use common::start_daemon;

const WORKLOAD: &str = "sign-pair";
const OPERATION: &str = "SignInit+Sign";
const WORKLOAD_REVISION: &str = "sign-pair-v1";
const CORPUS_HASH: &str = "payload-256B-0xAB-fixed";
const WARMUP: u64 = 100;

fn nanos_saturating(elapsed: Duration) -> u64 {
    elapsed.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn push_sample(
    samples: &mut Vec<serde_json::Value>,
    run: &str,
    index: u64,
    mode: &str,
    elapsed: Duration,
    result: Result<(), CkRv>,
    failures: &mut u64,
    hist: &mut Histogram<u64>,
) {
    match result {
        Ok(()) => {
            hist.record(elapsed.as_micros() as u64).unwrap();
            samples.push(common::receipts::sample(
                run,
                "a0",
                &format!("s{index}"),
                WORKLOAD,
                OPERATION,
                mode,
                nanos_saturating(elapsed),
                "success",
                Some(0),
                None,
            ));
        }
        Err(rv) => {
            *failures += 1;
            samples.push(common::receipts::sample(
                run,
                "a0",
                &format!("s{index}"),
                WORKLOAD,
                OPERATION,
                mode,
                nanos_saturating(elapsed),
                "error",
                Some(rv.0),
                None,
            ));
        }
    }
}

fn run_proxied(n: u64) -> (Histogram<u64>, Vec<serde_json::Value>, u64, Duration) {
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

    for _ in 0..WARMUP {
        rt.block_on(async {
            client.sign_init(session, &mech, key).await.unwrap();
            let _ = client.sign(session, &payload).await.unwrap();
        });
    }
    let total_start = Instant::now();
    // T1 samples: every op records an outcome (success/error) instead of
    // aborting on the first failure, so mixed evidence is retained.
    let mut t1_samples: Vec<serde_json::Value> = Vec::new();
    let t1_run = common::receipts::run_id("sign-pair");
    let mut failures: u64 = 0;
    for i in 0..n {
        let (elapsed, result) = rt.block_on(async {
            let t0 = Instant::now();
            let result = async {
                client.sign_init(session, &mech, key).await?;
                let _sig = client.sign(session, &payload).await?;
                Ok::<_, CkRv>(())
            }
            .await;
            (t0.elapsed(), result)
        });
        push_sample(
            &mut t1_samples,
            &t1_run,
            i,
            "proxied",
            elapsed,
            result,
            &mut failures,
            &mut hist,
        );
    }
    (hist, t1_samples, failures, total_start.elapsed())
}

fn run_direct(n: u64) -> (Histogram<u64>, Vec<serde_json::Value>, u64, Duration) {
    // Same op sequence as the proxied leg, minus gRPC: MockBackend driven
    // in-process on one thread. Backend/session/key setup is not measured.
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::SERIAL_SESSION).unwrap();
    let key = backend.create_object(session, Some(&[])).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let payload = vec![0xABu8; 256];

    let mut hist: Histogram<u64> = Histogram::new(3).unwrap();
    for _ in 0..WARMUP {
        backend.sign_init(session, &mech, key).unwrap();
        let _ = backend.sign(session, CkInBuf::Bytes(&payload)).unwrap();
    }
    let total_start = Instant::now();
    let mut t1_samples: Vec<serde_json::Value> = Vec::new();
    let t1_run = common::receipts::run_id("sign-pair");
    let mut failures: u64 = 0;
    for i in 0..n {
        let t0 = Instant::now();
        let result = (|| -> CkResult<()> {
            backend.sign_init(session, &mech, key)?;
            let _sig = backend.sign(session, CkInBuf::Bytes(&payload))?;
            Ok(())
        })();
        push_sample(
            &mut t1_samples,
            &t1_run,
            i,
            "direct",
            t0.elapsed(),
            result,
            &mut failures,
            &mut hist,
        );
    }
    (hist, t1_samples, failures, total_start.elapsed())
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let direct = args.iter().any(|a| a == "--direct");
    let n: u64 =
        args.iter().find(|a| !a.starts_with('-')).and_then(|s| s.parse().ok()).unwrap_or(10_000);
    let mode = if direct { "direct" } else { "proxied" };

    let (hist, t1_samples, failures, total) = if direct { run_direct(n) } else { run_proxied(n) };

    println!(
        "mode={mode} n={n} duration={:.2}s mean_throughput={:.1}ops/s failures={failures}",
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
        writeln!(f, r#"{{"mode":"{mode}","n":{n},"mean_ops_per_sec":{:.2},"p50_us":{},"p90_us":{},"p99_us":{},"p99_9_us":{},"max_us":{}}}"#,
            n as f64 / total.as_secs_f64(),
            hist.value_at_quantile(0.5),
            hist.value_at_quantile(0.9),
            hist.value_at_quantile(0.99),
            hist.value_at_quantile(0.999),
            hist.max(),
        ).unwrap();
        eprintln!("wrote summary JSON to {path}");
    }

    // T1 run receipt for `scripts/perf/compare.py` (opt-in).
    if let Ok(dir) = env::var("T1_RECEIPT_DIR") {
        let manifest = common::receipts::bench_manifest(
            WORKLOAD_REVISION,
            CORPUS_HASH,
            &env::var("T1_BUILD_TAG").unwrap_or_else(|_| "candidate".to_string()),
            mode,
            WARMUP,
            1,
        );
        common::receipts::write_t1_receipt(std::path::Path::new(&dir), &manifest, &t1_samples)
            .unwrap();
        eprintln!("wrote T1 receipt to {dir}");
    }
}

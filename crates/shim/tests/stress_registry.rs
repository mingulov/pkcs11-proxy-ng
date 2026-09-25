//! Concurrency-audit stress test for the `MECHANISM_REGISTRY` swap
//! pattern (`OnceLock<RwLock<Arc<MechanismRegistry>>>`).
//!
//! 16 reader threads spin-loop calling `mechanism_registry()`; one
//! writer thread calls `replace_mechanism_registry()` every ~10 ms
//! for 60 seconds. The test passes if no thread panics, every clone
//! returns a `MechanismRegistry` whose embedded constants match one
//! of the writer-installed values (no torn read), and a tag the
//! writer flips between two known shapes per swap is observed by
//! readers in both states.
//!
//! Runtime is configurable via env to keep CI fast:
//!   * `R7_STRESS_DURATION_SECS` — default 60 in the production
//!     specification; honoured here, with a 5-second floor so a
//!     local `cargo test` invocation isn't unwieldy.
//!   * `R7_STRESS_READER_THREADS` — default 16 per the audit spec.
//!   * `R7_STRESS_WRITER_PERIOD_MS` — default 10 ms per the spec.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use pkcs11_proxy_ng_shim::__test_api::{mechanism_registry, replace_mechanism_registry};
use pkcs11_proxy_ng_types::MechanismRegistry;

/// Two well-known TOML overrides the writer cycles between. Choosing
/// disjoint, easily-checked content (a different mechanism in each
/// parameter shape) lets readers verify they got either snapshot
/// cleanly — i.e., they never observed a half-written hybrid.
const TOML_A: &str = r#"
    discovery_mode = "transparent"
    parameterless = [0xAAAA_AAAA]
    [[params]]
    shape = "gcm"
    mechanisms = [0x1000_0001]
"#;

const TOML_B: &str = r#"
    discovery_mode = "filtered"
    parameterless = [0xBBBB_BBBB]
    [[params]]
    shape = "iv"
    mechanisms = [0x2000_0002]
"#;

fn duration_secs_env(name: &str, default: u64) -> Duration {
    let secs = std::env::var(name).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(default);
    Duration::from_secs(secs.max(5))
}

fn usize_env(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|s| s.parse::<usize>().ok()).unwrap_or(default)
}

fn install(toml: &str, revision: &str) -> MechanismRegistry {
    let mut r =
        MechanismRegistry::load_with_override_str(Some(toml)).expect("override TOML parses");
    r.set_revision(revision.to_string());
    r
}

#[test]
fn registry_swap_16_readers_1_writer_60s() {
    let duration = duration_secs_env("R7_STRESS_DURATION_SECS", 60);
    let reader_threads = usize_env("R7_STRESS_READER_THREADS", 16);
    let writer_period = Duration::from_millis(usize_env("R7_STRESS_WRITER_PERIOD_MS", 10) as u64);

    // Seed with TOML_A so readers don't see an empty registry before
    // the first writer tick (which would panic in `mechanism_registry()`).
    replace_mechanism_registry(install(TOML_A, "rev-a"));

    let stop = Arc::new(AtomicBool::new(false));
    let observed_a = Arc::new(AtomicU64::new(0));
    let observed_b = Arc::new(AtomicU64::new(0));
    let torn_reads = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(reader_threads + 1);

    // Readers.
    for _ in 0..reader_threads {
        let stop = Arc::clone(&stop);
        let obs_a = Arc::clone(&observed_a);
        let obs_b = Arc::clone(&observed_b);
        let torn = Arc::clone(&torn_reads);
        handles.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let snap = mechanism_registry();
                // Determine which snapshot we got by checking a
                // single canary mechanism unique to each. A snapshot
                // that says it's TOML_A *and* contains TOML_B's
                // mechanism would prove a torn read; the Arc swap
                // semantics make that impossible, but we assert it
                // here for the public-facing audit record.
                let saw_a = snap.is_parameterless(0xAAAA_AAAA);
                let saw_b = snap.is_parameterless(0xBBBB_BBBB);
                let saw_gcm = snap.param_shape(0x1000_0001) == Some("gcm");
                let saw_iv = snap.param_shape(0x2000_0002) == Some("iv");

                match (saw_a, saw_b) {
                    (true, false) if saw_gcm && !saw_iv => {
                        obs_a.fetch_add(1, Ordering::Relaxed);
                    }
                    (false, true) if saw_iv && !saw_gcm => {
                        obs_b.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        torn.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // Force the Arc to be dropped here so the reader path
                // isn't accidentally optimised to a borrowed view.
                drop(snap);
            }
        }));
    }

    // Writer.
    {
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            let mut next = TOML_B;
            let mut rev_counter = 0u64;
            while !stop.load(Ordering::Relaxed) {
                rev_counter += 1;
                let label = if std::ptr::eq(next, TOML_A) { "rev-a" } else { "rev-b" };
                let revision = format!("{label}-{rev_counter}");
                let reg = install(next, &revision);
                replace_mechanism_registry(reg);
                next = if std::ptr::eq(next, TOML_A) { TOML_B } else { TOML_A };
                thread::sleep(writer_period);
            }
        }));
    }

    thread::sleep(duration);
    stop.store(true, Ordering::Relaxed);

    for h in handles {
        h.join().expect("worker thread did not panic");
    }

    let a = observed_a.load(Ordering::Relaxed);
    let b = observed_b.load(Ordering::Relaxed);
    let t = torn_reads.load(Ordering::Relaxed);
    println!(
        "stress_registry: observed_a={} observed_b={} torn={} duration={}s",
        a,
        b,
        t,
        duration.as_secs()
    );

    assert_eq!(t, 0, "any torn read is a correctness regression");
    assert!(a > 0, "no reader ever saw the TOML_A snapshot");
    assert!(b > 0, "no reader ever saw the TOML_B snapshot");
}

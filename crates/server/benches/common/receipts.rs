//! T1 run-receipt emission for the server benches.
//!
//! Writes a `manifest.json` plus newline-delimited `samples.jsonl` that the
//! `scripts/perf/compare.py` comparator consumes. The schema contract is
//! pinned by `tests/scripts/test_perf_receipts.py` (static fixtures) and by
//! live bench runs feeding `compare_pair` end to end.
//!
//! Bench legs are mock-backed microbenchmarks (`provider.module == "mock"`);
//! their honest comparison mode is baseline-proxy vs candidate-proxy across
//! builds (`build_id` differs), never direct-vs-provider.

//! Shared bench harness, compiled once per bench target via
//! `#[path = "common/mod.rs"]`: only the T1-emitting benches use this
//! module, so including targets that need just `start_daemon` would
//! otherwise report every helper as dead. Scoped to this module on
//! purpose — the daemon harness itself stays fully linted.
#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

/// Provenance for the tree the bench binary runs from.
pub struct GitIdentity {
    /// Full HEAD sha, or `"unknown"` when git is unavailable.
    pub head: String,
    /// True when `git status --porcelain` reports no changes.
    pub clean: bool,
    /// Null when clean; otherwise a deterministic dirty-tree descriptor
    /// (`dirty-N:<sorted-paths>`, truncated) — identity only, not a patch.
    pub dirty_patch_hash: Option<String>,
}

/// Best-effort git identity; never fails (falls back to `"unknown"`).
pub fn git_identity() -> GitIdentity {
    let head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let status = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    let mut paths: Vec<&str> =
        status.lines().filter_map(|line| line.get(3..)).filter(|p| !p.is_empty()).collect();
    paths.sort_unstable();
    paths.dedup();
    let dirty_patch_hash = if paths.is_empty() {
        None
    } else {
        let mut desc = format!("dirty-{}:", paths.len());
        for (i, path) in paths.iter().take(8).enumerate() {
            if i > 0 {
                desc.push(',');
            }
            desc.push_str(path);
        }
        if paths.len() > 8 {
            desc.push_str(",...");
        }
        Some(desc)
    };
    GitIdentity { head, clean: dirty_patch_hash.is_none(), dirty_patch_hash }
}

/// T1 manifest for a mock-backed bench leg. `mode` is `"direct"` for the
/// in-process leg and `"proxied"` for the gRPC leg; provider/workload
/// identity is deliberately identical so the pair is comparable.
pub fn bench_manifest(
    workload_revision: &str,
    corpus_hash: &str,
    build_tag: &str,
    mode: &str,
    warmup: u64,
    concurrency: u64,
) -> serde_json::Value {
    let git = git_identity();
    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    let head_short = git.head.chars().take(12).collect::<String>();
    serde_json::json!({
        "receipt_version": 1,
        "source_head": git.head,
        "dirty_patch_hash": git.dirty_patch_hash,
        "clean": git.clean,
        "profile": profile,
        "build_id": format!("{profile}-{head_short}-{build_tag}"),
        "target_abi": format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        "provider": {
            "module": "mock",
            "image": "in-process-mock",
            "config_fingerprint": "mock-default",
        },
        "workload": {
            "revision": workload_revision,
            "corpus_hash": corpus_hash,
        },
        "mode": mode,
        "host": {
            "arch": std::env::consts::ARCH,
            "os": std::env::consts::OS,
        },
        "transport": if mode == "direct" { "in-process" } else { "tcp-loopback-insecure" },
        "warmup": warmup,
        "concurrency": concurrency,
    })
}

/// One T1 sample record. `rv_u64` is `None` when the outcome has no RV
/// (success carries `Some(0)`); `native_call_count` stays `None` for
/// mock-backed benches (no native boundary crossed — unavailable, honest).
#[allow(clippy::too_many_arguments)]
pub fn sample(
    run_id: &str,
    attempt_id: &str,
    sample_id: &str,
    workload: &str,
    operation: &str,
    mode: &str,
    duration_ns: u64,
    outcome: &str,
    rv_u64: Option<u64>,
    native_call_count: Option<u64>,
) -> serde_json::Value {
    serde_json::json!({
        "run_id": run_id,
        "attempt_id": attempt_id,
        "sample_id": sample_id,
        "workload": workload,
        "operation": operation,
        "mode": mode,
        "duration_ns": duration_ns,
        "outcome": outcome,
        "rv": rv_u64,
        "native_call_count": native_call_count,
        "censored": false,
    })
}

/// Process-unique run id (pid + start nanos; no uuid dependency).
pub fn run_id(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{prefix}-{}-{nanos}", std::process::id())
}

/// Write `manifest.json` + `samples.jsonl` into `dir` (created if missing).
pub fn write_t1_receipt(
    dir: &Path,
    manifest: &serde_json::Value,
    samples: &[serde_json::Value],
) -> std::io::Result<()> {
    fn json_err(e: serde_json::Error) -> std::io::Error {
        std::io::Error::other(e.to_string())
    }
    std::fs::create_dir_all(dir)?;
    let manifest_json = serde_json::to_string_pretty(manifest).map_err(json_err)?;
    std::fs::write(dir.join("manifest.json"), manifest_json)?;
    let mut jsonl = String::new();
    for sample in samples {
        jsonl.push_str(&serde_json::to_string(sample).map_err(json_err)?);
        jsonl.push('\n');
    }
    std::fs::write(dir.join("samples.jsonl"), jsonl)?;
    Ok(())
}

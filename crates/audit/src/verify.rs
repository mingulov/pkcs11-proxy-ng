//! Audit directory verifier (ADR-0012, G1 Task 4).
//!
//! Reads all rotated JSONL audit files in a directory, replays the SHA-256
//! hash chain, detects gaps, and optionally verifies Ed25519-signed
//! checkpoints against a sidecar file.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::AuditError;
use crate::chain::{GENESIS_HASH, record_hash};
use crate::record::from_jsonl;
use crate::sign::{Checkpoint, Verifier};

/// Summary produced by [`verify_dir`].
#[derive(Debug)]
pub struct VerifyReport {
    /// Number of log files read.
    pub files: usize,
    /// Total audit records parsed across all files.
    pub records: u64,
    /// Sequence number of the first record (0 when empty).
    pub first_seq: u64,
    /// Sequence number of the last record (0 when empty).
    pub last_seq: u64,
    /// `true` if every hash-chain link was valid.
    pub chain_ok: bool,
    /// Missing sequence numbers in the range `0..=last_seq`.
    pub gaps: Vec<u64>,
    /// Number of checkpoints whose signature verified successfully.
    pub checkpoints_verified: u64,
    /// Number of checkpoints whose signature failed verification.
    pub checkpoints_failed: u64,
    /// `true` if signature checking was attempted (key supplied + sidecar present).
    pub signature_checked: bool,
}

/// A single line in `audit.checkpoints.jsonl`.
#[derive(Deserialize)]
struct CheckpointLine {
    seq: u64,
    chain_head_hash: String,
    ts_unix_ms: u64,
    record_count: u64,
    signature: String,
}

/// Verifies all audit log files in `dir`.
///
/// File discovery:
/// - `audit.jsonl` — the active log file.
/// - `audit.<N>.jsonl` — rotated files, where `<N>` is one or more ASCII digits.
///
/// All matching files are read, every line is parsed into an [`AuditRecord`],
/// and records are sorted by `seq` before the chain is replayed.
///
/// If `public_key_hex` is `Some` **and** `dir/audit.checkpoints.jsonl` exists,
/// each checkpoint line is verified against the supplied Ed25519 public key.
///
/// # Errors
///
/// - [`AuditError::Io`] — the directory is unreadable or a file cannot be opened.
/// - [`AuditError::Malformed`] — a JSONL line cannot be parsed.
pub fn verify_dir(dir: &Path, public_key_hex: Option<&str>) -> Result<VerifyReport, AuditError> {
    let log_files = collect_log_files(dir)?;
    let files = log_files.len();

    let mut all_records = Vec::new();
    for path in &log_files {
        let content = fs::read_to_string(path).map_err(|e| AuditError::Io(e.to_string()))?;
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }
            all_records.push(from_jsonl(line)?);
        }
    }

    // Robust: sort by seq regardless of file discovery order.
    all_records.sort_by_key(|r| r.seq);

    let records = all_records.len() as u64;
    let (first_seq, last_seq) = if all_records.is_empty() {
        (0, 0)
    } else {
        (all_records[0].seq, all_records[all_records.len() - 1].seq)
    };

    let (chain_ok, gaps) = replay_chain(&all_records, last_seq);
    let (checkpoints_verified, checkpoints_failed, signature_checked) =
        check_checkpoints(dir, public_key_hex)?;

    Ok(VerifyReport {
        files,
        records,
        first_seq,
        last_seq,
        chain_ok,
        gaps,
        checkpoints_verified,
        checkpoints_failed,
        signature_checked,
    })
}

// --- helpers ----------------------------------------------------------------

/// Returns the paths of all audit log files in `dir`.
fn collect_log_files(dir: &Path) -> Result<Vec<std::path::PathBuf>, AuditError> {
    let entries = fs::read_dir(dir).map_err(|e| AuditError::Io(e.to_string()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| AuditError::Io(e.to_string()))?;
        let name = entry.file_name();
        if is_audit_log(&name.to_string_lossy()) {
            paths.push(entry.path());
        }
    }
    Ok(paths)
}

/// Returns `true` for `audit.jsonl` and `audit.<digits>.jsonl`.
fn is_audit_log(name: &str) -> bool {
    if name == "audit.jsonl" {
        return true;
    }
    if let Some(rest) = name.strip_prefix("audit.")
        && let Some(digits) = rest.strip_suffix(".jsonl")
    {
        return !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

/// Replays the hash chain over `records` (already sorted by seq).
///
/// Returns `(chain_ok, gaps)` where `gaps` lists every missing seq in
/// `0..=last_seq`.
fn replay_chain(records: &[crate::record::AuditRecord], last_seq: u64) -> (bool, Vec<u64>) {
    if records.is_empty() {
        return (true, Vec::new());
    }

    let mut chain_ok = true;
    let mut expected_prev = GENESIS_HASH.to_string();

    let seq_set: HashSet<u64> = records.iter().map(|r| r.seq).collect();

    for rec in records {
        if rec.prev_hash != expected_prev {
            chain_ok = false;
        }
        // Advance the expected tip regardless so we keep walking the chain.
        expected_prev = record_hash(&expected_prev, rec);
    }

    let gaps: Vec<u64> = (0..=last_seq).filter(|s| !seq_set.contains(s)).collect();

    (chain_ok, gaps)
}

/// Reads `dir/audit.checkpoints.jsonl` and verifies each line's signature
/// against `public_key_hex` (if supplied).
///
/// Returns `(verified, failed, signature_checked)`.
fn check_checkpoints(
    dir: &Path,
    public_key_hex: Option<&str>,
) -> Result<(u64, u64, bool), AuditError> {
    let Some(pub_hex) = public_key_hex else {
        return Ok((0, 0, false));
    };

    let cp_path = dir.join("audit.checkpoints.jsonl");
    if !cp_path.exists() {
        return Ok((0, 0, false));
    }

    let verifier = Verifier::from_public_hex(pub_hex)?;
    let content = fs::read_to_string(&cp_path).map_err(|e| AuditError::Io(e.to_string()))?;

    let mut verified = 0u64;
    let mut failed = 0u64;

    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        let cl: CheckpointLine =
            serde_json::from_str(line).map_err(|e| AuditError::Malformed(e.to_string()))?;
        let cp = Checkpoint {
            seq: cl.seq,
            chain_head_hash: cl.chain_head_hash,
            ts_unix_ms: cl.ts_unix_ms,
            record_count: cl.record_count,
        };
        if verifier.verify_checkpoint(&cp, &cl.signature).is_ok() {
            verified += 1;
        } else {
            failed += 1;
        }
    }

    Ok((verified, failed, true))
}

// --- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainState;
    use crate::record::{AuditRecord, EventClass, to_jsonl};
    use crate::sign::Signer;

    fn rec(method: &str, ck_rv: u64) -> AuditRecord {
        AuditRecord {
            seq: 0,
            ts_unix_ms: 1,
            ts_monotonic_ns: 1,
            prev_hash: String::new(),
            request_id: "r".into(),
            identity: Some("uid=1000".into()),
            method: method.into(),
            class: EventClass::Auth,
            slot: Some(0),
            session: Some(1),
            object_ref: None,
            ck_rv,
            latency_us: 5,
        }
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("audit-verify-{}-{}", std::process::id(), tag))
    }

    /// Test 1: valid chain split across two files.
    ///
    /// `audit.1.jsonl` holds seqs 0–1; `audit.jsonl` holds seqs 2–3.
    /// All four records are linked through a single `ChainState`.
    #[test]
    fn valid_chain_split_two_files() {
        let dir = temp_dir("split");
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut r0 = rec("C_Login", 0);
        let mut r1 = rec("C_Logout", 0);
        let mut r2 = rec("C_FindObjects", 0);
        let mut r3 = rec("C_Sign", 0);
        st.append(&mut r0);
        st.append(&mut r1);
        st.append(&mut r2);
        st.append(&mut r3);

        // seqs 0–1 in the rotated file
        fs::write(dir.join("audit.1.jsonl"), format!("{}{}", to_jsonl(&r0), to_jsonl(&r1)))
            .unwrap();
        // seqs 2–3 in the active file
        fs::write(dir.join("audit.jsonl"), format!("{}{}", to_jsonl(&r2), to_jsonl(&r3))).unwrap();

        let report = verify_dir(&dir, None).unwrap();

        assert_eq!(report.files, 2, "should read both files");
        assert_eq!(report.records, 4, "four records total");
        assert_eq!(report.first_seq, 0);
        assert_eq!(report.last_seq, 3);
        assert!(report.chain_ok, "valid chain must be ok");
        assert!(report.gaps.is_empty(), "no gaps in seqs 0–3");
        assert!(!report.signature_checked, "no key supplied");

        fs::remove_dir_all(&dir).unwrap();
    }

    /// Test 2: corrupting a record's `ck_rv` must break the chain.
    #[test]
    fn tampered_record_breaks_chain() {
        let dir = temp_dir("tamper");
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut r0 = rec("C_Login", 0);
        let mut r1 = rec("C_Logout", 0);
        st.append(&mut r0);
        st.append(&mut r1);

        // Write r0 with a flipped ck_rv (tamper after chain construction).
        let mut tampered = r0.clone();
        tampered.ck_rv = 0xFF;
        fs::write(dir.join("audit.jsonl"), format!("{}{}", to_jsonl(&tampered), to_jsonl(&r1)))
            .unwrap();

        let report = verify_dir(&dir, None).unwrap();
        assert!(!report.chain_ok, "tampered record must break chain_ok");

        fs::remove_dir_all(&dir).unwrap();
    }

    /// Test 3: a valid signed checkpoint is counted in `checkpoints_verified`.
    #[test]
    fn signed_checkpoint_verified() {
        const SEED: [u8; 32] = [42u8; 32];

        let dir = temp_dir("signed");
        fs::create_dir_all(&dir).unwrap();

        // Build a 2-record chain.
        let mut st = ChainState::genesis();
        let mut r0 = rec("C_Login", 0);
        let mut r1 = rec("C_Logout", 0);
        st.append(&mut r0);
        let chain_head = st.append(&mut r1);

        fs::write(dir.join("audit.jsonl"), format!("{}{}", to_jsonl(&r0), to_jsonl(&r1))).unwrap();

        // Sign a checkpoint at the chain head.
        let signer = Signer::from_seed_bytes(&SEED).unwrap();
        let cp = Checkpoint {
            seq: r1.seq,
            chain_head_hash: chain_head.clone(),
            ts_unix_ms: 100,
            record_count: 2,
        };
        let sig = signer.sign_checkpoint(&cp);

        let line = serde_json::json!({
            "seq": cp.seq,
            "chain_head_hash": cp.chain_head_hash,
            "ts_unix_ms": cp.ts_unix_ms,
            "record_count": cp.record_count,
            "signature": sig,
        });
        fs::write(
            dir.join("audit.checkpoints.jsonl"),
            format!("{}\n", serde_json::to_string(&line).unwrap()),
        )
        .unwrap();

        let report = verify_dir(&dir, Some(&signer.public_hex())).unwrap();

        assert_eq!(report.checkpoints_verified, 1);
        assert_eq!(report.checkpoints_failed, 0);
        assert!(report.signature_checked);

        fs::remove_dir_all(&dir).unwrap();
    }
}

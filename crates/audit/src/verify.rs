//! Audit directory verifier (ADR-0012, G1 Task 4).
//!
//! Reads all rotated JSONL audit files in a directory, replays the SHA-256
//! hash chain, detects gaps, binds signed checkpoints to the replayed chain,
//! and cross-checks the `audit.anchor.json` seal.
//!
//! # Pruning-aware integrity model
//!
//! Rotated files are pruned once `rotate_keep_files` is exceeded, so the oldest
//! records legitimately disappear from disk. The verifier therefore does **not**
//! force the first retained record's `prev_hash` to [`GENESIS_HASH`]: it takes
//! the first retained record's stored `prev_hash` as the replay baseline and
//! verifies the retained *suffix* of the chain. A pruned prefix shortens the
//! verifiable range (it starts at `first_seq`) but is **not** treated as a gap.
//!
//! Records written after the last checkpoint are hash-chained and anchor-sealed
//! immediately, but become *signature*-sealed only at the next checkpoint. This
//! is expected: the anchor cross-check still detects tampering of those records
//! even before a covering checkpoint exists.
//!
//! Known limit: front-truncation *below the oldest retained checkpoint* cannot
//! be distinguished from legitimate pruning by this verifier alone — only the
//! retained suffix is cryptographically anchored.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::AuditError;
use crate::chain::{GENESIS_HASH, record_hash};
use crate::record::{AuditRecord, from_jsonl};
use crate::sign::{Checkpoint, Verifier};

/// Summary produced by [`verify_dir`].
#[derive(Debug)]
pub struct VerifyReport {
    /// Number of log files read.
    pub files: usize,
    /// Total audit records parsed across all files.
    pub records: u64,
    /// Sequence number of the first retained record (0 when empty).
    pub first_seq: u64,
    /// Sequence number of the last record (0 when empty).
    pub last_seq: u64,
    /// `true` if every retained hash-chain link was valid, the retained range
    /// is contiguous, no checkpoint failed, and the anchor (if any) matches.
    pub chain_ok: bool,
    /// Missing sequence numbers in the retained range `first_seq..=last_seq`.
    /// A pruned prefix (seqs below `first_seq`) is **not** a gap.
    pub gaps: Vec<u64>,
    /// Number of checkpoints that both verified (signature, if checked) and
    /// bound to the replayed chain head at their seq.
    pub checkpoints_verified: u64,
    /// Number of checkpoints that failed signature or content-binding.
    pub checkpoints_failed: u64,
    /// `true` if signature checking was attempted (key supplied + sidecar present).
    pub signature_checked: bool,
    /// `true` if there is no anchor, or the anchor matches the replayed head
    /// and last seq. `false` is a tamper signal (e.g. the tail was altered).
    pub head_matches_anchor: bool,
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

/// The `audit.anchor.json` seal written by the server sink.
///
/// `last_seq` is the *next* seq to be assigned (== the last written record's
/// seq + 1), matching `ChainState::last_seq`.
#[derive(Deserialize)]
struct AnchorFile {
    last_hash: String,
    last_seq: u64,
}

/// Outcome of replaying the retained record suffix.
struct ReplayOutcome {
    /// Every retained record's stored `prev_hash` matched the running head.
    links_ok: bool,
    /// The retained range `first_seq..=last_seq` had no missing seqs.
    contiguous: bool,
    /// Missing seqs within the retained range.
    gaps: Vec<u64>,
    /// Replayed chain head hash keyed by record seq (for checkpoint binding).
    seq_to_hash: HashMap<u64, String>,
    /// The chain head after replaying the last retained record.
    head: String,
}

/// Verifies all audit log files in `dir`.
///
/// File discovery:
/// - `audit.jsonl` — the active log file.
/// - `audit.<N>.jsonl` — rotated files, where `<N>` is one or more ASCII digits.
///
/// All matching files are read, every line is parsed into an [`AuditRecord`],
/// and records are sorted by `seq` before the retained suffix is replayed from
/// the first retained record's stored `prev_hash` (pruning-aware baseline).
///
/// Checkpoints in `dir/audit.checkpoints.jsonl` (if present) are bound to the
/// replayed chain head at their seq; when `public_key_hex` is `Some` their
/// Ed25519 signature is also verified. `dir/audit.anchor.json` (if present) is
/// cross-checked against the replayed head as a tamper signal.
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

    let replay = replay_chain(&all_records, first_seq, last_seq);

    let (checkpoints_verified, checkpoints_failed, signature_checked) = check_checkpoints(
        dir,
        public_key_hex,
        first_seq,
        last_seq,
        !all_records.is_empty(),
        &replay.seq_to_hash,
    )?;

    let (anchor_present, anchor_ok) =
        check_anchor(dir, all_records.is_empty(), last_seq, &replay.head)?;
    let head_matches_anchor = !anchor_present || anchor_ok;

    let chain_ok =
        replay.links_ok && replay.contiguous && checkpoints_failed == 0 && head_matches_anchor;

    Ok(VerifyReport {
        files,
        records,
        first_seq,
        last_seq,
        chain_ok,
        gaps: replay.gaps,
        checkpoints_verified,
        checkpoints_failed,
        signature_checked,
        head_matches_anchor,
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

/// Replays the retained record suffix (already sorted by seq).
///
/// The baseline is the **first retained record's stored `prev_hash`** — not
/// [`GENESIS_HASH`] — so a legitimately pruned prefix does not fail the replay.
/// Gaps are computed over `first_seq..=last_seq` only.
fn replay_chain(records: &[AuditRecord], first_seq: u64, last_seq: u64) -> ReplayOutcome {
    if records.is_empty() {
        return ReplayOutcome {
            links_ok: true,
            contiguous: true,
            gaps: Vec::new(),
            seq_to_hash: HashMap::new(),
            head: GENESIS_HASH.to_string(),
        };
    }

    let mut links_ok = true;
    // Pruning-aware baseline: trust the retained prefix boundary.
    let mut expected_prev = records[0].prev_hash.clone();
    let mut seq_to_hash: HashMap<u64, String> = HashMap::with_capacity(records.len());

    for rec in records {
        if rec.prev_hash != expected_prev {
            links_ok = false;
        }
        let h = record_hash(&expected_prev, rec);
        seq_to_hash.insert(rec.seq, h.clone());
        expected_prev = h;
    }

    let seq_set: HashSet<u64> = records.iter().map(|r| r.seq).collect();
    let gaps: Vec<u64> = (first_seq..=last_seq).filter(|s| !seq_set.contains(s)).collect();
    let contiguous = gaps.is_empty();

    ReplayOutcome { links_ok, contiguous, gaps, seq_to_hash, head: expected_prev }
}

/// Reads `dir/audit.checkpoints.jsonl`, binds each in-range checkpoint to the
/// replayed chain head at its seq, and (when a key is supplied) verifies its
/// signature.
///
/// - Checkpoints whose seq is outside the retained range `[first_seq, last_seq]`
///   (a pruned prefix, or beyond the retained tail) cannot be content-bound and
///   are **skipped** — not counted as failures.
/// - An in-range checkpoint counts as verified only when the signature (if
///   checked) **and** the content-binding both hold; otherwise it is a failure.
///
/// Returns `(verified, failed, signature_checked)`.
fn check_checkpoints(
    dir: &Path,
    public_key_hex: Option<&str>,
    first_seq: u64,
    last_seq: u64,
    records_present: bool,
    seq_to_hash: &HashMap<u64, String>,
) -> Result<(u64, u64, bool), AuditError> {
    let cp_path = dir.join("audit.checkpoints.jsonl");
    if !cp_path.exists() {
        return Ok((0, 0, false));
    }

    let verifier = match public_key_hex {
        Some(pub_hex) => Some(Verifier::from_public_hex(pub_hex)?),
        None => None,
    };
    let signature_checked = verifier.is_some();
    let content = fs::read_to_string(&cp_path).map_err(|e| AuditError::Io(e.to_string()))?;

    let mut verified = 0u64;
    let mut failed = 0u64;

    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        let cl: CheckpointLine =
            serde_json::from_str(line).map_err(|e| AuditError::Malformed(e.to_string()))?;

        // Only checkpoints that bind to a retained record are evaluated.
        if !records_present || cl.seq < first_seq || cl.seq > last_seq {
            continue;
        }

        // (a) Signature — only when a key was supplied.
        let sig_ok = match &verifier {
            Some(v) => {
                let cp = Checkpoint {
                    seq: cl.seq,
                    chain_head_hash: cl.chain_head_hash.clone(),
                    ts_unix_ms: cl.ts_unix_ms,
                    record_count: cl.record_count,
                };
                v.verify_checkpoint(&cp, &cl.signature).is_ok()
            }
            None => true,
        };

        // (b) Content-binding to the replayed chain head at this seq.
        let binding_ok = seq_to_hash.get(&cl.seq).is_some_and(|h| *h == cl.chain_head_hash);

        if sig_ok && binding_ok {
            verified += 1;
        } else {
            failed += 1;
        }
    }

    Ok((verified, failed, signature_checked))
}

/// Cross-checks `dir/audit.anchor.json` against the replayed chain.
///
/// Returns `(anchor_present, anchor_ok)`. When an anchor is present it must
/// match both the replayed head hash and the next-seq (`last_seq + 1`); any
/// mismatch is a tamper signal (e.g. the last record was altered).
fn check_anchor(
    dir: &Path,
    records_empty: bool,
    last_seq: u64,
    head: &str,
) -> Result<(bool, bool), AuditError> {
    let anchor_path = dir.join("audit.anchor.json");
    if !anchor_path.exists() {
        return Ok((false, true));
    }
    let data = fs::read(&anchor_path).map_err(|e| AuditError::Io(e.to_string()))?;
    let anchor: AnchorFile =
        serde_json::from_slice(&data).map_err(|e| AuditError::Malformed(e.to_string()))?;

    if records_empty {
        // No retained records: the only self-consistent anchor is genesis.
        let ok = anchor.last_hash == GENESIS_HASH && anchor.last_seq == 0;
        return Ok((true, ok));
    }

    // `anchor.last_seq` is the next slot, i.e. the last record's seq + 1.
    let head_ok = anchor.last_hash == head;
    let seq_ok = anchor.last_seq == last_seq + 1;
    Ok((true, head_ok && seq_ok))
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

    /// Write a minimal `audit.anchor.json` (the format the server sink emits).
    fn write_test_anchor(dir: &std::path::Path, last_hash: &str, last_seq: u64) {
        let j = serde_json::json!({ "last_hash": last_hash, "last_seq": last_seq });
        fs::write(dir.join("audit.anchor.json"), serde_json::to_vec(&j).unwrap()).unwrap();
    }

    /// Write a signed checkpoint line to `audit.checkpoints.jsonl`.
    fn write_checkpoint(dir: &std::path::Path, signer: &Signer, cp: &Checkpoint) {
        let sig = signer.sign_checkpoint(cp);
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

    /// Test 4 (fix): a pruned prefix does not fail verification.
    ///
    /// Build seqs 0..=5 across three files, delete the oldest rotated file
    /// (dropping seqs 0 and 1), and write a matching anchor for the head. The
    /// verifier must accept the retained suffix (seqs 2..=5) with no gaps.
    #[test]
    fn pruned_prefix_verifies_ok() {
        let dir = temp_dir("pruned");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut recs: Vec<AuditRecord> = (0..6).map(|_| rec("C_Op", 0)).collect();
        for r in recs.iter_mut() {
            st.append(r);
        }

        fs::write(
            dir.join("audit.1.jsonl"),
            format!("{}{}", to_jsonl(&recs[0]), to_jsonl(&recs[1])),
        )
        .unwrap();
        fs::write(
            dir.join("audit.2.jsonl"),
            format!("{}{}", to_jsonl(&recs[2]), to_jsonl(&recs[3])),
        )
        .unwrap();
        fs::write(dir.join("audit.jsonl"), format!("{}{}", to_jsonl(&recs[4]), to_jsonl(&recs[5])))
            .unwrap();
        // Anchor seals the head after the last record; last_seq is the next slot.
        write_test_anchor(&dir, &st.last_hash, st.last_seq);

        // Prune the oldest rotated file (seqs 0 and 1 disappear).
        fs::remove_file(dir.join("audit.1.jsonl")).unwrap();

        let report = verify_dir(&dir, None).unwrap();
        assert!(report.chain_ok, "pruned prefix must still verify: {report:?}");
        assert_eq!(report.first_seq, 2, "first retained seq is 2 after pruning");
        assert_eq!(report.last_seq, 5);
        assert!(report.gaps.is_empty(), "a pruned prefix is not a gap: {:?}", report.gaps);
        assert!(report.head_matches_anchor);

        fs::remove_dir_all(&dir).ok();
    }

    /// Test 5 (fix): altering the LAST record is caught by the anchor even
    /// though no subsequent link exists to break.
    #[test]
    fn tail_tamper_detected_via_anchor() {
        let dir = temp_dir("tail-tamper");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut recs: Vec<AuditRecord> = (0..3).map(|_| rec("C_Op", 0)).collect();
        for r in recs.iter_mut() {
            st.append(r);
        }

        // Tamper the LAST record after the chain (and anchor) were computed.
        let mut tampered_last = recs[2].clone();
        tampered_last.ck_rv = 0xFF;

        fs::write(
            dir.join("audit.jsonl"),
            format!("{}{}{}", to_jsonl(&recs[0]), to_jsonl(&recs[1]), to_jsonl(&tampered_last)),
        )
        .unwrap();
        // Anchor reflects the ORIGINAL (untampered) head.
        write_test_anchor(&dir, &st.last_hash, st.last_seq);

        let report = verify_dir(&dir, None).unwrap();
        assert!(!report.head_matches_anchor, "anchor must not match a tampered tail");
        assert!(!report.chain_ok, "tail tamper must fail chain_ok via anchor mismatch");

        fs::remove_dir_all(&dir).ok();
    }

    /// Test 6 (fix): a signed checkpoint binds to chain content, so tampering a
    /// record covered by the checkpoint is detected even if the signature over
    /// the (unchanged) checkpoint fields still verifies.
    #[test]
    fn checkpoint_binding_detects_covered_tamper() {
        const SEED: [u8; 32] = [9u8; 32];

        let dir = temp_dir("cp-binding");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let signer = Signer::from_seed_bytes(&SEED).unwrap();

        let mut st = ChainState::genesis();
        let mut recs: Vec<AuditRecord> = (0..5).map(|_| rec("C_Op", 0)).collect();
        for r in recs.iter_mut() {
            st.append(r);
        }

        // Checkpoint at S = 2, over the genuine head after seq 2.
        let head_at_2 = record_hash(&recs[2].prev_hash, &recs[2]);
        let cp = Checkpoint { seq: 2, chain_head_hash: head_at_2, ts_unix_ms: 50, record_count: 3 };
        write_checkpoint(&dir, &signer, &cp);

        // Tamper a record covered by the checkpoint (seq 1 <= S).
        let mut tampered = recs[1].clone();
        tampered.ck_rv = 0x77;
        fs::write(
            dir.join("audit.jsonl"),
            format!(
                "{}{}{}{}{}",
                to_jsonl(&recs[0]),
                to_jsonl(&tampered),
                to_jsonl(&recs[2]),
                to_jsonl(&recs[3]),
                to_jsonl(&recs[4]),
            ),
        )
        .unwrap();

        let report = verify_dir(&dir, Some(&signer.public_hex())).unwrap();
        assert!(report.checkpoints_failed > 0, "covered tamper must fail checkpoint binding");
        assert!(!report.chain_ok, "covered tamper must fail chain_ok");

        fs::remove_dir_all(&dir).ok();
    }
}

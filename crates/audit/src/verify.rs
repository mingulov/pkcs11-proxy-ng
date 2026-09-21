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

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::AuditError;
use crate::chain::{GENESIS_HASH, record_hash};
use crate::record::{AuditRecord, from_jsonl};
use crate::sign::{Checkpoint, Verifier};

/// Maximum number of missing seqs materialized into [`VerifyReport::gaps`].
///
/// The seq span `first_seq..=last_seq` is attacker-controlled (a 2-line log
/// can claim `{0, u64::MAX}`), so gap enumeration must never iterate the span
/// itself (W1-C12-03). The verifier scans sorted-adjacent records instead and
/// keeps at most this many sample gap seqs; anything more sets
/// [`VerifyReport::gaps_truncated`].
pub const MAX_VERIFY_GAPS: usize = 10_000;

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
    ///
    /// At most [`MAX_VERIFY_GAPS`] entries are materialized; when more seqs
    /// are missing, the oldest samples are kept and [`Self::gaps_truncated`]
    /// is set. `chain_ok` is `false` whenever any seq is missing, truncated
    /// or not.
    pub gaps: Vec<u64>,
    /// `true` when more than [`MAX_VERIFY_GAPS`] seqs are missing, i.e.
    /// [`Self::gaps`] holds only the first samples (W1-C12-03). Always `false`
    /// when [`Self::gaps`] is complete.
    pub gaps_truncated: bool,
    /// Number of checkpoints that both verified (signature, if checked) and
    /// bound to the replayed chain head at their seq.
    pub checkpoints_verified: u64,
    /// Number of checkpoints that failed signature or content-binding. A
    /// missing/empty/entirely-out-of-range sidecar with a key supplied counts
    /// as one failure (fail closed, W1-C12-01).
    pub checkpoints_failed: u64,
    /// `true` if a public key was supplied, i.e. signature verification was
    /// requested (regardless of whether the sidecar was usable).
    pub signature_checked: bool,
    /// `true` if the anchor matches the replayed head and last seq, or the log
    /// is empty and there is no anchor yet. `false` is a tamper signal (e.g.
    /// the tail was altered, or the anchor is missing on a non-empty log —
    /// fail closed, W1-C12-02).
    pub head_matches_anchor: bool,
    /// Total data-plane records dropped (fail-open) as reported by all
    /// `__AUDIT_GAP__` sentinel records in the log.
    ///
    /// Each sentinel is a normal chain link whose `dropped_count` field carries
    /// the number of data-plane records that could not be enqueued since the
    /// previous write. A non-zero value is informational — drops are expected
    /// under sustained data-plane load (fail-open design); the sentinel itself
    /// is tamper-evident because it is chained like any other record.
    pub dropped_records: u64,
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
    /// Missing seqs within the retained range (at most [`MAX_VERIFY_GAPS`]).
    gaps: Vec<u64>,
    /// `true` when more than [`MAX_VERIFY_GAPS`] seqs are missing.
    gaps_truncated: bool,
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
/// Ed25519 signature is also verified. `dir/audit.anchor.json` is cross-checked
/// against the replayed head as a tamper signal; a non-empty log without an
/// anchor fails closed (W1-C12-02).
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

    let replay = replay_chain(&all_records);

    // Tally dropped data-plane records from gap-sentinel entries.
    // A sentinel is any record whose `dropped_count` is `Some(n)`.
    // Using `dropped_count.is_some()` is more robust than matching the
    // `method` string: a sentinel is valid in the chain regardless.
    let dropped_records: u64 = all_records
        .iter()
        .filter_map(|r| r.dropped_count)
        .fold(0u64, |acc, n| acc.saturating_add(n));

    let (checkpoints_verified, checkpoints_failed, signature_checked) = check_checkpoints(
        dir,
        public_key_hex,
        first_seq,
        last_seq,
        !all_records.is_empty(),
        &replay.seq_to_hash,
    )?;

    let head_matches_anchor = check_anchor(dir, all_records.is_empty(), last_seq, &replay.head)?;

    let chain_ok =
        replay.links_ok && replay.contiguous && checkpoints_failed == 0 && head_matches_anchor;

    Ok(VerifyReport {
        files,
        records,
        first_seq,
        last_seq,
        chain_ok,
        gaps: replay.gaps,
        gaps_truncated: replay.gaps_truncated,
        checkpoints_verified,
        checkpoints_failed,
        signature_checked,
        head_matches_anchor,
        dropped_records,
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
/// Gaps are detected over `first_seq..=last_seq` only, via an O(n)
/// sorted-adjacent scan — the untrusted span itself is never iterated
/// (W1-C12-03: `{0, u64::MAX}` would hang/OOM a span enumeration).
fn replay_chain(records: &[AuditRecord]) -> ReplayOutcome {
    if records.is_empty() {
        return ReplayOutcome {
            links_ok: true,
            contiguous: true,
            gaps: Vec::new(),
            gaps_truncated: false,
            seq_to_hash: HashMap::new(),
            head: GENESIS_HASH.to_string(),
        };
    }

    let mut links_ok = true;
    // Pruning-aware baseline: trust the retained prefix boundary.
    let mut expected_prev = records[0].prev_hash.clone();
    let mut seq_to_hash: HashMap<u64, String> = HashMap::with_capacity(records.len());

    for (i, rec) in records.iter().enumerate() {
        // Backward link: this record must point at the running head.
        if rec.prev_hash != expected_prev {
            links_ok = false;
        }
        let h = record_hash(&expected_prev, rec);
        seq_to_hash.insert(rec.seq, h.clone());
        // Forward link (W1-C12-02): this record's hash must be the next
        // record's `prev_hash`. The tail record has no successor; its forward
        // commitment is the anchor, enforced fail-closed by `check_anchor`.
        if let Some(next) = records.get(i + 1)
            && next.prev_hash != h
        {
            links_ok = false;
        }
        expected_prev = h;
    }

    // Gap detection without span enumeration (W1-C12-03): `first_seq` and
    // `last_seq` come from untrusted record seqs, so `(first..=last)` may
    // cover ~2^64 values. Instead, scan sorted-adjacent pairs (O(n) in the
    // record count) and count missing seqs arithmetically, materializing at
    // most MAX_VERIFY_GAPS sample seqs. Duplicate seqs collapse exactly as
    // the old set-membership scan: they hide no missing seqs.
    let mut gaps: Vec<u64> = Vec::new();
    let mut missing_total: u64 = 0;
    for pair in records.windows(2) {
        let (a, b) = (pair[0].seq, pair[1].seq);
        if b <= a {
            continue;
        }
        // a < b, so `b - a - 1` cannot underflow and `a + 1` cannot overflow.
        let missing = b - a - 1;
        if missing == 0 {
            continue;
        }
        missing_total = missing_total.saturating_add(missing);
        let mut s = a + 1;
        while s < b && gaps.len() < MAX_VERIFY_GAPS {
            gaps.push(s);
            s += 1; // s < b <= u64::MAX, so this cannot overflow
        }
    }
    let gaps_truncated = missing_total > gaps.len() as u64;
    let contiguous = missing_total == 0;

    ReplayOutcome { links_ok, contiguous, gaps, gaps_truncated, seq_to_hash, head: expected_prev }
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
/// - Fail-closed (W1-C12-01): when a key is supplied and records are present
///   but **zero** checkpoints could be evaluated — sidecar missing, empty, or
///   entirely out of range — that counts as one failure instead of verifying
///   OK with 0 verified / 0 failed.
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
        // Fail closed only when signature verification was requested against a
        // non-empty log; an unsigned or empty log keeps the previous verdict.
        if public_key_hex.is_some() && records_present {
            return Ok((0, 1, true));
        }
        return Ok((0, 0, public_key_hex.is_some()));
    }

    let verifier = match public_key_hex {
        Some(pub_hex) => Some(Verifier::from_public_hex(pub_hex)?),
        None => None,
    };
    let signature_checked = verifier.is_some();
    let content = fs::read_to_string(&cp_path).map_err(|e| AuditError::Io(e.to_string()))?;

    let mut verified = 0u64;
    let mut failed = 0u64;
    let mut evaluated = 0u64;

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
        evaluated += 1;

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

    // Fail closed: a key was supplied but no checkpoint bound to anything
    // (empty sidecar, or every entry skipped as out of range).
    if verifier.is_some() && records_present && evaluated == 0 {
        failed += 1;
    }

    Ok((verified, failed, signature_checked))
}

/// Cross-checks `dir/audit.anchor.json` against the replayed chain.
///
/// Returns `true` when the anchor state is consistent with the replayed log:
/// - Anchor present: its `last_hash`/`last_seq` must match the replayed head
///   hash and the next-seq (`last_seq + 1`); any mismatch is a tamper signal
///   (e.g. the last record was altered).
/// - Anchor absent: consistent only when the log is empty (nothing sealed
///   yet). A non-empty log without an anchor fails closed (W1-C12-02): the
///   server always writes an anchor alongside records, so absence leaves the
///   tail with no forward commitment (e.g. tail altered + anchor deleted).
fn check_anchor(
    dir: &Path,
    records_empty: bool,
    last_seq: u64,
    head: &str,
) -> Result<bool, AuditError> {
    let anchor_path = dir.join("audit.anchor.json");
    if !anchor_path.exists() {
        return Ok(records_empty);
    }
    let data = fs::read(&anchor_path).map_err(|e| AuditError::Io(e.to_string()))?;
    let anchor: AnchorFile =
        serde_json::from_slice(&data).map_err(|e| AuditError::Malformed(e.to_string()))?;

    if records_empty {
        // No retained records: the only self-consistent anchor is genesis.
        return Ok(anchor.last_hash == GENESIS_HASH && anchor.last_seq == 0);
    }

    // `anchor.last_seq` is the next slot, i.e. the last record's seq + 1.
    let head_ok = anchor.last_hash == head;
    let seq_ok = anchor.last_seq == last_seq + 1;
    Ok(head_ok && seq_ok)
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
            schema_version: crate::record::AUDIT_SCHEMA_VERSION,
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
            dropped_count: None,
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
        // The server always seals records with an anchor (W1-C12-02).
        write_test_anchor(&dir, &st.last_hash, st.last_seq);

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

        // The server always seals records with an anchor (W1-C12-02).
        write_test_anchor(&dir, &st.last_hash, st.last_seq);

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

    // -----------------------------------------------------------------------
    // Tests 8–10: gap-sentinel awareness
    // -----------------------------------------------------------------------

    /// Returns a gap-sentinel record: `method = "__AUDIT_GAP__"`,
    /// `class = System`, `dropped_count = Some(n)`.
    fn sentinel(dropped: u64) -> AuditRecord {
        AuditRecord {
            schema_version: crate::record::AUDIT_SCHEMA_VERSION,
            seq: 0,
            ts_unix_ms: 1,
            ts_monotonic_ns: 1,
            prev_hash: String::new(),
            request_id: "gap".into(),
            identity: None,
            method: "__AUDIT_GAP__".into(),
            class: crate::record::EventClass::System,
            slot: None,
            session: None,
            object_ref: None,
            ck_rv: 0,
            latency_us: 0,
            dropped_count: Some(dropped),
        }
    }

    /// Test 8: sentinels are valid chain links; `dropped_records` is the sum
    /// of all sentinel `dropped_count` values; `chain_ok` remains `true`.
    #[test]
    fn gap_sentinels_tally_dropped_records() {
        let dir = temp_dir("sentinel-tally");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut r0 = rec("C_Login", 0);
        let mut s1 = sentinel(7);
        let mut r2 = rec("C_Logout", 0);
        let mut s3 = sentinel(3);
        let mut r4 = rec("C_Sign", 0);
        st.append(&mut r0);
        st.append(&mut s1);
        st.append(&mut r2);
        st.append(&mut s3);
        st.append(&mut r4);

        fs::write(
            dir.join("audit.jsonl"),
            format!(
                "{}{}{}{}{}",
                to_jsonl(&r0),
                to_jsonl(&s1),
                to_jsonl(&r2),
                to_jsonl(&s3),
                to_jsonl(&r4)
            ),
        )
        .unwrap();

        // The server always seals records with an anchor (W1-C12-02).
        write_test_anchor(&dir, &st.last_hash, st.last_seq);

        let report = verify_dir(&dir, None).unwrap();
        assert!(report.chain_ok, "chain with sentinels must be chain_ok: {report:?}");
        assert_eq!(report.dropped_records, 10, "7 + 3 = 10 dropped records");
        assert_eq!(report.records, 5, "5 records total (including 2 sentinels)");

        fs::remove_dir_all(&dir).ok();
    }

    /// Test 9: tampering a sentinel (altering its `dropped_count`) breaks the
    /// chain — the sentinel is tamper-evident because it is chained normally.
    #[test]
    fn tampered_sentinel_breaks_chain() {
        let dir = temp_dir("sentinel-tamper");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut r0 = rec("C_Login", 0);
        let mut s1 = sentinel(5);
        let mut r2 = rec("C_Logout", 0);
        st.append(&mut r0);
        st.append(&mut s1);
        st.append(&mut r2);

        // Tamper the sentinel's dropped_count AFTER the chain was built.
        let mut tampered_sentinel = s1.clone();
        tampered_sentinel.dropped_count = Some(999);

        fs::write(
            dir.join("audit.jsonl"),
            format!("{}{}{}", to_jsonl(&r0), to_jsonl(&tampered_sentinel), to_jsonl(&r2)),
        )
        .unwrap();

        let report = verify_dir(&dir, None).unwrap();
        assert!(!report.chain_ok, "tampered sentinel must break chain_ok: {report:?}");
    }

    /// Test 10: a log with no sentinels reports `dropped_records == 0` and
    /// `chain_ok == true` (back-compat: existing logs with no sentinels are
    /// unaffected).
    #[test]
    fn no_sentinels_dropped_records_is_zero() {
        let dir = temp_dir("no-sentinel");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut r0 = rec("C_Login", 0);
        let mut r1 = rec("C_FindObjects", 0);
        st.append(&mut r0);
        st.append(&mut r1);

        fs::write(dir.join("audit.jsonl"), format!("{}{}", to_jsonl(&r0), to_jsonl(&r1))).unwrap();

        // The server always seals records with an anchor (W1-C12-02).
        write_test_anchor(&dir, &st.last_hash, st.last_seq);

        let report = verify_dir(&dir, None).unwrap();
        assert!(report.chain_ok, "chain without sentinels must be chain_ok");
        assert_eq!(report.dropped_records, 0, "no sentinels → dropped_records == 0");

        fs::remove_dir_all(&dir).ok();
    }

    /// Test 7: a checkpoint signed with a DIFFERENT key (or byte-corrupted
    /// signature) is detected as a failure when verified with the expected key.
    ///
    /// Sign with `SEED_A`, verify with the public key derived from `SEED_B`.
    /// The signature will be cryptographically invalid → `checkpoints_failed > 0`
    /// and `chain_ok == false`.
    #[test]
    fn wrong_key_checkpoint_fails_verification() {
        const SEED_A: [u8; 32] = [0xAAu8; 32]; // signer seed
        const SEED_B: [u8; 32] = [0xBBu8; 32]; // wrong verifier seed

        let dir = temp_dir("wrong-key");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Build a 3-record chain.
        let mut st = ChainState::genesis();
        let mut recs: Vec<AuditRecord> = (0..3).map(|_| rec("C_Op", 0)).collect();
        for r in recs.iter_mut() {
            st.append(r);
        }
        let head = st.last_hash.clone();

        fs::write(
            dir.join("audit.jsonl"),
            format!("{}{}{}", to_jsonl(&recs[0]), to_jsonl(&recs[1]), to_jsonl(&recs[2])),
        )
        .unwrap();

        // Sign checkpoint with SEED_A.
        let signer_a = Signer::from_seed_bytes(&SEED_A).unwrap();
        let cp =
            Checkpoint { seq: recs[2].seq, chain_head_hash: head, ts_unix_ms: 1, record_count: 3 };
        write_checkpoint(&dir, &signer_a, &cp);

        // Verify with public key from SEED_B — signature must be invalid.
        let public_hex_b = Signer::from_seed_bytes(&SEED_B).unwrap().public_hex();
        let report = verify_dir(&dir, Some(&public_hex_b)).unwrap();

        assert!(
            report.checkpoints_failed > 0,
            "checkpoint signed by wrong key must count as failed; got: {report:?}"
        );
        assert_eq!(report.checkpoints_verified, 0, "no checkpoint must verify with the wrong key");
        assert!(
            !report.chain_ok,
            "wrong-key checkpoint failure must set chain_ok = false; got: {report:?}"
        );
        assert!(report.signature_checked, "signature checking must have been attempted");

        fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // W1-C12-01: fail closed on a bad sidecar when a key is supplied.
    // -----------------------------------------------------------------------

    /// Build a 3-record chained log in a fresh temp dir; returns the dir.
    /// Caller chooses whether to create a checkpoint sidecar.
    fn chained_log_no_sidecar(tag: &str) -> std::path::PathBuf {
        let dir = temp_dir(tag);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut recs: Vec<AuditRecord> = (0..3).map(|_| rec("C_Op", 0)).collect();
        for r in recs.iter_mut() {
            st.append(r);
        }
        fs::write(
            dir.join("audit.jsonl"),
            format!("{}{}{}", to_jsonl(&recs[0]), to_jsonl(&recs[1]), to_jsonl(&recs[2])),
        )
        .unwrap();
        dir
    }

    /// Missing sidecar + key supplied must fail closed (chain_ok=false, failed>0
    /// → CLI exits nonzero) instead of verifying OK with 0 verified / 0 failed.
    #[test]
    fn sidecar_missing_fails_closed_with_key() {
        const SEED: [u8; 32] = [7u8; 32];

        let dir = chained_log_no_sidecar("sidecar-missing");
        // No audit.checkpoints.jsonl created.

        let public_hex = Signer::from_seed_bytes(&SEED).unwrap().public_hex();
        let report = verify_dir(&dir, Some(&public_hex)).unwrap();

        assert!(!report.chain_ok, "missing sidecar with key must fail closed; got: {report:?}");
        assert!(
            report.checkpoints_failed > 0,
            "missing sidecar with key must count a failure; got: {report:?}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// Empty sidecar + key supplied must fail closed.
    #[test]
    fn sidecar_empty_fails_closed_with_key() {
        const SEED: [u8; 32] = [7u8; 32];

        let dir = chained_log_no_sidecar("sidecar-empty");
        fs::write(dir.join("audit.checkpoints.jsonl"), "").unwrap();

        let public_hex = Signer::from_seed_bytes(&SEED).unwrap().public_hex();
        let report = verify_dir(&dir, Some(&public_hex)).unwrap();

        assert!(!report.chain_ok, "empty sidecar with key must fail closed; got: {report:?}");
        assert!(
            report.checkpoints_failed > 0,
            "empty sidecar with key must count a failure; got: {report:?}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// All-out-of-range sidecar + key supplied must fail closed: skipped
    /// checkpoints bind nothing, so 0 verified / 0 failed must not verify OK.
    #[test]
    fn sidecar_out_of_range_fails_closed_with_key() {
        const SEED: [u8; 32] = [7u8; 32];

        let dir = chained_log_no_sidecar("sidecar-oor");
        // Log holds seqs 0..=2; the only checkpoint is beyond the retained tail.
        let signer = Signer::from_seed_bytes(&SEED).unwrap();
        let cp = Checkpoint {
            seq: 999,
            chain_head_hash: "00".repeat(32),
            ts_unix_ms: 1,
            record_count: 3,
        };
        write_checkpoint(&dir, &signer, &cp);

        let report = verify_dir(&dir, Some(&signer.public_hex())).unwrap();

        assert!(
            !report.chain_ok,
            "all-out-of-range sidecar with key must fail closed; got: {report:?}"
        );
        assert!(
            report.checkpoints_failed > 0,
            "all-out-of-range sidecar with key must count a failure; got: {report:?}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // W1-C12-02: validate anchor + forward links (tail-tamper must fail)
    // -----------------------------------------------------------------------

    /// A tampered tail with the anchor DELETED must fail. Before the fix, an
    /// absent anchor mapped to "match" and the backward-only replay had no
    /// successor link to break, so tail-tamper + anchor-delete verified OK.
    #[test]
    fn tail_tamper_without_anchor_fails() {
        let dir = temp_dir("tail-no-anchor");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut recs: Vec<AuditRecord> = (0..3).map(|_| rec("C_Op", 0)).collect();
        for r in recs.iter_mut() {
            st.append(r);
        }

        // Tamper the LAST record; write NO anchor (attacker deleted it).
        let mut tampered_last = recs[2].clone();
        tampered_last.ck_rv = 0xFF;
        fs::write(
            dir.join("audit.jsonl"),
            format!("{}{}{}", to_jsonl(&recs[0]), to_jsonl(&recs[1]), to_jsonl(&tampered_last)),
        )
        .unwrap();

        let report = verify_dir(&dir, None).unwrap();
        assert!(
            !report.head_matches_anchor,
            "absent anchor with records must not match; got: {report:?}"
        );
        assert!(!report.chain_ok, "tail tamper with deleted anchor must fail; got: {report:?}");

        fs::remove_dir_all(&dir).ok();
    }

    /// The server always writes an anchor alongside records, so a non-empty
    /// log without one fails closed even when the records are untampered.
    #[test]
    fn missing_anchor_with_records_fails_closed() {
        let dir = chained_log_no_sidecar("anchor-missing");
        // No audit.anchor.json created.

        let report = verify_dir(&dir, None).unwrap();
        assert!(
            !report.head_matches_anchor,
            "absent anchor with records must not match; got: {report:?}"
        );
        assert!(!report.chain_ok, "missing anchor with records must fail closed; got: {report:?}");

        fs::remove_dir_all(&dir).ok();
    }

    /// Corrupting the anchor itself (hash flipped while the records are
    /// genuine) must fail verification.
    #[test]
    fn tampered_anchor_fails_verification() {
        let dir = temp_dir("anchor-tamper");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut recs: Vec<AuditRecord> = (0..3).map(|_| rec("C_Op", 0)).collect();
        for r in recs.iter_mut() {
            st.append(r);
        }
        fs::write(
            dir.join("audit.jsonl"),
            format!("{}{}{}", to_jsonl(&recs[0]), to_jsonl(&recs[1]), to_jsonl(&recs[2])),
        )
        .unwrap();

        // Anchor with a corrupted hash (genuine seq).
        let mut bad_hash = st.last_hash.clone();
        let first = bad_hash.remove(0);
        bad_hash.insert(0, if first == '0' { '1' } else { '0' });
        write_test_anchor(&dir, &bad_hash, st.last_seq);

        let report = verify_dir(&dir, None).unwrap();
        assert!(!report.head_matches_anchor, "tampered anchor must not match; got: {report:?}");
        assert!(!report.chain_ok, "tampered anchor must fail verification; got: {report:?}");

        fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // W1-C12-03: bound gap enumeration (never iterate untrusted first..=last)
    // -----------------------------------------------------------------------

    /// An adversarial `first..=last` span must not hang the verifier. Two
    /// records `{0, u64::MAX}` made gap enumeration iterate ~2^64 entries
    /// (hang/OOM). Gap materialization is now capped: this must return fast
    /// with a bounded gap list and `chain_ok == false`.
    #[test]
    fn huge_span_gap_enumeration_is_bounded() {
        let dir = temp_dir("huge-span");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut r0 = rec("C_Op", 0);
        r0.seq = 0;
        r0.prev_hash = GENESIS_HASH.to_string();
        let mut r1 = rec("C_Op", 0);
        r1.seq = u64::MAX;
        r1.prev_hash = record_hash(&r0.prev_hash, &r0);

        fs::write(dir.join("audit.jsonl"), format!("{}{}", to_jsonl(&r0), to_jsonl(&r1))).unwrap();

        // Must return (pre-fix this iterated 0..=u64::MAX forever).
        let report = verify_dir(&dir, None).unwrap();
        assert_eq!(report.first_seq, 0);
        assert_eq!(report.last_seq, u64::MAX);
        assert!(
            report.gaps.len() <= MAX_VERIFY_GAPS,
            "gap list must be capped at {MAX_VERIFY_GAPS}; got {}",
            report.gaps.len()
        );
        assert!(report.gaps_truncated, "huge span must set gaps_truncated; got: {report:?}");
        assert!(!report.chain_ok, "huge gap must fail chain_ok; got: {report:?}");

        fs::remove_dir_all(&dir).ok();
    }

    /// A span with more missing seqs than the cap (but small enough to
    /// enumerate naively) must stop materializing at the cap and flag it.
    #[test]
    fn gap_samples_stop_at_cap() {
        let dir = temp_dir("gap-cap");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut r0 = rec("C_Op", 0);
        r0.seq = 0;
        r0.prev_hash = GENESIS_HASH.to_string();
        let mut r1 = rec("C_Op", 0);
        r1.seq = (2 * MAX_VERIFY_GAPS + 1) as u64;
        r1.prev_hash = record_hash(&r0.prev_hash, &r0);

        fs::write(dir.join("audit.jsonl"), format!("{}{}", to_jsonl(&r0), to_jsonl(&r1))).unwrap();

        let report = verify_dir(&dir, None).unwrap();
        assert_eq!(
            report.gaps.len(),
            MAX_VERIFY_GAPS,
            "over-cap span must materialize exactly the cap; got {}",
            report.gaps.len()
        );
        assert!(report.gaps_truncated, "over-cap span must set gaps_truncated; got: {report:?}");
        assert!(!report.chain_ok, "over-cap gap must fail chain_ok; got: {report:?}");

        fs::remove_dir_all(&dir).ok();
    }

    /// Gating pin: legitimate small gaps are still enumerated fully, with no
    /// truncation flag.
    #[test]
    fn small_gaps_enumerated_fully() {
        let dir = temp_dir("small-gap");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut recs: Vec<AuditRecord> = (0..5).map(|_| rec("C_Op", 0)).collect();
        for r in recs.iter_mut() {
            st.append(r);
        }
        // Drop seq 2 → retained seqs {0,1,3,4} with one missing seq.
        fs::write(
            dir.join("audit.jsonl"),
            format!(
                "{}{}{}{}",
                to_jsonl(&recs[0]),
                to_jsonl(&recs[1]),
                to_jsonl(&recs[3]),
                to_jsonl(&recs[4]),
            ),
        )
        .unwrap();

        let report = verify_dir(&dir, None).unwrap();
        assert_eq!(report.gaps, vec![2], "small gap must be enumerated fully; got: {report:?}");
        assert!(!report.gaps_truncated, "small gap must not truncate; got: {report:?}");
        assert!(!report.chain_ok, "gap must fail chain_ok; got: {report:?}");

        fs::remove_dir_all(&dir).ok();
    }

    /// Gating pin: an empty log with no anchor still verifies (nothing sealed
    /// yet) — the W1-C12-02 fail-closed applies only when records are present.
    #[test]
    fn empty_log_without_anchor_still_passes() {
        let dir = temp_dir("empty-no-anchor");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("audit.jsonl"), "").unwrap();

        let report = verify_dir(&dir, None).unwrap();
        assert!(report.chain_ok, "empty log with no anchor must still pass; got: {report:?}");
        assert!(report.head_matches_anchor);

        fs::remove_dir_all(&dir).ok();
    }
}

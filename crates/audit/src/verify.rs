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
use std::io::BufRead as _;
use std::path::Path;

use serde::Deserialize;

use crate::AuditError;
use crate::chain::{GENESIS_HASH, record_hash};
use crate::record::{AUDIT_SCHEMA_VERSION, AuditRecord, from_jsonl};
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
    /// is contiguous, no seq is duplicated, the stored order was
    /// seq-ascending, no checkpoint failed, and the anchor (if any) matches.
    pub chain_ok: bool,
    /// `true` when the stored record order is not seq-ascending, i.e. a
    /// record's seq decreased along the oldest→newest file stream
    /// (W1-C12-12). The writer always appends in ascending seq order, so
    /// disorder means the log was shuffled or spliced after the fact.
    pub unordered: bool,
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
    /// Sequence numbers that occur more than once across all log files, in
    /// ascending order (W1-C12-06). Any duplicate fails verification: a seq
    /// must identify exactly one record.
    ///
    /// At most [`MAX_VERIFY_GAPS`] values are materialized; see
    /// [`Self::duplicates_truncated`].
    pub duplicate_seqs: Vec<u64>,
    /// `true` when more than [`MAX_VERIFY_GAPS`] distinct seqs are
    /// duplicated, i.e. [`Self::duplicate_seqs`] holds only the first
    /// samples. Always `false` when [`Self::duplicate_seqs`] is complete.
    pub duplicates_truncated: bool,
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

/// A single line in `audit.checkpoints.jsonl`: the shared [`Checkpoint`]
/// shape plus the Ed25519 signature over it.
///
/// The checkpoint fields are *not* mirrored here (W1-C12-11): `flatten` keeps
/// one shape definition, so a field added to [`Checkpoint`] is automatically
/// part of both the parsed line and the signed bytes. Signature verification
/// and content binding consume `line.checkpoint` directly — never a
/// field-by-field reconstruction.
#[derive(Deserialize)]
struct CheckpointLine {
    #[serde(flatten)]
    checkpoint: Checkpoint,
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
    /// Total records replayed across all files.
    records: u64,
    /// Sequence number of the first retained record (0 when empty).
    first_seq: u64,
    /// Sequence number of the last retained record (0 when empty).
    last_seq: u64,
    /// Every retained record's stored `prev_hash` matched the running head.
    links_ok: bool,
    /// The retained range `first_seq..=last_seq` had no missing seqs.
    contiguous: bool,
    /// `true` when a record's seq decreased along the stream (stored order
    /// is not seq-ascending).
    unordered: bool,
    /// Missing seqs within the retained range (at most [`MAX_VERIFY_GAPS`]).
    gaps: Vec<u64>,
    /// `true` when more than [`MAX_VERIFY_GAPS`] seqs are missing.
    gaps_truncated: bool,
    /// Seqs occurring more than once (each value once, ascending, at most
    /// [`MAX_VERIFY_GAPS`] samples).
    duplicates: Vec<u64>,
    /// `true` when more than [`MAX_VERIFY_GAPS`] distinct seqs are duplicated.
    duplicates_truncated: bool,
    /// Replayed chain head hash for checkpoint-bound seqs only.
    seq_to_hash: HashMap<u64, String>,
    /// Record `ts_unix_ms` for checkpoint-bound seqs only.
    seq_to_ts: HashMap<u64, u64>,
    /// The chain head after replaying the last retained record.
    head: String,
    /// Total dropped data-plane records tallied from gap sentinels.
    dropped_records: u64,
}

/// Verifies all audit log files in `dir`.
///
/// File discovery:
/// - `audit.jsonl` — the active log file.
/// - `audit.<N>.jsonl` — rotated files, where `<N>` is one or more ASCII digits.
///
/// Files stream oldest→newest (ascending rotation index, active file last)
/// and each file streams line by line through a bounded `BufReader` buffer:
/// no file is ever read fully into memory and records are replayed in a
/// single pass without collecting them into a `Vec` (W1-C12-12). Besides the
/// I/O buffer, memory holds only capped sample lists ([`MAX_VERIFY_GAPS`]
/// gaps/duplicates) plus the replayed hash/ts of seqs a checkpoint actually
/// binds — never the log itself.
///
/// Records replay in stored order from the first retained record's stored
/// `prev_hash` (pruning-aware baseline). The writer always appends in
/// ascending seq order, so stored disorder (a seq decrease along the stream)
/// fails closed via [`VerifyReport::unordered`] instead of being re-sorted
/// into a pass.
///
/// Checkpoints in `dir/audit.checkpoints.jsonl` (if present) are bound to the
/// replayed log at their seq; when `public_key_hex` is `Some` their Ed25519
/// signature is also verified. `dir/audit.anchor.json` is cross-checked
/// against the replayed head as a tamper signal; a non-empty log without an
/// anchor fails closed (W1-C12-02).
///
/// # Errors
///
/// - [`AuditError::Io`] — the directory is unreadable or a file cannot be opened.
/// - [`AuditError::Malformed`] — a JSONL line cannot be parsed, a record's
///   `schema_version` skews from [`AUDIT_SCHEMA_VERSION`], or the anchor's
///   next-seq overflows at `last_seq == u64::MAX`.
pub fn verify_dir(dir: &Path, public_key_hex: Option<&str>) -> Result<VerifyReport, AuditError> {
    let log_files = collect_log_files(dir)?;
    let files = log_files.len();

    // Read the checkpoint sidecar first so the streaming replay only retains
    // the hash/ts of seqs a checkpoint actually binds (bounded memory).
    let sidecar = read_checkpoint_sidecar(dir, public_key_hex)?;
    let mut replay = StreamReplay::new(sidecar.needed_seqs());

    // Single-pass streaming replay: one line in flight at a time.
    for path in &log_files {
        for item in stream_file_records(path)? {
            let rec = item?;
            check_schema_version(&rec)?;
            replay.push(&rec);
        }
    }
    let outcome = replay.finish();

    let (checkpoints_verified, checkpoints_failed, signature_checked) = eval_checkpoints(
        &sidecar,
        outcome.first_seq,
        outcome.last_seq,
        outcome.records > 0,
        &outcome.seq_to_hash,
        &outcome.seq_to_ts,
    );

    let head_matches_anchor =
        check_anchor(dir, outcome.records == 0, outcome.last_seq, &outcome.head)?;

    let chain_ok = outcome.links_ok
        && outcome.contiguous
        && outcome.duplicates.is_empty()
        && !outcome.duplicates_truncated
        && !outcome.unordered
        && checkpoints_failed == 0
        && head_matches_anchor;

    Ok(VerifyReport {
        files,
        records: outcome.records,
        first_seq: outcome.first_seq,
        last_seq: outcome.last_seq,
        chain_ok,
        unordered: outcome.unordered,
        gaps: outcome.gaps,
        gaps_truncated: outcome.gaps_truncated,
        duplicate_seqs: outcome.duplicates,
        duplicates_truncated: outcome.duplicates_truncated,
        checkpoints_verified,
        checkpoints_failed,
        signature_checked,
        head_matches_anchor,
        dropped_records: outcome.dropped_records,
    })
}

// --- helpers ----------------------------------------------------------------

/// Rejects a record whose `schema_version` differs from
/// [`AUDIT_SCHEMA_VERSION`] with a skew error (W1-C12-09).
///
/// `record.rs` promises that verifiers detect format skew by comparing the
/// value they read against this constant; a version the verifier was not
/// built for must fail loudly rather than replay under a guessed shape.
fn check_schema_version(rec: &AuditRecord) -> Result<(), AuditError> {
    if rec.schema_version != AUDIT_SCHEMA_VERSION {
        return Err(AuditError::Malformed(format!(
            "schema version skew at seq {}: found {}, expected {}",
            rec.seq, rec.schema_version, AUDIT_SCHEMA_VERSION
        )));
    }
    Ok(())
}

/// Returns the paths of all audit log files in `dir`, ordered oldest→newest
/// for single-pass streaming replay (W1-C12-12).
fn collect_log_files(dir: &Path) -> Result<Vec<std::path::PathBuf>, AuditError> {
    let entries = fs::read_dir(dir).map_err(|e| AuditError::Io(e.to_string()))?;
    let mut logs: Vec<(String, std::path::PathBuf)> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| AuditError::Io(e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_audit_log(&name) {
            logs.push((name, entry.path()));
        }
    }
    logs.sort_by(|a, b| log_file_order_key(&a.0).cmp(&log_file_order_key(&b.0)));
    Ok(logs.into_iter().map(|(_, path)| path).collect())
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

/// Sort key ordering log files oldest→newest: rotated files by ascending
/// rotation index (the writer mints `max(N) + 1` per rotation, so a higher N
/// is newer), with the active `audit.jsonl` last.
///
/// The index compares length-then-lexicographic, i.e. numerically for
/// digit strings of any length — never parsed, so an absurd index cannot
/// overflow and `audit.10.jsonl` correctly sorts after `audit.2.jsonl`.
fn log_file_order_key(name: &str) -> (u8, usize, &str) {
    if name == "audit.jsonl" {
        return (1, 0, "");
    }
    let digits = name.strip_prefix("audit.").and_then(|r| r.strip_suffix(".jsonl")).unwrap_or("");
    (0, digits.len(), digits)
}

/// Streams the lines of one file through a bounded `BufReader` buffer instead
/// of `fs::read_to_string` (W1-C12-12): peak I/O buffering is O(line),
/// never O(file).
fn stream_lines(
    path: &Path,
) -> Result<impl Iterator<Item = Result<String, AuditError>>, AuditError> {
    let file = fs::File::open(path).map_err(|e| AuditError::Io(e.to_string()))?;
    Ok(std::io::BufReader::new(file).lines().map(|r| r.map_err(|e| AuditError::Io(e.to_string()))))
}

/// Streams the [`AuditRecord`]s of one log file, skipping blank lines.
/// The first malformed line aborts the stream with [`AuditError::Malformed`].
fn stream_file_records(
    path: &Path,
) -> Result<impl Iterator<Item = Result<AuditRecord, AuditError>>, AuditError> {
    Ok(stream_lines(path)?.filter_map(|item| match item {
        Err(e) => Some(Err(e)),
        Ok(line) if line.is_empty() => None,
        Ok(line) => Some(from_jsonl(&line)),
    }))
}

/// Incremental single-pass replay over the oldest→newest record stream
/// (W1-C12-12).
///
/// Only O(1) running state is kept per record (running head, previous seq,
/// capped sample lists): the stream is never collected, so memory stays
/// bounded no matter how large the log directory is. Replayed hashes and
/// timestamps are retained solely for seqs a checkpoint binds (`needed`,
/// collected from the sidecar before the replay starts).
struct StreamReplay {
    /// Seqs whose replayed hash/ts must be retained for checkpoint binding.
    needed: HashSet<u64>,
    records: u64,
    first_seq: u64,
    last_seq: u64,
    links_ok: bool,
    unordered: bool,
    /// Running chain head; `None` until the first record sets the baseline.
    expected_prev: Option<String>,
    prev_seq: Option<u64>,
    gaps: Vec<u64>,
    missing_total: u64,
    duplicates: Vec<u64>,
    dup_values_total: u64,
    seq_to_hash: HashMap<u64, String>,
    seq_to_ts: HashMap<u64, u64>,
    dropped_records: u64,
}

impl StreamReplay {
    fn new(needed: HashSet<u64>) -> Self {
        let cap = needed.len();
        StreamReplay {
            needed,
            records: 0,
            first_seq: 0,
            last_seq: 0,
            links_ok: true,
            unordered: false,
            expected_prev: None,
            prev_seq: None,
            gaps: Vec::new(),
            missing_total: 0,
            duplicates: Vec::new(),
            dup_values_total: 0,
            seq_to_hash: HashMap::with_capacity(cap),
            seq_to_ts: HashMap::with_capacity(cap),
            dropped_records: 0,
        }
    }

    /// Replays one record in stream order.
    ///
    /// The baseline is the **first retained record's stored `prev_hash`** —
    /// not [`GENESIS_HASH`] — so a legitimately pruned prefix does not fail
    /// the replay.
    fn push(&mut self, rec: &AuditRecord) {
        if self.records == 0 {
            // Pruning-aware baseline: trust the retained prefix boundary.
            self.first_seq = rec.seq;
            self.expected_prev = Some(rec.prev_hash.clone());
        } else if let Some(prev) = self.prev_seq {
            // Seq-order analysis over the stream-adjacent pair (W1-C12-03:
            // the untrusted span itself is never iterated).
            if rec.seq < prev {
                // The writer appends in ascending seq order; a decrease
                // means the log was shuffled or spliced — fail closed.
                self.unordered = true;
            } else if rec.seq == prev {
                // W1-C12-06: a run `p == p == ...` yields one adjacent
                // pair per extra occurrence; record the value once, at the
                // run's first pair.
                if self.duplicates.last() != Some(&prev) {
                    self.dup_values_total = self.dup_values_total.saturating_add(1);
                    if self.duplicates.len() < MAX_VERIFY_GAPS {
                        self.duplicates.push(prev);
                    }
                }
            } else {
                // prev < rec.seq, so `rec.seq - prev - 1` cannot underflow
                // and `prev + 1` cannot overflow.
                let missing = rec.seq - prev - 1;
                if missing > 0 {
                    self.missing_total = self.missing_total.saturating_add(missing);
                    let mut s = prev + 1;
                    while s < rec.seq && self.gaps.len() < MAX_VERIFY_GAPS {
                        self.gaps.push(s);
                        s += 1; // s < rec.seq <= u64::MAX: cannot overflow
                    }
                }
            }
        }
        self.prev_seq = Some(rec.seq);
        self.last_seq = rec.seq;
        self.records += 1;

        // Backward link: this record must point at the running head. (This
        // subsumes the old forward-link check (W1-C12-02): record N+1's
        // backward check IS record N's forward check. The tail record has no
        // successor; its forward commitment is the anchor, enforced
        // fail-closed by `check_anchor`.)
        let expected = self.expected_prev.as_deref().unwrap_or("");
        if rec.prev_hash != expected {
            self.links_ok = false;
        }
        let h = record_hash(expected, rec);
        if self.needed.contains(&rec.seq) {
            self.seq_to_hash.insert(rec.seq, h.clone());
            self.seq_to_ts.insert(rec.seq, rec.ts_unix_ms);
        }
        self.expected_prev = Some(h);

        // Tally dropped data-plane records from gap-sentinel entries: any
        // record whose `dropped_count` is `Some(n)` (matching on the field is
        // more robust than matching the `method` string).
        if let Some(n) = rec.dropped_count {
            self.dropped_records = self.dropped_records.saturating_add(n);
        }
    }

    fn finish(self) -> ReplayOutcome {
        let gaps_truncated = self.missing_total > self.gaps.len() as u64;
        let duplicates_truncated = self.dup_values_total > self.duplicates.len() as u64;
        ReplayOutcome {
            records: self.records,
            first_seq: self.first_seq,
            last_seq: self.last_seq,
            links_ok: self.links_ok,
            contiguous: self.missing_total == 0,
            unordered: self.unordered,
            gaps: self.gaps,
            gaps_truncated,
            duplicates: self.duplicates,
            duplicates_truncated,
            seq_to_hash: self.seq_to_hash,
            seq_to_ts: self.seq_to_ts,
            head: self.expected_prev.unwrap_or_else(|| GENESIS_HASH.to_string()),
            dropped_records: self.dropped_records,
        }
    }
}

/// The parsed `audit.checkpoints.jsonl` sidecar plus the verifier built from
/// the supplied public key (if any).
struct CheckpointSidecar {
    lines: Vec<CheckpointLine>,
    verifier: Option<Verifier>,
    signature_checked: bool,
    /// `true` when `audit.checkpoints.jsonl` does not exist.
    missing: bool,
}

impl CheckpointSidecar {
    /// Seqs whose replayed hash/ts the streaming replay must retain so the
    /// post-replay binding can be evaluated (bounded: one entry per sidecar
    /// line, and the sidecar holds one line per checkpoint interval).
    fn needed_seqs(&self) -> HashSet<u64> {
        self.lines.iter().map(|cl| cl.checkpoint.seq).collect()
    }
}

/// Reads and parses `dir/audit.checkpoints.jsonl` (line-streamed, like the
/// log files) and builds the signature verifier when a key is supplied.
///
/// The sidecar is read *before* the log replay so the replay knows which
/// seqs need their hash/ts retained (W1-C12-12); evaluation happens after
/// the replay, once the retained range is known (see [`eval_checkpoints`]).
fn read_checkpoint_sidecar(
    dir: &Path,
    public_key_hex: Option<&str>,
) -> Result<CheckpointSidecar, AuditError> {
    let cp_path = dir.join("audit.checkpoints.jsonl");
    if !cp_path.exists() {
        // A missing sidecar keeps the previous verdict here; the W1-C12-01
        // fail-closed (key supplied + non-empty log) is applied by
        // `eval_checkpoints`, once `records_present` is known.
        return Ok(CheckpointSidecar {
            lines: Vec::new(),
            verifier: None,
            signature_checked: public_key_hex.is_some(),
            missing: true,
        });
    }

    let verifier = match public_key_hex {
        Some(pub_hex) => Some(Verifier::from_public_hex(pub_hex)?),
        None => None,
    };
    let signature_checked = verifier.is_some();

    let mut lines = Vec::new();
    for item in stream_lines(&cp_path)? {
        let line = item?;
        if line.is_empty() {
            continue;
        }
        lines.push(
            serde_json::from_str::<CheckpointLine>(&line)
                .map_err(|e| AuditError::Malformed(e.to_string()))?,
        );
    }

    Ok(CheckpointSidecar { lines, verifier, signature_checked, missing: false })
}

/// Binds each in-range checkpoint to the replayed log at its seq, and (when
/// a key was supplied) verifies its signature.
///
/// - Checkpoints whose seq is outside the retained range `[first_seq, last_seq]`
///   (a pruned prefix, or beyond the retained tail) cannot be content-bound and
///   are **skipped** — not counted as failures.
/// - An in-range checkpoint counts as verified only when the signature (if
///   checked) **and** the content-binding both hold; otherwise it is a failure.
///   The binding covers the chain head hash **plus** `record_count` and
///   `ts_unix_ms` (W1-C12-07), not the hash alone.
/// - Fail-closed (W1-C12-01): when a key is supplied and records are present
///   but **zero** checkpoints could be evaluated — sidecar missing, empty, or
///   entirely out of range — that counts as one failure instead of verifying
///   OK with 0 verified / 0 failed.
///
/// Returns `(verified, failed, signature_checked)`.
fn eval_checkpoints(
    sidecar: &CheckpointSidecar,
    first_seq: u64,
    last_seq: u64,
    records_present: bool,
    seq_to_hash: &HashMap<u64, String>,
    seq_to_ts: &HashMap<u64, u64>,
) -> (u64, u64, bool) {
    if sidecar.missing {
        // Fail closed only when signature verification was requested against a
        // non-empty log; an unsigned or empty log keeps the previous verdict.
        if sidecar.signature_checked && records_present {
            return (0, 1, true);
        }
        return (0, 0, sidecar.signature_checked);
    }

    let mut verified = 0u64;
    let mut failed = 0u64;
    let mut evaluated = 0u64;

    for cl in &sidecar.lines {
        // Only checkpoints that bind to a retained record are evaluated.
        let cp = &cl.checkpoint;
        if !records_present || cp.seq < first_seq || cp.seq > last_seq {
            continue;
        }
        evaluated += 1;

        // (a) Signature — only when a key was supplied. The parsed
        // `Checkpoint` is verified directly: no field-by-field mirror exists
        // that a one-sided field add could slip past (W1-C12-11).
        let sig_ok = match &sidecar.verifier {
            Some(v) => v.verify_checkpoint(cp, &cl.signature).is_ok(),
            None => true,
        };

        // (b) Content-binding to the replayed log at this seq: the chain head
        // hash plus `record_count` and `ts_unix_ms` (W1-C12-07).
        //
        // `record_count` is process-local at the writer (records written since
        // sink start; reset on restart — see server `WriterState`), so no
        // exact log-derived total exists; the sound check is the `seq + 1`
        // upper bound (every counted record holds a distinct seq `<= S`),
        // written overflow-safe so `seq == u64::MAX` cannot wrap.
        let count_ok = cp.record_count.saturating_sub(1) <= cp.seq;
        // The checkpoint is sealed after the records it covers, so its wall
        // time must not predate the covered record's event time.
        let ts_ok = seq_to_ts.get(&cp.seq).is_some_and(|ts| cp.ts_unix_ms >= *ts);
        let hash_ok = seq_to_hash.get(&cp.seq).is_some_and(|h| *h == cp.chain_head_hash);
        let binding_ok = hash_ok && count_ok && ts_ok;

        if sig_ok && binding_ok {
            verified += 1;
        } else {
            failed += 1;
        }
    }

    // Fail closed: a key was supplied but no checkpoint bound to anything
    // (empty sidecar, or every entry skipped as out of range).
    if sidecar.verifier.is_some() && records_present && evaluated == 0 {
        failed += 1;
    }

    (verified, failed, sidecar.signature_checked)
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
    // Checked arithmetic (W1-C12-04): at `last_seq == u64::MAX` the next slot
    // is unrepresentable, so fail with a loud error instead of panicking
    // (debug) or wrapping to 0 (release).
    let Some(next_seq) = last_seq.checked_add(1) else {
        return Err(AuditError::Malformed(
            "anchor check overflow: last_seq is u64::MAX, the next slot is unrepresentable"
                .to_string(),
        ));
    };
    let head_ok = anchor.last_hash == head;
    let seq_ok = anchor.last_seq == next_seq;
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
    ///
    /// The line is built from the shared `Checkpoint` shape plus the
    /// signature — no field-by-field mirror (W1-C12-11).
    fn write_checkpoint(dir: &std::path::Path, signer: &Signer, cp: &Checkpoint) {
        let mut line = serde_json::to_value(cp).unwrap();
        line["signature"] = serde_json::Value::String(signer.sign_checkpoint(cp));
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

    // -----------------------------------------------------------------------
    // W1-C12-04: checked anchor arithmetic (last_seq + 1 must not panic/wrap)
    // -----------------------------------------------------------------------

    /// A log whose last seq is `u64::MAX` must produce a loud anchor error —
    /// never panic (debug) or wrap the expected next-seq to 0 (release).
    #[test]
    fn max_seq_anchor_errors_loudly() {
        let dir = temp_dir("max-seq-anchor");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut r0 = rec("C_Op", 0);
        r0.seq = u64::MAX;
        r0.prev_hash = GENESIS_HASH.to_string();
        fs::write(dir.join("audit.jsonl"), to_jsonl(&r0)).unwrap();
        // Anchor carries the genuine replayed head; the seq half cannot be
        // expressed (`MAX + 1` overflows), so verification must error loudly.
        let head = record_hash(&r0.prev_hash, &r0);
        write_test_anchor(&dir, &head, 0);

        let err = verify_dir(&dir, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("u64::MAX") || msg.contains("overflow"),
            "loud overflow error expected; got: {msg}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // W1-C12-06: duplicate seqs must fail verification
    // -----------------------------------------------------------------------

    /// Two records sharing one seq — with otherwise-valid hash links — must
    /// fail verification instead of collapsing silently.
    #[test]
    fn duplicate_seqs_fail_verification() {
        let dir = temp_dir("dup-seq");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut r0 = rec("C_Login", 0);
        let h0 = st.append(&mut r0); // seq 0
        // A second record reusing seq 0 but linked validly onto r0's hash.
        let mut r1 = rec("C_Logout", 1);
        r1.seq = 0;
        r1.prev_hash = h0;
        let head = record_hash(&r1.prev_hash, &r1);

        fs::write(dir.join("audit.jsonl"), format!("{}{}", to_jsonl(&r0), to_jsonl(&r1))).unwrap();
        // Anchor seals the replayed head; the dup itself must fail the verdict.
        write_test_anchor(&dir, &head, 1);

        let report = verify_dir(&dir, None).unwrap();
        assert!(!report.chain_ok, "dup-seq log must fail verification; got: {report:?}");
        assert_eq!(report.duplicate_seqs, vec![0], "dup seq 0 must be reported");
        assert!(!report.duplicates_truncated);

        fs::remove_dir_all(&dir).ok();
    }

    /// Gating pin: a clean log reports no duplicates (existing valid-chain
    /// tests also cover this via `chain_ok`, but pin the empty signal).
    #[test]
    fn clean_log_reports_no_duplicates() {
        let dir = temp_dir("dup-clean");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut r0 = rec("C_Login", 0);
        let mut r1 = rec("C_Logout", 0);
        st.append(&mut r0);
        st.append(&mut r1);
        fs::write(dir.join("audit.jsonl"), format!("{}{}", to_jsonl(&r0), to_jsonl(&r1))).unwrap();
        write_test_anchor(&dir, &st.last_hash, st.last_seq);

        let report = verify_dir(&dir, None).unwrap();
        assert!(report.chain_ok, "clean log must verify; got: {report:?}");
        assert!(report.duplicate_seqs.is_empty());
        assert!(!report.duplicates_truncated);

        fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // W1-C12-07: bind checkpoint record_count + ts to the log
    // -----------------------------------------------------------------------

    /// Build a 3-record chained log; returns `(dir, chain_state)`. The caller
    /// adds a checkpoint sidecar. Records carry `ts_unix_ms = 1`.
    fn chained_log_for_checkpoint(tag: &str) -> (std::path::PathBuf, ChainState) {
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
        write_test_anchor(&dir, &st.last_hash, st.last_seq);
        (dir, st)
    }

    /// A checkpoint whose `record_count` cannot describe the log (far above
    /// `seq + 1`) must fail binding even when correctly signed and pointing
    /// at the genuine chain head.
    #[test]
    fn checkpoint_count_mismatch_fails_binding() {
        const SEED: [u8; 32] = [11u8; 32];

        let (dir, st) = chained_log_for_checkpoint("cp-count");
        let signer = Signer::from_seed_bytes(&SEED).unwrap();
        // Genuine head at seq 2, but an absurd count — signed so the
        // signature half passes and only the count binding is exercised.
        let cp = Checkpoint {
            seq: 2,
            chain_head_hash: st.last_hash.clone(),
            ts_unix_ms: 100,
            record_count: 1_000_000,
        };
        write_checkpoint(&dir, &signer, &cp);

        let report = verify_dir(&dir, Some(&signer.public_hex())).unwrap();
        assert!(
            report.checkpoints_failed > 0,
            "count-mismatched checkpoint must fail binding; got: {report:?}"
        );
        assert!(!report.chain_ok, "count mismatch must fail chain_ok; got: {report:?}");

        fs::remove_dir_all(&dir).ok();
    }

    /// A checkpoint older than the records it covers (`ts` below the record
    /// ts at its seq) must fail binding even when correctly signed.
    #[test]
    fn checkpoint_ts_mismatch_fails_binding() {
        const SEED: [u8; 32] = [12u8; 32];

        let (dir, st) = chained_log_for_checkpoint("cp-ts");
        let signer = Signer::from_seed_bytes(&SEED).unwrap();
        // Records carry ts 1; a checkpoint at ts 0 predates them.
        let cp = Checkpoint {
            seq: 2,
            chain_head_hash: st.last_hash.clone(),
            ts_unix_ms: 0,
            record_count: 3,
        };
        write_checkpoint(&dir, &signer, &cp);

        let report = verify_dir(&dir, Some(&signer.public_hex())).unwrap();
        assert!(
            report.checkpoints_failed > 0,
            "ts-mismatched checkpoint must fail binding; got: {report:?}"
        );
        assert!(!report.chain_ok, "ts mismatch must fail chain_ok; got: {report:?}");

        fs::remove_dir_all(&dir).ok();
    }

    /// Boundary pin: `record_count == seq + 1` and `ts == record ts` match
    /// the log and must verify.
    #[test]
    fn checkpoint_count_and_ts_boundary_match_passes() {
        const SEED: [u8; 32] = [13u8; 32];

        let (dir, st) = chained_log_for_checkpoint("cp-boundary");
        let signer = Signer::from_seed_bytes(&SEED).unwrap();
        let cp = Checkpoint {
            seq: 2,
            chain_head_hash: st.last_hash.clone(),
            ts_unix_ms: 1,
            record_count: 3,
        };
        write_checkpoint(&dir, &signer, &cp);

        let report = verify_dir(&dir, Some(&signer.public_hex())).unwrap();
        assert_eq!(report.checkpoints_verified, 1, "boundary checkpoint must verify");
        assert_eq!(report.checkpoints_failed, 0);
        assert!(report.chain_ok, "boundary checkpoint must keep chain_ok; got: {report:?}");

        fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // W1-C12-09: schema_version skew detection
    // -----------------------------------------------------------------------

    /// A record whose `schema_version` differs from `AUDIT_SCHEMA_VERSION`
    /// must fail with a skew error (the record.rs format-skew promise).
    #[test]
    fn schema_version_skew_fails_with_skew_error() {
        let dir = temp_dir("schema-skew");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut recs: Vec<AuditRecord> = (0..2).map(|_| rec("C_Op", 0)).collect();
        for r in recs.iter_mut() {
            st.append(r);
        }
        // An older writer's record shape (v1) mixed into the log.
        recs[1].schema_version = crate::record::AUDIT_SCHEMA_VERSION - 1;
        fs::write(dir.join("audit.jsonl"), format!("{}{}", to_jsonl(&recs[0]), to_jsonl(&recs[1])))
            .unwrap();
        write_test_anchor(&dir, &st.last_hash, st.last_seq);

        let err = verify_dir(&dir, None).unwrap_err();
        assert!(err.to_string().contains("skew"), "a skew error is expected; got: {err}");

        fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // W1-C12-11: CheckpointLine shares the Checkpoint shape
    // -----------------------------------------------------------------------

    /// The sidecar line embeds the `Checkpoint` shape (single definition) plus
    /// the signature, so a field added on one side cannot escape the signed
    /// scope: a line built purely from the signed shape must round-trip every
    /// field.
    #[test]
    fn checkpoint_line_shares_checkpoint_shape() {
        const SEED: [u8; 32] = [14u8; 32];
        let signer = Signer::from_seed_bytes(&SEED).unwrap();
        let cp = Checkpoint {
            seq: 7,
            chain_head_hash: "ab".repeat(32),
            ts_unix_ms: 50,
            record_count: 8,
        };
        let mut v = serde_json::to_value(&cp).unwrap();
        v["signature"] = serde_json::Value::String(signer.sign_checkpoint(&cp));

        let line: CheckpointLine = serde_json::from_value(v).unwrap();
        assert_eq!(line.checkpoint.seq, cp.seq);
        assert_eq!(line.checkpoint.chain_head_hash, cp.chain_head_hash);
        assert_eq!(line.checkpoint.ts_unix_ms, cp.ts_unix_ms);
        assert_eq!(line.checkpoint.record_count, cp.record_count);
    }

    /// The checkpoint signature covers every `Checkpoint` field: tampering
    /// any serialized field must invalidate the signature. The sweep iterates
    /// the serialized keys (and pins their exact set), so a future field is
    /// covered by — and cannot silently escape — this probe.
    #[test]
    fn checkpoint_signature_covers_every_field() {
        use std::collections::BTreeSet;

        const SEED: [u8; 32] = [15u8; 32];
        let signer = Signer::from_seed_bytes(&SEED).unwrap();
        let verifier = Verifier::from_public_hex(&signer.public_hex()).unwrap();
        let cp = Checkpoint {
            seq: 7,
            chain_head_hash: "ab".repeat(32),
            ts_unix_ms: 50,
            record_count: 8,
        };
        let sig = signer.sign_checkpoint(&cp);

        // Pin the exact signed scope: adding a Checkpoint field must update
        // this test (and thereby acknowledge the signed-scope change).
        let obj = serde_json::to_value(&cp).unwrap();
        let keys: BTreeSet<String> = obj.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            BTreeSet::from(
                ["seq", "chain_head_hash", "ts_unix_ms", "record_count"].map(str::to_string)
            ),
            "signed Checkpoint scope changed"
        );

        for key in &keys {
            let mut v = serde_json::to_value(&cp).unwrap();
            v[key] = match v[key].clone() {
                serde_json::Value::Number(n) => {
                    serde_json::Value::Number((n.as_u64().unwrap() + 1).into())
                }
                serde_json::Value::String(s) => {
                    let mut t = s.clone();
                    let first = t.remove(0);
                    t.insert(0, if first == '0' { '1' } else { '0' });
                    serde_json::Value::String(t)
                }
                other => panic!("unexpected Checkpoint field type for {key}: {other}"),
            };
            let tampered: Checkpoint = serde_json::from_value(v).unwrap();
            assert!(
                verifier.verify_checkpoint(&tampered, &sig).is_err(),
                "tampering {key} must invalidate the checkpoint signature"
            );
        }
    }

    // -----------------------------------------------------------------------
    // W1-C12-12: streaming verify (bounded memory, no re-sort)
    // -----------------------------------------------------------------------

    /// The streaming verifier replays files oldest→newest in stored order; a
    /// log whose stored order is not seq-ascending (e.g. shuffled lines)
    /// fails closed instead of being re-sorted into a pass.
    #[test]
    fn out_of_order_log_fails_closed() {
        let dir = temp_dir("unordered");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut recs: Vec<AuditRecord> = (0..3).map(|_| rec("C_Op", 0)).collect();
        for r in recs.iter_mut() {
            st.append(r);
        }
        // Valid records + genuine anchor, but stored in reverse line order.
        fs::write(
            dir.join("audit.jsonl"),
            format!("{}{}{}", to_jsonl(&recs[2]), to_jsonl(&recs[1]), to_jsonl(&recs[0])),
        )
        .unwrap();
        write_test_anchor(&dir, &st.last_hash, st.last_seq);

        let report = verify_dir(&dir, None).unwrap();
        assert!(!report.chain_ok, "unordered log must fail verification; got: {report:?}");
        assert!(report.unordered, "unordered signal must be set; got: {report:?}");

        fs::remove_dir_all(&dir).ok();
    }

    /// Rotated files stream oldest→newest in *numeric* rotation order: with
    /// `audit.2.jsonl` holding older seqs than `audit.10.jsonl`, a
    /// lexicographic file order ("10" < "2") would replay out of order and
    /// fail, while numeric order verifies.
    #[test]
    fn rotated_files_stream_in_numeric_order() {
        let dir = temp_dir("numeric-order");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut recs: Vec<AuditRecord> = (0..6).map(|_| rec("C_Op", 0)).collect();
        for r in recs.iter_mut() {
            st.append(r);
        }
        fs::write(
            dir.join("audit.2.jsonl"),
            format!("{}{}", to_jsonl(&recs[0]), to_jsonl(&recs[1])),
        )
        .unwrap();
        fs::write(
            dir.join("audit.10.jsonl"),
            format!("{}{}", to_jsonl(&recs[2]), to_jsonl(&recs[3])),
        )
        .unwrap();
        fs::write(dir.join("audit.jsonl"), format!("{}{}", to_jsonl(&recs[4]), to_jsonl(&recs[5])))
            .unwrap();
        write_test_anchor(&dir, &st.last_hash, st.last_seq);

        let report = verify_dir(&dir, None).unwrap();
        assert!(report.chain_ok, "numeric rotation order must verify; got: {report:?}");
        assert_eq!((report.first_seq, report.last_seq), (0, 5));
        assert!(!report.unordered);

        fs::remove_dir_all(&dir).ok();
    }

    /// Unit pin for the oldest→newest file sort key: ascending rotation
    /// index, active file last, numeric (not lexicographic) index order, and
    /// no parsing (absurd indexes cannot overflow).
    #[test]
    fn log_file_order_key_pins_oldest_to_newest() {
        use std::cmp::Ordering;

        assert_eq!(
            log_file_order_key("audit.2.jsonl").cmp(&log_file_order_key("audit.10.jsonl")),
            Ordering::Less,
            "rotation indexes order numerically"
        );
        assert!(
            log_file_order_key("audit.10.jsonl") < log_file_order_key("audit.jsonl"),
            "the active file streams last"
        );
        assert!(
            log_file_order_key("audit.1.jsonl") < log_file_order_key("audit.2.jsonl"),
            "rotation indexes ascend"
        );
        let huge = format!("audit.{}.jsonl", "9".repeat(100));
        assert!(
            log_file_order_key(&huge) > log_file_order_key("audit.10.jsonl"),
            "absurd indexes order without parsing"
        );
    }

    /// Scale pin: a 20k-record log across three files — with gap sentinels, a
    /// signed mid-log checkpoint, and an anchor — streams in bounded memory
    /// with results identical to a fully materialized replay.
    #[test]
    fn large_dir_streams_with_identical_results() {
        const SEED: [u8; 32] = [16u8; 32];
        const N: usize = 20_000;
        const CP_SEQ: u64 = 15_000;

        let dir = temp_dir("large-dir");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let signer = Signer::from_seed_bytes(&SEED).unwrap();
        let mut st = ChainState::genesis();
        let mut part1 = String::new();
        let mut part2 = String::new();
        let mut part3 = String::new();
        let mut head_at_cp = String::new();
        for i in 0..N {
            // Every 5000th record is a gap sentinel (dropped_count = 2).
            let mut r = if i % 5000 == 4999 { sentinel(2) } else { rec("C_Op", 0) };
            let h = st.append(&mut r);
            if r.seq == CP_SEQ {
                head_at_cp = h;
            }
            let line = to_jsonl(&r);
            if i < 7_000 {
                part1.push_str(&line);
            } else if i < 14_000 {
                part2.push_str(&line);
            } else {
                part3.push_str(&line);
            }
        }
        fs::write(dir.join("audit.1.jsonl"), part1).unwrap();
        fs::write(dir.join("audit.2.jsonl"), part2).unwrap();
        fs::write(dir.join("audit.jsonl"), part3).unwrap();
        write_test_anchor(&dir, &st.last_hash, st.last_seq);

        let cp = Checkpoint {
            seq: CP_SEQ,
            chain_head_hash: head_at_cp,
            ts_unix_ms: 100,
            record_count: CP_SEQ + 1,
        };
        write_checkpoint(&dir, &signer, &cp);

        let report = verify_dir(&dir, Some(&signer.public_hex())).unwrap();
        assert!(report.chain_ok, "large ordered log must verify; got: {:?}", {
            // Summarize without dumping 20k-record internals.
            (report.files, report.records, report.checkpoints_failed, report.gaps.len())
        });
        assert_eq!(report.files, 3);
        assert_eq!(report.records, N as u64);
        assert_eq!((report.first_seq, report.last_seq), (0, (N - 1) as u64));
        assert!(!report.unordered);
        assert!(report.gaps.is_empty());
        assert!(report.duplicate_seqs.is_empty());
        assert_eq!(report.checkpoints_verified, 1);
        assert_eq!(report.checkpoints_failed, 0);
        assert!(report.head_matches_anchor);
        assert_eq!(report.dropped_records, 8, "4 sentinels x dropped_count 2");

        fs::remove_dir_all(&dir).ok();
    }
}

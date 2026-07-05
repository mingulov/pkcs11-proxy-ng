//! Tamper-evident audit sink (ADR-0012, G1 Task 5).
//!
//! A bounded MPSC channel feeds a background writer task that writes tamper-evident
//! JSONL audit logs to disk with rotation, an anchor file, and Ed25519-signed
//! checkpoints.
//!
//! Audit is off by default (`[audit]` section absent or `dir` unset). When off,
//! `spawn_audit_sink` returns `Ok(None)` with zero behaviour change for existing
//! deployments.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use pkcs11_proxy_ng_audit::chain::record_hash;
use pkcs11_proxy_ng_audit::record::{from_jsonl, to_jsonl};
use pkcs11_proxy_ng_audit::sign::{Checkpoint, Signer};
use pkcs11_proxy_ng_audit::{AuditRecord, ChainState};

use crate::config::AuditConfig;
use crate::server::transport::check_private_file_perms;

/// Bounded channel capacity for the audit writer task.
const CHANNEL_CAPACITY: usize = 1024;

/// Write a signed checkpoint every N records.
const CHECKPOINT_INTERVAL: u64 = 100;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Error returned by [`AuditSink::emit`] when a record cannot be queued and
/// the event class is fail-closed.
#[derive(Debug)]
pub struct AuditDropped;

impl std::fmt::Display for AuditDropped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "audit record dropped: channel full, fail-closed event class")
    }
}

impl std::error::Error for AuditDropped {}

/// Clonable handle to the background audit writer task.
///
/// Obtained from [`spawn_audit_sink`]. All clones share the same underlying
/// channel and dropped counter.
#[derive(Clone)]
pub struct AuditSink {
    tx: tokio::sync::mpsc::Sender<WriterMsg>,
    dropped: Arc<AtomicU64>,
}

impl AuditSink {
    /// Emit one audit record to the writer task.
    ///
    /// Uses non-blocking `try_send`. On a full channel:
    /// - Fail-closed classes (Auth, KeyMgmt, Admin, System) return `Err(AuditDropped)`.
    /// - Fail-open classes (DataPlane) silently increment the dropped counter
    ///   and return `Ok(())`.
    pub fn emit(&self, rec: AuditRecord) -> Result<(), AuditDropped> {
        // `EventClass` is `Copy`; capture it so `rec` can be moved into the
        // message without a clone.
        let class = rec.class;
        match self.tx.try_send(WriterMsg::Record(rec)) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                if class.fail_closed() {
                    Err(AuditDropped)
                } else {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
            }
            // Writer task exited; treat as fail-closed to surface the problem.
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(AuditDropped),
        }
    }

    /// Signal the writer task to fsync + write a final checkpoint, then wait
    /// for the acknowledgement before returning.
    pub async fn flush(&self) -> io::Result<()> {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        // If send fails the writer is gone; that is not an error for the flusher.
        let _ = self.tx.send(WriterMsg::Flush(ack_tx)).await;
        ack_rx.await.unwrap_or(Ok(()))
    }

    /// Number of records silently dropped due to a full channel.
    /// Only fail-open (DataPlane) records are counted here.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Internal channel message
// ---------------------------------------------------------------------------

enum WriterMsg {
    Record(AuditRecord),
    Flush(tokio::sync::oneshot::Sender<io::Result<()>>),
    /// A2: time-triggered checkpoint request from the periodic timer task.
    ///
    /// The writer seals the current log tail with a signed checkpoint when
    /// `records_since_checkpoint > 0` and a signer is configured, ensuring
    /// low-volume auth-only logs get sealed even if they never reach 100
    /// records (the count-based trigger).
    Checkpoint,
}

// ---------------------------------------------------------------------------
// Public constructor
// ---------------------------------------------------------------------------

/// Build and start an audit sink.
///
/// Returns `Ok(None)` when `cfg.dir` is `None` (audit disabled — zero behaviour
/// change for existing deployments).
///
/// When `cfg.dir` is `Some`:
/// 1. Creates the directory (mode 0700 on Unix) if missing.
/// 2. Validates `cfg.signing_key` private-key file permissions and loads the
///    32-byte seed.
/// 3. Reconstructs the chain tip deterministically from the active log tail
///    (falling back to the anchor, then genesis) — see [`reconstruct_chain_state`].
/// 4. Spawns the background writer on a blocking thread and returns the handle.
pub fn spawn_audit_sink(cfg: &AuditConfig) -> io::Result<Option<AuditSink>> {
    let Some(ref dir) = cfg.dir else {
        return Ok(None);
    };

    create_audit_dir(dir)?;

    let signer = load_signer(cfg)?;
    // A2: only the signer-present path needs the periodic checkpoint task;
    // an unsigned checkpoint has no cryptographic value.
    let has_signer = signer.is_some();

    let (tx, rx) = tokio::sync::mpsc::channel(CHANNEL_CAPACITY);
    let dropped = Arc::new(AtomicU64::new(0));

    let writer =
        WriterState::open(dir.clone(), signer, cfg.rotate_max_bytes, cfg.rotate_keep_files)?;
    // The writer does blocking `std::fs` I/O with `sync_all()`; keep it off the
    // async worker threads by running the loop on the blocking pool and draining
    // the tokio mpsc via `blocking_recv()`.
    tokio::task::spawn_blocking(move || writer_task(writer, rx));

    // A2: spawn a time-based checkpoint task so low-volume auth-only logs get
    // sealed even if they never reach CHECKPOINT_INTERVAL (100) records.
    // The task holds a Sender clone and exits when `send` fails, i.e. once the
    // WRITER side of the channel is gone. NOTE: because this clone keeps the
    // channel open, it does NOT unblock the writer's `blocking_recv()` on its
    // own — today that is harmless (durability is via explicit `flush()` + the
    // per-checkpoint anchor fsync, not a drop-based drain, and at runtime
    // teardown the scheduler drops this task before the blocking pool is
    // joined). If a future graceful-shutdown path drops the `AuditSink` and
    // joins the writer, give this task an explicit cancel (shutdown Notify /
    // select!) so it stops holding the sender independently of channel close.
    if has_signer && cfg.checkpoint_interval_secs > 0 {
        let tx_timer = tx.clone();
        let interval_secs = cfg.checkpoint_interval_secs;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
                if tx_timer.send(WriterMsg::Checkpoint).await.is_err() {
                    // Writer channel closed — daemon shutting down.
                    break;
                }
            }
        });
    }

    Ok(Some(AuditSink { tx, dropped }))
}

// ---------------------------------------------------------------------------
// Directory creation
// ---------------------------------------------------------------------------

fn create_audit_dir(dir: &Path) -> io::Result<()> {
    if dir.exists() {
        // H3: reject a pre-existing group/world-writable directory — an
        // adversary-controllable write surface.  The signing key (0o077)
        // and config (0o022) are already checked by their own paths; keep
        // the audit directory to the same standard.
        #[cfg(unix)]
        {
            crate::config::check_not_group_or_world_writable(dir, "audit directory")
                .map_err(io::Error::other)?;
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).recursive(true).create(dir)
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

// ---------------------------------------------------------------------------
// Signing key loader
// ---------------------------------------------------------------------------

fn load_signer(cfg: &AuditConfig) -> io::Result<Option<Signer>> {
    let Some(ref key_path) = cfg.signing_key else {
        return Ok(None);
    };
    check_private_file_perms(key_path, "audit.signing_key").map_err(io::Error::other)?;
    let seed = std::fs::read(key_path)?;
    if seed.len() != 32 {
        return Err(io::Error::other(format!(
            "audit signing key '{}' must be 32 bytes, got {}",
            key_path.display(),
            seed.len()
        )));
    }
    Signer::from_seed_bytes(&seed).map(Some).map_err(|e| io::Error::other(e.to_string()))
}

// ---------------------------------------------------------------------------
// Anchor file (chain tip seal + verification aid)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
struct AnchorFile {
    last_hash: String,
    /// The NEXT seq to assign (== the last written record's seq + 1), matching
    /// [`ChainState::last_seq`].
    last_seq: u64,
}

/// Deterministically reconstruct the chain tip at startup (Critical #2).
///
/// The periodic anchor is written only on checkpoint/rotation/flush, so after a
/// crash it may lag behind the records already durable in `audit.jsonl`. Trusting
/// the anchor for the resume seq would then **re-issue** sequence numbers. Resume
/// order:
/// 1. If `audit.jsonl` is non-empty, take the LAST valid record `r` and resume at
///    `last_seq = r.seq + 1`, `last_hash = record_hash(&r.prev_hash, &r)`. The
///    active file tail is authoritative.
/// 2. Else if `audit.anchor.json` exists, resume from it — this covers the "just
///    rotated, new active file empty" case, where the anchor holds the last
///    rotated file's head.
/// 3. Else start from genesis.
fn reconstruct_chain_state(active_path: &Path, dir: &Path) -> io::Result<ChainState> {
    if let Ok(content) = std::fs::read_to_string(active_path) {
        let mut last_valid: Option<AuditRecord> = None;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            // Tolerate a torn final line from a crash: keep the last line that
            // parses cleanly as the resume point.
            if let Ok(rec) = from_jsonl(line) {
                last_valid = Some(rec);
            }
        }
        if let Some(r) = last_valid {
            let last_hash = record_hash(&r.prev_hash, &r);
            return Ok(ChainState { last_hash, last_seq: r.seq + 1 });
        }
    }
    load_chain_state(dir)
}

/// Anchor fallback for the resume path (empty/absent active file): resume the
/// chain tip from `audit.anchor.json`, or genesis if it is absent.
fn load_chain_state(dir: &Path) -> io::Result<ChainState> {
    let anchor_path = dir.join("audit.anchor.json");
    if !anchor_path.exists() {
        return Ok(ChainState::genesis());
    }
    let data = std::fs::read(&anchor_path)?;
    let anchor: AnchorFile = serde_json::from_slice(&data)
        .map_err(|e| io::Error::other(format!("malformed audit anchor: {e}")))?;
    Ok(ChainState { last_hash: anchor.last_hash, last_seq: anchor.last_seq })
}

/// Fsync a directory so a preceding `rename` is durable across power loss (#5).
///
/// On unix, renaming a file makes the new name visible but the directory entry
/// is not guaranteed on stable storage until the directory itself is fsynced.
/// No-op on non-unix (opening a directory as a file is not portable).
fn fsync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let dir_file = std::fs::File::open(dir)?;
        dir_file.sync_all()?;
    }
    let _ = dir;
    Ok(())
}

/// Atomically update the anchor file: write to `.tmp` → fsync file → rename →
/// fsync directory (so the rename survives power loss).
fn write_anchor(dir: &Path, chain: &ChainState) -> io::Result<()> {
    let anchor = AnchorFile { last_hash: chain.last_hash.clone(), last_seq: chain.last_seq };
    let data = serde_json::to_vec(&anchor).map_err(|e| io::Error::other(e.to_string()))?;
    let tmp_path = dir.join("audit.anchor.json.tmp");
    {
        let mut f =
            std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(&tmp_path)?;
        f.write_all(&data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, dir.join("audit.anchor.json"))?;
    fsync_dir(dir)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Rotation helpers
// ---------------------------------------------------------------------------

/// Returns the highest N from any `audit.<N>.jsonl` in `dir`, or 0 if none.
fn find_max_rotation_n(dir: &Path) -> io::Result<u64> {
    let mut max_n = 0u64;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(n) = parse_rotation_n(&name.to_string_lossy())
            && n > max_n
        {
            max_n = n;
        }
    }
    Ok(max_n)
}

/// Returns `Some(N)` for `audit.<N>.jsonl` names where N is all ASCII digits.
fn parse_rotation_n(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("audit.")?;
    let digits = rest.strip_suffix(".jsonl")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Prune rotated files, keeping only the `keep` newest (by N).
fn prune_rotated_files(dir: &Path, keep: u32) -> io::Result<()> {
    if keep == 0 {
        return Ok(());
    }
    let mut rotated: Vec<(u64, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(n) = parse_rotation_n(&name.to_string_lossy()) {
            rotated.push((n, entry.path()));
        }
    }
    if rotated.len() <= keep as usize {
        return Ok(());
    }
    rotated.sort_by_key(|(n, _)| *n);
    let to_delete = rotated.len() - keep as usize;
    for (_, path) in rotated.into_iter().take(to_delete) {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Checkpoint writer
// ---------------------------------------------------------------------------

fn write_checkpoint_line(
    dir: &Path,
    chain: &ChainState,
    ts_unix_ms: u64,
    record_count: u64,
    signer: &Signer,
) -> io::Result<()> {
    // seq = last assigned seq = last_seq - 1 (last_seq points to the NEXT slot).
    let seq = chain.last_seq.saturating_sub(1);
    let cp = Checkpoint { seq, chain_head_hash: chain.last_hash.clone(), ts_unix_ms, record_count };
    let sig = signer.sign_checkpoint(&cp);
    let line = serde_json::json!({
        "seq": cp.seq,
        "chain_head_hash": cp.chain_head_hash,
        "ts_unix_ms": cp.ts_unix_ms,
        "record_count": cp.record_count,
        "signature": sig,
    });
    let mut line_str = serde_json::to_string(&line).map_err(|e| io::Error::other(e.to_string()))?;
    line_str.push('\n');

    let cp_path = dir.join("audit.checkpoints.jsonl");
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&cp_path)?;
    f.write_all(line_str.as_bytes())?;
    Ok(())
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Writer task state
// ---------------------------------------------------------------------------

struct WriterState {
    dir: PathBuf,
    chain: ChainState,
    file: std::fs::File,
    file_bytes: u64,
    signer: Option<Signer>,
    rotate_max_bytes: u64,
    rotate_keep_files: u32,
    /// Process-local count of records written since THIS sink was started. It is
    /// reset to 0 on every restart (it is not persisted or resumed), so it is an
    /// informational field in checkpoints, not a chain-wide total.
    record_count: u64,
    /// Records written since the last checkpoint (resets to 0 at each checkpoint).
    records_since_checkpoint: u64,
}

impl WriterState {
    fn open(
        dir: PathBuf,
        signer: Option<Signer>,
        rotate_max_bytes: u64,
        rotate_keep_files: u32,
    ) -> io::Result<Self> {
        let active_path = dir.join("audit.jsonl");
        // Resume the chain tip from the active-file tail (never the periodic
        // anchor seq) so a crash cannot re-issue sequence numbers (Critical #2).
        let chain = reconstruct_chain_state(&active_path, &dir)?;
        let file = std::fs::OpenOptions::new().create(true).append(true).open(&active_path)?;
        let file_bytes = file.metadata()?.len();
        Ok(Self {
            dir,
            chain,
            file,
            file_bytes,
            signer,
            rotate_max_bytes,
            rotate_keep_files,
            record_count: 0,
            records_since_checkpoint: 0,
        })
    }

    fn write_record(&mut self, mut rec: AuditRecord) -> io::Result<()> {
        self.chain.append(&mut rec);
        let line = to_jsonl(&rec);
        let line_bytes = line.len() as u64;

        // Rotate before writing if the new line would push the active file over the limit.
        // Never rotate an empty file (avoids infinite loop on a single oversized record).
        if self.file_bytes > 0 && self.file_bytes + line_bytes > self.rotate_max_bytes {
            self.rotate()?;
        }

        self.file.write_all(line.as_bytes())?;
        self.file_bytes += line_bytes;
        self.record_count += 1;
        self.records_since_checkpoint += 1;

        if self.records_since_checkpoint >= CHECKPOINT_INTERVAL {
            self.do_checkpoint()?;
        }

        Ok(())
    }

    /// Rotate the active log: fsync + rename audit.jsonl → audit.<N>.jsonl,
    /// open a fresh audit.jsonl, prune old rotated files, update the anchor.
    fn rotate(&mut self) -> io::Result<()> {
        self.file.sync_all()?;
        let next_n = find_max_rotation_n(&self.dir)? + 1;
        let rotated_path = self.dir.join(format!("audit.{next_n}.jsonl"));
        // Rename while holding the fd is safe on Unix: the fd still references
        // the old inode; the new path gets a fresh inode.
        std::fs::rename(self.dir.join("audit.jsonl"), &rotated_path)?;
        // Make the rotation rename durable before continuing (#5).
        fsync_dir(&self.dir)?;
        self.file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.dir.join("audit.jsonl"))?;
        self.file_bytes = 0;
        prune_rotated_files(&self.dir, self.rotate_keep_files)?;
        write_anchor(&self.dir, &self.chain)?;
        Ok(())
    }

    /// Write a signed checkpoint (if signer is configured), reset the
    /// interval counter, and update the anchor.
    fn do_checkpoint(&mut self) -> io::Result<()> {
        if let Some(ref signer) = self.signer {
            write_checkpoint_line(
                &self.dir,
                &self.chain,
                now_unix_ms(),
                self.record_count,
                signer,
            )?;
        }
        self.records_since_checkpoint = 0;
        write_anchor(&self.dir, &self.chain)?;
        Ok(())
    }

    /// Fsync the active file, write a final checkpoint if there are uncheck-
    /// pointed records, and update the anchor.
    fn flush(&mut self) -> io::Result<()> {
        self.file.sync_all()?;
        if self.records_since_checkpoint > 0 {
            self.do_checkpoint()?; // do_checkpoint writes the anchor
        } else {
            write_anchor(&self.dir, &self.chain)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Background writer task
// ---------------------------------------------------------------------------

/// Blocking writer loop, run on the tokio blocking pool via `spawn_blocking`.
///
/// Uses `blocking_recv()` / `try_recv()` on the mpsc receiver so the blocking
/// `std::fs` writes and `sync_all()` calls never run on an async worker thread.
fn writer_task(mut state: WriterState, mut rx: tokio::sync::mpsc::Receiver<WriterMsg>) {
    while let Some(msg) = rx.blocking_recv() {
        match msg {
            WriterMsg::Record(rec) => {
                if let Err(e) = state.write_record(rec) {
                    tracing::error!(error = %e, "audit writer: failed to write record");
                }
            }
            WriterMsg::Flush(ack) => {
                // Drain any buffered records before flushing.
                loop {
                    match rx.try_recv() {
                        Ok(WriterMsg::Record(rec)) => {
                            if let Err(e) = state.write_record(rec) {
                                tracing::error!(
                                    error = %e,
                                    "audit writer: failed to write record during flush drain"
                                );
                            }
                        }
                        Ok(WriterMsg::Flush(inner_ack)) => {
                            // A concurrent flush; our flush covers it.
                            let _ = inner_ack.send(Ok(()));
                        }
                        Ok(WriterMsg::Checkpoint) => {
                            // A time-triggered checkpoint is superseded by the
                            // flush that follows — no-op here.
                        }
                        Err(_) => break,
                    }
                }
                let result = state.flush();
                let _ = ack.send(result);
            }
            WriterMsg::Checkpoint => {
                // A2: time-triggered checkpoint. Seal the tail when there are
                // un-checkpointed records and a signer is configured.
                if state.records_since_checkpoint > 0
                    && state.signer.is_some()
                    && let Err(e) = state.do_checkpoint()
                {
                    tracing::error!(
                        error = %e,
                        "audit writer: failed time-triggered checkpoint"
                    );
                }
            }
        }
    }
    // Channel closed (daemon shutdown) — do a best-effort final flush.
    let _ = state.flush();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pkcs11_proxy_ng_audit::sign::Signer;
    use pkcs11_proxy_ng_audit::{AuditRecord, EventClass};

    use super::*;
    use crate::config::AuditConfig;

    fn make_record(class: EventClass) -> AuditRecord {
        AuditRecord {
            schema_version: pkcs11_proxy_ng_audit::AUDIT_SCHEMA_VERSION,
            seq: 0,
            ts_unix_ms: 1,
            ts_monotonic_ns: 1,
            prev_hash: String::new(),
            request_id: "r".into(),
            identity: None,
            method: "C_Sign".into(),
            class,
            slot: None,
            session: None,
            object_ref: None,
            ck_rv: 0,
            latency_us: 1,
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("audit-sink-{}-{}", std::process::id(), tag))
    }

    /// Test 1: rotation + PRUNING + pruning-aware chain verification.
    ///
    /// A small `rotate_keep_files` forces old rotated files to be pruned, so the
    /// retained chain is a suffix (`first_seq > 0`). The pruning-aware verifier
    /// must still report `chain_ok` with no gaps in the retained range.
    #[tokio::test]
    async fn test_basic_rotation_and_verify() {
        let dir = temp_dir("basic");
        let _ = std::fs::remove_dir_all(&dir);

        let cfg = AuditConfig {
            dir: Some(dir.clone()),
            signing_key: None,
            rotate_max_bytes: 512, // tiny limit → many rotations with ~250-byte records
            // Small keep value → the oldest rotated files ARE pruned, exercising
            // the pruning-aware verifier (a pruned prefix is not a gap).
            rotate_keep_files: 2,
            checkpoint_interval_secs: 300,
        };

        let sink = spawn_audit_sink(&cfg).unwrap().expect("sink should be created");

        let classes = [
            EventClass::Auth,
            EventClass::DataPlane,
            EventClass::KeyMgmt,
            EventClass::System,
            EventClass::Admin,
        ];
        for i in 0..50usize {
            sink.emit(make_record(classes[i % classes.len()])).unwrap();
        }
        sink.flush().await.unwrap();

        let report = pkcs11_proxy_ng_audit::verify::verify_dir(&dir, None).unwrap();
        assert!(report.chain_ok, "pruned chain must still verify after flush: {report:?}");
        assert!(report.gaps.is_empty(), "no seq gaps in the retained range: {:?}", report.gaps);
        assert!(report.head_matches_anchor, "anchor must seal the retained head");
        assert_eq!(report.last_seq, 49, "last seq is 49 (50 records emitted)");
        assert!(
            report.first_seq > 0,
            "pruning must have dropped the oldest records (first_seq={})",
            report.first_seq
        );
        assert!(report.records < 50, "pruning must have removed some records: {}", report.records);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Test 2: Ed25519-signed checkpoints round-trip through `verify_dir`.
    #[tokio::test]
    async fn test_signed_checkpoints() {
        let dir = temp_dir("signed");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let seed: [u8; 32] = [0x5Au8; 32];
        let key_path = dir.join("signing.key");
        std::fs::write(&key_path, seed).unwrap();
        // Private key material must be owner-only, or the sink refuses to load it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let public_hex = Signer::from_seed_bytes(&seed).unwrap().public_hex();

        let cfg = AuditConfig {
            dir: Some(dir.clone()),
            signing_key: Some(key_path),
            rotate_max_bytes: 64 * 1024, // large enough to avoid rotation
            rotate_keep_files: 10,
            checkpoint_interval_secs: 300,
        };

        let sink = spawn_audit_sink(&cfg).unwrap().expect("signed sink should be created");

        // Emit > CHECKPOINT_INTERVAL records to trigger at least one periodic checkpoint.
        for _ in 0..110 {
            sink.emit(make_record(EventClass::DataPlane)).unwrap();
        }
        sink.flush().await.unwrap();

        let report = pkcs11_proxy_ng_audit::verify::verify_dir(&dir, Some(&public_hex)).unwrap();
        assert!(report.chain_ok, "chain must be valid");
        assert_eq!(report.records, 110);
        assert!(report.signature_checked, "signature checking must have been attempted");
        assert!(report.checkpoints_verified >= 1, "at least one signed checkpoint must verify");
        assert_eq!(report.checkpoints_failed, 0, "no failed checkpoints");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Test 3: fail-closed vs fail-open policy on a saturated channel.
    ///
    /// We construct the sink directly with a channel of capacity 1 that is
    /// already full (no reader), avoiding any timing race.
    #[tokio::test]
    async fn test_fail_policy_saturated_channel() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<WriterMsg>(1);
        let dropped = Arc::new(AtomicU64::new(0));

        // Fill the channel to capacity.
        tx.try_send(WriterMsg::Record(make_record(EventClass::System))).unwrap();

        let sink = AuditSink { tx, dropped: dropped.clone() };

        // Auth is fail-closed → Err(AuditDropped) when channel is full.
        assert!(
            sink.emit(make_record(EventClass::Auth)).is_err(),
            "fail-closed Auth must return Err on full channel"
        );

        // DataPlane is fail-open → Ok + dropped counter increments.
        assert!(
            sink.emit(make_record(EventClass::DataPlane)).is_ok(),
            "fail-open DataPlane must return Ok on full channel"
        );
        assert_eq!(sink.dropped_count(), 1, "dropped counter must reflect the DataPlane drop");

        // A second fail-closed class also errors without changing the counter.
        assert!(sink.emit(make_record(EventClass::KeyMgmt)).is_err());
        assert_eq!(sink.dropped_count(), 1, "counter must not increment for fail-closed drops");
    }

    /// Test 4: audit disabled (dir = None) → Ok(None), no side effects.
    #[test]
    fn test_audit_off_returns_none() {
        let cfg = AuditConfig::default();
        let result = spawn_audit_sink(&cfg).unwrap();
        assert!(result.is_none(), "audit disabled must return Ok(None)");
    }

    /// Test 5 (fix Critical #2): after a crash the writer resumes from the file
    /// tail, NOT the (possibly stale) periodic anchor, so seqs are never
    /// re-issued.
    ///
    /// We reproduce a crash deterministically: 150 records are durable in
    /// `audit.jsonl`, but the anchor only advanced to the seq-99 checkpoint
    /// (`last_seq = 100`). A writer that trusted the anchor for its resume seq
    /// would re-issue seqs 100..149; a writer that resumes from the tail
    /// continues at 150.
    #[tokio::test]
    async fn restart_after_crash_no_duplicate_seqs() {
        let dir = temp_dir("crash-restart");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let mut st = ChainState::genesis();
        let mut lines = String::new();
        let mut stale = AnchorFile { last_hash: String::new(), last_seq: 0 };
        for i in 0..150u64 {
            let mut r = make_record(EventClass::DataPlane);
            st.append(&mut r);
            lines.push_str(&to_jsonl(&r));
            if i == 99 {
                // Anchor as it would stand right after the seq-99 checkpoint.
                stale = AnchorFile { last_hash: st.last_hash.clone(), last_seq: st.last_seq };
            }
        }
        std::fs::write(dir.join("audit.jsonl"), lines).unwrap();
        std::fs::write(dir.join("audit.anchor.json"), serde_json::to_vec(&stale).unwrap()).unwrap();

        // Restart: resume + 20 more records, then flush.
        let cfg = AuditConfig {
            dir: Some(dir.clone()),
            signing_key: None,
            rotate_max_bytes: 1 << 20, // no rotation
            rotate_keep_files: 10,
            checkpoint_interval_secs: 300,
        };
        let sink = spawn_audit_sink(&cfg).unwrap().expect("resumed sink");
        for _ in 0..20 {
            sink.emit(make_record(EventClass::DataPlane)).unwrap();
        }
        sink.flush().await.unwrap();

        let report = pkcs11_proxy_ng_audit::verify::verify_dir(&dir, None).unwrap();
        assert!(report.chain_ok, "resumed chain must verify: {report:?}");
        assert_eq!(report.first_seq, 0);
        assert_eq!(
            report.last_seq, 169,
            "resume-from-tail must continue at seq 150 and end at 169"
        );
        assert!(report.gaps.is_empty(), "no gaps: {:?}", report.gaps);
        // No duplicate seqs: exactly 170 records over the contiguous range 0..=169.
        assert_eq!(
            report.records,
            report.last_seq - report.first_seq + 1,
            "record count must equal the contiguous range (no duplicate seqs)"
        );
        assert_eq!(report.records, 170);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Test 6 (security HIGH): a group/other-accessible signing key is refused;
    /// an owner-only (0600) key is accepted.
    #[cfg(unix)]
    #[tokio::test]
    async fn signing_key_rejected_if_group_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("keyperms");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // H3: audit dir must be owner-only for spawn_audit_sink to accept it.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let key_path = dir.join("signing.key");
        std::fs::write(&key_path, [0x11u8; 32]).unwrap();

        let cfg = AuditConfig {
            dir: Some(dir.clone()),
            signing_key: Some(key_path.clone()),
            rotate_max_bytes: 1 << 20,
            rotate_keep_files: 10,
            checkpoint_interval_secs: 300,
        };

        // Group-readable (0640) → refused.
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            spawn_audit_sink(&cfg).is_err(),
            "group-readable (0640) signing key must be refused"
        );

        // Owner-only (0600) → accepted.
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let ok = spawn_audit_sink(&cfg);
        assert!(ok.is_ok(), "0600 signing key must be accepted: {:?}", ok.err());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Test H3: a pre-existing group/world-writable audit directory is rejected;
    /// a 0700 directory is accepted.
    ///
    /// Before this fix, `create_audit_dir` returned `Ok(())` for any existing
    /// directory, allowing an adversary to pre-plant a group-writable dir.
    #[cfg(unix)]
    #[tokio::test]
    async fn existing_audit_dir_writable_by_group_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let base = temp_dir("dirperms");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        let cfg_for_dir = |dir: &std::path::PathBuf| AuditConfig {
            dir: Some(dir.clone()),
            signing_key: None,
            rotate_max_bytes: 1 << 20,
            rotate_keep_files: 10,
            checkpoint_interval_secs: 300,
        };

        // 0777: group-writable + world-writable → refused.
        let dir_777 = base.join("audit_777");
        std::fs::create_dir_all(&dir_777).unwrap();
        std::fs::set_permissions(&dir_777, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            spawn_audit_sink(&cfg_for_dir(&dir_777)).is_err(),
            "0777 audit dir must be refused"
        );

        // 0772: group-writable + world-writable → refused.
        let dir_772 = base.join("audit_772");
        std::fs::create_dir_all(&dir_772).unwrap();
        std::fs::set_permissions(&dir_772, std::fs::Permissions::from_mode(0o772)).unwrap();
        assert!(
            spawn_audit_sink(&cfg_for_dir(&dir_772)).is_err(),
            "0772 audit dir must be refused"
        );

        // 0700: owner-only → accepted.
        let dir_700 = base.join("audit_700");
        std::fs::create_dir_all(&dir_700).unwrap();
        std::fs::set_permissions(&dir_700, std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = spawn_audit_sink(&cfg_for_dir(&dir_700));
        assert!(result.is_ok(), "0700 audit dir must be accepted: {:?}", result.err());

        std::fs::remove_dir_all(&base).ok();
    }

    /// Test A2: time-based checkpoint fires for a sub-100-record log.
    ///
    /// With `checkpoint_interval_secs = 1` and only 5 records emitted (well
    /// below the 100-record count trigger), the periodic timer must fire and
    /// produce at least one signed checkpoint before the flush.
    #[tokio::test]
    async fn time_triggered_checkpoint_seals_small_log() {
        let dir = temp_dir("timed-cp");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let seed: [u8; 32] = [0xBBu8; 32];
        let key_path = dir.join("signing.key");
        std::fs::write(&key_path, seed).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let public_hex = Signer::from_seed_bytes(&seed).unwrap().public_hex();

        let cfg = AuditConfig {
            dir: Some(dir.clone()),
            signing_key: Some(key_path),
            rotate_max_bytes: 64 * 1024,
            rotate_keep_files: 10,
            checkpoint_interval_secs: 1, // very short for test determinism
        };

        let sink = spawn_audit_sink(&cfg).unwrap().expect("timed-cp sink must be created");

        // Emit only 5 records — far below the 100-record count trigger.
        for _ in 0..5 {
            sink.emit(make_record(pkcs11_proxy_ng_audit::EventClass::Auth)).unwrap();
        }

        // Wait generously beyond the 1-second timer so the periodic task fires.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        sink.flush().await.unwrap();

        let report = pkcs11_proxy_ng_audit::verify::verify_dir(&dir, Some(&public_hex)).unwrap();
        assert!(report.chain_ok, "chain must be valid: {report:?}");
        assert_eq!(report.records, 5);
        assert!(
            report.checkpoints_verified >= 1,
            "time trigger must have produced at least one signed checkpoint; got: {report:?}"
        );
        assert_eq!(report.checkpoints_failed, 0, "no failed checkpoints");

        std::fs::remove_dir_all(&dir).ok();
    }
}

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

use pkcs11_proxy_ng_audit::record::to_jsonl;
use pkcs11_proxy_ng_audit::sign::{Checkpoint, Signer};
use pkcs11_proxy_ng_audit::{AuditRecord, ChainState};

use crate::config::AuditConfig;
use crate::server::transport::check_public_file_perms;

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
        match self.tx.try_send(WriterMsg::Record(rec.clone())) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                if rec.class.fail_closed() {
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
/// 2. Validates `cfg.signing_key` file permissions and loads the 32-byte seed.
/// 3. Reads `audit.anchor.json` to resume the chain (or starts from genesis).
/// 4. Spawns the background writer task and returns the sink handle.
pub fn spawn_audit_sink(cfg: &AuditConfig) -> io::Result<Option<AuditSink>> {
    let Some(ref dir) = cfg.dir else {
        return Ok(None);
    };

    create_audit_dir(dir)?;

    let signer = load_signer(cfg)?;
    let chain = load_chain_state(dir)?;

    let (tx, rx) = tokio::sync::mpsc::channel(CHANNEL_CAPACITY);
    let dropped = Arc::new(AtomicU64::new(0));

    let writer =
        WriterState::open(dir.clone(), chain, signer, cfg.rotate_max_bytes, cfg.rotate_keep_files)?;
    tokio::spawn(writer_task(writer, rx));

    Ok(Some(AuditSink { tx, dropped }))
}

// ---------------------------------------------------------------------------
// Directory creation
// ---------------------------------------------------------------------------

fn create_audit_dir(dir: &Path) -> io::Result<()> {
    if dir.exists() {
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
    check_public_file_perms(key_path, "audit.signing_key").map_err(io::Error::other)?;
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
// Anchor file (crash-recovery chain tip)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
struct AnchorFile {
    last_hash: String,
    last_seq: u64,
}

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

/// Atomically update the anchor file: write to `.tmp` → fsync → rename.
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
    /// Total records written since the sink was started (not resumed from anchor).
    record_count: u64,
    /// Records written since the last checkpoint (resets to 0 at each checkpoint).
    records_since_checkpoint: u64,
}

impl WriterState {
    fn open(
        dir: PathBuf,
        chain: ChainState,
        signer: Option<Signer>,
        rotate_max_bytes: u64,
        rotate_keep_files: u32,
    ) -> io::Result<Self> {
        let active_path = dir.join("audit.jsonl");
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

async fn writer_task(mut state: WriterState, mut rx: tokio::sync::mpsc::Receiver<WriterMsg>) {
    while let Some(msg) = rx.recv().await {
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
                        Err(_) => break,
                    }
                }
                let result = state.flush();
                let _ = ack.send(result);
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

    /// Test 1: basic rotation + full chain verification via `verify_dir`.
    #[tokio::test]
    async fn test_basic_rotation_and_verify() {
        let dir = temp_dir("basic");
        let _ = std::fs::remove_dir_all(&dir);

        let cfg = AuditConfig {
            dir: Some(dir.clone()),
            signing_key: None,
            rotate_max_bytes: 512, // tiny limit → many rotations with ~250-byte records
            // Use a high keep value so no old files are pruned — all 50 records
            // must remain on disk for verify_dir to see a contiguous chain.
            rotate_keep_files: 100,
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
            sink.emit(make_record(classes[i % classes.len()].clone())).unwrap();
        }
        sink.flush().await.unwrap();

        let report = pkcs11_proxy_ng_audit::verify::verify_dir(&dir, None).unwrap();
        assert!(report.chain_ok, "chain must be valid after flush");
        assert_eq!(report.records, 50, "all 50 records must be on disk");
        assert!(report.gaps.is_empty(), "no seq gaps");
        assert!(report.files >= 2, "rotation must have produced ≥2 files, got {}", report.files);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Test 2: Ed25519-signed checkpoints round-trip through `verify_dir`.
    #[tokio::test]
    async fn test_signed_checkpoints() {
        let dir = temp_dir("signed");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let seed: [u8; 32] = [0x5Au8; 32];
        let key_path = dir.join("signing.key");
        std::fs::write(&key_path, seed).unwrap();

        let public_hex = Signer::from_seed_bytes(&seed).unwrap().public_hex();

        let cfg = AuditConfig {
            dir: Some(dir.clone()),
            signing_key: Some(key_path),
            rotate_max_bytes: 64 * 1024, // large enough to avoid rotation
            rotate_keep_files: 10,
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
}

//! Audit record schema (ADR-0012, G1).

use serde::{Deserialize, Serialize};

use crate::AuditError;

/// The class of PKCS#11 operation being recorded.
///
/// `fail_closed` returns `true` for classes where a logging failure must
/// abort the operation rather than silently continue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventClass {
    Auth,
    KeyMgmt,
    Admin,
    DataPlane,
    System,
}

impl EventClass {
    /// Returns `true` if a logging failure for this class must cause the
    /// operation to be aborted (fail-closed policy).
    ///
    /// `DataPlane` is fail-open; all other classes are fail-closed.
    pub fn fail_closed(self) -> bool {
        !matches!(self, EventClass::DataPlane)
    }
}

/// A single audit log entry.
///
/// Field order is intentionally stable: `serde` serializes fields in
/// declaration order, so `serde_json::to_vec(rec)` is deterministic and
/// suitable as input to the hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Monotonically increasing sequence number within the hash chain.
    pub seq: u64,
    /// Wall-clock time of the event (milliseconds since Unix epoch).
    pub ts_unix_ms: u64,
    /// Monotonic timestamp of the event (nanoseconds since process start).
    pub ts_monotonic_ns: u64,
    /// Hex-encoded SHA-256 hash of the previous record, or `GENESIS_HASH`.
    pub prev_hash: String,
    /// Caller-supplied request identifier (e.g. a UUIDv4).
    pub request_id: String,
    /// Authenticated identity of the caller, if any.
    pub identity: Option<String>,
    /// PKCS#11 function name (e.g. `"C_Login"`).
    pub method: String,
    /// Broad category of the operation.
    pub class: EventClass,
    /// Token slot involved in the operation, if applicable.
    pub slot: Option<u64>,
    /// Session handle, if applicable.
    pub session: Option<u64>,
    /// Hashed object handle (never a label or raw handle).
    pub object_ref: Option<String>,
    /// PKCS#11 return value (`CK_RV`).
    pub ck_rv: u64,
    /// Operation latency in microseconds.
    pub latency_us: u64,
}

/// Serializes `rec` as a single JSON line terminated by `\n`.
pub fn to_jsonl(rec: &AuditRecord) -> String {
    let mut s = serde_json::to_string(rec).expect("AuditRecord is always JSON-serializable");
    s.push('\n');
    s
}

/// Deserializes a single JSONL line (trailing `\n` is stripped) into an
/// `AuditRecord`.
pub fn from_jsonl(s: &str) -> Result<AuditRecord, AuditError> {
    serde_json::from_str(s.trim_end_matches('\n')).map_err(|e| AuditError::Malformed(e.to_string()))
}

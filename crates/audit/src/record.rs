//! Audit record schema (ADR-0012, G1).

use serde::{Deserialize, Serialize};

use crate::AuditError;

/// Schema version used in every [`AuditRecord`].
///
/// `2` adds `dropped_count` (gap-sentinel field, `None` for normal records).
/// Verifiers can detect format skew by comparing the value they read against
/// this constant.  Bump this constant (and document the change) whenever the
/// record shape changes.
pub const AUDIT_SCHEMA_VERSION: u32 = 2;

/// `method` value marking a gap-sentinel record.
///
/// A record is a gap sentinel iff it matches the full ADR-0012 contract:
/// `method == GAP_SENTINEL_METHOD`, `class == EventClass::System`, and
/// `dropped_count.is_some()`. See [`AuditRecord::sentinel_dropped_count`].
pub const GAP_SENTINEL_METHOD: &str = "__AUDIT_GAP__";

/// The class of PKCS#11 operation being recorded.
///
/// `fail_closed` returns `true` for classes where a logging failure must
/// abort the operation rather than silently continue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventClass {
    Auth,
    KeyMgmt,
    Admin,
    DataPlane,
    System,
    /// Reserved for authorization-enforcement deny records; currently not emitted.
    ///
    /// Retained so that future emission is not a chain-format change (no
    /// schema-version bump needed).
    Deny,
}

impl EventClass {
    /// Returns `true` if a logging failure for this class must cause the
    /// operation to be aborted (fail-closed policy).
    ///
    /// `DataPlane` is fail-open; all other classes are fail-closed.
    /// `Deny` records are fail-closed: a denial that cannot be recorded must
    /// not be silently ignored (reserved and currently not emitted).
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
    /// Audit record schema version; 2 = the current field set.
    ///
    /// Bumped when the record shape changes so verifiers can detect format
    /// skew.  Always set to [`AUDIT_SCHEMA_VERSION`].
    pub schema_version: u32,
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
    /// Number of fail-open records dropped since the previous written record.
    ///
    /// Set to `Some(n)` only on gap-sentinel records (`method = "__AUDIT_GAP__"`);
    /// `None` for all normal records.  Added in schema version 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped_count: Option<u64>,
}

impl AuditRecord {
    /// Returns the dropped-record count iff this record matches the full
    /// gap-sentinel contract (W1-C12-08): the sentinel `method`, the
    /// `System` class, and a `Some` count. Anything else — a normal record
    /// smuggling the field, or a sentinel stripped of its method/class —
    /// yields `None` and must not tally.
    pub fn sentinel_dropped_count(&self) -> Option<u64> {
        if self.method == GAP_SENTINEL_METHOD && self.class == EventClass::System {
            self.dropped_count
        } else {
            None
        }
    }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainState;

    fn make_record() -> AuditRecord {
        AuditRecord {
            schema_version: AUDIT_SCHEMA_VERSION,
            seq: 0,
            ts_unix_ms: 1,
            ts_monotonic_ns: 1,
            prev_hash: String::new(),
            request_id: "r".into(),
            identity: None,
            method: "C_Login".into(),
            class: EventClass::Auth,
            slot: Some(0),
            session: Some(1),
            object_ref: None,
            ck_rv: 0,
            latency_us: 5,
            dropped_count: None,
        }
    }

    #[test]
    fn schema_version_constant_is_two() {
        assert_eq!(AUDIT_SCHEMA_VERSION, 2);
    }

    #[test]
    fn built_record_has_schema_version_two() {
        let rec = make_record();
        assert_eq!(rec.schema_version, 2);
    }

    #[test]
    fn deny_variant_is_fail_closed() {
        assert!(EventClass::Deny.fail_closed(), "Deny must be fail-closed");
    }

    #[test]
    fn record_with_schema_version_is_chainable() {
        let mut st = ChainState::genesis();
        let mut r0 = make_record();
        let mut r1 = make_record();
        st.append(&mut r0);
        st.append(&mut r1);
        // Chain advances correctly.
        assert_eq!(r0.seq, 0);
        assert_eq!(r1.seq, 1);
        assert_ne!(r0.prev_hash, r1.prev_hash);
        // Both records carry schema_version = 2 after append.
        assert_eq!(r0.schema_version, AUDIT_SCHEMA_VERSION);
        assert_eq!(r1.schema_version, AUDIT_SCHEMA_VERSION);
    }

    /// W1-C12-13: the `schema_version` field comment must describe 2 as the
    /// current field set, never 1 as the G1 set. Phrases are built from
    /// parts so this test's own source neither satisfies nor trips the scan
    /// (same pattern as the W1-C12-10 crate-docs test).
    #[test]
    fn schema_version_comment_matches_constant() {
        let src = include_str!("record.rs");
        let current = ["2 = the current", " field set"].concat();
        assert!(src.contains(&current), "schema_version comment must state: {current}");
        let stale = ["1 = the G", "1 field set"].concat();
        assert!(!src.contains(&stale), "schema_version comment must not state: {stale}");
    }

    /// W1-C12-08: `sentinel_dropped_count` requires the full contract —
    /// sentinel method, System class, and a `Some` count.
    #[test]
    fn sentinel_dropped_count_requires_full_contract() {
        let mut full = make_record();
        full.method = GAP_SENTINEL_METHOD.into();
        full.class = EventClass::System;
        full.dropped_count = Some(9);
        assert_eq!(full.sentinel_dropped_count(), Some(9));

        // Each stripped variant yields None.
        let mut wrong_method = full.clone();
        wrong_method.method = "C_Login".into();
        assert_eq!(wrong_method.sentinel_dropped_count(), None);

        let mut wrong_class = full.clone();
        wrong_class.class = EventClass::Auth;
        assert_eq!(wrong_class.sentinel_dropped_count(), None);

        let mut no_count = full.clone();
        no_count.dropped_count = None;
        assert_eq!(no_count.sentinel_dropped_count(), None);

        // A plain record never tallies.
        assert_eq!(make_record().sentinel_dropped_count(), None);
    }

    #[test]
    fn record_with_schema_version_roundtrips_jsonl() {
        let mut st = ChainState::genesis();
        let mut rec = make_record();
        st.append(&mut rec);
        let line = to_jsonl(&rec);
        let decoded = from_jsonl(&line).expect("jsonl round-trip must succeed");
        assert_eq!(decoded, rec);
        assert_eq!(decoded.schema_version, AUDIT_SCHEMA_VERSION); // version 2
    }
}

//! SHA-256 hash chain for audit records.
//!
//! # Canonical bytes determinism
//!
//! `canonical_bytes` uses `serde_json::to_vec` directly on `AuditRecord`.
//! Serde serializes struct fields in declaration order (guaranteed by the
//! `serde` crate), so the same record value always produces identical JSON
//! bytes. No key-sorting step is needed because the struct field order is
//! fixed at compile time and never changes between runs.

use sha2::{Digest, Sha256};

use crate::record::AuditRecord;

/// The starting prev_hash for the very first record in a chain.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Returns a deterministic byte representation of `rec`.
///
/// Determinism guarantee: `serde` serializes struct fields in the order they
/// are declared in the source. Because `AuditRecord`'s field order is fixed at
/// compile time, `serde_json::to_vec` produces identical bytes for identical
/// values across calls, processes, and restarts.
pub fn canonical_bytes(rec: &AuditRecord) -> Vec<u8> {
    serde_json::to_vec(rec).expect("AuditRecord is always JSON-serializable")
}

/// Returns `hex(SHA256(prev_hash_as_utf8_bytes || canonical_bytes(rec)))`.
pub fn record_hash(prev_hash_hex: &str, rec: &AuditRecord) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash_hex.as_bytes());
    hasher.update(canonical_bytes(rec));
    hex::encode(hasher.finalize())
}

/// Tracks the tip of a hash chain.
pub struct ChainState {
    pub last_hash: String,
    pub last_seq: u64,
}

impl ChainState {
    /// Returns a `ChainState` whose `last_hash` is `GENESIS_HASH` and
    /// `last_seq` is 0 (the seq that will be assigned to the first record).
    pub fn genesis() -> Self {
        ChainState { last_hash: GENESIS_HASH.to_string(), last_seq: 0 }
    }

    /// Appends `rec` to the chain:
    /// 1. Sets `rec.seq` to `self.last_seq`.
    /// 2. Sets `rec.prev_hash` to `self.last_hash`.
    /// 3. Computes the new record hash.
    /// 4. Advances `self.last_hash` and `self.last_seq`.
    /// 5. Returns the new hash.
    pub fn append(&mut self, rec: &mut AuditRecord) -> String {
        rec.seq = self.last_seq;
        rec.prev_hash = self.last_hash.clone();
        let hash = record_hash(&self.last_hash, rec);
        self.last_hash = hash.clone();
        self.last_seq += 1;
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{AuditRecord, EventClass};

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

    #[test]
    fn chain_links_and_detects_tamper() {
        let mut st = ChainState::genesis();
        assert_eq!(st.last_hash, GENESIS_HASH);
        let mut a = rec("C_Login", 0);
        let h1 = st.append(&mut a);
        assert_eq!(a.seq, 0);
        assert_eq!(a.prev_hash, GENESIS_HASH);
        let mut b = rec("C_Logout", 0);
        let h2 = st.append(&mut b);
        assert_eq!(b.seq, 1);
        assert_eq!(b.prev_hash, h1);
        assert_ne!(h1, h2);
        // Tamper: flipping a field changes the recomputed hash.
        let mut tampered = a.clone();
        tampered.ck_rv = 0x30;
        assert_ne!(crate::chain::record_hash(GENESIS_HASH, &tampered), h1);
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let a = rec("C_Login", 0);
        assert_eq!(crate::chain::canonical_bytes(&a), crate::chain::canonical_bytes(&a.clone()));
    }
}

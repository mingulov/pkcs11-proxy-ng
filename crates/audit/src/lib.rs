//! Audit primitives (ADR-0012, G1): record schema, SHA-256 hash chain,
//! Ed25519-signed checkpoints, and a directory verifier.
//!
//! # Integrity bounds
//!
//! Tamper-evidence is bounded to signed-checkpoint coverage: history up to
//! the last verified checkpoint is cryptographically tamper-evident (with a
//! configured signing key); the unsigned anchor gives corruption detection
//! for the post-checkpoint tail but is not proof against a writer who can
//! rewrite both the record and the anchor. Without a signing key the chain
//! is corruption-detecting only, not tamper-evident.
//!
//! No tokio, no I/O beyond what the verifier reads.
pub mod chain;
pub mod record;
pub mod sign;
pub mod verify;

pub use chain::{ChainState, GENESIS_HASH};
pub use record::{AUDIT_SCHEMA_VERSION, AuditRecord, EventClass};

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("malformed audit record: {0}")]
    Malformed(String),
    #[error("chain broken at seq {seq}: expected prev {expected}, found {found}")]
    ChainBroken { seq: u64, expected: String, found: String },
    #[error("signature verification failed: {0}")]
    BadSignature(String),
    #[error("io: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests {
    /// W1-C12-10: the crate docs must bound tamper-evidence to
    /// signed-checkpoint coverage per ADR-0012 (unsigned = corruption-only),
    /// never claim it unconditionally.
    #[test]
    fn crate_docs_bound_tamper_evidence_claim() {
        let src = include_str!("lib.rs");
        for sentence in [
            "bounded to signed-checkpoint coverage",
            "corruption-detecting only, not tamper-evident",
        ] {
            assert!(src.contains(sentence), "crate docs must state: {sentence}");
        }
        // Built from parts so this test's own source does not contain the
        // forbidden phrase it scans for.
        let unconditional = ["tamper-evident audit ", "primitives"].concat();
        assert!(
            !src.contains(&unconditional),
            "crate docs must not claim unconditional tamper-evidence"
        );
    }
}

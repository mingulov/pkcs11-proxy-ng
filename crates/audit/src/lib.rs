//! Pure, tamper-evident audit primitives (ADR-0012, G1): record schema,
//! SHA-256 hash chain, Ed25519-signed checkpoints, and a directory verifier.
//! No tokio, no I/O beyond what the verifier reads.
pub mod chain;
pub mod record;
pub mod sign;
pub mod verify;

pub use chain::{ChainState, GENESIS_HASH};
pub use record::{AuditRecord, EventClass};

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

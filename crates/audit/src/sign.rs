//! Ed25519-signed checkpoints (ADR-0012, G1).
//!
//! Signing keys are loaded from bytes only — no key generation path is
//! provided, which keeps `getrandom` / `rand_core` out of the dependency
//! tree (`default-features = false` on `ed25519-dalek`).
//!
//! # Determinism
//!
//! `checkpoint_bytes` serializes `Checkpoint` fields via `serde_json::to_vec`.
//! Serde serializes struct fields in declaration order (the same guarantee
//! that `chain::canonical_bytes` relies on), so the same `Checkpoint` value
//! always produces identical bytes across calls, processes, and restarts.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use zeroize::Zeroizing;

use crate::AuditError;

/// A checkpoint that summarizes the audit-chain state at a point in time.
///
/// This is the single shared shape: the sidecar line embeds it via
/// `#[serde(flatten)]` (see `verify::CheckpointLine`), so a field added here
/// is automatically covered by the signature and the content binding — a
/// one-sided add cannot silently escape the signed scope (W1-C12-11).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    pub seq: u64,
    pub chain_head_hash: String,
    pub ts_unix_ms: u64,
    pub record_count: u64,
}

/// Returns a deterministic byte representation of `cp`.
///
/// Field order matches the struct declaration order (guaranteed by serde),
/// so the same `Checkpoint` value always produces the same bytes.
pub fn checkpoint_bytes(cp: &Checkpoint) -> Vec<u8> {
    serde_json::to_vec(cp).expect("Checkpoint is always JSON-serializable")
}

/// An Ed25519 signing key loaded from a 32-byte seed.
///
/// Key material is wiped after use (W1-C12-16): the seed copy in
/// [`Signer::from_seed_bytes`] is zeroed once the key is built, and the key
/// itself wipes on drop (ed25519-dalek `zeroize`, pinned explicitly in this
/// crate's `Cargo.toml`).
pub struct Signer {
    key: SigningKey,
}

/// Dropping a [`Signer`] wipes its Ed25519 secret through the key's own
/// wiping `Drop` (see `signer_key_material_wiped_on_drop`).
impl zeroize::ZeroizeOnDrop for Signer {}

impl Signer {
    /// Load a [`Signer`] from a 32-byte Ed25519 seed.
    ///
    /// The seed copy is held in a wiping wrapper and zeroed on return, so no
    /// seed bytes linger on the stack after the key is built (W1-C12-16).
    ///
    /// Returns [`AuditError::Malformed`] if `seed` is not exactly 32 bytes.
    pub fn from_seed_bytes(seed: &[u8]) -> Result<Self, AuditError> {
        let arr: [u8; 32] = seed.try_into().map_err(|_| {
            AuditError::Malformed(format!("seed must be 32 bytes, got {}", seed.len()))
        })?;
        let arr = Zeroizing::new(arr);
        Ok(Signer { key: SigningKey::from_bytes(&arr) })
    }

    /// Sign a checkpoint; returns the hex-encoded 64-byte Ed25519 signature.
    pub fn sign_checkpoint(&self, cp: &Checkpoint) -> String {
        let sig: Signature = self.key.sign(&checkpoint_bytes(cp));
        hex::encode(sig.to_bytes())
    }

    /// Returns the hex-encoded 32-byte Ed25519 public (verifying) key.
    pub fn public_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }
}

/// An Ed25519 verifying key loaded from a hex-encoded public key.
pub struct Verifier {
    key: VerifyingKey,
}

impl Verifier {
    /// Load a [`Verifier`] from a hex-encoded 32-byte Ed25519 public key.
    ///
    /// Returns [`AuditError::BadSignature`] if the hex is malformed or the
    /// decoded bytes are not a valid Ed25519 public key point.
    pub fn from_public_hex(pub_hex: &str) -> Result<Self, AuditError> {
        let bytes = hex::decode(pub_hex)
            .map_err(|e| AuditError::BadSignature(format!("invalid public-key hex: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AuditError::BadSignature("public key must be 32 bytes".to_string()))?;
        let key = VerifyingKey::from_bytes(&arr)
            .map_err(|e| AuditError::BadSignature(format!("invalid public key: {e}")))?;
        Ok(Verifier { key })
    }

    /// Verify that `sig_hex` is a valid Ed25519 signature over `cp`.
    ///
    /// Returns [`AuditError::BadSignature`] on any failure (hex decode, wrong
    /// length, or cryptographic mismatch).
    pub fn verify_checkpoint(&self, cp: &Checkpoint, sig_hex: &str) -> Result<(), AuditError> {
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| AuditError::BadSignature(format!("invalid signature hex: {e}")))?;
        let arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| AuditError::BadSignature("signature must be 64 bytes".to_string()))?;
        let sig = Signature::from_bytes(&arr);
        self.key
            .verify(&checkpoint_bytes(cp), &sig)
            .map_err(|e| AuditError::BadSignature(format!("signature mismatch: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // A fixed 32-byte test seed (NOT a real key).
    const SEED: [u8; 32] = [7u8; 32];

    fn cp() -> Checkpoint {
        Checkpoint { seq: 42, chain_head_hash: "ab".repeat(32), ts_unix_ms: 100, record_count: 42 }
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let signer = Signer::from_seed_bytes(&SEED).unwrap();
        let c = cp();
        let sig = signer.sign_checkpoint(&c);
        let verifier = Verifier::from_public_hex(&signer.public_hex()).unwrap();
        verifier.verify_checkpoint(&c, &sig).unwrap();
    }

    #[test]
    fn tampered_checkpoint_fails_verify() {
        let signer = Signer::from_seed_bytes(&SEED).unwrap();
        let c = cp();
        let sig = signer.sign_checkpoint(&c);
        let mut bad = c.clone();
        bad.record_count = 43;
        let verifier = Verifier::from_public_hex(&signer.public_hex()).unwrap();
        assert!(verifier.verify_checkpoint(&bad, &sig).is_err());
    }

    #[test]
    fn wrong_seed_length_errors() {
        assert!(Signer::from_seed_bytes(&[0u8; 31]).is_err());
    }

    /// W1-C12-16: the seed copy in `from_seed_bytes` must be wiped after
    /// use (via the wiping wrapper), never left lingering on the stack.
    /// The scanned-for name is built from parts so this test's own source
    /// does not satisfy the scan (same pattern as the W1-C12-10 test).
    #[test]
    fn signer_seed_wiped_after_use() {
        let src = include_str!("sign.rs");
        let wiper = ["Zeroi", "zing"].concat();
        assert!(src.contains(&wiper), "seed handling must wipe via {wiper}");
    }

    /// W1-C12-16 (guard pin): `Signer` must keep the wiping drop glue over
    /// its key material. This already holds pre-fix (ed25519-dalek's
    /// `zeroize` feature arrives transitively via `std -> alloc`), so it
    /// pins the guarantee against future feature trims rather than going
    /// red here; the red half of this item is `signer_seed_wiped_after_use`.
    #[test]
    fn signer_key_material_wiped_on_drop() {
        assert!(
            std::mem::needs_drop::<Signer>(),
            "Signer must run a wiping Drop over its key material"
        );
    }

    /// W1-C12-16 (compile-time pins): the wipe-on-drop guarantee is carried
    /// by `ZeroizeOnDrop` markers — on our `Signer` and on dalek's
    /// `SigningKey` (i.e. the ed25519 `zeroize` feature is on). If either
    /// marker ever stops holding, this fails to compile.
    #[test]
    fn signer_zeroize_markers_hold() {
        fn assert_wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_wiped_on_drop::<Signer>();
        assert_wiped_on_drop::<SigningKey>();
    }
}

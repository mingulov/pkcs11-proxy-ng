use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Project-owned secret bytes that are wiped before their allocation is freed.
///
/// Access is closure-scoped so a borrow cannot accidentally become a general
/// byte-container API. Consuming transfer returns another wiping owner rather
/// than a plain `Vec<u8>`.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Takes ownership of an existing byte allocation.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Copies bytes into a new wiping owner.
    pub fn copy_from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    /// Exposes an immutable slice for the duration of `access` only.
    pub fn expose<R>(&self, access: impl FnOnce(&[u8]) -> R) -> R {
        access(self.0.as_slice())
    }

    /// Exposes a mutable slice for the duration of `access` only.
    pub fn expose_mut<R>(&mut self, access: impl FnOnce(&mut [u8]) -> R) -> R {
        access(self.0.as_mut_slice())
    }

    /// Transfers ownership while retaining automatic wiping on drop.
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for SecretBytes {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(bytes: &[u8]) -> Self {
        Self::copy_from_slice(bytes)
    }
}

impl From<String> for SecretBytes {
    /// Adopts the string's allocation without copying; the bytes keep their
    /// UTF-8 content and are wiped when the owner drops. Callers needing the
    /// text back must decode inside [`SecretBytes::expose`].
    fn from(text: String) -> Self {
        Self::new(text.into_bytes())
    }
}

impl From<&str> for SecretBytes {
    /// Copies the string's bytes into a new wiping owner.
    fn from(text: &str) -> Self {
        Self::copy_from_slice(text.as_bytes())
    }
}

impl From<Zeroizing<Vec<u8>>> for SecretBytes {
    /// Adopts a wiping allocation without copying. The wiping guarantee
    /// transfers with the allocation; this is the inverse of
    /// [`SecretBytes::into_zeroizing`] for readback paths that rebuild a
    /// `SecretBytes` from wiping FFI backing.
    fn from(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
}

impl Clone for SecretBytes {
    /// Copies the bytes into a new, independently wiping owner.
    ///
    /// Cloning is sound (every copy is wiped on drop) but multiplies live
    /// secret allocations; conversion paths must consume or transfer where
    /// possible instead of cloning (ADR-0013 §5).
    fn clone(&self) -> Self {
        self.expose(Self::copy_from_slice)
    }
}

impl PartialEq for SecretBytes {
    /// Byte equality only; reveals nothing beyond the comparison result.
    fn eq(&self, other: &Self) -> bool {
        self.expose(|left| other.expose(|right| left == right))
    }
}

impl Eq for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SecretBytes").field("len", &self.len()).finish()
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretBytes {}

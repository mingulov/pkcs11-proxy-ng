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

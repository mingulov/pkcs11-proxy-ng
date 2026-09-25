/// An input buffer as the client passed it: real bytes, or a NULL pointer
/// with a claimed length (ADR-0010 — NULL must reach the module as NULL).
#[derive(Debug, Clone, Copy)]
pub enum CkInBuf<'a> {
    Bytes(&'a [u8]),
    Null { len: u64 },
}

impl<'a> CkInBuf<'a> {
    /// Returns `(pointer, length)` exactly as the backend FFI call must receive them.
    ///
    /// The returned pointer is **borrowed from `self`** (lifetime enforced by the
    /// borrow checker, stated here for FFI readers who inspect the raw pointer).
    ///
    /// - For `Bytes`: the pointer is **non-null** even for an empty slice (it is a
    ///   valid dangling pointer into the slice's allocation and **must not be
    ///   dereferenced** when `len` is 0).
    /// - For `Null`: the pointer is `ptr::null()` regardless of the claimed `len`.
    ///
    /// Consumers must pass the `(pointer, len)` pair to the PKCS#11 call verbatim
    /// and must **never dereference** the pointer themselves.
    pub fn as_ptr_len(&self) -> (*const u8, u64) {
        match self {
            CkInBuf::Bytes(b) => (b.as_ptr(), b.len() as u64),
            CkInBuf::Null { len } => (std::ptr::null(), *len),
        }
    }
}

impl<'a> From<&'a [u8]> for CkInBuf<'a> {
    fn from(b: &'a [u8]) -> Self {
        CkInBuf::Bytes(b)
    }
}

#[cfg(test)]
mod tests {
    use super::CkInBuf;

    #[test]
    fn ck_in_buf_null_reconstructs_null_pointer_with_claimed_len() {
        let (p, l) = CkInBuf::Null { len: 9 }.as_ptr_len();
        assert!(p.is_null());
        assert_eq!(l, 9);
    }

    #[test]
    fn ck_in_buf_bytes_gives_non_null_ptr_and_correct_len() {
        let data = [1u8, 2];
        let (p, l) = CkInBuf::from(&data[..]).as_ptr_len();
        assert!(!p.is_null());
        assert_eq!(l, 2);
    }

    #[test]
    fn ck_in_buf_bytes_empty_slice_gives_non_null_dangling_ptr_and_zero_len() {
        let (p, l) = CkInBuf::Bytes(&[]).as_ptr_len();
        assert!(!p.is_null());
        assert_eq!(l, 0);
    }
}

/// An input buffer as the client passed it: real bytes, or a NULL pointer
/// with a claimed length (ADR-0010 — NULL must reach the module as NULL).
#[derive(Debug, Clone, Copy)]
pub enum CkInBuf<'a> {
    Bytes(&'a [u8]),
    Null { len: u64 },
}

impl<'a> CkInBuf<'a> {
    /// (pointer, length) exactly as the backend FFI call must receive them.
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
}

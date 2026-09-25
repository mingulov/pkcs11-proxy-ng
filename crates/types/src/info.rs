use crate::session::CkFlags;

/// Cryptoki library info (from C_GetInfo).
#[derive(Debug, Clone, PartialEq)]
pub struct CkInfo {
    pub cryptoki_version: (u8, u8),
    pub manufacturer_id: String,
    pub flags: CkFlags,
    pub library_description: String,
    pub library_version: (u8, u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    // W1-C9-14: CkInfo.flags is a wrapped CkFlags (sibling-mapper
    // convention), not a raw u64.
    #[test]
    fn w1_c9_14_info_flags_wrapped() {
        let info = CkInfo {
            cryptoki_version: (3, 2),
            manufacturer_id: "Test".into(),
            flags: CkFlags(0),
            library_description: "Library".into(),
            library_version: (1, 0),
        };
        assert_eq!(info.flags.0, 0);
    }
}

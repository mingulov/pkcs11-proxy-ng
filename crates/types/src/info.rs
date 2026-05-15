/// Cryptoki library info (from C_GetInfo).
#[derive(Debug, Clone, PartialEq)]
pub struct CkInfo {
    pub cryptoki_version: (u8, u8),
    pub manufacturer_id: String,
    pub flags: u64,
    pub library_description: String,
    pub library_version: (u8, u8),
}

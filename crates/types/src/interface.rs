/// Describes one PKCS#11 interface version and which functions are NULL.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub version_major: u8,
    pub version_minor: u8,
    /// Function names that are NULL in the backend's function list.
    /// e.g., ["C_WrapKey", "C_DeriveKey"]
    pub null_functions: Vec<String>,
}

/// The complete set of interface capabilities reported by a backend.
#[derive(Debug, Clone)]
pub struct InterfaceCapabilities {
    pub interfaces: Vec<InterfaceInfo>,
}

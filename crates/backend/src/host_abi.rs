//! Host (daemon) `CK_ULONG` ABI properties for the width bridge (ADR-0011 D2/D6).
//!
//! The backend FFI calls run in this daemon process, so the daemon's compiled
//! `cryptoki_sys::CK_ULONG` width and the host byte order are the *backend's*
//! width and order. The server advertises these to narrow clients (via
//! `GetBackendInterfacesResponse`) so a client whose `CK_ULONG` differs can
//! bridge ulong-typed attribute values and lengths. This module lives in the
//! backend crate because the daemon's compiled CK_ULONG width and byte order
//! define the backend's ABI.

/// The daemon's backend `sizeof(CK_ULONG)` in bytes: 4 on a narrow
/// (ILP32 / LLP64) build, 8 on an LP64 build.
pub fn host_ulong_size() -> u32 {
    std::mem::size_of::<cryptoki_sys::CK_ULONG>() as u32
}

/// The daemon's backend `CK_ULONG` byte order, encoded for the wire: `1` =
/// little-endian, `2` = big-endian (matching ADR-0011 D6 / the proto
/// `backend_byte_order` field).
pub fn host_byte_order() -> u32 {
    if cfg!(target_endian = "little") { 1 } else { 2 }
}

/// The daemon backend's exact native v1 mechanism-parameter ABI (Q04):
/// this build target's compiled layout fact — packing included, never
/// inferred from the width. `None` where no v1 ABI exists (big-endian
/// targets have no little-endian layout), in which case discovery stays
/// silent and struct prefixes fail closed downstream.
pub fn host_mechanism_param_abi() -> Option<pkcs11_proxy_ng_types::shape_descriptors::ParamAbi> {
    pkcs11_proxy_ng_types::shape_descriptors::ParamAbi::native()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulong_size_matches_cryptoki_and_is_valid() {
        let n = host_ulong_size();
        assert!(n == 4 || n == 8, "CK_ULONG must be 4 or 8 bytes, got {n}");
        assert_eq!(n as usize, std::mem::size_of::<cryptoki_sys::CK_ULONG>());
    }

    #[test]
    fn byte_order_matches_target_endianness() {
        // 1 = little-endian, 2 = big-endian per ADR-0011 D6: the compiled
        // target's own order, pinned here so a BE build proves the BE arm.
        let want = if cfg!(target_endian = "little") { 1 } else { 2 };
        assert_eq!(host_byte_order(), want);
    }

    #[test]
    fn host_mechanism_param_abi_matches_native_fact() {
        // Q04: the host native-ABI fact is coherent with the sibling
        // advertisements — a named ABI always agrees with the width and
        // order this module reports; big-endian hosts name no v1 ABI.
        use pkcs11_proxy_ng_types::shape_descriptors::ParamAbi;
        match host_mechanism_param_abi() {
            Some(abi) => {
                assert_eq!(ParamAbi::native(), Some(abi));
                assert_eq!(abi.ulong_size(), host_ulong_size() as usize);
                assert_eq!(host_byte_order(), 1);
            }
            None => {
                assert_eq!(ParamAbi::native(), None);
                assert_eq!(host_byte_order(), 2);
            }
        }
    }
}

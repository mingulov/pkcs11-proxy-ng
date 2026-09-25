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
}

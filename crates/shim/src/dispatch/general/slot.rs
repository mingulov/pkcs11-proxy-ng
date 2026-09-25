use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use crate::state;

use super::helpers::{catch_panics, rv_err, rv_ok, with_client};

pub unsafe extern "C" fn c_get_slot_list(
    token_present: CK_BBOOL,
    p_slot_list: CK_SLOT_ID_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_count.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.get_slot_list(token_present != 0)) {
            Ok(slots) => {
                let count = slots.len() as CK_ULONG;
                unsafe {
                    if p_slot_list.is_null() {
                        *pul_count = count;
                        return rv_ok();
                    }
                    if *pul_count < count {
                        *pul_count = count;
                        return rv_err(CkRv::BUFFER_TOO_SMALL);
                    }
                    for (i, s) in slots.iter().enumerate() {
                        *p_slot_list.add(i) = s.0 as CK_SLOT_ID;
                    }
                    *pul_count = count;
                }
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_get_slot_info(slot_id: CK_SLOT_ID, p_info: CK_SLOT_INFO_PTR) -> CK_RV {
    catch_panics(|| {
        if p_info.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.get_slot_info(CkSlotId(slot_id as u64))) {
            Ok(info) => {
                unsafe {
                    let out = &mut *p_info;
                    space_pad_into(&mut out.slotDescription, &info.slot_description);
                    space_pad_into(&mut out.manufacturerID, &info.manufacturer_id);
                    out.flags = info.flags.0 as CK_FLAGS;
                    out.hardwareVersion = CK_VERSION {
                        major: info.hardware_version.0,
                        minor: info.hardware_version.1,
                    };
                    out.firmwareVersion = CK_VERSION {
                        major: info.firmware_version.0,
                        minor: info.firmware_version.1,
                    };
                }
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

/// Narrow a wire-canonical `CK_TOKEN_INFO` sentinel-bearing field (session
/// counts and memory sizes) to the client's native `CK_ULONG`.
///
/// These fields may be `CK_UNAVAILABLE_INFORMATION`. The wire carries that
/// sentinel canonically as `u64::MAX` (ADR-0011); [`width::narrow_info_field`]
/// maps it — and any genuine value that does not fit a narrower client's
/// `CK_ULONG` — to the client-width `CK_UNAVAILABLE_INFORMATION`, so a 64-bit
/// backend value exceeding 32-bit range surfaces as "no information available"
/// rather than a silently truncated, misleading number.
fn token_info_field(wire: u64) -> CK_ULONG {
    narrow_info_field(wire, std::mem::size_of::<CK_ULONG>()) as CK_ULONG
}

pub unsafe extern "C" fn c_get_token_info(slot_id: CK_SLOT_ID, p_info: CK_TOKEN_INFO_PTR) -> CK_RV {
    catch_panics(|| {
        if p_info.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.get_token_info(CkSlotId(slot_id as u64))) {
            Ok(info) => {
                unsafe {
                    let out = &mut *p_info;
                    space_pad_into(&mut out.label, &info.label);
                    space_pad_into(&mut out.manufacturerID, &info.manufacturer_id);
                    space_pad_into(&mut out.model, &info.model);
                    space_pad_into(&mut out.serialNumber, &info.serial_number);
                    out.flags = info.flags.0 as CK_FLAGS;
                    out.ulMaxSessionCount = token_info_field(info.max_session_count);
                    out.ulSessionCount = token_info_field(info.session_count);
                    out.ulMaxRwSessionCount = token_info_field(info.max_rw_session_count);
                    out.ulRwSessionCount = token_info_field(info.rw_session_count);
                    // PIN lengths are never CK_UNAVAILABLE_INFORMATION and are
                    // bounded well within CK_ULONG range in every width.
                    out.ulMaxPinLen = info.max_pin_len as CK_ULONG;
                    out.ulMinPinLen = info.min_pin_len as CK_ULONG;
                    out.ulTotalPublicMemory = token_info_field(info.total_public_memory);
                    out.ulFreePublicMemory = token_info_field(info.free_public_memory);
                    out.ulTotalPrivateMemory = token_info_field(info.total_private_memory);
                    out.ulFreePrivateMemory = token_info_field(info.free_private_memory);
                    out.hardwareVersion = CK_VERSION {
                        major: info.hardware_version.0,
                        minor: info.hardware_version.1,
                    };
                    out.firmwareVersion = CK_VERSION {
                        major: info.firmware_version.0,
                        minor: info.firmware_version.1,
                    };
                    space_pad_into(&mut out.utcTime, &info.utc_time);
                }
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_get_mechanism_list(
    slot_id: CK_SLOT_ID,
    p_mechanism_list: CK_MECHANISM_TYPE_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_count.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.get_mechanism_list(CkSlotId(slot_id as u64))) {
            Ok(mechs) => {
                let registry = state::mechanism_registry();
                let filtered: Vec<u64> =
                    registry.filter_mechanisms(&mechs.iter().map(|m| m.0).collect::<Vec<_>>());
                let count = filtered.len() as CK_ULONG;
                unsafe {
                    if p_mechanism_list.is_null() {
                        *pul_count = count;
                        return rv_ok();
                    }
                    if *pul_count < count {
                        *pul_count = count;
                        return rv_err(CkRv::BUFFER_TOO_SMALL);
                    }
                    for (i, m) in filtered.iter().enumerate() {
                        *p_mechanism_list.add(i) = *m as CK_MECHANISM_TYPE;
                    }
                    *pul_count = count;
                }
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_get_mechanism_info(
    slot_id: CK_SLOT_ID,
    mechanism_type: CK_MECHANISM_TYPE,
    p_info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_info.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.get_mechanism_info(
            CkSlotId(slot_id as u64),
            CkMechanismType(mechanism_type as u64)
        )) {
            Ok(info) => {
                unsafe {
                    let out = &mut *p_info;
                    out.ulMinKeySize = info.min_key_size as CK_ULONG;
                    out.ulMaxKeySize = info.max_key_size as CK_ULONG;
                    out.flags = info.flags.0 as CK_FLAGS;
                }
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

#[cfg(test)]
mod token_info_field_tests {
    use super::token_info_field;
    use cryptoki_sys::{CK_ULONG, CK_UNAVAILABLE_INFORMATION};
    use pkcs11_proxy_ng_types::CANONICAL_UNAVAILABLE;

    #[test]
    fn maps_canonical_sentinel_to_native_unavailable() {
        // The wire sentinel must surface as the client's native
        // CK_UNAVAILABLE_INFORMATION regardless of CK_ULONG width.
        assert_eq!(token_info_field(CANONICAL_UNAVAILABLE), CK_UNAVAILABLE_INFORMATION);
    }

    #[test]
    fn passes_through_representable_values() {
        assert_eq!(token_info_field(42), 42 as CK_ULONG);
        // CK_EFFECTIVELY_INFINITE (0) is a real value, not a sentinel.
        assert_eq!(token_info_field(0), 0 as CK_ULONG);
    }

    #[test]
    fn reports_unrepresentable_value_as_unavailable_not_truncated() {
        // A 64-bit backend value exceeding the client's CK_ULONG range (e.g. a
        // >4 GiB memory counter reported to a 32-bit client) must surface as
        // CK_UNAVAILABLE_INFORMATION, never a silently truncated value. On a
        // 64-bit client nothing overflows and the value passes through.
        let big = 5_000_000_000u64;
        if std::mem::size_of::<CK_ULONG>() == 4 {
            assert_eq!(token_info_field(big), CK_UNAVAILABLE_INFORMATION);
        } else {
            assert_eq!(token_info_field(big), big as CK_ULONG);
        }
    }
}

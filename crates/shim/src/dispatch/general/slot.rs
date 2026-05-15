use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use crate::state;

#[allow(unused_imports)]
use super::*;

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
        match with_client!(client => client.get_slot_info(CkSlotId(slot_id))) {
            Ok(info) => {
                unsafe {
                    let out = &mut *p_info;
                    pad_string(&mut out.slotDescription, &info.slot_description);
                    pad_string(&mut out.manufacturerID, &info.manufacturer_id);
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

pub unsafe extern "C" fn c_get_token_info(slot_id: CK_SLOT_ID, p_info: CK_TOKEN_INFO_PTR) -> CK_RV {
    catch_panics(|| {
        if p_info.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.get_token_info(CkSlotId(slot_id))) {
            Ok(info) => {
                unsafe {
                    let out = &mut *p_info;
                    pad_string(&mut out.label, &info.label);
                    pad_string(&mut out.manufacturerID, &info.manufacturer_id);
                    pad_string(&mut out.model, &info.model);
                    pad_string(&mut out.serialNumber, &info.serial_number);
                    out.flags = info.flags.0 as CK_FLAGS;
                    out.ulMaxSessionCount = info.max_session_count as CK_ULONG;
                    out.ulSessionCount = info.session_count as CK_ULONG;
                    out.ulMaxRwSessionCount = info.max_rw_session_count as CK_ULONG;
                    out.ulRwSessionCount = info.rw_session_count as CK_ULONG;
                    out.ulMaxPinLen = info.max_pin_len as CK_ULONG;
                    out.ulMinPinLen = info.min_pin_len as CK_ULONG;
                    out.ulTotalPublicMemory = info.total_public_memory as CK_ULONG;
                    out.ulFreePublicMemory = info.free_public_memory as CK_ULONG;
                    out.ulTotalPrivateMemory = info.total_private_memory as CK_ULONG;
                    out.ulFreePrivateMemory = info.free_private_memory as CK_ULONG;
                    out.hardwareVersion = CK_VERSION {
                        major: info.hardware_version.0,
                        minor: info.hardware_version.1,
                    };
                    out.firmwareVersion = CK_VERSION {
                        major: info.firmware_version.0,
                        minor: info.firmware_version.1,
                    };
                    pad_string(&mut out.utcTime, &info.utc_time);
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
        match with_client!(client => client.get_mechanism_list(CkSlotId(slot_id))) {
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
            CkSlotId(slot_id),
            CkMechanismType(mechanism_type)
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

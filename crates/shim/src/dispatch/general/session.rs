use cryptoki_sys::*;
use pkcs11_proxy_ng_client::MessageCallErrorOrigin;
use pkcs11_proxy_ng_types::*;

use super::helpers::{
    catch_panics, rv_err, rv_ok, try_read_optional_bytes, unit_result_to_rv, with_client,
    write_session_handle_output,
};

pub unsafe extern "C" fn c_open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _p_application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    ph_session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    catch_panics(|| {
        if ph_session.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.open_session(CkSlotId(slot_id as u64), CkSessionFlags(flags as u64)))
        {
            Ok(handle) => {
                let raw_handle = handle.0 as CK_SESSION_HANDLE;
                unsafe { write_session_handle_output(handle, ph_session) };
                crate::state::remember_session_slot(raw_handle, slot_id);
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_close_session(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        let result = with_client!(client => client.close_session_stateful(
            CkSessionHandle(h_session as u64)
        ));
        // Authoritative session/message state survives only a decoded
        // transient provider failure, so a still-valid handle can safely
        // retry or continue. (W1-C6-04: no disposable output caches remain.)
        let evict_authoritative = match &result {
            Ok(()) => true,
            Err(error) if error.origin != MessageCallErrorOrigin::Backend => true,
            Err(error) => {
                error.ck_rv == CkRv::DEVICE_ERROR
                    || error.ck_rv == CkRv::SESSION_CLOSED
                    || error.ck_rv == CkRv::SESSION_HANDLE_INVALID
            }
        };
        if evict_authoritative {
            crate::state::evict_session_authoritative_state(h_session);
        }
        unit_result_to_rv(result.map_err(|error| error.ck_rv))
    })
}

pub unsafe extern "C" fn c_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    catch_panics(|| {
        let result = with_client!(client => client.close_all_sessions(CkSlotId(slot_id as u64)));
        // Evicted on the attempt, regardless of CK_RV (see evict_slot_session_caches).
        crate::state::evict_slot_session_caches(slot_id);
        unit_result_to_rv(result)
    })
}

pub unsafe extern "C" fn c_get_session_info(
    h_session: CK_SESSION_HANDLE,
    p_info: CK_SESSION_INFO_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_info.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.get_session_info(CkSessionHandle(h_session as u64))) {
            Ok(info) => {
                unsafe {
                    let out = &mut *p_info;
                    out.slotID = info.slot_id.0 as CK_SLOT_ID;
                    out.state = info.state as CK_STATE;
                    out.flags = info.flags.0 as CK_FLAGS;
                    out.ulDeviceError = info.device_error.0 as CK_ULONG;
                }
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_login(
    h_session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    p_pin: CK_UTF8CHAR_PTR,
    ul_pin_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let ut = match CkUserType::from_raw(user_type.into()) {
            Some(ut) => ut,
            None => return rv_err(CkRv::USER_TYPE_INVALID),
        };
        let pin = match unsafe { try_read_optional_bytes(p_pin, ul_pin_len) } {
            Ok(pin) => pin,
            Err(e) => return rv_err(e),
        };
        unit_result_to_rv(
            with_client!(client => client.login(CkSessionHandle(h_session as u64), ut, pin)),
        )
    })
}

pub unsafe extern "C" fn c_logout(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(with_client!(client => client.logout(
            CkSessionHandle(h_session as u64)
        )))
    })
}

// ---------------------------------------------------------------------------
// Legacy parallel function status (PKCS#11 2.40)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_get_function_status(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(with_client!(client => client.get_function_status(
            CkSessionHandle(h_session as u64)
        )))
    })
}

pub unsafe extern "C" fn c_cancel_function(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(with_client!(client => client.cancel_function(
            CkSessionHandle(h_session as u64)
        )))
    })
}

// ---------------------------------------------------------------------------
// Token / PIN administration
// ---------------------------------------------------------------------------

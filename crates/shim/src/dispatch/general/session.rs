use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

#[allow(unused_imports)]
use super::*;

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
        match with_client!(client => client.open_session(CkSlotId(slot_id), CkSessionFlags(flags)))
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
        let result = with_client!(client => client.close_session(
            CkSessionHandle(h_session)
        ));
        if result.is_ok() {
            crate::state::evict_session_caches(h_session);
        }
        unit_result_to_rv(result)
    })
}

pub unsafe extern "C" fn c_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    catch_panics(|| {
        let result = with_client!(client => client.close_all_sessions(CkSlotId(slot_id)));
        if result.is_ok() {
            crate::state::evict_slot_session_caches(slot_id);
        }
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
        match with_client!(client => client.get_session_info(CkSessionHandle(h_session))) {
            Ok(info) => {
                unsafe {
                    let out = &mut *p_info;
                    out.slotID = info.slot_id.0 as CK_SLOT_ID;
                    out.state = info.state as CK_STATE;
                    out.flags = info.flags.0 as CK_FLAGS;
                    out.ulDeviceError = info.device_error as CK_ULONG;
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
        let ut = match CkUserType::from_raw(user_type) {
            Some(ut) => ut,
            None => return rv_err(CkRv::USER_TYPE_INVALID),
        };
        let pin = if p_pin.is_null() {
            None
        } else {
            Some(unsafe { read_input_slice(p_pin, ul_pin_len) })
        };
        unit_result_to_rv(with_client!(client => client.login(CkSessionHandle(h_session), ut, pin)))
    })
}

pub unsafe extern "C" fn c_logout(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(with_client!(client => client.logout(
            CkSessionHandle(h_session)
        )))
    })
}

// ---------------------------------------------------------------------------
// Legacy parallel function status (PKCS#11 2.40)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_get_function_status(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(with_client!(client => client.get_function_status(
            CkSessionHandle(h_session)
        )))
    })
}

pub unsafe extern "C" fn c_cancel_function(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(with_client!(client => client.cancel_function(
            CkSessionHandle(h_session)
        )))
    })
}

// ---------------------------------------------------------------------------
// Token / PIN administration
// ---------------------------------------------------------------------------

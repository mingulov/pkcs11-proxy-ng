use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

#[allow(unused_imports)]
use super::*;

pub unsafe extern "C" fn c_init_token(
    slot_id: CK_SLOT_ID,
    p_pin: CK_UTF8CHAR_PTR,
    ul_pin_len: CK_ULONG,
    p_label: CK_UTF8CHAR_PTR,
) -> CK_RV {
    catch_panics(|| {
        let so_pin = if p_pin.is_null() {
            None
        } else {
            Some(unsafe { read_input_slice(p_pin, ul_pin_len) })
        };
        // PKCS#11 label is 32 bytes, space-padded; trim trailing spaces for client.
        let label = if p_label.is_null() {
            String::new()
        } else {
            let raw = unsafe { read_input_slice(p_label, 32) };
            String::from_utf8_lossy(raw).trim_end().to_string()
        };
        match with_client!(client => client.init_token(CkSlotId(slot_id), so_pin, &label)) {
            Ok(()) => rv_ok(),
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_init_pin(
    h_session: CK_SESSION_HANDLE,
    p_pin: CK_UTF8CHAR_PTR,
    ul_pin_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let pin = if p_pin.is_null() {
            None
        } else {
            Some(unsafe { read_input_slice(p_pin, ul_pin_len) })
        };
        match with_client!(client => client.init_pin(CkSessionHandle(h_session), pin)) {
            Ok(()) => rv_ok(),
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_set_pin(
    h_session: CK_SESSION_HANDLE,
    p_old_pin: CK_UTF8CHAR_PTR,
    ul_old_len: CK_ULONG,
    p_new_pin: CK_UTF8CHAR_PTR,
    ul_new_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let old_pin = if p_old_pin.is_null() {
            None
        } else {
            Some(unsafe { read_input_slice(p_old_pin, ul_old_len) })
        };
        let new_pin = if p_new_pin.is_null() {
            None
        } else {
            Some(unsafe { read_input_slice(p_new_pin, ul_new_len) })
        };
        match with_client!(client => client.set_pin(CkSessionHandle(h_session), old_pin, new_pin)) {
            Ok(()) => rv_ok(),
            Err(e) => rv_err(e),
        }
    })
}

// ---------------------------------------------------------------------------
// Object discovery
// ---------------------------------------------------------------------------

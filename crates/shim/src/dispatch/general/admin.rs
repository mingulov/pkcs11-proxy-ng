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
        let so_pin = match unsafe { try_read_optional_bytes(p_pin, ul_pin_len) } {
            Ok(pin) => pin,
            Err(e) => return rv_err(e),
        };
        // PKCS#11 label is 32 bytes, space-padded; trim trailing spaces for client.
        let label = if p_label.is_null() {
            String::new()
        } else {
            let raw = unsafe { read_input_slice(p_label, 32) };
            String::from_utf8_lossy(raw).trim_end().to_string()
        };
        match with_client!(client => client.init_token(CkSlotId(slot_id as u64), so_pin, &label)) {
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
        let pin = match unsafe { try_read_optional_bytes(p_pin, ul_pin_len) } {
            Ok(pin) => pin,
            Err(e) => return rv_err(e),
        };
        match with_client!(client => client.init_pin(CkSessionHandle(h_session as u64), pin)) {
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
        let old_pin = match unsafe { try_read_optional_bytes(p_old_pin, ul_old_len) } {
            Ok(pin) => pin,
            Err(e) => return rv_err(e),
        };
        let new_pin = match unsafe { try_read_optional_bytes(p_new_pin, ul_new_len) } {
            Ok(pin) => pin,
            Err(e) => return rv_err(e),
        };
        match with_client!(client => client.set_pin(CkSessionHandle(h_session as u64), old_pin, new_pin))
        {
            Ok(()) => rv_ok(),
            Err(e) => rv_err(e),
        }
    })
}

// ---------------------------------------------------------------------------
// Object discovery
// ---------------------------------------------------------------------------

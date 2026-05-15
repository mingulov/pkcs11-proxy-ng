//! Shim dispatch for PKCS#11 3.2 async operations (Wave 5, Option B: polling only).
//!
//! - `C_AsyncComplete` — calls client, maps CK_ASYNC_DATA
//! - `C_AsyncGetID` — returns CKR_STATE_UNSAVEABLE
//! - `C_AsyncJoin` — returns CKR_SAVED_STATE_INVALID

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use super::helpers::*;

// ---------------------------------------------------------------------------
// C_AsyncComplete — forwards to client, fills CK_ASYNC_DATA on success
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_async_complete(
    h_session: CK_SESSION_HANDLE,
    p_function_name: *mut CK_UTF8CHAR,
    p_async_data: *mut CK_ASYNC_DATA,
) -> CK_RV {
    catch_panics(|| {
        if p_function_name.is_null() || p_async_data.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }

        // Read the null-terminated function name string
        let function_name =
            unsafe { std::ffi::CStr::from_ptr(p_function_name as *const std::os::raw::c_char) };
        let function_name = match function_name.to_str() {
            Ok(s) => s,
            Err(_) => return rv_err(CkRv::ARGUMENTS_BAD),
        };

        let result = with_client!(client => client.async_complete(
            CkSessionHandle(h_session),
            function_name,
        ));

        match result {
            Ok((version, value, value_len, object_handle, additional_object_handle)) => {
                let async_data = unsafe { &mut *p_async_data };
                async_data.ulVersion = version as CK_ULONG;
                // Write value bytes into the async_data value buffer.
                // The caller must provide the pValue buffer;
                // we copy data into it if there is space.
                if !async_data.pValue.is_null() && async_data.ulValue > 0 {
                    let copy_len = value.len().min(async_data.ulValue as usize);
                    if copy_len > 0 {
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                value.as_ptr(),
                                async_data.pValue,
                                copy_len,
                            );
                        }
                    }
                }
                async_data.ulValue = value_len as CK_ULONG;
                async_data.hObject = object_handle.0 as CK_OBJECT_HANDLE;
                async_data.hAdditionalObject = additional_object_handle.0 as CK_OBJECT_HANDLE;
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

// ---------------------------------------------------------------------------
// C_AsyncGetID — always returns CKR_STATE_UNSAVEABLE (Option B)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_async_get_id(
    _h_session: CK_SESSION_HANDLE,
    _p_function_name: *mut CK_UTF8CHAR,
    _pul_operation_id: *mut CK_ULONG,
) -> CK_RV {
    catch_panics(|| rv_err(CkRv::STATE_UNSAVEABLE))
}

// ---------------------------------------------------------------------------
// C_AsyncJoin — always returns CKR_SAVED_STATE_INVALID (Option B)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_async_join(
    _h_session: CK_SESSION_HANDLE,
    _p_function_name: *mut CK_UTF8CHAR,
    _ul_id: CK_ULONG,
    _p_data: *mut CK_BYTE,
    _ul_data: CK_ULONG,
) -> CK_RV {
    catch_panics(|| rv_err(CkRv::SAVED_STATE_INVALID))
}

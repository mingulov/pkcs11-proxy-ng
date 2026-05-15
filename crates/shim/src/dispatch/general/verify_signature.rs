//! Shim dispatch for PKCS#11 3.2 VerifySignature operations (Wave 5).
//!
//! - `C_VerifySignatureInit` — nullable mechanism (NULL = cancel)
//! - `C_VerifySignature` — single-part verify (no output buffer)
//! - `C_VerifySignatureUpdate` — multi-part data feed (no output)
//! - `C_VerifySignatureFinal` — completes multi-part (session-only)

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use super::helpers::*;

// ---------------------------------------------------------------------------
// C_VerifySignatureInit — mechanism is nullable (NULL = cancel active state)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_verify_signature_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
    p_signature: CK_BYTE_PTR,
    ul_signature_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let mech = if p_mechanism.is_null() {
            None // cancel path
        } else {
            let rv = unsafe { validate_mechanism(p_mechanism) };
            if rv != rv_ok() {
                return rv;
            }
            Some(unsafe { read_mechanism(p_mechanism) })
        };
        let signature = unsafe { read_input_slice(p_signature, ul_signature_len) };
        unit_result_to_rv(with_client!(client => client.verify_signature_init(
            CkSessionHandle(h_session),
            mech.as_ref(),
            CkObjectHandle(h_key),
            signature,
        )))
    })
}

// ---------------------------------------------------------------------------
// C_VerifySignature — single-part verify (no output buffer)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_verify_signature(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let data = unsafe { read_input_slice(p_data, ul_data_len) };
        unit_result_to_rv(
            with_client!(client => client.verify_signature(CkSessionHandle(h_session), data)),
        )
    })
}

// ---------------------------------------------------------------------------
// C_VerifySignatureUpdate — multi-part data feed (no output)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_verify_signature_update(
    h_session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    ul_part_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let part = unsafe { read_input_slice(p_part, ul_part_len) };
        unit_result_to_rv(
            with_client!(client => client.verify_signature_update(CkSessionHandle(h_session), part)),
        )
    })
}

// ---------------------------------------------------------------------------
// C_VerifySignatureFinal — session-only
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_verify_signature_final(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(
            with_client!(client => client.verify_signature_final(CkSessionHandle(h_session))),
        )
    })
}

// CK_ULONG is u64 on 64-bit and u32 on 32-bit; `as u64` casts are intentional
// for cross-platform PKCS#11 portability.
#![allow(clippy::unnecessary_cast)]

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

pub(crate) fn rv_ok() -> CK_RV {
    CkRv::OK.0 as CK_RV
}

pub(crate) fn rv_err(e: CkRv) -> CK_RV {
    e.0 as CK_RV
}

pub(crate) fn unit_result_to_rv(result: Result<(), CkRv>) -> CK_RV {
    match result {
        Ok(()) => rv_ok(),
        Err(e) => rv_err(e),
    }
}

macro_rules! with_client {
    ($client:ident => $call:expr) => {{
        if !crate::state::is_initialized() {
            return rv_err(pkcs11_proxy_ng_types::CkRv::CRYPTOKI_NOT_INITIALIZED);
        }
        crate::state::runtime().block_on(async {
            let mut $client = crate::state::client().lock().await;
            $call.await
        })
    }};
}

pub(crate) use with_client;

/// Maximum byte count we will serialize over gRPC.  Any `CK_ULONG` length
/// whose byte size exceeds this is clearly invalid (no real PKCS#11 operation
/// processes 512 MiB of data in one call).  Returning an empty slice for such
/// values prevents undefined behavior from `from_raw_parts` and lets the
/// backend return its own error instead of the shim crashing with SIGABRT.
const MAX_SERIALIZABLE_BYTES: usize = 512 * 1024 * 1024;

pub(crate) unsafe fn read_input_slice<'a, T>(ptr: *const T, len: CK_ULONG) -> &'a [T] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    let count = len as usize;
    let byte_size = count.checked_mul(std::mem::size_of::<T>());
    match byte_size {
        Some(n) if n <= MAX_SERIALIZABLE_BYTES => unsafe { std::slice::from_raw_parts(ptr, count) },
        // Panic instead of returning empty — catch_panics converts
        // to CKR_GENERAL_ERROR so the request never reaches the daemon.
        // Returning empty silently would send broken data to the backend.
        _ => panic!("input length {len} exceeds serializable limit"),
    }
}

pub(crate) unsafe fn write_output_slice<'a, T>(ptr: *mut T, len: usize) -> &'a mut [T] {
    if ptr.is_null() || len == 0 {
        return &mut [];
    }
    let byte_size = len.checked_mul(std::mem::size_of::<T>());
    match byte_size {
        Some(n) if n <= MAX_SERIALIZABLE_BYTES => unsafe {
            std::slice::from_raw_parts_mut(ptr, len)
        },
        _ => panic!("output length {len} exceeds serializable limit"),
    }
}

/// Build a `CkOutputBufferSpec` from the C caller's pointer pair.
///
/// This captures exactly what the PKCS#11 caller passed:
/// - NULL `p_output` → size query (buffer_present = false)
/// - non-NULL `p_output` → data query with the length from `*pul_output_len`
///
/// # Safety
///
/// `pul_output_len` must be non-null and point to a valid `CK_ULONG`.
/// The caller must have already validated `pul_output_len` before calling this.
pub(crate) unsafe fn output_buffer_spec(
    p_output: CK_BYTE_PTR,
    pul_output_len: CK_ULONG_PTR,
) -> pkcs11_proxy_ng_types::CkOutputBufferSpec {
    if p_output.is_null() {
        pkcs11_proxy_ng_types::CkOutputBufferSpec { buffer_present: false, buffer_len: 0 }
    } else {
        pkcs11_proxy_ng_types::CkOutputBufferSpec {
            buffer_present: true,
            buffer_len: unsafe { *pul_output_len } as u64,
        }
    }
}

/// Write an exact `CkOutputBufferResult` back to the C caller.
///
/// Handles all three PKCS#11 outcomes:
/// - `CKR_OK` with no value (size query response): writes `returned_len` to `*pul_output_len`
/// - `CKR_OK` with value: copies bytes to `p_output`, writes `returned_len` to `*pul_output_len`
/// - `CKR_BUFFER_TOO_SMALL`: writes `returned_len` to `*pul_output_len`, no data copy
/// - Other errors: returns the `ck_rv` directly
///
/// # Safety
///
/// `pul_output_len` must be non-null. If the result contains data and `p_output` is non-null,
/// `p_output` must point to a writable buffer of at least `returned_len` bytes.
pub(crate) unsafe fn write_exact_output(
    result: &pkcs11_proxy_ng_types::CkOutputBufferResult,
    p_output: CK_BYTE_PTR,
    pul_output_len: CK_ULONG_PTR,
) -> CK_RV {
    if pul_output_len.is_null() {
        return rv_err(CkRv::ARGUMENTS_BAD);
    }
    let caller_capacity = unsafe { *pul_output_len } as u64;

    // Always write back the returned length
    unsafe { *pul_output_len = result.returned_len as CK_ULONG };

    if result.ck_rv != CkRv::OK {
        return result.ck_rv.0 as CK_RV;
    }

    let Some(ref value) = result.value else {
        return result.ck_rv.0 as CK_RV;
    };
    if p_output.is_null() {
        return result.ck_rv.0 as CK_RV;
    }

    let value_len = value.len() as u64;
    if value_len != result.returned_len || value_len > caller_capacity {
        return rv_err(CkRv::GENERAL_ERROR);
    }
    if !value.is_empty() {
        unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), p_output, value.len()) };
    }

    result.ck_rv.0 as CK_RV
}

pub(crate) unsafe fn write_session_handle_output(
    handle: CkSessionHandle,
    p_handle: CK_SESSION_HANDLE_PTR,
) {
    unsafe { *p_handle = handle.0 as CK_SESSION_HANDLE };
}

pub(crate) unsafe fn write_object_handle_output(
    handle: CkObjectHandle,
    p_handle: CK_OBJECT_HANDLE_PTR,
) {
    unsafe { *p_handle = handle.0 as CK_OBJECT_HANDLE };
}

pub(crate) unsafe fn write_object_handle_pair_output(
    public_handle: CkObjectHandle,
    private_handle: CkObjectHandle,
    p_public_handle: CK_OBJECT_HANDLE_PTR,
    p_private_handle: CK_OBJECT_HANDLE_PTR,
) {
    unsafe {
        *p_public_handle = public_handle.0 as CK_OBJECT_HANDLE;
        *p_private_handle = private_handle.0 as CK_OBJECT_HANDLE;
    }
}

/// Write parameter_out back to a C caller's pParameter buffer.
/// Copies min(parameter_out.len(), ul_parameter_len) bytes.
///
/// # Safety
///
/// `p_parameter` must be either null or point to a writable buffer of at
/// least `ul_parameter_len` bytes.
pub(crate) unsafe fn write_parameter_out(
    parameter_out: &[u8],
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
) {
    if p_parameter.is_null() || ul_parameter_len == 0 {
        return;
    }
    let copy_len = parameter_out.len().min(ul_parameter_len as usize);
    if copy_len > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(parameter_out.as_ptr(), p_parameter as *mut u8, copy_len);
        }
    }
}

/// Build a `CkParameterRoundtripSpec` from the C caller's parameter pointer pair.
///
/// Captures what the caller passed for the dual-purpose parameter buffer:
/// - Non-null `p_parameter` with `ul_parameter_len > 0` → buffer_present = true,
///   and we capture the input bytes as `value`.
/// - Otherwise → buffer_present = false.
///
/// # Safety
///
/// `p_parameter` must be either null or point to a readable buffer of at
/// least `ul_parameter_len` bytes.
pub(crate) unsafe fn parameter_roundtrip_spec(
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
) -> pkcs11_proxy_ng_types::CkParameterRoundtripSpec {
    if p_parameter.is_null() || ul_parameter_len == 0 {
        pkcs11_proxy_ng_types::CkParameterRoundtripSpec {
            buffer_present: false,
            buffer_len: 0,
            value: None,
        }
    } else {
        let input = unsafe {
            std::slice::from_raw_parts(p_parameter as *const u8, ul_parameter_len as usize)
        };
        pkcs11_proxy_ng_types::CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: ul_parameter_len as u64,
            value: Some(input.to_vec()),
        }
    }
}

/// Build a message-parameter roundtrip spec after validating the caller's
/// pointer pair. Message APIs do not go through `CK_MECHANISM`, so they need
/// their own null/size guard before any raw byte capture.
///
/// # Safety
///
/// If `p_parameter` is non-null and `ul_parameter_len > 0`, it must point to
/// a readable buffer of at least `ul_parameter_len` bytes.
pub(crate) unsafe fn message_parameter_roundtrip_spec(
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
) -> pkcs11_proxy_ng_types::CkResult<pkcs11_proxy_ng_types::CkParameterRoundtripSpec> {
    if p_parameter.is_null() {
        return if ul_parameter_len == 0 {
            Ok(pkcs11_proxy_ng_types::CkParameterRoundtripSpec {
                buffer_present: false,
                buffer_len: 0,
                value: None,
            })
        } else {
            Err(pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD)
        };
    }

    if ul_parameter_len == 0 {
        return Ok(pkcs11_proxy_ng_types::CkParameterRoundtripSpec {
            buffer_present: false,
            buffer_len: 0,
            value: None,
        });
    }

    if (ul_parameter_len as usize) > MAX_MECHANISM_PARAM_LEN {
        return Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID);
    }

    Ok(unsafe { parameter_roundtrip_spec(p_parameter, ul_parameter_len) })
}

/// Write both an exact `CkOutputBufferResult` and a `CkParameterRoundtripResult`
/// back to the C caller.
///
/// Handles:
/// 1. Writing the main output via [`write_exact_output`].
/// 2. Writing the parameter write-back bytes to the caller's `p_parameter` buffer.
///
/// # Safety
///
/// Same safety requirements as `write_exact_output` plus `p_parameter` must be
/// writable for `ul_parameter_len` bytes if non-null.
pub(crate) unsafe fn write_exact_parameter_output(
    output_result: &pkcs11_proxy_ng_types::CkOutputBufferResult,
    param_result: &pkcs11_proxy_ng_types::CkParameterRoundtripResult,
    p_output: CK_BYTE_PTR,
    pul_output_len: CK_ULONG_PTR,
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
) -> CK_RV {
    // Write the main output first
    let rv = unsafe { write_exact_output(output_result, p_output, pul_output_len) };

    // Write back the parameter if present and the main result was OK or
    // BUFFER_TOO_SMALL (parameter write-back happens regardless for size queries)
    if let Some(ref param_bytes) = param_result.value {
        unsafe { write_parameter_out(param_bytes, p_parameter, ul_parameter_len) };
    }

    rv
}

pub(crate) fn pad_string(dest: &mut [CK_UTF8CHAR], src: &str) {
    let bytes = src.as_bytes();
    let copy_len = bytes.len().min(dest.len());
    dest[..copy_len].copy_from_slice(&bytes[..copy_len]);
    for b in dest[copy_len..].iter_mut() {
        *b = b' ';
    }
}

pub(crate) fn catch_panics<F>(f: F) -> CK_RV
where
    F: FnOnce() -> CK_RV + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(rv) => rv,
        Err(_) => rv_err(CkRv::GENERAL_ERROR),
    }
}

/// Validate that the proxy can forward a mechanism invocation.
///
/// Uses the global [`MechanismRegistry`] to check whether parameterized
/// mechanisms have a known parameter shape.  Parameterless invocations
/// are always allowed.
///
/// The check is done against the raw `CK_MECHANISM` pointer so that the
/// proxy rejects mechanisms whose parameter shapes are not modeled in the
/// registry before attempting conversion. For mechanisms with known shapes,
/// `read_mechanism` will properly parse the C struct; for unknown shapes
/// it falls back to raw bytes, but `validate_mechanism` prevents those
/// from reaching the server.
///
/// Returns `rv_ok()` when the mechanism is acceptable, or
/// `CKR_MECHANISM_PARAM_INVALID` when the mechanism has unmodeled
/// parameters that the proxy cannot safely serialize.
///
/// # Safety
///
/// `p_mechanism` must point to a valid `CK_MECHANISM` (caller already
/// checked non-null before calling this).
/// Maximum mechanism parameter byte length.  No standard PKCS#11 mechanism
/// parameter struct exceeds a few hundred bytes; 64 KiB is extremely generous.
const MAX_MECHANISM_PARAM_LEN: usize = 65_536;

#[repr(C)]
struct CkKmacParams {
    h_key: CK_OBJECT_HANDLE,
    ul_mac_length: CK_ULONG,
    p_customization_string: CK_VOID_PTR,
    ul_customization_string_len: CK_ULONG,
}

#[repr(C)]
struct CkMuGenParams {
    h_key: CK_OBJECT_HANDLE,
    p_tr: CK_BYTE_PTR,
    ul_tr_len: CK_ULONG,
    p_ctx: CK_BYTE_PTR,
    ul_ctx_len: CK_ULONG,
}

pub(crate) unsafe fn validate_mechanism(p_mechanism: *const CK_MECHANISM) -> CK_RV {
    let c_mech = unsafe { &*p_mechanism };
    let has_params = !c_mech.pParameter.is_null() && c_mech.ulParameterLen > 0;
    // Reject absurd parameter lengths before we attempt to dereference
    // the parameter buffer.  This prevents undefined behavior when the
    // caller passes a small buffer with an enormous ulParameterLen.
    if has_params && (c_mech.ulParameterLen as usize) > MAX_MECHANISM_PARAM_LEN {
        return rv_err(CkRv::MECHANISM_PARAM_INVALID);
    }
    match crate::state::mechanism_registry().check_operation(c_mech.mechanism, has_params) {
        Ok(()) => rv_ok(),
        Err(rv) => rv_err(rv),
    }
}

/// Read a C `CK_MECHANISM` into the typed Rust `CkMechanism` representation.
///
/// Uses the global [`MechanismRegistry`] to determine the parameter shape for
/// the mechanism type. This is the inverse of `mechanism_to_ffi()` in the FFI
/// backend: it converts C structs → Rust types for the shim's gRPC path.
///
/// For mechanisms with no known shape but non-null params, the raw bytes are
/// preserved as `CkMechanismParams::Raw` so they can still reach the server.
///
/// # Safety
///
/// `p_mechanism` must point to a valid `CK_MECHANISM`. If the mechanism has
/// parameters, `pParameter` must point to a valid buffer of at least
/// `ulParameterLen` bytes containing the appropriate C struct.
pub(crate) unsafe fn read_mechanism(p_mechanism: *const CK_MECHANISM) -> CkMechanism {
    let c_mech = unsafe { &*p_mechanism };
    let shape = crate::state::mechanism_registry().param_shape(c_mech.mechanism);
    unsafe { read_mechanism_with_shape(c_mech, shape) }
}

unsafe fn read_mechanism_with_shape(c_mech: &CK_MECHANISM, shape: Option<&str>) -> CkMechanism {
    let mech_type = CkMechanismType(c_mech.mechanism);

    if c_mech.pParameter.is_null() || c_mech.ulParameterLen == 0 {
        return CkMechanism { mechanism_type: mech_type, params: None };
    }

    let param_ptr = c_mech.pParameter;
    let param_len = c_mech.ulParameterLen as usize;

    let params = match shape {
        Some("iv") => {
            // Raw IV bytes — no struct, just the IV data directly.
            let iv =
                unsafe { std::slice::from_raw_parts(param_ptr as *const u8, param_len) }.to_vec();
            Some(CkMechanismParams::Iv(IvParams { iv }))
        }

        Some("rsa_pss") => {
            if param_len < std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: caller guarantees pParameter points to a valid
                // CK_RSA_PKCS_PSS_PARAMS and ulParameterLen >= sizeof.
                let pss = unsafe { &*(param_ptr as *const CK_RSA_PKCS_PSS_PARAMS) };
                Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
                    hash_alg: CkMechanismType(pss.hashAlg),
                    mgf: pss.mgf,
                    salt_len: pss.sLen,
                }))
            }
        }

        Some("rsa_oaep") => {
            if param_len < std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: caller guarantees pParameter points to a valid
                // CK_RSA_PKCS_OAEP_PARAMS and ulParameterLen >= sizeof.
                let oaep = unsafe { &*(param_ptr as *const CK_RSA_PKCS_OAEP_PARAMS) };
                if missing_embedded_pointer(oaep.pSourceData, oaep.ulSourceDataLen) {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let source_data = if oaep.pSourceData.is_null() || oaep.ulSourceDataLen == 0 {
                        Vec::new()
                    } else {
                        // Safety: pSourceData is non-null, ulSourceDataLen > 0.
                        unsafe {
                            std::slice::from_raw_parts(
                                oaep.pSourceData as *const u8,
                                oaep.ulSourceDataLen as usize,
                            )
                        }
                        .to_vec()
                    };
                    Some(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
                        hash_alg: CkMechanismType(oaep.hashAlg),
                        mgf: oaep.mgf,
                        source: oaep.source,
                        source_data,
                    }))
                }
            }
        }

        Some("gcm") => {
            if param_len < std::mem::size_of::<CK_GCM_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_GCM_PARAMS.
                let gcm = unsafe { &*(param_ptr as *const CK_GCM_PARAMS) };
                if missing_embedded_pointer(gcm.pIv, gcm.ulIvLen)
                    || missing_embedded_pointer(gcm.pAAD, gcm.ulAADLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let iv = if gcm.pIv.is_null() || gcm.ulIvLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(gcm.pIv, gcm.ulIvLen as usize) }
                            .to_vec()
                    };
                    let aad = if gcm.pAAD.is_null() || gcm.ulAADLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(gcm.pAAD, gcm.ulAADLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::Gcm(GcmParams {
                        iv,
                        iv_bits: gcm.ulIvBits,
                        iv_buffer_len: gcm_iv_buffer_len(gcm),
                        aad,
                        tag_bits: gcm.ulTagBits,
                    }))
                }
            }
        }

        Some("ccm") => {
            if param_len < std::mem::size_of::<CK_CCM_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_CCM_PARAMS.
                let ccm = unsafe { &*(param_ptr as *const CK_CCM_PARAMS) };
                let nonce = if ccm.pNonce.is_null() || ccm.ulNonceLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(ccm.pNonce, ccm.ulNonceLen as usize) }
                        .to_vec()
                };
                let aad = if ccm.pAAD.is_null() || ccm.ulAADLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(ccm.pAAD, ccm.ulAADLen as usize) }.to_vec()
                };
                Some(CkMechanismParams::Ccm(CcmParams {
                    data_len: ccm.ulDataLen,
                    nonce,
                    aad,
                    mac_len: ccm.ulMACLen,
                }))
            }
        }

        Some("ecdh1_derive") => {
            if param_len < std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_ECDH1_DERIVE_PARAMS.
                let ecdh = unsafe { &*(param_ptr as *const CK_ECDH1_DERIVE_PARAMS) };
                let shared_data = if ecdh.pSharedData.is_null() || ecdh.ulSharedDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(ecdh.pSharedData, ecdh.ulSharedDataLen as usize)
                    }
                    .to_vec()
                };
                let public_data = if ecdh.pPublicData.is_null() || ecdh.ulPublicDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(ecdh.pPublicData, ecdh.ulPublicDataLen as usize)
                    }
                    .to_vec()
                };
                Some(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
                    kdf: ecdh.kdf,
                    shared_data,
                    public_data,
                }))
            }
        }

        Some("aes_ctr") => {
            if param_len < std::mem::size_of::<CK_AES_CTR_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_AES_CTR_PARAMS.
                let ctr = unsafe { &*(param_ptr as *const CK_AES_CTR_PARAMS) };
                Some(CkMechanismParams::AesCtr(AesCtrParams {
                    counter_bits: ctr.ulCounterBits,
                    cb: ctr.cb.to_vec(),
                }))
            }
        }

        Some("camellia_ctr") => {
            if param_len < std::mem::size_of::<CK_CAMELLIA_CTR_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_CAMELLIA_CTR_PARAMS.
                let ctr = unsafe { &*(param_ptr as *const CK_CAMELLIA_CTR_PARAMS) };
                Some(CkMechanismParams::CamelliaCtr(CamelliaCtrParams {
                    counter_bits: ctr.ulCounterBits,
                    cb: ctr.cb.to_vec(),
                }))
            }
        }

        Some("hkdf") => {
            if param_len < std::mem::size_of::<CK_HKDF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_HKDF_PARAMS.
                let hkdf = unsafe { &*(param_ptr as *const CK_HKDF_PARAMS) };
                let salt = if hkdf.pSalt.is_null() || hkdf.ulSaltLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(hkdf.pSalt, hkdf.ulSaltLen as usize) }
                        .to_vec()
                };
                let info = if hkdf.pInfo.is_null() || hkdf.ulInfoLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(hkdf.pInfo, hkdf.ulInfoLen as usize) }
                        .to_vec()
                };
                Some(CkMechanismParams::Hkdf(HkdfParams {
                    extract: hkdf.bExtract != 0,
                    expand: hkdf.bExpand != 0,
                    prf_hash_mechanism: hkdf.prfHashMechanism,
                    salt_type: hkdf.ulSaltType,
                    salt,
                    salt_key_handle: hkdf.hSaltKey,
                    info,
                }))
            }
        }

        Some("eddsa") => {
            if param_len < std::mem::size_of::<CK_EDDSA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_EDDSA_PARAMS.
                let eddsa = unsafe { &*(param_ptr as *const CK_EDDSA_PARAMS) };
                let context_data = if eddsa.pContextData.is_null() || eddsa.ulContextDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            eddsa.pContextData,
                            eddsa.ulContextDataLen as usize,
                        )
                    }
                    .to_vec()
                };
                Some(CkMechanismParams::Eddsa(EddsaParams {
                    ph_flag: eddsa.phFlag != 0,
                    context_data,
                }))
            }
        }

        Some("chacha20") => {
            if param_len < std::mem::size_of::<CK_CHACHA20_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_CHACHA20_PARAMS.
                let ch = unsafe { &*(param_ptr as *const CK_CHACHA20_PARAMS) };
                let block_counter = if ch.pBlockCounter.is_null() {
                    Vec::new()
                } else {
                    // Block counter size is determined by blockCounterBits / 8
                    let bc_bytes = (ch.blockCounterBits as usize).div_ceil(8);
                    if bc_bytes > 0 {
                        unsafe { std::slice::from_raw_parts(ch.pBlockCounter, bc_bytes) }.to_vec()
                    } else {
                        Vec::new()
                    }
                };
                let nonce = if ch.pNonce.is_null() || ch.ulNonceBits == 0 {
                    Vec::new()
                } else {
                    let nonce_bytes = (ch.ulNonceBits as usize).div_ceil(8);
                    unsafe { std::slice::from_raw_parts(ch.pNonce, nonce_bytes) }.to_vec()
                };
                Some(CkMechanismParams::ChaCha20(ChaCha20Params {
                    block_counter,
                    block_counter_bits: ch.blockCounterBits,
                    nonce,
                    nonce_bits: ch.ulNonceBits,
                }))
            }
        }

        Some("salsa20") => {
            if param_len < std::mem::size_of::<CK_SALSA20_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let salsa = unsafe { &*(param_ptr as *const CK_SALSA20_PARAMS) };
                if salsa.pBlockCounter.is_null()
                    || missing_embedded_pointer(salsa.pNonce, salsa.ulNonceBits)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let block_counter =
                        unsafe { std::slice::from_raw_parts(salsa.pBlockCounter, 8) }.to_vec();
                    let nonce = if salsa.pNonce.is_null() || salsa.ulNonceBits == 0 {
                        Vec::new()
                    } else {
                        let nonce_bytes = (salsa.ulNonceBits as usize).div_ceil(8);
                        unsafe { std::slice::from_raw_parts(salsa.pNonce, nonce_bytes) }.to_vec()
                    };
                    Some(CkMechanismParams::Salsa20(Salsa20Params {
                        block_counter,
                        nonce,
                        nonce_bits: salsa.ulNonceBits,
                    }))
                }
            }
        }

        Some("salsa20_chacha20_poly1305") => {
            if param_len < std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_SALSA20_CHACHA20_POLY1305_PARAMS.
                let sp = unsafe { &*(param_ptr as *const CK_SALSA20_CHACHA20_POLY1305_PARAMS) };
                let nonce = if sp.pNonce.is_null() || sp.ulNonceLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(sp.pNonce, sp.ulNonceLen as usize) }
                        .to_vec()
                };
                let aad = if sp.pAAD.is_null() || sp.ulAADLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(sp.pAAD, sp.ulAADLen as usize) }.to_vec()
                };
                Some(CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
                    nonce,
                    aad,
                }))
            }
        }

        Some("aes_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_AES_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe { &*(param_ptr as *const CK_AES_CBC_ENCRYPT_DATA_PARAMS) };
                let data = if s.pData.is_null() || s.length == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(s.pData, s.length as usize) }.to_vec()
                };
                Some(CkMechanismParams::AesCbcEncryptData(AesCbcEncryptDataParams {
                    iv: s.iv.to_vec(),
                    data,
                }))
            }
        }

        Some("des_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_DES_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_DES_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe { &*(param_ptr as *const CK_DES_CBC_ENCRYPT_DATA_PARAMS) };
                let data = if s.pData.is_null() || s.length == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(s.pData, s.length as usize) }.to_vec()
                };
                Some(CkMechanismParams::DesCbcEncryptData(DesCbcEncryptDataParams {
                    iv: s.iv.to_vec(),
                    data,
                }))
            }
        }

        Some("camellia_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe { &*(param_ptr as *const CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS) };
                let data = if s.pData.is_null() || s.length == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(s.pData, s.length as usize) }.to_vec()
                };
                Some(CkMechanismParams::CamelliaCbcEncryptData(CamelliaCbcEncryptDataParams {
                    iv: s.iv.to_vec(),
                    data,
                }))
            }
        }

        Some("aria_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_ARIA_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe { &*(param_ptr as *const CK_ARIA_CBC_ENCRYPT_DATA_PARAMS) };
                let data = if s.pData.is_null() || s.length == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(s.pData, s.length as usize) }.to_vec()
                };
                Some(CkMechanismParams::AriaCbcEncryptData(AriaCbcEncryptDataParams {
                    iv: s.iv.to_vec(),
                    data,
                }))
            }
        }

        Some("seed_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_SEED_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_SEED_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe { &*(param_ptr as *const CK_SEED_CBC_ENCRYPT_DATA_PARAMS) };
                let data = if s.pData.is_null() || s.length == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(s.pData, s.length as usize) }.to_vec()
                };
                Some(CkMechanismParams::SeedCbcEncryptData(SeedCbcEncryptDataParams {
                    iv: s.iv.to_vec(),
                    data,
                }))
            }
        }

        Some("mac_general") => {
            if param_len < std::mem::size_of::<CK_MAC_GENERAL_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a CK_MAC_GENERAL_PARAMS
                // (which is a CK_ULONG).
                let val = unsafe { *(param_ptr as *const CK_MAC_GENERAL_PARAMS) };
                Some(CkMechanismParams::MacGeneral(MacGeneralParams { mac_length: val }))
            }
        }

        Some("object_handle") => {
            if param_len < std::mem::size_of::<CK_OBJECT_HANDLE>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a CK_OBJECT_HANDLE
                // (which is a CK_ULONG).
                let val = unsafe { *(param_ptr as *const CK_OBJECT_HANDLE) };
                Some(CkMechanismParams::ObjectHandle(ObjectHandleParam { handle: val as u64 }))
            }
        }

        Some("extract") => {
            if param_len < std::mem::size_of::<CK_EXTRACT_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let val = unsafe { *(param_ptr as *const CK_EXTRACT_PARAMS) };
                Some(CkMechanismParams::Extract(ExtractParams { bit_position: val as u64 }))
            }
        }

        Some("key_derivation_string") => {
            if param_len < std::mem::size_of::<CK_KEY_DERIVATION_STRING_DATA>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_KEY_DERIVATION_STRING_DATA.
                let kds = unsafe { &*(param_ptr as *const CK_KEY_DERIVATION_STRING_DATA) };
                let data = if kds.pData.is_null() || kds.ulLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(kds.pData, kds.ulLen as usize) }.to_vec()
                };
                Some(CkMechanismParams::KeyDerivationString(KeyDerivationStringData { data }))
            }
        }

        Some("gcm_wrap") => {
            if param_len < std::mem::size_of::<CK_GCM_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_GCM_WRAP_PARAMS.
                let gw = unsafe { &*(param_ptr as *const CK_GCM_WRAP_PARAMS) };
                let iv = if gw.pIv.is_null() || gw.ulIvLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(gw.pIv, gw.ulIvLen as usize) }.to_vec()
                };
                let aad = if gw.pAAD.is_null() || gw.ulAADLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(gw.pAAD, gw.ulAADLen as usize) }.to_vec()
                };
                Some(CkMechanismParams::GcmWrap(GcmWrapParams {
                    iv,
                    iv_fixed_bits: gw.ulIvFixedBits,
                    iv_generator: gw.ivGenerator,
                    aad,
                    tag_bits: gw.ulTagBits,
                }))
            }
        }

        Some("ccm_wrap") => {
            if param_len < std::mem::size_of::<CK_CCM_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_CCM_WRAP_PARAMS.
                let cw = unsafe { &*(param_ptr as *const CK_CCM_WRAP_PARAMS) };
                let nonce = if cw.pNonce.is_null() || cw.ulNonceLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(cw.pNonce, cw.ulNonceLen as usize) }
                        .to_vec()
                };
                let aad = if cw.pAAD.is_null() || cw.ulAADLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(cw.pAAD, cw.ulAADLen as usize) }.to_vec()
                };
                Some(CkMechanismParams::CcmWrap(CcmWrapParams {
                    data_len: cw.ulDataLen,
                    nonce,
                    nonce_fixed_bits: cw.ulNonceFixedBits,
                    nonce_generator: cw.nonceGenerator,
                    aad,
                    mac_len: cw.ulMACLen,
                }))
            }
        }

        Some("rc5") => {
            if param_len < std::mem::size_of::<CK_RC5_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_RC5_PARAMS.
                let rc5 = unsafe { &*(param_ptr as *const CK_RC5_PARAMS) };
                Some(CkMechanismParams::Rc5(Rc5Params {
                    word_size: rc5.ulWordsize,
                    rounds: rc5.ulRounds,
                }))
            }
        }

        Some("rc5_mac_general") => {
            if param_len < std::mem::size_of::<CK_RC5_MAC_GENERAL_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let rc5 = unsafe { &*(param_ptr as *const CK_RC5_MAC_GENERAL_PARAMS) };
                Some(CkMechanismParams::Rc5MacGeneral(Rc5MacGeneralParams {
                    word_size: rc5.ulWordsize,
                    rounds: rc5.ulRounds,
                    mac_length: rc5.ulMacLength,
                }))
            }
        }

        Some("rc5_cbc") => {
            if param_len < std::mem::size_of::<CK_RC5_CBC_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let rc5 = unsafe { &*(param_ptr as *const CK_RC5_CBC_PARAMS) };
                if missing_embedded_pointer(rc5.pIv, rc5.ulIvLen) {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let iv = if rc5.pIv.is_null() || rc5.ulIvLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(rc5.pIv, rc5.ulIvLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::Rc5Cbc(Rc5CbcParams {
                        word_size: rc5.ulWordsize,
                        rounds: rc5.ulRounds,
                        iv,
                    }))
                }
            }
        }

        Some("rc2_cbc") => {
            if param_len < std::mem::size_of::<CK_RC2_CBC_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_RC2_CBC_PARAMS.
                let rc2 = unsafe { &*(param_ptr as *const CK_RC2_CBC_PARAMS) };
                Some(CkMechanismParams::Rc2Cbc(Rc2CbcParams {
                    effective_bits: rc2.ulEffectiveBits,
                    iv: rc2.iv.to_vec(),
                }))
            }
        }

        Some("rc2_mac_general") => {
            if param_len < std::mem::size_of::<CK_RC2_MAC_GENERAL_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let rc2 = unsafe { &*(param_ptr as *const CK_RC2_MAC_GENERAL_PARAMS) };
                Some(CkMechanismParams::Rc2MacGeneral(Rc2MacGeneralParams {
                    effective_bits: rc2.ulEffectiveBits,
                    mac_length: rc2.ulMacLength,
                }))
            }
        }

        Some("xeddsa") => {
            if param_len < std::mem::size_of::<CK_XEDDSA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_XEDDSA_PARAMS.
                let xed = unsafe { &*(param_ptr as *const CK_XEDDSA_PARAMS) };
                Some(CkMechanismParams::Xeddsa(XeddsaParams { hash: xed.hash }))
            }
        }

        Some("tls_mac") => {
            if param_len < std::mem::size_of::<CK_TLS_MAC_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_TLS_MAC_PARAMS.
                let tls = unsafe { &*(param_ptr as *const CK_TLS_MAC_PARAMS) };
                Some(CkMechanismParams::TlsMac(TlsMacParams {
                    prf_hash_mechanism: tls.prfHashMechanism,
                    mac_length: tls.ulMacLength,
                    server_or_client: tls.ulServerOrClient,
                }))
            }
        }

        Some("rsa_aes_key_wrap") => {
            // CK_RSA_AES_KEY_WRAP_PARAMS: { CK_ULONG ulAESKeyBits,
            //                                CK_RSA_PKCS_OAEP_PARAMS_PTR pOAEPParams }
            // Not in cryptoki-sys, so read fields manually.
            let expected_size =
                std::mem::size_of::<CK_ULONG>() + std::mem::size_of::<*mut std::ffi::c_void>();
            if param_len < expected_size {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: param_ptr is valid for at least expected_size bytes.
                let aes_key_bits = unsafe { *(param_ptr as *const CK_ULONG) };
                let oaep_ptr_offset = std::mem::size_of::<CK_ULONG>();
                let oaep_ptr = unsafe {
                    *(param_ptr.add(oaep_ptr_offset) as *const *const CK_RSA_PKCS_OAEP_PARAMS)
                };
                if oaep_ptr.is_null() {
                    Some(CkMechanismParams::Raw(RawMechanismParams {
                        data: unsafe { read_raw_bytes(param_ptr, param_len) },
                    }))
                } else {
                    // Safety: oaep_ptr is non-null and points to a valid
                    // CK_RSA_PKCS_OAEP_PARAMS (caller contract).
                    let oaep = unsafe { &*oaep_ptr };
                    let source_data = if oaep.pSourceData.is_null() || oaep.ulSourceDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(
                                oaep.pSourceData as *const u8,
                                oaep.ulSourceDataLen as usize,
                            )
                        }
                        .to_vec()
                    };
                    Some(CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
                        aes_key_bits: aes_key_bits as u64,
                        oaep_params: RsaPkcsOaepParams {
                            hash_alg: CkMechanismType(oaep.hashAlg),
                            mgf: oaep.mgf,
                            source: oaep.source,
                            source_data,
                        },
                    }))
                }
            }
        }

        Some("sign_additional_context") => {
            // CK_SIGN_ADDITIONAL_CONTEXT: { CK_ULONG hedgeVariant, CK_BYTE_PTR pContext, CK_ULONG ulContextLen }
            let min_size = std::mem::size_of::<CK_ULONG>()
                + std::mem::size_of::<*mut u8>()
                + std::mem::size_of::<CK_ULONG>();
            if param_len < min_size {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let hedge_variant = unsafe { *(param_ptr as *const CK_ULONG) };
                let ptr_offset = std::mem::size_of::<CK_ULONG>();
                let ctx_ptr = unsafe { *(param_ptr.add(ptr_offset) as *const *const u8) };
                let len_offset = ptr_offset + std::mem::size_of::<*const u8>();
                let ctx_len = unsafe { *(param_ptr.add(len_offset) as *const CK_ULONG) };
                let context = if ctx_ptr.is_null() || ctx_len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(ctx_ptr, ctx_len as usize) }.to_vec()
                };
                Some(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                    hedge_variant: hedge_variant as u64,
                    context,
                }))
            }
        }

        Some("kmac") => {
            if param_len < std::mem::size_of::<CkKmacParams>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CkKmacParams) };
                if missing_embedded_pointer(
                    p.p_customization_string as *const u8,
                    p.ul_customization_string_len,
                ) {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let customization_string = if p.p_customization_string.is_null()
                        || p.ul_customization_string_len == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(
                                p.p_customization_string as *const u8,
                                p.ul_customization_string_len as usize,
                            )
                        }
                        .to_vec()
                    };
                    Some(CkMechanismParams::Kmac(KmacParams {
                        key_handle: p.h_key as u64,
                        mac_length: p.ul_mac_length as u64,
                        customization_string,
                    }))
                }
            }
        }

        Some("mu_gen") => {
            if param_len < std::mem::size_of::<CkMuGenParams>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CkMuGenParams) };
                if missing_embedded_pointer(p.p_tr, p.ul_tr_len)
                    || missing_embedded_pointer(p.p_ctx, p.ul_ctx_len)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let tr = if p.p_tr.is_null() || p.ul_tr_len == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.p_tr, p.ul_tr_len as usize) }.to_vec()
                    };
                    let context = if p.p_ctx.is_null() || p.ul_ctx_len == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.p_ctx, p.ul_ctx_len as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::MuGen(MuGenParams {
                        key_handle: p.h_key as u64,
                        tr,
                        context,
                    }))
                }
            }
        }

        Some("pkcs5_pbkd2") => {
            if param_len < std::mem::size_of::<CK_PKCS5_PBKD2_PARAMS2>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_PKCS5_PBKD2_PARAMS2) };
                let salt_source_data = if p.pSaltSourceData.is_null() || p.ulSaltSourceDataLen == 0
                {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            p.pSaltSourceData as *const u8,
                            p.ulSaltSourceDataLen as usize,
                        )
                    }
                    .to_vec()
                };
                let prf_data = if p.pPrfData.is_null() || p.ulPrfDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(p.pPrfData as *const u8, p.ulPrfDataLen as usize)
                    }
                    .to_vec()
                };
                let password = if p.pPassword.is_null() || p.ulPasswordLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pPassword, p.ulPasswordLen as usize) }
                        .to_vec()
                };
                Some(CkMechanismParams::Pkcs5Pbkd2(Pkcs5Pbkd2Params {
                    salt_source: p.saltSource as u64,
                    salt_source_data,
                    iterations: p.iterations as u64,
                    prf: p.prf as u64,
                    prf_data,
                    password,
                }))
            }
        }

        Some("wtls_master_key_derive") => {
            if param_len < std::mem::size_of::<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_WTLS_MASTER_KEY_DERIVE_PARAMS) };
                if missing_embedded_pointer(
                    p.RandomInfo.pClientRandom,
                    p.RandomInfo.ulClientRandomLen,
                ) || missing_embedded_pointer(
                    p.RandomInfo.pServerRandom,
                    p.RandomInfo.ulServerRandomLen,
                ) {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let client_random = if p.RandomInfo.pClientRandom.is_null()
                        || p.RandomInfo.ulClientRandomLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(
                                p.RandomInfo.pClientRandom,
                                p.RandomInfo.ulClientRandomLen as usize,
                            )
                        }
                        .to_vec()
                    };
                    let server_random = if p.RandomInfo.pServerRandom.is_null()
                        || p.RandomInfo.ulServerRandomLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(
                                p.RandomInfo.pServerRandom,
                                p.RandomInfo.ulServerRandomLen as usize,
                            )
                        }
                        .to_vec()
                    };
                    let version =
                        if p.pVersion.is_null() { 0 } else { unsafe { *p.pVersion as u32 } };
                    Some(CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
                        digest_mechanism: p.DigestMechanism as u64,
                        random_info: WtlsRandomData { client_random, server_random },
                        version,
                    }))
                }
            }
        }

        Some("wtls_prf") => {
            if param_len < std::mem::size_of::<CK_WTLS_PRF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_WTLS_PRF_PARAMS) };
                if missing_embedded_pointer(p.pSeed, p.ulSeedLen)
                    || missing_embedded_pointer(p.pLabel, p.ulLabelLen)
                    || p.ulSeedLen as usize > MAX_MECHANISM_PARAM_LEN
                    || p.ulLabelLen as usize > MAX_MECHANISM_PARAM_LEN
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let seed = if p.pSeed.is_null() || p.ulSeedLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pSeed, p.ulSeedLen as usize) }
                            .to_vec()
                    };
                    let label = if p.pLabel.is_null() || p.ulLabelLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pLabel, p.ulLabelLen as usize) }
                            .to_vec()
                    };
                    let output_len = if p.pulOutputLen.is_null() {
                        0
                    } else {
                        unsafe { *p.pulOutputLen as u64 }
                    };
                    Some(CkMechanismParams::WtlsPrf(WtlsPrfParams {
                        digest_mechanism: p.DigestMechanism as u64,
                        seed,
                        label,
                        output_len,
                    }))
                }
            }
        }

        Some("wtls_key_mat") => {
            if param_len < std::mem::size_of::<CK_WTLS_KEY_MAT_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_WTLS_KEY_MAT_PARAMS) };
                let requested_iv_len = ((p.ulIVSizeInBits as usize).saturating_add(7)) / 8;
                if missing_embedded_pointer(
                    p.RandomInfo.pClientRandom,
                    p.RandomInfo.ulClientRandomLen,
                ) || missing_embedded_pointer(
                    p.RandomInfo.pServerRandom,
                    p.RandomInfo.ulServerRandomLen,
                ) || p.pReturnedKeyMaterial.is_null()
                    || requested_iv_len > MAX_MECHANISM_PARAM_LEN
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let iv_len = requested_iv_len;
                    let output = unsafe { &*p.pReturnedKeyMaterial };
                    if missing_embedded_pointer(output.pIV, iv_len as CK_ULONG) {
                        Some(raw_mechanism_params(param_ptr, param_len))
                    } else {
                        let client_random = if p.RandomInfo.pClientRandom.is_null()
                            || p.RandomInfo.ulClientRandomLen == 0
                        {
                            Vec::new()
                        } else {
                            unsafe {
                                std::slice::from_raw_parts(
                                    p.RandomInfo.pClientRandom,
                                    p.RandomInfo.ulClientRandomLen as usize,
                                )
                            }
                            .to_vec()
                        };
                        let server_random = if p.RandomInfo.pServerRandom.is_null()
                            || p.RandomInfo.ulServerRandomLen == 0
                        {
                            Vec::new()
                        } else {
                            unsafe {
                                std::slice::from_raw_parts(
                                    p.RandomInfo.pServerRandom,
                                    p.RandomInfo.ulServerRandomLen as usize,
                                )
                            }
                            .to_vec()
                        };
                        let iv = if output.pIV.is_null() || iv_len == 0 {
                            Vec::new()
                        } else {
                            unsafe { std::slice::from_raw_parts(output.pIV, iv_len) }.to_vec()
                        };
                        Some(CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
                            digest_mechanism: p.DigestMechanism as u64,
                            mac_size_bits: p.ulMacSizeInBits as u64,
                            key_size_bits: p.ulKeySizeInBits as u64,
                            iv_size_bits: p.ulIVSizeInBits as u64,
                            sequence_number: p.ulSequenceNumber as u64,
                            is_export: p.bIsExport != 0,
                            random_info: WtlsRandomData { client_random, server_random },
                            mac_secret_handle: output.hMacSecret as u64,
                            key_handle: output.hKey as u64,
                            iv,
                        }))
                    }
                }
            }
        }

        Some("tls12_master_key_derive") => {
            if param_len < std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_TLS12_MASTER_KEY_DERIVE_PARAMS) };
                let client_random = if p.RandomInfo.pClientRandom.is_null()
                    || p.RandomInfo.ulClientRandomLen == 0
                {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            p.RandomInfo.pClientRandom,
                            p.RandomInfo.ulClientRandomLen as usize,
                        )
                    }
                    .to_vec()
                };
                let server_random = if p.RandomInfo.pServerRandom.is_null()
                    || p.RandomInfo.ulServerRandomLen == 0
                {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            p.RandomInfo.pServerRandom,
                            p.RandomInfo.ulServerRandomLen as usize,
                        )
                    }
                    .to_vec()
                };
                let (version_major, version_minor) = if p.pVersion.is_null() {
                    (0, 0)
                } else {
                    let v = unsafe { &*p.pVersion };
                    (v.major as u32, v.minor as u32)
                };
                Some(CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
                    random_info: SslRandomData { client_random, server_random },
                    version_major,
                    version_minor,
                    prf_hash_mechanism: p.prfHashMechanism as u64,
                }))
            }
        }

        Some("tls_prf") => {
            if param_len < std::mem::size_of::<CK_TLS_PRF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_TLS_PRF_PARAMS) };
                let seed = if p.pSeed.is_null() || p.ulSeedLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pSeed, p.ulSeedLen as usize) }.to_vec()
                };
                let label = if p.pLabel.is_null() || p.ulLabelLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pLabel, p.ulLabelLen as usize) }.to_vec()
                };
                let output_len = if p.pulOutputLen.is_null() {
                    0u64
                } else {
                    (unsafe { *p.pulOutputLen }) as u64
                };
                Some(CkMechanismParams::TlsPrf(TlsPrfParams { seed, label, output_len }))
            }
        }

        Some("tls_kdf") => {
            if param_len < std::mem::size_of::<CK_TLS_KDF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_TLS_KDF_PARAMS) };
                let label = if p.pLabel.is_null() || p.ulLabelLength == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pLabel, p.ulLabelLength as usize) }
                        .to_vec()
                };
                let client_random = if p.RandomInfo.pClientRandom.is_null()
                    || p.RandomInfo.ulClientRandomLen == 0
                {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            p.RandomInfo.pClientRandom,
                            p.RandomInfo.ulClientRandomLen as usize,
                        )
                    }
                    .to_vec()
                };
                let server_random = if p.RandomInfo.pServerRandom.is_null()
                    || p.RandomInfo.ulServerRandomLen == 0
                {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            p.RandomInfo.pServerRandom,
                            p.RandomInfo.ulServerRandomLen as usize,
                        )
                    }
                    .to_vec()
                };
                let context_data = if p.pContextData.is_null() || p.ulContextDataLength == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(p.pContextData, p.ulContextDataLength as usize)
                    }
                    .to_vec()
                };
                Some(CkMechanismParams::TlsKdf(TlsKdfParams {
                    prf_mechanism: p.prfMechanism as u64,
                    label,
                    random_info: SslRandomData { client_random, server_random },
                    context_data,
                }))
            }
        }

        Some("ssl3_master_key_derive") => {
            if param_len < std::mem::size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_SSL3_MASTER_KEY_DERIVE_PARAMS) };
                let client_random = if p.RandomInfo.pClientRandom.is_null()
                    || p.RandomInfo.ulClientRandomLen == 0
                {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            p.RandomInfo.pClientRandom,
                            p.RandomInfo.ulClientRandomLen as usize,
                        )
                    }
                    .to_vec()
                };
                let server_random = if p.RandomInfo.pServerRandom.is_null()
                    || p.RandomInfo.ulServerRandomLen == 0
                {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            p.RandomInfo.pServerRandom,
                            p.RandomInfo.ulServerRandomLen as usize,
                        )
                    }
                    .to_vec()
                };
                let (version_major, version_minor) = if p.pVersion.is_null() {
                    (0, 0)
                } else {
                    let v = unsafe { &*p.pVersion };
                    (v.major as u32, v.minor as u32)
                };
                Some(CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
                    random_info: SslRandomData { client_random, server_random },
                    version_major,
                    version_minor,
                }))
            }
        }

        Some("tls12_extended_master_key_derive") => {
            if param_len < std::mem::size_of::<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p =
                    unsafe { &*(param_ptr as *const CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS) };
                let session_hash = if p.pSessionHash.is_null() || p.ulSessionHashLen == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(p.pSessionHash, p.ulSessionHashLen as usize)
                    }
                    .to_vec()
                };
                let (version_major, version_minor) = if p.pVersion.is_null() {
                    (0, 0)
                } else {
                    let v = unsafe { &*p.pVersion };
                    (v.major as u32, v.minor as u32)
                };
                Some(CkMechanismParams::Tls12ExtendedMasterKeyDerive(
                    Tls12ExtendedMasterKeyDeriveParams {
                        prf_hash_mechanism: p.prfHashMechanism as u64,
                        session_hash,
                        version_major,
                        version_minor,
                    },
                ))
            }
        }

        Some("ssl3_key_mat") => {
            // Accept both CK_SSL3_KEY_MAT_PARAMS and CK_TLS12_KEY_MAT_PARAMS.
            // TLS12 is a superset with an extra prfHashMechanism field at the end.
            let ssl3_size = std::mem::size_of::<CK_SSL3_KEY_MAT_PARAMS>();
            let tls12_size = std::mem::size_of::<CK_TLS12_KEY_MAT_PARAMS>();
            if param_len < ssl3_size {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_SSL3_KEY_MAT_PARAMS) };
                let requested_iv_len = ((p.ulIVSizeInBits as usize).saturating_add(7)) / 8;
                if missing_embedded_pointer(
                    p.RandomInfo.pClientRandom,
                    p.RandomInfo.ulClientRandomLen,
                ) || missing_embedded_pointer(
                    p.RandomInfo.pServerRandom,
                    p.RandomInfo.ulServerRandomLen,
                ) || p.pReturnedKeyMaterial.is_null()
                    || requested_iv_len > MAX_MECHANISM_PARAM_LEN
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let output = unsafe { &*p.pReturnedKeyMaterial };
                    let iv_len = requested_iv_len;
                    if missing_embedded_pointer(output.pIVClient, iv_len as CK_ULONG)
                        || missing_embedded_pointer(output.pIVServer, iv_len as CK_ULONG)
                    {
                        Some(raw_mechanism_params(param_ptr, param_len))
                    } else {
                        let client_random = if p.RandomInfo.pClientRandom.is_null()
                            || p.RandomInfo.ulClientRandomLen == 0
                        {
                            Vec::new()
                        } else {
                            unsafe {
                                std::slice::from_raw_parts(
                                    p.RandomInfo.pClientRandom,
                                    p.RandomInfo.ulClientRandomLen as usize,
                                )
                            }
                            .to_vec()
                        };
                        let server_random = if p.RandomInfo.pServerRandom.is_null()
                            || p.RandomInfo.ulServerRandomLen == 0
                        {
                            Vec::new()
                        } else {
                            unsafe {
                                std::slice::from_raw_parts(
                                    p.RandomInfo.pServerRandom,
                                    p.RandomInfo.ulServerRandomLen as usize,
                                )
                            }
                            .to_vec()
                        };
                        let client_iv = if output.pIVClient.is_null() || iv_len == 0 {
                            Vec::new()
                        } else {
                            unsafe { std::slice::from_raw_parts(output.pIVClient, iv_len) }.to_vec()
                        };
                        let server_iv = if output.pIVServer.is_null() || iv_len == 0 {
                            Vec::new()
                        } else {
                            unsafe { std::slice::from_raw_parts(output.pIVServer, iv_len) }.to_vec()
                        };
                        let prf_hash_mechanism = if param_len >= tls12_size {
                            let t = unsafe { &*(param_ptr as *const CK_TLS12_KEY_MAT_PARAMS) };
                            t.prfHashMechanism as u64
                        } else {
                            0
                        };
                        Some(CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                            mac_size_bits: p.ulMacSizeInBits as u64,
                            key_size_bits: p.ulKeySizeInBits as u64,
                            iv_size_bits: p.ulIVSizeInBits as u64,
                            is_export: p.bIsExport != 0,
                            random_info: SslRandomData { client_random, server_random },
                            prf_hash_mechanism,
                            client_mac_secret_handle: output.hClientMacSecret as u64,
                            server_mac_secret_handle: output.hServerMacSecret as u64,
                            client_key_handle: output.hClientKey as u64,
                            server_key_handle: output.hServerKey as u64,
                            client_iv,
                            server_iv,
                        }))
                    }
                }
            }
        }

        Some("pbe") => {
            if param_len < std::mem::size_of::<CK_PBE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_PBE_PARAMS) };
                let init_vector = if p.pInitVector.is_null() {
                    Vec::new()
                } else {
                    // PBE init vector is typically 8 bytes but length is not explicit
                    // in the struct. Use 8 as the standard PBE IV size.
                    unsafe { std::slice::from_raw_parts(p.pInitVector, 8) }.to_vec()
                };
                let password = if p.pPassword.is_null() || p.ulPasswordLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pPassword, p.ulPasswordLen as usize) }
                        .to_vec()
                };
                let salt = if p.pSalt.is_null() || p.ulSaltLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pSalt, p.ulSaltLen as usize) }.to_vec()
                };
                Some(CkMechanismParams::Pbe(PbeParams {
                    init_vector,
                    password,
                    salt,
                    iteration: p.ulIteration as u64,
                }))
            }
        }

        Some("ecdh_aes_key_wrap") => {
            if param_len < std::mem::size_of::<CK_ECDH_AES_KEY_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_ECDH_AES_KEY_WRAP_PARAMS) };
                let shared_data = if p.pSharedData.is_null() || p.ulSharedDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pSharedData, p.ulSharedDataLen as usize) }
                        .to_vec()
                };
                Some(CkMechanismParams::EcdhAesKeyWrap(EcdhAesKeyWrapParams {
                    aes_key_bits: p.ulAESKeyBits as u64,
                    kdf: p.kdf as u64,
                    shared_data,
                }))
            }
        }

        Some("ecdh2_derive") => {
            if param_len < std::mem::size_of::<CK_ECDH2_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_ECDH2_DERIVE_PARAMS) };
                let shared_data = if p.pSharedData.is_null() || p.ulSharedDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pSharedData, p.ulSharedDataLen as usize) }
                        .to_vec()
                };
                let public_data = if p.pPublicData.is_null() || p.ulPublicDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pPublicData, p.ulPublicDataLen as usize) }
                        .to_vec()
                };
                let public_data2 = if p.pPublicData2.is_null() || p.ulPublicDataLen2 == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(p.pPublicData2, p.ulPublicDataLen2 as usize)
                    }
                    .to_vec()
                };
                Some(CkMechanismParams::Ecdh2Derive(Ecdh2DeriveParams {
                    kdf: p.kdf as u64,
                    shared_data,
                    public_data,
                    private_data_len: p.ulPrivateDataLen as u64,
                    private_data_handle: p.hPrivateData as u64,
                    public_data2,
                }))
            }
        }

        Some("ecmqv_derive") => {
            if param_len < std::mem::size_of::<CK_ECMQV_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_ECMQV_DERIVE_PARAMS) };
                let shared_data = if p.pSharedData.is_null() || p.ulSharedDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pSharedData, p.ulSharedDataLen as usize) }
                        .to_vec()
                };
                let public_data = if p.pPublicData.is_null() || p.ulPublicDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pPublicData, p.ulPublicDataLen as usize) }
                        .to_vec()
                };
                let public_data2 = if p.pPublicData2.is_null() || p.ulPublicDataLen2 == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(p.pPublicData2, p.ulPublicDataLen2 as usize)
                    }
                    .to_vec()
                };
                Some(CkMechanismParams::EcmqvDerive(EcmqvDeriveParams {
                    kdf: p.kdf as u64,
                    shared_data,
                    public_data,
                    private_data_len: p.ulPrivateDataLen as u64,
                    private_data_handle: p.hPrivateData as u64,
                    public_data2,
                    public_key_handle: p.publicKey as u64,
                }))
            }
        }

        Some("x942_dh1_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_DH1_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_X9_42_DH1_DERIVE_PARAMS) };
                let other_info = if p.pOtherInfo.is_null() || p.ulOtherInfoLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pOtherInfo, p.ulOtherInfoLen as usize) }
                        .to_vec()
                };
                let public_data = if p.pPublicData.is_null() || p.ulPublicDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pPublicData, p.ulPublicDataLen as usize) }
                        .to_vec()
                };
                Some(CkMechanismParams::X942Dh1Derive(X942Dh1DeriveParams {
                    kdf: p.kdf as u64,
                    other_info,
                    public_data,
                }))
            }
        }

        Some("x942_dh2_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_DH2_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_X9_42_DH2_DERIVE_PARAMS) };
                let other_info = if p.pOtherInfo.is_null() || p.ulOtherInfoLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pOtherInfo, p.ulOtherInfoLen as usize) }
                        .to_vec()
                };
                let public_data = if p.pPublicData.is_null() || p.ulPublicDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pPublicData, p.ulPublicDataLen as usize) }
                        .to_vec()
                };
                let public_data2 = if p.pPublicData2.is_null() || p.ulPublicDataLen2 == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(p.pPublicData2, p.ulPublicDataLen2 as usize)
                    }
                    .to_vec()
                };
                Some(CkMechanismParams::X942Dh2Derive(X942Dh2DeriveParams {
                    kdf: p.kdf as u64,
                    other_info,
                    public_data,
                    private_data_len: p.ulPrivateDataLen as u64,
                    private_data_handle: p.hPrivateData as u64,
                    public_data2,
                }))
            }
        }

        Some("x942_mqv_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_MQV_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_X9_42_MQV_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.OtherInfo, p.ulOtherInfoLen)
                    || missing_embedded_pointer(p.PublicData, p.ulPublicDataLen)
                    || missing_embedded_pointer(p.PublicData2, p.ulPublicDataLen2)
                    || p.ulOtherInfoLen as usize > MAX_MECHANISM_PARAM_LEN
                    || p.ulPublicDataLen as usize > MAX_MECHANISM_PARAM_LEN
                    || p.ulPublicDataLen2 as usize > MAX_MECHANISM_PARAM_LEN
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let other_info = if p.OtherInfo.is_null() || p.ulOtherInfoLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.OtherInfo, p.ulOtherInfoLen as usize)
                        }
                        .to_vec()
                    };
                    let public_data = if p.PublicData.is_null() || p.ulPublicDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.PublicData, p.ulPublicDataLen as usize)
                        }
                        .to_vec()
                    };
                    let public_data2 = if p.PublicData2.is_null() || p.ulPublicDataLen2 == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.PublicData2, p.ulPublicDataLen2 as usize)
                        }
                        .to_vec()
                    };
                    Some(CkMechanismParams::X942MqvDerive(X942MqvDeriveParams {
                        kdf: p.kdf as u64,
                        other_info,
                        public_data,
                        private_data_len: p.ulPrivateDataLen as u64,
                        private_data_handle: p.hPrivateData as u64,
                        public_data2,
                        public_key_handle: p.publicKey as u64,
                    }))
                }
            }
        }

        Some("gostr3410_derive") => {
            if param_len < std::mem::size_of::<CK_GOSTR3410_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_GOSTR3410_DERIVE_PARAMS) };
                let public_data = if p.pPublicData.is_null() || p.ulPublicDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pPublicData, p.ulPublicDataLen as usize) }
                        .to_vec()
                };
                let ukm = if p.pUKM.is_null() || p.ulUKMLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pUKM, p.ulUKMLen as usize) }.to_vec()
                };
                Some(CkMechanismParams::Gostr3410Derive(Gostr3410DeriveParams {
                    kdf: p.kdf as u64,
                    public_data,
                    ukm,
                }))
            }
        }

        Some("gostr3410_key_wrap") => {
            if param_len < std::mem::size_of::<CK_GOSTR3410_KEY_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_GOSTR3410_KEY_WRAP_PARAMS) };
                let wrap_oid = if p.pWrapOID.is_null() || p.ulWrapOIDLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pWrapOID, p.ulWrapOIDLen as usize) }
                        .to_vec()
                };
                let ukm = if p.pUKM.is_null() || p.ulUKMLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pUKM, p.ulUKMLen as usize) }.to_vec()
                };
                Some(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
                    wrap_oid,
                    ukm,
                    key_handle: p.hKey as u64,
                }))
            }
        }

        Some("key_wrap_set_oaep") => {
            if param_len < std::mem::size_of::<CK_KEY_WRAP_SET_OAEP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_KEY_WRAP_SET_OAEP_PARAMS) };
                let x = if p.pX.is_null() || p.ulXLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pX, p.ulXLen as usize) }.to_vec()
                };
                Some(CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams {
                    bc: p.bBC as u32,
                    x,
                }))
            }
        }

        Some("kea_derive") => {
            if param_len < std::mem::size_of::<CK_KEA_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_KEA_DERIVE_PARAMS) };
                let random_len = p.ulRandomLen as usize;
                let random_a = if p.RandomA.is_null() || random_len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.RandomA, random_len) }.to_vec()
                };
                let random_b = if p.RandomB.is_null() || random_len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.RandomB, random_len) }.to_vec()
                };
                let public_data = if p.PublicData.is_null() || p.ulPublicDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.PublicData, p.ulPublicDataLen as usize) }
                        .to_vec()
                };
                Some(CkMechanismParams::KeaDerive(KeaDeriveParams {
                    is_sender: p.isSender != 0,
                    random_a,
                    random_b,
                    public_data,
                }))
            }
        }

        Some("ike_prf_derive") => {
            if param_len < std::mem::size_of::<CK_IKE_PRF_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_IKE_PRF_DERIVE_PARAMS) };
                let ni = if p.pNi.is_null() || p.ulNiLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pNi, p.ulNiLen as usize) }.to_vec()
                };
                let nr = if p.pNr.is_null() || p.ulNrLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pNr, p.ulNrLen as usize) }.to_vec()
                };
                Some(CkMechanismParams::IkePrfDerive(IkePrfDeriveParams {
                    prf_mechanism: p.prfMechanism as u64,
                    data_as_key: p.bDataAsKey != 0,
                    rekey: p.bRekey != 0,
                    ni,
                    nr,
                    new_key_handle: p.hNewKey as u64,
                }))
            }
        }

        Some("ike1_prf_derive") => {
            if param_len < std::mem::size_of::<CK_IKE1_PRF_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_IKE1_PRF_DERIVE_PARAMS) };
                let ckyi = if p.pCKYi.is_null() || p.ulCKYiLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pCKYi, p.ulCKYiLen as usize) }.to_vec()
                };
                let ckyr = if p.pCKYr.is_null() || p.ulCKYrLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pCKYr, p.ulCKYrLen as usize) }.to_vec()
                };
                Some(CkMechanismParams::Ike1PrfDerive(Ike1PrfDeriveParams {
                    prf_mechanism: p.prfMechanism as u64,
                    has_prev_key: p.bHasPrevKey != 0,
                    keygxy_handle: p.hKeygxy as u64,
                    prev_key_handle: p.hPrevKey as u64,
                    ckyi,
                    ckyr,
                    key_number: p.keyNumber as u32,
                }))
            }
        }

        Some("ike1_extended_derive") => {
            if param_len < std::mem::size_of::<CK_IKE1_EXTENDED_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_IKE1_EXTENDED_DERIVE_PARAMS) };
                let extra_data = if p.pExtraData.is_null() || p.ulExtraDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pExtraData, p.ulExtraDataLen as usize) }
                        .to_vec()
                };
                Some(CkMechanismParams::Ike1ExtendedDerive(Ike1ExtendedDeriveParams {
                    prf_mechanism: p.prfMechanism as u64,
                    has_keygxy: p.bHasKeygxy != 0,
                    keygxy_handle: p.hKeygxy as u64,
                    extra_data,
                }))
            }
        }

        Some("ike2_prf_plus_derive") => {
            if param_len < std::mem::size_of::<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_IKE2_PRF_PLUS_DERIVE_PARAMS) };
                let seed_data = if p.pSeedData.is_null() || p.ulSeedDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pSeedData, p.ulSeedDataLen as usize) }
                        .to_vec()
                };
                Some(CkMechanismParams::Ike2PrfPlusDerive(Ike2PrfPlusDeriveParams {
                    prf_mechanism: p.prfMechanism as u64,
                    has_seed_key: p.bHasSeedKey != 0,
                    seed_key_handle: p.hSeedKey as u64,
                    seed_data,
                }))
            }
        }

        Some("kip") => {
            if param_len < std::mem::size_of::<CK_KIP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_KIP_PARAMS) };
                let nested_len_too_large = if p.pMechanism.is_null() {
                    false
                } else {
                    unsafe { (*p.pMechanism).ulParameterLen as usize > MAX_MECHANISM_PARAM_LEN }
                };
                if p.pMechanism.is_null()
                    || nested_len_too_large
                    || missing_embedded_pointer(p.pSeed, p.ulSeedLen)
                    || p.ulSeedLen as usize > MAX_MECHANISM_PARAM_LEN
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let mechanism = unsafe { read_mechanism(p.pMechanism) };
                    let seed = if p.pSeed.is_null() || p.ulSeedLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pSeed, p.ulSeedLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::Kip(KipParams {
                        mechanism: Box::new(mechanism),
                        key_handle: p.hKey as u64,
                        seed,
                    }))
                }
            }
        }

        Some("otp") => {
            if param_len < std::mem::size_of::<CK_OTP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_OTP_PARAMS) };
                if missing_embedded_pointer(p.pParams, p.ulCount)
                    || p.ulCount as usize > MAX_TEMPLATE_COUNT
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else if p.pParams.is_null() || p.ulCount == 0 {
                    Some(CkMechanismParams::Otp(OtpParams { params: Vec::new() }))
                } else {
                    let params =
                        unsafe { std::slice::from_raw_parts(p.pParams, p.ulCount as usize) };
                    if params.iter().any(|param| {
                        missing_embedded_pointer(param.pValue as *const u8, param.ulValueLen)
                            || param.ulValueLen as usize > MAX_MECHANISM_PARAM_LEN
                    }) {
                        Some(raw_mechanism_params(param_ptr, param_len))
                    } else {
                        Some(CkMechanismParams::Otp(OtpParams {
                            params: params
                                .iter()
                                .map(|param| {
                                    let value = if param.pValue.is_null() || param.ulValueLen == 0 {
                                        Vec::new()
                                    } else {
                                        unsafe {
                                            std::slice::from_raw_parts(
                                                param.pValue as *const u8,
                                                param.ulValueLen as usize,
                                            )
                                        }
                                        .to_vec()
                                    };
                                    OtpParam { type_: param.type_ as u64, value }
                                })
                                .collect(),
                        }))
                    }
                }
            }
        }

        Some("skipjack_private_wrap") => {
            if param_len < std::mem::size_of::<CK_SKIPJACK_PRIVATE_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_SKIPJACK_PRIVATE_WRAP_PARAMS) };
                if missing_embedded_pointer(p.pPassword, p.ulPasswordLen)
                    || missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || missing_embedded_pointer(p.pRandomA, p.ulRandomLen)
                    || missing_embedded_pointer(p.pPrimeP, p.ulPAndGLen)
                    || missing_embedded_pointer(p.pBaseG, p.ulPAndGLen)
                    || missing_embedded_pointer(p.pSubprimeQ, p.ulQLen)
                    || p.ulPasswordLen as usize > MAX_MECHANISM_PARAM_LEN
                    || p.ulPublicDataLen as usize > MAX_MECHANISM_PARAM_LEN
                    || p.ulRandomLen as usize > MAX_MECHANISM_PARAM_LEN
                    || p.ulPAndGLen as usize > MAX_MECHANISM_PARAM_LEN
                    || p.ulQLen as usize > MAX_MECHANISM_PARAM_LEN
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let password = if p.pPassword.is_null() || p.ulPasswordLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pPassword, p.ulPasswordLen as usize) }
                            .to_vec()
                    };
                    let public_data = if p.pPublicData.is_null() || p.ulPublicDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.pPublicData, p.ulPublicDataLen as usize)
                        }
                        .to_vec()
                    };
                    let random_a = if p.pRandomA.is_null() || p.ulRandomLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pRandomA, p.ulRandomLen as usize) }
                            .to_vec()
                    };
                    let prime_p = if p.pPrimeP.is_null() || p.ulPAndGLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pPrimeP, p.ulPAndGLen as usize) }
                            .to_vec()
                    };
                    let base_g = if p.pBaseG.is_null() || p.ulPAndGLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pBaseG, p.ulPAndGLen as usize) }
                            .to_vec()
                    };
                    let subprime_q = if p.pSubprimeQ.is_null() || p.ulQLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pSubprimeQ, p.ulQLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::SkipjackPrivateWrap(SkipjackPrivateWrapParams {
                        password,
                        public_data,
                        password_length: p.ulPasswordLen as u64,
                        random_a,
                        prime_p,
                        base_g,
                        subprime_q,
                    }))
                }
            }
        }

        Some("skipjack_relayx") => {
            if param_len < std::mem::size_of::<CK_SKIPJACK_RELAYX_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_SKIPJACK_RELAYX_PARAMS) };
                if missing_embedded_pointer(p.pOldWrappedX, p.ulOldWrappedXLen)
                    || missing_embedded_pointer(p.pOldPassword, p.ulOldPasswordLen)
                    || missing_embedded_pointer(p.pOldPublicData, p.ulOldPublicDataLen)
                    || missing_embedded_pointer(p.pOldRandomA, p.ulOldRandomLen)
                    || missing_embedded_pointer(p.pNewPassword, p.ulNewPasswordLen)
                    || missing_embedded_pointer(p.pNewPublicData, p.ulNewPublicDataLen)
                    || missing_embedded_pointer(p.pNewRandomA, p.ulNewRandomLen)
                    || p.ulOldWrappedXLen as usize > MAX_MECHANISM_PARAM_LEN
                    || p.ulOldPasswordLen as usize > MAX_MECHANISM_PARAM_LEN
                    || p.ulOldPublicDataLen as usize > MAX_MECHANISM_PARAM_LEN
                    || p.ulOldRandomLen as usize > MAX_MECHANISM_PARAM_LEN
                    || p.ulNewPasswordLen as usize > MAX_MECHANISM_PARAM_LEN
                    || p.ulNewPublicDataLen as usize > MAX_MECHANISM_PARAM_LEN
                    || p.ulNewRandomLen as usize > MAX_MECHANISM_PARAM_LEN
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let old_wrapped_x = if p.pOldWrappedX.is_null() || p.ulOldWrappedXLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.pOldWrappedX, p.ulOldWrappedXLen as usize)
                        }
                        .to_vec()
                    };
                    let old_password = if p.pOldPassword.is_null() || p.ulOldPasswordLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.pOldPassword, p.ulOldPasswordLen as usize)
                        }
                        .to_vec()
                    };
                    let old_public_data = if p.pOldPublicData.is_null() || p.ulOldPublicDataLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(
                                p.pOldPublicData,
                                p.ulOldPublicDataLen as usize,
                            )
                        }
                        .to_vec()
                    };
                    let old_random_a = if p.pOldRandomA.is_null() || p.ulOldRandomLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.pOldRandomA, p.ulOldRandomLen as usize)
                        }
                        .to_vec()
                    };
                    let new_password = if p.pNewPassword.is_null() || p.ulNewPasswordLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.pNewPassword, p.ulNewPasswordLen as usize)
                        }
                        .to_vec()
                    };
                    let new_public_data = if p.pNewPublicData.is_null() || p.ulNewPublicDataLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(
                                p.pNewPublicData,
                                p.ulNewPublicDataLen as usize,
                            )
                        }
                        .to_vec()
                    };
                    let new_random_a = if p.pNewRandomA.is_null() || p.ulNewRandomLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.pNewRandomA, p.ulNewRandomLen as usize)
                        }
                        .to_vec()
                    };
                    Some(CkMechanismParams::SkipjackRelayx(SkipjackRelayxParams {
                        old_wrapped_x,
                        old_password,
                        old_public_data,
                        old_random_a,
                        new_password,
                        new_public_data,
                        new_random_a,
                    }))
                }
            }
        }

        Some("sp800_108_kdf") => {
            if param_len < std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_SP800_108_KDF_PARAMS) };
                if unsafe {
                    sp800_108_data_params_invalid(p.pDataParams, p.ulNumberOfDataParams)
                        || sp800_108_derived_keys_invalid(
                            p.pAdditionalDerivedKeys,
                            p.ulAdditionalDerivedKeys,
                        )
                } {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                        prf_type: p.prfType as u64,
                        data_params: unsafe {
                            read_sp800_108_data_params(p.pDataParams, p.ulNumberOfDataParams)
                        },
                        additional_derived_keys: unsafe {
                            read_sp800_108_derived_keys(
                                p.pAdditionalDerivedKeys,
                                p.ulAdditionalDerivedKeys,
                            )
                        },
                    }))
                }
            }
        }

        Some("sp800_108_feedback_kdf") => {
            if param_len < std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_SP800_108_FEEDBACK_KDF_PARAMS) };
                if missing_embedded_pointer(p.pIV, p.ulIVLen)
                    || (p.ulIVLen as usize) > MAX_MECHANISM_PARAM_LEN
                    || unsafe {
                        sp800_108_data_params_invalid(p.pDataParams, p.ulNumberOfDataParams)
                            || sp800_108_derived_keys_invalid(
                                p.pAdditionalDerivedKeys,
                                p.ulAdditionalDerivedKeys,
                            )
                    }
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let iv = if p.pIV.is_null() || p.ulIVLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pIV, p.ulIVLen as usize) }.to_vec()
                    };
                    Some(CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                        prf_type: p.prfType as u64,
                        data_params: unsafe {
                            read_sp800_108_data_params(p.pDataParams, p.ulNumberOfDataParams)
                        },
                        iv,
                        additional_derived_keys: unsafe {
                            read_sp800_108_derived_keys(
                                p.pAdditionalDerivedKeys,
                                p.ulAdditionalDerivedKeys,
                            )
                        },
                    }))
                }
            }
        }

        // Unknown shape or no shape registered: preserve raw bytes so they
        // can still reach the server for forwarding.
        Some(_) | None => Some(CkMechanismParams::Raw(RawMechanismParams {
            data: unsafe { read_raw_bytes(param_ptr, param_len) },
        })),
    };

    CkMechanism { mechanism_type: mech_type, params }
}

fn gcm_iv_buffer_len(gcm: &CK_GCM_PARAMS) -> u64 {
    if gcm.pIv.is_null() {
        0
    } else if gcm.ulIvLen > 0 {
        gcm.ulIvLen as u64
    } else {
        ((gcm.ulIvBits as u64).saturating_add(7)) / 8
    }
}

unsafe fn read_sp800_108_data_params(
    data_params: *mut CK_PRF_DATA_PARAM,
    count: CK_ULONG,
) -> Vec<PrfDataParam> {
    if data_params.is_null() || count == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(data_params, count as usize) }
        .iter()
        .map(|param| {
            let value = if param.pValue.is_null() || param.ulValueLen == 0 {
                Vec::new()
            } else {
                unsafe {
                    std::slice::from_raw_parts(param.pValue as *const u8, param.ulValueLen as usize)
                }
                .to_vec()
            };
            PrfDataParam { type_: param.type_ as u64, value }
        })
        .collect()
}

unsafe fn sp800_108_data_params_invalid(
    data_params: *mut CK_PRF_DATA_PARAM,
    count: CK_ULONG,
) -> bool {
    if missing_embedded_pointer(data_params, count) {
        return true;
    }
    if data_params.is_null() || count == 0 {
        return false;
    }
    let n = count as usize;
    if n > MAX_TEMPLATE_COUNT {
        return true;
    }
    unsafe { std::slice::from_raw_parts(data_params, n) }.iter().any(|param| {
        missing_embedded_pointer(param.pValue as *const u8, param.ulValueLen)
            || (param.ulValueLen as usize) > MAX_MECHANISM_PARAM_LEN
    })
}

unsafe fn read_sp800_108_derived_keys(
    derived_keys: *mut CK_DERIVED_KEY,
    count: CK_ULONG,
) -> Vec<Sp800108DerivedKey> {
    if derived_keys.is_null() || count == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(derived_keys, count as usize) }
        .iter()
        .map(|derived| {
            let template = unsafe { ck_attrs_to_rust(derived.pTemplate, derived.ulAttributeCount) };
            let key_handle =
                if derived.phKey.is_null() { 0 } else { unsafe { *derived.phKey as u64 } };
            Sp800108DerivedKey { template, key_handle }
        })
        .collect()
}

unsafe fn sp800_108_derived_keys_invalid(
    derived_keys: *mut CK_DERIVED_KEY,
    count: CK_ULONG,
) -> bool {
    if missing_embedded_pointer(derived_keys, count) {
        return true;
    }
    if derived_keys.is_null() || count == 0 {
        return false;
    }
    let n = count as usize;
    if n > MAX_TEMPLATE_COUNT {
        return true;
    }
    unsafe { std::slice::from_raw_parts(derived_keys, n) }.iter().any(|derived| {
        missing_embedded_pointer(derived.pTemplate, derived.ulAttributeCount)
            || (derived.ulAttributeCount as usize) > MAX_TEMPLATE_COUNT
            || derived.phKey.is_null()
    })
}

pub(crate) unsafe fn write_mechanism_output_params(
    p_mechanism: CK_MECHANISM_PTR,
    params: &CkMechanismParams,
) {
    if p_mechanism.is_null() {
        return;
    }

    let mechanism = unsafe { &mut *p_mechanism };
    match params {
        CkMechanismParams::Gcm(gcm_out) => {
            if mechanism.ulParameterLen < std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG
                || mechanism.pParameter.is_null()
            {
                return;
            }

            let gcm = unsafe { &mut *(mechanism.pParameter as *mut CK_GCM_PARAMS) };
            if !gcm.pIv.is_null() {
                let capacity = gcm_iv_write_capacity(gcm);
                let copy_len = gcm_out.iv.len().min(capacity);
                if copy_len > 0 {
                    unsafe {
                        std::ptr::copy_nonoverlapping(gcm_out.iv.as_ptr(), gcm.pIv, copy_len);
                    }
                }
                gcm.ulIvLen = copy_len as CK_ULONG;
            }
            gcm.ulIvBits = gcm_out.iv_bits as CK_ULONG;
            gcm.ulTagBits = gcm_out.tag_bits as CK_ULONG;
        }
        CkMechanismParams::Tls12MasterKeyDerive(tls12_out) => {
            // `CK_TLS12_MASTER_KEY_DERIVE_PARAMS.pVersion` is OUT — the
            // HSM writes the negotiated CK_VERSION here when pVersion
            // is non-NULL.  The rest of the struct is caller-supplied
            // input and must not be overwritten.
            if mechanism.ulParameterLen
                < std::mem::size_of::<cryptoki_sys::CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG
                || mechanism.pParameter.is_null()
            {
                return;
            }
            let tls12 = unsafe {
                &mut *(mechanism.pParameter as *mut cryptoki_sys::CK_TLS12_MASTER_KEY_DERIVE_PARAMS)
            };
            if !tls12.pVersion.is_null() {
                let version = unsafe { &mut *tls12.pVersion };
                version.major = tls12_out.version_major as cryptoki_sys::CK_BYTE;
                version.minor = tls12_out.version_minor as cryptoki_sys::CK_BYTE;
            }
        }
        CkMechanismParams::WtlsMasterKeyDerive(wtls_out) => {
            if mechanism.ulParameterLen
                < std::mem::size_of::<cryptoki_sys::CK_WTLS_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG
                || mechanism.pParameter.is_null()
            {
                return;
            }
            let wtls = unsafe {
                &mut *(mechanism.pParameter as *mut cryptoki_sys::CK_WTLS_MASTER_KEY_DERIVE_PARAMS)
            };
            if !wtls.pVersion.is_null() {
                unsafe {
                    *wtls.pVersion = wtls_out.version as cryptoki_sys::CK_BYTE;
                }
            }
        }
        CkMechanismParams::WtlsKeyMat(wtls_out) => {
            if mechanism.ulParameterLen
                < std::mem::size_of::<cryptoki_sys::CK_WTLS_KEY_MAT_PARAMS>() as CK_ULONG
                || mechanism.pParameter.is_null()
            {
                return;
            }
            let wtls = unsafe {
                &mut *(mechanism.pParameter as *mut cryptoki_sys::CK_WTLS_KEY_MAT_PARAMS)
            };
            if wtls.pReturnedKeyMaterial.is_null() {
                return;
            }
            let output = unsafe { &mut *wtls.pReturnedKeyMaterial };
            output.hMacSecret = wtls_out.mac_secret_handle as cryptoki_sys::CK_OBJECT_HANDLE;
            output.hKey = wtls_out.key_handle as cryptoki_sys::CK_OBJECT_HANDLE;
            if !output.pIV.is_null() {
                let capacity = (((wtls.ulIVSizeInBits as usize).saturating_add(7)) / 8)
                    .min(MAX_MECHANISM_PARAM_LEN);
                let copy_len = wtls_out.iv.len().min(capacity);
                if copy_len > 0 {
                    unsafe {
                        std::ptr::copy_nonoverlapping(wtls_out.iv.as_ptr(), output.pIV, copy_len);
                    }
                }
            }
        }
        CkMechanismParams::Ssl3KeyMat(ssl3_out) => {
            if mechanism.ulParameterLen
                < std::mem::size_of::<cryptoki_sys::CK_SSL3_KEY_MAT_PARAMS>() as CK_ULONG
                || mechanism.pParameter.is_null()
            {
                return;
            }
            let ssl3 = unsafe {
                &mut *(mechanism.pParameter as *mut cryptoki_sys::CK_SSL3_KEY_MAT_PARAMS)
            };
            if ssl3.pReturnedKeyMaterial.is_null() {
                return;
            }
            let output = unsafe { &mut *ssl3.pReturnedKeyMaterial };
            output.hClientMacSecret =
                ssl3_out.client_mac_secret_handle as cryptoki_sys::CK_OBJECT_HANDLE;
            output.hServerMacSecret =
                ssl3_out.server_mac_secret_handle as cryptoki_sys::CK_OBJECT_HANDLE;
            output.hClientKey = ssl3_out.client_key_handle as cryptoki_sys::CK_OBJECT_HANDLE;
            output.hServerKey = ssl3_out.server_key_handle as cryptoki_sys::CK_OBJECT_HANDLE;
            let capacity = (((ssl3.ulIVSizeInBits as usize).saturating_add(7)) / 8)
                .min(MAX_MECHANISM_PARAM_LEN);
            if !output.pIVClient.is_null() {
                let copy_len = ssl3_out.client_iv.len().min(capacity);
                if copy_len > 0 {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            ssl3_out.client_iv.as_ptr(),
                            output.pIVClient,
                            copy_len,
                        );
                    }
                }
            }
            if !output.pIVServer.is_null() {
                let copy_len = ssl3_out.server_iv.len().min(capacity);
                if copy_len > 0 {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            ssl3_out.server_iv.as_ptr(),
                            output.pIVServer,
                            copy_len,
                        );
                    }
                }
            }
        }
        CkMechanismParams::Sp800108Kdf(sp800_out) => {
            if mechanism.ulParameterLen < std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG
                || mechanism.pParameter.is_null()
            {
                return;
            }
            let sp800 = unsafe { &mut *(mechanism.pParameter as *mut CK_SP800_108_KDF_PARAMS) };
            unsafe {
                write_sp800_108_derived_key_handles(
                    sp800.pAdditionalDerivedKeys,
                    sp800.ulAdditionalDerivedKeys,
                    &sp800_out.additional_derived_keys,
                );
            }
        }
        CkMechanismParams::Sp800108FeedbackKdf(sp800_out) => {
            if mechanism.ulParameterLen
                < std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>() as CK_ULONG
                || mechanism.pParameter.is_null()
            {
                return;
            }
            let sp800 =
                unsafe { &mut *(mechanism.pParameter as *mut CK_SP800_108_FEEDBACK_KDF_PARAMS) };
            unsafe {
                write_sp800_108_derived_key_handles(
                    sp800.pAdditionalDerivedKeys,
                    sp800.ulAdditionalDerivedKeys,
                    &sp800_out.additional_derived_keys,
                );
            }
        }
        _ => {}
    }
}

unsafe fn write_sp800_108_derived_key_handles(
    derived_keys: *mut CK_DERIVED_KEY,
    count: CK_ULONG,
    output_keys: &[Sp800108DerivedKey],
) {
    if derived_keys.is_null() || count == 0 {
        return;
    }
    for (derived, output) in unsafe { std::slice::from_raw_parts_mut(derived_keys, count as usize) }
        .iter_mut()
        .zip(output_keys.iter())
    {
        if !derived.phKey.is_null() {
            unsafe {
                *derived.phKey = output.key_handle as CK_OBJECT_HANDLE;
            }
        }
    }
}

fn gcm_iv_write_capacity(gcm: &CK_GCM_PARAMS) -> usize {
    if gcm.ulIvLen > 0 {
        gcm.ulIvLen as usize
    } else {
        (((gcm.ulIvBits as u64).saturating_add(7)) / 8) as usize
    }
}

fn missing_embedded_pointer<T>(ptr: *const T, len: CK_ULONG) -> bool {
    ptr.is_null() && len != 0
}

fn raw_mechanism_params(param_ptr: *mut std::ffi::c_void, param_len: usize) -> CkMechanismParams {
    CkMechanismParams::Raw(RawMechanismParams {
        data: unsafe { read_raw_bytes(param_ptr, param_len) },
    })
}

/// Read raw bytes from a C void pointer into a Vec.
///
/// # Safety
///
/// `ptr` must point to a readable buffer of at least `len` bytes.
unsafe fn read_raw_bytes(ptr: *mut std::ffi::c_void, len: usize) -> Vec<u8> {
    if len > MAX_MECHANISM_PARAM_LEN {
        return Vec::new(); // Validated earlier; defense-in-depth
    }
    unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }.to_vec()
}

// ---------------------------------------------------------------------------
// Message crypto parameter helpers (CK_*_MESSAGE_PARAMS ↔ structured proto)
// ---------------------------------------------------------------------------

/// Read a `CK_GCM_MESSAGE_PARAMS` C struct, dereferencing its embedded
/// pointers (`pIv`, `pTag`) to extract the actual IV/tag data.
///
/// # Safety
///
/// `p_parameter` must point to a valid `CK_GCM_MESSAGE_PARAMS` struct.
/// The embedded `pIv` and `pTag` pointers must be valid and point to
/// buffers of the sizes specified by `ulIvLen` and `ulTagBits/8`.
pub(crate) unsafe fn read_gcm_message_params(
    p_parameter: *const std::ffi::c_void,
) -> pkcs11_proxy_ng_proto::convert::message_params::GcmMessageParams {
    let p = unsafe { &*(p_parameter as *const CK_GCM_MESSAGE_PARAMS) };
    let iv = if !p.pIv.is_null() && p.ulIvLen > 0 {
        unsafe { std::slice::from_raw_parts(p.pIv, p.ulIvLen as usize) }.to_vec()
    } else {
        Vec::new()
    };
    let tag_bytes = (p.ulTagBits as usize).div_ceil(8);
    let tag = if !p.pTag.is_null() && tag_bytes > 0 {
        unsafe { std::slice::from_raw_parts(p.pTag, tag_bytes) }.to_vec()
    } else {
        Vec::new()
    };
    pkcs11_proxy_ng_proto::convert::message_params::GcmMessageParams {
        iv,
        iv_fixed_bits: p.ulIvFixedBits as u64,
        iv_generator: p.ivGenerator as u64,
        tag,
        tag_bits: p.ulTagBits as u64,
    }
}

/// Read a `CK_CCM_MESSAGE_PARAMS` C struct, dereferencing embedded pointers.
///
/// # Safety
///
/// `p_parameter` must point to a valid `CK_CCM_MESSAGE_PARAMS` struct.
pub(crate) unsafe fn read_ccm_message_params(
    p_parameter: *const std::ffi::c_void,
) -> pkcs11_proxy_ng_proto::convert::message_params::CcmMessageParams {
    let p = unsafe { &*(p_parameter as *const CK_CCM_MESSAGE_PARAMS) };
    let nonce = if !p.pNonce.is_null() && p.ulNonceLen > 0 {
        unsafe { std::slice::from_raw_parts(p.pNonce, p.ulNonceLen as usize) }.to_vec()
    } else {
        Vec::new()
    };
    let mac = if !p.pMAC.is_null() && p.ulMACLen > 0 {
        unsafe { std::slice::from_raw_parts(p.pMAC, p.ulMACLen as usize) }.to_vec()
    } else {
        Vec::new()
    };
    pkcs11_proxy_ng_proto::convert::message_params::CcmMessageParams {
        data_len: p.ulDataLen as u64,
        nonce,
        nonce_fixed_bits: p.ulNonceFixedBits as u64,
        nonce_generator: p.nonceGenerator as u64,
        mac,
        mac_len: p.ulMACLen as u64,
    }
}

/// Read a `CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS` C struct.
///
/// # Safety
///
/// `p_parameter` must point to a valid struct.
pub(crate) unsafe fn read_salsa_chacha_message_params(
    p_parameter: *const std::ffi::c_void,
) -> pkcs11_proxy_ng_proto::convert::message_params::Salsa20ChaCha20Poly1305MessageParams {
    let p = unsafe { &*(p_parameter as *const CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS) };
    let nonce = if !p.pNonce.is_null() && p.ulNonceLen > 0 {
        unsafe { std::slice::from_raw_parts(p.pNonce, p.ulNonceLen as usize) }.to_vec()
    } else {
        Vec::new()
    };
    // Poly1305 tag is always 16 bytes
    let tag = if !p.pTag.is_null() {
        unsafe { std::slice::from_raw_parts(p.pTag, 16) }.to_vec()
    } else {
        Vec::new()
    };
    pkcs11_proxy_ng_proto::convert::message_params::Salsa20ChaCha20Poly1305MessageParams {
        nonce,
        tag,
    }
}

/// Read the message parameter C struct based on its size, returning
/// a structured `MessageParameter` for safe serialization over gRPC.
///
/// Size detection (x86_64): GCM=48, CCM=56, Salsa/ChaCha=24.
/// Falls back to `MessageParameter::Raw` for unknown sizes.
///
/// # Safety
///
/// `p_parameter` must point to a valid message parameter struct of
/// the appropriate type for the size indicated by `ul_parameter_len`.
pub(crate) unsafe fn read_message_parameter(
    p_parameter: *const std::ffi::c_void,
    ul_parameter_len: CK_ULONG,
) -> pkcs11_proxy_ng_proto::convert::message_params::MessageParameter {
    use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;
    let len = ul_parameter_len as usize;
    let gcm_size = std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>();
    let ccm_size = std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>();
    let salsa_size = std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>();

    if len == gcm_size {
        MessageParameter::GcmMessage(unsafe { read_gcm_message_params(p_parameter) })
    } else if len == ccm_size {
        MessageParameter::CcmMessage(unsafe { read_ccm_message_params(p_parameter) })
    } else if len == salsa_size {
        MessageParameter::SalaChacha(unsafe { read_salsa_chacha_message_params(p_parameter) })
    } else {
        // Unknown struct — send raw bytes (will likely crash the daemon
        // if it contains embedded pointers, but we can't parse what we
        // don't recognise).
        let raw = unsafe { std::slice::from_raw_parts(p_parameter as *const u8, len) }.to_vec();
        MessageParameter::Raw(raw)
    }
}

/// Safely read an optional message parameter after validating the outer
/// pointer/length pair. This prevents undefined behavior for NULL/0 and
/// NULL/non-zero inputs before the structured readers dereference C pointers.
///
/// # Safety
///
/// If `p_parameter` is non-null and `ul_parameter_len > 0`, it must point to
/// a readable message parameter object or raw buffer of at least
/// `ul_parameter_len` bytes.
pub(crate) unsafe fn try_read_message_parameter(
    p_parameter: *const std::ffi::c_void,
    ul_parameter_len: CK_ULONG,
) -> pkcs11_proxy_ng_types::CkResult<
    Option<pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
> {
    if p_parameter.is_null() {
        return if ul_parameter_len == 0 {
            Ok(None)
        } else {
            Err(pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD)
        };
    }

    if ul_parameter_len == 0 {
        return Ok(None);
    }

    if (ul_parameter_len as usize) > MAX_MECHANISM_PARAM_LEN {
        return Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID);
    }

    Ok(Some(unsafe { read_message_parameter(p_parameter, ul_parameter_len) }))
}

/// Write modified GCM message parameters back to the caller's C struct.
///
/// After the backend call, the IV may have been updated by the IV generator
/// and the tag buffer contains the authentication tag (for encrypt).
///
/// # Safety
///
/// `p_parameter` must point to the original `CK_GCM_MESSAGE_PARAMS`.
pub(crate) unsafe fn write_gcm_message_params_back(
    result: &pkcs11_proxy_ng_proto::convert::message_params::GcmMessageParams,
    p_parameter: *mut std::ffi::c_void,
) {
    let p = unsafe { &mut *(p_parameter as *mut CK_GCM_MESSAGE_PARAMS) };
    if !p.pIv.is_null() {
        let copy_len = result.iv.len().min(p.ulIvLen as usize);
        if copy_len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(result.iv.as_ptr(), p.pIv, copy_len);
            }
        }
    }
    if !p.pTag.is_null() {
        let tag_bytes = (p.ulTagBits as usize).div_ceil(8);
        let copy_len = result.tag.len().min(tag_bytes);
        if copy_len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(result.tag.as_ptr(), p.pTag, copy_len);
            }
        }
    }
}

/// Write modified CCM message parameters back to the caller's C struct.
///
/// # Safety
///
/// `p_parameter` must point to the original `CK_CCM_MESSAGE_PARAMS`.
pub(crate) unsafe fn write_ccm_message_params_back(
    result: &pkcs11_proxy_ng_proto::convert::message_params::CcmMessageParams,
    p_parameter: *mut std::ffi::c_void,
) {
    let p = unsafe { &mut *(p_parameter as *mut CK_CCM_MESSAGE_PARAMS) };
    if !p.pNonce.is_null() {
        let copy_len = result.nonce.len().min(p.ulNonceLen as usize);
        if copy_len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(result.nonce.as_ptr(), p.pNonce, copy_len);
            }
        }
    }
    if !p.pMAC.is_null() {
        let copy_len = result.mac.len().min(p.ulMACLen as usize);
        if copy_len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(result.mac.as_ptr(), p.pMAC, copy_len);
            }
        }
    }
}

/// Write modified Salsa20/ChaCha20-Poly1305 message parameters back.
///
/// # Safety
///
/// `p_parameter` must point to the original struct.
pub(crate) unsafe fn write_salsa_chacha_message_params_back(
    result: &pkcs11_proxy_ng_proto::convert::message_params::Salsa20ChaCha20Poly1305MessageParams,
    p_parameter: *mut std::ffi::c_void,
) {
    let p = unsafe { &mut *(p_parameter as *mut CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS) };
    if !p.pNonce.is_null() {
        let copy_len = result.nonce.len().min(p.ulNonceLen as usize);
        if copy_len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(result.nonce.as_ptr(), p.pNonce, copy_len);
            }
        }
    }
    if !p.pTag.is_null() {
        let copy_len = result.tag.len().min(16); // Poly1305 tag is always 16 bytes
        if copy_len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(result.tag.as_ptr(), p.pTag, copy_len);
            }
        }
    }
}

/// Write a `MessageParameter` result back to the caller's C struct.
///
/// # Safety
///
/// `p_parameter` must point to the original message parameter C struct.
pub(crate) unsafe fn write_message_parameter_back(
    result: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    p_parameter: *mut std::ffi::c_void,
    ul_parameter_len: CK_ULONG,
) {
    use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;
    match result {
        MessageParameter::GcmMessage(gcm) => unsafe {
            write_gcm_message_params_back(gcm, p_parameter);
        },
        MessageParameter::CcmMessage(ccm) => unsafe {
            write_ccm_message_params_back(ccm, p_parameter);
        },
        MessageParameter::SalaChacha(sc) => unsafe {
            write_salsa_chacha_message_params_back(sc, p_parameter);
        },
        MessageParameter::Raw(data) => {
            // Write raw bytes back (same as the old path)
            let copy_len = data.len().min(ul_parameter_len as usize);
            if copy_len > 0 && !p_parameter.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), p_parameter as *mut u8, copy_len);
                }
            }
        }
    }
}

/// Maximum template entry count we will serialize.  No real PKCS#11
/// template has more than 64 K attributes.
pub(crate) const MAX_TEMPLATE_COUNT: usize = 65_536;

pub(crate) unsafe fn ck_attrs_to_rust(
    p_template: *const CK_ATTRIBUTE,
    count: CK_ULONG,
) -> Vec<CkAttribute> {
    if p_template.is_null() || count == 0 {
        return Vec::new();
    }
    let n = count as usize;
    if n > MAX_TEMPLATE_COUNT {
        panic!("template count {n} exceeds limit");
    }
    let slice = unsafe { std::slice::from_raw_parts(p_template, n) };
    let mut result = Vec::with_capacity(count as usize);
    for attr in slice {
        let ck_type = CkAttributeType(attr.type_);
        let value = if attr.pValue.is_null() || attr.ulValueLen == 0 {
            None
        } else {
            let len = attr.ulValueLen as usize;
            if ck_type.is_bool() && len == std::mem::size_of::<CK_BBOOL>() {
                let v = unsafe { *(attr.pValue as *const CK_BBOOL) };
                Some(CkAttributeValue::Bool(v != 0))
            } else if ck_type.is_ulong() && len == std::mem::size_of::<CK_ULONG>() {
                let v = unsafe { *(attr.pValue as *const CK_ULONG) };
                // Reject absurd allocation-size attributes (VALUE_LEN, MODULUS_BITS).
                // Backends may use these as Vec capacities inside extern "C" functions
                // where a capacity-overflow panic aborts the daemon process.
                if ck_type.is_allocation_size() && (v as usize) > MAX_SERIALIZABLE_BYTES {
                    panic!("attribute {:#x} value {v:#x} exceeds allocation limit", ck_type.0);
                }
                Some(CkAttributeValue::Ulong(v))
            } else if len > MAX_SERIALIZABLE_BYTES {
                panic!("attribute ulValueLen {len} exceeds limit");
            } else {
                let bytes =
                    unsafe { std::slice::from_raw_parts(attr.pValue as *const u8, len) }.to_vec();
                Some(CkAttributeValue::Bytes(bytes))
            }
        };
        result.push(CkAttribute { attr_type: ck_type, value });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::pad_string;

    #[test]
    fn short_src_pads_remainder_with_spaces() {
        let mut buf = [0u8; 8];
        pad_string(&mut buf, "hi");
        assert_eq!(&buf, b"hi      ");
    }

    #[test]
    fn exact_length_src_no_padding_needed() {
        let mut buf = [0u8; 4];
        pad_string(&mut buf, "ABCD");
        assert_eq!(&buf, b"ABCD");
    }

    #[test]
    fn longer_src_truncated_to_dest_len() {
        let mut buf = [0u8; 4];
        pad_string(&mut buf, "ABCDEFGH");
        assert_eq!(&buf, b"ABCD");
    }

    #[test]
    fn empty_src_fills_all_spaces() {
        let mut buf = [0u8; 6];
        pad_string(&mut buf, "");
        assert_eq!(&buf, b"      ");
    }

    #[test]
    fn no_null_terminator_written() {
        let mut buf = [0xFFu8; 6];
        pad_string(&mut buf, "ab");
        assert_eq!(buf[0], b'a');
        assert_eq!(buf[1], b'b');
        for &b in &buf[2..] {
            assert_eq!(b, b' ');
        }
    }

    #[test]
    fn full_32_byte_token_label_field() {
        let mut label = [0u8; 32];
        pad_string(&mut label, "My Test Token");
        assert_eq!(&label[..13], b"My Test Token");
        assert!(label[13..].iter().all(|&b| b == b' '));
    }

    #[test]
    fn overlong_label_truncated_at_32_bytes() {
        let mut label = [0u8; 32];
        let long = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB";
        pad_string(&mut label, long);
        assert!(label.iter().all(|&b| b == b'A'));
    }
}

#[cfg(test)]
mod mechanism_parameter_tests {
    use super::{
        read_mechanism, read_mechanism_with_shape, validate_mechanism,
        write_mechanism_output_params,
    };
    use cryptoki_sys::*;
    use pkcs11_proxy_ng_types::{
        CcmParams, CcmWrapParams, ChaCha20Params, CkAttributeType, CkAttributeValue,
        CkMechanismParams, CkMechanismType, CkRv, ExtractParams, GcmParams, GcmWrapParams,
        KeyWrapSetOaepParams, KmacParams, MechanismRegistry, MuGenParams, RsaAesKeyWrapParams,
        RsaPkcsOaepParams, RsaPkcsPssParams, Salsa20ChaCha20Poly1305Params, Sp800108DerivedKey,
        Sp800108FeedbackKdfParams,
    };

    fn ensure_registry() {
        let registry = MechanismRegistry::load(None).expect("default mechanism registry");
        let _ = crate::state::init_mechanism_registry(registry);
    }

    unsafe fn read_ck_mechanism(mechanism: &CK_MECHANISM) -> CkMechanismParams {
        ensure_registry();
        unsafe { read_mechanism(mechanism) }.params.expect("mechanism params")
    }

    #[test]
    fn unsafe_official_lengthless_parameter_shapes_are_rejected_before_shim_read() {
        ensure_registry();
        let mut opaque = [0xA5u8];

        for mechanism_type in [
            CKM_CMS_SIG,
            CKM_X3DH_INITIALIZE,
            CKM_X3DH_RESPOND,
            CKM_X2RATCHET_INITIALIZE,
            CKM_X2RATCHET_RESPOND,
        ] {
            let mechanism = CK_MECHANISM {
                mechanism: mechanism_type,
                pParameter: opaque.as_mut_ptr() as CK_VOID_PTR,
                ulParameterLen: opaque.len() as CK_ULONG,
            };

            let rv = unsafe { validate_mechanism(&mechanism) };

            assert_eq!(
                rv,
                CkRv::MECHANISM_PARAM_INVALID.0 as CK_RV,
                "0x{mechanism_type:08X} should reject unmodeled caller-owned pointer shapes"
            );
        }
    }

    #[test]
    fn reads_common_mechanism_parameter_structs() {
        let mut source_data = [0xA0u8, 0xA1, 0xA2];
        let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            mgf: 1,
            source: 1,
            pSourceData: source_data.as_mut_ptr() as CK_VOID_PTR,
            ulSourceDataLen: source_data.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType::RSA_PKCS_OAEP.0 as CK_MECHANISM_TYPE,
            pParameter: &mut oaep as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams { source_data, .. }) => {
                assert_eq!(source_data, [0xA0, 0xA1, 0xA2]);
            }
            other => panic!("unexpected OAEP params: {other:?}"),
        }

        let mut pss = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            mgf: 1,
            sLen: 32,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType::RSA_PKCS_PSS.0 as CK_MECHANISM_TYPE,
            pParameter: &mut pss as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams { hash_alg, salt_len, .. }) => {
                assert_eq!(hash_alg, CkMechanismType::SHA256);
                assert_eq!(salt_len, 32);
            }
            other => panic!("unexpected PSS params: {other:?}"),
        }

        let mut iv = [0x10; 12];
        let mut aad = [0xAA, 0xBB, 0xCC];
        let mut gcm = CK_GCM_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: 96,
            pAAD: aad.as_mut_ptr(),
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: 128,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
            pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Gcm(GcmParams { iv, iv_bits, iv_buffer_len, aad, tag_bits }) => {
                assert_eq!(iv, [0x10; 12]);
                assert_eq!(iv_bits, 96);
                assert_eq!(iv_buffer_len, 12);
                assert_eq!(aad, [0xAA, 0xBB, 0xCC]);
                assert_eq!(tag_bits, 128);
            }
            other => panic!("unexpected GCM params: {other:?}"),
        }

        let mut cbc_iv = [0x55u8; 16];
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType::AES_CBC.0 as CK_MECHANISM_TYPE,
            pParameter: cbc_iv.as_mut_ptr() as CK_VOID_PTR,
            ulParameterLen: cbc_iv.len() as CK_ULONG,
        };
        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Iv(params) => assert_eq!(params.iv, [0x55; 16]),
            other => panic!("unexpected CBC IV params: {other:?}"),
        }

        const CKM_AES_CTR: CK_MECHANISM_TYPE = 0x0000_1086;
        let mut ctr = CK_AES_CTR_PARAMS { ulCounterBits: 128, cb: [0x33; 16] };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: &mut ctr as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_AES_CTR_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::AesCtr(params) => {
                assert_eq!(params.counter_bits, 128);
                assert_eq!(params.cb, [0x33; 16]);
            }
            other => panic!("unexpected CTR params: {other:?}"),
        }
    }

    #[test]
    fn reads_handle_string_and_sign_context_parameter_structs() {
        let mut object_handle: CK_OBJECT_HANDLE = 0xCAFE;
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType(0x0000_0500).0 as CK_MECHANISM_TYPE,
            pParameter: &mut object_handle as *mut CK_OBJECT_HANDLE as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_OBJECT_HANDLE>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("object_handle")) }.params {
            Some(CkMechanismParams::ObjectHandle(params)) => {
                assert_eq!(params.handle, 0xCAFE);
            }
            other => panic!("unexpected object handle params: {other:?}"),
        }

        let mut derivation_data = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut key_derivation = CK_KEY_DERIVATION_STRING_DATA {
            pData: derivation_data.as_mut_ptr(),
            ulLen: derivation_data.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType(0x0000_0501).0 as CK_MECHANISM_TYPE,
            pParameter: &mut key_derivation as *mut CK_KEY_DERIVATION_STRING_DATA as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_KEY_DERIVATION_STRING_DATA>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("key_derivation_string")) }.params
        {
            Some(CkMechanismParams::KeyDerivationString(params)) => {
                assert_eq!(params.data, [0xDE, 0xAD, 0xBE, 0xEF]);
            }
            other => panic!("unexpected key derivation string params: {other:?}"),
        }

        #[repr(C)]
        struct TestSignAdditionalContext {
            hedge_variant: CK_ULONG,
            p_context: *mut CK_BYTE,
            ul_context_len: CK_ULONG,
        }

        let mut sign_context = [0xA1, 0xA2, 0xA3];
        let mut additional_context = TestSignAdditionalContext {
            hedge_variant: 1,
            p_context: sign_context.as_mut_ptr(),
            ul_context_len: sign_context.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType(0x0000_0502).0 as CK_MECHANISM_TYPE,
            pParameter: &mut additional_context as *mut TestSignAdditionalContext as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<TestSignAdditionalContext>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("sign_additional_context")) }
            .params
        {
            Some(CkMechanismParams::SignAdditionalContext(params)) => {
                assert_eq!(params.hedge_variant, 1);
                assert_eq!(params.context, [0xA1, 0xA2, 0xA3]);
            }
            other => panic!("unexpected sign additional context params: {other:?}"),
        }
    }

    #[test]
    fn reads_signature_parameter_structs() {
        const CKM_TEST_EDDSA: CK_MECHANISM_TYPE = 0x8000_1040;
        const CKM_TEST_XEDDSA: CK_MECHANISM_TYPE = 0x8000_1041;

        let mut context = [0xA1u8, 0xA2, 0xA3];
        let mut eddsa = CK_EDDSA_PARAMS {
            phFlag: CK_TRUE,
            ulContextDataLen: context.len() as CK_ULONG,
            pContextData: context.as_mut_ptr(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_EDDSA,
            pParameter: &mut eddsa as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("eddsa")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Eddsa(params) => {
                assert!(params.ph_flag);
                assert_eq!(params.context_data, vec![0xA1, 0xA2, 0xA3]);
            }
            other => panic!("unexpected EdDSA params: {other:?}"),
        }

        let mut xeddsa = CK_XEDDSA_PARAMS { hash: CkMechanismType::SHA256.0 };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_XEDDSA,
            pParameter: &mut xeddsa as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_XEDDSA_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("xeddsa")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Xeddsa(params) => {
                assert_eq!(params.hash, CkMechanismType::SHA256.0);
            }
            other => panic!("unexpected XEdDSA params: {other:?}"),
        }
    }

    #[test]
    fn reads_rsa_wrap_parameter_structs() {
        let mut source_data = [0xA0u8, 0xA1, 0xA2];
        let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            mgf: 1,
            source: 1,
            pSourceData: source_data.as_mut_ptr() as CK_VOID_PTR,
            ulSourceDataLen: source_data.len() as CK_ULONG,
        };
        let mut rsa_aes_wrap =
            CK_RSA_AES_KEY_WRAP_PARAMS { ulAESKeyBits: 256, pOAEPParams: &mut oaep };
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType(0x0000_1054).0 as CK_MECHANISM_TYPE,
            pParameter: &mut rsa_aes_wrap as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams { aes_key_bits, oaep_params }) => {
                assert_eq!(aes_key_bits, 256);
                assert_eq!(oaep_params.hash_alg, CkMechanismType::SHA256);
                assert_eq!(oaep_params.mgf, 1);
                assert_eq!(oaep_params.source, 1);
                assert_eq!(oaep_params.source_data, [0xA0, 0xA1, 0xA2]);
            }
            other => panic!("unexpected RSA-AES key wrap params: {other:?}"),
        }

        let mut x = [0x51u8, 0x52, 0x53, 0x54];
        let mut key_wrap_set =
            CK_KEY_WRAP_SET_OAEP_PARAMS { bBC: 7, pX: x.as_mut_ptr(), ulXLen: x.len() as CK_ULONG };
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType(0x0000_0401).0 as CK_MECHANISM_TYPE,
            pParameter: &mut key_wrap_set as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_KEY_WRAP_SET_OAEP_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams { bc, x }) => {
                assert_eq!(bc, 7);
                assert_eq!(x, [0x51, 0x52, 0x53, 0x54]);
            }
            other => panic!("unexpected SET OAEP key wrap params: {other:?}"),
        }
    }

    #[test]
    fn reads_authenticated_wrap_parameter_structs() {
        const CKM_TEST_GCM_WRAP: CK_MECHANISM_TYPE = 0x8000_1030;
        const CKM_TEST_CCM_WRAP: CK_MECHANISM_TYPE = 0x8000_1031;

        let mut iv = [0x11u8; 12];
        let mut gcm_aad = [0xA1u8, 0xA2];
        let mut gcm_wrap = CK_GCM_WRAP_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 32,
            ivGenerator: 1,
            pAAD: gcm_aad.as_mut_ptr(),
            ulAADLen: gcm_aad.len() as CK_ULONG,
            ulTagBits: 128,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_GCM_WRAP,
            pParameter: &mut gcm_wrap as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_GCM_WRAP_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("gcm_wrap")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::GcmWrap(GcmWrapParams {
                iv,
                iv_fixed_bits,
                iv_generator,
                aad,
                tag_bits,
            }) => {
                assert_eq!(iv, [0x11; 12]);
                assert_eq!(iv_fixed_bits, 32);
                assert_eq!(iv_generator, 1);
                assert_eq!(aad, [0xA1, 0xA2]);
                assert_eq!(tag_bits, 128);
            }
            other => panic!("unexpected GCM wrap params: {other:?}"),
        }

        let mut nonce = [0x22u8; 7];
        let mut ccm_aad = [0xB1u8, 0xB2, 0xB3];
        let mut ccm_wrap = CK_CCM_WRAP_PARAMS {
            ulDataLen: 1024,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            ulNonceFixedBits: 24,
            nonceGenerator: 2,
            pAAD: ccm_aad.as_mut_ptr(),
            ulAADLen: ccm_aad.len() as CK_ULONG,
            ulMACLen: 16,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_CCM_WRAP,
            pParameter: &mut ccm_wrap as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_CCM_WRAP_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("ccm_wrap")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::CcmWrap(CcmWrapParams {
                data_len,
                nonce,
                nonce_fixed_bits,
                nonce_generator,
                aad,
                mac_len,
            }) => {
                assert_eq!(data_len, 1024);
                assert_eq!(nonce, [0x22; 7]);
                assert_eq!(nonce_fixed_bits, 24);
                assert_eq!(nonce_generator, 2);
                assert_eq!(aad, [0xB1, 0xB2, 0xB3]);
                assert_eq!(mac_len, 16);
            }
            other => panic!("unexpected CCM wrap params: {other:?}"),
        }
    }

    #[test]
    fn reads_aead_and_chacha_parameter_structs() {
        const CKM_TEST_CCM: CK_MECHANISM_TYPE = 0x8000_1040;
        const CKM_TEST_CHACHA20: CK_MECHANISM_TYPE = 0x8000_1041;
        const CKM_TEST_SALSA_CHACHA_POLY1305: CK_MECHANISM_TYPE = 0x8000_1042;

        let mut nonce = [0x31u8; 11];
        let mut ccm_aad = [0xC1u8, 0xC2];
        let mut ccm = CK_CCM_PARAMS {
            ulDataLen: 2048,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            pAAD: ccm_aad.as_mut_ptr(),
            ulAADLen: ccm_aad.len() as CK_ULONG,
            ulMACLen: 12,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_CCM,
            pParameter: &mut ccm as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_CCM_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("ccm")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Ccm(CcmParams { data_len, nonce, aad, mac_len }) => {
                assert_eq!(data_len, 2048);
                assert_eq!(nonce, [0x31; 11]);
                assert_eq!(aad, [0xC1, 0xC2]);
                assert_eq!(mac_len, 12);
            }
            other => panic!("unexpected CCM params: {other:?}"),
        }

        let mut block_counter = [0x41u8; 4];
        let mut chacha_nonce = [0x42u8; 12];
        let mut chacha = CK_CHACHA20_PARAMS {
            pBlockCounter: block_counter.as_mut_ptr(),
            blockCounterBits: 32,
            pNonce: chacha_nonce.as_mut_ptr(),
            ulNonceBits: 96,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_CHACHA20,
            pParameter: &mut chacha as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_CHACHA20_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("chacha20")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::ChaCha20(ChaCha20Params {
                block_counter,
                block_counter_bits,
                nonce,
                nonce_bits,
            }) => {
                assert_eq!(block_counter, [0x41; 4]);
                assert_eq!(block_counter_bits, 32);
                assert_eq!(nonce, [0x42; 12]);
                assert_eq!(nonce_bits, 96);
            }
            other => panic!("unexpected ChaCha20 params: {other:?}"),
        }

        let mut poly_nonce = [0x51u8; 12];
        let mut poly_aad = [0x52u8, 0x53, 0x54];
        let mut salsa_chacha_poly = CK_SALSA20_CHACHA20_POLY1305_PARAMS {
            pNonce: poly_nonce.as_mut_ptr(),
            ulNonceLen: poly_nonce.len() as CK_ULONG,
            pAAD: poly_aad.as_mut_ptr(),
            ulAADLen: poly_aad.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_SALSA_CHACHA_POLY1305,
            pParameter: &mut salsa_chacha_poly as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("salsa20_chacha20_poly1305")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
                nonce,
                aad,
            }) => {
                assert_eq!(nonce, [0x51; 12]);
                assert_eq!(aad, [0x52, 0x53, 0x54]);
            }
            other => panic!("unexpected Salsa20/ChaCha20-Poly1305 params: {other:?}"),
        }
    }

    #[test]
    fn reads_counter_and_encrypt_data_parameter_structs() {
        const CKM_TEST_AES_CTR: CK_MECHANISM_TYPE = 0x8000_1050;
        const CKM_TEST_CAMELLIA_CTR: CK_MECHANISM_TYPE = 0x8000_1051;
        const CKM_TEST_AES_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1052;
        const CKM_TEST_DES_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1053;
        const CKM_TEST_ARIA_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1054;
        const CKM_TEST_CAMELLIA_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1055;
        const CKM_TEST_SEED_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1056;

        let mut aes_ctr = CK_AES_CTR_PARAMS { ulCounterBits: 128, cb: [0xA1; 16] };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_AES_CTR,
            pParameter: &mut aes_ctr as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_AES_CTR_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("aes_ctr")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::AesCtr(params) => {
                assert_eq!(params.counter_bits, 128);
                assert_eq!(params.cb, [0xA1; 16]);
            }
            other => panic!("unexpected AES CTR params: {other:?}"),
        }

        let mut camellia_ctr = CK_CAMELLIA_CTR_PARAMS { ulCounterBits: 64, cb: [0xC1; 16] };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_CAMELLIA_CTR,
            pParameter: &mut camellia_ctr as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_CAMELLIA_CTR_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("camellia_ctr")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::CamelliaCtr(params) => {
                assert_eq!(params.counter_bits, 64);
                assert_eq!(params.cb, [0xC1; 16]);
            }
            other => panic!("unexpected Camellia CTR params: {other:?}"),
        }

        let mut aes_data = [0xA2u8, 0xA3, 0xA4];
        let mut aes = CK_AES_CBC_ENCRYPT_DATA_PARAMS {
            iv: [0xA5; 16],
            pData: aes_data.as_mut_ptr(),
            length: aes_data.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_AES_CBC_ENCRYPT_DATA,
            pParameter: &mut aes as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("aes_cbc_encrypt_data")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::AesCbcEncryptData(params) => {
                assert_eq!(params.iv, [0xA5; 16]);
                assert_eq!(params.data, [0xA2, 0xA3, 0xA4]);
            }
            other => panic!("unexpected AES CBC encrypt-data params: {other:?}"),
        }

        let mut des_data = [0xD2u8, 0xD3];
        let mut des = CK_DES_CBC_ENCRYPT_DATA_PARAMS {
            iv: [0xD5; 8],
            pData: des_data.as_mut_ptr(),
            length: des_data.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_DES_CBC_ENCRYPT_DATA,
            pParameter: &mut des as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_DES_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("des_cbc_encrypt_data")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::DesCbcEncryptData(params) => {
                assert_eq!(params.iv, [0xD5; 8]);
                assert_eq!(params.data, [0xD2, 0xD3]);
            }
            other => panic!("unexpected DES CBC encrypt-data params: {other:?}"),
        }

        let mut aria_data = [0x12u8, 0x13, 0x14, 0x15];
        let mut aria = CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
            iv: [0x15; 16],
            pData: aria_data.as_mut_ptr(),
            length: aria_data.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_ARIA_CBC_ENCRYPT_DATA,
            pParameter: &mut aria as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("aria_cbc_encrypt_data")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::AriaCbcEncryptData(params) => {
                assert_eq!(params.iv, [0x15; 16]);
                assert_eq!(params.data, [0x12, 0x13, 0x14, 0x15]);
            }
            other => panic!("unexpected ARIA CBC encrypt-data params: {other:?}"),
        }

        let mut camellia_data = [0x22u8, 0x23, 0x24];
        let mut camellia = CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS {
            iv: [0x25; 16],
            pData: camellia_data.as_mut_ptr(),
            length: camellia_data.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_CAMELLIA_CBC_ENCRYPT_DATA,
            pParameter: &mut camellia as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("camellia_cbc_encrypt_data")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::CamelliaCbcEncryptData(params) => {
                assert_eq!(params.iv, [0x25; 16]);
                assert_eq!(params.data, [0x22, 0x23, 0x24]);
            }
            other => panic!("unexpected Camellia CBC encrypt-data params: {other:?}"),
        }

        let mut seed_data = [0x32u8, 0x33];
        let mut seed = CK_SEED_CBC_ENCRYPT_DATA_PARAMS {
            iv: [0x35; 16],
            pData: seed_data.as_mut_ptr(),
            length: seed_data.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_SEED_CBC_ENCRYPT_DATA,
            pParameter: &mut seed as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SEED_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("seed_cbc_encrypt_data")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::SeedCbcEncryptData(params) => {
                assert_eq!(params.iv, [0x35; 16]);
                assert_eq!(params.data, [0x32, 0x33]);
            }
            other => panic!("unexpected SEED CBC encrypt-data params: {other:?}"),
        }
    }

    #[test]
    fn reads_legacy_rc2_rc5_and_salsa20_parameter_structs() {
        const CKM_TEST_RC5: CK_MECHANISM_TYPE = 0x8000_1000;
        const CKM_TEST_RC2_MAC_GENERAL: CK_MECHANISM_TYPE = 0x8000_1001;
        const CKM_TEST_RC5_MAC_GENERAL: CK_MECHANISM_TYPE = 0x8000_1002;
        const CKM_TEST_RC5_CBC: CK_MECHANISM_TYPE = 0x8000_1003;
        const CKM_TEST_SALSA20: CK_MECHANISM_TYPE = 0x8000_1004;
        const CKM_TEST_RC2_CBC: CK_MECHANISM_TYPE = 0x8000_1005;
        const CKM_TEST_MAC_GENERAL: CK_MECHANISM_TYPE = 0x8000_1006;

        let mut rc5 = CK_RC5_PARAMS { ulWordsize: 32, ulRounds: 12 };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_RC5,
            pParameter: &mut rc5 as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RC5_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("rc5")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Rc5(params) => {
                assert_eq!(params.word_size, 32);
                assert_eq!(params.rounds, 12);
            }
            other => panic!("unexpected RC5 params: {other:?}"),
        }

        let mut rc2_mac = CK_RC2_MAC_GENERAL_PARAMS { ulEffectiveBits: 128, ulMacLength: 12 };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_RC2_MAC_GENERAL,
            pParameter: &mut rc2_mac as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RC2_MAC_GENERAL_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("rc2_mac_general")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Rc2MacGeneral(params) => {
                assert_eq!(params.effective_bits, 128);
                assert_eq!(params.mac_length, 12);
            }
            other => panic!("unexpected RC2 MAC-GENERAL params: {other:?}"),
        }

        let mut rc5_mac =
            CK_RC5_MAC_GENERAL_PARAMS { ulWordsize: 32, ulRounds: 16, ulMacLength: 20 };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_RC5_MAC_GENERAL,
            pParameter: &mut rc5_mac as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RC5_MAC_GENERAL_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("rc5_mac_general")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Rc5MacGeneral(params) => {
                assert_eq!(params.word_size, 32);
                assert_eq!(params.rounds, 16);
                assert_eq!(params.mac_length, 20);
            }
            other => panic!("unexpected RC5 MAC-GENERAL params: {other:?}"),
        }

        let mut iv = [0xA5u8; 8];
        let mut rc5_cbc = CK_RC5_CBC_PARAMS {
            ulWordsize: 32,
            ulRounds: 18,
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_RC5_CBC,
            pParameter: &mut rc5_cbc as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RC5_CBC_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("rc5_cbc")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Rc5Cbc(params) => {
                assert_eq!(params.word_size, 32);
                assert_eq!(params.rounds, 18);
                assert_eq!(params.iv, vec![0xA5; 8]);
            }
            other => panic!("unexpected RC5-CBC params: {other:?}"),
        }

        let mut rc2_cbc = CK_RC2_CBC_PARAMS { ulEffectiveBits: 128, iv: [0xC2; 8] };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_RC2_CBC,
            pParameter: &mut rc2_cbc as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RC2_CBC_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("rc2_cbc")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Rc2Cbc(params) => {
                assert_eq!(params.effective_bits, 128);
                assert_eq!(params.iv, vec![0xC2; 8]);
            }
            other => panic!("unexpected RC2-CBC params: {other:?}"),
        }

        let mut mac_length: CK_MAC_GENERAL_PARAMS = 16;
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_MAC_GENERAL,
            pParameter: &mut mac_length as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_MAC_GENERAL_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("mac_general")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::MacGeneral(params) => {
                assert_eq!(params.mac_length, 16);
            }
            other => panic!("unexpected MAC-GENERAL params: {other:?}"),
        }

        let mut block_counter = [0x11u8; 8];
        let mut nonce = [0x22u8; 8];
        let mut salsa20 = CK_SALSA20_PARAMS {
            pBlockCounter: block_counter.as_mut_ptr(),
            pNonce: nonce.as_mut_ptr(),
            ulNonceBits: 64,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_SALSA20,
            pParameter: &mut salsa20 as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SALSA20_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("salsa20")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Salsa20(params) => {
                assert_eq!(params.block_counter, vec![0x11; 8]);
                assert_eq!(params.nonce, vec![0x22; 8]);
                assert_eq!(params.nonce_bits, 64);
            }
            other => panic!("unexpected Salsa20 params: {other:?}"),
        }
    }

    #[test]
    fn reads_tls_ssl_parameter_structs() {
        const CKM_TEST_TLS_MAC: CK_MECHANISM_TYPE = 0x8000_1008;
        const CKM_TEST_TLS_PRF: CK_MECHANISM_TYPE = 0x8000_1009;
        const CKM_TEST_TLS_KDF: CK_MECHANISM_TYPE = 0x8000_100A;
        const CKM_TEST_SSL3_MASTER_KEY_DERIVE: CK_MECHANISM_TYPE = 0x8000_100B;
        const CKM_TEST_TLS12_EXTENDED_MASTER_KEY_DERIVE: CK_MECHANISM_TYPE = 0x8000_100C;

        let mut tls_mac = CK_TLS_MAC_PARAMS {
            prfHashMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            ulMacLength: 32,
            ulServerOrClient: 1,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_TLS_MAC,
            pParameter: &mut tls_mac as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_TLS_MAC_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("tls_mac")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::TlsMac(params) => {
                assert_eq!(params.prf_hash_mechanism, CkMechanismType::SHA256.0);
                assert_eq!(params.mac_length, 32);
                assert_eq!(params.server_or_client, 1);
            }
            other => panic!("unexpected TLS MAC params: {other:?}"),
        }

        let mut seed = [0xA1u8, 0xA2, 0xA3];
        let mut label = [0xB1u8, 0xB2];
        let mut output = [0u8; 12];
        let mut output_len = output.len() as CK_ULONG;
        let mut tls_prf = CK_TLS_PRF_PARAMS {
            pSeed: seed.as_mut_ptr(),
            ulSeedLen: seed.len() as CK_ULONG,
            pLabel: label.as_mut_ptr(),
            ulLabelLen: label.len() as CK_ULONG,
            pOutput: output.as_mut_ptr(),
            pulOutputLen: &mut output_len,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_TLS_PRF,
            pParameter: &mut tls_prf as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_TLS_PRF_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("tls_prf")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::TlsPrf(params) => {
                assert_eq!(params.seed, vec![0xA1, 0xA2, 0xA3]);
                assert_eq!(params.label, vec![0xB1, 0xB2]);
                assert_eq!(params.output_len, 12);
            }
            other => panic!("unexpected TLS PRF params: {other:?}"),
        }

        let mut client_random = [0x11u8; 4];
        let mut server_random = [0x22u8; 4];
        let mut kdf_label = [0x33u8, 0x34];
        let mut context_data = [0x44u8, 0x45, 0x46];
        let mut tls_kdf = CK_TLS_KDF_PARAMS {
            prfMechanism: CkMechanismType::SHA384.0 as CK_MECHANISM_TYPE,
            pLabel: kdf_label.as_mut_ptr(),
            ulLabelLength: kdf_label.len() as CK_ULONG,
            RandomInfo: CK_SSL3_RANDOM_DATA {
                pClientRandom: client_random.as_mut_ptr(),
                ulClientRandomLen: client_random.len() as CK_ULONG,
                pServerRandom: server_random.as_mut_ptr(),
                ulServerRandomLen: server_random.len() as CK_ULONG,
            },
            pContextData: context_data.as_mut_ptr(),
            ulContextDataLength: context_data.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_TLS_KDF,
            pParameter: &mut tls_kdf as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_TLS_KDF_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("tls_kdf")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::TlsKdf(params) => {
                assert_eq!(params.prf_mechanism, CkMechanismType::SHA384.0);
                assert_eq!(params.label, vec![0x33, 0x34]);
                assert_eq!(params.random_info.client_random, vec![0x11; 4]);
                assert_eq!(params.random_info.server_random, vec![0x22; 4]);
                assert_eq!(params.context_data, vec![0x44, 0x45, 0x46]);
            }
            other => panic!("unexpected TLS KDF params: {other:?}"),
        }

        let mut ssl3_client_random = [0x51u8; 4];
        let mut ssl3_server_random = [0x52u8; 4];
        let mut ssl3_version = CK_VERSION { major: 3, minor: 0 };
        let mut ssl3_master = CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
            RandomInfo: CK_SSL3_RANDOM_DATA {
                pClientRandom: ssl3_client_random.as_mut_ptr(),
                ulClientRandomLen: ssl3_client_random.len() as CK_ULONG,
                pServerRandom: ssl3_server_random.as_mut_ptr(),
                ulServerRandomLen: ssl3_server_random.len() as CK_ULONG,
            },
            pVersion: &mut ssl3_version,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_SSL3_MASTER_KEY_DERIVE,
            pParameter: &mut ssl3_master as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("ssl3_master_key_derive")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Ssl3MasterKeyDerive(params) => {
                assert_eq!(params.random_info.client_random, vec![0x51; 4]);
                assert_eq!(params.random_info.server_random, vec![0x52; 4]);
                assert_eq!(params.version_major, 3);
                assert_eq!(params.version_minor, 0);
            }
            other => panic!("unexpected SSL3 master-key params: {other:?}"),
        }

        let mut session_hash = [0x61u8; 8];
        let mut tls12_version = CK_VERSION { major: 3, minor: 3 };
        let mut tls12_extended = CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS {
            prfHashMechanism: CkMechanismType::SHA512.0 as CK_MECHANISM_TYPE,
            pSessionHash: session_hash.as_mut_ptr(),
            ulSessionHashLen: session_hash.len() as CK_ULONG,
            pVersion: &mut tls12_version,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_TLS12_EXTENDED_MASTER_KEY_DERIVE,
            pParameter: &mut tls12_extended as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>()
                as CK_ULONG,
        };
        match unsafe {
            read_mechanism_with_shape(&mechanism, Some("tls12_extended_master_key_derive"))
        }
        .params
        .expect("mechanism params")
        {
            CkMechanismParams::Tls12ExtendedMasterKeyDerive(params) => {
                assert_eq!(params.prf_hash_mechanism, CkMechanismType::SHA512.0);
                assert_eq!(params.session_hash, vec![0x61; 8]);
                assert_eq!(params.version_major, 3);
                assert_eq!(params.version_minor, 3);
            }
            other => panic!("unexpected TLS 1.2 extended master-key params: {other:?}"),
        }
    }

    #[test]
    fn reads_kdf_and_legacy_agreement_parameter_structs() {
        const CKM_TEST_HKDF: CK_MECHANISM_TYPE = 0x8000_100D;
        const CKM_TEST_GOSTR3410_DERIVE: CK_MECHANISM_TYPE = 0x8000_100E;
        const CKM_TEST_GOSTR3410_KEY_WRAP: CK_MECHANISM_TYPE = 0x8000_100F;
        const CKM_TEST_KEA_DERIVE: CK_MECHANISM_TYPE = 0x8000_1012;
        const CKM_TEST_PKCS5_PBKD2: CK_MECHANISM_TYPE = 0x8000_1013;

        let mut salt = [0xA1u8, 0xA2, 0xA3];
        let mut info = [0xB1u8, 0xB2];
        let mut hkdf = CK_HKDF_PARAMS {
            bExtract: CK_TRUE,
            bExpand: CK_TRUE,
            prfHashMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            ulSaltType: 1,
            pSalt: salt.as_mut_ptr(),
            ulSaltLen: salt.len() as CK_ULONG,
            hSaltKey: 0x1234,
            pInfo: info.as_mut_ptr(),
            ulInfoLen: info.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_HKDF,
            pParameter: &mut hkdf as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("hkdf")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Hkdf(params) => {
                assert!(params.extract);
                assert!(params.expand);
                assert_eq!(params.prf_hash_mechanism, CkMechanismType::SHA256.0);
                assert_eq!(params.salt_type, 1);
                assert_eq!(params.salt, vec![0xA1, 0xA2, 0xA3]);
                assert_eq!(params.salt_key_handle, 0x1234);
                assert_eq!(params.info, vec![0xB1, 0xB2]);
            }
            other => panic!("unexpected HKDF params: {other:?}"),
        }

        let mut public_data = [0xC1u8, 0xC2, 0xC3];
        let mut ukm = [0xD1u8, 0xD2];
        let mut gostr_derive = CK_GOSTR3410_DERIVE_PARAMS {
            kdf: 1,
            pPublicData: public_data.as_mut_ptr(),
            ulPublicDataLen: public_data.len() as CK_ULONG,
            pUKM: ukm.as_mut_ptr(),
            ulUKMLen: ukm.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_GOSTR3410_DERIVE,
            pParameter: &mut gostr_derive as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_GOSTR3410_DERIVE_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("gostr3410_derive")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Gostr3410Derive(params) => {
                assert_eq!(params.kdf, 1);
                assert_eq!(params.public_data, vec![0xC1, 0xC2, 0xC3]);
                assert_eq!(params.ukm, vec![0xD1, 0xD2]);
            }
            other => panic!("unexpected GOSTR3410 derive params: {other:?}"),
        }

        let mut wrap_oid = [0x06u8, 0x07, 0x2A];
        let mut wrap_ukm = [0xE1u8, 0xE2, 0xE3, 0xE4];
        let mut gostr_wrap = CK_GOSTR3410_KEY_WRAP_PARAMS {
            pWrapOID: wrap_oid.as_mut_ptr(),
            ulWrapOIDLen: wrap_oid.len() as CK_ULONG,
            pUKM: wrap_ukm.as_mut_ptr(),
            ulUKMLen: wrap_ukm.len() as CK_ULONG,
            hKey: 0xBEEF,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_GOSTR3410_KEY_WRAP,
            pParameter: &mut gostr_wrap as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_GOSTR3410_KEY_WRAP_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("gostr3410_key_wrap")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Gostr3410KeyWrap(params) => {
                assert_eq!(params.wrap_oid, vec![0x06, 0x07, 0x2A]);
                assert_eq!(params.ukm, vec![0xE1, 0xE2, 0xE3, 0xE4]);
                assert_eq!(params.key_handle, 0xBEEF);
            }
            other => panic!("unexpected GOSTR3410 key-wrap params: {other:?}"),
        }

        let mut random_a = [0x11u8, 0x12];
        let mut random_b = [0x21u8, 0x22];
        let mut kea_public = [0x31u8, 0x32, 0x33];
        let mut kea = CK_KEA_DERIVE_PARAMS {
            isSender: CK_TRUE,
            ulRandomLen: random_a.len() as CK_ULONG,
            RandomA: random_a.as_mut_ptr(),
            RandomB: random_b.as_mut_ptr(),
            ulPublicDataLen: kea_public.len() as CK_ULONG,
            PublicData: kea_public.as_mut_ptr(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_KEA_DERIVE,
            pParameter: &mut kea as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_KEA_DERIVE_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("kea_derive")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::KeaDerive(params) => {
                assert!(params.is_sender);
                assert_eq!(params.random_a, vec![0x11, 0x12]);
                assert_eq!(params.random_b, vec![0x21, 0x22]);
                assert_eq!(params.public_data, vec![0x31, 0x32, 0x33]);
            }
            other => panic!("unexpected KEA derive params: {other:?}"),
        }

        let mut salt_source_data = [0x41u8, 0x42];
        let mut prf_data = [0x51u8];
        let mut password = [0x73u8, 0x65, 0x63, 0x72, 0x65, 0x74];
        let mut pbkd2 = CK_PKCS5_PBKD2_PARAMS2 {
            saltSource: 1,
            pSaltSourceData: salt_source_data.as_mut_ptr() as CK_VOID_PTR,
            ulSaltSourceDataLen: salt_source_data.len() as CK_ULONG,
            iterations: 600_000,
            prf: 2,
            pPrfData: prf_data.as_mut_ptr() as CK_VOID_PTR,
            ulPrfDataLen: prf_data.len() as CK_ULONG,
            pPassword: password.as_mut_ptr(),
            ulPasswordLen: password.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_PKCS5_PBKD2,
            pParameter: &mut pbkd2 as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_PKCS5_PBKD2_PARAMS2>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("pkcs5_pbkd2")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Pkcs5Pbkd2(params) => {
                assert_eq!(params.salt_source, 1);
                assert_eq!(params.salt_source_data, vec![0x41, 0x42]);
                assert_eq!(params.iterations, 600_000);
                assert_eq!(params.prf, 2);
                assert_eq!(params.prf_data, vec![0x51]);
                assert_eq!(params.password, b"secret");
            }
            other => panic!("unexpected PKCS#5 PBKD2 params: {other:?}"),
        }
    }

    #[test]
    fn reads_ecdh_and_x942_parameter_structs() {
        const CKM_TEST_ECDH1_DERIVE: CK_MECHANISM_TYPE = 0x8000_1014;
        const CKM_TEST_ECDH2_DERIVE: CK_MECHANISM_TYPE = 0x8000_1015;
        const CKM_TEST_ECMQV_DERIVE: CK_MECHANISM_TYPE = 0x8000_1016;
        const CKM_TEST_ECDH_AES_KEY_WRAP: CK_MECHANISM_TYPE = 0x8000_1017;
        const CKM_TEST_X942_DH1_DERIVE: CK_MECHANISM_TYPE = 0x8000_1018;
        const CKM_TEST_X942_DH2_DERIVE: CK_MECHANISM_TYPE = 0x8000_1019;

        let mut shared_data = [0xA1u8, 0xA2];
        let mut public_data = [0xB1u8, 0xB2, 0xB3];
        let mut ecdh1 = CK_ECDH1_DERIVE_PARAMS {
            kdf: 7,
            ulSharedDataLen: shared_data.len() as CK_ULONG,
            pSharedData: shared_data.as_mut_ptr(),
            ulPublicDataLen: public_data.len() as CK_ULONG,
            pPublicData: public_data.as_mut_ptr(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_ECDH1_DERIVE,
            pParameter: &mut ecdh1 as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("ecdh1_derive")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Ecdh1Derive(params) => {
                assert_eq!(params.kdf, 7);
                assert_eq!(params.shared_data, vec![0xA1, 0xA2]);
                assert_eq!(params.public_data, vec![0xB1, 0xB2, 0xB3]);
            }
            other => panic!("unexpected ECDH1 derive params: {other:?}"),
        }

        let mut shared_data = [0xC1u8, 0xC2, 0xC3];
        let mut public_data = [0xD1u8, 0xD2];
        let mut public_data2 = [0xE1u8, 0xE2, 0xE3, 0xE4];
        let mut ecdh2 = CK_ECDH2_DERIVE_PARAMS {
            kdf: 8,
            ulSharedDataLen: shared_data.len() as CK_ULONG,
            pSharedData: shared_data.as_mut_ptr(),
            ulPublicDataLen: public_data.len() as CK_ULONG,
            pPublicData: public_data.as_mut_ptr(),
            ulPrivateDataLen: 32,
            hPrivateData: 0x1234,
            ulPublicDataLen2: public_data2.len() as CK_ULONG,
            pPublicData2: public_data2.as_mut_ptr(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_ECDH2_DERIVE,
            pParameter: &mut ecdh2 as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_ECDH2_DERIVE_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("ecdh2_derive")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Ecdh2Derive(params) => {
                assert_eq!(params.kdf, 8);
                assert_eq!(params.shared_data, vec![0xC1, 0xC2, 0xC3]);
                assert_eq!(params.public_data, vec![0xD1, 0xD2]);
                assert_eq!(params.private_data_len, 32);
                assert_eq!(params.private_data_handle, 0x1234);
                assert_eq!(params.public_data2, vec![0xE1, 0xE2, 0xE3, 0xE4]);
            }
            other => panic!("unexpected ECDH2 derive params: {other:?}"),
        }

        let mut shared_data = [0x11u8, 0x12];
        let mut public_data = [0x21u8, 0x22, 0x23];
        let mut public_data2 = [0x31u8, 0x32];
        let mut ecmqv = CK_ECMQV_DERIVE_PARAMS {
            kdf: 9,
            ulSharedDataLen: shared_data.len() as CK_ULONG,
            pSharedData: shared_data.as_mut_ptr(),
            ulPublicDataLen: public_data.len() as CK_ULONG,
            pPublicData: public_data.as_mut_ptr(),
            ulPrivateDataLen: 48,
            hPrivateData: 0x2345,
            ulPublicDataLen2: public_data2.len() as CK_ULONG,
            pPublicData2: public_data2.as_mut_ptr(),
            publicKey: 0x3456,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_ECMQV_DERIVE,
            pParameter: &mut ecmqv as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_ECMQV_DERIVE_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("ecmqv_derive")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::EcmqvDerive(params) => {
                assert_eq!(params.kdf, 9);
                assert_eq!(params.shared_data, vec![0x11, 0x12]);
                assert_eq!(params.public_data, vec![0x21, 0x22, 0x23]);
                assert_eq!(params.private_data_len, 48);
                assert_eq!(params.private_data_handle, 0x2345);
                assert_eq!(params.public_data2, vec![0x31, 0x32]);
                assert_eq!(params.public_key_handle, 0x3456);
            }
            other => panic!("unexpected ECMQV derive params: {other:?}"),
        }

        let mut shared_data = [0x41u8, 0x42, 0x43];
        let mut ecdh_wrap = CK_ECDH_AES_KEY_WRAP_PARAMS {
            ulAESKeyBits: 256,
            kdf: 10,
            ulSharedDataLen: shared_data.len() as CK_ULONG,
            pSharedData: shared_data.as_mut_ptr(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_ECDH_AES_KEY_WRAP,
            pParameter: &mut ecdh_wrap as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_ECDH_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("ecdh_aes_key_wrap")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::EcdhAesKeyWrap(params) => {
                assert_eq!(params.aes_key_bits, 256);
                assert_eq!(params.kdf, 10);
                assert_eq!(params.shared_data, vec![0x41, 0x42, 0x43]);
            }
            other => panic!("unexpected ECDH AES key-wrap params: {other:?}"),
        }

        let mut other_info = [0x51u8, 0x52];
        let mut public_data = [0x61u8, 0x62, 0x63];
        let mut x942_dh1 = CK_X9_42_DH1_DERIVE_PARAMS {
            kdf: 11,
            ulOtherInfoLen: other_info.len() as CK_ULONG,
            pOtherInfo: other_info.as_mut_ptr(),
            ulPublicDataLen: public_data.len() as CK_ULONG,
            pPublicData: public_data.as_mut_ptr(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_X942_DH1_DERIVE,
            pParameter: &mut x942_dh1 as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_X9_42_DH1_DERIVE_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("x942_dh1_derive")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::X942Dh1Derive(params) => {
                assert_eq!(params.kdf, 11);
                assert_eq!(params.other_info, vec![0x51, 0x52]);
                assert_eq!(params.public_data, vec![0x61, 0x62, 0x63]);
            }
            other => panic!("unexpected X9.42 DH1 derive params: {other:?}"),
        }

        let mut other_info = [0x71u8, 0x72, 0x73];
        let mut public_data = [0x81u8, 0x82];
        let mut public_data2 = [0x91u8, 0x92, 0x93, 0x94];
        let mut x942_dh2 = CK_X9_42_DH2_DERIVE_PARAMS {
            kdf: 12,
            ulOtherInfoLen: other_info.len() as CK_ULONG,
            pOtherInfo: other_info.as_mut_ptr(),
            ulPublicDataLen: public_data.len() as CK_ULONG,
            pPublicData: public_data.as_mut_ptr(),
            ulPrivateDataLen: 64,
            hPrivateData: 0x4567,
            ulPublicDataLen2: public_data2.len() as CK_ULONG,
            pPublicData2: public_data2.as_mut_ptr(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_X942_DH2_DERIVE,
            pParameter: &mut x942_dh2 as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_X9_42_DH2_DERIVE_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("x942_dh2_derive")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::X942Dh2Derive(params) => {
                assert_eq!(params.kdf, 12);
                assert_eq!(params.other_info, vec![0x71, 0x72, 0x73]);
                assert_eq!(params.public_data, vec![0x81, 0x82]);
                assert_eq!(params.private_data_len, 64);
                assert_eq!(params.private_data_handle, 0x4567);
                assert_eq!(params.public_data2, vec![0x91, 0x92, 0x93, 0x94]);
            }
            other => panic!("unexpected X9.42 DH2 derive params: {other:?}"),
        }
    }

    #[test]
    fn reads_ike_parameter_structs() {
        const CKM_TEST_IKE_PRF_DERIVE: CK_MECHANISM_TYPE = 0x8000_101A;
        const CKM_TEST_IKE1_PRF_DERIVE: CK_MECHANISM_TYPE = 0x8000_101B;
        const CKM_TEST_IKE1_EXTENDED_DERIVE: CK_MECHANISM_TYPE = 0x8000_101C;
        const CKM_TEST_IKE2_PRF_PLUS_DERIVE: CK_MECHANISM_TYPE = 0x8000_101D;

        let mut ni = [0xA1u8, 0xA2, 0xA3];
        let mut nr = [0xB1u8, 0xB2];
        let mut ike_prf = CK_IKE_PRF_DERIVE_PARAMS {
            prfMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            bDataAsKey: CK_TRUE,
            bRekey: CK_FALSE,
            pNi: ni.as_mut_ptr(),
            ulNiLen: ni.len() as CK_ULONG,
            pNr: nr.as_mut_ptr(),
            ulNrLen: nr.len() as CK_ULONG,
            hNewKey: 0x1234,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_IKE_PRF_DERIVE,
            pParameter: &mut ike_prf as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_IKE_PRF_DERIVE_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("ike_prf_derive")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::IkePrfDerive(params) => {
                assert_eq!(params.prf_mechanism, CkMechanismType::SHA256.0);
                assert!(params.data_as_key);
                assert!(!params.rekey);
                assert_eq!(params.ni, vec![0xA1, 0xA2, 0xA3]);
                assert_eq!(params.nr, vec![0xB1, 0xB2]);
                assert_eq!(params.new_key_handle, 0x1234);
            }
            other => panic!("unexpected IKE PRF derive params: {other:?}"),
        }

        let mut ckyi = [0xC1u8, 0xC2];
        let mut ckyr = [0xD1u8, 0xD2, 0xD3];
        let mut ike1_prf = CK_IKE1_PRF_DERIVE_PARAMS {
            prfMechanism: CkMechanismType::SHA384.0 as CK_MECHANISM_TYPE,
            bHasPrevKey: CK_TRUE,
            hKeygxy: 0x2345,
            hPrevKey: 0x3456,
            pCKYi: ckyi.as_mut_ptr(),
            ulCKYiLen: ckyi.len() as CK_ULONG,
            pCKYr: ckyr.as_mut_ptr(),
            ulCKYrLen: ckyr.len() as CK_ULONG,
            keyNumber: 3,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_IKE1_PRF_DERIVE,
            pParameter: &mut ike1_prf as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_IKE1_PRF_DERIVE_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("ike1_prf_derive")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Ike1PrfDerive(params) => {
                assert_eq!(params.prf_mechanism, CkMechanismType::SHA384.0);
                assert!(params.has_prev_key);
                assert_eq!(params.keygxy_handle, 0x2345);
                assert_eq!(params.prev_key_handle, 0x3456);
                assert_eq!(params.ckyi, vec![0xC1, 0xC2]);
                assert_eq!(params.ckyr, vec![0xD1, 0xD2, 0xD3]);
                assert_eq!(params.key_number, 3);
            }
            other => panic!("unexpected IKE1 PRF derive params: {other:?}"),
        }

        let mut extra_data = [0xE1u8, 0xE2, 0xE3, 0xE4];
        let mut ike1_extended = CK_IKE1_EXTENDED_DERIVE_PARAMS {
            prfMechanism: CkMechanismType::SHA512.0 as CK_MECHANISM_TYPE,
            bHasKeygxy: CK_TRUE,
            hKeygxy: 0x4567,
            pExtraData: extra_data.as_mut_ptr(),
            ulExtraDataLen: extra_data.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_IKE1_EXTENDED_DERIVE,
            pParameter: &mut ike1_extended as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_IKE1_EXTENDED_DERIVE_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("ike1_extended_derive")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Ike1ExtendedDerive(params) => {
                assert_eq!(params.prf_mechanism, CkMechanismType::SHA512.0);
                assert!(params.has_keygxy);
                assert_eq!(params.keygxy_handle, 0x4567);
                assert_eq!(params.extra_data, vec![0xE1, 0xE2, 0xE3, 0xE4]);
            }
            other => panic!("unexpected IKE1 extended derive params: {other:?}"),
        }

        let mut seed_data = [0xF1u8, 0xF2, 0xF3];
        let mut ike2 = CK_IKE2_PRF_PLUS_DERIVE_PARAMS {
            prfMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            bHasSeedKey: CK_TRUE,
            hSeedKey: 0x5678,
            pSeedData: seed_data.as_mut_ptr(),
            ulSeedDataLen: seed_data.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_IKE2_PRF_PLUS_DERIVE,
            pParameter: &mut ike2 as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("ike2_prf_plus_derive")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Ike2PrfPlusDerive(params) => {
                assert_eq!(params.prf_mechanism, CkMechanismType::SHA256.0);
                assert!(params.has_seed_key);
                assert_eq!(params.seed_key_handle, 0x5678);
                assert_eq!(params.seed_data, vec![0xF1, 0xF2, 0xF3]);
            }
            other => panic!("unexpected IKE2 PRF-plus derive params: {other:?}"),
        }
    }

    #[test]
    fn reads_wtls_prf_and_x942_mqv_parameter_structs() {
        const CKM_TEST_WTLS_PRF: CK_MECHANISM_TYPE = 0x8000_1010;
        const CKM_TEST_X942_MQV: CK_MECHANISM_TYPE = 0x8000_1011;

        let mut seed = [0xA1u8, 0xA2, 0xA3];
        let mut label = [0xB1u8, 0xB2];
        let mut output = [0u8; 12];
        let mut output_len = output.len() as CK_ULONG;
        let mut wtls = CK_WTLS_PRF_PARAMS {
            DigestMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            pSeed: seed.as_mut_ptr(),
            ulSeedLen: seed.len() as CK_ULONG,
            pLabel: label.as_mut_ptr(),
            ulLabelLen: label.len() as CK_ULONG,
            pOutput: output.as_mut_ptr(),
            pulOutputLen: &mut output_len,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_WTLS_PRF,
            pParameter: &mut wtls as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_WTLS_PRF_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("wtls_prf")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::WtlsPrf(params) => {
                assert_eq!(params.digest_mechanism, CkMechanismType::SHA256.0);
                assert_eq!(params.seed, vec![0xA1, 0xA2, 0xA3]);
                assert_eq!(params.label, vec![0xB1, 0xB2]);
                assert_eq!(params.output_len, 12);
            }
            other => panic!("unexpected WTLS PRF params: {other:?}"),
        }

        let mut other_info = [0xC1u8, 0xC2];
        let mut public_data = [0xD1u8, 0xD2, 0xD3];
        let mut public_data2 = [0xE1u8, 0xE2, 0xE3, 0xE4];
        let mut x942 = CK_X9_42_MQV_DERIVE_PARAMS {
            kdf: 7,
            ulOtherInfoLen: other_info.len() as CK_ULONG,
            OtherInfo: other_info.as_mut_ptr(),
            ulPublicDataLen: public_data.len() as CK_ULONG,
            PublicData: public_data.as_mut_ptr(),
            ulPrivateDataLen: 32,
            hPrivateData: 77,
            ulPublicDataLen2: public_data2.len() as CK_ULONG,
            PublicData2: public_data2.as_mut_ptr(),
            publicKey: 88,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_X942_MQV,
            pParameter: &mut x942 as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_X9_42_MQV_DERIVE_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("x942_mqv_derive")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::X942MqvDerive(params) => {
                assert_eq!(params.kdf, 7);
                assert_eq!(params.other_info, vec![0xC1, 0xC2]);
                assert_eq!(params.public_data, vec![0xD1, 0xD2, 0xD3]);
                assert_eq!(params.private_data_len, 32);
                assert_eq!(params.private_data_handle, 77);
                assert_eq!(params.public_data2, vec![0xE1, 0xE2, 0xE3, 0xE4]);
                assert_eq!(params.public_key_handle, 88);
            }
            other => panic!("unexpected X9.42 MQV params: {other:?}"),
        }
    }

    #[test]
    fn reads_otp_and_skipjack_parameter_structs() {
        const CKM_TEST_OTP: CK_MECHANISM_TYPE = 0x8000_1020;
        const CKM_TEST_SKIPJACK_PRIVATE_WRAP: CK_MECHANISM_TYPE = 0x8000_1021;
        const CKM_TEST_SKIPJACK_RELAYX: CK_MECHANISM_TYPE = 0x8000_1022;

        let mut otp_value = [0x11u8, 0x12, 0x13];
        let mut otp_pin = [0x21u8, 0x22];
        let mut otp_params = [
            CK_OTP_PARAM {
                type_: 0,
                pValue: otp_value.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: otp_value.len() as CK_ULONG,
            },
            CK_OTP_PARAM {
                type_: 1,
                pValue: otp_pin.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: otp_pin.len() as CK_ULONG,
            },
        ];
        let mut otp = CK_OTP_PARAMS {
            pParams: otp_params.as_mut_ptr(),
            ulCount: otp_params.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_OTP,
            pParameter: &mut otp as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_OTP_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("otp")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Otp(params) => {
                assert_eq!(params.params.len(), 2);
                assert_eq!(params.params[0].type_, 0);
                assert_eq!(params.params[0].value, vec![0x11, 0x12, 0x13]);
                assert_eq!(params.params[1].type_, 1);
                assert_eq!(params.params[1].value, vec![0x21, 0x22]);
            }
            other => panic!("unexpected OTP params: {other:?}"),
        }

        let mut password = [0x31u8, 0x32];
        let mut public_data = [0x41u8, 0x42, 0x43];
        let mut random_a = [0x51u8, 0x52, 0x53, 0x54];
        let mut prime_p = [0x61u8, 0x62];
        let mut base_g = [0x71u8, 0x72];
        let mut subprime_q = [0x81u8, 0x82, 0x83];
        let mut private_wrap = CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
            ulPasswordLen: password.len() as CK_ULONG,
            pPassword: password.as_mut_ptr(),
            ulPublicDataLen: public_data.len() as CK_ULONG,
            pPublicData: public_data.as_mut_ptr(),
            ulPAndGLen: prime_p.len() as CK_ULONG,
            ulQLen: subprime_q.len() as CK_ULONG,
            ulRandomLen: random_a.len() as CK_ULONG,
            pRandomA: random_a.as_mut_ptr(),
            pPrimeP: prime_p.as_mut_ptr(),
            pBaseG: base_g.as_mut_ptr(),
            pSubprimeQ: subprime_q.as_mut_ptr(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_SKIPJACK_PRIVATE_WRAP,
            pParameter: &mut private_wrap as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SKIPJACK_PRIVATE_WRAP_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("skipjack_private_wrap")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::SkipjackPrivateWrap(params) => {
                assert_eq!(params.password, vec![0x31, 0x32]);
                assert_eq!(params.password_length, 2);
                assert_eq!(params.public_data, vec![0x41, 0x42, 0x43]);
                assert_eq!(params.random_a, vec![0x51, 0x52, 0x53, 0x54]);
                assert_eq!(params.prime_p, vec![0x61, 0x62]);
                assert_eq!(params.base_g, vec![0x71, 0x72]);
                assert_eq!(params.subprime_q, vec![0x81, 0x82, 0x83]);
            }
            other => panic!("unexpected Skipjack private-wrap params: {other:?}"),
        }

        let mut old_wrapped_x = [0x91u8, 0x92];
        let mut old_password = [0xA1u8, 0xA2, 0xA3];
        let mut old_public_data = [0xB1u8];
        let mut old_random_a = [0xC1u8, 0xC2];
        let mut new_password = [0xD1u8, 0xD2, 0xD3, 0xD4];
        let mut new_public_data = [0xE1u8, 0xE2];
        let mut new_random_a = [0xF1u8, 0xF2, 0xF3];
        let mut relayx = CK_SKIPJACK_RELAYX_PARAMS {
            ulOldWrappedXLen: old_wrapped_x.len() as CK_ULONG,
            pOldWrappedX: old_wrapped_x.as_mut_ptr(),
            ulOldPasswordLen: old_password.len() as CK_ULONG,
            pOldPassword: old_password.as_mut_ptr(),
            ulOldPublicDataLen: old_public_data.len() as CK_ULONG,
            pOldPublicData: old_public_data.as_mut_ptr(),
            ulOldRandomLen: old_random_a.len() as CK_ULONG,
            pOldRandomA: old_random_a.as_mut_ptr(),
            ulNewPasswordLen: new_password.len() as CK_ULONG,
            pNewPassword: new_password.as_mut_ptr(),
            ulNewPublicDataLen: new_public_data.len() as CK_ULONG,
            pNewPublicData: new_public_data.as_mut_ptr(),
            ulNewRandomLen: new_random_a.len() as CK_ULONG,
            pNewRandomA: new_random_a.as_mut_ptr(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_SKIPJACK_RELAYX,
            pParameter: &mut relayx as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SKIPJACK_RELAYX_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("skipjack_relayx")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::SkipjackRelayx(params) => {
                assert_eq!(params.old_wrapped_x, vec![0x91, 0x92]);
                assert_eq!(params.old_password, vec![0xA1, 0xA2, 0xA3]);
                assert_eq!(params.old_public_data, vec![0xB1]);
                assert_eq!(params.old_random_a, vec![0xC1, 0xC2]);
                assert_eq!(params.new_password, vec![0xD1, 0xD2, 0xD3, 0xD4]);
                assert_eq!(params.new_public_data, vec![0xE1, 0xE2]);
                assert_eq!(params.new_random_a, vec![0xF1, 0xF2, 0xF3]);
            }
            other => panic!("unexpected Skipjack relayx params: {other:?}"),
        }
    }

    #[test]
    fn reads_kip_parameter_struct_with_nested_mechanism() {
        const CKM_TEST_KIP: CK_MECHANISM_TYPE = 0x8000_1030;

        ensure_registry();

        let mut nested = CK_MECHANISM {
            mechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut seed = [0x44u8, 0x45, 0x46];
        let mut kip = CK_KIP_PARAMS {
            pMechanism: &mut nested,
            hKey: 99,
            pSeed: seed.as_mut_ptr(),
            ulSeedLen: seed.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_KIP,
            pParameter: &mut kip as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("kip")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Kip(params) => {
                assert_eq!(params.mechanism.mechanism_type, CkMechanismType::SHA256);
                assert!(params.mechanism.params.is_none());
                assert_eq!(params.key_handle, 99);
                assert_eq!(params.seed, vec![0x44, 0x45, 0x46]);
            }
            other => panic!("unexpected KIP params: {other:?}"),
        }
    }

    #[test]
    fn oaep_null_source_pointer_with_nonzero_len_stays_raw() {
        let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            mgf: 1,
            source: 1,
            pSourceData: std::ptr::null_mut(),
            ulSourceDataLen: 3,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType::RSA_PKCS_OAEP.0 as CK_MECHANISM_TYPE,
            pParameter: &mut oaep as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };

        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Raw(raw) => {
                assert_eq!(raw.data.len(), std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>());
            }
            other => panic!("expected raw params for invalid OAEP pointer, got {other:?}"),
        }
    }

    #[test]
    fn gcm_null_embedded_pointer_with_nonzero_len_stays_raw() {
        let mut aad = [0xAB, 0xCD];
        let mut gcm = CK_GCM_PARAMS {
            pIv: std::ptr::null_mut(),
            ulIvLen: 12,
            ulIvBits: 96,
            pAAD: aad.as_mut_ptr(),
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: 128,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
            pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        };

        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Raw(raw) => {
                assert_eq!(raw.data.len(), std::mem::size_of::<CK_GCM_PARAMS>());
            }
            other => panic!("expected raw params for invalid GCM pointer, got {other:?}"),
        }
    }

    #[test]
    fn gcm_generated_iv_buffer_is_preserved_and_written_back() {
        let mut iv = [0u8; 12];
        let mut gcm = CK_GCM_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: 0,
            ulIvBits: 96,
            pAAD: std::ptr::null_mut(),
            ulAADLen: 0,
            ulTagBits: 128,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
            pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        };

        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Gcm(GcmParams { iv, iv_bits, iv_buffer_len, aad, tag_bits }) => {
                assert!(iv.is_empty());
                assert_eq!(iv_bits, 96);
                assert_eq!(iv_buffer_len, 12);
                assert!(aad.is_empty());
                assert_eq!(tag_bits, 128);
            }
            other => panic!("unexpected generated-IV GCM params: {other:?}"),
        }

        let generated = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        unsafe {
            write_mechanism_output_params(
                &mut mechanism,
                &CkMechanismParams::Gcm(GcmParams {
                    iv: generated.clone(),
                    iv_bits: 96,
                    iv_buffer_len: 12,
                    aad: Vec::new(),
                    tag_bits: 128,
                }),
            );
        }

        assert_eq!(iv, generated.as_slice());
        assert_eq!(gcm.ulIvLen, 12);
        assert_eq!(gcm.ulIvBits, 96);
    }

    #[test]
    fn extract_params_reads_ck_ulong_bit_position() {
        const CKM_EXTRACT_KEY_FROM_KEY: CK_MECHANISM_TYPE = 0x0000_0365;

        let mut bit_position = 21 as CK_EXTRACT_PARAMS;
        let mechanism = CK_MECHANISM {
            mechanism: CKM_EXTRACT_KEY_FROM_KEY,
            pParameter: &mut bit_position as *mut CK_EXTRACT_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_EXTRACT_PARAMS>() as CK_ULONG,
        };

        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Extract(ExtractParams { bit_position }) => {
                assert_eq!(bit_position, 21);
            }
            other => panic!("unexpected extract params: {other:?}"),
        }
    }

    #[test]
    fn kmac_params_reads_key_length_and_customization_string() {
        const CKM_TEST_KMAC: CK_MECHANISM_TYPE = 0x8000_0001;

        let mut customization = *b"custom";
        let mut params = super::CkKmacParams {
            h_key: 0xCAFE,
            ul_mac_length: 64,
            p_customization_string: customization.as_mut_ptr() as CK_VOID_PTR,
            ul_customization_string_len: customization.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_KMAC,
            pParameter: &mut params as *mut super::CkKmacParams as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<super::CkKmacParams>() as CK_ULONG,
        };

        match unsafe { read_mechanism_with_shape(&mechanism, Some("kmac")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Kmac(KmacParams {
                key_handle,
                mac_length,
                customization_string,
            }) => {
                assert_eq!(key_handle, 0xCAFE);
                assert_eq!(mac_length, 64);
                assert_eq!(customization_string, b"custom");
            }
            other => panic!("unexpected KMAC params: {other:?}"),
        }
    }

    #[test]
    fn mu_gen_params_reads_key_tr_and_context() {
        const CKM_TEST_MU_GEN: CK_MECHANISM_TYPE = 0x8000_0002;

        let mut tr = *b"precomputed-tr";
        let mut context = *b"context";
        let mut params = super::CkMuGenParams {
            h_key: 0xA11CE,
            p_tr: tr.as_mut_ptr(),
            ul_tr_len: tr.len() as CK_ULONG,
            p_ctx: context.as_mut_ptr(),
            ul_ctx_len: context.len() as CK_ULONG,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_MU_GEN,
            pParameter: &mut params as *mut super::CkMuGenParams as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<super::CkMuGenParams>() as CK_ULONG,
        };

        match unsafe { read_mechanism_with_shape(&mechanism, Some("mu_gen")) }
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::MuGen(MuGenParams { key_handle, tr, context }) => {
                assert_eq!(key_handle, 0xA11CE);
                assert_eq!(tr, b"precomputed-tr");
                assert_eq!(context, b"context");
            }
            other => panic!("unexpected mu-gen params: {other:?}"),
        }
    }

    #[test]
    fn sp800_108_kdf_null_data_params_with_nonzero_count_stays_raw() {
        const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
        const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

        let mut params = CK_SP800_108_KDF_PARAMS {
            prfType: CKM_SHA256_HMAC,
            ulNumberOfDataParams: 1,
            pDataParams: std::ptr::null_mut(),
            ulAdditionalDerivedKeys: 0,
            pAdditionalDerivedKeys: std::ptr::null_mut(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_SP800_108_COUNTER_KDF,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
        };

        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Raw(raw) => {
                assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
            }
            other => panic!("unexpected SP800-108 params: {other:?}"),
        }
    }

    #[test]
    fn sp800_108_kdf_null_additional_keys_with_nonzero_count_stays_raw() {
        const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
        const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

        let mut params = CK_SP800_108_KDF_PARAMS {
            prfType: CKM_SHA256_HMAC,
            ulNumberOfDataParams: 0,
            pDataParams: std::ptr::null_mut(),
            ulAdditionalDerivedKeys: 1,
            pAdditionalDerivedKeys: std::ptr::null_mut(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_SP800_108_COUNTER_KDF,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
        };

        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Raw(raw) => {
                assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
            }
            other => panic!("unexpected SP800-108 params: {other:?}"),
        }
    }

    #[test]
    fn sp800_108_kdf_null_data_value_with_nonzero_len_stays_raw() {
        const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
        const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;
        const CK_SP800_108_BYTE_ARRAY: CK_PRF_DATA_TYPE = 4;

        let mut data_params = [CK_PRF_DATA_PARAM {
            type_: CK_SP800_108_BYTE_ARRAY,
            pValue: std::ptr::null_mut(),
            ulValueLen: 4,
        }];
        let mut params = CK_SP800_108_KDF_PARAMS {
            prfType: CKM_SHA256_HMAC,
            ulNumberOfDataParams: data_params.len() as CK_ULONG,
            pDataParams: data_params.as_mut_ptr(),
            ulAdditionalDerivedKeys: 0,
            pAdditionalDerivedKeys: std::ptr::null_mut(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_SP800_108_COUNTER_KDF,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
        };

        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Raw(raw) => {
                assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
            }
            other => panic!("unexpected SP800-108 params: {other:?}"),
        }
    }

    #[test]
    fn sp800_108_kdf_null_template_with_nonzero_attr_count_stays_raw() {
        const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
        const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

        let mut output_handle = 0 as CK_OBJECT_HANDLE;
        let mut additional_keys = [CK_DERIVED_KEY {
            pTemplate: std::ptr::null_mut(),
            ulAttributeCount: 1,
            phKey: &mut output_handle,
        }];
        let mut params = CK_SP800_108_KDF_PARAMS {
            prfType: CKM_SHA256_HMAC,
            ulNumberOfDataParams: 0,
            pDataParams: std::ptr::null_mut(),
            ulAdditionalDerivedKeys: additional_keys.len() as CK_ULONG,
            pAdditionalDerivedKeys: additional_keys.as_mut_ptr(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_SP800_108_COUNTER_KDF,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
        };

        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Raw(raw) => {
                assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
            }
            other => panic!("unexpected SP800-108 params: {other:?}"),
        }
    }

    #[test]
    fn sp800_108_kdf_null_output_handle_stays_raw() {
        const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
        const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

        let mut additional_keys = [CK_DERIVED_KEY {
            pTemplate: std::ptr::null_mut(),
            ulAttributeCount: 0,
            phKey: std::ptr::null_mut(),
        }];
        let mut params = CK_SP800_108_KDF_PARAMS {
            prfType: CKM_SHA256_HMAC,
            ulNumberOfDataParams: 0,
            pDataParams: std::ptr::null_mut(),
            ulAdditionalDerivedKeys: additional_keys.len() as CK_ULONG,
            pAdditionalDerivedKeys: additional_keys.as_mut_ptr(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_SP800_108_COUNTER_KDF,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
        };

        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Raw(raw) => {
                assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
            }
            other => panic!("unexpected SP800-108 params: {other:?}"),
        }
    }

    #[test]
    fn sp800_108_feedback_null_iv_with_nonzero_len_stays_raw() {
        const CKM_SP800_108_FEEDBACK_KDF: CK_MECHANISM_TYPE = 0x0000_03AD;
        const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

        let mut params = CK_SP800_108_FEEDBACK_KDF_PARAMS {
            prfType: CKM_SHA256_HMAC,
            ulNumberOfDataParams: 0,
            pDataParams: std::ptr::null_mut(),
            ulIVLen: 16,
            pIV: std::ptr::null_mut(),
            ulAdditionalDerivedKeys: 0,
            pAdditionalDerivedKeys: std::ptr::null_mut(),
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_SP800_108_FEEDBACK_KDF,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>() as CK_ULONG,
        };

        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Raw(raw) => {
                assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>());
            }
            other => panic!("unexpected SP800-108 feedback params: {other:?}"),
        }
    }

    #[test]
    fn sp800_108_feedback_reads_additional_keys_and_writes_handles_back() {
        const CKM_SP800_108_FEEDBACK_KDF: CK_MECHANISM_TYPE = 0x0000_03AD;
        const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

        let mut label = *b"extra";
        let mut value_len = 32 as CK_ULONG;
        let mut template = [
            CK_ATTRIBUTE {
                type_: CkAttributeType::LABEL.0,
                pValue: label.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: label.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CkAttributeType::VALUE_LEN.0,
                pValue: &mut value_len as *mut _ as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
        ];
        let mut additional_key_handle = 0 as CK_OBJECT_HANDLE;
        let mut additional_keys = [CK_DERIVED_KEY {
            pTemplate: template.as_mut_ptr(),
            ulAttributeCount: template.len() as CK_ULONG,
            phKey: &mut additional_key_handle,
        }];
        let mut iv = [0xA5u8; 16];
        let mut params = CK_SP800_108_FEEDBACK_KDF_PARAMS {
            prfType: CKM_SHA256_HMAC,
            ulNumberOfDataParams: 0,
            pDataParams: std::ptr::null_mut(),
            ulIVLen: iv.len() as CK_ULONG,
            pIV: iv.as_mut_ptr(),
            ulAdditionalDerivedKeys: additional_keys.len() as CK_ULONG,
            pAdditionalDerivedKeys: additional_keys.as_mut_ptr(),
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_SP800_108_FEEDBACK_KDF,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>() as CK_ULONG,
        };

        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Sp800108FeedbackKdf(params) => {
                assert_eq!(params.prf_type, CKM_SHA256_HMAC);
                assert_eq!(params.iv, vec![0xA5; 16]);
                assert_eq!(params.additional_derived_keys.len(), 1);
                let derived = &params.additional_derived_keys[0];
                assert_eq!(derived.key_handle, 0);
                assert_eq!(derived.template.len(), 2);
                assert_eq!(
                    derived.template[0].value,
                    Some(CkAttributeValue::Bytes(b"extra".to_vec()))
                );
                assert_eq!(derived.template[1].value, Some(CkAttributeValue::Ulong(32)));
            }
            other => panic!("unexpected SP800-108 feedback params: {other:?}"),
        }

        unsafe {
            write_mechanism_output_params(
                &mut mechanism,
                &CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                    prf_type: CKM_SHA256_HMAC,
                    data_params: Vec::new(),
                    iv: vec![0xA5; 16],
                    additional_derived_keys: vec![Sp800108DerivedKey {
                        template: Vec::new(),
                        key_handle: 0xCAFE,
                    }],
                }),
            );
        }

        assert_eq!(additional_key_handle, 0xCAFE);
    }
}

#[cfg(test)]
mod message_parameter_tests {
    use super::{message_parameter_roundtrip_spec, try_read_message_parameter};
    use cryptoki_sys::*;
    use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;
    use pkcs11_proxy_ng_types::CkRv;

    #[test]
    fn null_zero_len_message_parameter_is_absent() {
        let param =
            unsafe { try_read_message_parameter(std::ptr::null(), 0) }.expect("valid null/zero");

        assert!(param.is_none());
    }

    #[test]
    fn null_nonzero_len_message_parameter_is_rejected() {
        let err = unsafe { try_read_message_parameter(std::ptr::null(), 1) }.unwrap_err();

        assert_eq!(err, CkRv::ARGUMENTS_BAD);
    }

    #[test]
    fn oversized_message_parameter_is_rejected_before_reading() {
        let mut byte = 0u8;
        let err = unsafe {
            try_read_message_parameter(
                &mut byte as *mut _ as *const _,
                (super::MAX_MECHANISM_PARAM_LEN + 1) as CK_ULONG,
            )
        }
        .unwrap_err();

        assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
    }

    #[test]
    fn raw_message_parameter_preserves_small_unknown_shape() {
        let bytes = [0xA5, 0x5A, 0x01];
        let param = unsafe {
            try_read_message_parameter(bytes.as_ptr() as *const _, bytes.len() as CK_ULONG)
        }
        .expect("small raw parameter")
        .expect("message parameter should be present");

        assert_eq!(param, MessageParameter::Raw(bytes.to_vec()));
    }

    #[test]
    fn message_roundtrip_spec_rejects_null_nonzero_len() {
        let err = unsafe { message_parameter_roundtrip_spec(std::ptr::null_mut(), 1) }.unwrap_err();

        assert_eq!(err, CkRv::ARGUMENTS_BAD);
    }

    #[test]
    fn message_roundtrip_spec_rejects_oversized_len_before_reading() {
        let mut byte = 0u8;
        let err = unsafe {
            message_parameter_roundtrip_spec(
                &mut byte as *mut _ as *mut _,
                (super::MAX_MECHANISM_PARAM_LEN + 1) as CK_ULONG,
            )
        }
        .unwrap_err();

        assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
    }

    #[test]
    fn write_mechanism_output_params_writes_tls12_pversion() {
        // Verify that the shim's writeback function fills in the
        // CK_VERSION buffer pointed at by
        // CK_TLS12_MASTER_KEY_DERIVE_PARAMS.pVersion when the backend
        // returns a Tls12MasterKeyDerive params variant. Without this,
        // applications calling C_DeriveKey on a remote HSM would never
        // learn the negotiated TLS version.
        use pkcs11_proxy_ng_types::{
            CkMechanismParams, CkMechanismType, SslRandomData, Tls12MasterKeyDeriveParams,
        };

        let mut version = CK_VERSION { major: 0, minor: 0 };
        let mut params = CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
            RandomInfo: CK_SSL3_RANDOM_DATA {
                pClientRandom: std::ptr::null_mut(),
                ulClientRandomLen: 0,
                pServerRandom: std::ptr::null_mut(),
                ulServerRandomLen: 0,
            },
            pVersion: &mut version,
            prfHashMechanism: CkMechanismType::SHA256.0,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CkMechanismType::TLS12_MASTER_KEY_DERIVE.0,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
        };

        let mech_out = CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
            random_info: SslRandomData { client_random: vec![], server_random: vec![] },
            version_major: 3,
            version_minor: 3, // TLS 1.2
            prf_hash_mechanism: CkMechanismType::SHA256.0,
        });

        unsafe {
            super::write_mechanism_output_params(&mut mechanism, &mech_out);
        }

        assert_eq!(version.major, 3);
        assert_eq!(version.minor, 3);
    }

    #[test]
    fn write_mechanism_output_params_tls12_safe_when_pversion_null() {
        // The TLS12 writeback path is a no-op when pVersion is NULL —
        // matching the spec which says the caller may pass NULL to
        // suppress version output.  Guard against UB.
        use pkcs11_proxy_ng_types::{
            CkMechanismParams, CkMechanismType, SslRandomData, Tls12MasterKeyDeriveParams,
        };

        let mut params = CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
            RandomInfo: CK_SSL3_RANDOM_DATA {
                pClientRandom: std::ptr::null_mut(),
                ulClientRandomLen: 0,
                pServerRandom: std::ptr::null_mut(),
                ulServerRandomLen: 0,
            },
            pVersion: std::ptr::null_mut(),
            prfHashMechanism: CkMechanismType::SHA256.0,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CkMechanismType::TLS12_MASTER_KEY_DERIVE.0,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
        };

        let mech_out = CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
            random_info: SslRandomData { client_random: vec![], server_random: vec![] },
            version_major: 3,
            version_minor: 3,
            prf_hash_mechanism: CkMechanismType::SHA256.0,
        });

        unsafe {
            super::write_mechanism_output_params(&mut mechanism, &mech_out);
        }
        // Did not crash, did not write through NULL.
    }

    #[test]
    fn wtls_master_key_derive_reads_version_byte_and_writes_it_back() {
        use pkcs11_proxy_ng_types::{
            CkMechanismParams, CkMechanismType, WtlsMasterKeyDeriveParams, WtlsRandomData,
        };

        const CKM_WTLS_MASTER_KEY_DERIVE: CK_MECHANISM_TYPE = 0x0000_03D1;

        let mut client_random = [0xA1u8, 0xA2, 0xA3];
        let mut server_random = [0xB1u8, 0xB2];
        let mut version = 1u8;
        let mut params = CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
            DigestMechanism: CkMechanismType::SHA256.0,
            RandomInfo: CK_WTLS_RANDOM_DATA {
                pClientRandom: client_random.as_mut_ptr(),
                ulClientRandomLen: client_random.len() as CK_ULONG,
                pServerRandom: server_random.as_mut_ptr(),
                ulServerRandomLen: server_random.len() as CK_ULONG,
            },
            pVersion: &mut version,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_WTLS_MASTER_KEY_DERIVE,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
        };

        match unsafe {
            super::read_mechanism_with_shape(&mechanism, Some("wtls_master_key_derive"))
        }
        .params
        .expect("wtls params")
        {
            CkMechanismParams::WtlsMasterKeyDerive(params) => {
                assert_eq!(params.digest_mechanism, CkMechanismType::SHA256.0);
                assert_eq!(params.random_info.client_random, client_random);
                assert_eq!(params.random_info.server_random, server_random);
                assert_eq!(params.version, 1);
            }
            other => panic!("unexpected WTLS params: {other:?}"),
        }

        let mech_out = CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
            digest_mechanism: CkMechanismType::SHA256.0,
            random_info: WtlsRandomData {
                client_random: client_random.to_vec(),
                server_random: server_random.to_vec(),
            },
            version: 2,
        });
        unsafe {
            super::write_mechanism_output_params(&mut mechanism, &mech_out);
        }

        assert_eq!(version, 2);
    }

    #[test]
    fn wtls_key_mat_reads_caller_stack_params_and_writes_outputs_back() {
        use pkcs11_proxy_ng_types::{
            CkMechanismParams, CkMechanismType, WtlsKeyMatParams, WtlsRandomData,
        };

        const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: CK_MECHANISM_TYPE = 0x0000_03D4;

        let mut client_random = [0xC1u8, 0xC2, 0xC3];
        let mut server_random = [0xD1u8, 0xD2];
        let mut iv = [0u8; 4];
        let mut key_mat_out = CK_WTLS_KEY_MAT_OUT { hMacSecret: 0, hKey: 0, pIV: iv.as_mut_ptr() };
        let mut params = CK_WTLS_KEY_MAT_PARAMS {
            DigestMechanism: CkMechanismType::SHA256.0,
            ulMacSizeInBits: 160,
            ulKeySizeInBits: 128,
            ulIVSizeInBits: 32,
            ulSequenceNumber: 7,
            bIsExport: CK_TRUE,
            RandomInfo: CK_WTLS_RANDOM_DATA {
                pClientRandom: client_random.as_mut_ptr(),
                ulClientRandomLen: client_random.len() as CK_ULONG,
                pServerRandom: server_random.as_mut_ptr(),
                ulServerRandomLen: server_random.len() as CK_ULONG,
            },
            pReturnedKeyMaterial: &mut key_mat_out,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_WTLS_KEY_MAT_PARAMS>() as CK_ULONG,
        };

        match unsafe { super::read_mechanism_with_shape(&mechanism, Some("wtls_key_mat")) }
            .params
            .expect("wtls key material params")
        {
            CkMechanismParams::WtlsKeyMat(params) => {
                assert_eq!(params.digest_mechanism, CkMechanismType::SHA256.0);
                assert_eq!(params.mac_size_bits, 160);
                assert_eq!(params.key_size_bits, 128);
                assert_eq!(params.iv_size_bits, 32);
                assert_eq!(params.sequence_number, 7);
                assert!(params.is_export);
                assert_eq!(params.random_info.client_random, client_random);
                assert_eq!(params.random_info.server_random, server_random);
                assert_eq!(params.mac_secret_handle, 0);
                assert_eq!(params.key_handle, 0);
                assert_eq!(params.iv, [0u8; 4]);
            }
            other => panic!("unexpected WTLS key material params: {other:?}"),
        }

        let mech_out = CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
            digest_mechanism: CkMechanismType::SHA256.0,
            mac_size_bits: 160,
            key_size_bits: 128,
            iv_size_bits: 32,
            sequence_number: 7,
            is_export: true,
            random_info: WtlsRandomData {
                client_random: client_random.to_vec(),
                server_random: server_random.to_vec(),
            },
            mac_secret_handle: 101,
            key_handle: 202,
            iv: vec![0xA1, 0xA2, 0xA3, 0xA4],
        });
        unsafe {
            super::write_mechanism_output_params(&mut mechanism, &mech_out);
        }

        assert_eq!(key_mat_out.hMacSecret, 101);
        assert_eq!(key_mat_out.hKey, 202);
        assert_eq!(iv, [0xA1, 0xA2, 0xA3, 0xA4]);
    }

    #[test]
    fn ssl3_key_mat_reads_caller_stack_params_and_writes_outputs_back() {
        use pkcs11_proxy_ng_types::{
            CkMechanismParams, CkMechanismType, Ssl3KeyMatParams, SslRandomData,
        };

        const CKM_TLS12_KEY_AND_MAC_DERIVE: CK_MECHANISM_TYPE = 0x0000_03E1;

        let mut client_random = [0x11u8, 0x12, 0x13];
        let mut server_random = [0x21u8, 0x22];
        let mut client_iv = [0u8; 4];
        let mut server_iv = [0u8; 4];
        let mut key_mat_out = CK_SSL3_KEY_MAT_OUT {
            hClientMacSecret: 0,
            hServerMacSecret: 0,
            hClientKey: 0,
            hServerKey: 0,
            pIVClient: client_iv.as_mut_ptr(),
            pIVServer: server_iv.as_mut_ptr(),
        };
        let mut params = CK_TLS12_KEY_MAT_PARAMS {
            ulMacSizeInBits: 160,
            ulKeySizeInBits: 128,
            ulIVSizeInBits: 32,
            bIsExport: CK_FALSE,
            RandomInfo: CK_SSL3_RANDOM_DATA {
                pClientRandom: client_random.as_mut_ptr(),
                ulClientRandomLen: client_random.len() as CK_ULONG,
                pServerRandom: server_random.as_mut_ptr(),
                ulServerRandomLen: server_random.len() as CK_ULONG,
            },
            pReturnedKeyMaterial: &mut key_mat_out,
            prfHashMechanism: CkMechanismType::SHA256.0,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_TLS12_KEY_AND_MAC_DERIVE,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_TLS12_KEY_MAT_PARAMS>() as CK_ULONG,
        };

        match unsafe { super::read_mechanism_with_shape(&mechanism, Some("ssl3_key_mat")) }
            .params
            .expect("ssl3/tls key material params")
        {
            CkMechanismParams::Ssl3KeyMat(params) => {
                assert_eq!(params.mac_size_bits, 160);
                assert_eq!(params.key_size_bits, 128);
                assert_eq!(params.iv_size_bits, 32);
                assert!(!params.is_export);
                assert_eq!(params.random_info.client_random, client_random);
                assert_eq!(params.random_info.server_random, server_random);
                assert_eq!(params.prf_hash_mechanism, CkMechanismType::SHA256.0);
                assert_eq!(params.client_mac_secret_handle, 0);
                assert_eq!(params.server_mac_secret_handle, 0);
                assert_eq!(params.client_key_handle, 0);
                assert_eq!(params.server_key_handle, 0);
                assert_eq!(params.client_iv, [0u8; 4]);
                assert_eq!(params.server_iv, [0u8; 4]);
            }
            other => panic!("unexpected SSL3/TLS key material params: {other:?}"),
        }

        let mech_out = CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
            mac_size_bits: 160,
            key_size_bits: 128,
            iv_size_bits: 32,
            is_export: false,
            random_info: SslRandomData {
                client_random: client_random.to_vec(),
                server_random: server_random.to_vec(),
            },
            prf_hash_mechanism: CkMechanismType::SHA256.0,
            client_mac_secret_handle: 101,
            server_mac_secret_handle: 102,
            client_key_handle: 201,
            server_key_handle: 202,
            client_iv: vec![0xA1, 0xA2, 0xA3, 0xA4],
            server_iv: vec![0xB1, 0xB2, 0xB3, 0xB4],
        });
        unsafe {
            super::write_mechanism_output_params(&mut mechanism, &mech_out);
        }

        assert_eq!(key_mat_out.hClientMacSecret, 101);
        assert_eq!(key_mat_out.hServerMacSecret, 102);
        assert_eq!(key_mat_out.hClientKey, 201);
        assert_eq!(key_mat_out.hServerKey, 202);
        assert_eq!(client_iv, [0xA1, 0xA2, 0xA3, 0xA4]);
        assert_eq!(server_iv, [0xB1, 0xB2, 0xB3, 0xB4]);
    }
}

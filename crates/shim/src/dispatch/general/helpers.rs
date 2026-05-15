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
    let mech_type = CkMechanismType(c_mech.mechanism);

    if c_mech.pParameter.is_null() || c_mech.ulParameterLen == 0 {
        return CkMechanism { mechanism_type: mech_type, params: None };
    }

    let param_ptr = c_mech.pParameter;
    let param_len = c_mech.ulParameterLen as usize;

    let shape = crate::state::mechanism_registry().param_shape(c_mech.mechanism);

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
                }))
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

        Some("sp800_108_kdf") => {
            if param_len < std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_SP800_108_KDF_PARAMS) };
                let mut data_params = Vec::new();
                if !p.pDataParams.is_null() && p.ulNumberOfDataParams > 0 {
                    let params_slice = unsafe {
                        std::slice::from_raw_parts(p.pDataParams, p.ulNumberOfDataParams as usize)
                    };
                    for dp in params_slice {
                        let value = if dp.pValue.is_null() || dp.ulValueLen == 0 {
                            Vec::new()
                        } else {
                            unsafe {
                                std::slice::from_raw_parts(
                                    dp.pValue as *const u8,
                                    dp.ulValueLen as usize,
                                )
                            }
                            .to_vec()
                        };
                        data_params.push(PrfDataParam { type_: dp.type_ as u64, value });
                    }
                }
                Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                    prf_type: p.prfType as u64,
                    data_params,
                }))
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

pub(crate) unsafe fn write_mechanism_output_params(
    p_mechanism: CK_MECHANISM_PTR,
    params: &CkMechanismParams,
) {
    if p_mechanism.is_null() {
        return;
    }

    let mechanism = unsafe { &mut *p_mechanism };
    if let CkMechanismParams::Gcm(gcm_out) = params {
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
    use super::{read_mechanism, write_mechanism_output_params};
    use cryptoki_sys::*;
    use pkcs11_proxy_ng_types::{
        CkMechanismParams, CkMechanismType, GcmParams, MechanismRegistry, RsaPkcsOaepParams,
        RsaPkcsPssParams,
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
}

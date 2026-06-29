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
        let __result = crate::state::runtime().block_on(async {
            // Take a cheap clone of the shared client and drop the
            // mutex guard before the RPC. `Pkcs11Client` wraps a tonic
            // `Channel` (Arc'd, HTTP/2 multiplexed), so concurrent
            // shim calls now share the connection instead of
            // serializing on the mutex. The mutex remains as the
            // swap point for reconnect (state::ensure_client_connected
            // overwrites the stored client on reconnect; in-flight
            // RPCs keep using their pre-swap clones).
            let mut $client = crate::state::client().lock().await.clone();
            $call.await
        });
        // FOLLOWUP-dns-reresolve: reconnect-on-transport-failure is driven
        // by the client crate's transport-failure hook (registered in
        // c_initialize), which fires ONLY when a gRPC transport `Status` is
        // mapped to a CK_RV — never on a backend `ck_rv`. The next call then
        // rebuilds the channel via `Endpoint::from_shared`, re-resolving the
        // hostname, letting a shim follow a daemon whose DNS A-record changed
        // (k8s rolling deploy / blue-green). We deliberately do NOT key the
        // reconnect off the returned CK_RV here: kryoptic uses
        // CKR_DEVICE_ERROR (OpenSSL catch-all) and CKR_GENERAL_ERROR
        // (internal catch-all) as ordinary results, so doing so churned the
        // channel on every routine backend error.
        __result
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

/// Pointer-class-faithful input reader (ADR-0010 Scope 2). Unlike
/// `read_input_slice`, NULL is preserved as NULL (with the caller's claimed
/// length) and unmaterializable lengths become a value, not a panic, so the
/// dispatch layer can return the documented stable RV (CKR_ARGUMENTS_BAD)
/// instead of GENERAL_ERROR.
#[derive(Debug)]
pub(crate) enum InputBuf<'a> {
    Bytes(&'a [u8]),
    Null {
        len: u64,
    },
    TooLarge {
        #[allow(dead_code)]
        len: u64,
    },
}

/// Classify a raw C input-pointer pair into a typed `InputBuf`.
///
/// # Safety
///
/// When `ptr` is non-null, it must point to a valid, readable buffer of at
/// least `len` bytes (as required by PKCS#11 semantics for input parameters).
/// The returned `InputBuf::Bytes` slice borrows from that memory and must not
/// outlive it. When `ptr` is null, no memory is accessed regardless of `len`.
pub(crate) unsafe fn classify_input<'a>(ptr: *const u8, len: CK_ULONG) -> InputBuf<'a> {
    if ptr.is_null() {
        return InputBuf::Null { len: len as u64 };
    }
    let count = len as usize;
    match count.checked_mul(std::mem::size_of::<u8>()) {
        Some(n) if n <= MAX_SERIALIZABLE_BYTES => {
            InputBuf::Bytes(unsafe { std::slice::from_raw_parts(ptr, count) })
        }
        _ => InputBuf::TooLarge { len: len as u64 },
    }
}

/// Convert a classified input to the backend-facing type. TooLarge is the
/// transport-impossible class: documented stable RV (ADR-0010 Limits).
pub(crate) fn input_buf_to_ck_in_buf(buf: InputBuf<'_>) -> Result<CkInBuf<'_>, CkRv> {
    match buf {
        InputBuf::Bytes(b) => Ok(CkInBuf::Bytes(b)),
        InputBuf::Null { len } => Ok(CkInBuf::Null { len }),
        InputBuf::TooLarge { .. } => Err(CkRv::ARGUMENTS_BAD),
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

    if (ul_parameter_len as usize) > MAX_MECHANISM_PARAM_STRUCT_LEN {
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

/// Maximum mechanism **parameter-struct** byte length.  No standard PKCS#11
/// mechanism parameter struct exceeds a few hundred bytes; 64 KiB is
/// extremely generous.  This constant bounds `ulParameterLen` of a mechanism
/// or message parameter **struct** only — not embedded variable-length data
/// fields (seeds, labels, AADs, IVs, etc.) which are data, not structs, and
/// are bounded by `MAX_SERIALIZABLE_BYTES`.
const MAX_MECHANISM_PARAM_STRUCT_LEN: usize = 65_536;

/// Return `true` when an embedded mechanism-parameter **data** payload (seed,
/// label, AAD, IV, OtherInfo, public-data, password, random, …) has a length
/// that can be materialized and serialized over gRPC.
///
/// These fields are data, not structs; they must not be capped by the much
/// smaller `MAX_MECHANISM_PARAM_STRUCT_LEN`.  An unmaterializable length
/// (> 512 MiB) causes the caller to fall back to the raw-bytes path, returning
/// `MECHANISM_PARAM_INVALID` or a raw forwarding blob instead of calling
/// `from_raw_parts` with an absurd size.  (ADR-0010 transport limit.)
#[inline]
fn embedded_payload_len_ok(len: CK_ULONG) -> bool {
    (len as usize) <= MAX_SERIALIZABLE_BYTES
}

// LLP64 (Windows x64): the app passes these param structs laid out per the
// `#pragma pack(1)` PKCS#11 headers, so the shim's mirror must be packed there
// to read the fields at the right offsets. Natural alignment is correct on
// LP64/ILP32 (ADR-0011 Bucket 2). Fields are read by value (never `&field`),
// so packed access stays E0793-safe.
#[repr(C)]
#[cfg_attr(windows, repr(packed))]
struct CkKmacParams {
    h_key: CK_OBJECT_HANDLE,
    ul_mac_length: CK_ULONG,
    p_customization_string: CK_VOID_PTR,
    ul_customization_string_len: CK_ULONG,
}

#[repr(C)]
#[cfg_attr(windows, repr(packed))] // LLP64: match `#pragma pack(1)` (ADR-0011 Bucket 2)
struct CkMuGenParams {
    h_key: CK_OBJECT_HANDLE,
    p_tr: CK_BYTE_PTR,
    ul_tr_len: CK_ULONG,
    p_ctx: CK_BYTE_PTR,
    ul_ctx_len: CK_ULONG,
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
pub(crate) unsafe fn validate_mechanism(p_mechanism: *const CK_MECHANISM) -> CK_RV {
    let c_mech = unsafe { &*p_mechanism };
    let has_params = !c_mech.pParameter.is_null() && c_mech.ulParameterLen > 0;
    // Reject absurd parameter lengths before we attempt to dereference
    // the parameter buffer.  This prevents undefined behavior when the
    // caller passes a small buffer with an enormous ulParameterLen.
    if has_params && (c_mech.ulParameterLen as usize) > MAX_MECHANISM_PARAM_STRUCT_LEN {
        return rv_err(CkRv::MECHANISM_PARAM_INVALID);
    }
    match crate::state::mechanism_registry().check_operation(c_mech.mechanism.into(), has_params) {
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
    // Hold the Arc until after we have copied the shape string out — the
    // returned `&str` borrows from the Arc, so dropping it before the call
    // below would leave a dangling reference.
    let registry = crate::state::mechanism_registry();
    let shape = registry.param_shape(c_mech.mechanism.into());
    unsafe { read_mechanism_with_shape(c_mech, shape) }
}

pub(crate) unsafe fn read_wrap_key_mechanism(p_mechanism: *const CK_MECHANISM) -> CkMechanism {
    let c_mech = unsafe { &*p_mechanism };
    let param_len = c_mech.ulParameterLen as usize;
    let registry = crate::state::mechanism_registry();
    let shape = match c_mech.mechanism {
        CKM_AES_GCM if param_len == std::mem::size_of::<CK_GCM_WRAP_PARAMS>() => Some("gcm_wrap"),
        CKM_AES_CCM if param_len == std::mem::size_of::<CK_CCM_WRAP_PARAMS>() => Some("ccm_wrap"),
        _ => registry.param_shape(c_mech.mechanism.into()),
    };
    unsafe { read_mechanism_with_shape(c_mech, shape) }
}

unsafe fn read_mechanism_with_shape(c_mech: &CK_MECHANISM, shape: Option<&str>) -> CkMechanism {
    let mech_type = CkMechanismType(c_mech.mechanism as u64);

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
                    hash_alg: CkMechanismType(pss.hashAlg as u64),
                    mgf: pss.mgf as u64,
                    salt_len: pss.sLen as u64,
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
                if missing_embedded_pointer(oaep.pSourceData, oaep.ulSourceDataLen)
                    || !embedded_payload_len_ok(oaep.ulSourceDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let source_data = if oaep.pSourceData.is_null() || oaep.ulSourceDataLen == 0 {
                        Vec::new()
                    } else {
                        // Safety: pSourceData is non-null, ulSourceDataLen > 0,
                        // and ulSourceDataLen <= MAX_SERIALIZABLE_BYTES (guard above).
                        unsafe {
                            std::slice::from_raw_parts(
                                oaep.pSourceData as *const u8,
                                oaep.ulSourceDataLen as usize,
                            )
                        }
                        .to_vec()
                    };
                    Some(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
                        hash_alg: CkMechanismType(oaep.hashAlg as u64),
                        mgf: oaep.mgf as u64,
                        source: oaep.source as u64,
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
                    || !embedded_payload_len_ok(gcm.ulIvLen)
                    || !embedded_payload_len_ok(gcm.ulAADLen)
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
                        iv_bits: gcm.ulIvBits as u64,
                        iv_buffer_len: gcm_iv_buffer_len(gcm),
                        aad,
                        tag_bits: gcm.ulTagBits as u64,
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
                if missing_embedded_pointer(ccm.pNonce, ccm.ulNonceLen)
                    || missing_embedded_pointer(ccm.pAAD, ccm.ulAADLen)
                    || !embedded_payload_len_ok(ccm.ulNonceLen)
                    || !embedded_payload_len_ok(ccm.ulAADLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let nonce = if ccm.pNonce.is_null() || ccm.ulNonceLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(ccm.pNonce, ccm.ulNonceLen as usize) }
                            .to_vec()
                    };
                    let aad = if ccm.pAAD.is_null() || ccm.ulAADLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(ccm.pAAD, ccm.ulAADLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::Ccm(CcmParams {
                        data_len: ccm.ulDataLen as u64,
                        nonce,
                        aad,
                        mac_len: ccm.ulMACLen as u64,
                    }))
                }
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
                if missing_embedded_pointer(ecdh.pSharedData, ecdh.ulSharedDataLen)
                    || missing_embedded_pointer(ecdh.pPublicData, ecdh.ulPublicDataLen)
                    || !embedded_payload_len_ok(ecdh.ulSharedDataLen)
                    || !embedded_payload_len_ok(ecdh.ulPublicDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let shared_data = if ecdh.pSharedData.is_null() || ecdh.ulSharedDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(
                                ecdh.pSharedData,
                                ecdh.ulSharedDataLen as usize,
                            )
                        }
                        .to_vec()
                    };
                    let public_data = if ecdh.pPublicData.is_null() || ecdh.ulPublicDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(
                                ecdh.pPublicData,
                                ecdh.ulPublicDataLen as usize,
                            )
                        }
                        .to_vec()
                    };
                    Some(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
                        kdf: ecdh.kdf as u64,
                        shared_data,
                        public_data,
                    }))
                }
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
                    counter_bits: ctr.ulCounterBits as u64,
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
                    counter_bits: ctr.ulCounterBits as u64,
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
                if missing_embedded_pointer(hkdf.pSalt, hkdf.ulSaltLen)
                    || missing_embedded_pointer(hkdf.pInfo, hkdf.ulInfoLen)
                    || !embedded_payload_len_ok(hkdf.ulSaltLen)
                    || !embedded_payload_len_ok(hkdf.ulInfoLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
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
                        prf_hash_mechanism: hkdf.prfHashMechanism as u64,
                        salt_type: hkdf.ulSaltType as u64,
                        salt,
                        salt_key_handle: hkdf.hSaltKey as u64,
                        info,
                    }))
                }
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
                if missing_embedded_pointer(eddsa.pContextData, eddsa.ulContextDataLen)
                    || !embedded_payload_len_ok(eddsa.ulContextDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let context_data =
                        if eddsa.pContextData.is_null() || eddsa.ulContextDataLen == 0 {
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
        }

        Some("chacha20") => {
            if param_len < std::mem::size_of::<CK_CHACHA20_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                // Safety: pParameter points to a valid CK_CHACHA20_PARAMS.
                let ch = unsafe { &*(param_ptr as *const CK_CHACHA20_PARAMS) };
                let bc_bytes = (ch.blockCounterBits as usize).div_ceil(8);
                let nonce_bytes = (ch.ulNonceBits as usize).div_ceil(8);
                // `>=`, not `>`: on a 32-bit CK_ULONG target div_ceil(u32::MAX, 8)
                // equals MAX_SERIALIZABLE_BYTES exactly, so `>` is unreachable and
                // the guard would wild-read at the boundary (i686 SIGSEGV).
                if bc_bytes >= MAX_SERIALIZABLE_BYTES || nonce_bytes >= MAX_SERIALIZABLE_BYTES {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let block_counter = if ch.pBlockCounter.is_null() {
                        Vec::new()
                    } else if bc_bytes > 0 {
                        // Safety: pBlockCounter is non-null, bc_bytes <= MAX_SERIALIZABLE_BYTES.
                        unsafe { std::slice::from_raw_parts(ch.pBlockCounter, bc_bytes) }.to_vec()
                    } else {
                        Vec::new()
                    };
                    let nonce = if ch.pNonce.is_null() || ch.ulNonceBits == 0 {
                        Vec::new()
                    } else {
                        // Safety: pNonce is non-null, nonce_bytes <= MAX_SERIALIZABLE_BYTES.
                        unsafe { std::slice::from_raw_parts(ch.pNonce, nonce_bytes) }.to_vec()
                    };
                    Some(CkMechanismParams::ChaCha20(ChaCha20Params {
                        block_counter,
                        block_counter_bits: ch.blockCounterBits as u64,
                        nonce,
                        nonce_bits: ch.ulNonceBits as u64,
                    }))
                }
            }
        }

        Some("salsa20") => {
            if param_len < std::mem::size_of::<CK_SALSA20_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let salsa = unsafe { &*(param_ptr as *const CK_SALSA20_PARAMS) };
                let nonce_bytes = (salsa.ulNonceBits as usize).div_ceil(8);
                // `>=`, not `>`: on a 32-bit CK_ULONG target div_ceil(u32::MAX, 8)
                // equals MAX_SERIALIZABLE_BYTES exactly, so `>` is unreachable and
                // the guard would wild-read at the boundary (i686 SIGSEGV).
                if salsa.pBlockCounter.is_null()
                    || missing_embedded_pointer(salsa.pNonce, salsa.ulNonceBits)
                    || nonce_bytes >= MAX_SERIALIZABLE_BYTES
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let block_counter =
                        unsafe { std::slice::from_raw_parts(salsa.pBlockCounter, 8) }.to_vec();
                    let nonce = if salsa.pNonce.is_null() || salsa.ulNonceBits == 0 {
                        Vec::new()
                    } else {
                        // Safety: pNonce is non-null, nonce_bytes <= MAX_SERIALIZABLE_BYTES.
                        unsafe { std::slice::from_raw_parts(salsa.pNonce, nonce_bytes) }.to_vec()
                    };
                    Some(CkMechanismParams::Salsa20(Salsa20Params {
                        block_counter,
                        nonce,
                        nonce_bits: salsa.ulNonceBits as u64,
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
                if missing_embedded_pointer(sp.pNonce, sp.ulNonceLen)
                    || missing_embedded_pointer(sp.pAAD, sp.ulAADLen)
                    || !embedded_payload_len_ok(sp.ulNonceLen)
                    || !embedded_payload_len_ok(sp.ulAADLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let nonce = if sp.pNonce.is_null() || sp.ulNonceLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(sp.pNonce, sp.ulNonceLen as usize) }
                            .to_vec()
                    };
                    let aad = if sp.pAAD.is_null() || sp.ulAADLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(sp.pAAD, sp.ulAADLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::Salsa20ChaCha20Poly1305(
                        Salsa20ChaCha20Poly1305Params { nonce, aad },
                    ))
                }
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
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
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
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
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
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
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
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
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
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
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
                Some(CkMechanismParams::MacGeneral(MacGeneralParams { mac_length: val as u64 }))
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
                if missing_embedded_pointer(kds.pData, kds.ulLen)
                    || !embedded_payload_len_ok(kds.ulLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let data = if kds.pData.is_null() || kds.ulLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(kds.pData, kds.ulLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::KeyDerivationString(KeyDerivationStringData { data }))
                }
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
                if missing_embedded_pointer(gw.pIv, gw.ulIvLen)
                    || missing_embedded_pointer(gw.pAAD, gw.ulAADLen)
                    || !embedded_payload_len_ok(gw.ulIvLen)
                    || !embedded_payload_len_ok(gw.ulAADLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let iv = if gw.pIv.is_null() || gw.ulIvLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(gw.pIv, gw.ulIvLen as usize) }.to_vec()
                    };
                    let aad = if gw.pAAD.is_null() || gw.ulAADLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(gw.pAAD, gw.ulAADLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::GcmWrap(GcmWrapParams {
                        iv,
                        iv_fixed_bits: gw.ulIvFixedBits as u64,
                        iv_generator: gw.ivGenerator as u64,
                        aad,
                        tag_bits: gw.ulTagBits as u64,
                    }))
                }
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
                if missing_embedded_pointer(cw.pNonce, cw.ulNonceLen)
                    || missing_embedded_pointer(cw.pAAD, cw.ulAADLen)
                    || !embedded_payload_len_ok(cw.ulNonceLen)
                    || !embedded_payload_len_ok(cw.ulAADLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let nonce = if cw.pNonce.is_null() || cw.ulNonceLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(cw.pNonce, cw.ulNonceLen as usize) }
                            .to_vec()
                    };
                    let aad = if cw.pAAD.is_null() || cw.ulAADLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(cw.pAAD, cw.ulAADLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::CcmWrap(CcmWrapParams {
                        data_len: cw.ulDataLen as u64,
                        nonce,
                        nonce_fixed_bits: cw.ulNonceFixedBits as u64,
                        nonce_generator: cw.nonceGenerator as u64,
                        aad,
                        mac_len: cw.ulMACLen as u64,
                    }))
                }
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
                    word_size: rc5.ulWordsize as u64,
                    rounds: rc5.ulRounds as u64,
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
                    word_size: rc5.ulWordsize as u64,
                    rounds: rc5.ulRounds as u64,
                    mac_length: rc5.ulMacLength as u64,
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
                if missing_embedded_pointer(rc5.pIv, rc5.ulIvLen)
                    || !embedded_payload_len_ok(rc5.ulIvLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let iv = if rc5.pIv.is_null() || rc5.ulIvLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(rc5.pIv, rc5.ulIvLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::Rc5Cbc(Rc5CbcParams {
                        word_size: rc5.ulWordsize as u64,
                        rounds: rc5.ulRounds as u64,
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
                    effective_bits: rc2.ulEffectiveBits as u64,
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
                    effective_bits: rc2.ulEffectiveBits as u64,
                    mac_length: rc2.ulMacLength as u64,
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
                Some(CkMechanismParams::Xeddsa(XeddsaParams { hash: xed.hash as u64 }))
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
                    prf_hash_mechanism: tls.prfHashMechanism as u64,
                    mac_length: tls.ulMacLength as u64,
                    server_or_client: tls.ulServerOrClient as u64,
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
                    if missing_embedded_pointer(oaep.pSourceData as *const u8, oaep.ulSourceDataLen)
                        || !embedded_payload_len_ok(oaep.ulSourceDataLen)
                    {
                        Some(raw_mechanism_params(param_ptr, param_len))
                    } else {
                        let source_data = if oaep.pSourceData.is_null() || oaep.ulSourceDataLen == 0
                        {
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
                                hash_alg: CkMechanismType(oaep.hashAlg as u64),
                                mgf: oaep.mgf as u64,
                                source: oaep.source as u64,
                                source_data,
                            },
                        }))
                    } // close inner else (source data ok)
                }
            }
        }

        Some("sign_additional_context") => {
            // Accept both CK_SIGN_ADDITIONAL_CONTEXT
            //   { CK_ULONG hedgeVariant, CK_BYTE_PTR pContext, CK_ULONG ulContextLen }
            // and CK_HASH_SIGN_ADDITIONAL_CONTEXT (the same, plus a trailing
            //   CK_MECHANISM_TYPE hash) used by the generic CKM_HASH_ML_DSA /
            // CKM_HASH_SLH_DSA. The larger struct is detected by ulParameterLen.
            let base_size = std::mem::size_of::<CK_ULONG>()
                + std::mem::size_of::<*mut u8>()
                + std::mem::size_of::<CK_ULONG>();
            let hash_size = base_size + std::mem::size_of::<CK_ULONG>();
            if param_len < base_size {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let hedge_variant = unsafe { *(param_ptr as *const CK_ULONG) };
                let ptr_offset = std::mem::size_of::<CK_ULONG>();
                let ctx_ptr = unsafe { *(param_ptr.add(ptr_offset) as *const *const u8) };
                let len_offset = ptr_offset + std::mem::size_of::<*const u8>();
                let ctx_len = unsafe { *(param_ptr.add(len_offset) as *const CK_ULONG) };
                if missing_embedded_pointer(ctx_ptr, ctx_len) || !embedded_payload_len_ok(ctx_len) {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let context = if ctx_ptr.is_null() || ctx_len == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(ctx_ptr, ctx_len as usize) }.to_vec()
                    };
                    let hash = if param_len >= hash_size {
                        let hash_offset = len_offset + std::mem::size_of::<CK_ULONG>();
                        unsafe { *(param_ptr.add(hash_offset) as *const CK_ULONG) as u64 }
                    } else {
                        0
                    };
                    Some(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                        hedge_variant: hedge_variant as u64,
                        context,
                        hash,
                    }))
                }
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
                ) || !embedded_payload_len_ok(p.ul_customization_string_len)
                {
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
                    || !embedded_payload_len_ok(p.ul_tr_len)
                    || !embedded_payload_len_ok(p.ul_ctx_len)
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
                if missing_embedded_pointer(p.pSaltSourceData as *const u8, p.ulSaltSourceDataLen)
                    || missing_embedded_pointer(p.pPrfData as *const u8, p.ulPrfDataLen)
                    || missing_embedded_pointer(p.pPassword, p.ulPasswordLen)
                    || !embedded_payload_len_ok(p.ulSaltSourceDataLen)
                    || !embedded_payload_len_ok(p.ulPrfDataLen)
                    || !embedded_payload_len_ok(p.ulPasswordLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let salt_source_data =
                        if p.pSaltSourceData.is_null() || p.ulSaltSourceDataLen == 0 {
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
                            std::slice::from_raw_parts(
                                p.pPrfData as *const u8,
                                p.ulPrfDataLen as usize,
                            )
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
                ) || !embedded_payload_len_ok(p.RandomInfo.ulClientRandomLen)
                    || !embedded_payload_len_ok(p.RandomInfo.ulServerRandomLen)
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
                    || !embedded_payload_len_ok(p.ulSeedLen)
                    || !embedded_payload_len_ok(p.ulLabelLen)
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
                    || requested_iv_len > MAX_SERIALIZABLE_BYTES
                    || !embedded_payload_len_ok(p.RandomInfo.ulClientRandomLen)
                    || !embedded_payload_len_ok(p.RandomInfo.ulServerRandomLen)
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
                if missing_embedded_pointer(
                    p.RandomInfo.pClientRandom,
                    p.RandomInfo.ulClientRandomLen,
                ) || missing_embedded_pointer(
                    p.RandomInfo.pServerRandom,
                    p.RandomInfo.ulServerRandomLen,
                ) || !embedded_payload_len_ok(p.RandomInfo.ulClientRandomLen)
                    || !embedded_payload_len_ok(p.RandomInfo.ulServerRandomLen)
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
        }

        Some("tls_prf") => {
            if param_len < std::mem::size_of::<CK_TLS_PRF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_TLS_PRF_PARAMS) };
                if missing_embedded_pointer(p.pSeed, p.ulSeedLen)
                    || missing_embedded_pointer(p.pLabel, p.ulLabelLen)
                    || !embedded_payload_len_ok(p.ulSeedLen)
                    || !embedded_payload_len_ok(p.ulLabelLen)
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
                        0u64
                    } else {
                        (unsafe { *p.pulOutputLen }) as u64
                    };
                    Some(CkMechanismParams::TlsPrf(TlsPrfParams { seed, label, output_len }))
                }
            }
        }

        Some("tls_kdf") => {
            if param_len < std::mem::size_of::<CK_TLS_KDF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_TLS_KDF_PARAMS) };
                if missing_embedded_pointer(p.pLabel, p.ulLabelLength)
                    || missing_embedded_pointer(
                        p.RandomInfo.pClientRandom,
                        p.RandomInfo.ulClientRandomLen,
                    )
                    || missing_embedded_pointer(
                        p.RandomInfo.pServerRandom,
                        p.RandomInfo.ulServerRandomLen,
                    )
                    || missing_embedded_pointer(p.pContextData, p.ulContextDataLength)
                    || !embedded_payload_len_ok(p.ulLabelLength)
                    || !embedded_payload_len_ok(p.RandomInfo.ulClientRandomLen)
                    || !embedded_payload_len_ok(p.RandomInfo.ulServerRandomLen)
                    || !embedded_payload_len_ok(p.ulContextDataLength)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
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
                            std::slice::from_raw_parts(
                                p.pContextData,
                                p.ulContextDataLength as usize,
                            )
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
        }

        Some("ssl3_master_key_derive") => {
            if param_len < std::mem::size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_SSL3_MASTER_KEY_DERIVE_PARAMS) };
                if missing_embedded_pointer(
                    p.RandomInfo.pClientRandom,
                    p.RandomInfo.ulClientRandomLen,
                ) || missing_embedded_pointer(
                    p.RandomInfo.pServerRandom,
                    p.RandomInfo.ulServerRandomLen,
                ) || !embedded_payload_len_ok(p.RandomInfo.ulClientRandomLen)
                    || !embedded_payload_len_ok(p.RandomInfo.ulServerRandomLen)
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
        }

        Some("tls12_extended_master_key_derive") => {
            if param_len < std::mem::size_of::<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p =
                    unsafe { &*(param_ptr as *const CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pSessionHash, p.ulSessionHashLen)
                    || !embedded_payload_len_ok(p.ulSessionHashLen)
                {
                    return CkMechanism {
                        mechanism_type: mech_type,
                        params: Some(raw_mechanism_params(param_ptr, param_len)),
                    };
                }
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
                    || requested_iv_len > MAX_SERIALIZABLE_BYTES
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
                if !embedded_payload_len_ok(p.ulPasswordLen)
                    || !embedded_payload_len_ok(p.ulSaltLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
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
                        unsafe { std::slice::from_raw_parts(p.pSalt, p.ulSaltLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::Pbe(PbeParams {
                        init_vector,
                        password,
                        salt,
                        iteration: p.ulIteration as u64,
                    }))
                }
            }
        }

        Some("ecdh_aes_key_wrap") => {
            if param_len < std::mem::size_of::<CK_ECDH_AES_KEY_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_ECDH_AES_KEY_WRAP_PARAMS) };
                if missing_embedded_pointer(p.pSharedData, p.ulSharedDataLen)
                    || !embedded_payload_len_ok(p.ulSharedDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let shared_data = if p.pSharedData.is_null() || p.ulSharedDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.pSharedData, p.ulSharedDataLen as usize)
                        }
                        .to_vec()
                    };
                    Some(CkMechanismParams::EcdhAesKeyWrap(EcdhAesKeyWrapParams {
                        aes_key_bits: p.ulAESKeyBits as u64,
                        kdf: p.kdf as u64,
                        shared_data,
                    }))
                }
            }
        }

        Some("ecdh2_derive") => {
            if param_len < std::mem::size_of::<CK_ECDH2_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_ECDH2_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pSharedData, p.ulSharedDataLen)
                    || missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || missing_embedded_pointer(p.pPublicData2, p.ulPublicDataLen2)
                    || !embedded_payload_len_ok(p.ulSharedDataLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen2)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let shared_data = if p.pSharedData.is_null() || p.ulSharedDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.pSharedData, p.ulSharedDataLen as usize)
                        }
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
        }

        Some("ecmqv_derive") => {
            if param_len < std::mem::size_of::<CK_ECMQV_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_ECMQV_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pSharedData, p.ulSharedDataLen)
                    || missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || missing_embedded_pointer(p.pPublicData2, p.ulPublicDataLen2)
                    || !embedded_payload_len_ok(p.ulSharedDataLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen2)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let shared_data = if p.pSharedData.is_null() || p.ulSharedDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.pSharedData, p.ulSharedDataLen as usize)
                        }
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
        }

        Some("x942_dh1_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_DH1_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_X9_42_DH1_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pOtherInfo, p.ulOtherInfoLen)
                    || missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulOtherInfoLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let other_info = if p.pOtherInfo.is_null() || p.ulOtherInfoLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.pOtherInfo, p.ulOtherInfoLen as usize)
                        }
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
                    Some(CkMechanismParams::X942Dh1Derive(X942Dh1DeriveParams {
                        kdf: p.kdf as u64,
                        other_info,
                        public_data,
                    }))
                }
            }
        }

        Some("x942_dh2_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_DH2_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_X9_42_DH2_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pOtherInfo, p.ulOtherInfoLen)
                    || missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || missing_embedded_pointer(p.pPublicData2, p.ulPublicDataLen2)
                    || !embedded_payload_len_ok(p.ulOtherInfoLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen2)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let other_info = if p.pOtherInfo.is_null() || p.ulOtherInfoLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.pOtherInfo, p.ulOtherInfoLen as usize)
                        }
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
                    || !embedded_payload_len_ok(p.ulOtherInfoLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen2)
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
                if missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || missing_embedded_pointer(p.pUKM, p.ulUKMLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulUKMLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let public_data = if p.pPublicData.is_null() || p.ulPublicDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.pPublicData, p.ulPublicDataLen as usize)
                        }
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
        }

        Some("gostr3410_key_wrap") => {
            if param_len < std::mem::size_of::<CK_GOSTR3410_KEY_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_GOSTR3410_KEY_WRAP_PARAMS) };
                if missing_embedded_pointer(p.pWrapOID, p.ulWrapOIDLen)
                    || missing_embedded_pointer(p.pUKM, p.ulUKMLen)
                    || !embedded_payload_len_ok(p.ulWrapOIDLen)
                    || !embedded_payload_len_ok(p.ulUKMLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
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
        }

        Some("key_wrap_set_oaep") => {
            if param_len < std::mem::size_of::<CK_KEY_WRAP_SET_OAEP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_KEY_WRAP_SET_OAEP_PARAMS) };
                if missing_embedded_pointer(p.pX, p.ulXLen) || !embedded_payload_len_ok(p.ulXLen) {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
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
        }

        Some("kea_derive") => {
            if param_len < std::mem::size_of::<CK_KEA_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_KEA_DERIVE_PARAMS) };
                if !embedded_payload_len_ok(p.ulRandomLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
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
                        unsafe {
                            std::slice::from_raw_parts(p.PublicData, p.ulPublicDataLen as usize)
                        }
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
        }

        Some("ike_prf_derive") => {
            if param_len < std::mem::size_of::<CK_IKE_PRF_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_IKE_PRF_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pNi, p.ulNiLen)
                    || missing_embedded_pointer(p.pNr, p.ulNrLen)
                    || !embedded_payload_len_ok(p.ulNiLen)
                    || !embedded_payload_len_ok(p.ulNrLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
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
        }

        Some("ike1_prf_derive") => {
            if param_len < std::mem::size_of::<CK_IKE1_PRF_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_IKE1_PRF_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pCKYi, p.ulCKYiLen)
                    || missing_embedded_pointer(p.pCKYr, p.ulCKYrLen)
                    || !embedded_payload_len_ok(p.ulCKYiLen)
                    || !embedded_payload_len_ok(p.ulCKYrLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let ckyi = if p.pCKYi.is_null() || p.ulCKYiLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pCKYi, p.ulCKYiLen as usize) }
                            .to_vec()
                    };
                    let ckyr = if p.pCKYr.is_null() || p.ulCKYrLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pCKYr, p.ulCKYrLen as usize) }
                            .to_vec()
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
        }

        Some("ike1_extended_derive") => {
            if param_len < std::mem::size_of::<CK_IKE1_EXTENDED_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_IKE1_EXTENDED_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pExtraData, p.ulExtraDataLen)
                    || !embedded_payload_len_ok(p.ulExtraDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
                    let extra_data = if p.pExtraData.is_null() || p.ulExtraDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(p.pExtraData, p.ulExtraDataLen as usize)
                        }
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
        }

        Some("ike2_prf_plus_derive") => {
            if param_len < std::mem::size_of::<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len) },
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_IKE2_PRF_PLUS_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pSeedData, p.ulSeedDataLen)
                    || !embedded_payload_len_ok(p.ulSeedDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len))
                } else {
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
                    unsafe {
                        (*p.pMechanism).ulParameterLen as usize > MAX_MECHANISM_PARAM_STRUCT_LEN
                    }
                };
                if p.pMechanism.is_null()
                    || nested_len_too_large
                    || missing_embedded_pointer(p.pSeed, p.ulSeedLen)
                    || !embedded_payload_len_ok(p.ulSeedLen)
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
                            || !embedded_payload_len_ok(param.ulValueLen)
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
                    || !embedded_payload_len_ok(p.ulPasswordLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulRandomLen)
                    || !embedded_payload_len_ok(p.ulPAndGLen)
                    || !embedded_payload_len_ok(p.ulQLen)
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
                    || !embedded_payload_len_ok(p.ulOldWrappedXLen)
                    || !embedded_payload_len_ok(p.ulOldPasswordLen)
                    || !embedded_payload_len_ok(p.ulOldPublicDataLen)
                    || !embedded_payload_len_ok(p.ulOldRandomLen)
                    || !embedded_payload_len_ok(p.ulNewPasswordLen)
                    || !embedded_payload_len_ok(p.ulNewPublicDataLen)
                    || !embedded_payload_len_ok(p.ulNewRandomLen)
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
                    || !embedded_payload_len_ok(p.ulIVLen)
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
            || !embedded_payload_len_ok(param.ulValueLen)
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
            // Inputs are pre-validated by `sp800_108_derived_keys_invalid`, so
            // the fallible path is unreachable here; use the checked variant
            // (empty template on the impossible error) rather than panicking.
            let template =
                unsafe { ck_attrs_to_rust_checked(derived.pTemplate, derived.ulAttributeCount) }
                    .unwrap_or_default();
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
        CkMechanismParams::GcmWrap(gcm_out) => {
            if mechanism.ulParameterLen < std::mem::size_of::<CK_GCM_WRAP_PARAMS>() as CK_ULONG
                || mechanism.pParameter.is_null()
            {
                return;
            }

            let gcm = unsafe { &mut *(mechanism.pParameter as *mut CK_GCM_WRAP_PARAMS) };
            if !gcm.pIv.is_null() {
                let capacity = gcm.ulIvLen as usize;
                let copy_len = gcm_out.iv.len().min(capacity);
                if copy_len > 0 {
                    unsafe {
                        std::ptr::copy_nonoverlapping(gcm_out.iv.as_ptr(), gcm.pIv, copy_len);
                    }
                }
                gcm.ulIvLen = copy_len as CK_ULONG;
            }
            gcm.ulIvFixedBits = gcm_out.iv_fixed_bits as CK_ULONG;
            gcm.ivGenerator = gcm_out.iv_generator as CK_GENERATOR_FUNCTION;
            gcm.ulTagBits = gcm_out.tag_bits as CK_ULONG;
        }
        CkMechanismParams::CcmWrap(ccm_out) => {
            if mechanism.ulParameterLen < std::mem::size_of::<CK_CCM_WRAP_PARAMS>() as CK_ULONG
                || mechanism.pParameter.is_null()
            {
                return;
            }

            let ccm = unsafe { &mut *(mechanism.pParameter as *mut CK_CCM_WRAP_PARAMS) };
            if !ccm.pNonce.is_null() {
                let capacity = ccm.ulNonceLen as usize;
                let copy_len = ccm_out.nonce.len().min(capacity);
                if copy_len > 0 {
                    unsafe {
                        std::ptr::copy_nonoverlapping(ccm_out.nonce.as_ptr(), ccm.pNonce, copy_len);
                    }
                }
                ccm.ulNonceLen = copy_len as CK_ULONG;
            }
            ccm.ulDataLen = ccm_out.data_len as CK_ULONG;
            ccm.ulNonceFixedBits = ccm_out.nonce_fixed_bits as CK_ULONG;
            ccm.nonceGenerator = ccm_out.nonce_generator as CK_GENERATOR_FUNCTION;
            ccm.ulMACLen = ccm_out.mac_len as CK_ULONG;
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
                    .min(MAX_SERIALIZABLE_BYTES);
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
                .min(MAX_SERIALIZABLE_BYTES);
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
        CkMechanismParams::Pbe(pbe_out) => {
            // CK_PBE_PARAMS.pInitVector is OUT — the HSM writes the generated
            // 8-byte IV here during PBE key generation. Only the IV is written
            // back; pPassword/pSalt are caller-supplied inputs and are left
            // untouched (the backend never echoes them back).
            if mechanism.ulParameterLen < std::mem::size_of::<CK_PBE_PARAMS>() as CK_ULONG
                || mechanism.pParameter.is_null()
            {
                return;
            }
            let pbe = unsafe { &*(mechanism.pParameter as *const CK_PBE_PARAMS) };
            if !pbe.pInitVector.is_null() && !pbe_out.init_vector.is_empty() {
                // PBE IV is 8 bytes; copy no more than the caller's buffer holds.
                let n = pbe_out.init_vector.len().min(8);
                unsafe {
                    std::ptr::copy_nonoverlapping(pbe_out.init_vector.as_ptr(), pbe.pInitVector, n);
                }
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
    if len > MAX_MECHANISM_PARAM_STRUCT_LEN {
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
/// `pIv` must be valid for `ulIvLen` bytes only when `pIv` is non-null
/// and `ulIvLen <= MAX_SERIALIZABLE_BYTES`; otherwise the IV field is
/// read as empty without dereferencing the pointer.  `pTag` must be
/// valid for `ulTagBits/8` bytes only when `pTag` is non-null and the
/// derived byte count is `<= MAX_SERIALIZABLE_BYTES`; otherwise the tag
/// field is read as empty.
pub(crate) unsafe fn read_gcm_message_params(
    p_parameter: *const std::ffi::c_void,
) -> pkcs11_proxy_ng_proto::convert::message_params::GcmMessageParams {
    let p = unsafe { &*(p_parameter as *const CK_GCM_MESSAGE_PARAMS) };
    let iv = if !p.pIv.is_null() && p.ulIvLen > 0 && (p.ulIvLen as usize) <= MAX_SERIALIZABLE_BYTES
    {
        unsafe { std::slice::from_raw_parts(p.pIv, p.ulIvLen as usize) }.to_vec()
    } else {
        Vec::new()
    };
    // Compute in u64 and reject at the cap (`<`, not `<=`): on a 32-bit CK_ULONG
    // target a near-u32::MAX bit count's byte length sits AT MAX_SERIALIZABLE_BYTES,
    // so `<=` would wild-read a dangling/short pTag at the boundary (i686 SIGSEGV).
    let tag_bytes = (p.ulTagBits as u64).div_ceil(8);
    let tag = if !p.pTag.is_null() && tag_bytes > 0 && tag_bytes < MAX_SERIALIZABLE_BYTES as u64 {
        unsafe { std::slice::from_raw_parts(p.pTag, tag_bytes as usize) }.to_vec()
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
/// `pNonce` must be valid for `ulNonceLen` bytes only when `pNonce` is
/// non-null and `ulNonceLen <= MAX_SERIALIZABLE_BYTES`; otherwise the
/// nonce field is read as empty.  `pMAC` must be valid for `ulMACLen`
/// bytes only when `pMAC` is non-null and `ulMACLen <= MAX_SERIALIZABLE_BYTES`;
/// otherwise the mac field is read as empty.
pub(crate) unsafe fn read_ccm_message_params(
    p_parameter: *const std::ffi::c_void,
) -> pkcs11_proxy_ng_proto::convert::message_params::CcmMessageParams {
    let p = unsafe { &*(p_parameter as *const CK_CCM_MESSAGE_PARAMS) };
    let nonce = if !p.pNonce.is_null()
        && p.ulNonceLen > 0
        && (p.ulNonceLen as usize) <= MAX_SERIALIZABLE_BYTES
    {
        unsafe { std::slice::from_raw_parts(p.pNonce, p.ulNonceLen as usize) }.to_vec()
    } else {
        Vec::new()
    };
    let mac =
        if !p.pMAC.is_null() && p.ulMACLen > 0 && (p.ulMACLen as usize) <= MAX_SERIALIZABLE_BYTES {
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
/// `p_parameter` must point to a valid struct.  `pNonce` must be valid
/// for `ulNonceLen` bytes only when `pNonce` is non-null and
/// `ulNonceLen <= MAX_SERIALIZABLE_BYTES`; otherwise the nonce field is
/// read as empty.  `pTag` must be valid for 16 bytes when non-null
/// (Poly1305 tag is a compile-time constant 16 bytes; no length guard
/// is required).
pub(crate) unsafe fn read_salsa_chacha_message_params(
    p_parameter: *const std::ffi::c_void,
) -> pkcs11_proxy_ng_proto::convert::message_params::Salsa20ChaCha20Poly1305MessageParams {
    let p = unsafe { &*(p_parameter as *const CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS) };
    let nonce = if !p.pNonce.is_null()
        && p.ulNonceLen > 0
        && (p.ulNonceLen as usize) <= MAX_SERIALIZABLE_BYTES
    {
        unsafe { std::slice::from_raw_parts(p.pNonce, p.ulNonceLen as usize) }.to_vec()
    } else {
        Vec::new()
    };
    // Poly1305 tag is always 16 bytes (compile-time constant, no length guard needed)
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

    if (ul_parameter_len as usize) > MAX_MECHANISM_PARAM_STRUCT_LEN {
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

pub(crate) unsafe fn ck_attrs_to_rust_checked(
    p_template: *const CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CkResult<Vec<CkAttribute>> {
    unsafe { ck_attrs_to_rust_result(p_template, count, true) }
}

unsafe fn ck_attrs_to_rust_result(
    p_template: *const CK_ATTRIBUTE,
    count: CK_ULONG,
    reject_null_nonzero_count: bool,
) -> CkResult<Vec<CkAttribute>> {
    if p_template.is_null() {
        return if count == 0 || !reject_null_nonzero_count {
            Ok(Vec::new())
        } else {
            Err(CkRv::ARGUMENTS_BAD)
        };
    }
    if count as usize > MAX_TEMPLATE_COUNT {
        return Err(CkRv::ARGUMENTS_BAD);
    }
    // Width bridge (ADR-0011): a ulong array whose element width differs between
    // this client and the backend is re-encoded here, on the client edge.
    // (Scalar ulongs already travel width-independently as a typed `ulong_value`.)
    let client_ulong_width = std::mem::size_of::<CK_ULONG>();
    let backend_ulong_width = crate::interface_probe::backend_ulong_size();
    let slice = unsafe { std::slice::from_raw_parts(p_template, count as usize) };
    let mut result = Vec::with_capacity(count as usize);
    for attr in slice {
        let ck_type = CkAttributeType(attr.type_ as u64);
        let value = if attr.pValue.is_null() {
            if attr.ulValueLen != 0 && reject_null_nonzero_count {
                return Err(CkRv::ARGUMENTS_BAD);
            }
            None
        } else if attr.ulValueLen == 0 {
            None
        } else {
            let len = attr.ulValueLen as usize;
            if ck_type.is_bool() && len == std::mem::size_of::<CK_BBOOL>() {
                let v = unsafe { *(attr.pValue as *const CK_BBOOL) };
                Some(CkAttributeValue::Bool(v != 0))
            } else if ck_type.is_ulong() && len == std::mem::size_of::<CK_ULONG>() {
                // `CK_ULONG` is u32 on narrow (32-bit-CK_ULONG) targets; widen to
                // the wire's u64 so the shim compiles on i686/armv7/Windows-x64.
                let v = unsafe { *(attr.pValue as *const CK_ULONG) };
                Some(CkAttributeValue::Ulong(v as u64))
            } else if len > MAX_SERIALIZABLE_BYTES {
                return Err(CkRv::ARGUMENTS_BAD);
            } else if ck_type.is_ulong_array()
                && client_ulong_width != backend_ulong_width
                && len.is_multiple_of(client_ulong_width)
            {
                // A ulong array (e.g. CKA_ALLOWED_MECHANISMS) whose element width
                // differs from the backend's: re-encode each element to the
                // backend width here, then send as opaque bytes the server writes
                // verbatim (ADR-0011). Same-width arrays fall through to the
                // raw-bytes path below, byte-identical to before.
                let bytes = unsafe { std::slice::from_raw_parts(attr.pValue as *const u8, len) };
                match pkcs11_proxy_ng_types::width::reencode_ulong(
                    bytes,
                    client_ulong_width,
                    backend_ulong_width,
                    pkcs11_proxy_ng_types::width::ByteOrder::Little,
                ) {
                    Ok(reencoded) => Some(CkAttributeValue::Bytes(reencoded)),
                    // D4: an element exceeds the backend's CK_ULONG range.
                    Err(_) => return Err(CkRv::ATTRIBUTE_VALUE_INVALID),
                }
            } else {
                let bytes =
                    unsafe { std::slice::from_raw_parts(attr.pValue as *const u8, len) }.to_vec();
                Some(CkAttributeValue::Bytes(bytes))
            }
        };
        result.push(CkAttribute { attr_type: ck_type, value });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::pad_string;
    use cryptoki_sys::CK_ULONG;

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
    fn catch_panics_converts_panic_to_general_error() {
        // AGENTS.md §3: a panic inside an extern "C" entry must be CAUGHT and
        // surfaced as CKR_GENERAL_ERROR at runtime, never unwind across the C
        // boundary. Source-substring audits pass even if catch_panics were
        // gutted to `f()`; this runtime check would not.
        let rv = super::catch_panics(|| panic!("boom across the FFI boundary"));
        assert_eq!(rv, pkcs11_proxy_ng_types::CkRv::GENERAL_ERROR.0 as _);
    }

    #[test]
    fn catch_panics_passes_through_non_panicking_rv() {
        let rv = super::catch_panics(|| pkcs11_proxy_ng_types::CkRv::OK.0 as _);
        assert_eq!(rv, pkcs11_proxy_ng_types::CkRv::OK.0 as _);
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

    #[test]
    fn classify_input_valid_pointer() {
        let buf = [1u8, 2, 3];
        match unsafe { super::classify_input(buf.as_ptr(), 3) } {
            super::InputBuf::Bytes(s) => assert_eq!(s, &[1, 2, 3]),
            other => panic!("expected Bytes, got {other:?}"),
        }
    }

    #[test]
    fn classify_input_null_with_len_is_preserved_not_flattened() {
        match unsafe { super::classify_input(std::ptr::null::<u8>(), 7) } {
            super::InputBuf::Null { len } => assert_eq!(len, 7),
            other => panic!("expected Null{{7}}, got {other:?}"),
        }
    }

    #[test]
    fn classify_input_null_len0_and_valid_len0_both_empty_null_flagged() {
        assert!(matches!(
            unsafe { super::classify_input(std::ptr::null::<u8>(), 0) },
            super::InputBuf::Null { len: 0 }
        ));
        let b = [0u8; 1];
        assert!(matches!(
            unsafe { super::classify_input(b.as_ptr(), 0) },
            super::InputBuf::Bytes(&[])
        ));
    }

    #[test]
    fn classify_input_unmaterializable_len_is_too_large_not_panic() {
        let b = [0u8; 1];
        // CK_ULONG::MAX, not `u64::MAX as CK_ULONG`: on a 32-bit CK_ULONG target
        // the latter truncates to 0xFFFF_FFFF, so the returned (widened) len would
        // not equal u64::MAX. Both are far above MAX_SERIALIZABLE_BYTES → TooLarge.
        match unsafe { super::classify_input(b.as_ptr(), CK_ULONG::MAX) } {
            super::InputBuf::TooLarge { len } => assert_eq!(len, CK_ULONG::MAX as u64),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn input_buf_to_ck_in_buf_too_large_returns_arguments_bad() {
        let buf = super::InputBuf::TooLarge { len: u64::MAX };
        assert_eq!(
            super::input_buf_to_ck_in_buf(buf).unwrap_err(),
            pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD
        );
    }

    #[test]
    fn input_buf_to_ck_in_buf_bytes_roundtrips() {
        let data = b"hello";
        let buf = super::InputBuf::Bytes(data);
        let result = super::input_buf_to_ck_in_buf(buf).unwrap();
        assert!(matches!(result, pkcs11_proxy_ng_types::CkInBuf::Bytes(b) if b == data));
    }

    #[test]
    fn input_buf_to_ck_in_buf_null_roundtrips() {
        let buf = super::InputBuf::Null { len: 42 };
        let result = super::input_buf_to_ck_in_buf(buf).unwrap();
        assert!(matches!(result, pkcs11_proxy_ng_types::CkInBuf::Null { len: 42 }));
    }
}

// Mechanism/message parameter conversion tests live in sibling files (M6) so
// this module stays focused on the production helpers; they remain child
// modules of `helpers`, so their `use super::*` still reaches private items.
#[cfg(test)]
mod mechanism_parameter_tests;
#[cfg(test)]
mod message_parameter_tests;

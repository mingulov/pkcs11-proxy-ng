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
pub(crate) const MAX_SERIALIZABLE_BYTES: usize = 512 * 1024 * 1024;

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
pub(crate) const MAX_MECHANISM_PARAM_STRUCT_LEN: usize = 65_536;

mod mechanism_read;
mod mechanism_writeback;
mod message_params;
mod template_input;

pub(crate) use mechanism_read::*;
pub(crate) use mechanism_writeback::*;
pub(crate) use message_params::*;
pub(crate) use template_input::*;

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
        assert_eq!(rv, pkcs11_proxy_ng_types::CkRv::GENERAL_ERROR.0 as u64);
    }

    #[test]
    fn catch_panics_passes_through_non_panicking_rv() {
        let rv = super::catch_panics(|| pkcs11_proxy_ng_types::CkRv::OK.0 as _);
        assert_eq!(rv, pkcs11_proxy_ng_types::CkRv::OK.0 as u64);
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

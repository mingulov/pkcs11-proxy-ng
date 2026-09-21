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
        // W1-L6-29: consume the reconnect flag on the steady-state data
        // plane. A transport failure on an earlier call (client-crate
        // hook), a fork, or C_Finalize marks the cached channel stale;
        // without this the flag was honored only across
        // C_Initialize/probe, so steady-state calls never re-dialed (no
        // DNS re-resolve, no recovery). Runs OUTSIDE block_on (the slow
        // path block_ons itself); the fast path is two atomic loads.
        // Best-effort: on failure the call below proceeds with the
        // cached client and the RPC surfaces the transport error.
        let _ = crate::state::ensure_client_connected();
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
        Some(n)
            if n <= MAX_SERIALIZABLE_BYTES
                && n <= isize::MAX as usize
                && (ptr as usize).checked_add(n).is_some() =>
        {
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

/// Fallible reader for optional PIN-style byte inputs (W1-L3-03).
///
/// Unlike `read_input_slice` (which panics on unmaterializable lengths, and
/// the panic surfaces as CKR_GENERAL_ERROR via `catch_panics`), this returns
/// the transport-impossible class as `Err(CkRv::ARGUMENTS_BAD)` — the same
/// documented stable RV that `classify_input` + `input_buf_to_ck_in_buf`
/// produce — and never panics. NULL maps to `None` for any claimed length,
/// matching the historical null handling of the PIN call sites.
///
/// # Safety
///
/// When `ptr` is non-null, it must point to a valid, readable buffer of at
/// least `len` bytes (as required by PKCS#11 semantics for input parameters).
/// The returned slice borrows from that memory and must not outlive it. When
/// `ptr` is null, no memory is accessed regardless of `len`. Lengths that
/// cannot be materialized are rejected before any memory access.
pub(crate) unsafe fn try_read_optional_bytes<'a>(
    ptr: *const u8,
    len: CK_ULONG,
) -> Result<Option<&'a [u8]>, CkRv> {
    match unsafe { classify_input(ptr, len) } {
        InputBuf::Bytes(b) => Ok(Some(b)),
        InputBuf::Null { .. } => Ok(None),
        InputBuf::TooLarge { .. } => Err(CkRv::ARGUMENTS_BAD),
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
/// A non-null `pul_output_len` must point to a valid `CK_ULONG`.
pub(crate) unsafe fn output_buffer_spec(
    p_output: CK_BYTE_PTR,
    pul_output_len: CK_ULONG_PTR,
) -> pkcs11_proxy_ng_types::CkOutputBufferSpec {
    let length_pointer_null = pul_output_len.is_null();
    let buffer_present = !p_output.is_null();
    pkcs11_proxy_ng_types::CkOutputBufferSpec {
        buffer_present,
        buffer_len: if length_pointer_null || !buffer_present {
            0
        } else {
            (unsafe { *pul_output_len }) as u64
        },
        length_pointer_null,
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
/// When the captured spec says the length pointer was present, `pul_output_len` must still be
/// non-null. If the result contains data and `p_output` is non-null, `p_output` must point to a
/// writable buffer of at least `returned_len` bytes. A captured missing-length call never
/// dereferences or writes either output pointer.
pub(crate) unsafe fn write_exact_output(
    spec: &pkcs11_proxy_ng_types::CkOutputBufferSpec,
    result: &pkcs11_proxy_ng_types::CkOutputBufferResult,
    p_output: CK_BYTE_PTR,
    pul_output_len: CK_ULONG_PTR,
) -> CK_RV {
    if p_output.is_null() == spec.buffer_present
        || pul_output_len.is_null() != spec.length_pointer_null
    {
        return rv_err(CkRv::ARGUMENTS_BAD);
    }
    if let Err(rv) = result.validate_for(spec, CK_ULONG::MAX as u64) {
        return rv_err(rv);
    }
    // The validated request snapshot is the capacity authority. In particular,
    // a NULL-output query may have an uninitialized incoming length cell.
    let rv = CK_RV::try_from(result.ck_rv.0).unwrap_or(CKR_GENERAL_ERROR);
    let length = result.returned_len.map(|n| CK_ULONG::try_from(n).expect("validated width"));
    if let Some(value) = &result.value
        && !value.is_empty()
    {
        value.expose(|raw| unsafe {
            std::ptr::copy_nonoverlapping(raw.as_ptr(), p_output, raw.len())
        });
    }
    if let Some(length) = length {
        unsafe { pul_output_len.write(length) };
    }
    rv
}

#[cfg(test)]
mod exact_scalar_tests {
    use super::*;

    #[test]
    fn write_exact_output_size_query_never_reads_incoming_length() {
        let mut length = std::mem::MaybeUninit::<CK_ULONG>::uninit();
        let pointer = length.as_mut_ptr();
        let spec = unsafe { output_buffer_spec(std::ptr::null_mut(), pointer) };
        assert_eq!(spec.buffer_len, 0);
        let output = CkOutputBufferResult {
            ck_rv: CkRv::FUNCTION_FAILED,
            returned_len: Some(7),
            value: None,
        };
        assert_eq!(
            unsafe { write_exact_output(&spec, &output, std::ptr::null_mut(), pointer) },
            CKR_FUNCTION_FAILED
        );
        assert_eq!(unsafe { length.assume_init() }, 7);
    }

    #[test]
    fn write_exact_output_preprovider_failure_leaves_length_and_bytes_untouched() {
        let mut value = [0xa5u8; 4];
        let mut length = 4;
        let spec = unsafe { output_buffer_spec(value.as_mut_ptr(), &mut length) };
        let output = CkOutputBufferResult::no_effects(CkRv::HOST_MEMORY);
        assert_eq!(
            unsafe { write_exact_output(&spec, &output, value.as_mut_ptr(), &mut length) },
            CKR_HOST_MEMORY
        );
        assert_eq!(length, 4);
        assert_eq!(value, [0xa5; 4]);
    }
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
    Ok(pkcs11_proxy_ng_types::CkParameterRoundtripSpec {
        buffer_present: !p_parameter.is_null(),
        buffer_len: ul_parameter_len as u64,
        value: None,
    })
}

/// Sign/Verify message parameters are empty-only. Reject a positive length
/// before touching the caller address, then preserve the two legal zero-length
/// pointer classes in the shared roundtrip envelope.
pub(crate) unsafe fn empty_message_parameter_roundtrip_spec(
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
) -> pkcs11_proxy_ng_types::CkResult<pkcs11_proxy_ng_types::CkParameterRoundtripSpec> {
    if ul_parameter_len > 0 {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    unsafe { message_parameter_roundtrip_spec(p_parameter, ul_parameter_len) }
}

pub(crate) fn catch_panics<F>(f: F) -> CK_RV
where
    F: FnOnce() -> CK_RV + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(|| {
        // W1-C7-04 forced-panic injection: fires before the export body runs,
        // inside the boundary's own `catch_unwind`. Test builds only.
        #[cfg(test)]
        if panic_inject_enabled_for_test() {
            panic!("W1-C7-04 injected panic at the extern \"C\" boundary");
        }
        f()
    }) {
        Ok(rv) => rv,
        Err(_) => rv_err(CkRv::GENERAL_ERROR),
    }
}

// Thread-local forced-panic injection for the per-export runtime boundary
// test (W1-C7-04). Thread-local (not global) so arming it cannot perturb
// exports called concurrently by other test threads — several
// early-return tests call exports without holding the shared state guard.
// `#[cfg(test)]` throughout: zero impact on shipped builds.
#[cfg(test)]
thread_local! {
    static PANIC_INJECT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_panic_inject_for_test(enabled: bool) {
    PANIC_INJECT.with(|flag| flag.set(enabled));
}

#[cfg(test)]
pub(crate) fn panic_inject_enabled_for_test() -> bool {
    PANIC_INJECT.with(|flag| flag.get())
}

/// Maximum mechanism **parameter-struct** byte length.  No standard PKCS#11
/// mechanism parameter struct exceeds a few hundred bytes; 64 KiB is
/// extremely generous.  This constant bounds `ulParameterLen` of a mechanism
/// or message parameter **struct** only — not embedded variable-length data
/// fields (seeds, labels, AADs, IVs, etc.) which are data, not structs, and
/// are bounded by `MAX_SERIALIZABLE_BYTES`.
pub(crate) const MAX_MECHANISM_PARAM_STRUCT_LEN: usize = 65_536;

mod authenticated_params;
mod mechanism_read;
mod mechanism_writeback;
mod message_params;
mod template_input;

pub(crate) use authenticated_params::*;
pub(crate) use mechanism_read::*;
pub(crate) use mechanism_writeback::*;
pub(crate) use message_params::*;
pub(crate) use template_input::*;

#[cfg(test)]
mod tests {
    use cryptoki_sys::{CK_RV, CK_ULONG};
    use pkcs11_proxy_ng_types::space_pad_into;

    #[test]
    fn short_src_pads_remainder_with_spaces() {
        let mut buf = [0u8; 8];
        space_pad_into(&mut buf, "hi");
        assert_eq!(&buf, b"hi      ");
    }

    #[test]
    fn exact_length_src_no_padding_needed() {
        let mut buf = [0u8; 4];
        space_pad_into(&mut buf, "ABCD");
        assert_eq!(&buf, b"ABCD");
    }

    #[test]
    fn catch_panics_converts_panic_to_general_error() {
        // AGENTS.md §3: a panic inside an extern "C" entry must be CAUGHT and
        // surfaced as CKR_GENERAL_ERROR at runtime, never unwind across the C
        // boundary. Source-substring audits pass even if catch_panics were
        // gutted to `f()`; this runtime check would not.
        let rv = super::catch_panics(|| panic!("boom across the FFI boundary"));
        assert_eq!(rv, pkcs11_proxy_ng_types::CkRv::GENERAL_ERROR.0 as CK_RV);
    }

    #[test]
    fn catch_panics_passes_through_non_panicking_rv() {
        let rv = super::catch_panics(|| pkcs11_proxy_ng_types::CkRv::OK.0 as _);
        assert_eq!(rv, pkcs11_proxy_ng_types::CkRv::OK.0 as CK_RV);
    }

    #[test]
    fn longer_src_truncated_to_dest_len() {
        let mut buf = [0u8; 4];
        space_pad_into(&mut buf, "ABCDEFGH");
        assert_eq!(&buf, b"ABCD");
    }

    #[test]
    fn empty_src_fills_all_spaces() {
        let mut buf = [0u8; 6];
        space_pad_into(&mut buf, "");
        assert_eq!(&buf, b"      ");
    }

    #[test]
    fn no_null_terminator_written() {
        let mut buf = [0xFFu8; 6];
        space_pad_into(&mut buf, "ab");
        assert_eq!(buf[0], b'a');
        assert_eq!(buf[1], b'b');
        for &b in &buf[2..] {
            assert_eq!(b, b' ');
        }
    }

    #[test]
    fn full_32_byte_token_label_field() {
        let mut label = [0u8; 32];
        space_pad_into(&mut label, "My Test Token");
        assert_eq!(&label[..13], b"My Test Token");
        assert!(label[13..].iter().all(|&b| b == b' '));
    }

    #[test]
    fn overlong_label_truncated_at_32_bytes() {
        let mut label = [0u8; 32];
        let long = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB";
        space_pad_into(&mut label, long);
        assert!(label.iter().all(|&b| b == b'A'));
    }

    // W1-L11-12 pin: byte-wise copy splits a multibyte char at the
    // edge — mirrored in the backend's `space_pad` vectors; both must
    // agree before unification and the shared helper after.
    #[test]
    fn multibyte_src_truncates_by_bytes() {
        let mut buf = [0u8; 4];
        space_pad_into(&mut buf, "héllo");
        assert_eq!(buf, [0x68, 0xC3, 0xA9, 0x6C]);
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
    fn classify_input_rejects_address_range_end_overflow_before_reading() {
        let pointer = (usize::MAX - 1) as *const u8;
        assert!(matches!(
            unsafe { super::classify_input(pointer, 4) },
            super::InputBuf::TooLarge { len: 4 }
        ));
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

    #[test]
    fn try_read_optional_bytes_oversize_returns_arguments_bad_without_panic() {
        // W1-L3-03: the fallible PIN reader must return Err(ARGUMENTS_BAD) for
        // the transport-impossible class — never panic (which catch_panics
        // would surface as CKR_GENERAL_ERROR). The outer catch_unwind proves
        // no unwind happens at all, not just that the RV differs.
        let buf = [0u8; 1];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            super::try_read_optional_bytes(buf.as_ptr(), CK_ULONG::MAX)
        }));
        let inner = result.expect("fallible PIN reader must not panic");
        assert_eq!(inner.unwrap_err(), pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD);
    }

    #[test]
    fn try_read_optional_bytes_valid_pin_roundtrips() {
        // W1-L3-03: valid PINs are unaffected — Some(bytes) with exact content.
        let pin = *b"1234";
        let result = unsafe { super::try_read_optional_bytes(pin.as_ptr(), 4) }.unwrap();
        assert_eq!(result, Some(pin.as_slice()));
    }

    #[test]
    fn try_read_optional_bytes_null_is_none_for_any_length() {
        // Historical null handling preserved: NULL → None regardless of the
        // claimed length (read_input_slice returned empty for NULL too, and
        // the call sites mapped NULL to None before ever reading).
        assert_eq!(unsafe { super::try_read_optional_bytes(std::ptr::null(), 0) }.unwrap(), None);
        assert_eq!(
            unsafe { super::try_read_optional_bytes(std::ptr::null(), CK_ULONG::MAX) }.unwrap(),
            None
        );
    }

    #[test]
    fn try_read_optional_bytes_non_null_len0_is_some_empty() {
        // Matches read_input_slice: non-NULL + len 0 → Some(&[]), not None.
        let buf = [0u8; 1];
        let result = unsafe { super::try_read_optional_bytes(buf.as_ptr(), 0) }.unwrap();
        assert_eq!(result, Some([].as_slice()));
    }
}

// Mechanism/message parameter conversion tests live in sibling files (M6) so
// this module stays focused on the production helpers; they remain child
// modules of `helpers`, so their `use super::*` still reaches private items.
#[cfg(test)]
mod mechanism_parameter_tests;
#[cfg(test)]
mod message_parameter_tests;

// CK_ULONG is u64 on 64-bit and u32 on 32-bit; `as u64` casts are intentional
// for cross-platform PKCS#11 portability.
#![allow(clippy::unnecessary_cast)]

use std::ffi::CStr;

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

/// Run a data-plane call against the shared gRPC client (W1-L11-01).
///
/// Looks like a plain call, but the expansion carries hidden control flow —
/// every expansion site (all shim data-plane entries) shares this shape:
/// - an early `return CKR_CRYPTOKI_NOT_INITIALIZED` when the shim is not
///   initialized (callers must be `CK_RV`-returning `catch_panics` closures);
/// - a best-effort `state::ensure_client_connected` reconnect-flag
///   consumption outside the runtime (fast path: two atomic loads);
/// - a `runtime().block_on` around the whole call: `$call` is an async
///   expression awaited on the shim's current-thread runtime;
/// - a clone-before-RPC of the shared client (the `Mutex` guard is dropped
///   before the RPC; `$client` binds the owned clone for `$call`).
///
/// Evaluates to the awaited `$call` value (`__result`); transport failures
/// surface through it, never through the flag-consumption step.
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
        // FOLLOWUP-dns-reresolve: RESOLVED (W1-L11-24, reconciling
        // W1-L6-29). Reconnect-on-transport-failure is driven by the
        // client crate's transport-failure hook (registered in
        // c_initialize), which fires ONLY when a gRPC transport `Status`
        // is mapped to a CK_RV — never on a backend `ck_rv`. The next
        // data-plane call then rebuilds the channel via a fresh
        // `Endpoint::from_shared` per dial, so DNS is re-resolved on
        // every reconnect — never cached with the old `Channel` — and a
        // long-lived shim follows a daemon whose DNS A-record changed
        // (k8s rolling deploy / blue-green). Evidence:
        // `steady_state_call_consumes_reconnect_flag` and
        // `get_info_consumes_reconnect_flag` (next-call re-dial) plus
        // `reconnect_rereads_endpoint_and_redials` (the endpoint is
        // re-read per reconnect). We deliberately do NOT key the
        // reconnect off the returned CK_RV here: kryoptic uses
        // CKR_DEVICE_ERROR (OpenSSL catch-all) and CKR_GENERAL_ERROR
        // (internal catch-all) as ordinary results, so doing so churned
        // the channel on every routine backend error.
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

/// Pointer-class-faithful input reader (ADR-0010 Scope 2). NULL is
/// preserved as NULL (with the caller's claimed length) and
/// unmaterializable lengths become a value, not a panic, so the dispatch
/// layer can return the documented stable RV (CKR_ARGUMENTS_BAD) instead
/// of GENERAL_ERROR. This is the only input reader: the historical
/// panicking reader was removed (W1-L11-10) once every call site migrated
/// to the fallible paths, so no TooLarge panic arm remains.
#[derive(Debug)]
pub(crate) enum InputBuf<'a> {
    Bytes(&'a [u8]),
    Null { len: u64 },
    TooLarge { len: u64 },
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
/// The rejected length is logged (lengths carry no secret content) so the
/// field is read at conversion, not kept by `allow(dead_code)` (W1-L12-09).
pub(crate) fn input_buf_to_ck_in_buf(buf: InputBuf<'_>) -> Result<CkInBuf<'_>, CkRv> {
    match buf {
        InputBuf::Bytes(b) => Ok(CkInBuf::Bytes(b)),
        InputBuf::Null { len } => Ok(CkInBuf::Null { len }),
        InputBuf::TooLarge { len } => {
            tracing::debug!(rejected_len = len, "oversize input rejected as ARGUMENTS_BAD");
            Err(CkRv::ARGUMENTS_BAD)
        }
    }
}

/// Fallible reader for optional PIN-style byte inputs (W1-L3-03,
/// extended to every PIN/username/label site by W1-L11-10).
///
/// Returns the transport-impossible class as `Err(CkRv::ARGUMENTS_BAD)` —
/// the same documented stable RV that `classify_input` +
/// `input_buf_to_ck_in_buf` produce — and never panics. NULL maps to
/// `None` for any claimed length, matching the historical null handling
/// of the PIN call sites.
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
        InputBuf::TooLarge { len } => {
            tracing::debug!(rejected_len = len, "oversize input rejected as ARGUMENTS_BAD");
            Err(CkRv::ARGUMENTS_BAD)
        }
    }
}

/// Fail-closed reader for credential inputs (PIN/username).
///
/// The credential wire format cannot preserve a nonzero length alongside a
/// NULL pointer. Refuse that unsupported shape with `ARGUMENTS_BAD` rather
/// than silently changing what a backend evaluates. This is a documented
/// transport limit, not a claim that PKCS#11 forbids every such input:
/// protected authentication paths may ignore the length of a NULL PIN.
/// (NULL, 0) still maps to `None` per the `c_login` convention. Other input
/// readers keep their separate contracts (ADR-0010).
///
/// # Safety
///
/// Same contract as `try_read_optional_bytes`.
pub(crate) unsafe fn try_read_credential_bytes<'a>(
    ptr: *const u8,
    len: CK_ULONG,
) -> Result<Option<&'a [u8]>, CkRv> {
    if ptr.is_null() && len != 0 {
        return Err(CkRv::ARGUMENTS_BAD);
    }
    unsafe { try_read_optional_bytes(ptr, len) }
}

/// Validate caller-memory extent arithmetic before constructing any slice or
/// performing any multi-byte unaligned copy (T03).
///
/// Checks, in order: `count` fits `usize` (32-bit `CK_ULONG` hosts),
/// `count * stride` does not overflow, the byte extent is within `cap` and
/// `isize::MAX` (the slice limit), and `address + extent` does not wrap the
/// address space. Returns the byte extent only — it does NOT certify that the
/// range is mapped or allocated; callers still rely on the FFI contract for
/// readability and must never treat a passing extent as proof of validity.
///
/// The rejection is `ARGUMENTS_BAD` (arithmetic-invalid input). Mechanism
/// readers map it to `MECHANISM_PARAM_INVALID` at their wrappers to match
/// the entry-gate convention.
pub(crate) fn checked_extent(
    address: usize,
    count: u64,
    stride: usize,
    cap: usize,
) -> CkResult<usize> {
    let count = usize::try_from(count).map_err(|_| CkRv::ARGUMENTS_BAD)?;
    let extent = count.checked_mul(stride).ok_or(CkRv::ARGUMENTS_BAD)?;
    if extent > cap || extent > isize::MAX as usize {
        return Err(CkRv::ARGUMENTS_BAD);
    }
    address.checked_add(extent).ok_or(CkRv::ARGUMENTS_BAD)?;
    Ok(extent)
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
            // Unaligned load (T06): the capacity cell carries no alignment
            // promise beyond the FFI readability contract.
            (unsafe { pul_output_len.read_unaligned() }) as u64
        },
        length_pointer_null,
    }
}

/// Caller C-string scan window, in bytes (W1-C6-06): at most 255 content
/// bytes plus the NUL fit inside — a NUL at index 256 is already outside
/// the window, so 256 content bytes are rejected. Interface and async
/// function names are short literals (`"PKCS 11"`, `"C_Sign"`); anything
/// without a NUL inside this bound is a buggy caller, answered loudly
/// instead of scanned unboundedly.
/// Mirrors the backend's `MAX_INTERFACE_NAME_LEN` (W1-C4-06).
pub(crate) const MAX_C_STRING_LEN: usize = 256;

/// Read a NUL-terminated caller string with a bounded scan (W1-C6-06).
///
/// Returns `Err(CkRv::ARGUMENTS_BAD)` when no NUL appears within the
/// [`MAX_C_STRING_LEN`]-byte scan window (at most 255 content bytes plus
/// the NUL) — the loud error for an unterminated or overlong caller string.
/// Never `CStr::from_ptr`: it would scan unboundedly into caller memory.
///
/// # Safety
///
/// `ptr` must be non-null, and the bytes from `ptr` up to and including
/// the first NUL (or [`MAX_C_STRING_LEN`] bytes when no NUL appears
/// sooner) must be readable for the returned borrow's lifetime.
pub(crate) unsafe fn read_bounded_cstr<'a>(ptr: *const std::ffi::c_char) -> Result<&'a CStr, CkRv> {
    let mut len = 0usize;
    while len < MAX_C_STRING_LEN {
        // SAFETY: non-null per the contract; the scan stays within the
        // readable prefix it guarantees.
        if unsafe { *ptr.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    if len == MAX_C_STRING_LEN {
        return Err(CkRv::ARGUMENTS_BAD);
    }
    // SAFETY: the `len` bytes before the NUL were just scanned readable
    // one by one; `from_bytes_with_nul` re-validates the terminator.
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len + 1) };
    std::ffi::CStr::from_bytes_with_nul(bytes).map_err(|_| CkRv::ARGUMENTS_BAD)
}

/// Decide the host-width mapping for a 64-bit wire `ck_rv` (W1-L3-13).
///
/// Returns `None` when `rv` fits `host_max` (the path every real backend
/// takes: all genuine PKCS#11 RVs are small). Returns
/// `Some(CkRv::GENERAL_ERROR)` when the value is unrepresentable — reachable
/// only on hosts where `CK_ULONG` is 32 bits (ILP32, Windows LLP64) meeting
/// a peer that emits a >32-bit RV. `GENERAL_ERROR` is the documented
/// proxy-originated fallback (no PKCS#11 RV names "unrepresentable"; cause
/// recorded in error-reference.md); the caller logs the saturation loudly.
/// Split out as a pure decision so the 32-bit mapping is pinnable on 64-bit
/// CI by simulating `host_max = u32::MAX`.
pub(crate) fn ck_rv_width_fallback(rv: u64, host_max: u64) -> Option<CkRv> {
    (rv > host_max).then_some(CkRv::GENERAL_ERROR)
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
    // W1-L3-13: loud, documented narrowing — a 64-bit wire ck_rv the host
    // CK_RV cannot represent (32-bit CK_ULONG hosts only) saturates to
    // GENERAL_ERROR with a warn, never silently.
    let rv = match ck_rv_width_fallback(result.ck_rv.0, CK_ULONG::MAX as u64) {
        Some(fallback) => {
            tracing::warn!(
                wire_ck_rv = result.ck_rv.0,
                "ck_rv unrepresentable in host CK_RV; saturating to CKR_GENERAL_ERROR"
            );
            rv_err(fallback)
        }
        // `result.ck_rv.0 <= CK_ULONG::MAX`, so the narrowing cast is exact.
        None => result.ck_rv.0 as CK_RV,
    };
    let length = result.returned_len.map(|n| CK_ULONG::try_from(n).expect("validated width"));
    if let Some(value) = &result.value
        && !value.is_empty()
    {
        value.expose(|raw| unsafe {
            std::ptr::copy_nonoverlapping(raw.as_ptr(), p_output, raw.len())
        });
    }
    if let Some(length) = length {
        // Unaligned store (T06); the length cell needs no alignment promise.
        unsafe { pul_output_len.write_unaligned(length) };
    }
    rv
}

/// Shared classify→spec→`byte_output_exact`→write_exact dispatch shape
/// (W1-L11-09). One implementation for the byte-output exports; every
/// site below delegates instead of repeating the four steps.
///
/// Order is load-bearing and matches every historical site: the input is
/// classified first (TooLarge answers `CKR_ARGUMENTS_BAD` before any
/// client use), then the output spec is captured, then the RPC runs, and
/// finally the exact result is written back.
///
/// # Safety
///
/// When `p_input` is non-null, it must point to a valid, readable buffer
/// of at least `ul_input_len` bytes. A non-null `pul_output_len` must
/// point to a valid `CK_ULONG`; when the result contains data and
/// `p_output` is non-null, `p_output` must point to a writable buffer of
/// at least the returned length. See [`classify_input`],
/// [`output_buffer_spec`], and [`write_exact_output`].
pub(crate) unsafe fn dispatch_byte_output_exact(
    h_session: CK_SESSION_HANDLE,
    function: ByteOutputFunction,
    p_input: CK_BYTE_PTR,
    ul_input_len: CK_ULONG,
    p_output: CK_BYTE_PTR,
    pul_output_len: CK_ULONG_PTR,
) -> CK_RV {
    let input = match input_buf_to_ck_in_buf(unsafe { classify_input(p_input, ul_input_len) }) {
        Ok(buf) => buf,
        Err(e) => return rv_err(e),
    };
    unsafe { byte_output_exact_with_input(h_session, function, input, p_output, pul_output_len) }
}

/// Output-only variant of [`dispatch_byte_output_exact`] (W1-L11-09) for
/// the `*_final` / state exports, which take no input pointer pair. The
/// input sent is always empty bytes — never a classified NULL — exactly
/// as every historical site did.
///
/// # Safety
///
/// Same output-pointer contract as [`dispatch_byte_output_exact`].
pub(crate) unsafe fn dispatch_byte_output_exact_no_input(
    h_session: CK_SESSION_HANDLE,
    function: ByteOutputFunction,
    p_output: CK_BYTE_PTR,
    pul_output_len: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        byte_output_exact_with_input(
            h_session,
            function,
            CkInBuf::Bytes(&[]),
            p_output,
            pul_output_len,
        )
    }
}

/// spec→RPC→write_exact core shared by [`dispatch_byte_output_exact`] and
/// [`dispatch_byte_output_exact_no_input`].
///
/// # Safety
///
/// Same output-pointer contract as [`dispatch_byte_output_exact`].
unsafe fn byte_output_exact_with_input(
    h_session: CK_SESSION_HANDLE,
    function: ByteOutputFunction,
    input: CkInBuf<'_>,
    p_output: CK_BYTE_PTR,
    pul_output_len: CK_ULONG_PTR,
) -> CK_RV {
    let spec = unsafe { output_buffer_spec(p_output, pul_output_len) };
    let result = with_client!(client => client.byte_output_exact(
        CkSessionHandle(h_session as u64),
        function,
        &spec,
        input,
        None,
        0,
        0,
    ));
    match result {
        Ok(r) => unsafe { write_exact_output(&spec, &r, p_output, pul_output_len) },
        Err(e) => rv_err(e),
    }
}

#[cfg(test)]
mod exact_scalar_tests {
    use super::*;

    /// W1-L3-13: the 32-bit saturation mapping, pinned via a simulated host
    /// width (real 32-bit-CK_ULONG hosts — ILP32, Windows LLP64 — cannot run
    /// in 64-bit CI, so the pure decision is tested with `host_max = u32::MAX`).
    #[test]
    fn ck_rv_width_fallback_pins_32bit_saturation_mapping() {
        let max32 = u32::MAX as u64;
        assert_eq!(super::ck_rv_width_fallback(0, max32), None);
        assert_eq!(super::ck_rv_width_fallback(CKR_GENERAL_ERROR as u64, max32), None);
        assert_eq!(super::ck_rv_width_fallback(max32, max32), None);
        assert_eq!(
            super::ck_rv_width_fallback(max32 + 1, max32),
            Some(CkRv::GENERAL_ERROR),
            "first unrepresentable value must saturate loudly to GENERAL_ERROR"
        );
        assert_eq!(super::ck_rv_width_fallback(u64::MAX, max32), Some(CkRv::GENERAL_ERROR));
        // 64-bit host: everything fits, never saturates.
        assert_eq!(super::ck_rv_width_fallback(u64::MAX, u64::MAX), None);
        assert_eq!(super::ck_rv_width_fallback(0x150, u64::MAX), None);
    }

    /// W1-L3-13: no silent narrowing fallback to CKR_GENERAL_ERROR may
    /// remain — the 32-bit path must saturate through the loud helper.
    #[test]
    fn ck_rv_narrowing_has_no_silent_general_error_fallback() {
        let src = include_str!("mod.rs");
        // Built via concat so the assertions do not match their own source text.
        let silent = ["unwrap_or", "(CKR_GENERAL_ERROR)"].concat();
        assert!(
            !src.contains(&silent),
            "silent ck_rv narrowing must be replaced by the loud W1-L3-13 helper"
        );
        let loud = ["unrepresentable in host ", "CK_RV"].concat();
        assert!(
            src.contains(&loud),
            "the 32-bit saturation must log loudly (W1-L3-13 warn marker)"
        );
    }

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

/// Store a session handle into the caller's out-pointer (W1-L1-04).
///
/// # Safety
///
/// `p_handle` must be non-null and writable for one handle.
pub(crate) unsafe fn write_session_handle_output(
    handle: CkSessionHandle,
    p_handle: CK_SESSION_HANDLE_PTR,
) {
    unsafe { *p_handle = handle.0 as CK_SESSION_HANDLE };
}

/// Narrow a daemon-returned `u64` to a native caller-width integer (T06).
///
/// Infallible where the target is 64 bits; on narrow hosts an
/// unrepresentable value is malformed daemon output
/// (`GENERAL_ERROR`), never a truncation (mirrors the
/// [`ck_rv_width_fallback`] precedent). The `u32` instantiation pins the
/// checking machinery itself on 64-bit CI.
pub(crate) fn narrow_u64_to_native<T>(value: u64) -> CkResult<T>
where
    T: TryFrom<u64>,
{
    T::try_from(value).map_err(|_| CkRv::GENERAL_ERROR)
}

/// Store an object handle into the caller's out-pointer (W1-L1-04).
///
/// The handle is validated before the store (T06): unrepresentable on a
/// narrow host fails without writing. The store itself assumes no
/// alignment.
///
/// # Safety
///
/// `p_handle` must be non-null and writable for one handle (alignment
/// not required).
pub(crate) unsafe fn write_object_handle_output(
    handle: CkObjectHandle,
    p_handle: CK_OBJECT_HANDLE_PTR,
) -> CkResult<()> {
    let native = narrow_u64_to_native(handle.0)?;
    unsafe { p_handle.write_unaligned(native) };
    Ok(())
}

/// Store a generated key pair into the caller's out-pointers (W1-L1-04).
///
/// Both handles are validated before either store (T06), so a malformed
/// second handle preserves the first cell.
///
/// # Safety
///
/// Both out-pointers must be non-null and writable for one handle each
/// (alignment not required).
pub(crate) unsafe fn write_object_handle_pair_output(
    public_handle: CkObjectHandle,
    private_handle: CkObjectHandle,
    p_public_handle: CK_OBJECT_HANDLE_PTR,
    p_private_handle: CK_OBJECT_HANDLE_PTR,
) -> CkResult<()> {
    let public = narrow_u64_to_native(public_handle.0)?;
    let private = narrow_u64_to_native(private_handle.0)?;
    unsafe {
        p_public_handle.write_unaligned(public);
        p_private_handle.write_unaligned(private);
    }
    Ok(())
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
    p_parameter: *mut ::std::ffi::c_void,
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
///
/// # Safety
///
/// No caller memory is dereferenced — `p_parameter` is only null-tested
/// (the shared spec constructor records presence/length without reading).
pub(crate) unsafe fn empty_message_parameter_roundtrip_spec(
    p_parameter: *mut ::std::ffi::c_void,
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
    use cryptoki_sys::{CK_RV, CK_TOKEN_INFO, CK_ULONG};
    use pkcs11_proxy_ng_types::{CkRv, PKCS11_TOKEN_LABEL_LEN, space_pad_into};

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
    fn bounded_cstr_accepts_short_and_boundary_names() {
        // W1-C6-06: NUL-terminated names within the 256-content-byte bound
        // read back verbatim, including the empty string and the exact
        // 255-content-byte boundary.
        for content in [b"".as_slice(), b"PKCS 11".as_slice(), [b'A'; 255].as_slice()] {
            let mut owned = content.to_vec();
            owned.push(0);
            let read =
                unsafe { super::read_bounded_cstr(owned.as_ptr() as *const std::ffi::c_char) };
            assert_eq!(read.expect("in-bound name must parse").to_bytes(), content);
        }
    }

    #[test]
    fn bounded_cstr_rejects_names_without_nul_in_bound() {
        // W1-C6-06: no NUL within 256 content bytes is a loud
        // ARGUMENTS_BAD. The trailing NUL at byte 300 keeps the buffer
        // itself well-formed; only the bound refuses it.
        let mut owned = vec![b'A'; 300];
        owned.push(0);
        let err = unsafe { super::read_bounded_cstr(owned.as_ptr() as *const std::ffi::c_char) }
            .expect_err("overlong name must be refused");
        assert_eq!(err, pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD);
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
        // W1-L12-08 pin: the named width matches the authoritative
        // `CK_TOKEN_INFO.label` field, not just the literal 32.
        let info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
        assert_eq!(info.label.len(), PKCS11_TOKEN_LABEL_LEN);
        let mut label = [0u8; PKCS11_TOKEN_LABEL_LEN];
        space_pad_into(&mut label, "My Test Token");
        assert_eq!(&label[..13], b"My Test Token");
        assert!(label[13..].iter().all(|&b| b == b' '));
    }

    #[test]
    fn overlong_label_truncated_at_32_bytes() {
        let mut label = [0u8; PKCS11_TOKEN_LABEL_LEN];
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
    fn credential_null_with_nonzero_len_is_rejected() {
        // Proxy-vs-direct finding (pkcs11-check 0.2.1rc1, nss-main,
        // test_login_null_pin_nonzero_length): collapsing (NULL, len>0) to
        // the empty credential let a no-PIN token answer CKR_OK. Fail
        // closed instead; (NULL, 0) still maps to None.
        let err = unsafe { super::try_read_credential_bytes(std::ptr::null(), 8) }.unwrap_err();
        assert_eq!(err, CkRv::ARGUMENTS_BAD);
        assert_eq!(unsafe { super::try_read_credential_bytes(std::ptr::null(), 0) }.unwrap(), None);
        let pin = b"1234";
        assert_eq!(
            unsafe { super::try_read_credential_bytes(pin.as_ptr(), pin.len() as CK_ULONG) }
                .unwrap(),
            Some(pin.as_slice())
        );
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
        // claimed length (the call sites mapped NULL to None before ever
        // reading).
        assert_eq!(unsafe { super::try_read_optional_bytes(std::ptr::null(), 0) }.unwrap(), None);
        assert_eq!(
            unsafe { super::try_read_optional_bytes(std::ptr::null(), CK_ULONG::MAX) }.unwrap(),
            None
        );
    }

    #[test]
    fn try_read_optional_bytes_non_null_len0_is_some_empty() {
        // Matches the historical reader: non-NULL + len 0 → Some(&[]), not None.
        let buf = [0u8; 1];
        let result = unsafe { super::try_read_optional_bytes(buf.as_ptr(), 0) }.unwrap();
        assert_eq!(result, Some([].as_slice()));
    }

    #[test]
    fn checked_extent_pins_arithmetic_rejection_without_dereference() {
        // Pure arithmetic: sentinel addresses are never dereferenced.
        assert_eq!(super::checked_extent(8, 2, 4, 64), Ok(8));
        assert!(super::checked_extent(usize::MAX - 3, 2, 4, 64).is_err());
        assert!(super::checked_extent(8, u64::MAX, 8, 64).is_err());
        assert!(super::checked_extent(8, 65_537, 1, 65_536).is_err());
    }

    #[test]
    fn narrow_u64_to_native_checks_before_storing() {
        // T06: the u32 instantiation pins the checking machinery on any
        // host; the native instantiation is exact for fittable values.
        assert_eq!(super::narrow_u64_to_native::<u32>(0), Ok(0));
        assert_eq!(super::narrow_u64_to_native::<u32>(u32::MAX as u64), Ok(u32::MAX));
        assert_eq!(
            super::narrow_u64_to_native::<u32>(u32::MAX as u64 + 1),
            Err(CkRv::GENERAL_ERROR)
        );
        assert_eq!(super::narrow_u64_to_native::<CK_ULONG>(7), Ok(7 as CK_ULONG));
    }
}

// Mechanism/message parameter conversion tests live in sibling files (M6) so
// this module stays focused on the production helpers; they remain child
// modules of `helpers`, so their `use super::*` still reaches private items.
#[cfg(test)]
mod mechanism_parameter_tests;
#[cfg(test)]
mod mechanism_writeback_tests;
#[cfg(test)]
mod message_parameter_tests;

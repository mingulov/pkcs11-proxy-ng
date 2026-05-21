//! Minimal PKCS#11 stub backend with env-var-controlled delays.
//!
//! Closes `R2-FOLLOWUP-slow-backend` (cross-references
//! `R4-FOLLOWUP-mock-backend`). The R2 resilience round only exercises
//! NETWORK slowness via toxiproxy; this backend gives us BACKEND
//! slowness so the daemon's `request_timeout_secs` and circuit-breaker
//! paths can be tested end-to-end against a real `.so`.
//!
//! Env vars (read on each call):
//!   SLOW_BACKEND_SIGN_DELAY_MS  — sleep this long in every C_Sign /
//!                                 C_SignFinal before returning OK.
//!   SLOW_BACKEND_INIT_DELAY_MS  — sleep this long in C_Initialize.
//!   SLOW_BACKEND_INIT_HANG=1    — block forever in C_Initialize.
//!   SLOW_BACKEND_SIGN_RV_HEX    — instead of OK, return this CK_RV.
//!                                 Hex with or without 0x prefix.
//!                                 Example: 0x2 = CKR_HOST_MEMORY.
//!   SLOW_BACKEND_BREAK_AFTER_CALLS — after this many successful calls,
//!                                 every subsequent call (irrespective
//!                                 of which entry point) returns
//!                                 SLOW_BACKEND_BREAK_RV_HEX. Lets a
//!                                 consumer "warm up" through Login /
//!                                 FindObjects normally, then drive a
//!                                 monotonically-failing tail used by
//!                                 R8 scenario 2 to flip backend health.
//!   SLOW_BACKEND_BREAK_RV_HEX   — CK_RV to return after the break.
//!                                 Defaults to 0x2 (CKR_HOST_MEMORY).
//!
//! Everything else is a stub: minimum valid return values, no real
//! state. Sufficient to drive the daemon's lifecycle but not to do
//! anything cryptographic.

use std::ptr;
use std::time::Duration;

use cryptoki_sys::*;

const CKR_OK: CK_RV = CKR_OK_LITERAL;
const CKR_OK_LITERAL: CK_RV = 0;
const CKR_GENERAL_ERROR_LITERAL: CK_RV = 0x00000005;
const CKR_FUNCTION_NOT_SUPPORTED_LITERAL: CK_RV = 0x00000054;
const CKR_BUFFER_TOO_SMALL_LITERAL: CK_RV = 0x00000150;

const SLOT_ID: CK_SLOT_ID = 0;

fn env_ms(name: &str) -> Option<Duration> {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
}

fn maybe_sleep(env: &str) {
    if let Some(d) = env_ms(env) {
        std::thread::sleep(d);
    }
}

fn maybe_hang(env: &str) {
    if std::env::var(env).is_ok_and(|v| v == "1") {
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
}

// ─── lifecycle ──────────────────────────────────────────────────

unsafe extern "C" fn c_initialize(_args: CK_VOID_PTR) -> CK_RV {
    maybe_hang("SLOW_BACKEND_INIT_HANG");
    maybe_sleep("SLOW_BACKEND_INIT_DELAY_MS");
    CKR_OK
}

unsafe extern "C" fn c_finalize(_args: CK_VOID_PTR) -> CK_RV {
    CKR_OK
}

unsafe extern "C" fn c_get_info(info: CK_INFO_PTR) -> CK_RV {
    if info.is_null() {
        return CKR_GENERAL_ERROR_LITERAL;
    }
    let stub = CK_INFO {
        cryptokiVersion: CK_VERSION { major: 3, minor: 0 },
        manufacturerID: ascii32(b"slow-backend stub"),
        flags: 0,
        libraryDescription: ascii32(b"R6 audit stub backend"),
        libraryVersion: CK_VERSION { major: 0, minor: 1 },
    };
    unsafe { *info = stub; }
    CKR_OK
}

unsafe extern "C" fn c_get_function_list(
    list: *mut *mut CK_FUNCTION_LIST,
) -> CK_RV {
    if list.is_null() {
        return CKR_GENERAL_ERROR_LITERAL;
    }
    unsafe { *list = &raw const FUNCTION_LIST as *mut _; }
    CKR_OK
}

// ─── slot / token / mechanism discovery ─────────────────────────

unsafe extern "C" fn c_get_slot_list(
    _token_present: CK_BBOOL,
    slot_list: CK_SLOT_ID_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    if pul_count.is_null() {
        return CKR_GENERAL_ERROR_LITERAL;
    }
    if slot_list.is_null() {
        unsafe { *pul_count = 1; }
        return CKR_OK;
    }
    if unsafe { *pul_count } < 1 {
        unsafe { *pul_count = 1; }
        return CKR_BUFFER_TOO_SMALL_LITERAL;
    }
    unsafe {
        *slot_list = SLOT_ID;
        *pul_count = 1;
    }
    CKR_OK
}

unsafe extern "C" fn c_get_slot_info(
    _slot_id: CK_SLOT_ID,
    info: CK_SLOT_INFO_PTR,
) -> CK_RV {
    if info.is_null() {
        return CKR_GENERAL_ERROR_LITERAL;
    }
    let stub = CK_SLOT_INFO {
        slotDescription: ascii64(b"slow-backend slot"),
        manufacturerID: ascii32(b"slow-backend stub"),
        flags: CKF_TOKEN_PRESENT,
        hardwareVersion: CK_VERSION { major: 0, minor: 1 },
        firmwareVersion: CK_VERSION { major: 0, minor: 1 },
    };
    unsafe { *info = stub; }
    CKR_OK
}

unsafe extern "C" fn c_get_token_info(
    _slot_id: CK_SLOT_ID,
    info: CK_TOKEN_INFO_PTR,
) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    if info.is_null() {
        return CKR_GENERAL_ERROR_LITERAL;
    }
    let stub = CK_TOKEN_INFO {
        label: ascii32(b"slow-backend token"),
        manufacturerID: ascii32(b"slow-backend stub"),
        model: ascii16(b"stub-0"),
        serialNumber: ascii16(b"deadbeef"),
        flags: CKF_TOKEN_INITIALIZED | CKF_RNG,
        ulMaxSessionCount: 0,
        ulSessionCount: 0,
        ulMaxRwSessionCount: 0,
        ulRwSessionCount: 0,
        ulMaxPinLen: 16,
        ulMinPinLen: 4,
        ulTotalPublicMemory: CK_EFFECTIVELY_INFINITE as CK_ULONG,
        ulFreePublicMemory: CK_EFFECTIVELY_INFINITE as CK_ULONG,
        ulTotalPrivateMemory: CK_EFFECTIVELY_INFINITE as CK_ULONG,
        ulFreePrivateMemory: CK_EFFECTIVELY_INFINITE as CK_ULONG,
        hardwareVersion: CK_VERSION { major: 0, minor: 1 },
        firmwareVersion: CK_VERSION { major: 0, minor: 1 },
        utcTime: ascii16(b"0"),
    };
    unsafe { *info = stub; }
    CKR_OK
}

unsafe extern "C" fn c_get_mechanism_list(
    _slot_id: CK_SLOT_ID,
    _mechanism_list: CK_MECHANISM_TYPE_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    if !pul_count.is_null() {
        unsafe { *pul_count = 0; }
    }
    CKR_OK
}

unsafe extern "C" fn c_get_mechanism_info(
    _slot_id: CK_SLOT_ID,
    _mech_type: CK_MECHANISM_TYPE,
    _info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED_LITERAL
}

// ─── sessions ───────────────────────────────────────────────────

unsafe extern "C" fn c_open_session(
    _slot_id: CK_SLOT_ID,
    _flags: CK_FLAGS,
    _app: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    phsession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    if phsession.is_null() {
        return CKR_GENERAL_ERROR_LITERAL;
    }
    unsafe { *phsession = 1; }
    CKR_OK
}

unsafe extern "C" fn c_close_session(_h: CK_SESSION_HANDLE) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    CKR_OK
}

unsafe extern "C" fn c_login(
    _h: CK_SESSION_HANDLE,
    _user_type: CK_USER_TYPE,
    _pin: CK_UTF8CHAR_PTR,
    _pin_len: CK_ULONG,
) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    CKR_OK
}

unsafe extern "C" fn c_logout(_h: CK_SESSION_HANDLE) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    CKR_OK
}

// ─── sign — the configurable-slowness path ──────────────────────

unsafe extern "C" fn c_sign_init(
    _h: CK_SESSION_HANDLE,
    _mech: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    CKR_OK
}

unsafe extern "C" fn c_sign(
    _h: CK_SESSION_HANDLE,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    sig: CK_BYTE_PTR,
    sig_len: CK_ULONG_PTR,
) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    maybe_sleep("SLOW_BACKEND_SIGN_DELAY_MS");
    // R8 scenario 2: optionally return a forced error code instead
    // of OK. Useful for exercising the daemon's circuit-breaker /
    // backend-health gating.
    if let Some(rv) = env_rv("SLOW_BACKEND_SIGN_RV_HEX") {
        return rv;
    }
    if sig_len.is_null() {
        return CKR_GENERAL_ERROR_LITERAL;
    }
    if sig.is_null() {
        unsafe { *sig_len = 32; }
        return CKR_OK;
    }
    if unsafe { *sig_len } < 32 {
        unsafe { *sig_len = 32; }
        return CKR_BUFFER_TOO_SMALL_LITERAL;
    }
    unsafe {
        ptr::write_bytes(sig, 0u8, 32);
        *sig_len = 32;
    }
    CKR_OK
}

fn env_rv(name: &str) -> Option<CK_RV> {
    let raw = std::env::var(name).ok()?;
    let stripped = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(&raw);
    u64::from_str_radix(stripped, 16).ok()
}

/// Monotonic counter of every backend entry that goes through
/// `count_op_and_maybe_break`. Once it exceeds
/// `SLOW_BACKEND_BREAK_AFTER_CALLS`, every subsequent call returns
/// `SLOW_BACKEND_BREAK_RV_HEX` (default 0x2 = CKR_HOST_MEMORY).
///
/// Used by R8 scenario 2 to flip backend-health to NOT_SERVING
/// after `backend_health_consecutive_failures` consecutive backend
/// errors — without the consumer-side warmup calls (Login,
/// FindObjects, GetAttributeValue, …) registering as Successes and
/// resetting the gate counter between Sign attempts.
static OP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static BROKEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Apply to every backend entry-point. Returns `Some(rv)` if the
/// caller should bail out with that CK_RV; `None` if the call may
/// proceed normally.
///
/// Once the cumulative operation count exceeds
/// `SLOW_BACKEND_BREAK_AFTER_CALLS`, latches a global "broken" flag
/// so every subsequent call — across ALL entry points — fails with
/// `SLOW_BACKEND_BREAK_RV_HEX` (default 0x2 = CKR_HOST_MEMORY). This
/// produces an unbroken stream of Failure events at the daemon
/// without intervening Success calls resetting the gate counter.
fn count_op_and_maybe_break() -> Option<CK_RV> {
    // Already broken — every subsequent call fails fast.
    if BROKEN.load(std::sync::atomic::Ordering::Relaxed) {
        let rv = env_rv("SLOW_BACKEND_BREAK_RV_HEX").unwrap_or(0x2);
        eprintln!("slow_backend: BROKEN, returning rv=0x{rv:x}");
        return Some(rv);
    }
    let break_after = std::env::var("SLOW_BACKEND_BREAK_AFTER_CALLS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let n = OP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    eprintln!("slow_backend: op#{n} (break_after={break_after:?})");
    if let Some(threshold) = break_after
        && n >= threshold
    {
        BROKEN.store(true, std::sync::atomic::Ordering::Relaxed);
        let rv = env_rv("SLOW_BACKEND_BREAK_RV_HEX").unwrap_or(0x2);
        eprintln!("slow_backend: tripped break at op#{n}, latching BROKEN");
        return Some(rv);
    }
    None
}

// ─── everything else: not supported ─────────────────────────────

macro_rules! unsupported {
    ($name:ident, $($arg:ty),*) => {
        #[allow(unused_variables)]
        unsafe extern "C" fn $name($(_: $arg),*) -> CK_RV {
            CKR_FUNCTION_NOT_SUPPORTED_LITERAL
        }
    };
}

unsupported!(c_init_token, CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR);
unsupported!(c_init_pin, CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG);
unsupported!(c_set_pin, CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG);
unsupported!(c_close_all_sessions, CK_SLOT_ID);
unsupported!(c_get_session_info, CK_SESSION_HANDLE, CK_SESSION_INFO_PTR);
unsupported!(c_get_operation_state, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_set_operation_state, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);
unsupported!(c_create_object, CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
unsupported!(c_copy_object, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
unsupported!(c_destroy_object, CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
unsupported!(c_get_object_size, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR);
// Minimal GetAttributeValue: report the fake handle as an RSA-2048
// private key. Sufficient for pkcs11-tool's `--sign` path which
// queries CKA_CLASS + CKA_KEY_TYPE to confirm the object is signable.
// Anything not in our handful of known attrs is reported as
// CKA_TYPE_INVALID per spec.
unsafe extern "C" fn c_get_attribute_value(
    _h: CK_SESSION_HANDLE,
    _obj: CK_OBJECT_HANDLE,
    tmpl: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    if tmpl.is_null() && count > 0 {
        return CKR_GENERAL_ERROR_LITERAL;
    }
    const CKA_CLASS_LITERAL: CK_ATTRIBUTE_TYPE = 0;
    const CKA_KEY_TYPE_LITERAL: CK_ATTRIBUTE_TYPE = 0x100;
    const CKA_LABEL_LITERAL: CK_ATTRIBUTE_TYPE = 0x3;
    const CKA_ID_LITERAL: CK_ATTRIBUTE_TYPE = 0x102;
    const CKA_SIGN_LITERAL: CK_ATTRIBUTE_TYPE = 0x108;
    const CKO_PRIVATE_KEY_LITERAL: CK_ULONG = 3;
    const CKK_RSA_LITERAL: CK_ULONG = 0;

    let mut had_unknown = false;
    for i in 0..count as isize {
        let attr = unsafe { &mut *tmpl.offset(i) };
        match attr.type_ {
            CKA_CLASS_LITERAL => {
                if attr.pValue.is_null() {
                    attr.ulValueLen = std::mem::size_of::<CK_ULONG>() as CK_ULONG;
                } else if attr.ulValueLen as usize >= std::mem::size_of::<CK_ULONG>() {
                    unsafe {
                        *(attr.pValue as *mut CK_ULONG) = CKO_PRIVATE_KEY_LITERAL;
                    }
                    attr.ulValueLen = std::mem::size_of::<CK_ULONG>() as CK_ULONG;
                } else {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                }
            }
            CKA_KEY_TYPE_LITERAL => {
                if attr.pValue.is_null() {
                    attr.ulValueLen = std::mem::size_of::<CK_ULONG>() as CK_ULONG;
                } else if attr.ulValueLen as usize >= std::mem::size_of::<CK_ULONG>() {
                    unsafe {
                        *(attr.pValue as *mut CK_ULONG) = CKK_RSA_LITERAL;
                    }
                    attr.ulValueLen = std::mem::size_of::<CK_ULONG>() as CK_ULONG;
                } else {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                }
            }
            CKA_SIGN_LITERAL => {
                if attr.pValue.is_null() {
                    attr.ulValueLen = 1;
                } else if attr.ulValueLen >= 1 {
                    unsafe {
                        *(attr.pValue as *mut CK_BBOOL) = 1; // CK_TRUE
                    }
                    attr.ulValueLen = 1;
                } else {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                }
            }
            CKA_LABEL_LITERAL | CKA_ID_LITERAL => {
                let label = b"slow-backend-key";
                if attr.pValue.is_null() {
                    attr.ulValueLen = label.len() as CK_ULONG;
                } else if (attr.ulValueLen as usize) >= label.len() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            label.as_ptr(),
                            attr.pValue as *mut u8,
                            label.len(),
                        );
                    }
                    attr.ulValueLen = label.len() as CK_ULONG;
                } else {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                }
            }
            _ => {
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                had_unknown = true;
            }
        }
    }
    if had_unknown {
        // CKR_ATTRIBUTE_TYPE_INVALID
        0x12
    } else {
        CKR_OK
    }
}
// not used — kept for macro slot count compatibility, but the macro
// will be removed for this name below.
unsupported!(c_set_attribute_value, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
// R8 scenarios need real FindObjects support so pkcs11-tool --sign
// can resolve a key handle. We return a fixed handle (42) on first
// invocation, then 0-results on subsequent invocations of the same
// FindObjects sequence. Thread-unsafe; the chaos fixture is
// single-consumer so that's fine.
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
static FIND_RETURNED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn c_find_objects_init(
    _h: CK_SESSION_HANDLE,
    _tmpl: CK_ATTRIBUTE_PTR,
    _count: CK_ULONG,
) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    FIND_RETURNED.store(false, AtomicOrdering::SeqCst);
    CKR_OK
}

unsafe extern "C" fn c_find_objects(
    _h: CK_SESSION_HANDLE,
    out: CK_OBJECT_HANDLE_PTR,
    max: CK_ULONG,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    if pul_count.is_null() {
        return CKR_GENERAL_ERROR_LITERAL;
    }
    let already_returned = FIND_RETURNED.swap(true, AtomicOrdering::SeqCst);
    if already_returned || max == 0 || out.is_null() {
        unsafe { *pul_count = 0; }
        return CKR_OK;
    }
    unsafe {
        *out = 42;
        *pul_count = 1;
    }
    CKR_OK
}

unsafe extern "C" fn c_find_objects_final(_h: CK_SESSION_HANDLE) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    CKR_OK
}
unsupported!(c_encrypt_init, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
unsupported!(c_encrypt, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_encrypt_update, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_encrypt_final, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_decrypt_init, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
unsupported!(c_decrypt, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_decrypt_update, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_decrypt_final, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_digest_init, CK_SESSION_HANDLE, CK_MECHANISM_PTR);
unsupported!(c_digest, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_digest_update, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
unsupported!(c_digest_key, CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
unsupported!(c_digest_final, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
unsafe extern "C" fn c_sign_update(
    _h: CK_SESSION_HANDLE,
    _part: CK_BYTE_PTR,
    _part_len: CK_ULONG,
) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    if let Some(rv) = env_rv("SLOW_BACKEND_SIGN_RV_HEX") {
        return rv;
    }
    CKR_OK
}

unsafe extern "C" fn c_sign_final(
    _h: CK_SESSION_HANDLE,
    sig: CK_BYTE_PTR,
    sig_len: CK_ULONG_PTR,
) -> CK_RV {
    if let Some(rv) = count_op_and_maybe_break() {
        return rv;
    }
    maybe_sleep("SLOW_BACKEND_SIGN_DELAY_MS");
    if let Some(rv) = env_rv("SLOW_BACKEND_SIGN_RV_HEX") {
        return rv;
    }
    if sig_len.is_null() {
        return CKR_GENERAL_ERROR_LITERAL;
    }
    if sig.is_null() {
        unsafe { *sig_len = 32; }
        return CKR_OK;
    }
    if unsafe { *sig_len } < 32 {
        unsafe { *sig_len = 32; }
        return CKR_BUFFER_TOO_SMALL_LITERAL;
    }
    unsafe {
        ptr::write_bytes(sig, 0u8, 32);
        *sig_len = 32;
    }
    CKR_OK
}
unsupported!(c_sign_recover_init, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
unsupported!(c_sign_recover, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_verify_init, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
unsupported!(c_verify, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
unsupported!(c_verify_update, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
unsupported!(c_verify_final, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
unsupported!(c_verify_recover_init, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
unsupported!(c_verify_recover, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_digest_encrypt_update, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_decrypt_digest_update, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_sign_encrypt_update, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_decrypt_verify_update, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_generate_key, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
unsupported!(c_generate_key_pair, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
unsupported!(c_wrap_key, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
unsupported!(c_unwrap_key, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
unsupported!(c_derive_key, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
unsupported!(c_seed_random, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
unsupported!(c_generate_random, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
unsupported!(c_get_function_status, CK_SESSION_HANDLE);
unsupported!(c_cancel_function, CK_SESSION_HANDLE);
unsupported!(c_wait_for_slot_event, CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR);

// ─── helpers ────────────────────────────────────────────────────

fn ascii32(s: &[u8]) -> [CK_UTF8CHAR; 32] {
    let mut out = [b' '; 32];
    let n = s.len().min(32);
    out[..n].copy_from_slice(&s[..n]);
    out
}

fn ascii64(s: &[u8]) -> [CK_UTF8CHAR; 64] {
    let mut out = [b' '; 64];
    let n = s.len().min(64);
    out[..n].copy_from_slice(&s[..n]);
    out
}

fn ascii16(s: &[u8]) -> [CK_UTF8CHAR; 16] {
    let mut out = [b' '; 16];
    let n = s.len().min(16);
    out[..n].copy_from_slice(&s[..n]);
    out
}

const CK_EFFECTIVELY_INFINITE: u64 = 0;

// ─── function-list singleton ────────────────────────────────────

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 40 },
    C_Initialize: Some(c_initialize),
    C_Finalize: Some(c_finalize),
    C_GetInfo: Some(c_get_info),
    C_GetFunctionList: Some(c_get_function_list),
    C_GetSlotList: Some(c_get_slot_list),
    C_GetSlotInfo: Some(c_get_slot_info),
    C_GetTokenInfo: Some(c_get_token_info),
    C_GetMechanismList: Some(c_get_mechanism_list),
    C_GetMechanismInfo: Some(c_get_mechanism_info),
    C_InitToken: Some(c_init_token),
    C_InitPIN: Some(c_init_pin),
    C_SetPIN: Some(c_set_pin),
    C_OpenSession: Some(c_open_session),
    C_CloseSession: Some(c_close_session),
    C_CloseAllSessions: Some(c_close_all_sessions),
    C_GetSessionInfo: Some(c_get_session_info),
    C_GetOperationState: Some(c_get_operation_state),
    C_SetOperationState: Some(c_set_operation_state),
    C_Login: Some(c_login),
    C_Logout: Some(c_logout),
    C_CreateObject: Some(c_create_object),
    C_CopyObject: Some(c_copy_object),
    C_DestroyObject: Some(c_destroy_object),
    C_GetObjectSize: Some(c_get_object_size),
    C_GetAttributeValue: Some(c_get_attribute_value),
    C_SetAttributeValue: Some(c_set_attribute_value),
    C_FindObjectsInit: Some(c_find_objects_init),
    C_FindObjects: Some(c_find_objects),
    C_FindObjectsFinal: Some(c_find_objects_final),
    C_EncryptInit: Some(c_encrypt_init),
    C_Encrypt: Some(c_encrypt),
    C_EncryptUpdate: Some(c_encrypt_update),
    C_EncryptFinal: Some(c_encrypt_final),
    C_DecryptInit: Some(c_decrypt_init),
    C_Decrypt: Some(c_decrypt),
    C_DecryptUpdate: Some(c_decrypt_update),
    C_DecryptFinal: Some(c_decrypt_final),
    C_DigestInit: Some(c_digest_init),
    C_Digest: Some(c_digest),
    C_DigestUpdate: Some(c_digest_update),
    C_DigestKey: Some(c_digest_key),
    C_DigestFinal: Some(c_digest_final),
    C_SignInit: Some(c_sign_init),
    C_Sign: Some(c_sign),
    C_SignUpdate: Some(c_sign_update),
    C_SignFinal: Some(c_sign_final),
    C_SignRecoverInit: Some(c_sign_recover_init),
    C_SignRecover: Some(c_sign_recover),
    C_VerifyInit: Some(c_verify_init),
    C_Verify: Some(c_verify),
    C_VerifyUpdate: Some(c_verify_update),
    C_VerifyFinal: Some(c_verify_final),
    C_VerifyRecoverInit: Some(c_verify_recover_init),
    C_VerifyRecover: Some(c_verify_recover),
    C_DigestEncryptUpdate: Some(c_digest_encrypt_update),
    C_DecryptDigestUpdate: Some(c_decrypt_digest_update),
    C_SignEncryptUpdate: Some(c_sign_encrypt_update),
    C_DecryptVerifyUpdate: Some(c_decrypt_verify_update),
    C_GenerateKey: Some(c_generate_key),
    C_GenerateKeyPair: Some(c_generate_key_pair),
    C_WrapKey: Some(c_wrap_key),
    C_UnwrapKey: Some(c_unwrap_key),
    C_DeriveKey: Some(c_derive_key),
    C_SeedRandom: Some(c_seed_random),
    C_GenerateRandom: Some(c_generate_random),
    C_GetFunctionStatus: Some(c_get_function_status),
    C_CancelFunction: Some(c_cancel_function),
    C_WaitForSlotEvent: Some(c_wait_for_slot_event),
};

// Public entry point — what dlopen sees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    unsafe { c_get_function_list(list) }
}

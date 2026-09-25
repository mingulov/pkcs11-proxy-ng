// CK_ULONG is u64 on 64-bit and u32 on 32-bit; `as u64` casts are intentional
// for cross-platform PKCS#11 portability.
#![allow(clippy::unnecessary_cast)]

use cryptoki_sys::{CK_STATE, CK_UTF8CHAR};
use pkcs11_proxy_ng_types::*;
use zeroize::Zeroizing;

/// D4 (ADR-0011): checked wire-to-native `CK_ULONG` narrowing.
///
/// On a narrow-`CK_ULONG` host, a wire value the native type cannot
/// represent must fail loudly (`CKR_FUNCTION_FAILED`), never truncate —
/// a native module could not have been handed that value either. On a
/// 64-bit host this is an infallible pass-through.
#[allow(clippy::unnecessary_fallible_conversions)] // width-generic: fallible only on narrow hosts
pub(super) fn narrow_wire_ulong(value: u64) -> CkResult<cryptoki_sys::CK_ULONG> {
    cryptoki_sys::CK_ULONG::try_from(value).map_err(|_| CkRv::FUNCTION_FAILED)
}

/// Trim trailing spaces/nulls from a fixed-size byte array and convert to String.
/// Uses lossy UTF-8 decoding so that ISO 8859-1 bytes from real HSMs are preserved
/// rather than silently replaced with an empty string.
pub(super) fn utf8_trim(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end_matches([' ', '\0']).to_string()
}

/// Copy a Rust string into a fixed-width PKCS#11 field, padding with spaces.
pub(super) fn space_pad<const N: usize>(value: &str) -> [CK_UTF8CHAR; N] {
    let mut padded = [b' '; N];
    let value = value.as_bytes();
    let copy_len = value.len().min(N);
    padded[..copy_len].copy_from_slice(&value[..copy_len]);
    padded
}

/// Convert a raw PKCS#11 session state value into the modeled enum.
///
/// Unknown values fall back to `RoPublic` so older consumers continue to work
/// if a backend returns an unexpected value.
pub(super) fn session_state_from_ck(state: CK_STATE) -> CkSessionState {
    match state {
        0 => CkSessionState::RoPublic,
        1 => CkSessionState::RoUser,
        2 => CkSessionState::RwPublic,
        3 => CkSessionState::RwUser,
        4 => CkSessionState::RwSo,
        _ => CkSessionState::RoPublic,
    }
}

/// Owns FFI `CK_ATTRIBUTE` arrays and their backing storage for the duration of an FFI call.
///
/// `CkAttributeValue::Ulong` stores `u64` but `CK_ULONG` is platform-sized (32-bit on 32-bit
/// targets). To pass a correctly-sized value to C, convert to native `CK_ULONG` bytes and
/// keep those bytes alive alongside the attribute array.
mod attrs;
mod mechanism;
mod tests;

pub(in crate::ffi) use attrs::*;
pub(in crate::ffi) use mechanism::*;

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use super::helpers::{
    catch_panics, rv_err, rv_ok, try_read_credential_bytes, try_read_optional_bytes, with_client,
};

/// Q03 phase 2: split the raw `C_InitToken` label read into its
/// legacy string and exact forms — pure over the read bytes, unit
/// tested. NULL yields the empty compat string plus the NULL exact
/// form (never an empty-label rewrite); non-NULL yields the phase-1
/// string (valid → trailing-space-trimmed, invalid → legacy lossy
/// compat, populated exactly as before) plus the raw 32 bytes. The
/// client negotiates which form the daemon receives; the exact form
/// is never normalized here.
fn split_init_token_label(
    raw: Option<&[u8; PKCS11_TOKEN_LABEL_LEN]>,
) -> (String, Option<ExactTokenLabel>) {
    match raw {
        None => (String::new(), Some(ExactTokenLabel::Null)),
        Some(bytes) => {
            let exact = Some(ExactTokenLabel::Bytes(*bytes));
            // `label[32]` is blank-padded, so only trailing ASCII
            // spaces are padding — strip exactly those, never
            // `trim_end`'s general Unicode whitespace: a trailing
            // TAB/NBSP is caller bytes the provider may accept.
            match std::str::from_utf8(bytes) {
                Ok(valid) => (valid.trim_end_matches(' ').to_string(), exact),
                // Legacy lossy compat for the string field ONLY (kept
                // byte-identical to phase 1); the exact bytes above
                // carry the input unmodified and the daemon prefers
                // them whenever the capability was negotiated.
                Err(_) => (String::from_utf8_lossy(bytes).trim_end().to_string(), exact),
            }
        }
    }
}

pub unsafe extern "C" fn c_init_token(
    slot_id: CK_SLOT_ID,
    p_pin: CK_UTF8CHAR_PTR,
    ul_pin_len: CK_ULONG,
    p_label: CK_UTF8CHAR_PTR,
) -> CK_RV {
    catch_panics(|| {
        let so_pin = match unsafe { try_read_credential_bytes(p_pin, ul_pin_len) } {
            Ok(pin) => pin,
            Err(e) => return rv_err(e),
        };
        // PKCS#11 label is 32 bytes, space-padded.
        // W1-L11-10: fallible read like the PIN sites (also rejects an
        // address-range overflow the old panicking reader never checked).
        let raw = if p_label.is_null() {
            None
        } else {
            let raw = match unsafe {
                try_read_optional_bytes(p_label, PKCS11_TOKEN_LABEL_LEN as CK_ULONG)
            } {
                Ok(Some(raw)) => raw,
                // Unreachable for a non-null pointer with a constant
                // in-bounds length, except a hostile near-TOP address.
                Ok(None) | Err(_) => return rv_err(CkRv::ARGUMENTS_BAD),
            };
            let raw: &[u8; PKCS11_TOKEN_LABEL_LEN] = match raw.try_into() {
                Ok(array) => array,
                // Unreachable: the read extent is the same constant.
                Err(_) => return rv_err(CkRv::ARGUMENTS_BAD),
            };
            Some(raw)
        };
        // Q03 phase 2: both forms travel to the client, which
        // negotiates with the daemon — exact when the capability was
        // advertised, lossless string fallback for valid labels, local
        // `CKR_ARGUMENTS_BAD` for NULL/invalid against a legacy peer.
        // No normalization and no silent rewrite happens here.
        let (label, exact) = split_init_token_label(raw);
        let label = InitTokenLabel { text: &label, exact };
        match with_client!(client => client.init_token(CkSlotId(slot_id as u64), so_pin, label)) {
            Ok(()) => rv_ok(),
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_init_pin(
    h_session: CK_SESSION_HANDLE,
    p_pin: CK_UTF8CHAR_PTR,
    ul_pin_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let pin = match unsafe { try_read_credential_bytes(p_pin, ul_pin_len) } {
            Ok(pin) => pin,
            Err(e) => return rv_err(e),
        };
        match with_client!(client => client.init_pin(CkSessionHandle(h_session as u64), pin)) {
            Ok(()) => rv_ok(),
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_set_pin(
    h_session: CK_SESSION_HANDLE,
    p_old_pin: CK_UTF8CHAR_PTR,
    ul_old_len: CK_ULONG,
    p_new_pin: CK_UTF8CHAR_PTR,
    ul_new_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let old_pin = match unsafe { try_read_credential_bytes(p_old_pin, ul_old_len) } {
            Ok(pin) => pin,
            Err(e) => return rv_err(e),
        };
        let new_pin = match unsafe { try_read_credential_bytes(p_new_pin, ul_new_len) } {
            Ok(pin) => pin,
            Err(e) => return rv_err(e),
        };
        match with_client!(client => client.set_pin(CkSessionHandle(h_session as u64), old_pin, new_pin))
        {
            Ok(()) => rv_ok(),
            Err(e) => rv_err(e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::split_init_token_label;
    use pkcs11_proxy_ng_types::{ExactTokenLabel, PKCS11_TOKEN_LABEL_LEN};

    fn pad_label(prefix: &[u8]) -> [u8; PKCS11_TOKEN_LABEL_LEN] {
        let mut label = [b' '; PKCS11_TOKEN_LABEL_LEN];
        label[..prefix.len()].copy_from_slice(prefix);
        label
    }

    /// Q03 phase 2: NULL splits to the empty compat string plus the
    /// NULL exact form — never an empty-label rewrite.
    #[test]
    fn split_null_label_yields_null_exact() {
        assert_eq!(split_init_token_label(None), (String::new(), Some(ExactTokenLabel::Null)));
    }

    /// Q03 phase 2: valid labels split to the trimmed string plus the
    /// raw bytes; blank-pad of the string reproduces the caller bytes
    /// (the lossless-fallback foundation of the interop invariant).
    #[test]
    fn split_valid_labels_keep_raw_bytes() {
        for (text, raw) in [
            ("hello", pad_label(b"hello")),
            ("tökén-héllo", pad_label("tökén-héllo".as_bytes())),
            ("0123456789abcdef0123456789abcdef", *b"0123456789abcdef0123456789abcdef"),
            ("A\t", pad_label(b"A\t")),
            ("B\u{a0}", pad_label("B\u{a0}".as_bytes())),
            ("", [b' '; PKCS11_TOKEN_LABEL_LEN]),
            ("C\0D", pad_label(b"C\0D")),
        ] {
            let (split_text, exact) = split_init_token_label(Some(&raw));
            assert_eq!(split_text, text, "compat string for {raw:02x?}");
            assert_eq!(exact, Some(ExactTokenLabel::Bytes(raw)), "exact bytes for {text:?}");
            let mut repadded = [0u8; PKCS11_TOKEN_LABEL_LEN];
            pkcs11_proxy_ng_types::space_pad_into(&mut repadded, &split_text);
            assert_eq!(repadded, raw, "string fallback reproduces {text:?} byte-exact");
        }
    }

    /// Q03 phase 2: invalid-encoding bytes keep the legacy lossy
    /// compat string (byte-identical to phase 1) while the exact
    /// form carries the raw bytes unmodified.
    #[test]
    fn split_invalid_labels_keep_raw_bytes_beside_lossy_compat() {
        let raw = pad_label(b"BAD\xff");
        let (split_text, exact) = split_init_token_label(Some(&raw));
        assert_eq!(split_text, "BAD\u{fffd}", "compat string stays phase-1 lossy");
        assert_eq!(exact, Some(ExactTokenLabel::Bytes(raw)), "exact bytes stay raw");
    }
}

// ---------------------------------------------------------------------------
// Object discovery
// ---------------------------------------------------------------------------

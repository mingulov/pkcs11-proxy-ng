//! Message-based API (v3.0) parameter structs: read GCM/CCM/
//! Salsa-ChaCha message params from caller memory and write results
//! back (incl. the bits-derived-length wild-read guards).

use cryptoki_sys::*;

use super::*;

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

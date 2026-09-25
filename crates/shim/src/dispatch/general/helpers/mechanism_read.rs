//! Mechanism-parameter FFI readers: validate_mechanism / read_mechanism
//! and the per-shape `read_mechanism_with_shape` match (kept flat by
//! design for auditability), plus the shared raw-parameter utilities.

use super::*;

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
pub(crate) fn embedded_payload_len_ok(len: CK_ULONG) -> bool {
    (len as usize) <= MAX_SERIALIZABLE_BYTES
}

// LLP64 (Windows x64): the app passes these param structs laid out per the
// `#pragma pack(1)` PKCS#11 headers, so the shim's mirror must be packed there
// to read the fields at the right offsets. Natural alignment is correct on
// LP64/ILP32 (ADR-0011 Bucket 2). Fields are read by value (never `&field`),
// so packed access stays E0793-safe.
#[repr(C)]
#[cfg_attr(windows, repr(packed))]
pub(crate) struct CkKmacParams {
    pub(crate) h_key: CK_OBJECT_HANDLE,
    pub(crate) ul_mac_length: CK_ULONG,
    pub(crate) p_customization_string: CK_VOID_PTR,
    pub(crate) ul_customization_string_len: CK_ULONG,
}

#[repr(C)]
#[cfg_attr(windows, repr(packed))] // LLP64: match `#pragma pack(1)` (ADR-0011 Bucket 2)
pub(crate) struct CkMuGenParams {
    pub(crate) h_key: CK_OBJECT_HANDLE,
    pub(crate) p_tr: CK_BYTE_PTR,
    pub(crate) ul_tr_len: CK_ULONG,
    pub(crate) p_ctx: CK_BYTE_PTR,
    pub(crate) ul_ctx_len: CK_ULONG,
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
pub(crate) unsafe fn read_mechanism(p_mechanism: *const CK_MECHANISM) -> CkResult<CkMechanism> {
    let c_mech = unsafe { &*p_mechanism };
    // Hold the Arc until after we have copied the shape string out — the
    // returned `&str` borrows from the Arc, so dropping it before the call
    // below would leave a dangling reference.
    let registry = crate::state::mechanism_registry();
    let shape = registry.param_shape(c_mech.mechanism.into());
    unsafe { read_mechanism_with_shape(c_mech, shape) }
}

pub(crate) unsafe fn read_wrap_key_mechanism(
    p_mechanism: *const CK_MECHANISM,
) -> CkResult<CkMechanism> {
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

pub(crate) unsafe fn read_mechanism_with_shape(
    c_mech: &CK_MECHANISM,
    shape: Option<&str>,
) -> CkResult<CkMechanism> {
    let mech_type = CkMechanismType(c_mech.mechanism as u64);

    if c_mech.pParameter.is_null() || c_mech.ulParameterLen == 0 {
        return Ok(CkMechanism { mechanism_type: mech_type, params: None });
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: caller guarantees pParameter points to a valid
                // CK_RSA_PKCS_PSS_PARAMS and ulParameterLen >= sizeof.
                let pss = unsafe { &*(param_ptr as *const CK_RSA_PKCS_PSS_PARAMS) };
                Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
                    hash_alg: CkMechanismType(pss.hashAlg as u64),
                    mgf: CkMgf(pss.mgf as u64),
                    salt_len: pss.sLen as u64,
                }))
            }
        }

        Some("rsa_oaep") => {
            if param_len < std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: caller guarantees pParameter points to a valid
                // CK_RSA_PKCS_OAEP_PARAMS and ulParameterLen >= sizeof.
                let oaep = unsafe { &*(param_ptr as *const CK_RSA_PKCS_OAEP_PARAMS) };
                if missing_embedded_pointer(oaep.pSourceData, oaep.ulSourceDataLen)
                    || !embedded_payload_len_ok(oaep.ulSourceDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        mgf: CkMgf(oaep.mgf as u64),
                        source: CkOaepSource(oaep.source as u64),
                        source_data: source_data.into(),
                        // F3/D2: (NULL, 0) vs (ptr, 0) must survive the
                        // crossing; (NULL, len > 0) took the Raw path above.
                        source_null: oaep.pSourceData.is_null(),
                    }))
                }
            }
        }

        Some("gcm") => {
            if param_len < std::mem::size_of::<CK_GCM_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_GCM_PARAMS.
                let gcm = unsafe { &*(param_ptr as *const CK_GCM_PARAMS) };
                if missing_embedded_pointer(gcm.pIv, gcm.ulIvLen)
                    || missing_embedded_pointer(gcm.pAAD, gcm.ulAADLen)
                    || !embedded_payload_len_ok(gcm.ulIvLen)
                    || !embedded_payload_len_ok(gcm.ulAADLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        aad: aad.into(),
                        tag_bits: gcm.ulTagBits as u64,
                        // F3/D2: (NULL, 0) vs (ptr, 0) must survive the
                        // crossing; (NULL, len > 0) took the Raw path above.
                        iv_null: gcm.pIv.is_null(),
                        aad_null: gcm.pAAD.is_null(),
                    }))
                }
            }
        }

        Some("ccm") => {
            if param_len < std::mem::size_of::<CK_CCM_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_CCM_PARAMS.
                let ccm = unsafe { &*(param_ptr as *const CK_CCM_PARAMS) };
                if missing_embedded_pointer(ccm.pNonce, ccm.ulNonceLen)
                    || missing_embedded_pointer(ccm.pAAD, ccm.ulAADLen)
                    || !embedded_payload_len_ok(ccm.ulNonceLen)
                    || !embedded_payload_len_ok(ccm.ulAADLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        aad: aad.into(),
                        mac_len: ccm.ulMACLen as u64,
                    }))
                }
            }
        }

        Some("ecdh1_derive") => {
            if param_len < std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_ECDH1_DERIVE_PARAMS.
                let ecdh = unsafe { &*(param_ptr as *const CK_ECDH1_DERIVE_PARAMS) };
                if missing_embedded_pointer(ecdh.pSharedData, ecdh.ulSharedDataLen)
                    || missing_embedded_pointer(ecdh.pPublicData, ecdh.ulPublicDataLen)
                    || !embedded_payload_len_ok(ecdh.ulSharedDataLen)
                    || !embedded_payload_len_ok(ecdh.ulPublicDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        kdf: CkKdf(ecdh.kdf as u64),
                        shared_data: shared_data.into(),
                        public_data,
                    }))
                }
            }
        }

        Some("aes_ctr") => {
            if param_len < std::mem::size_of::<CK_AES_CTR_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_HKDF_PARAMS.
                let hkdf = unsafe { &*(param_ptr as *const CK_HKDF_PARAMS) };
                if missing_embedded_pointer(hkdf.pSalt, hkdf.ulSaltLen)
                    || missing_embedded_pointer(hkdf.pInfo, hkdf.ulInfoLen)
                    || !embedded_payload_len_ok(hkdf.ulSaltLen)
                    || !embedded_payload_len_ok(hkdf.ulInfoLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        prf_hash_mechanism: CkMechanismType(hkdf.prfHashMechanism as u64),
                        salt_type: hkdf.ulSaltType as u64,
                        salt: salt.into(),
                        salt_key_handle: CkObjectHandle(hkdf.hSaltKey as u64),
                        info: info.into(),
                    }))
                }
            }
        }

        Some("eddsa") => {
            if param_len < std::mem::size_of::<CK_EDDSA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_EDDSA_PARAMS.
                let eddsa = unsafe { &*(param_ptr as *const CK_EDDSA_PARAMS) };
                if missing_embedded_pointer(eddsa.pContextData, eddsa.ulContextDataLen)
                    || !embedded_payload_len_ok(eddsa.ulContextDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        context_data: context_data.into(),
                    }))
                }
            }
        }

        Some("chacha20") => {
            if param_len < std::mem::size_of::<CK_CHACHA20_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        Salsa20ChaCha20Poly1305Params { nonce, aad: aad.into() },
                    ))
                }
            }
        }

        Some("aes_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_AES_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe { &*(param_ptr as *const CK_AES_CBC_ENCRYPT_DATA_PARAMS) };
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let data = if s.pData.is_null() || s.length == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(s.pData, s.length as usize) }.to_vec()
                    };
                    Some(CkMechanismParams::AesCbcEncryptData(AesCbcEncryptDataParams {
                        iv: s.iv.to_vec(),
                        data: data.into(),
                    }))
                }
            }
        }

        Some("des_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_DES_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_DES_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe { &*(param_ptr as *const CK_DES_CBC_ENCRYPT_DATA_PARAMS) };
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let data = if s.pData.is_null() || s.length == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(s.pData, s.length as usize) }.to_vec()
                    };
                    Some(CkMechanismParams::DesCbcEncryptData(DesCbcEncryptDataParams {
                        iv: s.iv.to_vec(),
                        data: data.into(),
                    }))
                }
            }
        }

        Some("camellia_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe { &*(param_ptr as *const CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS) };
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let data = if s.pData.is_null() || s.length == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(s.pData, s.length as usize) }.to_vec()
                    };
                    Some(CkMechanismParams::CamelliaCbcEncryptData(CamelliaCbcEncryptDataParams {
                        iv: s.iv.to_vec(),
                        data: data.into(),
                    }))
                }
            }
        }

        Some("aria_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_ARIA_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe { &*(param_ptr as *const CK_ARIA_CBC_ENCRYPT_DATA_PARAMS) };
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let data = if s.pData.is_null() || s.length == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(s.pData, s.length as usize) }.to_vec()
                    };
                    Some(CkMechanismParams::AriaCbcEncryptData(AriaCbcEncryptDataParams {
                        iv: s.iv.to_vec(),
                        data: data.into(),
                    }))
                }
            }
        }

        Some("seed_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_SEED_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_SEED_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe { &*(param_ptr as *const CK_SEED_CBC_ENCRYPT_DATA_PARAMS) };
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let data = if s.pData.is_null() || s.length == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(s.pData, s.length as usize) }.to_vec()
                    };
                    Some(CkMechanismParams::SeedCbcEncryptData(SeedCbcEncryptDataParams {
                        iv: s.iv.to_vec(),
                        data: data.into(),
                    }))
                }
            }
        }

        Some("mac_general") => {
            if param_len < std::mem::size_of::<CK_MAC_GENERAL_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a CK_OBJECT_HANDLE
                // (which is a CK_ULONG).
                let val = unsafe { *(param_ptr as *const CK_OBJECT_HANDLE) };
                Some(CkMechanismParams::ObjectHandle(ObjectHandleParam {
                    handle: CkObjectHandle(val as u64),
                }))
            }
        }

        Some("extract") => {
            if param_len < std::mem::size_of::<CK_EXTRACT_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let val = unsafe { *(param_ptr as *const CK_EXTRACT_PARAMS) };
                Some(CkMechanismParams::Extract(ExtractParams { bit_position: val as u64 }))
            }
        }

        Some("key_derivation_string") => {
            if param_len < std::mem::size_of::<CK_KEY_DERIVATION_STRING_DATA>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_KEY_DERIVATION_STRING_DATA.
                let kds = unsafe { &*(param_ptr as *const CK_KEY_DERIVATION_STRING_DATA) };
                if missing_embedded_pointer(kds.pData, kds.ulLen)
                    || !embedded_payload_len_ok(kds.ulLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let data = if kds.pData.is_null() || kds.ulLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(kds.pData, kds.ulLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
                        data: data.into(),
                    }))
                }
            }
        }

        Some("gcm_wrap") => {
            if param_len < std::mem::size_of::<CK_GCM_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_GCM_WRAP_PARAMS.
                let gw = unsafe { &*(param_ptr as *const CK_GCM_WRAP_PARAMS) };
                if missing_embedded_pointer(gw.pIv, gw.ulIvLen)
                    || missing_embedded_pointer(gw.pAAD, gw.ulAADLen)
                    || !embedded_payload_len_ok(gw.ulIvLen)
                    || !embedded_payload_len_ok(gw.ulAADLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        iv_generator: CkGeneratorFunction(gw.ivGenerator as u64),
                        aad: aad.into(),
                        tag_bits: gw.ulTagBits as u64,
                    }))
                }
            }
        }

        Some("ccm_wrap") => {
            if param_len < std::mem::size_of::<CK_CCM_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_CCM_WRAP_PARAMS.
                let cw = unsafe { &*(param_ptr as *const CK_CCM_WRAP_PARAMS) };
                if missing_embedded_pointer(cw.pNonce, cw.ulNonceLen)
                    || missing_embedded_pointer(cw.pAAD, cw.ulAADLen)
                    || !embedded_payload_len_ok(cw.ulNonceLen)
                    || !embedded_payload_len_ok(cw.ulAADLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        nonce_generator: CkGeneratorFunction(cw.nonceGenerator as u64),
                        aad: aad.into(),
                        mac_len: cw.ulMACLen as u64,
                    }))
                }
            }
        }

        Some("rc5") => {
            if param_len < std::mem::size_of::<CK_RC5_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let rc5 = unsafe { &*(param_ptr as *const CK_RC5_CBC_PARAMS) };
                if missing_embedded_pointer(rc5.pIv, rc5.ulIvLen)
                    || !embedded_payload_len_ok(rc5.ulIvLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_XEDDSA_PARAMS.
                let xed = unsafe { &*(param_ptr as *const CK_XEDDSA_PARAMS) };
                Some(CkMechanismParams::Xeddsa(XeddsaParams {
                    hash: CkMechanismType(xed.hash as u64),
                }))
            }
        }

        Some("tls_mac") => {
            if param_len < std::mem::size_of::<CK_TLS_MAC_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_TLS_MAC_PARAMS.
                let tls = unsafe { &*(param_ptr as *const CK_TLS_MAC_PARAMS) };
                Some(CkMechanismParams::TlsMac(TlsMacParams {
                    prf_hash_mechanism: CkMechanismType(tls.prfHashMechanism as u64),
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: param_ptr is valid for at least expected_size bytes.
                // Unaligned-safe: a pack(1) caller struct may place 8-byte
                // fields at misaligned offsets (W1-C6-03, W1-L1-01).
                let aes_key_bits = unsafe { (param_ptr as *const CK_ULONG).read_unaligned() };
                let oaep_ptr_offset = std::mem::size_of::<CK_ULONG>();
                let oaep_ptr = unsafe {
                    (param_ptr.add(oaep_ptr_offset) as *const *const CK_RSA_PKCS_OAEP_PARAMS)
                        .read_unaligned()
                };
                if oaep_ptr.is_null() {
                    Some(CkMechanismParams::Raw(RawMechanismParams {
                        data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                    }))
                } else {
                    // Safety: oaep_ptr is non-null and points to a valid
                    // CK_RSA_PKCS_OAEP_PARAMS (caller contract).
                    let oaep = unsafe { &*oaep_ptr };
                    if missing_embedded_pointer(oaep.pSourceData as *const u8, oaep.ulSourceDataLen)
                        || !embedded_payload_len_ok(oaep.ulSourceDataLen)
                    {
                        Some(raw_mechanism_params(param_ptr, param_len)?)
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
                                mgf: CkMgf(oaep.mgf as u64),
                                source: CkOaepSource(oaep.source as u64),
                                source_data: source_data.into(),
                                source_null: oaep.pSourceData.is_null(),
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Unaligned-safe: see the rsa_aes_key_wrap arm above (W1-C6-03,
                // W1-L1-01). Offsets unchanged.
                let hedge_variant = unsafe { (param_ptr as *const CK_ULONG).read_unaligned() };
                let ptr_offset = std::mem::size_of::<CK_ULONG>();
                let ctx_ptr =
                    unsafe { (param_ptr.add(ptr_offset) as *const *const u8).read_unaligned() };
                let len_offset = ptr_offset + std::mem::size_of::<*const u8>();
                let ctx_len =
                    unsafe { (param_ptr.add(len_offset) as *const CK_ULONG).read_unaligned() };
                if missing_embedded_pointer(ctx_ptr, ctx_len) || !embedded_payload_len_ok(ctx_len) {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let context = if ctx_ptr.is_null() || ctx_len == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(ctx_ptr, ctx_len as usize) }.to_vec()
                    };
                    let hash = if param_len >= hash_size {
                        let hash_offset = len_offset + std::mem::size_of::<CK_ULONG>();
                        unsafe {
                            (param_ptr.add(hash_offset) as *const CK_ULONG).read_unaligned() as u64
                        }
                    } else {
                        0
                    };
                    Some(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                        hedge_variant: hedge_variant as u64,
                        context: context.into(),
                        hash: CkMechanismType(hash),
                    }))
                }
            }
        }

        Some("kmac") => {
            if param_len < std::mem::size_of::<CkKmacParams>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CkKmacParams) };
                if missing_embedded_pointer(
                    p.p_customization_string as *const u8,
                    p.ul_customization_string_len,
                ) || !embedded_payload_len_ok(p.ul_customization_string_len)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        key_handle: CkObjectHandle(p.h_key as u64),
                        mac_length: p.ul_mac_length as u64,
                        customization_string: customization_string.into(),
                    }))
                }
            }
        }

        Some("mu_gen") => {
            if param_len < std::mem::size_of::<CkMuGenParams>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CkMuGenParams) };
                if missing_embedded_pointer(p.p_tr, p.ul_tr_len)
                    || missing_embedded_pointer(p.p_ctx, p.ul_ctx_len)
                    || !embedded_payload_len_ok(p.ul_tr_len)
                    || !embedded_payload_len_ok(p.ul_ctx_len)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        key_handle: CkObjectHandle(p.h_key as u64),
                        tr: tr.into(),
                        context: context.into(),
                    }))
                }
            }
        }

        Some("pkcs5_pbkd2") => {
            if param_len < std::mem::size_of::<CK_PKCS5_PBKD2_PARAMS2>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        salt_source: CkPbkdf2SaltSource(p.saltSource as u64),
                        salt_source_data: salt_source_data.into(),
                        iterations: p.iterations as u64,
                        prf: CkPbkdf2Prf(p.prf as u64),
                        prf_data: prf_data.into(),
                        password: password.into(),
                    }))
                }
            }
        }

        Some("wtls_master_key_derive") => {
            if param_len < std::mem::size_of::<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        digest_mechanism: CkMechanismType(p.DigestMechanism as u64),
                        random_info: WtlsRandomData { client_random, server_random },
                        version,
                    }))
                }
            }
        }

        Some("wtls_prf") => {
            if param_len < std::mem::size_of::<CK_WTLS_PRF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_WTLS_PRF_PARAMS) };
                if missing_embedded_pointer(p.pSeed, p.ulSeedLen)
                    || missing_embedded_pointer(p.pLabel, p.ulLabelLen)
                    || !embedded_payload_len_ok(p.ulSeedLen)
                    || !embedded_payload_len_ok(p.ulLabelLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        digest_mechanism: CkMechanismType(p.DigestMechanism as u64),
                        seed: seed.into(),
                        label: label.into(),
                        output_len,
                        // W1-C5-01: `pOutput` is OUT — never read the
                        // caller's uninitialized buffer into the request.
                        output: Vec::new().into(),
                    }))
                }
            }
        }

        Some("wtls_key_mat") => {
            if param_len < std::mem::size_of::<CK_WTLS_KEY_MAT_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let iv_len = requested_iv_len;
                    let output = unsafe { &*p.pReturnedKeyMaterial };
                    if missing_embedded_pointer(output.pIV, iv_len as CK_ULONG) {
                        Some(raw_mechanism_params(param_ptr, param_len)?)
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
                            digest_mechanism: CkMechanismType(p.DigestMechanism as u64),
                            mac_size_bits: p.ulMacSizeInBits as u64,
                            key_size_bits: p.ulKeySizeInBits as u64,
                            iv_size_bits: p.ulIVSizeInBits as u64,
                            sequence_number: p.ulSequenceNumber as u64,
                            is_export: p.bIsExport != 0,
                            random_info: WtlsRandomData { client_random, server_random },
                            mac_secret_handle: CkObjectHandle(output.hMacSecret as u64),
                            key_handle: CkObjectHandle(output.hKey as u64),
                            iv,
                        }))
                    }
                }
            }
        }

        Some("tls12_master_key_derive") => {
            if param_len < std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        prf_hash_mechanism: CkMechanismType(p.prfHashMechanism as u64),
                    }))
                }
            }
        }

        Some("tls_prf") => {
            if param_len < std::mem::size_of::<CK_TLS_PRF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_TLS_PRF_PARAMS) };
                if missing_embedded_pointer(p.pSeed, p.ulSeedLen)
                    || missing_embedded_pointer(p.pLabel, p.ulLabelLen)
                    || !embedded_payload_len_ok(p.ulSeedLen)
                    || !embedded_payload_len_ok(p.ulLabelLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                    Some(CkMechanismParams::TlsPrf(TlsPrfParams {
                        seed: seed.into(),
                        label: label.into(),
                        output_len,
                        // W1-C5-01: `pOutput` is OUT — never read the
                        // caller's uninitialized buffer into the request.
                        output: Vec::new().into(),
                    }))
                }
            }
        }

        Some("tls_kdf") => {
            if param_len < std::mem::size_of::<CK_TLS_KDF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                        label: label.into(),
                        random_info: SslRandomData { client_random, server_random },
                        context_data: context_data.into(),
                    }))
                }
            }
        }

        Some("ssl3_master_key_derive") => {
            if param_len < std::mem::size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p =
                    unsafe { &*(param_ptr as *const CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pSessionHash, p.ulSessionHashLen)
                    || !embedded_payload_len_ok(p.ulSessionHashLen)
                {
                    return Ok(CkMechanism {
                        mechanism_type: mech_type,
                        params: Some(raw_mechanism_params(param_ptr, param_len)?),
                    });
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
                        prf_hash_mechanism: CkMechanismType(p.prfHashMechanism as u64),
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let output = unsafe { &*p.pReturnedKeyMaterial };
                    let iv_len = requested_iv_len;
                    if missing_embedded_pointer(output.pIVClient, iv_len as CK_ULONG)
                        || missing_embedded_pointer(output.pIVServer, iv_len as CK_ULONG)
                    {
                        Some(raw_mechanism_params(param_ptr, param_len)?)
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
                            prf_hash_mechanism: CkMechanismType(prf_hash_mechanism),
                            client_mac_secret_handle: CkObjectHandle(
                                output.hClientMacSecret as u64,
                            ),
                            server_mac_secret_handle: CkObjectHandle(
                                output.hServerMacSecret as u64,
                            ),
                            client_key_handle: CkObjectHandle(output.hClientKey as u64),
                            server_key_handle: CkObjectHandle(output.hServerKey as u64),
                            client_iv: client_iv.into(),
                            server_iv: server_iv.into(),
                        }))
                    }
                }
            }
        }

        Some("pbe") => {
            if param_len < std::mem::size_of::<CK_PBE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_PBE_PARAMS) };
                if !embedded_payload_len_ok(p.ulPasswordLen)
                    || !embedded_payload_len_ok(p.ulSaltLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        init_vector: init_vector.into(),
                        password: password.into(),
                        salt: salt.into(),
                        iteration: p.ulIteration as u64,
                    }))
                }
            }
        }

        Some("ecdh_aes_key_wrap") => {
            if param_len < std::mem::size_of::<CK_ECDH_AES_KEY_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_ECDH_AES_KEY_WRAP_PARAMS) };
                if missing_embedded_pointer(p.pSharedData, p.ulSharedDataLen)
                    || !embedded_payload_len_ok(p.ulSharedDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        kdf: CkKdf(p.kdf as u64),
                        shared_data: shared_data.into(),
                    }))
                }
            }
        }

        Some("ecdh2_derive") => {
            if param_len < std::mem::size_of::<CK_ECDH2_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        kdf: CkKdf(p.kdf as u64),
                        shared_data: shared_data.into(),
                        public_data,
                        private_data_len: p.ulPrivateDataLen as u64,
                        private_data_handle: CkObjectHandle(p.hPrivateData as u64),
                        public_data2,
                    }))
                }
            }
        }

        Some("ecmqv_derive") => {
            if param_len < std::mem::size_of::<CK_ECMQV_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        kdf: CkKdf(p.kdf as u64),
                        shared_data: shared_data.into(),
                        public_data,
                        private_data_len: p.ulPrivateDataLen as u64,
                        private_data_handle: CkObjectHandle(p.hPrivateData as u64),
                        public_data2,
                        public_key_handle: CkObjectHandle(p.publicKey as u64),
                    }))
                }
            }
        }

        Some("x942_dh1_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_DH1_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_X9_42_DH1_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pOtherInfo, p.ulOtherInfoLen)
                    || missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulOtherInfoLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        kdf: CkKdf(p.kdf as u64),
                        other_info: other_info.into(),
                        public_data,
                    }))
                }
            }
        }

        Some("x942_dh2_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_DH2_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        kdf: CkKdf(p.kdf as u64),
                        other_info: other_info.into(),
                        public_data,
                        private_data_len: p.ulPrivateDataLen as u64,
                        private_data_handle: CkObjectHandle(p.hPrivateData as u64),
                        public_data2,
                    }))
                }
            }
        }

        Some("x942_mqv_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_MQV_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        kdf: CkKdf(p.kdf as u64),
                        other_info: other_info.into(),
                        public_data,
                        private_data_len: p.ulPrivateDataLen as u64,
                        private_data_handle: CkObjectHandle(p.hPrivateData as u64),
                        public_data2,
                        public_key_handle: CkObjectHandle(p.publicKey as u64),
                    }))
                }
            }
        }

        Some("gostr3410_derive") => {
            if param_len < std::mem::size_of::<CK_GOSTR3410_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_GOSTR3410_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || missing_embedded_pointer(p.pUKM, p.ulUKMLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulUKMLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        kdf: CkKdf(p.kdf as u64),
                        public_data,
                        ukm,
                    }))
                }
            }
        }

        Some("gostr3410_key_wrap") => {
            if param_len < std::mem::size_of::<CK_GOSTR3410_KEY_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_GOSTR3410_KEY_WRAP_PARAMS) };
                if missing_embedded_pointer(p.pWrapOID, p.ulWrapOIDLen)
                    || missing_embedded_pointer(p.pUKM, p.ulUKMLen)
                    || !embedded_payload_len_ok(p.ulWrapOIDLen)
                    || !embedded_payload_len_ok(p.ulUKMLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        key_handle: CkObjectHandle(p.hKey as u64),
                    }))
                }
            }
        }

        Some("key_wrap_set_oaep") => {
            if param_len < std::mem::size_of::<CK_KEY_WRAP_SET_OAEP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_KEY_WRAP_SET_OAEP_PARAMS) };
                if missing_embedded_pointer(p.pX, p.ulXLen) || !embedded_payload_len_ok(p.ulXLen) {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let x = if p.pX.is_null() || p.ulXLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pX, p.ulXLen as usize) }.to_vec()
                    };
                    Some(CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams {
                        bc: p.bBC as u32,
                        x: x.into(),
                    }))
                }
            }
        }

        Some("kea_derive") => {
            if param_len < std::mem::size_of::<CK_KEA_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_KEA_DERIVE_PARAMS) };
                if !embedded_payload_len_ok(p.ulRandomLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_IKE_PRF_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pNi, p.ulNiLen)
                    || missing_embedded_pointer(p.pNr, p.ulNrLen)
                    || !embedded_payload_len_ok(p.ulNiLen)
                    || !embedded_payload_len_ok(p.ulNrLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                        data_as_key: p.bDataAsKey != 0,
                        rekey: p.bRekey != 0,
                        ni: ni.into(),
                        nr: nr.into(),
                        new_key_handle: CkObjectHandle(p.hNewKey as u64),
                    }))
                }
            }
        }

        Some("ike1_prf_derive") => {
            if param_len < std::mem::size_of::<CK_IKE1_PRF_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_IKE1_PRF_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pCKYi, p.ulCKYiLen)
                    || missing_embedded_pointer(p.pCKYr, p.ulCKYrLen)
                    || !embedded_payload_len_ok(p.ulCKYiLen)
                    || !embedded_payload_len_ok(p.ulCKYrLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                        has_prev_key: p.bHasPrevKey != 0,
                        keygxy_handle: CkObjectHandle(p.hKeygxy as u64),
                        prev_key_handle: CkObjectHandle(p.hPrevKey as u64),
                        ckyi: ckyi.into(),
                        ckyr: ckyr.into(),
                        key_number: p.keyNumber as u32,
                    }))
                }
            }
        }

        Some("ike1_extended_derive") => {
            if param_len < std::mem::size_of::<CK_IKE1_EXTENDED_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_IKE1_EXTENDED_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pExtraData, p.ulExtraDataLen)
                    || !embedded_payload_len_ok(p.ulExtraDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                        has_keygxy: p.bHasKeygxy != 0,
                        keygxy_handle: CkObjectHandle(p.hKeygxy as u64),
                        extra_data: extra_data.into(),
                    }))
                }
            }
        }

        Some("ike2_prf_plus_derive") => {
            if param_len < std::mem::size_of::<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_IKE2_PRF_PLUS_DERIVE_PARAMS) };
                if missing_embedded_pointer(p.pSeedData, p.ulSeedDataLen)
                    || !embedded_payload_len_ok(p.ulSeedDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let seed_data = if p.pSeedData.is_null() || p.ulSeedDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pSeedData, p.ulSeedDataLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::Ike2PrfPlusDerive(Ike2PrfPlusDeriveParams {
                        prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                        has_seed_key: p.bHasSeedKey != 0,
                        seed_key_handle: CkObjectHandle(p.hSeedKey as u64),
                        seed_data: seed_data.into(),
                    }))
                }
            }
        }

        Some("kip") => {
            if param_len < std::mem::size_of::<CK_KIP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let mechanism = unsafe { read_mechanism(p.pMechanism) }?;
                    let seed = if p.pSeed.is_null() || p.ulSeedLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pSeed, p.ulSeedLen as usize) }
                            .to_vec()
                    };
                    Some(CkMechanismParams::Kip(KipParams {
                        mechanism: Box::new(mechanism),
                        key_handle: CkObjectHandle(p.hKey as u64),
                        seed: seed.into(),
                    }))
                }
            }
        }

        Some("otp") => {
            if param_len < std::mem::size_of::<CK_OTP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { &*(param_ptr as *const CK_OTP_PARAMS) };
                if missing_embedded_pointer(p.pParams, p.ulCount)
                    || p.ulCount as usize > MAX_TEMPLATE_COUNT
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else if p.pParams.is_null() || p.ulCount == 0 {
                    Some(CkMechanismParams::Otp(OtpParams { params: Vec::new() }))
                } else {
                    let params =
                        unsafe { std::slice::from_raw_parts(p.pParams, p.ulCount as usize) };
                    if params.iter().any(|param| {
                        missing_embedded_pointer(param.pValue as *const u8, param.ulValueLen)
                            || !embedded_payload_len_ok(param.ulValueLen)
                    }) {
                        Some(raw_mechanism_params(param_ptr, param_len)?)
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
                                    OtpParam { type_: param.type_ as u64, value: value.into() }
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        password: password.into(),
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
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
                        old_wrapped_x: old_wrapped_x.into(),
                        old_password: old_password.into(),
                        old_public_data: old_public_data.into(),
                        old_random_a: old_random_a.into(),
                        new_password: new_password.into(),
                        new_public_data: new_public_data.into(),
                        new_random_a: new_random_a.into(),
                    }))
                }
            }
        }

        Some("sp800_108_kdf") => {
            if param_len < std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                        prf_type: CkMechanismType(p.prfType as u64),
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
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
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
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let iv = if p.pIV.is_null() || p.ulIVLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(p.pIV, p.ulIVLen as usize) }.to_vec()
                    };
                    Some(CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                        prf_type: CkMechanismType(p.prfType as u64),
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
            data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
        })),
    };

    Ok(CkMechanism { mechanism_type: mech_type, params })
}

pub(crate) fn gcm_iv_buffer_len(gcm: &CK_GCM_PARAMS) -> u64 {
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
            PrfDataParam { type_: param.type_ as u64, value: value.into() }
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
            Sp800108DerivedKey { template, key_handle: CkObjectHandle(key_handle) }
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

pub(crate) fn gcm_iv_write_capacity(gcm: &CK_GCM_PARAMS) -> usize {
    if gcm.ulIvLen > 0 {
        gcm.ulIvLen as usize
    } else {
        (((gcm.ulIvBits as u64).saturating_add(7)) / 8) as usize
    }
}

pub(crate) fn missing_embedded_pointer<T>(ptr: *const T, len: CK_ULONG) -> bool {
    ptr.is_null() && len != 0
}

pub(crate) fn raw_mechanism_params(
    param_ptr: *mut std::ffi::c_void,
    param_len: usize,
) -> CkResult<CkMechanismParams> {
    Ok(CkMechanismParams::Raw(RawMechanismParams {
        data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
    }))
}

/// Read raw bytes from a C void pointer into a Vec.
///
/// Lengths above `MAX_MECHANISM_PARAM_STRUCT_LEN` are an explicit
/// `MECHANISM_PARAM_INVALID` error (W1-L12-06: never conflate overlong
/// with empty). The `validate_mechanism` entry gate already rejects such
/// lengths, so the error arm is unreachable in production and exists as
/// defense-in-depth at the API boundary.
///
/// # Safety
///
/// `ptr` must point to a readable buffer of at least `len` bytes, except
/// that no memory is accessed when `len` is overlong (the error returns
/// before any dereference) or zero.
pub(crate) unsafe fn read_raw_bytes(ptr: *mut std::ffi::c_void, len: usize) -> CkResult<Vec<u8>> {
    if len > MAX_MECHANISM_PARAM_STRUCT_LEN {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }.to_vec())
}

// ---------------------------------------------------------------------------
// Message crypto parameter helpers (CK_*_MESSAGE_PARAMS ↔ structured proto)
// ---------------------------------------------------------------------------

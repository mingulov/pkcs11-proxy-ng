//! Output-parameter writeback: copying daemon-returned mechanism
//! output params (generated GCM IVs, SP800-108 derived-key handles)
//! back into the caller's parameter structs.

use super::*;

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
                    ssl3_out.client_iv.expose(|raw| unsafe {
                        std::ptr::copy_nonoverlapping(raw.as_ptr(), output.pIVClient, copy_len);
                    });
                }
            }
            if !output.pIVServer.is_null() {
                let copy_len = ssl3_out.server_iv.len().min(capacity);
                if copy_len > 0 {
                    ssl3_out.server_iv.expose(|raw| unsafe {
                        std::ptr::copy_nonoverlapping(raw.as_ptr(), output.pIVServer, copy_len);
                    });
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
                pbe_out.init_vector.expose(|raw| unsafe {
                    std::ptr::copy_nonoverlapping(raw.as_ptr(), pbe.pInitVector, n);
                });
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

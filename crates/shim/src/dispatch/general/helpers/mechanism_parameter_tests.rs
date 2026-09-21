use super::{
    MAX_MECHANISM_PARAM_STRUCT_LEN, read_mechanism, read_mechanism_with_shape, read_raw_bytes,
    read_wrap_key_mechanism, validate_mechanism, write_mechanism_output_params,
};
use cryptoki_sys::*;
use pkcs11_proxy_ng_types::{
    CcmParams, CcmWrapParams, ChaCha20Params, CkAttributeType, CkAttributeValue,
    CkGeneratorFunction, CkKdf, CkMechanismParams, CkMechanismType, CkMgf, CkOaepSource,
    CkObjectHandle, CkPbkdf2Prf, CkPbkdf2SaltSource, CkRv, ExtractParams, GcmParams, GcmWrapParams,
    KeyWrapSetOaepParams, KmacParams, MechanismRegistry, MuGenParams, RsaAesKeyWrapParams,
    RsaPkcsOaepParams, RsaPkcsPssParams, Salsa20ChaCha20Poly1305Params, SecretBytes,
    SignAdditionalContext, Sp800108DerivedKey, Sp800108FeedbackKdfParams,
};

fn ensure_registry() {
    let registry = MechanismRegistry::load(None).expect("default mechanism registry");
    crate::state::replace_mechanism_registry(registry);
}

unsafe fn read_ck_mechanism(mechanism: &CK_MECHANISM) -> CkMechanismParams {
    ensure_registry();
    unsafe { read_mechanism(mechanism) }.expect("read mechanism").params.expect("mechanism params")
}

#[test]
fn read_raw_bytes_overlong_errors_while_empty_stays_empty() {
    // W1-L12-06: the raw-bytes reader must not conflate "overlong" with
    // "empty" — overlong is an explicit MECHANISM_PARAM_INVALID error
    // (matching the `validate_mechanism` entry gate), empty stays empty.
    let overlong = MAX_MECHANISM_PARAM_STRUCT_LEN + 1;
    // No memory is touched on the overlong path, so a null pointer is
    // a valid probe for the length check itself.
    let err = unsafe { read_raw_bytes(std::ptr::null_mut(), overlong) }
        .expect_err("overlong raw params must error, not read");
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);

    // Empty stays empty: len 0 reads nothing.
    let mut sentinel = 0xA5u8;
    let empty =
        unsafe { read_raw_bytes(std::ptr::addr_of_mut!(sentinel).cast(), 0) }.expect("empty read");
    assert!(empty.is_empty());

    // Ordinary lengths still read through.
    let data = [0x5Au8; 16];
    let out = unsafe { read_raw_bytes(data.as_ptr() as *mut std::ffi::c_void, data.len()) }
        .expect("bounded read");
    assert_eq!(out, data);
}

#[test]
fn unsafe_official_lengthless_parameter_shapes_are_rejected_before_shim_read() {
    ensure_registry();
    let mut opaque = [0xA5u8];

    for mechanism_type in [
        CKM_CMS_SIG,
        CKM_X3DH_INITIALIZE,
        CKM_X3DH_RESPOND,
        CKM_X2RATCHET_INITIALIZE,
        CKM_X2RATCHET_RESPOND,
    ] {
        let mechanism = CK_MECHANISM {
            mechanism: mechanism_type,
            pParameter: opaque.as_mut_ptr() as CK_VOID_PTR,
            ulParameterLen: opaque.len() as CK_ULONG,
        };

        let rv = unsafe { validate_mechanism(&mechanism) };

        assert_eq!(
            rv,
            CkRv::MECHANISM_PARAM_INVALID.0 as CK_RV,
            "0x{mechanism_type:08X} should reject unmodeled caller-owned pointer shapes"
        );
    }
}

#[test]
fn reads_common_mechanism_parameter_structs() {
    let mut source_data = [0xA0u8, 0xA1, 0xA2];
    let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        source: 1,
        pSourceData: source_data.as_mut_ptr() as CK_VOID_PTR,
        ulSourceDataLen: source_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_OAEP.0 as CK_MECHANISM_TYPE,
        pParameter: &mut oaep as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams { source_data, .. }) => {
            assert_eq!(source_data, SecretBytes::copy_from_slice(&[0xA0, 0xA1, 0xA2]));
        }
        other => panic!("unexpected OAEP params: {other:?}"),
    }

    let mut pss = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        sLen: 32,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_PSS.0 as CK_MECHANISM_TYPE,
        pParameter: &mut pss as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams { hash_alg, salt_len, .. }) => {
            assert_eq!(hash_alg, CkMechanismType::SHA256);
            assert_eq!(salt_len, 32);
        }
        other => panic!("unexpected PSS params: {other:?}"),
    }

    let mut iv = [0x10; 12];
    let mut aad = [0xAA, 0xBB, 0xCC];
    let mut gcm = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvBits: 96,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
        pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Gcm(GcmParams { iv, iv_bits, iv_buffer_len, aad, tag_bits, .. }) => {
            assert_eq!(iv, [0x10; 12]);
            assert_eq!(iv_bits, 96);
            assert_eq!(iv_buffer_len, 12);
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xAA, 0xBB, 0xCC]));
            assert_eq!(tag_bits, 128);
        }
        other => panic!("unexpected GCM params: {other:?}"),
    }

    let mut cbc_iv = [0x55u8; 16];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_CBC.0 as CK_MECHANISM_TYPE,
        pParameter: cbc_iv.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: cbc_iv.len() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Iv(params) => assert_eq!(params.iv, [0x55; 16]),
        other => panic!("unexpected CBC IV params: {other:?}"),
    }

    const CKM_AES_CTR: CK_MECHANISM_TYPE = 0x0000_1086;
    let mut ctr = CK_AES_CTR_PARAMS { ulCounterBits: 128, cb: [0x33; 16] };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CTR,
        pParameter: &mut ctr as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_AES_CTR_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::AesCtr(params) => {
            assert_eq!(params.counter_bits, 128);
            assert_eq!(params.cb, [0x33; 16]);
        }
        other => panic!("unexpected CTR params: {other:?}"),
    }
}

#[test]
fn reads_handle_string_and_sign_context_parameter_structs() {
    let mut object_handle: CK_OBJECT_HANDLE = 0xCAFE;
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType(0x0000_0500).0 as CK_MECHANISM_TYPE,
        pParameter: &mut object_handle as *mut CK_OBJECT_HANDLE as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_OBJECT_HANDLE>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("object_handle")) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::ObjectHandle(params)) => {
            assert_eq!(params.handle.0, 0xCAFE);
        }
        other => panic!("unexpected object handle params: {other:?}"),
    }

    let mut derivation_data = [0xDE, 0xAD, 0xBE, 0xEF];
    let mut key_derivation = CK_KEY_DERIVATION_STRING_DATA {
        pData: derivation_data.as_mut_ptr(),
        ulLen: derivation_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType(0x0000_0501).0 as CK_MECHANISM_TYPE,
        pParameter: &mut key_derivation as *mut CK_KEY_DERIVATION_STRING_DATA as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KEY_DERIVATION_STRING_DATA>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("key_derivation_string")) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::KeyDerivationString(params)) => {
            assert_eq!(params.data, SecretBytes::copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]));
        }
        other => panic!("unexpected key derivation string params: {other:?}"),
    }

    #[repr(C)]
    struct TestSignAdditionalContext {
        hedge_variant: CK_ULONG,
        p_context: *mut CK_BYTE,
        ul_context_len: CK_ULONG,
    }

    let mut sign_context = [0xA1, 0xA2, 0xA3];
    let mut additional_context = TestSignAdditionalContext {
        hedge_variant: 1,
        p_context: sign_context.as_mut_ptr(),
        ul_context_len: sign_context.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType(0x0000_0502).0 as CK_MECHANISM_TYPE,
        pParameter: &mut additional_context as *mut TestSignAdditionalContext as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<TestSignAdditionalContext>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("sign_additional_context")) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::SignAdditionalContext(params)) => {
            assert_eq!(params.hedge_variant, 1);
            assert_eq!(params.context, SecretBytes::copy_from_slice(&[0xA1, 0xA2, 0xA3]));
        }
        other => panic!("unexpected sign additional context params: {other:?}"),
    }
}

#[test]
fn reads_signature_parameter_structs() {
    const CKM_TEST_EDDSA: CK_MECHANISM_TYPE = 0x8000_1040;
    const CKM_TEST_XEDDSA: CK_MECHANISM_TYPE = 0x8000_1041;

    let mut context = [0xA1u8, 0xA2, 0xA3];
    let mut eddsa = CK_EDDSA_PARAMS {
        phFlag: CK_TRUE,
        ulContextDataLen: context.len() as CK_ULONG,
        pContextData: context.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_EDDSA,
        pParameter: &mut eddsa as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("eddsa")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Eddsa(params) => {
            assert!(params.ph_flag);
            assert_eq!(params.context_data, vec![0xA1, 0xA2, 0xA3].into());
        }
        other => panic!("unexpected EdDSA params: {other:?}"),
    }

    let mut xeddsa = CK_XEDDSA_PARAMS { hash: CkMechanismType::SHA256.0 };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_XEDDSA,
        pParameter: &mut xeddsa as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_XEDDSA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("xeddsa")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Xeddsa(params) => {
            assert_eq!(params.hash, CkMechanismType::SHA256);
        }
        other => panic!("unexpected XEdDSA params: {other:?}"),
    }
}

#[test]
fn reads_rsa_wrap_parameter_structs() {
    let mut source_data = [0xA0u8, 0xA1, 0xA2];
    let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        source: 1,
        pSourceData: source_data.as_mut_ptr() as CK_VOID_PTR,
        ulSourceDataLen: source_data.len() as CK_ULONG,
    };
    let mut rsa_aes_wrap = CK_RSA_AES_KEY_WRAP_PARAMS { ulAESKeyBits: 256, pOAEPParams: &mut oaep };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType(0x0000_1054).0 as CK_MECHANISM_TYPE,
        pParameter: &mut rsa_aes_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams { aes_key_bits, oaep_params }) => {
            assert_eq!(aes_key_bits, 256);
            assert_eq!(oaep_params.hash_alg, CkMechanismType::SHA256);
            assert_eq!(oaep_params.mgf, CkMgf(1));
            assert_eq!(oaep_params.source, CkOaepSource(1));
            assert_eq!(oaep_params.source_data, SecretBytes::copy_from_slice(&[0xA0, 0xA1, 0xA2]));
        }
        other => panic!("unexpected RSA-AES key wrap params: {other:?}"),
    }

    let mut x = [0x51u8, 0x52, 0x53, 0x54];
    let mut key_wrap_set =
        CK_KEY_WRAP_SET_OAEP_PARAMS { bBC: 7, pX: x.as_mut_ptr(), ulXLen: x.len() as CK_ULONG };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType(0x0000_0401).0 as CK_MECHANISM_TYPE,
        pParameter: &mut key_wrap_set as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KEY_WRAP_SET_OAEP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams { bc, x }) => {
            assert_eq!(bc, 7);
            assert_eq!(x, SecretBytes::copy_from_slice(&[0x51, 0x52, 0x53, 0x54]));
        }
        other => panic!("unexpected SET OAEP key wrap params: {other:?}"),
    }
}

#[test]
fn reads_authenticated_wrap_parameter_structs() {
    const CKM_TEST_GCM_WRAP: CK_MECHANISM_TYPE = 0x8000_1030;
    const CKM_TEST_CCM_WRAP: CK_MECHANISM_TYPE = 0x8000_1031;

    let mut iv = [0x11u8; 12];
    let mut gcm_aad = [0xA1u8, 0xA2];
    let mut gcm_wrap = CK_GCM_WRAP_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 32,
        ivGenerator: 1,
        pAAD: gcm_aad.as_mut_ptr(),
        ulAADLen: gcm_aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_GCM_WRAP,
        pParameter: &mut gcm_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("gcm_wrap")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::GcmWrap(GcmWrapParams {
            iv,
            iv_fixed_bits,
            iv_generator,
            aad,
            tag_bits,
        }) => {
            assert_eq!(iv, [0x11; 12]);
            assert_eq!(iv_fixed_bits, 32);
            assert_eq!(iv_generator, CkGeneratorFunction(1));
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xA1, 0xA2]));
            assert_eq!(tag_bits, 128);
        }
        other => panic!("unexpected GCM wrap params: {other:?}"),
    }

    let mut nonce = [0x22u8; 7];
    let mut ccm_aad = [0xB1u8, 0xB2, 0xB3];
    let mut ccm_wrap = CK_CCM_WRAP_PARAMS {
        ulDataLen: 1024,
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: nonce.len() as CK_ULONG,
        ulNonceFixedBits: 24,
        nonceGenerator: 2,
        pAAD: ccm_aad.as_mut_ptr(),
        ulAADLen: ccm_aad.len() as CK_ULONG,
        ulMACLen: 16,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_CCM_WRAP,
        pParameter: &mut ccm_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CCM_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ccm_wrap")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::CcmWrap(CcmWrapParams {
            data_len,
            nonce,
            nonce_fixed_bits,
            nonce_generator,
            aad,
            mac_len,
        }) => {
            assert_eq!(data_len, 1024);
            assert_eq!(nonce, [0x22; 7]);
            assert_eq!(nonce_fixed_bits, 24);
            assert_eq!(nonce_generator, CkGeneratorFunction(2));
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xB1, 0xB2, 0xB3]));
            assert_eq!(mac_len, 16);
        }
        other => panic!("unexpected CCM wrap params: {other:?}"),
    }
}

#[test]
fn wrap_key_reader_uses_v32_aead_wrap_shapes() {
    ensure_registry();

    let mut iv = [0x11u8; 12];
    let mut gcm_aad = [0xA1u8, 0xA2];
    let mut gcm_wrap = CK_GCM_WRAP_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 32,
        ivGenerator: CKG_GENERATE as _,
        pAAD: gcm_aad.as_mut_ptr(),
        ulAADLen: gcm_aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: &mut gcm_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_wrap_key_mechanism(&mechanism) }
        .expect("read mechanism")
        .params
        .expect("params")
    {
        CkMechanismParams::GcmWrap(GcmWrapParams { iv, iv_generator, aad, .. }) => {
            assert_eq!(iv, [0x11; 12]);
            assert_eq!(iv_generator, CkGeneratorFunction(CKG_GENERATE as u64));
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xA1, 0xA2]));
        }
        other => panic!("unexpected GCM wrap-key params: {other:?}"),
    }

    let mut nonce = [0x22u8; 12];
    let mut ccm_aad = [0xB1u8, 0xB2, 0xB3];
    let mut ccm_wrap = CK_CCM_WRAP_PARAMS {
        ulDataLen: 16,
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: nonce.len() as CK_ULONG,
        ulNonceFixedBits: 0,
        nonceGenerator: CKG_GENERATE as _,
        pAAD: ccm_aad.as_mut_ptr(),
        ulAADLen: ccm_aad.len() as CK_ULONG,
        ulMACLen: 16,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CCM,
        pParameter: &mut ccm_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CCM_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_wrap_key_mechanism(&mechanism) }
        .expect("read mechanism")
        .params
        .expect("params")
    {
        CkMechanismParams::CcmWrap(CcmWrapParams {
            data_len,
            nonce,
            nonce_generator,
            aad,
            mac_len,
            ..
        }) => {
            assert_eq!(data_len, 16);
            assert_eq!(nonce, [0x22; 12]);
            assert_eq!(nonce_generator, CkGeneratorFunction(CKG_GENERATE as u64));
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xB1, 0xB2, 0xB3]));
            assert_eq!(mac_len, 16);
        }
        other => panic!("unexpected CCM wrap-key params: {other:?}"),
    }
}

#[test]
fn wrap_key_reader_uses_wrap_shapes_only_on_exact_v32_size() {
    ensure_registry();

    #[repr(C)]
    struct GcmWithPadding {
        params: CK_GCM_PARAMS,
        padding: [CK_ULONG; 4],
    }

    #[repr(C)]
    struct CcmWithPadding {
        params: CK_CCM_PARAMS,
        padding: [CK_ULONG; 4],
    }

    assert!(std::mem::size_of::<GcmWithPadding>() > std::mem::size_of::<CK_GCM_WRAP_PARAMS>());
    assert!(std::mem::size_of::<CcmWithPadding>() > std::mem::size_of::<CK_CCM_WRAP_PARAMS>());

    let mut iv = [0x33u8; 12];
    let mut gcm_aad = [0xC1u8, 0xC2];
    let mut gcm_padded = GcmWithPadding {
        params: CK_GCM_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: 96,
            pAAD: gcm_aad.as_mut_ptr(),
            ulAADLen: gcm_aad.len() as CK_ULONG,
            ulTagBits: 128,
        },
        padding: [0; 4],
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: &mut gcm_padded as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<GcmWithPadding>() as CK_ULONG,
    };
    match unsafe { read_wrap_key_mechanism(&mechanism) }
        .expect("read mechanism")
        .params
        .expect("params")
    {
        CkMechanismParams::Gcm(GcmParams { iv, aad, tag_bits, .. }) => {
            assert_eq!(iv, [0x33; 12]);
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xC1, 0xC2]));
            assert_eq!(tag_bits, 128);
        }
        other => panic!("larger non-wrap GCM params must not be parsed as wrap: {other:?}"),
    }

    let mut nonce = [0x44u8; 12];
    let mut ccm_aad = [0xD1u8, 0xD2];
    let mut ccm_padded = CcmWithPadding {
        params: CK_CCM_PARAMS {
            ulDataLen: 16,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            pAAD: ccm_aad.as_mut_ptr(),
            ulAADLen: ccm_aad.len() as CK_ULONG,
            ulMACLen: 16,
        },
        padding: [0; 4],
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CCM,
        pParameter: &mut ccm_padded as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CcmWithPadding>() as CK_ULONG,
    };
    match unsafe { read_wrap_key_mechanism(&mechanism) }
        .expect("read mechanism")
        .params
        .expect("params")
    {
        CkMechanismParams::Ccm(CcmParams { data_len, nonce, aad, mac_len, .. }) => {
            assert_eq!(data_len, 16);
            assert_eq!(nonce, [0x44; 12]);
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xD1, 0xD2]));
            assert_eq!(mac_len, 16);
        }
        other => panic!("larger non-wrap CCM params must not be parsed as wrap: {other:?}"),
    }
}

#[test]
fn write_mechanism_output_params_writes_aead_wrap_generated_fields() {
    let mut iv = [0u8; 12];
    let mut gcm_wrap = CK_GCM_WRAP_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 0,
        ivGenerator: CKG_GENERATE as _,
        pAAD: std::ptr::null_mut(),
        ulAADLen: 0,
        ulTagBits: 128,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: &mut gcm_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_WRAP_PARAMS>() as CK_ULONG,
    };
    let output = CkMechanismParams::GcmWrap(GcmWrapParams {
        iv: vec![1, 2, 3, 4],
        iv_fixed_bits: 0,
        iv_generator: CkGeneratorFunction(CKG_GENERATE as u64),
        aad: Vec::new().into(),
        tag_bits: 96,
    });
    unsafe { write_mechanism_output_params(&mut mechanism, &output) };
    assert_eq!(&iv[..4], &[1, 2, 3, 4]);
    // E0793: params structs are packed on Windows; assert on by-value copies.
    let (gcm_iv_len, gcm_tag_bits) = (gcm_wrap.ulIvLen, gcm_wrap.ulTagBits);
    assert_eq!(gcm_iv_len, 4);
    assert_eq!(gcm_tag_bits, 96);

    let mut nonce = [0u8; 12];
    let mut ccm_wrap = CK_CCM_WRAP_PARAMS {
        ulDataLen: 16,
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: nonce.len() as CK_ULONG,
        ulNonceFixedBits: 0,
        nonceGenerator: CKG_GENERATE as _,
        pAAD: std::ptr::null_mut(),
        ulAADLen: 0,
        ulMACLen: 16,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CCM,
        pParameter: &mut ccm_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CCM_WRAP_PARAMS>() as CK_ULONG,
    };
    let output = CkMechanismParams::CcmWrap(CcmWrapParams {
        data_len: 16,
        nonce: vec![9, 8, 7, 6],
        nonce_fixed_bits: 0,
        nonce_generator: CkGeneratorFunction(CKG_GENERATE as u64),
        aad: Vec::new().into(),
        mac_len: 12,
    });
    unsafe { write_mechanism_output_params(&mut mechanism, &output) };
    assert_eq!(&nonce[..4], &[9, 8, 7, 6]);
    let (ccm_nonce_len, ccm_mac_len) = (ccm_wrap.ulNonceLen, ccm_wrap.ulMACLen);
    assert_eq!(ccm_nonce_len, 4);
    assert_eq!(ccm_mac_len, 12);
}

#[test]
fn reads_aead_and_chacha_parameter_structs() {
    const CKM_TEST_CCM: CK_MECHANISM_TYPE = 0x8000_1040;
    const CKM_TEST_CHACHA20: CK_MECHANISM_TYPE = 0x8000_1041;
    const CKM_TEST_SALSA_CHACHA_POLY1305: CK_MECHANISM_TYPE = 0x8000_1042;

    let mut nonce = [0x31u8; 11];
    let mut ccm_aad = [0xC1u8, 0xC2];
    let mut ccm = CK_CCM_PARAMS {
        ulDataLen: 2048,
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: nonce.len() as CK_ULONG,
        pAAD: ccm_aad.as_mut_ptr(),
        ulAADLen: ccm_aad.len() as CK_ULONG,
        ulMACLen: 12,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_CCM,
        pParameter: &mut ccm as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CCM_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ccm")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ccm(CcmParams { data_len, nonce, aad, mac_len }) => {
            assert_eq!(data_len, 2048);
            assert_eq!(nonce, [0x31; 11]);
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xC1, 0xC2]));
            assert_eq!(mac_len, 12);
        }
        other => panic!("unexpected CCM params: {other:?}"),
    }

    let mut block_counter = [0x41u8; 4];
    let mut chacha_nonce = [0x42u8; 12];
    let mut chacha = CK_CHACHA20_PARAMS {
        pBlockCounter: block_counter.as_mut_ptr(),
        blockCounterBits: 32,
        pNonce: chacha_nonce.as_mut_ptr(),
        ulNonceBits: 96,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_CHACHA20,
        pParameter: &mut chacha as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CHACHA20_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("chacha20")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::ChaCha20(ChaCha20Params {
            block_counter,
            block_counter_bits,
            nonce,
            nonce_bits,
        }) => {
            assert_eq!(block_counter, [0x41; 4]);
            assert_eq!(block_counter_bits, 32);
            assert_eq!(nonce, [0x42; 12]);
            assert_eq!(nonce_bits, 96);
        }
        other => panic!("unexpected ChaCha20 params: {other:?}"),
    }

    let mut poly_nonce = [0x51u8; 12];
    let mut poly_aad = [0x52u8, 0x53, 0x54];
    let mut salsa_chacha_poly = CK_SALSA20_CHACHA20_POLY1305_PARAMS {
        pNonce: poly_nonce.as_mut_ptr(),
        ulNonceLen: poly_nonce.len() as CK_ULONG,
        pAAD: poly_aad.as_mut_ptr(),
        ulAADLen: poly_aad.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_SALSA_CHACHA_POLY1305,
        pParameter: &mut salsa_chacha_poly as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("salsa20_chacha20_poly1305")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
            nonce,
            aad,
        }) => {
            assert_eq!(nonce, [0x51; 12]);
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0x52, 0x53, 0x54]));
        }
        other => panic!("unexpected Salsa20/ChaCha20-Poly1305 params: {other:?}"),
    }
}

#[test]
fn reads_counter_and_encrypt_data_parameter_structs() {
    const CKM_TEST_AES_CTR: CK_MECHANISM_TYPE = 0x8000_1050;
    const CKM_TEST_CAMELLIA_CTR: CK_MECHANISM_TYPE = 0x8000_1051;
    const CKM_TEST_AES_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1052;
    const CKM_TEST_DES_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1053;
    const CKM_TEST_ARIA_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1054;
    const CKM_TEST_CAMELLIA_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1055;
    const CKM_TEST_SEED_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1056;

    let mut aes_ctr = CK_AES_CTR_PARAMS { ulCounterBits: 128, cb: [0xA1; 16] };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_AES_CTR,
        pParameter: &mut aes_ctr as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_AES_CTR_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("aes_ctr")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::AesCtr(params) => {
            assert_eq!(params.counter_bits, 128);
            assert_eq!(params.cb, [0xA1; 16]);
        }
        other => panic!("unexpected AES CTR params: {other:?}"),
    }

    let mut camellia_ctr = CK_CAMELLIA_CTR_PARAMS { ulCounterBits: 64, cb: [0xC1; 16] };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_CAMELLIA_CTR,
        pParameter: &mut camellia_ctr as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CAMELLIA_CTR_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("camellia_ctr")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::CamelliaCtr(params) => {
            assert_eq!(params.counter_bits, 64);
            assert_eq!(params.cb, [0xC1; 16]);
        }
        other => panic!("unexpected Camellia CTR params: {other:?}"),
    }

    let mut aes_data = [0xA2u8, 0xA3, 0xA4];
    let mut aes = CK_AES_CBC_ENCRYPT_DATA_PARAMS {
        iv: [0xA5; 16],
        pData: aes_data.as_mut_ptr(),
        length: aes_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_AES_CBC_ENCRYPT_DATA,
        pParameter: &mut aes as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("aes_cbc_encrypt_data")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::AesCbcEncryptData(params) => {
            assert_eq!(params.iv, [0xA5; 16]);
            assert_eq!(params.data, SecretBytes::copy_from_slice(&[0xA2, 0xA3, 0xA4]));
        }
        other => panic!("unexpected AES CBC encrypt-data params: {other:?}"),
    }

    let mut des_data = [0xD2u8, 0xD3];
    let mut des = CK_DES_CBC_ENCRYPT_DATA_PARAMS {
        iv: [0xD5; 8],
        pData: des_data.as_mut_ptr(),
        length: des_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_DES_CBC_ENCRYPT_DATA,
        pParameter: &mut des as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_DES_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("des_cbc_encrypt_data")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::DesCbcEncryptData(params) => {
            assert_eq!(params.iv, [0xD5; 8]);
            assert_eq!(params.data, SecretBytes::copy_from_slice(&[0xD2, 0xD3]));
        }
        other => panic!("unexpected DES CBC encrypt-data params: {other:?}"),
    }

    let mut aria_data = [0x12u8, 0x13, 0x14, 0x15];
    let mut aria = CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
        iv: [0x15; 16],
        pData: aria_data.as_mut_ptr(),
        length: aria_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_ARIA_CBC_ENCRYPT_DATA,
        pParameter: &mut aria as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("aria_cbc_encrypt_data")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::AriaCbcEncryptData(params) => {
            assert_eq!(params.iv, [0x15; 16]);
            assert_eq!(params.data, SecretBytes::copy_from_slice(&[0x12, 0x13, 0x14, 0x15]));
        }
        other => panic!("unexpected ARIA CBC encrypt-data params: {other:?}"),
    }

    let mut camellia_data = [0x22u8, 0x23, 0x24];
    let mut camellia = CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS {
        iv: [0x25; 16],
        pData: camellia_data.as_mut_ptr(),
        length: camellia_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_CAMELLIA_CBC_ENCRYPT_DATA,
        pParameter: &mut camellia as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("camellia_cbc_encrypt_data")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::CamelliaCbcEncryptData(params) => {
            assert_eq!(params.iv, [0x25; 16]);
            assert_eq!(params.data, SecretBytes::copy_from_slice(&[0x22, 0x23, 0x24]));
        }
        other => panic!("unexpected Camellia CBC encrypt-data params: {other:?}"),
    }

    let mut seed_data = [0x32u8, 0x33];
    let mut seed = CK_SEED_CBC_ENCRYPT_DATA_PARAMS {
        iv: [0x35; 16],
        pData: seed_data.as_mut_ptr(),
        length: seed_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_SEED_CBC_ENCRYPT_DATA,
        pParameter: &mut seed as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SEED_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("seed_cbc_encrypt_data")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::SeedCbcEncryptData(params) => {
            assert_eq!(params.iv, [0x35; 16]);
            assert_eq!(params.data, SecretBytes::copy_from_slice(&[0x32, 0x33]));
        }
        other => panic!("unexpected SEED CBC encrypt-data params: {other:?}"),
    }
}

#[test]
fn reads_legacy_rc2_rc5_and_salsa20_parameter_structs() {
    const CKM_TEST_RC5: CK_MECHANISM_TYPE = 0x8000_1000;
    const CKM_TEST_RC2_MAC_GENERAL: CK_MECHANISM_TYPE = 0x8000_1001;
    const CKM_TEST_RC5_MAC_GENERAL: CK_MECHANISM_TYPE = 0x8000_1002;
    const CKM_TEST_RC5_CBC: CK_MECHANISM_TYPE = 0x8000_1003;
    const CKM_TEST_SALSA20: CK_MECHANISM_TYPE = 0x8000_1004;
    const CKM_TEST_RC2_CBC: CK_MECHANISM_TYPE = 0x8000_1005;
    const CKM_TEST_MAC_GENERAL: CK_MECHANISM_TYPE = 0x8000_1006;

    let mut rc5 = CK_RC5_PARAMS { ulWordsize: 32, ulRounds: 12 };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_RC5,
        pParameter: &mut rc5 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RC5_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("rc5")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Rc5(params) => {
            assert_eq!(params.word_size, 32);
            assert_eq!(params.rounds, 12);
        }
        other => panic!("unexpected RC5 params: {other:?}"),
    }

    let mut rc2_mac = CK_RC2_MAC_GENERAL_PARAMS { ulEffectiveBits: 128, ulMacLength: 12 };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_RC2_MAC_GENERAL,
        pParameter: &mut rc2_mac as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RC2_MAC_GENERAL_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("rc2_mac_general")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Rc2MacGeneral(params) => {
            assert_eq!(params.effective_bits, 128);
            assert_eq!(params.mac_length, 12);
        }
        other => panic!("unexpected RC2 MAC-GENERAL params: {other:?}"),
    }

    let mut rc5_mac = CK_RC5_MAC_GENERAL_PARAMS { ulWordsize: 32, ulRounds: 16, ulMacLength: 20 };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_RC5_MAC_GENERAL,
        pParameter: &mut rc5_mac as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RC5_MAC_GENERAL_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("rc5_mac_general")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Rc5MacGeneral(params) => {
            assert_eq!(params.word_size, 32);
            assert_eq!(params.rounds, 16);
            assert_eq!(params.mac_length, 20);
        }
        other => panic!("unexpected RC5 MAC-GENERAL params: {other:?}"),
    }

    let mut iv = [0xA5u8; 8];
    let mut rc5_cbc = CK_RC5_CBC_PARAMS {
        ulWordsize: 32,
        ulRounds: 18,
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_RC5_CBC,
        pParameter: &mut rc5_cbc as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RC5_CBC_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("rc5_cbc")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Rc5Cbc(params) => {
            assert_eq!(params.word_size, 32);
            assert_eq!(params.rounds, 18);
            assert_eq!(params.iv, vec![0xA5; 8]);
        }
        other => panic!("unexpected RC5-CBC params: {other:?}"),
    }

    let mut rc2_cbc = CK_RC2_CBC_PARAMS { ulEffectiveBits: 128, iv: [0xC2; 8] };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_RC2_CBC,
        pParameter: &mut rc2_cbc as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RC2_CBC_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("rc2_cbc")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Rc2Cbc(params) => {
            assert_eq!(params.effective_bits, 128);
            assert_eq!(params.iv, vec![0xC2; 8]);
        }
        other => panic!("unexpected RC2-CBC params: {other:?}"),
    }

    let mut mac_length: CK_MAC_GENERAL_PARAMS = 16;
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_MAC_GENERAL,
        pParameter: &mut mac_length as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_MAC_GENERAL_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("mac_general")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::MacGeneral(params) => {
            assert_eq!(params.mac_length, 16);
        }
        other => panic!("unexpected MAC-GENERAL params: {other:?}"),
    }

    let mut block_counter = [0x11u8; 8];
    let mut nonce = [0x22u8; 8];
    let mut salsa20 = CK_SALSA20_PARAMS {
        pBlockCounter: block_counter.as_mut_ptr(),
        pNonce: nonce.as_mut_ptr(),
        ulNonceBits: 64,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_SALSA20,
        pParameter: &mut salsa20 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SALSA20_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("salsa20")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Salsa20(params) => {
            assert_eq!(params.block_counter, vec![0x11; 8]);
            assert_eq!(params.nonce, vec![0x22; 8]);
            assert_eq!(params.nonce_bits, 64);
        }
        other => panic!("unexpected Salsa20 params: {other:?}"),
    }
}

#[test]
fn reads_tls_ssl_parameter_structs() {
    const CKM_TEST_TLS_MAC: CK_MECHANISM_TYPE = 0x8000_1008;
    const CKM_TEST_TLS_PRF: CK_MECHANISM_TYPE = 0x8000_1009;
    const CKM_TEST_TLS_KDF: CK_MECHANISM_TYPE = 0x8000_100A;
    const CKM_TEST_SSL3_MASTER_KEY_DERIVE: CK_MECHANISM_TYPE = 0x8000_100B;
    const CKM_TEST_TLS12_EXTENDED_MASTER_KEY_DERIVE: CK_MECHANISM_TYPE = 0x8000_100C;

    let mut tls_mac = CK_TLS_MAC_PARAMS {
        prfHashMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        ulMacLength: 32,
        ulServerOrClient: 1,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_TLS_MAC,
        pParameter: &mut tls_mac as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS_MAC_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("tls_mac")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::TlsMac(params) => {
            assert_eq!(params.prf_hash_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert_eq!(params.mac_length, 32);
            assert_eq!(params.server_or_client, 1);
        }
        other => panic!("unexpected TLS MAC params: {other:?}"),
    }

    let mut seed = [0xA1u8, 0xA2, 0xA3];
    let mut label = [0xB1u8, 0xB2];
    let mut output = [0u8; 12];
    let mut output_len = output.len() as CK_ULONG;
    let mut tls_prf = CK_TLS_PRF_PARAMS {
        pSeed: seed.as_mut_ptr(),
        ulSeedLen: seed.len() as CK_ULONG,
        pLabel: label.as_mut_ptr(),
        ulLabelLen: label.len() as CK_ULONG,
        pOutput: output.as_mut_ptr(),
        pulOutputLen: &mut output_len,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_TLS_PRF,
        pParameter: &mut tls_prf as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS_PRF_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("tls_prf")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::TlsPrf(params) => {
            assert_eq!(params.seed, vec![0xA1, 0xA2, 0xA3].into());
            assert_eq!(params.label, vec![0xB1, 0xB2].into());
            assert_eq!(params.output_len, 12);
        }
        other => panic!("unexpected TLS PRF params: {other:?}"),
    }

    let mut client_random = [0x11u8; 4];
    let mut server_random = [0x22u8; 4];
    let mut kdf_label = [0x33u8, 0x34];
    let mut context_data = [0x44u8, 0x45, 0x46];
    let mut tls_kdf = CK_TLS_KDF_PARAMS {
        prfMechanism: CkMechanismType::SHA384.0 as CK_MECHANISM_TYPE,
        pLabel: kdf_label.as_mut_ptr(),
        ulLabelLength: kdf_label.len() as CK_ULONG,
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: client_random.as_mut_ptr(),
            ulClientRandomLen: client_random.len() as CK_ULONG,
            pServerRandom: server_random.as_mut_ptr(),
            ulServerRandomLen: server_random.len() as CK_ULONG,
        },
        pContextData: context_data.as_mut_ptr(),
        ulContextDataLength: context_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_TLS_KDF,
        pParameter: &mut tls_kdf as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS_KDF_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("tls_kdf")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::TlsKdf(params) => {
            assert_eq!(params.prf_mechanism.0, CkMechanismType::SHA384.0 as u64);
            assert_eq!(params.label, vec![0x33, 0x34].into());
            assert_eq!(params.random_info.client_random, vec![0x11; 4]);
            assert_eq!(params.random_info.server_random, vec![0x22; 4]);
            assert_eq!(params.context_data, vec![0x44, 0x45, 0x46].into());
        }
        other => panic!("unexpected TLS KDF params: {other:?}"),
    }

    let mut ssl3_client_random = [0x51u8; 4];
    let mut ssl3_server_random = [0x52u8; 4];
    let mut ssl3_version = CK_VERSION { major: 3, minor: 0 };
    let mut ssl3_master = CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: ssl3_client_random.as_mut_ptr(),
            ulClientRandomLen: ssl3_client_random.len() as CK_ULONG,
            pServerRandom: ssl3_server_random.as_mut_ptr(),
            ulServerRandomLen: ssl3_server_random.len() as CK_ULONG,
        },
        pVersion: &mut ssl3_version,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_SSL3_MASTER_KEY_DERIVE,
        pParameter: &mut ssl3_master as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ssl3_master_key_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ssl3MasterKeyDerive(params) => {
            assert_eq!(params.random_info.client_random, vec![0x51; 4]);
            assert_eq!(params.random_info.server_random, vec![0x52; 4]);
            assert_eq!(params.version_major, 3);
            assert_eq!(params.version_minor, 0);
        }
        other => panic!("unexpected SSL3 master-key params: {other:?}"),
    }

    let mut session_hash = [0x61u8; 8];
    let mut tls12_version = CK_VERSION { major: 3, minor: 3 };
    let mut tls12_extended = CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS {
        prfHashMechanism: CkMechanismType::SHA512.0 as CK_MECHANISM_TYPE,
        pSessionHash: session_hash.as_mut_ptr(),
        ulSessionHashLen: session_hash.len() as CK_ULONG,
        pVersion: &mut tls12_version,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_TLS12_EXTENDED_MASTER_KEY_DERIVE,
        pParameter: &mut tls12_extended as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>()
            as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("tls12_extended_master_key_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Tls12ExtendedMasterKeyDerive(params) => {
            assert_eq!(params.prf_hash_mechanism.0, CkMechanismType::SHA512.0 as u64);
            assert_eq!(params.session_hash, vec![0x61; 8]);
            assert_eq!(params.version_major, 3);
            assert_eq!(params.version_minor, 3);
        }
        other => panic!("unexpected TLS 1.2 extended master-key params: {other:?}"),
    }
}

#[test]
fn reads_kdf_and_legacy_agreement_parameter_structs() {
    const CKM_TEST_HKDF: CK_MECHANISM_TYPE = 0x8000_100D;
    const CKM_TEST_GOSTR3410_DERIVE: CK_MECHANISM_TYPE = 0x8000_100E;
    const CKM_TEST_GOSTR3410_KEY_WRAP: CK_MECHANISM_TYPE = 0x8000_100F;
    const CKM_TEST_KEA_DERIVE: CK_MECHANISM_TYPE = 0x8000_1012;
    const CKM_TEST_PKCS5_PBKD2: CK_MECHANISM_TYPE = 0x8000_1013;

    let mut salt = [0xA1u8, 0xA2, 0xA3];
    let mut info = [0xB1u8, 0xB2];
    let mut hkdf = CK_HKDF_PARAMS {
        bExtract: CK_TRUE,
        bExpand: CK_TRUE,
        prfHashMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        ulSaltType: 1,
        pSalt: salt.as_mut_ptr(),
        ulSaltLen: salt.len() as CK_ULONG,
        hSaltKey: 0x1234,
        pInfo: info.as_mut_ptr(),
        ulInfoLen: info.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_HKDF,
        pParameter: &mut hkdf as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("hkdf")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Hkdf(params) => {
            assert!(params.extract);
            assert!(params.expand);
            assert_eq!(params.prf_hash_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert_eq!(params.salt_type, 1);
            assert_eq!(params.salt, vec![0xA1, 0xA2, 0xA3].into());
            assert_eq!(params.salt_key_handle.0, 0x1234);
            assert_eq!(params.info, vec![0xB1, 0xB2].into());
        }
        other => panic!("unexpected HKDF params: {other:?}"),
    }

    let mut public_data = [0xC1u8, 0xC2, 0xC3];
    let mut ukm = [0xD1u8, 0xD2];
    let mut gostr_derive = CK_GOSTR3410_DERIVE_PARAMS {
        kdf: 1,
        pPublicData: public_data.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pUKM: ukm.as_mut_ptr(),
        ulUKMLen: ukm.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_GOSTR3410_DERIVE,
        pParameter: &mut gostr_derive as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GOSTR3410_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("gostr3410_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Gostr3410Derive(params) => {
            assert_eq!(params.kdf, CkKdf(1));
            assert_eq!(params.public_data, vec![0xC1, 0xC2, 0xC3]);
            assert_eq!(params.ukm, vec![0xD1, 0xD2]);
        }
        other => panic!("unexpected GOSTR3410 derive params: {other:?}"),
    }

    let mut wrap_oid = [0x06u8, 0x07, 0x2A];
    let mut wrap_ukm = [0xE1u8, 0xE2, 0xE3, 0xE4];
    let mut gostr_wrap = CK_GOSTR3410_KEY_WRAP_PARAMS {
        pWrapOID: wrap_oid.as_mut_ptr(),
        ulWrapOIDLen: wrap_oid.len() as CK_ULONG,
        pUKM: wrap_ukm.as_mut_ptr(),
        ulUKMLen: wrap_ukm.len() as CK_ULONG,
        hKey: 0xBEEF,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_GOSTR3410_KEY_WRAP,
        pParameter: &mut gostr_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GOSTR3410_KEY_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("gostr3410_key_wrap")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Gostr3410KeyWrap(params) => {
            assert_eq!(params.wrap_oid, vec![0x06, 0x07, 0x2A]);
            assert_eq!(params.ukm, vec![0xE1, 0xE2, 0xE3, 0xE4]);
            assert_eq!(params.key_handle.0, 0xBEEF);
        }
        other => panic!("unexpected GOSTR3410 key-wrap params: {other:?}"),
    }

    let mut random_a = [0x11u8, 0x12];
    let mut random_b = [0x21u8, 0x22];
    let mut kea_public = [0x31u8, 0x32, 0x33];
    let mut kea = CK_KEA_DERIVE_PARAMS {
        isSender: CK_TRUE,
        ulRandomLen: random_a.len() as CK_ULONG,
        RandomA: random_a.as_mut_ptr(),
        RandomB: random_b.as_mut_ptr(),
        ulPublicDataLen: kea_public.len() as CK_ULONG,
        PublicData: kea_public.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_KEA_DERIVE,
        pParameter: &mut kea as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KEA_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("kea_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::KeaDerive(params) => {
            assert!(params.is_sender);
            assert_eq!(params.random_a, vec![0x11, 0x12]);
            assert_eq!(params.random_b, vec![0x21, 0x22]);
            assert_eq!(params.public_data, vec![0x31, 0x32, 0x33]);
        }
        other => panic!("unexpected KEA derive params: {other:?}"),
    }

    let mut salt_source_data = [0x41u8, 0x42];
    let mut prf_data = [0x51u8];
    let mut password = [0x73u8, 0x65, 0x63, 0x72, 0x65, 0x74];
    let mut pbkd2 = CK_PKCS5_PBKD2_PARAMS2 {
        saltSource: 1,
        pSaltSourceData: salt_source_data.as_mut_ptr() as CK_VOID_PTR,
        ulSaltSourceDataLen: salt_source_data.len() as CK_ULONG,
        iterations: 600_000,
        prf: 2,
        pPrfData: prf_data.as_mut_ptr() as CK_VOID_PTR,
        ulPrfDataLen: prf_data.len() as CK_ULONG,
        pPassword: password.as_mut_ptr(),
        ulPasswordLen: password.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_PKCS5_PBKD2,
        pParameter: &mut pbkd2 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_PKCS5_PBKD2_PARAMS2>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("pkcs5_pbkd2")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Pkcs5Pbkd2(params) => {
            assert_eq!(params.salt_source, CkPbkdf2SaltSource(1));
            assert_eq!(params.salt_source_data, vec![0x41, 0x42].into());
            assert_eq!(params.iterations, 600_000);
            assert_eq!(params.prf, CkPbkdf2Prf(2));
            assert_eq!(params.prf_data, vec![0x51].into());
            assert_eq!(params.password, SecretBytes::copy_from_slice(b"secret"));
        }
        other => panic!("unexpected PKCS#5 PBKD2 params: {other:?}"),
    }
}

#[test]
fn reads_ecdh_and_x942_parameter_structs() {
    const CKM_TEST_ECDH1_DERIVE: CK_MECHANISM_TYPE = 0x8000_1014;
    const CKM_TEST_ECDH2_DERIVE: CK_MECHANISM_TYPE = 0x8000_1015;
    const CKM_TEST_ECMQV_DERIVE: CK_MECHANISM_TYPE = 0x8000_1016;
    const CKM_TEST_ECDH_AES_KEY_WRAP: CK_MECHANISM_TYPE = 0x8000_1017;
    const CKM_TEST_X942_DH1_DERIVE: CK_MECHANISM_TYPE = 0x8000_1018;
    const CKM_TEST_X942_DH2_DERIVE: CK_MECHANISM_TYPE = 0x8000_1019;

    let mut shared_data = [0xA1u8, 0xA2];
    let mut public_data = [0xB1u8, 0xB2, 0xB3];
    let mut ecdh1 = CK_ECDH1_DERIVE_PARAMS {
        kdf: 7,
        ulSharedDataLen: shared_data.len() as CK_ULONG,
        pSharedData: shared_data.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pPublicData: public_data.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_ECDH1_DERIVE,
        pParameter: &mut ecdh1 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ecdh1_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ecdh1Derive(params) => {
            assert_eq!(params.kdf, CkKdf(7));
            assert_eq!(params.shared_data, vec![0xA1, 0xA2].into());
            assert_eq!(params.public_data, vec![0xB1, 0xB2, 0xB3]);
        }
        other => panic!("unexpected ECDH1 derive params: {other:?}"),
    }

    let mut shared_data = [0xC1u8, 0xC2, 0xC3];
    let mut public_data = [0xD1u8, 0xD2];
    let mut public_data2 = [0xE1u8, 0xE2, 0xE3, 0xE4];
    let mut ecdh2 = CK_ECDH2_DERIVE_PARAMS {
        kdf: 8,
        ulSharedDataLen: shared_data.len() as CK_ULONG,
        pSharedData: shared_data.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pPublicData: public_data.as_mut_ptr(),
        ulPrivateDataLen: 32,
        hPrivateData: 0x1234,
        ulPublicDataLen2: public_data2.len() as CK_ULONG,
        pPublicData2: public_data2.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_ECDH2_DERIVE,
        pParameter: &mut ecdh2 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_ECDH2_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ecdh2_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ecdh2Derive(params) => {
            assert_eq!(params.kdf, CkKdf(8));
            assert_eq!(params.shared_data, vec![0xC1, 0xC2, 0xC3].into());
            assert_eq!(params.public_data, vec![0xD1, 0xD2]);
            assert_eq!(params.private_data_len, 32);
            assert_eq!(params.private_data_handle.0, 0x1234);
            assert_eq!(params.public_data2, vec![0xE1, 0xE2, 0xE3, 0xE4]);
        }
        other => panic!("unexpected ECDH2 derive params: {other:?}"),
    }

    let mut shared_data = [0x11u8, 0x12];
    let mut public_data = [0x21u8, 0x22, 0x23];
    let mut public_data2 = [0x31u8, 0x32];
    let mut ecmqv = CK_ECMQV_DERIVE_PARAMS {
        kdf: 9,
        ulSharedDataLen: shared_data.len() as CK_ULONG,
        pSharedData: shared_data.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pPublicData: public_data.as_mut_ptr(),
        ulPrivateDataLen: 48,
        hPrivateData: 0x2345,
        ulPublicDataLen2: public_data2.len() as CK_ULONG,
        pPublicData2: public_data2.as_mut_ptr(),
        publicKey: 0x3456,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_ECMQV_DERIVE,
        pParameter: &mut ecmqv as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_ECMQV_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ecmqv_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::EcmqvDerive(params) => {
            assert_eq!(params.kdf, CkKdf(9));
            assert_eq!(params.shared_data, vec![0x11, 0x12].into());
            assert_eq!(params.public_data, vec![0x21, 0x22, 0x23]);
            assert_eq!(params.private_data_len, 48);
            assert_eq!(params.private_data_handle.0, 0x2345);
            assert_eq!(params.public_data2, vec![0x31, 0x32]);
            assert_eq!(params.public_key_handle.0, 0x3456);
        }
        other => panic!("unexpected ECMQV derive params: {other:?}"),
    }

    let mut shared_data = [0x41u8, 0x42, 0x43];
    let mut ecdh_wrap = CK_ECDH_AES_KEY_WRAP_PARAMS {
        ulAESKeyBits: 256,
        kdf: 10,
        ulSharedDataLen: shared_data.len() as CK_ULONG,
        pSharedData: shared_data.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_ECDH_AES_KEY_WRAP,
        pParameter: &mut ecdh_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_ECDH_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ecdh_aes_key_wrap")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::EcdhAesKeyWrap(params) => {
            assert_eq!(params.aes_key_bits, 256);
            assert_eq!(params.kdf, CkKdf(10));
            assert_eq!(params.shared_data, vec![0x41, 0x42, 0x43].into());
        }
        other => panic!("unexpected ECDH AES key-wrap params: {other:?}"),
    }

    let mut other_info = [0x51u8, 0x52];
    let mut public_data = [0x61u8, 0x62, 0x63];
    let mut x942_dh1 = CK_X9_42_DH1_DERIVE_PARAMS {
        kdf: 11,
        ulOtherInfoLen: other_info.len() as CK_ULONG,
        pOtherInfo: other_info.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pPublicData: public_data.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_X942_DH1_DERIVE,
        pParameter: &mut x942_dh1 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_X9_42_DH1_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("x942_dh1_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::X942Dh1Derive(params) => {
            assert_eq!(params.kdf, CkKdf(11));
            assert_eq!(params.other_info, vec![0x51, 0x52].into());
            assert_eq!(params.public_data, vec![0x61, 0x62, 0x63]);
        }
        other => panic!("unexpected X9.42 DH1 derive params: {other:?}"),
    }

    let mut other_info = [0x71u8, 0x72, 0x73];
    let mut public_data = [0x81u8, 0x82];
    let mut public_data2 = [0x91u8, 0x92, 0x93, 0x94];
    let mut x942_dh2 = CK_X9_42_DH2_DERIVE_PARAMS {
        kdf: 12,
        ulOtherInfoLen: other_info.len() as CK_ULONG,
        pOtherInfo: other_info.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pPublicData: public_data.as_mut_ptr(),
        ulPrivateDataLen: 64,
        hPrivateData: 0x4567,
        ulPublicDataLen2: public_data2.len() as CK_ULONG,
        pPublicData2: public_data2.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_X942_DH2_DERIVE,
        pParameter: &mut x942_dh2 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_X9_42_DH2_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("x942_dh2_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::X942Dh2Derive(params) => {
            assert_eq!(params.kdf, CkKdf(12));
            assert_eq!(params.other_info, vec![0x71, 0x72, 0x73].into());
            assert_eq!(params.public_data, vec![0x81, 0x82]);
            assert_eq!(params.private_data_len, 64);
            assert_eq!(params.private_data_handle.0, 0x4567);
            assert_eq!(params.public_data2, vec![0x91, 0x92, 0x93, 0x94]);
        }
        other => panic!("unexpected X9.42 DH2 derive params: {other:?}"),
    }
}

#[test]
fn reads_ike_parameter_structs() {
    const CKM_TEST_IKE_PRF_DERIVE: CK_MECHANISM_TYPE = 0x8000_101A;
    const CKM_TEST_IKE1_PRF_DERIVE: CK_MECHANISM_TYPE = 0x8000_101B;
    const CKM_TEST_IKE1_EXTENDED_DERIVE: CK_MECHANISM_TYPE = 0x8000_101C;
    const CKM_TEST_IKE2_PRF_PLUS_DERIVE: CK_MECHANISM_TYPE = 0x8000_101D;

    let mut ni = [0xA1u8, 0xA2, 0xA3];
    let mut nr = [0xB1u8, 0xB2];
    let mut ike_prf = CK_IKE_PRF_DERIVE_PARAMS {
        prfMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        bDataAsKey: CK_TRUE,
        bRekey: CK_FALSE,
        pNi: ni.as_mut_ptr(),
        ulNiLen: ni.len() as CK_ULONG,
        pNr: nr.as_mut_ptr(),
        ulNrLen: nr.len() as CK_ULONG,
        hNewKey: 0x1234,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_IKE_PRF_DERIVE,
        pParameter: &mut ike_prf as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_IKE_PRF_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ike_prf_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::IkePrfDerive(params) => {
            assert_eq!(params.prf_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert!(params.data_as_key);
            assert!(!params.rekey);
            assert_eq!(params.ni, vec![0xA1, 0xA2, 0xA3].into());
            assert_eq!(params.nr, vec![0xB1, 0xB2].into());
            assert_eq!(params.new_key_handle.0, 0x1234);
        }
        other => panic!("unexpected IKE PRF derive params: {other:?}"),
    }

    let mut ckyi = [0xC1u8, 0xC2];
    let mut ckyr = [0xD1u8, 0xD2, 0xD3];
    let mut ike1_prf = CK_IKE1_PRF_DERIVE_PARAMS {
        prfMechanism: CkMechanismType::SHA384.0 as CK_MECHANISM_TYPE,
        bHasPrevKey: CK_TRUE,
        hKeygxy: 0x2345,
        hPrevKey: 0x3456,
        pCKYi: ckyi.as_mut_ptr(),
        ulCKYiLen: ckyi.len() as CK_ULONG,
        pCKYr: ckyr.as_mut_ptr(),
        ulCKYrLen: ckyr.len() as CK_ULONG,
        keyNumber: 3,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_IKE1_PRF_DERIVE,
        pParameter: &mut ike1_prf as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_IKE1_PRF_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ike1_prf_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ike1PrfDerive(params) => {
            assert_eq!(params.prf_mechanism.0, CkMechanismType::SHA384.0 as u64);
            assert!(params.has_prev_key);
            assert_eq!(params.keygxy_handle.0, 0x2345);
            assert_eq!(params.prev_key_handle.0, 0x3456);
            assert_eq!(params.ckyi, vec![0xC1, 0xC2].into());
            assert_eq!(params.ckyr, vec![0xD1, 0xD2, 0xD3].into());
            assert_eq!(params.key_number, 3);
        }
        other => panic!("unexpected IKE1 PRF derive params: {other:?}"),
    }

    let mut extra_data = [0xE1u8, 0xE2, 0xE3, 0xE4];
    let mut ike1_extended = CK_IKE1_EXTENDED_DERIVE_PARAMS {
        prfMechanism: CkMechanismType::SHA512.0 as CK_MECHANISM_TYPE,
        bHasKeygxy: CK_TRUE,
        hKeygxy: 0x4567,
        pExtraData: extra_data.as_mut_ptr(),
        ulExtraDataLen: extra_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_IKE1_EXTENDED_DERIVE,
        pParameter: &mut ike1_extended as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_IKE1_EXTENDED_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ike1_extended_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ike1ExtendedDerive(params) => {
            assert_eq!(params.prf_mechanism.0, CkMechanismType::SHA512.0 as u64);
            assert!(params.has_keygxy);
            assert_eq!(params.keygxy_handle.0, 0x4567);
            assert_eq!(params.extra_data, vec![0xE1, 0xE2, 0xE3, 0xE4].into());
        }
        other => panic!("unexpected IKE1 extended derive params: {other:?}"),
    }

    let mut seed_data = [0xF1u8, 0xF2, 0xF3];
    let mut ike2 = CK_IKE2_PRF_PLUS_DERIVE_PARAMS {
        prfMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        bHasSeedKey: CK_TRUE,
        hSeedKey: 0x5678,
        pSeedData: seed_data.as_mut_ptr(),
        ulSeedDataLen: seed_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_IKE2_PRF_PLUS_DERIVE,
        pParameter: &mut ike2 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ike2_prf_plus_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ike2PrfPlusDerive(params) => {
            assert_eq!(params.prf_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert!(params.has_seed_key);
            assert_eq!(params.seed_key_handle.0, 0x5678);
            assert_eq!(params.seed_data, vec![0xF1, 0xF2, 0xF3].into());
        }
        other => panic!("unexpected IKE2 PRF-plus derive params: {other:?}"),
    }
}

#[test]
fn reads_wtls_prf_and_x942_mqv_parameter_structs() {
    const CKM_TEST_WTLS_PRF: CK_MECHANISM_TYPE = 0x8000_1010;
    const CKM_TEST_X942_MQV: CK_MECHANISM_TYPE = 0x8000_1011;

    let mut seed = [0xA1u8, 0xA2, 0xA3];
    let mut label = [0xB1u8, 0xB2];
    let mut output = [0u8; 12];
    let mut output_len = output.len() as CK_ULONG;
    let mut wtls = CK_WTLS_PRF_PARAMS {
        DigestMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        pSeed: seed.as_mut_ptr(),
        ulSeedLen: seed.len() as CK_ULONG,
        pLabel: label.as_mut_ptr(),
        ulLabelLen: label.len() as CK_ULONG,
        pOutput: output.as_mut_ptr(),
        pulOutputLen: &mut output_len,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_WTLS_PRF,
        pParameter: &mut wtls as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_WTLS_PRF_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("wtls_prf")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::WtlsPrf(params) => {
            assert_eq!(params.digest_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert_eq!(params.seed, vec![0xA1, 0xA2, 0xA3].into());
            assert_eq!(params.label, vec![0xB1, 0xB2].into());
            assert_eq!(params.output_len, 12);
        }
        other => panic!("unexpected WTLS PRF params: {other:?}"),
    }

    let mut other_info = [0xC1u8, 0xC2];
    let mut public_data = [0xD1u8, 0xD2, 0xD3];
    let mut public_data2 = [0xE1u8, 0xE2, 0xE3, 0xE4];
    let mut x942 = CK_X9_42_MQV_DERIVE_PARAMS {
        kdf: 7,
        ulOtherInfoLen: other_info.len() as CK_ULONG,
        OtherInfo: other_info.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        PublicData: public_data.as_mut_ptr(),
        ulPrivateDataLen: 32,
        hPrivateData: 77,
        ulPublicDataLen2: public_data2.len() as CK_ULONG,
        PublicData2: public_data2.as_mut_ptr(),
        publicKey: 88,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_X942_MQV,
        pParameter: &mut x942 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_X9_42_MQV_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("x942_mqv_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::X942MqvDerive(params) => {
            assert_eq!(params.kdf, CkKdf(7));
            assert_eq!(params.other_info, vec![0xC1, 0xC2].into());
            assert_eq!(params.public_data, vec![0xD1, 0xD2, 0xD3]);
            assert_eq!(params.private_data_len, 32);
            assert_eq!(params.private_data_handle.0, 77);
            assert_eq!(params.public_data2, vec![0xE1, 0xE2, 0xE3, 0xE4]);
            assert_eq!(params.public_key_handle.0, 88);
        }
        other => panic!("unexpected X9.42 MQV params: {other:?}"),
    }
}

#[test]
fn reads_otp_and_skipjack_parameter_structs() {
    const CKM_TEST_OTP: CK_MECHANISM_TYPE = 0x8000_1020;
    const CKM_TEST_SKIPJACK_PRIVATE_WRAP: CK_MECHANISM_TYPE = 0x8000_1021;
    const CKM_TEST_SKIPJACK_RELAYX: CK_MECHANISM_TYPE = 0x8000_1022;

    let mut otp_value = [0x11u8, 0x12, 0x13];
    let mut otp_pin = [0x21u8, 0x22];
    let mut otp_params = [
        CK_OTP_PARAM {
            type_: 0,
            pValue: otp_value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: otp_value.len() as CK_ULONG,
        },
        CK_OTP_PARAM {
            type_: 1,
            pValue: otp_pin.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: otp_pin.len() as CK_ULONG,
        },
    ];
    let mut otp =
        CK_OTP_PARAMS { pParams: otp_params.as_mut_ptr(), ulCount: otp_params.len() as CK_ULONG };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_OTP,
        pParameter: &mut otp as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_OTP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("otp")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Otp(params) => {
            assert_eq!(params.params.len(), 2);
            assert_eq!(params.params[0].type_, 0);
            assert_eq!(params.params[0].value, vec![0x11, 0x12, 0x13].into());
            assert_eq!(params.params[1].type_, 1);
            assert_eq!(params.params[1].value, vec![0x21, 0x22].into());
        }
        other => panic!("unexpected OTP params: {other:?}"),
    }

    let mut password = [0x31u8, 0x32];
    let mut public_data = [0x41u8, 0x42, 0x43];
    let mut random_a = [0x51u8, 0x52, 0x53, 0x54];
    let mut prime_p = [0x61u8, 0x62];
    let mut base_g = [0x71u8, 0x72];
    let mut subprime_q = [0x81u8, 0x82, 0x83];
    let mut private_wrap = CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
        ulPasswordLen: password.len() as CK_ULONG,
        pPassword: password.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pPublicData: public_data.as_mut_ptr(),
        ulPAndGLen: prime_p.len() as CK_ULONG,
        ulQLen: subprime_q.len() as CK_ULONG,
        ulRandomLen: random_a.len() as CK_ULONG,
        pRandomA: random_a.as_mut_ptr(),
        pPrimeP: prime_p.as_mut_ptr(),
        pBaseG: base_g.as_mut_ptr(),
        pSubprimeQ: subprime_q.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_SKIPJACK_PRIVATE_WRAP,
        pParameter: &mut private_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SKIPJACK_PRIVATE_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("skipjack_private_wrap")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::SkipjackPrivateWrap(params) => {
            assert_eq!(params.password, vec![0x31, 0x32].into());
            assert_eq!(params.password_length, 2);
            assert_eq!(params.public_data, vec![0x41, 0x42, 0x43]);
            assert_eq!(params.random_a, vec![0x51, 0x52, 0x53, 0x54]);
            assert_eq!(params.prime_p, vec![0x61, 0x62]);
            assert_eq!(params.base_g, vec![0x71, 0x72]);
            assert_eq!(params.subprime_q, vec![0x81, 0x82, 0x83]);
        }
        other => panic!("unexpected Skipjack private-wrap params: {other:?}"),
    }

    let mut old_wrapped_x = [0x91u8, 0x92];
    let mut old_password = [0xA1u8, 0xA2, 0xA3];
    let mut old_public_data = [0xB1u8];
    let mut old_random_a = [0xC1u8, 0xC2];
    let mut new_password = [0xD1u8, 0xD2, 0xD3, 0xD4];
    let mut new_public_data = [0xE1u8, 0xE2];
    let mut new_random_a = [0xF1u8, 0xF2, 0xF3];
    let mut relayx = CK_SKIPJACK_RELAYX_PARAMS {
        ulOldWrappedXLen: old_wrapped_x.len() as CK_ULONG,
        pOldWrappedX: old_wrapped_x.as_mut_ptr(),
        ulOldPasswordLen: old_password.len() as CK_ULONG,
        pOldPassword: old_password.as_mut_ptr(),
        ulOldPublicDataLen: old_public_data.len() as CK_ULONG,
        pOldPublicData: old_public_data.as_mut_ptr(),
        ulOldRandomLen: old_random_a.len() as CK_ULONG,
        pOldRandomA: old_random_a.as_mut_ptr(),
        ulNewPasswordLen: new_password.len() as CK_ULONG,
        pNewPassword: new_password.as_mut_ptr(),
        ulNewPublicDataLen: new_public_data.len() as CK_ULONG,
        pNewPublicData: new_public_data.as_mut_ptr(),
        ulNewRandomLen: new_random_a.len() as CK_ULONG,
        pNewRandomA: new_random_a.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_SKIPJACK_RELAYX,
        pParameter: &mut relayx as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SKIPJACK_RELAYX_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("skipjack_relayx")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::SkipjackRelayx(params) => {
            assert_eq!(params.old_wrapped_x, vec![0x91, 0x92].into());
            assert_eq!(params.old_password, vec![0xA1, 0xA2, 0xA3].into());
            assert_eq!(params.old_public_data, vec![0xB1].into());
            assert_eq!(params.old_random_a, vec![0xC1, 0xC2].into());
            assert_eq!(params.new_password, vec![0xD1, 0xD2, 0xD3, 0xD4].into());
            assert_eq!(params.new_public_data, vec![0xE1, 0xE2].into());
            assert_eq!(params.new_random_a, vec![0xF1, 0xF2, 0xF3].into());
        }
        other => panic!("unexpected Skipjack relayx params: {other:?}"),
    }
}

#[test]
fn reads_kip_parameter_struct_with_nested_mechanism() {
    const CKM_TEST_KIP: CK_MECHANISM_TYPE = 0x8000_1030;

    ensure_registry();

    let mut nested = CK_MECHANISM {
        mechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut seed = [0x44u8, 0x45, 0x46];
    let mut kip = CK_KIP_PARAMS {
        pMechanism: &mut nested,
        hKey: 99,
        pSeed: seed.as_mut_ptr(),
        ulSeedLen: seed.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_KIP,
        pParameter: &mut kip as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("kip")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Kip(params) => {
            assert_eq!(params.mechanism.mechanism_type, CkMechanismType::SHA256);
            assert!(params.mechanism.params.is_none());
            assert_eq!(params.key_handle.0, 99);
            assert_eq!(params.seed, vec![0x44, 0x45, 0x46].into());
        }
        other => panic!("unexpected KIP params: {other:?}"),
    }
}

#[test]
fn oaep_null_source_pointer_with_nonzero_len_stays_raw() {
    let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        source: 1,
        pSourceData: std::ptr::null_mut(),
        ulSourceDataLen: 3,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_OAEP.0 as CK_MECHANISM_TYPE,
        pParameter: &mut oaep as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>());
        }
        other => panic!("expected raw params for invalid OAEP pointer, got {other:?}"),
    }
}

#[test]
fn gcm_null_embedded_pointer_with_nonzero_len_stays_raw() {
    let mut aad = [0xAB, 0xCD];
    let mut gcm = CK_GCM_PARAMS {
        pIv: std::ptr::null_mut(),
        ulIvLen: 12,
        ulIvBits: 96,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
        pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_GCM_PARAMS>());
        }
        other => panic!("expected raw params for invalid GCM pointer, got {other:?}"),
    }
}

#[test]
fn gcm_generated_iv_buffer_is_preserved_and_written_back() {
    let mut iv = [0u8; 12];
    let mut gcm = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: 0,
        ulIvBits: 96,
        pAAD: std::ptr::null_mut(),
        ulAADLen: 0,
        ulTagBits: 128,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
        pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Gcm(GcmParams { iv, iv_bits, iv_buffer_len, aad, tag_bits, .. }) => {
            assert!(iv.is_empty());
            assert_eq!(iv_bits, 96);
            assert_eq!(iv_buffer_len, 12);
            assert!(aad.is_empty());
            assert_eq!(tag_bits, 128);
        }
        other => panic!("unexpected generated-IV GCM params: {other:?}"),
    }

    let generated = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    unsafe {
        write_mechanism_output_params(
            &mut mechanism,
            &CkMechanismParams::Gcm(GcmParams {
                iv: generated.clone(),
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: Vec::new().into(),
                tag_bits: 128,

                iv_null: false,
                aad_null: false,
            }),
        );
    }

    assert_eq!(iv, generated.as_slice());
    let (gcm_iv_len, gcm_iv_bits) = (gcm.ulIvLen, gcm.ulIvBits);
    assert_eq!(gcm_iv_len, 12);
    assert_eq!(gcm_iv_bits, 96);
}

#[test]
fn extract_params_reads_ck_ulong_bit_position() {
    const CKM_EXTRACT_KEY_FROM_KEY: CK_MECHANISM_TYPE = 0x0000_0365;

    let mut bit_position = 21 as CK_EXTRACT_PARAMS;
    let mechanism = CK_MECHANISM {
        mechanism: CKM_EXTRACT_KEY_FROM_KEY,
        pParameter: &mut bit_position as *mut CK_EXTRACT_PARAMS as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_EXTRACT_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Extract(ExtractParams { bit_position }) => {
            assert_eq!(bit_position, 21);
        }
        other => panic!("unexpected extract params: {other:?}"),
    }
}

#[test]
fn kmac_params_reads_key_length_and_customization_string() {
    const CKM_TEST_KMAC: CK_MECHANISM_TYPE = 0x8000_0001;

    let mut customization = *b"custom";
    let mut params = super::CkKmacParams {
        h_key: 0xCAFE,
        ul_mac_length: 64,
        p_customization_string: customization.as_mut_ptr() as CK_VOID_PTR,
        ul_customization_string_len: customization.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_KMAC,
        pParameter: &mut params as *mut super::CkKmacParams as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<super::CkKmacParams>() as CK_ULONG,
    };

    match unsafe { read_mechanism_with_shape(&mechanism, Some("kmac")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Kmac(KmacParams { key_handle, mac_length, customization_string }) => {
            assert_eq!(key_handle.0, 0xCAFE);
            assert_eq!(mac_length, 64);
            assert_eq!(customization_string, SecretBytes::copy_from_slice(b"custom"));
        }
        other => panic!("unexpected KMAC params: {other:?}"),
    }
}

#[test]
fn mu_gen_params_reads_key_tr_and_context() {
    const CKM_TEST_MU_GEN: CK_MECHANISM_TYPE = 0x8000_0002;

    let mut tr = *b"precomputed-tr";
    let mut context = *b"context";
    let mut params = super::CkMuGenParams {
        h_key: 0xA11CE,
        p_tr: tr.as_mut_ptr(),
        ul_tr_len: tr.len() as CK_ULONG,
        p_ctx: context.as_mut_ptr(),
        ul_ctx_len: context.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_MU_GEN,
        pParameter: &mut params as *mut super::CkMuGenParams as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<super::CkMuGenParams>() as CK_ULONG,
    };

    match unsafe { read_mechanism_with_shape(&mechanism, Some("mu_gen")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::MuGen(MuGenParams { key_handle, tr, context }) => {
            assert_eq!(key_handle.0, 0xA11CE);
            assert_eq!(tr, SecretBytes::copy_from_slice(b"precomputed-tr"));
            assert_eq!(context, SecretBytes::copy_from_slice(b"context"));
        }
        other => panic!("unexpected mu-gen params: {other:?}"),
    }
}

#[test]
fn sp800_108_kdf_null_data_params_with_nonzero_count_stays_raw() {
    const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: 1,
        pDataParams: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: 0,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
        }
        other => panic!("unexpected SP800-108 params: {other:?}"),
    }
}

#[test]
fn sp800_108_kdf_null_additional_keys_with_nonzero_count_stays_raw() {
    const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: 1,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
        }
        other => panic!("unexpected SP800-108 params: {other:?}"),
    }
}

#[test]
fn sp800_108_kdf_null_data_value_with_nonzero_len_stays_raw() {
    const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;
    const CK_SP800_108_BYTE_ARRAY: CK_PRF_DATA_TYPE = 4;

    let mut data_params = [CK_PRF_DATA_PARAM {
        type_: CK_SP800_108_BYTE_ARRAY,
        pValue: std::ptr::null_mut(),
        ulValueLen: 4,
    }];
    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: data_params.len() as CK_ULONG,
        pDataParams: data_params.as_mut_ptr(),
        ulAdditionalDerivedKeys: 0,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
        }
        other => panic!("unexpected SP800-108 params: {other:?}"),
    }
}

#[test]
fn sp800_108_kdf_null_template_with_nonzero_attr_count_stays_raw() {
    const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

    let mut output_handle = 0 as CK_OBJECT_HANDLE;
    let mut additional_keys = [CK_DERIVED_KEY {
        pTemplate: std::ptr::null_mut(),
        ulAttributeCount: 1,
        phKey: &mut output_handle,
    }];
    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: additional_keys.len() as CK_ULONG,
        pAdditionalDerivedKeys: additional_keys.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
        }
        other => panic!("unexpected SP800-108 params: {other:?}"),
    }
}

#[test]
fn sp800_108_kdf_null_output_handle_stays_raw() {
    const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

    let mut additional_keys = [CK_DERIVED_KEY {
        pTemplate: std::ptr::null_mut(),
        ulAttributeCount: 0,
        phKey: std::ptr::null_mut(),
    }];
    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: additional_keys.len() as CK_ULONG,
        pAdditionalDerivedKeys: additional_keys.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
        }
        other => panic!("unexpected SP800-108 params: {other:?}"),
    }
}

#[test]
fn sp800_108_feedback_null_iv_with_nonzero_len_stays_raw() {
    const CKM_SP800_108_FEEDBACK_KDF: CK_MECHANISM_TYPE = 0x0000_03AD;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

    let mut params = CK_SP800_108_FEEDBACK_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulIVLen: 16,
        pIV: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: 0,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_FEEDBACK_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>());
        }
        other => panic!("unexpected SP800-108 feedback params: {other:?}"),
    }
}

#[test]
fn sp800_108_feedback_reads_additional_keys_and_writes_handles_back() {
    const CKM_SP800_108_FEEDBACK_KDF: CK_MECHANISM_TYPE = 0x0000_03AD;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

    let mut label = *b"extra";
    let mut value_len = 32 as CK_ULONG;
    let mut template = [
        CK_ATTRIBUTE {
            type_: CkAttributeType::LABEL.0 as _,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CkAttributeType::VALUE_LEN.0 as _,
            pValue: &mut value_len as *mut _ as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
    ];
    let mut additional_key_handle = 0 as CK_OBJECT_HANDLE;
    let mut additional_keys = [CK_DERIVED_KEY {
        pTemplate: template.as_mut_ptr(),
        ulAttributeCount: template.len() as CK_ULONG,
        phKey: &mut additional_key_handle,
    }];
    let mut iv = [0xA5u8; 16];
    let mut params = CK_SP800_108_FEEDBACK_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulIVLen: iv.len() as CK_ULONG,
        pIV: iv.as_mut_ptr(),
        ulAdditionalDerivedKeys: additional_keys.len() as CK_ULONG,
        pAdditionalDerivedKeys: additional_keys.as_mut_ptr(),
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_FEEDBACK_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Sp800108FeedbackKdf(params) => {
            assert_eq!(params.prf_type.0, CKM_SHA256_HMAC as u64);
            assert_eq!(params.iv, vec![0xA5; 16]);
            assert_eq!(params.additional_derived_keys.len(), 1);
            let derived = &params.additional_derived_keys[0];
            assert_eq!(derived.key_handle.0, 0);
            assert_eq!(derived.template.len(), 2);
            assert_eq!(
                derived.template[0].value,
                Some(CkAttributeValue::Bytes(b"extra".to_vec().into()))
            );
            assert_eq!(derived.template[1].value, Some(CkAttributeValue::Ulong(32)));
        }
        other => panic!("unexpected SP800-108 feedback params: {other:?}"),
    }

    unsafe {
        write_mechanism_output_params(
            &mut mechanism,
            &CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CkMechanismType(CKM_SHA256_HMAC),
                data_params: Vec::new(),
                iv: vec![0xA5; 16],
                additional_derived_keys: vec![Sp800108DerivedKey {
                    template: Vec::new(),
                    key_handle: CkObjectHandle(0xCAFE),
                }],
            }),
        );
    }

    assert_eq!(additional_key_handle, 0xCAFE);
}

/// ADR-0010 Scope 2: an unmaterializable AAD length (CK_ULONG::MAX) on a GCM
/// parameter must NOT cause a wild read / process abort.  The shim must fall
/// back to the raw-bytes path (or return a length-error) rather than
/// constructing a slice via `slice::from_raw_parts` with an absurd length.
///
/// The test is intentionally written as a "survives without aborting" check:
/// the observable contract is (a) no crash, and (b) the result is the safe
/// `Raw` fallback rather than a typed `Gcm` variant. (W1-L12-06: the read
/// itself is fallible at the type level, but this input is in-bounds, so
/// the read succeeds and the assertion targets the fallback shape.)
#[test]
fn gcm_aad_unmaterializable_len_rejected_not_wild_read() {
    ensure_registry();
    let mut gcm = CK_GCM_PARAMS {
        pIv: std::ptr::null_mut(),
        ulIvLen: 0,
        ulIvBits: 0,
        // Non-null pointer, but an absurd claimed length — must never be
        // dereferenced as a slice of this size.
        pAAD: std::ptr::dangling_mut::<u8>(),
        ulAADLen: CK_ULONG::MAX,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    // Must not crash.  With the guard in place the shim falls back to the raw
    // path; without the guard it would construct a slice of size usize::MAX
    // (UB) and typically kill the process.
    let result =
        unsafe { read_mechanism_with_shape(&mechanism, Some("gcm")) }.expect("read mechanism");
    match result.params.expect("params") {
        CkMechanismParams::Raw(_) => {} // expected: safe fallback
        other => panic!("expected Raw fallback for unmaterializable AAD len, got {other:?}"),
    }
}

/// ADR-0010 Scope 2: RSA OAEP params with a dangling (non-null) pSourceData
/// and ulSourceDataLen = CK_ULONG::MAX must NOT cause a wild read.  The shim
/// falls back to the raw-bytes path rather than calling
/// `slice::from_raw_parts` with an absurd length.
#[test]
fn rsa_oaep_unmaterializable_source_data_len_falls_back_to_raw() {
    ensure_registry();
    let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        source: 1,
        pSourceData: std::ptr::dangling_mut::<u8>() as CK_VOID_PTR,
        ulSourceDataLen: CK_ULONG::MAX,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_OAEP.0 as CK_MECHANISM_TYPE,
        pParameter: &mut oaep as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
    };
    // Must not crash or do a wild read.  With the guard the shim falls back to
    // the raw path; without it `slice::from_raw_parts` would be called with
    // size usize::MAX (UB).
    let result = unsafe { read_ck_mechanism(&mechanism) };
    match result {
        CkMechanismParams::Raw(_) => {} // expected: safe Raw fallback
        other => {
            panic!("expected Raw fallback for unmaterializable source data len, got {other:?}")
        }
    }
}

/// ADR-0010 Scope 2: an unmaterializable password length (CK_ULONG::MAX) on a
/// PBE parameter must NOT cause a wild read.  The shim falls back to the
/// raw-bytes path rather than calling `slice::from_raw_parts` with an absurd
/// length.
#[test]
fn pbe_password_unmaterializable_len_rejected_not_wild_read() {
    ensure_registry();
    let mut pbe = CK_PBE_PARAMS {
        pInitVector: std::ptr::null_mut(),
        pPassword: std::ptr::dangling_mut::<u8>(),
        ulPasswordLen: CK_ULONG::MAX,
        pSalt: std::ptr::null_mut(),
        ulSaltLen: 0,
        ulIteration: 1,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_PBE_SHA1_DES3_EDE_CBC,
        pParameter: &mut pbe as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_PBE_PARAMS>() as CK_ULONG,
    };
    // Must not crash or do a wild read.  With the guard the shim falls back to
    // the raw path; without it `slice::from_raw_parts` would be called with
    // size usize::MAX (UB).
    let result =
        unsafe { read_mechanism_with_shape(&mechanism, Some("pbe")) }.expect("read mechanism");
    match result.params.expect("params") {
        CkMechanismParams::Raw(_) => {} // expected: safe Raw fallback
        other => panic!("expected Raw fallback for unmaterializable password len, got {other:?}"),
    }
}

/// ADR-0010 Scope 2: an unmaterializable nonce bit-length (CK_ULONG::MAX) on a
/// Salsa20 parameter must NOT cause a wild read.  The shim falls back to the
/// raw-bytes path rather than calling `slice::from_raw_parts` with the absurd
/// derived byte count.
#[test]
fn salsa20_nonce_unmaterializable_bits_rejected_not_wild_read() {
    ensure_registry();
    let mut salsa20 = CK_SALSA20_PARAMS {
        pBlockCounter: std::ptr::dangling_mut::<u8>(),
        pNonce: std::ptr::dangling_mut::<u8>(),
        ulNonceBits: CK_ULONG::MAX,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SALSA20,
        pParameter: &mut salsa20 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SALSA20_PARAMS>() as CK_ULONG,
    };
    // Must not crash or do a wild read.  With the guard the shim falls back to
    // the raw path; without it `slice::from_raw_parts` would be called with
    // size usize::MAX (UB).
    let result =
        unsafe { read_mechanism_with_shape(&mechanism, Some("salsa20")) }.expect("read mechanism");
    match result.params.expect("params") {
        CkMechanismParams::Raw(_) => {} // expected: safe Raw fallback
        other => panic!("expected Raw fallback for unmaterializable nonce bits, got {other:?}"),
    }
}

#[test]
fn gcm_null_vs_empty_iv_aad_survive_the_read() {
    // F3/D2: (NULL, 0) vs (ptr, 0) for pIv/pAAD must remain distinguishable
    // after the shim read so the daemon can materialize the caller's shape.
    for (p_iv, iv_null, p_aad, aad_null) in [
        (std::ptr::null_mut(), true, std::ptr::null_mut(), true),
        (std::ptr::null_mut(), true, std::ptr::dangling_mut(), false),
        (std::ptr::dangling_mut(), false, std::ptr::null_mut(), true),
        (std::ptr::dangling_mut(), false, std::ptr::dangling_mut(), false),
    ] {
        let mut gcm = CK_GCM_PARAMS {
            pIv: p_iv,
            ulIvLen: 0,
            ulIvBits: 0,
            pAAD: p_aad,
            ulAADLen: 0,
            ulTagBits: 128,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
            pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Gcm(gcm) => {
                assert!(gcm.iv.is_empty());
                assert!(gcm.aad.expose(|b| b.is_empty()));
                assert_eq!(gcm.iv_null, iv_null, "pIv nullness must survive");
                assert_eq!(gcm.aad_null, aad_null, "pAAD nullness must survive");
            }
            other => panic!("unexpected GCM params: {other:?}"),
        }
    }
}

#[test]
fn misaligned_rsa_aes_key_wrap_reads_byte_identical_values() {
    // W1-C6-03 / W1-L1-01 residual: the manual field reads for
    // rsa_aes_key_wrap must not dereference 8-byte fields at
    // potentially-misaligned pack(1) offsets. Place the outer struct at a
    // misaligned address (built with write_unaligned, so the test setup
    // itself is Miri-clean); the nested OAEP struct stays aligned per the
    // caller contract. Run under Miri: misaligned derefs are UB errors.
    let mut source_data = [0xA0u8, 0xA1, 0xA2];
    let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        source: 1,
        pSourceData: source_data.as_mut_ptr() as CK_VOID_PTR,
        ulSourceDataLen: source_data.len() as CK_ULONG,
    };
    let ulong_size = std::mem::size_of::<CK_ULONG>();
    let ptr_size = std::mem::size_of::<*mut std::ffi::c_void>();
    let wrap_size = ulong_size + ptr_size;
    let mut buf = [0u8; 64];
    let buf_addr = buf.as_mut_ptr() as usize;
    // Deterministic misalignment: some offset in 0..8 always misses 8-byte
    // alignment, regardless of the stack address.
    let offset = (0..8usize)
        .find(|o| !(buf_addr + o).is_multiple_of(ulong_size))
        .expect("a misaligned offset always exists");
    let base = buf.as_mut_ptr().wrapping_add(offset);
    assert_ne!(base as usize % ulong_size, 0, "test setup must be misaligned");
    unsafe {
        std::ptr::write_unaligned(base as *mut CK_ULONG, 256);
        std::ptr::write_unaligned(
            base.add(ulong_size) as *mut *mut CK_RSA_PKCS_OAEP_PARAMS,
            &mut oaep,
        );
    }
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType(0x0000_1054).0 as CK_MECHANISM_TYPE,
        pParameter: base as CK_VOID_PTR,
        ulParameterLen: wrap_size as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("rsa_aes_key_wrap")) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
            aes_key_bits,
            oaep_params,
        })) => {
            assert_eq!(aes_key_bits, 256);
            assert_eq!(oaep_params.hash_alg, CkMechanismType::SHA256);
            assert_eq!(oaep_params.mgf, CkMgf(1));
            assert_eq!(oaep_params.source, CkOaepSource(1));
            assert_eq!(oaep_params.source_data, SecretBytes::copy_from_slice(&[0xA0, 0xA1, 0xA2]));
        }
        other => panic!("unexpected RSA-AES key wrap params: {other:?}"),
    }
}

#[test]
fn misaligned_sign_additional_context_reads_byte_identical_values() {
    // W1-C6-03 / W1-L1-01 residual: same misalignment class for the
    // sign_additional_context manual reads, covering both the base
    // CK_SIGN_ADDITIONAL_CONTEXT and the hash-extended
    // CK_HASH_SIGN_ADDITIONAL_CONTEXT variant (trailing hash word).
    for with_hash in [false, true] {
        let mut sign_context = [0xB1u8, 0xB2];
        let ulong_size = std::mem::size_of::<CK_ULONG>();
        let ptr_size = std::mem::size_of::<*mut u8>();
        let base_size = ulong_size + ptr_size + ulong_size;
        let hash_size = base_size + ulong_size;
        let total = if with_hash { hash_size } else { base_size };
        let mut buf = [0u8; 64];
        let buf_addr = buf.as_mut_ptr() as usize;
        let offset = (0..8usize)
            .find(|o| !(buf_addr + o).is_multiple_of(ulong_size))
            .expect("a misaligned offset always exists");
        let base = buf.as_mut_ptr().wrapping_add(offset);
        assert_ne!(base as usize % ulong_size, 0, "test setup must be misaligned");
        unsafe {
            std::ptr::write_unaligned(base as *mut CK_ULONG, 7);
            std::ptr::write_unaligned(
                base.add(ulong_size) as *mut *mut u8,
                sign_context.as_mut_ptr(),
            );
            std::ptr::write_unaligned(
                base.add(ulong_size + ptr_size) as *mut CK_ULONG,
                sign_context.len() as CK_ULONG,
            );
            if with_hash {
                std::ptr::write_unaligned(base.add(base_size) as *mut CK_ULONG, 0xA5A5);
            }
        }
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType(0x0000_0502).0 as CK_MECHANISM_TYPE,
            pParameter: base as CK_VOID_PTR,
            ulParameterLen: total as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("sign_additional_context")) }
            .expect("read mechanism")
            .params
        {
            Some(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                hedge_variant,
                context,
                hash,
            })) => {
                assert_eq!(hedge_variant, 7, "with_hash={with_hash}");
                assert_eq!(
                    context,
                    SecretBytes::copy_from_slice(&[0xB1, 0xB2]),
                    "with_hash={with_hash}"
                );
                assert_eq!(hash.0, if with_hash { 0xA5A5 } else { 0 }, "with_hash={with_hash}");
            }
            other => panic!("unexpected sign additional context params: {other:?}"),
        }
    }
}

#[test]
fn oaep_null_vs_empty_source_survives_the_read() {
    // F3/D2: (NULL, 0) vs (ptr, 0) for pSourceData must remain
    // distinguishable after the shim read.
    for (p_source, source_null) in [(std::ptr::null_mut(), true), (std::ptr::dangling_mut(), false)]
    {
        let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            mgf: 1,
            source: 1,
            pSourceData: p_source,
            ulSourceDataLen: 0,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType::RSA_PKCS_OAEP.0 as CK_MECHANISM_TYPE,
            pParameter: &mut oaep as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::RsaPkcsOaep(oaep) => {
                assert!(oaep.source_data.expose(|b| b.is_empty()));
                assert_eq!(oaep.source_null, source_null, "pSourceData nullness must survive");
            }
            other => panic!("unexpected OAEP params: {other:?}"),
        }
    }
}

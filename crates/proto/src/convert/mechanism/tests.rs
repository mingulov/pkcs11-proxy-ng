use super::*;
use pkcs11_proxy_ng_types::{
    AesCmacKeyDerivationParams, CkAttribute, CkAttributeType, CkAttributeValue,
    CkGeneratorFunction, CkKdf, CkMechanismType, CkMgf, CkOaepSource, CkObjectHandle, CkPbkdf2Prf,
    CkPbkdf2SaltSource, CmsSigParams, DilithiumParams, Ecdh1DeriveParams, Ecdh2DeriveParams,
    EcdhAesKeyWrapParams, EciesParams, EcmqvDeriveParams, EddsaParams, ExtractParams, GcmParams,
    Gostr3410DeriveParams, Gostr3410KeyWrapParams, HdKeyDeriveParams, HkdfParams,
    Ike1ExtendedDeriveParams, Ike1PrfDeriveParams, Ike2PrfPlusDeriveParams, IkePrfDeriveParams,
    IvParams, KeaDeriveParams, KeyDerivationStringData, KeyWrapSetOaepParams, KipParams,
    KmacParams, KyberParams, MacGeneralParams, MuGenParams, ObjectHandleParam, OtpParam, OtpParams,
    PbeParams, Pkcs5Pbkd2Params, PointerArray, PointerBytes, PrfDataParam, RawMechanismParams,
    RsaAesKeyWrapParams, SignAdditionalContext, SkipjackPrivateWrapParams, SkipjackRelayxParams,
    Sp800108DerivedKey, Sp800108FeedbackKdfParams, Sp800108KdfParams, Ssl3KeyMatParams,
    Ssl3MasterKeyDeriveParams, SslRandomData, Tls12ExtendedMasterKeyDeriveParams,
    Tls12MasterKeyDeriveParams, TlsKdfParams, TlsPrfParams, VendorObjectExtractParams,
    VendorObjectInsertParams, WtlsKeyMatParams, WtlsMasterKeyDeriveParams, WtlsPrfParams,
    WtlsRandomData, X2RatchetInitializeParams, X2RatchetRespondParams, X3dhInitiateParams,
    X3dhRespondParams, X942Dh1DeriveParams, X942Dh2DeriveParams, X942MqvDeriveParams,
};

/// Helper: wrap params in a mechanism, round-trip through proto, return the result.
/// W1-C8-05: pins full-field equality plus mechanism_type for every caller,
/// so a dropped field or a mistyped mechanism fails the suite even when the
/// per-test match arm below only spot-checks individual fields.
fn round_trip(params: CkMechanismParams) -> CkMechanismParams {
    let mech = CkMechanism {
        mechanism_type: CkMechanismType(0x9999), // arbitrary, doesn't matter for conversion
        params: Some(params),
    };
    let proto: v1_proto::Mechanism = (&mech).try_into().unwrap();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(back, mech, "round-trip must preserve every field and mechanism_type");
    back.params.expect("params should survive round-trip")
}

fn expect_mechanism_param_invalid(proto: v1_proto::Mechanism) {
    let err = CkMechanism::try_from(&proto).expect_err("invalid mechanism params should fail");
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
}

#[test]
fn mechanism_parameterless_round_trip() {
    let original = CkMechanism { mechanism_type: CkMechanismType::SHA256_RSA_PKCS, params: None };
    let proto: v1_proto::Mechanism = (&original).try_into().unwrap();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(back.mechanism_type, original.mechanism_type);
    assert!(back.params.is_none());
}

#[test]
fn mechanism_pss_round_trip() {
    let original = CkMechanism {
        mechanism_type: CkMechanismType::RSA_PKCS_PSS,
        params: Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: CkMgf(1),
            salt_len: 32,
        })),
    };
    let proto: v1_proto::Mechanism = (&original).try_into().unwrap();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(back.mechanism_type, original.mechanism_type);
    match back.params.unwrap() {
        CkMechanismParams::RsaPkcsPss(p) => {
            assert_eq!(p.salt_len, 32);
            assert_eq!(p.hash_alg, CkMechanismType::SHA256);
            assert_eq!(p.mgf.0, 1);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn mechanism_oaep_round_trip() {
    let original = CkMechanism {
        mechanism_type: CkMechanismType::RSA_PKCS_OAEP,
        params: Some(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: CkMgf(1),
            source: CkOaepSource(1),
            source_data_presence: PointerBytes::from_legacy(&[1, 2, 3], false),
        })),
    };
    let proto: v1_proto::Mechanism = (&original).try_into().unwrap();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(back.mechanism_type, original.mechanism_type);
    match back.params.unwrap() {
        CkMechanismParams::RsaPkcsOaep(p) => {
            // W1-C8-05: full-field assertions; a dropped field must fail.
            assert_eq!(p.hash_alg, CkMechanismType::SHA256);
            assert_eq!(p.mgf.0, 1);
            assert_eq!(p.source.0, 1);
            assert_eq!(*p.source_data_presence.as_present().unwrap(), vec![1, 2, 3].into());
            assert!(!p.source_data_presence.is_null());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn mechanism_oaep_empty_source_data_round_trip() {
    let original = CkMechanism {
        mechanism_type: CkMechanismType::RSA_PKCS_OAEP,
        params: Some(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: CkMgf(0x00000002),
            source: CkOaepSource(0x00000001),
            source_data_presence: PointerBytes::from_legacy(&[], false),
        })),
    };
    let proto: v1_proto::Mechanism = (&original).try_into().unwrap();
    let back = CkMechanism::try_from(&proto).unwrap();
    // W1-C8-05: full-field + mechanism_type assertions; a dropped field must fail.
    assert_eq!(back.mechanism_type, original.mechanism_type);
    match back.params.unwrap() {
        CkMechanismParams::RsaPkcsOaep(p) => {
            assert_eq!(p.hash_alg, CkMechanismType::SHA256);
            assert_eq!(p.mgf.0, 0x00000002);
            assert_eq!(p.source.0, 0x00000001);
            assert!(p.source_data_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
            assert!(!p.source_data_presence.is_null());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn mechanism_gcm_round_trip() {
    let original = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv_bits: 96,
            iv_buffer_len: 12,
            tag_bits: 128,
            iv_presence: PointerBytes::from_legacy(&[0u8; 12], false),
            aad_presence: PointerBytes::from_legacy(&[0xAA, 0xBB], false),
        })),
    };
    let proto: v1_proto::Mechanism = (&original).try_into().unwrap();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(back.mechanism_type, CkMechanismType::AES_GCM);
    match back.params.unwrap() {
        CkMechanismParams::Gcm(p) => {
            assert_eq!(p.iv_presence, PointerBytes::present_copy(&[0u8; 12]));
            assert_eq!(p.iv_bits, 96);
            assert_eq!(p.iv_buffer_len, 12);
            assert_eq!(*p.aad_presence.as_present().unwrap(), vec![0xAA, 0xBB].into());
            assert_eq!(p.tag_bits, 128);
            // W1-C8-05: null flags are fields too; a dropped flag must fail.
            assert!(!p.iv_presence.is_null());
            assert!(!p.aad_presence.is_null());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn mechanism_gcm_empty_aad_round_trip() {
    let original = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv_bits: 96,
            iv_buffer_len: 12,
            tag_bits: 96,
            iv_presence: PointerBytes::from_legacy(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], false),
            aad_presence: PointerBytes::from_legacy(&[], false),
        })),
    };
    let proto: v1_proto::Mechanism = (&original).try_into().unwrap();
    let back = CkMechanism::try_from(&proto).unwrap();
    // W1-C8-05: full-field + mechanism_type assertions; a dropped field must fail.
    assert_eq!(back.mechanism_type, original.mechanism_type);
    match back.params.unwrap() {
        CkMechanismParams::Gcm(p) => {
            assert_eq!(
                p.iv_presence,
                PointerBytes::present_copy(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
            );
            assert_eq!(p.iv_bits, 96);
            assert_eq!(p.iv_buffer_len, 12);
            assert!(p.aad_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
            assert_eq!(p.tag_bits, 96);
            assert!(!p.iv_presence.is_null());
            assert!(!p.aad_presence.is_null());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn mechanism_ecdh1_derive_round_trip() {
    let original = CkMechanism {
        mechanism_type: CkMechanismType::ECDH1_DERIVE,
        params: Some(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
            kdf: CkKdf(2),
            shared_data_presence: PointerBytes::present_copy(&[0x01, 0x02, 0x03]),
            public_data_presence: PointerBytes::present_copy(&[0x04; 65]),
        })),
    };
    let proto: v1_proto::Mechanism = (&original).try_into().unwrap();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(back.mechanism_type, CkMechanismType::ECDH1_DERIVE);
    match back.params.unwrap() {
        CkMechanismParams::Ecdh1Derive(p) => {
            assert_eq!(p.kdf.0, 2);
            assert_eq!(
                *p.shared_data_presence.as_present().unwrap(),
                vec![0x01, 0x02, 0x03].into()
            );
            assert_eq!(p.public_data_presence, PointerBytes::present_copy(&[0x04; 65]));
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn mechanism_ecdh1_derive_null_kdf_no_shared_data() {
    let original = CkMechanism {
        mechanism_type: CkMechanismType::ECDH1_DERIVE,
        params: Some(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
            kdf: CkKdf(1),
            shared_data_presence: PointerBytes::present_copy(&[]),
            public_data_presence: PointerBytes::present_copy(&[0x04; 65]),
        })),
    };
    let proto: v1_proto::Mechanism = (&original).try_into().unwrap();
    let back = CkMechanism::try_from(&proto).unwrap();
    // W1-C8-05: mechanism_type must be pinned alongside the fields.
    assert_eq!(back.mechanism_type, original.mechanism_type);
    match back.params.unwrap() {
        CkMechanismParams::Ecdh1Derive(p) => {
            assert_eq!(p.kdf.0, 1);
            assert!(p.shared_data_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
            assert_eq!(p.public_data_presence.as_present().unwrap().len(), 65);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn aes_cbc_iv_round_trip() {
    let mech = CkMechanism {
        mechanism_type: CkMechanismType::AES_CBC,
        params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0x01; 16] })),
    };
    let proto: v1_proto::Mechanism = (&mech).try_into().unwrap();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(mech, back);
}

#[test]
fn des3_cbc_iv_round_trip() {
    let mech = CkMechanism {
        mechanism_type: CkMechanismType::DES3_CBC,
        params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0xAB; 8] })),
    };
    let proto: v1_proto::Mechanism = (&mech).try_into().unwrap();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(mech, back);
}

#[test]
fn mechanism_unknown_type_preserved_as_parameterless() {
    let original = CkMechanism { mechanism_type: CkMechanismType(0xFFFF_FFFF), params: None };
    let proto: v1_proto::Mechanism = (&original).try_into().unwrap();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(back.mechanism_type, CkMechanismType(0xFFFF_FFFF));
    assert!(back.params.is_none());
}

#[test]
fn mechanism_info_sign_verify_round_trip() {
    let original = CkMechanismInfo {
        min_key_size: 512,
        max_key_size: 4096,
        flags: CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY,
    };
    let proto: v1_proto::MechanismInfo = (&original).into();
    let back = CkMechanismInfo::from(&proto);
    assert_eq!(back, original);
}

#[test]
fn mechanism_info_sign_recover_flags_round_trip() {
    let flags = CkMechanismFlags::SIGN
        | CkMechanismFlags::SIGN_RECOVER
        | CkMechanismFlags::VERIFY
        | CkMechanismFlags::VERIFY_RECOVER;
    let original = CkMechanismInfo { min_key_size: 2048, max_key_size: 2048, flags };
    let proto: v1_proto::MechanismInfo = (&original).into();
    let back = CkMechanismInfo::from(&proto);
    assert_eq!(back.flags.0 & CkMechanismFlags::SIGN_RECOVER.0, CkMechanismFlags::SIGN_RECOVER.0);
    assert_eq!(
        back.flags.0 & CkMechanismFlags::VERIFY_RECOVER.0,
        CkMechanismFlags::VERIFY_RECOVER.0
    );
    assert_eq!(back, original);
}

#[test]
fn mechanism_info_all_known_flags_round_trip() {
    let flags = CkMechanismFlags::ENCRYPT
        | CkMechanismFlags::DECRYPT
        | CkMechanismFlags::DIGEST
        | CkMechanismFlags::SIGN
        | CkMechanismFlags::SIGN_RECOVER
        | CkMechanismFlags::VERIFY
        | CkMechanismFlags::VERIFY_RECOVER
        | CkMechanismFlags::GENERATE_KEY_PAIR
        | CkMechanismFlags::WRAP
        | CkMechanismFlags::UNWRAP
        | CkMechanismFlags::DERIVE;
    let original = CkMechanismInfo { min_key_size: 0, max_key_size: u64::MAX, flags };
    let proto: v1_proto::MechanismInfo = (&original).into();
    let back = CkMechanismInfo::from(&proto);
    assert_eq!(back.flags, flags);
    // W1-C8-05: full-field assertions; a dropped field must fail.
    assert_eq!(back.min_key_size, 0);
    assert_eq!(back.max_key_size, u64::MAX);
}

#[test]
fn mechanism_info_sentinel_key_sizes() {
    let original =
        CkMechanismInfo { min_key_size: 0, max_key_size: u64::MAX, flags: CkMechanismFlags(0) };
    let proto: v1_proto::MechanismInfo = (&original).into();
    let back = CkMechanismInfo::from(&proto);
    // W1-C8-05: full-field assertions; a dropped field must fail.
    assert_eq!(back.flags, CkMechanismFlags(0));
    assert_eq!(back.min_key_size, 0);
    assert_eq!(back.max_key_size, u64::MAX);
}

#[test]
fn mechanism_info_flags_zero_round_trip() {
    let original = CkMechanismInfo { min_key_size: 0, max_key_size: 0, flags: CkMechanismFlags(0) };
    let proto: v1_proto::MechanismInfo = (&original).into();
    let back = CkMechanismInfo::from(&proto);
    assert_eq!(back, original);
}

// ---------------------------------------------------------------------------
// Batch 2: Key Derivation round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn ecdh2_derive_round_trip() {
    let params = CkMechanismParams::Ecdh2Derive(Ecdh2DeriveParams {
        kdf: CkKdf(2),
        private_data_len: 32,
        private_data_handle: CkObjectHandle(0x1234),
        shared_data_presence: PointerBytes::present_copy(&[0x01, 0x02]),
        public_data_presence: PointerBytes::present_copy(&[0x04; 65]),
        public_data2_presence: PointerBytes::present_copy(&[0x04; 65]),
    });
    match round_trip(params) {
        CkMechanismParams::Ecdh2Derive(p) => {
            assert_eq!(p.kdf.0, 2);
            assert_eq!(*p.shared_data_presence.as_present().unwrap(), vec![0x01, 0x02].into());
            assert_eq!(p.public_data_presence.as_present().unwrap().len(), 65);
            assert_eq!(p.private_data_len, 32);
            assert_eq!(p.private_data_handle.0, 0x1234);
            assert_eq!(p.public_data2_presence.as_present().unwrap().len(), 65);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ecmqv_derive_round_trip() {
    let params = CkMechanismParams::EcmqvDerive(EcmqvDeriveParams {
        kdf: CkKdf(3),
        private_data_len: 16,
        private_data_handle: CkObjectHandle(0xABCD),
        public_key_handle: CkObjectHandle(0xDEAD),
        shared_data_presence: PointerBytes::present_copy(&[0xAA]),
        public_data_presence: PointerBytes::present_copy(&[0x04; 33]),
        public_data2_presence: PointerBytes::present_copy(&[0x04; 33]),
    });
    match round_trip(params) {
        CkMechanismParams::EcmqvDerive(p) => {
            // W1-C8-05: full-field assertions; a dropped field must fail.
            assert_eq!(p.kdf.0, 3);
            assert_eq!(*p.shared_data_presence.as_present().unwrap(), vec![0xAA].into());
            assert_eq!(p.public_data_presence, PointerBytes::present_copy(&[0x04; 33]));
            assert_eq!(p.private_data_len, 16);
            assert_eq!(p.public_data2_presence, PointerBytes::present_copy(&[0x04; 33]));
            assert_eq!(p.public_key_handle.0, 0xDEAD);
            assert_eq!(p.private_data_handle.0, 0xABCD);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn x942_dh1_derive_round_trip() {
    let params = CkMechanismParams::X942Dh1Derive(X942Dh1DeriveParams {
        kdf: CkKdf(1),
        other_info_presence: PointerBytes::present_copy(&[0x10, 0x20]),
        public_data_presence: PointerBytes::present_copy(&[0x55; 128]),
    });
    match round_trip(params) {
        CkMechanismParams::X942Dh1Derive(p) => {
            assert_eq!(p.kdf.0, 1);
            assert_eq!(*p.other_info_presence.as_present().unwrap(), vec![0x10, 0x20].into());
            assert_eq!(p.public_data_presence.as_present().unwrap().len(), 128);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn x942_dh2_derive_round_trip() {
    let params = CkMechanismParams::X942Dh2Derive(X942Dh2DeriveParams {
        kdf: CkKdf(2),
        private_data_len: 64,
        private_data_handle: CkObjectHandle(42),
        other_info_presence: PointerBytes::present_copy(&[]),
        public_data_presence: PointerBytes::present_copy(&[0x55; 128]),
        public_data2_presence: PointerBytes::present_copy(&[0x66; 128]),
    });
    match round_trip(params) {
        CkMechanismParams::X942Dh2Derive(p) => {
            // W1-C8-05: full-field assertions; a dropped field must fail.
            assert_eq!(p.kdf.0, 2);
            assert!(p.other_info_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
            assert_eq!(p.public_data_presence, PointerBytes::present_copy(&[0x55; 128]));
            assert_eq!(p.private_data_len, 64);
            assert_eq!(p.private_data_handle.0, 42);
            assert_eq!(p.public_data2_presence.as_present().unwrap().len(), 128);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn x942_mqv_derive_round_trip() {
    let params = CkMechanismParams::X942MqvDerive(X942MqvDeriveParams {
        kdf: CkKdf(3),
        private_data_len: 32,
        private_data_handle: CkObjectHandle(100),
        other_info_presence: PointerBytes::present_copy(&[0xFF]),
        public_data_presence: PointerBytes::present_copy(&[0x11; 64]),
        public_data2_presence: PointerBytes::present_copy(&[0x22; 64]),
        public_key_handle: CkObjectHandle(200),
    });
    match round_trip(params) {
        CkMechanismParams::X942MqvDerive(p) => {
            // W1-C8-05: full-field assertions; a dropped field must fail.
            assert_eq!(p.kdf.0, 3);
            assert_eq!(*p.other_info_presence.as_present().unwrap(), vec![0xFF].into());
            assert_eq!(p.public_data_presence, PointerBytes::present_copy(&[0x11; 64]));
            assert_eq!(p.private_data_len, 32);
            assert_eq!(p.private_data_handle.0, 100);
            assert_eq!(p.public_data2_presence, PointerBytes::present_copy(&[0x22; 64]));
            assert_eq!(p.public_key_handle.0, 200);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn hkdf_round_trip() {
    let params = CkMechanismParams::Hkdf(HkdfParams {
        extract: true,
        expand: true,
        prf_hash_mechanism: CkMechanismType::SHA256,
        salt_type: 1,
        salt_key_handle: CkObjectHandle(0),
        salt_presence: PointerBytes::present_copy(&[0xAA; 32]),
        info_presence: PointerBytes::present_copy(&[0xBB; 16]),
    });
    match round_trip(params) {
        CkMechanismParams::Hkdf(p) => {
            // W1-C8-05: full-field assertions; a dropped field must fail.
            assert!(p.extract);
            assert!(p.expand);
            assert_eq!(p.prf_hash_mechanism.0, CkMechanismType::SHA256.0);
            assert_eq!(p.salt_type, 1);
            assert_eq!(p.salt_presence.as_present().unwrap().len(), 32);
            assert_eq!(p.salt_key_handle.0, 0);
            assert_eq!(p.info_presence.as_present().unwrap().len(), 16);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn hkdf_extract_only_round_trip() {
    let params = CkMechanismParams::Hkdf(HkdfParams {
        extract: true,
        expand: false,
        prf_hash_mechanism: CkMechanismType::SHA384,
        salt_type: 2,
        salt_key_handle: CkObjectHandle(0x42),
        salt_presence: PointerBytes::present_copy(&[]),
        info_presence: PointerBytes::present_copy(&[]),
    });
    match round_trip(params) {
        CkMechanismParams::Hkdf(p) => {
            // W1-C8-05: full-field assertions; a dropped field must fail.
            assert!(p.extract);
            assert!(!p.expand);
            assert_eq!(p.prf_hash_mechanism.0, CkMechanismType::SHA384.0);
            assert_eq!(p.salt_type, 2);
            assert!(p.salt_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
            assert_eq!(p.salt_key_handle.0, 0x42);
            assert!(p.info_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn eddsa_round_trip() {
    let params = CkMechanismParams::Eddsa(EddsaParams {
        ph_flag: true,
        context_data_presence: PointerBytes::present_copy(&[0x01, 0x02, 0x03]),
    });
    match round_trip(params) {
        CkMechanismParams::Eddsa(p) => {
            assert!(p.ph_flag);
            assert_eq!(
                *p.context_data_presence.as_present().unwrap(),
                vec![0x01, 0x02, 0x03].into()
            );
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn eddsa_no_context_round_trip() {
    let params = CkMechanismParams::Eddsa(EddsaParams {
        ph_flag: false,
        context_data_presence: PointerBytes::present_copy(&[]),
    });
    match round_trip(params) {
        CkMechanismParams::Eddsa(p) => {
            assert!(!p.ph_flag);
            assert!(p.context_data_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn gostr3410_derive_round_trip() {
    let params = CkMechanismParams::Gostr3410Derive(Gostr3410DeriveParams {
        kdf: CkKdf(1),
        public_data_presence: PointerBytes::present_copy(&[0xCC; 64]),
        ukm_presence: PointerBytes::present_copy(&[0xDD; 8]),
    });
    match round_trip(params) {
        CkMechanismParams::Gostr3410Derive(p) => {
            assert_eq!(p.kdf.0, 1);
            assert_eq!(p.public_data_presence.as_present().unwrap().len(), 64);
            assert_eq!(p.ukm_presence, PointerBytes::present_copy(&[0xDD; 8]));
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn kea_derive_round_trip() {
    let params = CkMechanismParams::KeaDerive(KeaDeriveParams {
        is_sender: true,
        random_a_presence: PointerBytes::present_copy(&[0x11; 128]),
        random_b_presence: PointerBytes::present_copy(&[0x22; 128]),
        public_data_presence: PointerBytes::present_copy(&[0x33; 128]),
    });
    match round_trip(params) {
        CkMechanismParams::KeaDerive(p) => {
            assert!(p.is_sender);
            assert_eq!(p.random_a_presence.as_present().unwrap().len(), 128);
            assert_eq!(p.random_b_presence.as_present().unwrap().len(), 128);
            assert_eq!(p.public_data_presence.as_present().unwrap().len(), 128);
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// Batch 2: Key Wrapping round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn ecdh_aes_key_wrap_round_trip() {
    let params = CkMechanismParams::EcdhAesKeyWrap(EcdhAesKeyWrapParams {
        aes_key_bits: 256,
        kdf: CkKdf(2),
        shared_data_presence: PointerBytes::present_copy(&[0xAA, 0xBB]),
    });
    match round_trip(params) {
        CkMechanismParams::EcdhAesKeyWrap(p) => {
            assert_eq!(p.aes_key_bits, 256);
            assert_eq!(p.kdf.0, 2);
            assert_eq!(*p.shared_data_presence.as_present().unwrap(), vec![0xAA, 0xBB].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn rsa_aes_key_wrap_round_trip() {
    let params = CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
        aes_key_bits: 128,
        oaep_params: RsaPkcsOaepParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: CkMgf(1),
            source: CkOaepSource(1),
            source_data_presence: PointerBytes::from_legacy(&[0x01, 0x02], false),
        },
    });
    match round_trip(params) {
        CkMechanismParams::RsaAesKeyWrap(p) => {
            assert_eq!(p.aes_key_bits, 128);
            assert_eq!(p.oaep_params.hash_alg, CkMechanismType::SHA256);
            assert_eq!(p.oaep_params.mgf.0, 1);
            assert_eq!(p.oaep_params.source.0, 1);
            assert_eq!(
                *p.oaep_params.source_data_presence.as_present().unwrap(),
                vec![0x01, 0x02].into()
            );
            // W1-C8-05: nested source_null is a field too; a drop must fail.
            assert!(!p.oaep_params.source_data_presence.is_null());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn rsa_aes_key_wrap_rejects_missing_nested_oaep_params() {
    let proto = v1_proto::Mechanism {
        mechanism_type: CkMechanismType::RSA_PKCS_OAEP.0,
        params: Some(v1_proto::mechanism::Params::RsaAesKeyWrapParams(
            v1_proto::RsaAesKeyWrapParams { aes_key_bits: 128, oaep_params: None },
        )),
        parameter_encoding_version: 0,
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn gostr3410_key_wrap_round_trip() {
    let params = CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
        key_handle: CkObjectHandle(0xBEEF),
        wrap_oid_presence: PointerBytes::present_copy(&[0x06, 0x07, 0x2A]),
        ukm_presence: PointerBytes::present_copy(&[0xEE; 8]),
    });
    match round_trip(params) {
        CkMechanismParams::Gostr3410KeyWrap(p) => {
            assert_eq!(p.wrap_oid_presence, PointerBytes::present_copy(&[0x06, 0x07, 0x2A]));
            assert_eq!(p.ukm_presence.as_present().unwrap().len(), 8);
            assert_eq!(p.key_handle.0, 0xBEEF);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn key_wrap_set_oaep_round_trip() {
    let params = CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams {
        bc: 42,
        x_presence: PointerBytes::present_copy(&[0xFF; 8]),
    });
    match round_trip(params) {
        CkMechanismParams::KeyWrapSetOaep(p) => {
            assert_eq!(p.bc, 42);
            assert_eq!(*p.x_presence.as_present().unwrap(), vec![0xFF; 8].into());
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// Batch 2: PBE round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn pbe_round_trip() {
    let params = CkMechanismParams::Pbe(PbeParams {
        iteration: 10000,
        init_vector_presence: PointerBytes::present_copy(&[0x01; 16]),
        password_presence: PointerBytes::present_copy(&[0x70, 0x61, 0x73, 0x73]),
        salt_presence: PointerBytes::present_copy(&[0xAA; 16]),
    });
    match round_trip(params) {
        CkMechanismParams::Pbe(p) => {
            assert_eq!(p.init_vector_presence.as_present().unwrap().len(), 16);
            assert_eq!(
                *p.password_presence.as_present().unwrap(),
                vec![0x70, 0x61, 0x73, 0x73].into()
            );
            assert_eq!(p.salt_presence.as_present().unwrap().len(), 16);
            assert_eq!(p.iteration, 10000);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn pkcs5_pbkd2_round_trip() {
    let params = CkMechanismParams::Pkcs5Pbkd2(Pkcs5Pbkd2Params {
        salt_source: CkPbkdf2SaltSource(1),
        iterations: 600000,
        prf: CkPbkdf2Prf(2),
        salt_source_data_presence: PointerBytes::present_copy(&[0xBB; 16]),
        prf_data_presence: PointerBytes::present_copy(&[]),
        password_presence: PointerBytes::present_copy(&[0x73, 0x65, 0x63, 0x72, 0x65, 0x74]),
    });
    match round_trip(params) {
        CkMechanismParams::Pkcs5Pbkd2(p) => {
            assert_eq!(p.salt_source.0, 1);
            assert_eq!(p.salt_source_data_presence.as_present().unwrap().len(), 16);
            assert_eq!(p.iterations, 600000);
            assert_eq!(p.prf.0, 2);
            assert!(p.prf_data_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
            assert_eq!(p.password_presence.as_present().unwrap().len(), 6);
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// W1-L2-04: owned-adopting PBE conversions wipe the source password buffers
// ---------------------------------------------------------------------------

#[test]
fn pbe_adopting_conversion_wipes_source() {
    let canary = vec![0xA5u8; 32];
    let mut proto = v1_proto::PbeParams {
        init_vector: vec![0x01; 16],
        password: canary.clone(),
        salt: vec![0xAA; 16],
        iteration: 10000,
        init_vector_null_len: None,
        password_null_len: None,
        salt_null_len: None,
    };
    let adopted = PbeParams::from(&mut proto);
    // Source buffers adopted out: no secret bytes remain in the prost message.
    assert!(proto.init_vector.is_empty());
    assert!(proto.password.is_empty());
    assert!(proto.salt.is_empty());
    // Converted value holds the canary.
    adopted
        .password_presence
        .as_present()
        .unwrap()
        .expose(|bytes| assert_eq!(bytes, canary.as_slice()));
    assert_eq!(adopted.init_vector_presence.as_present().unwrap().len(), 16);
    assert_eq!(adopted.salt_presence.as_present().unwrap().len(), 16);
    assert_eq!(adopted.iteration, 10000);
}

#[test]
fn pkcs5_pbkd2_adopting_conversion_wipes_source() {
    let canary = vec![0x5Au8; 16];
    let mut proto = v1_proto::Pkcs5Pbkd2Params {
        salt_source: 1,
        salt_source_data: vec![0xBB; 16],
        iterations: 600000,
        prf: 2,
        prf_data: vec![0xCC; 8],
        password: canary.clone(),
        salt_source_data_null_len: None,
        prf_data_null_len: None,
        password_null_len: None,
    };
    let adopted = Pkcs5Pbkd2Params::from(&mut proto);
    // Every source buffer adopted out; nothing secret remains behind.
    assert!(proto.salt_source_data.is_empty());
    assert!(proto.prf_data.is_empty());
    assert!(proto.password.is_empty());
    // Converted values hold the canary.
    adopted
        .password_presence
        .as_present()
        .unwrap()
        .expose(|bytes| assert_eq!(bytes, canary.as_slice()));
    adopted
        .salt_source_data_presence
        .as_present()
        .unwrap()
        .expose(|bytes| assert_eq!(bytes, vec![0xBB; 16].as_slice()));
    adopted
        .prf_data_presence
        .as_present()
        .unwrap()
        .expose(|bytes| assert_eq!(bytes, vec![0xCC; 8].as_slice()));
    assert_eq!(adopted.salt_source.0, 1);
    assert_eq!(adopted.iterations, 600000);
    assert_eq!(adopted.prf.0, 2);
}

#[test]
fn pbe_prost_messages_zeroize_wipes_passwords() {
    use zeroize::Zeroize;
    // `ZeroizeOnDrop` (derived alongside `Zeroize` in build.rs) delegates
    // drop-wiping to this same `zeroize`; post-drop memory is unobservable,
    // so the test pins the wipe behavior directly.
    // All fields spelled out: struct-update syntax cannot move fields out
    // of the `ZeroizeOnDrop` temporary.
    let mut pbe = v1_proto::PbeParams {
        init_vector: vec![0x01; 16],
        password: vec![0xA5u8; 32],
        salt: vec![0xAA; 16],
        iteration: 10000,
        init_vector_null_len: None,
        password_null_len: None,
        salt_null_len: None,
    };
    pbe.zeroize();
    assert!(pbe.password.iter().all(|&byte| byte == 0));
    assert!(pbe.init_vector.iter().all(|&byte| byte == 0));
    assert!(pbe.salt.iter().all(|&byte| byte == 0));
    let mut pbkd2 = v1_proto::Pkcs5Pbkd2Params {
        salt_source: 1,
        salt_source_data: vec![0xBB; 16],
        iterations: 600000,
        prf: 2,
        prf_data: vec![0xCC; 8],
        password: vec![0x5Au8; 16],
        salt_source_data_null_len: None,
        prf_data_null_len: None,
        password_null_len: None,
    };
    pbkd2.zeroize();
    assert!(pbkd2.password.iter().all(|&byte| byte == 0));
    assert!(pbkd2.salt_source_data.iter().all(|&byte| byte == 0));
    assert!(pbkd2.prf_data.iter().all(|&byte| byte == 0));
}

#[test]
fn pbe_prost_messages_wipe_on_drop() {
    // Compile-time pin (Task 8 review-B1 pattern): deleting `ZeroizeOnDrop`
    // from either build.rs `type_attribute` line must fail compilation here.
    fn assert_wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_wiped_on_drop::<v1_proto::PbeParams>();
    assert_wiped_on_drop::<v1_proto::Pkcs5Pbkd2Params>();
}

// ---------------------------------------------------------------------------
// Batch 1: Trivial scalar-only round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn rc5_params_round_trip() {
    let p = round_trip(CkMechanismParams::Rc5(Rc5Params { word_size: 4, rounds: 12 }));
    match p {
        CkMechanismParams::Rc5(v) => {
            assert_eq!(v.word_size, 4);
            assert_eq!(v.rounds, 12);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn rc5_mac_general_params_round_trip() {
    let p = round_trip(CkMechanismParams::Rc5MacGeneral(Rc5MacGeneralParams {
        word_size: 4,
        rounds: 12,
        mac_length: 16,
    }));
    match p {
        CkMechanismParams::Rc5MacGeneral(v) => {
            assert_eq!(v.word_size, 4);
            assert_eq!(v.rounds, 12);
            assert_eq!(v.mac_length, 16);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn rc2_mac_general_params_round_trip() {
    let p = round_trip(CkMechanismParams::Rc2MacGeneral(Rc2MacGeneralParams {
        effective_bits: 128,
        mac_length: 8,
    }));
    match p {
        CkMechanismParams::Rc2MacGeneral(v) => {
            assert_eq!(v.effective_bits, 128);
            assert_eq!(v.mac_length, 8);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn xeddsa_params_round_trip() {
    let p = round_trip(CkMechanismParams::Xeddsa(XeddsaParams { hash: CkMechanismType(0x250) }));
    match p {
        CkMechanismParams::Xeddsa(v) => assert_eq!(v.hash.0, 0x250),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn tls_mac_params_round_trip() {
    let p = round_trip(CkMechanismParams::TlsMac(TlsMacParams {
        prf_hash_mechanism: CkMechanismType(0x250),
        mac_length: 32,
        server_or_client: 1,
    }));
    match p {
        CkMechanismParams::TlsMac(v) => {
            assert_eq!(v.prf_hash_mechanism.0, 0x250);
            assert_eq!(v.mac_length, 32);
            assert_eq!(v.server_or_client, 1);
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// Batch 1: Symmetric with fixed IV round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn aes_ctr_params_round_trip() {
    let p = round_trip(CkMechanismParams::AesCtr(AesCtrParams {
        counter_bits: 128,
        cb: vec![0x01; 16],
    }));
    match p {
        CkMechanismParams::AesCtr(v) => {
            assert_eq!(v.counter_bits, 128);
            assert_eq!(v.cb, vec![0x01; 16]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn camellia_ctr_params_round_trip() {
    let p = round_trip(CkMechanismParams::CamelliaCtr(CamelliaCtrParams {
        counter_bits: 64,
        cb: vec![0xAB; 16],
    }));
    match p {
        CkMechanismParams::CamelliaCtr(v) => {
            assert_eq!(v.counter_bits, 64);
            assert_eq!(v.cb, vec![0xAB; 16]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn rc2_cbc_params_round_trip() {
    let p = round_trip(CkMechanismParams::Rc2Cbc(Rc2CbcParams {
        effective_bits: 64,
        iv: vec![0x11; 8],
    }));
    match p {
        CkMechanismParams::Rc2Cbc(v) => {
            assert_eq!(v.effective_bits, 64);
            assert_eq!(v.iv, vec![0x11; 8]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn rc5_cbc_params_round_trip() {
    let p = round_trip(CkMechanismParams::Rc5Cbc(Rc5CbcParams {
        word_size: 4,
        rounds: 16,
        iv_presence: PointerBytes::present_copy(&[0xCC; 8]),
    }));
    match p {
        CkMechanismParams::Rc5Cbc(v) => {
            assert_eq!(v.word_size, 4);
            assert_eq!(v.rounds, 16);
            assert_eq!(v.iv_presence, PointerBytes::present_copy(&[0xCC; 8]));
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// Batch 1: CBC encrypt data round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn aes_cbc_encrypt_data_params_round_trip() {
    let p = round_trip(CkMechanismParams::AesCbcEncryptData(AesCbcEncryptDataParams {
        iv: vec![0x01; 16],
        data_presence: PointerBytes::present_copy(&[0xDE, 0xAD, 0xBE, 0xEF]),
    }));
    match p {
        CkMechanismParams::AesCbcEncryptData(v) => {
            assert_eq!(v.iv, vec![0x01; 16]);
            assert_eq!(*v.data_presence.as_present().unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn des_cbc_encrypt_data_params_round_trip() {
    let p = round_trip(CkMechanismParams::DesCbcEncryptData(DesCbcEncryptDataParams {
        iv: vec![0xAA; 8],
        data_presence: PointerBytes::present_copy(&[0x01, 0x02, 0x03]),
    }));
    match p {
        CkMechanismParams::DesCbcEncryptData(v) => {
            assert_eq!(v.iv, vec![0xAA; 8]);
            assert_eq!(*v.data_presence.as_present().unwrap(), vec![0x01, 0x02, 0x03].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn aria_cbc_encrypt_data_params_round_trip() {
    let p = round_trip(CkMechanismParams::AriaCbcEncryptData(AriaCbcEncryptDataParams {
        iv: vec![0xBB; 16],
        data_presence: PointerBytes::present_copy(&[0x10; 32]),
    }));
    match p {
        CkMechanismParams::AriaCbcEncryptData(v) => {
            assert_eq!(v.iv, vec![0xBB; 16]);
            assert_eq!(*v.data_presence.as_present().unwrap(), vec![0x10; 32].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn camellia_cbc_encrypt_data_params_round_trip() {
    let p = round_trip(CkMechanismParams::CamelliaCbcEncryptData(CamelliaCbcEncryptDataParams {
        iv: vec![0xCC; 16],
        data_presence: PointerBytes::present_copy(&[0x20; 48]),
    }));
    match p {
        CkMechanismParams::CamelliaCbcEncryptData(v) => {
            assert_eq!(v.iv, vec![0xCC; 16]);
            assert_eq!(*v.data_presence.as_present().unwrap(), vec![0x20; 48].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn seed_cbc_encrypt_data_params_round_trip() {
    let p = round_trip(CkMechanismParams::SeedCbcEncryptData(SeedCbcEncryptDataParams {
        iv: vec![0xDD; 16],
        data_presence: PointerBytes::present_copy(&[]),
    }));
    match p {
        CkMechanismParams::SeedCbcEncryptData(v) => {
            assert_eq!(v.iv, vec![0xDD; 16]);
            assert!(v.data_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// Batch 1: AEAD round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn ccm_params_round_trip() {
    let p = round_trip(CkMechanismParams::Ccm(CcmParams {
        data_len: 256,
        mac_len: 16,
        nonce_presence: PointerBytes::from_legacy(&[0x01; 12], false),
        aad_presence: PointerBytes::from_legacy(&[0xAA, 0xBB], false),
    }));
    match p {
        CkMechanismParams::Ccm(v) => {
            assert_eq!(v.data_len, 256);
            assert_eq!(v.nonce_presence, PointerBytes::present_copy(&[0x01; 12]));
            assert_eq!(*v.aad_presence.as_present().unwrap(), vec![0xAA, 0xBB].into());
            assert_eq!(v.mac_len, 16);
            assert!(!v.nonce_presence.is_null());
            assert!(!v.aad_presence.is_null());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn chacha20_params_round_trip() {
    let p = round_trip(CkMechanismParams::ChaCha20(ChaCha20Params {
        block_counter_bits: 32,
        nonce_bits: 96,
        block_counter_presence: PointerBytes::present_copy(&[0x00; 4]),
        nonce_presence: PointerBytes::present_copy(&[0x01; 12]),
    }));
    match p {
        CkMechanismParams::ChaCha20(v) => {
            assert_eq!(v.block_counter_presence, PointerBytes::present_copy(&[0x00; 4]));
            assert_eq!(v.block_counter_bits, 32);
            assert_eq!(v.nonce_presence, PointerBytes::present_copy(&[0x01; 12]));
            assert_eq!(v.nonce_bits, 96);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn salsa20_params_round_trip() {
    let p = round_trip(CkMechanismParams::Salsa20(Salsa20Params {
        nonce_bits: 64,
        block_counter_presence: PointerBytes::present_copy(&[0x00; 8]),
        nonce_presence: PointerBytes::present_copy(&[0x02; 8]),
    }));
    match p {
        CkMechanismParams::Salsa20(v) => {
            assert_eq!(v.block_counter_presence, PointerBytes::present_copy(&[0x00; 8]));
            assert_eq!(v.nonce_presence, PointerBytes::present_copy(&[0x02; 8]));
            assert_eq!(v.nonce_bits, 64);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn salsa20_chacha20_poly1305_params_round_trip() {
    let p = round_trip(CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
        nonce_presence: PointerBytes::present_copy(&[0x03; 12]),
        aad_presence: PointerBytes::present_copy(&[0x04; 20]),
    }));
    match p {
        CkMechanismParams::Salsa20ChaCha20Poly1305(v) => {
            assert_eq!(v.nonce_presence, PointerBytes::present_copy(&[0x03; 12]));
            assert_eq!(*v.aad_presence.as_present().unwrap(), vec![0x04; 20].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn salsa20_chacha20_poly1305_empty_aad_round_trip() {
    let p = round_trip(CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
        nonce_presence: PointerBytes::present_copy(&[0x05; 12]),
        aad_presence: PointerBytes::present_copy(&[]),
    }));
    match p {
        CkMechanismParams::Salsa20ChaCha20Poly1305(v) => {
            assert_eq!(v.nonce_presence, PointerBytes::present_copy(&[0x05; 12]));
            assert!(v.aad_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn gcm_wrap_params_round_trip() {
    let p = round_trip(CkMechanismParams::GcmWrap(GcmWrapParams {
        iv_fixed_bits: 32,
        iv_generator: CkGeneratorFunction(1),
        tag_bits: 128,
        iv_presence: PointerBytes::present_copy(&[0x01; 12]),
        aad_presence: PointerBytes::present_copy(&[0xAA]),
    }));
    match p {
        CkMechanismParams::GcmWrap(v) => {
            assert_eq!(v.iv_presence, PointerBytes::present_copy(&[0x01; 12]));
            assert_eq!(v.iv_fixed_bits, 32);
            assert_eq!(v.iv_generator.0, 1);
            assert_eq!(*v.aad_presence.as_present().unwrap(), vec![0xAA].into());
            assert_eq!(v.tag_bits, 128);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ccm_wrap_params_round_trip() {
    let p = round_trip(CkMechanismParams::CcmWrap(CcmWrapParams {
        data_len: 1024,
        nonce_fixed_bits: 24,
        nonce_generator: CkGeneratorFunction(2),
        mac_len: 8,
        nonce_presence: PointerBytes::present_copy(&[0x02; 7]),
        aad_presence: PointerBytes::present_copy(&[0xBB, 0xCC]),
    }));
    match p {
        CkMechanismParams::CcmWrap(v) => {
            assert_eq!(v.data_len, 1024);
            assert_eq!(v.nonce_presence, PointerBytes::present_copy(&[0x02; 7]));
            assert_eq!(v.nonce_fixed_bits, 24);
            assert_eq!(v.nonce_generator.0, 2);
            assert_eq!(*v.aad_presence.as_present().unwrap(), vec![0xBB, 0xCC].into());
            assert_eq!(v.mac_len, 8);
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// Batch 3: TLS/SSL round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn tls_prf_params_round_trip() {
    let p = round_trip(CkMechanismParams::TlsPrf(TlsPrfParams {
        output_len: 48,
        // W1-C5-01: the provider-written output must survive the trip.
        output: vec![0x5A; 48].into(),
        seed_presence: PointerBytes::present_copy(&[0x01; 32]),
        label_presence: PointerBytes::present_copy(&[0x6D, 0x61, 0x73, 0x74]),
        output_is_null: false,
        output_len_is_null: false,
    }));
    match p {
        CkMechanismParams::TlsPrf(v) => {
            assert_eq!(v.seed_presence.as_present().unwrap().len(), 32);
            assert_eq!(
                *v.label_presence.as_present().unwrap(),
                vec![0x6D, 0x61, 0x73, 0x74].into()
            );
            assert_eq!(v.output_len, 48);
            assert_eq!(v.output, vec![0x5A; 48].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn tls_kdf_params_round_trip() {
    let p = round_trip(CkMechanismParams::TlsKdf(TlsKdfParams {
        prf_mechanism: CkMechanismType(0x250),
        random_info: SslRandomData {
            client_random_presence: PointerBytes::present_copy(&[0xAA; 32]),
            server_random_presence: PointerBytes::present_copy(&[0xBB; 32]),
        },
        label_presence: PointerBytes::present_copy(&[0x6B, 0x65, 0x79]),
        context_data_presence: PointerBytes::present_copy(&[0xCC; 16]),
    }));
    match p {
        CkMechanismParams::TlsKdf(v) => {
            assert_eq!(v.prf_mechanism.0, 0x250);
            assert_eq!(*v.label_presence.as_present().unwrap(), vec![0x6B, 0x65, 0x79].into());
            assert_eq!(
                v.random_info.client_random_presence,
                PointerBytes::present_copy(&[0xAA; 32])
            );
            assert_eq!(
                v.random_info.server_random_presence,
                PointerBytes::present_copy(&[0xBB; 32])
            );
            assert_eq!(v.context_data_presence.as_present().unwrap().len(), 16);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn tls_kdf_params_reject_missing_random_info() {
    let proto = v1_proto::Mechanism {
        mechanism_type: 0x0000_0037,
        params: Some(v1_proto::mechanism::Params::TlsKdfParams(v1_proto::TlsKdfParams {
            prf_mechanism: CkMechanismType::SHA256.0,
            label: b"key".to_vec(),
            random_info: None,
            context_data: vec![],
            label_null_len: None,
            context_data_null_len: None,
        })),
        parameter_encoding_version: 0,
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn tls_kdf_params_preserve_present_empty_random_info() {
    let p = round_trip(CkMechanismParams::TlsKdf(TlsKdfParams {
        prf_mechanism: CkMechanismType::SHA256,
        random_info: SslRandomData {
            client_random_presence: PointerBytes::present_copy(&[]),
            server_random_presence: PointerBytes::present_copy(&[]),
        },
        label_presence: PointerBytes::present_copy(&[]),
        context_data_presence: PointerBytes::present_copy(&[]),
    }));

    match p {
        CkMechanismParams::TlsKdf(v) => {
            assert!(v.label_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
            assert!(
                v.random_info
                    .client_random_presence
                    .as_present()
                    .map(|b| b.is_empty())
                    .unwrap_or(true)
            );
            assert!(
                v.random_info
                    .server_random_presence
                    .as_present()
                    .map(|b| b.is_empty())
                    .unwrap_or(true)
            );
            assert!(v.context_data_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ssl3_master_key_derive_round_trip() {
    let p = round_trip(CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
        random_info: SslRandomData {
            client_random_presence: PointerBytes::present_copy(&[0x11; 32]),
            server_random_presence: PointerBytes::present_copy(&[0x22; 32]),
        },
        version_major: 3,
        version_minor: 0,
        version_is_null: false,
    }));
    match p {
        CkMechanismParams::Ssl3MasterKeyDerive(v) => {
            assert_eq!(v.random_info.client_random_presence.as_present().unwrap().len(), 32);
            // W1-C8-05: server_random is a field too; a dropped half must fail.
            assert_eq!(
                v.random_info.server_random_presence,
                PointerBytes::present_copy(&[0x22; 32])
            );
            assert_eq!(v.version_major, 3);
            assert_eq!(v.version_minor, 0);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ssl3_master_key_derive_rejects_missing_random_info() {
    // W1-C8-04: required nested random_info must be rejected when absent.
    let proto = v1_proto::Mechanism {
        mechanism_type: CkMechanismType::SSL3_MASTER_KEY_DERIVE.0,
        params: Some(v1_proto::mechanism::Params::Ssl3MasterKeyDeriveParams(
            v1_proto::Ssl3MasterKeyDeriveParams {
                random_info: None,
                version_major: 3,
                version_minor: 0,
                version_null: None,
            },
        )),
        parameter_encoding_version: 0,
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn tls12_master_key_derive_round_trip() {
    let p = round_trip(CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
        random_info: SslRandomData {
            client_random_presence: PointerBytes::present_copy(&[0x33; 32]),
            server_random_presence: PointerBytes::present_copy(&[0x44; 32]),
        },
        version_major: 3,
        version_minor: 3,
        prf_hash_mechanism: CkMechanismType(0x250),
        version_is_null: false,
    }));
    match p {
        CkMechanismParams::Tls12MasterKeyDerive(v) => {
            assert_eq!(v.version_major, 3);
            assert_eq!(v.version_minor, 3);
            assert_eq!(v.prf_hash_mechanism.0, 0x250);
            assert_eq!(v.random_info.client_random_presence.as_present().unwrap().len(), 32);
            // W1-C8-05: server_random is a field too; a dropped half must fail.
            assert_eq!(
                v.random_info.server_random_presence,
                PointerBytes::present_copy(&[0x44; 32])
            );
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn tls12_master_key_derive_rejects_missing_random_info() {
    // W1-C8-04: required nested random_info must be rejected when absent.
    let proto = v1_proto::Mechanism {
        mechanism_type: CkMechanismType::TLS12_MASTER_KEY_DERIVE.0,
        params: Some(v1_proto::mechanism::Params::Tls12MasterKeyDeriveParams(
            v1_proto::Tls12MasterKeyDeriveParams {
                random_info: None,
                version_major: 3,
                version_minor: 3,
                prf_hash_mechanism: 0x250,
                version_null: None,
            },
        )),
        parameter_encoding_version: 0,
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn tls12_extended_master_key_derive_round_trip() {
    let p = round_trip(CkMechanismParams::Tls12ExtendedMasterKeyDerive(
        Tls12ExtendedMasterKeyDeriveParams {
            prf_hash_mechanism: CkMechanismType(0x260),
            version_major: 3,
            version_minor: 3,
            session_hash_presence: PointerBytes::present_copy(&[0x55; 48]),
            version_is_null: false,
        },
    ));
    match p {
        CkMechanismParams::Tls12ExtendedMasterKeyDerive(v) => {
            assert_eq!(v.prf_hash_mechanism.0, 0x260);
            assert_eq!(v.session_hash_presence.as_present().unwrap().len(), 48);
            assert_eq!(v.version_major, 3);
            assert_eq!(v.version_minor, 3);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ssl3_key_mat_params_round_trip() {
    let p = round_trip(CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
        mac_size_bits: 160,
        key_size_bits: 128,
        iv_size_bits: 128,
        is_export: false,
        random_info: SslRandomData {
            client_random_presence: PointerBytes::present_copy(&[0x66; 32]),
            server_random_presence: PointerBytes::present_copy(&[0x77; 32]),
        },
        prf_hash_mechanism: CkMechanismType(0x250),
        client_mac_secret_handle: CkObjectHandle(101),
        server_mac_secret_handle: CkObjectHandle(102),
        client_key_handle: CkObjectHandle(201),
        server_key_handle: CkObjectHandle(202),
        client_iv_presence: PointerBytes::present_copy(&[0xA1; 16]),
        server_iv_presence: PointerBytes::present_copy(&[0xB1; 16]),
        returned_key_material_is_null: false,
    }));
    match p {
        CkMechanismParams::Ssl3KeyMat(v) => {
            assert_eq!(v.mac_size_bits, 160);
            assert_eq!(v.key_size_bits, 128);
            assert_eq!(v.iv_size_bits, 128);
            assert!(!v.is_export);
            // W1-C8-05: random_info contents are fields too; a drop must fail.
            assert_eq!(
                v.random_info.client_random_presence,
                PointerBytes::present_copy(&[0x66; 32])
            );
            assert_eq!(
                v.random_info.server_random_presence,
                PointerBytes::present_copy(&[0x77; 32])
            );
            assert_eq!(v.prf_hash_mechanism.0, 0x250);
            assert_eq!(v.client_mac_secret_handle.0, 101);
            assert_eq!(v.server_mac_secret_handle.0, 102);
            assert_eq!(v.client_key_handle.0, 201);
            assert_eq!(v.server_key_handle.0, 202);
            assert_eq!(*v.client_iv_presence.as_present().unwrap(), vec![0xA1; 16].into());
            assert_eq!(*v.server_iv_presence.as_present().unwrap(), vec![0xB1; 16].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ssl3_key_mat_params_rejects_missing_random_info() {
    // W1-C8-04: required nested random_info must be rejected when absent.
    let proto = v1_proto::Mechanism {
        mechanism_type: CkMechanismType::SSL3_KEY_AND_MAC_DERIVE.0,
        params: Some(v1_proto::mechanism::Params::Ssl3KeyMatParams(v1_proto::Ssl3KeyMatParams {
            mac_size_bits: 160,
            key_size_bits: 128,
            iv_size_bits: 128,
            is_export: false,
            random_info: None,
            prf_hash_mechanism: 0x250,
            client_mac_secret_handle: 101,
            server_mac_secret_handle: 102,
            client_key_handle: 201,
            server_key_handle: 202,
            client_iv: vec![0xA1; 16],
            server_iv: vec![0xB1; 16],
            returned_key_material_null: None,
            client_iv_null_len: None,
            server_iv_null_len: None,
        })),
        parameter_encoding_version: 0,
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn wtls_master_key_derive_round_trip() {
    let p = round_trip(CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
        digest_mechanism: CkMechanismType(0x250),
        random_info: WtlsRandomData {
            client_random_presence: PointerBytes::present_copy(&[0x88; 16]),
            server_random_presence: PointerBytes::present_copy(&[0x99; 16]),
        },
        version: 1,
        version_is_null: false,
    }));
    match p {
        CkMechanismParams::WtlsMasterKeyDerive(v) => {
            assert_eq!(v.digest_mechanism.0, 0x250);
            assert_eq!(v.random_info.client_random_presence.as_present().unwrap().len(), 16);
            // W1-C8-05: server_random is a field too; a dropped half must fail.
            assert_eq!(
                v.random_info.server_random_presence,
                PointerBytes::present_copy(&[0x99; 16])
            );
            assert_eq!(v.version, 1);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn wtls_master_key_derive_rejects_missing_random_info() {
    let proto = v1_proto::Mechanism {
        mechanism_type: 0x0000_0250,
        params: Some(v1_proto::mechanism::Params::WtlsMasterKeyDeriveParams(
            v1_proto::WtlsMasterKeyDeriveParams {
                digest_mechanism: CkMechanismType::SHA256.0,
                random_info: None,
                version: 1,
                version_null: None,
            },
        )),
        parameter_encoding_version: 0,
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn wtls_prf_params_round_trip() {
    let p = round_trip(CkMechanismParams::WtlsPrf(WtlsPrfParams {
        digest_mechanism: CkMechanismType(0x260),
        output_len: 32,
        // W1-C5-01: the provider-written output must survive the trip.
        output: vec![0xA5; 32].into(),
        seed_presence: PointerBytes::present_copy(&[0xAA; 20]),
        label_presence: PointerBytes::present_copy(&[0xBB; 10]),
        output_is_null: false,
        output_len_is_null: false,
    }));
    match p {
        CkMechanismParams::WtlsPrf(v) => {
            assert_eq!(v.digest_mechanism.0, 0x260);
            assert_eq!(v.seed_presence.as_present().unwrap().len(), 20);
            assert_eq!(v.label_presence.as_present().unwrap().len(), 10);
            assert_eq!(v.output_len, 32);
            assert_eq!(v.output, vec![0xA5; 32].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn wtls_key_mat_params_round_trip() {
    let p = round_trip(CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
        digest_mechanism: CkMechanismType(0x250),
        mac_size_bits: 160,
        key_size_bits: 128,
        iv_size_bits: 64,
        sequence_number: 42,
        is_export: true,
        random_info: WtlsRandomData {
            client_random_presence: PointerBytes::present_copy(&[0xCC; 16]),
            server_random_presence: PointerBytes::present_copy(&[0xDD; 16]),
        },
        mac_secret_handle: CkObjectHandle(101),
        key_handle: CkObjectHandle(202),
        iv_presence: PointerBytes::present_copy(&[0xA1; 8]),
        returned_key_material_is_null: false,
    }));
    match p {
        CkMechanismParams::WtlsKeyMat(v) => {
            // W1-C8-05: full-field assertions; a dropped field must fail.
            assert_eq!(v.digest_mechanism.0, 0x250);
            assert_eq!(v.mac_size_bits, 160);
            assert_eq!(v.key_size_bits, 128);
            assert_eq!(v.iv_size_bits, 64);
            assert_eq!(v.sequence_number, 42);
            assert!(v.is_export);
            assert_eq!(v.random_info.client_random_presence.as_present().unwrap().len(), 16);
            assert_eq!(
                v.random_info.server_random_presence,
                PointerBytes::present_copy(&[0xDD; 16])
            );
            assert_eq!(v.mac_secret_handle.0, 101);
            assert_eq!(v.key_handle.0, 202);
            assert_eq!(*v.iv_presence.as_present().unwrap(), vec![0xA1; 8].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn wtls_key_mat_params_rejects_missing_random_info() {
    // W1-C8-04: required nested random_info must be rejected when absent.
    let proto = v1_proto::Mechanism {
        mechanism_type: CkMechanismType::WTLS_PRF.0,
        params: Some(v1_proto::mechanism::Params::WtlsKeyMatParams(v1_proto::WtlsKeyMatParams {
            digest_mechanism: 0x250,
            mac_size_bits: 160,
            key_size_bits: 128,
            iv_size_bits: 64,
            sequence_number: 42,
            is_export: true,
            random_info: None,
            mac_secret_handle: 101,
            key_handle: 202,
            iv: vec![0xA1; 8],
            returned_key_material_null: None,
            iv_null_len: None,
        })),
        parameter_encoding_version: 0,
    };

    expect_mechanism_param_invalid(proto);
}

// ---------------------------------------------------------------------------
// Batch 3: IKE/IPSec round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn ike_prf_derive_round_trip() {
    let p = round_trip(CkMechanismParams::IkePrfDerive(IkePrfDeriveParams {
        prf_mechanism: CkMechanismType(0x250),
        data_as_key: true,
        rekey: false,
        new_key_handle: CkObjectHandle(0x1234),
        ni_presence: PointerBytes::present_copy(&[0x01; 32]),
        nr_presence: PointerBytes::present_copy(&[0x02; 32]),
    }));
    match p {
        CkMechanismParams::IkePrfDerive(v) => {
            assert_eq!(v.prf_mechanism.0, 0x250);
            assert!(v.data_as_key);
            assert!(!v.rekey);
            assert_eq!(v.ni_presence.as_present().unwrap().len(), 32);
            assert_eq!(v.nr_presence.as_present().unwrap().len(), 32);
            assert_eq!(v.new_key_handle.0, 0x1234);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ike1_prf_derive_round_trip() {
    let p = round_trip(CkMechanismParams::Ike1PrfDerive(Ike1PrfDeriveParams {
        prf_mechanism: CkMechanismType(0x260),
        has_prev_key: true,
        keygxy_handle: CkObjectHandle(0xAAAA),
        prev_key_handle: CkObjectHandle(0xBBBB),
        key_number: 3,
        ckyi_presence: PointerBytes::present_copy(&[0x11; 8]),
        ckyr_presence: PointerBytes::present_copy(&[0x22; 8]),
    }));
    match p {
        CkMechanismParams::Ike1PrfDerive(v) => {
            assert_eq!(v.prf_mechanism.0, 0x260);
            assert!(v.has_prev_key);
            assert_eq!(v.keygxy_handle.0, 0xAAAA);
            assert_eq!(v.prev_key_handle.0, 0xBBBB);
            assert_eq!(v.ckyi_presence.as_present().unwrap().len(), 8);
            // W1-C8-05: ckyr is a field too; a dropped half must fail.
            assert_eq!(*v.ckyr_presence.as_present().unwrap(), vec![0x22; 8].into());
            assert_eq!(v.key_number, 3);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ike1_extended_derive_round_trip() {
    let p = round_trip(CkMechanismParams::Ike1ExtendedDerive(Ike1ExtendedDeriveParams {
        prf_mechanism: CkMechanismType(0x270),
        has_keygxy: true,
        keygxy_handle: CkObjectHandle(0xCCCC),
        extra_data_presence: PointerBytes::present_copy(&[0x33; 64]),
    }));
    match p {
        CkMechanismParams::Ike1ExtendedDerive(v) => {
            assert_eq!(v.prf_mechanism.0, 0x270);
            assert!(v.has_keygxy);
            assert_eq!(v.keygxy_handle.0, 0xCCCC);
            assert_eq!(v.extra_data_presence.as_present().unwrap().len(), 64);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ike2_prf_plus_derive_round_trip() {
    let p = round_trip(CkMechanismParams::Ike2PrfPlusDerive(Ike2PrfPlusDeriveParams {
        prf_mechanism: CkMechanismType(0x250),
        has_seed_key: true,
        seed_key_handle: CkObjectHandle(0xDDDD),
        seed_data_presence: PointerBytes::present_copy(&[0x44; 32]),
    }));
    match p {
        CkMechanismParams::Ike2PrfPlusDerive(v) => {
            assert_eq!(v.prf_mechanism.0, 0x250);
            assert!(v.has_seed_key);
            assert_eq!(v.seed_key_handle.0, 0xDDDD);
            assert_eq!(v.seed_data_presence.as_present().unwrap().len(), 32);
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// Batch 3: SP800-108 KDF round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn sp800_108_kdf_params_round_trip() {
    let p = round_trip(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
        prf_type: CkMechanismType(0x250),
        data_params_presence: PointerArray::present(vec![
            PrfDataParam { type_: 1, value_presence: PointerBytes::present_copy(&[0xAA; 4]) },
            PrfDataParam { type_: 2, value_presence: PointerBytes::present_copy(&[0xBB; 8]) },
        ]),
        additional_derived_keys_presence: PointerArray::present(vec![Sp800108DerivedKey {
            key_handle: CkObjectHandle(0xAA55),
            template_presence: PointerArray::present(vec![
                CkAttribute {
                    attr_type: CkAttributeType::LABEL,
                    value: Some(CkAttributeValue::String("extra-a".to_string().into())),
                },
                CkAttribute {
                    attr_type: CkAttributeType::VALUE_LEN,
                    value: Some(CkAttributeValue::Ulong(32)),
                },
            ]),
            ph_key_is_null: false,
        }]),
    }));
    match p {
        CkMechanismParams::Sp800108Kdf(v) => {
            assert_eq!(v.prf_type.0, 0x250);
            assert_eq!(v.data_params_presence.as_present().unwrap().len(), 2);
            assert_eq!(v.data_params_presence.as_present().unwrap()[0].type_, 1);
            assert_eq!(
                *v.data_params_presence.as_present().unwrap()[0]
                    .value_presence
                    .as_present()
                    .unwrap(),
                vec![0xAA; 4].into()
            );
            assert_eq!(v.data_params_presence.as_present().unwrap()[1].type_, 2);
            assert_eq!(
                *v.data_params_presence.as_present().unwrap()[1]
                    .value_presence
                    .as_present()
                    .unwrap(),
                vec![0xBB; 8].into()
            );
            assert_eq!(v.additional_derived_keys_presence.as_present().unwrap().len(), 1);
            assert_eq!(
                v.additional_derived_keys_presence.as_present().unwrap()[0].key_handle.0,
                0xAA55
            );
            assert_eq!(
                v.additional_derived_keys_presence.as_present().unwrap()[0]
                    .template_presence
                    .as_present()
                    .unwrap()
                    .len(),
                2
            );
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn sp800_108_feedback_kdf_params_round_trip() {
    let p = round_trip(CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
        prf_type: CkMechanismType(0x260),
        data_params_presence: PointerArray::present(vec![PrfDataParam {
            type_: 3,
            value_presence: PointerBytes::present_copy(&[0xCC; 16]),
        }]),
        iv_presence: PointerBytes::present_copy(&[0xDD; 16]),
        additional_derived_keys_presence: PointerArray::present(vec![Sp800108DerivedKey {
            key_handle: CkObjectHandle(0xBB66),
            template_presence: PointerArray::present(vec![CkAttribute {
                attr_type: CkAttributeType::VALUE_LEN,
                value: Some(CkAttributeValue::Ulong(16)),
            }]),
            ph_key_is_null: false,
        }]),
    }));
    match p {
        CkMechanismParams::Sp800108FeedbackKdf(v) => {
            assert_eq!(v.prf_type.0, 0x260);
            assert_eq!(v.data_params_presence.as_present().unwrap().len(), 1);
            assert_eq!(v.iv_presence.as_present().unwrap().len(), 16);
            assert_eq!(v.additional_derived_keys_presence.as_present().unwrap().len(), 1);
            assert_eq!(
                v.additional_derived_keys_presence.as_present().unwrap()[0].key_handle.0,
                0xBB66
            );
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn sp800_108_kdf_empty_data_params_round_trip() {
    let p = round_trip(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
        prf_type: CkMechanismType(1),
        data_params_presence: PointerArray::present(vec![]),
        additional_derived_keys_presence: PointerArray::present(vec![]),
    }));
    match p {
        CkMechanismParams::Sp800108Kdf(v) => {
            assert_eq!(v.prf_type.0, 1);
            assert!(v.data_params_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
            assert!(
                v.additional_derived_keys_presence
                    .as_present()
                    .map(|b| b.is_empty())
                    .unwrap_or(true)
            );
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn sp800_108_kdf_nested_template_refused_loudly() {
    // W1-C8-01: a nested template inside an SP800-108 derived-key
    // sub-template is not representable in Sp800108Attribute; the
    // Rust→Proto conversion must refuse it with an explicit error
    // instead of silently encoding it as value-absent.
    let template = vec![CkAttribute {
        attr_type: CkAttributeType::WRAP_TEMPLATE,
        value: Some(CkAttributeValue::NestedTemplate(vec![CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(4)),
        }])),
    }];
    let params = Sp800108KdfParams {
        prf_type: CkMechanismType(0x250),
        data_params_presence: PointerArray::present(vec![]),
        additional_derived_keys_presence: PointerArray::present(vec![Sp800108DerivedKey {
            key_handle: CkObjectHandle(0),
            template_presence: PointerArray::present(template),
            ph_key_is_null: false,
        }]),
    };
    let err = v1_proto::Sp800108KdfParams::try_from(&params)
        .expect_err("nested template must be refused loudly");
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
    // The loud refusal must also surface through the full convert path.
    let mech = CkMechanism {
        mechanism_type: CkMechanismType(0x9999),
        params: Some(CkMechanismParams::Sp800108Kdf(params)),
    };
    let err = v1_proto::Mechanism::try_from(&mech)
        .expect_err("nested template must be refused through the full path");
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
}

#[test]
fn sp800_108_feedback_kdf_nested_template_refused_loudly() {
    // W1-C8-01: same loud refusal for the feedback-KDF shape.
    let template = vec![CkAttribute {
        attr_type: CkAttributeType::WRAP_TEMPLATE,
        value: Some(CkAttributeValue::NestedTemplate(vec![])),
    }];
    let params = Sp800108FeedbackKdfParams {
        prf_type: CkMechanismType(0x260),
        data_params_presence: PointerArray::present(vec![]),
        iv_presence: PointerBytes::present_copy(&[]),
        additional_derived_keys_presence: PointerArray::present(vec![Sp800108DerivedKey {
            key_handle: CkObjectHandle(0),
            template_presence: PointerArray::present(template),
            ph_key_is_null: false,
        }]),
    };
    let err = v1_proto::Sp800108FeedbackKdfParams::try_from(&params)
        .expect_err("nested template must be refused loudly");
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
    let mech = CkMechanism {
        mechanism_type: CkMechanismType(0x9999),
        params: Some(CkMechanismParams::Sp800108FeedbackKdf(params)),
    };
    let err = v1_proto::Mechanism::try_from(&mech)
        .expect_err("nested template must be refused through the full path");
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
}

#[test]
fn kip_embedded_sp800_108_nested_template_refused_loudly() {
    // W1-C8-01 review I-1: the loud refusal must also pin the embedded
    // path — a nested template buried inside a nested mechanism (here
    // SP800-108 inside Kip) must fail loudly rather than silently
    // dropping the nested mechanism.
    let nested = CkMechanism {
        mechanism_type: CkMechanismType(0x9999),
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CkMechanismType(0x250),
            data_params_presence: PointerArray::present(vec![]),
            additional_derived_keys_presence: PointerArray::present(vec![Sp800108DerivedKey {
                key_handle: CkObjectHandle(0),
                template_presence: PointerArray::present(vec![CkAttribute {
                    attr_type: CkAttributeType::WRAP_TEMPLATE,
                    value: Some(CkAttributeValue::NestedTemplate(vec![])),
                }]),
                ph_key_is_null: false,
            }]),
        })),
    };
    let params = KipParams {
        mechanism: Some(Box::new(nested)),
        key_handle: CkObjectHandle(0xBEEF),
        seed_presence: PointerBytes::present_copy(&[0xAA; 16]),
    };
    let err = v1_proto::KipParams::try_from(&params)
        .expect_err("embedded nested template must be refused loudly");
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
    let mech = CkMechanism {
        mechanism_type: CkMechanismType(0x9999),
        params: Some(CkMechanismParams::Kip(params)),
    };
    let err = v1_proto::Mechanism::try_from(&mech)
        .expect_err("embedded nested template must be refused through the full path");
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
}

// ---------------------------------------------------------------------------
// Batch 3: Signal protocol round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn x3dh_initiate_round_trip() {
    let p = round_trip(CkMechanismParams::X3dhInitiate(X3dhInitiateParams {
        kdf: 1,
        peer_identity_handle: CkObjectHandle(0x1111),
        peer_prekey_handle: CkObjectHandle(0x2222),
        prekey_signature: vec![0xAA; 64],
        onetime_key_handle: CkObjectHandle(0x3333),
        own_identity_handle: CkObjectHandle(0x4444),
        own_ephemeral_handle: CkObjectHandle(0x5555),
    }));
    match p {
        CkMechanismParams::X3dhInitiate(v) => {
            assert_eq!(v.kdf, 1);
            assert_eq!(v.peer_identity_handle.0, 0x1111);
            assert_eq!(v.peer_prekey_handle.0, 0x2222);
            assert_eq!(v.prekey_signature.len(), 64);
            assert_eq!(v.onetime_key_handle.0, 0x3333);
            assert_eq!(v.own_identity_handle.0, 0x4444);
            assert_eq!(v.own_ephemeral_handle.0, 0x5555);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn x3dh_respond_round_trip() {
    let p = round_trip(CkMechanismParams::X3dhRespond(X3dhRespondParams {
        kdf: 2,
        identity_handle: CkObjectHandle(0xAAAA),
        prekey_handle: CkObjectHandle(0xBBBB),
        onetime_key_handle: CkObjectHandle(0xCCCC),
        initiator_identity_handle: CkObjectHandle(0xDDDD),
        initiator_ephemeral_handle: CkObjectHandle(0xEEEE),
    }));
    match p {
        CkMechanismParams::X3dhRespond(v) => {
            assert_eq!(v.kdf, 2);
            assert_eq!(v.identity_handle.0, 0xAAAA);
            assert_eq!(v.prekey_handle.0, 0xBBBB);
            assert_eq!(v.onetime_key_handle.0, 0xCCCC);
            assert_eq!(v.initiator_identity_handle.0, 0xDDDD);
            assert_eq!(v.initiator_ephemeral_handle.0, 0xEEEE);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn x2_ratchet_initialize_round_trip() {
    let p = round_trip(CkMechanismParams::X2RatchetInitialize(X2RatchetInitializeParams {
        sk: vec![0x01; 32].into(),
        peer_public_prekey_handle: CkObjectHandle(0x1111),
        peer_public_identity_handle: CkObjectHandle(0x2222),
        own_public_identity_handle: CkObjectHandle(0x3333),
        encrypted_header: true,
        curve: 0x0403, // CKP_EC_NIST_P256 for example
        aead_mechanism: CkMechanismType(0x1087),
        kdf_mechanism: CkKdf(0x0250),
    }));
    match p {
        CkMechanismParams::X2RatchetInitialize(v) => {
            // W1-C8-05: full-field assertions; a dropped field must fail.
            assert_eq!(v.sk.len(), 32);
            assert_eq!(v.peer_public_prekey_handle.0, 0x1111);
            assert_eq!(v.peer_public_identity_handle.0, 0x2222);
            assert_eq!(v.own_public_identity_handle.0, 0x3333);
            assert!(v.encrypted_header);
            assert_eq!(v.curve, 0x0403);
            assert_eq!(v.aead_mechanism.0, 0x1087);
            assert_eq!(v.kdf_mechanism.0, 0x0250);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn x2_ratchet_respond_round_trip() {
    let p = round_trip(CkMechanismParams::X2RatchetRespond(X2RatchetRespondParams {
        sk: vec![0x02; 32].into(),
        own_prekey_handle: CkObjectHandle(0xAAAA),
        initiator_identity_handle: CkObjectHandle(0xBBBB),
        own_identity_handle: CkObjectHandle(0xCCCC),
        encrypted_header: false,
        curve: 0x0403,
        aead_mechanism: CkMechanismType(0x1087),
        kdf_mechanism: CkKdf(0x0260),
    }));
    match p {
        CkMechanismParams::X2RatchetRespond(v) => {
            // W1-C8-05: full-field assertions; a dropped field must fail.
            assert_eq!(v.sk.len(), 32);
            assert_eq!(v.own_prekey_handle.0, 0xAAAA);
            assert_eq!(v.initiator_identity_handle.0, 0xBBBB);
            assert_eq!(v.own_identity_handle.0, 0xCCCC);
            assert!(!v.encrypted_header);
            assert_eq!(v.curve, 0x0403);
            assert_eq!(v.aead_mechanism.0, 0x1087);
            assert_eq!(v.kdf_mechanism.0, 0x0260);
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// Batch 3: Miscellaneous round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn otp_params_round_trip() {
    let params_vec = vec![
        OtpParam { type_: 1, value_presence: PointerBytes::present_copy(&[0x01; 6]) },
        OtpParam { type_: 2, value_presence: PointerBytes::present_copy(&[0x02; 4]) },
    ];
    let p = round_trip(CkMechanismParams::Otp(OtpParams {
        params_presence: PointerArray::present(params_vec),
    }));
    match p {
        CkMechanismParams::Otp(v) => {
            assert_eq!(v.params_presence.as_present().unwrap().len(), 2);
            assert_eq!(v.params_presence.as_present().unwrap()[0].type_, 1);
            assert_eq!(
                *v.params_presence.as_present().unwrap()[0].value_presence.as_present().unwrap(),
                vec![0x01; 6].into()
            );
            assert_eq!(v.params_presence.as_present().unwrap()[1].type_, 2);
            assert_eq!(
                *v.params_presence.as_present().unwrap()[1].value_presence.as_present().unwrap(),
                vec![0x02; 4].into()
            );
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn otp_params_empty_round_trip() {
    let p = round_trip(CkMechanismParams::Otp(OtpParams {
        params_presence: PointerArray::present(vec![]),
    }));
    match p {
        CkMechanismParams::Otp(v) => {
            assert!(v.params_presence.as_present().map(|b| b.is_empty()).unwrap_or(true))
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn kip_params_round_trip() {
    let nested = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let p = round_trip(CkMechanismParams::Kip(KipParams {
        mechanism: Some(Box::new(nested)),
        key_handle: CkObjectHandle(0xBEEF),
        seed_presence: PointerBytes::present_copy(&[0xAA; 16]),
    }));
    match p {
        CkMechanismParams::Kip(v) => {
            assert_eq!(v.mechanism.as_ref().unwrap().mechanism_type, CkMechanismType::SHA256);
            assert!(v.mechanism.as_ref().unwrap().params.is_none());
            assert_eq!(v.key_handle.0, 0xBEEF);
            assert_eq!(*v.seed_presence.as_present().unwrap(), vec![0xAA; 16].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn kip_params_reject_missing_nested_mechanism() {
    let proto = v1_proto::Mechanism {
        mechanism_type: 0x0000_0000,
        params: Some(v1_proto::mechanism::Params::KipParams(Box::new(v1_proto::KipParams {
            mechanism: None,
            key_handle: 0xBEEF,
            seed: vec![0xAA],
            mechanism_null: None,
            seed_null_len: None,
        }))),
        parameter_encoding_version: 0,
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn cms_sig_params_round_trip() {
    let signing = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let digest = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let p = round_trip(CkMechanismParams::CmsSig(CmsSigParams {
        certificate_handle: CkObjectHandle(0x42),
        signing_mechanism: Box::new(signing),
        digest_mechanism: Box::new(digest),
        content_type: "1.2.840.113549.1.7.1".to_string(),
        requested_attributes: vec![0x30, 0x00].into(),
        required_attributes: vec![0x31, 0x00].into(),
    }));
    match p {
        CkMechanismParams::CmsSig(v) => {
            assert_eq!(v.certificate_handle.0, 0x42);
            assert_eq!(v.signing_mechanism.mechanism_type, CkMechanismType::RSA_PKCS);
            assert_eq!(v.digest_mechanism.mechanism_type, CkMechanismType::SHA256);
            assert_eq!(v.content_type, "1.2.840.113549.1.7.1");
            assert_eq!(v.requested_attributes, vec![0x30, 0x00].into());
            assert_eq!(v.required_attributes, vec![0x31, 0x00].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn cms_sig_params_reject_missing_digest_mechanism() {
    let proto = v1_proto::Mechanism {
        mechanism_type: 0x0000_0000,
        params: Some(v1_proto::mechanism::Params::CmsSigParams(Box::new(v1_proto::CmsSigParams {
            certificate_handle: 0x42,
            signing_mechanism: Some(Box::new(v1_proto::Mechanism {
                mechanism_type: CkMechanismType::RSA_PKCS.0,
                params: None,
                parameter_encoding_version: 0,
            })),
            digest_mechanism: None,
            content_type: "1.2.840.113549.1.7.1".to_string(),
            requested_attributes: vec![],
            required_attributes: vec![],
        }))),
        parameter_encoding_version: 0,
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn cms_sig_params_reject_missing_signing_mechanism() {
    // W1-C8-04: required nested signing_mechanism must be rejected when absent.
    let proto = v1_proto::Mechanism {
        mechanism_type: CkMechanismType::CMS_SIG.0,
        params: Some(v1_proto::mechanism::Params::CmsSigParams(Box::new(v1_proto::CmsSigParams {
            certificate_handle: 0x42,
            signing_mechanism: None,
            digest_mechanism: Some(Box::new(v1_proto::Mechanism {
                mechanism_type: CkMechanismType::SHA256.0,
                params: None,
                parameter_encoding_version: 0,
            })),
            content_type: "1.2.840.113549.1.7.1".to_string(),
            requested_attributes: vec![],
            required_attributes: vec![],
        }))),
        parameter_encoding_version: 0,
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn skipjack_private_wrap_round_trip() {
    let p = round_trip(CkMechanismParams::SkipjackPrivateWrap(SkipjackPrivateWrapParams {
        password_length: 4,
        password_presence: PointerBytes::present_copy(&[0x70, 0x61, 0x73, 0x73]),
        public_data_presence: PointerBytes::present_copy(&[0x11; 128]),
        random_a_presence: PointerBytes::present_copy(&[0x22; 20]),
        prime_p_presence: PointerBytes::present_copy(&[0x33; 128]),
        base_g_presence: PointerBytes::present_copy(&[0x44; 128]),
        subprime_q_presence: PointerBytes::present_copy(&[0x55; 20]),
    }));
    match p {
        CkMechanismParams::SkipjackPrivateWrap(v) => {
            assert_eq!(
                *v.password_presence.as_present().unwrap(),
                vec![0x70, 0x61, 0x73, 0x73].into()
            );
            assert_eq!(v.public_data_presence.as_present().unwrap().len(), 128);
            assert_eq!(v.password_length, 4);
            assert_eq!(v.random_a_presence.as_present().unwrap().len(), 20);
            assert_eq!(v.prime_p_presence.as_present().unwrap().len(), 128);
            assert_eq!(v.base_g_presence.as_present().unwrap().len(), 128);
            assert_eq!(v.subprime_q_presence.as_present().unwrap().len(), 20);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn skipjack_relayx_round_trip() {
    let p = round_trip(CkMechanismParams::SkipjackRelayx(SkipjackRelayxParams {
        old_wrapped_x_presence: PointerBytes::present_copy(&[0x01; 24]),
        old_password_presence: PointerBytes::present_copy(&[0x02; 8]),
        old_public_data_presence: PointerBytes::present_copy(&[0x03; 128]),
        old_random_a_presence: PointerBytes::present_copy(&[0x04; 20]),
        new_password_presence: PointerBytes::present_copy(&[0x05; 8]),
        new_public_data_presence: PointerBytes::present_copy(&[0x06; 128]),
        new_random_a_presence: PointerBytes::present_copy(&[0x07; 20]),
    }));
    match p {
        CkMechanismParams::SkipjackRelayx(v) => {
            assert_eq!(v.old_wrapped_x_presence.as_present().unwrap().len(), 24);
            assert_eq!(v.old_password_presence.as_present().unwrap().len(), 8);
            assert_eq!(v.old_public_data_presence.as_present().unwrap().len(), 128);
            assert_eq!(v.old_random_a_presence.as_present().unwrap().len(), 20);
            assert_eq!(v.new_password_presence.as_present().unwrap().len(), 8);
            assert_eq!(v.new_public_data_presence.as_present().unwrap().len(), 128);
            assert_eq!(v.new_random_a_presence.as_present().unwrap().len(), 20);
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// W1-C8-02: owned-adopting Skipjack conversions wipe the source buffers
// ---------------------------------------------------------------------------

#[test]
fn skipjack_private_wrap_adopting_conversion_wipes_source() {
    let canary = vec![0xA5u8; 32];
    let mut proto = v1_proto::SkipjackPrivateWrapParams {
        password: canary.clone(),
        public_data: vec![0x11; 128],
        password_length: 32,
        random_a: vec![0x22; 20],
        prime_p: vec![0x33; 128],
        base_g: vec![0x44; 128],
        subprime_q: vec![0x55; 20],
        password_null_len: None,
        public_data_null_len: None,
        random_a_null_len: None,
        prime_p_null_len: None,
        base_g_null_len: None,
        subprime_q_null_len: None,
    };
    let adopted = SkipjackPrivateWrapParams::from(&mut proto);
    // Source buffers adopted out: no secret bytes remain in the prost message.
    assert!(proto.password.is_empty());
    // Converted value holds the canary.
    adopted
        .password_presence
        .as_present()
        .unwrap()
        .expose(|bytes| assert_eq!(bytes, canary.as_slice()));
    // Non-secret fields moved intact.
    assert_eq!(adopted.public_data_presence, PointerBytes::present_copy(&[0x11; 128]));
    assert_eq!(adopted.password_length, 32);
    assert_eq!(adopted.random_a_presence, PointerBytes::present_copy(&[0x22; 20]));
    assert_eq!(adopted.prime_p_presence, PointerBytes::present_copy(&[0x33; 128]));
    assert_eq!(adopted.base_g_presence, PointerBytes::present_copy(&[0x44; 128]));
    assert_eq!(adopted.subprime_q_presence, PointerBytes::present_copy(&[0x55; 20]));
}

#[test]
fn skipjack_relayx_adopting_conversion_wipes_source() {
    let canary_old = vec![0xA5u8; 8];
    let canary_new = vec![0x5Au8; 8];
    let mut proto = v1_proto::SkipjackRelayxParams {
        old_wrapped_x: vec![0x01; 24],
        old_password: canary_old.clone(),
        old_public_data: vec![0x03; 128],
        old_random_a: vec![0x04; 20],
        new_password: canary_new.clone(),
        new_public_data: vec![0x06; 128],
        new_random_a: vec![0x07; 20],
        old_wrapped_x_null_len: None,
        old_password_null_len: None,
        old_public_data_null_len: None,
        old_random_a_null_len: None,
        new_password_null_len: None,
        new_public_data_null_len: None,
        new_random_a_null_len: None,
    };
    let adopted = SkipjackRelayxParams::from(&mut proto);
    // Every source buffer adopted out; nothing secret remains behind.
    assert!(proto.old_wrapped_x.is_empty());
    assert!(proto.old_password.is_empty());
    assert!(proto.old_public_data.is_empty());
    assert!(proto.old_random_a.is_empty());
    assert!(proto.new_password.is_empty());
    assert!(proto.new_public_data.is_empty());
    assert!(proto.new_random_a.is_empty());
    // Converted values hold the canaries.
    adopted
        .old_wrapped_x_presence
        .as_present()
        .unwrap()
        .expose(|bytes| assert_eq!(bytes, vec![0x01; 24].as_slice()));
    adopted
        .old_password_presence
        .as_present()
        .unwrap()
        .expose(|bytes| assert_eq!(bytes, canary_old.as_slice()));
    adopted
        .new_password_presence
        .as_present()
        .unwrap()
        .expose(|bytes| assert_eq!(bytes, canary_new.as_slice()));
    assert_eq!(adopted.old_public_data_presence.as_present().unwrap().len(), 128);
    assert_eq!(adopted.old_random_a_presence.as_present().unwrap().len(), 20);
    assert_eq!(adopted.new_public_data_presence.as_present().unwrap().len(), 128);
    assert_eq!(adopted.new_random_a_presence.as_present().unwrap().len(), 20);
}

#[test]
fn skipjack_prost_messages_zeroize_wipes_passwords() {
    use zeroize::Zeroize;
    // `ZeroizeOnDrop` (derived alongside `Zeroize` in build.rs) delegates
    // drop-wiping to this same `zeroize`; post-drop memory is unobservable,
    // so the test pins the wipe behavior directly.
    // All fields spelled out: struct-update syntax cannot move fields out
    // of the `ZeroizeOnDrop` temporary.
    let mut private_wrap = v1_proto::SkipjackPrivateWrapParams {
        password: vec![0xA5u8; 32],
        public_data: Vec::new(),
        password_length: 0,
        random_a: Vec::new(),
        prime_p: Vec::new(),
        base_g: Vec::new(),
        subprime_q: Vec::new(),
        password_null_len: None,
        public_data_null_len: None,
        random_a_null_len: None,
        prime_p_null_len: None,
        base_g_null_len: None,
        subprime_q_null_len: None,
    };
    private_wrap.zeroize();
    assert!(private_wrap.password.iter().all(|&byte| byte == 0));
    let mut relayx = v1_proto::SkipjackRelayxParams {
        old_wrapped_x: vec![0x01; 24],
        old_password: vec![0xA5u8; 8],
        old_public_data: Vec::new(),
        old_random_a: Vec::new(),
        new_password: vec![0x5Au8; 8],
        new_public_data: Vec::new(),
        new_random_a: Vec::new(),
        old_wrapped_x_null_len: None,
        old_password_null_len: None,
        old_public_data_null_len: None,
        old_random_a_null_len: None,
        new_password_null_len: None,
        new_public_data_null_len: None,
        new_random_a_null_len: None,
    };
    relayx.zeroize();
    assert!(relayx.old_password.iter().all(|&byte| byte == 0));
    assert!(relayx.new_password.iter().all(|&byte| byte == 0));
    assert!(relayx.old_wrapped_x.iter().all(|&byte| byte == 0));
}

#[test]
fn skipjack_prost_messages_wipe_on_drop() {
    // Compile-time pin (W1-C8-02 review B1): deleting `ZeroizeOnDrop` from
    // either build.rs `type_attribute` line must fail compilation here.
    fn assert_wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_wiped_on_drop::<v1_proto::SkipjackPrivateWrapParams>();
    assert_wiped_on_drop::<v1_proto::SkipjackRelayxParams>();
}

// ---------------------------------------------------------------------------
// Generic / vendor parameter shapes round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn mac_general_params_round_trip() {
    let p = round_trip(CkMechanismParams::MacGeneral(MacGeneralParams { mac_length: 16 }));
    match p {
        CkMechanismParams::MacGeneral(v) => {
            assert_eq!(v.mac_length, 16);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn mac_general_params_zero_round_trip() {
    let p = round_trip(CkMechanismParams::MacGeneral(MacGeneralParams { mac_length: 0 }));
    match p {
        CkMechanismParams::MacGeneral(v) => {
            assert_eq!(v.mac_length, 0);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn extract_params_round_trip() {
    let p = round_trip(CkMechanismParams::Extract(ExtractParams { bit_position: 21 }));
    match p {
        CkMechanismParams::Extract(v) => {
            assert_eq!(v.bit_position, 21);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn key_derivation_string_data_round_trip() {
    let p = round_trip(CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
        data_presence: PointerBytes::present_copy(&[0xDE, 0xAD, 0xBE, 0xEF]),
    }));
    match p {
        CkMechanismParams::KeyDerivationString(v) => {
            assert_eq!(*v.data_presence.as_present().unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn key_derivation_string_data_empty_round_trip() {
    let p = round_trip(CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
        data_presence: PointerBytes::present_copy(&[]),
    }));
    match p {
        CkMechanismParams::KeyDerivationString(v) => {
            assert!(v.data_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn raw_mechanism_params_round_trip() {
    let p = round_trip(CkMechanismParams::Raw(RawMechanismParams {
        data: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08].into(),
    }));
    match p {
        CkMechanismParams::Raw(v) => {
            assert_eq!(v.data, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn raw_mechanism_params_empty_round_trip() {
    let p = round_trip(CkMechanismParams::Raw(RawMechanismParams { data: vec![].into() }));
    match p {
        CkMechanismParams::Raw(v) => {
            assert!(v.data.is_empty());
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// Vendor-specific parameter shapes round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn ecies_params_round_trip() {
    let derivation = CkMechanism { mechanism_type: CkMechanismType::ECDH1_DERIVE, params: None };
    let encryption = CkMechanism {
        mechanism_type: CkMechanismType::AES_CBC_PAD,
        params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0xAA; 16] })),
    };
    let mac = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let p = round_trip(CkMechanismParams::Ecies(EciesParams {
        derivation_mechanism: Box::new(derivation),
        encryption_mechanism: Box::new(encryption),
        mac_mechanism: Box::new(mac),
        shared_data: vec![0x01, 0x02, 0x03].into(),
    }));
    match p {
        CkMechanismParams::Ecies(v) => {
            assert_eq!(v.derivation_mechanism.mechanism_type, CkMechanismType::ECDH1_DERIVE);
            assert!(v.derivation_mechanism.params.is_none());
            assert_eq!(v.encryption_mechanism.mechanism_type, CkMechanismType::AES_CBC_PAD);
            match v.encryption_mechanism.params.as_ref().unwrap() {
                CkMechanismParams::Iv(iv) => assert_eq!(iv.iv, vec![0xAA; 16]),
                _ => panic!("wrong nested variant"),
            }
            assert_eq!(v.mac_mechanism.mechanism_type, CkMechanismType::SHA256);
            assert_eq!(v.shared_data, vec![0x01, 0x02, 0x03].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ecies_params_empty_shared_data_round_trip() {
    let derivation = CkMechanism { mechanism_type: CkMechanismType::ECDH1_DERIVE, params: None };
    let encryption = CkMechanism { mechanism_type: CkMechanismType::AES_CBC, params: None };
    let mac = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let p = round_trip(CkMechanismParams::Ecies(EciesParams {
        derivation_mechanism: Box::new(derivation),
        encryption_mechanism: Box::new(encryption),
        mac_mechanism: Box::new(mac),
        shared_data: vec![].into(),
    }));
    match p {
        CkMechanismParams::Ecies(v) => {
            // W1-C8-05: full-field assertions; a dropped field must fail.
            assert_eq!(v.derivation_mechanism.mechanism_type, CkMechanismType::ECDH1_DERIVE);
            assert!(v.derivation_mechanism.params.is_none());
            assert_eq!(v.encryption_mechanism.mechanism_type, CkMechanismType::AES_CBC);
            assert!(v.encryption_mechanism.params.is_none());
            assert_eq!(v.mac_mechanism.mechanism_type, CkMechanismType::SHA256);
            assert!(v.mac_mechanism.params.is_none());
            assert!(v.shared_data.is_empty());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ecies_params_reject_missing_mac_mechanism() {
    let proto = v1_proto::Mechanism {
        mechanism_type: CkMechanismType::ECDH1_DERIVE.0,
        params: Some(v1_proto::mechanism::Params::EciesParams(Box::new(v1_proto::EciesParams {
            derivation_mechanism: Some(Box::new(v1_proto::Mechanism {
                mechanism_type: CkMechanismType::ECDH1_DERIVE.0,
                params: None,
                parameter_encoding_version: 0,
            })),
            encryption_mechanism: Some(Box::new(v1_proto::Mechanism {
                mechanism_type: CkMechanismType::AES_CBC.0,
                params: None,
                parameter_encoding_version: 0,
            })),
            mac_mechanism: None,
            shared_data: vec![],
        }))),
        parameter_encoding_version: 0,
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn ecies_params_reject_missing_derivation_mechanism() {
    // W1-C8-04: required nested derivation_mechanism must be rejected when absent.
    let proto = v1_proto::Mechanism {
        mechanism_type: CkMechanismType::ECDH1_DERIVE.0,
        params: Some(v1_proto::mechanism::Params::EciesParams(Box::new(v1_proto::EciesParams {
            derivation_mechanism: None,
            encryption_mechanism: Some(Box::new(v1_proto::Mechanism {
                mechanism_type: CkMechanismType::AES_CBC.0,
                params: None,
                parameter_encoding_version: 0,
            })),
            mac_mechanism: Some(Box::new(v1_proto::Mechanism {
                mechanism_type: CkMechanismType::SHA256.0,
                params: None,
                parameter_encoding_version: 0,
            })),
            shared_data: vec![],
        }))),
        parameter_encoding_version: 0,
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn ecies_params_reject_missing_encryption_mechanism() {
    // W1-C8-04: required nested encryption_mechanism must be rejected when absent.
    let proto = v1_proto::Mechanism {
        mechanism_type: CkMechanismType::ECDH1_DERIVE.0,
        params: Some(v1_proto::mechanism::Params::EciesParams(Box::new(v1_proto::EciesParams {
            derivation_mechanism: Some(Box::new(v1_proto::Mechanism {
                mechanism_type: CkMechanismType::ECDH1_DERIVE.0,
                params: None,
                parameter_encoding_version: 0,
            })),
            encryption_mechanism: None,
            mac_mechanism: Some(Box::new(v1_proto::Mechanism {
                mechanism_type: CkMechanismType::SHA256.0,
                params: None,
                parameter_encoding_version: 0,
            })),
            shared_data: vec![],
        }))),
        parameter_encoding_version: 0,
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn aes_cmac_key_derivation_params_round_trip() {
    let p = round_trip(CkMechanismParams::AesCmacKeyDerivation(AesCmacKeyDerivationParams {
        context: vec![0x10; 32].into(),
        label: vec![0x20; 16].into(),
    }));
    match p {
        CkMechanismParams::AesCmacKeyDerivation(v) => {
            assert_eq!(v.context, vec![0x10; 32].into());
            assert_eq!(v.label, vec![0x20; 16].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn dilithium_params_round_trip() {
    let p = round_trip(CkMechanismParams::Dilithium(DilithiumParams { version: 3, mode: 1 }));
    match p {
        CkMechanismParams::Dilithium(v) => {
            assert_eq!(v.version, 3);
            assert_eq!(v.mode, 1);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn kyber_params_round_trip() {
    let p = round_trip(CkMechanismParams::Kyber(KyberParams {
        version: 2,
        mode: 1,
        secret_handle: CkObjectHandle(0xDEAD),
        shared_data: vec![0xAB; 32].into(),
        blob: vec![0xCD; 64].into(),
    }));
    match p {
        CkMechanismParams::Kyber(v) => {
            assert_eq!(v.version, 2);
            assert_eq!(v.mode, 1);
            assert_eq!(v.secret_handle.0, 0xDEAD);
            assert_eq!(v.shared_data, vec![0xAB; 32].into());
            assert_eq!(v.blob, vec![0xCD; 64].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn kyber_params_empty_optional_fields_round_trip() {
    let p = round_trip(CkMechanismParams::Kyber(KyberParams {
        version: 1,
        mode: 0,
        secret_handle: CkObjectHandle(0),
        shared_data: vec![].into(),
        blob: vec![].into(),
    }));
    match p {
        CkMechanismParams::Kyber(v) => {
            // W1-C8-05: full-field assertions; a dropped field must fail.
            assert_eq!(v.version, 1);
            assert_eq!(v.mode, 0);
            assert_eq!(v.secret_handle.0, 0);
            assert!(v.shared_data.is_empty());
            assert!(v.blob.is_empty());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn hd_key_derive_params_round_trip() {
    let p = round_trip(CkMechanismParams::HdKeyDerive(HdKeyDeriveParams {
        derive_type: 32,              // BIP-32
        child_key_index: 0x8000_0000, // hardened
        chain_code: vec![0xFF; 32].into(),
        version: 1,
    }));
    match p {
        CkMechanismParams::HdKeyDerive(v) => {
            assert_eq!(v.derive_type, 32);
            assert_eq!(v.child_key_index, 0x8000_0000);
            assert_eq!(v.chain_code, vec![0xFF; 32].into());
            assert_eq!(v.version, 1);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn vendor_object_extract_params_round_trip() {
    let p = round_trip(CkMechanismParams::VendorObjectExtract(VendorObjectExtractParams {
        format: 1,
        context: vec![0x42; 24].into(),
    }));
    match p {
        CkMechanismParams::VendorObjectExtract(v) => {
            assert_eq!(v.format, 1);
            assert_eq!(v.context, vec![0x42; 24].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn vendor_object_insert_params_round_trip() {
    let p = round_trip(CkMechanismParams::VendorObjectInsert(VendorObjectInsertParams {
        format: 2,
        context: vec![0x43; 24].into(),
        object_data: vec![0xBE, 0xEF, 0xCA, 0xFE].into(),
    }));
    match p {
        CkMechanismParams::VendorObjectInsert(v) => {
            assert_eq!(v.format, 2);
            assert_eq!(v.context, vec![0x43; 24].into());
            assert_eq!(v.object_data, vec![0xBE, 0xEF, 0xCA, 0xFE].into());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn kmac_params_round_trip() {
    let p = round_trip(CkMechanismParams::Kmac(KmacParams {
        key_handle: CkObjectHandle(0xCAFE),
        mac_length: 64,
        customization_string_presence: PointerBytes::present_copy(b"custom"),
    }));
    match p {
        CkMechanismParams::Kmac(v) => {
            assert_eq!(v.key_handle.0, 0xCAFE);
            assert_eq!(v.mac_length, 64);
            assert_eq!(
                v.customization_string_presence,
                PointerBytes::present_cloned(&SecretBytes::copy_from_slice(b"custom"))
            );
        }
        other => panic!("expected Kmac params, got {other:?}"),
    }
}

#[test]
fn mu_gen_params_round_trip() {
    let p = round_trip(CkMechanismParams::MuGen(MuGenParams {
        key_handle: CkObjectHandle(0xA11CE),
        tr_presence: PointerBytes::present_copy(b"precomputed-tr"),
        context_presence: PointerBytes::present_copy(b"context"),
    }));
    match p {
        CkMechanismParams::MuGen(v) => {
            assert_eq!(v.key_handle.0, 0xA11CE);
            assert_eq!(
                v.tr_presence,
                PointerBytes::present_cloned(&SecretBytes::copy_from_slice(b"precomputed-tr"))
            );
            assert_eq!(
                v.context_presence,
                PointerBytes::present_cloned(&SecretBytes::copy_from_slice(b"context"))
            );
        }
        other => panic!("expected MuGen params, got {other:?}"),
    }
}

#[test]
fn object_handle_param_round_trip() {
    let p = round_trip(CkMechanismParams::ObjectHandle(ObjectHandleParam {
        handle: CkObjectHandle(42),
    }));
    match p {
        CkMechanismParams::ObjectHandle(v) => assert_eq!(v.handle.0, 42),
        other => panic!("expected ObjectHandle, got {other:?}"),
    }
}

#[test]
fn sign_additional_context_round_trip() {
    let p = round_trip(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
        hedge_variant: 1, // CKH_HEDGE_REQUIRED
        hash: CkMechanismType(0),
        context_presence: PointerBytes::present_copy(&[1, 2, 3]),
    }));
    match p {
        CkMechanismParams::SignAdditionalContext(v) => {
            assert_eq!(v.hedge_variant, 1);
            assert_eq!(*v.context_presence.as_present().unwrap(), vec![1, 2, 3].into());
            assert_eq!(v.hash.0, 0);
        }
        other => panic!("expected SignAdditionalContext, got {other:?}"),
    }
}

#[test]
fn hash_sign_additional_context_round_trip() {
    // The generic CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA carry the hash mechanism.
    let p = round_trip(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
        hedge_variant: 1,
        hash: CkMechanismType::SHA256,
        context_presence: PointerBytes::present_copy(&[4, 5]),
    }));
    match p {
        CkMechanismParams::SignAdditionalContext(v) => {
            assert_eq!(v.hedge_variant, 1);
            assert_eq!(*v.context_presence.as_present().unwrap(), vec![4, 5].into());
            assert_eq!(v.hash, CkMechanismType::SHA256);
        }
        other => panic!("expected SignAdditionalContext, got {other:?}"),
    }
}

#[test]
fn gcm_null_flags_round_trip() {
    // F3/D2: iv_null/aad_null must survive the proto crossing.
    for (iv_null, aad_null) in [(true, true), (true, false), (false, true), (false, false)] {
        let p = round_trip(CkMechanismParams::Gcm(GcmParams {
            iv_bits: 0,
            iv_buffer_len: 0,
            tag_bits: 128,
            iv_presence: PointerBytes::from_legacy(&[], iv_null),
            aad_presence: PointerBytes::from_legacy(&[], aad_null),
        }));
        match p {
            CkMechanismParams::Gcm(v) => {
                assert_eq!(v.iv_presence.is_null(), iv_null);
                assert_eq!(v.aad_presence.is_null(), aad_null);
            }
            _ => panic!("wrong variant"),
        }
    }
}

#[test]
fn ccm_null_flags_round_trip() {
    // nonce_null/aad_null must survive the proto crossing.
    for (nonce_null, aad_null) in [(true, true), (true, false), (false, true), (false, false)] {
        let p = round_trip(CkMechanismParams::Ccm(CcmParams {
            data_len: 16,
            mac_len: 12,
            nonce_presence: PointerBytes::from_legacy(&[], nonce_null),
            aad_presence: PointerBytes::from_legacy(&[], aad_null),
        }));
        match p {
            CkMechanismParams::Ccm(v) => {
                assert_eq!(v.nonce_presence.is_null(), nonce_null);
                assert_eq!(v.aad_presence.is_null(), aad_null);
            }
            _ => panic!("wrong variant"),
        }
    }
}

#[test]
fn oaep_source_null_round_trip() {
    // F3/D2: source_null must survive the proto crossing.
    for source_null in [true, false] {
        let p = round_trip(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: CkMgf(1),
            source: CkOaepSource(1),
            source_data_presence: PointerBytes::from_legacy(&[], source_null),
        }));
        match p {
            CkMechanismParams::RsaPkcsOaep(v) => {
                assert_eq!(v.source_data_presence.is_null(), source_null);
            }
            _ => panic!("wrong variant"),
        }
    }
}

// R6 golden tests: classic v1 wire schema (S2 §3). Additive only: legacy
// encodings decode exactly as before the v1 fields landed, and Flat/Null
// round-trip at the prost layer while conversion stays fail-closed
// (acceptance is R9+; fingerprint computation is R7).

#[test]
fn r6_legacy_decode_stability_all_oneof_members() {
    use prost::Message as _;
    // Every pre-R6 `Mechanism.params` arm (tags 2–80: 79 members, matching
    // the AGENTS.md §13 historical count): tag, field name, default-valued
    // arm, golden wire bytes, default-message conversion outcome. Each
    // golden is field 1 (`mechanism_type` 0x9999) + the arm's tag key +
    // empty message; any tag renumbering or new-byte emission on legacy
    // values breaks the equality below. Per-variant value fidelity stays
    // pinned by the existing per-member round-trip tests above.
    type MemberRow<'a> = (u32, &'a str, v1_proto::mechanism::Params, Vec<u8>, Result<(), CkRv>);
    let members: Vec<MemberRow<'_>> = vec![
        (
            2u32,
            "rsa_pkcs_pss_params",
            v1_proto::mechanism::Params::RsaPkcsPssParams(v1_proto::RsaPkcsPssParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x12, 0x00],
            Ok(()),
        ),
        (
            3u32,
            "rsa_pkcs_oaep_params",
            v1_proto::mechanism::Params::RsaPkcsOaepParams(v1_proto::RsaPkcsOaepParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x1A, 0x00],
            Ok(()),
        ),
        (
            4u32,
            "gcm_params",
            v1_proto::mechanism::Params::GcmParams(v1_proto::GcmParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x22, 0x00],
            Ok(()),
        ),
        (
            5u32,
            "ecdh1_derive_params",
            v1_proto::mechanism::Params::Ecdh1DeriveParams(v1_proto::Ecdh1DeriveParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x2A, 0x00],
            Ok(()),
        ),
        (
            6u32,
            "iv_params",
            v1_proto::mechanism::Params::IvParams(v1_proto::IvParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x32, 0x00],
            Ok(()),
        ),
        (
            7u32,
            "aes_ctr_params",
            v1_proto::mechanism::Params::AesCtrParams(v1_proto::AesCtrParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x3A, 0x00],
            Ok(()),
        ),
        (
            8u32,
            "ccm_params",
            v1_proto::mechanism::Params::CcmParams(v1_proto::CcmParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x42, 0x00],
            Ok(()),
        ),
        (
            9u32,
            "aes_cbc_encrypt_data_params",
            v1_proto::mechanism::Params::AesCbcEncryptDataParams(
                v1_proto::AesCbcEncryptDataParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0x4A, 0x00],
            Ok(()),
        ),
        (
            10u32,
            "des_cbc_encrypt_data_params",
            v1_proto::mechanism::Params::DesCbcEncryptDataParams(
                v1_proto::DesCbcEncryptDataParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0x52, 0x00],
            Ok(()),
        ),
        (
            11u32,
            "aria_cbc_encrypt_data_params",
            v1_proto::mechanism::Params::AriaCbcEncryptDataParams(
                v1_proto::AriaCbcEncryptDataParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0x5A, 0x00],
            Ok(()),
        ),
        (
            12u32,
            "camellia_cbc_encrypt_data_params",
            v1_proto::mechanism::Params::CamelliaCbcEncryptDataParams(
                v1_proto::CamelliaCbcEncryptDataParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0x62, 0x00],
            Ok(()),
        ),
        (
            13u32,
            "camellia_ctr_params",
            v1_proto::mechanism::Params::CamelliaCtrParams(v1_proto::CamelliaCtrParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x6A, 0x00],
            Ok(()),
        ),
        (
            14u32,
            "seed_cbc_encrypt_data_params",
            v1_proto::mechanism::Params::SeedCbcEncryptDataParams(
                v1_proto::SeedCbcEncryptDataParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0x72, 0x00],
            Ok(()),
        ),
        (
            15u32,
            "rc2_cbc_params",
            v1_proto::mechanism::Params::Rc2CbcParams(v1_proto::Rc2CbcParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x7A, 0x00],
            Ok(()),
        ),
        (
            16u32,
            "rc2_mac_general_params",
            v1_proto::mechanism::Params::Rc2MacGeneralParams(
                v1_proto::Rc2MacGeneralParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0x82, 0x01, 0x00],
            Ok(()),
        ),
        (
            17u32,
            "rc5_params",
            v1_proto::mechanism::Params::Rc5Params(v1_proto::Rc5Params::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x8A, 0x01, 0x00],
            Ok(()),
        ),
        (
            18u32,
            "rc5_cbc_params",
            v1_proto::mechanism::Params::Rc5CbcParams(v1_proto::Rc5CbcParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x92, 0x01, 0x00],
            Ok(()),
        ),
        (
            19u32,
            "rc5_mac_general_params",
            v1_proto::mechanism::Params::Rc5MacGeneralParams(
                v1_proto::Rc5MacGeneralParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0x9A, 0x01, 0x00],
            Ok(()),
        ),
        (
            20u32,
            "chacha20_params",
            v1_proto::mechanism::Params::Chacha20Params(v1_proto::ChaCha20Params::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xA2, 0x01, 0x00],
            Ok(()),
        ),
        (
            21u32,
            "salsa20_params",
            v1_proto::mechanism::Params::Salsa20Params(v1_proto::Salsa20Params::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xAA, 0x01, 0x00],
            Ok(()),
        ),
        (
            22u32,
            "salsa20_chacha20_poly1305_params",
            v1_proto::mechanism::Params::Salsa20Chacha20Poly1305Params(
                v1_proto::Salsa20ChaCha20Poly1305Params::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xB2, 0x01, 0x00],
            Ok(()),
        ),
        (
            23u32,
            "gcm_wrap_params",
            v1_proto::mechanism::Params::GcmWrapParams(v1_proto::GcmWrapParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xBA, 0x01, 0x00],
            Ok(()),
        ),
        (
            24u32,
            "ccm_wrap_params",
            v1_proto::mechanism::Params::CcmWrapParams(v1_proto::CcmWrapParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xC2, 0x01, 0x00],
            Ok(()),
        ),
        (
            25u32,
            "ecdh2_derive_params",
            v1_proto::mechanism::Params::Ecdh2DeriveParams(v1_proto::Ecdh2DeriveParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xCA, 0x01, 0x00],
            Ok(()),
        ),
        (
            26u32,
            "ecmqv_derive_params",
            v1_proto::mechanism::Params::EcmqvDeriveParams(v1_proto::EcmqvDeriveParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xD2, 0x01, 0x00],
            Ok(()),
        ),
        (
            27u32,
            "x942_dh1_derive_params",
            v1_proto::mechanism::Params::X942Dh1DeriveParams(
                v1_proto::X942Dh1DeriveParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xDA, 0x01, 0x00],
            Ok(()),
        ),
        (
            28u32,
            "x942_dh2_derive_params",
            v1_proto::mechanism::Params::X942Dh2DeriveParams(
                v1_proto::X942Dh2DeriveParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xE2, 0x01, 0x00],
            Ok(()),
        ),
        (
            29u32,
            "x942_mqv_derive_params",
            v1_proto::mechanism::Params::X942MqvDeriveParams(
                v1_proto::X942MqvDeriveParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xEA, 0x01, 0x00],
            Ok(()),
        ),
        (
            30u32,
            "hkdf_params",
            v1_proto::mechanism::Params::HkdfParams(v1_proto::HkdfParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xF2, 0x01, 0x00],
            Ok(()),
        ),
        (
            31u32,
            "eddsa_params",
            v1_proto::mechanism::Params::EddsaParams(v1_proto::EddsaParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xFA, 0x01, 0x00],
            Ok(()),
        ),
        (
            32u32,
            "xeddsa_params",
            v1_proto::mechanism::Params::XeddsaParams(v1_proto::XeddsaParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x82, 0x02, 0x00],
            Ok(()),
        ),
        (
            33u32,
            "gostr3410_derive_params",
            v1_proto::mechanism::Params::Gostr3410DeriveParams(
                v1_proto::Gostr3410DeriveParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0x8A, 0x02, 0x00],
            Ok(()),
        ),
        (
            34u32,
            "kea_derive_params",
            v1_proto::mechanism::Params::KeaDeriveParams(v1_proto::KeaDeriveParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x92, 0x02, 0x00],
            Ok(()),
        ),
        (
            35u32,
            "ecdh_aes_key_wrap_params",
            v1_proto::mechanism::Params::EcdhAesKeyWrapParams(
                v1_proto::EcdhAesKeyWrapParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0x9A, 0x02, 0x00],
            Ok(()),
        ),
        (
            36u32,
            "rsa_aes_key_wrap_params",
            v1_proto::mechanism::Params::RsaAesKeyWrapParams(
                v1_proto::RsaAesKeyWrapParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xA2, 0x02, 0x00],
            Err(CkRv::MECHANISM_PARAM_INVALID),
        ),
        (
            37u32,
            "gostr3410_key_wrap_params",
            v1_proto::mechanism::Params::Gostr3410KeyWrapParams(
                v1_proto::Gostr3410KeyWrapParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xAA, 0x02, 0x00],
            Ok(()),
        ),
        (
            38u32,
            "key_wrap_set_oaep_params",
            v1_proto::mechanism::Params::KeyWrapSetOaepParams(
                v1_proto::KeyWrapSetOaepParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xB2, 0x02, 0x00],
            Ok(()),
        ),
        (
            39u32,
            "pbe_params",
            v1_proto::mechanism::Params::PbeParams(v1_proto::PbeParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xBA, 0x02, 0x00],
            Ok(()),
        ),
        (
            40u32,
            "pkcs5_pbkd2_params",
            v1_proto::mechanism::Params::Pkcs5Pbkd2Params(v1_proto::Pkcs5Pbkd2Params::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xC2, 0x02, 0x00],
            Ok(()),
        ),
        (
            41u32,
            "tls_mac_params",
            v1_proto::mechanism::Params::TlsMacParams(v1_proto::TlsMacParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xCA, 0x02, 0x00],
            Ok(()),
        ),
        (
            42u32,
            "tls_prf_params",
            v1_proto::mechanism::Params::TlsPrfParams(v1_proto::TlsPrfParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xD2, 0x02, 0x00],
            Ok(()),
        ),
        (
            43u32,
            "tls_kdf_params",
            v1_proto::mechanism::Params::TlsKdfParams(v1_proto::TlsKdfParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xDA, 0x02, 0x00],
            Err(CkRv::MECHANISM_PARAM_INVALID),
        ),
        (
            44u32,
            "ssl3_master_key_derive_params",
            v1_proto::mechanism::Params::Ssl3MasterKeyDeriveParams(
                v1_proto::Ssl3MasterKeyDeriveParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xE2, 0x02, 0x00],
            Err(CkRv::MECHANISM_PARAM_INVALID),
        ),
        (
            45u32,
            "tls12_master_key_derive_params",
            v1_proto::mechanism::Params::Tls12MasterKeyDeriveParams(
                v1_proto::Tls12MasterKeyDeriveParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xEA, 0x02, 0x00],
            Err(CkRv::MECHANISM_PARAM_INVALID),
        ),
        (
            46u32,
            "tls12_extended_master_key_derive_params",
            v1_proto::mechanism::Params::Tls12ExtendedMasterKeyDeriveParams(
                v1_proto::Tls12ExtendedMasterKeyDeriveParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xF2, 0x02, 0x00],
            Ok(()),
        ),
        (
            47u32,
            "ssl3_key_mat_params",
            v1_proto::mechanism::Params::Ssl3KeyMatParams(v1_proto::Ssl3KeyMatParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xFA, 0x02, 0x00],
            Err(CkRv::MECHANISM_PARAM_INVALID),
        ),
        (
            48u32,
            "wtls_master_key_derive_params",
            v1_proto::mechanism::Params::WtlsMasterKeyDeriveParams(
                v1_proto::WtlsMasterKeyDeriveParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0x82, 0x03, 0x00],
            Err(CkRv::MECHANISM_PARAM_INVALID),
        ),
        (
            49u32,
            "wtls_prf_params",
            v1_proto::mechanism::Params::WtlsPrfParams(v1_proto::WtlsPrfParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x8A, 0x03, 0x00],
            Ok(()),
        ),
        (
            50u32,
            "wtls_key_mat_params",
            v1_proto::mechanism::Params::WtlsKeyMatParams(v1_proto::WtlsKeyMatParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x92, 0x03, 0x00],
            Err(CkRv::MECHANISM_PARAM_INVALID),
        ),
        (
            51u32,
            "ike_prf_derive_params",
            v1_proto::mechanism::Params::IkePrfDeriveParams(v1_proto::IkePrfDeriveParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x9A, 0x03, 0x00],
            Ok(()),
        ),
        (
            52u32,
            "ike1_prf_derive_params",
            v1_proto::mechanism::Params::Ike1PrfDeriveParams(
                v1_proto::Ike1PrfDeriveParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xA2, 0x03, 0x00],
            Ok(()),
        ),
        (
            53u32,
            "ike1_extended_derive_params",
            v1_proto::mechanism::Params::Ike1ExtendedDeriveParams(
                v1_proto::Ike1ExtendedDeriveParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xAA, 0x03, 0x00],
            Ok(()),
        ),
        (
            54u32,
            "ike2_prf_plus_derive_params",
            v1_proto::mechanism::Params::Ike2PrfPlusDeriveParams(
                v1_proto::Ike2PrfPlusDeriveParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xB2, 0x03, 0x00],
            Ok(()),
        ),
        (
            55u32,
            "sp800_108_kdf_params",
            v1_proto::mechanism::Params::Sp800108KdfParams(v1_proto::Sp800108KdfParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xBA, 0x03, 0x00],
            Ok(()),
        ),
        (
            56u32,
            "sp800_108_feedback_kdf_params",
            v1_proto::mechanism::Params::Sp800108FeedbackKdfParams(
                v1_proto::Sp800108FeedbackKdfParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xC2, 0x03, 0x00],
            Ok(()),
        ),
        (
            57u32,
            "x3dh_initiate_params",
            v1_proto::mechanism::Params::X3dhInitiateParams(v1_proto::X3dhInitiateParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xCA, 0x03, 0x00],
            Ok(()),
        ),
        (
            58u32,
            "x3dh_respond_params",
            v1_proto::mechanism::Params::X3dhRespondParams(v1_proto::X3dhRespondParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xD2, 0x03, 0x00],
            Ok(()),
        ),
        (
            59u32,
            "x2_ratchet_initialize_params",
            v1_proto::mechanism::Params::X2RatchetInitializeParams(
                v1_proto::X2RatchetInitializeParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xDA, 0x03, 0x00],
            Ok(()),
        ),
        (
            60u32,
            "x2_ratchet_respond_params",
            v1_proto::mechanism::Params::X2RatchetRespondParams(
                v1_proto::X2RatchetRespondParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xE2, 0x03, 0x00],
            Ok(()),
        ),
        (
            61u32,
            "otp_params",
            v1_proto::mechanism::Params::OtpParams(v1_proto::OtpParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xEA, 0x03, 0x00],
            Ok(()),
        ),
        (
            62u32,
            "kip_params",
            v1_proto::mechanism::Params::KipParams(Box::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xF2, 0x03, 0x00],
            Err(CkRv::MECHANISM_PARAM_INVALID),
        ),
        (
            63u32,
            "cms_sig_params",
            v1_proto::mechanism::Params::CmsSigParams(Box::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xFA, 0x03, 0x00],
            Err(CkRv::MECHANISM_PARAM_INVALID),
        ),
        (
            64u32,
            "skipjack_private_wrap_params",
            v1_proto::mechanism::Params::SkipjackPrivateWrapParams(
                v1_proto::SkipjackPrivateWrapParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0x82, 0x04, 0x00],
            Ok(()),
        ),
        (
            65u32,
            "skipjack_relayx_params",
            v1_proto::mechanism::Params::SkipjackRelayxParams(
                v1_proto::SkipjackRelayxParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0x8A, 0x04, 0x00],
            Ok(()),
        ),
        (
            66u32,
            "mac_general_params",
            v1_proto::mechanism::Params::MacGeneralParams(v1_proto::MacGeneralParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x92, 0x04, 0x00],
            Ok(()),
        ),
        (
            67u32,
            "key_derivation_string_data",
            v1_proto::mechanism::Params::KeyDerivationStringData(
                v1_proto::KeyDerivationStringData::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0x9A, 0x04, 0x00],
            Ok(()),
        ),
        (
            68u32,
            "raw_mechanism_params",
            v1_proto::mechanism::Params::RawMechanismParams(v1_proto::RawMechanismParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xA2, 0x04, 0x00],
            Ok(()),
        ),
        (
            69u32,
            "ecies_params",
            v1_proto::mechanism::Params::EciesParams(Box::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xAA, 0x04, 0x00],
            Err(CkRv::MECHANISM_PARAM_INVALID),
        ),
        (
            70u32,
            "aes_cmac_key_derivation_params",
            v1_proto::mechanism::Params::AesCmacKeyDerivationParams(
                v1_proto::AesCmacKeyDerivationParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xB2, 0x04, 0x00],
            Ok(()),
        ),
        (
            71u32,
            "dilithium_params",
            v1_proto::mechanism::Params::DilithiumParams(v1_proto::DilithiumParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xBA, 0x04, 0x00],
            Ok(()),
        ),
        (
            72u32,
            "kyber_params",
            v1_proto::mechanism::Params::KyberParams(v1_proto::KyberParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xC2, 0x04, 0x00],
            Ok(()),
        ),
        (
            73u32,
            "hd_key_derive_params",
            v1_proto::mechanism::Params::HdKeyDeriveParams(v1_proto::HdKeyDeriveParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xCA, 0x04, 0x00],
            Ok(()),
        ),
        (
            74u32,
            "vendor_object_extract_params",
            v1_proto::mechanism::Params::VendorObjectExtractParams(
                v1_proto::VendorObjectExtractParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xD2, 0x04, 0x00],
            Ok(()),
        ),
        (
            75u32,
            "vendor_object_insert_params",
            v1_proto::mechanism::Params::VendorObjectInsertParams(
                v1_proto::VendorObjectInsertParams::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xDA, 0x04, 0x00],
            Ok(()),
        ),
        (
            76u32,
            "object_handle_param",
            v1_proto::mechanism::Params::ObjectHandleParam(v1_proto::ObjectHandleParam::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xE2, 0x04, 0x00],
            Ok(()),
        ),
        (
            77u32,
            "sign_additional_context",
            v1_proto::mechanism::Params::SignAdditionalContext(
                v1_proto::SignAdditionalContext::default(),
            ),
            vec![0x08, 0x99, 0xB3, 0x02, 0xEA, 0x04, 0x00],
            Ok(()),
        ),
        (
            78u32,
            "extract_params",
            v1_proto::mechanism::Params::ExtractParams(v1_proto::ExtractParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xF2, 0x04, 0x00],
            Ok(()),
        ),
        (
            79u32,
            "kmac_params",
            v1_proto::mechanism::Params::KmacParams(v1_proto::KmacParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0xFA, 0x04, 0x00],
            Ok(()),
        ),
        (
            80u32,
            "mu_gen_params",
            v1_proto::mechanism::Params::MuGenParams(v1_proto::MuGenParams::default()),
            vec![0x08, 0x99, 0xB3, 0x02, 0x82, 0x05, 0x00],
            Ok(()),
        ),
    ];
    assert_eq!(members.len(), 79, "one row per pre-R6 oneof tag 2..=80");
    let mut tags: Vec<u32> = members.iter().map(|row| row.0).collect();
    tags.sort_unstable();
    assert_eq!(tags, (2u32..=80u32).collect::<Vec<_>>(), "tags must cover 2..=80 exactly");
    for (tag, name, params, golden, expected) in members {
        let wire = v1_proto::Mechanism {
            mechanism_type: 0x9999,
            params: Some(params.clone()),
            parameter_encoding_version: 0,
        };
        // Legacy encode emits no new bytes (version 0 is never serialized).
        assert_eq!(wire.encode_to_vec(), golden, "{name} (tag {tag}) golden bytes");
        let decoded = v1_proto::Mechanism::decode(golden.as_slice()).unwrap();
        assert_eq!(decoded, wire, "{name} (tag {tag}) must decode bit-identically");
        // Conversion outcome pinned: default-valued messages convert as today.
        let outcome = CkMechanism::try_from(&decoded).map(|_| ());
        assert_eq!(outcome, expected, "{name} (tag {tag}) conversion outcome");
        if outcome.is_ok() {
            let back = CkMechanism::try_from(&decoded).unwrap();
            assert_eq!(back.mechanism_type.0, 0x9999);
            assert!(back.params.is_some());
        }
        // R9 v1 enforcement (S2 §3): a newer version alongside an encoded
        // legacy arm is FUNCTION_NOT_SUPPORTED pre-entry (R6 pinned
        // version-blindness as current behavior with "R9 adds v1
        // enforcement"). The legacy Raw arm (tag 68) is the exception: it
        // stays version-blind at conversion and fails closed later at
        // transport validation uniformly across versions.
        let versioned = v1_proto::Mechanism {
            mechanism_type: 0x9999,
            params: Some(params),
            parameter_encoding_version: 99,
        };
        let versioned_outcome = CkMechanism::try_from(&versioned).map(|_| ());
        let versioned_expected =
            if tag == 68 { expected } else { Err(CkRv::FUNCTION_NOT_SUPPORTED) };
        assert_eq!(versioned_outcome, versioned_expected, "{name} (tag {tag}) version-99 outcome");
    }
}

#[test]
fn r6_v1_wire_tags_pin_flat_null_and_version_placement() {
    use prost::Message as _;
    // R2 enum reuse pin: the v1 contract shares one ABI vocabulary.
    assert_eq!(v1_proto::MechanismParamAbi::Lp64NativeLe as i32, 1);
    // Pins Mechanism tags 81 (flat, LEN) and 83 (version, varint) plus
    // FlatMechanismParams tags 1 (data, LEN), 2 (declared_len, varint),
    // 3 (source_abi, varint enum) and 4 (fingerprint, fixed64).
    // Hand-computed, not round-tripped. The fingerprint value below is an
    // opaque placeholder: derivation is R7, R6 pins only the wire field.
    let flat_golden = [
        0x08, 0x99, 0xB3, 0x02, // mechanism_type 0x9999
        0x8A, 0x05, 0x11, // tag 81, LEN, 17 bytes
        0x0A, 0x02, 0x41, 0x42, // data "AB"
        0x10, 0x02, // declared_len 2
        0x18, 0x01, // source_abi LP64_NATIVE_LE
        0x21, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // fingerprint
        0x98, 0x05, 0x01, // tag 83, version 1
    ];
    let flat = v1_proto::Mechanism {
        mechanism_type: 0x9999,
        params: Some(v1_proto::mechanism::Params::FlatMechanismParams(
            v1_proto::FlatMechanismParams {
                data: b"AB".to_vec(),
                declared_len: 2,
                source_abi: v1_proto::MechanismParamAbi::Lp64NativeLe as i32,
                shape_layout_fingerprint: 0x0102_0304_0506_0708,
            },
        )),
        parameter_encoding_version: 1,
    };
    assert_eq!(flat.encode_to_vec(), flat_golden);
    assert_eq!(v1_proto::Mechanism::decode(flat_golden.as_slice()).unwrap(), flat);
    // Pins Mechanism tag 82 (null, LEN) plus NullMechanismParams tag 1
    // (declared_len, varint). NULL + nonzero length needs no bytes.
    let null_golden = [
        0x08, 0x99, 0xB3, 0x02, // mechanism_type 0x9999
        0x92, 0x05, 0x02, // tag 82, LEN, 2 bytes
        0x08, 0x05, // declared_len 5
        0x98, 0x05, 0x01, // tag 83, version 1
    ];
    let null = v1_proto::Mechanism {
        mechanism_type: 0x9999,
        params: Some(v1_proto::mechanism::Params::NullMechanismParams(
            v1_proto::NullMechanismParams { declared_len: 5 },
        )),
        parameter_encoding_version: 1,
    };
    assert_eq!(null.encode_to_vec(), null_golden);
    assert_eq!(v1_proto::Mechanism::decode(null_golden.as_slice()).unwrap(), null);
}

#[test]
fn r9_v1_presence_matrix_acceptance() {
    // Ex-R6 presence matrix (`r6_v1_presence_matrix_fail_closed_until_r9`):
    // R9 resolves its TODO(R9) — the version-1 row converts, newer versions
    // report FUNCTION_NOT_SUPPORTED, version 0 stays contradictory.
    use prost::Message as _;
    let flat = || {
        Some(v1_proto::mechanism::Params::FlatMechanismParams(v1_proto::FlatMechanismParams {
            data: vec![0xA5; 16],
            declared_len: 16,
            source_abi: v1_proto::MechanismParamAbi::Lp64NativeLe as i32,
            shape_layout_fingerprint: 0,
        }))
    };
    let null = || {
        Some(v1_proto::mechanism::Params::NullMechanismParams(v1_proto::NullMechanismParams {
            declared_len: 16,
        }))
    };
    // Flat/Null × {0, 1, newer}: prost round-trips every combination.
    // R9 acceptance (TODO(R9) resolved): version 1 converts; version 0 is
    // contradictory metadata (Flat/Null are valid only with v1); anything
    // newer is FUNCTION_NOT_SUPPORTED pre-entry (S2 §3).
    for (name, params) in [("flat", flat()), ("null", null())] {
        for version in [0u32, 1, 2, u32::MAX] {
            let wire = v1_proto::Mechanism {
                mechanism_type: 0x1082, // CKM_AES_GCM
                params: params.clone(),
                parameter_encoding_version: version,
            };
            let round_tripped =
                v1_proto::Mechanism::decode(wire.encode_to_vec().as_slice()).unwrap();
            assert_eq!(round_tripped, wire, "{name} version {version} must round-trip");
            let outcome = CkMechanism::try_from(&wire).map(|_| ());
            let expected = if version == 0 {
                Err(CkRv::MECHANISM_PARAM_INVALID)
            } else if version == 1 {
                Ok(())
            } else {
                Err(CkRv::FUNCTION_NOT_SUPPORTED)
            };
            assert_eq!(outcome, expected, "{name} version {version} conversion outcome");
        }
    }
    // Absent oneof stays convertible at any version (parameterless).
    for version in [0u32, 1, 99] {
        let wire = v1_proto::Mechanism {
            mechanism_type: 0x1082,
            params: None,
            parameter_encoding_version: version,
        };
        let back = CkMechanism::try_from(&wire).unwrap();
        assert!(back.params.is_none());
    }
    // Legacy typed arms with unset bools convert identically with and
    // without version 1 (absence is consistent with v1 presence semantics).
    let legacy = v1_proto::GcmParams {
        iv: vec![0x01; 12],
        iv_bits: 96,
        aad: Vec::new(),
        tag_bits: 128,
        iv_buffer_len: 0,
        iv_null: false,
        aad_null: false,
        iv_null_len: None,
        aad_null_len: None,
    };
    let baseline = CkMechanism::try_from(&v1_proto::Mechanism {
        mechanism_type: 0x1082,
        params: Some(v1_proto::mechanism::Params::GcmParams(legacy.clone())),
        parameter_encoding_version: 0,
    })
    .unwrap();
    let wire_v1 = v1_proto::Mechanism {
        mechanism_type: 0x1082,
        params: Some(v1_proto::mechanism::Params::GcmParams(legacy.clone())),
        parameter_encoding_version: 1,
    };
    assert_eq!(
        CkMechanism::try_from(&wire_v1).unwrap(),
        baseline,
        "legacy GCM conversion must ignore version 1",
    );
    // R9 v1 enforcement (S2 §3): a version newer than the daemon on an
    // encoded member is FUNCTION_NOT_SUPPORTED pre-entry — even for
    // legacy-typed arms (R6 pinned version-blindness as current behavior
    // with "R9 adds v1 enforcement").
    let wire_newer = v1_proto::Mechanism {
        mechanism_type: 0x1082,
        params: Some(v1_proto::mechanism::Params::GcmParams(legacy.clone())),
        parameter_encoding_version: 99,
    };
    assert_eq!(
        CkMechanism::try_from(&wire_newer),
        Err(CkRv::FUNCTION_NOT_SUPPORTED),
        "legacy GCM with a newer version must be FUNCTION_NOT_SUPPORTED",
    );
}

#[test]
fn r6_contradictory_metadata_vectors() {
    // Legacy NULL-bool set in a v1-stamped message: S2 §3 reconciliation
    // rejects it as contradictory metadata (TODO(R9) resolved).
    let legacy_bool_v1 = v1_proto::Mechanism {
        mechanism_type: 0x1082,
        params: Some(v1_proto::mechanism::Params::GcmParams(v1_proto::GcmParams {
            iv: Vec::new(),
            iv_bits: 0,
            aad: Vec::new(),
            tag_bits: 0,
            iv_buffer_len: 0,
            iv_null: true,
            aad_null: false,
            iv_null_len: None,
            aad_null_len: None,
        })),
        parameter_encoding_version: 1,
    };
    assert_eq!(CkMechanism::try_from(&legacy_bool_v1), Err(CkRv::MECHANISM_PARAM_INVALID));
    // Flat with version 0: contradictory (Flat is valid only with v1).
    let flat_v0 = v1_proto::Mechanism {
        mechanism_type: 0x1082,
        params: Some(v1_proto::mechanism::Params::FlatMechanismParams(
            v1_proto::FlatMechanismParams {
                data: b"AB".to_vec(),
                declared_len: 2,
                source_abi: v1_proto::MechanismParamAbi::Lp64NativeLe as i32,
                shape_layout_fingerprint: 0,
            },
        )),
        parameter_encoding_version: 0,
    };
    assert_eq!(CkMechanism::try_from(&flat_v0), Err(CkRv::MECHANISM_PARAM_INVALID));
    // Flat length mismatch (data.len() != declared_len): contradictory.
    let flat_mismatch = v1_proto::Mechanism {
        mechanism_type: 0x1082,
        params: Some(v1_proto::mechanism::Params::FlatMechanismParams(
            v1_proto::FlatMechanismParams {
                data: b"ABC".to_vec(),
                declared_len: 2,
                source_abi: v1_proto::MechanismParamAbi::Lp64NativeLe as i32,
                shape_layout_fingerprint: 0,
            },
        )),
        parameter_encoding_version: 1,
    };
    assert_eq!(CkMechanism::try_from(&flat_mismatch), Err(CkRv::MECHANISM_PARAM_INVALID));
    // Null with version 0: contradictory (Null is valid only with v1).
    let null_v0 = v1_proto::Mechanism {
        mechanism_type: 0x1082,
        params: Some(v1_proto::mechanism::Params::NullMechanismParams(
            v1_proto::NullMechanismParams { declared_len: 7 },
        )),
        parameter_encoding_version: 0,
    };
    assert_eq!(CkMechanism::try_from(&null_v0), Err(CkRv::MECHANISM_PARAM_INVALID));
    // Message-opaque/version mismatch (R2 wire, R3 validation): opaque
    // bytes without version 1 stay rejected with PARAM_INVALID.
    let opaque_v0 = v1_proto::MessageParameter {
        params: Some(v1_proto::message_parameter::Params::OpaqueMessageParams(
            v1_proto::OpaqueMessageParams { data: b"AB".to_vec(), declared_len: 2 },
        )),
        parameter_encoding_version: 0,
    };
    assert_eq!(
        super::super::message_params::validate_structured_wire_parameter(&opaque_v0),
        Err(CkRv::MECHANISM_PARAM_INVALID),
    );
}

#[test]
fn r6_old_new_mix() {
    use prost::Message as _;
    // New decoder × old encoder output: pre-v1 bytes (no version field)
    // decode exactly as before — the tag-4 GCM row of the stability table.
    let legacy_golden = [0x08, 0x99, 0xB3, 0x02, 0x22, 0x00];
    let decoded = v1_proto::Mechanism::decode(legacy_golden.as_slice()).unwrap();
    assert_eq!(decoded.parameter_encoding_version, 0);
    assert_eq!(
        decoded.params,
        Some(v1_proto::mechanism::Params::GcmParams(v1_proto::GcmParams::default())),
    );
    let back = CkMechanism::try_from(&decoded).unwrap();
    assert!(matches!(back.params, Some(CkMechanismParams::Gcm(_))));
    // Unknown-field tolerance (the property old decoders rely on when a new
    // encoder emits tags they do not know): trailing tag-99 bytes change
    // nothing at decode.
    let mut future = legacy_golden.to_vec();
    future.extend_from_slice(&[0x9A, 0x06, 0x02, 0x5A, 0x5A]);
    assert_eq!(v1_proto::Mechanism::decode(future.as_slice()).unwrap(), decoded);
    // New encoder, legacy value: conversion emits version 0 with no new
    // bytes — byte-identical to the old encoder's output.
    let legacy = CkMechanism {
        mechanism_type: CkMechanismType(0x9999),
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv_bits: 0,
            tag_bits: 0,
            iv_buffer_len: 0,
            iv_presence: PointerBytes::from_legacy(&[], false),
            aad_presence: PointerBytes::from_legacy(&[], false),
        })),
    };
    let encoded = v1_proto::Mechanism::try_from(&legacy).unwrap();
    assert_eq!(encoded.parameter_encoding_version, 0);
    assert_eq!(encoded.encode_to_vec(), legacy_golden);
}

// ---------------------------------------------------------------------------
// R9: v1 Flat/Null domain conversion (S2 §3/§6). Tests first (TDD RED):
// Flat/Null decode currently fails closed (R6 catch-all), so the v1
// acceptance assertions below fail until conversion lands.
// ---------------------------------------------------------------------------

fn r9_flat_wire(data: Vec<u8>, declared_len: u64, abi: i32, version: u32) -> v1_proto::Mechanism {
    v1_proto::Mechanism {
        mechanism_type: 0x1082,
        params: Some(v1_proto::mechanism::Params::FlatMechanismParams(
            v1_proto::FlatMechanismParams {
                data,
                declared_len,
                source_abi: abi,
                shape_layout_fingerprint: 0x0102_0304_0506_0708,
            },
        )),
        parameter_encoding_version: version,
    }
}

fn r9_null_wire(declared_len: u64, version: u32) -> v1_proto::Mechanism {
    v1_proto::Mechanism {
        mechanism_type: 0x1082,
        params: Some(v1_proto::mechanism::Params::NullMechanismParams(
            v1_proto::NullMechanismParams { declared_len },
        )),
        parameter_encoding_version: version,
    }
}

#[test]
fn r9_flat_v1_decodes_and_threads_every_field() {
    use pkcs11_proxy_ng_types::shape_descriptors::ParamAbi;
    let wire = r9_flat_wire(b"AB".to_vec(), 2, v1_proto::MechanismParamAbi::Lp64NativeLe as i32, 1);
    let back = CkMechanism::try_from(&wire).unwrap();
    assert_eq!(back.mechanism_type.0, 0x1082);
    let Some(CkMechanismParams::Flat(flat)) = back.params else {
        panic!("v1 Flat must decode to the Flat domain variant")
    };
    flat.bytes.expose(|b| assert_eq!(b, b"AB"));
    assert_eq!(flat.declared_len, 2);
    assert_eq!(flat.source_abi, Some(ParamAbi::Lp64NativeLe));
    assert_eq!(flat.fingerprint, 0x0102_0304_0506_0708);
    assert_eq!(flat.version, 1);
    // ILP32, LLP64-pack1, and ILP32-pack1 thread through distinctly.
    for (wire_abi, domain_abi) in [
        (v1_proto::MechanismParamAbi::Ilp32NativeLe, ParamAbi::Ilp32NativeLe),
        (v1_proto::MechanismParamAbi::Llp64Packed1Le, ParamAbi::Llp64Packed1Le),
        (v1_proto::MechanismParamAbi::Ilp32Packed1Le, ParamAbi::Ilp32Packed1Le),
    ] {
        let back =
            CkMechanism::try_from(&r9_flat_wire(b"AB".to_vec(), 2, wire_abi as i32, 1)).unwrap();
        let Some(CkMechanismParams::Flat(flat)) = back.params else {
            panic!("must decode to Flat")
        };
        assert_eq!(flat.source_abi, Some(domain_abi));
    }
}

#[test]
fn r9_null_v1_decodes_and_threads_version() {
    let back = CkMechanism::try_from(&r9_null_wire(41, 1)).unwrap();
    assert_eq!(back.mechanism_type.0, 0x1082);
    assert_eq!(back.params, Some(CkMechanismParams::Null { declared_len: 41, version: 1 }));
}

#[test]
fn r9_flat_null_v1_wire_round_trip() {
    // wire → domain → wire is byte-identical for v1 members.
    for wire in [
        r9_flat_wire(b"AB".to_vec(), 2, v1_proto::MechanismParamAbi::Lp64NativeLe as i32, 1),
        r9_flat_wire(Vec::new(), 0, v1_proto::MechanismParamAbi::Ilp32NativeLe as i32, 1),
        r9_null_wire(0, 1),
        r9_null_wire(u64::MAX, 1),
    ] {
        let domain = CkMechanism::try_from(&wire).unwrap();
        let back = v1_proto::Mechanism::try_from(&domain).unwrap();
        assert_eq!(back, wire, "v1 wire→domain→wire must be identical");
    }
}

#[test]
fn r9_unknown_source_abi_threads_as_none() {
    // UNSPECIFIED (0) and unrecognized values decode to source_abi None;
    // transport validation rejects them (validation owns the ABI match).
    for abi in [0, 99, -1] {
        let back = CkMechanism::try_from(&r9_flat_wire(b"AB".to_vec(), 2, abi, 1)).unwrap();
        let Some(CkMechanismParams::Flat(flat)) = back.params.clone() else {
            panic!("must decode to Flat")
        };
        assert_eq!(flat.source_abi, None, "wire ABI {abi} must thread as None");
        // ... and re-encode as UNSPECIFIED (faithful round-trip).
        let wire = v1_proto::Mechanism::try_from(&CkMechanism {
            mechanism_type: CkMechanismType(0x1082),
            params: back.params,
        })
        .unwrap();
        let Some(v1_proto::mechanism::Params::FlatMechanismParams(flat_wire)) =
            wire.params.as_ref()
        else {
            panic!("must encode back to Flat")
        };
        assert_eq!(flat_wire.source_abi, v1_proto::MechanismParamAbi::Unspecified as i32);
    }
}

#[test]
fn r9_newer_version_is_function_not_supported() {
    // S2 §3: per-message version newer than the daemon understands is
    // FUNCTION_NOT_SUPPORTED pre-entry — for every ENCODED member.
    let flat = || r9_flat_wire(b"AB".to_vec(), 2, 1, 99).params.clone();
    let null = || r9_null_wire(7, 99).params.clone();
    let typed = || Some(v1_proto::mechanism::Params::GcmParams(v1_proto::GcmParams::default()));
    for (name, params) in [("flat", flat()), ("null", null()), ("typed", typed())] {
        for version in [2u32, 99, u32::MAX] {
            let wire = v1_proto::Mechanism {
                mechanism_type: 0x1082,
                params: params.clone(),
                parameter_encoding_version: version,
            };
            assert_eq!(
                CkMechanism::try_from(&wire),
                Err(CkRv::FUNCTION_NOT_SUPPORTED),
                "{name} with version {version} must be FUNCTION_NOT_SUPPORTED"
            );
        }
    }
    // Unencoded messages stay version-blind (R6-pinned): nothing to
    // misread in an absent oneof, and Raw fails closed later at
    // transport validation uniformly across versions.
    for version in [0u32, 1, 2, 99] {
        let none = v1_proto::Mechanism {
            mechanism_type: 0x1082,
            params: None,
            parameter_encoding_version: version,
        };
        assert!(CkMechanism::try_from(&none).unwrap().params.is_none());
        let raw = v1_proto::Mechanism {
            mechanism_type: 0x1082,
            params: Some(v1_proto::mechanism::Params::RawMechanismParams(
                v1_proto::RawMechanismParams { data: b"AB".to_vec() },
            )),
            parameter_encoding_version: version,
        };
        assert!(matches!(
            CkMechanism::try_from(&raw).unwrap().params,
            Some(CkMechanismParams::Raw(_))
        ));
    }
}

#[test]
fn r9_legacy_bool_reconciliation_matrix() {
    // S2 §3 NULL-bool reconciliation: v1 is presence-only — any set legacy
    // bool in a versioned message is contradictory metadata (PARAM_INVALID).
    // Every legacy `*_null` bool site in the classic conversion:
    // Full literals (no struct-update syntax: the generated message types
    // implement Drop, so field moves out of a default temporary are rejected).
    let gcm_iv = || {
        v1_proto::mechanism::Params::GcmParams(v1_proto::GcmParams {
            iv: Vec::new(),
            iv_bits: 0,
            aad: Vec::new(),
            tag_bits: 0,
            iv_buffer_len: 0,
            iv_null: true,
            aad_null: false,
            iv_null_len: None,
            aad_null_len: None,
        })
    };
    let gcm_aad = || {
        v1_proto::mechanism::Params::GcmParams(v1_proto::GcmParams {
            iv: Vec::new(),
            iv_bits: 0,
            aad: Vec::new(),
            tag_bits: 0,
            iv_buffer_len: 0,
            iv_null: false,
            aad_null: true,
            iv_null_len: None,
            aad_null_len: None,
        })
    };
    let ccm_nonce = || {
        v1_proto::mechanism::Params::CcmParams(v1_proto::CcmParams {
            data_len: 0,
            nonce: Vec::new(),
            aad: Vec::new(),
            mac_len: 0,
            nonce_null: true,
            aad_null: false,
            nonce_null_len: None,
            aad_null_len: None,
        })
    };
    let ccm_aad = || {
        v1_proto::mechanism::Params::CcmParams(v1_proto::CcmParams {
            data_len: 0,
            nonce: Vec::new(),
            aad: Vec::new(),
            mac_len: 0,
            nonce_null: false,
            aad_null: true,
            nonce_null_len: None,
            aad_null_len: None,
        })
    };
    let oaep_source = || {
        v1_proto::mechanism::Params::RsaPkcsOaepParams(v1_proto::RsaPkcsOaepParams {
            hash_alg: 0,
            mgf: 0,
            source: 0,
            source_data: Vec::new(),
            source_null: true,
            source_data_null_len: None,
        })
    };
    let nested_oaep_source = || {
        v1_proto::mechanism::Params::RsaAesKeyWrapParams(v1_proto::RsaAesKeyWrapParams {
            aes_key_bits: 0,
            oaep_params: Some(v1_proto::RsaPkcsOaepParams {
                hash_alg: 0,
                mgf: 0,
                source: 0,
                source_data: Vec::new(),
                source_null: true,
                source_data_null_len: None,
            }),
        })
    };
    let sites: Vec<(&str, v1_proto::mechanism::Params)> = vec![
        ("gcm.iv_null", gcm_iv()),
        ("gcm.aad_null", gcm_aad()),
        ("ccm.nonce_null", ccm_nonce()),
        ("ccm.aad_null", ccm_aad()),
        ("oaep.source_null", oaep_source()),
        ("rsa_aes_key_wrap.oaep.source_null", nested_oaep_source()),
    ];
    for (name, params) in &sites {
        // Version 0: legacy meaning preserved bit-identically.
        let legacy = v1_proto::Mechanism {
            mechanism_type: 0x1082,
            params: Some(params.clone()),
            parameter_encoding_version: 0,
        };
        assert!(
            CkMechanism::try_from(&legacy).is_ok(),
            "{name} set at version 0 must keep its legacy meaning"
        );
        // Version 1: contradictory metadata.
        let versioned = v1_proto::Mechanism {
            mechanism_type: 0x1082,
            params: Some(params.clone()),
            parameter_encoding_version: 1,
        };
        assert_eq!(
            CkMechanism::try_from(&versioned),
            Err(CkRv::MECHANISM_PARAM_INVALID),
            "{name} set at version 1 must be contradictory metadata"
        );
    }
    // Unset bools at version 1 stay convertible (R6-pinned version-blind
    // arm): absence is consistent with v1 presence semantics.
    let unset = v1_proto::Mechanism {
        mechanism_type: 0x1082,
        params: Some(v1_proto::mechanism::Params::GcmParams(v1_proto::GcmParams::default())),
        parameter_encoding_version: 1,
    };
    assert!(matches!(
        CkMechanism::try_from(&unset).unwrap().params,
        Some(CkMechanismParams::Gcm(_))
    ));
}

#[test]
fn r9_null_has_no_cap_at_decode() {
    // Null carries no bytes: only CK_ULONG narrowing applies (validation),
    // never the 64 KiB cap — even u64::MAX decodes.
    let back = CkMechanism::try_from(&r9_null_wire(u64::MAX, 1)).unwrap();
    assert_eq!(back.params, Some(CkMechanismParams::Null { declared_len: u64::MAX, version: 1 }));
}

#[test]
fn r9_encode_emits_threaded_version_for_v1_only() {
    use pkcs11_proxy_ng_types::shape_descriptors::ParamAbi;
    // Flat/Null encode the stored (threaded) version; every legacy member
    // keeps emitting version 0 (R6 old/new mix, extended to Raw).
    let flat = CkMechanism {
        mechanism_type: CkMechanismType(0x1082),
        params: Some(CkMechanismParams::Flat(FlatParams {
            bytes: b"AB".to_vec().into(),
            declared_len: 2,
            source_abi: Some(ParamAbi::Lp64NativeLe),
            fingerprint: 0x0102_0304_0506_0708,
            version: 1,
        })),
    };
    let wire = v1_proto::Mechanism::try_from(&flat).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    let null = CkMechanism {
        mechanism_type: CkMechanismType(0x1082),
        params: Some(CkMechanismParams::Null { declared_len: 7, version: 1 }),
    };
    let wire = v1_proto::Mechanism::try_from(&null).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    let raw = CkMechanism {
        mechanism_type: CkMechanismType(0x1082),
        params: Some(CkMechanismParams::Raw(RawMechanismParams { data: b"AB".to_vec().into() })),
    };
    let wire = v1_proto::Mechanism::try_from(&raw).unwrap();
    assert_eq!(wire.parameter_encoding_version, 0);
}

// ---------------------------------------------------------------------------
// R16 typed-presence matrices (S2 §3, input-pointer families in S2 §8 order)
// ---------------------------------------------------------------------------

/// Decode one `Mechanism.params` arm under an explicit wire version.
fn r16_decode(params: v1_proto::mechanism::Params, version: u32) -> Result<CkMechanism, CkRv> {
    CkMechanism::try_from(&v1_proto::Mechanism {
        mechanism_type: 0x1087, // CKM_AES_GCM (arbitrary for conversion)
        params: Some(params),
        parameter_encoding_version: version,
    })
}

/// Assert a `Present` arm with exactly these bytes.
fn r16_assert_present(presence: &PointerBytes, expected: &[u8]) {
    match presence {
        PointerBytes::Present(bytes) => bytes.expose(|got| assert_eq!(got, expected)),
        PointerBytes::Null { declared_len } => {
            panic!("expected Present({expected:?}), got Null{{{declared_len}}}")
        }
    }
}

/// Assert a `Null` arm with exactly this declared length.
fn r16_assert_null(presence: &PointerBytes, expected_len: u64) {
    match presence {
        PointerBytes::Null { declared_len } => assert_eq!(*declared_len, expected_len),
        PointerBytes::Present(bytes) => {
            bytes.expose(|got| panic!("expected Null{{{expected_len}}}, got Present({got:?})"));
        }
    }
}

/// Assert legacy secret bytes equal the expected slice.
fn r16_assert_secret_eq(actual: &SecretBytes, expected: &[u8]) {
    actual.expose(|got| assert_eq!(got, expected));
}

#[test]
fn r16_gcm_presence_matrix() {
    #[allow(clippy::too_many_arguments)]
    let wire = |iv: Vec<u8>,
                iv_null_len: Option<u64>,
                aad: Vec<u8>,
                aad_null_len: Option<u64>,
                iv_null: bool,
                aad_null: bool,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::GcmParams(v1_proto::GcmParams {
                iv,
                iv_bits: 96,
                aad,
                tag_bits: 128,
                iv_buffer_len: 0,
                iv_null,
                aad_null,
                iv_null_len,
                aad_null_len,
            }),
            version,
        )
    };
    fn gcm(mechanism: &CkMechanism) -> &GcmParams {
        match &mechanism.params {
            Some(CkMechanismParams::Gcm(p)) => p,
            other => panic!("expected Gcm, got {other:?}"),
        }
    }
    // NULL/0 × NULL/0 (v1): the presence peers ARE the whole value
    // post-R19 (no legacy mirrors remain; validation normalizes the
    // NULL/0 shape for the backend).
    let back = wire(vec![], Some(0), vec![], Some(0), false, false, 1).unwrap();
    let p = gcm(&back);
    r16_assert_null(&p.iv_presence, 0);
    r16_assert_null(&p.aad_presence, 0);
    // NULL/12 × NULL/16.
    let back = wire(vec![], Some(12), vec![], Some(16), false, false, 1).unwrap();
    let p = gcm(&back);
    r16_assert_null(&p.iv_presence, 12);
    r16_assert_null(&p.aad_presence, 16);
    // non-NULL/0 × non-NULL/0: absent presence + empty bytes is Present.
    let back = wire(vec![], None, vec![], None, false, false, 1).unwrap();
    let p = gcm(&back);
    r16_assert_present(&p.iv_presence, &[]);
    r16_assert_present(&p.aad_presence, &[]);
    // non-NULL/n × non-NULL/n.
    let back = wire(vec![1; 12], None, vec![2; 16], None, false, false, 1).unwrap();
    let p = gcm(&back);
    r16_assert_present(&p.iv_presence, &[1; 12]);
    r16_assert_present(&p.aad_presence, &[2; 16]);
    assert_eq!(p.iv_presence, PointerBytes::present_copy(&[1; 12]));
    r16_assert_secret_eq(p.aad_presence.as_present().unwrap(), &[2; 16]);
    // Mixed: valid IV + NULL AAD stays one typed message (fields decode
    // independently — the R17 fix shape).
    let back = wire(vec![1; 12], None, vec![], Some(16), false, false, 1).unwrap();
    let p = gcm(&back);
    r16_assert_present(&p.iv_presence, &[1; 12]);
    r16_assert_null(&p.aad_presence, 16);
    // v1 rejects any set legacy bool (bool-only and bool+presence alike).
    assert_eq!(
        wire(vec![], None, vec![], None, true, false, 1),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
    assert_eq!(
        wire(vec![], None, vec![], None, false, true, 1),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
    assert_eq!(
        wire(vec![], Some(0), vec![], None, true, false, 1),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
    // v0 keeps the legacy meaning (bools), with the Null{0} mirror.
    let back = wire(vec![], None, vec![], None, true, true, 0).unwrap();
    let p = gcm(&back);
    assert!(p.iv_presence.is_null() && p.aad_presence.is_null());
    r16_assert_null(&p.iv_presence, 0);
    r16_assert_null(&p.aad_presence, 0);
    // v0 + presence set is contradictory (v1-only metadata, legacy stamp).
    assert_eq!(
        wire(vec![], Some(0), vec![], None, false, false, 0),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
    // Presence + non-empty bytes is contradictory (NULL-with-bytes).
    assert_eq!(
        wire(vec![1], Some(1), vec![], None, false, false, 1),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
}

#[test]
fn r16_ccm_presence_matrix() {
    #[allow(clippy::too_many_arguments)]
    let wire = |nonce: Vec<u8>,
                nonce_null_len: Option<u64>,
                aad: Vec<u8>,
                aad_null_len: Option<u64>,
                nonce_null: bool,
                aad_null: bool,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::CcmParams(v1_proto::CcmParams {
                data_len: 0,
                nonce,
                aad,
                mac_len: 16,
                nonce_null,
                aad_null,
                nonce_null_len,
                aad_null_len,
            }),
            version,
        )
    };
    fn ccm(mechanism: &CkMechanism) -> &CcmParams {
        match &mechanism.params {
            Some(CkMechanismParams::Ccm(p)) => p,
            other => panic!("expected Ccm, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), false, false, 1).unwrap();
    let p = ccm(&back);
    r16_assert_null(&p.nonce_presence, 0);
    r16_assert_null(&p.aad_presence, 0);
    let back = wire(vec![], Some(13), vec![], Some(9), false, false, 1).unwrap();
    let p = ccm(&back);
    r16_assert_null(&p.nonce_presence, 13);
    r16_assert_null(&p.aad_presence, 9);
    let back = wire(vec![], None, vec![], None, false, false, 1).unwrap();
    let p = ccm(&back);
    r16_assert_present(&p.nonce_presence, &[]);
    r16_assert_present(&p.aad_presence, &[]);
    let back = wire(vec![3; 13], None, vec![4; 9], None, false, false, 1).unwrap();
    let p = ccm(&back);
    r16_assert_present(&p.nonce_presence, &[3; 13]);
    r16_assert_present(&p.aad_presence, &[4; 9]);
    assert_eq!(p.nonce_presence, PointerBytes::present_copy(&[3; 13]));
    r16_assert_secret_eq(p.aad_presence.as_present().unwrap(), &[4; 9]);
    let back = wire(vec![3; 13], None, vec![], Some(9), false, false, 1).unwrap();
    let p = ccm(&back);
    r16_assert_present(&p.nonce_presence, &[3; 13]);
    r16_assert_null(&p.aad_presence, 9);
    assert_eq!(
        wire(vec![], None, vec![], None, true, false, 1),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
    assert_eq!(
        wire(vec![], None, vec![], None, false, true, 1),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
    let back = wire(vec![], None, vec![], None, true, true, 0).unwrap();
    let p = ccm(&back);
    assert!(p.nonce_presence.is_null() && p.aad_presence.is_null());
    r16_assert_null(&p.nonce_presence, 0);
    r16_assert_null(&p.aad_presence, 0);
    assert_eq!(
        wire(vec![], Some(0), vec![], None, false, false, 0),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
    assert_eq!(
        wire(vec![], None, vec![5], Some(1), false, false, 1),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
}

#[test]
fn r16_gcm_wrap_presence_matrix() {
    let wire = |iv: Vec<u8>,
                iv_null_len: Option<u64>,
                aad: Vec<u8>,
                aad_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::GcmWrapParams(v1_proto::GcmWrapParams {
                iv,
                iv_fixed_bits: 0,
                iv_generator: 0,
                aad,
                tag_bits: 128,
                iv_null_len,
                aad_null_len,
            }),
            version,
        )
    };
    fn wrap(mechanism: &CkMechanism) -> &GcmWrapParams {
        match &mechanism.params {
            Some(CkMechanismParams::GcmWrap(p)) => p,
            other => panic!("expected GcmWrap, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = wrap(&back);
    r16_assert_null(&p.iv_presence, 0);
    r16_assert_null(&p.aad_presence, 0);
    let back = wire(vec![], Some(12), vec![], Some(7), 1).unwrap();
    let p = wrap(&back);
    r16_assert_null(&p.iv_presence, 12);
    r16_assert_null(&p.aad_presence, 7);
    let back = wire(vec![], None, vec![], None, 1).unwrap();
    let p = wrap(&back);
    r16_assert_present(&p.iv_presence, &[]);
    r16_assert_present(&p.aad_presence, &[]);
    let back = wire(vec![1; 12], None, vec![2; 7], None, 1).unwrap();
    let p = wrap(&back);
    r16_assert_present(&p.iv_presence, &[1; 12]);
    r16_assert_present(&p.aad_presence, &[2; 7]);
    let back = wire(vec![], Some(12), vec![2; 7], None, 1).unwrap();
    let p = wrap(&back);
    r16_assert_null(&p.iv_presence, 12);
    r16_assert_present(&p.aad_presence, &[2; 7]);
    // v0 meaning: empty/non-empty bytes mirror to Present (no bools).
    let back = wire(vec![], None, vec![9; 3], None, 0).unwrap();
    let p = wrap(&back);
    r16_assert_present(&p.iv_presence, &[]);
    r16_assert_present(&p.aad_presence, &[9; 3]);
    assert_eq!(wire(vec![], Some(0), vec![], None, 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), vec![], None, 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_ccm_wrap_presence_matrix() {
    let wire = |nonce: Vec<u8>,
                nonce_null_len: Option<u64>,
                aad: Vec<u8>,
                aad_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::CcmWrapParams(v1_proto::CcmWrapParams {
                data_len: 0,
                nonce,
                nonce_fixed_bits: 0,
                nonce_generator: 0,
                aad,
                mac_len: 16,
                nonce_null_len,
                aad_null_len,
            }),
            version,
        )
    };
    fn wrap(mechanism: &CkMechanism) -> &CcmWrapParams {
        match &mechanism.params {
            Some(CkMechanismParams::CcmWrap(p)) => p,
            other => panic!("expected CcmWrap, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = wrap(&back);
    r16_assert_null(&p.nonce_presence, 0);
    r16_assert_null(&p.aad_presence, 0);
    let back = wire(vec![], Some(11), vec![], Some(5), 1).unwrap();
    let p = wrap(&back);
    r16_assert_null(&p.nonce_presence, 11);
    r16_assert_null(&p.aad_presence, 5);
    let back = wire(vec![], None, vec![], None, 1).unwrap();
    let p = wrap(&back);
    r16_assert_present(&p.nonce_presence, &[]);
    r16_assert_present(&p.aad_presence, &[]);
    let back = wire(vec![6; 11], None, vec![7; 5], None, 1).unwrap();
    let p = wrap(&back);
    r16_assert_present(&p.nonce_presence, &[6; 11]);
    r16_assert_present(&p.aad_presence, &[7; 5]);
    let back = wire(vec![6; 11], None, vec![], Some(5), 1).unwrap();
    let p = wrap(&back);
    r16_assert_present(&p.nonce_presence, &[6; 11]);
    r16_assert_null(&p.aad_presence, 5);
    let back = wire(vec![8; 2], None, vec![], None, 0).unwrap();
    let p = wrap(&back);
    r16_assert_present(&p.nonce_presence, &[8; 2]);
    r16_assert_present(&p.aad_presence, &[]);
    assert_eq!(wire(vec![], None, vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![], None, vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_eddsa_presence_matrix() {
    let wire = |context_data: Vec<u8>, context_data_null_len: Option<u64>, version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::EddsaParams(v1_proto::EddsaParams {
                ph_flag: false,
                context_data,
                context_data_null_len,
            }),
            version,
        )
    };
    fn eddsa(mechanism: &CkMechanism) -> &EddsaParams {
        match &mechanism.params {
            Some(CkMechanismParams::Eddsa(p)) => p,
            other => panic!("expected Eddsa, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), 1).unwrap();
    r16_assert_null(&eddsa(&back).context_data_presence, 0);
    let back = wire(vec![], Some(41), 1).unwrap();
    r16_assert_null(&eddsa(&back).context_data_presence, 41);
    let back = wire(vec![], None, 1).unwrap();
    let p = eddsa(&back);
    r16_assert_present(&p.context_data_presence, &[]);
    r16_assert_secret_eq(p.context_data_presence.as_present().unwrap(), &[]);
    let back = wire(vec![0xA5; 9], None, 1).unwrap();
    let p = eddsa(&back);
    r16_assert_present(&p.context_data_presence, &[0xA5; 9]);
    r16_assert_secret_eq(p.context_data_presence.as_present().unwrap(), &[0xA5; 9]);
    let back = wire(vec![], None, 0).unwrap();
    r16_assert_present(&eddsa(&back).context_data_presence, &[]);
    assert_eq!(wire(vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_oaep_presence_matrix() {
    let wire = |source_data: Vec<u8>,
                source_data_null_len: Option<u64>,
                source_null: bool,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::RsaPkcsOaepParams(v1_proto::RsaPkcsOaepParams {
                hash_alg: 0x250,
                mgf: 1,
                source: 1,
                source_data,
                source_null,
                source_data_null_len,
            }),
            version,
        )
    };
    fn oaep(mechanism: &CkMechanism) -> &RsaPkcsOaepParams {
        match &mechanism.params {
            Some(CkMechanismParams::RsaPkcsOaep(p)) => p,
            other => panic!("expected RsaPkcsOaep, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), false, 1).unwrap();
    let p = oaep(&back);
    r16_assert_null(&p.source_data_presence, 0);
    let back = wire(vec![], Some(20), false, 1).unwrap();
    r16_assert_null(&oaep(&back).source_data_presence, 20);
    let back = wire(vec![], None, false, 1).unwrap();
    r16_assert_present(&oaep(&back).source_data_presence, &[]);
    let back = wire(vec![0xBB; 20], None, false, 1).unwrap();
    let p = oaep(&back);
    r16_assert_present(&p.source_data_presence, &[0xBB; 20]);
    r16_assert_secret_eq(p.source_data_presence.as_present().unwrap(), &[0xBB; 20]);
    assert_eq!(wire(vec![], None, true, 1), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![], Some(0), true, 1), Err(CkRv::MECHANISM_PARAM_INVALID));
    let back = wire(vec![], None, true, 0).unwrap();
    let p = oaep(&back);
    assert!(p.source_data_presence.is_null());
    r16_assert_null(&p.source_data_presence, 0);
    assert_eq!(wire(vec![], Some(0), false, 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), false, 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_key_wrap_set_oaep_presence_matrix() {
    let wire = |x: Vec<u8>, x_null_len: Option<u64>, version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::KeyWrapSetOaepParams(v1_proto::KeyWrapSetOaepParams {
                bc: 0,
                x,
                x_null_len,
            }),
            version,
        )
    };
    fn set(mechanism: &CkMechanism) -> &KeyWrapSetOaepParams {
        match &mechanism.params {
            Some(CkMechanismParams::KeyWrapSetOaep(p)) => p,
            other => panic!("expected KeyWrapSetOaep, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), 1).unwrap();
    r16_assert_null(&set(&back).x_presence, 0);
    let back = wire(vec![], Some(8), 1).unwrap();
    r16_assert_null(&set(&back).x_presence, 8);
    let back = wire(vec![], None, 1).unwrap();
    r16_assert_present(&set(&back).x_presence, &[]);
    let back = wire(vec![0xCC; 8], None, 1).unwrap();
    let p = set(&back);
    r16_assert_present(&p.x_presence, &[0xCC; 8]);
    r16_assert_secret_eq(p.x_presence.as_present().unwrap(), &[0xCC; 8]);
    let back = wire(vec![], None, 0).unwrap();
    r16_assert_present(&set(&back).x_presence, &[]);
    assert_eq!(wire(vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_ecdh1_derive_presence_matrix() {
    let wire = |shared_data: Vec<u8>,
                shared_data_null_len: Option<u64>,
                public_data: Vec<u8>,
                public_data_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::Ecdh1DeriveParams(v1_proto::Ecdh1DeriveParams {
                kdf: 2,
                shared_data,
                public_data,
                shared_data_null_len,
                public_data_null_len,
            }),
            version,
        )
    };
    fn ecdh(mechanism: &CkMechanism) -> &Ecdh1DeriveParams {
        match &mechanism.params {
            Some(CkMechanismParams::Ecdh1Derive(p)) => p,
            other => panic!("expected Ecdh1Derive, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = ecdh(&back);
    r16_assert_null(&p.shared_data_presence, 0);
    r16_assert_null(&p.public_data_presence, 0);
    let back = wire(vec![], Some(6), vec![], Some(65), 1).unwrap();
    let p = ecdh(&back);
    r16_assert_null(&p.shared_data_presence, 6);
    r16_assert_null(&p.public_data_presence, 65);
    let back = wire(vec![], None, vec![], None, 1).unwrap();
    let p = ecdh(&back);
    r16_assert_present(&p.shared_data_presence, &[]);
    r16_assert_present(&p.public_data_presence, &[]);
    let back = wire(vec![1; 6], None, vec![2; 65], None, 1).unwrap();
    let p = ecdh(&back);
    r16_assert_present(&p.shared_data_presence, &[1; 6]);
    r16_assert_present(&p.public_data_presence, &[2; 65]);
    r16_assert_secret_eq(p.shared_data_presence.as_present().unwrap(), &[1; 6]);
    assert_eq!(p.public_data_presence, PointerBytes::present_copy(&[2; 65]));
    let back = wire(vec![], Some(6), vec![2; 65], None, 1).unwrap();
    let p = ecdh(&back);
    r16_assert_null(&p.shared_data_presence, 6);
    r16_assert_present(&p.public_data_presence, &[2; 65]);
    let back = wire(vec![1; 6], None, vec![], None, 0).unwrap();
    let p = ecdh(&back);
    r16_assert_present(&p.shared_data_presence, &[1; 6]);
    r16_assert_present(&p.public_data_presence, &[]);
    assert_eq!(wire(vec![], Some(0), vec![], None, 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), vec![], None, 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_ecdh2_derive_presence_matrix() {
    let wire = |shared_data: Vec<u8>,
                shared_data_null_len: Option<u64>,
                public_data: Vec<u8>,
                public_data_null_len: Option<u64>,
                public_data2: Vec<u8>,
                public_data2_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::Ecdh2DeriveParams(v1_proto::Ecdh2DeriveParams {
                kdf: 2,
                shared_data,
                public_data,
                private_data_len: 0,
                private_data_handle: 0,
                public_data2,
                shared_data_null_len,
                public_data_null_len,
                public_data2_null_len,
            }),
            version,
        )
    };
    fn ecdh(mechanism: &CkMechanism) -> &Ecdh2DeriveParams {
        match &mechanism.params {
            Some(CkMechanismParams::Ecdh2Derive(p)) => p,
            other => panic!("expected Ecdh2Derive, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = ecdh(&back);
    r16_assert_null(&p.shared_data_presence, 0);
    r16_assert_null(&p.public_data_presence, 0);
    r16_assert_null(&p.public_data2_presence, 0);
    let back = wire(vec![], Some(6), vec![], Some(65), vec![], Some(33), 1).unwrap();
    let p = ecdh(&back);
    r16_assert_null(&p.shared_data_presence, 6);
    r16_assert_null(&p.public_data_presence, 65);
    r16_assert_null(&p.public_data2_presence, 33);
    let back = wire(vec![], None, vec![], None, vec![], None, 1).unwrap();
    let p = ecdh(&back);
    r16_assert_present(&p.shared_data_presence, &[]);
    r16_assert_present(&p.public_data_presence, &[]);
    r16_assert_present(&p.public_data2_presence, &[]);
    let back = wire(vec![1; 6], None, vec![2; 65], None, vec![3; 33], None, 1).unwrap();
    let p = ecdh(&back);
    r16_assert_present(&p.shared_data_presence, &[1; 6]);
    r16_assert_present(&p.public_data_presence, &[2; 65]);
    r16_assert_present(&p.public_data2_presence, &[3; 33]);
    let back = wire(vec![], Some(6), vec![2; 65], None, vec![], Some(33), 1).unwrap();
    let p = ecdh(&back);
    r16_assert_null(&p.shared_data_presence, 6);
    r16_assert_present(&p.public_data_presence, &[2; 65]);
    r16_assert_null(&p.public_data2_presence, 33);
    let back = wire(vec![], None, vec![2; 65], None, vec![], None, 0).unwrap();
    let p = ecdh(&back);
    r16_assert_present(&p.shared_data_presence, &[]);
    r16_assert_present(&p.public_data_presence, &[2; 65]);
    r16_assert_present(&p.public_data2_presence, &[]);
    assert_eq!(
        wire(vec![], None, vec![], Some(0), vec![], None, 0),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
    assert_eq!(
        wire(vec![], None, vec![], None, vec![1], Some(1), 1),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
}

#[test]
fn r16_ecmqv_derive_presence_matrix() {
    let wire = |shared_data: Vec<u8>,
                shared_data_null_len: Option<u64>,
                public_data: Vec<u8>,
                public_data_null_len: Option<u64>,
                public_data2: Vec<u8>,
                public_data2_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::EcmqvDeriveParams(v1_proto::EcmqvDeriveParams {
                kdf: 2,
                shared_data,
                public_data,
                private_data_len: 0,
                private_data_handle: 0,
                public_data2,
                public_key_handle: 0,
                shared_data_null_len,
                public_data_null_len,
                public_data2_null_len,
            }),
            version,
        )
    };
    fn mqv(mechanism: &CkMechanism) -> &EcmqvDeriveParams {
        match &mechanism.params {
            Some(CkMechanismParams::EcmqvDerive(p)) => p,
            other => panic!("expected EcmqvDerive, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = mqv(&back);
    r16_assert_null(&p.shared_data_presence, 0);
    r16_assert_null(&p.public_data_presence, 0);
    r16_assert_null(&p.public_data2_presence, 0);
    let back = wire(vec![], Some(4), vec![], Some(65), vec![], Some(65), 1).unwrap();
    let p = mqv(&back);
    r16_assert_null(&p.shared_data_presence, 4);
    r16_assert_null(&p.public_data_presence, 65);
    r16_assert_null(&p.public_data2_presence, 65);
    let back = wire(vec![], None, vec![], None, vec![], None, 1).unwrap();
    let p = mqv(&back);
    r16_assert_present(&p.shared_data_presence, &[]);
    r16_assert_present(&p.public_data_presence, &[]);
    r16_assert_present(&p.public_data2_presence, &[]);
    let back = wire(vec![1; 4], None, vec![2; 65], None, vec![3; 65], None, 1).unwrap();
    let p = mqv(&back);
    r16_assert_present(&p.shared_data_presence, &[1; 4]);
    r16_assert_present(&p.public_data_presence, &[2; 65]);
    r16_assert_present(&p.public_data2_presence, &[3; 65]);
    let back = wire(vec![1; 4], None, vec![], Some(65), vec![3; 65], None, 1).unwrap();
    let p = mqv(&back);
    r16_assert_present(&p.shared_data_presence, &[1; 4]);
    r16_assert_null(&p.public_data_presence, 65);
    r16_assert_present(&p.public_data2_presence, &[3; 65]);
    let back = wire(vec![], None, vec![], None, vec![3; 65], None, 0).unwrap();
    r16_assert_present(&mqv(&back).public_data2_presence, &[3; 65]);
    assert_eq!(
        wire(vec![], None, vec![], None, vec![], Some(0), 0),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
    assert_eq!(
        wire(vec![1], Some(1), vec![], None, vec![], None, 1),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
}

#[test]
fn r16_x942_dh1_derive_presence_matrix() {
    let wire = |other_info: Vec<u8>,
                other_info_null_len: Option<u64>,
                public_data: Vec<u8>,
                public_data_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::X942Dh1DeriveParams(v1_proto::X942Dh1DeriveParams {
                kdf: 2,
                other_info,
                public_data,
                other_info_null_len,
                public_data_null_len,
            }),
            version,
        )
    };
    fn dh(mechanism: &CkMechanism) -> &X942Dh1DeriveParams {
        match &mechanism.params {
            Some(CkMechanismParams::X942Dh1Derive(p)) => p,
            other => panic!("expected X942Dh1Derive, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = dh(&back);
    r16_assert_null(&p.other_info_presence, 0);
    r16_assert_null(&p.public_data_presence, 0);
    let back = wire(vec![], Some(10), vec![], Some(128), 1).unwrap();
    let p = dh(&back);
    r16_assert_null(&p.other_info_presence, 10);
    r16_assert_null(&p.public_data_presence, 128);
    let back = wire(vec![], None, vec![], None, 1).unwrap();
    let p = dh(&back);
    r16_assert_present(&p.other_info_presence, &[]);
    r16_assert_present(&p.public_data_presence, &[]);
    let back = wire(vec![1; 10], None, vec![2; 128], None, 1).unwrap();
    let p = dh(&back);
    r16_assert_present(&p.other_info_presence, &[1; 10]);
    r16_assert_present(&p.public_data_presence, &[2; 128]);
    let back = wire(vec![1; 10], None, vec![], Some(128), 1).unwrap();
    let p = dh(&back);
    r16_assert_present(&p.other_info_presence, &[1; 10]);
    r16_assert_null(&p.public_data_presence, 128);
    let back = wire(vec![], None, vec![2; 128], None, 0).unwrap();
    let p = dh(&back);
    r16_assert_present(&p.other_info_presence, &[]);
    r16_assert_present(&p.public_data_presence, &[2; 128]);
    assert_eq!(wire(vec![], Some(0), vec![], None, 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![], None, vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_x942_dh2_derive_presence_matrix() {
    let wire = |other_info: Vec<u8>,
                other_info_null_len: Option<u64>,
                public_data: Vec<u8>,
                public_data_null_len: Option<u64>,
                public_data2: Vec<u8>,
                public_data2_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::X942Dh2DeriveParams(v1_proto::X942Dh2DeriveParams {
                kdf: 2,
                other_info,
                public_data,
                private_data_len: 0,
                private_data_handle: 0,
                public_data2,
                other_info_null_len,
                public_data_null_len,
                public_data2_null_len,
            }),
            version,
        )
    };
    fn dh(mechanism: &CkMechanism) -> &X942Dh2DeriveParams {
        match &mechanism.params {
            Some(CkMechanismParams::X942Dh2Derive(p)) => p,
            other => panic!("expected X942Dh2Derive, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = dh(&back);
    r16_assert_null(&p.other_info_presence, 0);
    r16_assert_null(&p.public_data_presence, 0);
    r16_assert_null(&p.public_data2_presence, 0);
    let back = wire(vec![], Some(10), vec![], Some(128), vec![], Some(64), 1).unwrap();
    let p = dh(&back);
    r16_assert_null(&p.other_info_presence, 10);
    r16_assert_null(&p.public_data_presence, 128);
    r16_assert_null(&p.public_data2_presence, 64);
    let back = wire(vec![], None, vec![], None, vec![], None, 1).unwrap();
    let p = dh(&back);
    r16_assert_present(&p.other_info_presence, &[]);
    r16_assert_present(&p.public_data_presence, &[]);
    r16_assert_present(&p.public_data2_presence, &[]);
    let back = wire(vec![1; 10], None, vec![2; 4], None, vec![3; 4], None, 1).unwrap();
    let p = dh(&back);
    r16_assert_present(&p.other_info_presence, &[1; 10]);
    r16_assert_present(&p.public_data_presence, &[2; 4]);
    r16_assert_present(&p.public_data2_presence, &[3; 4]);
    let back = wire(vec![], Some(10), vec![2; 4], None, vec![3; 4], None, 1).unwrap();
    let p = dh(&back);
    r16_assert_null(&p.other_info_presence, 10);
    r16_assert_present(&p.public_data_presence, &[2; 4]);
    r16_assert_present(&p.public_data2_presence, &[3; 4]);
    let back = wire(vec![], None, vec![], None, vec![], None, 0).unwrap();
    r16_assert_present(&dh(&back).public_data2_presence, &[]);
    assert_eq!(
        wire(vec![], None, vec![], Some(1), vec![], None, 0),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
    assert_eq!(
        wire(vec![1], Some(2), vec![], None, vec![], None, 1),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
}

#[test]
fn r16_x942_mqv_derive_presence_matrix() {
    let wire = |other_info: Vec<u8>,
                other_info_null_len: Option<u64>,
                public_data: Vec<u8>,
                public_data_null_len: Option<u64>,
                public_data2: Vec<u8>,
                public_data2_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::X942MqvDeriveParams(v1_proto::X942MqvDeriveParams {
                kdf: 2,
                other_info,
                public_data,
                private_data_len: 0,
                private_data_handle: 0,
                public_data2,
                public_key_handle: 0,
                other_info_null_len,
                public_data_null_len,
                public_data2_null_len,
            }),
            version,
        )
    };
    fn mqv(mechanism: &CkMechanism) -> &X942MqvDeriveParams {
        match &mechanism.params {
            Some(CkMechanismParams::X942MqvDerive(p)) => p,
            other => panic!("expected X942MqvDerive, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = mqv(&back);
    r16_assert_null(&p.other_info_presence, 0);
    r16_assert_null(&p.public_data_presence, 0);
    r16_assert_null(&p.public_data2_presence, 0);
    let back = wire(vec![], Some(3), vec![], Some(5), vec![], Some(7), 1).unwrap();
    let p = mqv(&back);
    r16_assert_null(&p.other_info_presence, 3);
    r16_assert_null(&p.public_data_presence, 5);
    r16_assert_null(&p.public_data2_presence, 7);
    let back = wire(vec![], None, vec![], None, vec![], None, 1).unwrap();
    let p = mqv(&back);
    r16_assert_present(&p.other_info_presence, &[]);
    r16_assert_present(&p.public_data_presence, &[]);
    r16_assert_present(&p.public_data2_presence, &[]);
    let back = wire(vec![1; 3], None, vec![2; 5], None, vec![3; 7], None, 1).unwrap();
    let p = mqv(&back);
    r16_assert_present(&p.other_info_presence, &[1; 3]);
    r16_assert_present(&p.public_data_presence, &[2; 5]);
    r16_assert_present(&p.public_data2_presence, &[3; 7]);
    let back = wire(vec![1; 3], None, vec![2; 5], None, vec![], Some(7), 1).unwrap();
    let p = mqv(&back);
    r16_assert_present(&p.other_info_presence, &[1; 3]);
    r16_assert_present(&p.public_data_presence, &[2; 5]);
    r16_assert_null(&p.public_data2_presence, 7);
    let back = wire(vec![1; 3], None, vec![], None, vec![], None, 0).unwrap();
    r16_assert_present(&mqv(&back).other_info_presence, &[1; 3]);
    assert_eq!(
        wire(vec![], None, vec![], None, vec![], Some(7), 0),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
    assert_eq!(
        wire(vec![], None, vec![1], Some(2), vec![], None, 1),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
}

#[test]
fn r16_hkdf_presence_matrix() {
    let wire = |salt: Vec<u8>,
                salt_null_len: Option<u64>,
                info: Vec<u8>,
                info_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::HkdfParams(v1_proto::HkdfParams {
                extract: true,
                expand: true,
                prf_hash_mechanism: 0x250,
                salt_type: 0,
                salt,
                salt_key_handle: 0,
                info,
                salt_null_len,
                info_null_len,
            }),
            version,
        )
    };
    fn hkdf(mechanism: &CkMechanism) -> &HkdfParams {
        match &mechanism.params {
            Some(CkMechanismParams::Hkdf(p)) => p,
            other => panic!("expected Hkdf, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = hkdf(&back);
    r16_assert_null(&p.salt_presence, 0);
    r16_assert_null(&p.info_presence, 0);
    let back = wire(vec![], Some(32), vec![], Some(11), 1).unwrap();
    let p = hkdf(&back);
    r16_assert_null(&p.salt_presence, 32);
    r16_assert_null(&p.info_presence, 11);
    let back = wire(vec![], None, vec![], None, 1).unwrap();
    let p = hkdf(&back);
    r16_assert_present(&p.salt_presence, &[]);
    r16_assert_present(&p.info_presence, &[]);
    let back = wire(vec![1; 32], None, vec![2; 11], None, 1).unwrap();
    let p = hkdf(&back);
    r16_assert_present(&p.salt_presence, &[1; 32]);
    r16_assert_present(&p.info_presence, &[2; 11]);
    r16_assert_secret_eq(p.salt_presence.as_present().unwrap(), &[1; 32]);
    r16_assert_secret_eq(p.info_presence.as_present().unwrap(), &[2; 11]);
    let back = wire(vec![], Some(32), vec![2; 11], None, 1).unwrap();
    let p = hkdf(&back);
    r16_assert_null(&p.salt_presence, 32);
    r16_assert_present(&p.info_presence, &[2; 11]);
    let back = wire(vec![], None, vec![], None, 0).unwrap();
    let p = hkdf(&back);
    r16_assert_present(&p.salt_presence, &[]);
    r16_assert_present(&p.info_presence, &[]);
    assert_eq!(wire(vec![], Some(0), vec![], None, 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![], None, vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_gostr3410_derive_presence_matrix() {
    let wire = |public_data: Vec<u8>,
                public_data_null_len: Option<u64>,
                ukm: Vec<u8>,
                ukm_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::Gostr3410DeriveParams(v1_proto::Gostr3410DeriveParams {
                kdf: 2,
                public_data,
                ukm,
                public_data_null_len,
                ukm_null_len,
            }),
            version,
        )
    };
    fn gost(mechanism: &CkMechanism) -> &Gostr3410DeriveParams {
        match &mechanism.params {
            Some(CkMechanismParams::Gostr3410Derive(p)) => p,
            other => panic!("expected Gostr3410Derive, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = gost(&back);
    r16_assert_null(&p.public_data_presence, 0);
    r16_assert_null(&p.ukm_presence, 0);
    let back = wire(vec![], Some(64), vec![], Some(8), 1).unwrap();
    let p = gost(&back);
    r16_assert_null(&p.public_data_presence, 64);
    r16_assert_null(&p.ukm_presence, 8);
    let back = wire(vec![], None, vec![], None, 1).unwrap();
    let p = gost(&back);
    r16_assert_present(&p.public_data_presence, &[]);
    r16_assert_present(&p.ukm_presence, &[]);
    let back = wire(vec![1; 64], None, vec![2; 8], None, 1).unwrap();
    let p = gost(&back);
    r16_assert_present(&p.public_data_presence, &[1; 64]);
    r16_assert_present(&p.ukm_presence, &[2; 8]);
    let back = wire(vec![1; 64], None, vec![], Some(8), 1).unwrap();
    let p = gost(&back);
    r16_assert_present(&p.public_data_presence, &[1; 64]);
    r16_assert_null(&p.ukm_presence, 8);
    let back = wire(vec![], None, vec![2; 8], None, 0).unwrap();
    let p = gost(&back);
    r16_assert_present(&p.public_data_presence, &[]);
    r16_assert_present(&p.ukm_presence, &[2; 8]);
    assert_eq!(wire(vec![], Some(0), vec![], None, 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), vec![], None, 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_gostr3410_key_wrap_presence_matrix() {
    let wire = |wrap_oid: Vec<u8>,
                wrap_oid_null_len: Option<u64>,
                ukm: Vec<u8>,
                ukm_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::Gostr3410KeyWrapParams(v1_proto::Gostr3410KeyWrapParams {
                wrap_oid,
                ukm,
                key_handle: 0,
                wrap_oid_null_len,
                ukm_null_len,
            }),
            version,
        )
    };
    fn wrap(mechanism: &CkMechanism) -> &Gostr3410KeyWrapParams {
        match &mechanism.params {
            Some(CkMechanismParams::Gostr3410KeyWrap(p)) => p,
            other => panic!("expected Gostr3410KeyWrap, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = wrap(&back);
    r16_assert_null(&p.wrap_oid_presence, 0);
    r16_assert_null(&p.ukm_presence, 0);
    let back = wire(vec![], Some(9), vec![], Some(8), 1).unwrap();
    let p = wrap(&back);
    r16_assert_null(&p.wrap_oid_presence, 9);
    r16_assert_null(&p.ukm_presence, 8);
    let back = wire(vec![], None, vec![], None, 1).unwrap();
    let p = wrap(&back);
    r16_assert_present(&p.wrap_oid_presence, &[]);
    r16_assert_present(&p.ukm_presence, &[]);
    let back = wire(vec![1; 9], None, vec![2; 8], None, 1).unwrap();
    let p = wrap(&back);
    r16_assert_present(&p.wrap_oid_presence, &[1; 9]);
    r16_assert_present(&p.ukm_presence, &[2; 8]);
    assert_eq!(p.wrap_oid_presence, PointerBytes::present_copy(&[1; 9]));
    assert_eq!(p.ukm_presence, PointerBytes::present_copy(&[2; 8]));
    let back = wire(vec![], Some(9), vec![2; 8], None, 1).unwrap();
    let p = wrap(&back);
    r16_assert_null(&p.wrap_oid_presence, 9);
    r16_assert_present(&p.ukm_presence, &[2; 8]);
    let back = wire(vec![1; 9], None, vec![], None, 0).unwrap();
    let p = wrap(&back);
    r16_assert_present(&p.wrap_oid_presence, &[1; 9]);
    r16_assert_present(&p.ukm_presence, &[]);
    assert_eq!(wire(vec![], None, vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![], None, vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

// The five CBC-encrypt-data shapes share one layout (fixed IV + `data`
// pointer); one matrix per message, asserting the fixed IV never gains
// presence (no `iv_null_len`: the IV is inline, never NULL).
#[test]
fn r16_aes_cbc_encrypt_data_presence_matrix() {
    let wire = |iv: Vec<u8>, data: Vec<u8>, data_null_len: Option<u64>, version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::AesCbcEncryptDataParams(
                v1_proto::AesCbcEncryptDataParams { iv, data, data_null_len },
            ),
            version,
        )
    };
    fn params(mechanism: &CkMechanism) -> &AesCbcEncryptDataParams {
        match &mechanism.params {
            Some(CkMechanismParams::AesCbcEncryptData(p)) => p,
            other => panic!("expected AesCbcEncryptData, got {other:?}"),
        }
    }
    let back = wire(vec![0x11; 16], vec![], Some(0), 1).unwrap();
    let p = params(&back);
    r16_assert_null(&p.data_presence, 0);
    assert_eq!(p.iv, vec![0x11; 16]);
    let back = wire(vec![0x11; 16], vec![], Some(24), 1).unwrap();
    r16_assert_null(&params(&back).data_presence, 24);
    let back = wire(vec![0x11; 16], vec![], None, 1).unwrap();
    r16_assert_present(&params(&back).data_presence, &[]);
    let back = wire(vec![0x11; 16], vec![0x22; 24], None, 1).unwrap();
    let p = params(&back);
    r16_assert_present(&p.data_presence, &[0x22; 24]);
    r16_assert_secret_eq(p.data_presence.as_present().unwrap(), &[0x22; 24]);
    let back = wire(vec![0x11; 16], vec![0x22; 24], None, 0).unwrap();
    r16_assert_present(&params(&back).data_presence, &[0x22; 24]);
    assert_eq!(wire(vec![0x11; 16], vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![0x11; 16], vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_des_cbc_encrypt_data_presence_matrix() {
    let wire = |iv: Vec<u8>, data: Vec<u8>, data_null_len: Option<u64>, version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::DesCbcEncryptDataParams(
                v1_proto::DesCbcEncryptDataParams { iv, data, data_null_len },
            ),
            version,
        )
    };
    fn params(mechanism: &CkMechanism) -> &DesCbcEncryptDataParams {
        match &mechanism.params {
            Some(CkMechanismParams::DesCbcEncryptData(p)) => p,
            other => panic!("expected DesCbcEncryptData, got {other:?}"),
        }
    }
    let back = wire(vec![0x11; 8], vec![], Some(0), 1).unwrap();
    r16_assert_null(&params(&back).data_presence, 0);
    let back = wire(vec![0x11; 8], vec![], Some(16), 1).unwrap();
    r16_assert_null(&params(&back).data_presence, 16);
    let back = wire(vec![0x11; 8], vec![], None, 1).unwrap();
    r16_assert_present(&params(&back).data_presence, &[]);
    let back = wire(vec![0x11; 8], vec![0x22; 16], None, 1).unwrap();
    r16_assert_present(&params(&back).data_presence, &[0x22; 16]);
    let back = wire(vec![0x11; 8], vec![], None, 0).unwrap();
    r16_assert_present(&params(&back).data_presence, &[]);
    assert_eq!(wire(vec![0x11; 8], vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![0x11; 8], vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_aria_cbc_encrypt_data_presence_matrix() {
    let wire = |iv: Vec<u8>, data: Vec<u8>, data_null_len: Option<u64>, version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::AriaCbcEncryptDataParams(
                v1_proto::AriaCbcEncryptDataParams { iv, data, data_null_len },
            ),
            version,
        )
    };
    fn params(mechanism: &CkMechanism) -> &AriaCbcEncryptDataParams {
        match &mechanism.params {
            Some(CkMechanismParams::AriaCbcEncryptData(p)) => p,
            other => panic!("expected AriaCbcEncryptData, got {other:?}"),
        }
    }
    let back = wire(vec![0x11; 16], vec![], Some(0), 1).unwrap();
    r16_assert_null(&params(&back).data_presence, 0);
    let back = wire(vec![0x11; 16], vec![], Some(16), 1).unwrap();
    r16_assert_null(&params(&back).data_presence, 16);
    let back = wire(vec![0x11; 16], vec![], None, 1).unwrap();
    r16_assert_present(&params(&back).data_presence, &[]);
    let back = wire(vec![0x11; 16], vec![0x22; 16], None, 1).unwrap();
    r16_assert_present(&params(&back).data_presence, &[0x22; 16]);
    let back = wire(vec![0x11; 16], vec![0x22; 16], None, 0).unwrap();
    r16_assert_present(&params(&back).data_presence, &[0x22; 16]);
    assert_eq!(wire(vec![0x11; 16], vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![0x11; 16], vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_camellia_cbc_encrypt_data_presence_matrix() {
    let wire = |iv: Vec<u8>, data: Vec<u8>, data_null_len: Option<u64>, version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::CamelliaCbcEncryptDataParams(
                v1_proto::CamelliaCbcEncryptDataParams { iv, data, data_null_len },
            ),
            version,
        )
    };
    fn params(mechanism: &CkMechanism) -> &CamelliaCbcEncryptDataParams {
        match &mechanism.params {
            Some(CkMechanismParams::CamelliaCbcEncryptData(p)) => p,
            other => panic!("expected CamelliaCbcEncryptData, got {other:?}"),
        }
    }
    let back = wire(vec![0x11; 16], vec![], Some(0), 1).unwrap();
    r16_assert_null(&params(&back).data_presence, 0);
    let back = wire(vec![0x11; 16], vec![], Some(16), 1).unwrap();
    r16_assert_null(&params(&back).data_presence, 16);
    let back = wire(vec![0x11; 16], vec![], None, 1).unwrap();
    r16_assert_present(&params(&back).data_presence, &[]);
    let back = wire(vec![0x11; 16], vec![0x22; 16], None, 1).unwrap();
    r16_assert_present(&params(&back).data_presence, &[0x22; 16]);
    let back = wire(vec![0x11; 16], vec![], None, 0).unwrap();
    r16_assert_present(&params(&back).data_presence, &[]);
    assert_eq!(wire(vec![0x11; 16], vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![0x11; 16], vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_seed_cbc_encrypt_data_presence_matrix() {
    let wire = |iv: Vec<u8>, data: Vec<u8>, data_null_len: Option<u64>, version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::SeedCbcEncryptDataParams(
                v1_proto::SeedCbcEncryptDataParams { iv, data, data_null_len },
            ),
            version,
        )
    };
    fn params(mechanism: &CkMechanism) -> &SeedCbcEncryptDataParams {
        match &mechanism.params {
            Some(CkMechanismParams::SeedCbcEncryptData(p)) => p,
            other => panic!("expected SeedCbcEncryptData, got {other:?}"),
        }
    }
    let back = wire(vec![0x11; 16], vec![], Some(0), 1).unwrap();
    r16_assert_null(&params(&back).data_presence, 0);
    let back = wire(vec![0x11; 16], vec![], Some(16), 1).unwrap();
    r16_assert_null(&params(&back).data_presence, 16);
    let back = wire(vec![0x11; 16], vec![], None, 1).unwrap();
    r16_assert_present(&params(&back).data_presence, &[]);
    let back = wire(vec![0x11; 16], vec![0x22; 16], None, 1).unwrap();
    r16_assert_present(&params(&back).data_presence, &[0x22; 16]);
    let back = wire(vec![0x11; 16], vec![0x22; 16], None, 0).unwrap();
    r16_assert_present(&params(&back).data_presence, &[0x22; 16]);
    assert_eq!(wire(vec![0x11; 16], vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![0x11; 16], vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_rc5_cbc_presence_matrix() {
    // Unlike the fixed-IV CBC shapes, RC5's IV is a variable-length
    // pointer — it carries presence.
    let wire = |iv: Vec<u8>, iv_null_len: Option<u64>, version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::Rc5CbcParams(v1_proto::Rc5CbcParams {
                word_size: 4,
                rounds: 12,
                iv,
                iv_null_len,
            }),
            version,
        )
    };
    fn rc5(mechanism: &CkMechanism) -> &Rc5CbcParams {
        match &mechanism.params {
            Some(CkMechanismParams::Rc5Cbc(p)) => p,
            other => panic!("expected Rc5Cbc, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), 1).unwrap();
    r16_assert_null(&rc5(&back).iv_presence, 0);
    let back = wire(vec![], Some(8), 1).unwrap();
    r16_assert_null(&rc5(&back).iv_presence, 8);
    let back = wire(vec![], None, 1).unwrap();
    r16_assert_present(&rc5(&back).iv_presence, &[]);
    let back = wire(vec![0x1B; 8], None, 1).unwrap();
    let p = rc5(&back);
    r16_assert_present(&p.iv_presence, &[0x1B; 8]);
    assert_eq!(p.iv_presence, PointerBytes::present_copy(&[0x1B; 8]));
    let back = wire(vec![], None, 0).unwrap();
    r16_assert_present(&rc5(&back).iv_presence, &[]);
    assert_eq!(wire(vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_chacha20_presence_matrix() {
    let wire = |block_counter: Vec<u8>,
                block_counter_null_len: Option<u64>,
                nonce: Vec<u8>,
                nonce_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::Chacha20Params(v1_proto::ChaCha20Params {
                block_counter,
                block_counter_bits: 64,
                nonce,
                nonce_bits: 96,
                block_counter_null_len,
                nonce_null_len,
            }),
            version,
        )
    };
    fn chacha(mechanism: &CkMechanism) -> &ChaCha20Params {
        match &mechanism.params {
            Some(CkMechanismParams::ChaCha20(p)) => p,
            other => panic!("expected ChaCha20, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = chacha(&back);
    r16_assert_null(&p.block_counter_presence, 0);
    r16_assert_null(&p.nonce_presence, 0);
    let back = wire(vec![], Some(8), vec![], Some(12), 1).unwrap();
    let p = chacha(&back);
    r16_assert_null(&p.block_counter_presence, 8);
    r16_assert_null(&p.nonce_presence, 12);
    let back = wire(vec![], None, vec![], None, 1).unwrap();
    let p = chacha(&back);
    r16_assert_present(&p.block_counter_presence, &[]);
    r16_assert_present(&p.nonce_presence, &[]);
    let back = wire(vec![1; 8], None, vec![2; 12], None, 1).unwrap();
    let p = chacha(&back);
    r16_assert_present(&p.block_counter_presence, &[1; 8]);
    r16_assert_present(&p.nonce_presence, &[2; 12]);
    let back = wire(vec![1; 8], None, vec![], Some(12), 1).unwrap();
    let p = chacha(&back);
    r16_assert_present(&p.block_counter_presence, &[1; 8]);
    r16_assert_null(&p.nonce_presence, 12);
    let back = wire(vec![], None, vec![2; 12], None, 0).unwrap();
    let p = chacha(&back);
    r16_assert_present(&p.block_counter_presence, &[]);
    r16_assert_present(&p.nonce_presence, &[2; 12]);
    assert_eq!(wire(vec![], Some(0), vec![], None, 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![], None, vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_salsa20_presence_matrix() {
    let wire = |block_counter: Vec<u8>,
                block_counter_null_len: Option<u64>,
                nonce: Vec<u8>,
                nonce_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::Salsa20Params(v1_proto::Salsa20Params {
                block_counter,
                nonce,
                nonce_bits: 64,
                block_counter_null_len,
                nonce_null_len,
            }),
            version,
        )
    };
    fn salsa(mechanism: &CkMechanism) -> &Salsa20Params {
        match &mechanism.params {
            Some(CkMechanismParams::Salsa20(p)) => p,
            other => panic!("expected Salsa20, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = salsa(&back);
    r16_assert_null(&p.block_counter_presence, 0);
    r16_assert_null(&p.nonce_presence, 0);
    let back = wire(vec![], Some(8), vec![], Some(8), 1).unwrap();
    let p = salsa(&back);
    r16_assert_null(&p.block_counter_presence, 8);
    r16_assert_null(&p.nonce_presence, 8);
    let back = wire(vec![], None, vec![], None, 1).unwrap();
    let p = salsa(&back);
    r16_assert_present(&p.block_counter_presence, &[]);
    r16_assert_present(&p.nonce_presence, &[]);
    let back = wire(vec![1; 8], None, vec![2; 8], None, 1).unwrap();
    let p = salsa(&back);
    r16_assert_present(&p.block_counter_presence, &[1; 8]);
    r16_assert_present(&p.nonce_presence, &[2; 8]);
    let back = wire(vec![], Some(8), vec![2; 8], None, 1).unwrap();
    let p = salsa(&back);
    r16_assert_null(&p.block_counter_presence, 8);
    r16_assert_present(&p.nonce_presence, &[2; 8]);
    let back = wire(vec![1; 8], None, vec![], None, 0).unwrap();
    let p = salsa(&back);
    r16_assert_present(&p.block_counter_presence, &[1; 8]);
    r16_assert_present(&p.nonce_presence, &[]);
    assert_eq!(wire(vec![], None, vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), vec![], None, 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_salsa20_chacha20_poly1305_presence_matrix() {
    let wire = |nonce: Vec<u8>,
                nonce_null_len: Option<u64>,
                aad: Vec<u8>,
                aad_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::Salsa20Chacha20Poly1305Params(
                v1_proto::Salsa20ChaCha20Poly1305Params {
                    nonce,
                    aad,
                    nonce_null_len,
                    aad_null_len,
                },
            ),
            version,
        )
    };
    fn aead(mechanism: &CkMechanism) -> &Salsa20ChaCha20Poly1305Params {
        match &mechanism.params {
            Some(CkMechanismParams::Salsa20ChaCha20Poly1305(p)) => p,
            other => panic!("expected Salsa20ChaCha20Poly1305, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = aead(&back);
    r16_assert_null(&p.nonce_presence, 0);
    r16_assert_null(&p.aad_presence, 0);
    let back = wire(vec![], Some(12), vec![], Some(5), 1).unwrap();
    let p = aead(&back);
    r16_assert_null(&p.nonce_presence, 12);
    r16_assert_null(&p.aad_presence, 5);
    let back = wire(vec![], None, vec![], None, 1).unwrap();
    let p = aead(&back);
    r16_assert_present(&p.nonce_presence, &[]);
    r16_assert_present(&p.aad_presence, &[]);
    let back = wire(vec![1; 12], None, vec![2; 5], None, 1).unwrap();
    let p = aead(&back);
    r16_assert_present(&p.nonce_presence, &[1; 12]);
    r16_assert_present(&p.aad_presence, &[2; 5]);
    let back = wire(vec![1; 12], None, vec![], Some(5), 1).unwrap();
    let p = aead(&back);
    r16_assert_present(&p.nonce_presence, &[1; 12]);
    r16_assert_null(&p.aad_presence, 5);
    let back = wire(vec![], None, vec![2; 5], None, 0).unwrap();
    let p = aead(&back);
    r16_assert_present(&p.nonce_presence, &[]);
    r16_assert_present(&p.aad_presence, &[2; 5]);
    assert_eq!(wire(vec![], Some(0), vec![], None, 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![], None, vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_pkcs5_pbkd2_presence_matrix() {
    let wire = |salt_source_data: Vec<u8>,
                salt_source_data_null_len: Option<u64>,
                prf_data: Vec<u8>,
                prf_data_null_len: Option<u64>,
                password: Vec<u8>,
                password_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::Pkcs5Pbkd2Params(v1_proto::Pkcs5Pbkd2Params {
                salt_source: 1,
                salt_source_data,
                iterations: 1000,
                prf: 1,
                prf_data,
                password,
                salt_source_data_null_len,
                prf_data_null_len,
                password_null_len,
            }),
            version,
        )
    };
    fn pbkd2(mechanism: &CkMechanism) -> &Pkcs5Pbkd2Params {
        match &mechanism.params {
            Some(CkMechanismParams::Pkcs5Pbkd2(p)) => p,
            other => panic!("expected Pkcs5Pbkd2, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = pbkd2(&back);
    r16_assert_null(&p.salt_source_data_presence, 0);
    r16_assert_null(&p.prf_data_presence, 0);
    r16_assert_null(&p.password_presence, 0);
    let back = wire(vec![], Some(8), vec![], Some(4), vec![], Some(6), 1).unwrap();
    let p = pbkd2(&back);
    r16_assert_null(&p.salt_source_data_presence, 8);
    r16_assert_null(&p.prf_data_presence, 4);
    r16_assert_null(&p.password_presence, 6);
    let back = wire(vec![], None, vec![], None, vec![], None, 1).unwrap();
    let p = pbkd2(&back);
    r16_assert_present(&p.salt_source_data_presence, &[]);
    r16_assert_present(&p.prf_data_presence, &[]);
    r16_assert_present(&p.password_presence, &[]);
    let back = wire(vec![1; 8], None, vec![2; 4], None, vec![3; 6], None, 1).unwrap();
    let p = pbkd2(&back);
    r16_assert_present(&p.salt_source_data_presence, &[1; 8]);
    r16_assert_present(&p.prf_data_presence, &[2; 4]);
    r16_assert_present(&p.password_presence, &[3; 6]);
    r16_assert_secret_eq(p.password_presence.as_present().unwrap(), &[3; 6]);
    let back = wire(vec![1; 8], None, vec![], Some(4), vec![3; 6], None, 1).unwrap();
    let p = pbkd2(&back);
    r16_assert_present(&p.salt_source_data_presence, &[1; 8]);
    r16_assert_null(&p.prf_data_presence, 4);
    r16_assert_present(&p.password_presence, &[3; 6]);
    let back = wire(vec![], None, vec![], None, vec![3; 6], None, 0).unwrap();
    let p = pbkd2(&back);
    r16_assert_present(&p.salt_source_data_presence, &[]);
    r16_assert_present(&p.password_presence, &[3; 6]);
    assert_eq!(
        wire(vec![], None, vec![], None, vec![], Some(0), 0),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
    assert_eq!(
        wire(vec![], None, vec![1], Some(1), vec![], None, 1),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
}

#[test]
fn r16_pbe_presence_matrix() {
    let wire = |init_vector: Vec<u8>,
                init_vector_null_len: Option<u64>,
                password: Vec<u8>,
                password_null_len: Option<u64>,
                salt: Vec<u8>,
                salt_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::PbeParams(v1_proto::PbeParams {
                init_vector,
                password,
                salt,
                iteration: 1000,
                init_vector_null_len,
                password_null_len,
                salt_null_len,
            }),
            version,
        )
    };
    fn pbe(mechanism: &CkMechanism) -> &PbeParams {
        match &mechanism.params {
            Some(CkMechanismParams::Pbe(p)) => p,
            other => panic!("expected Pbe, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = pbe(&back);
    r16_assert_null(&p.init_vector_presence, 0);
    r16_assert_null(&p.password_presence, 0);
    r16_assert_null(&p.salt_presence, 0);
    let back = wire(vec![], Some(8), vec![], Some(6), vec![], Some(4), 1).unwrap();
    let p = pbe(&back);
    r16_assert_null(&p.init_vector_presence, 8);
    r16_assert_null(&p.password_presence, 6);
    r16_assert_null(&p.salt_presence, 4);
    let back = wire(vec![], None, vec![], None, vec![], None, 1).unwrap();
    let p = pbe(&back);
    r16_assert_present(&p.init_vector_presence, &[]);
    r16_assert_present(&p.password_presence, &[]);
    r16_assert_present(&p.salt_presence, &[]);
    let back = wire(vec![1; 8], None, vec![2; 6], None, vec![3; 4], None, 1).unwrap();
    let p = pbe(&back);
    r16_assert_present(&p.init_vector_presence, &[1; 8]);
    r16_assert_present(&p.password_presence, &[2; 6]);
    r16_assert_present(&p.salt_presence, &[3; 4]);
    r16_assert_secret_eq(p.password_presence.as_present().unwrap(), &[2; 6]);
    let back = wire(vec![1; 8], None, vec![], Some(6), vec![3; 4], None, 1).unwrap();
    let p = pbe(&back);
    r16_assert_present(&p.init_vector_presence, &[1; 8]);
    r16_assert_null(&p.password_presence, 6);
    r16_assert_present(&p.salt_presence, &[3; 4]);
    let back = wire(vec![1; 8], None, vec![2; 6], None, vec![], None, 0).unwrap();
    let p = pbe(&back);
    r16_assert_present(&p.init_vector_presence, &[1; 8]);
    r16_assert_present(&p.password_presence, &[2; 6]);
    r16_assert_present(&p.salt_presence, &[]);
    assert_eq!(
        wire(vec![], Some(0), vec![], None, vec![], None, 0),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
    assert_eq!(
        wire(vec![], None, vec![], None, vec![1], Some(1), 1),
        Err(CkRv::MECHANISM_PARAM_INVALID)
    );
}

#[test]
fn r16_ike_prf_derive_presence_matrix() {
    let wire = |ni: Vec<u8>,
                ni_null_len: Option<u64>,
                nr: Vec<u8>,
                nr_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::IkePrfDeriveParams(v1_proto::IkePrfDeriveParams {
                prf_mechanism: 0x250,
                data_as_key: false,
                rekey: false,
                ni,
                nr,
                new_key_handle: 0,
                ni_null_len,
                nr_null_len,
            }),
            version,
        )
    };
    fn ike(mechanism: &CkMechanism) -> &IkePrfDeriveParams {
        match &mechanism.params {
            Some(CkMechanismParams::IkePrfDerive(p)) => p,
            other => panic!("expected IkePrfDerive, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = ike(&back);
    r16_assert_null(&p.ni_presence, 0);
    r16_assert_null(&p.nr_presence, 0);
    let back = wire(vec![], Some(18), vec![], Some(22), 1).unwrap();
    let p = ike(&back);
    r16_assert_null(&p.ni_presence, 18);
    r16_assert_null(&p.nr_presence, 22);
    let back = wire(vec![], None, vec![], None, 1).unwrap();
    let p = ike(&back);
    r16_assert_present(&p.ni_presence, &[]);
    r16_assert_present(&p.nr_presence, &[]);
    let back = wire(vec![1; 18], None, vec![2; 22], None, 1).unwrap();
    let p = ike(&back);
    r16_assert_present(&p.ni_presence, &[1; 18]);
    r16_assert_present(&p.nr_presence, &[2; 22]);
    let back = wire(vec![1; 18], None, vec![], Some(22), 1).unwrap();
    let p = ike(&back);
    r16_assert_present(&p.ni_presence, &[1; 18]);
    r16_assert_null(&p.nr_presence, 22);
    let back = wire(vec![], None, vec![2; 22], None, 0).unwrap();
    let p = ike(&back);
    r16_assert_present(&p.ni_presence, &[]);
    r16_assert_present(&p.nr_presence, &[2; 22]);
    assert_eq!(wire(vec![], Some(0), vec![], None, 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), vec![], None, 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_ike1_prf_derive_presence_matrix() {
    let wire = |ckyi: Vec<u8>,
                ckyi_null_len: Option<u64>,
                ckyr: Vec<u8>,
                ckyr_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::Ike1PrfDeriveParams(v1_proto::Ike1PrfDeriveParams {
                prf_mechanism: 0x250,
                has_prev_key: false,
                keygxy_handle: 0,
                prev_key_handle: 0,
                ckyi,
                ckyr,
                key_number: 0,
                ckyi_null_len,
                ckyr_null_len,
            }),
            version,
        )
    };
    fn ike(mechanism: &CkMechanism) -> &Ike1PrfDeriveParams {
        match &mechanism.params {
            Some(CkMechanismParams::Ike1PrfDerive(p)) => p,
            other => panic!("expected Ike1PrfDerive, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = ike(&back);
    r16_assert_null(&p.ckyi_presence, 0);
    r16_assert_null(&p.ckyr_presence, 0);
    let back = wire(vec![], Some(8), vec![], Some(8), 1).unwrap();
    let p = ike(&back);
    r16_assert_null(&p.ckyi_presence, 8);
    r16_assert_null(&p.ckyr_presence, 8);
    let back = wire(vec![], None, vec![], None, 1).unwrap();
    let p = ike(&back);
    r16_assert_present(&p.ckyi_presence, &[]);
    r16_assert_present(&p.ckyr_presence, &[]);
    let back = wire(vec![1; 8], None, vec![2; 8], None, 1).unwrap();
    let p = ike(&back);
    r16_assert_present(&p.ckyi_presence, &[1; 8]);
    r16_assert_present(&p.ckyr_presence, &[2; 8]);
    let back = wire(vec![], Some(8), vec![2; 8], None, 1).unwrap();
    let p = ike(&back);
    r16_assert_null(&p.ckyi_presence, 8);
    r16_assert_present(&p.ckyr_presence, &[2; 8]);
    let back = wire(vec![1; 8], None, vec![], None, 0).unwrap();
    let p = ike(&back);
    r16_assert_present(&p.ckyi_presence, &[1; 8]);
    r16_assert_present(&p.ckyr_presence, &[]);
    assert_eq!(wire(vec![], None, vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![], None, vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_ike1_extended_derive_presence_matrix() {
    let wire = |extra_data: Vec<u8>, extra_data_null_len: Option<u64>, version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::Ike1ExtendedDeriveParams(
                v1_proto::Ike1ExtendedDeriveParams {
                    prf_mechanism: 0x250,
                    has_keygxy: false,
                    keygxy_handle: 0,
                    extra_data,
                    extra_data_null_len,
                },
            ),
            version,
        )
    };
    fn ike(mechanism: &CkMechanism) -> &Ike1ExtendedDeriveParams {
        match &mechanism.params {
            Some(CkMechanismParams::Ike1ExtendedDerive(p)) => p,
            other => panic!("expected Ike1ExtendedDerive, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), 1).unwrap();
    r16_assert_null(&ike(&back).extra_data_presence, 0);
    let back = wire(vec![], Some(15), 1).unwrap();
    r16_assert_null(&ike(&back).extra_data_presence, 15);
    let back = wire(vec![], None, 1).unwrap();
    r16_assert_present(&ike(&back).extra_data_presence, &[]);
    let back = wire(vec![0xD1; 15], None, 1).unwrap();
    let p = ike(&back);
    r16_assert_present(&p.extra_data_presence, &[0xD1; 15]);
    r16_assert_secret_eq(p.extra_data_presence.as_present().unwrap(), &[0xD1; 15]);
    let back = wire(vec![], None, 0).unwrap();
    r16_assert_present(&ike(&back).extra_data_presence, &[]);
    assert_eq!(wire(vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_ike2_prf_plus_derive_presence_matrix() {
    let wire = |seed_data: Vec<u8>, seed_data_null_len: Option<u64>, version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::Ike2PrfPlusDeriveParams(
                v1_proto::Ike2PrfPlusDeriveParams {
                    prf_mechanism: 0x250,
                    has_seed_key: false,
                    seed_key_handle: 0,
                    seed_data,
                    seed_data_null_len,
                },
            ),
            version,
        )
    };
    fn ike(mechanism: &CkMechanism) -> &Ike2PrfPlusDeriveParams {
        match &mechanism.params {
            Some(CkMechanismParams::Ike2PrfPlusDerive(p)) => p,
            other => panic!("expected Ike2PrfPlusDerive, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), 1).unwrap();
    r16_assert_null(&ike(&back).seed_data_presence, 0);
    let back = wire(vec![], Some(21), 1).unwrap();
    r16_assert_null(&ike(&back).seed_data_presence, 21);
    let back = wire(vec![], None, 1).unwrap();
    r16_assert_present(&ike(&back).seed_data_presence, &[]);
    let back = wire(vec![0xE2; 21], None, 1).unwrap();
    let p = ike(&back);
    r16_assert_present(&p.seed_data_presence, &[0xE2; 21]);
    r16_assert_secret_eq(p.seed_data_presence.as_present().unwrap(), &[0xE2; 21]);
    let back = wire(vec![0xE2; 21], None, 0).unwrap();
    r16_assert_present(&ike(&back).seed_data_presence, &[0xE2; 21]);
    assert_eq!(wire(vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_key_derivation_string_presence_matrix() {
    let wire = |data: Vec<u8>, data_null_len: Option<u64>, version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::KeyDerivationStringData(
                v1_proto::KeyDerivationStringData { data, data_null_len },
            ),
            version,
        )
    };
    fn kdf(mechanism: &CkMechanism) -> &KeyDerivationStringData {
        match &mechanism.params {
            Some(CkMechanismParams::KeyDerivationString(p)) => p,
            other => panic!("expected KeyDerivationString, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), 1).unwrap();
    r16_assert_null(&kdf(&back).data_presence, 0);
    let back = wire(vec![], Some(13), 1).unwrap();
    r16_assert_null(&kdf(&back).data_presence, 13);
    let back = wire(vec![], None, 1).unwrap();
    r16_assert_present(&kdf(&back).data_presence, &[]);
    let back = wire(vec![0xF1; 13], None, 1).unwrap();
    let p = kdf(&back);
    r16_assert_present(&p.data_presence, &[0xF1; 13]);
    r16_assert_secret_eq(p.data_presence.as_present().unwrap(), &[0xF1; 13]);
    let back = wire(vec![], None, 0).unwrap();
    r16_assert_present(&kdf(&back).data_presence, &[]);
    assert_eq!(wire(vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_kmac_presence_matrix() {
    let wire = |customization_string: Vec<u8>,
                customization_string_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::KmacParams(v1_proto::KmacParams {
                key_handle: 0,
                mac_length: 32,
                customization_string,
                customization_string_null_len,
            }),
            version,
        )
    };
    fn kmac(mechanism: &CkMechanism) -> &KmacParams {
        match &mechanism.params {
            Some(CkMechanismParams::Kmac(p)) => p,
            other => panic!("expected Kmac, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), 1).unwrap();
    r16_assert_null(&kmac(&back).customization_string_presence, 0);
    let back = wire(vec![], Some(6), 1).unwrap();
    r16_assert_null(&kmac(&back).customization_string_presence, 6);
    let back = wire(vec![], None, 1).unwrap();
    r16_assert_present(&kmac(&back).customization_string_presence, &[]);
    let back = wire(b"custom".to_vec(), None, 1).unwrap();
    let p = kmac(&back);
    r16_assert_present(&p.customization_string_presence, b"custom");
    r16_assert_secret_eq(p.customization_string_presence.as_present().unwrap(), b"custom");
    let back = wire(vec![], None, 0).unwrap();
    r16_assert_present(&kmac(&back).customization_string_presence, &[]);
    assert_eq!(wire(vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_ecdh_aes_key_wrap_presence_matrix() {
    let wire = |shared_data: Vec<u8>, shared_data_null_len: Option<u64>, version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::EcdhAesKeyWrapParams(v1_proto::EcdhAesKeyWrapParams {
                aes_key_bits: 256,
                kdf: 2,
                shared_data,
                shared_data_null_len,
            }),
            version,
        )
    };
    fn wrap(mechanism: &CkMechanism) -> &EcdhAesKeyWrapParams {
        match &mechanism.params {
            Some(CkMechanismParams::EcdhAesKeyWrap(p)) => p,
            other => panic!("expected EcdhAesKeyWrap, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), 1).unwrap();
    r16_assert_null(&wrap(&back).shared_data_presence, 0);
    let back = wire(vec![], Some(12), 1).unwrap();
    r16_assert_null(&wrap(&back).shared_data_presence, 12);
    let back = wire(vec![], None, 1).unwrap();
    r16_assert_present(&wrap(&back).shared_data_presence, &[]);
    let back = wire(vec![0xA1; 12], None, 1).unwrap();
    let p = wrap(&back);
    r16_assert_present(&p.shared_data_presence, &[0xA1; 12]);
    r16_assert_secret_eq(p.shared_data_presence.as_present().unwrap(), &[0xA1; 12]);
    let back = wire(vec![0xA1; 12], None, 0).unwrap();
    r16_assert_present(&wrap(&back).shared_data_presence, &[0xA1; 12]);
    assert_eq!(wire(vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_rsa_aes_key_wrap_nested_oaep_presence_matrix() {
    // No direct byte buffer: presence rides the nested OAEP envelope,
    // decoded with the outer wire version.
    let wire = |source_data: Vec<u8>,
                source_data_null_len: Option<u64>,
                source_null: bool,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::RsaAesKeyWrapParams(v1_proto::RsaAesKeyWrapParams {
                aes_key_bits: 256,
                oaep_params: Some(v1_proto::RsaPkcsOaepParams {
                    hash_alg: 0x250,
                    mgf: 1,
                    source: 1,
                    source_data,
                    source_null,
                    source_data_null_len,
                }),
            }),
            version,
        )
    };
    fn wrap(mechanism: &CkMechanism) -> &RsaAesKeyWrapParams {
        match &mechanism.params {
            Some(CkMechanismParams::RsaAesKeyWrap(p)) => p,
            other => panic!("expected RsaAesKeyWrap, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), false, 1).unwrap();
    r16_assert_null(&wrap(&back).oaep_params.source_data_presence, 0);
    let back = wire(vec![], Some(20), false, 1).unwrap();
    r16_assert_null(&wrap(&back).oaep_params.source_data_presence, 20);
    let back = wire(vec![], None, false, 1).unwrap();
    r16_assert_present(&wrap(&back).oaep_params.source_data_presence, &[]);
    let back = wire(vec![0xBB; 20], None, false, 1).unwrap();
    let p = wrap(&back);
    r16_assert_present(&p.oaep_params.source_data_presence, &[0xBB; 20]);
    r16_assert_secret_eq(p.oaep_params.source_data_presence.as_present().unwrap(), &[0xBB; 20]);
    assert_eq!(wire(vec![], None, true, 1), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), false, 1), Err(CkRv::MECHANISM_PARAM_INVALID));
    let back = wire(vec![], None, true, 0).unwrap();
    let p = wrap(&back);
    assert!(p.oaep_params.source_data_presence.is_null());
    r16_assert_null(&p.oaep_params.source_data_presence, 0);
    assert_eq!(wire(vec![], Some(0), false, 0), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_mu_gen_presence_matrix() {
    let wire = |tr: Vec<u8>,
                tr_null_len: Option<u64>,
                context: Vec<u8>,
                context_null_len: Option<u64>,
                version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::MuGenParams(v1_proto::MuGenParams {
                key_handle: 0,
                tr,
                context,
                tr_null_len,
                context_null_len,
            }),
            version,
        )
    };
    fn mu(mechanism: &CkMechanism) -> &MuGenParams {
        match &mechanism.params {
            Some(CkMechanismParams::MuGen(p)) => p,
            other => panic!("expected MuGen, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), vec![], Some(0), 1).unwrap();
    let p = mu(&back);
    r16_assert_null(&p.tr_presence, 0);
    r16_assert_null(&p.context_presence, 0);
    let back = wire(vec![], Some(64), vec![], Some(10), 1).unwrap();
    let p = mu(&back);
    r16_assert_null(&p.tr_presence, 64);
    r16_assert_null(&p.context_presence, 10);
    let back = wire(vec![], None, vec![], None, 1).unwrap();
    let p = mu(&back);
    r16_assert_present(&p.tr_presence, &[]);
    r16_assert_present(&p.context_presence, &[]);
    let back = wire(vec![1; 64], None, vec![2; 10], None, 1).unwrap();
    let p = mu(&back);
    r16_assert_present(&p.tr_presence, &[1; 64]);
    r16_assert_present(&p.context_presence, &[2; 10]);
    let back = wire(vec![], Some(64), vec![2; 10], None, 1).unwrap();
    let p = mu(&back);
    r16_assert_null(&p.tr_presence, 64);
    r16_assert_present(&p.context_presence, &[2; 10]);
    let back = wire(vec![], None, vec![], None, 0).unwrap();
    let p = mu(&back);
    r16_assert_present(&p.tr_presence, &[]);
    r16_assert_present(&p.context_presence, &[]);
    assert_eq!(wire(vec![], Some(0), vec![], None, 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![], None, vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn r16_sign_additional_context_presence_matrix() {
    let wire = |context: Vec<u8>, context_null_len: Option<u64>, version: u32| {
        r16_decode(
            v1_proto::mechanism::Params::SignAdditionalContext(v1_proto::SignAdditionalContext {
                hedge_variant: 0,
                context,
                hash: 0,
                context_null_len,
            }),
            version,
        )
    };
    fn ctx(mechanism: &CkMechanism) -> &SignAdditionalContext {
        match &mechanism.params {
            Some(CkMechanismParams::SignAdditionalContext(p)) => p,
            other => panic!("expected SignAdditionalContext, got {other:?}"),
        }
    }
    let back = wire(vec![], Some(0), 1).unwrap();
    r16_assert_null(&ctx(&back).context_presence, 0);
    let back = wire(vec![], Some(17), 1).unwrap();
    r16_assert_null(&ctx(&back).context_presence, 17);
    let back = wire(vec![], None, 1).unwrap();
    r16_assert_present(&ctx(&back).context_presence, &[]);
    let back = wire(vec![0xC7; 17], None, 1).unwrap();
    let p = ctx(&back);
    r16_assert_present(&p.context_presence, &[0xC7; 17]);
    r16_assert_secret_eq(p.context_presence.as_present().unwrap(), &[0xC7; 17]);
    let back = wire(vec![0xC7; 17], None, 0).unwrap();
    r16_assert_present(&ctx(&back).context_presence, &[0xC7; 17]);
    assert_eq!(wire(vec![], Some(0), 0), Err(CkRv::MECHANISM_PARAM_INVALID));
    assert_eq!(wire(vec![1], Some(1), 1), Err(CkRv::MECHANISM_PARAM_INVALID));
}

// --- R16 v1 round-trips (R17 productionized the encode direction as
// `super::pointer_to_wire`; these tests ride the production helper) ---

#[test]
fn r16_presence_helpers_round_trip() {
    // Helper-level round-trip: every (bytes, null_len) pair survives
    // test-encode → production-decode → test-encode.
    for (bytes, null_len) in
        [(vec![], Some(0)), (vec![], Some(41)), (vec![], None), (vec![0xA5; 37], None)]
    {
        let presence = super::pointer_from_wire(&bytes, null_len, 1).unwrap();
        let (back_bytes, back_null) = super::pointer_to_wire(&presence);
        assert_eq!((back_bytes, back_null), (bytes.clone(), null_len));
        let legacy = super::pointer_from_wire_legacy(&bytes, null_len, false, 1).unwrap();
        assert_eq!(super::pointer_to_wire(&legacy), (bytes.clone(), null_len));
    }
    // Legacy-bool mirror at v0: set → Null{0}, unset → Present.
    assert_eq!(
        super::pointer_to_wire(&super::pointer_from_wire_legacy(&[], None, true, 0).unwrap()),
        (Vec::new(), Some(0))
    );
    assert_eq!(
        super::pointer_to_wire(
            &super::pointer_from_wire_legacy(&[0xA5; 3], None, false, 0).unwrap()
        ),
        (vec![0xA5; 3], None)
    );
}

#[test]
fn r16_production_encode_never_emits_presence_fields_gcm() {
    // GCM-representative pin (R16 minor: the name previously implied all
    // families): even a v1-decoded domain value (NULL/41 presence)
    // production-encodes v0-shaped through the legacy `TryFrom` —
    // legacy bytes only, no presence fields, version 0. (Since R17 the
    // shim emits v1 through `to_wire_with_transport_version`; this
    // `TryFrom` stays v0. Every family's v0 arm hard-codes the same
    // `*_null_len: None` shape; GCM pins it once.)
    let domain = CkMechanism {
        mechanism_type: CkMechanismType(0x1087),
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv_bits: 96,
            iv_buffer_len: 0,
            tag_bits: 128,
            iv_presence: PointerBytes::Null { declared_len: 41 },
            aad_presence: PointerBytes::Present(SecretBytes::copy_from_slice(&[2; 16])),
        })),
    };
    let wire = v1_proto::Mechanism::try_from(&domain).unwrap();
    assert_eq!(wire.parameter_encoding_version, 0);
    match &wire.params {
        Some(v1_proto::mechanism::Params::GcmParams(p)) => {
            assert!(p.iv.is_empty() && p.iv_null_len.is_none());
            assert_eq!(p.aad, vec![2; 16]);
            assert!(p.aad_null_len.is_none());
        }
        other => panic!("expected GcmParams, got {other:?}"),
    }
}

#[test]
fn r16_gcm_v1_round_trip_through_test_encode() {
    // Representative full round-trip: hand-built v1 wire → production
    // decode → production presence encode → identical wire.
    let wire = v1_proto::GcmParams {
        iv: vec![1; 12],
        iv_bits: 96,
        aad: Vec::new(),
        tag_bits: 128,
        iv_buffer_len: 0,
        iv_null: false,
        aad_null: false,
        iv_null_len: None,
        aad_null_len: Some(16),
    };
    let back = CkMechanism::try_from(&v1_proto::Mechanism {
        mechanism_type: 0x1087,
        params: Some(v1_proto::mechanism::Params::GcmParams(wire.clone())),
        parameter_encoding_version: 1,
    })
    .unwrap();
    let Some(CkMechanismParams::Gcm(p)) = &back.params else {
        panic!("expected Gcm, got {:?}", back.params)
    };
    assert_eq!(p.iv_presence, PointerBytes::present_copy(&[1; 12]));
    let (iv, iv_null_len) = super::pointer_to_wire(&p.iv_presence);
    let (aad, aad_null_len) = super::pointer_to_wire(&p.aad_presence);
    assert_eq!(
        v1_proto::GcmParams {
            iv,
            iv_bits: p.iv_bits,
            aad,
            tag_bits: p.tag_bits,
            iv_buffer_len: p.iv_buffer_len,
            iv_null: false,
            aad_null: false,
            iv_null_len,
            aad_null_len,
        },
        wire
    );
}

// --- R17 version-threaded production encode (S2 §3/§5: shim emits v1) ---
//
// Coverage decomposition (see the R17 report): `pointer_to_wire` carries
// the 4-state (NULL/0, NULL/n, ptr/0, ptr/n) semantics once (pinned
// below); each per-family test below pins WIRING — every `*_null_len`
// rides its own peer (distinct declared lengths catch crossed wires),
// Present bytes ride the peer bytes, legacy bools are forced unset, and
// the outer stamp is 1.

fn r17_mech(params: Option<CkMechanismParams>) -> CkMechanism {
    CkMechanism { mechanism_type: CkMechanismType(0x1087), params }
}

#[test]
fn r17_encode_v0_is_legacy_identical() {
    // Capability 0 delegates to the legacy `TryFrom` exactly — even for
    // v1-reader-shaped domain input (NULL presence + cleared bools).
    let cases: Vec<Option<CkMechanismParams>> = vec![
        None,
        Some(CkMechanismParams::Gcm(GcmParams {
            iv_bits: 96,
            iv_buffer_len: 12,
            tag_bits: 128,
            iv_presence: PointerBytes::present_copy(&[1; 12]),
            aad_presence: PointerBytes::null_len(16),
        })),
        Some(CkMechanismParams::Hkdf(HkdfParams {
            extract: true,
            expand: true,
            prf_hash_mechanism: CkMechanismType(0x250),
            salt_type: 0,
            salt_key_handle: CkObjectHandle(0),
            salt_presence: PointerBytes::null_len(41),
            info_presence: PointerBytes::present_copy(&[2; 8]),
        })),
        Some(CkMechanismParams::ChaCha20(ChaCha20Params {
            block_counter_bits: 32,
            nonce_bits: 96,
            block_counter_presence: PointerBytes::null_len(4),
            nonce_presence: PointerBytes::present_copy(&[3; 12]),
        })),
        Some(CkMechanismParams::KeaDerive(KeaDeriveParams {
            is_sender: true,
            random_a_presence: PointerBytes::present_copy(&[4; 8]),
            random_b_presence: PointerBytes::present_copy(&[]),
            public_data_presence: PointerBytes::present_copy(&[5; 16]),
        })),
    ];
    for params in cases {
        let m = r17_mech(params);
        let legacy = v1_proto::Mechanism::try_from(&m).unwrap();
        let wire = super::to_wire_with_transport_version(&m, 0).unwrap();
        assert_eq!(wire, legacy, "capability 0 is the legacy encode exactly");
        assert_eq!(wire.parameter_encoding_version, 0);
    }
}

#[test]
fn r17_pointer_to_wire_matrix() {
    // The 4-state semantics every per-family arm rides: NULL (any length,
    // incl. zero) = empty bytes + Some(len); Present = bytes + None.
    assert_eq!(super::pointer_to_wire(&PointerBytes::null_len(0)), (Vec::new(), Some(0)));
    assert_eq!(super::pointer_to_wire(&PointerBytes::null_len(41)), (Vec::new(), Some(41)));
    assert_eq!(super::pointer_to_wire(&PointerBytes::present_copy(&[])), (Vec::new(), None));
    assert_eq!(
        super::pointer_to_wire(&PointerBytes::present_copy(&[0xA5; 37])),
        (vec![0xA5; 37], None)
    );
}

#[test]
fn r17_encode_v1_newer_capability_still_v1() {
    // Monotonic capabilities (S2 §3, message-path precedent): a capability
    // newer than this encoder still emits the v1 form it knows.
    let m = r17_mech(Some(CkMechanismParams::Eddsa(EddsaParams {
        ph_flag: false,
        context_data_presence: PointerBytes::null_len(7),
    })));
    for version in [1, 2, u32::MAX] {
        let wire = super::to_wire_with_transport_version(&m, version).unwrap();
        assert_eq!(wire.parameter_encoding_version, 1, "capability {version}");
        match &wire.params {
            Some(v1_proto::mechanism::Params::EddsaParams(p)) => {
                assert!(p.context_data.is_empty());
                assert_eq!(p.context_data_null_len, Some(7));
            }
            other => panic!("capability {version} must emit EddsaParams, got {other:?}"),
        }
    }
}

#[test]
fn r17_encode_v1_non_r17_families_stay_v0_shaped() {
    // Scalar/output families take the identical legacy path at every
    // capability (scalar shapes have no presence). R18 owns the tail:
    // KEA moved to the v1 tail encoder (S2 §8), so this pin now covers
    // scalar shapes only (TlsMac is the R18 scalar empty row).
    let scalar_cases = [
        CkMechanismParams::TlsMac(pkcs11_proxy_ng_types::TlsMacParams {
            prf_hash_mechanism: CkMechanismType::SHA256,
            mac_length: 32,
            server_or_client: 1,
        }),
        CkMechanismParams::RsaPkcsPss(pkcs11_proxy_ng_types::RsaPkcsPssParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: CkMgf(1),
            salt_len: 32,
        }),
    ];
    for params in scalar_cases {
        let m = r17_mech(Some(params));
        for version in [0, 1, 2] {
            let wire = super::to_wire_with_transport_version(&m, version).unwrap();
            assert_eq!(wire, v1_proto::Mechanism::try_from(&m).unwrap());
            assert_eq!(wire.parameter_encoding_version, 0, "capability {version}");
        }
    }
    // Flat/Null keep their stored (R11-threaded) stamp, untouched.
    let flat = r17_mech(Some(CkMechanismParams::Flat(FlatParams {
        bytes: SecretBytes::copy_from_slice(&[9; 8]),
        declared_len: 8,
        source_abi: None,
        fingerprint: 0,
        version: 1,
    })));
    let wire = super::to_wire_with_transport_version(&flat, 1).unwrap();
    assert_eq!(wire, v1_proto::Mechanism::try_from(&flat).unwrap());
    assert_eq!(wire.parameter_encoding_version, 1);
}

#[test]
fn r17_encode_v1_rsa_oaep() {
    // Adversarial legacy bool (set) is forced unset; NULL rides presence.
    let m = r17_mech(Some(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
        hash_alg: CkMechanismType(0x250),
        mgf: CkMgf(1),
        source: CkOaepSource(1),
        source_data_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::RsaPkcsOaepParams(p)) => {
            assert!(p.source_data.is_empty());
            assert_eq!(p.source_data_null_len, Some(41));
            assert!(!p.source_null);
        }
        other => panic!("must emit RsaPkcsOaepParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
        hash_alg: CkMechanismType(0x250),
        mgf: CkMgf(1),
        source: CkOaepSource(1),
        source_data_presence: PointerBytes::present_copy(&[7; 5]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::RsaPkcsOaepParams(p)) => {
            assert_eq!(p.source_data, vec![7; 5]);
            assert_eq!(p.source_data_null_len, None);
        }
        other => panic!("must emit RsaPkcsOaepParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_gcm() {
    // THE mixed-field fix on the wire: copied IV + aad_null_len, bools
    // forced unset even when the domain input carries legacy-bool state.
    let m = r17_mech(Some(CkMechanismParams::Gcm(GcmParams {
        iv_bits: 96,
        iv_buffer_len: 12,
        tag_bits: 128,
        iv_presence: PointerBytes::present_copy(&[1; 12]),
        aad_presence: PointerBytes::null_len(16),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::GcmParams(p)) => {
            assert_eq!(p.iv, vec![1; 12]);
            assert_eq!(p.iv_null_len, None);
            assert!(p.aad.is_empty());
            assert_eq!(p.aad_null_len, Some(16));
            assert!(!p.iv_null && !p.aad_null);
        }
        other => panic!("must emit GcmParams, got {other:?}"),
    }
    // Distinct NULL lens catch crossed wires (iv⟷aad swap).
    let m = r17_mech(Some(CkMechanismParams::Gcm(GcmParams {
        iv_bits: 96,
        iv_buffer_len: 0,
        tag_bits: 128,
        iv_presence: PointerBytes::null_len(11),
        aad_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::GcmParams(p)) => {
            assert_eq!(p.iv_null_len, Some(11));
            assert_eq!(p.aad_null_len, Some(22));
        }
        other => panic!("must emit GcmParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_ecdh1_derive() {
    let m = r17_mech(Some(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
        kdf: CkKdf(3),
        shared_data_presence: PointerBytes::null_len(11),
        public_data_presence: PointerBytes::present_copy(&[2; 65]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::Ecdh1DeriveParams(p)) => {
            assert!(p.shared_data.is_empty());
            assert_eq!(p.shared_data_null_len, Some(11));
            assert_eq!(p.public_data, vec![2; 65]);
            assert_eq!(p.public_data_null_len, None);
        }
        other => panic!("must emit Ecdh1DeriveParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
        kdf: CkKdf(3),
        shared_data_presence: PointerBytes::present_copy(&[3; 4]),
        public_data_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::Ecdh1DeriveParams(p)) => {
            assert_eq!(p.shared_data, vec![3; 4]);
            assert_eq!(p.shared_data_null_len, None);
            assert!(p.public_data.is_empty());
            assert_eq!(p.public_data_null_len, Some(22));
        }
        other => panic!("must emit Ecdh1DeriveParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_ccm() {
    let m = r17_mech(Some(CkMechanismParams::Ccm(CcmParams {
        data_len: 32,
        mac_len: 16,
        nonce_presence: PointerBytes::null_len(11),
        aad_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::CcmParams(p)) => {
            assert!(p.nonce.is_empty());
            assert_eq!(p.nonce_null_len, Some(11));
            assert!(p.aad.is_empty());
            assert_eq!(p.aad_null_len, Some(22));
            assert!(!p.nonce_null && !p.aad_null);
        }
        other => panic!("must emit CcmParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Ccm(CcmParams {
        data_len: 32,
        mac_len: 16,
        nonce_presence: PointerBytes::present_copy(&[4; 13]),
        aad_presence: PointerBytes::present_copy(&[5; 6]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::CcmParams(p)) => {
            assert_eq!(p.nonce, vec![4; 13]);
            assert_eq!(p.nonce_null_len, None);
            assert_eq!(p.aad, vec![5; 6]);
            assert_eq!(p.aad_null_len, None);
        }
        other => panic!("must emit CcmParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_chacha20() {
    let m = r17_mech(Some(CkMechanismParams::ChaCha20(ChaCha20Params {
        block_counter_bits: 32,
        nonce_bits: 96,
        block_counter_presence: PointerBytes::null_len(11),
        nonce_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::Chacha20Params(p)) => {
            assert!(p.block_counter.is_empty());
            assert_eq!(p.block_counter_null_len, Some(11));
            assert!(p.nonce.is_empty());
            assert_eq!(p.nonce_null_len, Some(22));
        }
        other => panic!("must emit Chacha20Params, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::ChaCha20(ChaCha20Params {
        block_counter_bits: 32,
        nonce_bits: 96,
        block_counter_presence: PointerBytes::present_copy(&[6; 4]),
        nonce_presence: PointerBytes::present_copy(&[7; 12]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::Chacha20Params(p)) => {
            assert_eq!(p.block_counter, vec![6; 4]);
            assert_eq!(p.block_counter_null_len, None);
            assert_eq!(p.nonce, vec![7; 12]);
            assert_eq!(p.nonce_null_len, None);
        }
        other => panic!("must emit Chacha20Params, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_salsa20() {
    let m = r17_mech(Some(CkMechanismParams::Salsa20(Salsa20Params {
        nonce_bits: 64,
        block_counter_presence: PointerBytes::null_len(11),
        nonce_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::Salsa20Params(p)) => {
            assert_eq!(p.block_counter_null_len, Some(11));
            assert_eq!(p.nonce_null_len, Some(22));
        }
        other => panic!("must emit Salsa20Params, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Salsa20(Salsa20Params {
        nonce_bits: 0,
        block_counter_presence: PointerBytes::present_copy(&[8; 8]),
        nonce_presence: PointerBytes::present_copy(&[]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::Salsa20Params(p)) => {
            assert_eq!(p.block_counter, vec![8; 8]);
            assert_eq!(p.block_counter_null_len, None);
            assert!(p.nonce.is_empty());
            assert_eq!(p.nonce_null_len, None);
        }
        other => panic!("must emit Salsa20Params, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_salsa20_chacha20_poly1305() {
    let m =
        r17_mech(Some(CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
            nonce_presence: PointerBytes::null_len(11),
            aad_presence: PointerBytes::null_len(22),
        })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::Salsa20Chacha20Poly1305Params(p)) => {
            assert_eq!(p.nonce_null_len, Some(11));
            assert_eq!(p.aad_null_len, Some(22));
        }
        other => panic!("must emit Salsa20Chacha20Poly1305Params, got {other:?}"),
    }
    let m =
        r17_mech(Some(CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
            nonce_presence: PointerBytes::present_copy(&[9; 8]),
            aad_presence: PointerBytes::present_copy(&[1; 3]),
        })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::Salsa20Chacha20Poly1305Params(p)) => {
            assert_eq!(p.nonce, vec![9; 8]);
            assert_eq!(p.nonce_null_len, None);
            assert_eq!(p.aad, vec![1; 3]);
            assert_eq!(p.aad_null_len, None);
        }
        other => panic!("must emit Salsa20Chacha20Poly1305Params, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_gcm_wrap() {
    let m = r17_mech(Some(CkMechanismParams::GcmWrap(GcmWrapParams {
        iv_fixed_bits: 32,
        iv_generator: CkGeneratorFunction(2),
        tag_bits: 128,
        iv_presence: PointerBytes::null_len(11),
        aad_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::GcmWrapParams(p)) => {
            assert_eq!(p.iv_null_len, Some(11));
            assert_eq!(p.aad_null_len, Some(22));
        }
        other => panic!("must emit GcmWrapParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::GcmWrap(GcmWrapParams {
        iv_fixed_bits: 32,
        iv_generator: CkGeneratorFunction(2),
        tag_bits: 128,
        iv_presence: PointerBytes::present_copy(&[2; 8]),
        aad_presence: PointerBytes::present_copy(&[3; 5]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::GcmWrapParams(p)) => {
            assert_eq!(p.iv, vec![2; 8]);
            assert_eq!(p.iv_null_len, None);
            assert_eq!(p.aad, vec![3; 5]);
            assert_eq!(p.aad_null_len, None);
        }
        other => panic!("must emit GcmWrapParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_ccm_wrap() {
    let m = r17_mech(Some(CkMechanismParams::CcmWrap(CcmWrapParams {
        data_len: 64,
        nonce_fixed_bits: 16,
        nonce_generator: CkGeneratorFunction(2),
        mac_len: 12,
        nonce_presence: PointerBytes::null_len(11),
        aad_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::CcmWrapParams(p)) => {
            assert_eq!(p.nonce_null_len, Some(11));
            assert_eq!(p.aad_null_len, Some(22));
        }
        other => panic!("must emit CcmWrapParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::CcmWrap(CcmWrapParams {
        data_len: 64,
        nonce_fixed_bits: 16,
        nonce_generator: CkGeneratorFunction(2),
        mac_len: 12,
        nonce_presence: PointerBytes::present_copy(&[4; 7]),
        aad_presence: PointerBytes::present_copy(&[5; 9]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::CcmWrapParams(p)) => {
            assert_eq!(p.nonce, vec![4; 7]);
            assert_eq!(p.nonce_null_len, None);
            assert_eq!(p.aad, vec![5; 9]);
            assert_eq!(p.aad_null_len, None);
        }
        other => panic!("must emit CcmWrapParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_rc5_cbc() {
    let m = r17_mech(Some(CkMechanismParams::Rc5Cbc(Rc5CbcParams {
        word_size: 4,
        rounds: 12,
        iv_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::Rc5CbcParams(p)) => {
            assert!(p.iv.is_empty());
            assert_eq!(p.iv_null_len, Some(41));
        }
        other => panic!("must emit Rc5CbcParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Rc5Cbc(Rc5CbcParams {
        word_size: 4,
        rounds: 12,
        iv_presence: PointerBytes::present_copy(&[6; 8]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::Rc5CbcParams(p)) => {
            assert_eq!(p.iv, vec![6; 8]);
            assert_eq!(p.iv_null_len, None);
        }
        other => panic!("must emit Rc5CbcParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_aes_cbc_encrypt_data() {
    let m = r17_mech(Some(CkMechanismParams::AesCbcEncryptData(AesCbcEncryptDataParams {
        iv: vec![1; 16],
        data_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::AesCbcEncryptDataParams(p)) => {
            assert_eq!(p.iv, vec![1; 16]);
            assert!(p.data.is_empty());
            assert_eq!(p.data_null_len, Some(41));
        }
        other => panic!("must emit AesCbcEncryptDataParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::AesCbcEncryptData(AesCbcEncryptDataParams {
        iv: vec![1; 16],
        data_presence: PointerBytes::present_copy(&[2; 16]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::AesCbcEncryptDataParams(p)) => {
            assert_eq!(p.data, vec![2; 16]);
            assert_eq!(p.data_null_len, None);
        }
        other => panic!("must emit AesCbcEncryptDataParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_des_cbc_encrypt_data() {
    let m = r17_mech(Some(CkMechanismParams::DesCbcEncryptData(DesCbcEncryptDataParams {
        iv: vec![1; 8],
        data_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::DesCbcEncryptDataParams(p)) => {
            assert!(p.data.is_empty());
            assert_eq!(p.data_null_len, Some(41));
        }
        other => panic!("must emit DesCbcEncryptDataParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::DesCbcEncryptData(DesCbcEncryptDataParams {
        iv: vec![1; 8],
        data_presence: PointerBytes::present_copy(&[2; 8]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::DesCbcEncryptDataParams(p)) => {
            assert_eq!(p.data, vec![2; 8]);
            assert_eq!(p.data_null_len, None);
        }
        other => panic!("must emit DesCbcEncryptDataParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_camellia_cbc_encrypt_data() {
    let m =
        r17_mech(Some(CkMechanismParams::CamelliaCbcEncryptData(CamelliaCbcEncryptDataParams {
            iv: vec![1; 16],
            data_presence: PointerBytes::null_len(41),
        })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::CamelliaCbcEncryptDataParams(p)) => {
            assert_eq!(p.data_null_len, Some(41));
        }
        other => panic!("must emit CamelliaCbcEncryptDataParams, got {other:?}"),
    }
    let m =
        r17_mech(Some(CkMechanismParams::CamelliaCbcEncryptData(CamelliaCbcEncryptDataParams {
            iv: vec![1; 16],
            data_presence: PointerBytes::present_copy(&[2; 16]),
        })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::CamelliaCbcEncryptDataParams(p)) => {
            assert_eq!(p.data, vec![2; 16]);
            assert_eq!(p.data_null_len, None);
        }
        other => panic!("must emit CamelliaCbcEncryptDataParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_aria_cbc_encrypt_data() {
    let m = r17_mech(Some(CkMechanismParams::AriaCbcEncryptData(AriaCbcEncryptDataParams {
        iv: vec![1; 16],
        data_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::AriaCbcEncryptDataParams(p)) => {
            assert_eq!(p.data_null_len, Some(41));
        }
        other => panic!("must emit AriaCbcEncryptDataParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::AriaCbcEncryptData(AriaCbcEncryptDataParams {
        iv: vec![1; 16],
        data_presence: PointerBytes::present_copy(&[2; 16]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::AriaCbcEncryptDataParams(p)) => {
            assert_eq!(p.data, vec![2; 16]);
            assert_eq!(p.data_null_len, None);
        }
        other => panic!("must emit AriaCbcEncryptDataParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_seed_cbc_encrypt_data() {
    let m = r17_mech(Some(CkMechanismParams::SeedCbcEncryptData(SeedCbcEncryptDataParams {
        iv: vec![1; 16],
        data_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::SeedCbcEncryptDataParams(p)) => {
            assert_eq!(p.data_null_len, Some(41));
        }
        other => panic!("must emit SeedCbcEncryptDataParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::SeedCbcEncryptData(SeedCbcEncryptDataParams {
        iv: vec![1; 16],
        data_presence: PointerBytes::present_copy(&[2; 16]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::SeedCbcEncryptDataParams(p)) => {
            assert_eq!(p.data, vec![2; 16]);
            assert_eq!(p.data_null_len, None);
        }
        other => panic!("must emit SeedCbcEncryptDataParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_ecdh2_derive() {
    let m = r17_mech(Some(CkMechanismParams::Ecdh2Derive(Ecdh2DeriveParams {
        kdf: CkKdf(3),
        private_data_len: 0,
        private_data_handle: CkObjectHandle(0),
        shared_data_presence: PointerBytes::null_len(11),
        public_data_presence: PointerBytes::null_len(22),
        public_data2_presence: PointerBytes::null_len(33),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::Ecdh2DeriveParams(p)) => {
            assert_eq!(p.shared_data_null_len, Some(11));
            assert_eq!(p.public_data_null_len, Some(22));
            assert_eq!(p.public_data2_null_len, Some(33));
        }
        other => panic!("must emit Ecdh2DeriveParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Ecdh2Derive(Ecdh2DeriveParams {
        kdf: CkKdf(3),
        private_data_len: 0,
        private_data_handle: CkObjectHandle(0),
        shared_data_presence: PointerBytes::present_copy(&[1; 4]),
        public_data_presence: PointerBytes::present_copy(&[2; 65]),
        public_data2_presence: PointerBytes::present_copy(&[]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::Ecdh2DeriveParams(p)) => {
            assert_eq!(p.shared_data, vec![1; 4]);
            assert_eq!(p.shared_data_null_len, None);
            assert_eq!(p.public_data, vec![2; 65]);
            assert_eq!(p.public_data_null_len, None);
            assert!(p.public_data2.is_empty());
            assert_eq!(p.public_data2_null_len, None);
        }
        other => panic!("must emit Ecdh2DeriveParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_ecmqv_derive() {
    let m = r17_mech(Some(CkMechanismParams::EcmqvDerive(EcmqvDeriveParams {
        kdf: CkKdf(3),
        private_data_len: 0,
        private_data_handle: CkObjectHandle(0),
        public_key_handle: CkObjectHandle(7),
        shared_data_presence: PointerBytes::null_len(11),
        public_data_presence: PointerBytes::null_len(22),
        public_data2_presence: PointerBytes::null_len(33),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::EcmqvDeriveParams(p)) => {
            assert_eq!(p.shared_data_null_len, Some(11));
            assert_eq!(p.public_data_null_len, Some(22));
            assert_eq!(p.public_data2_null_len, Some(33));
            assert_eq!(p.public_key_handle, 7);
        }
        other => panic!("must emit EcmqvDeriveParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::EcmqvDerive(EcmqvDeriveParams {
        kdf: CkKdf(3),
        private_data_len: 0,
        private_data_handle: CkObjectHandle(0),
        public_key_handle: CkObjectHandle(7),
        shared_data_presence: PointerBytes::present_copy(&[1; 4]),
        public_data_presence: PointerBytes::present_copy(&[2; 65]),
        public_data2_presence: PointerBytes::present_copy(&[3; 65]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::EcmqvDeriveParams(p)) => {
            assert_eq!(p.shared_data_null_len, None);
            assert_eq!(p.public_data_null_len, None);
            assert_eq!(p.public_data2_null_len, None);
        }
        other => panic!("must emit EcmqvDeriveParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_x942_dh1_derive() {
    let m = r17_mech(Some(CkMechanismParams::X942Dh1Derive(X942Dh1DeriveParams {
        kdf: CkKdf(2),
        other_info_presence: PointerBytes::null_len(11),
        public_data_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::X942Dh1DeriveParams(p)) => {
            assert_eq!(p.other_info_null_len, Some(11));
            assert_eq!(p.public_data_null_len, Some(22));
        }
        other => panic!("must emit X942Dh1DeriveParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::X942Dh1Derive(X942Dh1DeriveParams {
        kdf: CkKdf(2),
        other_info_presence: PointerBytes::present_copy(&[4; 6]),
        public_data_presence: PointerBytes::present_copy(&[5; 64]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::X942Dh1DeriveParams(p)) => {
            assert_eq!(p.other_info, vec![4; 6]);
            assert_eq!(p.other_info_null_len, None);
            assert_eq!(p.public_data, vec![5; 64]);
            assert_eq!(p.public_data_null_len, None);
        }
        other => panic!("must emit X942Dh1DeriveParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_x942_dh2_derive() {
    let m = r17_mech(Some(CkMechanismParams::X942Dh2Derive(X942Dh2DeriveParams {
        kdf: CkKdf(2),
        private_data_len: 0,
        private_data_handle: CkObjectHandle(0),
        other_info_presence: PointerBytes::null_len(11),
        public_data_presence: PointerBytes::null_len(22),
        public_data2_presence: PointerBytes::null_len(33),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::X942Dh2DeriveParams(p)) => {
            assert_eq!(p.other_info_null_len, Some(11));
            assert_eq!(p.public_data_null_len, Some(22));
            assert_eq!(p.public_data2_null_len, Some(33));
        }
        other => panic!("must emit X942Dh2DeriveParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::X942Dh2Derive(X942Dh2DeriveParams {
        kdf: CkKdf(2),
        private_data_len: 0,
        private_data_handle: CkObjectHandle(0),
        other_info_presence: PointerBytes::present_copy(&[6; 6]),
        public_data_presence: PointerBytes::present_copy(&[7; 64]),
        public_data2_presence: PointerBytes::present_copy(&[8; 64]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::X942Dh2DeriveParams(p)) => {
            assert_eq!(p.other_info_null_len, None);
            assert_eq!(p.public_data_null_len, None);
            assert_eq!(p.public_data2_null_len, None);
        }
        other => panic!("must emit X942Dh2DeriveParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_x942_mqv_derive() {
    let m = r17_mech(Some(CkMechanismParams::X942MqvDerive(X942MqvDeriveParams {
        kdf: CkKdf(2),
        private_data_len: 0,
        private_data_handle: CkObjectHandle(0),
        public_key_handle: CkObjectHandle(9),
        other_info_presence: PointerBytes::null_len(11),
        public_data_presence: PointerBytes::null_len(22),
        public_data2_presence: PointerBytes::null_len(33),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::X942MqvDeriveParams(p)) => {
            assert_eq!(p.other_info_null_len, Some(11));
            assert_eq!(p.public_data_null_len, Some(22));
            assert_eq!(p.public_data2_null_len, Some(33));
        }
        other => panic!("must emit X942MqvDeriveParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::X942MqvDerive(X942MqvDeriveParams {
        kdf: CkKdf(2),
        private_data_len: 0,
        private_data_handle: CkObjectHandle(0),
        public_key_handle: CkObjectHandle(9),
        other_info_presence: PointerBytes::present_copy(&[1; 2]),
        public_data_presence: PointerBytes::present_copy(&[2; 64]),
        public_data2_presence: PointerBytes::present_copy(&[3; 64]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::X942MqvDeriveParams(p)) => {
            assert_eq!(p.other_info_null_len, None);
            assert_eq!(p.public_data_null_len, None);
            assert_eq!(p.public_data2_null_len, None);
        }
        other => panic!("must emit X942MqvDeriveParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_hkdf() {
    let m = r17_mech(Some(CkMechanismParams::Hkdf(HkdfParams {
        extract: true,
        expand: false,
        prf_hash_mechanism: CkMechanismType(0x250),
        salt_type: 1,
        salt_key_handle: CkObjectHandle(0),
        salt_presence: PointerBytes::null_len(11),
        info_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::HkdfParams(p)) => {
            assert_eq!(p.salt_null_len, Some(11));
            assert_eq!(p.info_null_len, Some(22));
        }
        other => panic!("must emit HkdfParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Hkdf(HkdfParams {
        extract: true,
        expand: true,
        prf_hash_mechanism: CkMechanismType(0x250),
        salt_type: 0,
        salt_key_handle: CkObjectHandle(0),
        salt_presence: PointerBytes::present_copy(&[1; 16]),
        info_presence: PointerBytes::present_copy(&[2; 8]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::HkdfParams(p)) => {
            assert_eq!(p.salt, vec![1; 16]);
            assert_eq!(p.salt_null_len, None);
            assert_eq!(p.info, vec![2; 8]);
            assert_eq!(p.info_null_len, None);
        }
        other => panic!("must emit HkdfParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_eddsa() {
    let m = r17_mech(Some(CkMechanismParams::Eddsa(EddsaParams {
        ph_flag: true,
        context_data_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::EddsaParams(p)) => {
            assert!(p.context_data.is_empty());
            assert_eq!(p.context_data_null_len, Some(41));
        }
        other => panic!("must emit EddsaParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Eddsa(EddsaParams {
        ph_flag: false,
        context_data_presence: PointerBytes::present_copy(&[3; 9]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::EddsaParams(p)) => {
            assert_eq!(p.context_data, vec![3; 9]);
            assert_eq!(p.context_data_null_len, None);
        }
        other => panic!("must emit EddsaParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_gostr3410_derive() {
    let m = r17_mech(Some(CkMechanismParams::Gostr3410Derive(Gostr3410DeriveParams {
        kdf: CkKdf(1),
        public_data_presence: PointerBytes::null_len(11),
        ukm_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::Gostr3410DeriveParams(p)) => {
            assert_eq!(p.public_data_null_len, Some(11));
            assert_eq!(p.ukm_null_len, Some(22));
        }
        other => panic!("must emit Gostr3410DeriveParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Gostr3410Derive(Gostr3410DeriveParams {
        kdf: CkKdf(1),
        public_data_presence: PointerBytes::present_copy(&[4; 64]),
        ukm_presence: PointerBytes::present_copy(&[5; 8]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::Gostr3410DeriveParams(p)) => {
            assert_eq!(p.public_data, vec![4; 64]);
            assert_eq!(p.public_data_null_len, None);
            assert_eq!(p.ukm, vec![5; 8]);
            assert_eq!(p.ukm_null_len, None);
        }
        other => panic!("must emit Gostr3410DeriveParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_gostr3410_key_wrap() {
    let m = r17_mech(Some(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
        key_handle: CkObjectHandle(3),
        wrap_oid_presence: PointerBytes::null_len(11),
        ukm_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::Gostr3410KeyWrapParams(p)) => {
            assert_eq!(p.wrap_oid_null_len, Some(11));
            assert_eq!(p.ukm_null_len, Some(22));
            assert_eq!(p.key_handle, 3);
        }
        other => panic!("must emit Gostr3410KeyWrapParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
        key_handle: CkObjectHandle(3),
        wrap_oid_presence: PointerBytes::present_copy(&[6; 9]),
        ukm_presence: PointerBytes::present_copy(&[7; 8]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::Gostr3410KeyWrapParams(p)) => {
            assert_eq!(p.wrap_oid_null_len, None);
            assert_eq!(p.ukm_null_len, None);
        }
        other => panic!("must emit Gostr3410KeyWrapParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_ecdh_aes_key_wrap() {
    let m = r17_mech(Some(CkMechanismParams::EcdhAesKeyWrap(EcdhAesKeyWrapParams {
        aes_key_bits: 256,
        kdf: CkKdf(3),
        shared_data_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::EcdhAesKeyWrapParams(p)) => {
            assert!(p.shared_data.is_empty());
            assert_eq!(p.shared_data_null_len, Some(41));
        }
        other => panic!("must emit EcdhAesKeyWrapParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::EcdhAesKeyWrap(EcdhAesKeyWrapParams {
        aes_key_bits: 256,
        kdf: CkKdf(3),
        shared_data_presence: PointerBytes::present_copy(&[8; 12]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::EcdhAesKeyWrapParams(p)) => {
            assert_eq!(p.shared_data, vec![8; 12]);
            assert_eq!(p.shared_data_null_len, None);
        }
        other => panic!("must emit EcdhAesKeyWrapParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_rsa_aes_key_wrap() {
    // Nested OAEP envelope: nested bool forced unset, nested presence set.
    let m = r17_mech(Some(CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
        aes_key_bits: 256,
        oaep_params: RsaPkcsOaepParams {
            hash_alg: CkMechanismType(0x250),
            mgf: CkMgf(1),
            source: CkOaepSource(1),
            source_data_presence: PointerBytes::null_len(41),
        },
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::RsaAesKeyWrapParams(p)) => {
            let o = p.oaep_params.as_ref().expect("nested OAEP present");
            assert!(o.source_data.is_empty());
            assert_eq!(o.source_data_null_len, Some(41));
            assert!(!o.source_null);
        }
        other => panic!("must emit RsaAesKeyWrapParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
        aes_key_bits: 128,
        oaep_params: RsaPkcsOaepParams {
            hash_alg: CkMechanismType(0x250),
            mgf: CkMgf(1),
            source: CkOaepSource(0),
            source_data_presence: PointerBytes::present_copy(&[9; 6]),
        },
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::RsaAesKeyWrapParams(p)) => {
            let o = p.oaep_params.as_ref().expect("nested OAEP present");
            assert_eq!(o.source_data, vec![9; 6]);
            assert_eq!(o.source_data_null_len, None);
        }
        other => panic!("must emit RsaAesKeyWrapParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_key_wrap_set_oaep() {
    let m = r17_mech(Some(CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams {
        bc: 1,
        x_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::KeyWrapSetOaepParams(p)) => {
            assert!(p.x.is_empty());
            assert_eq!(p.x_null_len, Some(41));
        }
        other => panic!("must emit KeyWrapSetOaepParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams {
        bc: 0,
        x_presence: PointerBytes::present_copy(&[1; 20]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::KeyWrapSetOaepParams(p)) => {
            assert_eq!(p.x, vec![1; 20]);
            assert_eq!(p.x_null_len, None);
        }
        other => panic!("must emit KeyWrapSetOaepParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_pbe() {
    let m = r17_mech(Some(CkMechanismParams::Pbe(PbeParams {
        iteration: 1000,
        init_vector_presence: PointerBytes::null_len(11),
        password_presence: PointerBytes::null_len(22),
        salt_presence: PointerBytes::null_len(33),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::PbeParams(p)) => {
            assert_eq!(p.init_vector_null_len, Some(11));
            assert_eq!(p.password_null_len, Some(22));
            assert_eq!(p.salt_null_len, Some(33));
        }
        other => panic!("must emit PbeParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Pbe(PbeParams {
        iteration: 1000,
        init_vector_presence: PointerBytes::present_copy(&[2; 8]),
        password_presence: PointerBytes::present_copy(&[3; 6]),
        salt_presence: PointerBytes::present_copy(&[4; 8]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::PbeParams(p)) => {
            assert_eq!(p.init_vector, vec![2; 8]);
            assert_eq!(p.init_vector_null_len, None);
            assert_eq!(p.password, vec![3; 6]);
            assert_eq!(p.password_null_len, None);
            assert_eq!(p.salt, vec![4; 8]);
            assert_eq!(p.salt_null_len, None);
        }
        other => panic!("must emit PbeParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_pkcs5_pbkd2() {
    let m = r17_mech(Some(CkMechanismParams::Pkcs5Pbkd2(Pkcs5Pbkd2Params {
        salt_source: CkPbkdf2SaltSource(1),
        iterations: 2048,
        prf: CkPbkdf2Prf(1),
        salt_source_data_presence: PointerBytes::null_len(11),
        prf_data_presence: PointerBytes::null_len(22),
        password_presence: PointerBytes::null_len(33),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::Pkcs5Pbkd2Params(p)) => {
            assert_eq!(p.salt_source_data_null_len, Some(11));
            assert_eq!(p.prf_data_null_len, Some(22));
            assert_eq!(p.password_null_len, Some(33));
        }
        other => panic!("must emit Pkcs5Pbkd2Params, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Pkcs5Pbkd2(Pkcs5Pbkd2Params {
        salt_source: CkPbkdf2SaltSource(0),
        iterations: 2048,
        prf: CkPbkdf2Prf(1),
        salt_source_data_presence: PointerBytes::present_copy(&[5; 8]),
        prf_data_presence: PointerBytes::present_copy(&[6; 4]),
        password_presence: PointerBytes::present_copy(&[7; 10]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::Pkcs5Pbkd2Params(p)) => {
            assert_eq!(p.salt_source_data_null_len, None);
            assert_eq!(p.prf_data_null_len, None);
            assert_eq!(p.password_null_len, None);
        }
        other => panic!("must emit Pkcs5Pbkd2Params, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_sign_additional_context() {
    let m = r17_mech(Some(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
        hedge_variant: 1,
        hash: CkMechanismType(0x250),
        context_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::SignAdditionalContext(p)) => {
            assert!(p.context.is_empty());
            assert_eq!(p.context_null_len, Some(41));
        }
        other => panic!("must emit SignAdditionalContext, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
        hedge_variant: 0,
        hash: CkMechanismType(0),
        context_presence: PointerBytes::present_copy(&[8; 5]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::SignAdditionalContext(p)) => {
            assert_eq!(p.context, vec![8; 5]);
            assert_eq!(p.context_null_len, None);
        }
        other => panic!("must emit SignAdditionalContext, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_kmac() {
    let m = r17_mech(Some(CkMechanismParams::Kmac(KmacParams {
        key_handle: CkObjectHandle(5),
        mac_length: 32,
        customization_string_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::KmacParams(p)) => {
            assert!(p.customization_string.is_empty());
            assert_eq!(p.customization_string_null_len, Some(41));
        }
        other => panic!("must emit KmacParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Kmac(KmacParams {
        key_handle: CkObjectHandle(5),
        mac_length: 32,
        customization_string_presence: PointerBytes::present_copy(&[9; 7]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::KmacParams(p)) => {
            assert_eq!(p.customization_string, vec![9; 7]);
            assert_eq!(p.customization_string_null_len, None);
        }
        other => panic!("must emit KmacParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_mu_gen() {
    let m = r17_mech(Some(CkMechanismParams::MuGen(MuGenParams {
        key_handle: CkObjectHandle(6),
        tr_presence: PointerBytes::null_len(11),
        context_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::MuGenParams(p)) => {
            assert_eq!(p.tr_null_len, Some(11));
            assert_eq!(p.context_null_len, Some(22));
        }
        other => panic!("must emit MuGenParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::MuGen(MuGenParams {
        key_handle: CkObjectHandle(6),
        tr_presence: PointerBytes::present_copy(&[1; 64]),
        context_presence: PointerBytes::present_copy(&[2; 9]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::MuGenParams(p)) => {
            assert_eq!(p.tr, vec![1; 64]);
            assert_eq!(p.tr_null_len, None);
            assert_eq!(p.context, vec![2; 9]);
            assert_eq!(p.context_null_len, None);
        }
        other => panic!("must emit MuGenParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_key_derivation_string() {
    let m = r17_mech(Some(CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
        data_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::KeyDerivationStringData(p)) => {
            assert!(p.data.is_empty());
            assert_eq!(p.data_null_len, Some(41));
        }
        other => panic!("must emit KeyDerivationStringData, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
        data_presence: PointerBytes::present_copy(&[3; 12]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::KeyDerivationStringData(p)) => {
            assert_eq!(p.data, vec![3; 12]);
            assert_eq!(p.data_null_len, None);
        }
        other => panic!("must emit KeyDerivationStringData, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_ike_prf_derive() {
    let m = r17_mech(Some(CkMechanismParams::IkePrfDerive(IkePrfDeriveParams {
        prf_mechanism: CkMechanismType(0x250),
        data_as_key: false,
        rekey: false,
        new_key_handle: CkObjectHandle(0),
        ni_presence: PointerBytes::null_len(11),
        nr_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::IkePrfDeriveParams(p)) => {
            assert_eq!(p.ni_null_len, Some(11));
            assert_eq!(p.nr_null_len, Some(22));
        }
        other => panic!("must emit IkePrfDeriveParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::IkePrfDerive(IkePrfDeriveParams {
        prf_mechanism: CkMechanismType(0x250),
        data_as_key: true,
        rekey: true,
        new_key_handle: CkObjectHandle(0),
        ni_presence: PointerBytes::present_copy(&[4; 8]),
        nr_presence: PointerBytes::present_copy(&[5; 8]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::IkePrfDeriveParams(p)) => {
            assert_eq!(p.ni, vec![4; 8]);
            assert_eq!(p.ni_null_len, None);
            assert_eq!(p.nr, vec![5; 8]);
            assert_eq!(p.nr_null_len, None);
        }
        other => panic!("must emit IkePrfDeriveParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_ike1_prf_derive() {
    let m = r17_mech(Some(CkMechanismParams::Ike1PrfDerive(Ike1PrfDeriveParams {
        prf_mechanism: CkMechanismType(0x250),
        has_prev_key: false,
        keygxy_handle: CkObjectHandle(0),
        prev_key_handle: CkObjectHandle(0),
        key_number: 1,
        ckyi_presence: PointerBytes::null_len(11),
        ckyr_presence: PointerBytes::null_len(22),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::Ike1PrfDeriveParams(p)) => {
            assert_eq!(p.ckyi_null_len, Some(11));
            assert_eq!(p.ckyr_null_len, Some(22));
        }
        other => panic!("must emit Ike1PrfDeriveParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Ike1PrfDerive(Ike1PrfDeriveParams {
        prf_mechanism: CkMechanismType(0x250),
        has_prev_key: true,
        keygxy_handle: CkObjectHandle(1),
        prev_key_handle: CkObjectHandle(2),
        key_number: 1,
        ckyi_presence: PointerBytes::present_copy(&[6; 8]),
        ckyr_presence: PointerBytes::present_copy(&[7; 8]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::Ike1PrfDeriveParams(p)) => {
            assert_eq!(p.ckyi_null_len, None);
            assert_eq!(p.ckyr_null_len, None);
        }
        other => panic!("must emit Ike1PrfDeriveParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_ike1_extended_derive() {
    let m = r17_mech(Some(CkMechanismParams::Ike1ExtendedDerive(Ike1ExtendedDeriveParams {
        prf_mechanism: CkMechanismType(0x250),
        has_keygxy: false,
        keygxy_handle: CkObjectHandle(0),
        extra_data_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::Ike1ExtendedDeriveParams(p)) => {
            assert!(p.extra_data.is_empty());
            assert_eq!(p.extra_data_null_len, Some(41));
        }
        other => panic!("must emit Ike1ExtendedDeriveParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Ike1ExtendedDerive(Ike1ExtendedDeriveParams {
        prf_mechanism: CkMechanismType(0x250),
        has_keygxy: true,
        keygxy_handle: CkObjectHandle(3),
        extra_data_presence: PointerBytes::present_copy(&[8; 10]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::Ike1ExtendedDeriveParams(p)) => {
            assert_eq!(p.extra_data, vec![8; 10]);
            assert_eq!(p.extra_data_null_len, None);
        }
        other => panic!("must emit Ike1ExtendedDeriveParams, got {other:?}"),
    }
}

#[test]
fn r17_encode_v1_ike2_prf_plus_derive() {
    let m = r17_mech(Some(CkMechanismParams::Ike2PrfPlusDerive(Ike2PrfPlusDeriveParams {
        prf_mechanism: CkMechanismType(0x250),
        has_seed_key: false,
        seed_key_handle: CkObjectHandle(0),
        seed_data_presence: PointerBytes::null_len(41),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::Ike2PrfPlusDeriveParams(p)) => {
            assert!(p.seed_data.is_empty());
            assert_eq!(p.seed_data_null_len, Some(41));
        }
        other => panic!("must emit Ike2PrfPlusDeriveParams, got {other:?}"),
    }
    let m = r17_mech(Some(CkMechanismParams::Ike2PrfPlusDerive(Ike2PrfPlusDeriveParams {
        prf_mechanism: CkMechanismType(0x250),
        has_seed_key: true,
        seed_key_handle: CkObjectHandle(4),
        seed_data_presence: PointerBytes::present_copy(&[9; 14]),
    })));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    match &wire.params {
        Some(v1_proto::mechanism::Params::Ike2PrfPlusDeriveParams(p)) => {
            assert_eq!(p.seed_data, vec![9; 14]);
            assert_eq!(p.seed_data_null_len, None);
        }
        other => panic!("must emit Ike2PrfPlusDeriveParams, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// R18: exotic-tail envelopes (S2 §8 tail, D1(a)) — subphase T
// ---------------------------------------------------------------------------
//
// RED/GREEN: these tests fail on the pre-R18 tree (tail families encode
// v0-shaped and decode ignores envelopes) and pass once the tail
// FromWire/ToWireV1 conversions land. Written first (TDD RED).

/// Minimal all-present SslRandomData for R18 encode-shape tests.
fn r18_ssl_random() -> SslRandomData {
    SslRandomData {
        client_random_presence: PointerBytes::present_copy(&[0x11; 32]),
        server_random_presence: PointerBytes::present_copy(&[0x22; 32]),
    }
}

/// Minimal all-present WtlsRandomData for R18 encode-shape tests.
fn r18_wtls_random() -> WtlsRandomData {
    WtlsRandomData {
        client_random_presence: PointerBytes::present_copy(&[0x11; 20]),
        server_random_presence: PointerBytes::present_copy(&[0x22; 20]),
    }
}

/// One all-present domain value per R18 tail family (16 v1 arms; TlsMac
/// is the scalar empty row and stays v0 — see `r18_tls_mac_stays_v0`).
fn r18_tail_present_cases() -> Vec<(&'static str, CkMechanismParams)> {
    vec![
        (
            "kea_derive",
            CkMechanismParams::KeaDerive(KeaDeriveParams {
                is_sender: true,
                random_a_presence: PointerBytes::present_copy(&[1; 8]),
                random_b_presence: PointerBytes::present_copy(&[2; 8]),
                public_data_presence: PointerBytes::present_copy(&[3; 16]),
            }),
        ),
        (
            "skipjack_private_wrap",
            CkMechanismParams::SkipjackPrivateWrap(SkipjackPrivateWrapParams {
                password_length: 4,
                password_presence: PointerBytes::present_copy(&[0x70; 4]),
                public_data_presence: PointerBytes::present_copy(&[0x11; 8]),
                random_a_presence: PointerBytes::present_copy(&[0x22; 8]),
                prime_p_presence: PointerBytes::present_copy(&[0x33; 8]),
                base_g_presence: PointerBytes::present_copy(&[0x44; 8]),
                subprime_q_presence: PointerBytes::present_copy(&[0x55; 8]),
            }),
        ),
        (
            "skipjack_relayx",
            CkMechanismParams::SkipjackRelayx(SkipjackRelayxParams {
                old_wrapped_x_presence: PointerBytes::present_copy(&[0x01; 4]),
                old_password_presence: PointerBytes::present_copy(&[0x02; 4]),
                old_public_data_presence: PointerBytes::present_copy(&[0x03; 4]),
                old_random_a_presence: PointerBytes::present_copy(&[0x04; 4]),
                new_password_presence: PointerBytes::present_copy(&[0x05; 4]),
                new_public_data_presence: PointerBytes::present_copy(&[0x06; 4]),
                new_random_a_presence: PointerBytes::present_copy(&[0x07; 4]),
            }),
        ),
        (
            "otp",
            CkMechanismParams::Otp(OtpParams {
                params_presence: PointerArray::present(vec![OtpParam {
                    type_: 1,
                    value_presence: PointerBytes::present_copy(&[0x01; 6]),
                }]),
            }),
        ),
        (
            "kip",
            CkMechanismParams::Kip(KipParams {
                mechanism: Some(Box::new(CkMechanism {
                    mechanism_type: CkMechanismType::SHA256,
                    params: None,
                })),
                key_handle: CkObjectHandle(0xBEEF),
                seed_presence: PointerBytes::present_copy(&[0xAA; 16]),
            }),
        ),
        (
            "sp800_108_kdf",
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CkMechanismType(0x250),
                data_params_presence: PointerArray::present(vec![]),
                additional_derived_keys_presence: PointerArray::present(vec![]),
            }),
        ),
        (
            "sp800_108_feedback_kdf",
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CkMechanismType(0x260),
                data_params_presence: PointerArray::present(vec![]),
                iv_presence: PointerBytes::present_copy(&[0xDD; 16]),
                additional_derived_keys_presence: PointerArray::present(vec![]),
            }),
        ),
        (
            "tls_prf",
            CkMechanismParams::TlsPrf(TlsPrfParams {
                output_len: 32,
                output: SecretBytes::copy_from_slice(&[]),
                seed_presence: PointerBytes::present_copy(&[0xA1; 8]),
                label_presence: PointerBytes::present_copy(&[0xB2; 4]),
                output_is_null: false,
                output_len_is_null: false,
            }),
        ),
        (
            "tls_kdf",
            CkMechanismParams::TlsKdf(TlsKdfParams {
                prf_mechanism: CkMechanismType(0x250),
                random_info: r18_ssl_random(),
                label_presence: PointerBytes::present_copy(&[0xC3; 4]),
                context_data_presence: PointerBytes::present_copy(&[0xD4; 8]),
            }),
        ),
        (
            "ssl3_master_key_derive",
            CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
                random_info: r18_ssl_random(),
                version_major: 3,
                version_minor: 0,
                version_is_null: false,
            }),
        ),
        (
            "tls12_master_key_derive",
            CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
                random_info: r18_ssl_random(),
                version_major: 3,
                version_minor: 3,
                prf_hash_mechanism: CkMechanismType::SHA256,
                version_is_null: false,
            }),
        ),
        (
            "tls12_extended_master_key_derive",
            CkMechanismParams::Tls12ExtendedMasterKeyDerive(Tls12ExtendedMasterKeyDeriveParams {
                prf_hash_mechanism: CkMechanismType::SHA256,
                version_major: 3,
                version_minor: 3,
                session_hash_presence: PointerBytes::present_copy(&[0xE5; 32]),
                version_is_null: false,
            }),
        ),
        (
            "ssl3_key_mat",
            CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                mac_size_bits: 128,
                key_size_bits: 128,
                iv_size_bits: 64,
                is_export: false,
                random_info: r18_ssl_random(),
                prf_hash_mechanism: CkMechanismType::SHA256,
                client_mac_secret_handle: CkObjectHandle(1),
                server_mac_secret_handle: CkObjectHandle(2),
                client_key_handle: CkObjectHandle(3),
                server_key_handle: CkObjectHandle(4),
                client_iv_presence: PointerBytes::present_copy(&[0xF1; 8]),
                server_iv_presence: PointerBytes::present_copy(&[0xF2; 8]),
                returned_key_material_is_null: false,
            }),
        ),
        (
            "wtls_master_key_derive",
            CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
                digest_mechanism: CkMechanismType::SHA256,
                random_info: r18_wtls_random(),
                version: 1,
                version_is_null: false,
            }),
        ),
        (
            "wtls_prf",
            CkMechanismParams::WtlsPrf(WtlsPrfParams {
                digest_mechanism: CkMechanismType::SHA256,
                output_len: 20,
                output: SecretBytes::copy_from_slice(&[]),
                seed_presence: PointerBytes::present_copy(&[0xA1; 8]),
                label_presence: PointerBytes::present_copy(&[0xB2; 4]),
                output_is_null: false,
                output_len_is_null: false,
            }),
        ),
        (
            "wtls_key_mat",
            CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
                digest_mechanism: CkMechanismType::SHA256,
                mac_size_bits: 64,
                key_size_bits: 40,
                iv_size_bits: 40,
                sequence_number: 7,
                is_export: false,
                random_info: r18_wtls_random(),
                mac_secret_handle: CkObjectHandle(11),
                key_handle: CkObjectHandle(12),
                iv_presence: PointerBytes::present_copy(&[0xF3; 8]),
                returned_key_material_is_null: false,
            }),
        ),
    ]
}

#[test]
fn r18_tail_families_stamp_v1_at_capability_1() {
    // Every R18 tail family (S2 §8 tail: KEA/KIP/OTP/SP800-108/Skipjack/
    // TLS-WTLS) encodes presence-based with the outer stamp 1 at
    // capability ≥ 1. TlsMac is the scalar empty row (no arm).
    let cases = r18_tail_present_cases();
    assert_eq!(cases.len(), 16, "16 v1 tail arms (17th shape TlsMac stays v0)");
    for (family, params) in cases {
        let m = r17_mech(Some(params));
        let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
        assert_eq!(wire.parameter_encoding_version, 1, "{family} must stamp v1 at capability 1");
    }
}

#[test]
fn r18_tls_mac_stays_v0() {
    // TlsMac is scalar-only (the R18 "empty row"): no envelopes, so the
    // v1 encode is the identical legacy path (no arm, stamp 0).
    let m = r17_mech(Some(CkMechanismParams::TlsMac(pkcs11_proxy_ng_types::TlsMacParams {
        prf_hash_mechanism: CkMechanismType::SHA256,
        mac_length: 32,
        server_or_client: 1,
    })));
    let legacy = v1_proto::Mechanism::try_from(&m).unwrap();
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire, legacy, "scalar tail row stays on the legacy encode");
    assert_eq!(wire.parameter_encoding_version, 0);
}

#[test]
fn r18_kea_null_a_v1_round_trip() {
    // KEA companions: NULL A with declared length rides the envelope and
    // survives the v1 round trip; the shared length agrees (8 == 8).
    let params = CkMechanismParams::KeaDerive(KeaDeriveParams {
        is_sender: false,
        random_a_presence: PointerBytes::null_len(8),
        random_b_presence: PointerBytes::present_copy(&[2; 8]),
        public_data_presence: PointerBytes::present_copy(&[]),
    });
    let m = r17_mech(Some(params));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::KeaDeriveParams(p)) => {
            assert!(p.random_a.is_empty());
            assert_eq!(p.random_a_null_len, Some(8));
            assert_eq!(p.random_b, vec![2; 8]);
            assert_eq!(p.random_b_null_len, None);
        }
        other => panic!("must emit KeaDeriveParams, got {other:?}"),
    }
    let back = CkMechanism::try_from(&wire).unwrap();
    match back.params {
        Some(CkMechanismParams::KeaDerive(v)) => {
            assert_eq!(v.random_a_presence, PointerBytes::null_len(8));
            assert!(v.random_a_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
            assert_eq!(v.random_b_presence, PointerBytes::present_copy(&[2; 8]));
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn r18_sp800108_null_template_closes_residual() {
    // ADR-0010 Scope-2 class-4 residual: a NULL SP800-108 pTemplate used
    // to conflate with an empty template. Under v1 it rides
    // template_null_count + empty template and decodes back to Null.
    let params = CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
        prf_type: CkMechanismType(0x250),
        data_params_presence: PointerArray::present(vec![]),
        additional_derived_keys_presence: PointerArray::present(vec![Sp800108DerivedKey {
            key_handle: CkObjectHandle(0xAA55),
            template_presence: PointerArray::null_count(2),
            ph_key_is_null: false,
        }]),
    });
    let m = r17_mech(Some(params));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::Sp800108KdfParams(p)) => {
            assert_eq!(p.additional_derived_keys.len(), 1);
            let dk = &p.additional_derived_keys[0];
            assert!(dk.template.is_empty());
            assert_eq!(dk.template_null_count, Some(2));
        }
        other => panic!("must emit Sp800108KdfParams, got {other:?}"),
    }
    let back = CkMechanism::try_from(&wire).unwrap();
    match back.params {
        Some(CkMechanismParams::Sp800108Kdf(v)) => {
            assert_eq!(v.additional_derived_keys_presence.as_present().unwrap().len(), 1);
            assert!(
                v.additional_derived_keys_presence.as_present().unwrap()[0]
                    .template_presence
                    .as_present()
                    .map(|b| b.is_empty())
                    .unwrap_or(true)
            );
            assert_eq!(
                v.additional_derived_keys_presence.as_present().unwrap()[0].template_presence,
                PointerArray::null_count(2)
            );
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn r18_kip_null_nested_round_trip() {
    // KIP nesting presence: NULL pMechanism rides mechanism_null with no
    // nested message and decodes to the canonical placeholder + set bit.
    let params = CkMechanismParams::Kip(KipParams {
        mechanism: None,
        key_handle: CkObjectHandle(0xBEEF),
        seed_presence: PointerBytes::null_len(0),
    });
    let m = r17_mech(Some(params));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::KipParams(p)) => {
            assert!(p.mechanism.is_none());
            assert_eq!(p.mechanism_null, Some(true));
            assert!(p.seed.is_empty());
            assert_eq!(p.seed_null_len, Some(0));
        }
        other => panic!("must emit KipParams, got {other:?}"),
    }
    let back = CkMechanism::try_from(&wire).unwrap();
    match back.params {
        Some(CkMechanismParams::Kip(v)) => {
            assert!(v.mechanism.is_none());
            assert_eq!(v.seed_presence, PointerBytes::null_len(0));
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn r18_tls_output_null_bits_round_trip() {
    // TLS output envelopes: NULL pOutput / pulOutputLen ride the bool bits
    // with forced-zero companions and decode back set.
    let params = CkMechanismParams::TlsPrf(TlsPrfParams {
        output_len: 0,
        output: SecretBytes::copy_from_slice(&[]),
        seed_presence: PointerBytes::present_copy(&[0xA1; 8]),
        label_presence: PointerBytes::present_copy(&[0xB2; 4]),
        output_is_null: true,
        output_len_is_null: true,
    });
    let m = r17_mech(Some(params));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::TlsPrfParams(p)) => {
            assert_eq!(p.output_null, Some(true));
            assert_eq!(p.output_len_null, Some(true));
        }
        other => panic!("must emit TlsPrfParams, got {other:?}"),
    }
    let back = CkMechanism::try_from(&wire).unwrap();
    match back.params {
        Some(CkMechanismParams::TlsPrf(v)) => {
            assert!(v.output_is_null);
            assert!(v.output_len_is_null);
            assert_eq!(v.output_len, 0);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn r18_otp_null_array_round_trip() {
    // OTP array presence: NULL pParams with count rides params_null_count
    // + empty array and decodes back to Null (count-0 edge below).
    let params = CkMechanismParams::Otp(OtpParams { params_presence: PointerArray::null_count(3) });
    let m = r17_mech(Some(params));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    match &wire.params {
        Some(v1_proto::mechanism::Params::OtpParams(p)) => {
            assert!(p.params.is_empty());
            assert_eq!(p.params_null_count, Some(3));
        }
        other => panic!("must emit OtpParams, got {other:?}"),
    }
    let back = CkMechanism::try_from(&wire).unwrap();
    match back.params {
        Some(CkMechanismParams::Otp(v)) => {
            assert!(v.params_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
            assert_eq!(v.params_presence, PointerArray::null_count(3));
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn r18_v0_tail_envelope_is_contradictory() {
    // No v0 encoder emits tail envelopes: a set envelope on a version-0
    // message is contradictory metadata (mirrors the R9 legacy-bool
    // rule for the new fields — per-field, since these are Optionals).
    let proto = v1_proto::Mechanism {
        mechanism_type: 0x1087,
        params: Some(v1_proto::mechanism::Params::TlsPrfParams(v1_proto::TlsPrfParams {
            seed: vec![],
            label: vec![],
            output_len: 0,
            output: vec![],
            seed_null_len: Some(4),
            label_null_len: None,
            output_null: None,
            output_len_null: None,
        })),
        parameter_encoding_version: 0,
    };
    expect_mechanism_param_invalid(proto);
}

#[test]
fn r18_v0_tail_null_bit_is_contradictory() {
    // Same rule for the bool envelopes: set at v0 → reject.
    let proto = v1_proto::Mechanism {
        mechanism_type: 0x1087,
        params: Some(v1_proto::mechanism::Params::TlsPrfParams(v1_proto::TlsPrfParams {
            seed: vec![],
            label: vec![],
            output_len: 0,
            output: vec![],
            seed_null_len: None,
            label_null_len: None,
            output_null: Some(true),
            output_len_null: None,
        })),
        parameter_encoding_version: 0,
    };
    expect_mechanism_param_invalid(proto);
}

#[test]
fn r18_v1_explicit_false_null_bit_is_dual() {
    // S2 §3 "no dual representations": v1 canonical non-NULL is an
    // ABSENT bit; explicit Some(false) is a second spelling → reject.
    let proto = v1_proto::Mechanism {
        mechanism_type: 0x1087,
        params: Some(v1_proto::mechanism::Params::TlsPrfParams(v1_proto::TlsPrfParams {
            seed: vec![],
            label: vec![],
            output_len: 0,
            output: vec![],
            seed_null_len: None,
            label_null_len: None,
            output_null: Some(false),
            output_len_null: None,
        })),
        parameter_encoding_version: 1,
    };
    expect_mechanism_param_invalid(proto);
}

#[test]
fn r18_shared_len_disagreement_rejected() {
    // KEA RandomA/B share the one C ulRandomLen: under v1 every
    // companion leg's effective length must agree (the shim always emits
    // agreement, so disagreement is crafted input).
    let proto = v1_proto::Mechanism {
        mechanism_type: 0x1087,
        params: Some(v1_proto::mechanism::Params::KeaDeriveParams(v1_proto::KeaDeriveParams {
            is_sender: false,
            random_a: vec![],
            random_b: vec![],
            public_data: vec![],
            random_a_null_len: Some(4),
            random_b_null_len: Some(8),
            public_data_null_len: None,
        })),
        parameter_encoding_version: 1,
    };
    expect_mechanism_param_invalid(proto);
}

#[test]
fn r18_kem_rides_general_mechanism_path() {
    // S2 §8: KEM needs no new envelope — Kyber/Dilithium encode via the
    // identical legacy path at every capability (no arm, stamp 0).
    for params in [
        CkMechanismParams::Kyber(KyberParams {
            version: 1,
            mode: 2,
            secret_handle: CkObjectHandle(9),
            shared_data: vec![0xAA; 8].into(),
            blob: vec![0xBB; 8].into(),
        }),
        CkMechanismParams::Dilithium(DilithiumParams { version: 1, mode: 2 }),
    ] {
        let m = r17_mech(Some(params));
        let legacy = v1_proto::Mechanism::try_from(&m).unwrap();
        let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
        assert_eq!(wire, legacy, "KEM has no v1 arm (general Mechanism path)");
        assert_eq!(wire.parameter_encoding_version, 0);
    }
}

/// Encode one domain value at capability 1 and decode it back (NULL-edge
/// matrix shorthand).
fn r18_wire_round_trip(params: CkMechanismParams) -> (v1_proto::Mechanism, CkMechanism) {
    let m = r17_mech(Some(params));
    let wire = super::to_wire_with_transport_version(&m, 1).unwrap();
    assert_eq!(wire.parameter_encoding_version, 1);
    let back = CkMechanism::try_from(&wire).unwrap();
    (wire, back)
}

#[test]
fn r18_tail_null_edges_round_trip() {
    // Per-tail-family NULL-edge matrix (S2 §8 tail): one NULL envelope
    // leg per remaining family, each surviving the v1 round trip with
    // its declared length/count/bit intact.
    // Skipjack companions: NULL PrimeP + present BaseG (shared length).
    let (wire, back) =
        r18_wire_round_trip(CkMechanismParams::SkipjackPrivateWrap(SkipjackPrivateWrapParams {
            password_length: 4,
            password_presence: PointerBytes::present_copy(&[0x70; 4]),
            public_data_presence: PointerBytes::present_copy(&[0x11; 8]),
            random_a_presence: PointerBytes::present_copy(&[0x22; 8]),
            prime_p_presence: PointerBytes::null_len(8),
            base_g_presence: PointerBytes::present_copy(&[0x44; 8]),
            subprime_q_presence: PointerBytes::present_copy(&[0x55; 8]),
        }));
    match &wire.params {
        Some(v1_proto::mechanism::Params::SkipjackPrivateWrapParams(p)) => {
            assert_eq!(p.prime_p_null_len, Some(8));
            assert_eq!(p.base_g_null_len, None);
        }
        other => panic!("must emit SkipjackPrivateWrapParams, got {other:?}"),
    }
    match back.params {
        Some(CkMechanismParams::SkipjackPrivateWrap(v)) => {
            assert_eq!(v.prime_p_presence, PointerBytes::null_len(8));
            assert!(v.prime_p_presence.as_present().map(|b| b.is_empty()).unwrap_or(true));
        }
        other => panic!("wrong variant: {other:?}"),
    }

    // RelayX: NULL old password.
    let (wire, back) =
        r18_wire_round_trip(CkMechanismParams::SkipjackRelayx(SkipjackRelayxParams {
            old_wrapped_x_presence: PointerBytes::present_copy(&[0x01; 4]),
            old_password_presence: PointerBytes::null_len(6),
            old_public_data_presence: PointerBytes::present_copy(&[0x03; 4]),
            old_random_a_presence: PointerBytes::present_copy(&[0x04; 4]),
            new_password_presence: PointerBytes::present_copy(&[0x05; 4]),
            new_public_data_presence: PointerBytes::present_copy(&[0x06; 4]),
            new_random_a_presence: PointerBytes::present_copy(&[0x07; 4]),
        }));
    match &wire.params {
        Some(v1_proto::mechanism::Params::SkipjackRelayxParams(p)) => {
            assert_eq!(p.old_password_null_len, Some(6));
            assert_eq!(p.old_wrapped_x_null_len, None);
        }
        other => panic!("must emit SkipjackRelayxParams, got {other:?}"),
    }
    match back.params {
        Some(CkMechanismParams::SkipjackRelayx(v)) => {
            assert_eq!(v.old_password_presence, PointerBytes::null_len(6));
        }
        other => panic!("wrong variant: {other:?}"),
    }

    // SSL3 key-mat: set returned-material bit + NULL IV legs.
    let (wire, back) = r18_wire_round_trip(CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
        mac_size_bits: 128,
        key_size_bits: 128,
        iv_size_bits: 64,
        is_export: false,
        random_info: r18_ssl_random(),
        prf_hash_mechanism: CkMechanismType::SHA256,
        client_mac_secret_handle: CkObjectHandle(0),
        server_mac_secret_handle: CkObjectHandle(0),
        client_key_handle: CkObjectHandle(0),
        server_key_handle: CkObjectHandle(0),
        client_iv_presence: PointerBytes::null_len(8),
        server_iv_presence: PointerBytes::null_len(8),
        returned_key_material_is_null: true,
    }));
    match &wire.params {
        Some(v1_proto::mechanism::Params::Ssl3KeyMatParams(p)) => {
            assert_eq!(p.returned_key_material_null, Some(true));
            assert_eq!(p.client_iv_null_len, Some(8));
            assert_eq!(p.server_iv_null_len, Some(8));
        }
        other => panic!("must emit Ssl3KeyMatParams, got {other:?}"),
    }
    match back.params {
        Some(CkMechanismParams::Ssl3KeyMat(v)) => {
            assert!(v.returned_key_material_is_null);
            assert_eq!(v.client_iv_presence, PointerBytes::null_len(8));
            assert_eq!(v.server_iv_presence, PointerBytes::null_len(8));
        }
        other => panic!("wrong variant: {other:?}"),
    }

    // TLS12 master: set version bit.
    let (wire, back) =
        r18_wire_round_trip(CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
            random_info: r18_ssl_random(),
            version_major: 0,
            version_minor: 0,
            prf_hash_mechanism: CkMechanismType::SHA256,
            version_is_null: true,
        }));
    match &wire.params {
        Some(v1_proto::mechanism::Params::Tls12MasterKeyDeriveParams(p)) => {
            assert_eq!(p.version_null, Some(true));
        }
        other => panic!("must emit Tls12MasterKeyDeriveParams, got {other:?}"),
    }
    match back.params {
        Some(CkMechanismParams::Tls12MasterKeyDerive(v)) => {
            assert!(v.version_is_null);
            assert_eq!((v.version_major, v.version_minor), (0, 0));
        }
        other => panic!("wrong variant: {other:?}"),
    }

    // TLS KDF: NULL label + NULL server random.
    let (wire, back) = r18_wire_round_trip(CkMechanismParams::TlsKdf(TlsKdfParams {
        prf_mechanism: CkMechanismType(0x250),
        random_info: SslRandomData {
            client_random_presence: PointerBytes::present_copy(&[0x11; 32]),
            server_random_presence: PointerBytes::null_len(32),
        },
        label_presence: PointerBytes::null_len(3),
        context_data_presence: PointerBytes::present_copy(&[0xD4; 8]),
    }));
    match &wire.params {
        Some(v1_proto::mechanism::Params::TlsKdfParams(p)) => {
            assert_eq!(p.label_null_len, Some(3));
            assert_eq!(p.context_data_null_len, None);
            let ri = p.random_info.as_ref().expect("random_info");
            assert_eq!(ri.client_random_null_len, None);
            assert_eq!(ri.server_random_null_len, Some(32));
        }
        other => panic!("must emit TlsKdfParams, got {other:?}"),
    }
    match back.params {
        Some(CkMechanismParams::TlsKdf(v)) => {
            assert_eq!(v.label_presence, PointerBytes::null_len(3));
            assert_eq!(v.random_info.server_random_presence, PointerBytes::null_len(32));
        }
        other => panic!("wrong variant: {other:?}"),
    }

    // TLS12 extended master: NULL session hash.
    let (wire, back) = r18_wire_round_trip(CkMechanismParams::Tls12ExtendedMasterKeyDerive(
        Tls12ExtendedMasterKeyDeriveParams {
            prf_hash_mechanism: CkMechanismType::SHA256,
            version_major: 3,
            version_minor: 3,
            session_hash_presence: PointerBytes::null_len(48),
            version_is_null: false,
        },
    ));
    match &wire.params {
        Some(v1_proto::mechanism::Params::Tls12ExtendedMasterKeyDeriveParams(p)) => {
            assert_eq!(p.session_hash_null_len, Some(48));
            assert_eq!(p.version_null, None);
        }
        other => panic!("must emit Tls12ExtendedMasterKeyDeriveParams, got {other:?}"),
    }
    match back.params {
        Some(CkMechanismParams::Tls12ExtendedMasterKeyDerive(v)) => {
            assert_eq!(v.session_hash_presence, PointerBytes::null_len(48));
            assert!(!v.version_is_null);
        }
        other => panic!("wrong variant: {other:?}"),
    }

    // WTLS key-mat: set returned-material bit.
    let (wire, back) = r18_wire_round_trip(CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
        digest_mechanism: CkMechanismType::SHA256,
        mac_size_bits: 64,
        key_size_bits: 40,
        iv_size_bits: 40,
        sequence_number: 7,
        is_export: false,
        random_info: r18_wtls_random(),
        mac_secret_handle: CkObjectHandle(0),
        key_handle: CkObjectHandle(0),
        iv_presence: PointerBytes::null_len(5),
        returned_key_material_is_null: true,
    }));
    match &wire.params {
        Some(v1_proto::mechanism::Params::WtlsKeyMatParams(p)) => {
            assert_eq!(p.returned_key_material_null, Some(true));
            assert_eq!(p.iv_null_len, Some(5));
        }
        other => panic!("must emit WtlsKeyMatParams, got {other:?}"),
    }
    match back.params {
        Some(CkMechanismParams::WtlsKeyMat(v)) => {
            assert!(v.returned_key_material_is_null);
            assert_eq!(v.iv_presence, PointerBytes::null_len(5));
        }
        other => panic!("wrong variant: {other:?}"),
    }

    // SP800-108 KDF: NULL data-params + NULL derived-keys arrays.
    let (wire, back) = r18_wire_round_trip(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
        prf_type: CkMechanismType(0x250),
        data_params_presence: PointerArray::null_count(2),
        additional_derived_keys_presence: PointerArray::null_count(1),
    }));
    match &wire.params {
        Some(v1_proto::mechanism::Params::Sp800108KdfParams(p)) => {
            assert_eq!(p.data_params_null_count, Some(2));
            assert_eq!(p.additional_derived_keys_null_count, Some(1));
        }
        other => panic!("must emit Sp800108KdfParams, got {other:?}"),
    }
    match back.params {
        Some(CkMechanismParams::Sp800108Kdf(v)) => {
            assert_eq!(v.data_params_presence, PointerArray::null_count(2));
            assert_eq!(v.additional_derived_keys_presence, PointerArray::null_count(1));
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn r18_count_zero_edges_stay_distinct() {
    // Count-0/empty edges (S2 §3): NULL-with-zero (`Null{0}`) and
    // present-empty (`Present([])`) are distinct v1 spellings on both
    // sides of the wire — never conflated, in either direction.
    for (name, presence, expect_some) in [
        ("null-0", PointerArray::null_count(0), true),
        ("present-empty", PointerArray::present(vec![]), false),
    ] {
        let params = CkMechanismParams::Otp(OtpParams { params_presence: presence });
        let (wire, back) = r18_wire_round_trip(params);
        match &wire.params {
            Some(v1_proto::mechanism::Params::OtpParams(p)) => {
                assert_eq!(
                    p.params_null_count.is_some(),
                    expect_some,
                    "{name}: envelope set-ness must survive"
                );
                if expect_some {
                    assert_eq!(p.params_null_count, Some(0));
                }
            }
            other => panic!("must emit OtpParams, got {other:?}"),
        }
        match back.params {
            Some(CkMechanismParams::Otp(v)) => {
                if expect_some {
                    assert_eq!(v.params_presence, PointerArray::null_count(0), "{name}");
                } else {
                    assert_eq!(v.params_presence, PointerArray::present(vec![]), "{name}");
                }
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }
}

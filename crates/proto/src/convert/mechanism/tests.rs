use super::*;
use pkcs11_proxy_ng_types::{
    AesCmacKeyDerivationParams, CmsSigParams, DilithiumParams, Ecdh1DeriveParams,
    Ecdh2DeriveParams, EcdhAesKeyWrapParams, EciesParams, EcmqvDeriveParams, EddsaParams,
    GcmParams, Gostr3410DeriveParams, Gostr3410KeyWrapParams, HdKeyDeriveParams, HkdfParams,
    Ike1ExtendedDeriveParams, Ike1PrfDeriveParams, Ike2PrfPlusDeriveParams, IkePrfDeriveParams,
    IvParams, KeaDeriveParams, KeyDerivationStringData, KeyWrapSetOaepParams, KipParams,
    KyberParams, MacGeneralParams, ObjectHandleParam, OtpParam, OtpParams, PbeParams,
    Pkcs5Pbkd2Params, PrfDataParam, RawMechanismParams, RsaAesKeyWrapParams, SignAdditionalContext,
    SkipjackPrivateWrapParams, SkipjackRelayxParams, Sp800108FeedbackKdfParams, Sp800108KdfParams,
    Ssl3KeyMatParams, Ssl3MasterKeyDeriveParams, SslRandomData, Tls12ExtendedMasterKeyDeriveParams,
    Tls12MasterKeyDeriveParams, TlsKdfParams, TlsPrfParams, VendorObjectExtractParams,
    VendorObjectInsertParams, WtlsKeyMatParams, WtlsMasterKeyDeriveParams, WtlsPrfParams,
    WtlsRandomData, X2RatchetInitializeParams, X2RatchetRespondParams, X3dhInitiateParams,
    X3dhRespondParams, X942Dh1DeriveParams, X942Dh2DeriveParams, X942MqvDeriveParams,
};

/// Helper: wrap params in a mechanism, round-trip through proto, return the result.
fn round_trip(params: CkMechanismParams) -> CkMechanismParams {
    let mech = CkMechanism {
        mechanism_type: CkMechanismType(0x9999), // arbitrary, doesn't matter for conversion
        params: Some(params),
    };
    let proto: v1_proto::Mechanism = (&mech).into();
    let back = CkMechanism::try_from(&proto).unwrap();
    back.params.expect("params should survive round-trip")
}

fn expect_mechanism_param_invalid(proto: v1_proto::Mechanism) {
    let err = CkMechanism::try_from(&proto).expect_err("invalid mechanism params should fail");
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
}

#[test]
fn mechanism_parameterless_round_trip() {
    let original = CkMechanism { mechanism_type: CkMechanismType::SHA256_RSA_PKCS, params: None };
    let proto: v1_proto::Mechanism = (&original).into();
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
            mgf: 1,
            salt_len: 32,
        })),
    };
    let proto: v1_proto::Mechanism = (&original).into();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(back.mechanism_type, original.mechanism_type);
    match back.params.unwrap() {
        CkMechanismParams::RsaPkcsPss(p) => {
            assert_eq!(p.salt_len, 32);
            assert_eq!(p.hash_alg, CkMechanismType::SHA256);
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
            mgf: 1,
            source: 1,
            source_data: vec![1, 2, 3],
        })),
    };
    let proto: v1_proto::Mechanism = (&original).into();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(back.mechanism_type, original.mechanism_type);
    match back.params.unwrap() {
        CkMechanismParams::RsaPkcsOaep(p) => assert_eq!(p.source_data, vec![1, 2, 3]),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn mechanism_oaep_empty_source_data_round_trip() {
    let original = CkMechanism {
        mechanism_type: CkMechanismType::RSA_PKCS_OAEP,
        params: Some(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: 0x00000002,
            source: 0x00000001,
            source_data: vec![],
        })),
    };
    let proto: v1_proto::Mechanism = (&original).into();
    let back = CkMechanism::try_from(&proto).unwrap();
    match back.params.unwrap() {
        CkMechanismParams::RsaPkcsOaep(p) => assert!(p.source_data.is_empty()),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn mechanism_gcm_round_trip() {
    let original = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: vec![0u8; 12],
            iv_bits: 96,
            iv_buffer_len: 12,
            aad: vec![0xAA, 0xBB],
            tag_bits: 128,
        })),
    };
    let proto: v1_proto::Mechanism = (&original).into();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(back.mechanism_type, CkMechanismType::AES_GCM);
    match back.params.unwrap() {
        CkMechanismParams::Gcm(p) => {
            assert_eq!(p.iv, vec![0u8; 12]);
            assert_eq!(p.iv_bits, 96);
            assert_eq!(p.iv_buffer_len, 12);
            assert_eq!(p.aad, vec![0xAA, 0xBB]);
            assert_eq!(p.tag_bits, 128);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn mechanism_gcm_empty_aad_round_trip() {
    let original = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            iv_bits: 96,
            iv_buffer_len: 12,
            aad: vec![],
            tag_bits: 96,
        })),
    };
    let proto: v1_proto::Mechanism = (&original).into();
    let back = CkMechanism::try_from(&proto).unwrap();
    match back.params.unwrap() {
        CkMechanismParams::Gcm(p) => {
            assert!(p.aad.is_empty());
            assert_eq!(p.tag_bits, 96);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn mechanism_ecdh1_derive_round_trip() {
    let original = CkMechanism {
        mechanism_type: CkMechanismType::ECDH1_DERIVE,
        params: Some(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
            kdf: 2,
            shared_data: vec![0x01, 0x02, 0x03],
            public_data: vec![0x04; 65],
        })),
    };
    let proto: v1_proto::Mechanism = (&original).into();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(back.mechanism_type, CkMechanismType::ECDH1_DERIVE);
    match back.params.unwrap() {
        CkMechanismParams::Ecdh1Derive(p) => {
            assert_eq!(p.kdf, 2);
            assert_eq!(p.shared_data, vec![0x01, 0x02, 0x03]);
            assert_eq!(p.public_data, vec![0x04; 65]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn mechanism_ecdh1_derive_null_kdf_no_shared_data() {
    let original = CkMechanism {
        mechanism_type: CkMechanismType::ECDH1_DERIVE,
        params: Some(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
            kdf: 1,
            shared_data: vec![],
            public_data: vec![0x04; 65],
        })),
    };
    let proto: v1_proto::Mechanism = (&original).into();
    let back = CkMechanism::try_from(&proto).unwrap();
    match back.params.unwrap() {
        CkMechanismParams::Ecdh1Derive(p) => {
            assert_eq!(p.kdf, 1);
            assert!(p.shared_data.is_empty());
            assert_eq!(p.public_data.len(), 65);
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
    let proto: v1_proto::Mechanism = (&mech).into();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(mech, back);
}

#[test]
fn des3_cbc_iv_round_trip() {
    let mech = CkMechanism {
        mechanism_type: CkMechanismType::DES3_CBC,
        params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0xAB; 8] })),
    };
    let proto: v1_proto::Mechanism = (&mech).into();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(mech, back);
}

#[test]
fn mechanism_unknown_type_preserved_as_parameterless() {
    let original = CkMechanism { mechanism_type: CkMechanismType(0xFFFF_FFFF), params: None };
    let proto: v1_proto::Mechanism = (&original).into();
    let back = CkMechanism::try_from(&proto).unwrap();
    assert_eq!(back.mechanism_type, CkMechanismType(0xFFFF_FFFF));
    assert!(back.params.is_none());
}

#[test]
fn mechanism_info_sign_verify_round_trip() {
    let original = CkMechanismInfo {
        min_key_size: 512,
        max_key_size: 4096,
        flags: CkMechanismFlags(CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY),
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
    let original =
        CkMechanismInfo { min_key_size: 2048, max_key_size: 2048, flags: CkMechanismFlags(flags) };
    let proto: v1_proto::MechanismInfo = (&original).into();
    let back = CkMechanismInfo::from(&proto);
    assert_eq!(back.flags.0 & CkMechanismFlags::SIGN_RECOVER, CkMechanismFlags::SIGN_RECOVER);
    assert_eq!(back.flags.0 & CkMechanismFlags::VERIFY_RECOVER, CkMechanismFlags::VERIFY_RECOVER);
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
    let original =
        CkMechanismInfo { min_key_size: 0, max_key_size: u64::MAX, flags: CkMechanismFlags(flags) };
    let proto: v1_proto::MechanismInfo = (&original).into();
    let back = CkMechanismInfo::from(&proto);
    assert_eq!(back.flags.0, flags);
    assert_eq!(back.max_key_size, u64::MAX);
}

#[test]
fn mechanism_info_sentinel_key_sizes() {
    let original =
        CkMechanismInfo { min_key_size: 0, max_key_size: u64::MAX, flags: CkMechanismFlags(0) };
    let proto: v1_proto::MechanismInfo = (&original).into();
    let back = CkMechanismInfo::from(&proto);
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
        kdf: 2,
        shared_data: vec![0x01, 0x02],
        public_data: vec![0x04; 65],
        private_data_len: 32,
        private_data_handle: 0x1234,
        public_data2: vec![0x04; 65],
    });
    match round_trip(params) {
        CkMechanismParams::Ecdh2Derive(p) => {
            assert_eq!(p.kdf, 2);
            assert_eq!(p.shared_data, vec![0x01, 0x02]);
            assert_eq!(p.public_data.len(), 65);
            assert_eq!(p.private_data_len, 32);
            assert_eq!(p.private_data_handle, 0x1234);
            assert_eq!(p.public_data2.len(), 65);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ecmqv_derive_round_trip() {
    let params = CkMechanismParams::EcmqvDerive(EcmqvDeriveParams {
        kdf: 3,
        shared_data: vec![0xAA],
        public_data: vec![0x04; 33],
        private_data_len: 16,
        private_data_handle: 0xABCD,
        public_data2: vec![0x04; 33],
        public_key_handle: 0xDEAD,
    });
    match round_trip(params) {
        CkMechanismParams::EcmqvDerive(p) => {
            assert_eq!(p.kdf, 3);
            assert_eq!(p.public_key_handle, 0xDEAD);
            assert_eq!(p.private_data_handle, 0xABCD);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn x942_dh1_derive_round_trip() {
    let params = CkMechanismParams::X942Dh1Derive(X942Dh1DeriveParams {
        kdf: 1,
        other_info: vec![0x10, 0x20],
        public_data: vec![0x55; 128],
    });
    match round_trip(params) {
        CkMechanismParams::X942Dh1Derive(p) => {
            assert_eq!(p.kdf, 1);
            assert_eq!(p.other_info, vec![0x10, 0x20]);
            assert_eq!(p.public_data.len(), 128);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn x942_dh2_derive_round_trip() {
    let params = CkMechanismParams::X942Dh2Derive(X942Dh2DeriveParams {
        kdf: 2,
        other_info: vec![],
        public_data: vec![0x55; 128],
        private_data_len: 64,
        private_data_handle: 42,
        public_data2: vec![0x66; 128],
    });
    match round_trip(params) {
        CkMechanismParams::X942Dh2Derive(p) => {
            assert_eq!(p.kdf, 2);
            assert!(p.other_info.is_empty());
            assert_eq!(p.private_data_handle, 42);
            assert_eq!(p.public_data2.len(), 128);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn x942_mqv_derive_round_trip() {
    let params = CkMechanismParams::X942MqvDerive(X942MqvDeriveParams {
        kdf: 3,
        other_info: vec![0xFF],
        public_data: vec![0x11; 64],
        private_data_len: 32,
        private_data_handle: 100,
        public_data2: vec![0x22; 64],
        public_key_handle: 200,
    });
    match round_trip(params) {
        CkMechanismParams::X942MqvDerive(p) => {
            assert_eq!(p.kdf, 3);
            assert_eq!(p.public_key_handle, 200);
            assert_eq!(p.private_data_handle, 100);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn hkdf_round_trip() {
    let params = CkMechanismParams::Hkdf(HkdfParams {
        extract: true,
        expand: true,
        prf_hash_mechanism: CkMechanismType::SHA256.0,
        salt_type: 1,
        salt: vec![0xAA; 32],
        salt_key_handle: 0,
        info: vec![0xBB; 16],
    });
    match round_trip(params) {
        CkMechanismParams::Hkdf(p) => {
            assert!(p.extract);
            assert!(p.expand);
            assert_eq!(p.prf_hash_mechanism, CkMechanismType::SHA256.0);
            assert_eq!(p.salt.len(), 32);
            assert_eq!(p.info.len(), 16);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn hkdf_extract_only_round_trip() {
    let params = CkMechanismParams::Hkdf(HkdfParams {
        extract: true,
        expand: false,
        prf_hash_mechanism: CkMechanismType::SHA384.0,
        salt_type: 2,
        salt: vec![],
        salt_key_handle: 0x42,
        info: vec![],
    });
    match round_trip(params) {
        CkMechanismParams::Hkdf(p) => {
            assert!(p.extract);
            assert!(!p.expand);
            assert_eq!(p.salt_key_handle, 0x42);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn eddsa_round_trip() {
    let params = CkMechanismParams::Eddsa(EddsaParams {
        ph_flag: true,
        context_data: vec![0x01, 0x02, 0x03],
    });
    match round_trip(params) {
        CkMechanismParams::Eddsa(p) => {
            assert!(p.ph_flag);
            assert_eq!(p.context_data, vec![0x01, 0x02, 0x03]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn eddsa_no_context_round_trip() {
    let params = CkMechanismParams::Eddsa(EddsaParams { ph_flag: false, context_data: vec![] });
    match round_trip(params) {
        CkMechanismParams::Eddsa(p) => {
            assert!(!p.ph_flag);
            assert!(p.context_data.is_empty());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn gostr3410_derive_round_trip() {
    let params = CkMechanismParams::Gostr3410Derive(Gostr3410DeriveParams {
        kdf: 1,
        public_data: vec![0xCC; 64],
        ukm: vec![0xDD; 8],
    });
    match round_trip(params) {
        CkMechanismParams::Gostr3410Derive(p) => {
            assert_eq!(p.kdf, 1);
            assert_eq!(p.public_data.len(), 64);
            assert_eq!(p.ukm, vec![0xDD; 8]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn kea_derive_round_trip() {
    let params = CkMechanismParams::KeaDerive(KeaDeriveParams {
        is_sender: true,
        random_a: vec![0x11; 128],
        random_b: vec![0x22; 128],
        public_data: vec![0x33; 128],
    });
    match round_trip(params) {
        CkMechanismParams::KeaDerive(p) => {
            assert!(p.is_sender);
            assert_eq!(p.random_a.len(), 128);
            assert_eq!(p.random_b.len(), 128);
            assert_eq!(p.public_data.len(), 128);
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
        kdf: 2,
        shared_data: vec![0xAA, 0xBB],
    });
    match round_trip(params) {
        CkMechanismParams::EcdhAesKeyWrap(p) => {
            assert_eq!(p.aes_key_bits, 256);
            assert_eq!(p.kdf, 2);
            assert_eq!(p.shared_data, vec![0xAA, 0xBB]);
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
            mgf: 1,
            source: 1,
            source_data: vec![0x01, 0x02],
        },
    });
    match round_trip(params) {
        CkMechanismParams::RsaAesKeyWrap(p) => {
            assert_eq!(p.aes_key_bits, 128);
            assert_eq!(p.oaep_params.hash_alg, CkMechanismType::SHA256);
            assert_eq!(p.oaep_params.mgf, 1);
            assert_eq!(p.oaep_params.source, 1);
            assert_eq!(p.oaep_params.source_data, vec![0x01, 0x02]);
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
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn gostr3410_key_wrap_round_trip() {
    let params = CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
        wrap_oid: vec![0x06, 0x07, 0x2A],
        ukm: vec![0xEE; 8],
        key_handle: 0xBEEF,
    });
    match round_trip(params) {
        CkMechanismParams::Gostr3410KeyWrap(p) => {
            assert_eq!(p.wrap_oid, vec![0x06, 0x07, 0x2A]);
            assert_eq!(p.ukm.len(), 8);
            assert_eq!(p.key_handle, 0xBEEF);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn key_wrap_set_oaep_round_trip() {
    let params =
        CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams { bc: 42, x: vec![0xFF; 8] });
    match round_trip(params) {
        CkMechanismParams::KeyWrapSetOaep(p) => {
            assert_eq!(p.bc, 42);
            assert_eq!(p.x, vec![0xFF; 8]);
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
        init_vector: vec![0x01; 16],
        password: vec![0x70, 0x61, 0x73, 0x73], // "pass"
        salt: vec![0xAA; 16],
        iteration: 10000,
    });
    match round_trip(params) {
        CkMechanismParams::Pbe(p) => {
            assert_eq!(p.init_vector.len(), 16);
            assert_eq!(p.password, vec![0x70, 0x61, 0x73, 0x73]);
            assert_eq!(p.salt.len(), 16);
            assert_eq!(p.iteration, 10000);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn pkcs5_pbkd2_round_trip() {
    let params = CkMechanismParams::Pkcs5Pbkd2(Pkcs5Pbkd2Params {
        salt_source: 1,
        salt_source_data: vec![0xBB; 16],
        iterations: 600000,
        prf: 2,
        prf_data: vec![],
        password: vec![0x73, 0x65, 0x63, 0x72, 0x65, 0x74], // "secret"
    });
    match round_trip(params) {
        CkMechanismParams::Pkcs5Pbkd2(p) => {
            assert_eq!(p.salt_source, 1);
            assert_eq!(p.salt_source_data.len(), 16);
            assert_eq!(p.iterations, 600000);
            assert_eq!(p.prf, 2);
            assert!(p.prf_data.is_empty());
            assert_eq!(p.password.len(), 6);
        }
        _ => panic!("wrong variant"),
    }
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
    let p = round_trip(CkMechanismParams::Xeddsa(XeddsaParams { hash: 0x250 }));
    match p {
        CkMechanismParams::Xeddsa(v) => assert_eq!(v.hash, 0x250),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn tls_mac_params_round_trip() {
    let p = round_trip(CkMechanismParams::TlsMac(TlsMacParams {
        prf_hash_mechanism: 0x250,
        mac_length: 32,
        server_or_client: 1,
    }));
    match p {
        CkMechanismParams::TlsMac(v) => {
            assert_eq!(v.prf_hash_mechanism, 0x250);
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
        iv: vec![0xCC; 8],
    }));
    match p {
        CkMechanismParams::Rc5Cbc(v) => {
            assert_eq!(v.word_size, 4);
            assert_eq!(v.rounds, 16);
            assert_eq!(v.iv, vec![0xCC; 8]);
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
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
    }));
    match p {
        CkMechanismParams::AesCbcEncryptData(v) => {
            assert_eq!(v.iv, vec![0x01; 16]);
            assert_eq!(v.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn des_cbc_encrypt_data_params_round_trip() {
    let p = round_trip(CkMechanismParams::DesCbcEncryptData(DesCbcEncryptDataParams {
        iv: vec![0xAA; 8],
        data: vec![0x01, 0x02, 0x03],
    }));
    match p {
        CkMechanismParams::DesCbcEncryptData(v) => {
            assert_eq!(v.iv, vec![0xAA; 8]);
            assert_eq!(v.data, vec![0x01, 0x02, 0x03]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn aria_cbc_encrypt_data_params_round_trip() {
    let p = round_trip(CkMechanismParams::AriaCbcEncryptData(AriaCbcEncryptDataParams {
        iv: vec![0xBB; 16],
        data: vec![0x10; 32],
    }));
    match p {
        CkMechanismParams::AriaCbcEncryptData(v) => {
            assert_eq!(v.iv, vec![0xBB; 16]);
            assert_eq!(v.data, vec![0x10; 32]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn camellia_cbc_encrypt_data_params_round_trip() {
    let p = round_trip(CkMechanismParams::CamelliaCbcEncryptData(CamelliaCbcEncryptDataParams {
        iv: vec![0xCC; 16],
        data: vec![0x20; 48],
    }));
    match p {
        CkMechanismParams::CamelliaCbcEncryptData(v) => {
            assert_eq!(v.iv, vec![0xCC; 16]);
            assert_eq!(v.data, vec![0x20; 48]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn seed_cbc_encrypt_data_params_round_trip() {
    let p = round_trip(CkMechanismParams::SeedCbcEncryptData(SeedCbcEncryptDataParams {
        iv: vec![0xDD; 16],
        data: vec![],
    }));
    match p {
        CkMechanismParams::SeedCbcEncryptData(v) => {
            assert_eq!(v.iv, vec![0xDD; 16]);
            assert!(v.data.is_empty());
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
        nonce: vec![0x01; 12],
        aad: vec![0xAA, 0xBB],
        mac_len: 16,
    }));
    match p {
        CkMechanismParams::Ccm(v) => {
            assert_eq!(v.data_len, 256);
            assert_eq!(v.nonce, vec![0x01; 12]);
            assert_eq!(v.aad, vec![0xAA, 0xBB]);
            assert_eq!(v.mac_len, 16);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn chacha20_params_round_trip() {
    let p = round_trip(CkMechanismParams::ChaCha20(ChaCha20Params {
        block_counter: vec![0x00; 4],
        block_counter_bits: 32,
        nonce: vec![0x01; 12],
        nonce_bits: 96,
    }));
    match p {
        CkMechanismParams::ChaCha20(v) => {
            assert_eq!(v.block_counter, vec![0x00; 4]);
            assert_eq!(v.block_counter_bits, 32);
            assert_eq!(v.nonce, vec![0x01; 12]);
            assert_eq!(v.nonce_bits, 96);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn salsa20_params_round_trip() {
    let p = round_trip(CkMechanismParams::Salsa20(Salsa20Params {
        block_counter: vec![0x00; 8],
        nonce: vec![0x02; 8],
        nonce_bits: 64,
    }));
    match p {
        CkMechanismParams::Salsa20(v) => {
            assert_eq!(v.block_counter, vec![0x00; 8]);
            assert_eq!(v.nonce, vec![0x02; 8]);
            assert_eq!(v.nonce_bits, 64);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn salsa20_chacha20_poly1305_params_round_trip() {
    let p = round_trip(CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
        nonce: vec![0x03; 12],
        aad: vec![0x04; 20],
    }));
    match p {
        CkMechanismParams::Salsa20ChaCha20Poly1305(v) => {
            assert_eq!(v.nonce, vec![0x03; 12]);
            assert_eq!(v.aad, vec![0x04; 20]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn salsa20_chacha20_poly1305_empty_aad_round_trip() {
    let p = round_trip(CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
        nonce: vec![0x05; 12],
        aad: vec![],
    }));
    match p {
        CkMechanismParams::Salsa20ChaCha20Poly1305(v) => {
            assert_eq!(v.nonce, vec![0x05; 12]);
            assert!(v.aad.is_empty());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn gcm_wrap_params_round_trip() {
    let p = round_trip(CkMechanismParams::GcmWrap(GcmWrapParams {
        iv: vec![0x01; 12],
        iv_fixed_bits: 32,
        iv_generator: 1,
        aad: vec![0xAA],
        tag_bits: 128,
    }));
    match p {
        CkMechanismParams::GcmWrap(v) => {
            assert_eq!(v.iv, vec![0x01; 12]);
            assert_eq!(v.iv_fixed_bits, 32);
            assert_eq!(v.iv_generator, 1);
            assert_eq!(v.aad, vec![0xAA]);
            assert_eq!(v.tag_bits, 128);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ccm_wrap_params_round_trip() {
    let p = round_trip(CkMechanismParams::CcmWrap(CcmWrapParams {
        data_len: 1024,
        nonce: vec![0x02; 7],
        nonce_fixed_bits: 24,
        nonce_generator: 2,
        aad: vec![0xBB, 0xCC],
        mac_len: 8,
    }));
    match p {
        CkMechanismParams::CcmWrap(v) => {
            assert_eq!(v.data_len, 1024);
            assert_eq!(v.nonce, vec![0x02; 7]);
            assert_eq!(v.nonce_fixed_bits, 24);
            assert_eq!(v.nonce_generator, 2);
            assert_eq!(v.aad, vec![0xBB, 0xCC]);
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
        seed: vec![0x01; 32],
        label: vec![0x6D, 0x61, 0x73, 0x74], // "mast"
        output_len: 48,
    }));
    match p {
        CkMechanismParams::TlsPrf(v) => {
            assert_eq!(v.seed.len(), 32);
            assert_eq!(v.label, vec![0x6D, 0x61, 0x73, 0x74]);
            assert_eq!(v.output_len, 48);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn tls_kdf_params_round_trip() {
    let p = round_trip(CkMechanismParams::TlsKdf(TlsKdfParams {
        prf_mechanism: 0x250,
        label: vec![0x6B, 0x65, 0x79], // "key"
        random_info: SslRandomData { client_random: vec![0xAA; 32], server_random: vec![0xBB; 32] },
        context_data: vec![0xCC; 16],
    }));
    match p {
        CkMechanismParams::TlsKdf(v) => {
            assert_eq!(v.prf_mechanism, 0x250);
            assert_eq!(v.label, vec![0x6B, 0x65, 0x79]);
            assert_eq!(v.random_info.client_random, vec![0xAA; 32]);
            assert_eq!(v.random_info.server_random, vec![0xBB; 32]);
            assert_eq!(v.context_data.len(), 16);
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
        })),
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn tls_kdf_params_preserve_present_empty_random_info() {
    let p = round_trip(CkMechanismParams::TlsKdf(TlsKdfParams {
        prf_mechanism: CkMechanismType::SHA256.0,
        label: vec![],
        random_info: SslRandomData { client_random: vec![], server_random: vec![] },
        context_data: vec![],
    }));

    match p {
        CkMechanismParams::TlsKdf(v) => {
            assert!(v.label.is_empty());
            assert!(v.random_info.client_random.is_empty());
            assert!(v.random_info.server_random.is_empty());
            assert!(v.context_data.is_empty());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ssl3_master_key_derive_round_trip() {
    let p = round_trip(CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
        random_info: SslRandomData { client_random: vec![0x11; 32], server_random: vec![0x22; 32] },
        version_major: 3,
        version_minor: 0,
    }));
    match p {
        CkMechanismParams::Ssl3MasterKeyDerive(v) => {
            assert_eq!(v.random_info.client_random.len(), 32);
            assert_eq!(v.version_major, 3);
            assert_eq!(v.version_minor, 0);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn tls12_master_key_derive_round_trip() {
    let p = round_trip(CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
        random_info: SslRandomData { client_random: vec![0x33; 32], server_random: vec![0x44; 32] },
        version_major: 3,
        version_minor: 3,
        prf_hash_mechanism: 0x250,
    }));
    match p {
        CkMechanismParams::Tls12MasterKeyDerive(v) => {
            assert_eq!(v.version_major, 3);
            assert_eq!(v.version_minor, 3);
            assert_eq!(v.prf_hash_mechanism, 0x250);
            assert_eq!(v.random_info.client_random.len(), 32);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn tls12_extended_master_key_derive_round_trip() {
    let p = round_trip(CkMechanismParams::Tls12ExtendedMasterKeyDerive(
        Tls12ExtendedMasterKeyDeriveParams {
            prf_hash_mechanism: 0x260,
            session_hash: vec![0x55; 48],
            version_major: 3,
            version_minor: 3,
        },
    ));
    match p {
        CkMechanismParams::Tls12ExtendedMasterKeyDerive(v) => {
            assert_eq!(v.prf_hash_mechanism, 0x260);
            assert_eq!(v.session_hash.len(), 48);
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
        random_info: SslRandomData { client_random: vec![0x66; 32], server_random: vec![0x77; 32] },
        prf_hash_mechanism: 0x250,
    }));
    match p {
        CkMechanismParams::Ssl3KeyMat(v) => {
            assert_eq!(v.mac_size_bits, 160);
            assert_eq!(v.key_size_bits, 128);
            assert_eq!(v.iv_size_bits, 128);
            assert!(!v.is_export);
            assert_eq!(v.prf_hash_mechanism, 0x250);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn wtls_master_key_derive_round_trip() {
    let p = round_trip(CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
        digest_mechanism: 0x250,
        random_info: WtlsRandomData {
            client_random: vec![0x88; 16],
            server_random: vec![0x99; 16],
        },
        version: 1,
    }));
    match p {
        CkMechanismParams::WtlsMasterKeyDerive(v) => {
            assert_eq!(v.digest_mechanism, 0x250);
            assert_eq!(v.random_info.client_random.len(), 16);
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
            },
        )),
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn wtls_prf_params_round_trip() {
    let p = round_trip(CkMechanismParams::WtlsPrf(WtlsPrfParams {
        digest_mechanism: 0x260,
        seed: vec![0xAA; 20],
        label: vec![0xBB; 10],
        output_len: 32,
    }));
    match p {
        CkMechanismParams::WtlsPrf(v) => {
            assert_eq!(v.digest_mechanism, 0x260);
            assert_eq!(v.seed.len(), 20);
            assert_eq!(v.label.len(), 10);
            assert_eq!(v.output_len, 32);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn wtls_key_mat_params_round_trip() {
    let p = round_trip(CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
        digest_mechanism: 0x250,
        mac_size_bits: 160,
        key_size_bits: 128,
        iv_size_bits: 64,
        sequence_number: 42,
        is_export: true,
        random_info: WtlsRandomData {
            client_random: vec![0xCC; 16],
            server_random: vec![0xDD; 16],
        },
    }));
    match p {
        CkMechanismParams::WtlsKeyMat(v) => {
            assert_eq!(v.digest_mechanism, 0x250);
            assert_eq!(v.mac_size_bits, 160);
            assert_eq!(v.sequence_number, 42);
            assert!(v.is_export);
            assert_eq!(v.random_info.client_random.len(), 16);
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// Batch 3: IKE/IPSec round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn ike_prf_derive_round_trip() {
    let p = round_trip(CkMechanismParams::IkePrfDerive(IkePrfDeriveParams {
        prf_mechanism: 0x250,
        data_as_key: true,
        rekey: false,
        ni: vec![0x01; 32],
        nr: vec![0x02; 32],
        new_key_handle: 0x1234,
    }));
    match p {
        CkMechanismParams::IkePrfDerive(v) => {
            assert_eq!(v.prf_mechanism, 0x250);
            assert!(v.data_as_key);
            assert!(!v.rekey);
            assert_eq!(v.ni.len(), 32);
            assert_eq!(v.nr.len(), 32);
            assert_eq!(v.new_key_handle, 0x1234);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ike1_prf_derive_round_trip() {
    let p = round_trip(CkMechanismParams::Ike1PrfDerive(Ike1PrfDeriveParams {
        prf_mechanism: 0x260,
        has_prev_key: true,
        keygxy_handle: 0xAAAA,
        prev_key_handle: 0xBBBB,
        ckyi: vec![0x11; 8],
        ckyr: vec![0x22; 8],
        key_number: 3,
    }));
    match p {
        CkMechanismParams::Ike1PrfDerive(v) => {
            assert_eq!(v.prf_mechanism, 0x260);
            assert!(v.has_prev_key);
            assert_eq!(v.keygxy_handle, 0xAAAA);
            assert_eq!(v.prev_key_handle, 0xBBBB);
            assert_eq!(v.ckyi.len(), 8);
            assert_eq!(v.key_number, 3);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ike1_extended_derive_round_trip() {
    let p = round_trip(CkMechanismParams::Ike1ExtendedDerive(Ike1ExtendedDeriveParams {
        prf_mechanism: 0x270,
        has_keygxy: true,
        keygxy_handle: 0xCCCC,
        extra_data: vec![0x33; 64],
    }));
    match p {
        CkMechanismParams::Ike1ExtendedDerive(v) => {
            assert_eq!(v.prf_mechanism, 0x270);
            assert!(v.has_keygxy);
            assert_eq!(v.keygxy_handle, 0xCCCC);
            assert_eq!(v.extra_data.len(), 64);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ike2_prf_plus_derive_round_trip() {
    let p = round_trip(CkMechanismParams::Ike2PrfPlusDerive(Ike2PrfPlusDeriveParams {
        prf_mechanism: 0x250,
        has_seed_key: true,
        seed_key_handle: 0xDDDD,
        seed_data: vec![0x44; 32],
    }));
    match p {
        CkMechanismParams::Ike2PrfPlusDerive(v) => {
            assert_eq!(v.prf_mechanism, 0x250);
            assert!(v.has_seed_key);
            assert_eq!(v.seed_key_handle, 0xDDDD);
            assert_eq!(v.seed_data.len(), 32);
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
        prf_type: 0x250,
        data_params: vec![
            PrfDataParam { type_: 1, value: vec![0xAA; 4] },
            PrfDataParam { type_: 2, value: vec![0xBB; 8] },
        ],
    }));
    match p {
        CkMechanismParams::Sp800108Kdf(v) => {
            assert_eq!(v.prf_type, 0x250);
            assert_eq!(v.data_params.len(), 2);
            assert_eq!(v.data_params[0].type_, 1);
            assert_eq!(v.data_params[0].value, vec![0xAA; 4]);
            assert_eq!(v.data_params[1].type_, 2);
            assert_eq!(v.data_params[1].value, vec![0xBB; 8]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn sp800_108_feedback_kdf_params_round_trip() {
    let p = round_trip(CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
        prf_type: 0x260,
        data_params: vec![PrfDataParam { type_: 3, value: vec![0xCC; 16] }],
        iv: vec![0xDD; 16],
    }));
    match p {
        CkMechanismParams::Sp800108FeedbackKdf(v) => {
            assert_eq!(v.prf_type, 0x260);
            assert_eq!(v.data_params.len(), 1);
            assert_eq!(v.iv.len(), 16);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn sp800_108_kdf_empty_data_params_round_trip() {
    let p = round_trip(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
        prf_type: 1,
        data_params: vec![],
    }));
    match p {
        CkMechanismParams::Sp800108Kdf(v) => {
            assert_eq!(v.prf_type, 1);
            assert!(v.data_params.is_empty());
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// Batch 3: Signal protocol round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn x3dh_initiate_round_trip() {
    let p = round_trip(CkMechanismParams::X3dhInitiate(X3dhInitiateParams {
        kdf: 1,
        peer_identity_handle: 0x1111,
        peer_prekey_handle: 0x2222,
        prekey_signature: vec![0xAA; 64],
        onetime_key_handle: 0x3333,
        own_identity_handle: 0x4444,
        own_ephemeral_handle: 0x5555,
    }));
    match p {
        CkMechanismParams::X3dhInitiate(v) => {
            assert_eq!(v.kdf, 1);
            assert_eq!(v.peer_identity_handle, 0x1111);
            assert_eq!(v.peer_prekey_handle, 0x2222);
            assert_eq!(v.prekey_signature.len(), 64);
            assert_eq!(v.onetime_key_handle, 0x3333);
            assert_eq!(v.own_identity_handle, 0x4444);
            assert_eq!(v.own_ephemeral_handle, 0x5555);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn x3dh_respond_round_trip() {
    let p = round_trip(CkMechanismParams::X3dhRespond(X3dhRespondParams {
        kdf: 2,
        identity_handle: 0xAAAA,
        prekey_handle: 0xBBBB,
        onetime_key_handle: 0xCCCC,
        initiator_identity_handle: 0xDDDD,
        initiator_ephemeral_handle: 0xEEEE,
    }));
    match p {
        CkMechanismParams::X3dhRespond(v) => {
            assert_eq!(v.kdf, 2);
            assert_eq!(v.identity_handle, 0xAAAA);
            assert_eq!(v.prekey_handle, 0xBBBB);
            assert_eq!(v.onetime_key_handle, 0xCCCC);
            assert_eq!(v.initiator_identity_handle, 0xDDDD);
            assert_eq!(v.initiator_ephemeral_handle, 0xEEEE);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn x2_ratchet_initialize_round_trip() {
    let p = round_trip(CkMechanismParams::X2RatchetInitialize(X2RatchetInitializeParams {
        sk: vec![0x01; 32],
        peer_public_prekey_handle: 0x1111,
        peer_public_identity_handle: 0x2222,
        own_public_identity_handle: 0x3333,
        encrypted_header: true,
        curve: 0x0403, // CKP_EC_NIST_P256 for example
        aead_mechanism: 0x1087,
        kdf_mechanism: 0x0250,
    }));
    match p {
        CkMechanismParams::X2RatchetInitialize(v) => {
            assert_eq!(v.sk.len(), 32);
            assert_eq!(v.peer_public_prekey_handle, 0x1111);
            assert!(v.encrypted_header);
            assert_eq!(v.curve, 0x0403);
            assert_eq!(v.aead_mechanism, 0x1087);
            assert_eq!(v.kdf_mechanism, 0x0250);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn x2_ratchet_respond_round_trip() {
    let p = round_trip(CkMechanismParams::X2RatchetRespond(X2RatchetRespondParams {
        sk: vec![0x02; 32],
        own_prekey_handle: 0xAAAA,
        initiator_identity_handle: 0xBBBB,
        own_identity_handle: 0xCCCC,
        encrypted_header: false,
        curve: 0x0403,
        aead_mechanism: 0x1087,
        kdf_mechanism: 0x0260,
    }));
    match p {
        CkMechanismParams::X2RatchetRespond(v) => {
            assert_eq!(v.sk.len(), 32);
            assert_eq!(v.own_prekey_handle, 0xAAAA);
            assert!(!v.encrypted_header);
            assert_eq!(v.kdf_mechanism, 0x0260);
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// Batch 3: Miscellaneous round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn otp_params_round_trip() {
    let p = round_trip(CkMechanismParams::Otp(OtpParams {
        params: vec![
            OtpParam { type_: 1, value: vec![0x01; 6] },
            OtpParam { type_: 2, value: vec![0x02; 4] },
        ],
    }));
    match p {
        CkMechanismParams::Otp(v) => {
            assert_eq!(v.params.len(), 2);
            assert_eq!(v.params[0].type_, 1);
            assert_eq!(v.params[0].value, vec![0x01; 6]);
            assert_eq!(v.params[1].type_, 2);
            assert_eq!(v.params[1].value, vec![0x02; 4]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn otp_params_empty_round_trip() {
    let p = round_trip(CkMechanismParams::Otp(OtpParams { params: vec![] }));
    match p {
        CkMechanismParams::Otp(v) => assert!(v.params.is_empty()),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn kip_params_round_trip() {
    let nested = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let p = round_trip(CkMechanismParams::Kip(KipParams {
        mechanism: Box::new(nested),
        key_handle: 0xBEEF,
        seed: vec![0xAA; 16],
    }));
    match p {
        CkMechanismParams::Kip(v) => {
            assert_eq!(v.mechanism.mechanism_type, CkMechanismType::SHA256);
            assert!(v.mechanism.params.is_none());
            assert_eq!(v.key_handle, 0xBEEF);
            assert_eq!(v.seed, vec![0xAA; 16]);
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
        }))),
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn cms_sig_params_round_trip() {
    let signing = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let digest = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let p = round_trip(CkMechanismParams::CmsSig(CmsSigParams {
        certificate_handle: 0x42,
        signing_mechanism: Box::new(signing),
        digest_mechanism: Box::new(digest),
        content_type: "1.2.840.113549.1.7.1".to_string(),
        requested_attributes: vec![0x30, 0x00],
        required_attributes: vec![0x31, 0x00],
    }));
    match p {
        CkMechanismParams::CmsSig(v) => {
            assert_eq!(v.certificate_handle, 0x42);
            assert_eq!(v.signing_mechanism.mechanism_type, CkMechanismType::RSA_PKCS);
            assert_eq!(v.digest_mechanism.mechanism_type, CkMechanismType::SHA256);
            assert_eq!(v.content_type, "1.2.840.113549.1.7.1");
            assert_eq!(v.requested_attributes, vec![0x30, 0x00]);
            assert_eq!(v.required_attributes, vec![0x31, 0x00]);
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
            })),
            digest_mechanism: None,
            content_type: "1.2.840.113549.1.7.1".to_string(),
            requested_attributes: vec![],
            required_attributes: vec![],
        }))),
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn skipjack_private_wrap_round_trip() {
    let p = round_trip(CkMechanismParams::SkipjackPrivateWrap(SkipjackPrivateWrapParams {
        password: vec![0x70, 0x61, 0x73, 0x73],
        public_data: vec![0x11; 128],
        password_length: 4,
        random_a: vec![0x22; 20],
        prime_p: vec![0x33; 128],
        base_g: vec![0x44; 128],
        subprime_q: vec![0x55; 20],
    }));
    match p {
        CkMechanismParams::SkipjackPrivateWrap(v) => {
            assert_eq!(v.password, vec![0x70, 0x61, 0x73, 0x73]);
            assert_eq!(v.public_data.len(), 128);
            assert_eq!(v.password_length, 4);
            assert_eq!(v.random_a.len(), 20);
            assert_eq!(v.prime_p.len(), 128);
            assert_eq!(v.base_g.len(), 128);
            assert_eq!(v.subprime_q.len(), 20);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn skipjack_relayx_round_trip() {
    let p = round_trip(CkMechanismParams::SkipjackRelayx(SkipjackRelayxParams {
        old_wrapped_x: vec![0x01; 24],
        old_password: vec![0x02; 8],
        old_public_data: vec![0x03; 128],
        old_random_a: vec![0x04; 20],
        new_password: vec![0x05; 8],
        new_public_data: vec![0x06; 128],
        new_random_a: vec![0x07; 20],
    }));
    match p {
        CkMechanismParams::SkipjackRelayx(v) => {
            assert_eq!(v.old_wrapped_x.len(), 24);
            assert_eq!(v.old_password.len(), 8);
            assert_eq!(v.old_public_data.len(), 128);
            assert_eq!(v.old_random_a.len(), 20);
            assert_eq!(v.new_password.len(), 8);
            assert_eq!(v.new_public_data.len(), 128);
            assert_eq!(v.new_random_a.len(), 20);
        }
        _ => panic!("wrong variant"),
    }
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
fn key_derivation_string_data_round_trip() {
    let p = round_trip(CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
    }));
    match p {
        CkMechanismParams::KeyDerivationString(v) => {
            assert_eq!(v.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn key_derivation_string_data_empty_round_trip() {
    let p = round_trip(CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
        data: vec![],
    }));
    match p {
        CkMechanismParams::KeyDerivationString(v) => {
            assert!(v.data.is_empty());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn raw_mechanism_params_round_trip() {
    let p = round_trip(CkMechanismParams::Raw(RawMechanismParams {
        data: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    }));
    match p {
        CkMechanismParams::Raw(v) => {
            assert_eq!(v.data, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn raw_mechanism_params_empty_round_trip() {
    let p = round_trip(CkMechanismParams::Raw(RawMechanismParams { data: vec![] }));
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
        shared_data: vec![0x01, 0x02, 0x03],
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
            assert_eq!(v.shared_data, vec![0x01, 0x02, 0x03]);
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
        shared_data: vec![],
    }));
    match p {
        CkMechanismParams::Ecies(v) => {
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
            })),
            encryption_mechanism: Some(Box::new(v1_proto::Mechanism {
                mechanism_type: CkMechanismType::AES_CBC.0,
                params: None,
            })),
            mac_mechanism: None,
            shared_data: vec![],
        }))),
    };

    expect_mechanism_param_invalid(proto);
}

#[test]
fn aes_cmac_key_derivation_params_round_trip() {
    let p = round_trip(CkMechanismParams::AesCmacKeyDerivation(AesCmacKeyDerivationParams {
        context: vec![0x10; 32],
        label: vec![0x20; 16],
    }));
    match p {
        CkMechanismParams::AesCmacKeyDerivation(v) => {
            assert_eq!(v.context, vec![0x10; 32]);
            assert_eq!(v.label, vec![0x20; 16]);
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
        secret_handle: 0xDEAD,
        shared_data: vec![0xAB; 32],
        blob: vec![0xCD; 64],
    }));
    match p {
        CkMechanismParams::Kyber(v) => {
            assert_eq!(v.version, 2);
            assert_eq!(v.mode, 1);
            assert_eq!(v.secret_handle, 0xDEAD);
            assert_eq!(v.shared_data, vec![0xAB; 32]);
            assert_eq!(v.blob, vec![0xCD; 64]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn kyber_params_empty_optional_fields_round_trip() {
    let p = round_trip(CkMechanismParams::Kyber(KyberParams {
        version: 1,
        mode: 0,
        secret_handle: 0,
        shared_data: vec![],
        blob: vec![],
    }));
    match p {
        CkMechanismParams::Kyber(v) => {
            assert_eq!(v.version, 1);
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
        chain_code: vec![0xFF; 32],
        version: 1,
    }));
    match p {
        CkMechanismParams::HdKeyDerive(v) => {
            assert_eq!(v.derive_type, 32);
            assert_eq!(v.child_key_index, 0x8000_0000);
            assert_eq!(v.chain_code, vec![0xFF; 32]);
            assert_eq!(v.version, 1);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn vendor_object_extract_params_round_trip() {
    let p = round_trip(CkMechanismParams::VendorObjectExtract(VendorObjectExtractParams {
        format: 1,
        context: vec![0x42; 24],
    }));
    match p {
        CkMechanismParams::VendorObjectExtract(v) => {
            assert_eq!(v.format, 1);
            assert_eq!(v.context, vec![0x42; 24]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn vendor_object_insert_params_round_trip() {
    let p = round_trip(CkMechanismParams::VendorObjectInsert(VendorObjectInsertParams {
        format: 2,
        context: vec![0x43; 24],
        object_data: vec![0xBE, 0xEF, 0xCA, 0xFE],
    }));
    match p {
        CkMechanismParams::VendorObjectInsert(v) => {
            assert_eq!(v.format, 2);
            assert_eq!(v.context, vec![0x43; 24]);
            assert_eq!(v.object_data, vec![0xBE, 0xEF, 0xCA, 0xFE]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn object_handle_param_round_trip() {
    let p = round_trip(CkMechanismParams::ObjectHandle(ObjectHandleParam { handle: 42 }));
    match p {
        CkMechanismParams::ObjectHandle(v) => assert_eq!(v.handle, 42),
        other => panic!("expected ObjectHandle, got {other:?}"),
    }
}

#[test]
fn sign_additional_context_round_trip() {
    let p = round_trip(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
        hedge_variant: 1, // CKH_HEDGE_REQUIRED
        context: vec![1, 2, 3],
    }));
    match p {
        CkMechanismParams::SignAdditionalContext(v) => {
            assert_eq!(v.hedge_variant, 1);
            assert_eq!(v.context, vec![1, 2, 3]);
        }
        other => panic!("expected SignAdditionalContext, got {other:?}"),
    }
}

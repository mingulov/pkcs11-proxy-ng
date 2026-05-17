use super::*;
use pkcs11_proxy_ng_proto::convert::message_params::{
    CcmMessageParams, GcmMessageParams, MessageParameter, Salsa20ChaCha20Poly1305MessageParams,
};

#[test]
fn mock_lifecycle() {
    let backend = MockBackend::default_test();
    assert!(backend.initialize().is_ok());
    assert_eq!(backend.initialize().unwrap_err(), CkRv::CRYPTOKI_ALREADY_INITIALIZED);
    assert!(backend.finalize().is_ok());
}

#[test]
fn mock_session_lifecycle() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let h = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert!(backend.get_session_info(h).is_ok());
    assert!(backend.close_session(h).is_ok());
    assert_eq!(backend.close_session(h).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
}

#[test]
fn mock_invalid_slot() {
    let backend = MockBackend::default_test();
    assert_eq!(backend.get_slot_info(CkSlotId(99)).unwrap_err(), CkRv::SLOT_ID_INVALID);
    assert_eq!(
        backend.open_session(CkSlotId(99), CkSessionFlags::default()).unwrap_err(),
        CkRv::SLOT_ID_INVALID
    );
}

#[test]
fn slot_scoped_workflows_reject_invalid_slot() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

    assert_eq!(
        backend.init_token(CkSlotId(99), Some(b"so-pin"), "MockToken").unwrap_err(),
        CkRv::SLOT_ID_INVALID
    );
    assert_eq!(backend.close_all_sessions(CkSlotId(99)).unwrap_err(), CkRv::SLOT_ID_INVALID);
    assert!(backend.get_session_info(session).is_ok());
}

#[test]
fn full_registry_mock_advertises_every_default_registered_mechanism() {
    let registry = MechanismRegistry::load_with_override_str(None).unwrap();
    let expected =
        registry.registered_mechanisms().into_iter().map(CkMechanismType).collect::<Vec<_>>();
    let backend = MockBackend::with_mechanism_registry(vec![CkSlotId(0)], &registry);

    let advertised = backend.get_mechanism_list(CkSlotId(0)).unwrap();

    assert_eq!(advertised, expected);
    for mechanism in advertised {
        assert!(
            backend.get_mechanism_info(CkSlotId(0), mechanism).is_ok(),
            "mechanism 0x{:08X} should have mock mechanism info",
            mechanism.0
        );
    }
}

#[test]
fn full_registry_mock_includes_vendor_override_mechanisms() {
    let registry = MechanismRegistry::load_with_override_str(Some(
        r#"
        parameterless = [0x80FF0001]

        [[params]]
        shape = "gcm"
        mechanisms = [0x80001087]
        "#,
    ))
    .unwrap();
    let backend = MockBackend::with_mechanism_registry(vec![CkSlotId(0)], &registry);
    let advertised = backend.get_mechanism_list(CkSlotId(0)).unwrap();

    assert!(advertised.contains(&CkMechanismType(0x80FF0001)));
    assert!(advertised.contains(&CkMechanismType(0x80001087)));
}

#[test]
fn official_mechanism_mock_advertises_provider_gap_mechanisms() {
    let backend = MockBackend::with_official_mechanisms(vec![CkSlotId(0)]);
    let advertised = backend.get_mechanism_list(CkSlotId(0)).unwrap();

    assert_eq!(advertised, pkcs11_3_2_official_mechanisms());
    assert!(advertised.contains(&CkMechanismType(0x0000_001F))); // CKM_HASH_ML_DSA
    assert!(advertised.contains(&CkMechanismType(0x0000_002E))); // CKM_SLH_DSA
    assert!(advertised.contains(&CkMechanismType(0x0000_03D5))); // CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
    assert!(advertised.contains(&CkMechanismType(0x0000_4037))); // CKM_XMSSMT
}

#[test]
fn mock_backend_reports_3x_interface_capabilities_by_default() {
    let backend = MockBackend::default_test();
    let versions = backend
        .get_interface_capabilities()
        .interfaces
        .into_iter()
        .map(|interface| {
            (interface.version_major, interface.version_minor, interface.null_functions)
        })
        .collect::<Vec<_>>();

    assert_eq!(versions, vec![(2, 40, Vec::new()), (3, 0, Vec::new()), (3, 2, Vec::new())]);
}

#[test]
fn mock_mechanism_info_uses_source_grounded_workflow_flags() {
    let blake2b_digest_mechanisms = [
        CkMechanismType(0x0000_400C), // CKM_BLAKE2B_160
        CkMechanismType(0x0000_4011), // CKM_BLAKE2B_256
        CkMechanismType(0x0000_4016), // CKM_BLAKE2B_384
        CkMechanismType(0x0000_401B), // CKM_BLAKE2B_512
    ];
    let blake2b_hmac_mechanisms = [
        CkMechanismType(0x0000_400D), // CKM_BLAKE2B_160_HMAC
        CkMechanismType(0x0000_400E), // CKM_BLAKE2B_160_HMAC_GENERAL
        CkMechanismType(0x0000_4012), // CKM_BLAKE2B_256_HMAC
        CkMechanismType(0x0000_4013), // CKM_BLAKE2B_256_HMAC_GENERAL
        CkMechanismType(0x0000_4017), // CKM_BLAKE2B_384_HMAC
        CkMechanismType(0x0000_4018), // CKM_BLAKE2B_384_HMAC_GENERAL
        CkMechanismType(0x0000_401C), // CKM_BLAKE2B_512_HMAC
        CkMechanismType(0x0000_401D), // CKM_BLAKE2B_512_HMAC_GENERAL
    ];
    let blake2b_derive_mechanisms = [
        CkMechanismType(0x0000_400F), // CKM_BLAKE2B_160_KEY_DERIVE
        CkMechanismType(0x0000_4014), // CKM_BLAKE2B_256_KEY_DERIVE
        CkMechanismType(0x0000_4019), // CKM_BLAKE2B_384_KEY_DERIVE
        CkMechanismType(0x0000_401E), // CKM_BLAKE2B_512_KEY_DERIVE
    ];
    let blake2b_key_gen_mechanisms = [
        CkMechanismType(0x0000_4010), // CKM_BLAKE2B_160_KEY_GEN
        CkMechanismType(0x0000_4015), // CKM_BLAKE2B_256_KEY_GEN
        CkMechanismType(0x0000_401A), // CKM_BLAKE2B_384_KEY_GEN
        CkMechanismType(0x0000_401F), // CKM_BLAKE2B_512_KEY_GEN
    ];
    let rsa_hash_sign_verify_mechanisms = [
        CkMechanismType(0x0000_000D), // CKM_RSA_PKCS_PSS
        CkMechanismType(0x0000_0004), // CKM_MD2_RSA_PKCS
        CkMechanismType(0x0000_0005), // CKM_MD5_RSA_PKCS
        CkMechanismType(0x0000_0007), // CKM_RIPEMD128_RSA_PKCS
        CkMechanismType(0x0000_0008), // CKM_RIPEMD160_RSA_PKCS
        CkMechanismType(0x0000_0006), // CKM_SHA1_RSA_PKCS
        CkMechanismType(0x0000_000E), // CKM_SHA1_RSA_PKCS_PSS
        CkMechanismType(0x0000_000C), // CKM_SHA1_RSA_X9_31
        CkMechanismType(0x0000_0046), // CKM_SHA224_RSA_PKCS
        CkMechanismType(0x0000_0047), // CKM_SHA224_RSA_PKCS_PSS
        CkMechanismType(0x0000_0040), // CKM_SHA256_RSA_PKCS
        CkMechanismType(0x0000_0043), // CKM_SHA256_RSA_PKCS_PSS
        CkMechanismType(0x0000_0041), // CKM_SHA384_RSA_PKCS
        CkMechanismType(0x0000_0044), // CKM_SHA384_RSA_PKCS_PSS
        CkMechanismType(0x0000_0042), // CKM_SHA512_RSA_PKCS
        CkMechanismType(0x0000_0045), // CKM_SHA512_RSA_PKCS_PSS
        CkMechanismType(0x0000_0066), // CKM_SHA3_224_RSA_PKCS
        CkMechanismType(0x0000_0067), // CKM_SHA3_224_RSA_PKCS_PSS
        CkMechanismType(0x0000_0060), // CKM_SHA3_256_RSA_PKCS
        CkMechanismType(0x0000_0063), // CKM_SHA3_256_RSA_PKCS_PSS
        CkMechanismType(0x0000_0061), // CKM_SHA3_384_RSA_PKCS
        CkMechanismType(0x0000_0064), // CKM_SHA3_384_RSA_PKCS_PSS
        CkMechanismType(0x0000_0062), // CKM_SHA3_512_RSA_PKCS
        CkMechanismType(0x0000_0065), // CKM_SHA3_512_RSA_PKCS_PSS
    ];
    let dsa_key_pair_gen_mechanisms = [
        CkMechanismType(0x0000_0010), // CKM_DSA_KEY_PAIR_GEN
    ];
    let dsa_parameter_gen_mechanisms = [
        CkMechanismType(0x0000_2000), // CKM_DSA_PARAMETER_GEN
        CkMechanismType(0x0000_2003), // CKM_DSA_PROBABILISTIC_PARAMETER_GEN
        CkMechanismType(0x0000_2004), // CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN
        CkMechanismType(0x0000_2005), // CKM_DSA_FIPS_G_GEN
    ];
    let dsa_sign_verify_mechanisms = [
        CkMechanismType(0x0000_0011), // CKM_DSA
        CkMechanismType(0x0000_0012), // CKM_DSA_SHA1
        CkMechanismType(0x0000_0013), // CKM_DSA_SHA224
        CkMechanismType(0x0000_0014), // CKM_DSA_SHA256
        CkMechanismType(0x0000_0015), // CKM_DSA_SHA384
        CkMechanismType(0x0000_0016), // CKM_DSA_SHA512
        CkMechanismType(0x0000_0018), // CKM_DSA_SHA3_224
        CkMechanismType(0x0000_0019), // CKM_DSA_SHA3_256
        CkMechanismType(0x0000_001A), // CKM_DSA_SHA3_384
        CkMechanismType(0x0000_001B), // CKM_DSA_SHA3_512
    ];
    let pq_dsa_key_pair_gen_mechanisms = [
        CkMechanismType(0x0000_001C), // CKM_ML_DSA_KEY_PAIR_GEN
        CkMechanismType(0x0000_002D), // CKM_SLH_DSA_KEY_PAIR_GEN
    ];
    let pq_dsa_sign_verify_mechanisms = [
        CkMechanismType(0x0000_001D), // CKM_ML_DSA
        CkMechanismType(0x0000_001F), // CKM_HASH_ML_DSA
        CkMechanismType(0x0000_0023), // CKM_HASH_ML_DSA_SHA224
        CkMechanismType(0x0000_0024), // CKM_HASH_ML_DSA_SHA256
        CkMechanismType(0x0000_0025), // CKM_HASH_ML_DSA_SHA384
        CkMechanismType(0x0000_0026), // CKM_HASH_ML_DSA_SHA512
        CkMechanismType(0x0000_0027), // CKM_HASH_ML_DSA_SHA3_224
        CkMechanismType(0x0000_0028), // CKM_HASH_ML_DSA_SHA3_256
        CkMechanismType(0x0000_0029), // CKM_HASH_ML_DSA_SHA3_384
        CkMechanismType(0x0000_002A), // CKM_HASH_ML_DSA_SHA3_512
        CkMechanismType(0x0000_002B), // CKM_HASH_ML_DSA_SHAKE128
        CkMechanismType(0x0000_002C), // CKM_HASH_ML_DSA_SHAKE256
        CkMechanismType(0x0000_002E), // CKM_SLH_DSA
        CkMechanismType(0x0000_0034), // CKM_HASH_SLH_DSA
        CkMechanismType(0x0000_0036), // CKM_HASH_SLH_DSA_SHA224
        CkMechanismType(0x0000_0037), // CKM_HASH_SLH_DSA_SHA256
        CkMechanismType(0x0000_0038), // CKM_HASH_SLH_DSA_SHA384
        CkMechanismType(0x0000_0039), // CKM_HASH_SLH_DSA_SHA512
        CkMechanismType(0x0000_003A), // CKM_HASH_SLH_DSA_SHA3_224
        CkMechanismType(0x0000_003B), // CKM_HASH_SLH_DSA_SHA3_256
        CkMechanismType(0x0000_003C), // CKM_HASH_SLH_DSA_SHA3_384
        CkMechanismType(0x0000_003D), // CKM_HASH_SLH_DSA_SHA3_512
        CkMechanismType(0x0000_003E), // CKM_HASH_SLH_DSA_SHAKE128
        CkMechanismType(0x0000_003F), // CKM_HASH_SLH_DSA_SHAKE256
    ];
    let sha_digest_mechanisms = [
        CkMechanismType::MD2,
        CkMechanismType::MD5,
        CkMechanismType(0x0000_0220), // CKM_SHA_1
        CkMechanismType(0x0000_0255), // CKM_SHA224
        CkMechanismType(0x0000_0250), // CKM_SHA256
        CkMechanismType(0x0000_0260), // CKM_SHA384
        CkMechanismType(0x0000_0270), // CKM_SHA512
        CkMechanismType(0x0000_0048), // CKM_SHA512_224
        CkMechanismType(0x0000_004C), // CKM_SHA512_256
        CkMechanismType(0x0000_0050), // CKM_SHA512_T
    ];
    let sha_hmac_mechanisms = [
        CkMechanismType(0x0000_0221), // CKM_SHA_1_HMAC
        CkMechanismType(0x0000_0222), // CKM_SHA_1_HMAC_GENERAL
        CkMechanismType(0x0000_0256), // CKM_SHA224_HMAC
        CkMechanismType(0x0000_0257), // CKM_SHA224_HMAC_GENERAL
        CkMechanismType(0x0000_0251), // CKM_SHA256_HMAC
        CkMechanismType(0x0000_0252), // CKM_SHA256_HMAC_GENERAL
        CkMechanismType(0x0000_0261), // CKM_SHA384_HMAC
        CkMechanismType(0x0000_0262), // CKM_SHA384_HMAC_GENERAL
        CkMechanismType(0x0000_0271), // CKM_SHA512_HMAC
        CkMechanismType(0x0000_0272), // CKM_SHA512_HMAC_GENERAL
        CkMechanismType(0x0000_0049), // CKM_SHA512_224_HMAC
        CkMechanismType(0x0000_004A), // CKM_SHA512_224_HMAC_GENERAL
        CkMechanismType(0x0000_004D), // CKM_SHA512_256_HMAC
        CkMechanismType(0x0000_004E), // CKM_SHA512_256_HMAC_GENERAL
        CkMechanismType(0x0000_0051), // CKM_SHA512_T_HMAC
        CkMechanismType(0x0000_0052), // CKM_SHA512_T_HMAC_GENERAL
    ];
    let sha_derive_mechanisms = [
        CkMechanismType(0x0000_0392), // CKM_SHA1_KEY_DERIVATION
        CkMechanismType(0x0000_0396), // CKM_SHA224_KEY_DERIVATION
        CkMechanismType(0x0000_0393), // CKM_SHA256_KEY_DERIVATION
        CkMechanismType(0x0000_0394), // CKM_SHA384_KEY_DERIVATION
        CkMechanismType(0x0000_0395), // CKM_SHA512_KEY_DERIVATION
        CkMechanismType(0x0000_004B), // CKM_SHA512_224_KEY_DERIVATION
        CkMechanismType(0x0000_004F), // CKM_SHA512_256_KEY_DERIVATION
        CkMechanismType(0x0000_0053), // CKM_SHA512_T_KEY_DERIVATION
    ];
    let sha_key_gen_mechanisms = [
        CkMechanismType(0x0000_4003), // CKM_SHA_1_KEY_GEN
        CkMechanismType(0x0000_4004), // CKM_SHA224_KEY_GEN
        CkMechanismType(0x0000_4005), // CKM_SHA256_KEY_GEN
        CkMechanismType(0x0000_4006), // CKM_SHA384_KEY_GEN
        CkMechanismType(0x0000_4007), // CKM_SHA512_KEY_GEN
        CkMechanismType(0x0000_4008), // CKM_SHA512_224_KEY_GEN
        CkMechanismType(0x0000_4009), // CKM_SHA512_256_KEY_GEN
        CkMechanismType(0x0000_400A), // CKM_SHA512_T_KEY_GEN
    ];
    let sha3_digest_mechanisms = [
        CkMechanismType(0x0000_02B5), // CKM_SHA3_224
        CkMechanismType(0x0000_02B0), // CKM_SHA3_256
        CkMechanismType(0x0000_02C0), // CKM_SHA3_384
        CkMechanismType(0x0000_02D0), // CKM_SHA3_512
    ];
    let sha3_hmac_mechanisms = [
        CkMechanismType(0x0000_02B6), // CKM_SHA3_224_HMAC
        CkMechanismType(0x0000_02B7), // CKM_SHA3_224_HMAC_GENERAL
        CkMechanismType(0x0000_02B1), // CKM_SHA3_256_HMAC
        CkMechanismType(0x0000_02B2), // CKM_SHA3_256_HMAC_GENERAL
        CkMechanismType(0x0000_02C1), // CKM_SHA3_384_HMAC
        CkMechanismType(0x0000_02C2), // CKM_SHA3_384_HMAC_GENERAL
        CkMechanismType(0x0000_02D1), // CKM_SHA3_512_HMAC
        CkMechanismType(0x0000_02D2), // CKM_SHA3_512_HMAC_GENERAL
    ];
    let sha3_derive_mechanisms = [
        CkMechanismType(0x0000_0398), // CKM_SHA3_224_KEY_DERIVATION
        CkMechanismType(0x0000_0397), // CKM_SHA3_256_KEY_DERIVATION
        CkMechanismType(0x0000_0399), // CKM_SHA3_384_KEY_DERIVATION
        CkMechanismType(0x0000_039A), // CKM_SHA3_512_KEY_DERIVATION
    ];
    let sha3_key_gen_mechanisms = [
        CkMechanismType(0x0000_02B8), // CKM_SHA3_224_KEY_GEN
        CkMechanismType(0x0000_02B3), // CKM_SHA3_256_KEY_GEN
        CkMechanismType(0x0000_02C3), // CKM_SHA3_384_KEY_GEN
        CkMechanismType(0x0000_02D3), // CKM_SHA3_512_KEY_GEN
    ];
    let sp800_108_derive_mechanisms = [
        CkMechanismType(0x0000_03AC), // CKM_SP800_108_COUNTER_KDF
        CkMechanismType(0x0000_03AD), // CKM_SP800_108_FEEDBACK_KDF
        CkMechanismType(0x0000_03AE), // CKM_SP800_108_DOUBLE_PIPELINE_KDF
    ];
    let aes_encrypt_wrap_mechanisms = [
        CkMechanismType::AES_CBC,
        CkMechanismType::AES_CBC_PAD,
        CkMechanismType::AES_CTR,
        CkMechanismType::AES_CTS,
        CkMechanismType::AES_XTS,
        CkMechanismType::AES_OFB,
        CkMechanismType::AES_CFB64,
        CkMechanismType::AES_CFB8,
        CkMechanismType::AES_CFB128,
        CkMechanismType::AES_CFB1,
        CkMechanismType::AES_KEY_WRAP,
        CkMechanismType::AES_KEY_WRAP_PAD,
        CkMechanismType::AES_KEY_WRAP_KWP,
        CkMechanismType::AES_KEY_WRAP_PKCS7,
    ];
    let aes_sign_verify_mechanisms = [
        CkMechanismType::AES_MAC,
        CkMechanismType::AES_MAC_GENERAL,
        CkMechanismType::AES_CMAC,
        CkMechanismType::AES_CMAC_GENERAL,
        CkMechanismType::AES_XCBC_MAC,
        CkMechanismType::AES_XCBC_MAC_96,
        CkMechanismType::AES_GMAC,
    ];
    let aes_generate_mechanisms = [CkMechanismType::AES_XTS_KEY_GEN];
    let aes_message_encrypt_decrypt_mechanisms = [CkMechanismType::AES_CCM];
    let salsa_chacha_encrypt_wrap_mechanisms =
        [CkMechanismType::CHACHA20, CkMechanismType::SALSA20];
    let salsa_chacha_generate_mechanisms =
        [CkMechanismType::CHACHA20_KEY_GEN, CkMechanismType::SALSA20_KEY_GEN];
    let salsa_chacha_aead_message_mechanisms =
        [CkMechanismType::CHACHA20_POLY1305, CkMechanismType::SALSA20_POLY1305];
    let poly1305_sign_verify_mechanisms = [CkMechanismType::POLY1305];
    let poly1305_generate_mechanisms = [CkMechanismType::POLY1305_KEY_GEN];
    let aria_camellia_seed_encrypt_wrap_mechanisms = [
        CkMechanismType::ARIA_ECB,
        CkMechanismType::ARIA_CBC,
        CkMechanismType::ARIA_CBC_PAD,
        CkMechanismType::CAMELLIA_ECB,
        CkMechanismType::CAMELLIA_CBC,
        CkMechanismType::CAMELLIA_CBC_PAD,
        CkMechanismType::SEED_ECB,
        CkMechanismType::SEED_CBC,
        CkMechanismType::SEED_CBC_PAD,
    ];
    let aria_camellia_seed_sign_verify_mechanisms = [
        CkMechanismType::ARIA_MAC,
        CkMechanismType::ARIA_MAC_GENERAL,
        CkMechanismType::CAMELLIA_MAC,
        CkMechanismType::CAMELLIA_MAC_GENERAL,
        CkMechanismType::SEED_MAC,
        CkMechanismType::SEED_MAC_GENERAL,
    ];
    let aria_camellia_seed_generate_mechanisms = [
        CkMechanismType::ARIA_KEY_GEN,
        CkMechanismType::CAMELLIA_KEY_GEN,
        CkMechanismType::SEED_KEY_GEN,
    ];
    let aria_camellia_seed_derive_mechanisms = [
        CkMechanismType::ARIA_ECB_ENCRYPT_DATA,
        CkMechanismType::ARIA_CBC_ENCRYPT_DATA,
        CkMechanismType::CAMELLIA_ECB_ENCRYPT_DATA,
        CkMechanismType::CAMELLIA_CBC_ENCRYPT_DATA,
        CkMechanismType::SEED_ECB_ENCRYPT_DATA,
        CkMechanismType::SEED_CBC_ENCRYPT_DATA,
    ];
    let des_family_encrypt_wrap_mechanisms =
        [CkMechanismType::DES3_ECB, CkMechanismType::DES3_CBC, CkMechanismType::DES3_CBC_PAD];
    let des_family_encrypt_only_mechanisms = [
        CkMechanismType::DES_ECB,
        CkMechanismType::DES_CBC_PAD,
        CkMechanismType::DES_OFB64,
        CkMechanismType::DES_OFB8,
        CkMechanismType::DES_CFB64,
        CkMechanismType::DES_CFB8,
    ];
    let des_family_sign_verify_mechanisms = [
        CkMechanismType::DES_MAC,
        CkMechanismType::DES3_MAC,
        CkMechanismType::DES3_MAC_GENERAL,
        CkMechanismType::DES3_CMAC,
        CkMechanismType::DES3_CMAC_GENERAL,
    ];
    let des_family_generate_mechanisms = [
        CkMechanismType::DES_KEY_GEN,
        CkMechanismType::DES2_KEY_GEN,
        CkMechanismType::DES3_KEY_GEN,
    ];
    let des_family_derive_mechanisms = [
        CkMechanismType::DES_ECB_ENCRYPT_DATA,
        CkMechanismType::DES_CBC_ENCRYPT_DATA,
        CkMechanismType::DES3_ECB_ENCRYPT_DATA,
        CkMechanismType::DES3_CBC_ENCRYPT_DATA,
    ];
    let ec_sign_verify_mechanisms = [
        CkMechanismType::ECDSA,
        CkMechanismType::ECDSA_SHA1,
        CkMechanismType::ECDSA_SHA224,
        CkMechanismType::ECDSA_SHA256,
        CkMechanismType::ECDSA_SHA384,
        CkMechanismType::ECDSA_SHA512,
        CkMechanismType::ECDSA_SHA3_224,
        CkMechanismType::ECDSA_SHA3_256,
        CkMechanismType::ECDSA_SHA3_384,
        CkMechanismType::ECDSA_SHA3_512,
        CkMechanismType::EDDSA,
        CkMechanismType::XEDDSA,
    ];
    let ec_generate_key_pair_mechanisms = [
        CkMechanismType::EC_KEY_PAIR_GEN,
        CkMechanismType::EC_EDWARDS_KEY_PAIR_GEN,
        CkMechanismType::EC_MONTGOMERY_KEY_PAIR_GEN,
    ];
    let ec_generate_and_generate_key_pair_mechanisms =
        [CkMechanismType::EC_KEY_PAIR_GEN_W_EXTRA_BITS];
    let ec_derive_encapsulate_mechanisms =
        [CkMechanismType::ECDH1_DERIVE, CkMechanismType::ECDH1_COFACTOR_DERIVE];
    let ec_derive_mechanisms = [CkMechanismType::ECMQV_DERIVE];
    let ec_wrap_unwrap_mechanisms = [
        CkMechanismType::ECDH_AES_KEY_WRAP,
        CkMechanismType::ECDH_COF_AES_KEY_WRAP,
        CkMechanismType::ECDH_X_AES_KEY_WRAP,
    ];
    let dh_key_pair_gen_mechanisms =
        [CkMechanismType::DH_PKCS_KEY_PAIR_GEN, CkMechanismType::X9_42_DH_KEY_PAIR_GEN];
    let dh_generate_and_generate_key_pair_mechanisms =
        [CkMechanismType::DH_PKCS_PARAMETER_GEN, CkMechanismType::X9_42_DH_PARAMETER_GEN];
    let dh_derive_encapsulate_mechanisms =
        [CkMechanismType::DH_PKCS_DERIVE, CkMechanismType::X9_42_DH_DERIVE];
    let dh_derive_mechanisms =
        [CkMechanismType::X9_42_DH_HYBRID_DERIVE, CkMechanismType::X9_42_MQV_DERIVE];
    let remaining_key_pair_gen_mechanisms =
        [CkMechanismType::RSA_X9_31_KEY_PAIR_GEN, CkMechanismType::GOSTR3410_KEY_PAIR_GEN];
    let remaining_generate_mechanisms = [
        CkMechanismType::PBE_SHA1_DES3_EDE_CBC,
        CkMechanismType::PBE_SHA1_DES2_EDE_CBC,
        CkMechanismType::PKCS5_PBKD2,
        CkMechanismType::PBA_SHA1_WITH_SHA1_HMAC,
        CkMechanismType::GOST28147_KEY_GEN,
    ];
    let remaining_digest_mechanisms = [CkMechanismType::GOSTR3411];
    let remaining_sign_verify_mechanisms = [
        CkMechanismType::RSA_X9_31,
        CkMechanismType::GOSTR3410,
        CkMechanismType::GOSTR3410_WITH_GOSTR3411,
        CkMechanismType::GOSTR3411_HMAC,
        CkMechanismType::GOST28147_MAC,
    ];
    let remaining_sign_recover_verify_recover_mechanisms =
        [CkMechanismType::RSA_9796, CkMechanismType::CMS_SIG];
    let remaining_encrypt_wrap_mechanisms = [
        CkMechanismType::RSA_PKCS_TPM_1_1,
        CkMechanismType::RSA_PKCS_OAEP_TPM_1_1,
        CkMechanismType::GOST28147_ECB,
        CkMechanismType::GOST28147,
        CkMechanismType::X2RATCHET_ENCRYPT,
        CkMechanismType::X2RATCHET_DECRYPT,
    ];
    let remaining_wrap_mechanisms = [
        CkMechanismType::RSA_AES_KEY_WRAP,
        CkMechanismType::GOSTR3410_KEY_WRAP,
        CkMechanismType::GOST28147_KEY_WRAP,
    ];
    let remaining_derive_mechanisms = [
        CkMechanismType::GOSTR3410_DERIVE,
        CkMechanismType::X3DH_INITIALIZE,
        CkMechanismType::X3DH_RESPOND,
        CkMechanismType::X2RATCHET_INITIALIZE,
        CkMechanismType::X2RATCHET_RESPOND,
    ];
    let blowfish_twofish_generate_mechanisms =
        [CkMechanismType::BLOWFISH_KEY_GEN, CkMechanismType::TWOFISH_KEY_GEN];
    let blowfish_twofish_encrypt_wrap_mechanisms = [
        CkMechanismType::BLOWFISH_CBC,
        CkMechanismType::BLOWFISH_CBC_PAD,
        CkMechanismType::TWOFISH_CBC,
        CkMechanismType::TWOFISH_CBC_PAD,
    ];
    let simple_key_generate_mechanisms = [CkMechanismType::GENERIC_SECRET_KEY_GEN];
    let simple_key_derive_mechanisms = [
        CkMechanismType::CONCATENATE_BASE_AND_KEY,
        CkMechanismType::CONCATENATE_BASE_AND_DATA,
        CkMechanismType::CONCATENATE_DATA_AND_BASE,
        CkMechanismType::XOR_BASE_AND_DATA,
        CkMechanismType::EXTRACT_KEY_FROM_KEY,
        CkMechanismType::PUB_KEY_FROM_PRIV_KEY,
    ];
    let hkdf_generate_mechanisms = [CkMechanismType::HKDF_KEY_GEN];
    let hkdf_derive_mechanisms = [CkMechanismType::HKDF_DERIVE, CkMechanismType::HKDF_DATA];
    let kip_derive_mechanisms = [CkMechanismType::KIP_DERIVE];
    let kip_wrap_mechanisms = [CkMechanismType::KIP_WRAP];
    let kip_sign_mechanisms = [CkMechanismType::KIP_MAC];
    let ike_derive_mechanisms = [
        CkMechanismType::IKE2_PRF_PLUS_DERIVE,
        CkMechanismType::IKE_PRF_DERIVE,
        CkMechanismType::IKE1_PRF_DERIVE,
        CkMechanismType::IKE1_EXTENDED_DERIVE,
    ];
    let shake_key_derivation_mechanisms =
        [CkMechanismType::SHAKE_128_KEY_DERIVATION, CkMechanismType::SHAKE_256_KEY_DERIVATION];
    let otp_generate_mechanisms = [CkMechanismType::SECURID_KEY_GEN, CkMechanismType::HOTP_KEY_GEN];
    let otp_sign_mechanisms = [CkMechanismType::SECURID, CkMechanismType::HOTP];
    let stateful_hash_key_pair_gen_mechanisms = [
        CkMechanismType::HSS_KEY_PAIR_GEN,
        CkMechanismType::XMSS_KEY_PAIR_GEN,
        CkMechanismType::XMSSMT_KEY_PAIR_GEN,
    ];
    let stateful_hash_sign_mechanisms =
        [CkMechanismType::HSS, CkMechanismType::XMSS, CkMechanismType::XMSSMT];
    let tls_ssl_wtls_generate_mechanisms = [
        CkMechanismType::SSL3_PRE_MASTER_KEY_GEN,
        CkMechanismType::TLS_PRE_MASTER_KEY_GEN,
        CkMechanismType::WTLS_PRE_MASTER_KEY_GEN,
    ];
    let tls_ssl_wtls_sign_mechanisms = [
        CkMechanismType::SSL3_MD5_MAC,
        CkMechanismType::SSL3_SHA1_MAC,
        CkMechanismType::TLS_MAC,
        CkMechanismType::TLS12_MAC,
    ];
    let tls_ssl_wtls_derive_mechanisms = [
        CkMechanismType::TLS12_EXTENDED_MASTER_KEY_DERIVE,
        CkMechanismType::TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
        CkMechanismType::SSL3_MASTER_KEY_DERIVE,
        CkMechanismType::SSL3_KEY_AND_MAC_DERIVE,
        CkMechanismType::SSL3_MASTER_KEY_DERIVE_DH,
        CkMechanismType::WTLS_MASTER_KEY_DERIVE,
        CkMechanismType::WTLS_MASTER_KEY_DERIVE_DH_ECC,
        CkMechanismType::WTLS_PRF,
        CkMechanismType::WTLS_SERVER_KEY_AND_MAC_DERIVE,
        CkMechanismType::WTLS_CLIENT_KEY_AND_MAC_DERIVE,
        CkMechanismType::TLS12_KDF,
        CkMechanismType::TLS12_MASTER_KEY_DERIVE,
        CkMechanismType::TLS12_KEY_AND_MAC_DERIVE,
        CkMechanismType::TLS12_MASTER_KEY_DERIVE_DH,
        CkMechanismType::TLS12_KEY_SAFE_DERIVE,
        CkMechanismType::TLS_PRF,
        CkMechanismType::TLS_KDF,
    ];

    let mut mechanisms = vec![
        CkMechanismType::RSA_PKCS_KEY_PAIR_GEN,
        CkMechanismType::RSA_PKCS,
        CkMechanismType::RSA_PKCS_OAEP,
        CkMechanismType::SHA256,
        CkMechanismType::AES_KEY_GEN,
        CkMechanismType::AES_ECB,
        CkMechanismType::AES_GCM,
        CkMechanismType(0x0000_000F), // CKM_ML_KEM_KEY_PAIR_GEN
        CkMechanismType(0x0000_0017), // CKM_ML_KEM
        CkMechanismType(0x0000_02A0), // CKM_ACTI
        CkMechanismType(0x0000_02A1), // CKM_ACTI_KEY_GEN
    ];
    mechanisms.extend(blake2b_digest_mechanisms.iter().copied());
    mechanisms.extend(blake2b_hmac_mechanisms.iter().copied());
    mechanisms.extend(blake2b_derive_mechanisms.iter().copied());
    mechanisms.extend(blake2b_key_gen_mechanisms.iter().copied());
    mechanisms.extend(rsa_hash_sign_verify_mechanisms.iter().copied());
    mechanisms.extend(dsa_key_pair_gen_mechanisms.iter().copied());
    mechanisms.extend(dsa_parameter_gen_mechanisms.iter().copied());
    mechanisms.extend(dsa_sign_verify_mechanisms.iter().copied());
    mechanisms.extend(pq_dsa_key_pair_gen_mechanisms.iter().copied());
    mechanisms.extend(pq_dsa_sign_verify_mechanisms.iter().copied());
    mechanisms.extend(sha_digest_mechanisms.iter().copied());
    mechanisms.extend(sha_hmac_mechanisms.iter().copied());
    mechanisms.extend(sha_derive_mechanisms.iter().copied());
    mechanisms.extend(sha_key_gen_mechanisms.iter().copied());
    mechanisms.extend(sha3_digest_mechanisms.iter().copied());
    mechanisms.extend(sha3_hmac_mechanisms.iter().copied());
    mechanisms.extend(sha3_derive_mechanisms.iter().copied());
    mechanisms.extend(sha3_key_gen_mechanisms.iter().copied());
    mechanisms.extend(sp800_108_derive_mechanisms.iter().copied());
    mechanisms.extend(aes_encrypt_wrap_mechanisms.iter().copied());
    mechanisms.extend(aes_sign_verify_mechanisms.iter().copied());
    mechanisms.extend(aes_generate_mechanisms.iter().copied());
    mechanisms.extend(aes_message_encrypt_decrypt_mechanisms.iter().copied());
    mechanisms.extend(salsa_chacha_encrypt_wrap_mechanisms.iter().copied());
    mechanisms.extend(salsa_chacha_generate_mechanisms.iter().copied());
    mechanisms.extend(salsa_chacha_aead_message_mechanisms.iter().copied());
    mechanisms.extend(poly1305_sign_verify_mechanisms.iter().copied());
    mechanisms.extend(poly1305_generate_mechanisms.iter().copied());
    mechanisms.extend(aria_camellia_seed_encrypt_wrap_mechanisms.iter().copied());
    mechanisms.extend(aria_camellia_seed_sign_verify_mechanisms.iter().copied());
    mechanisms.extend(aria_camellia_seed_generate_mechanisms.iter().copied());
    mechanisms.extend(aria_camellia_seed_derive_mechanisms.iter().copied());
    mechanisms.extend(des_family_encrypt_wrap_mechanisms.iter().copied());
    mechanisms.extend(des_family_encrypt_only_mechanisms.iter().copied());
    mechanisms.extend(des_family_sign_verify_mechanisms.iter().copied());
    mechanisms.extend(des_family_generate_mechanisms.iter().copied());
    mechanisms.extend(des_family_derive_mechanisms.iter().copied());
    mechanisms.extend(ec_sign_verify_mechanisms.iter().copied());
    mechanisms.extend(ec_generate_key_pair_mechanisms.iter().copied());
    mechanisms.extend(ec_generate_and_generate_key_pair_mechanisms.iter().copied());
    mechanisms.extend(ec_derive_encapsulate_mechanisms.iter().copied());
    mechanisms.extend(ec_derive_mechanisms.iter().copied());
    mechanisms.extend(ec_wrap_unwrap_mechanisms.iter().copied());
    mechanisms.extend(dh_key_pair_gen_mechanisms.iter().copied());
    mechanisms.extend(dh_generate_and_generate_key_pair_mechanisms.iter().copied());
    mechanisms.extend(dh_derive_encapsulate_mechanisms.iter().copied());
    mechanisms.extend(dh_derive_mechanisms.iter().copied());
    mechanisms.extend(remaining_key_pair_gen_mechanisms.iter().copied());
    mechanisms.extend(remaining_generate_mechanisms.iter().copied());
    mechanisms.extend(remaining_digest_mechanisms.iter().copied());
    mechanisms.extend(remaining_sign_verify_mechanisms.iter().copied());
    mechanisms.extend(remaining_sign_recover_verify_recover_mechanisms.iter().copied());
    mechanisms.extend(remaining_encrypt_wrap_mechanisms.iter().copied());
    mechanisms.extend(remaining_wrap_mechanisms.iter().copied());
    mechanisms.extend(remaining_derive_mechanisms.iter().copied());
    mechanisms.push(CkMechanismType::NULL);
    mechanisms.extend(blowfish_twofish_generate_mechanisms.iter().copied());
    mechanisms.extend(blowfish_twofish_encrypt_wrap_mechanisms.iter().copied());
    mechanisms.extend(simple_key_generate_mechanisms.iter().copied());
    mechanisms.extend(simple_key_derive_mechanisms.iter().copied());
    mechanisms.extend(hkdf_generate_mechanisms.iter().copied());
    mechanisms.extend(hkdf_derive_mechanisms.iter().copied());
    mechanisms.extend(kip_derive_mechanisms.iter().copied());
    mechanisms.extend(kip_wrap_mechanisms.iter().copied());
    mechanisms.extend(kip_sign_mechanisms.iter().copied());
    mechanisms.extend(ike_derive_mechanisms.iter().copied());
    mechanisms.extend(shake_key_derivation_mechanisms.iter().copied());
    mechanisms.extend(otp_generate_mechanisms.iter().copied());
    mechanisms.extend(otp_sign_mechanisms.iter().copied());
    mechanisms.extend(stateful_hash_key_pair_gen_mechanisms.iter().copied());
    mechanisms.extend(stateful_hash_sign_mechanisms.iter().copied());
    mechanisms.extend(tls_ssl_wtls_generate_mechanisms.iter().copied());
    mechanisms.extend(tls_ssl_wtls_sign_mechanisms.iter().copied());
    mechanisms.extend(tls_ssl_wtls_derive_mechanisms.iter().copied());
    let backend = MockBackend::new(vec![CkSlotId(0)], mechanisms);

    let mut cases = vec![
        (CkMechanismType::SHA256, CkMechanismFlags::DIGEST),
        (CkMechanismType::AES_KEY_GEN, CkMechanismFlags::GENERATE),
        (CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, CkMechanismFlags::GENERATE_KEY_PAIR),
        (
            CkMechanismType::AES_ECB,
            CkMechanismFlags::ENCRYPT
                | CkMechanismFlags::DECRYPT
                | CkMechanismFlags::WRAP
                | CkMechanismFlags::UNWRAP,
        ),
        (
            CkMechanismType::AES_GCM,
            CkMechanismFlags::MESSAGE_ENCRYPT
                | CkMechanismFlags::MESSAGE_DECRYPT
                | CkMechanismFlags::ENCRYPT
                | CkMechanismFlags::DECRYPT
                | CkMechanismFlags::WRAP
                | CkMechanismFlags::UNWRAP,
        ),
        (CkMechanismType(0x0000_000F), CkMechanismFlags::GENERATE_KEY_PAIR),
        (
            CkMechanismType(0x0000_0017),
            CkMechanismFlags::ENCAPSULATE | CkMechanismFlags::DECAPSULATE,
        ),
        (CkMechanismType(0x0000_02A0), CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY),
        (CkMechanismType(0x0000_02A1), CkMechanismFlags::GENERATE),
        (
            CkMechanismType::RSA_PKCS_OAEP,
            CkMechanismFlags::ENCAPSULATE
                | CkMechanismFlags::DECAPSULATE
                | CkMechanismFlags::ENCRYPT
                | CkMechanismFlags::DECRYPT
                | CkMechanismFlags::WRAP
                | CkMechanismFlags::UNWRAP,
        ),
        (
            CkMechanismType::RSA_PKCS,
            CkMechanismFlags::ENCAPSULATE
                | CkMechanismFlags::DECAPSULATE
                | CkMechanismFlags::ENCRYPT
                | CkMechanismFlags::DECRYPT
                | CkMechanismFlags::SIGN
                | CkMechanismFlags::SIGN_RECOVER
                | CkMechanismFlags::VERIFY
                | CkMechanismFlags::VERIFY_RECOVER
                | CkMechanismFlags::WRAP
                | CkMechanismFlags::UNWRAP,
        ),
    ];
    cases.extend(
        blake2b_digest_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::DIGEST)),
    );
    cases.extend(
        blake2b_hmac_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        blake2b_derive_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.extend(
        blake2b_key_gen_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(
        rsa_hash_sign_verify_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        dsa_key_pair_gen_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE_KEY_PAIR)),
    );
    cases.extend(dsa_parameter_gen_mechanisms.into_iter().map(|mechanism| {
        (mechanism, CkMechanismFlags::GENERATE | CkMechanismFlags::GENERATE_KEY_PAIR)
    }));
    cases.extend(
        dsa_sign_verify_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        pq_dsa_key_pair_gen_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE_KEY_PAIR)),
    );
    cases.extend(
        pq_dsa_sign_verify_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        sha_digest_mechanisms.into_iter().map(|mechanism| (mechanism, CkMechanismFlags::DIGEST)),
    );
    cases.extend(
        sha_hmac_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        sha_derive_mechanisms.into_iter().map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.extend(
        sha_key_gen_mechanisms.into_iter().map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(
        sha3_digest_mechanisms.into_iter().map(|mechanism| (mechanism, CkMechanismFlags::DIGEST)),
    );
    cases.extend(
        sha3_hmac_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        sha3_derive_mechanisms.into_iter().map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.extend(
        sha3_key_gen_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(
        sp800_108_derive_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.extend(aes_encrypt_wrap_mechanisms.into_iter().map(|mechanism| {
        (
            mechanism,
            CkMechanismFlags::ENCRYPT
                | CkMechanismFlags::DECRYPT
                | CkMechanismFlags::WRAP
                | CkMechanismFlags::UNWRAP,
        )
    }));
    cases.extend(
        aes_sign_verify_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        aes_generate_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(aes_message_encrypt_decrypt_mechanisms.into_iter().map(|mechanism| {
        (
            mechanism,
            CkMechanismFlags::MESSAGE_ENCRYPT
                | CkMechanismFlags::MESSAGE_DECRYPT
                | CkMechanismFlags::ENCRYPT
                | CkMechanismFlags::DECRYPT
                | CkMechanismFlags::WRAP
                | CkMechanismFlags::UNWRAP,
        )
    }));
    cases.extend(salsa_chacha_encrypt_wrap_mechanisms.into_iter().map(|mechanism| {
        (
            mechanism,
            CkMechanismFlags::ENCRYPT
                | CkMechanismFlags::DECRYPT
                | CkMechanismFlags::WRAP
                | CkMechanismFlags::UNWRAP,
        )
    }));
    cases.extend(
        salsa_chacha_generate_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(salsa_chacha_aead_message_mechanisms.into_iter().map(|mechanism| {
        (
            mechanism,
            CkMechanismFlags::MESSAGE_ENCRYPT
                | CkMechanismFlags::MESSAGE_DECRYPT
                | CkMechanismFlags::ENCRYPT
                | CkMechanismFlags::DECRYPT,
        )
    }));
    cases.extend(
        poly1305_sign_verify_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        poly1305_generate_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(aria_camellia_seed_encrypt_wrap_mechanisms.into_iter().map(|mechanism| {
        (
            mechanism,
            CkMechanismFlags::ENCRYPT
                | CkMechanismFlags::DECRYPT
                | CkMechanismFlags::WRAP
                | CkMechanismFlags::UNWRAP,
        )
    }));
    cases.extend(
        aria_camellia_seed_sign_verify_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        aria_camellia_seed_generate_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(
        aria_camellia_seed_derive_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.extend(des_family_encrypt_wrap_mechanisms.into_iter().map(|mechanism| {
        (
            mechanism,
            CkMechanismFlags::ENCRYPT
                | CkMechanismFlags::DECRYPT
                | CkMechanismFlags::WRAP
                | CkMechanismFlags::UNWRAP,
        )
    }));
    cases.extend(
        des_family_encrypt_only_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::ENCRYPT | CkMechanismFlags::DECRYPT)),
    );
    cases.extend(
        des_family_sign_verify_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        des_family_generate_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(
        des_family_derive_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.extend(
        ec_sign_verify_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        ec_generate_key_pair_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE_KEY_PAIR)),
    );
    cases.extend(ec_generate_and_generate_key_pair_mechanisms.into_iter().map(|mechanism| {
        (mechanism, CkMechanismFlags::GENERATE | CkMechanismFlags::GENERATE_KEY_PAIR)
    }));
    cases.extend(ec_derive_encapsulate_mechanisms.into_iter().map(|mechanism| {
        (
            mechanism,
            CkMechanismFlags::DERIVE
                | CkMechanismFlags::ENCAPSULATE
                | CkMechanismFlags::DECAPSULATE,
        )
    }));
    cases.extend(
        ec_derive_mechanisms.into_iter().map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.extend(
        ec_wrap_unwrap_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::WRAP | CkMechanismFlags::UNWRAP)),
    );
    cases.extend(
        dh_key_pair_gen_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE_KEY_PAIR)),
    );
    cases.extend(dh_generate_and_generate_key_pair_mechanisms.into_iter().map(|mechanism| {
        (mechanism, CkMechanismFlags::GENERATE | CkMechanismFlags::GENERATE_KEY_PAIR)
    }));
    cases.extend(dh_derive_encapsulate_mechanisms.into_iter().map(|mechanism| {
        (
            mechanism,
            CkMechanismFlags::DERIVE
                | CkMechanismFlags::ENCAPSULATE
                | CkMechanismFlags::DECAPSULATE,
        )
    }));
    cases.extend(
        dh_derive_mechanisms.into_iter().map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.extend(
        remaining_key_pair_gen_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE_KEY_PAIR)),
    );
    cases.extend(
        remaining_generate_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(
        remaining_digest_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::DIGEST)),
    );
    cases.extend(
        remaining_sign_verify_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(remaining_sign_recover_verify_recover_mechanisms.into_iter().map(|mechanism| {
        (
            mechanism,
            CkMechanismFlags::SIGN
                | CkMechanismFlags::VERIFY
                | CkMechanismFlags::SIGN_RECOVER
                | CkMechanismFlags::VERIFY_RECOVER,
        )
    }));
    cases.extend(remaining_encrypt_wrap_mechanisms.into_iter().map(|mechanism| {
        (
            mechanism,
            CkMechanismFlags::ENCRYPT
                | CkMechanismFlags::DECRYPT
                | CkMechanismFlags::WRAP
                | CkMechanismFlags::UNWRAP,
        )
    }));
    cases.extend(
        remaining_wrap_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::WRAP | CkMechanismFlags::UNWRAP)),
    );
    cases.extend(
        remaining_derive_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.push((
        CkMechanismType::NULL,
        CkMechanismFlags::ENCRYPT
            | CkMechanismFlags::DECRYPT
            | CkMechanismFlags::SIGN
            | CkMechanismFlags::VERIFY
            | CkMechanismFlags::SIGN_RECOVER
            | CkMechanismFlags::VERIFY_RECOVER
            | CkMechanismFlags::DIGEST
            | CkMechanismFlags::WRAP
            | CkMechanismFlags::UNWRAP
            | CkMechanismFlags::DERIVE,
    ));
    cases.extend(
        blowfish_twofish_generate_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(blowfish_twofish_encrypt_wrap_mechanisms.into_iter().map(|mechanism| {
        (
            mechanism,
            CkMechanismFlags::ENCRYPT
                | CkMechanismFlags::DECRYPT
                | CkMechanismFlags::WRAP
                | CkMechanismFlags::UNWRAP,
        )
    }));
    cases.extend(
        simple_key_generate_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(
        simple_key_derive_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.extend(
        hkdf_generate_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(
        hkdf_derive_mechanisms.into_iter().map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.extend(
        kip_derive_mechanisms.into_iter().map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.extend(
        kip_wrap_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::WRAP | CkMechanismFlags::UNWRAP)),
    );
    cases.extend(
        kip_sign_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        ike_derive_mechanisms.into_iter().map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.extend(
        shake_key_derivation_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );
    cases.extend(
        otp_generate_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(
        otp_sign_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        stateful_hash_key_pair_gen_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE_KEY_PAIR)),
    );
    cases.extend(
        stateful_hash_sign_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        tls_ssl_wtls_generate_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::GENERATE)),
    );
    cases.extend(
        tls_ssl_wtls_sign_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY)),
    );
    cases.extend(
        tls_ssl_wtls_derive_mechanisms
            .into_iter()
            .map(|mechanism| (mechanism, CkMechanismFlags::DERIVE)),
    );

    for (mechanism, expected_flags) in cases {
        let info = backend.get_mechanism_info(CkSlotId(0), mechanism).unwrap();
        assert_eq!(info.flags, CkMechanismFlags(expected_flags), "mechanism {mechanism:?}");
    }
}

#[test]
fn mock_mechanism_info_leaves_flags_empty_without_source_workflow_evidence() {
    let backend = MockBackend::with_official_mechanisms(vec![CkSlotId(0)]);

    for mechanism in [
        CkMechanismType(0x0000_1030), // CKM_BATON_KEY_GEN
        CkMechanismType(0x0000_0558), // CKM_CAMELLIA_CTR
        CkMechanismType(0x0000_0322), // CKM_CAST5_CBC
    ] {
        let info = backend.get_mechanism_info(CkSlotId(0), mechanism).unwrap();
        assert_eq!(
            info.flags,
            CkMechanismFlags::default(),
            "mechanism {mechanism:?} should not receive inferred flags without source workflow evidence"
        );
    }
}

#[test]
fn mock_backend_supports_provider_gap_3x_workflows() {
    let backend = MockBackend::with_official_mechanism_catalog_smoke(vec![CkSlotId(0)]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = backend.create_object(session, &[]).unwrap();
    let mechanism = CkMechanism { mechanism_type: CkMechanismType(0x0000_0017), params: None };

    assert_eq!(backend.login_user(session, CkUserType::User, b"alice", b"1234"), Ok(()));
    assert_eq!(backend.session_cancel(session, CkFlags(0)), Ok(()));
    assert_eq!(backend.get_session_validation_flags(session, 0), Ok(0));

    let (capsule, encapsulated_key) =
        backend.encapsulate_key(session, &mechanism, key, &[]).unwrap();
    assert!(!capsule.is_empty());
    assert_ne!(encapsulated_key, CkObjectHandle(0));
    let decapsulated_key =
        backend.decapsulate_key(session, &mechanism, key, &[], &capsule).unwrap();
    assert_ne!(decapsulated_key, CkObjectHandle(0));

    backend.message_encrypt_init(session, Some(&mechanism), key).unwrap();
    let mut parameter = vec![0x11, 0x22, 0x33, 0x44];
    let (parameter_out, ciphertext) =
        backend.encrypt_message(session, &mut parameter, b"aad", b"plaintext").unwrap();
    assert_eq!(parameter_out, parameter);
    assert_ne!(ciphertext, b"plaintext");
    backend.message_encrypt_final(session).unwrap();

    backend.message_decrypt_init(session, Some(&mechanism), key).unwrap();
    let mut decrypt_parameter = parameter.clone();
    let (_parameter_out, recovered) =
        backend.decrypt_message(session, &mut decrypt_parameter, b"aad", &ciphertext).unwrap();
    assert_eq!(recovered, b"plaintext");
    backend.message_decrypt_final(session).unwrap();

    backend.message_sign_init(session, Some(&mechanism), key).unwrap();
    let mut sign_parameter = vec![0x55];
    let (_parameter_out, signature) =
        backend.sign_message(session, &mut sign_parameter, b"payload").unwrap();
    assert!(!signature.is_empty());
    backend.message_sign_final(session).unwrap();

    backend.message_verify_init(session, Some(&mechanism), key).unwrap();
    assert_eq!(backend.verify_message(session, &sign_parameter, b"payload", &signature), Ok(()));
    backend.message_verify_final(session).unwrap();

    backend.verify_signature_init(session, Some(&mechanism), key, &signature).unwrap();
    assert_eq!(backend.verify_signature(session, b"payload"), Ok(()));

    let (wrapped, wrap_parameter_out) =
        backend.wrap_key_authenticated(session, &mechanism, key, key, b"aad").unwrap();
    assert!(!wrapped.is_empty());
    assert!(!wrap_parameter_out.is_empty());
    let (unwrapped, unwrap_parameter_out) =
        backend.unwrap_key_authenticated(session, &mechanism, key, &wrapped, &[], b"aad").unwrap();
    assert_ne!(unwrapped, CkObjectHandle(0));
    assert_eq!(unwrap_parameter_out, wrap_parameter_out);

    let async_result = backend.async_complete(session, "C_Encrypt").unwrap();
    assert_ne!(async_result.2, 0);
}

#[test]
fn official_source_grounded_mock_enforces_mechanism_workflow_flags() {
    let backend = MockBackend::with_official_mechanisms(vec![CkSlotId(0)]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = live_key(&backend, session);

    let aes_key_gen = CkMechanism { mechanism_type: CkMechanismType::AES_KEY_GEN, params: None };
    assert_ne!(backend.generate_key(session, &aes_key_gen, &[]).unwrap(), CkObjectHandle(0));
    assert_eq!(backend.sign_init(session, &aes_key_gen, key).unwrap_err(), CkRv::MECHANISM_INVALID);
    assert_eq!(
        backend.encrypt_init(session, &aes_key_gen, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let sha256 = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    backend.digest_init(session, &sha256).unwrap();
    assert!(!backend.digest(session, b"payload").unwrap().is_empty());
    assert_eq!(backend.generate_key(session, &sha256, &[]).unwrap_err(), CkRv::MECHANISM_INVALID);
    assert_eq!(backend.encrypt_init(session, &sha256, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    let md5 = CkMechanism { mechanism_type: CkMechanismType::MD5, params: None };
    backend.digest_init(session, &md5).unwrap();
    assert!(!backend.digest(session, b"payload").unwrap().is_empty());
    assert_eq!(backend.sign_init(session, &md5, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    let aes_gcm = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
    backend.encrypt_init(session, &aes_gcm, key).unwrap();
    let ciphertext = backend.encrypt(session, b"plaintext").unwrap();
    backend.decrypt_init(session, &aes_gcm, key).unwrap();
    assert_eq!(backend.decrypt(session, &ciphertext).unwrap(), b"plaintext");
    let wrapped = backend.wrap_key(session, &aes_gcm, key, key).unwrap();
    assert!(!wrapped.is_empty());
    assert_ne!(
        backend.unwrap_key(session, &aes_gcm, key, &wrapped, &[]).unwrap(),
        CkObjectHandle(0)
    );
    backend.message_encrypt_init(session, Some(&aes_gcm), key).unwrap();
    assert_eq!(backend.sign_init(session, &aes_gcm, key).unwrap_err(), CkRv::MECHANISM_INVALID);
    assert_eq!(backend.generate_key(session, &aes_gcm, &[]).unwrap_err(), CkRv::MECHANISM_INVALID);

    let ml_kem = CkMechanism { mechanism_type: CkMechanismType(0x0000_0017), params: None };
    let (capsule, encapsulated) = backend.encapsulate_key(session, &ml_kem, key, &[]).unwrap();
    assert!(!capsule.is_empty());
    assert_ne!(encapsulated, CkObjectHandle(0));
    assert_ne!(
        backend.decapsulate_key(session, &ml_kem, key, &[], &capsule).unwrap(),
        CkObjectHandle(0)
    );
    assert_eq!(backend.encrypt_init(session, &ml_kem, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    let md2_rsa_pkcs = CkMechanism { mechanism_type: CkMechanismType(0x0000_0004), params: None };
    backend.sign_init(session, &md2_rsa_pkcs, key).unwrap();
    let signature = backend.sign(session, b"payload").unwrap();
    backend.verify_init(session, &md2_rsa_pkcs, key).unwrap();
    backend.verify(session, b"payload", &signature).unwrap();
    assert_eq!(
        backend.encrypt_init(session, &md2_rsa_pkcs, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let tls_prf = CkMechanism { mechanism_type: CkMechanismType::TLS_PRF, params: None };
    assert_ne!(backend.derive_key(session, &tls_prf, key, &[]).unwrap(), CkObjectHandle(0));
    assert_eq!(backend.sign_init(session, &tls_prf, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    let des_cbc_pad = CkMechanism { mechanism_type: CkMechanismType::DES_CBC_PAD, params: None };
    backend.encrypt_init(session, &des_cbc_pad, key).unwrap();
    let des_ciphertext = backend.encrypt(session, b"plaintext").unwrap();
    backend.decrypt_init(session, &des_cbc_pad, key).unwrap();
    assert_eq!(backend.decrypt(session, &des_ciphertext).unwrap(), b"plaintext");
    assert_eq!(
        backend.wrap_key(session, &des_cbc_pad, key, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let des_key_gen = CkMechanism { mechanism_type: CkMechanismType::DES_KEY_GEN, params: None };
    assert_ne!(backend.generate_key(session, &des_key_gen, &[]).unwrap(), CkObjectHandle(0));
    assert_eq!(
        backend.encrypt_init(session, &des_key_gen, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let des_mac = CkMechanism { mechanism_type: CkMechanismType::DES_MAC, params: None };
    backend.sign_init(session, &des_mac, key).unwrap();
    let des_signature = backend.sign(session, b"payload").unwrap();
    backend.verify_init(session, &des_mac, key).unwrap();
    backend.verify(session, b"payload", &des_signature).unwrap();
    assert_eq!(backend.encrypt_init(session, &des_mac, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    let no_source = CkMechanism { mechanism_type: CkMechanismType(0x0000_1030), params: None };
    assert_eq!(
        backend.generate_key(session, &no_source, &[]).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );
    assert_eq!(backend.digest_init(session, &no_source).unwrap_err(), CkRv::MECHANISM_INVALID);
}

#[test]
fn official_source_grounded_mock_rejects_all_no_source_workflow_mechanisms() {
    fn assert_mechanism_invalid<T>(
        workflow: &str,
        mechanism_type: CkMechanismType,
        result: CkResult<T>,
    ) {
        match result {
            Err(rv) => assert_eq!(
                rv,
                CkRv::MECHANISM_INVALID,
                "{workflow} should reject no-source mechanism 0x{:08X}",
                mechanism_type.0
            ),
            Ok(_) => {
                panic!("{workflow} should reject no-source mechanism 0x{:08X}", mechanism_type.0)
            }
        }
    }

    let backend = MockBackend::with_official_mechanisms(vec![CkSlotId(0)]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = live_key(&backend, session);
    let no_source_mechanisms = pkcs11_3_2_official_mechanisms()
        .iter()
        .copied()
        .filter(|mechanism_type| session_ops::mock_mechanism_workflow_flags(*mechanism_type) == 0)
        .collect::<Vec<_>>();

    assert!(no_source_mechanisms.contains(&CkMechanismType(0x0000_1030))); // CKM_BATON_KEY_GEN
    assert!(no_source_mechanisms.contains(&CkMechanismType(0x0000_0558))); // CKM_CAMELLIA_CTR
    assert!(no_source_mechanisms.contains(&CkMechanismType(0x0000_0122))); // CKM_DES_CBC

    for mechanism_type in no_source_mechanisms {
        let mechanism = CkMechanism { mechanism_type, params: None };

        assert_mechanism_invalid(
            "generate_key",
            mechanism_type,
            backend.generate_key(session, &mechanism, &[]),
        );
        assert_mechanism_invalid(
            "generate_key_pair",
            mechanism_type,
            backend.generate_key_pair(session, &mechanism, &[], &[]),
        );
        assert_mechanism_invalid(
            "digest_init",
            mechanism_type,
            backend.digest_init(session, &mechanism),
        );
        assert_mechanism_invalid(
            "sign_init",
            mechanism_type,
            backend.sign_init(session, &mechanism, key),
        );
        assert_mechanism_invalid(
            "verify_init",
            mechanism_type,
            backend.verify_init(session, &mechanism, key),
        );
        assert_mechanism_invalid(
            "sign_recover_init",
            mechanism_type,
            backend.sign_recover_init(session, &mechanism, key),
        );
        assert_mechanism_invalid(
            "verify_recover_init",
            mechanism_type,
            backend.verify_recover_init(session, &mechanism, key),
        );
        assert_mechanism_invalid(
            "encrypt_init",
            mechanism_type,
            backend.encrypt_init(session, &mechanism, key),
        );
        assert_mechanism_invalid(
            "decrypt_init",
            mechanism_type,
            backend.decrypt_init(session, &mechanism, key),
        );
        assert_mechanism_invalid(
            "wrap_key",
            mechanism_type,
            backend.wrap_key(session, &mechanism, key, key),
        );
        assert_mechanism_invalid(
            "unwrap_key",
            mechanism_type,
            backend.unwrap_key(session, &mechanism, key, b"wrapped", &[]),
        );
        assert_mechanism_invalid(
            "derive_key",
            mechanism_type,
            backend.derive_key(session, &mechanism, key, &[]),
        );
        assert_mechanism_invalid(
            "encapsulate_key",
            mechanism_type,
            backend.encapsulate_key(session, &mechanism, key, &[]),
        );
        assert_mechanism_invalid(
            "decapsulate_key",
            mechanism_type,
            backend.decapsulate_key(session, &mechanism, key, &[], b"ciphertext"),
        );
        assert_mechanism_invalid(
            "message_encrypt_init",
            mechanism_type,
            backend.message_encrypt_init(session, Some(&mechanism), key),
        );
        assert_mechanism_invalid(
            "message_decrypt_init",
            mechanism_type,
            backend.message_decrypt_init(session, Some(&mechanism), key),
        );
        assert_mechanism_invalid(
            "message_sign_init",
            mechanism_type,
            backend.message_sign_init(session, Some(&mechanism), key),
        );
        assert_mechanism_invalid(
            "message_verify_init",
            mechanism_type,
            backend.message_verify_init(session, Some(&mechanism), key),
        );
        assert_mechanism_invalid(
            "verify_signature_init",
            mechanism_type,
            backend.verify_signature_init(session, Some(&mechanism), key, b"signature"),
        );
        assert_mechanism_invalid(
            "wrap_key_authenticated",
            mechanism_type,
            backend.wrap_key_authenticated(session, &mechanism, key, key, b"aad"),
        );
        assert_mechanism_invalid(
            "unwrap_key_authenticated",
            mechanism_type,
            backend.unwrap_key_authenticated(session, &mechanism, key, b"wrapped", &[], b"aad"),
        );
    }
}

#[test]
fn typed_message_exact_paths_return_structured_mock_outputs() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let output_spec = CkOutputBufferSpec { buffer_present: true, buffer_len: 64 };

    let gcm = MessageParameter::GcmMessage(GcmMessageParams {
        iv: vec![0x10; 12],
        iv_fixed_bits: 32,
        iv_generator: 1,
        tag: Vec::new(),
        tag_bits: 128,
    });
    let (encrypted, gcm_out) =
        backend.encrypt_message_exact_msg(session, &gcm, b"aad", b"hello", &output_spec).unwrap();
    assert_eq!(encrypted.ck_rv, CkRv::OK);
    assert_eq!(encrypted.value, Some(b"hello".iter().map(|byte| byte ^ 0x42).collect()));
    match gcm_out {
        MessageParameter::GcmMessage(params) => {
            assert_eq!(params.iv, vec![0x10; 12]);
            assert_eq!(params.tag, vec![0xA5; 16]);
            assert_eq!(params.tag_bits, 128);
        }
        other => panic!("unexpected GCM message params: {other:?}"),
    }

    let ccm = MessageParameter::CcmMessage(CcmMessageParams {
        data_len: 5,
        nonce: vec![0x20; 13],
        nonce_fixed_bits: 16,
        nonce_generator: 2,
        mac: Vec::new(),
        mac_len: 12,
    });
    let (decrypted, ccm_out) = backend
        .decrypt_message_next_exact_msg(session, &ccm, b"cipher", CkFlags(0), &output_spec)
        .unwrap();
    assert_eq!(decrypted.ck_rv, CkRv::OK);
    match ccm_out {
        MessageParameter::CcmMessage(params) => {
            assert_eq!(params.nonce, vec![0x20; 13]);
            assert_eq!(params.mac, vec![0xC3; 12]);
            assert_eq!(params.mac_len, 12);
        }
        other => panic!("unexpected CCM message params: {other:?}"),
    }

    let chacha = MessageParameter::SalaChacha(Salsa20ChaCha20Poly1305MessageParams {
        nonce: vec![0x30; 12],
        tag: Vec::new(),
    });
    let (signature, chacha_out) =
        backend.sign_message_next_exact_msg(session, &chacha, b"payload", &output_spec).unwrap();
    assert_eq!(signature.ck_rv, CkRv::OK);
    assert_eq!(signature.value, Some(b"payload".iter().rev().copied().collect()));
    match chacha_out {
        MessageParameter::SalaChacha(params) => {
            assert_eq!(params.nonce, vec![0x30; 12]);
            assert_eq!(params.tag, vec![0x5A; 16]);
        }
        other => panic!("unexpected Salsa/ChaCha message params: {other:?}"),
    }

    let too_small = CkOutputBufferSpec { buffer_present: true, buffer_len: 1 };
    let (small, _) =
        backend.encrypt_message_exact_msg(session, &gcm, b"aad", b"hello", &too_small).unwrap();
    assert_eq!(small.ck_rv, CkRv::BUFFER_TOO_SMALL);
    assert_eq!(small.returned_len, 5);
    assert_eq!(small.value, None);

    assert_eq!(
        backend
            .encrypt_message_exact_msg(CkSessionHandle(999), &gcm, b"aad", b"hello", &output_spec)
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
}

#[test]
fn encapsulate_key_returns_live_key_with_template_attributes() {
    let backend = MockBackend::with_official_mechanisms(vec![CkSlotId(0)]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let public_key = live_key(&backend, session);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType(0x0000_0017), params: None };

    let (ciphertext, encapsulated_key) = backend
        .encapsulate_key(
            session,
            &mechanism,
            public_key,
            &[CkAttribute {
                attr_type: CkAttributeType::LABEL,
                value: Some(CkAttributeValue::String("kem-output".to_string())),
            }],
        )
        .unwrap();

    assert!(!ciphertext.is_empty());
    let (rv, results) = backend
        .get_attribute_value_exact(
            session,
            encapsulated_key,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: true,
                buffer_len: "kem-output".len() as u64,
                nested: None,
            }],
        )
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(results[0].value, Some(b"kem-output".to_vec()));
}

#[test]
fn encapsulate_key_exact_data_query_returns_live_key_with_template_attributes() {
    let backend = MockBackend::with_official_mechanisms(vec![CkSlotId(0)]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let public_key = live_key(&backend, session);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType(0x0000_0017), params: None };

    let result = backend
        .encapsulate_key_exact(
            session,
            &mechanism,
            public_key,
            &[CkAttribute {
                attr_type: CkAttributeType::LABEL,
                value: Some(CkAttributeValue::String("kem-exact".to_string())),
            }],
            &CkOutputBufferSpec { buffer_present: true, buffer_len: 8 },
        )
        .unwrap();

    assert_eq!(result.ck_rv, CkRv::OK);
    assert_eq!(result.returned_len, 8);
    assert_ne!(result.object_handle, CkObjectHandle(0));
    let (rv, results) = backend
        .get_attribute_value_exact(
            session,
            result.object_handle,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: true,
                buffer_len: "kem-exact".len() as u64,
                nested: None,
            }],
        )
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(results[0].value, Some(b"kem-exact".to_vec()));
}

#[test]
fn encapsulate_key_exact_non_data_queries_do_not_allocate_key() {
    let backend = MockBackend::with_official_mechanisms(vec![CkSlotId(0)]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let public_key = live_key(&backend, session);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType(0x0000_0017), params: None };

    let size_query = backend
        .encapsulate_key_exact(
            session,
            &mechanism,
            public_key,
            &[],
            &CkOutputBufferSpec { buffer_present: false, buffer_len: 0 },
        )
        .unwrap();
    assert_eq!(size_query.ck_rv, CkRv::OK);
    assert_eq!(size_query.object_handle, CkObjectHandle(0));

    let too_small = backend
        .encapsulate_key_exact(
            session,
            &mechanism,
            public_key,
            &[],
            &CkOutputBufferSpec { buffer_present: true, buffer_len: 1 },
        )
        .unwrap();
    assert_eq!(too_small.ck_rv, CkRv::BUFFER_TOO_SMALL);
    assert_eq!(too_small.object_handle, CkObjectHandle(0));

    assert_eq!(
        backend.destroy_object(session, CkObjectHandle(public_key.0 + 1)).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
}

#[test]
fn official_mechanism_mock_accepts_every_official_mechanism_across_core_workflows() {
    let backend = MockBackend::with_official_mechanism_catalog_smoke(vec![CkSlotId(0)]);
    backend.initialize().unwrap();

    for mechanism_type in pkcs11_3_2_official_mechanisms() {
        let mechanism = CkMechanism { mechanism_type: *mechanism_type, params: None };
        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();

        backend.sign_init(session, &mechanism, key).unwrap();
        let signature = backend.sign(session, b"data").unwrap();
        assert!(!signature.is_empty(), "sign output for 0x{:08X}", mechanism_type.0);

        backend.verify_init(session, &mechanism, key).unwrap();
        backend.verify(session, b"data", &signature).unwrap();

        backend.sign_recover_init(session, &mechanism, key).unwrap();
        let recovered_signature = backend.sign_recover(session, b"data").unwrap();
        assert!(
            !recovered_signature.is_empty(),
            "sign-recover output for 0x{:08X}",
            mechanism_type.0
        );

        backend.verify_recover_init(session, &mechanism, key).unwrap();
        let recovered_data = backend.verify_recover(session, &recovered_signature).unwrap();
        assert!(!recovered_data.is_empty(), "verify-recover output for 0x{:08X}", mechanism_type.0);

        backend.sign_init(session, &mechanism, key).unwrap();
        backend.sign_update(session, b"part").unwrap();
        assert!(
            !backend.sign_final(session).unwrap().is_empty(),
            "multipart sign output for 0x{:08X}",
            mechanism_type.0
        );

        backend.verify_init(session, &mechanism, key).unwrap();
        backend.verify_update(session, b"part").unwrap();
        backend.verify_final(session, &signature).unwrap();

        backend.digest_init(session, &mechanism).unwrap();
        let digest = backend.digest(session, b"data").unwrap();
        assert!(!digest.is_empty(), "digest output for 0x{:08X}", mechanism_type.0);

        backend.digest_init(session, &mechanism).unwrap();
        backend.digest_update(session, b"part").unwrap();
        assert!(
            !backend.digest_final(session).unwrap().is_empty(),
            "multipart digest output for 0x{:08X}",
            mechanism_type.0
        );

        backend.encrypt_init(session, &mechanism, key).unwrap();
        let ciphertext = backend.encrypt(session, b"plaintext").unwrap();
        assert_ne!(ciphertext, b"plaintext", "encrypt output for 0x{:08X}", mechanism_type.0);

        backend.encrypt_init(session, &mechanism, key).unwrap();
        assert!(
            !backend.encrypt_update(session, b"part").unwrap().is_empty(),
            "encrypt-update output for 0x{:08X}",
            mechanism_type.0
        );
        backend.encrypt_final(session).unwrap();

        backend.decrypt_init(session, &mechanism, key).unwrap();
        assert_eq!(backend.decrypt(session, &ciphertext).unwrap(), b"plaintext");

        backend.decrypt_init(session, &mechanism, key).unwrap();
        assert!(
            !backend.decrypt_update(session, &ciphertext).unwrap().is_empty(),
            "decrypt-update output for 0x{:08X}",
            mechanism_type.0
        );
        backend.decrypt_final(session).unwrap();

        assert!(backend.derive_key(session, &mechanism, key, &[]).is_ok());
        assert!(backend.generate_key(session, &mechanism, &[]).is_ok());
        assert!(backend.generate_key_pair(session, &mechanism, &[], &[]).is_ok());
        let wrapping_key = backend.create_object(session, &[]).unwrap();
        let wrapped = backend.wrap_key(session, &mechanism, wrapping_key, key).unwrap();
        assert!(!wrapped.is_empty(), "wrap output for 0x{:08X}", mechanism_type.0);
        assert!(backend.unwrap_key(session, &mechanism, wrapping_key, &wrapped, &[]).is_ok());

        let (capsule, encapsulated_key) =
            backend.encapsulate_key(session, &mechanism, key, &[]).unwrap();
        assert!(!capsule.is_empty(), "encapsulate output for 0x{:08X}", mechanism_type.0);
        assert_ne!(encapsulated_key, CkObjectHandle(0));
        assert_ne!(
            backend.decapsulate_key(session, &mechanism, key, &[], &capsule).unwrap(),
            CkObjectHandle(0)
        );

        let mut message_parameter = vec![0x11, 0x22, 0x33, 0x44];
        backend.message_encrypt_init(session, Some(&mechanism), key).unwrap();
        let (message_encrypt_parameter, message_ciphertext) =
            backend.encrypt_message(session, &mut message_parameter, b"aad", b"message").unwrap();
        assert_eq!(message_encrypt_parameter, message_parameter);
        assert_ne!(message_ciphertext, b"message");
        backend.message_encrypt_final(session).unwrap();

        backend.message_decrypt_init(session, Some(&mechanism), key).unwrap();
        let (message_decrypt_parameter, message_plaintext) = backend
            .decrypt_message(session, &mut message_parameter, b"aad", &message_ciphertext)
            .unwrap();
        assert_eq!(message_decrypt_parameter, message_parameter);
        assert_eq!(message_plaintext, b"message");
        backend.message_decrypt_final(session).unwrap();

        backend.message_sign_init(session, Some(&mechanism), key).unwrap();
        let (message_sign_parameter, message_signature) =
            backend.sign_message(session, &mut message_parameter, b"payload").unwrap();
        assert_eq!(message_sign_parameter, message_parameter);
        assert!(!message_signature.is_empty());
        backend.message_sign_final(session).unwrap();

        backend.message_verify_init(session, Some(&mechanism), key).unwrap();
        backend
            .verify_message(session, &message_parameter, b"payload", &message_signature)
            .unwrap();
        backend.message_verify_final(session).unwrap();

        backend.verify_signature_init(session, Some(&mechanism), key, &message_signature).unwrap();
        backend.verify_signature(session, b"payload").unwrap();

        let (authenticated_wrapped, authenticated_parameter) =
            backend.wrap_key_authenticated(session, &mechanism, wrapping_key, key, b"aad").unwrap();
        assert!(!authenticated_wrapped.is_empty());
        assert!(!authenticated_parameter.is_empty());
        let (authenticated_unwrapped, authenticated_unwrap_parameter) = backend
            .unwrap_key_authenticated(
                session,
                &mechanism,
                wrapping_key,
                &authenticated_wrapped,
                &[],
                b"aad",
            )
            .unwrap();
        assert_ne!(authenticated_unwrapped, CkObjectHandle(0));
        assert_eq!(authenticated_unwrap_parameter, authenticated_parameter);

        let async_result = backend.async_complete(session, "C_Encrypt").unwrap();
        assert_eq!(async_result.0, 1);
        assert!(!async_result.1.is_empty());
        assert_ne!(async_result.2, 0);

        backend.close_session(session).unwrap();
    }
}

#[test]
fn full_registry_mock_accepts_every_registered_mechanism_across_core_workflows() {
    let registry = MechanismRegistry::load_with_override_str(None).unwrap();
    let mechanisms =
        registry.registered_mechanisms().into_iter().map(CkMechanismType).collect::<Vec<_>>();
    let backend = MockBackend::with_mechanism_registry(vec![CkSlotId(0)], &registry);
    backend.initialize().unwrap();

    for mechanism_type in mechanisms {
        let mechanism = CkMechanism { mechanism_type, params: None };

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.sign_init(session, &mechanism, key).unwrap();
        assert!(!backend.sign(session, b"data").unwrap().is_empty());
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.sign_init(session, &mechanism, key).unwrap();
        backend.sign_update(session, b"part").unwrap();
        assert!(!backend.sign_final(session).unwrap().is_empty());
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.sign_recover_init(session, &mechanism, key).unwrap();
        assert!(!backend.sign_recover(session, b"data").unwrap().is_empty());
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.verify_init(session, &mechanism, key).unwrap();
        backend.verify(session, b"data", b"signature").unwrap();
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.verify_init(session, &mechanism, key).unwrap();
        backend.verify_update(session, b"part").unwrap();
        backend.verify_final(session, b"signature").unwrap();
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.verify_recover_init(session, &mechanism, key).unwrap();
        assert!(!backend.verify_recover(session, b"signature").unwrap().is_empty());
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        backend.digest_init(session, &mechanism).unwrap();
        assert!(!backend.digest(session, b"data").unwrap().is_empty());
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        backend.digest_init(session, &mechanism).unwrap();
        backend.digest_update(session, b"part").unwrap();
        assert!(!backend.digest_final(session).unwrap().is_empty());
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.encrypt_init(session, &mechanism, key).unwrap();
        let ciphertext = backend.encrypt(session, b"plaintext").unwrap();
        assert_ne!(ciphertext, b"plaintext");
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.encrypt_init(session, &mechanism, key).unwrap();
        assert!(!backend.encrypt_update(session, b"part").unwrap().is_empty());
        backend.encrypt_final(session).unwrap();
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.decrypt_init(session, &mechanism, key).unwrap();
        assert_eq!(backend.decrypt(session, &ciphertext).unwrap(), b"plaintext");
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.decrypt_init(session, &mechanism, key).unwrap();
        assert!(!backend.decrypt_update(session, &ciphertext).unwrap().is_empty());
        backend.decrypt_final(session).unwrap();
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        assert!(backend.derive_key(session, &mechanism, key, &[]).is_ok());
        assert!(backend.generate_key(session, &mechanism, &[]).is_ok());
        assert!(backend.generate_key_pair(session, &mechanism, &[], &[]).is_ok());
        let wrapping_key = backend.create_object(session, &[]).unwrap();
        let wrapped_key = backend.wrap_key(session, &mechanism, wrapping_key, key).unwrap();
        assert!(!wrapped_key.is_empty());
        assert!(backend.unwrap_key(session, &mechanism, wrapping_key, &wrapped_key, &[]).is_ok());
        backend.close_session(session).unwrap();
    }
}

#[test]
fn full_registry_mock_accepts_every_registered_mechanism_for_exact_wrap_workflow() {
    let registry = MechanismRegistry::load_with_override_str(None).unwrap();
    let mechanisms =
        registry.registered_mechanisms().into_iter().map(CkMechanismType).collect::<Vec<_>>();
    let backend = MockBackend::with_mechanism_registry(vec![CkSlotId(0)], &registry);
    backend.initialize().unwrap();

    for mechanism_type in mechanisms {
        let mechanism = CkMechanism { mechanism_type, params: None };
        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let wrapping_key = backend.create_object(session, &[]).unwrap();
        let key = backend.create_object(session, &[]).unwrap();

        let size_spec = CkOutputBufferSpec { buffer_present: false, buffer_len: 0 };
        let size_result =
            backend.wrap_key_exact(session, &mechanism, wrapping_key, key, &size_spec).unwrap();
        assert_eq!(size_result.ck_rv, CkRv::OK);
        assert_eq!(size_result.returned_len, 4);
        assert!(size_result.value.is_none());

        let data_spec = CkOutputBufferSpec { buffer_present: true, buffer_len: 4 };
        let data_result =
            backend.wrap_key_exact(session, &mechanism, wrapping_key, key, &data_spec).unwrap();
        assert_eq!(data_result.ck_rv, CkRv::OK);
        assert_eq!(data_result.value, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));

        backend.close_session(session).unwrap();
    }
}

#[test]
fn mechanism_info_unknown_mechanism_returns_mechanism_invalid() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::SHA256]);
    assert_eq!(
        backend.get_mechanism_info(CkSlotId(0), CkMechanismType::RSA_PKCS).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );
}

fn unsupported_mechanism_fixture()
-> (MockBackend, CkSessionHandle, CkObjectHandle, CkObjectHandle, CkMechanism) {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::SHA256]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = live_key(&backend, session);
    let other_key = live_key(&backend, session);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    (backend, session, key, other_key, mechanism)
}

#[test]
fn mechanism_bearing_workflows_reject_unadvertised_mechanisms() {
    let output_spec = CkOutputBufferSpec { buffer_present: true, buffer_len: 64 };
    let param_spec = CkParameterRoundtripSpec { buffer_present: true, buffer_len: 16, value: None };

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(backend.sign_init(session, &mechanism, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(backend.verify_init(session, &mechanism, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.sign_recover_init(session, &mechanism, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.verify_recover_init(session, &mechanism, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, _, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(backend.digest_init(session, &mechanism).unwrap_err(), CkRv::MECHANISM_INVALID);

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.encrypt_init(session, &mechanism, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.decrypt_init(session, &mechanism, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.derive_key(session, &mechanism, key, &[]).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.derive_key_with_output(session, &mechanism, key, &[]).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, other_key, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.wrap_key(session, &mechanism, key, other_key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.unwrap_key(session, &mechanism, key, b"wrapped", &[]).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, _, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.generate_key(session, &mechanism, &[]).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, _, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.generate_key_pair(session, &mechanism, &[], &[]).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, other_key, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.wrap_key_exact(session, &mechanism, key, other_key, &output_spec).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, other_key, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend
            .wrap_key_exact_with_output(session, &mechanism, key, other_key, &output_spec)
            .unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.encapsulate_key(session, &mechanism, key, &[]).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.encapsulate_key_exact(session, &mechanism, key, &[], &output_spec).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.decapsulate_key(session, &mechanism, key, &[], b"ciphertext").unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.message_encrypt_init(session, Some(&mechanism), key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.message_decrypt_init(session, Some(&mechanism), key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.message_sign_init(session, Some(&mechanism), key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.message_verify_init(session, Some(&mechanism), key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.verify_signature_init(session, Some(&mechanism), key, b"sig").unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, other_key, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.wrap_key_authenticated(session, &mechanism, key, other_key, b"aad").unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend
            .unwrap_key_authenticated(session, &mechanism, key, b"wrapped", &[], b"aad")
            .unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, other_key, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend
            .wrap_key_authenticated_exact(
                session,
                &mechanism,
                key,
                other_key,
                b"aad",
                &output_spec,
                &param_spec,
            )
            .unwrap_err(),
        CkRv::MECHANISM_INVALID
    );
}

#[test]
fn mock_generate_key_pair_returns_unique_handles() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };
    let (pub_h, priv_h) = backend.generate_key_pair(session, &mech, &[], &[]).unwrap();
    assert_ne!(pub_h, priv_h);
}

fn label_attr(label: &str) -> CkAttribute {
    CkAttribute {
        attr_type: CkAttributeType::LABEL,
        value: Some(CkAttributeValue::String(label.to_string())),
    }
}

fn live_key(backend: &MockBackend, session: CkSessionHandle) -> CkObjectHandle {
    backend.create_object(session, &[label_attr("key")]).unwrap()
}

fn exact_size_spec() -> CkOutputBufferSpec {
    CkOutputBufferSpec { buffer_present: false, buffer_len: 0 }
}

fn exact_data_spec() -> CkOutputBufferSpec {
    CkOutputBufferSpec { buffer_present: true, buffer_len: 1024 }
}

fn exact_param_size_spec() -> CkParameterRoundtripSpec {
    CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None }
}

fn exact_param_data_spec() -> CkParameterRoundtripSpec {
    CkParameterRoundtripSpec { buffer_present: true, buffer_len: 1024, value: None }
}

fn assert_exact_byte_result(
    workflow: &str,
    mechanism_type: CkMechanismType,
    buffer_present: bool,
    result: CkOutputBufferResult,
) {
    assert_eq!(result.ck_rv, CkRv::OK, "{workflow} rv for 0x{:08X}", mechanism_type.0);
    if buffer_present {
        let value = result.value.unwrap_or_else(|| {
            panic!("{workflow} data query value for 0x{:08X}", mechanism_type.0)
        });
        assert_eq!(
            result.returned_len as usize,
            value.len(),
            "{workflow} data query length for 0x{:08X}",
            mechanism_type.0
        );
    } else {
        assert!(
            result.value.is_none(),
            "{workflow} size query value for 0x{:08X}",
            mechanism_type.0
        );
    }
}

fn assert_exact_byte_size_and_data<F>(workflow: &str, mechanism_type: CkMechanismType, mut run: F)
where
    F: FnMut(&CkOutputBufferSpec) -> CkResult<CkOutputBufferResult>,
{
    let size_result = run(&exact_size_spec()).unwrap();
    assert_exact_byte_result(workflow, mechanism_type, false, size_result);
    let data_result = run(&exact_data_spec()).unwrap();
    assert_exact_byte_result(workflow, mechanism_type, true, data_result);
}

fn assert_exact_parameter_result(
    workflow: &str,
    mechanism_type: CkMechanismType,
    buffer_present: bool,
    result: CkParameterRoundtripResult,
) {
    assert_eq!(result.ck_rv, CkRv::OK, "{workflow} param rv for 0x{:08X}", mechanism_type.0);
    if buffer_present {
        let value = result
            .value
            .unwrap_or_else(|| panic!("{workflow} param data for 0x{:08X}", mechanism_type.0));
        assert_eq!(
            result.returned_len as usize,
            value.len(),
            "{workflow} param length for 0x{:08X}",
            mechanism_type.0
        );
    } else {
        assert!(
            result.value.is_none(),
            "{workflow} param size value for 0x{:08X}",
            mechanism_type.0
        );
    }
}

fn assert_exact_parameter_size_and_data<F>(
    workflow: &str,
    mechanism_type: CkMechanismType,
    mut run: F,
) where
    F: FnMut(
        &CkOutputBufferSpec,
        &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)>,
{
    let (size_output, size_param) = run(&exact_size_spec(), &exact_param_size_spec()).unwrap();
    assert_exact_byte_result(workflow, mechanism_type, false, size_output);
    assert_exact_parameter_result(workflow, mechanism_type, false, size_param);

    let (data_output, data_param) = run(&exact_data_spec(), &exact_param_data_spec()).unwrap();
    assert_exact_byte_result(workflow, mechanism_type, true, data_output);
    assert_exact_parameter_result(workflow, mechanism_type, true, data_param);
}

fn assert_exact_handle_size_and_data<F>(workflow: &str, mechanism_type: CkMechanismType, mut run: F)
where
    F: FnMut(&CkOutputBufferSpec) -> CkResult<CkOutputAndHandleResult>,
{
    let size_result = run(&exact_size_spec()).unwrap();
    assert_eq!(size_result.ck_rv, CkRv::OK, "{workflow} size rv for 0x{:08X}", mechanism_type.0);
    assert!(size_result.value.is_none(), "{workflow} size value for 0x{:08X}", mechanism_type.0);
    assert_eq!(
        size_result.object_handle,
        CkObjectHandle(0),
        "{workflow} size query handle for 0x{:08X}",
        mechanism_type.0
    );

    let data_result = run(&exact_data_spec()).unwrap();
    assert_eq!(data_result.ck_rv, CkRv::OK, "{workflow} data rv for 0x{:08X}", mechanism_type.0);
    let value = data_result
        .value
        .unwrap_or_else(|| panic!("{workflow} data value for 0x{:08X}", mechanism_type.0));
    assert_eq!(
        data_result.returned_len as usize,
        value.len(),
        "{workflow} data length for 0x{:08X}",
        mechanism_type.0
    );
    assert_ne!(
        data_result.object_handle,
        CkObjectHandle(0),
        "{workflow} data query handle for 0x{:08X}",
        mechanism_type.0
    );
}

#[test]
fn official_mechanism_mock_accepts_every_official_mechanism_across_exact_output_workflows() {
    let backend = MockBackend::with_official_mechanism_catalog_smoke(vec![CkSlotId(0)]);
    backend.initialize().unwrap();

    for mechanism_type in pkcs11_3_2_official_mechanisms() {
        let mechanism = CkMechanism { mechanism_type: *mechanism_type, params: None };
        let data = b"exact-output official workflow";
        let parameter = b"param";

        assert_exact_byte_size_and_data("sign_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.sign_init(session, &mechanism, key).unwrap();
            let result = backend.sign_exact(session, data, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("sign_final_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.sign_init(session, &mechanism, key).unwrap();
            backend.sign_update(session, data).unwrap();
            let result = backend.sign_final_exact(session, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("sign_recover_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.sign_recover_init(session, &mechanism, key).unwrap();
            let result = backend.sign_recover_exact(session, data, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("verify_recover_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.verify_recover_init(session, &mechanism, key).unwrap();
            let result = backend.verify_recover_exact(session, data, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("digest_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            backend.digest_init(session, &mechanism).unwrap();
            let result = backend.digest_exact(session, data, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("digest_final_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            backend.digest_init(session, &mechanism).unwrap();
            backend.digest_update(session, data).unwrap();
            let result = backend.digest_final_exact(session, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("encrypt_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.encrypt_init(session, &mechanism, key).unwrap();
            let result = backend.encrypt_exact(session, data, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("encrypt_update_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.encrypt_init(session, &mechanism, key).unwrap();
            let result = backend.encrypt_update_exact(session, data, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("encrypt_final_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.encrypt_init(session, &mechanism, key).unwrap();
            let result = backend.encrypt_final_exact(session, spec);
            backend.close_session(session).unwrap();
            result
        });

        let ciphertext = data.iter().map(|byte| byte ^ 0x42).collect::<Vec<_>>();
        assert_exact_byte_size_and_data("decrypt_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.decrypt_init(session, &mechanism, key).unwrap();
            let result = backend.decrypt_exact(session, &ciphertext, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("decrypt_update_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.decrypt_init(session, &mechanism, key).unwrap();
            let result = backend.decrypt_update_exact(session, &ciphertext, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("decrypt_final_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.decrypt_init(session, &mechanism, key).unwrap();
            let result = backend.decrypt_final_exact(session, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("digest_encrypt_update_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let result = backend.digest_encrypt_update_exact(session, data, spec);
            backend.close_session(session).unwrap();
            result
        });
        assert_exact_byte_size_and_data("decrypt_digest_update_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let result = backend.decrypt_digest_update_exact(session, data, spec);
            backend.close_session(session).unwrap();
            result
        });
        assert_exact_byte_size_and_data("sign_encrypt_update_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let result = backend.sign_encrypt_update_exact(session, data, spec);
            backend.close_session(session).unwrap();
            result
        });
        assert_exact_byte_size_and_data("decrypt_verify_update_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let result = backend.decrypt_verify_update_exact(session, data, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("wrap_key_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let wrapping_key = live_key(&backend, session);
            let key = live_key(&backend, session);
            let result = backend.wrap_key_exact(session, &mechanism, wrapping_key, key, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("get_operation_state_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.sign_init(session, &mechanism, key).unwrap();
            let result = backend.get_operation_state_exact(session, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_handle_size_and_data("encapsulate_key_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            let result =
                backend.encapsulate_key_exact(session, &mechanism, key, &[label_attr("kem")], spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_parameter_size_and_data(
            "encrypt_message_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let key = live_key(&backend, session);
                backend.encrypt_init(session, &mechanism, key).unwrap();
                let result = backend.encrypt_message_exact(
                    session,
                    parameter,
                    b"aad",
                    data,
                    output_spec,
                    param_spec,
                );
                backend.close_session(session).unwrap();
                result
            },
        );

        assert_exact_parameter_size_and_data(
            "decrypt_message_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let key = live_key(&backend, session);
                backend.decrypt_init(session, &mechanism, key).unwrap();
                let result = backend.decrypt_message_exact(
                    session,
                    parameter,
                    b"aad",
                    &ciphertext,
                    output_spec,
                    param_spec,
                );
                backend.close_session(session).unwrap();
                result
            },
        );

        assert_exact_parameter_size_and_data(
            "sign_message_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let key = live_key(&backend, session);
                backend.sign_init(session, &mechanism, key).unwrap();
                let result =
                    backend.sign_message_exact(session, parameter, data, output_spec, param_spec);
                backend.close_session(session).unwrap();
                result
            },
        );

        assert_exact_parameter_size_and_data(
            "encrypt_message_next_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let key = live_key(&backend, session);
                backend.encrypt_init(session, &mechanism, key).unwrap();
                let result = backend.encrypt_message_next_exact(
                    session,
                    parameter,
                    data,
                    CkFlags(0),
                    output_spec,
                    param_spec,
                );
                backend.close_session(session).unwrap();
                result
            },
        );

        assert_exact_parameter_size_and_data(
            "decrypt_message_next_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let key = live_key(&backend, session);
                backend.decrypt_init(session, &mechanism, key).unwrap();
                let result = backend.decrypt_message_next_exact(
                    session,
                    parameter,
                    &ciphertext,
                    CkFlags(0),
                    output_spec,
                    param_spec,
                );
                backend.close_session(session).unwrap();
                result
            },
        );

        assert_exact_parameter_size_and_data(
            "sign_message_next_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let key = live_key(&backend, session);
                backend.sign_init(session, &mechanism, key).unwrap();
                let result = backend.sign_message_next_exact(
                    session,
                    parameter,
                    data,
                    output_spec,
                    param_spec,
                );
                backend.close_session(session).unwrap();
                result
            },
        );

        assert_exact_parameter_size_and_data(
            "wrap_key_authenticated_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let wrapping_key = live_key(&backend, session);
                let key = live_key(&backend, session);
                let result = backend.wrap_key_authenticated_exact(
                    session,
                    &mechanism,
                    wrapping_key,
                    key,
                    b"aad",
                    output_spec,
                    param_spec,
                );
                backend.close_session(session).unwrap();
                result
            },
        );
    }
}

fn sp800_108_counter_iteration_param() -> PrfDataParam {
    const CK_SP800_108_ITERATION_VARIABLE: u64 = 0x0000_0001;

    PrfDataParam { type_: CK_SP800_108_ITERATION_VARIABLE, value: sp800_108_counter_format_bytes() }
}

fn sp800_108_null_iteration_param() -> PrfDataParam {
    const CK_SP800_108_ITERATION_VARIABLE: u64 = 0x0000_0001;

    PrfDataParam { type_: CK_SP800_108_ITERATION_VARIABLE, value: Vec::new() }
}

fn sp800_108_counter_format_bytes() -> Vec<u8> {
    vec![0; std::mem::size_of::<cryptoki_sys::CK_SP800_108_COUNTER_FORMAT>()]
}

fn sp800_108_dkm_length_format_bytes() -> Vec<u8> {
    sp800_108_dkm_length_format_bytes_with_method(1)
}

fn sp800_108_dkm_length_format_bytes_with_method(method: u64) -> Vec<u8> {
    let mut bytes = vec![0; std::mem::size_of::<cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT>()];
    match std::mem::size_of::<cryptoki_sys::CK_ULONG>() {
        8 => bytes[..8].copy_from_slice(&method.to_ne_bytes()),
        4 => bytes[..4].copy_from_slice(&(method as u32).to_ne_bytes()),
        _ => unreachable!("unsupported CK_ULONG width"),
    }
    bytes
}

const CKM_SHA256_HMAC: u64 = 0x0000_0251;

#[test]
fn derive_key_with_sp800_108_rejects_unsupported_prf_type() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);

    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_COUNTER_KDF]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);
    let mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CkMechanismType::SHA256.0,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: Vec::new(),
        })),
    };

    let err = backend.derive_key_with_output(session, &mechanism, base_key, &[]).unwrap_err();

    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
}

fn assert_mock_label(
    backend: &MockBackend,
    session: CkSessionHandle,
    object: CkObjectHandle,
    expected: &str,
) {
    let (rv, results) = backend
        .get_attribute_value_exact(
            session,
            object,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: true,
                buffer_len: expected.len() as u64,
                nested: None,
            }],
        )
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(results[0].value, Some(expected.as_bytes().to_vec()));
}

fn assert_invalid_session_does_not_allocate_object<R: std::fmt::Debug>(
    operation: impl FnOnce(&MockBackend, CkSessionHandle, &CkMechanism) -> CkResult<R>,
) {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let invalid_session = CkSessionHandle(999);
    let mechanism =
        CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };

    let err = operation(&backend, invalid_session, &mechanism).unwrap_err();

    assert_eq!(err, CkRv::SESSION_HANDLE_INVALID);
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(
        backend.destroy_object(session, CkObjectHandle(1)).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "invalid-session operation must not allocate a hidden object"
    );
}

#[test]
fn object_and_key_creation_workflows_preserve_template_attributes() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism =
        CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };

    let created = backend.create_object(session, &[label_attr("created")]).unwrap();
    assert_mock_label(&backend, session, created, "created");

    let copied = backend.copy_object(session, created, &[label_attr("copied")]).unwrap();
    assert_mock_label(&backend, session, copied, "copied");

    let generated = backend.generate_key(session, &mechanism, &[label_attr("generated")]).unwrap();
    assert_mock_label(&backend, session, generated, "generated");

    let unwrapped = backend
        .unwrap_key(session, &mechanism, generated, b"wrapped", &[label_attr("unwrapped")])
        .unwrap();
    assert_mock_label(&backend, session, unwrapped, "unwrapped");

    let (authenticated_unwrapped, authenticated_unwrap_parameter) = backend
        .unwrap_key_authenticated(
            session,
            &mechanism,
            generated,
            b"wrapped",
            &[label_attr("authenticated-unwrapped")],
            b"aad",
        )
        .unwrap();
    assert!(!authenticated_unwrap_parameter.is_empty());
    assert_mock_label(&backend, session, authenticated_unwrapped, "authenticated-unwrapped");

    let decapsulated = backend
        .decapsulate_key(session, &mechanism, generated, &[label_attr("decapsulated")], b"capsule")
        .unwrap();
    assert_mock_label(&backend, session, decapsulated, "decapsulated");

    let (public, private) = backend
        .generate_key_pair(session, &mechanism, &[label_attr("public")], &[label_attr("private")])
        .unwrap();
    assert_mock_label(&backend, session, public, "public");
    assert_mock_label(&backend, session, private, "private");
}

#[test]
fn object_and_key_creation_workflows_reject_invalid_session_without_allocating() {
    assert_invalid_session_does_not_allocate_object(|backend, session, _mechanism| {
        backend.create_object(session, &[label_attr("created")])
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, _mechanism| {
        backend.copy_object(session, CkObjectHandle(1), &[label_attr("copied")])
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.generate_key(session, mechanism, &[label_attr("generated")])
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.derive_key(session, mechanism, CkObjectHandle(1), &[label_attr("derived")])
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.derive_key_with_output(
            session,
            mechanism,
            CkObjectHandle(1),
            &[label_attr("derived-output")],
        )
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.unwrap_key(
            session,
            mechanism,
            CkObjectHandle(1),
            b"wrapped",
            &[label_attr("unwrapped")],
        )
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.generate_key_pair(
            session,
            mechanism,
            &[label_attr("public")],
            &[label_attr("private")],
        )
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.encapsulate_key(
            session,
            mechanism,
            CkObjectHandle(1),
            &[label_attr("encapsulated")],
        )
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.encapsulate_key_exact(
            session,
            mechanism,
            CkObjectHandle(1),
            &[label_attr("encapsulated-exact")],
            &CkOutputBufferSpec { buffer_present: true, buffer_len: 8 },
        )
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.decapsulate_key(
            session,
            mechanism,
            CkObjectHandle(1),
            &[label_attr("decapsulated")],
            b"capsule",
        )
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.unwrap_key_authenticated(
            session,
            mechanism,
            CkObjectHandle(1),
            b"wrapped",
            &[label_attr("authenticated-unwrapped")],
            b"aad",
        )
    });
}

#[test]
fn object_management_workflows_reject_invalid_session_without_mutating_objects() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let object = backend.create_object(session, &[label_attr("live")]).unwrap();
    let invalid_session = CkSessionHandle(999);

    assert_eq!(
        backend.find_objects_init(invalid_session, &[]).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(backend.find_objects(invalid_session, 1).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
    assert_eq!(
        backend.find_objects_final(invalid_session).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );

    let mut template = [label_attr("ignored")];
    assert_eq!(
        backend.get_attribute_value(invalid_session, object, &mut template).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .get_attribute_value_exact(
                invalid_session,
                object,
                &[CkAttributeQuery {
                    attr_type: CkAttributeType::LABEL,
                    buffer_present: true,
                    buffer_len: 4,
                    nested: None,
                }],
            )
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.get_object_size(invalid_session, object).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.set_attribute_value(invalid_session, object, &[label_attr("new")]).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.destroy_object(invalid_session, object).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );

    assert_eq!(backend.get_object_size(session, object).unwrap(), 0);
    assert_mock_label(&backend, session, object, "live");
}

#[test]
fn find_objects_tracks_active_search_operation() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = live_key(&backend, session);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };

    assert_eq!(backend.find_objects(session, 1).unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);
    assert_eq!(backend.find_objects_final(session).unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);

    backend.find_objects_init(session, &[]).unwrap();
    assert_eq!(backend.find_objects_init(session, &[]).unwrap_err(), CkRv::OPERATION_ACTIVE);
    assert_eq!(backend.sign_init(session, &mechanism, key).unwrap_err(), CkRv::OPERATION_ACTIVE);
    assert_eq!(backend.find_objects(session, 0).unwrap(), Vec::<CkObjectHandle>::new());
    backend.find_objects_final(session).unwrap();
    assert_eq!(backend.find_objects_final(session).unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);

    backend.sign_init(session, &mechanism, key).unwrap();
    assert_eq!(backend.find_objects_init(session, &[]).unwrap_err(), CkRv::OPERATION_ACTIVE);
}

#[test]
fn key_bearing_workflows_reject_invalid_object_handles() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let invalid_key = CkObjectHandle(999);
    let live_key = live_key(&backend, session);
    let output_spec = CkOutputBufferSpec { buffer_present: true, buffer_len: 64 };
    let param_spec = CkParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: 16,
        value: Some(vec![0xAA; 4]),
    };

    assert_eq!(
        backend.sign_init(session, &mechanism, invalid_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(backend.sign(session, b"data").unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);
    assert_eq!(
        backend.verify_init(session, &mechanism, invalid_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.sign_recover_init(session, &mechanism, invalid_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.verify_recover_init(session, &mechanism, invalid_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.encrypt_init(session, &mechanism, invalid_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.decrypt_init(session, &mechanism, invalid_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );

    backend.digest_init(session, &mechanism).unwrap();
    assert_eq!(backend.digest_key(session, invalid_key).unwrap_err(), CkRv::OBJECT_HANDLE_INVALID);
    backend.digest_final(session).unwrap();

    assert_eq!(
        backend.derive_key(session, &mechanism, invalid_key, &[label_attr("derived")]).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.wrap_key(session, &mechanism, live_key, invalid_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .unwrap_key(session, &mechanism, invalid_key, b"wrapped", &[label_attr("unwrapped")])
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .wrap_key_exact(session, &mechanism, live_key, invalid_key, &output_spec)
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .wrap_key_authenticated_exact(
                session,
                &mechanism,
                live_key,
                invalid_key,
                b"aad",
                &output_spec,
                &param_spec,
            )
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .encapsulate_key(session, &mechanism, invalid_key, &[label_attr("encapsulated")])
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .encapsulate_key_exact(
                session,
                &mechanism,
                invalid_key,
                &[label_attr("encapsulated-exact")],
                &output_spec,
            )
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .decapsulate_key(
                session,
                &mechanism,
                invalid_key,
                &[label_attr("decapsulated")],
                b"capsule"
            )
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .wrap_key_authenticated(session, &mechanism, live_key, invalid_key, b"aad")
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .unwrap_key_authenticated(
                session,
                &mechanism,
                invalid_key,
                b"wrapped",
                &[label_attr("authenticated-unwrapped")],
                b"aad",
            )
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.message_encrypt_init(session, Some(&mechanism), invalid_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.message_decrypt_init(session, Some(&mechanism), invalid_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.message_sign_init(session, Some(&mechanism), invalid_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.message_verify_init(session, Some(&mechanism), invalid_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.verify_signature_init(session, Some(&mechanism), invalid_key, b"sig").unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
}

fn signal_live_handles(
    backend: &MockBackend,
    session: CkSessionHandle,
    count: usize,
) -> Vec<CkObjectHandle> {
    (0..count).map(|_| live_key(backend, session)).collect()
}

fn expect_signal_derive_param_invalid(
    backend: &MockBackend,
    session: CkSessionHandle,
    mechanism_type: CkMechanismType,
    params: CkMechanismParams,
    label: &str,
) {
    let base_key = live_key(backend, session);
    let mechanism = CkMechanism { mechanism_type, params: Some(params) };

    assert_eq!(
        backend.derive_key(session, &mechanism, base_key, &[label_attr("derived")]).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "{label} should reject invalid source-defined handle fields"
    );
    assert_eq!(
        backend
            .derive_key_with_output(session, &mechanism, base_key, &[label_attr("derived")])
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "{label} exact/output path should reject invalid source-defined handle fields"
    );
}

#[test]
fn derive_key_validates_source_grounded_signal_parameter_handles() {
    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![
            CkMechanismType::X3DH_INITIALIZE,
            CkMechanismType::X3DH_RESPOND,
            CkMechanismType::X2RATCHET_INITIALIZE,
            CkMechanismType::X2RATCHET_RESPOND,
        ],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let handles = signal_live_handles(&backend, session, 16);
    let invalid = 0xFFFF_FFFF;

    let x3dh_initiate =
        |peer_identity_handle, peer_prekey_handle, own_identity_handle, own_ephemeral_handle| {
            CkMechanismParams::X3dhInitiate(X3dhInitiateParams {
                kdf: 1,
                peer_identity_handle,
                peer_prekey_handle,
                prekey_signature: vec![0xA5; 64],
                onetime_key_handle: invalid,
                own_identity_handle,
                own_ephemeral_handle,
            })
        };
    for (label, params) in [
        (
            "CK_X3DH_INITIATE_PARAMS.pPeer_identity",
            x3dh_initiate(invalid, handles[1].0, handles[2].0, handles[3].0),
        ),
        (
            "CK_X3DH_INITIATE_PARAMS.pPeer_prekey",
            x3dh_initiate(handles[0].0, invalid, handles[2].0, handles[3].0),
        ),
        (
            "CK_X3DH_INITIATE_PARAMS.pOwn_identity",
            x3dh_initiate(handles[0].0, handles[1].0, invalid, handles[3].0),
        ),
        (
            "CK_X3DH_INITIATE_PARAMS.pOwn_ephemeral",
            x3dh_initiate(handles[0].0, handles[1].0, handles[2].0, invalid),
        ),
    ] {
        expect_signal_derive_param_invalid(
            &backend,
            session,
            CkMechanismType::X3DH_INITIALIZE,
            params,
            label,
        );
    }

    expect_signal_derive_param_invalid(
        &backend,
        session,
        CkMechanismType::X3DH_RESPOND,
        CkMechanismParams::X3dhRespond(X3dhRespondParams {
            kdf: 1,
            identity_handle: invalid,
            prekey_handle: invalid,
            onetime_key_handle: invalid,
            initiator_identity_handle: invalid,
            initiator_ephemeral_handle: invalid,
        }),
        "CK_X3DH_RESPOND_PARAMS.pInitiator_identity",
    );

    let x2_initialize =
        |peer_public_prekey_handle, peer_public_identity_handle, own_public_identity_handle| {
            CkMechanismParams::X2RatchetInitialize(X2RatchetInitializeParams {
                sk: vec![0x42; 32],
                peer_public_prekey_handle,
                peer_public_identity_handle,
                own_public_identity_handle,
                encrypted_header: true,
                curve: 255,
                aead_mechanism: CkMechanismType::AES_GCM.0,
                kdf_mechanism: 1,
            })
        };
    for (label, params) in [
        (
            "CK_X2RATCHET_INITIALIZE_PARAMS.peer_public_prekey",
            x2_initialize(invalid, handles[5].0, handles[6].0),
        ),
        (
            "CK_X2RATCHET_INITIALIZE_PARAMS.peer_public_identity",
            x2_initialize(handles[4].0, invalid, handles[6].0),
        ),
        (
            "CK_X2RATCHET_INITIALIZE_PARAMS.own_public_identity",
            x2_initialize(handles[4].0, handles[5].0, invalid),
        ),
    ] {
        expect_signal_derive_param_invalid(
            &backend,
            session,
            CkMechanismType::X2RATCHET_INITIALIZE,
            params,
            label,
        );
    }

    let x2_respond = |own_prekey_handle, initiator_identity_handle, own_identity_handle| {
        CkMechanismParams::X2RatchetRespond(X2RatchetRespondParams {
            sk: vec![0x24; 32],
            own_prekey_handle,
            initiator_identity_handle,
            own_identity_handle,
            encrypted_header: false,
            curve: 255,
            aead_mechanism: CkMechanismType::AES_GCM.0,
            kdf_mechanism: 1,
        })
    };
    for (label, params) in [
        ("CK_X2RATCHET_RESPOND_PARAMS.own_prekey", x2_respond(invalid, handles[8].0, handles[9].0)),
        (
            "CK_X2RATCHET_RESPOND_PARAMS.initiator_identity",
            x2_respond(handles[7].0, invalid, handles[9].0),
        ),
        (
            "CK_X2RATCHET_RESPOND_PARAMS.own_public_identity",
            x2_respond(handles[7].0, handles[8].0, invalid),
        ),
    ] {
        expect_signal_derive_param_invalid(
            &backend,
            session,
            CkMechanismType::X2RATCHET_RESPOND,
            params,
            label,
        );
    }
}

#[test]
fn derive_key_leaves_lengthless_signal_byte_fields_unvalidated() {
    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::X3DH_INITIALIZE, CkMechanismType::X3DH_RESPOND],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let handles = signal_live_handles(&backend, session, 5);
    let base_key = live_key(&backend, session);
    let invalid = 0xFFFF_FFFF;

    let initiate = CkMechanism {
        mechanism_type: CkMechanismType::X3DH_INITIALIZE,
        params: Some(CkMechanismParams::X3dhInitiate(X3dhInitiateParams {
            kdf: 1,
            peer_identity_handle: handles[0].0,
            peer_prekey_handle: handles[1].0,
            prekey_signature: Vec::new(),
            onetime_key_handle: invalid,
            own_identity_handle: handles[2].0,
            own_ephemeral_handle: handles[3].0,
        })),
    };
    let respond = CkMechanism {
        mechanism_type: CkMechanismType::X3DH_RESPOND,
        params: Some(CkMechanismParams::X3dhRespond(X3dhRespondParams {
            kdf: 1,
            identity_handle: invalid,
            prekey_handle: invalid,
            onetime_key_handle: invalid,
            initiator_identity_handle: handles[4].0,
            initiator_ephemeral_handle: invalid,
        })),
    };

    assert_ne!(
        backend.derive_key(session, &initiate, base_key, &[label_attr("initiate")]).unwrap(),
        CkObjectHandle(0)
    );
    assert_ne!(
        backend.derive_key(session, &respond, base_key, &[label_attr("respond")]).unwrap(),
        CkObjectHandle(0)
    );
}

fn cms_sig_mechanism(certificate_handle: CkObjectHandle) -> CkMechanism {
    CkMechanism {
        mechanism_type: CkMechanismType::CMS_SIG,
        params: Some(CkMechanismParams::CmsSig(CmsSigParams {
            certificate_handle: certificate_handle.0,
            signing_mechanism: Box::new(CkMechanism {
                mechanism_type: CkMechanismType::RSA_PKCS,
                params: None,
            }),
            digest_mechanism: Box::new(CkMechanism {
                mechanism_type: CkMechanismType::SHA256,
                params: None,
            }),
            content_type: "application/octet-stream".to_string(),
            requested_attributes: Vec::new(),
            required_attributes: Vec::new(),
        })),
    }
}

#[test]
fn cms_sig_workflows_validate_optional_certificate_handle() {
    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::CMS_SIG, CkMechanismType::RSA_PKCS, CkMechanismType::SHA256],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let signing_key = live_key(&backend, session);
    let certificate = live_key(&backend, session);
    let invalid_certificate = CkObjectHandle(0xFFFF_FFFE);
    let invalid_cert_mechanism = cms_sig_mechanism(invalid_certificate);

    assert_eq!(
        backend.sign_init(session, &invalid_cert_mechanism, signing_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.verify_init(session, &invalid_cert_mechanism, signing_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.sign_recover_init(session, &invalid_cert_mechanism, signing_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.verify_recover_init(session, &invalid_cert_mechanism, signing_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );

    let live_cert_mechanism = cms_sig_mechanism(certificate);
    backend.sign_init(session, &live_cert_mechanism, signing_key).unwrap();
    backend.sign_final(session).unwrap();
    backend.verify_init(session, &live_cert_mechanism, signing_key).unwrap();
    backend.verify_final(session, b"sig").unwrap();
    backend.sign_recover_init(session, &live_cert_mechanism, signing_key).unwrap();
    backend.sign_recover(session, b"data").unwrap();
    backend.verify_recover_init(session, &live_cert_mechanism, signing_key).unwrap();
    backend.verify_recover(session, b"sig").unwrap();

    let absent_cert_mechanism = cms_sig_mechanism(CkObjectHandle(0));
    backend.sign_init(session, &absent_cert_mechanism, signing_key).unwrap();
    backend.sign_final(session).unwrap();
}

#[test]
fn derive_key_validates_concatenate_base_and_key_parameter_handle() {
    let backend =
        MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::CONCATENATE_BASE_AND_KEY]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);
    let other_key = live_key(&backend, session);
    let invalid = 0xFFFF_FFFD;

    let invalid_mechanism = CkMechanism {
        mechanism_type: CkMechanismType::CONCATENATE_BASE_AND_KEY,
        params: Some(CkMechanismParams::ObjectHandle(ObjectHandleParam { handle: invalid })),
    };
    assert_eq!(
        backend
            .derive_key(session, &invalid_mechanism, base_key, &[label_attr("derived")])
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .derive_key_with_output(session, &invalid_mechanism, base_key, &[label_attr("derived")])
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );

    let valid_mechanism = CkMechanism {
        mechanism_type: CkMechanismType::CONCATENATE_BASE_AND_KEY,
        params: Some(CkMechanismParams::ObjectHandle(ObjectHandleParam { handle: other_key.0 })),
    };
    assert_ne!(
        backend.derive_key(session, &valid_mechanism, base_key, &[label_attr("valid")]).unwrap(),
        CkObjectHandle(0)
    );
}

fn kip_mechanism(mechanism_type: CkMechanismType, key_handle: CkObjectHandle) -> CkMechanism {
    CkMechanism {
        mechanism_type,
        params: Some(CkMechanismParams::Kip(KipParams {
            mechanism: Box::new(CkMechanism {
                mechanism_type: CkMechanismType::SHA256,
                params: None,
            }),
            key_handle: key_handle.0,
            seed: b"seed".to_vec(),
        })),
    }
}

#[test]
fn kip_derive_and_mac_validate_hkey_but_wrap_does_not_use_it() {
    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::KIP_DERIVE, CkMechanismType::KIP_MAC, CkMechanismType::KIP_WRAP],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);
    let entropy_key = live_key(&backend, session);
    let wrapping_key = live_key(&backend, session);
    let wrapped_key = live_key(&backend, session);
    let invalid = CkObjectHandle(0xFFFF_FFFC);

    let invalid_derive = kip_mechanism(CkMechanismType::KIP_DERIVE, invalid);
    assert_eq!(
        backend
            .derive_key(session, &invalid_derive, base_key, &[label_attr("kip-derived")])
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .derive_key_with_output(
                session,
                &invalid_derive,
                base_key,
                &[label_attr("kip-derived")]
            )
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );

    let valid_derive = kip_mechanism(CkMechanismType::KIP_DERIVE, entropy_key);
    assert_ne!(
        backend.derive_key(session, &valid_derive, base_key, &[label_attr("kip-valid")]).unwrap(),
        CkObjectHandle(0)
    );

    let invalid_mac = kip_mechanism(CkMechanismType::KIP_MAC, invalid);
    assert_eq!(
        backend.sign_init(session, &invalid_mac, base_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.verify_init(session, &invalid_mac, base_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );

    let valid_mac = kip_mechanism(CkMechanismType::KIP_MAC, entropy_key);
    backend.sign_init(session, &valid_mac, base_key).unwrap();
    backend.sign_final(session).unwrap();
    backend.verify_init(session, &valid_mac, base_key).unwrap();
    backend.verify_final(session, b"sig").unwrap();

    let wrap_mechanism = kip_mechanism(CkMechanismType::KIP_WRAP, invalid);
    assert_eq!(
        backend.wrap_key(session, &wrap_mechanism, wrapping_key, wrapped_key).unwrap(),
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    );
    assert_ne!(
        backend
            .unwrap_key(
                session,
                &wrap_mechanism,
                wrapping_key,
                b"wrapped",
                &[label_attr("kip-unwrapped")]
            )
            .unwrap(),
        CkObjectHandle(0)
    );
}

fn expect_derive_param_handle_invalid(
    backend: &MockBackend,
    session: CkSessionHandle,
    mechanism_type: CkMechanismType,
    params: CkMechanismParams,
    label: &str,
) {
    let base_key = live_key(backend, session);
    let mechanism = CkMechanism { mechanism_type, params: Some(params) };

    assert_eq!(
        backend.derive_key(session, &mechanism, base_key, &[label_attr("derived")]).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "{label} should reject an invalid source-defined handle"
    );
    assert_eq!(
        backend
            .derive_key_with_output(session, &mechanism, base_key, &[label_attr("derived")])
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "{label} exact/output path should reject an invalid source-defined handle"
    );
}

#[test]
fn derive_key_validates_dual_ec_and_x942_parameter_handles() {
    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![
            CkMechanismType::ECMQV_DERIVE,
            CkMechanismType::X9_42_DH_HYBRID_DERIVE,
            CkMechanismType::X9_42_MQV_DERIVE,
        ],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let handles = signal_live_handles(&backend, session, 8);
    let invalid = 0xFFFF_FFFB;

    let ecdh2 = |private_data_handle| {
        CkMechanismParams::Ecdh2Derive(Ecdh2DeriveParams {
            kdf: 1,
            shared_data: b"shared".to_vec(),
            public_data: b"peer-public-1".to_vec(),
            private_data_len: 32,
            private_data_handle,
            public_data2: b"peer-public-2".to_vec(),
        })
    };
    expect_derive_param_handle_invalid(
        &backend,
        session,
        CkMechanismType::ECMQV_DERIVE,
        ecdh2(invalid),
        "CK_ECDH2_DERIVE_PARAMS.hPrivateData",
    );

    let ecmqv = |private_data_handle, public_key_handle| {
        CkMechanismParams::EcmqvDerive(EcmqvDeriveParams {
            kdf: 1,
            shared_data: b"shared".to_vec(),
            public_data: b"peer-public-1".to_vec(),
            private_data_len: 32,
            private_data_handle,
            public_data2: b"peer-public-2".to_vec(),
            public_key_handle,
        })
    };
    expect_derive_param_handle_invalid(
        &backend,
        session,
        CkMechanismType::ECMQV_DERIVE,
        ecmqv(invalid, handles[1].0),
        "CK_ECMQV_DERIVE_PARAMS.hPrivateData",
    );
    expect_derive_param_handle_invalid(
        &backend,
        session,
        CkMechanismType::ECMQV_DERIVE,
        ecmqv(handles[0].0, invalid),
        "CK_ECMQV_DERIVE_PARAMS.publicKey",
    );

    let x942_dh2 = |private_data_handle| {
        CkMechanismParams::X942Dh2Derive(X942Dh2DeriveParams {
            kdf: 1,
            other_info: b"other".to_vec(),
            public_data: b"dh-public-1".to_vec(),
            private_data_len: 32,
            private_data_handle,
            public_data2: b"dh-public-2".to_vec(),
        })
    };
    expect_derive_param_handle_invalid(
        &backend,
        session,
        CkMechanismType::X9_42_DH_HYBRID_DERIVE,
        x942_dh2(invalid),
        "CK_X9_42_DH2_DERIVE_PARAMS.hPrivateData",
    );

    let x942_mqv = |private_data_handle, public_key_handle| {
        CkMechanismParams::X942MqvDerive(X942MqvDeriveParams {
            kdf: 1,
            other_info: b"other".to_vec(),
            public_data: b"dh-public-1".to_vec(),
            private_data_len: 32,
            private_data_handle,
            public_data2: b"dh-public-2".to_vec(),
            public_key_handle,
        })
    };
    expect_derive_param_handle_invalid(
        &backend,
        session,
        CkMechanismType::X9_42_MQV_DERIVE,
        x942_mqv(invalid, handles[3].0),
        "CK_X9_42_MQV_DERIVE_PARAMS.hPrivateData",
    );
    expect_derive_param_handle_invalid(
        &backend,
        session,
        CkMechanismType::X9_42_MQV_DERIVE,
        x942_mqv(handles[2].0, invalid),
        "CK_X9_42_MQV_DERIVE_PARAMS.publicKey",
    );

    for (mechanism_type, params) in [
        (CkMechanismType::ECMQV_DERIVE, ecdh2(handles[4].0)),
        (CkMechanismType::ECMQV_DERIVE, ecmqv(handles[4].0, handles[5].0)),
        (CkMechanismType::X9_42_DH_HYBRID_DERIVE, x942_dh2(handles[6].0)),
        (CkMechanismType::X9_42_MQV_DERIVE, x942_mqv(handles[6].0, handles[7].0)),
    ] {
        let base_key = live_key(&backend, session);
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };
        assert_ne!(
            backend.derive_key(session, &mechanism, base_key, &[label_attr("valid")]).unwrap(),
            CkObjectHandle(0)
        );
    }
}

#[test]
fn stateless_session_workflows_reject_invalid_session() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let invalid_session = CkSessionHandle(999);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let output_spec = CkOutputBufferSpec { buffer_present: true, buffer_len: 64 };
    let param_spec = CkParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: 16,
        value: Some(vec![0xAA; 4]),
    };

    assert_eq!(
        backend.init_pin(invalid_session, Some(b"pin")).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.set_pin(invalid_session, Some(b"old"), Some(b"new")).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.sign_recover_init(invalid_session, &mechanism, CkObjectHandle(1)).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.sign_recover(invalid_session, b"data").unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.sign_recover_exact(invalid_session, b"data", &output_spec).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.verify_recover_init(invalid_session, &mechanism, CkObjectHandle(1)).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.verify_recover(invalid_session, b"signature").unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.verify_recover_exact(invalid_session, b"signature", &output_spec).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .wrap_key(invalid_session, &mechanism, CkObjectHandle(1), CkObjectHandle(2))
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .wrap_key_exact(
                invalid_session,
                &mechanism,
                CkObjectHandle(1),
                CkObjectHandle(2),
                &output_spec,
            )
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .wrap_key_authenticated_exact(
                invalid_session,
                &mechanism,
                CkObjectHandle(1),
                CkObjectHandle(2),
                b"aad",
                &output_spec,
                &param_spec,
            )
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.seed_random(invalid_session, b"seed").unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.generate_random(invalid_session, 8).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.digest_encrypt_update(invalid_session, b"part").unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.decrypt_digest_update(invalid_session, b"part").unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.sign_encrypt_update(invalid_session, b"part").unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.decrypt_verify_update(invalid_session, b"part").unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.digest_encrypt_update_exact(invalid_session, b"part", &output_spec).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.decrypt_digest_update_exact(invalid_session, b"part", &output_spec).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.sign_encrypt_update_exact(invalid_session, b"part", &output_spec).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.decrypt_verify_update_exact(invalid_session, b"part", &output_spec).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
}

#[test]
fn generate_key_pair_does_not_partially_allocate_on_quota_failure() {
    let backend = MockBackend::default_test().with_quotas(0, 1);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism =
        CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };

    let err = backend
        .generate_key_pair(session, &mechanism, &[label_attr("public")], &[label_attr("private")])
        .unwrap_err();

    assert_eq!(err, CkRv::DEVICE_MEMORY);
    assert_eq!(
        backend.destroy_object(session, CkObjectHandle(1)).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "failed key-pair generation must not leak a partial public key"
    );
}

#[test]
fn mock_generate_random_returns_correct_length() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let random = backend.generate_random(session, 32).unwrap();
    assert_eq!(random.len(), 32);
}

fn gcm_mechanism_output() -> CkMechanismParams {
    CkMechanismParams::Gcm(GcmParams {
        iv: vec![0xA5; 12],
        iv_bits: 96,
        iv_buffer_len: 12,
        aad: b"mock-aad".to_vec(),
        tag_bits: 128,
    })
}

#[test]
fn close_session_clears_session_mechanism_output() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let output = gcm_mechanism_output();
    backend.set_encrypt_init_output(Some(output.clone()));
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
    let key = live_key(&backend, session);

    backend.encrypt_init(session, &mechanism, key).unwrap();
    assert_eq!(backend.session_output_mechanism_params(session), Some(output));

    backend.close_session(session).unwrap();
    assert_eq!(backend.session_output_mechanism_params(session), None);
}

#[test]
fn close_all_sessions_clears_only_matching_session_mechanism_outputs() {
    let backend = MockBackend::new(vec![CkSlotId(0), CkSlotId(1)], vec![CkMechanismType::AES_GCM]);
    backend.initialize().unwrap();
    let s0 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let s1 = backend.open_session(CkSlotId(1), CkSessionFlags::default()).unwrap();
    let output = gcm_mechanism_output();
    backend.set_encrypt_init_output(Some(output.clone()));
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
    let key0 = live_key(&backend, s0);
    let key1 = live_key(&backend, s1);
    backend.encrypt_init(s0, &mechanism, key0).unwrap();
    backend.encrypt_init(s1, &mechanism, key1).unwrap();

    backend.close_all_sessions(CkSlotId(0)).unwrap();

    assert_eq!(backend.session_output_mechanism_params(s0), None);
    assert_eq!(backend.session_output_mechanism_params(s1), Some(output));
}

#[test]
fn finalize_clears_all_session_mechanism_outputs() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.set_encrypt_init_output(Some(gcm_mechanism_output()));
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
    let key = live_key(&backend, session);
    backend.encrypt_init(session, &mechanism, key).unwrap();
    assert!(backend.session_output_mechanism_params(session).is_some());

    backend.finalize().unwrap();
    assert_eq!(backend.session_output_mechanism_params(session), None);
}

#[test]
fn session_cancel_clears_all_session_scoped_mock_state() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
    let key = live_key(&backend, session);
    let signature = b"payload".iter().rev().copied().collect::<Vec<_>>();

    backend.set_encrypt_init_output(Some(gcm_mechanism_output()));
    backend.encrypt_init(session, &mechanism, key).unwrap();
    assert!(backend.session_output_mechanism_params(session).is_some());
    backend.verify_signature_init(session, Some(&mechanism), key, &signature).unwrap();
    backend.verify_signature_update(session, b"pay").unwrap();
    backend.verify_signature_update(session, b"load").unwrap();
    assert_eq!(backend.verify_signature_final(session), Ok(()));

    backend.session_cancel(session, CkFlags(0)).unwrap();

    assert_eq!(backend.session_output_mechanism_params(session), None);
    assert_eq!(
        backend.verify_signature(session, b"payload").unwrap_err(),
        CkRv::OPERATION_NOT_INITIALIZED
    );
    assert_eq!(
        backend.verify_signature_update(session, b"payload").unwrap_err(),
        CkRv::OPERATION_NOT_INITIALIZED
    );
}

#[test]
fn derive_key_with_output_returns_configured_tls_output_params() {
    let backend =
        MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::TLS12_MASTER_KEY_DERIVE]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism =
        CkMechanism { mechanism_type: CkMechanismType::TLS12_MASTER_KEY_DERIVE, params: None };
    let output = CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
        random_info: SslRandomData { client_random: vec![0x11; 32], server_random: vec![0x22; 32] },
        version_major: 3,
        version_minor: 3,
        prf_hash_mechanism: CkMechanismType::SHA256.0,
    });
    backend.set_derive_key_output(Some(output.clone()));
    let base_key = live_key(&backend, session);

    let (handle, mechanism_out) =
        backend.derive_key_with_output(session, &mechanism, base_key, &[]).unwrap();

    assert_ne!(handle, CkObjectHandle(0));
    assert_eq!(mechanism_out, Some(output));
}

#[test]
fn derive_key_with_output_returns_configured_pbe_iv_output_params() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType(0x0000_03A0)]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism = CkMechanism { mechanism_type: CkMechanismType(0x0000_03A0), params: None };
    let output = CkMechanismParams::Pbe(PbeParams {
        init_vector: vec![0x5A; 8],
        password: b"password".to_vec(),
        salt: b"salt".to_vec(),
        iteration: 4096,
    });
    backend.set_derive_key_output(Some(output.clone()));
    let base_key = live_key(&backend, session);

    let (handle, mechanism_out) =
        backend.derive_key_with_output(session, &mechanism, base_key, &[]).unwrap();

    assert_ne!(handle, CkObjectHandle(0));
    assert_eq!(mechanism_out, Some(output));
}

#[test]
fn derive_key_with_sp800_108_additional_keys_allocates_output_handles() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);

    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_COUNTER_KDF]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: vec![
                Sp800108DerivedKey {
                    template: vec![CkAttribute {
                        attr_type: CkAttributeType::VALUE_LEN,
                        value: Some(CkAttributeValue::Ulong(32)),
                    }],
                    key_handle: 0,
                },
                Sp800108DerivedKey {
                    template: vec![CkAttribute {
                        attr_type: CkAttributeType::LABEL,
                        value: Some(CkAttributeValue::String("extra".to_string())),
                    }],
                    key_handle: 0,
                },
            ],
        })),
    };
    let base_key = live_key(&backend, session);

    let (primary, mechanism_out) =
        backend.derive_key_with_output(session, &mechanism, base_key, &[]).unwrap();

    let Some(CkMechanismParams::Sp800108Kdf(output)) = mechanism_out else {
        panic!("expected SP800-108 output params");
    };
    assert_ne!(primary, CkObjectHandle(0));
    assert_eq!(output.additional_derived_keys.len(), 2);
    assert_ne!(output.additional_derived_keys[0].key_handle, 0);
    assert_ne!(output.additional_derived_keys[1].key_handle, 0);
    assert_ne!(
        output.additional_derived_keys[0].key_handle,
        output.additional_derived_keys[1].key_handle
    );
    assert_eq!(output.additional_derived_keys[0].template.len(), 1);
}

#[test]
fn derive_key_with_sp800_108_additional_key_handles_preserves_templates() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const CKM_SP800_108_FEEDBACK_KDF: CkMechanismType = CkMechanismType(0x0000_03AD);

    for (mechanism_type, params) in [
        (
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![sp800_108_counter_iteration_param()],
                additional_derived_keys: vec![Sp800108DerivedKey {
                    template: vec![
                        CkAttribute {
                            attr_type: CkAttributeType::VALUE_LEN,
                            value: Some(CkAttributeValue::Ulong(48)),
                        },
                        CkAttribute {
                            attr_type: CkAttributeType::LABEL,
                            value: Some(CkAttributeValue::String("sp800 extra".to_string())),
                        },
                    ],
                    key_handle: 0,
                }],
            }),
        ),
        (
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![sp800_108_null_iteration_param()],
                iv: vec![0xA5; 16],
                additional_derived_keys: vec![Sp800108DerivedKey {
                    template: vec![
                        CkAttribute {
                            attr_type: CkAttributeType::VALUE_LEN,
                            value: Some(CkAttributeValue::Ulong(48)),
                        },
                        CkAttribute {
                            attr_type: CkAttributeType::LABEL,
                            value: Some(CkAttributeValue::String("sp800 extra".to_string())),
                        },
                    ],
                    key_handle: 0,
                }],
            }),
        ),
    ] {
        let backend = MockBackend::new(vec![CkSlotId(0)], vec![mechanism_type]);
        backend.initialize().unwrap();
        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let base_key = live_key(&backend, session);
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };

        let (_, mechanism_out) =
            backend.derive_key_with_output(session, &mechanism, base_key, &[]).unwrap();
        let additional_key = match mechanism_out {
            Some(CkMechanismParams::Sp800108Kdf(output)) => {
                CkObjectHandle(output.additional_derived_keys[0].key_handle)
            }
            Some(CkMechanismParams::Sp800108FeedbackKdf(output)) => {
                CkObjectHandle(output.additional_derived_keys[0].key_handle)
            }
            other => panic!("expected SP800-108 output params, got {other:?}"),
        };

        let (rv, size_results) = backend
            .get_attribute_value_exact(
                session,
                additional_key,
                &[
                    CkAttributeQuery {
                        attr_type: CkAttributeType::VALUE_LEN,
                        buffer_present: false,
                        buffer_len: 0,
                        nested: None,
                    },
                    CkAttributeQuery {
                        attr_type: CkAttributeType::LABEL,
                        buffer_present: false,
                        buffer_len: 0,
                        nested: None,
                    },
                ],
            )
            .unwrap();
        assert_eq!(rv, CkRv::OK);
        assert_eq!(size_results[0].returned_len, 8);
        assert_eq!(size_results[1].returned_len, "sp800 extra".len() as u64);

        let (rv, data_results) = backend
            .get_attribute_value_exact(
                session,
                additional_key,
                &[
                    CkAttributeQuery {
                        attr_type: CkAttributeType::VALUE_LEN,
                        buffer_present: true,
                        buffer_len: size_results[0].returned_len,
                        nested: None,
                    },
                    CkAttributeQuery {
                        attr_type: CkAttributeType::LABEL,
                        buffer_present: true,
                        buffer_len: size_results[1].returned_len,
                        nested: None,
                    },
                ],
            )
            .unwrap();
        assert_eq!(rv, CkRv::OK);
        assert_eq!(data_results[0].value, Some(48_u64.to_le_bytes().to_vec()));
        assert_eq!(data_results[1].value, Some(b"sp800 extra".to_vec()));
    }
}

#[test]
fn derive_key_with_sp800_108_enforces_mode_data_param_rules() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const CKM_SP800_108_FEEDBACK_KDF: CkMechanismType = CkMechanismType(0x0000_03AD);
    const CKM_SP800_108_DOUBLE_PIPELINE_KDF: CkMechanismType = CkMechanismType(0x0000_03AE);
    const CK_SP800_108_COUNTER: u64 = 0x0000_0002;

    let counter_field = PrfDataParam { type_: CK_SP800_108_COUNTER, value: vec![0; 16] };
    for (name, mechanism_type, params) in [
        (
            "counter mode missing iteration variable",
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: Vec::new(),
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "feedback mode missing iteration variable",
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: Vec::new(),
                iv: vec![0xA5; 16],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "double-pipeline mode missing iteration variable",
            CKM_SP800_108_DOUBLE_PIPELINE_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: Vec::new(),
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "counter mode rejects CK_SP800_108_COUNTER",
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![sp800_108_counter_iteration_param(), counter_field.clone()],
                additional_derived_keys: Vec::new(),
            }),
        ),
    ] {
        let backend = MockBackend::new(vec![CkSlotId(0)], vec![mechanism_type]);
        backend.initialize().unwrap();
        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let base_key = live_key(&backend, session);
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };

        let err = backend.derive_key_with_output(session, &mechanism, base_key, &[]).unwrap_err();

        assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID, "{name}");
        assert_eq!(
            backend.destroy_object(session, CkObjectHandle(base_key.0 + 1)).unwrap_err(),
            CkRv::OBJECT_HANDLE_INVALID,
            "{name} must not allocate a primary derived object"
        );
    }
}

#[test]
fn derive_key_with_sp800_108_validates_data_param_payload_shapes_and_singletons() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const CKM_SP800_108_FEEDBACK_KDF: CkMechanismType = CkMechanismType(0x0000_03AD);
    const CKM_SP800_108_DOUBLE_PIPELINE_KDF: CkMechanismType = CkMechanismType(0x0000_03AE);
    const CK_SP800_108_ITERATION_VARIABLE: u64 = 0x0000_0001;
    const CK_SP800_108_COUNTER: u64 = 0x0000_0002;
    const CK_SP800_108_DKM_LENGTH: u64 = 0x0000_0003;
    const CK_SP800_108_BYTE_ARRAY: u64 = 0x0000_0004;

    let counter_format = sp800_108_counter_format_bytes();
    let dkm_length_format = sp800_108_dkm_length_format_bytes();
    let short_counter_format = vec![0; counter_format.len() - 1];
    let short_dkm_length_format = vec![0; dkm_length_format.len() - 1];

    let cases = vec![
        (
            "counter mode iteration variable requires counter-format payload",
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![PrfDataParam {
                    type_: CK_SP800_108_ITERATION_VARIABLE,
                    value: Vec::new(),
                }],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "feedback counter data field requires counter-format payload",
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_null_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_COUNTER,
                        value: short_counter_format.clone(),
                    },
                ],
                iv: vec![0xA5; 16],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "double-pipeline DKM length data field requires DKM-format payload",
            CKM_SP800_108_DOUBLE_PIPELINE_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_null_iteration_param(),
                    PrfDataParam { type_: CK_SP800_108_DKM_LENGTH, value: short_dkm_length_format },
                ],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "BYTE_ARRAY data field requires non-empty payload",
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_counter_iteration_param(),
                    PrfDataParam { type_: CK_SP800_108_BYTE_ARRAY, value: Vec::new() },
                ],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "feedback counter data field is single-instance",
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_null_iteration_param(),
                    PrfDataParam { type_: CK_SP800_108_COUNTER, value: counter_format.clone() },
                    PrfDataParam { type_: CK_SP800_108_COUNTER, value: counter_format },
                ],
                iv: vec![0xA5; 16],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "DKM length data field is single-instance",
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_counter_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_DKM_LENGTH,
                        value: dkm_length_format.clone(),
                    },
                    PrfDataParam { type_: CK_SP800_108_DKM_LENGTH, value: dkm_length_format },
                ],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "DKM length data field rejects unknown method",
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_counter_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_DKM_LENGTH,
                        value: sp800_108_dkm_length_format_bytes_with_method(0xDEAD_BEEF),
                    },
                ],
                additional_derived_keys: Vec::new(),
            }),
        ),
    ];

    for (name, mechanism_type, params) in cases {
        let backend = MockBackend::new(vec![CkSlotId(0)], vec![mechanism_type]);
        backend.initialize().unwrap();
        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let base_key = live_key(&backend, session);
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };

        let err = backend.derive_key_with_output(session, &mechanism, base_key, &[]).unwrap_err();

        assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID, "{name}");
        assert_eq!(
            backend.destroy_object(session, CkObjectHandle(base_key.0 + 1)).unwrap_err(),
            CkRv::OBJECT_HANDLE_INVALID,
            "{name} must not allocate a primary derived object"
        );
    }
}

#[test]
fn derive_key_with_sp800_108_key_handle_data_param_requires_live_input_key() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const CKM_SP800_108_FEEDBACK_KDF: CkMechanismType = CkMechanismType(0x0000_03AD);
    const CK_SP800_108_KEY_HANDLE: u64 = 0x0000_0005;

    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![CKM_SP800_108_COUNTER_KDF, CKM_SP800_108_FEEDBACK_KDF],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);

    for (mechanism_type, params) in [
        (
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_counter_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_KEY_HANDLE,
                        value: 0xBAD_u64.to_ne_bytes().to_vec(),
                    },
                ],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_null_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_KEY_HANDLE,
                        value: 0xBAD_u64.to_ne_bytes().to_vec(),
                    },
                ],
                iv: Vec::new(),
                additional_derived_keys: Vec::new(),
            }),
        ),
    ] {
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };
        let err = backend.derive_key_with_output(session, &mechanism, base_key, &[]).unwrap_err();

        assert_eq!(err, CkRv::OBJECT_HANDLE_INVALID);
    }
}

#[test]
fn derive_key_with_sp800_108_key_handle_data_param_accepts_live_input_key() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const CKM_SP800_108_FEEDBACK_KDF: CkMechanismType = CkMechanismType(0x0000_03AD);
    const CK_SP800_108_KEY_HANDLE: u64 = 0x0000_0005;

    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![CKM_SP800_108_COUNTER_KDF, CKM_SP800_108_FEEDBACK_KDF],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let input_key = backend.create_object(session, &[]).unwrap();

    for (mechanism_type, params) in [
        (
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_counter_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_KEY_HANDLE,
                        value: input_key.0.to_ne_bytes().to_vec(),
                    },
                ],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_null_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_KEY_HANDLE,
                        value: input_key.0.to_ne_bytes().to_vec(),
                    },
                ],
                iv: Vec::new(),
                additional_derived_keys: Vec::new(),
            }),
        ),
    ] {
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };
        let (derived, mechanism_out) =
            backend.derive_key_with_output(session, &mechanism, input_key, &[]).unwrap();

        assert_ne!(derived, CkObjectHandle(0));
        assert_eq!(mechanism_out, None);
    }
}

#[test]
fn derive_key_preserves_primary_key_template() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::SHA256]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };

    let derived_key = backend
        .derive_key(
            session,
            &mechanism,
            base_key,
            &[
                CkAttribute {
                    attr_type: CkAttributeType::VALUE_LEN,
                    value: Some(CkAttributeValue::Ulong(24)),
                },
                CkAttribute {
                    attr_type: CkAttributeType::LABEL,
                    value: Some(CkAttributeValue::String("primary derive".to_string())),
                },
            ],
        )
        .unwrap();

    let mut template = vec![
        CkAttribute { attr_type: CkAttributeType::VALUE_LEN, value: None },
        CkAttribute { attr_type: CkAttributeType::LABEL, value: None },
    ];
    backend.get_attribute_value(session, derived_key, &mut template).unwrap();

    assert_eq!(template[0].value, Some(CkAttributeValue::Ulong(24)));
    assert_eq!(template[1].value, Some(CkAttributeValue::String("primary derive".to_string())));
}

#[test]
fn derive_key_with_sp800_108_additional_key_handles_rejects_small_attribute_buffers() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);

    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_COUNTER_KDF]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: vec![Sp800108DerivedKey {
                template: vec![CkAttribute {
                    attr_type: CkAttributeType::LABEL,
                    value: Some(CkAttributeValue::String("sp800 extra".to_string())),
                }],
                key_handle: 0,
            }],
        })),
    };
    let base_key = live_key(&backend, session);

    let (_, mechanism_out) =
        backend.derive_key_with_output(session, &mechanism, base_key, &[]).unwrap();
    let Some(CkMechanismParams::Sp800108Kdf(output)) = mechanism_out else {
        panic!("expected SP800-108 output params");
    };
    let additional_key = CkObjectHandle(output.additional_derived_keys[0].key_handle);

    let (rv, results) = backend
        .get_attribute_value_exact(
            session,
            additional_key,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: true,
                buffer_len: 4,
                nested: None,
            }],
        )
        .unwrap();
    assert_eq!(rv, CkRv::BUFFER_TOO_SMALL);
    assert_eq!(results[0].returned_len, u64::MAX);
    assert_eq!(results[0].ck_rv, Some(CkRv::BUFFER_TOO_SMALL));
    assert_eq!(results[0].value, None);
}

#[test]
fn close_session_clears_sp800_108_session_keys_but_preserves_token_keys() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);

    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_COUNTER_KDF]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);
    let session_mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: vec![Sp800108DerivedKey {
                template: vec![label_attr("session-extra")],
                key_handle: 0,
            }],
        })),
    };
    let token_mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: vec![Sp800108DerivedKey {
                template: vec![
                    CkAttribute {
                        attr_type: CkAttributeType::TOKEN,
                        value: Some(CkAttributeValue::Bool(true)),
                    },
                    label_attr("token-extra"),
                ],
                key_handle: 0,
            }],
        })),
    };

    let (session_primary, session_output) = backend
        .derive_key_with_output(
            session,
            &session_mechanism,
            base_key,
            &[label_attr("session-primary")],
        )
        .unwrap();
    let session_extra = match session_output {
        Some(CkMechanismParams::Sp800108Kdf(output)) => {
            CkObjectHandle(output.additional_derived_keys[0].key_handle)
        }
        other => panic!("expected SP800-108 output params, got {other:?}"),
    };
    let (token_primary, token_output) = backend
        .derive_key_with_output(
            session,
            &token_mechanism,
            base_key,
            &[
                CkAttribute {
                    attr_type: CkAttributeType::TOKEN,
                    value: Some(CkAttributeValue::Bool(true)),
                },
                label_attr("token-primary"),
            ],
        )
        .unwrap();
    let token_extra = match token_output {
        Some(CkMechanismParams::Sp800108Kdf(output)) => {
            CkObjectHandle(output.additional_derived_keys[0].key_handle)
        }
        other => panic!("expected SP800-108 output params, got {other:?}"),
    };

    assert_mock_label(&backend, session, session_primary, "session-primary");
    assert_mock_label(&backend, session, session_extra, "session-extra");
    assert_mock_label(&backend, session, token_primary, "token-primary");
    assert_mock_label(&backend, session, token_extra, "token-extra");

    backend.close_session(session).unwrap();
    let fresh_session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

    for object in [session_primary, session_extra] {
        assert_eq!(
            backend.get_object_size(fresh_session, object).unwrap_err(),
            CkRv::OBJECT_HANDLE_INVALID
        );
        assert_eq!(
            backend
                .get_attribute_value_exact(
                    fresh_session,
                    object,
                    &[CkAttributeQuery {
                        attr_type: CkAttributeType::LABEL,
                        buffer_present: false,
                        buffer_len: 0,
                        nested: None,
                    }],
                )
                .unwrap_err(),
            CkRv::OBJECT_HANDLE_INVALID
        );
    }
    assert_mock_label(&backend, fresh_session, token_primary, "token-primary");
    assert_mock_label(&backend, fresh_session, token_extra, "token-extra");
}

#[test]
fn derive_key_with_sp800_108_additional_keys_does_not_partially_allocate_on_quota_failure() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const CKM_SP800_108_FEEDBACK_KDF: CkMechanismType = CkMechanismType(0x0000_03AD);

    for (mechanism_type, params) in [
        (
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![sp800_108_counter_iteration_param()],
                additional_derived_keys: vec![
                    Sp800108DerivedKey { template: Vec::new(), key_handle: 0 },
                    Sp800108DerivedKey { template: Vec::new(), key_handle: 0 },
                ],
            }),
        ),
        (
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![sp800_108_null_iteration_param()],
                iv: vec![0xA5; 16],
                additional_derived_keys: vec![
                    Sp800108DerivedKey { template: Vec::new(), key_handle: 0 },
                    Sp800108DerivedKey { template: Vec::new(), key_handle: 0 },
                ],
            }),
        ),
    ] {
        let backend = MockBackend::new(vec![CkSlotId(0)], vec![mechanism_type]).with_quotas(0, 3);
        backend.initialize().unwrap();
        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let base_key = live_key(&backend, session);
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };

        let err = backend.derive_key_with_output(session, &mechanism, base_key, &[]).unwrap_err();

        assert_eq!(err, CkRv::DEVICE_MEMORY);
        assert_eq!(
            backend.destroy_object(session, CkObjectHandle(base_key.0 + 1)).unwrap_err(),
            CkRv::OBJECT_HANDLE_INVALID,
            "failed SP800-108 derive must not leak the primary derived object"
        );
        assert_eq!(
            backend.destroy_object(session, CkObjectHandle(base_key.0 + 2)).unwrap_err(),
            CkRv::OBJECT_HANDLE_INVALID,
            "failed SP800-108 derive must not leak a partially allocated additional object"
        );
    }
}

#[test]
fn derive_key_with_sp800_108_template_failure_reports_invalid_additional_handle() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const SENTINEL_HANDLE: u64 = 0xCAFE_BABE;

    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_COUNTER_KDF]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);
    let mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: vec![
                Sp800108DerivedKey {
                    template: vec![CkAttribute {
                        attr_type: CkAttributeType::VALUE_LEN,
                        value: Some(CkAttributeValue::Ulong(32)),
                    }],
                    key_handle: SENTINEL_HANDLE,
                },
                Sp800108DerivedKey {
                    template: vec![CkAttribute {
                        attr_type: CkAttributeType::VALUE_LEN,
                        value: Some(CkAttributeValue::Ulong(0)),
                    }],
                    key_handle: SENTINEL_HANDLE,
                },
            ],
        })),
    };

    let result = backend
        .derive_key_with_output_result(session, &mechanism, base_key, &[])
        .expect("mock backend call should return a structured PKCS#11 result");

    assert_eq!(result.rv, CkRv::TEMPLATE_INCONSISTENT);
    assert_eq!(result.key_handle, None);
    let Some(CkMechanismParams::Sp800108Kdf(output)) = result.mechanism_out else {
        panic!("expected SP800-108 mechanism output on template failure");
    };
    assert_eq!(output.additional_derived_keys[0].key_handle, SENTINEL_HANDLE);
    assert_eq!(output.additional_derived_keys[1].key_handle, 0);
    assert_eq!(
        backend.destroy_object(session, CkObjectHandle(base_key.0 + 1)).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "failed SP800-108 derive must not leak the primary derived object"
    );
}

#[test]
fn close_all_sessions_is_slot_scoped() {
    let backend = MockBackend::new(vec![CkSlotId(0), CkSlotId(1)], vec![CkMechanismType::RSA_PKCS]);
    backend.initialize().unwrap();
    let s0 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let s1 = backend.open_session(CkSlotId(1), CkSessionFlags::default()).unwrap();
    backend.close_all_sessions(CkSlotId(0)).unwrap();
    assert_eq!(backend.close_session(s0).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
    assert!(backend.close_session(s1).is_ok());
}

#[test]
fn mock_encrypt_decrypt_roundtrip() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let key = live_key(&backend, session);
    backend.encrypt_init(session, &mech, key).unwrap();
    let plaintext = b"hello world";
    let ciphertext = backend.encrypt(session, plaintext).unwrap();
    assert_ne!(ciphertext.as_slice(), plaintext);
    backend.decrypt_init(session, &mech, key).unwrap();
    let recovered = backend.decrypt(session, &ciphertext).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn get_session_info_returns_correct_slot() {
    let backend = MockBackend::new(vec![CkSlotId(0), CkSlotId(5)], vec![CkMechanismType::RSA_PKCS]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(5), CkSessionFlags::default()).unwrap();
    let info = backend.get_session_info(session).unwrap();
    assert_eq!(info.slot_id, CkSlotId(5));
}

const CKF_DONT_BLOCK: u64 = 0x0000_0001;

#[test]
fn wait_for_slot_event_no_event_when_empty() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    assert_eq!(backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap_err(), CkRv::NO_EVENT);
}

#[test]
fn wait_for_slot_event_before_initialize_returns_cryptoki_not_initialized() {
    let backend = MockBackend::default_test();
    assert_eq!(
        backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap_err(),
        CkRv::CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
fn wait_for_slot_event_returns_queued_event() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    backend.enqueue_slot_event(CkSlotId(3));
    let slot = backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap();
    assert_eq!(slot, CkSlotId(3));
}

#[test]
fn wait_for_slot_event_fifo_order() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    backend.enqueue_slot_event(CkSlotId(1));
    backend.enqueue_slot_event(CkSlotId(2));
    backend.enqueue_slot_event(CkSlotId(3));
    assert_eq!(backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap(), CkSlotId(1));
    assert_eq!(backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap(), CkSlotId(2));
    assert_eq!(backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap(), CkSlotId(3));
    assert_eq!(backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap_err(), CkRv::NO_EVENT);
}

#[test]
fn wait_for_slot_event_blocks_until_event_when_flag_zero() {
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    let backend = Arc::new(MockBackend::default_test());
    backend.initialize().unwrap();
    let waiter_backend = Arc::clone(&backend);
    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();

    let waiter = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        result_tx.send(waiter_backend.wait_for_slot_event(0)).unwrap();
    });

    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(result_rx.recv_timeout(Duration::from_millis(50)).is_err());

    backend.enqueue_slot_event(CkSlotId(7));
    assert_eq!(result_rx.recv_timeout(Duration::from_secs(1)).unwrap().unwrap(), CkSlotId(7));
    waiter.join().unwrap();
}

#[test]
fn wait_for_slot_event_blocking_returns_not_initialized_after_finalize() {
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    let backend = Arc::new(MockBackend::default_test());
    backend.initialize().unwrap();
    let waiter_backend = Arc::clone(&backend);
    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();

    let waiter = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        result_tx.send(waiter_backend.wait_for_slot_event(0)).unwrap();
    });

    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(result_rx.recv_timeout(Duration::from_millis(50)).is_err());

    backend.finalize().unwrap();
    let result = match result_rx.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => result,
        Err(err) => {
            backend.enqueue_slot_event(CkSlotId(7));
            let _ = waiter.join();
            panic!("blocking slot-event wait did not return after finalize: {err}");
        }
    };
    assert_eq!(result.unwrap_err(), CkRv::CRYPTOKI_NOT_INITIALIZED);
    waiter.join().unwrap();
}

#[test]
fn finalize_clears_pending_slot_events() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    backend.enqueue_slot_event(CkSlotId(3));
    backend.finalize().unwrap();
    backend.initialize().unwrap();

    assert_eq!(backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap_err(), CkRv::NO_EVENT);
}

#[test]
fn initialize_clears_pending_slot_events() {
    let backend = MockBackend::default_test();
    backend.enqueue_slot_event(CkSlotId(3));
    backend.initialize().unwrap();

    assert_eq!(backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap_err(), CkRv::NO_EVENT);
}

#[test]
fn wait_for_slot_event_event_slots_need_not_be_in_slot_list() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    backend.enqueue_slot_event(CkSlotId(99));
    let slot = backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap();
    assert_eq!(slot, CkSlotId(99));
}

#[test]
fn sign_init_then_sign_single_pass_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let key = live_key(&backend, session);
    backend.sign_init(session, &mech, key).unwrap();
    assert!(backend.sign(session, b"data").is_ok());
}

#[test]
fn sign_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let err = backend.sign(session, b"data").unwrap_err();
    assert_eq!(err, CkRv::OPERATION_NOT_INITIALIZED);
}

#[test]
fn sign_update_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(
        backend.sign_update(session, b"chunk").unwrap_err(),
        CkRv::OPERATION_NOT_INITIALIZED
    );
}

#[test]
fn sign_final_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(backend.sign_final(session).unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);
}

#[test]
fn sign_multi_part_sequence_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let key = live_key(&backend, session);
    backend.sign_init(session, &mech, key).unwrap();
    backend.sign_update(session, b"part1").unwrap();
    backend.sign_update(session, b"part2").unwrap();
    assert!(backend.sign_final(session).is_ok());
}

#[test]
fn double_sign_init_returns_operation_active() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let key = live_key(&backend, session);
    backend.sign_init(session, &mech, key).unwrap();
    let err = backend.sign_init(session, &mech, key).unwrap_err();
    assert_eq!(err, CkRv::OPERATION_ACTIVE);
}

#[test]
fn sign_and_digest_interleaving_blocked_by_operation_active() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let sha_mech = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let key = live_key(&backend, session);
    backend.sign_init(session, &mech, key).unwrap();
    let err = backend.digest_init(session, &sha_mech).unwrap_err();
    assert_eq!(err, CkRv::OPERATION_ACTIVE);
}

#[test]
fn sign_operations_are_per_session_independent() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s1 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let s2 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let sha_mech = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let key = live_key(&backend, s1);
    backend.sign_init(s1, &mech, key).unwrap();
    backend.digest_init(s2, &sha_mech).unwrap();
    backend.sign_update(s1, b"data").unwrap();
    backend.digest_update(s2, b"data").unwrap();
    backend.sign_final(s1).unwrap();
    backend.digest_final(s2).unwrap();
}

#[test]
fn sign_state_cleared_after_sign_final() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let key = live_key(&backend, session);
    backend.sign_init(session, &mech, key).unwrap();
    backend.sign_final(session).unwrap();
    assert!(backend.sign_init(session, &mech, key).is_ok());
}

#[test]
fn digest_init_then_digest_single_pass_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    backend.digest_init(session, &mech).unwrap();
    assert!(backend.digest(session, b"hello").is_ok());
}

#[test]
fn digest_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(backend.digest(session, b"data").unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);
}

#[test]
fn digest_multi_part_sequence_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    backend.digest_init(session, &mech).unwrap();
    backend.digest_update(session, b"chunk1").unwrap();
    backend.digest_update(session, b"chunk2").unwrap();
    assert!(backend.digest_final(session).is_ok());
}

#[test]
fn encrypt_init_then_encrypt_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let key = live_key(&backend, session);
    backend.encrypt_init(session, &mech, key).unwrap();
    assert!(backend.encrypt(session, b"plaintext").is_ok());
}

#[test]
fn encrypt_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(backend.encrypt(session, b"data").unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);
}

#[test]
fn decrypt_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(backend.decrypt(session, b"data").unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);
}

#[test]
fn encrypt_multi_part_sequence_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let key = live_key(&backend, session);
    backend.encrypt_init(session, &mech, key).unwrap();
    let _part = backend.encrypt_update(session, b"part1").unwrap();
    assert!(backend.encrypt_final(session).is_ok());
}

#[test]
fn close_session_clears_active_op_state() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let key = live_key(&backend, session);
    backend.sign_init(session, &mech, key).unwrap();
    backend.close_session(session).unwrap();
    let session2 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(backend.sign(session2, b"data").unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);
}

include!("tests_rest.rs");

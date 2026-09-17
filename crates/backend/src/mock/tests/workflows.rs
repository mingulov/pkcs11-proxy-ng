use super::*;

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
        assert_eq!(info.flags, CkMechanismFlags(expected_flags as u64), "mechanism {mechanism:?}");
    }
}

#[test]
fn mock_mechanism_info_leaves_flags_empty_without_source_workflow_evidence() {
    let backend = MockBackend::with_official_mechanisms(vec![CkSlotId(0)]);

    // Camellia/ARIA are current-spec mechanisms whose working-spec markdown
    // carries no Mechanisms-vs-Functions table, and they are not in the
    // historical spec either — so they stay ungrounded (unlike the legacy
    // BATON/CAST families, which pkcs11-hist now grounds).
    for mechanism in [
        CkMechanismType(0x0000_0558), // CKM_CAMELLIA_CTR
        CkMechanismType(0x0000_0375), // CKM_TLS_MASTER_KEY_DERIVE
        CkMechanismType(0x0000_1012), // CKM_KEA_DERIVE
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
    let capsule_bytes = capsule.expose(|raw| raw.to_vec());
    assert!(!capsule.is_empty());
    assert_ne!(encapsulated_key, CkObjectHandle(0));
    let decapsulated_key = backend
        .decapsulate_key(session, &mechanism, key, &[], CkInBuf::Bytes(&capsule_bytes))
        .unwrap();
    assert_ne!(decapsulated_key, CkObjectHandle(0));

    backend.message_encrypt_init(session, Some(&mechanism), None, key).unwrap();
    let mut parameter = vec![0x11, 0x22, 0x33, 0x44];
    let (parameter_out, ciphertext) = backend
        .encrypt_message(
            session,
            &mut parameter,
            CkInBuf::Bytes(b"aad"),
            CkInBuf::Bytes(b"plaintext"),
        )
        .unwrap();
    let ciphertext_bytes = ciphertext.expose(|raw| raw.to_vec());
    assert_eq!(parameter_out, parameter.clone().into());
    assert!(ciphertext.expose(|raw| raw != b"plaintext"));
    backend.message_encrypt_final(session).unwrap();

    backend.message_decrypt_init(session, Some(&mechanism), None, key).unwrap();
    let mut decrypt_parameter = parameter.clone();
    let (_parameter_out, recovered) = backend
        .decrypt_message(
            session,
            &mut decrypt_parameter,
            CkInBuf::Bytes(b"aad"),
            CkInBuf::Bytes(&ciphertext_bytes),
        )
        .unwrap();
    assert_eq!(recovered, SecretBytes::copy_from_slice(b"plaintext"));
    backend.message_decrypt_final(session).unwrap();

    backend.message_sign_init(session, Some(&mechanism), key).unwrap();
    let mut sign_parameter = vec![0x55];
    let (_parameter_out, signature) =
        backend.sign_message(session, &mut sign_parameter, CkInBuf::Bytes(b"payload")).unwrap();
    let signature_bytes = signature.expose(|raw| raw.to_vec());
    assert!(!signature.is_empty());
    backend.message_sign_final(session).unwrap();

    backend.message_verify_init(session, Some(&mechanism), key).unwrap();
    assert_eq!(
        backend.verify_message(
            session,
            &sign_parameter,
            CkInBuf::Bytes(b"payload"),
            CkInBuf::Bytes(&signature_bytes)
        ),
        Ok(())
    );
    backend.message_verify_final(session).unwrap();

    backend
        .verify_signature_init(session, Some(&mechanism), key, CkInBuf::Bytes(&signature_bytes))
        .unwrap();
    assert_eq!(backend.verify_signature(session, CkInBuf::Bytes(b"payload")), Ok(()));

    let (wrapped, wrap_parameter_out) = backend
        .wrap_key_authenticated(session, &mechanism, key, key, CkInBuf::Bytes(b"aad"))
        .unwrap();
    let wrapped_bytes = wrapped.expose(|raw| raw.to_vec());
    assert!(!wrapped.is_empty());
    assert!(!wrap_parameter_out.is_empty());
    let (unwrapped, unwrap_parameter_out) = backend
        .unwrap_key_authenticated(
            session,
            &mechanism,
            key,
            CkInBuf::Bytes(&wrapped_bytes),
            &[],
            CkInBuf::Bytes(b"aad"),
        )
        .unwrap();
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
    assert!(!backend.digest(session, CkInBuf::Bytes(b"payload")).unwrap().is_empty());
    assert_eq!(backend.generate_key(session, &sha256, &[]).unwrap_err(), CkRv::MECHANISM_INVALID);
    assert_eq!(backend.encrypt_init(session, &sha256, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    let md5 = CkMechanism { mechanism_type: CkMechanismType::MD5, params: None };
    backend.digest_init(session, &md5).unwrap();
    assert!(!backend.digest(session, CkInBuf::Bytes(b"payload")).unwrap().is_empty());
    assert_eq!(backend.sign_init(session, &md5, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    let aes_gcm = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
    backend.encrypt_init(session, &aes_gcm, key).unwrap();
    let ciphertext = backend.encrypt(session, CkInBuf::Bytes(b"plaintext")).unwrap();
    let ciphertext_bytes = ciphertext.expose(|raw| raw.to_vec());
    backend.decrypt_init(session, &aes_gcm, key).unwrap();
    assert_eq!(
        backend.decrypt(session, CkInBuf::Bytes(&ciphertext_bytes)).unwrap(),
        SecretBytes::copy_from_slice(b"plaintext")
    );
    let wrapped = backend.wrap_key(session, &aes_gcm, key, key).unwrap();
    let wrapped_bytes = wrapped.expose(|raw| raw.to_vec());
    assert!(!wrapped.is_empty());
    assert_ne!(
        backend.unwrap_key(session, &aes_gcm, key, CkInBuf::Bytes(&wrapped_bytes), &[]).unwrap(),
        CkObjectHandle(0)
    );
    backend.message_encrypt_init(session, Some(&aes_gcm), None, key).unwrap();
    assert_eq!(backend.sign_init(session, &aes_gcm, key).unwrap_err(), CkRv::MECHANISM_INVALID);
    assert_eq!(backend.generate_key(session, &aes_gcm, &[]).unwrap_err(), CkRv::MECHANISM_INVALID);

    let ml_kem = CkMechanism { mechanism_type: CkMechanismType(0x0000_0017), params: None };
    let (capsule, encapsulated) = backend.encapsulate_key(session, &ml_kem, key, &[]).unwrap();
    let capsule_bytes = capsule.expose(|raw| raw.to_vec());
    assert!(!capsule.is_empty());
    assert_ne!(encapsulated, CkObjectHandle(0));
    assert_ne!(
        backend
            .decapsulate_key(session, &ml_kem, key, &[], CkInBuf::Bytes(&capsule_bytes))
            .unwrap(),
        CkObjectHandle(0)
    );
    assert_eq!(backend.encrypt_init(session, &ml_kem, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    let md2_rsa_pkcs = CkMechanism { mechanism_type: CkMechanismType(0x0000_0004), params: None };
    backend.sign_init(session, &md2_rsa_pkcs, key).unwrap();
    let signature = backend.sign(session, CkInBuf::Bytes(b"payload")).unwrap();
    let signature_bytes = signature.expose(|raw| raw.to_vec());
    backend.verify_init(session, &md2_rsa_pkcs, key).unwrap();
    backend.verify(session, CkInBuf::Bytes(b"payload"), CkInBuf::Bytes(&signature_bytes)).unwrap();
    assert_eq!(
        backend.encrypt_init(session, &md2_rsa_pkcs, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let tls_prf = CkMechanism { mechanism_type: CkMechanismType::TLS_PRF, params: None };
    assert_ne!(backend.derive_key(session, &tls_prf, key, &[]).unwrap(), CkObjectHandle(0));
    assert_eq!(backend.sign_init(session, &tls_prf, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    let des_cbc_pad = CkMechanism { mechanism_type: CkMechanismType::DES_CBC_PAD, params: None };
    backend.encrypt_init(session, &des_cbc_pad, key).unwrap();
    let des_ciphertext = backend.encrypt(session, CkInBuf::Bytes(b"plaintext")).unwrap();
    let des_ciphertext_bytes = des_ciphertext.expose(|raw| raw.to_vec());
    backend.decrypt_init(session, &des_cbc_pad, key).unwrap();
    assert_eq!(
        backend.decrypt(session, CkInBuf::Bytes(&des_ciphertext_bytes)).unwrap(),
        SecretBytes::copy_from_slice(b"plaintext")
    );
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
    let des_signature = backend.sign(session, CkInBuf::Bytes(b"payload")).unwrap();
    let des_signature_bytes = des_signature.expose(|raw| raw.to_vec());
    backend.verify_init(session, &des_mac, key).unwrap();
    backend
        .verify(session, CkInBuf::Bytes(b"payload"), CkInBuf::Bytes(&des_signature_bytes))
        .unwrap();
    assert_eq!(backend.encrypt_init(session, &des_mac, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    // A mechanism grounded by neither the current nor the historical spec
    // (CKM_CAMELLIA_CTR) has no workflow flags, so every keyed op rejects it.
    let no_source = CkMechanism { mechanism_type: CkMechanismType(0x0000_0558), params: None };
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

    assert!(no_source_mechanisms.contains(&CkMechanismType(0x0000_0558))); // CKM_CAMELLIA_CTR
    assert!(no_source_mechanisms.contains(&CkMechanismType(0x0000_1012))); // CKM_KEA_DERIVE
    assert!(no_source_mechanisms.contains(&CkMechanismType(0x0000_0375))); // CKM_TLS_MASTER_KEY_DERIVE

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
            backend.unwrap_key(session, &mechanism, key, CkInBuf::Bytes(b"wrapped"), &[]),
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
            backend.decapsulate_key(session, &mechanism, key, &[], CkInBuf::Bytes(b"ciphertext")),
        );
        assert_mechanism_invalid(
            "message_encrypt_init",
            mechanism_type,
            backend.message_encrypt_init(session, Some(&mechanism), None, key),
        );
        assert_mechanism_invalid(
            "message_decrypt_init",
            mechanism_type,
            backend.message_decrypt_init(session, Some(&mechanism), None, key),
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
            backend.verify_signature_init(
                session,
                Some(&mechanism),
                key,
                CkInBuf::Bytes(b"signature"),
            ),
        );
        assert_mechanism_invalid(
            "wrap_key_authenticated",
            mechanism_type,
            backend.wrap_key_authenticated(session, &mechanism, key, key, CkInBuf::Bytes(b"aad")),
        );
        assert_mechanism_invalid(
            "unwrap_key_authenticated",
            mechanism_type,
            backend.unwrap_key_authenticated(
                session,
                &mechanism,
                key,
                CkInBuf::Bytes(b"wrapped"),
                &[],
                CkInBuf::Bytes(b"aad"),
            ),
        );
    }
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
        let signature = backend.sign(session, CkInBuf::Bytes(b"data")).unwrap();
        let signature_bytes = signature.expose(|raw| raw.to_vec());
        assert!(!signature.is_empty(), "sign output for 0x{:08X}", mechanism_type.0);

        backend.verify_init(session, &mechanism, key).unwrap();
        backend.verify(session, CkInBuf::Bytes(b"data"), CkInBuf::Bytes(&signature_bytes)).unwrap();

        backend.sign_recover_init(session, &mechanism, key).unwrap();
        let recovered_signature = backend.sign_recover(session, CkInBuf::Bytes(b"data")).unwrap();
        let recovered_signature_bytes = recovered_signature.expose(|raw| raw.to_vec());
        assert!(
            !recovered_signature.is_empty(),
            "sign-recover output for 0x{:08X}",
            mechanism_type.0
        );

        backend.verify_recover_init(session, &mechanism, key).unwrap();
        let recovered_data =
            backend.verify_recover(session, CkInBuf::Bytes(&recovered_signature_bytes)).unwrap();
        assert!(!recovered_data.is_empty(), "verify-recover output for 0x{:08X}", mechanism_type.0);

        backend.sign_init(session, &mechanism, key).unwrap();
        backend.sign_update(session, CkInBuf::Bytes(b"part")).unwrap();
        let multipart_signature = backend.sign_final(session).unwrap();
        let multipart_signature_bytes = multipart_signature.expose(|raw| raw.to_vec());
        assert!(
            !multipart_signature.is_empty(),
            "multipart sign output for 0x{:08X}",
            mechanism_type.0
        );

        backend.verify_init(session, &mechanism, key).unwrap();
        backend.verify_update(session, CkInBuf::Bytes(b"part")).unwrap();
        backend.verify_final(session, CkInBuf::Bytes(&multipart_signature_bytes)).unwrap();

        backend.digest_init(session, &mechanism).unwrap();
        let digest = backend.digest(session, CkInBuf::Bytes(b"data")).unwrap();
        assert!(!digest.is_empty(), "digest output for 0x{:08X}", mechanism_type.0);

        backend.digest_init(session, &mechanism).unwrap();
        backend.digest_update(session, CkInBuf::Bytes(b"part")).unwrap();
        assert!(
            !backend.digest_final(session).unwrap().is_empty(),
            "multipart digest output for 0x{:08X}",
            mechanism_type.0
        );

        backend.encrypt_init(session, &mechanism, key).unwrap();
        let ciphertext = backend.encrypt(session, CkInBuf::Bytes(b"plaintext")).unwrap();
        let ciphertext_bytes = ciphertext.expose(|raw| raw.to_vec());
        assert!(
            ciphertext.expose(|raw| raw != b"plaintext"),
            "encrypt output for 0x{:08X}",
            mechanism_type.0
        );

        backend.encrypt_init(session, &mechanism, key).unwrap();
        assert!(
            !backend.encrypt_update(session, CkInBuf::Bytes(b"part")).unwrap().is_empty(),
            "encrypt-update output for 0x{:08X}",
            mechanism_type.0
        );
        backend.encrypt_final(session).unwrap();

        backend.decrypt_init(session, &mechanism, key).unwrap();
        assert_eq!(
            backend.decrypt(session, CkInBuf::Bytes(&ciphertext_bytes)).unwrap(),
            SecretBytes::copy_from_slice(b"plaintext")
        );

        backend.decrypt_init(session, &mechanism, key).unwrap();
        assert!(
            !backend.decrypt_update(session, CkInBuf::Bytes(&ciphertext_bytes)).unwrap().is_empty(),
            "decrypt-update output for 0x{:08X}",
            mechanism_type.0
        );
        backend.decrypt_final(session).unwrap();

        assert!(backend.derive_key(session, &mechanism, key, &[]).is_ok());
        assert!(backend.generate_key(session, &mechanism, &[]).is_ok());
        assert!(backend.generate_key_pair(session, &mechanism, &[], &[]).is_ok());
        let wrapping_key = backend.create_object(session, &[]).unwrap();
        let wrapped = backend.wrap_key(session, &mechanism, wrapping_key, key).unwrap();
        let wrapped_bytes = wrapped.expose(|raw| raw.to_vec());
        assert!(!wrapped.is_empty(), "wrap output for 0x{:08X}", mechanism_type.0);
        assert!(
            backend
                .unwrap_key(session, &mechanism, wrapping_key, CkInBuf::Bytes(&wrapped_bytes), &[])
                .is_ok()
        );

        let (capsule, encapsulated_key) =
            backend.encapsulate_key(session, &mechanism, key, &[]).unwrap();
        let capsule_bytes = capsule.expose(|raw| raw.to_vec());
        assert!(!capsule.is_empty(), "encapsulate output for 0x{:08X}", mechanism_type.0);
        assert_ne!(encapsulated_key, CkObjectHandle(0));
        assert_ne!(
            backend
                .decapsulate_key(session, &mechanism, key, &[], CkInBuf::Bytes(&capsule_bytes))
                .unwrap(),
            CkObjectHandle(0)
        );

        let mut message_parameter = vec![0x11, 0x22, 0x33, 0x44];
        backend.message_encrypt_init(session, Some(&mechanism), None, key).unwrap();
        let (message_encrypt_parameter, message_ciphertext) = backend
            .encrypt_message(
                session,
                &mut message_parameter,
                CkInBuf::Bytes(b"aad"),
                CkInBuf::Bytes(b"message"),
            )
            .unwrap();
        let message_ciphertext_bytes = message_ciphertext.expose(|raw| raw.to_vec());
        assert_eq!(message_encrypt_parameter, message_parameter.clone().into());
        assert!(message_ciphertext.expose(|raw| raw != b"message"));
        backend.message_encrypt_final(session).unwrap();

        backend.message_decrypt_init(session, Some(&mechanism), None, key).unwrap();
        let (message_decrypt_parameter, message_plaintext) = backend
            .decrypt_message(
                session,
                &mut message_parameter,
                CkInBuf::Bytes(b"aad"),
                CkInBuf::Bytes(&message_ciphertext_bytes),
            )
            .unwrap();
        assert_eq!(message_decrypt_parameter, message_parameter.clone().into());
        assert_eq!(message_plaintext, SecretBytes::copy_from_slice(b"message"));
        backend.message_decrypt_final(session).unwrap();

        backend.message_sign_init(session, Some(&mechanism), key).unwrap();
        let (message_sign_parameter, message_signature) = backend
            .sign_message(session, &mut message_parameter, CkInBuf::Bytes(b"payload"))
            .unwrap();
        let message_signature_bytes = message_signature.expose(|raw| raw.to_vec());
        assert_eq!(message_sign_parameter, message_parameter.clone().into());
        assert!(!message_signature.is_empty());
        backend.message_sign_final(session).unwrap();

        backend.message_verify_init(session, Some(&mechanism), key).unwrap();
        backend
            .verify_message(
                session,
                &message_parameter,
                CkInBuf::Bytes(b"payload"),
                CkInBuf::Bytes(&message_signature_bytes),
            )
            .unwrap();
        backend.message_verify_final(session).unwrap();

        backend
            .verify_signature_init(
                session,
                Some(&mechanism),
                key,
                CkInBuf::Bytes(&message_signature_bytes),
            )
            .unwrap();
        backend.verify_signature(session, CkInBuf::Bytes(b"payload")).unwrap();

        let (authenticated_wrapped, authenticated_parameter) = backend
            .wrap_key_authenticated(session, &mechanism, wrapping_key, key, CkInBuf::Bytes(b"aad"))
            .unwrap();
        let authenticated_wrapped_bytes = authenticated_wrapped.expose(|raw| raw.to_vec());
        assert!(!authenticated_wrapped.is_empty());
        assert!(!authenticated_parameter.is_empty());
        let (authenticated_unwrapped, authenticated_unwrap_parameter) = backend
            .unwrap_key_authenticated(
                session,
                &mechanism,
                wrapping_key,
                CkInBuf::Bytes(&authenticated_wrapped_bytes),
                &[],
                CkInBuf::Bytes(b"aad"),
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
    let mechanisms = registry
        .registered_mechanisms()
        .into_iter()
        .map(|x| CkMechanismType(x as u64))
        .collect::<Vec<_>>();
    let backend = MockBackend::with_mechanism_registry(vec![CkSlotId(0)], &registry);
    backend.initialize().unwrap();

    for mechanism_type in mechanisms {
        let mechanism = CkMechanism { mechanism_type, params: None };

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.sign_init(session, &mechanism, key).unwrap();
        assert!(!backend.sign(session, CkInBuf::Bytes(b"data")).unwrap().is_empty());
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.sign_init(session, &mechanism, key).unwrap();
        backend.sign_update(session, CkInBuf::Bytes(b"part")).unwrap();
        assert!(!backend.sign_final(session).unwrap().is_empty());
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.sign_recover_init(session, &mechanism, key).unwrap();
        assert!(!backend.sign_recover(session, CkInBuf::Bytes(b"data")).unwrap().is_empty());
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.sign_init(session, &mechanism, key).unwrap();
        let signature = backend.sign(session, CkInBuf::Bytes(b"data")).unwrap();
        let signature_bytes = signature.expose(|raw| raw.to_vec());
        backend.verify_init(session, &mechanism, key).unwrap();
        backend.verify(session, CkInBuf::Bytes(b"data"), CkInBuf::Bytes(&signature_bytes)).unwrap();
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.sign_init(session, &mechanism, key).unwrap();
        backend.sign_update(session, CkInBuf::Bytes(b"part")).unwrap();
        let multipart_signature = backend.sign_final(session).unwrap();
        let multipart_signature_bytes = multipart_signature.expose(|raw| raw.to_vec());
        backend.verify_init(session, &mechanism, key).unwrap();
        backend.verify_update(session, CkInBuf::Bytes(b"part")).unwrap();
        backend.verify_final(session, CkInBuf::Bytes(&multipart_signature_bytes)).unwrap();
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.verify_recover_init(session, &mechanism, key).unwrap();
        assert!(!backend.verify_recover(session, CkInBuf::Bytes(b"signature")).unwrap().is_empty());
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        backend.digest_init(session, &mechanism).unwrap();
        assert!(!backend.digest(session, CkInBuf::Bytes(b"data")).unwrap().is_empty());
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        backend.digest_init(session, &mechanism).unwrap();
        backend.digest_update(session, CkInBuf::Bytes(b"part")).unwrap();
        assert!(!backend.digest_final(session).unwrap().is_empty());
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.encrypt_init(session, &mechanism, key).unwrap();
        let ciphertext = backend.encrypt(session, CkInBuf::Bytes(b"plaintext")).unwrap();
        let ciphertext_bytes = ciphertext.expose(|raw| raw.to_vec());
        assert!(ciphertext.expose(|raw| raw != b"plaintext"));
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.encrypt_init(session, &mechanism, key).unwrap();
        assert!(!backend.encrypt_update(session, CkInBuf::Bytes(b"part")).unwrap().is_empty());
        backend.encrypt_final(session).unwrap();
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.decrypt_init(session, &mechanism, key).unwrap();
        assert_eq!(
            backend.decrypt(session, CkInBuf::Bytes(&ciphertext_bytes)).unwrap(),
            SecretBytes::copy_from_slice(b"plaintext")
        );
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        backend.decrypt_init(session, &mechanism, key).unwrap();
        assert!(
            !backend.decrypt_update(session, CkInBuf::Bytes(&ciphertext_bytes)).unwrap().is_empty()
        );
        backend.decrypt_final(session).unwrap();
        backend.close_session(session).unwrap();

        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let key = backend.create_object(session, &[]).unwrap();
        assert!(backend.derive_key(session, &mechanism, key, &[]).is_ok());
        assert!(backend.generate_key(session, &mechanism, &[]).is_ok());
        assert!(backend.generate_key_pair(session, &mechanism, &[], &[]).is_ok());
        let wrapping_key = backend.create_object(session, &[]).unwrap();
        let wrapped_key = backend.wrap_key(session, &mechanism, wrapping_key, key).unwrap();
        let wrapped_key_bytes = wrapped_key.expose(|raw| raw.to_vec());
        assert!(!wrapped_key.is_empty());
        assert!(
            backend
                .unwrap_key(
                    session,
                    &mechanism,
                    wrapping_key,
                    CkInBuf::Bytes(&wrapped_key_bytes),
                    &[]
                )
                .is_ok()
        );
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
        .unwrap_key(
            session,
            &mechanism,
            generated,
            CkInBuf::Bytes(b"wrapped"),
            &[label_attr("unwrapped")],
        )
        .unwrap();
    assert_mock_label(&backend, session, unwrapped, "unwrapped");

    let (authenticated_unwrapped, authenticated_unwrap_parameter) = backend
        .unwrap_key_authenticated(
            session,
            &mechanism,
            generated,
            CkInBuf::Bytes(b"wrapped"),
            &[label_attr("authenticated-unwrapped")],
            CkInBuf::Bytes(b"aad"),
        )
        .unwrap();
    assert!(!authenticated_unwrap_parameter.is_empty());
    assert_mock_label(&backend, session, authenticated_unwrapped, "authenticated-unwrapped");

    let decapsulated = backend
        .decapsulate_key(
            session,
            &mechanism,
            generated,
            &[label_attr("decapsulated")],
            CkInBuf::Bytes(b"capsule"),
        )
        .unwrap();
    assert_mock_label(&backend, session, decapsulated, "decapsulated");

    let (public, private) = backend
        .generate_key_pair(session, &mechanism, &[label_attr("public")], &[label_attr("private")])
        .unwrap();
    assert_mock_label(&backend, session, public, "public");
    assert_mock_label(&backend, session, private, "private");
}

#[test]
fn key_bearing_workflows_reject_invalid_object_handles() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let invalid_key = CkObjectHandle(999);
    let live_key = live_key(&backend, session);
    let output_spec =
        CkOutputBufferSpec { buffer_present: true, buffer_len: 64, length_pointer_null: false };
    let param_spec = CkParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: 16,
        value: Some(vec![0xAA; 4].into()),
    };

    assert_eq!(
        backend.sign_init(session, &mechanism, invalid_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.sign(session, CkInBuf::Bytes(b"data")).unwrap_err(),
        CkRv::OPERATION_NOT_INITIALIZED
    );
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
            .unwrap_key(
                session,
                &mechanism,
                invalid_key,
                CkInBuf::Bytes(b"wrapped"),
                &[label_attr("unwrapped")]
            )
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
                CkInBuf::Bytes(b"aad"),
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
                CkInBuf::Bytes(b"capsule")
            )
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .wrap_key_authenticated(
                session,
                &mechanism,
                live_key,
                invalid_key,
                CkInBuf::Bytes(b"aad")
            )
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .unwrap_key_authenticated(
                session,
                &mechanism,
                invalid_key,
                CkInBuf::Bytes(b"wrapped"),
                &[label_attr("authenticated-unwrapped")],
                CkInBuf::Bytes(b"aad"),
            )
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.message_encrypt_init(session, Some(&mechanism), None, invalid_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.message_decrypt_init(session, Some(&mechanism), None, invalid_key).unwrap_err(),
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
        backend
            .verify_signature_init(session, Some(&mechanism), invalid_key, CkInBuf::Bytes(b"sig"))
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
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
    let ciphertext = backend.encrypt(session, CkInBuf::Bytes(plaintext)).unwrap();
    assert!(ciphertext.expose(|raw| raw != plaintext));
    backend.decrypt_init(session, &mech, key).unwrap();
    let recovered = ciphertext.expose(|raw| backend.decrypt(session, CkInBuf::Bytes(raw)).unwrap());
    assert!(recovered.expose(|raw| raw == plaintext));
}

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
    assert!(backend.sign(session, CkInBuf::Bytes(b"data")).is_ok());
}

#[test]
fn sign_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let err = backend.sign(session, CkInBuf::Bytes(b"data")).unwrap_err();
    assert_eq!(err, CkRv::OPERATION_NOT_INITIALIZED);
}

#[test]
fn sign_update_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(
        backend.sign_update(session, CkInBuf::Bytes(b"chunk")).unwrap_err(),
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
    backend.sign_update(session, CkInBuf::Bytes(b"part1")).unwrap();
    backend.sign_update(session, CkInBuf::Bytes(b"part2")).unwrap();
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
    assert!(backend.digest(session, CkInBuf::Bytes(b"hello")).is_ok());
}

#[test]
fn digest_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(
        backend.digest(session, CkInBuf::Bytes(b"data")).unwrap_err(),
        CkRv::OPERATION_NOT_INITIALIZED
    );
}

#[test]
fn digest_multi_part_sequence_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    backend.digest_init(session, &mech).unwrap();
    backend.digest_update(session, CkInBuf::Bytes(b"chunk1")).unwrap();
    backend.digest_update(session, CkInBuf::Bytes(b"chunk2")).unwrap();
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
    assert!(backend.encrypt(session, CkInBuf::Bytes(b"plaintext")).is_ok());
}

#[test]
fn encrypt_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(
        backend.encrypt(session, CkInBuf::Bytes(b"data")).unwrap_err(),
        CkRv::OPERATION_NOT_INITIALIZED
    );
}

#[test]
fn decrypt_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(
        backend.decrypt(session, CkInBuf::Bytes(b"data")).unwrap_err(),
        CkRv::OPERATION_NOT_INITIALIZED
    );
}

#[test]
fn encrypt_multi_part_sequence_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let key = live_key(&backend, session);
    backend.encrypt_init(session, &mech, key).unwrap();
    let _part = backend.encrypt_update(session, CkInBuf::Bytes(b"part1")).unwrap();
    assert!(backend.encrypt_final(session).is_ok());
}

#[test]
fn digest_rejects_null_with_nonzero_len() {
    // `digest` is a data-consuming method; Null { len > 0 } must be ARGUMENTS_BAD.
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let sha256 = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    backend.digest_init(session, &sha256).unwrap();
    assert_eq!(backend.digest(session, CkInBuf::Null { len: 5 }).unwrap_err(), CkRv::ARGUMENTS_BAD,);
}

#[test]
fn sign_rejects_null_with_nonzero_len() {
    // `sign` was previously a stub that ignored its data argument; it must now
    // uniformly reject Null { len > 0 } before attempting the operation.
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = live_key(&backend, session);
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.sign_init(session, &mech, key).unwrap();
    assert_eq!(backend.sign(session, CkInBuf::Null { len: 5 }).unwrap_err(), CkRv::ARGUMENTS_BAD,);
}

#[test]
fn digest_update_rejects_null_with_nonzero_len() {
    // `digest_update` must validate its data argument and reject Null { len > 0 }.
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let sha256 = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    backend.digest_init(session, &sha256).unwrap();
    assert_eq!(
        backend.digest_update(session, CkInBuf::Null { len: 5 }).unwrap_err(),
        CkRv::ARGUMENTS_BAD,
    );
}

#[test]
fn encrypt_message_rejects_null_aad_with_nonzero_len() {
    // `encrypt_message` must validate the aad argument and reject Null { len > 0 }.
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = live_key(&backend, session);
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.message_encrypt_init(session, Some(&mech), None, key).unwrap();
    let mut parameter = vec![0x11, 0x22, 0x33, 0x44];
    assert_eq!(
        backend
            .encrypt_message(
                session,
                &mut parameter,
                CkInBuf::Null { len: 5 },
                CkInBuf::Bytes(b"plaintext"),
            )
            .unwrap_err(),
        CkRv::ARGUMENTS_BAD,
    );
}

#[test]
fn decrypt_message_rejects_null_aad_with_nonzero_len() {
    // `decrypt_message` must validate the aad argument and reject Null { len > 0 }.
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = live_key(&backend, session);
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.message_decrypt_init(session, Some(&mech), None, key).unwrap();
    let mut parameter = vec![0x11, 0x22, 0x33, 0x44];
    assert_eq!(
        backend
            .decrypt_message(
                session,
                &mut parameter,
                CkInBuf::Null { len: 5 },
                CkInBuf::Bytes(b"ciphertext"),
            )
            .unwrap_err(),
        CkRv::ARGUMENTS_BAD,
    );
}

#[test]
fn mechanism_info_reports_spec_grounded_key_sizes() {
    // AES: 16/24/32-byte keys (bytes, per the OASIS convention the mock
    // follows for symmetric key sizes); DES3: fixed 24. Mechanisms whose
    // spec tables define no size keep the mock's generic default.
    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![
            CkMechanismType::AES_KEY_GEN,
            CkMechanismType::DES3_KEY_GEN,
            CkMechanismType::RSA_PKCS_KEY_PAIR_GEN,
        ],
    );
    backend.initialize().unwrap();

    let aes = backend.get_mechanism_info(CkSlotId(0), CkMechanismType::AES_KEY_GEN).unwrap();
    assert_eq!(aes.min_key_size, 16);
    assert_eq!(aes.max_key_size, 32);

    let des3 = backend.get_mechanism_info(CkSlotId(0), CkMechanismType::DES3_KEY_GEN).unwrap();
    assert_eq!(des3.min_key_size, 24);
    assert_eq!(des3.max_key_size, 24);

    // A mechanism without a spec-grounded size table keeps the generic
    // default (asymmetric key-pair gen).
    let rsa =
        backend.get_mechanism_info(CkSlotId(0), CkMechanismType::RSA_PKCS_KEY_PAIR_GEN).unwrap();
    assert_eq!((rsa.min_key_size, rsa.max_key_size), (2048, 4096));
}

#[test]
fn historically_grounded_mechanisms_are_accepted_with_workflow_flags() {
    // C1: legacy mechanisms grounded from the historical spec (pkcs11-hist,
    // via the generated historical_flags table) must be accepted by the
    // mock — a client using SKIPJACK/CAST/RC/DES/IDEA/GOST legacy
    // mechanisms through the proxy is exercised, not blanket-rejected.
    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![
            CkMechanismType(0x0000_0122), // CKM_DES_CBC (enc/dec + wrap)
            CkMechanismType(0x0000_0322), // CKM_CAST5_CBC
            CkMechanismType(0x0000_1010), // CKM_SKIPJACK_ECB64
            CkMechanismType(0x0000_1030), // CKM_BATON_KEY_GEN (generate)
        ],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = backend.create_object(session, &[]).unwrap();

    // DES-CBC grounded with ENCRYPT/DECRYPT: encrypt_init is accepted.
    let des_cbc = CkMechanism { mechanism_type: CkMechanismType(0x0000_0122), params: None };
    backend.encrypt_init(session, &des_cbc, key).unwrap();
    backend.encrypt_init_cancel(session).unwrap();

    // BATON_KEY_GEN grounded with GENERATE: generate_key is accepted.
    let baton_gen = CkMechanism { mechanism_type: CkMechanismType(0x0000_1030), params: None };
    assert_ne!(backend.generate_key(session, &baton_gen, &[]).unwrap(), CkObjectHandle(0));

    // Every advertised historical mechanism reports non-empty flags.
    for mech in [CkMechanismType(0x0000_0322), CkMechanismType(0x0000_1010)] {
        let info = backend.get_mechanism_info(CkSlotId(0), mech).unwrap();
        assert_ne!(info.flags, CkMechanismFlags::default(), "{mech:?} should be grounded");
    }
}

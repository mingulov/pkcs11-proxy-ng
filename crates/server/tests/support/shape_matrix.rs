//! Representative full-stack case per [`CkMechanismParams`] variant (W1-L9-09).
//!
//! The sample parameter values below are adapted from the proto round-trip
//! tests (`crates/proto/src/convert/mechanism/tests.rs`); each case pairs one
//! shape with a representative mechanism ID (per
//! `crates/types/src/mechanism_params_default.toml` or the vendor examples,
//! noted per case) and a key hint for the live-backend driver in
//! `parameterized_mechanism_test.rs`.
//!
//! Exhaustiveness is fail-closed: [`variant_name`] matches exhaustively over
//! [`CkMechanismParams`], so adding a variant breaks compilation until this
//! table covers it, and the driver asserts the table length equals
//! [`EXPECTED_SHAPE_COUNT`].

use pkcs11_proxy_ng_types::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeKeyHint {
    Aes,
    GenericSecret,
    RsaPrivate,
    RsaPublic,
    EcPrivate,
}

pub struct ShapeCase {
    pub variant: &'static str,
    pub mechanism: CkMechanism,
    pub key: ShapeKeyHint,
}

/// Number of [`CkMechanismParams`] variants (tracks the OASIS inventory
/// `mechanism_parameter_shape_count`, currently 79).
pub const EXPECTED_SHAPE_COUNT: usize = 79;

pub fn all_shape_cases() -> Vec<ShapeCase> {
    vec![
        // RsaPkcsPss.
        ShapeCase {
            variant: "RsaPkcsPss",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::RSA_PKCS_PSS,
                params: Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
                    hash_alg: CkMechanismType::SHA256,
                    mgf: CkMgf(1),
                    salt_len: 32,
                })),
            },
            key: ShapeKeyHint::RsaPrivate,
        },
        // RsaPkcsOaep.
        ShapeCase {
            variant: "RsaPkcsOaep",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::RSA_PKCS_OAEP,
                params: Some(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
                    hash_alg: CkMechanismType::SHA256,
                    mgf: CkMgf(1),
                    source: CkOaepSource(1),
                    source_data: vec![1, 2, 3].into(),

                    source_null: false,
                })),
            },
            key: ShapeKeyHint::RsaPublic,
        },
        // Gcm.
        ShapeCase {
            variant: "Gcm",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::AES_GCM,
                params: Some(CkMechanismParams::Gcm(GcmParams {
                    iv: vec![0u8; 12],
                    iv_bits: 96,
                    iv_buffer_len: 12,
                    aad: vec![0xAA, 0xBB].into(),
                    tag_bits: 128,

                    iv_null: false,
                    aad_null: false,
                })),
            },
            key: ShapeKeyHint::Aes,
        },
        // Ecdh1Derive.
        ShapeCase {
            variant: "Ecdh1Derive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::ECDH1_DERIVE,
                params: Some(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
                    kdf: CkKdf(2),
                    shared_data: vec![0x01, 0x02, 0x03].into(),
                    public_data: vec![0x04; 65],
                })),
            },
            key: ShapeKeyHint::EcPrivate,
        },
        // Iv.
        ShapeCase {
            variant: "Iv",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::AES_CBC,
                params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0x01; 16] })),
            },
            key: ShapeKeyHint::Aes,
        },
        // Rc5: CKM_RC5_ECB per default registry.
        ShapeCase {
            variant: "Rc5",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x0331),
                params: Some(CkMechanismParams::Rc5(Rc5Params { word_size: 4, rounds: 12 })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Rc5MacGeneral: CKM_RC5_MAC_GENERAL per default registry.
        ShapeCase {
            variant: "Rc5MacGeneral",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x0334),
                params: Some(CkMechanismParams::Rc5MacGeneral(Rc5MacGeneralParams {
                    word_size: 4,
                    rounds: 12,
                    mac_length: 16,
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Rc2MacGeneral: CKM_RC2_MAC_GENERAL per default registry.
        ShapeCase {
            variant: "Rc2MacGeneral",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x0104),
                params: Some(CkMechanismParams::Rc2MacGeneral(Rc2MacGeneralParams {
                    effective_bits: 128,
                    mac_length: 8,
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Xeddsa.
        ShapeCase {
            variant: "Xeddsa",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::XEDDSA,
                params: Some(CkMechanismParams::Xeddsa(XeddsaParams {
                    hash: CkMechanismType(0x250),
                })),
            },
            key: ShapeKeyHint::EcPrivate,
        },
        // TlsMac.
        ShapeCase {
            variant: "TlsMac",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::TLS_MAC,
                params: Some(CkMechanismParams::TlsMac(TlsMacParams {
                    prf_hash_mechanism: CkMechanismType(0x250),
                    mac_length: 32,
                    server_or_client: 1,
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // AesCtr.
        ShapeCase {
            variant: "AesCtr",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::AES_CTR,
                params: Some(CkMechanismParams::AesCtr(AesCtrParams {
                    counter_bits: 128,
                    cb: vec![0x01; 16],
                })),
            },
            key: ShapeKeyHint::Aes,
        },
        // CamelliaCtr: CKM_CAMELLIA_CTR per default registry.
        ShapeCase {
            variant: "CamelliaCtr",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x0558),
                params: Some(CkMechanismParams::CamelliaCtr(CamelliaCtrParams {
                    counter_bits: 64,
                    cb: vec![0xAB; 16],
                })),
            },
            key: ShapeKeyHint::Aes,
        },
        // Rc2Cbc: CKM_RC2_CBC per default registry.
        ShapeCase {
            variant: "Rc2Cbc",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x0102),
                params: Some(CkMechanismParams::Rc2Cbc(Rc2CbcParams {
                    effective_bits: 64,
                    iv: vec![0x11; 8],
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Rc5Cbc: CKM_RC5_CBC per default registry.
        ShapeCase {
            variant: "Rc5Cbc",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x0332),
                params: Some(CkMechanismParams::Rc5Cbc(Rc5CbcParams {
                    word_size: 4,
                    rounds: 16,
                    iv: vec![0xCC; 8],
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // AesCbcEncryptData.
        ShapeCase {
            variant: "AesCbcEncryptData",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::AES_CBC_ENCRYPT_DATA,
                params: Some(CkMechanismParams::AesCbcEncryptData(AesCbcEncryptDataParams {
                    iv: vec![0x01; 16],
                    data: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
                })),
            },
            key: ShapeKeyHint::Aes,
        },
        // DesCbcEncryptData.
        ShapeCase {
            variant: "DesCbcEncryptData",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::DES_CBC_ENCRYPT_DATA,
                params: Some(CkMechanismParams::DesCbcEncryptData(DesCbcEncryptDataParams {
                    iv: vec![0xAA; 8],
                    data: vec![0x01, 0x02, 0x03].into(),
                })),
            },
            key: ShapeKeyHint::Aes,
        },
        // AriaCbcEncryptData.
        ShapeCase {
            variant: "AriaCbcEncryptData",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::ARIA_CBC_ENCRYPT_DATA,
                params: Some(CkMechanismParams::AriaCbcEncryptData(AriaCbcEncryptDataParams {
                    iv: vec![0xBB; 16],
                    data: vec![0x10; 32].into(),
                })),
            },
            key: ShapeKeyHint::Aes,
        },
        // CamelliaCbcEncryptData.
        ShapeCase {
            variant: "CamelliaCbcEncryptData",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::CAMELLIA_CBC_ENCRYPT_DATA,
                params: Some(CkMechanismParams::CamelliaCbcEncryptData(
                    CamelliaCbcEncryptDataParams {
                        iv: vec![0xCC; 16],
                        data: vec![0x20; 48].into(),
                    },
                )),
            },
            key: ShapeKeyHint::Aes,
        },
        // SeedCbcEncryptData.
        ShapeCase {
            variant: "SeedCbcEncryptData",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::SEED_CBC_ENCRYPT_DATA,
                params: Some(CkMechanismParams::SeedCbcEncryptData(SeedCbcEncryptDataParams {
                    iv: vec![0xDD; 16],
                    data: vec![].into(),
                })),
            },
            key: ShapeKeyHint::Aes,
        },
        // Ccm.
        ShapeCase {
            variant: "Ccm",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::AES_CCM,
                params: Some(CkMechanismParams::Ccm(CcmParams {
                    data_len: 256,
                    nonce: vec![0x01; 12],
                    aad: vec![0xAA, 0xBB].into(),
                    mac_len: 16,
                })),
            },
            key: ShapeKeyHint::Aes,
        },
        // ChaCha20.
        ShapeCase {
            variant: "ChaCha20",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::CHACHA20,
                params: Some(CkMechanismParams::ChaCha20(ChaCha20Params {
                    block_counter: vec![0x00; 4],
                    block_counter_bits: 32,
                    nonce: vec![0x01; 12],
                    nonce_bits: 96,
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Salsa20.
        ShapeCase {
            variant: "Salsa20",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::SALSA20,
                params: Some(CkMechanismParams::Salsa20(Salsa20Params {
                    block_counter: vec![0x00; 8],
                    nonce: vec![0x02; 8],
                    nonce_bits: 64,
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Salsa20ChaCha20Poly1305.
        ShapeCase {
            variant: "Salsa20ChaCha20Poly1305",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::CHACHA20_POLY1305,
                params: Some(CkMechanismParams::Salsa20ChaCha20Poly1305(
                    Salsa20ChaCha20Poly1305Params {
                        nonce: vec![0x03; 12],
                        aad: vec![0x04; 20].into(),
                    },
                )),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // GcmWrap: representative v3.2 CKM_AES_GCM_KDP id; provider support decides.
        ShapeCase {
            variant: "GcmWrap",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x1096),
                params: Some(CkMechanismParams::GcmWrap(GcmWrapParams {
                    iv: vec![0x01; 12],
                    iv_fixed_bits: 32,
                    iv_generator: CkGeneratorFunction(1),
                    aad: vec![0xAA].into(),
                    tag_bits: 128,
                })),
            },
            key: ShapeKeyHint::Aes,
        },
        // CcmWrap: representative v3.2 CKM_AES_CCM_KDP id; provider support decides.
        ShapeCase {
            variant: "CcmWrap",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x1097),
                params: Some(CkMechanismParams::CcmWrap(CcmWrapParams {
                    data_len: 1024,
                    nonce: vec![0x02; 7],
                    nonce_fixed_bits: 24,
                    nonce_generator: CkGeneratorFunction(2),
                    aad: vec![0xBB, 0xCC].into(),
                    mac_len: 8,
                })),
            },
            key: ShapeKeyHint::Aes,
        },
        // Ecdh2Derive: cofactor derive accepts ECDH2 params.
        ShapeCase {
            variant: "Ecdh2Derive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::ECDH1_COFACTOR_DERIVE,
                params: Some(CkMechanismParams::Ecdh2Derive(Ecdh2DeriveParams {
                    kdf: CkKdf(2),
                    shared_data: vec![0x01, 0x02].into(),
                    public_data: vec![0x04; 65],
                    private_data_len: 32,
                    private_data_handle: CkObjectHandle(0x1234),
                    public_data2: vec![0x04; 65],
                })),
            },
            key: ShapeKeyHint::EcPrivate,
        },
        // EcmqvDerive.
        ShapeCase {
            variant: "EcmqvDerive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::ECMQV_DERIVE,
                params: Some(CkMechanismParams::EcmqvDerive(EcmqvDeriveParams {
                    kdf: CkKdf(3),
                    shared_data: vec![0xAA].into(),
                    public_data: vec![0x04; 33],
                    private_data_len: 16,
                    private_data_handle: CkObjectHandle(0xABCD),
                    public_data2: vec![0x04; 33],
                    public_key_handle: CkObjectHandle(0xDEAD),
                })),
            },
            key: ShapeKeyHint::EcPrivate,
        },
        // X942Dh1Derive.
        ShapeCase {
            variant: "X942Dh1Derive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::X9_42_DH_DERIVE,
                params: Some(CkMechanismParams::X942Dh1Derive(X942Dh1DeriveParams {
                    kdf: CkKdf(1),
                    other_info: vec![0x10, 0x20].into(),
                    public_data: vec![0x55; 128],
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // X942Dh2Derive.
        ShapeCase {
            variant: "X942Dh2Derive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::X9_42_DH_HYBRID_DERIVE,
                params: Some(CkMechanismParams::X942Dh2Derive(X942Dh2DeriveParams {
                    kdf: CkKdf(2),
                    other_info: vec![].into(),
                    public_data: vec![0x55; 128],
                    private_data_len: 64,
                    private_data_handle: CkObjectHandle(42),
                    public_data2: vec![0x66; 128],
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // X942MqvDerive.
        ShapeCase {
            variant: "X942MqvDerive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::X9_42_MQV_DERIVE,
                params: Some(CkMechanismParams::X942MqvDerive(X942MqvDeriveParams {
                    kdf: CkKdf(3),
                    other_info: vec![0xFF].into(),
                    public_data: vec![0x11; 64],
                    private_data_len: 32,
                    private_data_handle: CkObjectHandle(100),
                    public_data2: vec![0x22; 64],
                    public_key_handle: CkObjectHandle(200),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Hkdf.
        ShapeCase {
            variant: "Hkdf",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::HKDF_DERIVE,
                params: Some(CkMechanismParams::Hkdf(HkdfParams {
                    extract: true,
                    expand: true,
                    prf_hash_mechanism: CkMechanismType::SHA256,
                    salt_type: 1,
                    salt: vec![0xAA; 32].into(),
                    salt_key_handle: CkObjectHandle(0),
                    info: vec![0xBB; 16].into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Eddsa.
        ShapeCase {
            variant: "Eddsa",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::EDDSA,
                params: Some(CkMechanismParams::Eddsa(EddsaParams {
                    ph_flag: true,
                    context_data: vec![0x01, 0x02, 0x03].into(),
                })),
            },
            key: ShapeKeyHint::EcPrivate,
        },
        // Gostr3410Derive.
        ShapeCase {
            variant: "Gostr3410Derive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::GOSTR3410_DERIVE,
                params: Some(CkMechanismParams::Gostr3410Derive(Gostr3410DeriveParams {
                    kdf: CkKdf(1),
                    public_data: vec![0xCC; 64],
                    ukm: vec![0xDD; 8],
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // KeaDerive: CKM_KEA_KEY_DERIVE per default registry.
        ShapeCase {
            variant: "KeaDerive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x1011),
                params: Some(CkMechanismParams::KeaDerive(KeaDeriveParams {
                    is_sender: true,
                    random_a: vec![0x11; 128],
                    random_b: vec![0x22; 128],
                    public_data: vec![0x33; 128],
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // EcdhAesKeyWrap.
        ShapeCase {
            variant: "EcdhAesKeyWrap",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::ECDH_AES_KEY_WRAP,
                params: Some(CkMechanismParams::EcdhAesKeyWrap(EcdhAesKeyWrapParams {
                    aes_key_bits: 256,
                    kdf: CkKdf(2),
                    shared_data: vec![0xAA, 0xBB].into(),
                })),
            },
            key: ShapeKeyHint::EcPrivate,
        },
        // RsaAesKeyWrap.
        ShapeCase {
            variant: "RsaAesKeyWrap",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::RSA_AES_KEY_WRAP,
                params: Some(CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
                    aes_key_bits: 128,
                    oaep_params: RsaPkcsOaepParams {
                        hash_alg: CkMechanismType::SHA256,
                        mgf: CkMgf(1),
                        source: CkOaepSource(1),
                        source_data: vec![0x01, 0x02].into(),

                        source_null: false,
                    },
                })),
            },
            key: ShapeKeyHint::RsaPrivate,
        },
        // Gostr3410KeyWrap.
        ShapeCase {
            variant: "Gostr3410KeyWrap",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::GOSTR3410_KEY_WRAP,
                params: Some(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
                    wrap_oid: vec![0x06, 0x07, 0x2A],
                    ukm: vec![0xEE; 8],
                    key_handle: CkObjectHandle(0xBEEF),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // KeyWrapSetOaep: CKM_KEY_WRAP_SET_OAEP per default registry.
        ShapeCase {
            variant: "KeyWrapSetOaep",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x0401),
                params: Some(CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams {
                    bc: 42,
                    x: vec![0xFF; 8].into(),
                })),
            },
            key: ShapeKeyHint::RsaPublic,
        },
        // Pbe.
        ShapeCase {
            variant: "Pbe",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::PBE_SHA1_DES3_EDE_CBC,
                params: Some(CkMechanismParams::Pbe(PbeParams {
                    init_vector: vec![0x01; 16].into(),
                    password: vec![0x70, 0x61, 0x73, 0x73].into(), // "pass"
                    salt: vec![0xAA; 16].into(),
                    iteration: 10000,
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Pkcs5Pbkd2.
        ShapeCase {
            variant: "Pkcs5Pbkd2",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::PKCS5_PBKD2,
                params: Some(CkMechanismParams::Pkcs5Pbkd2(Pkcs5Pbkd2Params {
                    salt_source: CkPbkdf2SaltSource(1),
                    salt_source_data: vec![0xBB; 16].into(),
                    iterations: 600000,
                    prf: CkPbkdf2Prf(2),
                    prf_data: vec![].into(),
                    password: vec![0x73, 0x65, 0x63, 0x72, 0x65, 0x74].into(), // "secret"
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // TlsPrf.
        ShapeCase {
            variant: "TlsPrf",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::TLS_PRF,
                params: Some(CkMechanismParams::TlsPrf(TlsPrfParams {
                    seed: vec![0x01; 32].into(),
                    label: vec![0x6D, 0x61, 0x73, 0x74].into(), // "mast"
                    output_len: 48,
                    output: Vec::new().into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // TlsKdf.
        ShapeCase {
            variant: "TlsKdf",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::TLS_KDF,
                params: Some(CkMechanismParams::TlsKdf(TlsKdfParams {
                    prf_mechanism: CkMechanismType(0x250),
                    label: vec![0x6B, 0x65, 0x79].into(), // "key"
                    random_info: SslRandomData {
                        client_random: vec![0xAA; 32],
                        server_random: vec![0xBB; 32],
                    },
                    context_data: vec![0xCC; 16].into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Ssl3MasterKeyDerive.
        ShapeCase {
            variant: "Ssl3MasterKeyDerive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::SSL3_MASTER_KEY_DERIVE,
                params: Some(CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
                    random_info: SslRandomData {
                        client_random: vec![0x11; 32],
                        server_random: vec![0x22; 32],
                    },
                    version_major: 3,
                    version_minor: 0,
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Tls12MasterKeyDerive.
        ShapeCase {
            variant: "Tls12MasterKeyDerive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::TLS12_MASTER_KEY_DERIVE,
                params: Some(CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
                    random_info: SslRandomData {
                        client_random: vec![0x33; 32],
                        server_random: vec![0x44; 32],
                    },
                    version_major: 3,
                    version_minor: 3,
                    prf_hash_mechanism: CkMechanismType(0x250),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Tls12ExtendedMasterKeyDerive.
        ShapeCase {
            variant: "Tls12ExtendedMasterKeyDerive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::TLS12_EXTENDED_MASTER_KEY_DERIVE,
                params: Some(CkMechanismParams::Tls12ExtendedMasterKeyDerive(
                    Tls12ExtendedMasterKeyDeriveParams {
                        prf_hash_mechanism: CkMechanismType(0x260),
                        session_hash: vec![0x55; 48],
                        version_major: 3,
                        version_minor: 3,
                    },
                )),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Ssl3KeyMat.
        ShapeCase {
            variant: "Ssl3KeyMat",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::SSL3_KEY_AND_MAC_DERIVE,
                params: Some(CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                    mac_size_bits: 160,
                    key_size_bits: 128,
                    iv_size_bits: 128,
                    is_export: false,
                    random_info: SslRandomData {
                        client_random: vec![0x66; 32],
                        server_random: vec![0x77; 32],
                    },
                    prf_hash_mechanism: CkMechanismType(0x250),
                    client_mac_secret_handle: CkObjectHandle(101),
                    server_mac_secret_handle: CkObjectHandle(102),
                    client_key_handle: CkObjectHandle(201),
                    server_key_handle: CkObjectHandle(202),
                    client_iv: vec![0xA1; 16].into(),
                    server_iv: vec![0xB1; 16].into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // WtlsMasterKeyDerive.
        ShapeCase {
            variant: "WtlsMasterKeyDerive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::WTLS_MASTER_KEY_DERIVE,
                params: Some(CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
                    digest_mechanism: CkMechanismType(0x250),
                    random_info: WtlsRandomData {
                        client_random: vec![0x88; 16],
                        server_random: vec![0x99; 16],
                    },
                    version: 1,
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // WtlsPrf.
        ShapeCase {
            variant: "WtlsPrf",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::WTLS_PRF,
                params: Some(CkMechanismParams::WtlsPrf(WtlsPrfParams {
                    digest_mechanism: CkMechanismType(0x260),
                    seed: vec![0xAA; 20].into(),
                    label: vec![0xBB; 10].into(),
                    output_len: 32,
                    output: Vec::new().into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // WtlsKeyMat.
        ShapeCase {
            variant: "WtlsKeyMat",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::WTLS_SERVER_KEY_AND_MAC_DERIVE,
                params: Some(CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
                    digest_mechanism: CkMechanismType(0x250),
                    mac_size_bits: 160,
                    key_size_bits: 128,
                    iv_size_bits: 64,
                    sequence_number: 42,
                    is_export: true,
                    random_info: WtlsRandomData {
                        client_random: vec![0xCC; 16],
                        server_random: vec![0xDD; 16],
                    },
                    mac_secret_handle: CkObjectHandle(101),
                    key_handle: CkObjectHandle(202),
                    iv: vec![0xA1; 8],
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // IkePrfDerive.
        ShapeCase {
            variant: "IkePrfDerive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::IKE_PRF_DERIVE,
                params: Some(CkMechanismParams::IkePrfDerive(IkePrfDeriveParams {
                    prf_mechanism: CkMechanismType(0x250),
                    data_as_key: true,
                    rekey: false,
                    ni: vec![0x01; 32].into(),
                    nr: vec![0x02; 32].into(),
                    new_key_handle: CkObjectHandle(0x1234),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Ike1PrfDerive.
        ShapeCase {
            variant: "Ike1PrfDerive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::IKE1_PRF_DERIVE,
                params: Some(CkMechanismParams::Ike1PrfDerive(Ike1PrfDeriveParams {
                    prf_mechanism: CkMechanismType(0x260),
                    has_prev_key: true,
                    keygxy_handle: CkObjectHandle(0xAAAA),
                    prev_key_handle: CkObjectHandle(0xBBBB),
                    ckyi: vec![0x11; 8].into(),
                    ckyr: vec![0x22; 8].into(),
                    key_number: 3,
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Ike1ExtendedDerive.
        ShapeCase {
            variant: "Ike1ExtendedDerive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::IKE1_EXTENDED_DERIVE,
                params: Some(CkMechanismParams::Ike1ExtendedDerive(Ike1ExtendedDeriveParams {
                    prf_mechanism: CkMechanismType(0x270),
                    has_keygxy: true,
                    keygxy_handle: CkObjectHandle(0xCCCC),
                    extra_data: vec![0x33; 64].into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Ike2PrfPlusDerive.
        ShapeCase {
            variant: "Ike2PrfPlusDerive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::IKE2_PRF_PLUS_DERIVE,
                params: Some(CkMechanismParams::Ike2PrfPlusDerive(Ike2PrfPlusDeriveParams {
                    prf_mechanism: CkMechanismType(0x250),
                    has_seed_key: true,
                    seed_key_handle: CkObjectHandle(0xDDDD),
                    seed_data: vec![0x44; 32].into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Sp800108Kdf: CKM_SP800_108_COUNTER_KDF per default registry.
        ShapeCase {
            variant: "Sp800108Kdf",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x03AC),
                params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                    prf_type: CkMechanismType(0x250),
                    data_params: vec![
                        PrfDataParam { type_: 1, value: vec![0xAA; 4].into() },
                        PrfDataParam { type_: 2, value: vec![0xBB; 8].into() },
                    ],
                    additional_derived_keys: vec![Sp800108DerivedKey {
                        template: vec![
                            CkAttribute {
                                attr_type: CkAttributeType::LABEL,
                                value: Some(CkAttributeValue::String("extra-a".to_string().into())),
                            },
                            CkAttribute {
                                attr_type: CkAttributeType::VALUE_LEN,
                                value: Some(CkAttributeValue::Ulong(32)),
                            },
                        ],
                        key_handle: CkObjectHandle(0xAA55),
                    }],
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Sp800108FeedbackKdf: CKM_SP800_108_FEEDBACK_KDF per default registry.
        ShapeCase {
            variant: "Sp800108FeedbackKdf",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x03AD),
                params: Some(CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                    prf_type: CkMechanismType(0x260),
                    data_params: vec![PrfDataParam { type_: 3, value: vec![0xCC; 16].into() }],
                    iv: vec![0xDD; 16],
                    additional_derived_keys: vec![Sp800108DerivedKey {
                        template: vec![CkAttribute {
                            attr_type: CkAttributeType::VALUE_LEN,
                            value: Some(CkAttributeValue::Ulong(16)),
                        }],
                        key_handle: CkObjectHandle(0xBB66),
                    }],
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // X3dhInitiate.
        ShapeCase {
            variant: "X3dhInitiate",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::X3DH_INITIALIZE,
                params: Some(CkMechanismParams::X3dhInitiate(X3dhInitiateParams {
                    kdf: 1,
                    peer_identity_handle: CkObjectHandle(0x1111),
                    peer_prekey_handle: CkObjectHandle(0x2222),
                    prekey_signature: vec![0xAA; 64],
                    onetime_key_handle: CkObjectHandle(0x3333),
                    own_identity_handle: CkObjectHandle(0x4444),
                    own_ephemeral_handle: CkObjectHandle(0x5555),
                })),
            },
            key: ShapeKeyHint::EcPrivate,
        },
        // X3dhRespond.
        ShapeCase {
            variant: "X3dhRespond",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::X3DH_RESPOND,
                params: Some(CkMechanismParams::X3dhRespond(X3dhRespondParams {
                    kdf: 2,
                    identity_handle: CkObjectHandle(0xAAAA),
                    prekey_handle: CkObjectHandle(0xBBBB),
                    onetime_key_handle: CkObjectHandle(0xCCCC),
                    initiator_identity_handle: CkObjectHandle(0xDDDD),
                    initiator_ephemeral_handle: CkObjectHandle(0xEEEE),
                })),
            },
            key: ShapeKeyHint::EcPrivate,
        },
        // X2RatchetInitialize.
        ShapeCase {
            variant: "X2RatchetInitialize",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::X2RATCHET_INITIALIZE,
                params: Some(CkMechanismParams::X2RatchetInitialize(X2RatchetInitializeParams {
                    sk: vec![0x01; 32].into(),
                    peer_public_prekey_handle: CkObjectHandle(0x1111),
                    peer_public_identity_handle: CkObjectHandle(0x2222),
                    own_public_identity_handle: CkObjectHandle(0x3333),
                    encrypted_header: true,
                    curve: 0x0403, // CKP_EC_NIST_P256 for example
                    aead_mechanism: CkMechanismType(0x1087),
                    kdf_mechanism: CkKdf(0x0250),
                })),
            },
            key: ShapeKeyHint::EcPrivate,
        },
        // X2RatchetRespond.
        ShapeCase {
            variant: "X2RatchetRespond",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::X2RATCHET_RESPOND,
                params: Some(CkMechanismParams::X2RatchetRespond(X2RatchetRespondParams {
                    sk: vec![0x02; 32].into(),
                    own_prekey_handle: CkObjectHandle(0xAAAA),
                    initiator_identity_handle: CkObjectHandle(0xBBBB),
                    own_identity_handle: CkObjectHandle(0xCCCC),
                    encrypted_header: false,
                    curve: 0x0403,
                    aead_mechanism: CkMechanismType(0x1087),
                    kdf_mechanism: CkKdf(0x0260),
                })),
            },
            key: ShapeKeyHint::EcPrivate,
        },
        // Otp.
        ShapeCase {
            variant: "Otp",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::HOTP,
                params: Some(CkMechanismParams::Otp(OtpParams {
                    params: vec![
                        OtpParam { type_: 1, value: vec![0x01; 6].into() },
                        OtpParam { type_: 2, value: vec![0x02; 4].into() },
                    ],
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Kip.
        ShapeCase {
            variant: "Kip",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::KIP_DERIVE,
                params: Some(CkMechanismParams::Kip(KipParams {
                    mechanism: Box::new(CkMechanism {
                        mechanism_type: CkMechanismType::SHA256,
                        params: None,
                    }),
                    key_handle: CkObjectHandle(0xBEEF),
                    seed: vec![0xAA; 16].into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // CmsSig.
        ShapeCase {
            variant: "CmsSig",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::CMS_SIG,
                params: Some(CkMechanismParams::CmsSig(CmsSigParams {
                    certificate_handle: CkObjectHandle(0x42),
                    signing_mechanism: Box::new(CkMechanism {
                        mechanism_type: CkMechanismType::RSA_PKCS,
                        params: None,
                    }),
                    digest_mechanism: Box::new(CkMechanism {
                        mechanism_type: CkMechanismType::SHA256,
                        params: None,
                    }),
                    content_type: "1.2.840.113549.1.7.1".to_string(),
                    requested_attributes: vec![0x30, 0x00].into(),
                    required_attributes: vec![0x31, 0x00].into(),
                })),
            },
            key: ShapeKeyHint::RsaPrivate,
        },
        // SkipjackPrivateWrap: CKM_SKIPJACK_PRIVATE_WRAP.
        ShapeCase {
            variant: "SkipjackPrivateWrap",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x1009),
                params: Some(CkMechanismParams::SkipjackPrivateWrap(SkipjackPrivateWrapParams {
                    password: vec![0x70, 0x61, 0x73, 0x73].into(),
                    public_data: vec![0x11; 128],
                    password_length: 4,
                    random_a: vec![0x22; 20],
                    prime_p: vec![0x33; 128],
                    base_g: vec![0x44; 128],
                    subprime_q: vec![0x55; 20],
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // SkipjackRelayx: CKM_SKIPJACK_RELAYX.
        ShapeCase {
            variant: "SkipjackRelayx",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x100A),
                params: Some(CkMechanismParams::SkipjackRelayx(SkipjackRelayxParams {
                    old_wrapped_x: vec![0x01; 24].into(),
                    old_password: vec![0x02; 8].into(),
                    old_public_data: vec![0x03; 128].into(),
                    old_random_a: vec![0x04; 20].into(),
                    new_password: vec![0x05; 8].into(),
                    new_public_data: vec![0x06; 128].into(),
                    new_random_a: vec![0x07; 20].into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // MacGeneral.
        ShapeCase {
            variant: "MacGeneral",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::AES_MAC_GENERAL,
                params: Some(CkMechanismParams::MacGeneral(MacGeneralParams { mac_length: 16 })),
            },
            key: ShapeKeyHint::Aes,
        },
        // ObjectHandle: per default registry.
        ShapeCase {
            variant: "ObjectHandle",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::CONCATENATE_BASE_AND_KEY,
                params: Some(CkMechanismParams::ObjectHandle(ObjectHandleParam {
                    handle: CkObjectHandle(42),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Extract.
        ShapeCase {
            variant: "Extract",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::EXTRACT_KEY_FROM_KEY,
                params: Some(CkMechanismParams::Extract(ExtractParams { bit_position: 21 })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // SignAdditionalContext: CKM_ML_DSA per default registry.
        ShapeCase {
            variant: "SignAdditionalContext",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x001D),
                params: Some(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                    hedge_variant: 1, // CKH_HEDGE_REQUIRED
                    context: vec![1, 2, 3].into(),
                    hash: CkMechanismType(0),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Kmac: representative CKM_KMAC128 id; provider support decides.
        ShapeCase {
            variant: "Kmac",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x02E1),
                params: Some(CkMechanismParams::Kmac(KmacParams {
                    key_handle: CkObjectHandle(0xCAFE),
                    mac_length: 64,
                    customization_string: b"custom".to_vec().into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // MuGen: CKM_ML_DSA external-mu; provider support decides.
        ShapeCase {
            variant: "MuGen",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x001D),
                params: Some(CkMechanismParams::MuGen(MuGenParams {
                    key_handle: CkObjectHandle(0xA11CE),
                    tr: b"precomputed-tr".to_vec().into(),
                    context: b"context".to_vec().into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // KeyDerivationString.
        ShapeCase {
            variant: "KeyDerivationString",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType::CONCATENATE_BASE_AND_DATA,
                params: Some(CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
                    data: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Raw: representative vendor id for the raw escape hatch.
        ShapeCase {
            variant: "Raw",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x8000_0009),
                params: Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08].into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Ecies: CKM_NC_ECIES per entrust-nshield example.
        ShapeCase {
            variant: "Ecies",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0xDE43_6993),
                params: Some(CkMechanismParams::Ecies(EciesParams {
                    derivation_mechanism: Box::new(CkMechanism {
                        mechanism_type: CkMechanismType::ECDH1_DERIVE,
                        params: None,
                    }),
                    encryption_mechanism: Box::new(CkMechanism {
                        mechanism_type: CkMechanismType::AES_CBC_PAD,
                        params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0xAA; 16] })),
                    }),
                    mac_mechanism: Box::new(CkMechanism {
                        mechanism_type: CkMechanismType::SHA256,
                        params: None,
                    }),
                    shared_data: vec![0x01, 0x02, 0x03].into(),
                })),
            },
            key: ShapeKeyHint::EcPrivate,
        },
        // AesCmacKeyDerivation: per entrust-nshield example.
        ShapeCase {
            variant: "AesCmacKeyDerivation",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0xDE43_6991),
                params: Some(CkMechanismParams::AesCmacKeyDerivation(AesCmacKeyDerivationParams {
                    context: vec![0x10; 32].into(),
                    label: vec![0x20; 16].into(),
                })),
            },
            key: ShapeKeyHint::Aes,
        },
        // Dilithium: CKM_IBM_DILITHIUM per ibm-ep11 example.
        ShapeCase {
            variant: "Dilithium",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x8001_0023),
                params: Some(CkMechanismParams::Dilithium(DilithiumParams { version: 3, mode: 1 })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // Kyber: CKM_IBM_KYBER per ibm-ep11 example.
        ShapeCase {
            variant: "Kyber",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x8001_0024),
                params: Some(CkMechanismParams::Kyber(KyberParams {
                    version: 2,
                    mode: 1,
                    secret_handle: CkObjectHandle(0xDEAD),
                    shared_data: vec![0xAB; 32].into(),
                    blob: vec![0xCD; 64].into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // HdKeyDerive: CKM_IBM_BTC_DERIVE per ibm-ep11 example.
        ShapeCase {
            variant: "HdKeyDerive",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x8007_0001),
                params: Some(CkMechanismParams::HdKeyDerive(HdKeyDeriveParams {
                    derive_type: 32,              // BIP-32
                    child_key_index: 0x8000_0000, // hardened
                    chain_code: vec![0xFF; 32].into(),
                    version: 1,
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // VendorObjectExtract: CKM_CPV4_EXTRACT per thales-luna example.
        ShapeCase {
            variant: "VendorObjectExtract",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x8000_0208),
                params: Some(CkMechanismParams::VendorObjectExtract(VendorObjectExtractParams {
                    format: 1,
                    context: vec![0x42; 24].into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
        // VendorObjectInsert: CKM_CPV4_INSERT per thales-luna example.
        ShapeCase {
            variant: "VendorObjectInsert",
            mechanism: CkMechanism {
                mechanism_type: CkMechanismType(0x8000_0209),
                params: Some(CkMechanismParams::VendorObjectInsert(VendorObjectInsertParams {
                    format: 2,
                    context: vec![0x43; 24].into(),
                    object_data: vec![0xBE, 0xEF, 0xCA, 0xFE].into(),
                })),
            },
            key: ShapeKeyHint::GenericSecret,
        },
    ]
}

/// Fail-closed variant discriminator: exhaustive over [`CkMechanismParams`].
pub fn variant_name(params: &CkMechanismParams) -> &'static str {
    match params {
        CkMechanismParams::RsaPkcsPss(_) => "RsaPkcsPss",
        CkMechanismParams::RsaPkcsOaep(_) => "RsaPkcsOaep",
        CkMechanismParams::Gcm(_) => "Gcm",
        CkMechanismParams::Ecdh1Derive(_) => "Ecdh1Derive",
        CkMechanismParams::Iv(_) => "Iv",
        CkMechanismParams::Rc5(_) => "Rc5",
        CkMechanismParams::Rc5MacGeneral(_) => "Rc5MacGeneral",
        CkMechanismParams::Rc2MacGeneral(_) => "Rc2MacGeneral",
        CkMechanismParams::Xeddsa(_) => "Xeddsa",
        CkMechanismParams::TlsMac(_) => "TlsMac",
        CkMechanismParams::AesCtr(_) => "AesCtr",
        CkMechanismParams::CamelliaCtr(_) => "CamelliaCtr",
        CkMechanismParams::Rc2Cbc(_) => "Rc2Cbc",
        CkMechanismParams::Rc5Cbc(_) => "Rc5Cbc",
        CkMechanismParams::AesCbcEncryptData(_) => "AesCbcEncryptData",
        CkMechanismParams::DesCbcEncryptData(_) => "DesCbcEncryptData",
        CkMechanismParams::AriaCbcEncryptData(_) => "AriaCbcEncryptData",
        CkMechanismParams::CamelliaCbcEncryptData(_) => "CamelliaCbcEncryptData",
        CkMechanismParams::SeedCbcEncryptData(_) => "SeedCbcEncryptData",
        CkMechanismParams::Ccm(_) => "Ccm",
        CkMechanismParams::ChaCha20(_) => "ChaCha20",
        CkMechanismParams::Salsa20(_) => "Salsa20",
        CkMechanismParams::Salsa20ChaCha20Poly1305(_) => "Salsa20ChaCha20Poly1305",
        CkMechanismParams::GcmWrap(_) => "GcmWrap",
        CkMechanismParams::CcmWrap(_) => "CcmWrap",
        CkMechanismParams::Ecdh2Derive(_) => "Ecdh2Derive",
        CkMechanismParams::EcmqvDerive(_) => "EcmqvDerive",
        CkMechanismParams::X942Dh1Derive(_) => "X942Dh1Derive",
        CkMechanismParams::X942Dh2Derive(_) => "X942Dh2Derive",
        CkMechanismParams::X942MqvDerive(_) => "X942MqvDerive",
        CkMechanismParams::Hkdf(_) => "Hkdf",
        CkMechanismParams::Eddsa(_) => "Eddsa",
        CkMechanismParams::Gostr3410Derive(_) => "Gostr3410Derive",
        CkMechanismParams::KeaDerive(_) => "KeaDerive",
        CkMechanismParams::EcdhAesKeyWrap(_) => "EcdhAesKeyWrap",
        CkMechanismParams::RsaAesKeyWrap(_) => "RsaAesKeyWrap",
        CkMechanismParams::Gostr3410KeyWrap(_) => "Gostr3410KeyWrap",
        CkMechanismParams::KeyWrapSetOaep(_) => "KeyWrapSetOaep",
        CkMechanismParams::Pbe(_) => "Pbe",
        CkMechanismParams::Pkcs5Pbkd2(_) => "Pkcs5Pbkd2",
        CkMechanismParams::TlsPrf(_) => "TlsPrf",
        CkMechanismParams::TlsKdf(_) => "TlsKdf",
        CkMechanismParams::Ssl3MasterKeyDerive(_) => "Ssl3MasterKeyDerive",
        CkMechanismParams::Tls12MasterKeyDerive(_) => "Tls12MasterKeyDerive",
        CkMechanismParams::Tls12ExtendedMasterKeyDerive(_) => "Tls12ExtendedMasterKeyDerive",
        CkMechanismParams::Ssl3KeyMat(_) => "Ssl3KeyMat",
        CkMechanismParams::WtlsMasterKeyDerive(_) => "WtlsMasterKeyDerive",
        CkMechanismParams::WtlsPrf(_) => "WtlsPrf",
        CkMechanismParams::WtlsKeyMat(_) => "WtlsKeyMat",
        CkMechanismParams::IkePrfDerive(_) => "IkePrfDerive",
        CkMechanismParams::Ike1PrfDerive(_) => "Ike1PrfDerive",
        CkMechanismParams::Ike1ExtendedDerive(_) => "Ike1ExtendedDerive",
        CkMechanismParams::Ike2PrfPlusDerive(_) => "Ike2PrfPlusDerive",
        CkMechanismParams::Sp800108Kdf(_) => "Sp800108Kdf",
        CkMechanismParams::Sp800108FeedbackKdf(_) => "Sp800108FeedbackKdf",
        CkMechanismParams::X3dhInitiate(_) => "X3dhInitiate",
        CkMechanismParams::X3dhRespond(_) => "X3dhRespond",
        CkMechanismParams::X2RatchetInitialize(_) => "X2RatchetInitialize",
        CkMechanismParams::X2RatchetRespond(_) => "X2RatchetRespond",
        CkMechanismParams::Otp(_) => "Otp",
        CkMechanismParams::Kip(_) => "Kip",
        CkMechanismParams::CmsSig(_) => "CmsSig",
        CkMechanismParams::SkipjackPrivateWrap(_) => "SkipjackPrivateWrap",
        CkMechanismParams::SkipjackRelayx(_) => "SkipjackRelayx",
        CkMechanismParams::MacGeneral(_) => "MacGeneral",
        CkMechanismParams::ObjectHandle(_) => "ObjectHandle",
        CkMechanismParams::Extract(_) => "Extract",
        CkMechanismParams::SignAdditionalContext(_) => "SignAdditionalContext",
        CkMechanismParams::Kmac(_) => "Kmac",
        CkMechanismParams::MuGen(_) => "MuGen",
        CkMechanismParams::KeyDerivationString(_) => "KeyDerivationString",
        CkMechanismParams::Raw(_) => "Raw",
        CkMechanismParams::Ecies(_) => "Ecies",
        CkMechanismParams::AesCmacKeyDerivation(_) => "AesCmacKeyDerivation",
        CkMechanismParams::Dilithium(_) => "Dilithium",
        CkMechanismParams::Kyber(_) => "Kyber",
        CkMechanismParams::HdKeyDerive(_) => "HdKeyDerive",
        CkMechanismParams::VendorObjectExtract(_) => "VendorObjectExtract",
        CkMechanismParams::VendorObjectInsert(_) => "VendorObjectInsert",
    }
}

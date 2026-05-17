use crate::attribute::CkAttribute;

/// Mechanism type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CkMechanismType(pub u64);

impl CkMechanismType {
    pub const VENDOR_DEFINED: Self = Self(0x8000_0000);

    // Phase 1 seed set — parameterless mechanisms
    pub const RSA_PKCS: Self = Self(0x00000001);
    pub const RSA_PKCS_KEY_PAIR_GEN: Self = Self(0x00000000);
    pub const RSA_9796: Self = Self(0x00000002);
    pub const RSA_X_509: Self = Self(0x00000003);
    pub const RSA_X9_31_KEY_PAIR_GEN: Self = Self(0x0000000A);
    pub const RSA_X9_31: Self = Self(0x0000000B);
    pub const SHA256_RSA_PKCS: Self = Self(0x00000040);
    pub const SHA384_RSA_PKCS: Self = Self(0x00000041);
    pub const SHA512_RSA_PKCS: Self = Self(0x00000042);
    pub const ECDSA: Self = Self(0x00001041);
    pub const ECDSA_SHA1: Self = Self(0x00001042);
    pub const ECDSA_SHA224: Self = Self(0x00001043);
    pub const ECDSA_SHA256: Self = Self(0x00001044);
    pub const ECDSA_SHA384: Self = Self(0x00001045);
    pub const ECDSA_SHA512: Self = Self(0x00001046);
    pub const ECDSA_SHA3_224: Self = Self(0x00001047);
    pub const ECDSA_SHA3_256: Self = Self(0x00001048);
    pub const ECDSA_SHA3_384: Self = Self(0x00001049);
    pub const ECDSA_SHA3_512: Self = Self(0x0000104A);
    pub const EC_KEY_PAIR_GEN: Self = Self(0x00001040);
    pub const EC_KEY_PAIR_GEN_W_EXTRA_BITS: Self = Self(0x0000140B);
    pub const EC_EDWARDS_KEY_PAIR_GEN: Self = Self(0x00001055);
    pub const EC_MONTGOMERY_KEY_PAIR_GEN: Self = Self(0x00001056);
    pub const EDDSA: Self = Self(0x00001057);
    pub const XEDDSA: Self = Self(0x00004029);
    pub const HKDF_DERIVE: Self = Self(0x0000402A);
    pub const HKDF_DATA: Self = Self(0x0000402B);
    pub const HKDF_KEY_GEN: Self = Self(0x0000402C);
    pub const IKE2_PRF_PLUS_DERIVE: Self = Self(0x0000402E);
    pub const IKE_PRF_DERIVE: Self = Self(0x0000402F);
    pub const IKE1_PRF_DERIVE: Self = Self(0x00004030);
    pub const IKE1_EXTENDED_DERIVE: Self = Self(0x00004031);
    pub const HSS_KEY_PAIR_GEN: Self = Self(0x00004032);
    pub const HSS: Self = Self(0x00004033);
    pub const XMSS_KEY_PAIR_GEN: Self = Self(0x00004034);
    pub const XMSSMT_KEY_PAIR_GEN: Self = Self(0x00004035);
    pub const XMSS: Self = Self(0x00004036);
    pub const XMSSMT: Self = Self(0x00004037);
    pub const SHA256: Self = Self(0x00000250);
    pub const SHA384: Self = Self(0x00000260);
    pub const SHA512: Self = Self(0x00000270);

    // Phase 1 — parameterized mechanisms (P0)
    pub const RSA_PKCS_PSS: Self = Self(0x0000000D);
    pub const RSA_PKCS_OAEP: Self = Self(0x00000009);
    pub const DH_PKCS_KEY_PAIR_GEN: Self = Self(0x00000020);
    pub const DH_PKCS_DERIVE: Self = Self(0x00000021);
    pub const X9_42_DH_KEY_PAIR_GEN: Self = Self(0x00000030);
    pub const X9_42_DH_DERIVE: Self = Self(0x00000031);
    pub const X9_42_DH_HYBRID_DERIVE: Self = Self(0x00000032);
    pub const X9_42_MQV_DERIVE: Self = Self(0x00000033);

    // Planned extensions (P1)
    pub const AES_XTS: Self = Self(0x00001071);
    pub const AES_XTS_KEY_GEN: Self = Self(0x00001072);
    pub const AES_KEY_GEN: Self = Self(0x00001080);
    pub const AES_ECB: Self = Self(0x00001081);
    pub const AES_MAC: Self = Self(0x00001083);
    pub const AES_MAC_GENERAL: Self = Self(0x00001084);
    pub const AES_CTR: Self = Self(0x00001086);
    pub const AES_GCM: Self = Self(0x00001087);
    pub const AES_CCM: Self = Self(0x00001088);
    pub const AES_CTS: Self = Self(0x00001089);
    pub const AES_CMAC: Self = Self(0x0000108A);
    pub const AES_CMAC_GENERAL: Self = Self(0x0000108B);
    pub const AES_XCBC_MAC: Self = Self(0x0000108C);
    pub const AES_XCBC_MAC_96: Self = Self(0x0000108D);
    pub const AES_GMAC: Self = Self(0x0000108E);
    pub const AES_ECB_ENCRYPT_DATA: Self = Self(0x00001104);
    pub const AES_CBC_ENCRYPT_DATA: Self = Self(0x00001105);
    pub const DES_ECB_ENCRYPT_DATA: Self = Self(0x00001100);
    pub const DES_CBC_ENCRYPT_DATA: Self = Self(0x00001101);
    pub const DES3_ECB_ENCRYPT_DATA: Self = Self(0x00001102);
    pub const DES3_CBC_ENCRYPT_DATA: Self = Self(0x00001103);
    pub const MD2: Self = Self(0x00000200);
    pub const MD5: Self = Self(0x00000210);
    pub const SHAKE_128_KEY_DERIVATION: Self = Self(0x0000039B);
    pub const SHAKE_256_KEY_DERIVATION: Self = Self(0x0000039C);
    pub const CHACHA20_KEY_GEN: Self = Self(0x00001225);
    pub const CHACHA20: Self = Self(0x00001226);
    pub const POLY1305_KEY_GEN: Self = Self(0x00001227);
    pub const POLY1305: Self = Self(0x00001228);
    pub const ECDH1_DERIVE: Self = Self(0x00001050);
    pub const ECDH1_COFACTOR_DERIVE: Self = Self(0x00001051);
    pub const ECMQV_DERIVE: Self = Self(0x00001052);
    pub const ECDH_AES_KEY_WRAP: Self = Self(0x00001053);
    pub const RSA_AES_KEY_WRAP: Self = Self(0x00001054);
    pub const ECDH_X_AES_KEY_WRAP: Self = Self(0x00004038);
    pub const ECDH_COF_AES_KEY_WRAP: Self = Self(0x00004039);
    pub const SECURID_KEY_GEN: Self = Self(0x00000280);
    pub const SECURID: Self = Self(0x00000282);
    pub const HOTP_KEY_GEN: Self = Self(0x00000290);
    pub const HOTP: Self = Self(0x00000291);
    pub const PBE_SHA1_DES3_EDE_CBC: Self = Self(0x000003A8);
    pub const PBE_SHA1_DES2_EDE_CBC: Self = Self(0x000003A9);
    pub const PKCS5_PBKD2: Self = Self(0x000003B0);
    pub const PBA_SHA1_WITH_SHA1_HMAC: Self = Self(0x000003C0);
    pub const CMS_SIG: Self = Self(0x00000500);
    pub const BLOWFISH_KEY_GEN: Self = Self(0x00001090);
    pub const BLOWFISH_CBC: Self = Self(0x00001091);
    pub const TWOFISH_KEY_GEN: Self = Self(0x00001092);
    pub const TWOFISH_CBC: Self = Self(0x00001093);
    pub const BLOWFISH_CBC_PAD: Self = Self(0x00001094);
    pub const TWOFISH_CBC_PAD: Self = Self(0x00001095);
    pub const GENERIC_SECRET_KEY_GEN: Self = Self(0x00000350);
    pub const CONCATENATE_BASE_AND_KEY: Self = Self(0x00000360);
    pub const CONCATENATE_BASE_AND_DATA: Self = Self(0x00000362);
    pub const CONCATENATE_DATA_AND_BASE: Self = Self(0x00000363);
    pub const XOR_BASE_AND_DATA: Self = Self(0x00000364);
    pub const EXTRACT_KEY_FROM_KEY: Self = Self(0x00000365);
    pub const PUB_KEY_FROM_PRIV_KEY: Self = Self(0x0000403A);
    pub const DES_KEY_GEN: Self = Self(0x00000120);
    pub const DES_ECB: Self = Self(0x00000121);
    pub const DES_MAC: Self = Self(0x00000123);
    pub const DES_CBC_PAD: Self = Self(0x00000125);
    pub const DES2_KEY_GEN: Self = Self(0x00000130);
    pub const DES3_KEY_GEN: Self = Self(0x00000131);
    pub const DES3_ECB: Self = Self(0x00000132);
    pub const DES3_MAC: Self = Self(0x00000134);
    pub const DES3_MAC_GENERAL: Self = Self(0x00000135);
    pub const DES3_CMAC_GENERAL: Self = Self(0x00000137);
    pub const DES3_CMAC: Self = Self(0x00000138);
    pub const KIP_DERIVE: Self = Self(0x00000510);
    pub const KIP_WRAP: Self = Self(0x00000511);
    pub const KIP_MAC: Self = Self(0x00000512);
    pub const CAMELLIA_KEY_GEN: Self = Self(0x00000550);
    pub const CAMELLIA_ECB: Self = Self(0x00000551);
    pub const CAMELLIA_CBC: Self = Self(0x00000552);
    pub const CAMELLIA_MAC: Self = Self(0x00000553);
    pub const CAMELLIA_MAC_GENERAL: Self = Self(0x00000554);
    pub const CAMELLIA_CBC_PAD: Self = Self(0x00000555);
    pub const CAMELLIA_ECB_ENCRYPT_DATA: Self = Self(0x00000556);
    pub const CAMELLIA_CBC_ENCRYPT_DATA: Self = Self(0x00000557);
    pub const ARIA_KEY_GEN: Self = Self(0x00000560);
    pub const ARIA_ECB: Self = Self(0x00000561);
    pub const ARIA_CBC: Self = Self(0x00000562);
    pub const ARIA_MAC: Self = Self(0x00000563);
    pub const ARIA_MAC_GENERAL: Self = Self(0x00000564);
    pub const ARIA_CBC_PAD: Self = Self(0x00000565);
    pub const ARIA_ECB_ENCRYPT_DATA: Self = Self(0x00000566);
    pub const ARIA_CBC_ENCRYPT_DATA: Self = Self(0x00000567);
    pub const SEED_KEY_GEN: Self = Self(0x00000650);
    pub const SEED_ECB: Self = Self(0x00000651);
    pub const SEED_CBC: Self = Self(0x00000652);
    pub const SEED_MAC: Self = Self(0x00000653);
    pub const SEED_MAC_GENERAL: Self = Self(0x00000654);
    pub const SEED_CBC_PAD: Self = Self(0x00000655);
    pub const SEED_ECB_ENCRYPT_DATA: Self = Self(0x00000656);
    pub const SEED_CBC_ENCRYPT_DATA: Self = Self(0x00000657);
    pub const GOSTR3410_KEY_PAIR_GEN: Self = Self(0x00001200);
    pub const GOSTR3410: Self = Self(0x00001201);
    pub const GOSTR3410_WITH_GOSTR3411: Self = Self(0x00001202);
    pub const GOSTR3410_KEY_WRAP: Self = Self(0x00001203);
    pub const GOSTR3410_DERIVE: Self = Self(0x00001204);
    pub const GOSTR3411: Self = Self(0x00001210);
    pub const GOSTR3411_HMAC: Self = Self(0x00001211);
    pub const GOST28147_KEY_GEN: Self = Self(0x00001220);
    pub const GOST28147_ECB: Self = Self(0x00001221);
    pub const GOST28147: Self = Self(0x00001222);
    pub const GOST28147_MAC: Self = Self(0x00001223);
    pub const GOST28147_KEY_WRAP: Self = Self(0x00001224);

    // IV-based symmetric mechanisms
    pub const AES_CBC: Self = Self(0x00001082);
    pub const AES_CBC_PAD: Self = Self(0x00001085);
    pub const AES_OFB: Self = Self(0x00002104);
    pub const AES_CFB64: Self = Self(0x00002105);
    pub const AES_CFB8: Self = Self(0x00002106);
    pub const AES_CFB128: Self = Self(0x00002107);
    pub const AES_CFB1: Self = Self(0x00002108);
    pub const DES_OFB64: Self = Self(0x00000150);
    pub const DES_OFB8: Self = Self(0x00000151);
    pub const DES_CFB64: Self = Self(0x00000152);
    pub const DES_CFB8: Self = Self(0x00000153);
    pub const DH_PKCS_PARAMETER_GEN: Self = Self(0x00002001);
    pub const X9_42_DH_PARAMETER_GEN: Self = Self(0x00002002);
    pub const AES_KEY_WRAP: Self = Self(0x00002109);
    pub const AES_KEY_WRAP_PAD: Self = Self(0x0000210A);
    pub const AES_KEY_WRAP_KWP: Self = Self(0x0000210B);
    pub const AES_KEY_WRAP_PKCS7: Self = Self(0x0000210C);
    pub const RSA_PKCS_TPM_1_1: Self = Self(0x00004001);
    pub const RSA_PKCS_OAEP_TPM_1_1: Self = Self(0x00004002);
    pub const NULL: Self = Self(0x0000400B);
    pub const SALSA20: Self = Self(0x00004020);
    pub const CHACHA20_POLY1305: Self = Self(0x00004021);
    pub const SALSA20_POLY1305: Self = Self(0x00004022);
    pub const X3DH_INITIALIZE: Self = Self(0x00004023);
    pub const X3DH_RESPOND: Self = Self(0x00004024);
    pub const X2RATCHET_INITIALIZE: Self = Self(0x00004025);
    pub const X2RATCHET_RESPOND: Self = Self(0x00004026);
    pub const X2RATCHET_ENCRYPT: Self = Self(0x00004027);
    pub const X2RATCHET_DECRYPT: Self = Self(0x00004028);
    pub const SALSA20_KEY_GEN: Self = Self(0x0000402D);
    pub const DES3_CBC: Self = Self(0x00000133);
    pub const DES3_CBC_PAD: Self = Self(0x00000136);

    // TLS / SSL key derive (output-parameter mechanisms — used for the
    // `mechanism_out` round-trip on `C_DeriveKey`).
    pub const TLS12_EXTENDED_MASTER_KEY_DERIVE: Self = Self(0x00000056);
    pub const TLS12_EXTENDED_MASTER_KEY_DERIVE_DH: Self = Self(0x00000057);
    pub const SSL3_PRE_MASTER_KEY_GEN: Self = Self(0x00000370);
    pub const SSL3_MASTER_KEY_DERIVE: Self = Self(0x00000371);
    pub const SSL3_KEY_AND_MAC_DERIVE: Self = Self(0x00000372);
    pub const SSL3_MASTER_KEY_DERIVE_DH: Self = Self(0x00000373);
    pub const TLS_PRE_MASTER_KEY_GEN: Self = Self(0x00000374);
    pub const TLS_PRF: Self = Self(0x00000378);
    pub const SSL3_MD5_MAC: Self = Self(0x00000380);
    pub const SSL3_SHA1_MAC: Self = Self(0x00000381);
    pub const WTLS_PRE_MASTER_KEY_GEN: Self = Self(0x000003D0);
    pub const WTLS_MASTER_KEY_DERIVE: Self = Self(0x000003D1);
    pub const WTLS_MASTER_KEY_DERIVE_DH_ECC: Self = Self(0x000003D2);
    pub const WTLS_PRF: Self = Self(0x000003D3);
    pub const WTLS_SERVER_KEY_AND_MAC_DERIVE: Self = Self(0x000003D4);
    pub const WTLS_CLIENT_KEY_AND_MAC_DERIVE: Self = Self(0x000003D5);
    pub const TLS12_MAC: Self = Self(0x000003D8);
    pub const TLS12_KDF: Self = Self(0x000003D9);
    pub const TLS12_MASTER_KEY_DERIVE: Self = Self(0x000003E0);
    pub const TLS12_KEY_AND_MAC_DERIVE: Self = Self(0x000003E1);
    pub const TLS12_MASTER_KEY_DERIVE_DH: Self = Self(0x000003E2);
    pub const TLS12_KEY_SAFE_DERIVE: Self = Self(0x000003E3);
    pub const TLS_MAC: Self = Self(0x000003E4);
    pub const TLS_KDF: Self = Self(0x000003E5);

    pub const fn from_vendor(offset: u32) -> Self {
        Self(Self::VENDOR_DEFINED.0 | offset as u64)
    }

    pub const fn is_vendor_defined(self) -> bool {
        (self.0 & Self::VENDOR_DEFINED.0) == Self::VENDOR_DEFINED.0
    }
}

/// Mechanism info returned by C_GetMechanismInfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkMechanismInfo {
    pub min_key_size: u64,
    pub max_key_size: u64,
    pub flags: CkMechanismFlags,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CkMechanismFlags(pub u64);

impl CkMechanismFlags {
    pub const HW: u64 = 0x00000001;
    pub const MESSAGE_ENCRYPT: u64 = 0x00000002;
    pub const MESSAGE_DECRYPT: u64 = 0x00000004;
    pub const MESSAGE_SIGN: u64 = 0x00000008;
    pub const MESSAGE_VERIFY: u64 = 0x00000010;
    pub const MULTI_MESSAGE: u64 = 0x00000020;
    pub const MULTI_MESSGE: u64 = Self::MULTI_MESSAGE;
    pub const FIND_OBJECTS: u64 = 0x00000040;
    pub const ENCRYPT: u64 = 0x00000100;
    pub const DECRYPT: u64 = 0x00000200;
    pub const DIGEST: u64 = 0x00000400;
    pub const SIGN: u64 = 0x00000800;
    pub const SIGN_RECOVER: u64 = 0x00001000;
    pub const VERIFY: u64 = 0x00002000;
    pub const VERIFY_RECOVER: u64 = 0x00004000;
    pub const GENERATE: u64 = 0x00008000;
    pub const GENERATE_KEY_PAIR: u64 = 0x00010000;
    pub const WRAP: u64 = 0x00020000;
    pub const UNWRAP: u64 = 0x00040000;
    pub const DERIVE: u64 = 0x00080000;
    pub const EC_F_P: u64 = 0x00100000;
    pub const EC_F_2M: u64 = 0x00200000;
    pub const EC_ECPARAMETERS: u64 = 0x00400000;
    pub const EC_OID: u64 = 0x00800000;
    pub const EC_NAMEDCURVE: u64 = Self::EC_OID;
    pub const EC_UNCOMPRESS: u64 = 0x01000000;
    pub const EC_COMPRESS: u64 = 0x02000000;
    pub const EC_CURVENAME: u64 = 0x04000000;
    pub const ENCAPSULATE: u64 = 0x10000000;
    pub const DECAPSULATE: u64 = 0x20000000;
    pub const EXTENSION: u64 = 0x80000000;
}

// --- Mechanism parameter structs (ADR-0001 §2: explicitly modeled) ---

/// CK_RSA_PKCS_PSS_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPkcsPssParams {
    pub hash_alg: CkMechanismType,
    pub mgf: u64, // CKG_MGF1_SHA256 etc.
    pub salt_len: u64,
}

/// CK_RSA_PKCS_OAEP_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPkcsOaepParams {
    pub hash_alg: CkMechanismType,
    pub mgf: u64,
    pub source: u64,
    pub source_data: Vec<u8>,
}

/// CK_GCM_PARAMS — parameters for CKM_AES_GCM.
///
/// - `iv`: initialisation vector bytes (typically 12 bytes / 96 bits)
/// - `iv_bits`: length of the IV in bits (must equal `iv.len() * 8` in standard usage)
/// - `iv_buffer_len`: writable IV buffer capacity when `iv` is an output parameter
/// - `aad`: additional authenticated data (may be empty)
/// - `tag_bits`: authentication tag length in bits (96, 112, or 128)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcmParams {
    pub iv: Vec<u8>,
    pub iv_bits: u64,
    pub iv_buffer_len: u64,
    pub aad: Vec<u8>,
    pub tag_bits: u64,
}

/// CK_ECDH1_DERIVE_PARAMS — parameters for CKM_ECDH1_DERIVE.
///
/// - `kdf`: key derivation function type (CKD_NULL = 1, CKD_SHA1_KDF = 2, etc.)
/// - `shared_data`: optional shared data input to the KDF (may be empty)
/// - `public_data`: other party's EC public key (uncompressed EC point)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ecdh1DeriveParams {
    pub kdf: u64,
    pub shared_data: Vec<u8>,
    pub public_data: Vec<u8>,
}

/// IV parameters for CBC/CBC-PAD mechanisms (AES-CBC, DES3-CBC, etc.)
/// The IV is typically 16 bytes for AES or 8 bytes for DES3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IvParams {
    pub iv: Vec<u8>,
}

// --- Trivial scalar-only parameter structs ---

/// CK_RC5_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rc5Params {
    pub word_size: u64,
    pub rounds: u64,
}

/// CK_RC5_MAC_GENERAL_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rc5MacGeneralParams {
    pub word_size: u64,
    pub rounds: u64,
    pub mac_length: u64,
}

/// CK_RC2_MAC_GENERAL_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rc2MacGeneralParams {
    pub effective_bits: u64,
    pub mac_length: u64,
}

/// CK_XEDDSA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XeddsaParams {
    pub hash: u64,
}

/// CK_TLS_MAC_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsMacParams {
    pub prf_hash_mechanism: u64,
    pub mac_length: u64,
    pub server_or_client: u64,
}

// --- Symmetric with fixed IV ---

/// CK_AES_CTR_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesCtrParams {
    pub counter_bits: u64,
    pub cb: Vec<u8>, // 16-byte counter block
}

/// CK_CAMELLIA_CTR_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CamelliaCtrParams {
    pub counter_bits: u64,
    pub cb: Vec<u8>, // 16-byte counter block
}

/// CK_RC2_CBC_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rc2CbcParams {
    pub effective_bits: u64,
    pub iv: Vec<u8>, // 8-byte IV
}

/// CK_RC5_CBC_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rc5CbcParams {
    pub word_size: u64,
    pub rounds: u64,
    pub iv: Vec<u8>,
}

// --- CBC encrypt data (IV + data pointer) ---

/// CK_AES_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesCbcEncryptDataParams {
    pub iv: Vec<u8>, // 16-byte IV
    pub data: Vec<u8>,
}

/// CK_DES_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesCbcEncryptDataParams {
    pub iv: Vec<u8>, // 8-byte IV
    pub data: Vec<u8>,
}

/// CK_ARIA_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AriaCbcEncryptDataParams {
    pub iv: Vec<u8>, // 16-byte IV
    pub data: Vec<u8>,
}

/// CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CamelliaCbcEncryptDataParams {
    pub iv: Vec<u8>, // 16-byte IV
    pub data: Vec<u8>,
}

/// CK_SEED_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedCbcEncryptDataParams {
    pub iv: Vec<u8>, // 16-byte IV
    pub data: Vec<u8>,
}

// --- AEAD parameter structs ---

/// CK_CCM_PARAMS / CK_AES_CCM_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcmParams {
    pub data_len: u64,
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
    pub mac_len: u64,
}

/// CK_CHACHA20_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChaCha20Params {
    pub block_counter: Vec<u8>,
    pub block_counter_bits: u64,
    pub nonce: Vec<u8>,
    pub nonce_bits: u64,
}

/// CK_SALSA20_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Salsa20Params {
    pub block_counter: Vec<u8>,
    pub nonce: Vec<u8>,
    pub nonce_bits: u64,
}

/// CK_SALSA20_CHACHA20_POLY1305_PARAMS (non-message variant)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Salsa20ChaCha20Poly1305Params {
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
}

/// CK_GCM_WRAP_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcmWrapParams {
    pub iv: Vec<u8>,
    pub iv_fixed_bits: u64,
    pub iv_generator: u64,
    pub aad: Vec<u8>,
    pub tag_bits: u64,
}

/// CK_CCM_WRAP_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcmWrapParams {
    pub data_len: u64,
    pub nonce: Vec<u8>,
    pub nonce_fixed_bits: u64,
    pub nonce_generator: u64,
    pub aad: Vec<u8>,
    pub mac_len: u64,
}

// ---------------------------------------------------------------------------
// Key Derivation parameter structs
// ---------------------------------------------------------------------------

/// CK_ECDH2_DERIVE_PARAMS — dual ECDH key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ecdh2DeriveParams {
    pub kdf: u64,
    pub shared_data: Vec<u8>,
    pub public_data: Vec<u8>,
    pub private_data_len: u64,
    pub private_data_handle: u64,
    pub public_data2: Vec<u8>,
}

/// CK_ECMQV_DERIVE_PARAMS — EC-MQV key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcmqvDeriveParams {
    pub kdf: u64,
    pub shared_data: Vec<u8>,
    pub public_data: Vec<u8>,
    pub private_data_len: u64,
    pub private_data_handle: u64,
    pub public_data2: Vec<u8>,
    pub public_key_handle: u64,
}

/// CK_X9_42_DH1_DERIVE_PARAMS — X9.42 DH key derivation (single).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X942Dh1DeriveParams {
    pub kdf: u64,
    pub other_info: Vec<u8>,
    pub public_data: Vec<u8>,
}

/// CK_X9_42_DH2_DERIVE_PARAMS — X9.42 DH key derivation (dual).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X942Dh2DeriveParams {
    pub kdf: u64,
    pub other_info: Vec<u8>,
    pub public_data: Vec<u8>,
    pub private_data_len: u64,
    pub private_data_handle: u64,
    pub public_data2: Vec<u8>,
}

/// CK_X9_42_MQV_DERIVE_PARAMS — X9.42 MQV key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X942MqvDeriveParams {
    pub kdf: u64,
    pub other_info: Vec<u8>,
    pub public_data: Vec<u8>,
    pub private_data_len: u64,
    pub private_data_handle: u64,
    pub public_data2: Vec<u8>,
    pub public_key_handle: u64,
}

/// CK_HKDF_PARAMS — HKDF key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HkdfParams {
    pub extract: bool,
    pub expand: bool,
    pub prf_hash_mechanism: u64,
    pub salt_type: u64,
    pub salt: Vec<u8>,
    pub salt_key_handle: u64,
    pub info: Vec<u8>,
}

/// CK_EDDSA_PARAMS — EdDSA signature parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EddsaParams {
    pub ph_flag: bool,
    pub context_data: Vec<u8>,
}

/// CK_GOSTR3410_DERIVE_PARAMS — GOST R 34.10 key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gostr3410DeriveParams {
    pub kdf: u64,
    pub public_data: Vec<u8>,
    pub ukm: Vec<u8>,
}

/// CK_KEA_DERIVE_PARAMS — KEA key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeaDeriveParams {
    pub is_sender: bool,
    pub random_a: Vec<u8>,
    pub random_b: Vec<u8>,
    pub public_data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Key Wrapping parameter structs
// ---------------------------------------------------------------------------

/// CK_ECDH_AES_KEY_WRAP_PARAMS — ECDH + AES key wrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdhAesKeyWrapParams {
    pub aes_key_bits: u64,
    pub kdf: u64,
    pub shared_data: Vec<u8>,
}

/// CK_RSA_AES_KEY_WRAP_PARAMS — RSA-OAEP + AES key wrap (nested OAEP params).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaAesKeyWrapParams {
    pub aes_key_bits: u64,
    pub oaep_params: RsaPkcsOaepParams,
}

/// CK_GOSTR3410_KEY_WRAP_PARAMS — GOST R 34.10 key wrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gostr3410KeyWrapParams {
    pub wrap_oid: Vec<u8>,
    pub ukm: Vec<u8>,
    pub key_handle: u64,
}

/// CK_KEY_WRAP_SET_OAEP_PARAMS — SET OAEP key wrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapSetOaepParams {
    pub bc: u32,
    pub x: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Password-Based Encryption parameter structs
// ---------------------------------------------------------------------------

/// CK_PBE_PARAMS — password-based encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PbeParams {
    pub init_vector: Vec<u8>,
    pub password: Vec<u8>,
    pub salt: Vec<u8>,
    pub iteration: u64,
}

/// CK_PKCS5_PBKD2_PARAMS / CK_PKCS5_PBKD2_PARAMS2 — PKCS#5 PBKDF2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs5Pbkd2Params {
    pub salt_source: u64,
    pub salt_source_data: Vec<u8>,
    pub iterations: u64,
    pub prf: u64,
    pub prf_data: Vec<u8>,
    pub password: Vec<u8>,
}

// ---------------------------------------------------------------------------
// TLS/SSL parameter structs
// ---------------------------------------------------------------------------

/// Shared sub-struct for TLS/SSL random data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslRandomData {
    pub client_random: Vec<u8>,
    pub server_random: Vec<u8>,
}

/// CK_TLS_PRF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPrfParams {
    pub seed: Vec<u8>,
    pub label: Vec<u8>,
    pub output_len: u64,
}

/// CK_TLS_KDF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsKdfParams {
    pub prf_mechanism: u64,
    pub label: Vec<u8>,
    pub random_info: SslRandomData,
    pub context_data: Vec<u8>,
}

/// CK_SSL3_MASTER_KEY_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssl3MasterKeyDeriveParams {
    pub random_info: SslRandomData,
    pub version_major: u32,
    pub version_minor: u32,
}

/// CK_TLS12_MASTER_KEY_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls12MasterKeyDeriveParams {
    pub random_info: SslRandomData,
    pub version_major: u32,
    pub version_minor: u32,
    pub prf_hash_mechanism: u64,
}

/// CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls12ExtendedMasterKeyDeriveParams {
    pub prf_hash_mechanism: u64,
    pub session_hash: Vec<u8>,
    pub version_major: u32,
    pub version_minor: u32,
}

/// CK_SSL3_KEY_MAT_PARAMS / CK_TLS12_KEY_MAT_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssl3KeyMatParams {
    pub mac_size_bits: u64,
    pub key_size_bits: u64,
    pub iv_size_bits: u64,
    pub is_export: bool,
    pub random_info: SslRandomData,
    pub prf_hash_mechanism: u64,
    pub client_mac_secret_handle: u64,
    pub server_mac_secret_handle: u64,
    pub client_key_handle: u64,
    pub server_key_handle: u64,
    pub client_iv: Vec<u8>,
    pub server_iv: Vec<u8>,
}

/// CK_WTLS_RANDOM_DATA
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtlsRandomData {
    pub client_random: Vec<u8>,
    pub server_random: Vec<u8>,
}

/// CK_WTLS_MASTER_KEY_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtlsMasterKeyDeriveParams {
    pub digest_mechanism: u64,
    pub random_info: WtlsRandomData,
    pub version: u32,
}

/// CK_WTLS_PRF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtlsPrfParams {
    pub digest_mechanism: u64,
    pub seed: Vec<u8>,
    pub label: Vec<u8>,
    pub output_len: u64,
}

/// CK_WTLS_KEY_MAT_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtlsKeyMatParams {
    pub digest_mechanism: u64,
    pub mac_size_bits: u64,
    pub key_size_bits: u64,
    pub iv_size_bits: u64,
    pub sequence_number: u64,
    pub is_export: bool,
    pub random_info: WtlsRandomData,
    pub mac_secret_handle: u64,
    pub key_handle: u64,
    pub iv: Vec<u8>,
}

// ---------------------------------------------------------------------------
// IKE/IPSec parameter structs
// ---------------------------------------------------------------------------

/// CK_IKE_PRF_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IkePrfDeriveParams {
    pub prf_mechanism: u64,
    pub data_as_key: bool,
    pub rekey: bool,
    pub ni: Vec<u8>,
    pub nr: Vec<u8>,
    pub new_key_handle: u64,
}

/// CK_IKE1_PRF_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ike1PrfDeriveParams {
    pub prf_mechanism: u64,
    pub has_prev_key: bool,
    pub keygxy_handle: u64,
    pub prev_key_handle: u64,
    pub ckyi: Vec<u8>,
    pub ckyr: Vec<u8>,
    pub key_number: u32,
}

/// CK_IKE1_EXTENDED_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ike1ExtendedDeriveParams {
    pub prf_mechanism: u64,
    pub has_keygxy: bool,
    pub keygxy_handle: u64,
    pub extra_data: Vec<u8>,
}

/// CK_IKE2_PRF_PLUS_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ike2PrfPlusDeriveParams {
    pub prf_mechanism: u64,
    pub has_seed_key: bool,
    pub seed_key_handle: u64,
    pub seed_data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// SP800-108 KDF parameter structs
// ---------------------------------------------------------------------------

/// CK_PRF_DATA_PARAM (used inside SP800-108 params)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfDataParam {
    pub type_: u64,
    pub value: Vec<u8>,
}

/// CK_SP800_108_KDF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp800108KdfParams {
    pub prf_type: u64,
    pub data_params: Vec<PrfDataParam>,
    pub additional_derived_keys: Vec<Sp800108DerivedKey>,
}

/// CK_SP800_108_FEEDBACK_KDF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp800108FeedbackKdfParams {
    pub prf_type: u64,
    pub data_params: Vec<PrfDataParam>,
    pub iv: Vec<u8>,
    pub additional_derived_keys: Vec<Sp800108DerivedKey>,
}

/// CK_DERIVED_KEY entry nested inside SP800-108 KDF params.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp800108DerivedKey {
    pub template: Vec<CkAttribute>,
    pub key_handle: u64,
}

/// CK_SP800_108_COUNTER_FORMAT
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp800108CounterFormat {
    pub width_in_bits: u64,
}

/// CK_SP800_108_DKM_LENGTH_FORMAT
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp800108DkmLengthFormat {
    pub dkm_length_method: u64,
    pub width_in_bits: u64,
}

// ---------------------------------------------------------------------------
// Signal Protocol parameter structs
// ---------------------------------------------------------------------------

/// CK_X3DH_INITIATE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X3dhInitiateParams {
    pub kdf: u64,
    pub peer_identity_handle: u64,
    pub peer_prekey_handle: u64,
    pub prekey_signature: Vec<u8>,
    pub onetime_key_handle: u64,
    pub own_identity_handle: u64,
    pub own_ephemeral_handle: u64,
}

/// CK_X3DH_RESPOND_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X3dhRespondParams {
    pub kdf: u64,
    pub identity_handle: u64,
    pub prekey_handle: u64,
    pub onetime_key_handle: u64,
    pub initiator_identity_handle: u64,
    pub initiator_ephemeral_handle: u64,
}

/// CK_X2RATCHET_INITIALIZE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X2RatchetInitializeParams {
    pub sk: Vec<u8>,
    pub peer_public_prekey_handle: u64,
    pub peer_public_identity_handle: u64,
    pub own_public_identity_handle: u64,
    pub encrypted_header: bool,
    pub curve: u64,
    pub aead_mechanism: u64,
    pub kdf_mechanism: u64,
}

/// CK_X2RATCHET_RESPOND_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X2RatchetRespondParams {
    pub sk: Vec<u8>,
    pub own_prekey_handle: u64,
    pub initiator_identity_handle: u64,
    pub own_identity_handle: u64,
    pub encrypted_header: bool,
    pub curve: u64,
    pub aead_mechanism: u64,
    pub kdf_mechanism: u64,
}

// ---------------------------------------------------------------------------
// Miscellaneous parameter structs
// ---------------------------------------------------------------------------

/// CK_OTP_PARAM (individual OTP parameter)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpParam {
    pub type_: u64,
    pub value: Vec<u8>,
}

/// CK_OTP_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpParams {
    pub params: Vec<OtpParam>,
}

/// CK_KIP_PARAMS — references a nested Mechanism (boxed to avoid infinite size).
#[derive(Debug, Clone, PartialEq)]
pub struct KipParams {
    pub mechanism: Box<CkMechanism>,
    pub key_handle: u64,
    pub seed: Vec<u8>,
}

/// CK_CMS_SIG_PARAMS — references nested Mechanisms (boxed to avoid infinite size).
#[derive(Debug, Clone, PartialEq)]
pub struct CmsSigParams {
    pub certificate_handle: u64,
    pub signing_mechanism: Box<CkMechanism>,
    pub digest_mechanism: Box<CkMechanism>,
    pub content_type: String,
    pub requested_attributes: Vec<u8>,
    pub required_attributes: Vec<u8>,
}

/// CK_SKIPJACK_PRIVATE_WRAP_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkipjackPrivateWrapParams {
    pub password: Vec<u8>,
    pub public_data: Vec<u8>,
    pub password_length: u64,
    pub random_a: Vec<u8>,
    pub prime_p: Vec<u8>,
    pub base_g: Vec<u8>,
    pub subprime_q: Vec<u8>,
}

/// CK_SKIPJACK_RELAYX_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkipjackRelayxParams {
    pub old_wrapped_x: Vec<u8>,
    pub old_password: Vec<u8>,
    pub old_public_data: Vec<u8>,
    pub old_random_a: Vec<u8>,
    pub new_password: Vec<u8>,
    pub new_public_data: Vec<u8>,
    pub new_random_a: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Generic / Vendor parameter structs
// ---------------------------------------------------------------------------

/// CK_MAC_GENERAL_PARAMS — a single CK_ULONG specifying the MAC/tag length.
/// Used by any *_HMAC_GENERAL or *_MAC_GENERAL mechanism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacGeneralParams {
    pub mac_length: u64,
}

/// Parameter for CKM_CONCATENATE_BASE_AND_KEY — a single CK_OBJECT_HANDLE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectHandleParam {
    pub handle: u64,
}

/// CK_EXTRACT_PARAMS — bit position for CKM_EXTRACT_KEY_FROM_KEY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractParams {
    pub bit_position: u64,
}

/// CK_KEY_DERIVATION_STRING_DATA — data bytes for key derivation.
/// Used by CONCATENATE_BASE_AND_DATA, CONCATENATE_DATA_AND_BASE, etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDerivationStringData {
    pub data: Vec<u8>,
}

/// CK_SIGN_ADDITIONAL_CONTEXT — hedge mode for ML-DSA/SLH-DSA signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignAdditionalContext {
    pub hedge_variant: u64,
    pub context: Vec<u8>,
}

/// CK_KMAC_PARAMS — keyed MAC output length and optional customization string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmacParams {
    pub key_handle: u64,
    pub mac_length: u64,
    pub customization_string: Vec<u8>,
}

/// CK_MU_GEN_PARAMS — ML-DSA external-mu generation inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuGenParams {
    pub key_handle: u64,
    pub tr: Vec<u8>,
    pub context: Vec<u8>,
}

/// Opaque raw parameter bytes — opt-in escape hatch for vendor-specific
/// mechanisms with scalar-only (non-pointer) parameter structures.
/// The config registry controls which mechanisms can use this variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMechanismParams {
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Vendor-specific parameter structs
// ---------------------------------------------------------------------------

/// CK_NC_ECIES_PARAMS — ECIES (Elliptic Curve Integrated Encryption Scheme) parameters.
/// Contains nested mechanisms for derivation, encryption, and MAC.
#[derive(Debug, Clone, PartialEq)]
pub struct EciesParams {
    pub derivation_mechanism: Box<CkMechanism>,
    pub encryption_mechanism: Box<CkMechanism>,
    pub mac_mechanism: Box<CkMechanism>,
    pub shared_data: Vec<u8>,
}

/// CK_NC_AES_CMAC_KEY_DERIVATION_PARAMS — AES-CMAC key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesCmacKeyDerivationParams {
    pub context: Vec<u8>,
    pub label: Vec<u8>,
}

/// CK_IBM_DILITHIUM_PARAMS — Dilithium / ML-DSA post-quantum signature parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DilithiumParams {
    pub version: u64,
    pub mode: u64,
}

/// CK_IBM_KYBER_PARAMS — Kyber / ML-KEM post-quantum key encapsulation parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KyberParams {
    pub version: u64,
    pub mode: u64,
    pub secret_handle: u64,
    pub shared_data: Vec<u8>,
    pub blob: Vec<u8>,
}

/// CK_IBM_BTC_DERIVE_PARAMS — HD key derivation (BIP-32, BIP-44, SLIP-10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HdKeyDeriveParams {
    pub derive_type: u64,
    pub child_key_index: u64,
    pub chain_code: Vec<u8>,
    pub version: u64,
}

/// Vendor object extraction (cloning/backup) parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorObjectExtractParams {
    pub format: u64,
    pub context: Vec<u8>,
}

/// Vendor object insertion (restore) parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorObjectInsertParams {
    pub format: u64,
    pub context: Vec<u8>,
    pub object_data: Vec<u8>,
}

/// A mechanism with optional typed parameters.
/// ADR-0001 §2: parameterless = None, modeled = Some(variant), unmodeled = rejected
/// before reaching this type.
#[derive(Debug, Clone, PartialEq)]
pub struct CkMechanism {
    pub mechanism_type: CkMechanismType,
    pub params: Option<CkMechanismParams>,
}

/// Enum of modeled mechanism parameter types. New variants are added as
/// parameter structures are modeled per ADR-0001 §6.
#[derive(Debug, Clone, PartialEq)]
pub enum CkMechanismParams {
    RsaPkcsPss(RsaPkcsPssParams),
    RsaPkcsOaep(RsaPkcsOaepParams),
    Gcm(GcmParams),
    Ecdh1Derive(Ecdh1DeriveParams),
    Iv(IvParams),
    // Trivial scalar-only
    Rc5(Rc5Params),
    Rc5MacGeneral(Rc5MacGeneralParams),
    Rc2MacGeneral(Rc2MacGeneralParams),
    Xeddsa(XeddsaParams),
    TlsMac(TlsMacParams),
    // Symmetric with fixed IV
    AesCtr(AesCtrParams),
    CamelliaCtr(CamelliaCtrParams),
    Rc2Cbc(Rc2CbcParams),
    Rc5Cbc(Rc5CbcParams),
    // CBC encrypt data
    AesCbcEncryptData(AesCbcEncryptDataParams),
    DesCbcEncryptData(DesCbcEncryptDataParams),
    AriaCbcEncryptData(AriaCbcEncryptDataParams),
    CamelliaCbcEncryptData(CamelliaCbcEncryptDataParams),
    SeedCbcEncryptData(SeedCbcEncryptDataParams),
    // AEAD
    Ccm(CcmParams),
    ChaCha20(ChaCha20Params),
    Salsa20(Salsa20Params),
    Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params),
    GcmWrap(GcmWrapParams),
    CcmWrap(CcmWrapParams),
    // Key derivation
    Ecdh2Derive(Ecdh2DeriveParams),
    EcmqvDerive(EcmqvDeriveParams),
    X942Dh1Derive(X942Dh1DeriveParams),
    X942Dh2Derive(X942Dh2DeriveParams),
    X942MqvDerive(X942MqvDeriveParams),
    Hkdf(HkdfParams),
    Eddsa(EddsaParams),
    Gostr3410Derive(Gostr3410DeriveParams),
    KeaDerive(KeaDeriveParams),
    // Key wrapping
    EcdhAesKeyWrap(EcdhAesKeyWrapParams),
    RsaAesKeyWrap(RsaAesKeyWrapParams),
    Gostr3410KeyWrap(Gostr3410KeyWrapParams),
    KeyWrapSetOaep(KeyWrapSetOaepParams),
    // Password-based encryption
    Pbe(PbeParams),
    Pkcs5Pbkd2(Pkcs5Pbkd2Params),
    // TLS/SSL
    TlsPrf(TlsPrfParams),
    TlsKdf(TlsKdfParams),
    Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams),
    Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams),
    Tls12ExtendedMasterKeyDerive(Tls12ExtendedMasterKeyDeriveParams),
    Ssl3KeyMat(Ssl3KeyMatParams),
    WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams),
    WtlsPrf(WtlsPrfParams),
    WtlsKeyMat(WtlsKeyMatParams),
    // IKE/IPSec
    IkePrfDerive(IkePrfDeriveParams),
    Ike1PrfDerive(Ike1PrfDeriveParams),
    Ike1ExtendedDerive(Ike1ExtendedDeriveParams),
    Ike2PrfPlusDerive(Ike2PrfPlusDeriveParams),
    // SP800-108 KDF
    Sp800108Kdf(Sp800108KdfParams),
    Sp800108FeedbackKdf(Sp800108FeedbackKdfParams),
    // Signal protocol
    X3dhInitiate(X3dhInitiateParams),
    X3dhRespond(X3dhRespondParams),
    X2RatchetInitialize(X2RatchetInitializeParams),
    X2RatchetRespond(X2RatchetRespondParams),
    // Miscellaneous
    Otp(OtpParams),
    Kip(KipParams),
    CmsSig(CmsSigParams),
    SkipjackPrivateWrap(SkipjackPrivateWrapParams),
    SkipjackRelayx(SkipjackRelayxParams),
    // Generic / vendor parameter shapes
    MacGeneral(MacGeneralParams),
    ObjectHandle(ObjectHandleParam),
    Extract(ExtractParams),
    SignAdditionalContext(SignAdditionalContext),
    Kmac(KmacParams),
    MuGen(MuGenParams),
    KeyDerivationString(KeyDerivationStringData),
    Raw(RawMechanismParams),
    // Vendor-specific parameter shapes
    Ecies(EciesParams),
    AesCmacKeyDerivation(AesCmacKeyDerivationParams),
    Dilithium(DilithiumParams),
    Kyber(KyberParams),
    HdKeyDerive(HdKeyDeriveParams),
    VendorObjectExtract(VendorObjectExtractParams),
    VendorObjectInsert(VendorObjectInsertParams),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_mechanism_helpers() {
        let vendor = CkMechanismType::from_vendor(0x42);
        assert_eq!(vendor.0, 0x8000_0042);
        assert!(vendor.is_vendor_defined());
        assert!(!CkMechanismType::AES_GCM.is_vendor_defined());
    }

    #[test]
    fn standard_aes_constants_match_spec() {
        assert_eq!(CkMechanismType::AES_KEY_GEN.0, 0x0000_1080);
        assert_eq!(CkMechanismType::AES_XTS.0, 0x0000_1071);
        assert_eq!(CkMechanismType::AES_XTS_KEY_GEN.0, 0x0000_1072);
        assert_eq!(CkMechanismType::AES_ECB.0, 0x0000_1081);
        assert_eq!(CkMechanismType::AES_CBC.0, 0x0000_1082);
        assert_eq!(CkMechanismType::AES_MAC.0, 0x0000_1083);
        assert_eq!(CkMechanismType::AES_MAC_GENERAL.0, 0x0000_1084);
        assert_eq!(CkMechanismType::AES_CBC_PAD.0, 0x0000_1085);
        assert_eq!(CkMechanismType::AES_CTR.0, 0x0000_1086);
        assert_eq!(CkMechanismType::AES_GCM.0, 0x0000_1087);
        assert_eq!(CkMechanismType::AES_CCM.0, 0x0000_1088);
        assert_eq!(CkMechanismType::AES_CTS.0, 0x0000_1089);
        assert_eq!(CkMechanismType::AES_CMAC.0, 0x0000_108A);
        assert_eq!(CkMechanismType::AES_CMAC_GENERAL.0, 0x0000_108B);
        assert_eq!(CkMechanismType::AES_XCBC_MAC.0, 0x0000_108C);
        assert_eq!(CkMechanismType::AES_XCBC_MAC_96.0, 0x0000_108D);
        assert_eq!(CkMechanismType::AES_GMAC.0, 0x0000_108E);
        assert_eq!(CkMechanismType::AES_ECB_ENCRYPT_DATA.0, 0x0000_1104);
        assert_eq!(CkMechanismType::AES_CBC_ENCRYPT_DATA.0, 0x0000_1105);
        assert_eq!(CkMechanismType::AES_OFB.0, 0x0000_2104);
        assert_eq!(CkMechanismType::AES_CFB64.0, 0x0000_2105);
        assert_eq!(CkMechanismType::AES_CFB8.0, 0x0000_2106);
        assert_eq!(CkMechanismType::AES_CFB128.0, 0x0000_2107);
        assert_eq!(CkMechanismType::AES_CFB1.0, 0x0000_2108);
        assert_eq!(CkMechanismType::AES_KEY_WRAP.0, 0x0000_2109);
        assert_eq!(CkMechanismType::AES_KEY_WRAP_PAD.0, 0x0000_210A);
        assert_eq!(CkMechanismType::AES_KEY_WRAP_KWP.0, 0x0000_210B);
        assert_eq!(CkMechanismType::AES_KEY_WRAP_PKCS7.0, 0x0000_210C);
    }

    #[test]
    fn standard_salsa_chacha_poly1305_constants_match_spec() {
        assert_eq!(CkMechanismType::CHACHA20_KEY_GEN.0, 0x0000_1225);
        assert_eq!(CkMechanismType::CHACHA20.0, 0x0000_1226);
        assert_eq!(CkMechanismType::POLY1305_KEY_GEN.0, 0x0000_1227);
        assert_eq!(CkMechanismType::POLY1305.0, 0x0000_1228);
        assert_eq!(CkMechanismType::SALSA20.0, 0x0000_4020);
        assert_eq!(CkMechanismType::CHACHA20_POLY1305.0, 0x0000_4021);
        assert_eq!(CkMechanismType::SALSA20_POLY1305.0, 0x0000_4022);
        assert_eq!(CkMechanismType::SALSA20_KEY_GEN.0, 0x0000_402D);
    }

    #[test]
    fn standard_aria_camellia_seed_constants_match_spec() {
        assert_eq!(CkMechanismType::CAMELLIA_KEY_GEN.0, 0x0000_0550);
        assert_eq!(CkMechanismType::CAMELLIA_ECB.0, 0x0000_0551);
        assert_eq!(CkMechanismType::CAMELLIA_CBC.0, 0x0000_0552);
        assert_eq!(CkMechanismType::CAMELLIA_MAC.0, 0x0000_0553);
        assert_eq!(CkMechanismType::CAMELLIA_MAC_GENERAL.0, 0x0000_0554);
        assert_eq!(CkMechanismType::CAMELLIA_CBC_PAD.0, 0x0000_0555);
        assert_eq!(CkMechanismType::CAMELLIA_ECB_ENCRYPT_DATA.0, 0x0000_0556);
        assert_eq!(CkMechanismType::CAMELLIA_CBC_ENCRYPT_DATA.0, 0x0000_0557);
        assert_eq!(CkMechanismType::ARIA_KEY_GEN.0, 0x0000_0560);
        assert_eq!(CkMechanismType::ARIA_ECB.0, 0x0000_0561);
        assert_eq!(CkMechanismType::ARIA_CBC.0, 0x0000_0562);
        assert_eq!(CkMechanismType::ARIA_MAC.0, 0x0000_0563);
        assert_eq!(CkMechanismType::ARIA_MAC_GENERAL.0, 0x0000_0564);
        assert_eq!(CkMechanismType::ARIA_CBC_PAD.0, 0x0000_0565);
        assert_eq!(CkMechanismType::ARIA_ECB_ENCRYPT_DATA.0, 0x0000_0566);
        assert_eq!(CkMechanismType::ARIA_CBC_ENCRYPT_DATA.0, 0x0000_0567);
        assert_eq!(CkMechanismType::SEED_KEY_GEN.0, 0x0000_0650);
        assert_eq!(CkMechanismType::SEED_ECB.0, 0x0000_0651);
        assert_eq!(CkMechanismType::SEED_CBC.0, 0x0000_0652);
        assert_eq!(CkMechanismType::SEED_MAC.0, 0x0000_0653);
        assert_eq!(CkMechanismType::SEED_MAC_GENERAL.0, 0x0000_0654);
        assert_eq!(CkMechanismType::SEED_CBC_PAD.0, 0x0000_0655);
        assert_eq!(CkMechanismType::SEED_ECB_ENCRYPT_DATA.0, 0x0000_0656);
        assert_eq!(CkMechanismType::SEED_CBC_ENCRYPT_DATA.0, 0x0000_0657);
    }

    #[test]
    fn standard_des_family_constants_match_spec() {
        assert_eq!(CkMechanismType::DES_KEY_GEN.0, 0x0000_0120);
        assert_eq!(CkMechanismType::DES_ECB.0, 0x0000_0121);
        assert_eq!(CkMechanismType::DES_MAC.0, 0x0000_0123);
        assert_eq!(CkMechanismType::DES_CBC_PAD.0, 0x0000_0125);
        assert_eq!(CkMechanismType::DES2_KEY_GEN.0, 0x0000_0130);
        assert_eq!(CkMechanismType::DES3_KEY_GEN.0, 0x0000_0131);
        assert_eq!(CkMechanismType::DES3_ECB.0, 0x0000_0132);
        assert_eq!(CkMechanismType::DES3_CBC.0, 0x0000_0133);
        assert_eq!(CkMechanismType::DES3_MAC.0, 0x0000_0134);
        assert_eq!(CkMechanismType::DES3_MAC_GENERAL.0, 0x0000_0135);
        assert_eq!(CkMechanismType::DES3_CBC_PAD.0, 0x0000_0136);
        assert_eq!(CkMechanismType::DES3_CMAC_GENERAL.0, 0x0000_0137);
        assert_eq!(CkMechanismType::DES3_CMAC.0, 0x0000_0138);
        assert_eq!(CkMechanismType::DES_OFB64.0, 0x0000_0150);
        assert_eq!(CkMechanismType::DES_OFB8.0, 0x0000_0151);
        assert_eq!(CkMechanismType::DES_CFB64.0, 0x0000_0152);
        assert_eq!(CkMechanismType::DES_CFB8.0, 0x0000_0153);
        assert_eq!(CkMechanismType::DES_ECB_ENCRYPT_DATA.0, 0x0000_1100);
        assert_eq!(CkMechanismType::DES_CBC_ENCRYPT_DATA.0, 0x0000_1101);
        assert_eq!(CkMechanismType::DES3_ECB_ENCRYPT_DATA.0, 0x0000_1102);
        assert_eq!(CkMechanismType::DES3_CBC_ENCRYPT_DATA.0, 0x0000_1103);
    }

    #[test]
    fn standard_ec_family_constants_match_spec() {
        assert_eq!(CkMechanismType::EC_KEY_PAIR_GEN.0, 0x0000_1040);
        assert_eq!(CkMechanismType::ECDSA.0, 0x0000_1041);
        assert_eq!(CkMechanismType::ECDSA_SHA1.0, 0x0000_1042);
        assert_eq!(CkMechanismType::ECDSA_SHA224.0, 0x0000_1043);
        assert_eq!(CkMechanismType::ECDSA_SHA256.0, 0x0000_1044);
        assert_eq!(CkMechanismType::ECDSA_SHA384.0, 0x0000_1045);
        assert_eq!(CkMechanismType::ECDSA_SHA512.0, 0x0000_1046);
        assert_eq!(CkMechanismType::ECDSA_SHA3_224.0, 0x0000_1047);
        assert_eq!(CkMechanismType::ECDSA_SHA3_256.0, 0x0000_1048);
        assert_eq!(CkMechanismType::ECDSA_SHA3_384.0, 0x0000_1049);
        assert_eq!(CkMechanismType::ECDSA_SHA3_512.0, 0x0000_104A);
        assert_eq!(CkMechanismType::ECDH1_DERIVE.0, 0x0000_1050);
        assert_eq!(CkMechanismType::ECDH1_COFACTOR_DERIVE.0, 0x0000_1051);
        assert_eq!(CkMechanismType::ECMQV_DERIVE.0, 0x0000_1052);
        assert_eq!(CkMechanismType::ECDH_AES_KEY_WRAP.0, 0x0000_1053);
        assert_eq!(CkMechanismType::EC_EDWARDS_KEY_PAIR_GEN.0, 0x0000_1055);
        assert_eq!(CkMechanismType::EC_MONTGOMERY_KEY_PAIR_GEN.0, 0x0000_1056);
        assert_eq!(CkMechanismType::EDDSA.0, 0x0000_1057);
        assert_eq!(CkMechanismType::EC_KEY_PAIR_GEN_W_EXTRA_BITS.0, 0x0000_140B);
        assert_eq!(CkMechanismType::XEDDSA.0, 0x0000_4029);
        assert_eq!(CkMechanismType::ECDH_X_AES_KEY_WRAP.0, 0x0000_4038);
        assert_eq!(CkMechanismType::ECDH_COF_AES_KEY_WRAP.0, 0x0000_4039);
    }

    #[test]
    fn standard_blowfish_twofish_constants_match_spec() {
        assert_eq!(CkMechanismType::BLOWFISH_KEY_GEN.0, 0x0000_1090);
        assert_eq!(CkMechanismType::BLOWFISH_CBC.0, 0x0000_1091);
        assert_eq!(CkMechanismType::TWOFISH_KEY_GEN.0, 0x0000_1092);
        assert_eq!(CkMechanismType::TWOFISH_CBC.0, 0x0000_1093);
        assert_eq!(CkMechanismType::BLOWFISH_CBC_PAD.0, 0x0000_1094);
        assert_eq!(CkMechanismType::TWOFISH_CBC_PAD.0, 0x0000_1095);
    }

    #[test]
    fn standard_simple_key_derivation_constants_match_spec() {
        assert_eq!(CkMechanismType::GENERIC_SECRET_KEY_GEN.0, 0x0000_0350);
        assert_eq!(CkMechanismType::CONCATENATE_BASE_AND_KEY.0, 0x0000_0360);
        assert_eq!(CkMechanismType::CONCATENATE_BASE_AND_DATA.0, 0x0000_0362);
        assert_eq!(CkMechanismType::CONCATENATE_DATA_AND_BASE.0, 0x0000_0363);
        assert_eq!(CkMechanismType::XOR_BASE_AND_DATA.0, 0x0000_0364);
        assert_eq!(CkMechanismType::EXTRACT_KEY_FROM_KEY.0, 0x0000_0365);
        assert_eq!(CkMechanismType::PUB_KEY_FROM_PRIV_KEY.0, 0x0000_403A);
    }

    #[test]
    fn standard_hkdf_constants_match_spec() {
        assert_eq!(CkMechanismType::HKDF_DERIVE.0, 0x0000_402A);
        assert_eq!(CkMechanismType::HKDF_DATA.0, 0x0000_402B);
        assert_eq!(CkMechanismType::HKDF_KEY_GEN.0, 0x0000_402C);
    }

    #[test]
    fn standard_kip_constants_match_spec() {
        assert_eq!(CkMechanismType::KIP_DERIVE.0, 0x0000_0510);
        assert_eq!(CkMechanismType::KIP_WRAP.0, 0x0000_0511);
        assert_eq!(CkMechanismType::KIP_MAC.0, 0x0000_0512);
    }

    #[test]
    fn standard_ike_constants_match_spec() {
        assert_eq!(CkMechanismType::IKE2_PRF_PLUS_DERIVE.0, 0x0000_402E);
        assert_eq!(CkMechanismType::IKE_PRF_DERIVE.0, 0x0000_402F);
        assert_eq!(CkMechanismType::IKE1_PRF_DERIVE.0, 0x0000_4030);
        assert_eq!(CkMechanismType::IKE1_EXTENDED_DERIVE.0, 0x0000_4031);
    }

    #[test]
    fn standard_shake_key_derivation_constants_match_spec() {
        assert_eq!(CkMechanismType::SHAKE_128_KEY_DERIVATION.0, 0x0000_039B);
        assert_eq!(CkMechanismType::SHAKE_256_KEY_DERIVATION.0, 0x0000_039C);
    }

    #[test]
    fn standard_historical_md_digest_constants_match_spec() {
        assert_eq!(CkMechanismType::MD2.0, 0x0000_0200);
        assert_eq!(CkMechanismType::MD5.0, 0x0000_0210);
    }

    #[test]
    fn standard_otp_constants_match_spec() {
        assert_eq!(CkMechanismType::SECURID_KEY_GEN.0, 0x0000_0280);
        assert_eq!(CkMechanismType::SECURID.0, 0x0000_0282);
        assert_eq!(CkMechanismType::HOTP_KEY_GEN.0, 0x0000_0290);
        assert_eq!(CkMechanismType::HOTP.0, 0x0000_0291);
    }

    #[test]
    fn standard_stateful_hash_signature_constants_match_spec() {
        assert_eq!(CkMechanismType::HSS_KEY_PAIR_GEN.0, 0x0000_4032);
        assert_eq!(CkMechanismType::HSS.0, 0x0000_4033);
        assert_eq!(CkMechanismType::XMSS_KEY_PAIR_GEN.0, 0x0000_4034);
        assert_eq!(CkMechanismType::XMSSMT_KEY_PAIR_GEN.0, 0x0000_4035);
        assert_eq!(CkMechanismType::XMSS.0, 0x0000_4036);
        assert_eq!(CkMechanismType::XMSSMT.0, 0x0000_4037);
    }

    #[test]
    fn standard_tls_ssl_wtls_constants_match_spec() {
        assert_eq!(CkMechanismType::SSL3_PRE_MASTER_KEY_GEN.0, 0x0000_0370);
        assert_eq!(CkMechanismType::SSL3_MASTER_KEY_DERIVE.0, 0x0000_0371);
        assert_eq!(CkMechanismType::SSL3_KEY_AND_MAC_DERIVE.0, 0x0000_0372);
        assert_eq!(CkMechanismType::SSL3_MASTER_KEY_DERIVE_DH.0, 0x0000_0373);
        assert_eq!(CkMechanismType::TLS_PRE_MASTER_KEY_GEN.0, 0x0000_0374);
        assert_eq!(CkMechanismType::SSL3_MD5_MAC.0, 0x0000_0380);
        assert_eq!(CkMechanismType::SSL3_SHA1_MAC.0, 0x0000_0381);
        assert_eq!(CkMechanismType::WTLS_PRE_MASTER_KEY_GEN.0, 0x0000_03D0);
        assert_eq!(CkMechanismType::WTLS_MASTER_KEY_DERIVE.0, 0x0000_03D1);
        assert_eq!(CkMechanismType::WTLS_MASTER_KEY_DERIVE_DH_ECC.0, 0x0000_03D2);
        assert_eq!(CkMechanismType::WTLS_PRF.0, 0x0000_03D3);
        assert_eq!(CkMechanismType::WTLS_SERVER_KEY_AND_MAC_DERIVE.0, 0x0000_03D4);
        assert_eq!(CkMechanismType::WTLS_CLIENT_KEY_AND_MAC_DERIVE.0, 0x0000_03D5);
        assert_eq!(CkMechanismType::TLS12_MAC.0, 0x0000_03D8);
        assert_eq!(CkMechanismType::TLS12_KDF.0, 0x0000_03D9);
        assert_eq!(CkMechanismType::TLS_PRF.0, 0x0000_0378);
        assert_eq!(CkMechanismType::TLS12_MASTER_KEY_DERIVE.0, 0x0000_03E0);
        assert_eq!(CkMechanismType::TLS12_KEY_AND_MAC_DERIVE.0, 0x0000_03E1);
        assert_eq!(CkMechanismType::TLS12_MASTER_KEY_DERIVE_DH.0, 0x0000_03E2);
        assert_eq!(CkMechanismType::TLS12_KEY_SAFE_DERIVE.0, 0x0000_03E3);
        assert_eq!(CkMechanismType::TLS_MAC.0, 0x0000_03E4);
        assert_eq!(CkMechanismType::TLS_KDF.0, 0x0000_03E5);
        assert_eq!(CkMechanismType::TLS12_EXTENDED_MASTER_KEY_DERIVE.0, 0x0000_0056);
        assert_eq!(CkMechanismType::TLS12_EXTENDED_MASTER_KEY_DERIVE_DH.0, 0x0000_0057);
    }

    #[test]
    fn standard_diffie_hellman_constants_match_spec() {
        assert_eq!(CkMechanismType::DH_PKCS_KEY_PAIR_GEN.0, 0x0000_0020);
        assert_eq!(CkMechanismType::DH_PKCS_DERIVE.0, 0x0000_0021);
        assert_eq!(CkMechanismType::X9_42_DH_KEY_PAIR_GEN.0, 0x0000_0030);
        assert_eq!(CkMechanismType::X9_42_DH_DERIVE.0, 0x0000_0031);
        assert_eq!(CkMechanismType::X9_42_DH_HYBRID_DERIVE.0, 0x0000_0032);
        assert_eq!(CkMechanismType::X9_42_MQV_DERIVE.0, 0x0000_0033);
        assert_eq!(CkMechanismType::DH_PKCS_PARAMETER_GEN.0, 0x0000_2001);
        assert_eq!(CkMechanismType::X9_42_DH_PARAMETER_GEN.0, 0x0000_2002);
    }

    #[test]
    fn standard_remaining_table_backed_constants_match_spec() {
        assert_eq!(CkMechanismType::RSA_9796.0, 0x0000_0002);
        assert_eq!(CkMechanismType::RSA_X_509.0, 0x0000_0003);
        assert_eq!(CkMechanismType::RSA_X9_31_KEY_PAIR_GEN.0, 0x0000_000A);
        assert_eq!(CkMechanismType::RSA_X9_31.0, 0x0000_000B);
        assert_eq!(CkMechanismType::CMS_SIG.0, 0x0000_0500);
        assert_eq!(CkMechanismType::PBE_SHA1_DES3_EDE_CBC.0, 0x0000_03A8);
        assert_eq!(CkMechanismType::PBE_SHA1_DES2_EDE_CBC.0, 0x0000_03A9);
        assert_eq!(CkMechanismType::PKCS5_PBKD2.0, 0x0000_03B0);
        assert_eq!(CkMechanismType::PBA_SHA1_WITH_SHA1_HMAC.0, 0x0000_03C0);
        assert_eq!(CkMechanismType::RSA_AES_KEY_WRAP.0, 0x0000_1054);
        assert_eq!(CkMechanismType::GOSTR3410_KEY_PAIR_GEN.0, 0x0000_1200);
        assert_eq!(CkMechanismType::GOSTR3410.0, 0x0000_1201);
        assert_eq!(CkMechanismType::GOSTR3410_WITH_GOSTR3411.0, 0x0000_1202);
        assert_eq!(CkMechanismType::GOSTR3410_KEY_WRAP.0, 0x0000_1203);
        assert_eq!(CkMechanismType::GOSTR3410_DERIVE.0, 0x0000_1204);
        assert_eq!(CkMechanismType::GOSTR3411.0, 0x0000_1210);
        assert_eq!(CkMechanismType::GOSTR3411_HMAC.0, 0x0000_1211);
        assert_eq!(CkMechanismType::GOST28147_KEY_GEN.0, 0x0000_1220);
        assert_eq!(CkMechanismType::GOST28147_ECB.0, 0x0000_1221);
        assert_eq!(CkMechanismType::GOST28147.0, 0x0000_1222);
        assert_eq!(CkMechanismType::GOST28147_MAC.0, 0x0000_1223);
        assert_eq!(CkMechanismType::GOST28147_KEY_WRAP.0, 0x0000_1224);
        assert_eq!(CkMechanismType::RSA_PKCS_TPM_1_1.0, 0x0000_4001);
        assert_eq!(CkMechanismType::RSA_PKCS_OAEP_TPM_1_1.0, 0x0000_4002);
        assert_eq!(CkMechanismType::NULL.0, 0x0000_400B);
        assert_eq!(CkMechanismType::X3DH_INITIALIZE.0, 0x0000_4023);
        assert_eq!(CkMechanismType::X3DH_RESPOND.0, 0x0000_4024);
        assert_eq!(CkMechanismType::X2RATCHET_INITIALIZE.0, 0x0000_4025);
        assert_eq!(CkMechanismType::X2RATCHET_RESPOND.0, 0x0000_4026);
        assert_eq!(CkMechanismType::X2RATCHET_ENCRYPT.0, 0x0000_4027);
        assert_eq!(CkMechanismType::X2RATCHET_DECRYPT.0, 0x0000_4028);
    }

    #[test]
    fn mechanism_info_flag_constants_match_pkcs11_3_2_header() {
        let flags = [
            (CkMechanismFlags::HW, 0x0000_0001),
            (CkMechanismFlags::MESSAGE_ENCRYPT, 0x0000_0002),
            (CkMechanismFlags::MESSAGE_DECRYPT, 0x0000_0004),
            (CkMechanismFlags::MESSAGE_SIGN, 0x0000_0008),
            (CkMechanismFlags::MESSAGE_VERIFY, 0x0000_0010),
            (CkMechanismFlags::MULTI_MESSAGE, 0x0000_0020),
            (CkMechanismFlags::MULTI_MESSGE, 0x0000_0020),
            (CkMechanismFlags::FIND_OBJECTS, 0x0000_0040),
            (CkMechanismFlags::ENCRYPT, 0x0000_0100),
            (CkMechanismFlags::DECRYPT, 0x0000_0200),
            (CkMechanismFlags::DIGEST, 0x0000_0400),
            (CkMechanismFlags::SIGN, 0x0000_0800),
            (CkMechanismFlags::SIGN_RECOVER, 0x0000_1000),
            (CkMechanismFlags::VERIFY, 0x0000_2000),
            (CkMechanismFlags::VERIFY_RECOVER, 0x0000_4000),
            (CkMechanismFlags::GENERATE, 0x0000_8000),
            (CkMechanismFlags::GENERATE_KEY_PAIR, 0x0001_0000),
            (CkMechanismFlags::WRAP, 0x0002_0000),
            (CkMechanismFlags::UNWRAP, 0x0004_0000),
            (CkMechanismFlags::DERIVE, 0x0008_0000),
            (CkMechanismFlags::EC_F_P, 0x0010_0000),
            (CkMechanismFlags::EC_F_2M, 0x0020_0000),
            (CkMechanismFlags::EC_ECPARAMETERS, 0x0040_0000),
            (CkMechanismFlags::EC_OID, 0x0080_0000),
            (CkMechanismFlags::EC_NAMEDCURVE, 0x0080_0000),
            (CkMechanismFlags::EC_UNCOMPRESS, 0x0100_0000),
            (CkMechanismFlags::EC_COMPRESS, 0x0200_0000),
            (CkMechanismFlags::EC_CURVENAME, 0x0400_0000),
            (CkMechanismFlags::ENCAPSULATE, 0x1000_0000),
            (CkMechanismFlags::DECAPSULATE, 0x2000_0000),
            (CkMechanismFlags::EXTENSION, 0x8000_0000),
        ];

        for (actual, expected) in flags {
            assert_eq!(actual, expected);
        }
    }
}

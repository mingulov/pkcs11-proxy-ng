use crate::attribute::CkAttribute;
use crate::object::CkObjectHandle;
use crate::secret::SecretBytes;

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

    // Post-quantum mechanisms (PKCS#11 3.2)
    pub const ML_KEM_KEY_PAIR_GEN: Self = Self(0x0000000F);
    pub const ML_KEM: Self = Self(0x00000017);
    pub const ML_DSA_KEY_PAIR_GEN: Self = Self(0x0000001C);
    pub const ML_DSA: Self = Self(0x0000001D);
    pub const HASH_ML_DSA: Self = Self(0x0000001F);
    pub const HASH_ML_DSA_SHA224: Self = Self(0x00000023);
    pub const HASH_ML_DSA_SHA256: Self = Self(0x00000024);
    pub const HASH_ML_DSA_SHA384: Self = Self(0x00000025);
    pub const HASH_ML_DSA_SHA512: Self = Self(0x00000026);
    pub const HASH_ML_DSA_SHA3_224: Self = Self(0x00000027);
    pub const HASH_ML_DSA_SHA3_256: Self = Self(0x00000028);
    pub const HASH_ML_DSA_SHA3_384: Self = Self(0x00000029);
    pub const HASH_ML_DSA_SHA3_512: Self = Self(0x0000002A);
    pub const HASH_ML_DSA_SHAKE128: Self = Self(0x0000002B);
    pub const HASH_ML_DSA_SHAKE256: Self = Self(0x0000002C);
    pub const SLH_DSA_KEY_PAIR_GEN: Self = Self(0x0000002D);
    pub const SLH_DSA: Self = Self(0x0000002E);
    pub const HASH_SLH_DSA: Self = Self(0x00000034);
    pub const HASH_SLH_DSA_SHA224: Self = Self(0x00000036);
    pub const HASH_SLH_DSA_SHA256: Self = Self(0x00000037);
    pub const HASH_SLH_DSA_SHA384: Self = Self(0x00000038);
    pub const HASH_SLH_DSA_SHA512: Self = Self(0x00000039);
    pub const HASH_SLH_DSA_SHA3_224: Self = Self(0x0000003A);
    pub const HASH_SLH_DSA_SHA3_256: Self = Self(0x0000003B);
    pub const HASH_SLH_DSA_SHA3_384: Self = Self(0x0000003C);
    pub const HASH_SLH_DSA_SHA3_512: Self = Self(0x0000003D);
    pub const HASH_SLH_DSA_SHAKE128: Self = Self(0x0000003E);
    pub const HASH_SLH_DSA_SHAKE256: Self = Self(0x0000003F);

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
    pub const SHA_1: Self = Self(0x00000220);
    pub const SHA_1_HMAC: Self = Self(0x00000221);
    pub const SHA_1_HMAC_GENERAL: Self = Self(0x00000222);
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
    pub const SP800_108_COUNTER_KDF: Self = Self(0x000003AC);
    pub const SP800_108_FEEDBACK_KDF: Self = Self(0x000003AD);
    pub const SP800_108_DOUBLE_PIPELINE_KDF: Self = Self(0x000003AE);
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
    pub const RC2_KEY_GEN: Self = Self(0x00000100);
    pub const RC2_ECB: Self = Self(0x00000101);
    pub const RC2_CBC: Self = Self(0x00000102);
    pub const RC2_MAC: Self = Self(0x00000103);
    pub const RC2_MAC_GENERAL: Self = Self(0x00000104);
    pub const RC2_CBC_PAD: Self = Self(0x00000105);
    pub const RC4_KEY_GEN: Self = Self(0x00000110);
    pub const RC4: Self = Self(0x00000111);
    pub const DES_KEY_GEN: Self = Self(0x00000120);
    pub const DES_ECB: Self = Self(0x00000121);
    pub const DES_CBC: Self = Self(0x00000122);
    pub const DES_MAC: Self = Self(0x00000123);
    pub const DES_MAC_GENERAL: Self = Self(0x00000124);
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
    pub const BLAKE2B_160: Self = Self(0x0000400C);
    pub const BLAKE2B_160_HMAC: Self = Self(0x0000400D);
    pub const BLAKE2B_160_HMAC_GENERAL: Self = Self(0x0000400E);
    pub const BLAKE2B_160_KEY_DERIVE: Self = Self(0x0000400F);
    pub const BLAKE2B_160_KEY_GEN: Self = Self(0x00004010);
    pub const BLAKE2B_256: Self = Self(0x00004011);
    pub const BLAKE2B_256_HMAC: Self = Self(0x00004012);
    pub const BLAKE2B_256_HMAC_GENERAL: Self = Self(0x00004013);
    pub const BLAKE2B_256_KEY_DERIVE: Self = Self(0x00004014);
    pub const BLAKE2B_256_KEY_GEN: Self = Self(0x00004015);
    pub const BLAKE2B_384: Self = Self(0x00004016);
    pub const BLAKE2B_384_HMAC: Self = Self(0x00004017);
    pub const BLAKE2B_384_HMAC_GENERAL: Self = Self(0x00004018);
    pub const BLAKE2B_384_KEY_DERIVE: Self = Self(0x00004019);
    pub const BLAKE2B_384_KEY_GEN: Self = Self(0x0000401A);
    pub const BLAKE2B_512: Self = Self(0x0000401B);
    pub const BLAKE2B_512_HMAC: Self = Self(0x0000401C);
    pub const BLAKE2B_512_HMAC_GENERAL: Self = Self(0x0000401D);
    pub const BLAKE2B_512_KEY_DERIVE: Self = Self(0x0000401E);
    pub const BLAKE2B_512_KEY_GEN: Self = Self(0x0000401F);
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

/// Mask generation function for RSA-PSS/OAEP (`CK_RSA_PKCS_MGF_TYPE`,
/// `CKG_MGF1_*` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CkMgf(pub u64);

impl CkMgf {
    pub const MGF1_SHA1: Self = Self(1);
    pub const MGF1_SHA256: Self = Self(2);
    pub const MGF1_SHA384: Self = Self(3);
    pub const MGF1_SHA512: Self = Self(4);
    pub const MGF1_SHA224: Self = Self(5);
    pub const MGF1_SHA3_224: Self = Self(6);
    pub const MGF1_SHA3_256: Self = Self(7);
    pub const MGF1_SHA3_384: Self = Self(8);
    pub const MGF1_SHA3_512: Self = Self(9);
}

/// IV/nonce generator function for GCM/CCM wrap params
/// (`CK_GENERATOR_FUNCTION`, `CKG_*` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CkGeneratorFunction(pub u64);

impl CkGeneratorFunction {
    pub const NO_GENERATE: Self = Self(0);
    pub const GENERATE: Self = Self(1);
    pub const GENERATE_COUNTER: Self = Self(2);
    pub const GENERATE_RANDOM: Self = Self(3);
    pub const GENERATE_COUNTER_XOR: Self = Self(4);
}

/// Key derivation function selector (`CK_EC_KDF_TYPE` / `CK_X9_42_DH_KDF_TYPE` /
/// `CK_X2RATCHET_KDF_TYPE`, shared `CKD_*` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CkKdf(pub u64);

impl CkKdf {
    pub const NULL: Self = Self(1);
    pub const SHA1_KDF: Self = Self(2);
    pub const SHA1_KDF_ASN1: Self = Self(3);
    pub const SHA1_KDF_CONCATENATE: Self = Self(4);
    pub const SHA224_KDF: Self = Self(5);
    pub const SHA256_KDF: Self = Self(6);
    pub const SHA384_KDF: Self = Self(7);
    pub const SHA512_KDF: Self = Self(8);
    pub const CPDIVERSIFY_KDF: Self = Self(9);
    pub const SHA3_224_KDF: Self = Self(10);
    pub const SHA3_256_KDF: Self = Self(11);
    pub const SHA3_384_KDF: Self = Self(12);
    pub const SHA3_512_KDF: Self = Self(13);
    pub const SHA1_KDF_SP800: Self = Self(14);
    pub const SHA224_KDF_SP800: Self = Self(15);
    pub const SHA256_KDF_SP800: Self = Self(16);
    pub const SHA384_KDF_SP800: Self = Self(17);
    pub const SHA512_KDF_SP800: Self = Self(18);
    pub const SHA3_224_KDF_SP800: Self = Self(19);
    pub const SHA3_256_KDF_SP800: Self = Self(20);
    pub const SHA3_384_KDF_SP800: Self = Self(21);
    pub const SHA3_512_KDF_SP800: Self = Self(22);
    pub const BLAKE2B_160_KDF: Self = Self(23);
    pub const BLAKE2B_256_KDF: Self = Self(24);
    pub const BLAKE2B_384_KDF: Self = Self(25);
    pub const BLAKE2B_512_KDF: Self = Self(26);
}

/// RSA-OAEP data source (`CK_RSA_PKCS_OAEP_SOURCE_TYPE`, `CKZ_*` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CkOaepSource(pub u64);

impl CkOaepSource {
    pub const DATA_SPECIFIED: Self = Self(1);
}

/// PBKDF2 salt source (`CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE`, `CKZ_*` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zeroize::Zeroize)]
pub struct CkPbkdf2SaltSource(pub u64);

impl CkPbkdf2SaltSource {
    pub const SALT_SPECIFIED: Self = Self(1);
}

/// PBKDF2 pseudo-random function (`CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE`,
/// `CKP_PKCS5_PBKD2_HMAC_*` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zeroize::Zeroize)]
pub struct CkPbkdf2Prf(pub u64);

impl CkPbkdf2Prf {
    pub const HMAC_SHA1: Self = Self(1);
    pub const HMAC_GOSTR3411: Self = Self(2);
    pub const HMAC_SHA224: Self = Self(3);
    pub const HMAC_SHA256: Self = Self(4);
    pub const HMAC_SHA384: Self = Self(5);
    pub const HMAC_SHA512: Self = Self(6);
    pub const HMAC_SHA512_224: Self = Self(7);
    pub const HMAC_SHA512_256: Self = Self(8);
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
    pub mgf: CkMgf,
    pub salt_len: u64,
}

/// CK_RSA_PKCS_OAEP_PARAMS
///
/// - `source_null`: the caller passed (NULL, 0) for `pSourceData` (Wave 3.5
///   D2; preserved so the daemon materializes NULL instead of (ptr, 0)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPkcsOaepParams {
    pub hash_alg: CkMechanismType,
    pub mgf: CkMgf,
    pub source: CkOaepSource,
    pub source_data: SecretBytes,
    pub source_null: bool,
}

/// CK_GCM_PARAMS — parameters for CKM_AES_GCM.
///
/// - `iv`: initialisation vector bytes (typically 12 bytes / 96 bits)
/// - `iv_bits`: length of the IV in bits (must equal `iv.len() * 8` in standard usage)
/// - `iv_buffer_len`: writable IV buffer capacity when `iv` is an output parameter
/// - `aad`: additional authenticated data (may be empty)
/// - `tag_bits`: authentication tag length in bits (96, 112, or 128)
/// - `iv_null` / `aad_null`: the caller passed (NULL, 0) for `pIv` / `pAAD`
///   (Wave 3.5 D2; preserved so the daemon materializes NULL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcmParams {
    pub iv: Vec<u8>,
    pub iv_bits: u64,
    pub iv_buffer_len: u64,
    pub aad: SecretBytes,
    pub tag_bits: u64,
    pub iv_null: bool,
    pub aad_null: bool,
}

/// CK_ECDH1_DERIVE_PARAMS — parameters for CKM_ECDH1_DERIVE.
///
/// - `kdf`: key derivation function type (CKD_NULL = 1, CKD_SHA1_KDF = 2, etc.)
/// - `shared_data`: optional shared data input to the KDF (may be empty)
/// - `public_data`: other party's EC public key (uncompressed EC point)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ecdh1DeriveParams {
    pub kdf: CkKdf,
    pub shared_data: SecretBytes,
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
    pub hash: CkMechanismType,
}

/// CK_TLS_MAC_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsMacParams {
    pub prf_hash_mechanism: CkMechanismType,
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
    pub data: SecretBytes,
}

/// CK_DES_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesCbcEncryptDataParams {
    pub iv: Vec<u8>, // 8-byte IV
    pub data: SecretBytes,
}

/// CK_ARIA_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AriaCbcEncryptDataParams {
    pub iv: Vec<u8>, // 16-byte IV
    pub data: SecretBytes,
}

/// CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CamelliaCbcEncryptDataParams {
    pub iv: Vec<u8>, // 16-byte IV
    pub data: SecretBytes,
}

/// CK_SEED_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedCbcEncryptDataParams {
    pub iv: Vec<u8>, // 16-byte IV
    pub data: SecretBytes,
}

// --- AEAD parameter structs ---

/// CK_CCM_PARAMS / CK_AES_CCM_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcmParams {
    pub data_len: u64,
    pub nonce: Vec<u8>,
    pub aad: SecretBytes,
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
    pub aad: SecretBytes,
}

/// CK_GCM_WRAP_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcmWrapParams {
    pub iv: Vec<u8>,
    pub iv_fixed_bits: u64,
    pub iv_generator: CkGeneratorFunction,
    pub aad: SecretBytes,
    pub tag_bits: u64,
}

/// CK_CCM_WRAP_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcmWrapParams {
    pub data_len: u64,
    pub nonce: Vec<u8>,
    pub nonce_fixed_bits: u64,
    pub nonce_generator: CkGeneratorFunction,
    pub aad: SecretBytes,
    pub mac_len: u64,
}

// ---------------------------------------------------------------------------
// Key Derivation parameter structs
// ---------------------------------------------------------------------------

/// CK_ECDH2_DERIVE_PARAMS — dual ECDH key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ecdh2DeriveParams {
    pub kdf: CkKdf,
    pub shared_data: SecretBytes,
    pub public_data: Vec<u8>,
    pub private_data_len: u64,
    pub private_data_handle: CkObjectHandle,
    pub public_data2: Vec<u8>,
}

/// CK_ECMQV_DERIVE_PARAMS — EC-MQV key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcmqvDeriveParams {
    pub kdf: CkKdf,
    pub shared_data: SecretBytes,
    pub public_data: Vec<u8>,
    pub private_data_len: u64,
    pub private_data_handle: CkObjectHandle,
    pub public_data2: Vec<u8>,
    pub public_key_handle: CkObjectHandle,
}

/// CK_X9_42_DH1_DERIVE_PARAMS — X9.42 DH key derivation (single).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X942Dh1DeriveParams {
    pub kdf: CkKdf,
    pub other_info: SecretBytes,
    pub public_data: Vec<u8>,
}

/// CK_X9_42_DH2_DERIVE_PARAMS — X9.42 DH key derivation (dual).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X942Dh2DeriveParams {
    pub kdf: CkKdf,
    pub other_info: SecretBytes,
    pub public_data: Vec<u8>,
    pub private_data_len: u64,
    pub private_data_handle: CkObjectHandle,
    pub public_data2: Vec<u8>,
}

/// CK_X9_42_MQV_DERIVE_PARAMS — X9.42 MQV key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X942MqvDeriveParams {
    pub kdf: CkKdf,
    pub other_info: SecretBytes,
    pub public_data: Vec<u8>,
    pub private_data_len: u64,
    pub private_data_handle: CkObjectHandle,
    pub public_data2: Vec<u8>,
    pub public_key_handle: CkObjectHandle,
}

/// CK_HKDF_PARAMS — HKDF key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HkdfParams {
    pub extract: bool,
    pub expand: bool,
    pub prf_hash_mechanism: CkMechanismType,
    pub salt_type: u64,
    pub salt: SecretBytes,
    pub salt_key_handle: CkObjectHandle,
    pub info: SecretBytes,
}

/// CK_EDDSA_PARAMS — EdDSA signature parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EddsaParams {
    pub ph_flag: bool,
    pub context_data: SecretBytes,
}

/// CK_GOSTR3410_DERIVE_PARAMS — GOST R 34.10 key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gostr3410DeriveParams {
    pub kdf: CkKdf,
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
    pub kdf: CkKdf,
    pub shared_data: SecretBytes,
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
    pub key_handle: CkObjectHandle,
}

/// CK_KEY_WRAP_SET_OAEP_PARAMS — SET OAEP key wrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapSetOaepParams {
    pub bc: u32,
    pub x: SecretBytes,
}

// ---------------------------------------------------------------------------
// Password-Based Encryption parameter structs
// ---------------------------------------------------------------------------

/// CK_PBE_PARAMS — password-based encryption.
///
/// Holds an in-memory password. `Debug` is overridden to redact the
/// password byte slice; `Zeroize` + `ZeroizeOnDrop` ensure the buffer
/// is overwritten when the value is dropped.
#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PbeParams {
    pub init_vector: SecretBytes,
    pub password: SecretBytes,
    pub salt: SecretBytes,
    pub iteration: u64,
}

impl std::fmt::Debug for PbeParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructure so the compiler errors here when a field is
        // added — preventing a future contributor from adding a
        // secret-bearing field that is silently omitted from Debug.
        let Self { init_vector, password, salt, iteration } = self;
        f.debug_struct("PbeParams")
            .field("init_vector", &format_args!("[{} bytes]", init_vector.len()))
            .field("password", &format_args!("[REDACTED; {} bytes]", password.len()))
            .field("salt", &format_args!("[{} bytes]", salt.len()))
            .field("iteration", iteration)
            .finish()
    }
}

/// CK_PKCS5_PBKD2_PARAMS / CK_PKCS5_PBKD2_PARAMS2 — PKCS#5 PBKDF2.
///
/// Password is redacted in Debug and zeroized on drop, as in
/// [`PbeParams`].
#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Pkcs5Pbkd2Params {
    pub salt_source: CkPbkdf2SaltSource,
    pub salt_source_data: SecretBytes,
    pub iterations: u64,
    pub prf: CkPbkdf2Prf,
    pub prf_data: SecretBytes,
    pub password: SecretBytes,
}

impl std::fmt::Debug for Pkcs5Pbkd2Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructure to gate against silently-omitted future fields.
        let Self { salt_source, salt_source_data, iterations, prf, prf_data, password } = self;
        f.debug_struct("Pkcs5Pbkd2Params")
            .field("salt_source", salt_source)
            .field("salt_source_data", &format_args!("[{} bytes]", salt_source_data.len()))
            .field("iterations", iterations)
            .field("prf", prf)
            .field("prf_data", &format_args!("[{} bytes]", prf_data.len()))
            .field("password", &format_args!("[REDACTED; {} bytes]", password.len()))
            .finish()
    }
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
    pub seed: SecretBytes,
    pub label: SecretBytes,
    pub output_len: u64,
}

/// CK_TLS_KDF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsKdfParams {
    pub prf_mechanism: CkMechanismType,
    pub label: SecretBytes,
    pub random_info: SslRandomData,
    pub context_data: SecretBytes,
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
    pub prf_hash_mechanism: CkMechanismType,
}

/// CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls12ExtendedMasterKeyDeriveParams {
    pub prf_hash_mechanism: CkMechanismType,
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
    pub prf_hash_mechanism: CkMechanismType,
    pub client_mac_secret_handle: CkObjectHandle,
    pub server_mac_secret_handle: CkObjectHandle,
    pub client_key_handle: CkObjectHandle,
    pub server_key_handle: CkObjectHandle,
    pub client_iv: SecretBytes,
    pub server_iv: SecretBytes,
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
    pub digest_mechanism: CkMechanismType,
    pub random_info: WtlsRandomData,
    pub version: u32,
}

/// CK_WTLS_PRF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtlsPrfParams {
    pub digest_mechanism: CkMechanismType,
    pub seed: SecretBytes,
    pub label: SecretBytes,
    pub output_len: u64,
}

/// CK_WTLS_KEY_MAT_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtlsKeyMatParams {
    pub digest_mechanism: CkMechanismType,
    pub mac_size_bits: u64,
    pub key_size_bits: u64,
    pub iv_size_bits: u64,
    pub sequence_number: u64,
    pub is_export: bool,
    pub random_info: WtlsRandomData,
    pub mac_secret_handle: CkObjectHandle,
    pub key_handle: CkObjectHandle,
    pub iv: Vec<u8>,
}

// ---------------------------------------------------------------------------
// IKE/IPSec parameter structs
// ---------------------------------------------------------------------------

/// CK_IKE_PRF_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IkePrfDeriveParams {
    pub prf_mechanism: CkMechanismType,
    pub data_as_key: bool,
    pub rekey: bool,
    pub ni: SecretBytes,
    pub nr: SecretBytes,
    pub new_key_handle: CkObjectHandle,
}

/// CK_IKE1_PRF_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ike1PrfDeriveParams {
    pub prf_mechanism: CkMechanismType,
    pub has_prev_key: bool,
    pub keygxy_handle: CkObjectHandle,
    pub prev_key_handle: CkObjectHandle,
    pub ckyi: SecretBytes,
    pub ckyr: SecretBytes,
    pub key_number: u32,
}

/// CK_IKE1_EXTENDED_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ike1ExtendedDeriveParams {
    pub prf_mechanism: CkMechanismType,
    pub has_keygxy: bool,
    pub keygxy_handle: CkObjectHandle,
    pub extra_data: SecretBytes,
}

/// CK_IKE2_PRF_PLUS_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ike2PrfPlusDeriveParams {
    pub prf_mechanism: CkMechanismType,
    pub has_seed_key: bool,
    pub seed_key_handle: CkObjectHandle,
    pub seed_data: SecretBytes,
}

// ---------------------------------------------------------------------------
// SP800-108 KDF parameter structs
// ---------------------------------------------------------------------------

/// CK_PRF_DATA_PARAM (used inside SP800-108 params)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfDataParam {
    pub type_: u64,
    pub value: SecretBytes,
}

/// CK_SP800_108_KDF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp800108KdfParams {
    pub prf_type: CkMechanismType,
    pub data_params: Vec<PrfDataParam>,
    pub additional_derived_keys: Vec<Sp800108DerivedKey>,
}

/// CK_SP800_108_FEEDBACK_KDF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp800108FeedbackKdfParams {
    pub prf_type: CkMechanismType,
    pub data_params: Vec<PrfDataParam>,
    pub iv: Vec<u8>,
    pub additional_derived_keys: Vec<Sp800108DerivedKey>,
}

/// CK_DERIVED_KEY entry nested inside SP800-108 KDF params.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp800108DerivedKey {
    pub template: Vec<CkAttribute>,
    pub key_handle: CkObjectHandle,
}

// W1-C9-12 removal note: CK_SP800_108_COUNTER_FORMAT and
// CK_SP800_108_DKM_LENGTH_FORMAT were previously modeled as exported structs
// here, but nothing referenced them — no CkMechanismParams variant, proto
// oneof member, or conversion. They are nested SP800-108 data-format structs,
// not mechanism parameters, so there is no valid enum variant to wire them
// into; their payloads ride opaquely in PrfDataParam::value (mirrored by the
// proto PrfDataParam bytes field). Removed from both the Rust types and
// mechanism_params.proto to keep types.proto and code in agreement.

// ---------------------------------------------------------------------------
// Signal Protocol parameter structs
// ---------------------------------------------------------------------------

/// CK_X3DH_INITIATE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X3dhInitiateParams {
    pub kdf: u64,
    pub peer_identity_handle: CkObjectHandle,
    pub peer_prekey_handle: CkObjectHandle,
    pub prekey_signature: Vec<u8>,
    pub onetime_key_handle: CkObjectHandle,
    pub own_identity_handle: CkObjectHandle,
    pub own_ephemeral_handle: CkObjectHandle,
}

/// CK_X3DH_RESPOND_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X3dhRespondParams {
    pub kdf: u64,
    pub identity_handle: CkObjectHandle,
    pub prekey_handle: CkObjectHandle,
    pub onetime_key_handle: CkObjectHandle,
    pub initiator_identity_handle: CkObjectHandle,
    pub initiator_ephemeral_handle: CkObjectHandle,
}

/// CK_X2RATCHET_INITIALIZE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X2RatchetInitializeParams {
    pub sk: SecretBytes,
    pub peer_public_prekey_handle: CkObjectHandle,
    pub peer_public_identity_handle: CkObjectHandle,
    pub own_public_identity_handle: CkObjectHandle,
    pub encrypted_header: bool,
    pub curve: u64,
    pub aead_mechanism: CkMechanismType,
    pub kdf_mechanism: CkKdf,
}

/// CK_X2RATCHET_RESPOND_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X2RatchetRespondParams {
    pub sk: SecretBytes,
    pub own_prekey_handle: CkObjectHandle,
    pub initiator_identity_handle: CkObjectHandle,
    pub own_identity_handle: CkObjectHandle,
    pub encrypted_header: bool,
    pub curve: u64,
    pub aead_mechanism: CkMechanismType,
    pub kdf_mechanism: CkKdf,
}

// ---------------------------------------------------------------------------
// Miscellaneous parameter structs
// ---------------------------------------------------------------------------

/// CK_OTP_PARAM (individual OTP parameter)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpParam {
    pub type_: u64,
    pub value: SecretBytes,
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
    pub key_handle: CkObjectHandle,
    pub seed: SecretBytes,
}

/// CK_CMS_SIG_PARAMS — references nested Mechanisms (boxed to avoid infinite size).
#[derive(Debug, Clone, PartialEq)]
pub struct CmsSigParams {
    pub certificate_handle: CkObjectHandle,
    pub signing_mechanism: Box<CkMechanism>,
    pub digest_mechanism: Box<CkMechanism>,
    pub content_type: String,
    pub requested_attributes: SecretBytes,
    pub required_attributes: SecretBytes,
}

/// CK_SKIPJACK_PRIVATE_WRAP_PARAMS
///
/// Password redacted in Debug and zeroized on drop, as in
/// [`PbeParams`].
#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SkipjackPrivateWrapParams {
    pub password: SecretBytes,
    pub public_data: Vec<u8>,
    pub password_length: u64,
    pub random_a: Vec<u8>,
    pub prime_p: Vec<u8>,
    pub base_g: Vec<u8>,
    pub subprime_q: Vec<u8>,
}

impl std::fmt::Debug for SkipjackPrivateWrapParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructure to gate against silently-omitted future fields.
        let Self { password, public_data, password_length, random_a, prime_p, base_g, subprime_q } =
            self;
        f.debug_struct("SkipjackPrivateWrapParams")
            .field("password", &format_args!("[REDACTED; {} bytes]", password.len()))
            .field("public_data", &format_args!("[{} bytes]", public_data.len()))
            .field("password_length", password_length)
            .field("random_a", &format_args!("[{} bytes]", random_a.len()))
            .field("prime_p", &format_args!("[{} bytes]", prime_p.len()))
            .field("base_g", &format_args!("[{} bytes]", base_g.len()))
            .field("subprime_q", &format_args!("[{} bytes]", subprime_q.len()))
            .finish()
    }
}

/// CK_SKIPJACK_RELAYX_PARAMS
///
/// Both old and new passwords are redacted in Debug and zeroized on
/// drop, as in [`PbeParams`].
#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SkipjackRelayxParams {
    pub old_wrapped_x: SecretBytes,
    pub old_password: SecretBytes,
    pub old_public_data: SecretBytes,
    pub old_random_a: SecretBytes,
    pub new_password: SecretBytes,
    pub new_public_data: SecretBytes,
    pub new_random_a: SecretBytes,
}

impl std::fmt::Debug for SkipjackRelayxParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructure to gate against silently-omitted future fields.
        let Self {
            old_wrapped_x,
            old_password,
            old_public_data,
            old_random_a,
            new_password,
            new_public_data,
            new_random_a,
        } = self;
        f.debug_struct("SkipjackRelayxParams")
            .field("old_wrapped_x", &format_args!("[{} bytes]", old_wrapped_x.len()))
            .field("old_password", &format_args!("[REDACTED; {} bytes]", old_password.len()))
            .field("old_public_data", &format_args!("[{} bytes]", old_public_data.len()))
            .field("old_random_a", &format_args!("[{} bytes]", old_random_a.len()))
            .field("new_password", &format_args!("[REDACTED; {} bytes]", new_password.len()))
            .field("new_public_data", &format_args!("[{} bytes]", new_public_data.len()))
            .field("new_random_a", &format_args!("[{} bytes]", new_random_a.len()))
            .finish()
    }
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
    pub handle: CkObjectHandle,
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
    pub data: SecretBytes,
}

/// CK_SIGN_ADDITIONAL_CONTEXT (`hash == 0`) or, for the generic
/// CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA, CK_HASH_SIGN_ADDITIONAL_CONTEXT
/// (`hash` = the hash mechanism). One Rust type covers both, the way
/// `Ssl3KeyMatParams` covers SSL3 and TLS12.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignAdditionalContext {
    pub hedge_variant: u64,
    pub context: SecretBytes,
    /// 0 = plain CK_SIGN_ADDITIONAL_CONTEXT; non-zero = CK_HASH_SIGN_ADDITIONAL_CONTEXT.
    pub hash: CkMechanismType,
}

/// CK_KMAC_PARAMS — keyed MAC output length and optional customization string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmacParams {
    pub key_handle: CkObjectHandle,
    pub mac_length: u64,
    pub customization_string: SecretBytes,
}

/// CK_MU_GEN_PARAMS — ML-DSA external-mu generation inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuGenParams {
    pub key_handle: CkObjectHandle,
    pub tr: SecretBytes,
    pub context: SecretBytes,
}

/// Opaque raw parameter bytes — opt-in escape hatch for vendor-specific
/// mechanisms with scalar-only (non-pointer) parameter structures.
/// The config registry controls which mechanisms can use this variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMechanismParams {
    pub data: SecretBytes,
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
    pub shared_data: SecretBytes,
}

/// CK_NC_AES_CMAC_KEY_DERIVATION_PARAMS — AES-CMAC key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesCmacKeyDerivationParams {
    pub context: SecretBytes,
    pub label: SecretBytes,
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
    pub secret_handle: CkObjectHandle,
    pub shared_data: SecretBytes,
    pub blob: SecretBytes,
}

/// CK_IBM_BTC_DERIVE_PARAMS — HD key derivation (BIP-32, BIP-44, SLIP-10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HdKeyDeriveParams {
    pub derive_type: u64,
    pub child_key_index: u64,
    pub chain_code: SecretBytes,
    pub version: u64,
}

/// Vendor object extraction (cloning/backup) parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorObjectExtractParams {
    pub format: u64,
    pub context: SecretBytes,
}

/// Vendor object insertion (restore) parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorObjectInsertParams {
    pub format: u64,
    pub context: SecretBytes,
    pub object_data: SecretBytes,
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
    use crate::object::CkObjectHandle;

    // W1-C9-04: all 42 object-handle fields across mechanism params use
    // CkObjectHandle (mirror the existing CkObjectHandle precedent). If any
    // handle field regresses to raw u64, this fails to compile.
    #[test]
    fn object_handle_fields_use_ck_object_handle() {
        let empty = SecretBytes::copy_from_slice(b"");
        let mech = || CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };

        let p = Ecdh2DeriveParams {
            kdf: CkKdf(1),
            shared_data: empty.clone(),
            public_data: vec![],
            private_data_len: 0,
            private_data_handle: CkObjectHandle(7),
            public_data2: vec![],
        };
        assert_eq!(p.private_data_handle.0, 7);

        let p = EcmqvDeriveParams {
            kdf: CkKdf(1),
            shared_data: empty.clone(),
            public_data: vec![],
            private_data_len: 0,
            private_data_handle: CkObjectHandle(7),
            public_data2: vec![],
            public_key_handle: CkObjectHandle(8),
        };
        assert_eq!((p.private_data_handle.0, p.public_key_handle.0), (7, 8));

        let p = X942Dh2DeriveParams {
            kdf: CkKdf(1),
            other_info: empty.clone(),
            public_data: vec![],
            private_data_len: 0,
            private_data_handle: CkObjectHandle(7),
            public_data2: vec![],
        };
        assert_eq!(p.private_data_handle.0, 7);

        let p = X942MqvDeriveParams {
            kdf: CkKdf(1),
            other_info: empty.clone(),
            public_data: vec![],
            private_data_len: 0,
            private_data_handle: CkObjectHandle(7),
            public_data2: vec![],
            public_key_handle: CkObjectHandle(8),
        };
        assert_eq!((p.private_data_handle.0, p.public_key_handle.0), (7, 8));

        let p = HkdfParams {
            extract: true,
            expand: true,
            prf_hash_mechanism: CkMechanismType(0x250),
            salt_type: 0,
            salt: empty.clone(),
            salt_key_handle: CkObjectHandle(9),
            info: empty.clone(),
        };
        assert_eq!(p.salt_key_handle.0, 9);

        let p =
            Gostr3410KeyWrapParams { wrap_oid: vec![], ukm: vec![], key_handle: CkObjectHandle(9) };
        assert_eq!(p.key_handle.0, 9);

        let p = Ssl3KeyMatParams {
            mac_size_bits: 0,
            key_size_bits: 0,
            iv_size_bits: 0,
            is_export: false,
            random_info: SslRandomData { client_random: vec![], server_random: vec![] },
            prf_hash_mechanism: CkMechanismType(0),
            client_mac_secret_handle: CkObjectHandle(1),
            server_mac_secret_handle: CkObjectHandle(2),
            client_key_handle: CkObjectHandle(3),
            server_key_handle: CkObjectHandle(4),
            client_iv: empty.clone(),
            server_iv: empty.clone(),
        };
        assert_eq!(p.server_key_handle.0, 4);

        let p = WtlsKeyMatParams {
            digest_mechanism: CkMechanismType(0),
            mac_size_bits: 0,
            key_size_bits: 0,
            iv_size_bits: 0,
            sequence_number: 0,
            is_export: false,
            random_info: WtlsRandomData { client_random: vec![], server_random: vec![] },
            mac_secret_handle: CkObjectHandle(5),
            key_handle: CkObjectHandle(6),
            iv: vec![],
        };
        assert_eq!((p.mac_secret_handle.0, p.key_handle.0), (5, 6));

        let p = IkePrfDeriveParams {
            prf_mechanism: CkMechanismType(0),
            data_as_key: false,
            rekey: false,
            ni: empty.clone(),
            nr: empty.clone(),
            new_key_handle: CkObjectHandle(10),
        };
        assert_eq!(p.new_key_handle.0, 10);

        let p = Ike1PrfDeriveParams {
            prf_mechanism: CkMechanismType(0),
            has_prev_key: false,
            keygxy_handle: CkObjectHandle(11),
            prev_key_handle: CkObjectHandle(12),
            ckyi: empty.clone(),
            ckyr: empty.clone(),
            key_number: 0,
        };
        assert_eq!((p.keygxy_handle.0, p.prev_key_handle.0), (11, 12));

        let p = Ike1ExtendedDeriveParams {
            prf_mechanism: CkMechanismType(0),
            has_keygxy: false,
            keygxy_handle: CkObjectHandle(11),
            extra_data: empty.clone(),
        };
        assert_eq!(p.keygxy_handle.0, 11);

        let p = Ike2PrfPlusDeriveParams {
            prf_mechanism: CkMechanismType(0),
            has_seed_key: false,
            seed_key_handle: CkObjectHandle(13),
            seed_data: empty.clone(),
        };
        assert_eq!(p.seed_key_handle.0, 13);

        let p = Sp800108DerivedKey { template: vec![], key_handle: CkObjectHandle(14) };
        assert_eq!(p.key_handle.0, 14);

        let p = X3dhInitiateParams {
            kdf: 1,
            peer_identity_handle: CkObjectHandle(21),
            peer_prekey_handle: CkObjectHandle(22),
            prekey_signature: vec![],
            onetime_key_handle: CkObjectHandle(23),
            own_identity_handle: CkObjectHandle(24),
            own_ephemeral_handle: CkObjectHandle(25),
        };
        assert_eq!(p.own_ephemeral_handle.0, 25);

        let p = X3dhRespondParams {
            kdf: 1,
            identity_handle: CkObjectHandle(26),
            prekey_handle: CkObjectHandle(27),
            onetime_key_handle: CkObjectHandle(28),
            initiator_identity_handle: CkObjectHandle(29),
            initiator_ephemeral_handle: CkObjectHandle(30),
        };
        assert_eq!(p.initiator_ephemeral_handle.0, 30);

        let p = X2RatchetInitializeParams {
            sk: empty.clone(),
            peer_public_prekey_handle: CkObjectHandle(31),
            peer_public_identity_handle: CkObjectHandle(32),
            own_public_identity_handle: CkObjectHandle(33),
            encrypted_header: false,
            curve: 255,
            aead_mechanism: CkMechanismType(0),
            kdf_mechanism: CkKdf(1),
        };
        assert_eq!(p.own_public_identity_handle.0, 33);

        let p = X2RatchetRespondParams {
            sk: empty.clone(),
            own_prekey_handle: CkObjectHandle(34),
            initiator_identity_handle: CkObjectHandle(35),
            own_identity_handle: CkObjectHandle(36),
            encrypted_header: false,
            curve: 255,
            aead_mechanism: CkMechanismType(0),
            kdf_mechanism: CkKdf(1),
        };
        assert_eq!(p.own_identity_handle.0, 36);

        let p = KipParams {
            mechanism: Box::new(mech()),
            key_handle: CkObjectHandle(37),
            seed: empty.clone(),
        };
        assert_eq!(p.key_handle.0, 37);

        let p = CmsSigParams {
            certificate_handle: CkObjectHandle(38),
            signing_mechanism: Box::new(mech()),
            digest_mechanism: Box::new(mech()),
            content_type: String::new(),
            requested_attributes: empty.clone(),
            required_attributes: empty.clone(),
        };
        assert_eq!(p.certificate_handle.0, 38);

        let p = ObjectHandleParam { handle: CkObjectHandle(39) };
        assert_eq!(p.handle.0, 39);

        let p = KmacParams {
            key_handle: CkObjectHandle(40),
            mac_length: 0,
            customization_string: empty.clone(),
        };
        assert_eq!(p.key_handle.0, 40);

        let p = MuGenParams {
            key_handle: CkObjectHandle(41),
            tr: empty.clone(),
            context: empty.clone(),
        };
        assert_eq!(p.key_handle.0, 41);

        let p = KyberParams {
            version: 0,
            mode: 0,
            secret_handle: CkObjectHandle(42),
            shared_data: empty.clone(),
            blob: empty.clone(),
        };
        assert_eq!(p.secret_handle.0, 42);
    }

    // W1-C9-05: all 19 mechanism-valued fields use CkMechanismType, matching
    // the hash_alg precedent. If any regresses to raw u64, this fails to compile.
    #[test]
    fn mechanism_valued_fields_use_ck_mechanism_type() {
        let empty = SecretBytes::copy_from_slice(b"");
        let sha256 = CkMechanismType::SHA256;

        let p = XeddsaParams { hash: sha256 };
        assert_eq!(p.hash.0, 0x250);

        let p = TlsMacParams { prf_hash_mechanism: sha256, mac_length: 0, server_or_client: 0 };
        assert_eq!(p.prf_hash_mechanism.0, 0x250);

        let p = HkdfParams {
            extract: true,
            expand: true,
            prf_hash_mechanism: sha256,
            salt_type: 0,
            salt: empty.clone(),
            salt_key_handle: CkObjectHandle(0),
            info: empty.clone(),
        };
        assert_eq!(p.prf_hash_mechanism.0, 0x250);

        let p = TlsKdfParams {
            prf_mechanism: sha256,
            label: empty.clone(),
            random_info: SslRandomData { client_random: vec![], server_random: vec![] },
            context_data: empty.clone(),
        };
        assert_eq!(p.prf_mechanism.0, 0x250);

        let p = Tls12MasterKeyDeriveParams {
            random_info: SslRandomData { client_random: vec![], server_random: vec![] },
            version_major: 3,
            version_minor: 3,
            prf_hash_mechanism: sha256,
        };
        assert_eq!(p.prf_hash_mechanism.0, 0x250);

        let p = Tls12ExtendedMasterKeyDeriveParams {
            prf_hash_mechanism: sha256,
            session_hash: vec![],
            version_major: 3,
            version_minor: 3,
        };
        assert_eq!(p.prf_hash_mechanism.0, 0x250);

        let p = Ssl3KeyMatParams {
            mac_size_bits: 0,
            key_size_bits: 0,
            iv_size_bits: 0,
            is_export: false,
            random_info: SslRandomData { client_random: vec![], server_random: vec![] },
            prf_hash_mechanism: sha256,
            client_mac_secret_handle: CkObjectHandle(0),
            server_mac_secret_handle: CkObjectHandle(0),
            client_key_handle: CkObjectHandle(0),
            server_key_handle: CkObjectHandle(0),
            client_iv: empty.clone(),
            server_iv: empty.clone(),
        };
        assert_eq!(p.prf_hash_mechanism.0, 0x250);

        let p = WtlsMasterKeyDeriveParams {
            digest_mechanism: sha256,
            random_info: WtlsRandomData { client_random: vec![], server_random: vec![] },
            version: 0,
        };
        assert_eq!(p.digest_mechanism.0, 0x250);

        let p = WtlsPrfParams {
            digest_mechanism: sha256,
            seed: empty.clone(),
            label: empty.clone(),
            output_len: 0,
        };
        assert_eq!(p.digest_mechanism.0, 0x250);

        let p = WtlsKeyMatParams {
            digest_mechanism: sha256,
            mac_size_bits: 0,
            key_size_bits: 0,
            iv_size_bits: 0,
            sequence_number: 0,
            is_export: false,
            random_info: WtlsRandomData { client_random: vec![], server_random: vec![] },
            mac_secret_handle: CkObjectHandle(0),
            key_handle: CkObjectHandle(0),
            iv: vec![],
        };
        assert_eq!(p.digest_mechanism.0, 0x250);

        let p = IkePrfDeriveParams {
            prf_mechanism: sha256,
            data_as_key: false,
            rekey: false,
            ni: empty.clone(),
            nr: empty.clone(),
            new_key_handle: CkObjectHandle(0),
        };
        assert_eq!(p.prf_mechanism.0, 0x250);

        let p = Ike1PrfDeriveParams {
            prf_mechanism: sha256,
            has_prev_key: false,
            keygxy_handle: CkObjectHandle(0),
            prev_key_handle: CkObjectHandle(0),
            ckyi: empty.clone(),
            ckyr: empty.clone(),
            key_number: 0,
        };
        assert_eq!(p.prf_mechanism.0, 0x250);

        let p = Ike1ExtendedDeriveParams {
            prf_mechanism: sha256,
            has_keygxy: false,
            keygxy_handle: CkObjectHandle(0),
            extra_data: empty.clone(),
        };
        assert_eq!(p.prf_mechanism.0, 0x250);

        let p = Ike2PrfPlusDeriveParams {
            prf_mechanism: sha256,
            has_seed_key: false,
            seed_key_handle: CkObjectHandle(0),
            seed_data: empty.clone(),
        };
        assert_eq!(p.prf_mechanism.0, 0x250);

        let p = X2RatchetInitializeParams {
            sk: empty.clone(),
            peer_public_prekey_handle: CkObjectHandle(0),
            peer_public_identity_handle: CkObjectHandle(0),
            own_public_identity_handle: CkObjectHandle(0),
            encrypted_header: false,
            curve: 255,
            aead_mechanism: CkMechanismType::AES_GCM,
            kdf_mechanism: CkKdf(1),
        };
        assert_eq!(p.aead_mechanism.0, 0x1087);

        let p = X2RatchetRespondParams {
            sk: empty.clone(),
            own_prekey_handle: CkObjectHandle(0),
            initiator_identity_handle: CkObjectHandle(0),
            own_identity_handle: CkObjectHandle(0),
            encrypted_header: false,
            curve: 255,
            aead_mechanism: CkMechanismType::AES_GCM,
            kdf_mechanism: CkKdf(1),
        };
        assert_eq!(p.aead_mechanism.0, 0x1087);

        let p = SignAdditionalContext { hedge_variant: 0, context: empty.clone(), hash: sha256 };
        assert_eq!(p.hash.0, 0x250);

        let p = Sp800108KdfParams {
            prf_type: sha256,
            data_params: vec![],
            additional_derived_keys: vec![],
        };
        assert_eq!(p.prf_type.0, 0x250);

        let p = Sp800108FeedbackKdfParams {
            prf_type: sha256,
            data_params: vec![],
            iv: vec![],
            additional_derived_keys: vec![],
        };
        assert_eq!(p.prf_type.0, 0x250);
    }

    // W1-C9-10: named tables for the CKG/CKD/CKZ/CKP/salt-source enums
    // (OASIS PKCS#11 v3.2, verified against cryptoki-sys 0.5.0).
    #[test]
    fn generator_and_kdf_tables_match_headers() {
        assert_eq!(CkMgf::MGF1_SHA1.0, 1);
        assert_eq!(CkMgf::MGF1_SHA256.0, 2);
        assert_eq!(CkMgf::MGF1_SHA384.0, 3);
        assert_eq!(CkMgf::MGF1_SHA512.0, 4);
        assert_eq!(CkMgf::MGF1_SHA224.0, 5);
        assert_eq!(CkMgf::MGF1_SHA3_224.0, 6);
        assert_eq!(CkMgf::MGF1_SHA3_256.0, 7);
        assert_eq!(CkMgf::MGF1_SHA3_384.0, 8);
        assert_eq!(CkMgf::MGF1_SHA3_512.0, 9);

        assert_eq!(CkGeneratorFunction::NO_GENERATE.0, 0);
        assert_eq!(CkGeneratorFunction::GENERATE.0, 1);
        assert_eq!(CkGeneratorFunction::GENERATE_COUNTER.0, 2);
        assert_eq!(CkGeneratorFunction::GENERATE_RANDOM.0, 3);
        assert_eq!(CkGeneratorFunction::GENERATE_COUNTER_XOR.0, 4);

        assert_eq!(CkKdf::NULL.0, 1);
        assert_eq!(CkKdf::SHA1_KDF.0, 2);
        assert_eq!(CkKdf::SHA1_KDF_ASN1.0, 3);
        assert_eq!(CkKdf::SHA1_KDF_CONCATENATE.0, 4);
        assert_eq!(CkKdf::SHA224_KDF.0, 5);
        assert_eq!(CkKdf::SHA256_KDF.0, 6);
        assert_eq!(CkKdf::SHA384_KDF.0, 7);
        assert_eq!(CkKdf::SHA512_KDF.0, 8);
        assert_eq!(CkKdf::CPDIVERSIFY_KDF.0, 9);
        assert_eq!(CkKdf::SHA3_224_KDF.0, 10);
        assert_eq!(CkKdf::SHA3_256_KDF.0, 11);
        assert_eq!(CkKdf::SHA3_384_KDF.0, 12);
        assert_eq!(CkKdf::SHA3_512_KDF.0, 13);
        assert_eq!(CkKdf::SHA1_KDF_SP800.0, 14);
        assert_eq!(CkKdf::SHA224_KDF_SP800.0, 15);
        assert_eq!(CkKdf::SHA256_KDF_SP800.0, 16);
        assert_eq!(CkKdf::SHA384_KDF_SP800.0, 17);
        assert_eq!(CkKdf::SHA512_KDF_SP800.0, 18);
        assert_eq!(CkKdf::SHA3_224_KDF_SP800.0, 19);
        assert_eq!(CkKdf::SHA3_256_KDF_SP800.0, 20);
        assert_eq!(CkKdf::SHA3_384_KDF_SP800.0, 21);
        assert_eq!(CkKdf::SHA3_512_KDF_SP800.0, 22);
        assert_eq!(CkKdf::BLAKE2B_160_KDF.0, 23);
        assert_eq!(CkKdf::BLAKE2B_256_KDF.0, 24);
        assert_eq!(CkKdf::BLAKE2B_384_KDF.0, 25);
        assert_eq!(CkKdf::BLAKE2B_512_KDF.0, 26);

        assert_eq!(CkOaepSource::DATA_SPECIFIED.0, 1);
        assert_eq!(CkPbkdf2SaltSource::SALT_SPECIFIED.0, 1);

        assert_eq!(CkPbkdf2Prf::HMAC_SHA1.0, 1);
        assert_eq!(CkPbkdf2Prf::HMAC_GOSTR3411.0, 2);
        assert_eq!(CkPbkdf2Prf::HMAC_SHA224.0, 3);
        assert_eq!(CkPbkdf2Prf::HMAC_SHA256.0, 4);
        assert_eq!(CkPbkdf2Prf::HMAC_SHA384.0, 5);
        assert_eq!(CkPbkdf2Prf::HMAC_SHA512.0, 6);
        assert_eq!(CkPbkdf2Prf::HMAC_SHA512_224.0, 7);
        assert_eq!(CkPbkdf2Prf::HMAC_SHA512_256.0, 8);
    }

    // W1-C9-10: mgf/kdf/source/salt-source/prf/iv-generator fields use the
    // enum newtypes. If any regresses to raw u64, this fails to compile.
    #[test]
    fn raw_enum_fields_use_newtypes() {
        let empty = SecretBytes::copy_from_slice(b"");

        let p = RsaPkcsPssParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: CkMgf::MGF1_SHA256,
            salt_len: 0,
        };
        assert_eq!(p.mgf.0, 2);

        let p = RsaPkcsOaepParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: CkMgf::MGF1_SHA1,
            source: CkOaepSource::DATA_SPECIFIED,
            source_data: empty.clone(),
            source_null: false,
        };
        assert_eq!((p.mgf.0, p.source.0), (1, 1));

        let p = GcmWrapParams {
            iv: vec![],
            iv_fixed_bits: 0,
            iv_generator: CkGeneratorFunction::GENERATE_RANDOM,
            aad: empty.clone(),
            tag_bits: 0,
        };
        assert_eq!(p.iv_generator.0, 3);

        let p = CcmWrapParams {
            data_len: 0,
            nonce: vec![],
            nonce_fixed_bits: 0,
            nonce_generator: CkGeneratorFunction::NO_GENERATE,
            aad: empty.clone(),
            mac_len: 0,
        };
        assert_eq!(p.nonce_generator.0, 0);

        let p = Ecdh1DeriveParams {
            kdf: CkKdf::SHA256_KDF,
            shared_data: empty.clone(),
            public_data: vec![],
        };
        assert_eq!(p.kdf.0, 6);

        let p = Pkcs5Pbkd2Params {
            salt_source: CkPbkdf2SaltSource::SALT_SPECIFIED,
            salt_source_data: empty.clone(),
            iterations: 0,
            prf: CkPbkdf2Prf::HMAC_SHA256,
            prf_data: empty.clone(),
            password: empty.clone(),
        };
        assert_eq!((p.salt_source.0, p.prf.0), (1, 4));

        let p = X2RatchetInitializeParams {
            sk: empty.clone(),
            peer_public_prekey_handle: CkObjectHandle(0),
            peer_public_identity_handle: CkObjectHandle(0),
            own_public_identity_handle: CkObjectHandle(0),
            encrypted_header: false,
            curve: 255,
            aead_mechanism: CkMechanismType::AES_GCM,
            kdf_mechanism: CkKdf::BLAKE2B_512_KDF,
        };
        assert_eq!(p.kdf_mechanism.0, 26);
    }

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
        assert_eq!(CkMechanismType::DES_CBC.0, 0x0000_0122);
        assert_eq!(CkMechanismType::DES_MAC.0, 0x0000_0123);
        assert_eq!(CkMechanismType::DES_MAC_GENERAL.0, 0x0000_0124);
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
        assert_eq!(CkMechanismType::SHA_1.0, 0x0000_0220);
        assert_eq!(CkMechanismType::SHA_1_HMAC.0, 0x0000_0221);
        assert_eq!(CkMechanismType::SHA_1_HMAC_GENERAL.0, 0x0000_0222);
    }

    #[test]
    fn standard_rivest_rc2_rc4_constants_match_spec() {
        assert_eq!(CkMechanismType::RC2_KEY_GEN.0, 0x0000_0100);
        assert_eq!(CkMechanismType::RC2_ECB.0, 0x0000_0101);
        assert_eq!(CkMechanismType::RC2_CBC.0, 0x0000_0102);
        assert_eq!(CkMechanismType::RC2_MAC.0, 0x0000_0103);
        assert_eq!(CkMechanismType::RC2_MAC_GENERAL.0, 0x0000_0104);
        assert_eq!(CkMechanismType::RC2_CBC_PAD.0, 0x0000_0105);
        assert_eq!(CkMechanismType::RC4_KEY_GEN.0, 0x0000_0110);
        assert_eq!(CkMechanismType::RC4.0, 0x0000_0111);
    }

    #[test]
    fn standard_sp800_108_kdf_constants_match_spec() {
        assert_eq!(CkMechanismType::SP800_108_COUNTER_KDF.0, 0x0000_03AC);
        assert_eq!(CkMechanismType::SP800_108_FEEDBACK_KDF.0, 0x0000_03AD);
        assert_eq!(CkMechanismType::SP800_108_DOUBLE_PIPELINE_KDF.0, 0x0000_03AE);
    }

    #[test]
    fn standard_blake2b_constants_match_spec() {
        assert_eq!(CkMechanismType::BLAKE2B_160.0, 0x0000_400C);
        assert_eq!(CkMechanismType::BLAKE2B_160_HMAC.0, 0x0000_400D);
        assert_eq!(CkMechanismType::BLAKE2B_160_HMAC_GENERAL.0, 0x0000_400E);
        assert_eq!(CkMechanismType::BLAKE2B_160_KEY_DERIVE.0, 0x0000_400F);
        assert_eq!(CkMechanismType::BLAKE2B_160_KEY_GEN.0, 0x0000_4010);
        assert_eq!(CkMechanismType::BLAKE2B_256.0, 0x0000_4011);
        assert_eq!(CkMechanismType::BLAKE2B_256_HMAC.0, 0x0000_4012);
        assert_eq!(CkMechanismType::BLAKE2B_256_HMAC_GENERAL.0, 0x0000_4013);
        assert_eq!(CkMechanismType::BLAKE2B_256_KEY_DERIVE.0, 0x0000_4014);
        assert_eq!(CkMechanismType::BLAKE2B_256_KEY_GEN.0, 0x0000_4015);
        assert_eq!(CkMechanismType::BLAKE2B_384.0, 0x0000_4016);
        assert_eq!(CkMechanismType::BLAKE2B_384_HMAC.0, 0x0000_4017);
        assert_eq!(CkMechanismType::BLAKE2B_384_HMAC_GENERAL.0, 0x0000_4018);
        assert_eq!(CkMechanismType::BLAKE2B_384_KEY_DERIVE.0, 0x0000_4019);
        assert_eq!(CkMechanismType::BLAKE2B_384_KEY_GEN.0, 0x0000_401A);
        assert_eq!(CkMechanismType::BLAKE2B_512.0, 0x0000_401B);
        assert_eq!(CkMechanismType::BLAKE2B_512_HMAC.0, 0x0000_401C);
        assert_eq!(CkMechanismType::BLAKE2B_512_HMAC_GENERAL.0, 0x0000_401D);
        assert_eq!(CkMechanismType::BLAKE2B_512_KEY_DERIVE.0, 0x0000_401E);
        assert_eq!(CkMechanismType::BLAKE2B_512_KEY_GEN.0, 0x0000_401F);
    }

    #[test]
    fn standard_pqc_mlkem_mldsa_slhdsa_constants_match_spec() {
        assert_eq!(CkMechanismType::ML_KEM_KEY_PAIR_GEN.0, 0x0000_000F);
        assert_eq!(CkMechanismType::ML_KEM.0, 0x0000_0017);
        assert_eq!(CkMechanismType::ML_DSA_KEY_PAIR_GEN.0, 0x0000_001C);
        assert_eq!(CkMechanismType::ML_DSA.0, 0x0000_001D);
        assert_eq!(CkMechanismType::HASH_ML_DSA.0, 0x0000_001F);
        assert_eq!(CkMechanismType::HASH_ML_DSA_SHA224.0, 0x0000_0023);
        assert_eq!(CkMechanismType::HASH_ML_DSA_SHA256.0, 0x0000_0024);
        assert_eq!(CkMechanismType::HASH_ML_DSA_SHA384.0, 0x0000_0025);
        assert_eq!(CkMechanismType::HASH_ML_DSA_SHA512.0, 0x0000_0026);
        assert_eq!(CkMechanismType::HASH_ML_DSA_SHA3_224.0, 0x0000_0027);
        assert_eq!(CkMechanismType::HASH_ML_DSA_SHA3_256.0, 0x0000_0028);
        assert_eq!(CkMechanismType::HASH_ML_DSA_SHA3_384.0, 0x0000_0029);
        assert_eq!(CkMechanismType::HASH_ML_DSA_SHA3_512.0, 0x0000_002A);
        assert_eq!(CkMechanismType::HASH_ML_DSA_SHAKE128.0, 0x0000_002B);
        assert_eq!(CkMechanismType::HASH_ML_DSA_SHAKE256.0, 0x0000_002C);
        assert_eq!(CkMechanismType::SLH_DSA_KEY_PAIR_GEN.0, 0x0000_002D);
        assert_eq!(CkMechanismType::SLH_DSA.0, 0x0000_002E);
        assert_eq!(CkMechanismType::HASH_SLH_DSA.0, 0x0000_0034);
        assert_eq!(CkMechanismType::HASH_SLH_DSA_SHA224.0, 0x0000_0036);
        assert_eq!(CkMechanismType::HASH_SLH_DSA_SHA256.0, 0x0000_0037);
        assert_eq!(CkMechanismType::HASH_SLH_DSA_SHA384.0, 0x0000_0038);
        assert_eq!(CkMechanismType::HASH_SLH_DSA_SHA512.0, 0x0000_0039);
        assert_eq!(CkMechanismType::HASH_SLH_DSA_SHA3_224.0, 0x0000_003A);
        assert_eq!(CkMechanismType::HASH_SLH_DSA_SHA3_256.0, 0x0000_003B);
        assert_eq!(CkMechanismType::HASH_SLH_DSA_SHA3_384.0, 0x0000_003C);
        assert_eq!(CkMechanismType::HASH_SLH_DSA_SHA3_512.0, 0x0000_003D);
        assert_eq!(CkMechanismType::HASH_SLH_DSA_SHAKE128.0, 0x0000_003E);
        assert_eq!(CkMechanismType::HASH_SLH_DSA_SHAKE256.0, 0x0000_003F);
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

    // ------------------------------------------------------------------
    // Zeroize / ZeroizeOnDrop on password-bearing structs
    // ------------------------------------------------------------------

    #[test]
    fn pbe_params_zeroizes_password_on_explicit_call() {
        use zeroize::Zeroize;
        let mut p = PbeParams {
            init_vector: vec![1u8; 16].into(),
            password: vec![0xAAu8; 32].into(),
            salt: vec![2u8; 16].into(),
            iteration: 4096,
        };
        p.zeroize();
        // After Zeroize::zeroize() Vec<u8> fields are cleared/truncated.
        assert!(p.password.expose(|b| b.iter().all(|&x| x == 0)), "password bytes not zeroed");
        assert!(p.init_vector.expose(|b| b.iter().all(|&x| x == 0)), "iv bytes not zeroed");
    }

    #[test]
    fn pkcs5_pbkd2_params_zeroizes_password() {
        use zeroize::Zeroize;
        let mut p = Pkcs5Pbkd2Params {
            salt_source: CkPbkdf2SaltSource::SALT_SPECIFIED,
            salt_source_data: vec![1u8; 8].into(),
            iterations: 10_000,
            prf: CkPbkdf2Prf(0x40),
            prf_data: vec![2u8; 4].into(),
            password: b"hunter2".to_vec().into(),
        };
        p.zeroize();
        assert!(p.password.expose(|b| b.iter().all(|&x| x == 0)));
    }

    #[test]
    fn skipjack_params_zeroize_passwords() {
        use zeroize::Zeroize;
        let mut a = SkipjackPrivateWrapParams {
            password: b"old-secret".to_vec().into(),
            public_data: vec![],
            password_length: 10,
            random_a: vec![],
            prime_p: vec![],
            base_g: vec![],
            subprime_q: vec![],
        };
        a.zeroize();
        assert!(a.password.expose(|b| b.iter().all(|&x| x == 0)));

        let mut b = SkipjackRelayxParams {
            old_wrapped_x: vec![].into(),
            old_password: b"old-pin".to_vec().into(),
            old_public_data: vec![].into(),
            old_random_a: vec![].into(),
            new_password: b"new-pin".to_vec().into(),
            new_public_data: vec![].into(),
            new_random_a: vec![].into(),
        };
        b.zeroize();
        assert!(b.old_password.expose(|b| b.iter().all(|&x| x == 0)));
        assert!(b.new_password.expose(|b| b.iter().all(|&x| x == 0)));
    }

    // Witness whose Zeroize impl records that it ran, so ZeroizeOnDrop's
    // generated Drop can be observed WITHOUT reading freed memory (the old
    // pbe_params_drop_runs_zeroize_on_drop test was a use-after-free).
    use zeroize::{Zeroize, ZeroizeOnDrop};
    struct ZeroizeWitness(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Zeroize for ZeroizeWitness {
        fn zeroize(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    #[derive(Zeroize, ZeroizeOnDrop)]
    struct ZeroizeHolder {
        secret: ZeroizeWitness,
    }

    #[test]
    fn zeroize_on_drop_invokes_zeroize_without_uaf() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let flag = Arc::new(AtomicBool::new(false));
        {
            let _holder = ZeroizeHolder { secret: ZeroizeWitness(flag.clone()) };
            // _holder drops here; ZeroizeOnDrop's Drop must call zeroize().
        }
        assert!(flag.load(Ordering::SeqCst), "ZeroizeOnDrop must call zeroize() on drop");
    }

    #[test]
    fn zeroize_on_drop_runs_during_panic_unwind() {
        // AGENTS.md §4: secret structs rely on ZeroizeOnDrop running during
        // stack UNWINDING — which is why the release profile must stay
        // panic="unwind". This would fail under panic="abort".
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let flag = Arc::new(AtomicBool::new(false));
        let flag_for_panic = flag.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _holder = ZeroizeHolder { secret: ZeroizeWitness(flag_for_panic) };
            panic!("boom");
        }));
        assert!(
            flag.load(Ordering::SeqCst),
            "ZeroizeOnDrop must run during stack unwinding (panic=unwind invariant)"
        );
    }

    #[test]
    fn pbe_params_debug_redacts_password() {
        let p = PbeParams {
            init_vector: vec![1u8; 16].into(),
            password: b"hunter2".to_vec().into(),
            salt: vec![2u8; 16].into(),
            iteration: 4096,
        };
        let formatted = format!("{p:?}");
        assert!(!formatted.contains("hunter2"), "password leaked into Debug output: {formatted}");
        assert!(formatted.contains("REDACTED"));
        assert!(formatted.contains("7 bytes"));
    }

    #[test]
    fn pkcs5_pbkd2_debug_redacts_password() {
        let p = Pkcs5Pbkd2Params {
            salt_source: CkPbkdf2SaltSource::SALT_SPECIFIED,
            salt_source_data: vec![].into(),
            iterations: 1,
            prf: CkPbkdf2Prf(0),
            prf_data: vec![].into(),
            password: b"correct horse battery staple".to_vec().into(),
        };
        let formatted = format!("{p:?}");
        assert!(!formatted.contains("correct horse"), "password leaked: {formatted}");
        assert!(formatted.contains("REDACTED"));
    }

    #[test]
    fn skipjack_debug_redacts_passwords() {
        let a = SkipjackPrivateWrapParams {
            password: b"alpha-pw".to_vec().into(),
            public_data: vec![],
            password_length: 8,
            random_a: vec![],
            prime_p: vec![],
            base_g: vec![],
            subprime_q: vec![],
        };
        let af = format!("{a:?}");
        assert!(!af.contains("alpha-pw"));
        assert!(af.contains("REDACTED"));

        let b = SkipjackRelayxParams {
            old_wrapped_x: vec![].into(),
            old_password: b"old-pw".to_vec().into(),
            old_public_data: vec![].into(),
            old_random_a: vec![].into(),
            new_password: b"new-pw".to_vec().into(),
            new_public_data: vec![].into(),
            new_random_a: vec![].into(),
        };
        let bf = format!("{b:?}");
        assert!(!bf.contains("old-pw"));
        assert!(!bf.contains("new-pw"));
    }
}

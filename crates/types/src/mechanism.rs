use crate::attribute::CkAttribute;
use crate::error::CkRv;
use crate::mechanism_registry::MechanismRegistry;
use crate::object::CkObjectHandle;
use crate::secret::SecretBytes;
use crate::shape_descriptors::{
    FlatDecision, FlatGrant, Operation, OuterKind, ParamAbi, decide_flat_for_registry,
};

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
    pub const HW: Self = Self(0x00000001);
    pub const MESSAGE_ENCRYPT: Self = Self(0x00000002);
    pub const MESSAGE_DECRYPT: Self = Self(0x00000004);
    pub const MESSAGE_SIGN: Self = Self(0x00000008);
    pub const MESSAGE_VERIFY: Self = Self(0x00000010);
    pub const MULTI_MESSAGE: Self = Self(0x00000020);
    pub const MULTI_MESSGE: Self = Self::MULTI_MESSAGE;
    pub const FIND_OBJECTS: Self = Self(0x00000040);
    pub const ENCRYPT: Self = Self(0x00000100);
    pub const DECRYPT: Self = Self(0x00000200);
    pub const DIGEST: Self = Self(0x00000400);
    pub const SIGN: Self = Self(0x00000800);
    pub const SIGN_RECOVER: Self = Self(0x00001000);
    pub const VERIFY: Self = Self(0x00002000);
    pub const VERIFY_RECOVER: Self = Self(0x00004000);
    pub const GENERATE: Self = Self(0x00008000);
    pub const GENERATE_KEY_PAIR: Self = Self(0x00010000);
    pub const WRAP: Self = Self(0x00020000);
    pub const UNWRAP: Self = Self(0x00040000);
    pub const DERIVE: Self = Self(0x00080000);
    pub const EC_F_P: Self = Self(0x00100000);
    pub const EC_F_2M: Self = Self(0x00200000);
    pub const EC_ECPARAMETERS: Self = Self(0x00400000);
    pub const EC_OID: Self = Self(0x00800000);
    pub const EC_NAMEDCURVE: Self = Self::EC_OID;
    pub const EC_UNCOMPRESS: Self = Self(0x01000000);
    pub const EC_COMPRESS: Self = Self(0x02000000);
    pub const EC_CURVENAME: Self = Self(0x04000000);
    pub const ENCAPSULATE: Self = Self(0x10000000);
    pub const DECAPSULATE: Self = Self(0x20000000);
    pub const EXTENSION: Self = Self(0x80000000);
}

impl std::ops::BitOr for CkMechanismFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CkMechanismFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
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
    // Non-contradictory NULL/length pointer (S2 §3).
    pub source_data_presence: PointerBytes,
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
    pub iv_bits: u64,
    pub iv_buffer_len: u64,
    pub tag_bits: u64,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub iv_presence: PointerBytes,
    pub aad_presence: PointerBytes,
}

/// CK_ECDH1_DERIVE_PARAMS — parameters for CKM_ECDH1_DERIVE.
///
/// - `kdf`: key derivation function type (CKD_NULL = 1, CKD_SHA1_KDF = 2, etc.)
/// - `shared_data`: optional shared data input to the KDF (may be empty)
/// - `public_data`: other party's EC public key (uncompressed EC point)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ecdh1DeriveParams {
    pub kdf: CkKdf,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub shared_data_presence: PointerBytes,
    pub public_data_presence: PointerBytes,
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
    // Non-contradictory NULL/length pointer (S2 §3).
    pub iv_presence: PointerBytes,
}

// --- CBC encrypt data (IV + data pointer) ---

/// CK_AES_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesCbcEncryptDataParams {
    pub iv: Vec<u8>, // 16-byte IV
    // Non-contradictory NULL/length pointer (S2 §3). The IV is a fixed inline array, never a
    // pointer, so it carries no presence.
    pub data_presence: PointerBytes,
}

/// CK_DES_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesCbcEncryptDataParams {
    pub iv: Vec<u8>, // 8-byte IV
    // Non-contradictory NULL/length pointer (S2 §3). The IV is a fixed inline array, never a
    // pointer, so it carries no presence.
    pub data_presence: PointerBytes,
}

/// CK_ARIA_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AriaCbcEncryptDataParams {
    pub iv: Vec<u8>, // 16-byte IV
    // Non-contradictory NULL/length pointer (S2 §3). The IV is a fixed inline array, never a
    // pointer, so it carries no presence.
    pub data_presence: PointerBytes,
}

/// CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CamelliaCbcEncryptDataParams {
    pub iv: Vec<u8>, // 16-byte IV
    // Non-contradictory NULL/length pointer (S2 §3). The IV is a fixed inline array, never a
    // pointer, so it carries no presence.
    pub data_presence: PointerBytes,
}

/// CK_SEED_CBC_ENCRYPT_DATA_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedCbcEncryptDataParams {
    pub iv: Vec<u8>, // 16-byte IV
    // Non-contradictory NULL/length pointer (S2 §3). The IV is a fixed inline array, never a
    // pointer, so it carries no presence.
    pub data_presence: PointerBytes,
}

// --- AEAD parameter structs ---

/// CK_CCM_PARAMS / CK_AES_CCM_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcmParams {
    pub data_len: u64,
    pub mac_len: u64,
    /// True when the caller passed `(NULL, 0)` for `pNonce` / `pAAD`.
    /// Distinguishes it from `(ptr, 0)`, which some backends reject.
    // Non-contradictory NULL/length pointers (S2 §3).
    pub nonce_presence: PointerBytes,
    pub aad_presence: PointerBytes,
}

/// CK_CHACHA20_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChaCha20Params {
    pub block_counter_bits: u64,
    pub nonce_bits: u64,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub block_counter_presence: PointerBytes,
    pub nonce_presence: PointerBytes,
}

/// CK_SALSA20_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Salsa20Params {
    pub nonce_bits: u64,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub block_counter_presence: PointerBytes,
    pub nonce_presence: PointerBytes,
}

/// CK_SALSA20_CHACHA20_POLY1305_PARAMS (non-message variant)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Salsa20ChaCha20Poly1305Params {
    // Non-contradictory NULL/length pointers (S2 §3).
    pub nonce_presence: PointerBytes,
    pub aad_presence: PointerBytes,
}

/// CK_GCM_WRAP_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcmWrapParams {
    pub iv_fixed_bits: u64,
    pub iv_generator: CkGeneratorFunction,
    pub tag_bits: u64,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub iv_presence: PointerBytes,
    pub aad_presence: PointerBytes,
}

/// CK_CCM_WRAP_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcmWrapParams {
    pub data_len: u64,
    pub nonce_fixed_bits: u64,
    pub nonce_generator: CkGeneratorFunction,
    pub mac_len: u64,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub nonce_presence: PointerBytes,
    pub aad_presence: PointerBytes,
}

// ---------------------------------------------------------------------------
// Key Derivation parameter structs
// ---------------------------------------------------------------------------

/// CK_ECDH2_DERIVE_PARAMS — dual ECDH key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ecdh2DeriveParams {
    pub kdf: CkKdf,
    pub private_data_len: u64,
    pub private_data_handle: CkObjectHandle,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub shared_data_presence: PointerBytes,
    pub public_data_presence: PointerBytes,
    pub public_data2_presence: PointerBytes,
}

/// CK_ECMQV_DERIVE_PARAMS — EC-MQV key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcmqvDeriveParams {
    pub kdf: CkKdf,
    pub private_data_len: u64,
    pub private_data_handle: CkObjectHandle,
    pub public_key_handle: CkObjectHandle,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub shared_data_presence: PointerBytes,
    pub public_data_presence: PointerBytes,
    pub public_data2_presence: PointerBytes,
}

/// CK_X9_42_DH1_DERIVE_PARAMS — X9.42 DH key derivation (single).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X942Dh1DeriveParams {
    pub kdf: CkKdf,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub other_info_presence: PointerBytes,
    pub public_data_presence: PointerBytes,
}

/// CK_X9_42_DH2_DERIVE_PARAMS — X9.42 DH key derivation (dual).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X942Dh2DeriveParams {
    pub kdf: CkKdf,
    pub private_data_len: u64,
    pub private_data_handle: CkObjectHandle,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub other_info_presence: PointerBytes,
    pub public_data_presence: PointerBytes,
    pub public_data2_presence: PointerBytes,
}

/// CK_X9_42_MQV_DERIVE_PARAMS — X9.42 MQV key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X942MqvDeriveParams {
    pub kdf: CkKdf,
    pub private_data_len: u64,
    pub private_data_handle: CkObjectHandle,
    pub public_key_handle: CkObjectHandle,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub other_info_presence: PointerBytes,
    pub public_data_presence: PointerBytes,
    pub public_data2_presence: PointerBytes,
}

/// CK_HKDF_PARAMS — HKDF key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HkdfParams {
    pub extract: bool,
    pub expand: bool,
    pub prf_hash_mechanism: CkMechanismType,
    pub salt_type: u64,
    pub salt_key_handle: CkObjectHandle,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub salt_presence: PointerBytes,
    pub info_presence: PointerBytes,
}

/// CK_EDDSA_PARAMS — EdDSA signature parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EddsaParams {
    pub ph_flag: bool,
    // Non-contradictory NULL/length pointer (S2 §3).
    pub context_data_presence: PointerBytes,
}

/// CK_GOSTR3410_DERIVE_PARAMS — GOST R 34.10 key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gostr3410DeriveParams {
    pub kdf: CkKdf,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub public_data_presence: PointerBytes,
    pub ukm_presence: PointerBytes,
}

/// CK_KEA_DERIVE_PARAMS — KEA key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeaDeriveParams {
    pub is_sender: bool,
    // Non-contradictory NULL/length pointers (S2 §8 tail). RandomA/B share the one
    // C `ulRandomLen` — their effective lengths MUST agree under v1.
    pub random_a_presence: PointerBytes,
    pub random_b_presence: PointerBytes,
    pub public_data_presence: PointerBytes,
}

// ---------------------------------------------------------------------------
// Key Wrapping parameter structs
// ---------------------------------------------------------------------------

/// CK_ECDH_AES_KEY_WRAP_PARAMS — ECDH + AES key wrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdhAesKeyWrapParams {
    pub aes_key_bits: u64,
    pub kdf: CkKdf,
    // Non-contradictory NULL/length pointer (S2 §3).
    pub shared_data_presence: PointerBytes,
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
    pub key_handle: CkObjectHandle,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub wrap_oid_presence: PointerBytes,
    pub ukm_presence: PointerBytes,
}

/// CK_KEY_WRAP_SET_OAEP_PARAMS — SET OAEP key wrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapSetOaepParams {
    pub bc: u32,
    // Non-contradictory NULL/length pointer (S2 §3).
    pub x_presence: PointerBytes,
}

// ---------------------------------------------------------------------------
// Password-Based Encryption parameter structs
// ---------------------------------------------------------------------------

/// Length-only rendering of a [`PointerBytes`] member for the redacting
/// `Debug` impls below: presence arm + declared length, never bytes.
fn presence_debug(presence: &PointerBytes) -> String {
    match presence {
        PointerBytes::Present(bytes) => format!("present, {} bytes", bytes.len()),
        PointerBytes::Null { declared_len } => format!("null, len {declared_len}"),
    }
}

/// CK_PBE_PARAMS — password-based encryption.
///
/// Holds an in-memory password. `Debug` is overridden to redact the
/// password byte slice; `Zeroize` + `ZeroizeOnDrop` ensure the buffer
/// is overwritten when the value is dropped.
#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PbeParams {
    pub iteration: u64,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub init_vector_presence: PointerBytes,
    pub password_presence: PointerBytes,
    pub salt_presence: PointerBytes,
}

impl std::fmt::Debug for PbeParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructure so the compiler errors here when a field is
        // added — preventing a future contributor from adding a
        // secret-bearing field that is silently omitted from Debug.
        let Self { iteration, init_vector_presence, password_presence, salt_presence } = self;
        f.debug_struct("PbeParams")
            .field("iteration", iteration)
            .field(
                "init_vector_presence",
                &format_args!("[{}]", presence_debug(init_vector_presence)),
            )
            .field(
                "password_presence",
                &format_args!("[REDACTED; {}]", presence_debug(password_presence)),
            )
            .field("salt_presence", &format_args!("[{}]", presence_debug(salt_presence)))
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
    pub iterations: u64,
    pub prf: CkPbkdf2Prf,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub salt_source_data_presence: PointerBytes,
    pub prf_data_presence: PointerBytes,
    pub password_presence: PointerBytes,
}

impl std::fmt::Debug for Pkcs5Pbkd2Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructure to gate against silently-omitted future fields.
        let Self {
            salt_source,
            iterations,
            prf,
            salt_source_data_presence,
            prf_data_presence,
            password_presence,
        } = self;
        f.debug_struct("Pkcs5Pbkd2Params")
            .field("salt_source", salt_source)
            .field("iterations", iterations)
            .field("prf", prf)
            .field(
                "salt_source_data_presence",
                &format_args!("[{}]", presence_debug(salt_source_data_presence)),
            )
            .field("prf_data_presence", &format_args!("[{}]", presence_debug(prf_data_presence)))
            .field(
                "password_presence",
                &format_args!("[REDACTED; {}]", presence_debug(password_presence)),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// TLS/SSL parameter structs
// ---------------------------------------------------------------------------

/// Shared sub-struct for TLS/SSL random data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslRandomData {
    // Non-contradictory NULL/length pointers (S2 §8 tail).
    pub client_random_presence: PointerBytes,
    pub server_random_presence: PointerBytes,
}

/// CK_TLS_PRF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPrfParams {
    pub output_len: u64,
    /// Provider-written PRF output (W1-C5-01). Empty on the request
    /// path — the shim sizes the daemon buffer from `output_len` —
    /// and populated from `pOutput`/`*pulOutputLen` on the
    /// mechanism-out path so the shim can write it back into the
    /// caller's buffer.
    pub output: SecretBytes,
    // R18 typed presence (S2 §8 tail): non-contradictory NULL/length
    // peers of the C `pSeed`/`pLabel` pointers.
    pub seed_presence: PointerBytes,
    pub label_presence: PointerBytes,
    /// R18 output envelope (S2 §8 tail): whether the caller's `pOutput`
    /// was NULL (its length rides `output_len`; a NULL output forces
    /// `output` empty).
    pub output_is_null: bool,
    /// R18 output envelope (S2 §8 tail): whether the caller's
    /// `pulOutputLen` was NULL (forces `output_len` zero).
    pub output_len_is_null: bool,
}

/// CK_TLS_KDF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsKdfParams {
    pub prf_mechanism: CkMechanismType,
    pub random_info: SslRandomData,
    // Non-contradictory NULL/length pointers (S2 §8 tail).
    pub label_presence: PointerBytes,
    pub context_data_presence: PointerBytes,
}

/// CK_SSL3_MASTER_KEY_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssl3MasterKeyDeriveParams {
    pub random_info: SslRandomData,
    pub version_major: u32,
    pub version_minor: u32,
    /// R18 output envelope (S2 §8 tail): whether the caller's `pVersion`
    /// was NULL (forces `version_major`/`version_minor` zero).
    pub version_is_null: bool,
}

/// CK_TLS12_MASTER_KEY_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls12MasterKeyDeriveParams {
    pub random_info: SslRandomData,
    pub version_major: u32,
    pub version_minor: u32,
    pub prf_hash_mechanism: CkMechanismType,
    /// R18 output envelope (S2 §8 tail): whether the caller's `pVersion`
    /// was NULL (forces `version_major`/`version_minor` zero).
    pub version_is_null: bool,
}

/// CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls12ExtendedMasterKeyDeriveParams {
    pub prf_hash_mechanism: CkMechanismType,
    pub version_major: u32,
    pub version_minor: u32,
    // Non-contradictory NULL/length pointer (S2 §8 tail).
    pub session_hash_presence: PointerBytes,
    /// R18 output envelope (S2 §8 tail): whether the caller's `pVersion`
    /// was NULL (forces `version_major`/`version_minor` zero).
    pub version_is_null: bool,
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
    // Non-contradictory NULL/length pointers (S2 §8 tail).
    pub client_iv_presence: PointerBytes,
    pub server_iv_presence: PointerBytes,
    /// R18 output envelope (S2 §8 tail): whether the caller's
    /// `pReturnedKeyMaterial` was NULL (forces every handle zero and
    /// both IVs empty).
    pub returned_key_material_is_null: bool,
}

/// CK_WTLS_RANDOM_DATA
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtlsRandomData {
    // Non-contradictory NULL/length pointers (S2 §8 tail).
    pub client_random_presence: PointerBytes,
    pub server_random_presence: PointerBytes,
}

/// CK_WTLS_MASTER_KEY_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtlsMasterKeyDeriveParams {
    pub digest_mechanism: CkMechanismType,
    pub random_info: WtlsRandomData,
    pub version: u32,
    /// R18 output envelope (S2 §8 tail): whether the caller's `pVersion`
    /// was NULL (forces `version` zero).
    pub version_is_null: bool,
}

/// CK_WTLS_PRF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtlsPrfParams {
    pub digest_mechanism: CkMechanismType,
    pub output_len: u64,
    /// Provider-written PRF output (W1-C5-01). Empty on the request
    /// path; populated from `pOutput`/`*pulOutputLen` on the
    /// mechanism-out path for shim writeback.
    pub output: SecretBytes,
    // R18 typed presence (S2 §8 tail): non-contradictory NULL/length
    // peers of the C `pSeed`/`pLabel` pointers.
    pub seed_presence: PointerBytes,
    pub label_presence: PointerBytes,
    /// R18 output envelope (S2 §8 tail): whether the caller's `pOutput`
    /// was NULL (its length rides `output_len`; a NULL output forces
    /// `output` empty).
    pub output_is_null: bool,
    /// R18 output envelope (S2 §8 tail): whether the caller's
    /// `pulOutputLen` was NULL (forces `output_len` zero).
    pub output_len_is_null: bool,
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
    // Non-contradictory NULL/length pointer (S2 §8 tail).
    pub iv_presence: PointerBytes,
    /// R18 output envelope (S2 §8 tail): whether the caller's
    /// `pReturnedKeyMaterial` was NULL (forces both handles zero and
    /// `iv` empty).
    pub returned_key_material_is_null: bool,
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
    pub new_key_handle: CkObjectHandle,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub ni_presence: PointerBytes,
    pub nr_presence: PointerBytes,
}

/// CK_IKE1_PRF_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ike1PrfDeriveParams {
    pub prf_mechanism: CkMechanismType,
    pub has_prev_key: bool,
    pub keygxy_handle: CkObjectHandle,
    pub prev_key_handle: CkObjectHandle,
    pub key_number: u32,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub ckyi_presence: PointerBytes,
    pub ckyr_presence: PointerBytes,
}

/// CK_IKE1_EXTENDED_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ike1ExtendedDeriveParams {
    pub prf_mechanism: CkMechanismType,
    pub has_keygxy: bool,
    pub keygxy_handle: CkObjectHandle,
    // Non-contradictory NULL/length pointer (S2 §3).
    pub extra_data_presence: PointerBytes,
}

/// CK_IKE2_PRF_PLUS_DERIVE_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ike2PrfPlusDeriveParams {
    pub prf_mechanism: CkMechanismType,
    pub has_seed_key: bool,
    pub seed_key_handle: CkObjectHandle,
    // Non-contradictory NULL/length pointer (S2 §3).
    pub seed_data_presence: PointerBytes,
}

// ---------------------------------------------------------------------------
// SP800-108 KDF parameter structs
// ---------------------------------------------------------------------------

/// CK_PRF_DATA_PARAM (used inside SP800-108 params)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfDataParam {
    pub type_: u64,
    // Non-contradictory NULL/length pointer (S2 §8 tail).
    pub value_presence: PointerBytes,
}

/// CK_SP800_108_KDF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp800108KdfParams {
    pub prf_type: CkMechanismType,
    // Non-contradictory NULL/count array pointer (S2 §8 tail).
    pub data_params_presence: PointerArray<PrfDataParam>,
    pub additional_derived_keys_presence: PointerArray<Sp800108DerivedKey>,
}

/// CK_SP800_108_FEEDBACK_KDF_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp800108FeedbackKdfParams {
    pub prf_type: CkMechanismType,
    // Non-contradictory NULL/count array pointer (S2 §8 tail).
    pub data_params_presence: PointerArray<PrfDataParam>,
    pub iv_presence: PointerBytes,
    pub additional_derived_keys_presence: PointerArray<Sp800108DerivedKey>,
}

/// CK_DERIVED_KEY entry nested inside SP800-108 KDF params.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp800108DerivedKey {
    pub key_handle: CkObjectHandle,
    // Non-contradictory NULL/count template pointer (S2 §8 tail): a
    // NULL `pTemplate` rides `Null{n}` — this closes the ADR-0010
    // Scope-2 class-4 SP800-108 embedded-template null-conflation
    // residual.
    pub template_presence: PointerArray<CkAttribute>,
    /// R18 output envelope (S2 §8 tail): whether the caller's `phKey`
    /// was NULL (forces `key_handle` zero).
    pub ph_key_is_null: bool,
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
    // Non-contradictory NULL/length pointer (S2 §8 tail).
    pub value_presence: PointerBytes,
}

/// CK_OTP_PARAMS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpParams {
    // Non-contradictory NULL/count array pointer (S2 §8 tail).
    pub params_presence: PointerArray<OtpParam>,
}

/// CK_KIP_PARAMS — references a nested Mechanism (boxed to avoid infinite size).
#[derive(Debug, Clone, PartialEq)]
pub struct KipParams {
    /// Nested mechanism, or `None` for a NULL `pMechanism` (S2 §3:
    /// non-contradictory by construction — the `Option` replaces the
    /// R18 transitional bool+dummy spelling).
    pub mechanism: Option<Box<CkMechanism>>,
    pub key_handle: CkObjectHandle,
    // Non-contradictory NULL/length pointer (S2 §8 tail).
    pub seed_presence: PointerBytes,
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
    pub password_length: u64,
    // Non-contradictory NULL/length pointers (S2 §8 tail). PrimeP/BaseG share the
    // one C `ulPAndGLen` — their effective lengths MUST agree under v1.
    pub password_presence: PointerBytes,
    pub public_data_presence: PointerBytes,
    pub random_a_presence: PointerBytes,
    pub prime_p_presence: PointerBytes,
    pub base_g_presence: PointerBytes,
    pub subprime_q_presence: PointerBytes,
}

impl std::fmt::Debug for SkipjackPrivateWrapParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructure to gate against silently-omitted future fields.
        let Self {
            password_length,
            password_presence,
            public_data_presence,
            random_a_presence,
            prime_p_presence,
            base_g_presence,
            subprime_q_presence,
        } = self;
        f.debug_struct("SkipjackPrivateWrapParams")
            .field("password_length", password_length)
            .field(
                "password_presence",
                &format_args!("[REDACTED; {}]", presence_debug(password_presence)),
            )
            .field(
                "public_data_presence",
                &format_args!("[{}]", presence_debug(public_data_presence)),
            )
            .field("random_a_presence", &format_args!("[{}]", presence_debug(random_a_presence)))
            .field("prime_p_presence", &format_args!("[{}]", presence_debug(prime_p_presence)))
            .field("base_g_presence", &format_args!("[{}]", presence_debug(base_g_presence)))
            .field(
                "subprime_q_presence",
                &format_args!("[{}]", presence_debug(subprime_q_presence)),
            )
            .finish()
    }
}

/// CK_SKIPJACK_RELAYX_PARAMS
///
/// Both old and new passwords are redacted in Debug and zeroized on
/// drop, as in [`PbeParams`].
#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SkipjackRelayxParams {
    // Non-contradictory NULL/length pointers (S2 §8 tail).
    pub old_wrapped_x_presence: PointerBytes,
    pub old_password_presence: PointerBytes,
    pub old_public_data_presence: PointerBytes,
    pub old_random_a_presence: PointerBytes,
    pub new_password_presence: PointerBytes,
    pub new_public_data_presence: PointerBytes,
    pub new_random_a_presence: PointerBytes,
}

impl std::fmt::Debug for SkipjackRelayxParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructure to gate against silently-omitted future fields.
        let Self {
            old_wrapped_x_presence,
            old_password_presence,
            old_public_data_presence,
            old_random_a_presence,
            new_password_presence,
            new_public_data_presence,
            new_random_a_presence,
        } = self;
        f.debug_struct("SkipjackRelayxParams")
            .field(
                "old_wrapped_x_presence",
                &format_args!("[{}]", presence_debug(old_wrapped_x_presence)),
            )
            .field(
                "old_password_presence",
                &format_args!("[REDACTED; {}]", presence_debug(old_password_presence)),
            )
            .field(
                "old_public_data_presence",
                &format_args!("[{}]", presence_debug(old_public_data_presence)),
            )
            .field(
                "old_random_a_presence",
                &format_args!("[{}]", presence_debug(old_random_a_presence)),
            )
            .field(
                "new_password_presence",
                &format_args!("[REDACTED; {}]", presence_debug(new_password_presence)),
            )
            .field(
                "new_public_data_presence",
                &format_args!("[{}]", presence_debug(new_public_data_presence)),
            )
            .field(
                "new_random_a_presence",
                &format_args!("[{}]", presence_debug(new_random_a_presence)),
            )
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
    // Non-contradictory NULL/length pointer (S2 §3).
    pub data_presence: PointerBytes,
}

/// CK_SIGN_ADDITIONAL_CONTEXT (`hash == 0`) or, for the generic
/// CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA, CK_HASH_SIGN_ADDITIONAL_CONTEXT
/// (`hash` = the hash mechanism). One Rust type covers both, the way
/// `Ssl3KeyMatParams` covers SSL3 and TLS12.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignAdditionalContext {
    pub hedge_variant: u64,
    /// 0 = plain CK_SIGN_ADDITIONAL_CONTEXT; non-zero = CK_HASH_SIGN_ADDITIONAL_CONTEXT.
    pub hash: CkMechanismType,
    // Non-contradictory NULL/length pointer (S2 §3).
    pub context_presence: PointerBytes,
}

/// CK_KMAC_PARAMS — keyed MAC output length and optional customization string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmacParams {
    pub key_handle: CkObjectHandle,
    pub mac_length: u64,
    // Non-contradictory NULL/length pointer (S2 §3).
    pub customization_string_presence: PointerBytes,
}

/// CK_MU_GEN_PARAMS — ML-DSA external-mu generation inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuGenParams {
    pub key_handle: CkObjectHandle,
    // Non-contradictory NULL/length pointers (S2 §3).
    pub tr_presence: PointerBytes,
    pub context_presence: PointerBytes,
}

/// Opaque raw parameter bytes — legacy wire-compat only (S2 §3/§6).
///
/// Historically an opt-in escape hatch for vendor-specific mechanisms;
/// under the v1 contract transport validation rejects this variant at
/// every version (`PARAM_INVALID`) and the backend FFI boundary keeps
/// rejecting it. New representable parameters use [`FlatParams`] /
/// the [`CkMechanismParams::Null`] variant instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMechanismParams {
    pub data: SecretBytes,
}

// ---------------------------------------------------------------------------
// R9: representable mechanism parameters (S2 §3/§6 + §10)
// ---------------------------------------------------------------------------

/// Daemon-supported classic mechanism-parameter transport version (S2 §3:
/// per-message `parameter_encoding_version`; 0/absent = legacy encoding,
/// 1 = the v1 Flat/Null contract).
///
/// Conversion (proto crate) and transport validation (this module's
/// [`ValidatedMechanismParams::validate`], reached via the server's
/// `validate_mechanism_transport`) share this single definition so the
/// "newer than daemon" gate cannot drift between layers. Monotonic
/// maximum capability: a newer daemon keeps accepting older encodings.
pub const MECHANISM_PARAMETER_TRANSPORT_VERSION: u32 = 1;

/// Non-contradictory variable-length pointer payload (S2 §6): either
/// present bytes or NULL with a declared length — never both, never
/// neither-with-bytes. Replaces vector+bool pairs: NULL-with-bytes and
/// present-with-undeclared-length are unrepresentable by construction
/// (each arm carries exactly what its presence claim allows, and no
/// accessor crosses the arms).
#[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize)]
pub enum PointerBytes {
    /// Non-NULL pointer to these bytes (including non-NULL/zero).
    Present(SecretBytes),
    /// NULL pointer with this declared length (no bytes cross).
    Null {
        /// Declared length (`ulParameterLen`); subject only to native
        /// `CK_ULONG` narrowing, never to the Flat cap.
        declared_len: u64,
    },
}

impl PointerBytes {
    /// Whether this is the NULL arm.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null { .. })
    }

    /// Declared length: the byte count for [`Self::Present`], the declared
    /// length for [`Self::Null`].
    pub fn declared_len(&self) -> u64 {
        match self {
            Self::Present(bytes) => bytes.len() as u64,
            Self::Null { declared_len } => *declared_len,
        }
    }

    /// Borrow the present bytes, or `None` for the NULL arm.
    pub fn as_present(&self) -> Option<&SecretBytes> {
        match self {
            Self::Present(bytes) => Some(bytes),
            Self::Null { .. } => None,
        }
    }

    /// NULL pointer with this declared length (no bytes cross).
    pub fn null_len(declared_len: u64) -> Self {
        Self::Null { declared_len }
    }

    /// Non-NULL pointer to a copy of these bytes (including empty).
    pub fn present_copy(bytes: &[u8]) -> Self {
        Self::Present(SecretBytes::copy_from_slice(bytes))
    }

    /// Non-NULL pointer to a clone of these secret bytes.
    pub fn present_cloned(bytes: &SecretBytes) -> Self {
        bytes.expose(Self::present_copy)
    }

    /// Build a peer from plain bytes plus a NULL bit: set bit → NULL
    /// with length zero, unset bit → the bytes as `Present`.
    pub fn from_legacy(bytes: &[u8], is_null: bool) -> Self {
        if is_null { Self::null_len(0) } else { Self::present_copy(bytes) }
    }
}

/// Non-contradictory fixed-size input-pointer payload (S2 §6 "presence
/// enums for fixed pointers"): exactly `N` bytes or NULL with a declared
/// length. Mirrors [`PointerBytes`]; the fixed length is enforced by
/// construction (the only `Present` constructor takes `[u8; N]`, so a
/// wrong length cannot be expressed), and NULL-with-bytes stays
/// unrepresentable via the wrapped [`PointerBytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedPointerBytes<const N: usize> {
    inner: PointerBytes,
}

impl<const N: usize> FixedPointerBytes<N> {
    /// Non-NULL pointer to exactly `N` bytes.
    pub fn present(bytes: [u8; N]) -> Self {
        Self { inner: PointerBytes::Present(SecretBytes::copy_from_slice(&bytes)) }
    }

    /// NULL pointer with this declared length (no bytes cross).
    pub fn null(declared_len: u64) -> Self {
        Self { inner: PointerBytes::Null { declared_len } }
    }

    /// Whether this is the NULL arm.
    pub fn is_null(&self) -> bool {
        self.inner.is_null()
    }

    /// Declared length: `N` for [`Self::present`], the declared length for
    /// [`Self::null`].
    pub fn declared_len(&self) -> u64 {
        self.inner.declared_len()
    }

    /// Borrow the wrapped [`PointerBytes`].
    pub fn as_pointer_bytes(&self) -> &PointerBytes {
        &self.inner
    }
}

/// Non-contradictory output-pointer payload (S2 §6 "presence enums for
/// output pointers"): a non-NULL caller buffer of known capacity for
/// provider output, or NULL with a declared length. Output buffers carry
/// capacity, never input bytes, so no byte field can contradict the
/// presence arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputPointerBytes {
    /// Non-NULL caller buffer of `capacity` bytes for provider output.
    Present {
        /// Buffer capacity in bytes.
        capacity: u64,
    },
    /// NULL pointer with this declared length.
    Null {
        /// Declared length.
        declared_len: u64,
    },
}

impl OutputPointerBytes {
    /// Whether this is the NULL arm.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null { .. })
    }

    /// Buffer capacity for [`Self::Present`], declared length for
    /// [`Self::Null`].
    pub fn capacity_or_len(&self) -> u64 {
        match self {
            Self::Present { capacity } => *capacity,
            Self::Null { declared_len } => *declared_len,
        }
    }
}

/// Non-contradictory counted-array pointer payload (R18 tail, S2 §8):
/// either a non-NULL array of known elements or NULL with a declared
/// count — never both, never neither-with-elements. The array analogue
/// of [`PointerBytes`] for the OTP/SP800-108 struct arrays (OTP params,
/// PRF data params, additional derived keys, derived-key templates).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerArray<T> {
    /// Non-NULL pointer to these array elements (including non-NULL/zero).
    Present(Vec<T>),
    /// NULL pointer with this declared count (no elements cross).
    Null {
        /// Declared count (`ulCount`); subject only to native `CK_ULONG`
        /// narrowing, never to the Flat cap.
        declared_count: u64,
    },
}

impl<T> PointerArray<T> {
    /// Whether this is the NULL arm.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null { .. })
    }

    /// Declared count: the element count for [`Self::Present`], the
    /// declared count for [`Self::Null`].
    pub fn declared_count(&self) -> u64 {
        match self {
            Self::Present(items) => items.len() as u64,
            Self::Null { declared_count } => *declared_count,
        }
    }

    /// Borrow the present elements, or `None` for the NULL arm.
    pub fn as_present(&self) -> Option<&Vec<T>> {
        match self {
            Self::Present(items) => Some(items),
            Self::Null { .. } => None,
        }
    }

    /// Mutably borrow the present elements, or `None` for the NULL arm.
    pub fn as_present_mut(&mut self) -> Option<&mut Vec<T>> {
        match self {
            Self::Present(items) => Some(items),
            Self::Null { .. } => None,
        }
    }

    /// NULL pointer with this declared count (no elements cross).
    pub fn null_count(declared_count: u64) -> Self {
        Self::Null { declared_count }
    }

    /// Non-NULL pointer to these array elements (including empty).
    pub fn present(items: Vec<T>) -> Self {
        Self::Present(items)
    }
}

/// Versioned flat classic parameter (S2 §3/§6): non-NULL caller bytes
/// with `ulParameterLen == declared_len == bytes.len()`; only those bytes
/// are caller input (adjacent caller memory is outside the fidelity
/// contract). The 64 KiB outer cap applies. Opaque bytes are
/// [`SecretBytes`] (wiped on drop): Flat input may carry key material,
/// and nothing in the validated path may retain a plain copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatParams {
    /// Caller bytes (exactly `declared_len` long once validated).
    pub bytes: SecretBytes,
    /// Declared extent (`ulParameterLen`).
    pub declared_len: u64,
    /// Caller-side native struct ABI, or `None` when the wire carried
    /// `UNSPECIFIED`/unknown (validation rejects: struct prefixes require
    /// exact ABI equality, so an unknown ABI can never match).
    pub source_abi: Option<ParamAbi>,
    /// Wire-sent layout fingerprint (checked against the compiled
    /// descriptor under the local ABI).
    pub fingerprint: u64,
    /// Threaded per-message `parameter_encoding_version`.
    pub version: u32,
}

/// Gate a v1-only member's threaded version (S2 §3/§6 RV table): a legacy
/// stamp on a v1-only encoding is contradictory metadata
/// (`PARAM_INVALID`); a version newer than this daemon is
/// `FUNCTION_NOT_SUPPORTED` pre-entry.
fn check_member_version(version: u32) -> Result<(), CkRv> {
    if version < MECHANISM_PARAMETER_TRANSPORT_VERSION {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    if version > MECHANISM_PARAMETER_TRANSPORT_VERSION {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    Ok(())
}

/// Narrow a wire `u64` declared length to the backend `CK_ULONG` width
/// (S2 §6 RV table: unnarrowable → `FUNCTION_FAILED`).
fn narrow_len_for_backend(declared_len: u64, backend_abi: ParamAbi) -> Result<(), CkRv> {
    if backend_abi.ulong_size() >= 8 {
        return Ok(());
    }
    u32::try_from(declared_len).map(|_| ()).map_err(|_| CkRv::FUNCTION_FAILED)
}

/// Fallible reservation mapping allocation failure to `HOST_MEMORY` (S2 §6
/// RV table: genuine sub-cap allocation failure). Split out so the row is
/// unit-pinnable via a forced `CapacityOverflow`.
fn reserve_or_host_memory(vec: &mut Vec<u8>, additional: usize) -> Result<(), CkRv> {
    vec.try_reserve(additional).map_err(|_| CkRv::HOST_MEMORY)
}

/// Scalar-pointer null-bit agreement (R18 tail): a set null bit
/// requires the zeroed legacy scalar(s) (`is_zero`); an unset bit
/// constrains nothing.
fn check_null_bit_pair(is_zero: bool, is_null: bool) -> Result<(), CkRv> {
    if is_null && !is_zero {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    Ok(())
}

/// SP800-108 derived-key agreement (R18 tail): template array pair +
/// output-handle null-bit pair.
fn check_sp800108_derived_key(key: &Sp800108DerivedKey) -> Result<(), CkRv> {
    check_null_bit_pair(key.key_handle.0 == 0, key.ph_key_is_null)
}

/// Proof that a mechanism's parameters passed daemon transport validation
/// (S2 §6). Opaque: the only way to obtain one is [`Self::validate`],
/// which runs every always-on check; `mechanism_to_ffi` (R12) accepts
/// only this type, so a public `Flat` value can never bypass the
/// invariant the way a bare enum could.
///
/// Handle remapping (R13) consumes the newtype and returns it:
/// substitution of virtual→native handle integers preserves every
/// validated property (lengths, caps, shape binding, ABI).
#[derive(Debug, Clone)]
pub struct ValidatedMechanismParams {
    mechanism: CkMechanism,
    /// `Some` for validated Flat (the stored grant lets later stages reuse
    /// the resolution without re-deciding policy); `None` otherwise.
    flat_grant: Option<FlatGrant>,
    /// The registry snapshot this value was validated against: the
    /// request's `current_registry()` snapshot on the server path, the
    /// empty backstop in the backend-local funnel. Nested descent
    /// reuses it so nested Flat eligibility is decided under the same
    /// bindings as the top level (F6) — S2 §6's "one snapshot per
    /// request" carried in the proof itself.
    registry: MechanismRegistry,
    /// The ABIs this value was validated under. Nested descent reuses
    /// them (never a width-derived guess — word width alone cannot
    /// distinguish ILP32 from LLP64-packed, NF2), and the nested
    /// sanitize scan classifies nested Flat under the same deciding
    /// edge as the top level (NF5).
    local_abi: ParamAbi,
    backend_abi: ParamAbi,
}

/// Value equality: the carried snapshot and ABIs are provenance, not
/// value, so two validations of equal mechanisms compare equal even
/// across different snapshots or ABIs (pre-F6 meaning preserved).
impl PartialEq for ValidatedMechanismParams {
    fn eq(&self, other: &Self) -> bool {
        self.mechanism == other.mechanism && self.flat_grant == other.flat_grant
    }
}

impl CkMechanismParams {
    /// Canonical registry shape name authorizing this typed variant
    /// (F1, S2 §4): the binding key the mechanism must carry for this
    /// variant to validate (modulo the `gcm_compat` union and
    /// WrapKey operation-selected layouts, applied by the caller).
    ///
    /// Exhaustive with no catch-all, so a future variant cannot
    /// silently skip binding (the compiler rejects the omission).
    /// Order mirrors the enum definition. `None` for the non-typed
    /// envelopes (Flat/Null/Raw), whose authorization rules live in
    /// their own [`ValidatedMechanismParams::validate`] arms.
    pub fn canonical_shape_name(&self) -> Option<&'static str> {
        use CkMechanismParams as P;
        match self {
            P::RsaPkcsPss(_) => Some("rsa_pss"),
            P::RsaPkcsOaep(_) => Some("rsa_oaep"),
            P::Gcm(_) => Some("gcm"),
            P::Ecdh1Derive(_) => Some("ecdh1_derive"),
            P::Iv(_) => Some("iv"),
            P::Rc5(_) => Some("rc5"),
            P::Rc5MacGeneral(_) => Some("rc5_mac_general"),
            P::Rc2MacGeneral(_) => Some("rc2_mac_general"),
            P::Xeddsa(_) => Some("xeddsa"),
            P::TlsMac(_) => Some("tls_mac"),
            P::AesCtr(_) => Some("aes_ctr"),
            P::CamelliaCtr(_) => Some("camellia_ctr"),
            P::Rc2Cbc(_) => Some("rc2_cbc"),
            P::Rc5Cbc(_) => Some("rc5_cbc"),
            P::AesCbcEncryptData(_) => Some("aes_cbc_encrypt_data"),
            P::DesCbcEncryptData(_) => Some("des_cbc_encrypt_data"),
            P::AriaCbcEncryptData(_) => Some("aria_cbc_encrypt_data"),
            P::CamelliaCbcEncryptData(_) => Some("camellia_cbc_encrypt_data"),
            P::SeedCbcEncryptData(_) => Some("seed_cbc_encrypt_data"),
            P::Ccm(_) => Some("ccm"),
            P::ChaCha20(_) => Some("chacha20"),
            P::Salsa20(_) => Some("salsa20"),
            P::Salsa20ChaCha20Poly1305(_) => Some("salsa20_chacha20_poly1305"),
            P::GcmWrap(_) => Some("gcm_wrap"),
            P::CcmWrap(_) => Some("ccm_wrap"),
            P::Ecdh2Derive(_) => Some("ecdh2_derive"),
            P::EcmqvDerive(_) => Some("ecmqv_derive"),
            P::X942Dh1Derive(_) => Some("x942_dh1_derive"),
            P::X942Dh2Derive(_) => Some("x942_dh2_derive"),
            P::X942MqvDerive(_) => Some("x942_mqv_derive"),
            P::Hkdf(_) => Some("hkdf"),
            P::Eddsa(_) => Some("eddsa"),
            P::Gostr3410Derive(_) => Some("gostr3410_derive"),
            P::KeaDerive(_) => Some("kea_derive"),
            P::EcdhAesKeyWrap(_) => Some("ecdh_aes_key_wrap"),
            P::RsaAesKeyWrap(_) => Some("rsa_aes_key_wrap"),
            P::Gostr3410KeyWrap(_) => Some("gostr3410_key_wrap"),
            P::KeyWrapSetOaep(_) => Some("key_wrap_set_oaep"),
            P::Pbe(_) => Some("pbe"),
            P::Pkcs5Pbkd2(_) => Some("pkcs5_pbkd2"),
            P::TlsPrf(_) => Some("tls_prf"),
            P::TlsKdf(_) => Some("tls_kdf"),
            P::Ssl3MasterKeyDerive(_) => Some("ssl3_master_key_derive"),
            P::Tls12MasterKeyDerive(_) => Some("tls12_master_key_derive"),
            P::Tls12ExtendedMasterKeyDerive(_) => Some("tls12_extended_master_key_derive"),
            P::Ssl3KeyMat(_) => Some("ssl3_key_mat"),
            P::WtlsMasterKeyDerive(_) => Some("wtls_master_key_derive"),
            P::WtlsPrf(_) => Some("wtls_prf"),
            P::WtlsKeyMat(_) => Some("wtls_key_mat"),
            P::IkePrfDerive(_) => Some("ike_prf_derive"),
            P::Ike1PrfDerive(_) => Some("ike1_prf_derive"),
            P::Ike1ExtendedDerive(_) => Some("ike1_extended_derive"),
            P::Ike2PrfPlusDerive(_) => Some("ike2_prf_plus_derive"),
            P::Sp800108Kdf(_) => Some("sp800_108_kdf"),
            P::Sp800108FeedbackKdf(_) => Some("sp800_108_feedback_kdf"),
            P::X3dhInitiate(_) => Some("x3dh_initiate"),
            P::X3dhRespond(_) => Some("x3dh_respond"),
            P::X2RatchetInitialize(_) => Some("x2ratchet_initialize"),
            P::X2RatchetRespond(_) => Some("x2ratchet_respond"),
            P::Otp(_) => Some("otp"),
            P::Kip(_) => Some("kip"),
            P::CmsSig(_) => Some("cms_sig"),
            P::SkipjackPrivateWrap(_) => Some("skipjack_private_wrap"),
            P::SkipjackRelayx(_) => Some("skipjack_relayx"),
            P::MacGeneral(_) => Some("mac_general"),
            P::ObjectHandle(_) => Some("object_handle"),
            P::Extract(_) => Some("extract"),
            P::SignAdditionalContext(_) => Some("sign_additional_context"),
            P::Kmac(_) => Some("kmac"),
            P::MuGen(_) => Some("mu_gen"),
            P::KeyDerivationString(_) => Some("key_derivation_string"),
            P::Raw(_) | P::Flat(_) | P::Null { .. } => None,
            P::Ecies(_) => Some("ecies"),
            P::AesCmacKeyDerivation(_) => Some("aes_cmac_key_derivation"),
            P::Dilithium(_) => Some("dilithium"),
            P::Kyber(_) => Some("kyber"),
            P::HdKeyDerive(_) => Some("hd_key_derive"),
            P::VendorObjectExtract(_) => Some("vendor_object_extract"),
            P::VendorObjectInsert(_) => Some("vendor_object_insert"),
        }
    }
}

/// Whether `registry` authorizes `mech_type` to carry typed params of
/// `variant_shape` under `operation` (F1, S2 §4 + §6): a direct
/// binding, the `gcm_compat` union (the manifest binds both typed
/// messages to it), or the WrapKey operation-selected wrap layouts
/// (mirrors `ShapeResolver::resolve` + the shim's
/// `select_reader_shape`: `General` never selects wrap layouts).
fn typed_shape_authorized(
    registry: &MechanismRegistry,
    mech_type: u64,
    variant_shape: &str,
    operation: Operation,
) -> bool {
    if registry.param_shape(mech_type) == Some(variant_shape) {
        return true;
    }
    if registry.param_shape(mech_type) == Some("gcm_compat")
        && matches!(variant_shape, "iv" | "gcm")
    {
        return true;
    }
    if operation == Operation::WrapKey {
        if mech_type == CkMechanismType::AES_GCM.0 && variant_shape == "gcm_wrap" {
            return true;
        }
        if mech_type == CkMechanismType::AES_CCM.0 && variant_shape == "ccm_wrap" {
            return true;
        }
    }
    false
}

impl ValidatedMechanismParams {
    /// Run every always-on transport check (S2 §6): version/oneof
    /// consistency, length equality, 64 KiB cap, registry binding, safe
    /// prefix, ABI match, no handles/pointers in Flat, legacy-Raw reject,
    /// typed presence/length consistency (R16).
    /// Pure and total: no I/O, no allocation beyond the validated copy.
    ///
    /// - `registry` is the daemon's `current_registry()` snapshot for this
    ///   request (SIGHUP safety: one snapshot feeds exclusion, descriptor
    ///   resolution, and validation).
    /// - `operation` is the call-site operation context (WrapKey selects
    ///   the GCM/CCM wrap layouts by operation+length).
    /// - `local_abi` is the deciding edge's native ABI; `backend_abi`
    ///   supplies the backend `CK_ULONG` width for narrowing.
    ///
    /// RV mapping (exact, S2 §6): operator exclusion →
    /// `MECHANISM_INVALID`; unknown mechanism without params → forwarded
    /// (`Ok`); unknown with params and no descriptor → `PARAM_INVALID`;
    /// unknown with `Null` → forwarded (`Ok`, no descriptor needed);
    /// per-message version newer than daemon → `FUNCTION_NOT_SUPPORTED`;
    /// legacy Raw, unsafe Flat, shape mismatch, contradictory metadata,
    /// unknown descriptor, ABI mismatch, length mismatch, cap violation →
    /// `PARAM_INVALID`; genuine sub-cap allocation failure → `HOST_MEMORY`;
    /// wire u64 unnarrowable to backend `CK_ULONG` → `FUNCTION_FAILED`;
    /// faithful bytes pass through verbatim.
    ///
    /// Typed (non-Flat/Null/Raw) params pass the R16 presence/length
    /// consistency gate ([`check_typed_presence`]) AND the F1
    /// mechanism-to-shape binding gate: the variant's canonical shape
    /// must be bound to the mechanism (modulo the `gcm_compat` union
    /// and WrapKey operation-selected layouts) — mismatches and
    /// descriptorless parameterized mechanisms reject with
    /// `PARAM_INVALID` (S2 §6 RV table: "shape mismatch" row), because
    /// no downstream layer re-binds before backend FFI.
    pub fn validate(
        mechanism: &CkMechanism,
        registry: &MechanismRegistry,
        operation: Operation,
        local_abi: ParamAbi,
        backend_abi: ParamAbi,
    ) -> Result<Self, CkRv> {
        let mech_type = mechanism.mechanism_type.0;
        if registry.excluded_view().contains(&mech_type) {
            return Err(CkRv::MECHANISM_INVALID);
        }
        match &mechanism.params {
            // Existing transparent contract: unknown or known, parameterless
            // invocations forward.
            None => Ok(Self {
                mechanism: mechanism.clone(),
                flat_grant: None,
                registry: registry.clone(),
                local_abi,
                backend_abi,
            }),
            // Legacy Raw fails closed at every version.
            Some(CkMechanismParams::Raw(_)) => Err(CkRv::MECHANISM_PARAM_INVALID),
            // NULL + narrowed length needs no descriptor (S2 §6 RV table).
            Some(CkMechanismParams::Null { declared_len, version }) => {
                check_member_version(*version)?;
                narrow_len_for_backend(*declared_len, backend_abi)?;
                Ok(Self {
                    mechanism: mechanism.clone(),
                    flat_grant: None,
                    registry: registry.clone(),
                    local_abi,
                    backend_abi,
                })
            }
            Some(CkMechanismParams::Flat(p)) => {
                check_member_version(p.version)?;
                let actual =
                    u64::try_from(p.bytes.len()).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
                if actual != p.declared_len {
                    return Err(CkRv::MECHANISM_PARAM_INVALID);
                }
                let peer_abi = p.source_abi.ok_or(CkRv::MECHANISM_PARAM_INVALID)?;
                let grant = match decide_flat_for_registry(
                    registry,
                    mech_type,
                    operation,
                    p.declared_len,
                    p.fingerprint,
                    peer_abi,
                    local_abi,
                ) {
                    FlatDecision::Eligible(grant) => grant,
                    // Unreachable (exclusion checked above); mapped anyway
                    // so a future reorder cannot silently forward.
                    FlatDecision::Excluded => return Err(CkRv::MECHANISM_INVALID),
                    // OverCap, VendorWithoutAllowlist, UnknownShape,
                    // NestedOrOutput, FullNativeImage, AbiMismatch,
                    // FingerprintMismatch, PrefixTooLong — every R7 denial
                    // reason is PARAM_INVALID per the S2 §6 RV table.
                    FlatDecision::Denied(_) => return Err(CkRv::MECHANISM_PARAM_INVALID),
                };
                // Post-cap lengths always narrow; the check documents the
                // invariant at the single narrowing site.
                narrow_len_for_backend(p.declared_len, backend_abi)?;
                let mut buf = Vec::new();
                reserve_or_host_memory(&mut buf, p.bytes.len())?;
                p.bytes.expose(|bytes| buf.extend_from_slice(bytes));
                let flat = FlatParams {
                    bytes: SecretBytes::new(buf),
                    declared_len: p.declared_len,
                    source_abi: p.source_abi,
                    fingerprint: p.fingerprint,
                    version: p.version,
                };
                Ok(Self {
                    mechanism: CkMechanism {
                        mechanism_type: mechanism.mechanism_type,
                        params: Some(CkMechanismParams::Flat(flat)),
                    },
                    flat_grant: Some(grant),
                    registry: registry.clone(),
                    local_abi,
                    backend_abi,
                })
            }
            // Typed params: R16 presence/length consistency (S2 §3)
            // over every input-pointer pair, then the F1 binding gate
            // (S2 §4 + §6) — shapes without presence peers still bind.
            Some(params) => {
                check_typed_presence(params)?;
                let authorized = params.canonical_shape_name().is_some_and(|shape| {
                    typed_shape_authorized(registry, mech_type, shape, operation)
                });
                if !authorized {
                    return Err(CkRv::MECHANISM_PARAM_INVALID);
                }
                Ok(Self {
                    mechanism: mechanism.clone(),
                    flat_grant: None,
                    registry: registry.clone(),
                    local_abi,
                    backend_abi,
                })
            }
        }
    }

    /// Borrow the validated mechanism.
    pub fn mechanism(&self) -> &CkMechanism {
        &self.mechanism
    }

    /// Unwrap the validated mechanism (re-entry to FFI still requires the
    /// newtype — R12 — so unwrapping cannot bypass validation).
    pub fn into_inner(self) -> CkMechanism {
        self.mechanism
    }

    /// The stored Flat grant (`Some` only for validated Flat).
    pub fn flat_grant(&self) -> Option<FlatGrant> {
        self.flat_grant
    }

    /// The registry snapshot this value was validated against (F6):
    /// nested descent reuses it so nested Flat eligibility is decided
    /// under the request's bindings.
    pub fn registry(&self) -> &MechanismRegistry {
        &self.registry
    }

    /// The deciding edge's ABI this value was validated under (NF2/NF5):
    /// nested descent revalidates and the nested sanitize scan
    /// classifies nested Flat under this ABI — never a width-derived
    /// guess.
    pub fn local_abi(&self) -> ParamAbi {
        self.local_abi
    }

    /// The backend ABI this value was validated under (NF2): nested
    /// descent revalidates nested nodes for this same backend width.
    pub fn backend_abi(&self) -> ParamAbi {
        self.backend_abi
    }

    /// Classic sanitize policy (S2 §6 matrix; R20). Pure: no I/O, no
    /// allocation — the top-level Flat reuses its stored
    /// [`FlatGrant`](crate::shape_descriptors::FlatGrant), while nested
    /// Flat envelopes (which carry no grant) classify against the
    /// carried registry snapshot under the carried deciding ABI, so the
    /// same matrix row governs every depth (NF5).
    ///
    /// OFF (default `false`): always `Ok` — stray flat bytes, safe
    /// truncated forms, and outer/embedded NULL-nonzero forward to the
    /// backend untouched. ON: parameterless+Flat → reject; struct-prefix
    /// Flat → reject; canonical byte-buffer Flat → allow (subject to the
    /// upstream mechanism policy, already enforced before validation);
    /// NULL/nonzero → reject (D3: NULL-huge rejects regardless — no D3
    /// forwarding under sanitize), outer AND embedded: typed params
    /// carrying any embedded NULL with a nonzero declared length/count
    /// reject, including nested structs, counted arrays, and nested
    /// mechanisms ([`typed_has_nonzero_embedded_null`]); NULL-zero (the
    /// canonical null) stays allowed, like the outer row. Legacy Raw →
    /// always reject. Every rejection is `PARAM_INVALID`
    /// (`ARGUMENTS_BAD` stays with the pre-existing
    /// whole-mechanism/data-pointer gates). Scalar/operation semantics
    /// belong to the backend — no provider-specific scalar conformance
    /// (forbidden by S2 §6).
    pub fn check_classic_sanitize_policy(&self, sanitize: bool) -> Result<(), CkRv> {
        use CkMechanismParams as P;
        if !sanitize {
            return Ok(());
        }
        match &self.mechanism.params {
            None => Ok(()),
            Some(P::Flat(_)) => {
                match self.flat_grant.map(|grant| grant.resolved.outer_kind()) {
                    // Canonical byte-buffer Flat (IV/nonce blobs, GMAC short
                    // form): the only Flat form sanitize admits.
                    Some(OuterKind::ByteBuffer) => Ok(()),
                    // Parameterless+Flat and struct-prefix Flat (scalar or
                    // pointer-bearing) reject; a missing grant (unreachable:
                    // validation stores one for every accepted Flat) and
                    // NestedOrOutput (unreachable: validation denies it)
                    // fail closed.
                    _ => Err(CkRv::MECHANISM_PARAM_INVALID),
                }
            }
            // D3: NULL-huge rejects regardless — no D3 forwarding under
            // sanitize. NULL/zero (the canonical null) stays allowed.
            Some(P::Null { declared_len, .. }) => {
                if *declared_len == 0 {
                    Ok(())
                } else {
                    Err(CkRv::MECHANISM_PARAM_INVALID)
                }
            }
            // Unreachable: transport validation rejects legacy Raw
            // always-on, before the sanitizer runs. The fail-closed arm
            // stays so a future constructor cannot silently forward Raw.
            Some(P::Raw(_)) => Err(CkRv::MECHANISM_PARAM_INVALID),
            // Typed params (exhaustive — no catch-all, so a future variant
            // cannot silently skip this gate): F2 embedded-NULL rule —
            // any nonzero declared length/count rejects; NULL-zero and
            // fully-present params pass. Enum order mirrors the definition.
            Some(
                params @ (P::RsaPkcsPss(_)
                | P::RsaPkcsOaep(_)
                | P::Gcm(_)
                | P::Ecdh1Derive(_)
                | P::Iv(_)
                | P::Rc5(_)
                | P::Rc5MacGeneral(_)
                | P::Rc2MacGeneral(_)
                | P::Xeddsa(_)
                | P::TlsMac(_)
                | P::AesCtr(_)
                | P::CamelliaCtr(_)
                | P::Rc2Cbc(_)
                | P::Rc5Cbc(_)
                | P::AesCbcEncryptData(_)
                | P::DesCbcEncryptData(_)
                | P::AriaCbcEncryptData(_)
                | P::CamelliaCbcEncryptData(_)
                | P::SeedCbcEncryptData(_)
                | P::Ccm(_)
                | P::ChaCha20(_)
                | P::Salsa20(_)
                | P::Salsa20ChaCha20Poly1305(_)
                | P::GcmWrap(_)
                | P::CcmWrap(_)
                | P::Ecdh2Derive(_)
                | P::EcmqvDerive(_)
                | P::X942Dh1Derive(_)
                | P::X942Dh2Derive(_)
                | P::X942MqvDerive(_)
                | P::Hkdf(_)
                | P::Eddsa(_)
                | P::Gostr3410Derive(_)
                | P::KeaDerive(_)
                | P::EcdhAesKeyWrap(_)
                | P::RsaAesKeyWrap(_)
                | P::Gostr3410KeyWrap(_)
                | P::KeyWrapSetOaep(_)
                | P::Pbe(_)
                | P::Pkcs5Pbkd2(_)
                | P::TlsPrf(_)
                | P::TlsKdf(_)
                | P::Ssl3MasterKeyDerive(_)
                | P::Tls12MasterKeyDerive(_)
                | P::Tls12ExtendedMasterKeyDerive(_)
                | P::Ssl3KeyMat(_)
                | P::WtlsMasterKeyDerive(_)
                | P::WtlsPrf(_)
                | P::WtlsKeyMat(_)
                | P::IkePrfDerive(_)
                | P::Ike1PrfDerive(_)
                | P::Ike1ExtendedDerive(_)
                | P::Ike2PrfPlusDerive(_)
                | P::Sp800108Kdf(_)
                | P::Sp800108FeedbackKdf(_)
                | P::X3dhInitiate(_)
                | P::X3dhRespond(_)
                | P::X2RatchetInitialize(_)
                | P::X2RatchetRespond(_)
                | P::Otp(_)
                | P::Kip(_)
                | P::CmsSig(_)
                | P::SkipjackPrivateWrap(_)
                | P::SkipjackRelayx(_)
                | P::MacGeneral(_)
                | P::ObjectHandle(_)
                | P::Extract(_)
                | P::SignAdditionalContext(_)
                | P::Kmac(_)
                | P::MuGen(_)
                | P::KeyDerivationString(_)
                | P::Ecies(_)
                | P::AesCmacKeyDerivation(_)
                | P::Dilithium(_)
                | P::Kyber(_)
                | P::HdKeyDerive(_)
                | P::VendorObjectExtract(_)
                | P::VendorObjectInsert(_)),
            ) => {
                let nested =
                    SanitizeNestedCx { registry: &self.registry, local_abi: self.local_abi };
                if typed_has_nonzero_embedded_null(params, 0, &nested) {
                    Err(CkRv::MECHANISM_PARAM_INVALID)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Substitute embedded virtual handle integers with backend values
    /// (R13 handle remapping, S2 §6).
    ///
    /// Consumes the newtype and returns it: `f` must only rewrite embedded
    /// `CK_OBJECT_HANDLE` fields (the remapper's contract — Flat/Null/None
    /// carry no handles, and typed substitution touches handle fields
    /// only). Every validated property (lengths, caps, shape binding, ABI)
    /// is preserved by construction — the stored `flat_grant`, the
    /// carried registry snapshot, and the carried ABIs travel with
    /// `self` untouched — and debug builds re-check the cheap invariant that
    /// nothing BUT handle fields changed (both sides compared with all
    /// embedded handles normalized to zero).
    pub fn substitute_handles(mut self, f: impl FnOnce(&mut CkMechanism)) -> Self {
        let before = normalized_for_handle_compare(&self.mechanism);
        f(&mut self.mechanism);
        debug_assert_eq!(
            normalized_for_handle_compare(&self.mechanism),
            before,
            "handle substitution must preserve every validated property"
        );
        self
    }
}

/// Whether a `PointerBytes` peer is a NULL with a nonzero declared
/// length (F2 sanitize-ON rule; NULL-zero is the canonical null).
fn is_nonzero_null(peer: &PointerBytes) -> bool {
    matches!(peer, PointerBytes::Null { declared_len } if *declared_len != 0)
}

/// Whether a `PointerArray` peer is a NULL with a nonzero declared
/// count (F2 sanitize-ON rule; NULL-zero is the canonical null).
fn is_nonzero_null_array<T>(peer: &PointerArray<T>) -> bool {
    matches!(peer, PointerArray::Null { declared_count } if *declared_count != 0)
}

/// Maximum nested-mechanism depth the F2 sanitize scan descends: aligned
/// with the backend FFI descent cap (`MAX_NESTED_MECHANISMS` = 16), so
/// the fail-closed over-deep verdict only fires for trees that cannot
/// convert anyway.
const SANITIZE_NESTING_CAP: u8 = 16;

/// Carried context for the nested sanitize scan (NF5): the snapshot
/// and deciding ABI the outer value was validated under, so nested
/// Flat envelopes classify exactly like the top level.
struct SanitizeNestedCx<'a> {
    registry: &'a MechanismRegistry,
    local_abi: ParamAbi,
}

/// Whether a nested Flat violates sanitize-ON (NF5): the envelope
/// carries no stored grant, so classify it exactly like the top-level
/// Flat arm (member version, actual==declared, known source ABI, then
/// the carried-registry decision under the carried deciding ABI with
/// `Operation::General` — nested nodes carry no wrap context, as in
/// backend descent) and apply the same matrix row — only a canonical
/// byte-buffer grant passes; struct-prefix grants, denials, and
/// malformed envelopes fail closed. Length narrowing stays with
/// validation (backend descent narrows through `validate`); the
/// sanitizer only classifies.
fn nested_flat_violates(mech_type: u64, flat: &FlatParams, cx: &SanitizeNestedCx) -> bool {
    if check_member_version(flat.version).is_err() {
        return true;
    }
    let Ok(actual) = u64::try_from(flat.bytes.len()) else {
        return true;
    };
    if actual != flat.declared_len {
        return true;
    }
    let Some(peer_abi) = flat.source_abi else {
        return true;
    };
    match decide_flat_for_registry(
        cx.registry,
        mech_type,
        Operation::General,
        flat.declared_len,
        flat.fingerprint,
        peer_abi,
        cx.local_abi,
    ) {
        FlatDecision::Eligible(grant) => {
            !matches!(grant.resolved.outer_kind(), OuterKind::ByteBuffer)
        }
        FlatDecision::Excluded | FlatDecision::Denied(_) => true,
    }
}

/// Whether a (possibly nested) mechanism carries a nonzero embedded
/// NULL anywhere sanitize polices (F2): a nested outer NULL with
/// nonzero length, a nested Flat that is not a canonical byte-buffer
/// grant under the carried snapshot ([`nested_flat_violates`], NF5), a
/// nested Raw (never validates — fail closed), or nonzero embedded
/// NULLs inside nested typed params (recursed with a depth cap;
/// over-deep trees fail closed).
fn mechanism_has_nonzero_null(mech: &CkMechanism, depth: u8, cx: &SanitizeNestedCx) -> bool {
    if depth > SANITIZE_NESTING_CAP {
        return true;
    }
    match &mech.params {
        None => false,
        Some(CkMechanismParams::Null { declared_len, .. }) => *declared_len != 0,
        Some(CkMechanismParams::Flat(flat)) => {
            nested_flat_violates(mech.mechanism_type.0, flat, cx)
        }
        Some(CkMechanismParams::Raw(_)) => true,
        Some(params) => typed_has_nonzero_embedded_null(params, depth, cx),
    }
}

/// Whether typed params carry any embedded NULL with a nonzero declared
/// length/count (F2 sanitize-ON rule, S2 §6 matrix "NULL/nonzero →
/// reject" + D3 "rejects regardless"): every `PointerBytes` /
/// `PointerArray` field, including nested structs (OAEP-in-wrap,
/// random-data, PRF params, OTP params, derived-key templates),
/// counted-array elements, and nested mechanisms (recursed via
/// [`mechanism_has_nonzero_null`]).
///
/// Exhaustive with no catch-all, so a future variant cannot silently
/// skip this gate (the compiler rejects the omission). Enum order
/// mirrors the definition. Null-bit bools (`*_is_null`) are output
/// envelopes, not NULL lengths, and are out of this rule's scope.
fn typed_has_nonzero_embedded_null(
    params: &CkMechanismParams,
    depth: u8,
    cx: &SanitizeNestedCx,
) -> bool {
    use CkMechanismParams as P;
    match params {
        P::RsaPkcsPss(_) => false,
        P::RsaPkcsOaep(p) => is_nonzero_null(&p.source_data_presence),
        P::Gcm(p) => is_nonzero_null(&p.iv_presence) || is_nonzero_null(&p.aad_presence),
        P::Ecdh1Derive(p) => {
            is_nonzero_null(&p.shared_data_presence) || is_nonzero_null(&p.public_data_presence)
        }
        P::Iv(_) => false,
        P::Rc5(_) => false,
        P::Rc5MacGeneral(_) => false,
        P::Rc2MacGeneral(_) => false,
        P::Xeddsa(_) => false,
        P::TlsMac(_) => false,
        P::AesCtr(_) => false,
        P::CamelliaCtr(_) => false,
        P::Rc2Cbc(_) => false,
        P::Rc5Cbc(p) => is_nonzero_null(&p.iv_presence),
        P::AesCbcEncryptData(p) => is_nonzero_null(&p.data_presence),
        P::DesCbcEncryptData(p) => is_nonzero_null(&p.data_presence),
        P::AriaCbcEncryptData(p) => is_nonzero_null(&p.data_presence),
        P::CamelliaCbcEncryptData(p) => is_nonzero_null(&p.data_presence),
        P::SeedCbcEncryptData(p) => is_nonzero_null(&p.data_presence),
        P::Ccm(p) => is_nonzero_null(&p.nonce_presence) || is_nonzero_null(&p.aad_presence),
        P::ChaCha20(p) => {
            is_nonzero_null(&p.block_counter_presence) || is_nonzero_null(&p.nonce_presence)
        }
        P::Salsa20(p) => {
            is_nonzero_null(&p.block_counter_presence) || is_nonzero_null(&p.nonce_presence)
        }
        P::Salsa20ChaCha20Poly1305(p) => {
            is_nonzero_null(&p.nonce_presence) || is_nonzero_null(&p.aad_presence)
        }
        P::GcmWrap(p) => is_nonzero_null(&p.iv_presence) || is_nonzero_null(&p.aad_presence),
        P::CcmWrap(p) => is_nonzero_null(&p.nonce_presence) || is_nonzero_null(&p.aad_presence),
        P::Ecdh2Derive(p) => {
            is_nonzero_null(&p.shared_data_presence)
                || is_nonzero_null(&p.public_data_presence)
                || is_nonzero_null(&p.public_data2_presence)
        }
        P::EcmqvDerive(p) => {
            is_nonzero_null(&p.shared_data_presence)
                || is_nonzero_null(&p.public_data_presence)
                || is_nonzero_null(&p.public_data2_presence)
        }
        P::X942Dh1Derive(p) => {
            is_nonzero_null(&p.other_info_presence) || is_nonzero_null(&p.public_data_presence)
        }
        P::X942Dh2Derive(p) => {
            is_nonzero_null(&p.other_info_presence)
                || is_nonzero_null(&p.public_data_presence)
                || is_nonzero_null(&p.public_data2_presence)
        }
        P::X942MqvDerive(p) => {
            is_nonzero_null(&p.other_info_presence)
                || is_nonzero_null(&p.public_data_presence)
                || is_nonzero_null(&p.public_data2_presence)
        }
        P::Hkdf(p) => is_nonzero_null(&p.salt_presence) || is_nonzero_null(&p.info_presence),
        P::Eddsa(p) => is_nonzero_null(&p.context_data_presence),
        P::Gostr3410Derive(p) => {
            is_nonzero_null(&p.public_data_presence) || is_nonzero_null(&p.ukm_presence)
        }
        P::KeaDerive(p) => {
            is_nonzero_null(&p.random_a_presence)
                || is_nonzero_null(&p.random_b_presence)
                || is_nonzero_null(&p.public_data_presence)
        }
        P::EcdhAesKeyWrap(p) => is_nonzero_null(&p.shared_data_presence),
        P::RsaAesKeyWrap(p) => is_nonzero_null(&p.oaep_params.source_data_presence),
        P::Gostr3410KeyWrap(p) => {
            is_nonzero_null(&p.wrap_oid_presence) || is_nonzero_null(&p.ukm_presence)
        }
        P::KeyWrapSetOaep(p) => is_nonzero_null(&p.x_presence),
        P::Pbe(p) => {
            is_nonzero_null(&p.init_vector_presence)
                || is_nonzero_null(&p.password_presence)
                || is_nonzero_null(&p.salt_presence)
        }
        P::Pkcs5Pbkd2(p) => {
            is_nonzero_null(&p.salt_source_data_presence)
                || is_nonzero_null(&p.prf_data_presence)
                || is_nonzero_null(&p.password_presence)
        }
        P::TlsPrf(p) => is_nonzero_null(&p.seed_presence) || is_nonzero_null(&p.label_presence),
        P::TlsKdf(p) => {
            is_nonzero_null(&p.label_presence)
                || is_nonzero_null(&p.context_data_presence)
                || ssl_random_has_nonzero_null(&p.random_info)
        }
        P::Ssl3MasterKeyDerive(p) => ssl_random_has_nonzero_null(&p.random_info),
        P::Tls12MasterKeyDerive(p) => ssl_random_has_nonzero_null(&p.random_info),
        P::Tls12ExtendedMasterKeyDerive(p) => is_nonzero_null(&p.session_hash_presence),
        P::Ssl3KeyMat(p) => {
            is_nonzero_null(&p.client_iv_presence)
                || is_nonzero_null(&p.server_iv_presence)
                || ssl_random_has_nonzero_null(&p.random_info)
        }
        P::WtlsMasterKeyDerive(p) => wtls_random_has_nonzero_null(&p.random_info),
        P::WtlsPrf(p) => is_nonzero_null(&p.seed_presence) || is_nonzero_null(&p.label_presence),
        P::WtlsKeyMat(p) => {
            is_nonzero_null(&p.iv_presence) || wtls_random_has_nonzero_null(&p.random_info)
        }
        P::IkePrfDerive(p) => is_nonzero_null(&p.ni_presence) || is_nonzero_null(&p.nr_presence),
        P::Ike1PrfDerive(p) => {
            is_nonzero_null(&p.ckyi_presence) || is_nonzero_null(&p.ckyr_presence)
        }
        P::Ike1ExtendedDerive(p) => is_nonzero_null(&p.extra_data_presence),
        P::Ike2PrfPlusDerive(p) => is_nonzero_null(&p.seed_data_presence),
        P::Sp800108Kdf(p) => {
            sp800_108_data_has_nonzero_null(&p.data_params_presence)
                || sp800_108_keys_has_nonzero_null(&p.additional_derived_keys_presence)
        }
        P::Sp800108FeedbackKdf(p) => {
            sp800_108_data_has_nonzero_null(&p.data_params_presence)
                || is_nonzero_null(&p.iv_presence)
                || sp800_108_keys_has_nonzero_null(&p.additional_derived_keys_presence)
        }
        P::X3dhInitiate(_) => false,
        P::X3dhRespond(_) => false,
        P::X2RatchetInitialize(_) => false,
        P::X2RatchetRespond(_) => false,
        P::Otp(p) => {
            is_nonzero_null_array(&p.params_presence)
                || p.params_presence
                    .as_present()
                    .is_some_and(|elems| elems.iter().any(|e| is_nonzero_null(&e.value_presence)))
        }
        P::Kip(p) => {
            is_nonzero_null(&p.seed_presence)
                || p.mechanism
                    .as_deref()
                    .is_some_and(|m| mechanism_has_nonzero_null(m, depth + 1, cx))
        }
        P::CmsSig(p) => {
            mechanism_has_nonzero_null(&p.signing_mechanism, depth + 1, cx)
                || mechanism_has_nonzero_null(&p.digest_mechanism, depth + 1, cx)
        }
        P::SkipjackPrivateWrap(p) => {
            is_nonzero_null(&p.password_presence)
                || is_nonzero_null(&p.public_data_presence)
                || is_nonzero_null(&p.random_a_presence)
                || is_nonzero_null(&p.prime_p_presence)
                || is_nonzero_null(&p.base_g_presence)
                || is_nonzero_null(&p.subprime_q_presence)
        }
        P::SkipjackRelayx(p) => {
            is_nonzero_null(&p.old_wrapped_x_presence)
                || is_nonzero_null(&p.old_password_presence)
                || is_nonzero_null(&p.old_public_data_presence)
                || is_nonzero_null(&p.old_random_a_presence)
                || is_nonzero_null(&p.new_password_presence)
                || is_nonzero_null(&p.new_public_data_presence)
                || is_nonzero_null(&p.new_random_a_presence)
        }
        P::MacGeneral(_) => false,
        P::ObjectHandle(_) => false,
        P::Extract(_) => false,
        P::SignAdditionalContext(p) => is_nonzero_null(&p.context_presence),
        P::Kmac(p) => is_nonzero_null(&p.customization_string_presence),
        P::MuGen(p) => is_nonzero_null(&p.tr_presence) || is_nonzero_null(&p.context_presence),
        P::KeyDerivationString(p) => is_nonzero_null(&p.data_presence),
        // Unreachable from the typed policy arm (it matches typed
        // variants only) and from nested descent (which routes envelopes
        // through `mechanism_has_nonzero_null`): fail closed so a future
        // caller cannot silently pass an envelope through here.
        P::Raw(_) | P::Flat(_) | P::Null { .. } => true,
        P::Ecies(p) => {
            mechanism_has_nonzero_null(&p.derivation_mechanism, depth + 1, cx)
                || mechanism_has_nonzero_null(&p.encryption_mechanism, depth + 1, cx)
                || mechanism_has_nonzero_null(&p.mac_mechanism, depth + 1, cx)
        }
        P::AesCmacKeyDerivation(_) => false,
        P::Dilithium(_) => false,
        P::Kyber(_) => false,
        P::HdKeyDerive(_) => false,
        P::VendorObjectExtract(_) => false,
        P::VendorObjectInsert(_) => false,
    }
}

/// F2 helper: nonzero NULLs in an SSL random-data pair.
fn ssl_random_has_nonzero_null(r: &SslRandomData) -> bool {
    is_nonzero_null(&r.client_random_presence) || is_nonzero_null(&r.server_random_presence)
}

/// F2 helper: nonzero NULLs in a WTLS random-data pair.
fn wtls_random_has_nonzero_null(r: &WtlsRandomData) -> bool {
    is_nonzero_null(&r.client_random_presence) || is_nonzero_null(&r.server_random_presence)
}

/// F2 helper: a nonzero NULL data-params array, or a NULL-nonzero value
/// in any present element.
fn sp800_108_data_has_nonzero_null(data: &PointerArray<PrfDataParam>) -> bool {
    is_nonzero_null_array(data)
        || data
            .as_present()
            .is_some_and(|elems| elems.iter().any(|e| is_nonzero_null(&e.value_presence)))
}

/// F2 helper: a nonzero NULL derived-keys array, or a nonzero NULL
/// template array in any present element (templates carry attributes,
/// which hold no NULLs — only the array count is policed).
fn sp800_108_keys_has_nonzero_null(keys: &PointerArray<Sp800108DerivedKey>) -> bool {
    is_nonzero_null_array(keys)
        || keys
            .as_present()
            .is_some_and(|elems| elems.iter().any(|k| is_nonzero_null_array(&k.template_presence)))
}

/// Clone `mechanism` with every embedded object-handle field zeroed, for
/// the [`ValidatedMechanismParams::substitute_handles`] debug assertion.
///
/// Exhaustive over `CkMechanismParams` by construction (no wildcard): the
/// handle-bearing list mirrors the server remapper
/// (`crates/server/src/server/grpc_service/mechanism_handles.rs`) — a new
/// variant fails to compile here until classified, so the two lists cannot
/// silently drift. SP800-108 byte-encoded key-handle values are zeroed
/// (lengths preserved) so its dedicated substitution compares equal.
/// R19 output-envelope consistency (S2 §6): every set null bit agrees
/// with its zeroed scalars ([`check_null_bit_pair`]). Presence peers
/// are non-contradictory by construction and need no validation; the
/// R16/R18 legacy/agreement checks are gone with the dual
/// representation. Exhaustive with no catch-all, so a future variant
/// cannot silently skip this gate (the compiler rejects the omission).
fn check_typed_presence(params: &CkMechanismParams) -> Result<(), CkRv> {
    match params {
        CkMechanismParams::TlsPrf(p) => {
            check_null_bit_pair(p.output.is_empty(), p.output_is_null)?;
            check_null_bit_pair(p.output_len == 0, p.output_len_is_null)
        }
        CkMechanismParams::Ssl3MasterKeyDerive(p) => {
            check_null_bit_pair(p.version_major == 0 && p.version_minor == 0, p.version_is_null)
        }
        CkMechanismParams::Tls12MasterKeyDerive(p) => {
            check_null_bit_pair(p.version_major == 0 && p.version_minor == 0, p.version_is_null)
        }
        CkMechanismParams::Tls12ExtendedMasterKeyDerive(p) => {
            check_null_bit_pair(p.version_major == 0 && p.version_minor == 0, p.version_is_null)
        }
        CkMechanismParams::Ssl3KeyMat(p) => check_null_bit_pair(
            p.client_mac_secret_handle.0 == 0
                && p.server_mac_secret_handle.0 == 0
                && p.client_key_handle.0 == 0
                && p.server_key_handle.0 == 0
                && p.client_iv_presence.as_present().map(|b| b.is_empty()).unwrap_or(true)
                && p.server_iv_presence.as_present().map(|b| b.is_empty()).unwrap_or(true),
            p.returned_key_material_is_null,
        ),
        CkMechanismParams::WtlsMasterKeyDerive(p) => {
            check_null_bit_pair(p.version == 0, p.version_is_null)
        }
        CkMechanismParams::WtlsPrf(p) => {
            check_null_bit_pair(p.output.is_empty(), p.output_is_null)?;
            check_null_bit_pair(p.output_len == 0, p.output_len_is_null)
        }
        CkMechanismParams::WtlsKeyMat(p) => check_null_bit_pair(
            p.mac_secret_handle.0 == 0
                && p.key_handle.0 == 0
                && p.iv_presence.as_present().map(|b| b.is_empty()).unwrap_or(true),
            p.returned_key_material_is_null,
        ),
        CkMechanismParams::Sp800108Kdf(p) => {
            if let Some(keys) = p.additional_derived_keys_presence.as_present() {
                for key in keys {
                    check_sp800108_derived_key(key)?;
                }
            }
            Ok(())
        }
        CkMechanismParams::Sp800108FeedbackKdf(p) => {
            if let Some(keys) = p.additional_derived_keys_presence.as_present() {
                for key in keys {
                    check_sp800108_derived_key(key)?;
                }
            }
            Ok(())
        }
        // Presence peers are non-contradictory by construction (no
        // validation needed), and scalar-only shapes carry nothing to
        // check: pass-through.
        CkMechanismParams::RsaPkcsOaep(_)
        | CkMechanismParams::Gcm(_)
        | CkMechanismParams::Ccm(_)
        | CkMechanismParams::GcmWrap(_)
        | CkMechanismParams::CcmWrap(_)
        | CkMechanismParams::Eddsa(_)
        | CkMechanismParams::KeyWrapSetOaep(_)
        | CkMechanismParams::Ecdh1Derive(_)
        | CkMechanismParams::Ecdh2Derive(_)
        | CkMechanismParams::EcmqvDerive(_)
        | CkMechanismParams::X942Dh1Derive(_)
        | CkMechanismParams::X942Dh2Derive(_)
        | CkMechanismParams::X942MqvDerive(_)
        | CkMechanismParams::Hkdf(_)
        | CkMechanismParams::Gostr3410Derive(_)
        | CkMechanismParams::Gostr3410KeyWrap(_)
        | CkMechanismParams::AesCbcEncryptData(_)
        | CkMechanismParams::DesCbcEncryptData(_)
        | CkMechanismParams::AriaCbcEncryptData(_)
        | CkMechanismParams::CamelliaCbcEncryptData(_)
        | CkMechanismParams::SeedCbcEncryptData(_)
        | CkMechanismParams::Rc5Cbc(_)
        | CkMechanismParams::ChaCha20(_)
        | CkMechanismParams::Salsa20(_)
        | CkMechanismParams::Salsa20ChaCha20Poly1305(_)
        | CkMechanismParams::Pkcs5Pbkd2(_)
        | CkMechanismParams::IkePrfDerive(_)
        | CkMechanismParams::Ike1PrfDerive(_)
        | CkMechanismParams::Ike1ExtendedDerive(_)
        | CkMechanismParams::Ike2PrfPlusDerive(_)
        | CkMechanismParams::KeyDerivationString(_)
        | CkMechanismParams::Kmac(_)
        | CkMechanismParams::Pbe(_)
        | CkMechanismParams::EcdhAesKeyWrap(_)
        | CkMechanismParams::RsaAesKeyWrap(_)
        | CkMechanismParams::MuGen(_)
        | CkMechanismParams::SignAdditionalContext(_)
        | CkMechanismParams::KeaDerive(_)
        | CkMechanismParams::TlsKdf(_)
        | CkMechanismParams::Otp(_)
        | CkMechanismParams::Kip(_)
        | CkMechanismParams::SkipjackPrivateWrap(_)
        | CkMechanismParams::SkipjackRelayx(_)
        | CkMechanismParams::RsaPkcsPss(_)
        | CkMechanismParams::Iv(_)
        | CkMechanismParams::Rc5(_)
        | CkMechanismParams::Rc5MacGeneral(_)
        | CkMechanismParams::Rc2MacGeneral(_)
        | CkMechanismParams::Xeddsa(_)
        | CkMechanismParams::TlsMac(_)
        | CkMechanismParams::AesCtr(_)
        | CkMechanismParams::CamelliaCtr(_)
        | CkMechanismParams::Rc2Cbc(_)
        | CkMechanismParams::MacGeneral(_)
        | CkMechanismParams::ObjectHandle(_)
        | CkMechanismParams::Extract(_)
        | CkMechanismParams::X3dhInitiate(_)
        | CkMechanismParams::X3dhRespond(_)
        | CkMechanismParams::X2RatchetInitialize(_)
        | CkMechanismParams::X2RatchetRespond(_)
        | CkMechanismParams::CmsSig(_)
        | CkMechanismParams::Ecies(_)
        | CkMechanismParams::AesCmacKeyDerivation(_)
        | CkMechanismParams::Dilithium(_)
        | CkMechanismParams::Kyber(_)
        | CkMechanismParams::HdKeyDerive(_)
        | CkMechanismParams::VendorObjectExtract(_)
        | CkMechanismParams::VendorObjectInsert(_) => Ok(()),
        // Decided by the outer arms (`None` never reaches here);
        // listed so a future variant cannot silently skip this gate.
        CkMechanismParams::Raw(_) | CkMechanismParams::Flat(_) | CkMechanismParams::Null { .. } => {
            Ok(())
        }
    }
}

fn normalized_for_handle_compare(mechanism: &CkMechanism) -> CkMechanism {
    let mut normalized = mechanism.clone();
    if let Some(params) = normalized.params.as_mut() {
        zero_embedded_handles(params);
    }
    normalized
}

/// PKCS#11 `CK_SP800_108_KEY_HANDLE` data-parameter type (`0x00000005`):
/// a SP800-108 `data_params` entry carrying the byte-encoded input key
/// handle. (Mirrors the server resolver's constant; kept in sync by the
/// SP800-108 substitution tests.)
pub(crate) const SP800_108_KEY_HANDLE_TYPE: u64 = 0x0000_0005;

/// Zero the byte-encoded key-handle values of SP800-108 `data_params`
/// entries (zero-filled, lengths preserved).
fn zero_sp800_108_key_handle_values(data_params: &mut [PrfDataParam]) {
    for data_param in data_params {
        if data_param.type_ != SP800_108_KEY_HANDLE_TYPE {
            continue;
        }
        // Zero in place (lengths preserved trivially); NULL entries
        // carry no bytes.
        if let PointerBytes::Present(bytes) = &mut data_param.value_presence {
            bytes.expose_mut(|b| b.fill(0));
        }
    }
}

fn zero_embedded_handles(params: &mut CkMechanismParams) {
    use CkMechanismParams as P;
    match params {
        P::Hkdf(p) => p.salt_key_handle.0 = 0,
        P::Ecdh2Derive(p) => p.private_data_handle.0 = 0,
        P::EcmqvDerive(p) => {
            p.private_data_handle.0 = 0;
            p.public_key_handle.0 = 0;
        }
        P::X942Dh2Derive(p) => p.private_data_handle.0 = 0,
        P::X942MqvDerive(p) => {
            p.private_data_handle.0 = 0;
            p.public_key_handle.0 = 0;
        }
        P::Gostr3410KeyWrap(p) => p.key_handle.0 = 0,
        P::Ssl3KeyMat(p) => {
            p.client_mac_secret_handle.0 = 0;
            p.server_mac_secret_handle.0 = 0;
            p.client_key_handle.0 = 0;
            p.server_key_handle.0 = 0;
        }
        P::WtlsKeyMat(p) => {
            p.mac_secret_handle.0 = 0;
            p.key_handle.0 = 0;
        }
        P::IkePrfDerive(p) => p.new_key_handle.0 = 0,
        P::Ike1PrfDerive(p) => {
            p.keygxy_handle.0 = 0;
            p.prev_key_handle.0 = 0;
        }
        P::Ike1ExtendedDerive(p) => p.keygxy_handle.0 = 0,
        P::Ike2PrfPlusDerive(p) => p.seed_key_handle.0 = 0,
        P::X3dhInitiate(p) => {
            p.peer_identity_handle.0 = 0;
            p.peer_prekey_handle.0 = 0;
            p.onetime_key_handle.0 = 0;
            p.own_identity_handle.0 = 0;
            p.own_ephemeral_handle.0 = 0;
        }
        P::X3dhRespond(p) => {
            p.identity_handle.0 = 0;
            p.prekey_handle.0 = 0;
            p.onetime_key_handle.0 = 0;
            p.initiator_identity_handle.0 = 0;
            p.initiator_ephemeral_handle.0 = 0;
        }
        P::X2RatchetInitialize(p) => {
            p.peer_public_prekey_handle.0 = 0;
            p.peer_public_identity_handle.0 = 0;
            p.own_public_identity_handle.0 = 0;
        }
        P::X2RatchetRespond(p) => {
            p.own_prekey_handle.0 = 0;
            p.initiator_identity_handle.0 = 0;
            p.own_identity_handle.0 = 0;
        }
        P::Kip(p) => {
            p.key_handle.0 = 0;
            if let Some(inner) = p.mechanism.as_mut().and_then(|nested| nested.params.as_mut()) {
                zero_embedded_handles(inner);
            }
        }
        P::Ecies(p) => {
            if let Some(inner) = p.derivation_mechanism.params.as_mut() {
                zero_embedded_handles(inner);
            }
            if let Some(inner) = p.encryption_mechanism.params.as_mut() {
                zero_embedded_handles(inner);
            }
            if let Some(inner) = p.mac_mechanism.params.as_mut() {
                zero_embedded_handles(inner);
            }
        }
        P::ObjectHandle(p) => p.handle.0 = 0,
        P::Kmac(p) => p.key_handle.0 = 0,
        P::MuGen(p) => p.key_handle.0 = 0,
        P::Kyber(p) => p.secret_handle.0 = 0,
        P::CmsSig(p) => {
            p.certificate_handle.0 = 0;
            if let Some(inner) = p.signing_mechanism.params.as_mut() {
                zero_embedded_handles(inner);
            }
            if let Some(inner) = p.digest_mechanism.params.as_mut() {
                zero_embedded_handles(inner);
            }
        }

        // SP800-108: the input key handle is byte-encoded inside
        // KEY_HANDLE `data_params` values (resolved by the server's
        // dedicated path); normalize those values (zero-filled, length
        // preserved) so handle substitution compares equal.
        P::Sp800108Kdf(p) => {
            if let Some(items) = p.data_params_presence.as_present_mut() {
                zero_sp800_108_key_handle_values(items);
            }
        }
        P::Sp800108FeedbackKdf(p) => {
            if let Some(items) = p.data_params_presence.as_present_mut() {
                zero_sp800_108_key_handle_values(items);
            }
        }

        // No embedded object handles.
        P::RsaPkcsPss(_)
        | P::RsaPkcsOaep(_)
        | P::Gcm(_)
        | P::Ecdh1Derive(_)
        | P::Iv(_)
        | P::Rc5(_)
        | P::Rc5MacGeneral(_)
        | P::Rc2MacGeneral(_)
        | P::Xeddsa(_)
        | P::TlsMac(_)
        | P::AesCtr(_)
        | P::CamelliaCtr(_)
        | P::Rc2Cbc(_)
        | P::Rc5Cbc(_)
        | P::AesCbcEncryptData(_)
        | P::DesCbcEncryptData(_)
        | P::AriaCbcEncryptData(_)
        | P::CamelliaCbcEncryptData(_)
        | P::SeedCbcEncryptData(_)
        | P::Ccm(_)
        | P::ChaCha20(_)
        | P::Salsa20(_)
        | P::Salsa20ChaCha20Poly1305(_)
        | P::GcmWrap(_)
        | P::CcmWrap(_)
        | P::X942Dh1Derive(_)
        | P::Eddsa(_)
        | P::Gostr3410Derive(_)
        | P::KeaDerive(_)
        | P::EcdhAesKeyWrap(_)
        | P::RsaAesKeyWrap(_)
        | P::KeyWrapSetOaep(_)
        | P::Pbe(_)
        | P::Pkcs5Pbkd2(_)
        | P::TlsPrf(_)
        | P::TlsKdf(_)
        | P::Ssl3MasterKeyDerive(_)
        | P::Tls12MasterKeyDerive(_)
        | P::Tls12ExtendedMasterKeyDerive(_)
        | P::WtlsMasterKeyDerive(_)
        | P::WtlsPrf(_)
        | P::Otp(_)
        | P::SkipjackPrivateWrap(_)
        | P::SkipjackRelayx(_)
        | P::MacGeneral(_)
        | P::Extract(_)
        | P::SignAdditionalContext(_)
        | P::KeyDerivationString(_)
        | P::Raw(_)
        | P::AesCmacKeyDerivation(_)
        | P::Dilithium(_)
        | P::HdKeyDerive(_)
        | P::VendorObjectExtract(_)
        | P::VendorObjectInsert(_)
        | P::Flat(_)
        | P::Null { .. } => {}
    }
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
    // Versioned representable parameters (S2 §3/§6; R9)
    Flat(FlatParams),
    Null {
        /// Declared length (`ulParameterLen`); no bytes cross.
        declared_len: u64,
        /// Threaded per-message `parameter_encoding_version`.
        version: u32,
    },
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
            private_data_len: 0,
            private_data_handle: CkObjectHandle(7),
            shared_data_presence: PointerBytes::present_cloned(&empty),
            public_data_presence: PointerBytes::present_copy(&[]),
            public_data2_presence: PointerBytes::present_copy(&[]),
        };
        assert_eq!(p.private_data_handle.0, 7);

        let p = EcmqvDeriveParams {
            kdf: CkKdf(1),
            private_data_len: 0,
            private_data_handle: CkObjectHandle(7),
            public_key_handle: CkObjectHandle(8),
            shared_data_presence: PointerBytes::present_cloned(&empty),
            public_data_presence: PointerBytes::present_copy(&[]),
            public_data2_presence: PointerBytes::present_copy(&[]),
        };
        assert_eq!((p.private_data_handle.0, p.public_key_handle.0), (7, 8));

        let p = X942Dh2DeriveParams {
            kdf: CkKdf(1),
            private_data_len: 0,
            private_data_handle: CkObjectHandle(7),
            other_info_presence: PointerBytes::present_cloned(&empty),
            public_data_presence: PointerBytes::present_copy(&[]),
            public_data2_presence: PointerBytes::present_copy(&[]),
        };
        assert_eq!(p.private_data_handle.0, 7);

        let p = X942MqvDeriveParams {
            kdf: CkKdf(1),
            private_data_len: 0,
            private_data_handle: CkObjectHandle(7),
            public_key_handle: CkObjectHandle(8),
            other_info_presence: PointerBytes::present_cloned(&empty),
            public_data_presence: PointerBytes::present_copy(&[]),
            public_data2_presence: PointerBytes::present_copy(&[]),
        };
        assert_eq!((p.private_data_handle.0, p.public_key_handle.0), (7, 8));

        let p = HkdfParams {
            extract: true,
            expand: true,
            prf_hash_mechanism: CkMechanismType(0x250),
            salt_type: 0,
            salt_key_handle: CkObjectHandle(9),
            salt_presence: PointerBytes::present_cloned(&empty),
            info_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!(p.salt_key_handle.0, 9);

        let p = Gostr3410KeyWrapParams {
            key_handle: CkObjectHandle(9),
            wrap_oid_presence: PointerBytes::present_copy(&[]),
            ukm_presence: PointerBytes::present_copy(&[]),
        };
        assert_eq!(p.key_handle.0, 9);

        let p = Ssl3KeyMatParams {
            mac_size_bits: 0,
            key_size_bits: 0,
            iv_size_bits: 0,
            is_export: false,
            random_info: SslRandomData {
                client_random_presence: PointerBytes::present_copy(&[]),
                server_random_presence: PointerBytes::present_copy(&[]),
            },
            prf_hash_mechanism: CkMechanismType(0),
            client_mac_secret_handle: CkObjectHandle(1),
            server_mac_secret_handle: CkObjectHandle(2),
            client_key_handle: CkObjectHandle(3),
            server_key_handle: CkObjectHandle(4),
            client_iv_presence: PointerBytes::present_cloned(&empty),
            server_iv_presence: PointerBytes::present_cloned(&empty),
            returned_key_material_is_null: false,
        };
        assert_eq!(p.server_key_handle.0, 4);

        let p = WtlsKeyMatParams {
            digest_mechanism: CkMechanismType(0),
            mac_size_bits: 0,
            key_size_bits: 0,
            iv_size_bits: 0,
            sequence_number: 0,
            is_export: false,
            random_info: WtlsRandomData {
                client_random_presence: PointerBytes::present_copy(&[]),
                server_random_presence: PointerBytes::present_copy(&[]),
            },
            mac_secret_handle: CkObjectHandle(5),
            key_handle: CkObjectHandle(6),
            iv_presence: PointerBytes::present_cloned(&empty),
            returned_key_material_is_null: false,
        };
        assert_eq!((p.mac_secret_handle.0, p.key_handle.0), (5, 6));

        let p = IkePrfDeriveParams {
            prf_mechanism: CkMechanismType(0),
            data_as_key: false,
            rekey: false,
            new_key_handle: CkObjectHandle(10),
            ni_presence: PointerBytes::present_cloned(&empty),
            nr_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!(p.new_key_handle.0, 10);

        let p = Ike1PrfDeriveParams {
            prf_mechanism: CkMechanismType(0),
            has_prev_key: false,
            keygxy_handle: CkObjectHandle(11),
            prev_key_handle: CkObjectHandle(12),
            key_number: 0,
            ckyi_presence: PointerBytes::present_cloned(&empty),
            ckyr_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!((p.keygxy_handle.0, p.prev_key_handle.0), (11, 12));

        let p = Ike1ExtendedDeriveParams {
            prf_mechanism: CkMechanismType(0),
            has_keygxy: false,
            keygxy_handle: CkObjectHandle(11),
            extra_data_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!(p.keygxy_handle.0, 11);

        let p = Ike2PrfPlusDeriveParams {
            prf_mechanism: CkMechanismType(0),
            has_seed_key: false,
            seed_key_handle: CkObjectHandle(13),
            seed_data_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!(p.seed_key_handle.0, 13);

        let p = Sp800108DerivedKey {
            key_handle: CkObjectHandle(14),
            template_presence: PointerArray::present(vec![]),
            ph_key_is_null: false,
        };
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
            mechanism: Some(Box::new(mech())),
            key_handle: CkObjectHandle(37),
            seed_presence: PointerBytes::present_cloned(&empty),
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
            customization_string_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!(p.key_handle.0, 40);

        let p = MuGenParams {
            key_handle: CkObjectHandle(41),
            tr_presence: PointerBytes::present_cloned(&empty),
            context_presence: PointerBytes::present_cloned(&empty),
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
            salt_key_handle: CkObjectHandle(0),
            salt_presence: PointerBytes::present_cloned(&empty),
            info_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!(p.prf_hash_mechanism.0, 0x250);

        let p = TlsKdfParams {
            prf_mechanism: sha256,
            random_info: SslRandomData {
                client_random_presence: PointerBytes::present_copy(&[]),
                server_random_presence: PointerBytes::present_copy(&[]),
            },
            label_presence: PointerBytes::present_cloned(&empty),
            context_data_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!(p.prf_mechanism.0, 0x250);

        let p = Tls12MasterKeyDeriveParams {
            random_info: SslRandomData {
                client_random_presence: PointerBytes::present_copy(&[]),
                server_random_presence: PointerBytes::present_copy(&[]),
            },
            version_major: 3,
            version_minor: 3,
            prf_hash_mechanism: sha256,
            version_is_null: false,
        };
        assert_eq!(p.prf_hash_mechanism.0, 0x250);

        let p = Tls12ExtendedMasterKeyDeriveParams {
            prf_hash_mechanism: sha256,
            version_major: 3,
            version_minor: 3,
            session_hash_presence: PointerBytes::present_copy(&[]),
            version_is_null: false,
        };
        assert_eq!(p.prf_hash_mechanism.0, 0x250);

        let p = Ssl3KeyMatParams {
            mac_size_bits: 0,
            key_size_bits: 0,
            iv_size_bits: 0,
            is_export: false,
            random_info: SslRandomData {
                client_random_presence: PointerBytes::present_copy(&[]),
                server_random_presence: PointerBytes::present_copy(&[]),
            },
            prf_hash_mechanism: sha256,
            client_mac_secret_handle: CkObjectHandle(0),
            server_mac_secret_handle: CkObjectHandle(0),
            client_key_handle: CkObjectHandle(0),
            server_key_handle: CkObjectHandle(0),
            client_iv_presence: PointerBytes::present_cloned(&empty),
            server_iv_presence: PointerBytes::present_cloned(&empty),
            returned_key_material_is_null: false,
        };
        assert_eq!(p.prf_hash_mechanism.0, 0x250);

        let p = WtlsMasterKeyDeriveParams {
            digest_mechanism: sha256,
            random_info: WtlsRandomData {
                client_random_presence: PointerBytes::present_copy(&[]),
                server_random_presence: PointerBytes::present_copy(&[]),
            },
            version: 0,
            version_is_null: false,
        };
        assert_eq!(p.digest_mechanism.0, 0x250);

        let p = WtlsPrfParams {
            digest_mechanism: sha256,
            output_len: 0,
            output: empty.clone(),
            seed_presence: PointerBytes::present_cloned(&empty),
            label_presence: PointerBytes::present_cloned(&empty),
            output_is_null: false,
            output_len_is_null: false,
        };
        assert_eq!(p.digest_mechanism.0, 0x250);

        let p = WtlsKeyMatParams {
            digest_mechanism: sha256,
            mac_size_bits: 0,
            key_size_bits: 0,
            iv_size_bits: 0,
            sequence_number: 0,
            is_export: false,
            random_info: WtlsRandomData {
                client_random_presence: PointerBytes::present_copy(&[]),
                server_random_presence: PointerBytes::present_copy(&[]),
            },
            mac_secret_handle: CkObjectHandle(0),
            key_handle: CkObjectHandle(0),
            iv_presence: PointerBytes::present_cloned(&empty),
            returned_key_material_is_null: false,
        };
        assert_eq!(p.digest_mechanism.0, 0x250);

        let p = IkePrfDeriveParams {
            prf_mechanism: sha256,
            data_as_key: false,
            rekey: false,
            new_key_handle: CkObjectHandle(0),
            ni_presence: PointerBytes::present_cloned(&empty),
            nr_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!(p.prf_mechanism.0, 0x250);

        let p = Ike1PrfDeriveParams {
            prf_mechanism: sha256,
            has_prev_key: false,
            keygxy_handle: CkObjectHandle(0),
            prev_key_handle: CkObjectHandle(0),
            key_number: 0,
            ckyi_presence: PointerBytes::present_cloned(&empty),
            ckyr_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!(p.prf_mechanism.0, 0x250);

        let p = Ike1ExtendedDeriveParams {
            prf_mechanism: sha256,
            has_keygxy: false,
            keygxy_handle: CkObjectHandle(0),
            extra_data_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!(p.prf_mechanism.0, 0x250);

        let p = Ike2PrfPlusDeriveParams {
            prf_mechanism: sha256,
            has_seed_key: false,
            seed_key_handle: CkObjectHandle(0),
            seed_data_presence: PointerBytes::present_cloned(&empty),
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

        let p = SignAdditionalContext {
            hedge_variant: 0,
            hash: sha256,
            context_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!(p.hash.0, 0x250);

        let p = Sp800108KdfParams {
            prf_type: sha256,
            data_params_presence: PointerArray::present(vec![]),
            additional_derived_keys_presence: PointerArray::present(vec![]),
        };
        assert_eq!(p.prf_type.0, 0x250);

        let p = Sp800108FeedbackKdfParams {
            prf_type: sha256,
            data_params_presence: PointerArray::present(vec![]),
            iv_presence: PointerBytes::present_copy(&[]),
            additional_derived_keys_presence: PointerArray::present(vec![]),
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
            source_data_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!((p.mgf.0, p.source.0), (1, 1));

        let p = GcmWrapParams {
            iv_fixed_bits: 0,
            iv_generator: CkGeneratorFunction::GENERATE_RANDOM,
            tag_bits: 0,
            iv_presence: PointerBytes::present_copy(&[]),
            aad_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!(p.iv_generator.0, 3);

        let p = CcmWrapParams {
            data_len: 0,
            nonce_fixed_bits: 0,
            nonce_generator: CkGeneratorFunction::NO_GENERATE,
            mac_len: 0,
            nonce_presence: PointerBytes::present_copy(&[]),
            aad_presence: PointerBytes::present_cloned(&empty),
        };
        assert_eq!(p.nonce_generator.0, 0);

        let p = Ecdh1DeriveParams {
            kdf: CkKdf::SHA256_KDF,
            shared_data_presence: PointerBytes::present_cloned(&empty),
            public_data_presence: PointerBytes::present_copy(&[]),
        };
        assert_eq!(p.kdf.0, 6);

        let p = Pkcs5Pbkd2Params {
            salt_source: CkPbkdf2SaltSource::SALT_SPECIFIED,
            iterations: 0,
            prf: CkPbkdf2Prf::HMAC_SHA256,
            salt_source_data_presence: PointerBytes::present_cloned(&empty),
            prf_data_presence: PointerBytes::present_cloned(&empty),
            password_presence: PointerBytes::present_cloned(&empty),
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
            assert_eq!(actual.0, expected);
        }
    }

    // ------------------------------------------------------------------
    // Zeroize / ZeroizeOnDrop on password-bearing structs
    // ------------------------------------------------------------------

    #[test]
    fn pbe_params_zeroizes_password_on_explicit_call() {
        use zeroize::Zeroize;
        let mut p = PbeParams {
            iteration: 4096,
            init_vector_presence: PointerBytes::present_copy(&[1u8; 16]),
            password_presence: PointerBytes::present_copy(&[0xAAu8; 32]),
            salt_presence: PointerBytes::present_copy(&[2u8; 16]),
        };
        p.zeroize();
        // After Zeroize::zeroize() Vec<u8> fields are cleared/truncated.
        assert!(
            p.password_presence.as_present().unwrap().expose(|b| b.iter().all(|&x| x == 0)),
            "password bytes not zeroed"
        );
        assert!(
            p.init_vector_presence.as_present().unwrap().expose(|b| b.iter().all(|&x| x == 0)),
            "iv bytes not zeroed"
        );
    }

    #[test]
    fn pkcs5_pbkd2_params_zeroizes_password() {
        use zeroize::Zeroize;
        let mut p = Pkcs5Pbkd2Params {
            salt_source: CkPbkdf2SaltSource::SALT_SPECIFIED,
            iterations: 10_000,
            prf: CkPbkdf2Prf(0x40),
            salt_source_data_presence: PointerBytes::present_copy(&[1u8; 8]),
            prf_data_presence: PointerBytes::present_copy(&[2u8; 4]),
            password_presence: PointerBytes::present_copy(b"hunter2"),
        };
        p.zeroize();
        assert!(p.password_presence.as_present().unwrap().expose(|b| b.iter().all(|&x| x == 0)));
    }

    #[test]
    fn skipjack_params_zeroize_passwords() {
        use zeroize::Zeroize;
        let mut a = SkipjackPrivateWrapParams {
            password_length: 10,
            password_presence: PointerBytes::present_copy(b"old-secret"),
            public_data_presence: PointerBytes::present_copy(&[]),
            random_a_presence: PointerBytes::present_copy(&[]),
            prime_p_presence: PointerBytes::present_copy(&[]),
            base_g_presence: PointerBytes::present_copy(&[]),
            subprime_q_presence: PointerBytes::present_copy(&[]),
        };
        a.zeroize();
        assert!(a.password_presence.as_present().unwrap().expose(|b| b.iter().all(|&x| x == 0)));

        let mut b = SkipjackRelayxParams {
            old_wrapped_x_presence: PointerBytes::present_copy(&[]),
            old_password_presence: PointerBytes::present_copy(b"old-pin"),
            old_public_data_presence: PointerBytes::present_copy(&[]),
            old_random_a_presence: PointerBytes::present_copy(&[]),
            new_password_presence: PointerBytes::present_copy(b"new-pin"),
            new_public_data_presence: PointerBytes::present_copy(&[]),
            new_random_a_presence: PointerBytes::present_copy(&[]),
        };
        b.zeroize();
        assert!(
            b.old_password_presence.as_present().unwrap().expose(|b| b.iter().all(|&x| x == 0))
        );
        assert!(
            b.new_password_presence.as_present().unwrap().expose(|b| b.iter().all(|&x| x == 0))
        );
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
            iteration: 4096,
            init_vector_presence: PointerBytes::present_copy(&[1u8; 16]),
            password_presence: PointerBytes::present_copy(b"hunter2"),
            salt_presence: PointerBytes::present_copy(&[2u8; 16]),
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
            iterations: 1,
            prf: CkPbkdf2Prf(0),
            salt_source_data_presence: PointerBytes::present_copy(&[]),
            prf_data_presence: PointerBytes::present_copy(&[]),
            password_presence: PointerBytes::present_copy(b"correct horse battery staple"),
        };
        let formatted = format!("{p:?}");
        assert!(!formatted.contains("correct horse"), "password leaked: {formatted}");
        assert!(formatted.contains("REDACTED"));
    }

    #[test]
    fn skipjack_debug_redacts_passwords() {
        let a = SkipjackPrivateWrapParams {
            password_length: 8,
            password_presence: PointerBytes::present_copy(b"alpha-pw"),
            public_data_presence: PointerBytes::present_copy(&[]),
            random_a_presence: PointerBytes::present_copy(&[]),
            prime_p_presence: PointerBytes::present_copy(&[]),
            base_g_presence: PointerBytes::present_copy(&[]),
            subprime_q_presence: PointerBytes::present_copy(&[]),
        };
        let af = format!("{a:?}");
        assert!(!af.contains("alpha-pw"));
        assert!(af.contains("REDACTED"));

        let b = SkipjackRelayxParams {
            old_wrapped_x_presence: PointerBytes::present_copy(&[]),
            old_password_presence: PointerBytes::present_copy(b"old-pw"),
            old_public_data_presence: PointerBytes::present_copy(&[]),
            old_random_a_presence: PointerBytes::present_copy(&[]),
            new_password_presence: PointerBytes::present_copy(b"new-pw"),
            new_public_data_presence: PointerBytes::present_copy(&[]),
            new_random_a_presence: PointerBytes::present_copy(&[]),
        };
        let bf = format!("{b:?}");
        assert!(!bf.contains("old-pw"));
        assert!(!bf.contains("new-pw"));
    }

    // W1-C9-13: mechanism flag consts are Self-typed (CkMechanismType
    // convention), combine with `|`, and keep their spec aliases.
    #[test]
    fn w1_c9_13_mechanism_flag_consts_are_self_typed() {
        let digest: CkMechanismFlags = CkMechanismFlags::DIGEST;
        assert_eq!(digest.0, 0x0000_0400);
        let combined: CkMechanismFlags = CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY;
        assert_eq!(combined.0, 0x0000_2800);
        assert_eq!(CkMechanismFlags::MULTI_MESSGE, CkMechanismFlags::MULTI_MESSAGE);
        assert_eq!(CkMechanismFlags::EC_NAMEDCURVE, CkMechanismFlags::EC_OID);
    }

    // W1-C9-17: WtlsKeyMatParams.iv is SecretBytes (Ssl3KeyMatParams
    // convention); Debug never prints the IV bytes.
    #[test]
    fn w1_c9_17_wtls_iv_is_secret_bytes() {
        let p = WtlsKeyMatParams {
            digest_mechanism: CkMechanismType(0),
            mac_size_bits: 0,
            key_size_bits: 0,
            iv_size_bits: 64,
            sequence_number: 0,
            is_export: false,
            random_info: WtlsRandomData {
                client_random_presence: PointerBytes::present_copy(&[]),
                server_random_presence: PointerBytes::present_copy(&[]),
            },
            mac_secret_handle: CkObjectHandle(0),
            key_handle: CkObjectHandle(0),
            iv_presence: PointerBytes::present_copy(b"super-secret-iv"),
            returned_key_material_is_null: false,
        };
        assert_eq!(p.iv_presence.as_present().unwrap().len(), 15);
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("super-secret-iv"), "IV leaked into Debug: {dbg}");
        // Sibling convention: same redacted shape as the SSL3 IVs.
        let ssl3 = Ssl3KeyMatParams {
            mac_size_bits: 0,
            key_size_bits: 0,
            iv_size_bits: 0,
            is_export: false,
            random_info: SslRandomData {
                client_random_presence: PointerBytes::present_copy(&[]),
                server_random_presence: PointerBytes::present_copy(&[]),
            },
            prf_hash_mechanism: CkMechanismType(0),
            client_mac_secret_handle: CkObjectHandle(0),
            server_mac_secret_handle: CkObjectHandle(0),
            client_key_handle: CkObjectHandle(0),
            server_key_handle: CkObjectHandle(0),
            client_iv_presence: PointerBytes::present_copy(b"super-secret-iv"),
            server_iv_presence: PointerBytes::present_copy(&[]),
            returned_key_material_is_null: false,
        };
        assert!(!format!("{ssl3:?}").contains("super-secret-iv"));
    }
}

// ---------------------------------------------------------------------------
// R9: representable mechanism parameters — presence types, Flat/Null domain,
// validated newtype (S2 §6 + §10). Tests first (TDD RED): these reference
// the new API before it exists.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pointer_bytes_tests {
    use super::*;

    // Non-contradiction core: Present([]) (non-NULL/zero) and Null{0} are
    // distinct values that never conflate, in either direction.
    #[test]
    fn present_empty_and_null_zero_never_conflate() {
        let present = PointerBytes::Present(SecretBytes::copy_from_slice(b""));
        let null = PointerBytes::Null { declared_len: 0 };
        assert_ne!(present, null);
        assert!(!present.is_null());
        assert!(null.is_null());
        assert_eq!(present.declared_len(), 0);
        assert_eq!(null.declared_len(), 0);
        assert!(present.as_present().is_some());
        assert!(null.as_present().is_none());
    }

    #[test]
    fn presence_and_bytes_cannot_disagree() {
        let payload = vec![0xA5u8; 37];
        let present = PointerBytes::Present(SecretBytes::copy_from_slice(&payload));
        assert!(!present.is_null());
        assert_eq!(present.declared_len(), 37);
        present.as_present().unwrap().expose(|b| assert_eq!(b, payload.as_slice()));

        // NULL-with-bytes is unrepresentable: the Null arm carries no byte
        // accessor at all (this exhaustive match proves the arm shape).
        let null = PointerBytes::Null { declared_len: 41 };
        assert!(null.is_null());
        assert_eq!(null.declared_len(), 41);
        match &null {
            PointerBytes::Present(_) => panic!("Null must not match Present"),
            PointerBytes::Null { declared_len } => assert_eq!(*declared_len, 41),
        }
        // Exhaustive match over a Present value: no wildcard, so any future
        // contradictory variant breaks this test at compile time.
        match &present {
            PointerBytes::Present(bytes) => assert_eq!(bytes.len(), 37),
            PointerBytes::Null { .. } => panic!("Present must not match Null"),
        }
    }

    #[test]
    fn debug_redacts_present_bytes() {
        let secret = PointerBytes::Present(SecretBytes::copy_from_slice(b"super-secret-iv"));
        let dbg = format!("{secret:?}");
        assert!(!dbg.contains("super-secret-iv"), "payload leaked into Debug: {dbg}");
    }

    #[test]
    fn clone_and_eq_follow_presence() {
        let a = PointerBytes::Present(SecretBytes::copy_from_slice(b"AB"));
        assert_eq!(a.clone(), a);
        assert_ne!(
            a,
            PointerBytes::Present(SecretBytes::copy_from_slice(b"AC")),
            "byte inequality must be observable"
        );
        assert_eq!(PointerBytes::Null { declared_len: 7 }, PointerBytes::Null { declared_len: 7 });
        assert_ne!(PointerBytes::Null { declared_len: 7 }, PointerBytes::Null { declared_len: 8 });
    }
}

#[cfg(test)]
mod fixed_pointer_bytes_tests {
    use super::*;

    #[test]
    fn present_enforces_exact_length_by_construction() {
        // The only Present constructor takes [u8; N]: a wrong length cannot
        // be expressed (this would fail to compile with 15 or 17 bytes).
        let fixed = FixedPointerBytes::present([0xA5u8; 16]);
        assert!(!fixed.is_null());
        assert_eq!(fixed.declared_len(), 16);
        fixed.as_pointer_bytes().as_present().unwrap().expose(|b| {
            assert_eq!(b, &[0xA5u8; 16]);
        });
    }

    #[test]
    fn null_carries_only_length() {
        let null: FixedPointerBytes<16> = FixedPointerBytes::null(9);
        assert!(null.is_null());
        assert_eq!(null.declared_len(), 9);
        assert!(null.as_pointer_bytes().as_present().is_none());
    }

    #[test]
    fn present_empty_array_and_null_zero_never_conflate() {
        let present = FixedPointerBytes::present([]);
        let null: FixedPointerBytes<0> = FixedPointerBytes::null(0);
        assert_ne!(present, null);
        assert!(!present.is_null());
        assert!(null.is_null());
    }

    #[test]
    fn debug_redacts_fixed_bytes() {
        let fixed = FixedPointerBytes::present(*b"super-secret-iv!!");
        let dbg = format!("{fixed:?}");
        assert!(!dbg.contains("super-secret-iv"), "payload leaked into Debug: {dbg}");
    }
}

#[cfg(test)]
mod output_pointer_bytes_tests {
    use super::*;

    #[test]
    fn capacity_and_nullness_cannot_disagree() {
        // Output buffers carry capacity, never input bytes: there is no
        // byte field to contradict the presence arm.
        let present = OutputPointerBytes::Present { capacity: 64 };
        assert!(!present.is_null());
        assert_eq!(present.capacity_or_len(), 64);
        match present {
            OutputPointerBytes::Present { capacity } => assert_eq!(capacity, 64),
            OutputPointerBytes::Null { .. } => panic!("Present must not match Null"),
        }
        let null = OutputPointerBytes::Null { declared_len: 64 };
        assert!(null.is_null());
        assert_eq!(null.capacity_or_len(), 64);
        assert_ne!(present, null);
        match null {
            OutputPointerBytes::Present { .. } => panic!("Null must not match Present"),
            OutputPointerBytes::Null { declared_len } => assert_eq!(declared_len, 64),
        }
    }
}

#[cfg(test)]
mod flat_null_domain_tests {
    use super::*;
    use crate::shape_descriptors::ParamAbi;

    #[test]
    fn transport_version_is_one() {
        assert_eq!(MECHANISM_PARAMETER_TRANSPORT_VERSION, 1);
    }

    #[test]
    fn flat_params_threads_wire_fields() {
        let flat = FlatParams {
            bytes: SecretBytes::copy_from_slice(b"AB"),
            declared_len: 2,
            source_abi: Some(ParamAbi::Lp64NativeLe),
            fingerprint: 0x0102_0304_0506_0708,
            version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
        };
        let params = CkMechanismParams::Flat(flat);
        let CkMechanismParams::Flat(back) = params else { panic!("must match Flat") };
        assert_eq!(back.declared_len, 2);
        assert_eq!(back.source_abi, Some(ParamAbi::Lp64NativeLe));
        assert_eq!(back.fingerprint, 0x0102_0304_0506_0708);
        assert_eq!(back.version, 1);
        back.bytes.expose(|b| assert_eq!(b, b"AB"));
    }

    #[test]
    fn null_variant_carries_length_and_version_only() {
        let params = CkMechanismParams::Null { declared_len: 7, version: 1 };
        let CkMechanismParams::Null { declared_len, version } = params else {
            panic!("must match Null")
        };
        assert_eq!((declared_len, version), (7, 1));
    }

    #[test]
    fn flat_debug_redacts_bytes_but_shows_shape() {
        let flat = FlatParams {
            bytes: SecretBytes::copy_from_slice(b"super-secret-flat"),
            declared_len: 17,
            source_abi: Some(ParamAbi::Lp64NativeLe),
            fingerprint: 0xDEAD_BEEF,
            version: 1,
        };
        let dbg = format!("{flat:?}");
        assert!(!dbg.contains("super-secret-flat"), "payload leaked into Debug: {dbg}");
        assert!(dbg.contains("17"), "declared_len must stay visible: {dbg}");
    }
}

#[cfg(test)]
mod validated_params_tests {
    use super::*;
    use crate::mechanism_registry::{DiscoveryMode, MechanismRegistry};
    use crate::shape_descriptors::{
        ABI_EXEMPT_FINGERPRINT, Operation, OperationContext, ParamAbi, ShapeResolver,
    };
    use std::collections::{HashMap, HashSet};

    const AES_CBC: u64 = 0x0000_1082;
    const UNKNOWN_MECH: u64 = 0x0000_9999;

    fn registry_with_binding(mech: u64, shape: &str) -> MechanismRegistry {
        registry_with_bindings(&[(shape, mech)])
    }

    fn registry_with_bindings(bindings: &[(&str, u64)]) -> MechanismRegistry {
        let mut shapes = HashMap::new();
        for (shape, mech) in bindings {
            shapes.insert(*mech, (*shape).to_string());
        }
        MechanismRegistry::from_parts(
            shapes,
            HashSet::new(),
            HashSet::new(),
            DiscoveryMode::Transparent,
            "test".to_string(),
        )
    }

    fn empty_registry() -> MechanismRegistry {
        MechanismRegistry::from_parts(
            HashMap::new(),
            HashSet::new(),
            HashSet::new(),
            DiscoveryMode::Transparent,
            "test".to_string(),
        )
    }

    fn excluded_registry(mech: u64) -> MechanismRegistry {
        let mut excluded = HashSet::new();
        excluded.insert(mech);
        MechanismRegistry::from_parts(
            HashMap::new(),
            HashSet::new(),
            excluded,
            DiscoveryMode::Transparent,
            "test".to_string(),
        )
    }

    fn validate(
        registry: &MechanismRegistry,
        mechanism: &CkMechanism,
    ) -> Result<ValidatedMechanismParams, CkRv> {
        ValidatedMechanismParams::validate(
            mechanism,
            registry,
            Operation::General,
            ParamAbi::Lp64NativeLe,
            ParamAbi::Lp64NativeLe,
        )
    }

    fn flat_mechanism(mech: u64, len: usize, abi: Option<ParamAbi>) -> (CkMechanism, u64) {
        let resolved = ShapeResolver::resolve(
            Some("iv"),
            OperationContext { mechanism: mech, operation: Operation::General, length: len as u64 },
            ParamAbi::Lp64NativeLe,
        )
        .unwrap();
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType(mech),
            params: Some(CkMechanismParams::Flat(FlatParams {
                bytes: SecretBytes::copy_from_slice(&vec![0xA5u8; len]),
                declared_len: len as u64,
                source_abi: abi,
                fingerprint: resolved.fingerprint(ParamAbi::Lp64NativeLe),
                version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
            })),
        };
        (mechanism, resolved.fingerprint(ParamAbi::Lp64NativeLe))
    }

    #[test]
    fn validated_value_carries_its_registry_snapshot() {
        // F6: nested descent reuses the validating snapshot, so `validate`
        // must carry it (notably its bindings) in the proof itself.
        let registry = registry_with_binding(AES_CBC, "iv");
        let mechanism = CkMechanism { mechanism_type: CkMechanismType(AES_CBC), params: None };
        let validated = validate(&registry, &mechanism).unwrap();
        assert_eq!(validated.registry().param_shape(AES_CBC), Some("iv"));
        assert_eq!(validated.registry().revision(), registry.revision());
        // Value equality ignores provenance: same mechanism validated
        // under different snapshots still compares equal.
        let other = validate(&empty_registry(), &mechanism).unwrap();
        assert_eq!(validated, other);
    }

    #[test]
    fn exclusion_wins_over_every_param_kind() {
        let registry = excluded_registry(AES_CBC);
        let typed = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Iv(IvParams { iv: vec![1, 2, 3] })),
        };
        let none = CkMechanism { mechanism_type: CkMechanismType(AES_CBC), params: None };
        let raw = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Raw(RawMechanismParams {
                data: SecretBytes::copy_from_slice(b"x"),
            })),
        };
        let null = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Null { declared_len: 0, version: 1 }),
        };
        let (flat, _) = flat_mechanism(AES_CBC, 16, Some(ParamAbi::Lp64NativeLe));
        for (name, mechanism) in
            [("typed", typed), ("none", none), ("raw", raw), ("null", null), ("flat", flat)]
        {
            assert_eq!(
                validate(&registry, &mechanism),
                Err(CkRv::MECHANISM_INVALID),
                "{name} on an excluded mechanism must report MECHANISM_INVALID"
            );
        }
    }

    #[test]
    fn unknown_without_params_forwards() {
        let registry = empty_registry();
        let mechanism = CkMechanism { mechanism_type: CkMechanismType(UNKNOWN_MECH), params: None };
        let validated = validate(&registry, &mechanism).unwrap();
        assert!(validated.flat_grant().is_none());
        assert_eq!(validated.mechanism(), &mechanism);
    }

    #[test]
    fn typed_params_rejected_without_descriptor() {
        // F1: the typed path is BOUND, not variant-driven — unknown
        // mechanisms with typed params have no descriptor and reject
        // (S2 §6 RV table: "unknown mechanism with params and no
        // descriptor → PARAM_INVALID").
        let registry = empty_registry();
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType(UNKNOWN_MECH),
            params: Some(CkMechanismParams::Iv(IvParams { iv: vec![1, 2, 3] })),
        };
        assert_eq!(validate(&registry, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
    }

    /// F1 probe: AES-GCM carrying RSA-PSS parameters must reject (shape
    /// mismatch) — no downstream layer re-binds before backend FFI, so
    /// the typed gate must.
    #[test]
    fn f1_mismatched_typed_shape_rejected() {
        let registry = registry_with_binding(CkMechanismType::AES_GCM.0, "gcm");
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
                hash_alg: CkMechanismType::SHA256,
                mgf: CkMgf(1),
                salt_len: 32,
            })),
        };
        assert_eq!(validate(&registry, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
    }

    /// F1 probe: an unknown mechanism carrying RSA-PSS parameters must
    /// reject (descriptorless parameterized mechanism, S2 §6 RV table).
    #[test]
    fn f1_unknown_mech_typed_params_rejected() {
        let registry = empty_registry();
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType(UNKNOWN_MECH),
            params: Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
                hash_alg: CkMechanismType::SHA256,
                mgf: CkMgf(1),
                salt_len: 32,
            })),
        };
        assert_eq!(validate(&registry, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
    }

    /// F1 operation forms: the `gcm_compat` union authorizes both Iv
    /// and Gcm variants (the manifest binds both typed messages to it);
    /// any other variant under a compat-bound mech still rejects.
    #[test]
    fn f1_gcm_compat_union_authorizes_iv_and_gcm() {
        const GMAC: u64 = 0x0000_10A6;
        let registry = registry_with_binding(GMAC, "gcm_compat");
        let iv = CkMechanism {
            mechanism_type: CkMechanismType(GMAC),
            params: Some(CkMechanismParams::Iv(IvParams { iv: vec![1, 2, 3] })),
        };
        validate(&registry, &iv).unwrap();
        let gcm = CkMechanism {
            mechanism_type: CkMechanismType(GMAC),
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv_bits: 96,
                iv_buffer_len: 12,
                tag_bits: 128,
                iv_presence: PointerBytes::from_legacy(&[0u8; 12], false),
                aad_presence: PointerBytes::from_legacy(&[], false),
            })),
        };
        validate(&registry, &gcm).unwrap();
        let other = CkMechanism {
            mechanism_type: CkMechanismType(GMAC),
            params: Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
                hash_alg: CkMechanismType::SHA256,
                mgf: CkMgf(1),
                salt_len: 32,
            })),
        };
        assert_eq!(validate(&registry, &other), Err(CkRv::MECHANISM_PARAM_INVALID));
    }

    /// F1 operation forms: WrapKey selects the GCM/CCM wrap layouts
    /// (mirrors `ShapeResolver::resolve`); `General` never does, and a
    /// wrap variant under an unrelated mech rejects under both.
    #[test]
    fn f1_wrap_operation_selects_wrap_layouts() {
        let gcm_wrap = || {
            CkMechanismParams::GcmWrap(GcmWrapParams {
                iv_fixed_bits: 32,
                iv_generator: CkGeneratorFunction(1),
                tag_bits: 128,
                iv_presence: PointerBytes::from_legacy(&[], false),
                aad_presence: PointerBytes::from_legacy(&[], false),
            })
        };
        let validate_op = |registry: &MechanismRegistry,
                           mechanism: &CkMechanism,
                           operation: Operation|
         -> Result<ValidatedMechanismParams, CkRv> {
            ValidatedMechanismParams::validate(
                mechanism,
                registry,
                operation,
                ParamAbi::Lp64NativeLe,
                ParamAbi::Lp64NativeLe,
            )
        };
        let bound = registry_with_binding(CkMechanismType::AES_GCM.0, "gcm");
        let wrap_mech =
            CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: Some(gcm_wrap()) };
        validate_op(&bound, &wrap_mech, Operation::WrapKey).unwrap();
        assert_eq!(
            validate_op(&bound, &wrap_mech, Operation::General),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
        // Direct TOML binding to the wrap shape authorizes under General too.
        let direct = registry_with_binding(CkMechanismType::AES_GCM.0, "gcm_wrap");
        validate_op(&direct, &wrap_mech, Operation::General).unwrap();
        // Unrelated mech + wrap variant: no authorization either way.
        let other =
            CkMechanism { mechanism_type: CkMechanismType(UNKNOWN_MECH), params: Some(gcm_wrap()) };
        let empty = empty_registry();
        assert_eq!(
            validate_op(&empty, &other, Operation::WrapKey),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
        assert_eq!(
            validate_op(&empty, &other, Operation::General),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
    }

    /// F1 mapping spot-check: canonical names track the manifest's
    /// wire-message bindings (the union members map to their primary
    /// shapes; the union itself is an authorization rule, not a name).
    #[test]
    fn f1_canonical_shape_names_spot_check() {
        use CkMechanismParams as P;
        assert_eq!(P::Iv(IvParams { iv: vec![] }).canonical_shape_name(), Some("iv"));
        assert_eq!(
            P::RsaPkcsPss(RsaPkcsPssParams {
                hash_alg: CkMechanismType::SHA256,
                mgf: CkMgf(1),
                salt_len: 0,
            })
            .canonical_shape_name(),
            Some("rsa_pss")
        );
        assert_eq!(
            P::MacGeneral(MacGeneralParams { mac_length: 0 }).canonical_shape_name(),
            Some("mac_general")
        );
        assert_eq!(
            P::Flat(FlatParams {
                bytes: SecretBytes::copy_from_slice(&[]),
                declared_len: 0,
                source_abi: None,
                fingerprint: 0,
                version: 0,
            })
            .canonical_shape_name(),
            None
        );
        assert_eq!(P::Null { declared_len: 0, version: 0 }.canonical_shape_name(), None);
        assert_eq!(
            P::Raw(RawMechanismParams { data: SecretBytes::copy_from_slice(&[]) })
                .canonical_shape_name(),
            None
        );
    }

    /// F2 probe: GCM with an embedded NULL-huge IV rejects under
    /// sanitize ON (D3 "rejects regardless" is unqualified — it covers
    /// embedded legs, not just the outer form); OFF still forwards.
    #[test]
    fn f2_sanitize_on_rejects_embedded_null_huge() {
        const HUGE: u64 = 512 * 1024 * 1024 + 1;
        let registry = registry_with_binding(CkMechanismType::AES_GCM.0, "gcm");
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv_bits: 96,
                iv_buffer_len: 12,
                tag_bits: 128,
                iv_presence: PointerBytes::null_len(HUGE),
                aad_presence: PointerBytes::from_legacy(&[0xAA], false),
            })),
        };
        let validated = validate(&registry, &mechanism).unwrap();
        assert_eq!(
            validated.check_classic_sanitize_policy(true),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
        validated.check_classic_sanitize_policy(false).unwrap();
    }

    /// F2 probe: the matrix row is "NULL/nonzero → reject" with no size
    /// qualifier — even a small embedded nonzero NULL rejects under ON.
    /// NULL-zero (the canonical null) stays allowed, like the outer row.
    #[test]
    fn f2_sanitize_on_rejects_embedded_null_nonzero_allows_zero() {
        let registry = registry_with_binding(CkMechanismType::AES_GCM.0, "gcm");
        let gcm = |iv: PointerBytes| CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv_bits: 96,
                iv_buffer_len: 12,
                tag_bits: 128,
                iv_presence: iv,
                aad_presence: PointerBytes::from_legacy(&[], false),
            })),
        };
        let small = validate(&registry, &gcm(PointerBytes::null_len(12))).unwrap();
        assert_eq!(small.check_classic_sanitize_policy(true), Err(CkRv::MECHANISM_PARAM_INVALID));
        small.check_classic_sanitize_policy(false).unwrap();
        let zero = validate(&registry, &gcm(PointerBytes::null_len(0))).unwrap();
        zero.check_classic_sanitize_policy(true).unwrap();
    }

    /// F2 probe: nested NULL lengths/counts reject under ON — the KIP
    /// seed leg, an SP800-108 NULL data-params array, an OTP element
    /// NULL value, and a nested outer NULL.
    #[test]
    fn f2_sanitize_on_rejects_nested_nulls() {
        let registry = registry_with_bindings(&[
            ("kip", CkMechanismType::KIP_DERIVE.0),
            ("sp800_108_kdf", CkMechanismType::SP800_108_COUNTER_KDF.0),
            ("otp", UNKNOWN_MECH),
        ]);
        // KIP seed NULL-nonzero.
        let kip = CkMechanism {
            mechanism_type: CkMechanismType::KIP_DERIVE,
            params: Some(CkMechanismParams::Kip(KipParams {
                mechanism: None,
                key_handle: CkObjectHandle(0),
                seed_presence: PointerBytes::null_len(5),
            })),
        };
        let validated = validate(&registry, &kip).unwrap();
        assert_eq!(
            validated.check_classic_sanitize_policy(true),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
        // SP800-108 NULL data-params array (nonzero count).
        let kdf = CkMechanism {
            mechanism_type: CkMechanismType::SP800_108_COUNTER_KDF,
            params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CkMechanismType::SHA256,
                data_params_presence: PointerArray::null_count(3),
                additional_derived_keys_presence: PointerArray::present(vec![]),
            })),
        };
        let validated = validate(&registry, &kdf).unwrap();
        assert_eq!(
            validated.check_classic_sanitize_policy(true),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
        // OTP element with a NULL-nonzero value.
        let otp = CkMechanism {
            mechanism_type: CkMechanismType(UNKNOWN_MECH),
            params: Some(CkMechanismParams::Otp(OtpParams {
                params_presence: PointerArray::present(vec![OtpParam {
                    type_: 1,
                    value_presence: PointerBytes::null_len(2),
                }]),
            })),
        };
        let validated = validate(&registry, &otp).unwrap();
        assert_eq!(
            validated.check_classic_sanitize_policy(true),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
        // Nested outer NULL-nonzero inside KIP.
        let nested_null = CkMechanism {
            mechanism_type: CkMechanismType::KIP_DERIVE,
            params: Some(CkMechanismParams::Kip(KipParams {
                mechanism: Some(Box::new(CkMechanism {
                    mechanism_type: CkMechanismType::SHA256,
                    params: Some(CkMechanismParams::Null { declared_len: 7, version: 1 }),
                })),
                key_handle: CkObjectHandle(0),
                seed_presence: PointerBytes::present_copy(&[]),
            })),
        };
        let validated = validate(&registry, &nested_null).unwrap();
        assert_eq!(
            validated.check_classic_sanitize_policy(true),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
        validated.check_classic_sanitize_policy(false).unwrap();
    }

    /// NF5 (F2 regression): a canonical byte-buffer Flat nested inside
    /// KIP sanitizes exactly like the top level — ON allows it. (Pre-fix
    /// the nested scan rejected every nested Flat.)
    #[test]
    fn nf5_nested_byte_buffer_flat_passes_sanitize() {
        let registry =
            registry_with_bindings(&[("kip", CkMechanismType::KIP_DERIVE.0), ("iv", AES_CBC)]);
        let (flat, _) = flat_mechanism(AES_CBC, 16, Some(ParamAbi::Lp64NativeLe));
        // Top-level control: ON allows the canonical byte-buffer Flat.
        let top = validate(&registry, &flat).unwrap();
        top.check_classic_sanitize_policy(true).unwrap();
        // Nested inside KIP: same matrix row, same verdict.
        let outer = CkMechanism {
            mechanism_type: CkMechanismType::KIP_DERIVE,
            params: Some(CkMechanismParams::Kip(KipParams {
                mechanism: Some(Box::new(flat)),
                key_handle: CkObjectHandle(0),
                seed_presence: PointerBytes::null_len(0),
            })),
        };
        let nested = validate(&registry, &outer).unwrap();
        nested.check_classic_sanitize_policy(true).unwrap();
        nested.check_classic_sanitize_policy(false).unwrap();
    }

    /// NF5 guard: a struct-prefix nested Flat rejects under ON, exactly
    /// like the top-level struct-prefix row.
    #[test]
    fn nf5_nested_struct_prefix_flat_still_rejects() {
        let mech = CkMechanismType::RSA_PKCS_PSS.0;
        let registry =
            registry_with_bindings(&[("kip", CkMechanismType::KIP_DERIVE.0), ("rsa_pss", mech)]);
        let resolved = ShapeResolver::resolve(
            Some("rsa_pss"),
            OperationContext { mechanism: mech, operation: Operation::General, length: 1 },
            ParamAbi::Lp64NativeLe,
        )
        .unwrap();
        let flat = CkMechanism {
            mechanism_type: CkMechanismType(mech),
            params: Some(CkMechanismParams::Flat(FlatParams {
                bytes: SecretBytes::copy_from_slice(&[0x01]),
                declared_len: 1,
                source_abi: Some(ParamAbi::Lp64NativeLe),
                fingerprint: resolved.fingerprint(ParamAbi::Lp64NativeLe),
                version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
            })),
        };
        // Top-level control: the prefix grant validates, but ON rejects
        // the struct-prefix row.
        let top = validate(&registry, &flat).unwrap();
        assert_eq!(top.check_classic_sanitize_policy(true), Err(CkRv::MECHANISM_PARAM_INVALID));
        // Nested inside KIP: same matrix row, same verdict.
        let outer = CkMechanism {
            mechanism_type: CkMechanismType::KIP_DERIVE,
            params: Some(CkMechanismParams::Kip(KipParams {
                mechanism: Some(Box::new(flat)),
                key_handle: CkObjectHandle(0),
                seed_presence: PointerBytes::present_copy(&[]),
            })),
        };
        let nested = validate(&registry, &outer).unwrap();
        assert_eq!(nested.check_classic_sanitize_policy(true), Err(CkRv::MECHANISM_PARAM_INVALID));
        nested.check_classic_sanitize_policy(false).unwrap();
    }

    /// NF5 guard: a nested Flat the carried registry denies (unknown
    /// shape) fails closed under ON.
    #[test]
    fn nf5_nested_denied_flat_still_rejects() {
        let registry = registry_with_bindings(&[("kip", CkMechanismType::KIP_DERIVE.0)]);
        let (flat, _) = flat_mechanism(UNKNOWN_MECH, 16, Some(ParamAbi::Lp64NativeLe));
        let outer = CkMechanism {
            mechanism_type: CkMechanismType::KIP_DERIVE,
            params: Some(CkMechanismParams::Kip(KipParams {
                mechanism: Some(Box::new(flat)),
                key_handle: CkObjectHandle(0),
                seed_presence: PointerBytes::present_copy(&[]),
            })),
        };
        let nested = validate(&registry, &outer).unwrap();
        assert_eq!(nested.check_classic_sanitize_policy(true), Err(CkRv::MECHANISM_PARAM_INVALID));
        nested.check_classic_sanitize_policy(false).unwrap();
    }

    /// NF5 guard: classifying nested Flat does not weaken embedded-NULL
    /// policing — a NULL-huge IV inside a nested typed GCM still rejects.
    #[test]
    fn nf5_nested_embedded_null_huge_still_rejects() {
        const HUGE: u64 = 512 * 1024 * 1024 + 1;
        let registry = registry_with_bindings(&[
            ("kip", CkMechanismType::KIP_DERIVE.0),
            ("gcm", CkMechanismType::AES_GCM.0),
        ]);
        let inner = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv_bits: 96,
                iv_buffer_len: 12,
                tag_bits: 128,
                iv_presence: PointerBytes::null_len(HUGE),
                aad_presence: PointerBytes::from_legacy(&[], false),
            })),
        };
        let outer = CkMechanism {
            mechanism_type: CkMechanismType::KIP_DERIVE,
            params: Some(CkMechanismParams::Kip(KipParams {
                mechanism: Some(Box::new(inner)),
                key_handle: CkObjectHandle(0),
                seed_presence: PointerBytes::present_copy(&[]),
            })),
        };
        let nested = validate(&registry, &outer).unwrap();
        assert_eq!(nested.check_classic_sanitize_policy(true), Err(CkRv::MECHANISM_PARAM_INVALID));
        nested.check_classic_sanitize_policy(false).unwrap();
    }

    /// F1 positive control: bound typed pairs keep forwarding, and the
    /// parameterless/Null transparent rows are untouched.
    #[test]
    fn f1_bound_typed_pair_still_forwards() {
        let registry = registry_with_binding(CkMechanismType::AES_GCM.0, "gcm");
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv_bits: 96,
                iv_buffer_len: 12,
                tag_bits: 128,
                iv_presence: PointerBytes::from_legacy(&[0u8; 12], false),
                aad_presence: PointerBytes::from_legacy(&[0xAA, 0xBB], false),
            })),
        };
        let validated = validate(&registry, &mechanism).unwrap();
        assert!(validated.flat_grant().is_none());
        assert_eq!(validated.into_inner(), mechanism);
        // Transparent rows untouched: unknown without params forwards,
        // unknown with Null forwards (no descriptor needed).
        let registry = empty_registry();
        let bare = CkMechanism { mechanism_type: CkMechanismType(UNKNOWN_MECH), params: None };
        validate(&registry, &bare).unwrap();
        let null = CkMechanism {
            mechanism_type: CkMechanismType(UNKNOWN_MECH),
            params: Some(CkMechanismParams::Null { declared_len: 5, version: 1 }),
        };
        validate(&registry, &null).unwrap();
    }

    #[test]
    fn legacy_raw_rejected() {
        let registry = registry_with_binding(AES_CBC, "iv");
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Raw(RawMechanismParams {
                data: SecretBytes::copy_from_slice(b"AB"),
            })),
        };
        assert_eq!(validate(&registry, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
    }

    #[test]
    fn null_bit_disagreement_rejected() {
        // R18(1): a set null bit with non-zeroed scalars is contradictory
        // metadata (PARAM_INVALID); agreement forwards. (R18 named three
        // validators; R19 removed check_array_pair/check_kip_nesting with
        // the dual representation, so the surviving Err branches are the
        // null-bit pairs plus the SP800-108 derived-key pair below.)
        // F1: each variant rides a mech bound to its own shape (one mech
        // binds one shape, so the two families use adjacent numbers).
        let registry = registry_with_bindings(&[
            ("tls_prf", UNKNOWN_MECH),
            ("ssl3_master_key_derive", UNKNOWN_MECH + 1),
        ]);
        let random = SslRandomData {
            client_random_presence: PointerBytes::present_copy(&[]),
            server_random_presence: PointerBytes::present_copy(&[]),
        };
        let tls_prf =
            |output: SecretBytes, output_len: u64, out_null: bool, len_null: bool| CkMechanism {
                mechanism_type: CkMechanismType(UNKNOWN_MECH),
                params: Some(CkMechanismParams::TlsPrf(TlsPrfParams {
                    output_len,
                    output,
                    seed_presence: PointerBytes::present_copy(&[]),
                    label_presence: PointerBytes::present_copy(&[]),
                    output_is_null: out_null,
                    output_len_is_null: len_null,
                })),
            };
        // Output pair: NULL bit + non-empty output rejects.
        assert_eq!(
            validate(&registry, &tls_prf(SecretBytes::copy_from_slice(&[0xA5]), 1, true, false)),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
        // Output-length pair: NULL bit + nonzero length rejects.
        assert_eq!(
            validate(&registry, &tls_prf(SecretBytes::copy_from_slice(&[]), 7, false, true)),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
        // Agreement (zeroed scalars + set bits, or unset bits) forwards.
        assert!(
            validate(&registry, &tls_prf(SecretBytes::copy_from_slice(&[]), 0, true, true)).is_ok()
        );
        assert!(
            validate(&registry, &tls_prf(SecretBytes::copy_from_slice(&[0xA5]), 1, false, false))
                .is_ok()
        );
        // Version pair (master-key derive): NULL bit + nonzero version rejects.
        let versioned = |major: u32, minor: u32, is_null: bool| CkMechanism {
            mechanism_type: CkMechanismType(UNKNOWN_MECH + 1),
            params: Some(CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
                random_info: random.clone(),
                version_major: major,
                version_minor: minor,
                version_is_null: is_null,
            })),
        };
        assert_eq!(validate(&registry, &versioned(3, 0, true)), Err(CkRv::MECHANISM_PARAM_INVALID));
        assert!(validate(&registry, &versioned(0, 0, true)).is_ok());
        assert!(validate(&registry, &versioned(3, 0, false)).is_ok());
    }

    #[test]
    fn sp800108_derived_key_disagreement_rejected() {
        // R18(1): SP800-108 `phKey` NULL bit with a nonzero handle
        // rejects (check_sp800108_derived_key); agreement forwards.
        // F1: the KDF rides a mech bound to its shape.
        let registry = registry_with_binding(UNKNOWN_MECH, "sp800_108_kdf");
        let kdf = |handle: u64, is_null: bool| CkMechanism {
            mechanism_type: CkMechanismType(UNKNOWN_MECH),
            params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CkMechanismType(0),
                data_params_presence: PointerArray::present(vec![]),
                additional_derived_keys_presence: PointerArray::present(vec![Sp800108DerivedKey {
                    key_handle: CkObjectHandle(handle),
                    template_presence: PointerArray::present(vec![]),
                    ph_key_is_null: is_null,
                }]),
            })),
        };
        assert_eq!(validate(&registry, &kdf(14, true)), Err(CkRv::MECHANISM_PARAM_INVALID));
        assert!(validate(&registry, &kdf(0, true)).is_ok());
        assert!(validate(&registry, &kdf(14, false)).is_ok());
    }

    #[test]
    fn null_forwards_without_descriptor() {
        let registry = empty_registry();
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType(UNKNOWN_MECH),
            params: Some(CkMechanismParams::Null { declared_len: 41, version: 1 }),
        };
        let validated = validate(&registry, &mechanism).unwrap();
        assert!(validated.flat_grant().is_none());
        assert_eq!(validated.into_inner(), mechanism);
    }

    #[test]
    fn null_version_gates() {
        let registry = empty_registry();
        let v0 = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Null { declared_len: 0, version: 0 }),
        };
        assert_eq!(
            validate(&registry, &v0),
            Err(CkRv::MECHANISM_PARAM_INVALID),
            "Null with a legacy stamp is contradictory metadata"
        );
        let newer = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Null { declared_len: 0, version: 2 }),
        };
        assert_eq!(
            validate(&registry, &newer),
            Err(CkRv::FUNCTION_NOT_SUPPORTED),
            "per-message version newer than the daemon"
        );
    }

    #[test]
    fn null_narrowing_to_backend_ck_ulong() {
        let registry = empty_registry();
        let huge = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Null {
                declared_len: u64::from(u32::MAX) + 1,
                version: 1,
            }),
        };
        // LP64 backend: every u64 narrows.
        assert!(
            ValidatedMechanismParams::validate(
                &huge,
                &registry,
                Operation::General,
                ParamAbi::Lp64NativeLe,
                ParamAbi::Lp64NativeLe,
            )
            .is_ok()
        );
        // 32-bit backend: the unnarrowable length fails closed.
        assert_eq!(
            ValidatedMechanismParams::validate(
                &huge,
                &registry,
                Operation::General,
                ParamAbi::Lp64NativeLe,
                ParamAbi::Ilp32NativeLe,
            ),
            Err(CkRv::FUNCTION_FAILED)
        );
        // Boundary: u32::MAX still narrows onto a 32-bit backend.
        let boundary = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Null { declared_len: u64::from(u32::MAX), version: 1 }),
        };
        assert!(
            ValidatedMechanismParams::validate(
                &boundary,
                &registry,
                Operation::General,
                ParamAbi::Lp64NativeLe,
                ParamAbi::Ilp32NativeLe,
            )
            .is_ok()
        );
    }

    #[test]
    fn flat_version_and_length_gates() {
        let registry = registry_with_binding(AES_CBC, "iv");
        let (mut mechanism, _) = flat_mechanism(AES_CBC, 16, Some(ParamAbi::Lp64NativeLe));
        // Sanity: the well-formed value validates.
        validate(&registry, &mechanism).unwrap();

        let CkMechanismParams::Flat(flat) = mechanism.params.as_mut().unwrap() else {
            panic!("test setup must build Flat")
        };
        flat.version = 0;
        assert_eq!(
            validate(&registry, &mechanism),
            Err(CkRv::MECHANISM_PARAM_INVALID),
            "Flat with a legacy stamp is contradictory metadata"
        );
        let CkMechanismParams::Flat(flat) = mechanism.params.as_mut().unwrap() else {
            panic!("test setup must build Flat")
        };
        flat.version = 99;
        assert_eq!(
            validate(&registry, &mechanism),
            Err(CkRv::FUNCTION_NOT_SUPPORTED),
            "per-message version newer than the daemon"
        );
        let CkMechanismParams::Flat(flat) = mechanism.params.as_mut().unwrap() else {
            panic!("test setup must build Flat")
        };
        flat.version = 1;
        flat.declared_len = 15;
        assert_eq!(
            validate(&registry, &mechanism),
            Err(CkRv::MECHANISM_PARAM_INVALID),
            "declared_len below the byte count is a length mismatch"
        );
        let CkMechanismParams::Flat(flat) = mechanism.params.as_mut().unwrap() else {
            panic!("test setup must build Flat")
        };
        flat.declared_len = 17;
        assert_eq!(
            validate(&registry, &mechanism),
            Err(CkRv::MECHANISM_PARAM_INVALID),
            "declared_len above the byte count is a length mismatch"
        );
    }

    #[test]
    fn flat_unknown_abi_rejected() {
        let registry = registry_with_binding(AES_CBC, "iv");
        let (mechanism, _) = flat_mechanism(AES_CBC, 16, None);
        assert_eq!(
            validate(&registry, &mechanism),
            Err(CkRv::MECHANISM_PARAM_INVALID),
            "Flat without a known source ABI is contradictory metadata"
        );
    }

    #[test]
    fn flat_grant_is_stored_on_success() {
        let registry = registry_with_binding(AES_CBC, "iv");
        let (mechanism, fingerprint) = flat_mechanism(AES_CBC, 16, Some(ParamAbi::Lp64NativeLe));
        assert_eq!(fingerprint, ABI_EXEMPT_FINGERPRINT);
        let validated = validate(&registry, &mechanism).unwrap();
        let grant = validated.flat_grant().expect("Flat success must store its grant");
        assert_eq!(grant.resolved.descriptor.name, "iv");
        assert_eq!(grant.fingerprint, ABI_EXEMPT_FINGERPRINT);
        assert_eq!(grant.local_abi, ParamAbi::Lp64NativeLe);
    }

    #[test]
    fn unknown_descriptor_fails_closed() {
        // Unbound mechanism with Flat bytes: no descriptor, no carriage.
        let registry = empty_registry();
        let (mechanism, _) = flat_mechanism(UNKNOWN_MECH, 16, Some(ParamAbi::Lp64NativeLe));
        assert_eq!(validate(&registry, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
        // Registry bound to a shape that does not exist: fail closed too.
        let bad = registry_with_binding(AES_CBC, "no_such_shape");
        let (mechanism, _) = flat_mechanism(AES_CBC, 16, Some(ParamAbi::Lp64NativeLe));
        assert_eq!(validate(&bad, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
    }

    #[test]
    fn validated_flat_bytes_are_verbatim() {
        // S2 §10: no client address bits are used or interpreted — even
        // pointer-looking byte patterns pass through untouched.
        let registry = registry_with_binding(AES_CBC, "iv");
        let mut address_like = 0x7ffd_aabb_ccdd_eeffu64.to_le_bytes().to_vec();
        address_like.extend_from_slice(&[0x00; 8]);
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Flat(FlatParams {
                bytes: SecretBytes::copy_from_slice(&address_like),
                declared_len: address_like.len() as u64,
                source_abi: Some(ParamAbi::Lp64NativeLe),
                fingerprint: ABI_EXEMPT_FINGERPRINT,
                version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
            })),
        };
        let validated = validate(&registry, &mechanism).unwrap();
        let CkMechanismParams::Flat(back) = validated.mechanism().params.as_ref().unwrap() else {
            panic!("validated output must stay Flat")
        };
        back.bytes.expose(|b| assert_eq!(b, address_like.as_slice()));
        assert_eq!(back.declared_len, address_like.len() as u64);
    }

    #[test]
    fn allocation_failure_maps_to_host_memory() {
        // The S2 §6 HOST_MEMORY row: genuine sub-cap allocation failure.
        // `usize::MAX` forces CapacityOverflow deterministically (no real
        // allocation is attempted), pinning the mapping the Flat clone uses.
        let mut vec = Vec::new();
        assert_eq!(super::reserve_or_host_memory(&mut vec, usize::MAX), Err(CkRv::HOST_MEMORY));
        assert_eq!(super::reserve_or_host_memory(&mut vec, 16), Ok(()));
    }

    #[test]
    fn substitute_handles_round_trip_preserves_validated_properties() {
        // R13 remap round-trip, unit level: substitution swaps the embedded
        // handle (virtual → backend) while lengths, binding, and the grant
        // (caps/ABI) carry over unchanged.
        // F1: the HKDF rides its own bound mech (AES_CBC stays iv-bound
        // for the Flat half below — one mech binds one shape).
        let registry = registry_with_bindings(&[("hkdf", UNKNOWN_MECH), ("iv", AES_CBC)]);
        // Typed HKDF: only the salt-key handle may change.
        let hkdf = CkMechanism {
            mechanism_type: CkMechanismType(UNKNOWN_MECH),
            params: Some(CkMechanismParams::Hkdf(HkdfParams {
                extract: true,
                expand: true,
                prf_hash_mechanism: CkMechanismType::SHA256,
                salt_type: 1,
                salt_key_handle: CkObjectHandle(11),
                salt_presence: PointerBytes::present_copy(b"salty"),
                info_presence: PointerBytes::present_copy(b"context"),
            })),
        };
        let before = hkdf.clone();
        let validated = validate(&registry, &hkdf).unwrap();
        assert!(validated.flat_grant().is_none());
        let substituted = validated.substitute_handles(|mechanism| {
            let Some(CkMechanismParams::Hkdf(params)) = mechanism.params.as_mut() else {
                panic!("typed params must survive validation");
            };
            params.salt_key_handle = CkObjectHandle(77);
        });
        assert!(substituted.flat_grant().is_none());
        assert_eq!(substituted.mechanism().mechanism_type, before.mechanism_type);
        let (Some(CkMechanismParams::Hkdf(got)), Some(CkMechanismParams::Hkdf(want))) =
            (substituted.mechanism().params.clone(), before.params.clone())
        else {
            panic!("typed params must survive substitution");
        };
        assert_eq!(got.salt_key_handle, CkObjectHandle(77));
        let mut normalized = got.clone();
        normalized.salt_key_handle = want.salt_key_handle;
        assert_eq!(normalized, want, "only the embedded handle may change");
        // Eligible Flat: the grant (fingerprint/caps/ABI) is carried over
        // verbatim and the bytes are untouched.
        let (flat, _) = flat_mechanism(AES_CBC, 16, Some(ParamAbi::Lp64NativeLe));
        let validated = validate(&registry, &flat).unwrap();
        let grant = validated.flat_grant().expect("iv Flat must be eligible");
        let substituted = validated.substitute_handles(|_| {});
        assert_eq!(substituted.flat_grant(), Some(grant));
        assert_eq!(substituted.mechanism(), &flat);
    }

    // ------------------------------------------------------------------
    // R16: typed presence/length consistency (S2 §3 "no dual
    // representations"). The v1 wire gate rejects set legacy bools at
    // decode; validation re-enforces the same rule on domain values,
    // plus presence/payload agreement for every pair.
    // ------------------------------------------------------------------

    fn r16_mech(mech: u64, params: CkMechanismParams) -> CkMechanism {
        CkMechanism { mechanism_type: CkMechanismType(mech), params: Some(params) }
    }

    fn r16_gcm(iv_presence: PointerBytes, aad_presence: PointerBytes) -> CkMechanismParams {
        CkMechanismParams::Gcm(GcmParams {
            iv_bits: 96,
            iv_buffer_len: 12,
            tag_bits: 128,
            iv_presence,
            aad_presence,
        })
    }

    #[test]
    fn r16_validation_accepts_consistent_presence() {
        // F1: each variant rides a mech bound to its own shape.
        let registry = registry_with_bindings(&[
            ("gcm", CkMechanismType::AES_GCM.0),
            ("hkdf", UNKNOWN_MECH),
            ("ecdh1_derive", UNKNOWN_MECH + 1),
            ("rsa_aes_key_wrap", UNKNOWN_MECH + 2),
        ]);
        // NULL IV + present-empty aad alongside.
        let v0_null = r16_gcm(PointerBytes::null_len(0), PointerBytes::present_copy(b""));
        validate(&registry, &r16_mech(CkMechanismType::AES_GCM.0, v0_null)).unwrap();
        // NULL with a declared length beside present aad.
        let v1_null = r16_gcm(PointerBytes::null_len(41), PointerBytes::present_copy(b"tag"));
        validate(&registry, &r16_mech(CkMechanismType::AES_GCM.0, v1_null)).unwrap();
        // Bool-less present + NULL pairs (HKDF).
        let hkdf = CkMechanismParams::Hkdf(HkdfParams {
            extract: true,
            expand: true,
            prf_hash_mechanism: CkMechanismType::SHA256,
            salt_type: 1,
            salt_key_handle: CkObjectHandle(11),
            salt_presence: PointerBytes::present_copy(b"salty"),
            info_presence: PointerBytes::null_len(12),
        });
        validate(&registry, &r16_mech(UNKNOWN_MECH, hkdf)).unwrap();
        // Bool-less Vec pair (ECDH1 public data).
        let ecdh1 = CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
            kdf: CkKdf(1),
            shared_data_presence: PointerBytes::present_copy(b""),
            public_data_presence: PointerBytes::present_copy(&[0x04; 65]),
        });
        validate(&registry, &r16_mech(UNKNOWN_MECH + 1, ecdh1)).unwrap();
        // Nested OAEP inside RSA-AES wrap.
        let wrap = CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
            aes_key_bits: 128,
            oaep_params: RsaPkcsOaepParams {
                hash_alg: CkMechanismType::SHA256,
                mgf: CkMgf(1),
                source: CkOaepSource(1),
                source_data_presence: PointerBytes::present_copy(b""),
            },
        });
        validate(&registry, &r16_mech(UNKNOWN_MECH + 2, wrap)).unwrap();
    }
}

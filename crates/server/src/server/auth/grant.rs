use pkcs11_proxy_ng_types::{CkMechanismType, CkObjectClass};

use super::token_selector::TokenSelector;

/// Whether sensitive key material (private/secret key extraction, wrap, etc.)
/// is permitted by a grant. Defaults to `Allow`; `Deny` is opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExtractPolicy {
    #[default]
    Allow,
    Deny,
}

/// Per-object extract-policy override for an entry in the `objects` allow-list.
///
/// `extract = None` means inherit the grant-level extract policy for this object.
/// `extract = Some(policy)` overrides the grant-level policy for this specific
/// object only, enabling per-object allow/deny independent of the grant default.
#[derive(Debug, Clone)]
pub struct ObjectAcl {
    pub unique_id: Vec<u8>,
    pub extract: Option<ExtractPolicy>,
}

/// A token grant that pairs a token selector with optional per-class,
/// per-mechanism, per-object restrictions and an extract policy.
///
/// `classes = None` means "all object classes allowed"; `mechanisms = None`
/// means "all mechanisms allowed"; `objects = None` means "all objects allowed"
/// (per-object restriction is an opt-in refinement, never a new default denial).
/// When `extract` is `Deny` the grant forbids extraction of sensitive key
/// material for the matched token.
#[derive(Debug, Clone)]
pub struct TokenGrant {
    pub selector: TokenSelector,
    pub classes: Option<Vec<CkObjectClass>>,
    pub mechanisms: Option<Vec<CkMechanismType>>,
    pub extract: ExtractPolicy,
    /// CKA_UNIQUE_ID allow-list. `None` = all objects permitted (back-compat
    /// default). `Some(list)` = only objects whose CKA_UNIQUE_ID byte value
    /// appears in `list` are permitted by this grant. Each entry may carry an
    /// optional per-object extract override (`ObjectAcl::extract`); `None`
    /// inherits the grant-level `extract` policy.
    pub objects: Option<Vec<ObjectAcl>>,
}

impl TokenGrant {
    /// Convenience constructor: a grant with no class/mechanism/object
    /// restriction and `extract = Allow`. Used for back-compat string selectors.
    pub fn simple(selector: TokenSelector) -> Self {
        Self {
            selector,
            classes: None,
            mechanisms: None,
            extract: ExtractPolicy::Allow,
            objects: None,
        }
    }

    /// Whether this grant matches the given token label and serial.
    pub fn matches_token(&self, token_label: &str, token_serial: &str) -> bool {
        self.selector.matches(token_label, token_serial)
    }
}

// ---------------------------------------------------------------------------
// Name / byte parsers
// ---------------------------------------------------------------------------

/// Parse an object-class string into a `CkObjectClass`.
///
/// Accepted forms:
/// - Short names: `"data"`, `"certificate"`, `"public_key"`, `"private_key"`,
///   `"secret_key"`, `"vendor_defined"`
/// - CKO_* prefix: `"CKO_DATA"`, `"CKO_CERTIFICATE"`, `"CKO_PUBLIC_KEY"`,
///   `"CKO_PRIVATE_KEY"`, `"CKO_SECRET_KEY"`, `"CKO_VENDOR_DEFINED"`
/// - Hex integer: `"0x00000003"` or decimal: `"3"`
pub fn parse_class(s: &str) -> Result<CkObjectClass, String> {
    let t = s.trim();
    match t {
        "data" | "CKO_DATA" => return Ok(CkObjectClass::DATA),
        "certificate" | "CKO_CERTIFICATE" => return Ok(CkObjectClass::CERTIFICATE),
        "public_key" | "CKO_PUBLIC_KEY" => return Ok(CkObjectClass::PUBLIC_KEY),
        "private_key" | "CKO_PRIVATE_KEY" => return Ok(CkObjectClass::PRIVATE_KEY),
        "secret_key" | "CKO_SECRET_KEY" => return Ok(CkObjectClass::SECRET_KEY),
        "vendor_defined" | "CKO_VENDOR_DEFINED" => return Ok(CkObjectClass::VENDOR_DEFINED),
        _ => {}
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).map(CkObjectClass).map_err(|_| {
            format!("unknown object class '{t}': invalid hex integer; expected e.g. 0x00000003")
        });
    }
    if let Ok(n) = t.parse::<u64>() {
        return Ok(CkObjectClass(n));
    }
    // W1-C3-20: the accepted-names list must include vendor_defined
    // (both the short name and the CKO_* form parse successfully above).
    Err(format!(
        "unknown object class '{t}'; expected one of: data, certificate, public_key, \
         private_key, secret_key, vendor_defined (or CKO_* prefix, or a hex/decimal integer)"
    ))
}

/// Parse a mechanism-type string into a `CkMechanismType`.
///
/// Accepted forms:
/// - `CKM_*` names for all constants defined in `CkMechanismType` (e.g. `"CKM_AES_GCM"`)
/// - Hex integer: `"0x00001087"` or decimal: `"4231"`
///
/// Unknown `CKM_*` names that do not appear in this table must be expressed
/// as a numeric value (hex or decimal).
pub fn parse_mechanism(s: &str) -> Result<CkMechanismType, String> {
    let t = s.trim();
    // Named constants — all consts from CkMechanismType
    let named: Option<CkMechanismType> = match t {
        "CKM_RSA_PKCS_KEY_PAIR_GEN" => Some(CkMechanismType::RSA_PKCS_KEY_PAIR_GEN),
        "CKM_RSA_PKCS" => Some(CkMechanismType::RSA_PKCS),
        "CKM_RSA_9796" => Some(CkMechanismType::RSA_9796),
        "CKM_RSA_X_509" => Some(CkMechanismType::RSA_X_509),
        "CKM_RSA_X9_31_KEY_PAIR_GEN" => Some(CkMechanismType::RSA_X9_31_KEY_PAIR_GEN),
        "CKM_RSA_X9_31" => Some(CkMechanismType::RSA_X9_31),
        "CKM_RSA_PKCS_PSS" => Some(CkMechanismType::RSA_PKCS_PSS),
        "CKM_RSA_PKCS_OAEP" => Some(CkMechanismType::RSA_PKCS_OAEP),
        "CKM_SHA256_RSA_PKCS" => Some(CkMechanismType::SHA256_RSA_PKCS),
        "CKM_SHA384_RSA_PKCS" => Some(CkMechanismType::SHA384_RSA_PKCS),
        "CKM_SHA512_RSA_PKCS" => Some(CkMechanismType::SHA512_RSA_PKCS),
        "CKM_ECDSA" => Some(CkMechanismType::ECDSA),
        "CKM_ECDSA_SHA1" => Some(CkMechanismType::ECDSA_SHA1),
        "CKM_ECDSA_SHA224" => Some(CkMechanismType::ECDSA_SHA224),
        "CKM_ECDSA_SHA256" => Some(CkMechanismType::ECDSA_SHA256),
        "CKM_ECDSA_SHA384" => Some(CkMechanismType::ECDSA_SHA384),
        "CKM_ECDSA_SHA512" => Some(CkMechanismType::ECDSA_SHA512),
        "CKM_ECDSA_SHA3_224" => Some(CkMechanismType::ECDSA_SHA3_224),
        "CKM_ECDSA_SHA3_256" => Some(CkMechanismType::ECDSA_SHA3_256),
        "CKM_ECDSA_SHA3_384" => Some(CkMechanismType::ECDSA_SHA3_384),
        "CKM_ECDSA_SHA3_512" => Some(CkMechanismType::ECDSA_SHA3_512),
        "CKM_EC_KEY_PAIR_GEN" => Some(CkMechanismType::EC_KEY_PAIR_GEN),
        "CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS" => Some(CkMechanismType::EC_KEY_PAIR_GEN_W_EXTRA_BITS),
        "CKM_EC_EDWARDS_KEY_PAIR_GEN" => Some(CkMechanismType::EC_EDWARDS_KEY_PAIR_GEN),
        "CKM_EC_MONTGOMERY_KEY_PAIR_GEN" => Some(CkMechanismType::EC_MONTGOMERY_KEY_PAIR_GEN),
        "CKM_EDDSA" => Some(CkMechanismType::EDDSA),
        "CKM_XEDDSA" => Some(CkMechanismType::XEDDSA),
        "CKM_HKDF_DERIVE" => Some(CkMechanismType::HKDF_DERIVE),
        "CKM_HKDF_DATA" => Some(CkMechanismType::HKDF_DATA),
        "CKM_HKDF_KEY_GEN" => Some(CkMechanismType::HKDF_KEY_GEN),
        "CKM_IKE2_PRF_PLUS_DERIVE" => Some(CkMechanismType::IKE2_PRF_PLUS_DERIVE),
        "CKM_IKE_PRF_DERIVE" => Some(CkMechanismType::IKE_PRF_DERIVE),
        "CKM_IKE1_PRF_DERIVE" => Some(CkMechanismType::IKE1_PRF_DERIVE),
        "CKM_IKE1_EXTENDED_DERIVE" => Some(CkMechanismType::IKE1_EXTENDED_DERIVE),
        "CKM_HSS_KEY_PAIR_GEN" => Some(CkMechanismType::HSS_KEY_PAIR_GEN),
        "CKM_HSS" => Some(CkMechanismType::HSS),
        "CKM_XMSS_KEY_PAIR_GEN" => Some(CkMechanismType::XMSS_KEY_PAIR_GEN),
        "CKM_XMSSMT_KEY_PAIR_GEN" => Some(CkMechanismType::XMSSMT_KEY_PAIR_GEN),
        "CKM_XMSS" => Some(CkMechanismType::XMSS),
        "CKM_XMSSMT" => Some(CkMechanismType::XMSSMT),
        "CKM_SHA256" => Some(CkMechanismType::SHA256),
        "CKM_SHA384" => Some(CkMechanismType::SHA384),
        "CKM_SHA512" => Some(CkMechanismType::SHA512),
        "CKM_DH_PKCS_KEY_PAIR_GEN" => Some(CkMechanismType::DH_PKCS_KEY_PAIR_GEN),
        "CKM_DH_PKCS_DERIVE" => Some(CkMechanismType::DH_PKCS_DERIVE),
        "CKM_X9_42_DH_KEY_PAIR_GEN" => Some(CkMechanismType::X9_42_DH_KEY_PAIR_GEN),
        "CKM_X9_42_DH_DERIVE" => Some(CkMechanismType::X9_42_DH_DERIVE),
        "CKM_X9_42_DH_HYBRID_DERIVE" => Some(CkMechanismType::X9_42_DH_HYBRID_DERIVE),
        "CKM_X9_42_MQV_DERIVE" => Some(CkMechanismType::X9_42_MQV_DERIVE),
        "CKM_AES_XTS" => Some(CkMechanismType::AES_XTS),
        "CKM_AES_XTS_KEY_GEN" => Some(CkMechanismType::AES_XTS_KEY_GEN),
        "CKM_AES_KEY_GEN" => Some(CkMechanismType::AES_KEY_GEN),
        "CKM_AES_ECB" => Some(CkMechanismType::AES_ECB),
        "CKM_AES_CBC" => Some(CkMechanismType::AES_CBC),
        "CKM_AES_CBC_PAD" => Some(CkMechanismType::AES_CBC_PAD),
        "CKM_AES_MAC" => Some(CkMechanismType::AES_MAC),
        "CKM_AES_MAC_GENERAL" => Some(CkMechanismType::AES_MAC_GENERAL),
        "CKM_AES_CTR" => Some(CkMechanismType::AES_CTR),
        "CKM_AES_GCM" => Some(CkMechanismType::AES_GCM),
        "CKM_AES_CCM" => Some(CkMechanismType::AES_CCM),
        "CKM_AES_CTS" => Some(CkMechanismType::AES_CTS),
        "CKM_AES_CMAC" => Some(CkMechanismType::AES_CMAC),
        "CKM_AES_CMAC_GENERAL" => Some(CkMechanismType::AES_CMAC_GENERAL),
        "CKM_AES_XCBC_MAC" => Some(CkMechanismType::AES_XCBC_MAC),
        "CKM_AES_XCBC_MAC_96" => Some(CkMechanismType::AES_XCBC_MAC_96),
        "CKM_AES_GMAC" => Some(CkMechanismType::AES_GMAC),
        "CKM_AES_OFB" => Some(CkMechanismType::AES_OFB),
        "CKM_AES_CFB64" => Some(CkMechanismType::AES_CFB64),
        "CKM_AES_CFB8" => Some(CkMechanismType::AES_CFB8),
        "CKM_AES_CFB128" => Some(CkMechanismType::AES_CFB128),
        "CKM_AES_CFB1" => Some(CkMechanismType::AES_CFB1),
        "CKM_AES_KEY_WRAP" => Some(CkMechanismType::AES_KEY_WRAP),
        "CKM_AES_KEY_WRAP_PAD" => Some(CkMechanismType::AES_KEY_WRAP_PAD),
        "CKM_AES_KEY_WRAP_KWP" => Some(CkMechanismType::AES_KEY_WRAP_KWP),
        "CKM_AES_KEY_WRAP_PKCS7" => Some(CkMechanismType::AES_KEY_WRAP_PKCS7),
        "CKM_AES_ECB_ENCRYPT_DATA" => Some(CkMechanismType::AES_ECB_ENCRYPT_DATA),
        "CKM_AES_CBC_ENCRYPT_DATA" => Some(CkMechanismType::AES_CBC_ENCRYPT_DATA),
        "CKM_MD2" => Some(CkMechanismType::MD2),
        "CKM_MD5" => Some(CkMechanismType::MD5),
        "CKM_SHAKE_128_KEY_DERIVATION" => Some(CkMechanismType::SHAKE_128_KEY_DERIVATION),
        "CKM_SHAKE_256_KEY_DERIVATION" => Some(CkMechanismType::SHAKE_256_KEY_DERIVATION),
        "CKM_CHACHA20_KEY_GEN" => Some(CkMechanismType::CHACHA20_KEY_GEN),
        "CKM_CHACHA20" => Some(CkMechanismType::CHACHA20),
        "CKM_POLY1305_KEY_GEN" => Some(CkMechanismType::POLY1305_KEY_GEN),
        "CKM_POLY1305" => Some(CkMechanismType::POLY1305),
        "CKM_ECDH1_DERIVE" => Some(CkMechanismType::ECDH1_DERIVE),
        "CKM_ECDH1_COFACTOR_DERIVE" => Some(CkMechanismType::ECDH1_COFACTOR_DERIVE),
        "CKM_ECMQV_DERIVE" => Some(CkMechanismType::ECMQV_DERIVE),
        "CKM_ECDH_AES_KEY_WRAP" => Some(CkMechanismType::ECDH_AES_KEY_WRAP),
        "CKM_RSA_AES_KEY_WRAP" => Some(CkMechanismType::RSA_AES_KEY_WRAP),
        "CKM_ECDH_X_AES_KEY_WRAP" => Some(CkMechanismType::ECDH_X_AES_KEY_WRAP),
        "CKM_ECDH_COF_AES_KEY_WRAP" => Some(CkMechanismType::ECDH_COF_AES_KEY_WRAP),
        "CKM_SECURID_KEY_GEN" => Some(CkMechanismType::SECURID_KEY_GEN),
        "CKM_SECURID" => Some(CkMechanismType::SECURID),
        "CKM_HOTP_KEY_GEN" => Some(CkMechanismType::HOTP_KEY_GEN),
        "CKM_HOTP" => Some(CkMechanismType::HOTP),
        "CKM_PBE_SHA1_DES3_EDE_CBC" => Some(CkMechanismType::PBE_SHA1_DES3_EDE_CBC),
        "CKM_PBE_SHA1_DES2_EDE_CBC" => Some(CkMechanismType::PBE_SHA1_DES2_EDE_CBC),
        "CKM_PKCS5_PBKD2" => Some(CkMechanismType::PKCS5_PBKD2),
        "CKM_PBA_SHA1_WITH_SHA1_HMAC" => Some(CkMechanismType::PBA_SHA1_WITH_SHA1_HMAC),
        "CKM_CMS_SIG" => Some(CkMechanismType::CMS_SIG),
        "CKM_BLOWFISH_KEY_GEN" => Some(CkMechanismType::BLOWFISH_KEY_GEN),
        "CKM_BLOWFISH_CBC" => Some(CkMechanismType::BLOWFISH_CBC),
        "CKM_TWOFISH_KEY_GEN" => Some(CkMechanismType::TWOFISH_KEY_GEN),
        "CKM_TWOFISH_CBC" => Some(CkMechanismType::TWOFISH_CBC),
        "CKM_BLOWFISH_CBC_PAD" => Some(CkMechanismType::BLOWFISH_CBC_PAD),
        "CKM_TWOFISH_CBC_PAD" => Some(CkMechanismType::TWOFISH_CBC_PAD),
        "CKM_GENERIC_SECRET_KEY_GEN" => Some(CkMechanismType::GENERIC_SECRET_KEY_GEN),
        "CKM_CONCATENATE_BASE_AND_KEY" => Some(CkMechanismType::CONCATENATE_BASE_AND_KEY),
        "CKM_CONCATENATE_BASE_AND_DATA" => Some(CkMechanismType::CONCATENATE_BASE_AND_DATA),
        "CKM_CONCATENATE_DATA_AND_BASE" => Some(CkMechanismType::CONCATENATE_DATA_AND_BASE),
        "CKM_XOR_BASE_AND_DATA" => Some(CkMechanismType::XOR_BASE_AND_DATA),
        "CKM_EXTRACT_KEY_FROM_KEY" => Some(CkMechanismType::EXTRACT_KEY_FROM_KEY),
        "CKM_PUB_KEY_FROM_PRIV_KEY" => Some(CkMechanismType::PUB_KEY_FROM_PRIV_KEY),
        "CKM_DES_KEY_GEN" => Some(CkMechanismType::DES_KEY_GEN),
        "CKM_DES_ECB" => Some(CkMechanismType::DES_ECB),
        "CKM_DES_MAC" => Some(CkMechanismType::DES_MAC),
        "CKM_DES_CBC_PAD" => Some(CkMechanismType::DES_CBC_PAD),
        "CKM_DES2_KEY_GEN" => Some(CkMechanismType::DES2_KEY_GEN),
        "CKM_DES3_KEY_GEN" => Some(CkMechanismType::DES3_KEY_GEN),
        "CKM_DES3_ECB" => Some(CkMechanismType::DES3_ECB),
        "CKM_DES3_CBC" => Some(CkMechanismType::DES3_CBC),
        "CKM_DES3_CBC_PAD" => Some(CkMechanismType::DES3_CBC_PAD),
        "CKM_DES3_MAC" => Some(CkMechanismType::DES3_MAC),
        "CKM_DES3_MAC_GENERAL" => Some(CkMechanismType::DES3_MAC_GENERAL),
        "CKM_DES3_CMAC_GENERAL" => Some(CkMechanismType::DES3_CMAC_GENERAL),
        "CKM_DES3_CMAC" => Some(CkMechanismType::DES3_CMAC),
        "CKM_KIP_DERIVE" => Some(CkMechanismType::KIP_DERIVE),
        "CKM_KIP_WRAP" => Some(CkMechanismType::KIP_WRAP),
        "CKM_KIP_MAC" => Some(CkMechanismType::KIP_MAC),
        "CKM_CAMELLIA_KEY_GEN" => Some(CkMechanismType::CAMELLIA_KEY_GEN),
        "CKM_CAMELLIA_ECB" => Some(CkMechanismType::CAMELLIA_ECB),
        "CKM_CAMELLIA_CBC" => Some(CkMechanismType::CAMELLIA_CBC),
        "CKM_CAMELLIA_MAC" => Some(CkMechanismType::CAMELLIA_MAC),
        "CKM_CAMELLIA_MAC_GENERAL" => Some(CkMechanismType::CAMELLIA_MAC_GENERAL),
        "CKM_CAMELLIA_CBC_PAD" => Some(CkMechanismType::CAMELLIA_CBC_PAD),
        "CKM_CAMELLIA_ECB_ENCRYPT_DATA" => Some(CkMechanismType::CAMELLIA_ECB_ENCRYPT_DATA),
        "CKM_CAMELLIA_CBC_ENCRYPT_DATA" => Some(CkMechanismType::CAMELLIA_CBC_ENCRYPT_DATA),
        "CKM_ARIA_KEY_GEN" => Some(CkMechanismType::ARIA_KEY_GEN),
        "CKM_ARIA_ECB" => Some(CkMechanismType::ARIA_ECB),
        "CKM_ARIA_CBC" => Some(CkMechanismType::ARIA_CBC),
        "CKM_ARIA_MAC" => Some(CkMechanismType::ARIA_MAC),
        "CKM_ARIA_MAC_GENERAL" => Some(CkMechanismType::ARIA_MAC_GENERAL),
        "CKM_ARIA_CBC_PAD" => Some(CkMechanismType::ARIA_CBC_PAD),
        "CKM_ARIA_ECB_ENCRYPT_DATA" => Some(CkMechanismType::ARIA_ECB_ENCRYPT_DATA),
        "CKM_ARIA_CBC_ENCRYPT_DATA" => Some(CkMechanismType::ARIA_CBC_ENCRYPT_DATA),
        "CKM_SEED_KEY_GEN" => Some(CkMechanismType::SEED_KEY_GEN),
        "CKM_SEED_ECB" => Some(CkMechanismType::SEED_ECB),
        "CKM_SEED_CBC" => Some(CkMechanismType::SEED_CBC),
        "CKM_SEED_MAC" => Some(CkMechanismType::SEED_MAC),
        "CKM_SEED_MAC_GENERAL" => Some(CkMechanismType::SEED_MAC_GENERAL),
        "CKM_SEED_CBC_PAD" => Some(CkMechanismType::SEED_CBC_PAD),
        "CKM_SEED_ECB_ENCRYPT_DATA" => Some(CkMechanismType::SEED_ECB_ENCRYPT_DATA),
        "CKM_SEED_CBC_ENCRYPT_DATA" => Some(CkMechanismType::SEED_CBC_ENCRYPT_DATA),
        "CKM_GOSTR3410_KEY_PAIR_GEN" => Some(CkMechanismType::GOSTR3410_KEY_PAIR_GEN),
        "CKM_GOSTR3410" => Some(CkMechanismType::GOSTR3410),
        "CKM_GOSTR3410_WITH_GOSTR3411" => Some(CkMechanismType::GOSTR3410_WITH_GOSTR3411),
        "CKM_GOSTR3410_KEY_WRAP" => Some(CkMechanismType::GOSTR3410_KEY_WRAP),
        "CKM_GOSTR3410_DERIVE" => Some(CkMechanismType::GOSTR3410_DERIVE),
        "CKM_GOSTR3411" => Some(CkMechanismType::GOSTR3411),
        "CKM_GOSTR3411_HMAC" => Some(CkMechanismType::GOSTR3411_HMAC),
        "CKM_GOST28147_KEY_GEN" => Some(CkMechanismType::GOST28147_KEY_GEN),
        "CKM_GOST28147_ECB" => Some(CkMechanismType::GOST28147_ECB),
        "CKM_GOST28147" => Some(CkMechanismType::GOST28147),
        "CKM_GOST28147_MAC" => Some(CkMechanismType::GOST28147_MAC),
        "CKM_GOST28147_KEY_WRAP" => Some(CkMechanismType::GOST28147_KEY_WRAP),
        "CKM_DES_ECB_ENCRYPT_DATA" => Some(CkMechanismType::DES_ECB_ENCRYPT_DATA),
        "CKM_DES_CBC_ENCRYPT_DATA" => Some(CkMechanismType::DES_CBC_ENCRYPT_DATA),
        "CKM_DES3_ECB_ENCRYPT_DATA" => Some(CkMechanismType::DES3_ECB_ENCRYPT_DATA),
        "CKM_DES3_CBC_ENCRYPT_DATA" => Some(CkMechanismType::DES3_CBC_ENCRYPT_DATA),
        "CKM_NULL" => Some(CkMechanismType::NULL),
        "CKM_SALSA20" => Some(CkMechanismType::SALSA20),
        "CKM_CHACHA20_POLY1305" => Some(CkMechanismType::CHACHA20_POLY1305),
        "CKM_SALSA20_POLY1305" => Some(CkMechanismType::SALSA20_POLY1305),
        "CKM_X3DH_INITIALIZE" => Some(CkMechanismType::X3DH_INITIALIZE),
        "CKM_X3DH_RESPOND" => Some(CkMechanismType::X3DH_RESPOND),
        "CKM_X2RATCHET_INITIALIZE" => Some(CkMechanismType::X2RATCHET_INITIALIZE),
        "CKM_X2RATCHET_RESPOND" => Some(CkMechanismType::X2RATCHET_RESPOND),
        "CKM_X2RATCHET_ENCRYPT" => Some(CkMechanismType::X2RATCHET_ENCRYPT),
        "CKM_X2RATCHET_DECRYPT" => Some(CkMechanismType::X2RATCHET_DECRYPT),
        "CKM_SALSA20_KEY_GEN" => Some(CkMechanismType::SALSA20_KEY_GEN),
        "CKM_DH_PKCS_PARAMETER_GEN" => Some(CkMechanismType::DH_PKCS_PARAMETER_GEN),
        "CKM_X9_42_DH_PARAMETER_GEN" => Some(CkMechanismType::X9_42_DH_PARAMETER_GEN),
        "CKM_RSA_PKCS_TPM_1_1" => Some(CkMechanismType::RSA_PKCS_TPM_1_1),
        "CKM_RSA_PKCS_OAEP_TPM_1_1" => Some(CkMechanismType::RSA_PKCS_OAEP_TPM_1_1),
        "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE" => {
            Some(CkMechanismType::TLS12_EXTENDED_MASTER_KEY_DERIVE)
        }
        "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH" => {
            Some(CkMechanismType::TLS12_EXTENDED_MASTER_KEY_DERIVE_DH)
        }
        "CKM_SSL3_PRE_MASTER_KEY_GEN" => Some(CkMechanismType::SSL3_PRE_MASTER_KEY_GEN),
        "CKM_SSL3_MASTER_KEY_DERIVE" => Some(CkMechanismType::SSL3_MASTER_KEY_DERIVE),
        "CKM_SSL3_KEY_AND_MAC_DERIVE" => Some(CkMechanismType::SSL3_KEY_AND_MAC_DERIVE),
        "CKM_SSL3_MASTER_KEY_DERIVE_DH" => Some(CkMechanismType::SSL3_MASTER_KEY_DERIVE_DH),
        "CKM_TLS_PRE_MASTER_KEY_GEN" => Some(CkMechanismType::TLS_PRE_MASTER_KEY_GEN),
        "CKM_TLS_PRF" => Some(CkMechanismType::TLS_PRF),
        "CKM_SSL3_MD5_MAC" => Some(CkMechanismType::SSL3_MD5_MAC),
        "CKM_SSL3_SHA1_MAC" => Some(CkMechanismType::SSL3_SHA1_MAC),
        "CKM_WTLS_PRE_MASTER_KEY_GEN" => Some(CkMechanismType::WTLS_PRE_MASTER_KEY_GEN),
        "CKM_WTLS_MASTER_KEY_DERIVE" => Some(CkMechanismType::WTLS_MASTER_KEY_DERIVE),
        "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC" => Some(CkMechanismType::WTLS_MASTER_KEY_DERIVE_DH_ECC),
        "CKM_WTLS_PRF" => Some(CkMechanismType::WTLS_PRF),
        "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE" => {
            Some(CkMechanismType::WTLS_SERVER_KEY_AND_MAC_DERIVE)
        }
        "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE" => {
            Some(CkMechanismType::WTLS_CLIENT_KEY_AND_MAC_DERIVE)
        }
        "CKM_TLS12_MAC" => Some(CkMechanismType::TLS12_MAC),
        "CKM_TLS12_KDF" => Some(CkMechanismType::TLS12_KDF),
        "CKM_TLS12_MASTER_KEY_DERIVE" => Some(CkMechanismType::TLS12_MASTER_KEY_DERIVE),
        "CKM_TLS12_KEY_AND_MAC_DERIVE" => Some(CkMechanismType::TLS12_KEY_AND_MAC_DERIVE),
        "CKM_TLS12_MASTER_KEY_DERIVE_DH" => Some(CkMechanismType::TLS12_MASTER_KEY_DERIVE_DH),
        "CKM_TLS12_KEY_SAFE_DERIVE" => Some(CkMechanismType::TLS12_KEY_SAFE_DERIVE),
        "CKM_TLS_MAC" => Some(CkMechanismType::TLS_MAC),
        "CKM_TLS_KDF" => Some(CkMechanismType::TLS_KDF),
        "CKM_DES_OFB64" => Some(CkMechanismType::DES_OFB64),
        "CKM_DES_OFB8" => Some(CkMechanismType::DES_OFB8),
        "CKM_DES_CFB64" => Some(CkMechanismType::DES_CFB64),
        "CKM_DES_CFB8" => Some(CkMechanismType::DES_CFB8),
        _ => None,
    };
    if let Some(m) = named {
        return Ok(m);
    }
    // Numeric fallback: 0x... hex or decimal
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).map(CkMechanismType).map_err(|_| {
            format!("unknown mechanism '{t}': invalid hex integer; expected e.g. 0x00001087")
        });
    }
    if let Ok(n) = t.parse::<u64>() {
        return Ok(CkMechanismType(n));
    }
    Err(format!(
        "unknown mechanism '{t}'; expected a CKM_* name (e.g. CKM_AES_GCM), \
         a hex value (e.g. 0x00001087), or a decimal integer"
    ))
}

/// Parse a hex-encoded byte string into raw bytes for the CKA_UNIQUE_ID
/// per-object allow-list.
///
/// Accepted form: a lowercase or uppercase hex string with an even number
/// of hex digits (`"a1b2c3"` → `[0xa1, 0xb2, 0xc3]`). An empty or
/// whitespace-only string is rejected: it would match nothing (no
/// `CKA_UNIQUE_ID` is ever the empty byte sequence) while still flipping
/// `per_object_active()` to `true`, silently denying every object. Odd-length
/// or non-hex input is also rejected with a clear error.
pub fn parse_object_unique_id(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err(
            "invalid objects entry: empty or whitespace string is not a valid CKA_UNIQUE_ID \
             hex value. An empty entry matches nothing yet activates per-object authz, silently \
             denying all objects — refuse-to-start instead. Use a non-empty even-length hex \
             byte string (e.g. \"a1b2c3\")."
                .into(),
        );
    }
    hex::decode(t).map_err(|e| {
        format!(
            "invalid objects entry '{t}': {e}; expected an even-length hex byte string \
             (e.g. \"a1b2\"); got a string that is not valid hex or has an odd number of digits"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::parse_object_unique_id;

    // M2: empty / whitespace `objects` entries must be rejected.

    #[test]
    fn parse_uid_empty_string_rejected() {
        // M2: empty string matches nothing but would activate per-object authz,
        // silently denying all objects.
        assert!(parse_object_unique_id("").is_err(), "empty objects entry must be rejected");
    }

    #[test]
    fn parse_uid_whitespace_only_rejected() {
        // M2: whitespace-only is equivalent to empty after trim.
        assert!(
            parse_object_unique_id("   ").is_err(),
            "whitespace-only objects entry must be rejected"
        );
    }

    #[test]
    fn parse_uid_valid_hex_accepted() {
        // Sanity: a valid even-length hex string produces the decoded bytes.
        let result = parse_object_unique_id("aabbcc").unwrap();
        assert_eq!(result, &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn parse_uid_odd_length_hex_rejected() {
        // Odd-length hex string is not valid.
        assert!(parse_object_unique_id("abc").is_err(), "odd-length hex must be rejected");
    }

    #[test]
    fn parse_uid_non_hex_rejected() {
        // Non-hex characters are rejected.
        assert!(parse_object_unique_id("xyz").is_err(), "non-hex input must be rejected");
    }
}

/// Attribute type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CkAttributeType(pub u64);

impl CkAttributeType {
    pub const VENDOR_DEFINED: Self = Self(0x8000_0000);

    pub const CLASS: Self = Self(0x00000000);
    pub const TOKEN: Self = Self(0x00000001);
    pub const PRIVATE: Self = Self(0x00000002);
    pub const LABEL: Self = Self(0x00000003);
    pub const VALUE: Self = Self(0x00000011);
    pub const CERTIFICATE_TYPE: Self = Self(0x00000080);
    pub const ISSUER: Self = Self(0x00000081);
    pub const SERIAL_NUMBER: Self = Self(0x00000082);
    pub const SUBJECT: Self = Self(0x00000101);
    pub const KEY_TYPE: Self = Self(0x00000100);
    pub const SENSITIVE: Self = Self(0x00000103);
    pub const ENCRYPT: Self = Self(0x00000104);
    pub const DECRYPT: Self = Self(0x00000105);
    pub const WRAP: Self = Self(0x00000106);
    pub const UNWRAP: Self = Self(0x00000107);
    pub const SIGN: Self = Self(0x00000108);
    pub const VERIFY: Self = Self(0x0000010A);
    pub const EXTRACTABLE: Self = Self(0x00000162);
    pub const MODULUS: Self = Self(0x00000120);
    pub const MODULUS_BITS: Self = Self(0x00000121);
    pub const PUBLIC_EXPONENT: Self = Self(0x00000122);
    pub const PRIVATE_EXPONENT: Self = Self(0x0000_0123);
    pub const PRIME_1: Self = Self(0x0000_0124);
    pub const PRIME_2: Self = Self(0x0000_0125);
    pub const EXPONENT_1: Self = Self(0x0000_0126);
    pub const EXPONENT_2: Self = Self(0x0000_0127);
    pub const COEFFICIENT: Self = Self(0x0000_0128);
    pub const EC_PARAMS: Self = Self(0x00000180);
    pub const EC_POINT: Self = Self(0x00000181);
    pub const ID: Self = Self(0x00000102);
    /// `CKA_UNIQUE_ID` — PKCS#11 v3.0 mandatory, immutable byte-string
    /// globally unique identifier for storage objects (CK_BYTE_PTR, value
    /// 0x0000_0004 per the v3.x published headers; absent from v2.40).
    pub const UNIQUE_ID: Self = Self(0x0000_0004);
    pub const VALUE_LEN: Self = Self(0x00000161);
    pub const LOCAL: Self = Self(0x00000163);

    /// `CKF_ARRAY_ATTRIBUTE` flag (0x40000000).
    const ARRAY_ATTRIBUTE_FLAG: u64 = 0x4000_0000;

    pub const WRAP_TEMPLATE: Self = Self(Self::ARRAY_ATTRIBUTE_FLAG | 0x00000211);
    pub const UNWRAP_TEMPLATE: Self = Self(Self::ARRAY_ATTRIBUTE_FLAG | 0x00000212);
    pub const DERIVE_TEMPLATE: Self = Self(Self::ARRAY_ATTRIBUTE_FLAG | 0x00000213);
    pub const ALLOWED_MECHANISMS: Self = Self(Self::ARRAY_ATTRIBUTE_FLAG | 0x00000600);

    // Additional scalar `CK_ULONG` / `CK_ULONG`-typedef attributes for the
    // width bridge (ADR-0011 D10). Values verified against `cryptoki-sys` 0.5
    // and the OASIS attribute-type tables (common/key/certificate/hardware/
    // validation/trust/profile/mechanism/otp/hss/double-ratchet object specs).
    pub const CERTIFICATE_CATEGORY: Self = Self(0x00000087); // CK_CERTIFICATE_CATEGORY
    pub const JAVA_MIDP_SECURITY_DOMAIN: Self = Self(0x00000088); // CK_JAVA_MIDP_SECURITY_DOMAIN
    pub const NAME_HASH_ALGORITHM: Self = Self(0x0000008C); // CK_MECHANISM_TYPE
    pub const AUTH_PIN_FLAGS: Self = Self(0x00000201); // CK_FLAGS (deprecated; not in v3.x spec)
    pub const PRIME_BITS: Self = Self(0x00000133); // CK_ULONG
    pub const SUBPRIME_BITS: Self = Self(0x00000134); // CK_ULONG (alias CKA_SUB_PRIME_BITS)
    pub const VALUE_BITS: Self = Self(0x00000160); // CK_ULONG
    pub const KEY_GEN_MECHANISM: Self = Self(0x00000166); // CK_MECHANISM_TYPE
    pub const OTP_FORMAT: Self = Self(0x00000220); // CK_ULONG
    pub const OTP_LENGTH: Self = Self(0x00000221); // CK_ULONG
    pub const OTP_TIME_INTERVAL: Self = Self(0x00000222); // CK_ULONG
    pub const OTP_CHALLENGE_REQUIREMENT: Self = Self(0x00000224); // CK_ULONG
    pub const OTP_TIME_REQUIREMENT: Self = Self(0x00000225); // CK_ULONG
    pub const OTP_COUNTER_REQUIREMENT: Self = Self(0x00000226); // CK_ULONG
    pub const OTP_PIN_REQUIREMENT: Self = Self(0x00000227); // CK_ULONG
    pub const HW_FEATURE_TYPE: Self = Self(0x00000300); // CK_HW_FEATURE_TYPE
    pub const PIXEL_X: Self = Self(0x00000400); // CK_ULONG
    pub const PIXEL_Y: Self = Self(0x00000401); // CK_ULONG
    pub const RESOLUTION: Self = Self(0x00000402); // CK_ULONG
    pub const CHAR_ROWS: Self = Self(0x00000403); // CK_ULONG
    pub const CHAR_COLUMNS: Self = Self(0x00000404); // CK_ULONG
    pub const BITS_PER_PIXEL: Self = Self(0x00000406); // CK_ULONG
    pub const MECHANISM_TYPE: Self = Self(0x00000500); // CK_MECHANISM_TYPE
    pub const PROFILE_ID: Self = Self(0x00000601); // CK_PROFILE_ID
    pub const X2RATCHET_BAGSIZE: Self = Self(0x00000603); // CK_ULONG
    pub const X2RATCHET_NR: Self = Self(0x0000060F); // CK_ULONG
    pub const X2RATCHET_NS: Self = Self(0x00000610); // CK_ULONG
    pub const X2RATCHET_PNS: Self = Self(0x00000611); // CK_ULONG
    pub const HSS_LEVELS: Self = Self(0x00000617); // CK_ULONG
    pub const HSS_LMS_TYPE: Self = Self(0x00000618); // CK_ULONG
    pub const HSS_LMOTS_TYPE: Self = Self(0x00000619); // CK_ULONG
    pub const HSS_KEYS_REMAINING: Self = Self(0x0000061C); // CK_ULONG
    pub const PARAMETER_SET: Self = Self(0x0000061D); // CK_*_PARAMETER_SET_TYPE = CK_ULONG
    pub const OBJECT_VALIDATION_FLAGS: Self = Self(0x0000061E); // CK_FLAGS
    pub const VALIDATION_TYPE: Self = Self(0x0000061F); // CK_VALIDATION_TYPE = CK_ULONG
    pub const VALIDATION_LEVEL: Self = Self(0x00000621); // CK_ULONG
    pub const VALIDATION_FLAG: Self = Self(0x00000623); // CK_FLAGS
    pub const VALIDATION_AUTHORITY_TYPE: Self = Self(0x00000624); // = CK_ULONG
    pub const TRUST_SERVER_AUTH: Self = Self(0x0000062C); // CK_TRUST = CK_ULONG
    pub const TRUST_CLIENT_AUTH: Self = Self(0x0000062D); // CK_TRUST
    pub const TRUST_CODE_SIGNING: Self = Self(0x0000062E); // CK_TRUST
    pub const TRUST_EMAIL_PROTECTION: Self = Self(0x0000062F); // CK_TRUST
    pub const TRUST_IPSEC_IKE: Self = Self(0x00000630); // CK_TRUST
    pub const TRUST_TIME_STAMPING: Self = Self(0x00000631); // CK_TRUST
    pub const TRUST_OCSP_SIGNING: Self = Self(0x00000632); // CK_TRUST

    // Arrays of `CK_ULONG` / `CK_MECHANISM_TYPE`. Note: the HSS arrays do NOT
    // carry the CKF_ARRAY_ATTRIBUTE bit (they are arrays per spec text only);
    // CKA_ALLOWED_MECHANISMS does.
    pub const HSS_LMS_TYPES: Self = Self(0x0000061A); // CK_ULONG[]
    pub const HSS_LMOTS_TYPES: Self = Self(0x0000061B); // CK_ULONG[]

    pub const fn from_vendor(offset: u32) -> Self {
        Self(Self::VENDOR_DEFINED.0 | offset as u64)
    }

    pub const fn is_vendor_defined(self) -> bool {
        (self.0 & Self::VENDOR_DEFINED.0) == Self::VENDOR_DEFINED.0
    }

    /// Returns true if this attribute type has the `CKF_ARRAY_ATTRIBUTE` flag set,
    /// meaning its value is a nested `CK_ATTRIBUTE[]` template.
    pub const fn is_array_attribute(self) -> bool {
        (self.0 & Self::ARRAY_ATTRIBUTE_FLAG) == Self::ARRAY_ATTRIBUTE_FLAG
    }

    /// Returns true if this attribute's value is a nested `CK_ATTRIBUTE[]`
    /// template: `CKA_WRAP_TEMPLATE`, `CKA_UNWRAP_TEMPLATE`, or
    /// `CKA_DERIVE_TEMPLATE`.
    ///
    /// Distinct from [`is_array_attribute`](Self::is_array_attribute): other
    /// array-flagged attributes such as `CKA_ALLOWED_MECHANISMS` carry
    /// `CKF_ARRAY_ATTRIBUTE` but hold an array of `CK_MECHANISM_TYPE`
    /// (`CK_ULONG`), not `CK_ATTRIBUTE`, and must not be parsed as a nested
    /// template.
    pub fn is_attribute_template(self) -> bool {
        matches!(self, Self::WRAP_TEMPLATE | Self::UNWRAP_TEMPLATE | Self::DERIVE_TEMPLATE)
    }

    /// Returns true if this attribute type has a boolean value.
    pub fn is_bool(self) -> bool {
        matches!(
            self,
            Self::TOKEN
                | Self::PRIVATE
                | Self::SENSITIVE
                | Self::ENCRYPT
                | Self::DECRYPT
                | Self::WRAP
                | Self::UNWRAP
                | Self::SIGN
                | Self::VERIFY
                | Self::EXTRACTABLE
        )
    }

    /// Returns true if this attribute type has a single scalar `CK_ULONG`
    /// value (or a `CK_ULONG`-based typedef: `CK_OBJECT_CLASS`, `CK_KEY_TYPE`,
    /// `CK_MECHANISM_TYPE`, `CK_FLAGS`, `CK_TRUST`, etc.).
    ///
    /// This is the width-bridge classifier (ADR-0011 D10): a scalar ulong is the
    /// only attribute shape whose value must be re-encoded between a 32-bit and
    /// a 64-bit `CK_ULONG` edge. The set is sourced from the OASIS attribute-type
    /// tables and pinned by a cross-checked consistency test; a missing entry is
    /// invisible at same width but corrupts the value across an ABI boundary.
    /// Array-of-ulong attributes are classified by [`is_ulong_array`](Self::is_ulong_array).
    pub fn is_ulong(self) -> bool {
        matches!(
            self,
            Self::CLASS
                | Self::CERTIFICATE_TYPE
                | Self::CERTIFICATE_CATEGORY
                | Self::JAVA_MIDP_SECURITY_DOMAIN
                | Self::NAME_HASH_ALGORITHM
                | Self::KEY_TYPE
                | Self::AUTH_PIN_FLAGS
                | Self::MODULUS_BITS
                | Self::PRIME_BITS
                | Self::SUBPRIME_BITS
                | Self::VALUE_BITS
                | Self::VALUE_LEN
                | Self::KEY_GEN_MECHANISM
                | Self::OTP_FORMAT
                | Self::OTP_LENGTH
                | Self::OTP_TIME_INTERVAL
                | Self::OTP_CHALLENGE_REQUIREMENT
                | Self::OTP_TIME_REQUIREMENT
                | Self::OTP_COUNTER_REQUIREMENT
                | Self::OTP_PIN_REQUIREMENT
                | Self::HW_FEATURE_TYPE
                | Self::PIXEL_X
                | Self::PIXEL_Y
                | Self::RESOLUTION
                | Self::CHAR_ROWS
                | Self::CHAR_COLUMNS
                | Self::BITS_PER_PIXEL
                | Self::MECHANISM_TYPE
                | Self::PROFILE_ID
                | Self::X2RATCHET_BAGSIZE
                | Self::X2RATCHET_NR
                | Self::X2RATCHET_NS
                | Self::X2RATCHET_PNS
                | Self::HSS_LEVELS
                | Self::HSS_LMS_TYPE
                | Self::HSS_LMOTS_TYPE
                | Self::HSS_KEYS_REMAINING
                | Self::PARAMETER_SET
                | Self::OBJECT_VALIDATION_FLAGS
                | Self::VALIDATION_TYPE
                | Self::VALIDATION_LEVEL
                | Self::VALIDATION_FLAG
                | Self::VALIDATION_AUTHORITY_TYPE
                | Self::TRUST_SERVER_AUTH
                | Self::TRUST_CLIENT_AUTH
                | Self::TRUST_CODE_SIGNING
                | Self::TRUST_EMAIL_PROTECTION
                | Self::TRUST_IPSEC_IKE
                | Self::TRUST_TIME_STAMPING
                | Self::TRUST_OCSP_SIGNING
        )
    }

    /// Returns true if this attribute's value is an **array of `CK_ULONG`**
    /// (or `CK_MECHANISM_TYPE`): `CKA_ALLOWED_MECHANISMS`, `CKA_HSS_LMS_TYPES`,
    /// `CKA_HSS_LMOTS_TYPES`.
    ///
    /// Distinct from [`is_attribute_template`](Self::is_attribute_template)
    /// (nested `CK_ATTRIBUTE[]`) and from [`is_ulong`](Self::is_ulong) (a single
    /// value). For the width bridge each element is re-encoded between widths,
    /// and the byte length rescales by element count. Note `CKA_ALLOWED_MECHANISMS`
    /// carries the `CKF_ARRAY_ATTRIBUTE` bit but the HSS arrays do not, so this
    /// must be keyed on the attribute type, not the flag.
    pub fn is_ulong_array(self) -> bool {
        matches!(self, Self::ALLOWED_MECHANISMS | Self::HSS_LMS_TYPES | Self::HSS_LMOTS_TYPES)
    }

    /// Returns true if this attribute's CK_ULONG value is used as an
    /// allocation size by backends.  Absurd values (e.g., ULONG_MAX)
    /// can cause capacity-overflow panics inside `extern "C"` backend
    /// functions, aborting the daemon process.
    pub fn is_allocation_size(self) -> bool {
        // W1-C9-11: ADR-0011 guards CKA_VALUE_LEN, CKA_MODULUS_BITS, and the
        // CKA_*_BITS length attributes against absurd backend allocations.
        matches!(
            self,
            Self::VALUE_LEN
                | Self::MODULUS_BITS
                | Self::PRIME_BITS
                | Self::SUBPRIME_BITS
                | Self::VALUE_BITS
        )
    }
}

/// Attributes that carry secret key material and must be protected during
/// extract/serialization operations. Used by the extract-deny authorization gate.
pub const VALUE_BEARING_SECRET: &[CkAttributeType] = &[
    CkAttributeType::VALUE,
    CkAttributeType::PRIVATE_EXPONENT,
    CkAttributeType::PRIME_1,
    CkAttributeType::PRIME_2,
    CkAttributeType::EXPONENT_1,
    CkAttributeType::EXPONENT_2,
    CkAttributeType::COEFFICIENT,
];

/// Returns true if the attribute type carries secret key material that must
/// be protected during extract/serialization operations.
pub fn is_value_bearing_secret(t: CkAttributeType) -> bool {
    VALUE_BEARING_SECRET.contains(&t)
}

/// A typed attribute value (ADR-0001: known attributes use typed serialization).
///
/// `Bytes`/`String` hold `SecretBytes` (ADR-0013): attribute fields are
/// polymorphic — `Attribute.bytes_value`/`string_value` are classified secret
/// and fail closed — so every value is a wiping, redacted owner. Text must be
/// decoded inside `SecretBytes::expose`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CkAttributeValue {
    Bool(bool),
    Ulong(u64),
    Bytes(crate::secret::SecretBytes),
    String(crate::secret::SecretBytes),
    /// A nested `CK_ATTRIBUTE[]` template value (the input direction of
    /// CKF_ARRAY_ATTRIBUTE attributes, e.g. CKA_WRAP_TEMPLATE inside a
    /// C_CreateObject template). Carried structurally: raw client
    /// `CK_ATTRIBUTE` struct bytes contain client-address-space pointers
    /// and are meaningless (and dangerous) on the backend. Depth is
    /// bounded at one level of nesting (ADR-0011 D8): sub-attributes must
    /// not themselves be templates.
    NestedTemplate(Vec<CkAttribute>),
}

/// A single PKCS#11 attribute (type + optional value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkAttribute {
    pub attr_type: CkAttributeType,
    pub value: Option<CkAttributeValue>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // `u64::from` is identity on 64-bit targets but widens `CK_ULONG` on
    // 32-bit targets; the conversion keeps this oracle portable.
    #[allow(clippy::useless_conversion)]
    fn unique_id_matches_published_header() {
        assert_eq!(CkAttributeType::UNIQUE_ID.0, u64::from(cryptoki_sys::CKA_UNIQUE_ID));
        assert_eq!(CkAttributeType::UNIQUE_ID.0, 0x04);
    }

    #[test]
    fn attr_type_classification() {
        assert!(CkAttributeType::TOKEN.is_bool());
        assert!(CkAttributeType::CLASS.is_ulong());
        assert!(!CkAttributeType::LABEL.is_bool());
        assert!(!CkAttributeType::LABEL.is_ulong());
    }

    #[test]
    fn is_ulong_covers_full_oasis_scalar_set() {
        // Representatives across every object category that carries a scalar
        // CK_ULONG / CK_ULONG-typedef value (OASIS 3.x + legacy). A missing
        // entry silently corrupts that attribute's value across a 32/64-bit ABI.
        for t in [
            CkAttributeType::CLASS,
            CkAttributeType::CERTIFICATE_CATEGORY,
            CkAttributeType::JAVA_MIDP_SECURITY_DOMAIN,
            CkAttributeType::NAME_HASH_ALGORITHM,
            CkAttributeType::AUTH_PIN_FLAGS,
            CkAttributeType::PRIME_BITS,
            CkAttributeType::SUBPRIME_BITS,
            CkAttributeType::VALUE_BITS,
            CkAttributeType::KEY_GEN_MECHANISM,
            CkAttributeType::OTP_FORMAT,
            CkAttributeType::OTP_PIN_REQUIREMENT,
            CkAttributeType::HW_FEATURE_TYPE,
            CkAttributeType::BITS_PER_PIXEL,
            CkAttributeType::MECHANISM_TYPE,
            CkAttributeType::PROFILE_ID,
            CkAttributeType::X2RATCHET_BAGSIZE,
            CkAttributeType::HSS_LEVELS,
            CkAttributeType::PARAMETER_SET,
            CkAttributeType::VALIDATION_TYPE,
            CkAttributeType::OBJECT_VALIDATION_FLAGS,
            CkAttributeType::TRUST_SERVER_AUTH,
            CkAttributeType::TRUST_OCSP_SIGNING,
        ] {
            assert!(t.is_ulong(), "expected {t:?} to be classified ulong");
            assert!(!t.is_ulong_array(), "scalar {t:?} must not be a ulong array");
        }
    }

    #[test]
    fn is_ulong_excludes_non_ulong_types() {
        for t in [
            CkAttributeType::LABEL,
            CkAttributeType::MODULUS,
            CkAttributeType::VALUE,
            CkAttributeType::ID,
            CkAttributeType::SUBJECT,
            CkAttributeType::TOKEN,              // bool
            CkAttributeType::ALLOWED_MECHANISMS, // array, not scalar
        ] {
            assert!(!t.is_ulong(), "expected {t:?} NOT to be classified scalar ulong");
        }
    }

    #[test]
    fn is_ulong_array_covers_oasis_array_set() {
        for t in [
            CkAttributeType::ALLOWED_MECHANISMS,
            CkAttributeType::HSS_LMS_TYPES,
            CkAttributeType::HSS_LMOTS_TYPES,
        ] {
            assert!(t.is_ulong_array(), "expected {t:?} to be a ulong array");
            assert!(!t.is_ulong(), "array {t:?} must not be a scalar ulong");
        }
        // Scalars and nested templates are not ulong arrays.
        assert!(!CkAttributeType::CLASS.is_ulong_array());
        assert!(!CkAttributeType::WRAP_TEMPLATE.is_ulong_array());
        assert!(!CkAttributeType::LABEL.is_ulong_array());
    }

    #[test]
    fn allocation_size_classification() {
        // W1-C9-11: ADR-0011 claims CKA_VALUE_LEN, CKA_MODULUS_BITS, and
        // CKA_*_BITS are all guarded as allocation sizes — enumerate all five.
        for t in [
            CkAttributeType::VALUE_LEN,
            CkAttributeType::MODULUS_BITS,
            CkAttributeType::PRIME_BITS,
            CkAttributeType::SUBPRIME_BITS,
            CkAttributeType::VALUE_BITS,
        ] {
            assert!(t.is_allocation_size(), "expected allocation size: {t:?}");
        }
        // Constants, not sizes — should not be flagged
        assert!(!CkAttributeType::CLASS.is_allocation_size());
        assert!(!CkAttributeType::KEY_TYPE.is_allocation_size());
        assert!(!CkAttributeType::CERTIFICATE_TYPE.is_allocation_size());
    }

    #[test]
    fn subject_attribute_has_standard_id() {
        assert_eq!(CkAttributeType::SUBJECT.0, 0x0000_0101);
    }

    // W1-C11-25: certificate ISSUER/SERIAL_NUMBER consts (OASIS ids
    // 0x81/0x82, matching cryptoki-sys 0.5 CKA_ISSUER=129,
    // CKA_SERIAL_NUMBER=130) so the CLI name table stays typed.
    #[test]
    fn issuer_and_serial_number_have_standard_ids() {
        assert_eq!(CkAttributeType::ISSUER.0, 0x0000_0081);
        assert_eq!(CkAttributeType::SERIAL_NUMBER.0, 0x0000_0082);
    }

    #[test]
    fn vendor_attribute_helpers() {
        let vendor = CkAttributeType::from_vendor(0x42);
        assert_eq!(vendor.0, 0x8000_0042);
        assert!(vendor.is_vendor_defined());
        assert!(!CkAttributeType::LABEL.is_vendor_defined());
    }

    #[test]
    fn value_bearing_secret_constants() {
        // Verify RSA private key component constants match PKCS#11 spec values
        assert_eq!(CkAttributeType::PRIVATE_EXPONENT.0, 0x0000_0123);
        assert_eq!(CkAttributeType::PRIME_1.0, 0x0000_0124);
        assert_eq!(CkAttributeType::PRIME_2.0, 0x0000_0125);
        assert_eq!(CkAttributeType::EXPONENT_1.0, 0x0000_0126);
        assert_eq!(CkAttributeType::EXPONENT_2.0, 0x0000_0127);
        assert_eq!(CkAttributeType::COEFFICIENT.0, 0x0000_0128);
    }

    #[test]
    fn is_value_bearing_secret_classification() {
        // Secret attributes should be classified as value-bearing secrets
        assert!(is_value_bearing_secret(CkAttributeType::VALUE));
        assert!(is_value_bearing_secret(CkAttributeType::PRIVATE_EXPONENT));
        assert!(is_value_bearing_secret(CkAttributeType::PRIME_1));
        assert!(is_value_bearing_secret(CkAttributeType::PRIME_2));
        assert!(is_value_bearing_secret(CkAttributeType::EXPONENT_1));
        assert!(is_value_bearing_secret(CkAttributeType::EXPONENT_2));
        assert!(is_value_bearing_secret(CkAttributeType::COEFFICIENT));

        // Public attributes must not be classified as value-bearing secrets
        assert!(!is_value_bearing_secret(CkAttributeType::MODULUS));
        assert!(!is_value_bearing_secret(CkAttributeType::PUBLIC_EXPONENT));
        assert!(!is_value_bearing_secret(CkAttributeType::EC_POINT));
        assert!(!is_value_bearing_secret(CkAttributeType::EC_PARAMS));
        assert!(!is_value_bearing_secret(CkAttributeType::LABEL));
    }
}

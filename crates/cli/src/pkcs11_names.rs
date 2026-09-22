use pkcs11_proxy_ng_types::*;

/// Every `CkAttributeType` const as its CLI name (W1-C11-25): one
/// table drives both `parse_attr_type` and `attr_type_name`, so the
/// CLI accepts every types-defined name (SUBJECT, ISSUER,
/// SERIAL_NUMBER, KEY_GEN_MECHANISM, LOCAL, ...) and both directions
/// stay in sync. Names match the const idents exactly.
const ATTR_NAMES: &[(&str, CkAttributeType)] = &[
    ("CLASS", CkAttributeType::CLASS),
    ("TOKEN", CkAttributeType::TOKEN),
    ("PRIVATE", CkAttributeType::PRIVATE),
    ("LABEL", CkAttributeType::LABEL),
    ("VALUE", CkAttributeType::VALUE),
    ("CERTIFICATE_TYPE", CkAttributeType::CERTIFICATE_TYPE),
    ("ISSUER", CkAttributeType::ISSUER),
    ("SERIAL_NUMBER", CkAttributeType::SERIAL_NUMBER),
    ("SUBJECT", CkAttributeType::SUBJECT),
    ("KEY_TYPE", CkAttributeType::KEY_TYPE),
    ("SENSITIVE", CkAttributeType::SENSITIVE),
    ("ENCRYPT", CkAttributeType::ENCRYPT),
    ("DECRYPT", CkAttributeType::DECRYPT),
    ("WRAP", CkAttributeType::WRAP),
    ("UNWRAP", CkAttributeType::UNWRAP),
    ("SIGN", CkAttributeType::SIGN),
    ("VERIFY", CkAttributeType::VERIFY),
    ("EXTRACTABLE", CkAttributeType::EXTRACTABLE),
    ("MODULUS", CkAttributeType::MODULUS),
    ("MODULUS_BITS", CkAttributeType::MODULUS_BITS),
    ("PUBLIC_EXPONENT", CkAttributeType::PUBLIC_EXPONENT),
    ("PRIVATE_EXPONENT", CkAttributeType::PRIVATE_EXPONENT),
    ("PRIME_1", CkAttributeType::PRIME_1),
    ("PRIME_2", CkAttributeType::PRIME_2),
    ("EXPONENT_1", CkAttributeType::EXPONENT_1),
    ("EXPONENT_2", CkAttributeType::EXPONENT_2),
    ("COEFFICIENT", CkAttributeType::COEFFICIENT),
    ("EC_PARAMS", CkAttributeType::EC_PARAMS),
    ("EC_POINT", CkAttributeType::EC_POINT),
    ("ID", CkAttributeType::ID),
    ("UNIQUE_ID", CkAttributeType::UNIQUE_ID),
    ("VALUE_LEN", CkAttributeType::VALUE_LEN),
    ("LOCAL", CkAttributeType::LOCAL),
    ("WRAP_TEMPLATE", CkAttributeType::WRAP_TEMPLATE),
    ("UNWRAP_TEMPLATE", CkAttributeType::UNWRAP_TEMPLATE),
    ("DERIVE_TEMPLATE", CkAttributeType::DERIVE_TEMPLATE),
    ("ALLOWED_MECHANISMS", CkAttributeType::ALLOWED_MECHANISMS),
    ("CERTIFICATE_CATEGORY", CkAttributeType::CERTIFICATE_CATEGORY),
    ("JAVA_MIDP_SECURITY_DOMAIN", CkAttributeType::JAVA_MIDP_SECURITY_DOMAIN),
    ("NAME_HASH_ALGORITHM", CkAttributeType::NAME_HASH_ALGORITHM),
    ("AUTH_PIN_FLAGS", CkAttributeType::AUTH_PIN_FLAGS),
    ("PRIME_BITS", CkAttributeType::PRIME_BITS),
    ("SUBPRIME_BITS", CkAttributeType::SUBPRIME_BITS),
    ("VALUE_BITS", CkAttributeType::VALUE_BITS),
    ("KEY_GEN_MECHANISM", CkAttributeType::KEY_GEN_MECHANISM),
    ("OTP_FORMAT", CkAttributeType::OTP_FORMAT),
    ("OTP_LENGTH", CkAttributeType::OTP_LENGTH),
    ("OTP_TIME_INTERVAL", CkAttributeType::OTP_TIME_INTERVAL),
    ("OTP_CHALLENGE_REQUIREMENT", CkAttributeType::OTP_CHALLENGE_REQUIREMENT),
    ("OTP_TIME_REQUIREMENT", CkAttributeType::OTP_TIME_REQUIREMENT),
    ("OTP_COUNTER_REQUIREMENT", CkAttributeType::OTP_COUNTER_REQUIREMENT),
    ("OTP_PIN_REQUIREMENT", CkAttributeType::OTP_PIN_REQUIREMENT),
    ("HW_FEATURE_TYPE", CkAttributeType::HW_FEATURE_TYPE),
    ("PIXEL_X", CkAttributeType::PIXEL_X),
    ("PIXEL_Y", CkAttributeType::PIXEL_Y),
    ("RESOLUTION", CkAttributeType::RESOLUTION),
    ("CHAR_ROWS", CkAttributeType::CHAR_ROWS),
    ("CHAR_COLUMNS", CkAttributeType::CHAR_COLUMNS),
    ("BITS_PER_PIXEL", CkAttributeType::BITS_PER_PIXEL),
    ("MECHANISM_TYPE", CkAttributeType::MECHANISM_TYPE),
    ("PROFILE_ID", CkAttributeType::PROFILE_ID),
    ("X2RATCHET_BAGSIZE", CkAttributeType::X2RATCHET_BAGSIZE),
    ("X2RATCHET_NR", CkAttributeType::X2RATCHET_NR),
    ("X2RATCHET_NS", CkAttributeType::X2RATCHET_NS),
    ("X2RATCHET_PNS", CkAttributeType::X2RATCHET_PNS),
    ("HSS_LEVELS", CkAttributeType::HSS_LEVELS),
    ("HSS_LMS_TYPE", CkAttributeType::HSS_LMS_TYPE),
    ("HSS_LMOTS_TYPE", CkAttributeType::HSS_LMOTS_TYPE),
    ("HSS_KEYS_REMAINING", CkAttributeType::HSS_KEYS_REMAINING),
    ("PARAMETER_SET", CkAttributeType::PARAMETER_SET),
    ("OBJECT_VALIDATION_FLAGS", CkAttributeType::OBJECT_VALIDATION_FLAGS),
    ("VALIDATION_TYPE", CkAttributeType::VALIDATION_TYPE),
    ("VALIDATION_LEVEL", CkAttributeType::VALIDATION_LEVEL),
    ("VALIDATION_FLAG", CkAttributeType::VALIDATION_FLAG),
    ("VALIDATION_AUTHORITY_TYPE", CkAttributeType::VALIDATION_AUTHORITY_TYPE),
    ("TRUST_SERVER_AUTH", CkAttributeType::TRUST_SERVER_AUTH),
    ("TRUST_CLIENT_AUTH", CkAttributeType::TRUST_CLIENT_AUTH),
    ("TRUST_CODE_SIGNING", CkAttributeType::TRUST_CODE_SIGNING),
    ("TRUST_EMAIL_PROTECTION", CkAttributeType::TRUST_EMAIL_PROTECTION),
    ("TRUST_IPSEC_IKE", CkAttributeType::TRUST_IPSEC_IKE),
    ("TRUST_TIME_STAMPING", CkAttributeType::TRUST_TIME_STAMPING),
    ("TRUST_OCSP_SIGNING", CkAttributeType::TRUST_OCSP_SIGNING),
    ("HSS_LMS_TYPES", CkAttributeType::HSS_LMS_TYPES),
    ("HSS_LMOTS_TYPES", CkAttributeType::HSS_LMOTS_TYPES),
];

/// Parse-only aliases (W1-C11-25): accepted by `parse_attr_type` but
/// never rendered by `attr_type_name` (`SUB_PRIME_BITS` is the
/// spec-text spelling types documents for `SUBPRIME_BITS`).
const ATTR_ALIASES: &[(&str, CkAttributeType)] =
    &[("SUB_PRIME_BITS", CkAttributeType::SUBPRIME_BITS)];

pub(crate) fn parse_attr_type(s: &str) -> Result<CkAttributeType, Box<dyn core::error::Error>> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16)
            .map(CkAttributeType)
            .map_err(|e| format!("Invalid attr type hex: {e}").into());
    }
    // Decimal ids, like parse_mechanism (W1-C11-25).
    if let Ok(n) = s.parse::<u64>() {
        return Ok(CkAttributeType(n));
    }
    let upper = s.to_uppercase();
    ATTR_NAMES
        .iter()
        .chain(ATTR_ALIASES.iter())
        .find(|(name, _)| *name == upper)
        .map(|(_, attr_type)| *attr_type)
        .ok_or_else(|| {
            format!(
                "Unknown attribute type '{s}'. Use 0x<hex>, a decimal id, or a name like \
                 LABEL, SUBJECT, ISSUER, SERIAL_NUMBER, CLASS, KEY_TYPE, ID, VALUE, EC_PARAMS."
            )
            .into()
        })
}

pub(crate) fn attr_type_name(v: u64) -> String {
    // Match against the typed constants from CkAttributeType so the
    // name table stays in sync with the canonical definitions.
    ATTR_NAMES
        .iter()
        .find(|(_, attr_type)| attr_type.0 == v)
        .map(|(name, _)| name.to_string())
        .unwrap_or_else(|| format!("0x{v:08X}"))
}

/// Interpret a native-order byte slice as a u64 (handles 4-byte and 8-byte CK_ULONG).
///
/// The bytes are the `Bytes` values from the client's non-exact
/// `get_attribute_value` convenience API (which wraps Exact-RPC results);
/// native decoding is correct for same-endian daemons (ADR-0011 D6 refuses
/// mismatched pairs).
pub(crate) fn bytes_to_u64(b: &[u8]) -> Option<u64> {
    match b.len() {
        4 => Some(u64::from(u32::from_ne_bytes(b.try_into().ok()?))),
        8 => Some(u64::from_ne_bytes(b.try_into().ok()?)),
        _ => None,
    }
}

pub(crate) fn object_class_name(v: u64) -> String {
    let name = match CkObjectClass(v) {
        CkObjectClass::DATA => "data",
        CkObjectClass::CERTIFICATE => "certificate",
        CkObjectClass::PUBLIC_KEY => "public-key",
        CkObjectClass::PRIVATE_KEY => "private-key",
        CkObjectClass::SECRET_KEY => "secret-key",
        CkObjectClass::HW_FEATURE => "hw-feature",
        CkObjectClass::DOMAIN_PARAMETERS => "domain-parameters",
        CkObjectClass::MECHANISM => "mechanism",
        CkObjectClass::OTP_KEY => "otp-key",
        _ => return format!("0x{v:08X}"),
    };
    name.to_string()
}

pub(crate) fn key_type_name(v: u64) -> String {
    let name = match CkKeyType(v) {
        CkKeyType::RSA => "RSA",
        CkKeyType::DSA => "DSA",
        CkKeyType::DH => "DH",
        CkKeyType::EC => "EC",
        CkKeyType::X9_42_DH => "X9_42_DH",
        CkKeyType::KEA => "KEA",
        CkKeyType::GENERIC_SECRET => "GENERIC_SECRET",
        CkKeyType::RC2 => "RC2",
        CkKeyType::RC4 => "RC4",
        CkKeyType::DES => "DES",
        CkKeyType::DES2 => "DES2",
        CkKeyType::DES3 => "DES3",
        CkKeyType::CAST => "CAST",
        CkKeyType::CAST3 => "CAST3",
        CkKeyType::CAST128 => "CAST128",
        CkKeyType::RC5 => "RC5",
        CkKeyType::IDEA => "IDEA",
        CkKeyType::SKIPJACK => "SKIPJACK",
        CkKeyType::BATON => "BATON",
        CkKeyType::JUNIPER => "JUNIPER",
        CkKeyType::CDMF => "CDMF",
        CkKeyType::AES => "AES",
        CkKeyType::BLOWFISH => "BLOWFISH",
        CkKeyType::TWOFISH => "TWOFISH",
        CkKeyType::SECURID => "SECURID",
        CkKeyType::HOTP => "HOTP",
        CkKeyType::ACTI => "ACTI",
        CkKeyType::CAMELLIA => "CAMELLIA",
        CkKeyType::ARIA => "ARIA",
        CkKeyType::SHA512_224 => "SHA512_224",
        CkKeyType::SHA512_256 => "SHA512_256",
        CkKeyType::SEED => "SEED",
        CkKeyType::GOSTR3410 => "GOSTR3410",
        CkKeyType::GOSTR3411 => "GOSTR3411",
        CkKeyType::GOST28147 => "GOST28147",
        CkKeyType::CHACHA20 => "CHACHA20",
        CkKeyType::POLY1305 => "POLY1305",
        CkKeyType::AES_XTS => "AES_XTS",
        CkKeyType::SHA3_224 => "SHA3_224",
        CkKeyType::SHA3_256 => "SHA3_256",
        CkKeyType::SHA3_384 => "SHA3_384",
        CkKeyType::SHA3_512 => "SHA3_512",
        CkKeyType::BLAKE2B_160 => "BLAKE2B_160",
        CkKeyType::BLAKE2B_256 => "BLAKE2B_256",
        CkKeyType::BLAKE2B_384 => "BLAKE2B_384",
        CkKeyType::BLAKE2B_512 => "BLAKE2B_512",
        CkKeyType::SALSA20 => "SALSA20",
        CkKeyType::X2RATCHET => "X2RATCHET",
        CkKeyType::EC_EDWARDS => "EC_EDWARDS",
        CkKeyType::EC_MONTGOMERY => "EC_MONTGOMERY",
        CkKeyType::HKDF => "HKDF",
        _ => return format!("0x{v:08X}"),
    };
    name.to_string()
}

#[cfg(test)]
mod object_class_name_tests {
    use super::*;

    #[test]
    fn resolves_standard_and_extended_classes() {
        assert_eq!(object_class_name(0), "data");
        assert_eq!(object_class_name(1), "certificate");
        assert_eq!(object_class_name(2), "public-key");
        assert_eq!(object_class_name(3), "private-key");
        assert_eq!(object_class_name(4), "secret-key");
        // W1-C9-07: extended classes resolve instead of falling through to hex.
        assert_eq!(object_class_name(5), "hw-feature");
        assert_eq!(object_class_name(6), "domain-parameters");
        assert_eq!(object_class_name(7), "mechanism");
        assert_eq!(object_class_name(8), "otp-key");
        assert_eq!(object_class_name(0x8000_0001), "0x80000001");
    }
}

#[cfg(test)]
mod attr_name_tests {
    use super::*;

    // W1-C11-30/W1-C11-25: every types-defined attr name parses
    // (case-insensitive) and round-trips through attr_type_name. The
    // count pin catches dropped rows; the id pins below catch
    // mis-mapped ones (a pure round-trip would stay green on a wrong
    // const). Aliases parse but render canonically.
    #[test]
    fn attr_names_parse_and_round_trip() {
        assert_eq!(super::ATTR_NAMES.len(), 84);
        for (name, id) in super::ATTR_NAMES {
            assert_eq!(parse_attr_type(name).unwrap(), *id, "{name}");
            assert_eq!(parse_attr_type(&name.to_lowercase()).unwrap(), *id, "{name} lower");
            assert_eq!(attr_type_name(id.0), (*name).to_string(), "0x{:X}", id.0);
        }
        assert_eq!(parse_attr_type("SUBJECT").unwrap().0, 0x101);
        assert_eq!(parse_attr_type("ISSUER").unwrap().0, 0x81);
        assert_eq!(parse_attr_type("SERIAL_NUMBER").unwrap().0, 0x82);
        assert_eq!(parse_attr_type("KEY_GEN_MECHANISM").unwrap().0, 0x166);
        assert_eq!(parse_attr_type("UNIQUE_ID").unwrap().0, 0x04);
        assert_eq!(parse_attr_type("SUB_PRIME_BITS").unwrap(), CkAttributeType::SUBPRIME_BITS);
        assert_eq!(attr_type_name(CkAttributeType::SUBPRIME_BITS.0), "SUBPRIME_BITS");
        // W1-C11-25: common cert/key names plus other types-defined
        // names and decimal ids parse (like parse_mechanism).
        assert_eq!(parse_attr_type("SUBJECT").unwrap(), CkAttributeType::SUBJECT);
        assert_eq!(parse_attr_type("subject").unwrap(), CkAttributeType::SUBJECT);
        assert_eq!(parse_attr_type("ISSUER").unwrap(), CkAttributeType::ISSUER);
        assert_eq!(parse_attr_type("SERIAL_NUMBER").unwrap(), CkAttributeType::SERIAL_NUMBER);
        assert_eq!(parse_attr_type("LOCAL").unwrap(), CkAttributeType::LOCAL);
        assert_eq!(
            parse_attr_type("KEY_GEN_MECHANISM").unwrap(),
            CkAttributeType::KEY_GEN_MECHANISM
        );
        assert_eq!(parse_attr_type("3").unwrap(), CkAttributeType::LABEL);
        assert_eq!(parse_attr_type("17").unwrap(), CkAttributeType::VALUE);
        // Hex spellings (either case prefix) and unknown handling.
        assert_eq!(parse_attr_type("0x3").unwrap(), CkAttributeType::LABEL);
        assert_eq!(parse_attr_type("0X3").unwrap(), CkAttributeType::LABEL);
        let err = parse_attr_type("NO_SUCH_ATTR").unwrap_err().to_string();
        assert!(err.contains("NO_SUCH_ATTR"), "must echo: {err}");
        assert_eq!(attr_type_name(0xDEAD_BEEF), "0xDEADBEEF");
    }
}

#[cfg(test)]
mod bytes_to_u64_tests {
    use super::*;

    #[test]
    fn decodes_native_order_at_both_widths() {
        // 0x0102_0304 distinguishes LE from BE absolutely: native decoding
        // must round-trip the native encoding on every host.
        assert_eq!(bytes_to_u64(&0x0102_0304u32.to_ne_bytes()), Some(0x0102_0304));
        assert_eq!(
            bytes_to_u64(&0x0102_0304_0506_0708u64.to_ne_bytes()),
            Some(0x0102_0304_0506_0708)
        );
        assert_eq!(bytes_to_u64(&[1, 2, 3]), None);
    }
}

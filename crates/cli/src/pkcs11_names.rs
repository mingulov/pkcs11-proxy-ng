use pkcs11_proxy_ng_types::*;

pub(crate) fn parse_attr_type(s: &str) -> Result<CkAttributeType, Box<dyn core::error::Error>> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16)
            .map(CkAttributeType)
            .map_err(|e| format!("Invalid attr type hex: {e}").into());
    }
    match s.to_uppercase().as_str() {
        "CLASS" => Ok(CkAttributeType::CLASS),
        "TOKEN" => Ok(CkAttributeType::TOKEN),
        "PRIVATE" => Ok(CkAttributeType::PRIVATE),
        "LABEL" => Ok(CkAttributeType::LABEL),
        "VALUE" => Ok(CkAttributeType::VALUE),
        "CERTIFICATE_TYPE" => Ok(CkAttributeType::CERTIFICATE_TYPE),
        "KEY_TYPE" => Ok(CkAttributeType::KEY_TYPE),
        "ID" => Ok(CkAttributeType::ID),
        "SENSITIVE" => Ok(CkAttributeType::SENSITIVE),
        "ENCRYPT" => Ok(CkAttributeType::ENCRYPT),
        "DECRYPT" => Ok(CkAttributeType::DECRYPT),
        "WRAP" => Ok(CkAttributeType::WRAP),
        "UNWRAP" => Ok(CkAttributeType::UNWRAP),
        "SIGN" => Ok(CkAttributeType::SIGN),
        "VERIFY" => Ok(CkAttributeType::VERIFY),
        "EXTRACTABLE" => Ok(CkAttributeType::EXTRACTABLE),
        "MODULUS" => Ok(CkAttributeType::MODULUS),
        "MODULUS_BITS" => Ok(CkAttributeType::MODULUS_BITS),
        "PUBLIC_EXPONENT" => Ok(CkAttributeType::PUBLIC_EXPONENT),
        "EC_PARAMS" => Ok(CkAttributeType::EC_PARAMS),
        "EC_POINT" => Ok(CkAttributeType::EC_POINT),
        "VALUE_LEN" => Ok(CkAttributeType::VALUE_LEN),
        _ => Err(format!(
            "Unknown attribute type '{s}'. Use 0x<hex> or a name like LABEL, CLASS, KEY_TYPE, ID, VALUE, EC_PARAMS."
        ).into()),
    }
}

pub(crate) fn attr_type_name(v: u64) -> String {
    // Match against the typed constants from CkAttributeType so the
    // name table stays in sync with the canonical definitions.
    let name = match CkAttributeType(v) {
        CkAttributeType::CLASS => "CLASS",
        CkAttributeType::TOKEN => "TOKEN",
        CkAttributeType::PRIVATE => "PRIVATE",
        CkAttributeType::LABEL => "LABEL",
        CkAttributeType::VALUE => "VALUE",
        CkAttributeType::CERTIFICATE_TYPE => "CERTIFICATE_TYPE",
        CkAttributeType::KEY_TYPE => "KEY_TYPE",
        CkAttributeType::ID => "ID",
        CkAttributeType::SENSITIVE => "SENSITIVE",
        CkAttributeType::ENCRYPT => "ENCRYPT",
        CkAttributeType::DECRYPT => "DECRYPT",
        CkAttributeType::WRAP => "WRAP",
        CkAttributeType::UNWRAP => "UNWRAP",
        CkAttributeType::SIGN => "SIGN",
        CkAttributeType::VERIFY => "VERIFY",
        CkAttributeType::MODULUS => "MODULUS",
        CkAttributeType::MODULUS_BITS => "MODULUS_BITS",
        CkAttributeType::PUBLIC_EXPONENT => "PUBLIC_EXPONENT",
        CkAttributeType::VALUE_LEN => "VALUE_LEN",
        CkAttributeType::EXTRACTABLE => "EXTRACTABLE",
        CkAttributeType::EC_PARAMS => "EC_PARAMS",
        CkAttributeType::EC_POINT => "EC_POINT",
        _ => return format!("0x{v:08X}"),
    };
    name.to_string()
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

    // W1-C11-30: every accepted attr name parses (case-insensitive)
    // and round-trips through attr_type_name (Task 39 extends the
    // accepted set; this test pins the current rows).
    #[test]
    fn attr_names_parse_and_round_trip() {
        let names: &[(&str, CkAttributeType)] = &[
            ("CLASS", CkAttributeType::CLASS),
            ("TOKEN", CkAttributeType::TOKEN),
            ("PRIVATE", CkAttributeType::PRIVATE),
            ("LABEL", CkAttributeType::LABEL),
            ("VALUE", CkAttributeType::VALUE),
            ("CERTIFICATE_TYPE", CkAttributeType::CERTIFICATE_TYPE),
            ("KEY_TYPE", CkAttributeType::KEY_TYPE),
            ("ID", CkAttributeType::ID),
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
            ("EC_PARAMS", CkAttributeType::EC_PARAMS),
            ("EC_POINT", CkAttributeType::EC_POINT),
            ("VALUE_LEN", CkAttributeType::VALUE_LEN),
        ];
        assert_eq!(names.len(), 22);
        for (name, id) in names {
            assert_eq!(parse_attr_type(name).unwrap(), *id, "{name}");
            assert_eq!(parse_attr_type(&name.to_lowercase()).unwrap(), *id, "{name} lower");
            assert_eq!(attr_type_name(id.0), *name.to_string(), "0x{:X}", id.0);
        }
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

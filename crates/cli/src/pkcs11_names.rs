use pkcs11_proxy_ng_types::*;

pub(crate) fn parse_attr_type(s: &str) -> Result<CkAttributeType, Box<dyn std::error::Error>> {
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
    match v {
        0x00000000 => "CLASS".to_string(),
        0x00000001 => "TOKEN".to_string(),
        0x00000002 => "PRIVATE".to_string(),
        0x00000003 => "LABEL".to_string(),
        0x00000011 => "VALUE".to_string(),
        0x00000080 => "CERTIFICATE_TYPE".to_string(),
        0x00000100 => "KEY_TYPE".to_string(),
        0x00000102 => "ID".to_string(),
        0x00000103 => "SENSITIVE".to_string(),
        0x00000104 => "ENCRYPT".to_string(),
        0x00000105 => "DECRYPT".to_string(),
        0x00000106 => "WRAP".to_string(),
        0x00000107 => "UNWRAP".to_string(),
        0x00000108 => "SIGN".to_string(),
        0x0000010A => "VERIFY".to_string(),
        0x00000120 => "MODULUS".to_string(),
        0x00000121 => "MODULUS_BITS".to_string(),
        0x00000122 => "PUBLIC_EXPONENT".to_string(),
        0x00000161 => "VALUE_LEN".to_string(),
        0x00000162 => "EXTRACTABLE".to_string(),
        0x00000180 => "EC_PARAMS".to_string(),
        0x00000181 => "EC_POINT".to_string(),
        _ => format!("0x{v:08X}"),
    }
}

/// Interpret a little-endian byte slice as a u64 (handles 4-byte and 8-byte CK_ULONG).
pub(crate) fn bytes_to_u64(b: &[u8]) -> Option<u64> {
    match b.len() {
        4 => Some(u64::from(u32::from_le_bytes(b.try_into().ok()?))),
        8 => Some(u64::from_le_bytes(b.try_into().ok()?)),
        _ => None,
    }
}

pub(crate) fn object_class_name(v: u64) -> String {
    match v {
        0 => "data".to_string(),
        1 => "certificate".to_string(),
        2 => "public-key".to_string(),
        3 => "private-key".to_string(),
        4 => "secret-key".to_string(),
        _ => format!("0x{v:08X}"),
    }
}

pub(crate) fn key_type_name(v: u64) -> String {
    match v {
        0x00 => "RSA".to_string(),
        0x01 => "DSA".to_string(),
        0x02 => "DH".to_string(),
        0x03 => "EC".to_string(),
        0x04 => "X9_42_DH".to_string(),
        0x05 => "KEA".to_string(),
        0x10 => "GENERIC_SECRET".to_string(),
        0x11 => "RC2".to_string(),
        0x12 => "RC4".to_string(),
        0x13 => "DES".to_string(),
        0x14 => "DES2".to_string(),
        0x15 => "DES3".to_string(),
        0x16 => "CAST".to_string(),
        0x17 => "CAST3".to_string(),
        0x18 => "CAST128".to_string(),
        0x19 => "RC5".to_string(),
        0x1A => "IDEA".to_string(),
        0x1B => "SKIPJACK".to_string(),
        0x1C => "BATON".to_string(),
        0x1D => "JUNIPER".to_string(),
        0x1E => "CDMF".to_string(),
        0x1F => "AES".to_string(),
        0x20 => "BLOWFISH".to_string(),
        0x21 => "TWOFISH".to_string(),
        0x22 => "SECURID".to_string(),
        0x23 => "HOTP".to_string(),
        0x24 => "ACTI".to_string(),
        0x25 => "CAMELLIA".to_string(),
        0x26 => "ARIA".to_string(),
        0x27 => "SHA512_224".to_string(),
        0x28 => "SHA512_256".to_string(),
        0x29 => "SEED".to_string(),
        0x2A => "GOSTR3410".to_string(),
        0x2B => "GOSTR3411".to_string(),
        0x2C => "GOST28147".to_string(),
        0x2D => "CHACHA20".to_string(),
        0x2E => "POLY1305".to_string(),
        0x2F => "AES_XTS".to_string(),
        0x30 => "SHA3_224".to_string(),
        0x31 => "SHA3_256".to_string(),
        0x32 => "SHA3_384".to_string(),
        0x33 => "SHA3_512".to_string(),
        0x34 => "BLAKE2B_160".to_string(),
        0x35 => "BLAKE2B_256".to_string(),
        0x36 => "BLAKE2B_384".to_string(),
        0x37 => "BLAKE2B_512".to_string(),
        0x38 => "SALSA20".to_string(),
        0x39 => "X2RATCHET".to_string(),
        0x3A => "EC_EDWARDS".to_string(),
        0x3B => "EC_MONTGOMERY".to_string(),
        0x3C => "HKDF".to_string(),
        _ => format!("0x{v:08X}"),
    }
}

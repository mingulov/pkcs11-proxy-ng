#[path = "mechanisms/table.rs"]
mod table;

pub(crate) use table::MECHANISM_NAMES;

/// Return the human-readable name for a mechanism value, or a hex fallback.
pub(crate) fn mechanism_name(value: u64) -> String {
    MECHANISM_NAMES
        .iter()
        .find(|(v, _)| *v == value)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("unknown (0x{value:08X})"))
}

pub(crate) fn parse_mechanism(name: &str) -> Result<u64, Box<dyn core::error::Error>> {
    // Accept hex (0x...) or decimal
    if let Some(hex_str) = name.strip_prefix("0x").or_else(|| name.strip_prefix("0X")) {
        return u64::from_str_radix(hex_str, 16)
            .map_err(|e| format!("Invalid mechanism hex: {e}").into());
    }
    if let Ok(n) = name.parse::<u64>() {
        return Ok(n);
    }

    // Strip optional CKM_ prefix then match case-insensitively against table
    let upper = name.to_uppercase();
    let key = upper.strip_prefix("CKM_").unwrap_or(&upper);

    // Also accept common aliases
    let key = match key {
        "SHA1" => "SHA_1",
        "SHA256" | "SHA_256" => "SHA256",
        "SHA384" | "SHA_384" => "SHA384",
        "SHA512" | "SHA_512" => "SHA512",
        "SHA224" => "SHA224",
        other => other,
    };

    MECHANISM_NAMES
        .iter()
        .find(|(_, n)| n.eq_ignore_ascii_case(key))
        .map(|(v, _)| Ok(*v))
        .unwrap_or_else(|| {
            Err(format!(
                "Unknown mechanism '{name}'. Use 0x<hex>, a decimal value, or a CKM_ name (e.g. AES_GCM, SHA256_RSA_PKCS). \
                Run 'list-mechanism-names' to see all known names."
            ).into())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_224_rows_use_official_ids() {
        // Official IDs per cryptoki-sys 0.5.0 (OASIS PKCS#11 bindings):
        // CKM_SHA512_224 = 72 (0x48), CKM_SHA512_224_HMAC = 73 (0x49).
        // Table names omit the CKM_ prefix. (W1-C11-01)
        assert_eq!(parse_mechanism("SHA512_224").unwrap(), 0x48);
        assert_eq!(parse_mechanism("CKM_SHA512_224_HMAC").unwrap(), 0x49);
        assert_eq!(mechanism_name(0x48), "SHA512_224");
        assert_eq!(mechanism_name(0x49), "SHA512_224_HMAC");
    }
}

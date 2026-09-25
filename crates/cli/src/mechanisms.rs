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

    // Also accept common aliases (W1-C11-24: SHA_224/SHA1_HMAC get
    // the same leniency as SHA_256/SHA1).
    let key = match key {
        "SHA1" => "SHA_1",
        "SHA1_HMAC" => "SHA_1_HMAC",
        "SHA256" | "SHA_256" => "SHA256",
        "SHA384" | "SHA_384" => "SHA384",
        "SHA512" | "SHA_512" => "SHA512",
        "SHA224" | "SHA_224" => "SHA224",
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

    #[test]
    fn sha_keygen_and_sha512t_rows_use_official_ids() {
        // Official IDs per cryptoki-sys 0.5.0 (OASIS PKCS#11 bindings):
        // CKM_SHA_1_KEY_GEN..CKM_SHA512_T_KEY_GEN = 16387..16394
        // (0x4003..0x400A); CKM_SHA512_T = 80 (0x50),
        // CKM_SHA512_T_HMAC = 81 (0x51),
        // CKM_SHA512_T_HMAC_GENERAL = 82 (0x52),
        // CKM_SHA512_T_KEY_DERIVATION = 83 (0x53).
        // Table names omit the CKM_ prefix. (W1-C11-02)
        let expected: &[(&str, u64)] = &[
            ("SHA_1_KEY_GEN", 0x4003),
            ("SHA224_KEY_GEN", 0x4004),
            ("SHA256_KEY_GEN", 0x4005),
            ("SHA384_KEY_GEN", 0x4006),
            ("SHA512_KEY_GEN", 0x4007),
            ("SHA512_224_KEY_GEN", 0x4008),
            ("SHA512_256_KEY_GEN", 0x4009),
            ("SHA512_T_KEY_GEN", 0x400A),
            ("SHA512_T", 0x50),
            ("SHA512_T_HMAC", 0x51),
            ("SHA512_T_HMAC_GENERAL", 0x52),
            ("SHA512_T_KEY_DERIVATION", 0x53),
        ];
        assert_eq!(expected.len(), 12);
        for (name, id) in expected {
            assert_eq!(parse_mechanism(name).unwrap(), *id, "{name}");
            assert_eq!(mechanism_name(*id), *name.to_string(), "0x{id:X}");
        }
    }

    /// Parse `(0xVALUE, "NAME")` rows from the CLI table source.
    fn parse_table_source(src: &str) -> Vec<(u64, String)> {
        let mut rows = Vec::new();
        for line in src.lines() {
            let Some(hex_start) = line.find("(0x") else { continue };
            let hex = &line[hex_start + 3..];
            let hex_end = hex.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(hex.len());
            let value = u64::from_str_radix(&hex[..hex_end], 16).unwrap();
            let rest = &hex[hex_end..];
            let quote = rest.find('"').unwrap() + 1;
            let end = rest[quote..].find('"').unwrap();
            rows.push((value, rest[quote..quote + end].to_string()));
        }
        rows
    }

    /// Parse `CkMechanismType(0xVALUE), // CKM_NAME` rows from the
    /// official inventory source. The canonical name is the first one;
    /// `// CKM_A / CKM_B` alias comments contribute only `CKM_A`.
    fn parse_official_source(src: &str) -> Vec<(u64, String)> {
        let mut rows = Vec::new();
        for line in src.lines() {
            let Some(hex_start) = line.find("CkMechanismType(0x") else { continue };
            let hex = &line[hex_start + "CkMechanismType(0x".len()..];
            let hex_end = hex.find(')').unwrap();
            let value = u64::from_str_radix(&hex[..hex_end], 16).unwrap();
            let comment = line.find("// CKM_").unwrap() + "// ".len();
            let mut name = line[comment..].split_whitespace().next().unwrap();
            name = name.strip_suffix('/').unwrap_or(name);
            rows.push((value, name.strip_prefix("CKM_").unwrap().to_string()));
        }
        rows
    }

    /// Pure table-vs-inventory checker (W1-C11-03, W1-C11-30): one
    /// message per drift; empty means the CLI table exactly matches the
    /// official PKCS#11 3.2 inventory (values, names, order).
    fn check_table_sync(table: &[(u64, String)], official: &[(u64, String)]) -> Vec<String> {
        let mut drifts = Vec::new();
        for (value, name) in official {
            match table.iter().find(|(v, _)| v == value) {
                None => drifts.push(format!("missing from CLI table: 0x{value:08X} {name}")),
                Some((_, table_name)) if table_name != name => drifts.push(format!(
                    "name mismatch at 0x{value:08X}: table has {table_name}, official is {name}"
                )),
                Some(_) => {}
            }
        }
        for (value, name) in table {
            if !official.iter().any(|(v, _)| v == value) {
                drifts.push(format!("extra CLI table row, not official: 0x{value:08X} {name}"));
            }
        }
        for pair in table.windows(2) {
            if pair[0].0 >= pair[1].0 {
                drifts.push(format!(
                    "CLI table not strictly sorted: 0x{:08X} before 0x{:08X}",
                    pair[0].0, pair[1].0
                ));
            }
        }
        let mut names: Vec<&str> = table.iter().map(|(_, n)| n.as_str()).collect();
        names.sort_unstable();
        for pair in names.windows(2) {
            if pair[0] == pair[1] {
                drifts.push(format!("duplicate CLI table name: {0}", pair[0]));
            }
        }
        drifts
    }

    /// `(value, name)` rows from one mechanism source file.
    type MechanismRows = Vec<(u64, String)>;

    fn read_workspace_sources() -> (MechanismRows, MechanismRows) {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let table_src = std::fs::read_to_string(manifest.join("src/mechanisms/table.rs")).unwrap();
        let official_src =
            std::fs::read_to_string(manifest.join("../types/src/mechanism_official.rs")).unwrap();
        let table = parse_table_source(&table_src);
        let official = parse_official_source(&official_src);
        // A silent zero-row parse would make the sync test vacuous.
        assert!(!table.is_empty(), "table parse found zero rows — format drift?");
        assert!(!official.is_empty(), "official parse found zero rows — format drift?");
        (table, official)
    }

    // W1-C11-03: the CLI table must exactly match the official 3.2
    // inventory; any drift (missing/extra/misnamed/misordered row)
    // fails loudly.
    #[test]
    fn table_matches_official_inventory() {
        let (table, official) = read_workspace_sources();
        let drifts = check_table_sync(&table, &official);
        assert!(
            drifts.is_empty(),
            "CLI table drifts from official inventory ({}):\n{}",
            drifts.len(),
            drifts.join("\n")
        );
    }

    // W1-C11-03: compiled cross-check — the linked table values must be
    // exactly the linked official value set (catches table.rs edits that
    // the source parser above might misread).
    #[test]
    fn compiled_table_values_match_compiled_inventory() {
        use pkcs11_proxy_ng_types::PKCS11_3_2_OFFICIAL_MECHANISMS;
        use std::collections::BTreeSet;
        let table: BTreeSet<u64> = MECHANISM_NAMES.iter().map(|(v, _)| *v).collect();
        let official: BTreeSet<u64> = PKCS11_3_2_OFFICIAL_MECHANISMS.iter().map(|t| t.0).collect();
        assert_eq!(table, official, "compiled value sets differ");
    }

    // W1-C11-03: the directive's ranges resolve both directions.
    #[test]
    fn directive_ranges_resolve_both_directions() {
        let expected: &[(&str, u64)] = &[
            // 0x17+ (post-quantum + DSA-SHA3).
            ("ML_KEM", 0x17),
            ("DSA_SHA3_256", 0x19),
            ("ML_DSA", 0x1D),
            ("HASH_ML_DSA_SHA256", 0x24),
            ("SLH_DSA", 0x2E),
            ("HASH_SLH_DSA_SHA512", 0x39),
            // 0x60-67 (SHA3-RSA).
            ("SHA3_256_RSA_PKCS", 0x60),
            ("SHA3_384_RSA_PKCS", 0x61),
            ("SHA3_512_RSA_PKCS", 0x62),
            ("SHA3_256_RSA_PKCS_PSS", 0x63),
            ("SHA3_384_RSA_PKCS_PSS", 0x64),
            ("SHA3_512_RSA_PKCS_PSS", 0x65),
            ("SHA3_224_RSA_PKCS", 0x66),
            ("SHA3_224_RSA_PKCS_PSS", 0x67),
            // 0x1047+ (ECDSA-SHA3).
            ("ECDSA_SHA3_224", 0x1047),
            ("ECDSA_SHA3_256", 0x1048),
            ("ECDSA_SHA3_384", 0x1049),
            ("ECDSA_SHA3_512", 0x104A),
            // 0x1053+ (key-wrap helpers + Edwards/Montgomery + EdDSA).
            ("ECDH_AES_KEY_WRAP", 0x1053),
            ("RSA_AES_KEY_WRAP", 0x1054),
            ("EC_EDWARDS_KEY_PAIR_GEN", 0x1055),
            ("EC_MONTGOMERY_KEY_PAIR_GEN", 0x1056),
            ("EDDSA", 0x1057),
            // 0x4003+ beyond the P0/P1 C11-02 pins (0x4003-0x400A).
            ("RSA_PKCS_TPM_1_1", 0x4001),
            ("NULL", 0x400B),
            ("BLAKE2B_512", 0x401B),
            ("HKDF_DERIVE", 0x402A),
            ("HSS", 0x4033),
            ("XMSSMT", 0x4037),
        ];
        for (name, id) in expected {
            assert_eq!(parse_mechanism(name).unwrap(), *id, "{name}");
            assert_eq!(mechanism_name(*id), *name.to_string(), "0x{id:X}");
        }
    }

    // W1-C11-30: pin every parse_mechanism alias arm plus the
    // prefix/case/hex/decimal spellings (Task 39 extends the alias
    // table; this test pins the current rows).
    #[test]
    fn parse_mechanism_aliases_resolve() {
        // Alias arms (mechanisms.rs match): each spelling hits its table id.
        let aliases: &[(&str, u64)] = &[
            ("SHA1", 0x220),
            ("SHA256", 0x250),
            ("SHA_256", 0x250),
            ("SHA384", 0x260),
            ("SHA_384", 0x260),
            ("SHA512", 0x270),
            ("SHA_512", 0x270),
            ("SHA224", 0x255),
            // W1-C11-24: same leniency as SHA_256/SHA1.
            ("SHA_224", 0x255),
            ("SHA1_HMAC", 0x221),
        ];
        for (alias, id) in aliases {
            assert_eq!(parse_mechanism(alias).unwrap(), *id, "{alias}");
            assert_eq!(parse_mechanism(&format!("CKM_{alias}")).unwrap(), *id, "CKM_{alias}");
        }
        // Case-insensitive table match with optional CKM_ prefix.
        assert_eq!(parse_mechanism("aes_gcm").unwrap(), 0x1087);
        assert_eq!(parse_mechanism("CKM_AES_GCM").unwrap(), 0x1087);
        assert_eq!(parse_mechanism("Ckm_Sha256_Rsa_Pkcs").unwrap(), 0x40);
        // Hex (either case prefix) and decimal spellings.
        assert_eq!(parse_mechanism("0x1087").unwrap(), 0x1087);
        assert_eq!(parse_mechanism("0X1087").unwrap(), 0x1087);
        assert_eq!(parse_mechanism("4231").unwrap(), 4231);
        // Unknown names error loudly, pointing at the name listing.
        let err = parse_mechanism("NO_SUCH_MECH").unwrap_err().to_string();
        assert!(err.contains("NO_SUCH_MECH"), "must echo: {err}");
        assert!(err.contains("list-mechanism-names"), "must point: {err}");
        // Unknown values fall back to a hex display, never a panic.
        assert_eq!(mechanism_name(0xDEAD_BEEF), "unknown (0xDEADBEEF)");
    }

    // W1-C11-30: the compiled table is strictly sorted by value with
    // unique values and names (companions the source-level sync check).
    #[test]
    fn compiled_table_is_sorted_and_unique() {
        use std::collections::BTreeSet;
        let values: Vec<u64> = MECHANISM_NAMES.iter().map(|(v, _)| *v).collect();
        let mut sorted = values.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(values, sorted, "table values must be strictly increasing");
        let names: BTreeSet<&str> = MECHANISM_NAMES.iter().map(|(_, n)| *n).collect();
        assert_eq!(names.len(), MECHANISM_NAMES.len(), "table names must be unique");
    }

    // W1-C11-30 negative control: the checker must catch every drift
    // class on tampered inputs (proves the sync test above has teeth).
    #[test]
    fn sync_checker_catches_every_drift_class() {
        let official = vec![(1u64, "A".to_string()), (2, "B".to_string()), (3, "C".to_string())];
        // Missing row.
        let table = vec![(1u64, "A".to_string()), (3, "C".to_string())];
        assert!(
            check_table_sync(&table, &official).iter().any(|d| d.contains("missing")),
            "dropped row must be reported"
        );
        // Renamed row.
        let table = vec![(1u64, "A".to_string()), (2, "B2".to_string()), (3, "C".to_string())];
        assert!(
            check_table_sync(&table, &official).iter().any(|d| d.contains("mismatch")),
            "renamed row must be reported"
        );
        // Extra row.
        let table = vec![
            (1u64, "A".to_string()),
            (2, "B".to_string()),
            (3, "C".to_string()),
            (4, "D".to_string()),
        ];
        assert!(
            check_table_sync(&table, &official).iter().any(|d| d.contains("extra")),
            "extra row must be reported"
        );
        // Misordered rows.
        let table = vec![(1u64, "A".to_string()), (3, "C".to_string()), (2, "B".to_string())];
        assert!(
            check_table_sync(&table, &official).iter().any(|d| d.contains("sorted")),
            "misordering must be reported"
        );
        // Duplicate name (kept sorted by aliasing the spare value).
        let table = vec![(1u64, "A".to_string()), (2, "A".to_string()), (3, "C".to_string())];
        let drifts = check_table_sync(&table, &official);
        assert!(
            drifts.iter().any(|d| d.contains("duplicate")),
            "duplicate name must be reported: {drifts:?}"
        );
        // Clean inputs stay silent.
        assert!(check_table_sync(&official, &official).is_empty());
    }
}

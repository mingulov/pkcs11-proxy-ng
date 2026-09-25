//! Mechanism parameters for CLI crypto/key ops (W1-C11-08).
//!
//! `--params-file` carries a JSON object with the parameters for the
//! parameterized mechanisms the CLI supports: `AES_GCM`, `RSA_PKCS_OAEP`,
//! and the `RSA_PKCS_PSS` family (`RSA_PKCS_PSS` + `SHA*_RSA_PKCS_PSS`).
//! Using one of those mechanisms without a params file is a loud CLI
//! error (with a JSON example), never a bare backend CKR.

use pkcs11_proxy_ng_types::*;
use std::path::Path;

use crate::mechanisms::parse_mechanism;

/// Parameterized families the CLI can supply via `--params-file`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamFamily {
    Gcm,
    Oaep,
    Pss,
}

fn param_family(mechanism_type: u64) -> Option<ParamFamily> {
    if mechanism_type == CkMechanismType::AES_GCM.0 {
        return Some(ParamFamily::Gcm);
    }
    if mechanism_type == CkMechanismType::RSA_PKCS_OAEP.0 {
        return Some(ParamFamily::Oaep);
    }
    if is_pss_family(mechanism_type) {
        return Some(ParamFamily::Pss);
    }
    None
}

/// Base + combined-hash PSS ids, resolved through the CLI mechanism
/// table (the single source — the combined ids have no
/// `CkMechanismType` consts to match on).
fn is_pss_family(mechanism_type: u64) -> bool {
    [
        "RSA_PKCS_PSS",
        "SHA1_RSA_PKCS_PSS",
        "SHA224_RSA_PKCS_PSS",
        "SHA256_RSA_PKCS_PSS",
        "SHA384_RSA_PKCS_PSS",
        "SHA512_RSA_PKCS_PSS",
    ]
    .iter()
    .filter_map(|name| parse_mechanism(name).ok())
    .any(|id| id == mechanism_type)
}

/// Build a (possibly parameterized) mechanism from its CLI name plus an
/// optional JSON `--params-file`.
pub(crate) fn build_mechanism(
    name: &str,
    params_file: Option<&Path>,
) -> Result<CkMechanism, Box<dyn core::error::Error>> {
    let mechanism_type = parse_mechanism(name)?;
    let mechanism = CkMechanismType(mechanism_type);
    match (param_family(mechanism_type), params_file) {
        (None, None) => Ok(CkMechanism { mechanism_type: mechanism, params: None }),
        (None, Some(_)) => Err(format!(
            "mechanism {name} does not take CLI mechanism parameters \
             (--params-file is only for AES_GCM, RSA_PKCS_OAEP, RSA_PKCS_PSS); \
             remove --params-file"
        )
        .into()),
        (Some(family), None) => Err(missing_params_hint(name, family).into()),
        (Some(family), Some(path)) => {
            let json = read_params_json(path)?;
            let params = match family {
                ParamFamily::Gcm => gcm_params(&json)?,
                ParamFamily::Oaep => oaep_params(&json)?,
                ParamFamily::Pss => pss_params(&json)?,
            };
            Ok(CkMechanism { mechanism_type: mechanism, params: Some(params) })
        }
    }
}

fn missing_params_hint(name: &str, family: ParamFamily) -> String {
    let example = match family {
        ParamFamily::Gcm => r#"{"iv_hex": "<hex>", "aad_hex": "<hex>", "tag_bits": 128}"#,
        ParamFamily::Oaep => {
            r#"{"hash": "SHA256", "mgf": "MGF1_SHA256", "source_data_hex": "<hex>"}"#
        }
        ParamFamily::Pss => r#"{"hash": "SHA256", "mgf": "MGF1_SHA256", "salt_len": 32}"#,
    };
    format!(
        "mechanism {name} requires parameters: pass --params-file <path> with JSON like {example}"
    )
}

fn read_params_json(path: &Path) -> Result<serde_json::Value, Box<dyn core::error::Error>> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read --params-file '{}': {e}", path.display()))?;
    serde_json::from_str(&body)
        .map_err(|e| format!("invalid JSON in --params-file '{}': {e}", path.display()).into())
}

fn params_object(
    json: &serde_json::Value,
) -> Result<&serde_json::Map<String, serde_json::Value>, String> {
    json.as_object().ok_or_else(|| "--params-file must contain a JSON object".to_string())
}

fn hex_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Vec<u8>, String> {
    let text = obj
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("--params-file needs \"{field}\" (hex)"))?;
    hex::decode(text).map_err(|e| format!("invalid {field}: {e}"))
}

fn optional_hex_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Vec<u8>, String> {
    match obj.get(field).and_then(|v| v.as_str()) {
        None => Ok(Vec::new()),
        Some(text) => hex::decode(text).map_err(|e| format!("invalid {field}: {e}")),
    }
}

/// `{"iv_hex": <hex>, "aad_hex": <hex>, "tag_bits": 128}` (`aad_hex`
/// and `tag_bits` optional).
fn gcm_params(json: &serde_json::Value) -> Result<CkMechanismParams, String> {
    let obj = params_object(json)?;
    let iv = hex_field(obj, "iv_hex")?;
    if iv.is_empty() {
        return Err("GCM iv_hex must not be empty".to_string());
    }
    let aad = optional_hex_field(obj, "aad_hex")?;
    let tag_bits = obj.get("tag_bits").and_then(|v| v.as_u64()).unwrap_or(128);
    if tag_bits == 0 || tag_bits > 128 {
        return Err(format!("GCM tag_bits must be 1..=128 (got {tag_bits})"));
    }
    Ok(CkMechanismParams::Gcm(GcmParams {
        iv_bits: iv.len() as u64 * 8,
        iv,
        iv_buffer_len: 0,
        aad: aad.into(),
        tag_bits,
        iv_null: false,
        aad_null: false,
    }))
}

/// `{"hash": "SHA256", "mgf": "MGF1_SHA256", "source_data_hex": <hex>}`
/// (all optional; MGF defaults to the hash's MGF1).
fn oaep_params(json: &serde_json::Value) -> Result<CkMechanismParams, String> {
    let obj = params_object(json)?;
    let (hash_alg, mgf) = hash_and_mgf(obj)?;
    let source_data = optional_hex_field(obj, "source_data_hex")?;
    Ok(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
        hash_alg,
        mgf,
        source: CkOaepSource::DATA_SPECIFIED,
        // Empty label is the (NULL, 0) encoding, preserved end to end.
        source_null: source_data.is_empty(),
        source_data: source_data.into(),
    }))
}

/// `{"hash": "SHA256", "mgf": "MGF1_SHA256", "salt_len": 32}` (all
/// optional; MGF follows the hash, salt defaults to the digest length).
fn pss_params(json: &serde_json::Value) -> Result<CkMechanismParams, String> {
    let obj = params_object(json)?;
    let (hash_alg, mgf) = hash_and_mgf(obj)?;
    let salt_len =
        obj.get("salt_len").and_then(|v| v.as_u64()).unwrap_or_else(|| digest_len(hash_alg));
    Ok(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams { hash_alg, mgf, salt_len }))
}

fn hash_and_mgf(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<(CkMechanismType, CkMgf), String> {
    let hash_alg = match obj.get("hash").and_then(|v| v.as_str()) {
        None => CkMechanismType::SHA256,
        Some(name) => parse_hash(name)?,
    };
    let mgf = match obj.get("mgf").and_then(|v| v.as_str()) {
        None => default_mgf(hash_alg),
        Some(name) => parse_mgf(name)?,
    };
    Ok((hash_alg, mgf))
}

fn parse_hash(name: &str) -> Result<CkMechanismType, String> {
    let normalized: String =
        name.chars().filter(|c| *c != '_' && *c != '-').collect::<String>().to_uppercase();
    match normalized.as_str() {
        "SHA1" => Ok(CkMechanismType::SHA_1),
        "SHA256" => Ok(CkMechanismType::SHA256),
        "SHA384" => Ok(CkMechanismType::SHA384),
        "SHA512" => Ok(CkMechanismType::SHA512),
        _ => Err(format!("unknown hash '{name}' (supported: SHA1, SHA256, SHA384, SHA512)")),
    }
}

fn parse_mgf(name: &str) -> Result<CkMgf, String> {
    match name.to_uppercase().as_str() {
        "MGF1_SHA1" => Ok(CkMgf::MGF1_SHA1),
        "MGF1_SHA224" => Ok(CkMgf::MGF1_SHA224),
        "MGF1_SHA256" => Ok(CkMgf::MGF1_SHA256),
        "MGF1_SHA384" => Ok(CkMgf::MGF1_SHA384),
        "MGF1_SHA512" => Ok(CkMgf::MGF1_SHA512),
        _ => Err(format!(
            "unknown mgf '{name}' (supported: MGF1_SHA1, MGF1_SHA224, MGF1_SHA256, MGF1_SHA384, MGF1_SHA512)"
        )),
    }
}

fn default_mgf(hash_alg: CkMechanismType) -> CkMgf {
    if hash_alg == CkMechanismType::SHA_1 {
        CkMgf::MGF1_SHA1
    } else if hash_alg == CkMechanismType::SHA384 {
        CkMgf::MGF1_SHA384
    } else if hash_alg == CkMechanismType::SHA512 {
        CkMgf::MGF1_SHA512
    } else {
        CkMgf::MGF1_SHA256
    }
}

fn digest_len(hash_alg: CkMechanismType) -> u64 {
    if hash_alg == CkMechanismType::SHA_1 {
        20
    } else if hash_alg == CkMechanismType::SHA384 {
        48
    } else if hash_alg == CkMechanismType::SHA512 {
        64
    } else {
        32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_params_file(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
        let path = dir.path().join("params.json");
        std::fs::write(&path, body).unwrap();
        path
    }

    // W1-C11-08: parameterless mechanisms are unchanged without a file.
    #[test]
    fn paramless_mechanism_unchanged_without_params_file() {
        let mech = build_mechanism("AES_ECB", None).unwrap();
        assert_eq!(mech.mechanism_type, CkMechanismType::AES_ECB);
        assert_eq!(mech.params, None);
    }

    // W1-C11-08: bare parameterized calls error with a CLI hint naming
    // --params-file, not a bare backend CKR.
    #[test]
    fn bare_gcm_errors_with_hint() {
        let err = build_mechanism("AES_GCM", None).unwrap_err().to_string();
        assert!(err.contains("requires parameters"), "no hint: {err}");
        assert!(err.contains("--params-file"), "no hint: {err}");
    }

    #[test]
    fn bare_oaep_errors_with_hint() {
        let err = build_mechanism("RSA_PKCS_OAEP", None).unwrap_err().to_string();
        assert!(err.contains("requires parameters"), "no hint: {err}");
        assert!(err.contains("--params-file"), "no hint: {err}");
    }

    #[test]
    fn bare_pss_family_errors_with_hint() {
        for name in ["RSA_PKCS_PSS", "SHA256_RSA_PKCS_PSS"] {
            let err = build_mechanism(name, None).unwrap_err().to_string();
            assert!(err.contains("requires parameters"), "{name}: no hint: {err}");
            assert!(err.contains("--params-file"), "{name}: no hint: {err}");
        }
    }

    // W1-C11-08: a params file supplies real GCM/OAEP/PSS params.
    #[test]
    fn gcm_params_file_builds_params() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_params_file(
            &dir,
            r#"{"iv_hex": "00112233445566778899aabb", "aad_hex": "aabb", "tag_bits": 96}"#,
        );
        let mech = build_mechanism("AES_GCM", Some(&path)).unwrap();
        let CkMechanismParams::Gcm(params) = mech.params.clone().unwrap() else {
            panic!("expected GCM params, got {:?}", mech.params);
        };
        assert_eq!(params.iv, hex::decode("00112233445566778899aabb").unwrap());
        assert_eq!(params.iv_bits, 96);
        assert_eq!(params.tag_bits, 96);
        params.aad.expose(|aad| assert_eq!(aad, &hex::decode("aabb").unwrap()));
    }

    #[test]
    fn oaep_params_file_builds_params_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_params_file(&dir, r#"{}"#);
        let mech = build_mechanism("RSA_PKCS_OAEP", Some(&path)).unwrap();
        let CkMechanismParams::RsaPkcsOaep(params) = mech.params.clone().unwrap() else {
            panic!("expected OAEP params, got {:?}", mech.params);
        };
        assert_eq!(params.hash_alg, CkMechanismType::SHA256);
        assert_eq!(params.mgf, CkMgf::MGF1_SHA256);
        assert_eq!(params.source, CkOaepSource::DATA_SPECIFIED);
        assert!(params.source_null);
    }

    #[test]
    fn pss_params_file_builds_params_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path =
            write_params_file(&dir, r#"{"hash": "SHA512", "mgf": "MGF1_SHA512", "salt_len": 64}"#);
        let mech = build_mechanism("SHA256_RSA_PKCS_PSS", Some(&path)).unwrap();
        let CkMechanismParams::RsaPkcsPss(params) = mech.params.clone().unwrap() else {
            panic!("expected PSS params, got {:?}", mech.params);
        };
        assert_eq!(params.hash_alg, CkMechanismType::SHA512);
        assert_eq!(params.mgf, CkMgf::MGF1_SHA512);
        assert_eq!(params.salt_len, 64);
    }

    // W1-C11-08: a params file for a parameterless mechanism is a loud
    // error, not silently ignored.
    #[test]
    fn params_file_for_paramless_mech_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_params_file(&dir, r#"{}"#);
        let err = build_mechanism("AES_ECB", Some(&path)).unwrap_err().to_string();
        assert!(err.contains("--params-file"), "no hint: {err}");
    }

    // W1-C11-08: missing/unparseable params files error loudly.
    #[test]
    fn missing_or_invalid_params_file_errors() {
        let missing = std::path::PathBuf::from("/nonexistent/params.json");
        assert!(build_mechanism("AES_GCM", Some(&missing)).is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = write_params_file(&dir, r#"{"iv_hex": "zzz"}"#);
        assert!(build_mechanism("AES_GCM", Some(&path)).is_err());
    }
}

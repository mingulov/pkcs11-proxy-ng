use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::super::{CliResult, cli_mechanism, close_session, login_user, open_session};

/// Convert `--key-size` (bits) to `CKA_VALUE_LEN` bytes (W1-C11-10):
/// exact division, rejecting non-multiples-of-8 instead of silently
/// truncating (`--key-size 20` is 2.5 bytes, not 2).
fn value_len_from_key_size_bits(key_size: u64) -> Result<u64, Box<dyn core::error::Error>> {
    if !key_size.is_multiple_of(8) {
        return Err(
            format!("--key-size is in bits and must be a multiple of 8 (got {key_size})").into()
        );
    }
    Ok(key_size / 8)
}

/// DER OID encodings for the `--ec-params` named curves (W1-C11-11).
fn named_curve_der(normalized: &str) -> Option<&'static str> {
    match normalized {
        "PRIME256V1" | "SECP256R1" | "P256" => Some("06082A8648CE3D030107"),
        "SECP384R1" | "P384" => Some("06052B81040022"),
        "SECP521R1" | "P521" => Some("06052B81040023"),
        "SECP256K1" => Some("06052B8104000A"),
        _ => None,
    }
}

/// Resolve `--ec-params` to DER `ECParameters` bytes (W1-C11-11): a
/// named curve (case-insensitive, `-`/`_` ignored) or raw hex DER.
fn ec_params_for_curve(name: &str) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
    let normalized: String =
        name.chars().filter(|c| *c != '-' && *c != '_').collect::<String>().to_uppercase();
    if let Some(der_hex) = named_curve_der(&normalized) {
        return Ok(hex::decode(der_hex)?);
    }
    let hex_text = name.strip_prefix("0x").or_else(|| name.strip_prefix("0X")).unwrap_or(name);
    let decoded = hex::decode(hex_text).unwrap_or_default();
    if decoded.is_empty() {
        return Err(format!(
            "unknown EC curve '{name}' (known: prime256v1, secp384r1, secp521r1, secp256k1; \
             or pass hex-encoded DER ECParameters)"
        )
        .into());
    }
    Ok(decoded)
}

fn is_ec_keygen(mechanism_type: u64) -> bool {
    mechanism_type == CkMechanismType::EC_KEY_PAIR_GEN.0
        || mechanism_type == CkMechanismType::EC_KEY_PAIR_GEN_W_EXTRA_BITS.0
}

/// Build the public-template size attribute for `generate-key-pair`
/// (W1-C11-11): `CKA_EC_PARAMS` for EC keygen (from `--ec-params`),
/// `CKA_MODULUS_BITS` for RSA-style `--key-size`; every other
/// combination is a loud error instead of a wrong-attribute template.
fn public_size_attr(
    mechanism_type: u64,
    key_size: Option<u64>,
    ec_params: Option<&str>,
) -> Result<Option<CkAttribute>, Box<dyn core::error::Error>> {
    if is_ec_keygen(mechanism_type) {
        if key_size.is_some() {
            return Err("--key-size cannot name an EC curve; pass --ec-params \
                (prime256v1, secp384r1, secp521r1, secp256k1, or hex DER)"
                .into());
        }
        let Some(curve) = ec_params else {
            return Err("EC keygen requires --ec-params \
                (prime256v1, secp384r1, secp521r1, secp256k1, or hex DER)"
                .into());
        };
        return Ok(Some(CkAttribute {
            attr_type: CkAttributeType::EC_PARAMS,
            value: Some(CkAttributeValue::Bytes(ec_params_for_curve(curve)?.into())),
        }));
    }
    if let Some(curve) = ec_params {
        return Err(format!(
            "--ec-params ('{curve}') only applies to EC keygen; \
             this mechanism takes --key-size"
        )
        .into());
    }
    Ok(key_size.map(|bits| CkAttribute {
        attr_type: CkAttributeType::MODULUS_BITS,
        value: Some(CkAttributeValue::Ulong(bits)),
    }))
}

pub(crate) async fn wrap_key(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: SecretBytes,
    mechanism: String,
    params_file: Option<std::path::PathBuf>,
    wrapping_key_handle: u64,
    key_handle: u64,
) -> CliResult {
    let mechanism = cli_mechanism(&mechanism, params_file.as_deref())?;
    let session = open_session(client, slot_id, CkSessionFlags::SERIAL_SESSION).await?;
    login_user(client, session, pin).await?;
    let wrapped = client
        .wrap_key(
            session,
            &mechanism,
            CkObjectHandle(wrapping_key_handle),
            CkObjectHandle(key_handle),
        )
        .await
        .map_err(crate::handlers::cli_err("C_WrapKey"))?;
    println!("{}", wrapped.expose(|bytes| hex::encode(bytes)));
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn unwrap_key(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: SecretBytes,
    mechanism: String,
    params_file: Option<std::path::PathBuf>,
    unwrapping_key_handle: u64,
    wrapped_key: String,
    label: Option<String>,
) -> CliResult {
    let mechanism = cli_mechanism(&mechanism, params_file.as_deref())?;
    let session =
        open_session(client, slot_id, CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
            .await?;
    login_user(client, session, pin).await?;

    let wrapped_key = hex::decode(&wrapped_key).map_err(|e| format!("Invalid hex: {e}"))?;
    let mut template = vec![
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::DECRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    if let Some(label) = label {
        template.push(CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.into())),
        });
    }

    let handle = client
        .unwrap_key(
            session,
            &mechanism,
            CkObjectHandle(unwrapping_key_handle),
            CkInBuf::Bytes(&wrapped_key),
            Some(&template),
        )
        .await
        .map_err(crate::handlers::cli_err("C_UnwrapKey"))?;
    println!("Unwrapped key handle: {}", handle.0);
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn derive_key(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: SecretBytes,
    mechanism: String,
    params_file: Option<std::path::PathBuf>,
    base_key_handle: u64,
    label: Option<String>,
) -> CliResult {
    let mechanism = cli_mechanism(&mechanism, params_file.as_deref())?;
    let session =
        open_session(client, slot_id, CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
            .await?;
    login_user(client, session, pin).await?;

    let mut template = vec![CkAttribute {
        attr_type: CkAttributeType::TOKEN,
        value: Some(CkAttributeValue::Bool(true)),
    }];
    if let Some(label) = label {
        template.push(CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.into())),
        });
    }

    let handle = client
        .derive_key(session, &mechanism, CkObjectHandle(base_key_handle), Some(&template))
        .await
        .map_err(crate::handlers::cli_err("C_DeriveKey"))?;
    println!("Derived key handle: {}", handle.0);
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn generate_key(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: SecretBytes,
    mechanism: String,
    params_file: Option<std::path::PathBuf>,
    label: String,
    key_size: Option<u64>,
) -> CliResult {
    let mechanism = cli_mechanism(&mechanism, params_file.as_deref())?;
    let session =
        open_session(client, slot_id, CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
            .await?;
    login_user(client, session, pin).await?;

    let mut template = vec![
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.into())),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::ENCRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::DECRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    if let Some(key_size) = key_size {
        template.push(CkAttribute {
            attr_type: CkAttributeType::VALUE_LEN,
            value: Some(CkAttributeValue::Ulong(value_len_from_key_size_bits(key_size)?)),
        });
    }

    let key_handle = client
        .generate_key(session, &mechanism, Some(&template))
        .await
        .map_err(crate::handlers::cli_err("C_GenerateKey"))?;
    println!("Generated key handle: {}", key_handle.0);
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn generate_key_pair(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: SecretBytes,
    mechanism: String,
    params_file: Option<std::path::PathBuf>,
    label: String,
    key_size: Option<u64>,
    ec_params: Option<String>,
) -> CliResult {
    let mechanism = cli_mechanism(&mechanism, params_file.as_deref())?;
    let session =
        open_session(client, slot_id, CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
            .await?;
    login_user(client, session, pin).await?;

    let mut public_template = vec![
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.clone().into())),
        },
        CkAttribute {
            attr_type: CkAttributeType::VERIFY,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    // W1-C11-11: EC keygen emits CKA_EC_PARAMS (from --ec-params),
    // RSA-style keygen keeps CKA_MODULUS_BITS.
    if let Some(attr) =
        public_size_attr(mechanism.mechanism_type.0, key_size, ec_params.as_deref())?
    {
        public_template.push(attr);
    }

    let private_template = vec![
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.into())),
        },
        CkAttribute { attr_type: CkAttributeType::SIGN, value: Some(CkAttributeValue::Bool(true)) },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];

    let (public_key, private_key) = client
        .generate_key_pair(session, &mechanism, Some(&public_template), Some(&private_template))
        .await
        .map_err(crate::handlers::cli_err("C_GenerateKeyPair"))?;
    println!("Public key handle:  {}", public_key.0);
    println!("Private key handle: {}", private_key.0);
    close_session(client, session, true).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::value_len_from_key_size_bits;

    // W1-C11-10: --key-size is bits; valid sizes convert exactly,
    // non-multiples-of-8 error naming bits (no silent truncation).
    #[test]
    fn key_size_bits_convert_exactly() {
        assert_eq!(value_len_from_key_size_bits(128).unwrap(), 16);
        assert_eq!(value_len_from_key_size_bits(256).unwrap(), 32);
    }

    #[test]
    fn non_multiple_of_8_errors_naming_bits() {
        let err = value_len_from_key_size_bits(20).unwrap_err().to_string();
        assert!(err.contains("bits"), "must name units: {err}");
        assert!(err.contains("20"), "must echo value: {err}");
    }

    use super::{ec_params_for_curve, public_size_attr};
    use pkcs11_proxy_ng_types::{CkAttributeType, CkAttributeValue, CkMechanismType};

    // W1-C11-11: named curves resolve to DER OID ECParameters.
    #[test]
    fn named_curves_resolve_to_der_oids() {
        assert_eq!(
            ec_params_for_curve("prime256v1").unwrap(),
            hex::decode("06082A8648CE3D030107").unwrap()
        );
        assert_eq!(
            ec_params_for_curve("secp384r1").unwrap(),
            hex::decode("06052B81040022").unwrap()
        );
        assert_eq!(
            ec_params_for_curve("secp521r1").unwrap(),
            hex::decode("06052B81040023").unwrap()
        );
        assert_eq!(
            ec_params_for_curve("secp256k1").unwrap(),
            hex::decode("06052B8104000A").unwrap()
        );
        // Aliases + raw hex DER passthrough.
        assert_eq!(
            ec_params_for_curve("P-256").unwrap(),
            ec_params_for_curve("prime256v1").unwrap()
        );
        assert_eq!(
            ec_params_for_curve("06052B81040022").unwrap(),
            hex::decode("06052B81040022").unwrap()
        );
    }

    #[test]
    fn unknown_curve_errors_listing_known_curves() {
        let err = ec_params_for_curve("curve25519").unwrap_err().to_string();
        assert!(err.contains("curve25519"), "must echo: {err}");
        assert!(err.contains("prime256v1"), "must list curves: {err}");
    }

    // W1-C11-11: RSA keeps MODULUS_BITS; EC emits EC_PARAMS and
    // rejects --key-size (which cannot name a curve).
    #[test]
    fn rsa_keygen_emits_modulus_bits() {
        let attr = public_size_attr(CkMechanismType::RSA_PKCS_KEY_PAIR_GEN.0, Some(2048), None)
            .unwrap()
            .unwrap();
        assert_eq!(attr.attr_type, CkAttributeType::MODULUS_BITS);
        assert_eq!(attr.value, Some(CkAttributeValue::Ulong(2048)));
        assert!(
            public_size_attr(CkMechanismType::RSA_PKCS_KEY_PAIR_GEN.0, None, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ec_keygen_emits_ec_params() {
        let attr = public_size_attr(CkMechanismType::EC_KEY_PAIR_GEN.0, None, Some("prime256v1"))
            .unwrap()
            .unwrap();
        assert_eq!(attr.attr_type, CkAttributeType::EC_PARAMS);
        let expected = ec_params_for_curve("prime256v1").unwrap();
        assert!(matches!(attr.value, Some(CkAttributeValue::Bytes(_))));
        if let Some(CkAttributeValue::Bytes(bytes)) = attr.value {
            bytes.expose(|raw| assert_eq!(raw, expected.as_slice()));
        }
    }

    #[test]
    fn ec_keygen_rejects_key_size_and_missing_curve() {
        // --key-size cannot name an EC curve: loud error, not MODULUS_BITS.
        let err = public_size_attr(CkMechanismType::EC_KEY_PAIR_GEN.0, Some(256), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--ec-params"), "must redirect: {err}");
        // No curve at all: loud error, not silent RSA-shaped template.
        let err = public_size_attr(CkMechanismType::EC_KEY_PAIR_GEN.0, None, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--ec-params"), "must require curve: {err}");
        // --ec-params with a non-EC mechanism: loud error.
        let err =
            public_size_attr(CkMechanismType::RSA_PKCS_KEY_PAIR_GEN.0, None, Some("prime256v1"))
                .unwrap_err()
                .to_string();
        assert!(err.contains("--ec-params"), "must scope flag: {err}");
    }
}

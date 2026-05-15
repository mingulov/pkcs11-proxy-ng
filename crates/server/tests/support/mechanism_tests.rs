// Shared PKCS#11 mechanism test fixtures
//
// This module contains shared helper functions, constants, and parameterized
// test implementations used by both SoftHSM2 and Kryoptic mechanism tests.
//
// Moving these shared components here reduces code duplication by ~70%
// between the two provider-specific test files.

use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::{
    AesCbcEncryptDataParams, AesCtrParams, CkAttribute, CkAttributeType, CkAttributeValue,
    CkKeyType, CkMechanism, CkMechanismParams, CkMechanismType, CkObjectClass, CkObjectHandle,
    CkResult, CkSessionHandle, Ecdh1DeriveParams, HkdfParams, IvParams, RsaPkcsOaepParams,
    RsaPkcsPssParams,
};

use super::get_attribute_bytes;

// ---------------------------------------------------------------------------
// PKCS#11 constants not yet in the types crate
// ---------------------------------------------------------------------------

/// CKA_DERIVE (0x0000010C)
pub const CKA_DERIVE: CkAttributeType = CkAttributeType(0x0000010C);

/// CKK_GENERIC_SECRET (0x00000010)
pub const CKK_GENERIC_SECRET: u64 = 0x00000010;

/// CKG_MGF1_SHA256 — mask generation function for PSS/OAEP.
pub const CKG_MGF1_SHA256: u64 = 0x00000002;

/// CKG_MGF1_SHA1 — mask generation function for OAEP with SHA-1.
pub const CKG_MGF1_SHA1: u64 = 0x00000001;

/// CKZ_DATA_SPECIFIED — OAEP source type.
pub const CKZ_DATA_SPECIFIED: u64 = 0x00000001;

/// CKD_NULL — no KDF applied in ECDH derivation.
pub const CKD_NULL: u64 = 0x00000001;

/// CKM_SHA256_RSA_PKCS_PSS (0x0043) — combined hash-and-sign PSS mechanism.
pub const CKM_SHA256_RSA_PKCS_PSS: CkMechanismType = CkMechanismType(0x0043);

/// CKM_SHA_1 (0x0220)
pub const CKM_SHA_1: CkMechanismType = CkMechanismType(0x0220);

/// CKM_AES_CTR (0x1086)
pub const CKM_AES_CTR: CkMechanismType = CkMechanismType(0x1086);

/// CKM_AES_CBC_ENCRYPT_DATA (0x1105) -- AES CBC encrypt data key derivation.
pub const CKM_AES_CBC_ENCRYPT_DATA: CkMechanismType = CkMechanismType(0x1105);

/// CKM_HKDF_DERIVE (0x402A)
pub const CKM_HKDF_DERIVE: CkMechanismType = CkMechanismType(0x402A);

/// CKF_HKDF_SALT_DATA (2) -- salt provided in pSalt for HKDF.
pub const CKF_HKDF_SALT_DATA: u64 = 2;

/// CKK_DES3 (0x00000015) - for SoftHSM2 DES3 tests
pub const CKK_DES3: u64 = 0x00000015;

/// CKM_DES3_KEY_GEN (0x0131) - for SoftHSM2 DES3 tests  
pub const CKM_DES3_KEY_GEN: CkMechanismType = CkMechanismType(0x0131);

/// CKM_ECDSA_SHA3_256 (0x1048) -- ECDSA with SHA3-256 hash. (Kryoptic only)
pub const CKM_ECDSA_SHA3_256: CkMechanismType = CkMechanismType(0x1048);

// ---------------------------------------------------------------------------
// Shared helper functions
// ---------------------------------------------------------------------------

/// Generate an AES key with the given size (in bytes) for encrypt/decrypt/derive.
///
/// Note: SoftHSM2 version adds WRAP attribute when wrap=true. Kryoptic
/// version doesn't include WRAP since it's not needed for Kryoptic tests.
pub async fn generate_aes_key(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    key_size: u64,
) -> CkResult<CkObjectHandle> {
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::AES_KEY_GEN, params: None };
    let template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CkKeyType::AES.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE_LEN,
            value: Some(CkAttributeValue::Ulong(key_size)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::ENCRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::DECRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute { attr_type: CKA_DERIVE, value: Some(CkAttributeValue::Bool(true)) },
        // Note: WRAP attribute is included for SoftHSM2 compatibility
        CkAttribute { attr_type: CkAttributeType::WRAP, value: Some(CkAttributeValue::Bool(true)) },
    ];
    client.generate_key(session, &mechanism, &template).await
}

/// Generate a generic secret key for HKDF derivation tests.
pub async fn generate_generic_secret_key(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    key_size: u64,
) -> CkResult<CkObjectHandle> {
    // CKM_GENERIC_SECRET_KEY_GEN = 0x0350
    let mechanism = CkMechanism { mechanism_type: CkMechanismType(0x0350), params: None };
    let template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CKK_GENERIC_SECRET)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE_LEN,
            value: Some(CkAttributeValue::Ulong(key_size)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute { attr_type: CKA_DERIVE, value: Some(CkAttributeValue::Bool(true)) },
    ];
    client.generate_key(session, &mechanism, &template).await
}

/// Generate an EC P-256 key pair for ECDH derivation and ECDSA tests.
pub async fn generate_ec_key_pair(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    label_prefix: &str,
) -> Result<(CkObjectHandle, CkObjectHandle), String> {
    // P-256 OID: 1.2.840.10045.3.1.7 (DER-encoded)
    let ec_params_p256: Vec<u8> = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    let pub_template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::PUBLIC_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CkKeyType::EC.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::EC_PARAMS,
            value: Some(CkAttributeValue::Bytes(ec_params_p256.clone())),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VERIFY,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(format!("{label_prefix}-pub"))),
        },
    ];

    let priv_template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::PRIVATE_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CkKeyType::EC.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::PRIVATE,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute { attr_type: CkAttributeType::SIGN, value: Some(CkAttributeValue::Bool(true)) },
        CkAttribute { attr_type: CKA_DERIVE, value: Some(CkAttributeValue::Bool(true)) },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(format!("{label_prefix}-priv"))),
        },
    ];

    let mechanism = CkMechanism { mechanism_type: CkMechanismType::EC_KEY_PAIR_GEN, params: None };
    client
        .generate_key_pair(session, &mechanism, &pub_template, &priv_template)
        .await
        .map_err(|rv| format!("EC key pair generation failed: {rv}"))
}

/// Generate an RSA key pair for sign/verify and encrypt/decrypt tests.
/// This version is used by Kryoptic. SoftHSM2 uses the version from ops.rs.
pub async fn generate_rsa_key_pair(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    label_prefix: &str,
) -> Result<(CkObjectHandle, CkObjectHandle), String> {
    let public_template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::PUBLIC_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CkKeyType::RSA.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::MODULUS_BITS,
            value: Some(CkAttributeValue::Ulong(2048)),
        },
        CkAttribute {
            attr_type: CkAttributeType::PUBLIC_EXPONENT,
            value: Some(CkAttributeValue::Bytes(vec![0x01, 0x00, 0x01])),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::PRIVATE,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(format!("{label_prefix}-pub"))),
        },
        CkAttribute {
            attr_type: CkAttributeType::ENCRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VERIFY,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    let private_template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::PRIVATE_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CkKeyType::RSA.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::PRIVATE,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(format!("{label_prefix}-priv"))),
        },
        CkAttribute {
            attr_type: CkAttributeType::DECRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute { attr_type: CkAttributeType::SIGN, value: Some(CkAttributeValue::Bool(true)) },
        CkAttribute {
            attr_type: CkAttributeType::SENSITIVE,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::EXTRACTABLE,
            value: Some(CkAttributeValue::Bool(false)),
        },
    ];
    let mechanism =
        CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };
    client
        .generate_key_pair(session, &mechanism, &public_template, &private_template)
        .await
        .map_err(|rv| format!("RSA key pair generation failed: {rv}"))
}

/// Extract the EC_POINT attribute (uncompressed public key) from an EC public key.
///
/// Uses the two-call pattern: first call to get the size, then second call
/// with a pre-allocated buffer to get the actual data.
pub async fn get_ec_point(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    pub_key: CkObjectHandle,
) -> Result<Vec<u8>, String> {
    get_attribute_bytes(client, session, pub_key, CkAttributeType::EC_POINT)
        .await?
        .ok_or_else(|| "EC_POINT data not found".into())
}

/// Strip a DER OCTET STRING wrapper from an EC_POINT value.
///
/// PKCS#11 modules return CKA_EC_POINT as a DER-encoded OCTET STRING
/// (tag 0x04). The ECDH1_DERIVE mechanism expects the raw EC point
/// (starting with the 0x04 uncompressed marker).
pub fn strip_der_octet_string(data: &[u8]) -> Vec<u8> {
    if data.len() < 2 || data[0] != 0x04 {
        return data.to_vec();
    }
    // Simple length encoding (1-byte length).
    let content_len = data[1] as usize;
    if content_len == data.len() - 2 && data.len() > 2 {
        return data[2..].to_vec();
    }
    // Long-form length encoding: 0x81 + 1-byte length.
    if data[1] == 0x81 && data.len() > 3 {
        let content_len = data[2] as usize;
        if content_len == data.len() - 3 {
            return data[3..].to_vec();
        }
    }
    // Not DER-wrapped or unrecognized format — return as-is.
    data.to_vec()
}

// ---------------------------------------------------------------------------
// Parameterized test implementations (shared test bodies)
// ---------------------------------------------------------------------------

/// AES-CBC encrypt + decrypt with IvParams (16-byte IV) through the proxy.
///
/// Proves that symmetric IV-based parameterized mechanisms with block-aligned
/// plaintext work through the full proxy stack.
pub async fn test_aes_cbc_encrypt_decrypt(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    _slot: pkcs11_proxy_ng_types::CkSlotId,
) -> Result<(), String> {
    let aes_key = generate_aes_key(client, session, 32)
        .await
        .map_err(|rv| format!("AES key generation failed: {rv}"))?;

    // 16-byte IV for AES-CBC.
    let iv = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let cbc_mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_CBC,
        params: Some(CkMechanismParams::Iv(IvParams { iv: iv.clone() })),
    };

    // Plaintext must be block-aligned (multiple of 16) for AES-CBC without padding.
    let plaintext = b"AES-CBC test!!!!"; // exactly 16 bytes

    // Encrypt.
    client
        .encrypt_init(session, &cbc_mechanism, aes_key)
        .await
        .map_err(|rv| format!("C_EncryptInit(AES-CBC) failed: {rv}"))?;
    let ciphertext = client
        .encrypt(session, plaintext)
        .await
        .map_err(|rv| format!("C_Encrypt(AES-CBC) failed: {rv}"))?;

    if ciphertext.is_empty() {
        return Err("ciphertext should be non-empty".into());
    }
    if ciphertext.as_slice() == plaintext.as_slice() {
        return Err("ciphertext should differ from plaintext".into());
    }

    // Decrypt with same IV.
    client
        .decrypt_init(session, &cbc_mechanism, aes_key)
        .await
        .map_err(|rv| format!("C_DecryptInit(AES-CBC) failed: {rv}"))?;
    let decrypted = client
        .decrypt(session, &ciphertext)
        .await
        .map_err(|rv| format!("C_Decrypt(AES-CBC) failed: {rv}"))?;

    if decrypted.as_slice() != plaintext.as_slice() {
        return Err("AES-CBC round-trip should recover plaintext".into());
    }

    // Clean up.
    client.destroy_object(session, aes_key).await.map_err(|rv| rv.to_string())?;

    Ok(())
}

/// AES-CTR encrypt + decrypt with AesCtrParams through the proxy.
///
/// AES-CTR is a stream cipher mode -- no block alignment required.
pub async fn test_aes_ctr_encrypt_decrypt(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
) -> Result<(), String> {
    let aes_key = generate_aes_key(client, session, 32)
        .await
        .map_err(|rv| format!("AES key generation failed: {rv}"))?;

    // 16-byte counter block (nonce + counter).
    let cb = vec![
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0x00, 0x00, 0x00,
        0x01,
    ];
    let ctr_mechanism = CkMechanism {
        mechanism_type: CKM_AES_CTR,
        params: Some(CkMechanismParams::AesCtr(AesCtrParams { counter_bits: 128, cb: cb.clone() })),
    };

    let plaintext = b"AES-CTR stream cipher test via proxy!";

    // Encrypt.
    client
        .encrypt_init(session, &ctr_mechanism, aes_key)
        .await
        .map_err(|rv| format!("C_EncryptInit(AES-CTR) failed: {rv}"))?;
    let ciphertext = client
        .encrypt(session, plaintext)
        .await
        .map_err(|rv| format!("C_Encrypt(AES-CTR) failed: {rv}"))?;

    if ciphertext.is_empty() {
        return Err("ciphertext should be non-empty".into());
    }
    if ciphertext.len() != plaintext.len() {
        return Err("CTR ciphertext should be same length as plaintext".into());
    }
    if ciphertext.as_slice() == plaintext.as_slice() {
        return Err("ciphertext should differ from plaintext".into());
    }

    // Decrypt with same counter starting point.
    let ctr_decrypt_mechanism = CkMechanism {
        mechanism_type: CKM_AES_CTR,
        params: Some(CkMechanismParams::AesCtr(AesCtrParams { counter_bits: 128, cb })),
    };
    client
        .decrypt_init(session, &ctr_decrypt_mechanism, aes_key)
        .await
        .map_err(|rv| format!("C_DecryptInit(AES-CTR) failed: {rv}"))?;
    let decrypted = client
        .decrypt(session, &ciphertext)
        .await
        .map_err(|rv| format!("C_Decrypt(AES-CTR) failed: {rv}"))?;

    if decrypted.as_slice() != plaintext.as_slice() {
        return Err("AES-CTR round-trip should recover plaintext".into());
    }

    // Clean up.
    client.destroy_object(session, aes_key).await.map_err(|rv| rv.to_string())?;

    Ok(())
}

/// RSA-PSS sign + verify with PssParams through the proxy.
///
/// Uses CKM_SHA256_RSA_PKCS_PSS (combined hash-and-sign) with explicit
/// CK_RSA_PKCS_PSS_PARAMS. The backend hashes the data internally.
pub async fn test_rsa_pss_sign_verify(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    public_key: CkObjectHandle,
    private_key: CkObjectHandle,
) -> Result<(), String> {
    let pss_mechanism = CkMechanism {
        mechanism_type: CKM_SHA256_RSA_PKCS_PSS,
        params: Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: CKG_MGF1_SHA256,
            salt_len: 32,
        })),
    };

    let data = b"RSA-PSS parameterized mechanism test payload";

    // Sign.
    client
        .sign_init(session, &pss_mechanism, private_key)
        .await
        .map_err(|rv| format!("C_SignInit(PSS) failed: {rv}"))?;
    let signature =
        client.sign(session, data).await.map_err(|rv| format!("C_Sign(PSS) failed: {rv}"))?;

    if signature.is_empty() {
        return Err("PSS signature should be non-empty".into());
    }

    // Verify.
    client
        .verify_init(session, &pss_mechanism, public_key)
        .await
        .map_err(|rv| format!("C_VerifyInit(PSS) failed: {rv}"))?;
    client
        .verify(session, data, &signature)
        .await
        .map_err(|rv| format!("C_Verify(PSS) failed: {rv}"))?;

    let modulus = get_attribute_bytes(client, session, public_key, CkAttributeType::MODULUS)
        .await?
        .ok_or_else(|| "RSA MODULUS not found".to_string())?;
    if modulus.is_empty() {
        return Err("RSA MODULUS should be non-empty".into());
    }

    // Clean up.
    client.destroy_object(session, public_key).await.map_err(|rv| rv.to_string())?;
    client.destroy_object(session, private_key).await.map_err(|rv| rv.to_string())?;

    Ok(())
}

/// RSA-OAEP encrypt + decrypt with OaepParams through the proxy.
///
/// Uses CKM_RSA_PKCS_OAEP with SHA-1, MGF1-SHA1, and CKZ_DATA_SPECIFIED with
/// empty source data. SHA-1 OAEP is the universally supported combination.
pub async fn test_rsa_oaep_encrypt_decrypt(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    public_key: CkObjectHandle,
    private_key: CkObjectHandle,
) -> Result<(), String> {
    let oaep_params = RsaPkcsOaepParams {
        hash_alg: CKM_SHA_1,
        mgf: CKG_MGF1_SHA1,
        source: CKZ_DATA_SPECIFIED,
        source_data: Vec::new(),
    };
    let oaep_mechanism = CkMechanism {
        mechanism_type: CkMechanismType::RSA_PKCS_OAEP,
        params: Some(CkMechanismParams::RsaPkcsOaep(oaep_params.clone())),
    };

    // OAEP plaintext max length = modulus_bytes - 2*hash_bytes - 2
    // For RSA-2048 with SHA-1: 256 - 40 - 2 = 214 bytes max.
    let plaintext = b"RSA-OAEP test message for proxy";

    // Encrypt.
    client
        .encrypt_init(session, &oaep_mechanism, public_key)
        .await
        .map_err(|rv| format!("C_EncryptInit(OAEP) failed: {rv}"))?;
    let ciphertext = client
        .encrypt(session, plaintext)
        .await
        .map_err(|rv| format!("C_Encrypt(OAEP) failed: {rv}"))?;

    if ciphertext.is_empty() {
        return Err("OAEP ciphertext should be non-empty".into());
    }
    if ciphertext.len() != 256 {
        return Err("OAEP ciphertext should be 256 bytes for RSA-2048".into());
    }

    // Decrypt with same OAEP params.
    let oaep_decrypt_mechanism = CkMechanism {
        mechanism_type: CkMechanismType::RSA_PKCS_OAEP,
        params: Some(CkMechanismParams::RsaPkcsOaep(oaep_params)),
    };
    client
        .decrypt_init(session, &oaep_decrypt_mechanism, private_key)
        .await
        .map_err(|rv| format!("C_DecryptInit(OAEP) failed: {rv}"))?;
    let decrypted = client
        .decrypt(session, &ciphertext)
        .await
        .map_err(|rv| format!("C_Decrypt(OAEP) failed: {rv}"))?;

    if decrypted.as_slice() != plaintext.as_slice() {
        return Err("OAEP round-trip should recover plaintext".into());
    }

    // Clean up.
    client.destroy_object(session, public_key).await.map_err(|rv| rv.to_string())?;
    client.destroy_object(session, private_key).await.map_err(|rv| rv.to_string())?;

    Ok(())
}

/// ECDH1-DERIVE key derivation with Ecdh1DeriveParams through the proxy.
///
/// Generates two EC P-256 key pairs (Alice and Bob), then Alice derives a
/// shared secret using Bob's public key. This proves the Ecdh1DeriveParams
/// (kdf + shared_data + public_data) serialize correctly through the full stack.
pub async fn test_ecdh1_derive(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
) -> Result<(), String> {
    // Generate two EC P-256 key pairs: Alice and Bob.
    let (alice_pub, alice_priv) = generate_ec_key_pair(client, session, "ecdh-alice").await?;
    let (bob_pub, bob_priv) = generate_ec_key_pair(client, session, "ecdh-bob").await?;

    // Get Bob's public key point for Alice's derivation.
    let bob_ec_point_raw = get_ec_point(client, session, bob_pub).await?;
    let bob_ec_point = strip_der_octet_string(&bob_ec_point_raw);

    // Alice derives a shared secret using Bob's public key.
    let derive_mechanism = CkMechanism {
        mechanism_type: CkMechanismType::ECDH1_DERIVE,
        params: Some(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
            kdf: CKD_NULL,
            shared_data: Vec::new(),
            public_data: bob_ec_point.clone(),
        })),
    };

    let derived_key_template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CKK_GENERIC_SECRET)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE_LEN,
            value: Some(CkAttributeValue::Ulong(32)), // 256-bit derived key
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::SENSITIVE,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::EXTRACTABLE,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];

    let alice_derived = client
        .derive_key(session, &derive_mechanism, alice_priv, &derived_key_template)
        .await
        .map_err(|rv| format!("C_DeriveKey(ECDH1, Alice) failed: {rv}"))?;

    let alice_secret = get_attribute_bytes(client, session, alice_derived, CkAttributeType::VALUE)
        .await?
        .ok_or_else(|| "derived key VALUE not found".to_string())?;

    if alice_secret.len() != 32 {
        return Err("derived key should be 32 bytes".into());
    }
    if !alice_secret.iter().any(|&b| b != 0) {
        return Err("derived key should not be all zeros".into());
    }

    // Clean up.
    client.destroy_object(session, alice_derived).await.map_err(|rv| rv.to_string())?;
    client.destroy_object(session, alice_pub).await.map_err(|rv| rv.to_string())?;
    client.destroy_object(session, alice_priv).await.map_err(|rv| rv.to_string())?;
    client.destroy_object(session, bob_pub).await.map_err(|rv| rv.to_string())?;
    client.destroy_object(session, bob_priv).await.map_err(|rv| rv.to_string())?;

    Ok(())
}

/// HKDF key derivation with HkdfParams through the proxy.
///
/// CKM_HKDF_DERIVE (0x402A): generates a generic secret key, then derives
/// another key using HKDF with SHA-256, out-of-band salt, and info.
pub async fn test_hkdf_derive(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    salt: &[u8],
    info: &[u8],
) -> Result<(), String> {
    // Generate a generic secret key as the base key for HKDF.
    let base_key = generate_generic_secret_key(client, session, 32)
        .await
        .map_err(|rv| format!("generic secret key generation failed: {rv}"))?;

    // HKDF parameters: extract + expand with SHA-256, explicit salt data, and info.
    let hkdf_mechanism = CkMechanism {
        mechanism_type: CKM_HKDF_DERIVE,
        params: Some(CkMechanismParams::Hkdf(HkdfParams {
            extract: true,
            expand: true,
            prf_hash_mechanism: CkMechanismType::SHA256.0,
            salt_type: CKF_HKDF_SALT_DATA,
            salt: salt.to_vec(),
            salt_key_handle: 0, // not used with DATA salt
            info: info.to_vec(),
        })),
    };

    let derived_key_template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CKK_GENERIC_SECRET)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE_LEN,
            value: Some(CkAttributeValue::Ulong(32)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::SENSITIVE,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::EXTRACTABLE,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];

    let derived_key = client
        .derive_key(session, &hkdf_mechanism, base_key, &derived_key_template)
        .await
        .map_err(|rv| format!("C_DeriveKey(HKDF) failed: {rv}"))?;

    let derived_value = get_attribute_bytes(client, session, derived_key, CkAttributeType::VALUE)
        .await?
        .ok_or_else(|| "HKDF derived key VALUE not found".to_string())?;

    if derived_value.len() != 32 {
        return Err("HKDF derived key should be 32 bytes".into());
    }
    if !derived_value.iter().any(|&b| b != 0) {
        return Err("HKDF derived key should not be all zeros".into());
    }

    // Clean up.
    client.destroy_object(session, derived_key).await.map_err(|rv| rv.to_string())?;
    client.destroy_object(session, base_key).await.map_err(|rv| rv.to_string())?;

    Ok(())
}

/// AES-CBC-ENCRYPT-DATA key derivation with AesCbcEncryptDataParams through
/// the proxy.
///
/// CKM_AES_CBC_ENCRYPT_DATA (0x1105): derives a new AES key from an existing
/// AES key by encrypting data with AES-CBC using a specified IV.
/// After derivation, verifies the derived key is usable by performing an
/// AES-CBC encryption with it.
pub async fn test_aes_cbc_encrypt_data_derive(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
) -> Result<(), String> {
    // Generate a base AES key with DERIVE flag for derivation.
    let base_key = generate_aes_key(client, session, 32)
        .await
        .map_err(|rv| format!("AES key generation failed: {rv}"))?;

    // AES-CBC-ENCRYPT-DATA: 16-byte IV + data (must be block-aligned, multiple of 16).
    let derive_mechanism = CkMechanism {
        mechanism_type: CKM_AES_CBC_ENCRYPT_DATA,
        params: Some(CkMechanismParams::AesCbcEncryptData(AesCbcEncryptDataParams {
            iv: vec![0u8; 16],
            data: b"data to derive key from!"
                .iter()
                .copied()
                .chain(std::iter::repeat_n(0u8, 8))
                .collect(), // 32 bytes (multiple of 16)
        })),
    };

    let derived_key_template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CkKeyType::AES.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE_LEN,
            value: Some(CkAttributeValue::Ulong(32)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::ENCRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute { attr_type: CKA_DERIVE, value: Some(CkAttributeValue::Bool(true)) },
    ];

    let derived_key = client
        .derive_key(session, &derive_mechanism, base_key, &derived_key_template)
        .await
        .map_err(|rv| format!("C_DeriveKey(AES-CBC-ENCRYPT-DATA) failed: {rv}"))?;

    // Verify derived key is usable: encrypt with it using AES-CBC.
    let test_iv = vec![0x01u8; 16];
    let test_mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_CBC,
        params: Some(CkMechanismParams::Iv(IvParams { iv: test_iv })),
    };
    let test_plaintext = b"derived key test"; // 16 bytes (block-aligned)
    client
        .encrypt_init(session, &test_mechanism, derived_key)
        .await
        .map_err(|rv| format!("C_EncryptInit with derived key failed: {rv}"))?;
    let ct = client
        .encrypt(session, test_plaintext)
        .await
        .map_err(|rv| format!("C_Encrypt with derived key failed: {rv}"))?;
    if ct.is_empty() {
        return Err("encryption with derived key should produce ciphertext".into());
    }

    // Clean up.
    client.destroy_object(session, derived_key).await.map_err(|rv| rv.to_string())?;
    client.destroy_object(session, base_key).await.map_err(|rv| rv.to_string())?;

    Ok(())
}

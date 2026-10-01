//! Proto <-> Rust conversions for key derivation, key wrapping, and PBE
//! mechanism parameters.

use crate::pkcs11_proxy_ng::v1 as v1_proto;
// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use super::{
    FromWire, ToWireV1, check_shared_len_agreement, pointer_from_wire, pointer_from_wire_legacy,
    pointer_to_wire,
};
use crate::secret_boundary::secret_to_plain;
use pkcs11_proxy_ng_types::{
    CkKdf, CkMechanismType, CkMgf, CkOaepSource, CkObjectHandle, CkPbkdf2Prf, CkPbkdf2SaltSource,
    CkRv, Ecdh2DeriveParams, EcdhAesKeyWrapParams, EcmqvDeriveParams, EddsaParams,
    Gostr3410DeriveParams, Gostr3410KeyWrapParams, HkdfParams, KeaDeriveParams,
    KeyWrapSetOaepParams, PbeParams, Pkcs5Pbkd2Params, PointerBytes, RsaAesKeyWrapParams,
    RsaPkcsOaepParams, SecretBytes, X942Dh1DeriveParams, X942Dh2DeriveParams, X942MqvDeriveParams,
};

// ---------------------------------------------------------------------------
// Key Derivation: Ecdh2DeriveParams
// ---------------------------------------------------------------------------

impl From<&Ecdh2DeriveParams> for v1_proto::Ecdh2DeriveParams {
    fn from(p: &Ecdh2DeriveParams) -> Self {
        Self {
            kdf: p.kdf.0,
            shared_data: secret_to_plain(&p.shared_data),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: p.private_data_handle.0,
            public_data2: p.public_data2.clone(),
            // R16: production encode stays v0-shaped.
            shared_data_null_len: None,
            public_data_null_len: None,
            public_data2_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::Ecdh2DeriveParams> for Ecdh2DeriveParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::Ecdh2DeriveParams {
        let (shared_data, shared_data_null_len) = pointer_to_wire(&self.shared_data_presence);
        let (public_data, public_data_null_len) = pointer_to_wire(&self.public_data_presence);
        let (public_data2, public_data2_null_len) = pointer_to_wire(&self.public_data2_presence);
        v1_proto::Ecdh2DeriveParams {
            kdf: self.kdf.0,
            shared_data,
            public_data,
            private_data_len: self.private_data_len,
            private_data_handle: self.private_data_handle.0,
            public_data2,
            shared_data_null_len,
            public_data_null_len,
            public_data2_null_len,
        }
    }
}

impl FromWire<v1_proto::Ecdh2DeriveParams> for Ecdh2DeriveParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::Ecdh2DeriveParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            kdf: CkKdf(p.kdf),
            shared_data: SecretBytes::copy_from_slice(&p.shared_data),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: CkObjectHandle(p.private_data_handle),
            public_data2: p.public_data2.clone(),
            shared_data_presence: pointer_from_wire(
                &p.shared_data,
                p.shared_data_null_len,
                version,
            )?,
            public_data_presence: pointer_from_wire(
                &p.public_data,
                p.public_data_null_len,
                version,
            )?,
            public_data2_presence: pointer_from_wire(
                &p.public_data2,
                p.public_data2_null_len,
                version,
            )?,
        })
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: EcmqvDeriveParams
// ---------------------------------------------------------------------------

impl From<&EcmqvDeriveParams> for v1_proto::EcmqvDeriveParams {
    fn from(p: &EcmqvDeriveParams) -> Self {
        Self {
            kdf: p.kdf.0,
            shared_data: secret_to_plain(&p.shared_data),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: p.private_data_handle.0,
            public_data2: p.public_data2.clone(),
            public_key_handle: p.public_key_handle.0,
            // R16: production encode stays v0-shaped.
            shared_data_null_len: None,
            public_data_null_len: None,
            public_data2_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::EcmqvDeriveParams> for EcmqvDeriveParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::EcmqvDeriveParams {
        let (shared_data, shared_data_null_len) = pointer_to_wire(&self.shared_data_presence);
        let (public_data, public_data_null_len) = pointer_to_wire(&self.public_data_presence);
        let (public_data2, public_data2_null_len) = pointer_to_wire(&self.public_data2_presence);
        v1_proto::EcmqvDeriveParams {
            kdf: self.kdf.0,
            shared_data,
            public_data,
            private_data_len: self.private_data_len,
            private_data_handle: self.private_data_handle.0,
            public_data2,
            public_key_handle: self.public_key_handle.0,
            shared_data_null_len,
            public_data_null_len,
            public_data2_null_len,
        }
    }
}

impl FromWire<v1_proto::EcmqvDeriveParams> for EcmqvDeriveParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::EcmqvDeriveParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            kdf: CkKdf(p.kdf),
            shared_data: SecretBytes::copy_from_slice(&p.shared_data),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: CkObjectHandle(p.private_data_handle),
            public_data2: p.public_data2.clone(),
            public_key_handle: CkObjectHandle(p.public_key_handle),
            shared_data_presence: pointer_from_wire(
                &p.shared_data,
                p.shared_data_null_len,
                version,
            )?,
            public_data_presence: pointer_from_wire(
                &p.public_data,
                p.public_data_null_len,
                version,
            )?,
            public_data2_presence: pointer_from_wire(
                &p.public_data2,
                p.public_data2_null_len,
                version,
            )?,
        })
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: X942Dh1DeriveParams
// ---------------------------------------------------------------------------

impl From<&X942Dh1DeriveParams> for v1_proto::X942Dh1DeriveParams {
    fn from(p: &X942Dh1DeriveParams) -> Self {
        Self {
            kdf: p.kdf.0,
            other_info: secret_to_plain(&p.other_info),
            public_data: p.public_data.clone(),
            // R16: production encode stays v0-shaped.
            other_info_null_len: None,
            public_data_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::X942Dh1DeriveParams> for X942Dh1DeriveParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::X942Dh1DeriveParams {
        let (other_info, other_info_null_len) = pointer_to_wire(&self.other_info_presence);
        let (public_data, public_data_null_len) = pointer_to_wire(&self.public_data_presence);
        v1_proto::X942Dh1DeriveParams {
            kdf: self.kdf.0,
            other_info,
            public_data,
            other_info_null_len,
            public_data_null_len,
        }
    }
}

impl FromWire<v1_proto::X942Dh1DeriveParams> for X942Dh1DeriveParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::X942Dh1DeriveParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            kdf: CkKdf(p.kdf),
            other_info: SecretBytes::copy_from_slice(&p.other_info),
            public_data: p.public_data.clone(),
            other_info_presence: pointer_from_wire(&p.other_info, p.other_info_null_len, version)?,
            public_data_presence: pointer_from_wire(
                &p.public_data,
                p.public_data_null_len,
                version,
            )?,
        })
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: X942Dh2DeriveParams
// ---------------------------------------------------------------------------

impl From<&X942Dh2DeriveParams> for v1_proto::X942Dh2DeriveParams {
    fn from(p: &X942Dh2DeriveParams) -> Self {
        Self {
            kdf: p.kdf.0,
            other_info: secret_to_plain(&p.other_info),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: p.private_data_handle.0,
            public_data2: p.public_data2.clone(),
            // R16: production encode stays v0-shaped.
            other_info_null_len: None,
            public_data_null_len: None,
            public_data2_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::X942Dh2DeriveParams> for X942Dh2DeriveParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::X942Dh2DeriveParams {
        let (other_info, other_info_null_len) = pointer_to_wire(&self.other_info_presence);
        let (public_data, public_data_null_len) = pointer_to_wire(&self.public_data_presence);
        let (public_data2, public_data2_null_len) = pointer_to_wire(&self.public_data2_presence);
        v1_proto::X942Dh2DeriveParams {
            kdf: self.kdf.0,
            other_info,
            public_data,
            private_data_len: self.private_data_len,
            private_data_handle: self.private_data_handle.0,
            public_data2,
            other_info_null_len,
            public_data_null_len,
            public_data2_null_len,
        }
    }
}

impl FromWire<v1_proto::X942Dh2DeriveParams> for X942Dh2DeriveParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::X942Dh2DeriveParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            kdf: CkKdf(p.kdf),
            other_info: SecretBytes::copy_from_slice(&p.other_info),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: CkObjectHandle(p.private_data_handle),
            public_data2: p.public_data2.clone(),
            other_info_presence: pointer_from_wire(&p.other_info, p.other_info_null_len, version)?,
            public_data_presence: pointer_from_wire(
                &p.public_data,
                p.public_data_null_len,
                version,
            )?,
            public_data2_presence: pointer_from_wire(
                &p.public_data2,
                p.public_data2_null_len,
                version,
            )?,
        })
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: X942MqvDeriveParams
// ---------------------------------------------------------------------------

impl From<&X942MqvDeriveParams> for v1_proto::X942MqvDeriveParams {
    fn from(p: &X942MqvDeriveParams) -> Self {
        Self {
            kdf: p.kdf.0,
            other_info: secret_to_plain(&p.other_info),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: p.private_data_handle.0,
            public_data2: p.public_data2.clone(),
            public_key_handle: p.public_key_handle.0,
            // R16: production encode stays v0-shaped.
            other_info_null_len: None,
            public_data_null_len: None,
            public_data2_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::X942MqvDeriveParams> for X942MqvDeriveParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::X942MqvDeriveParams {
        let (other_info, other_info_null_len) = pointer_to_wire(&self.other_info_presence);
        let (public_data, public_data_null_len) = pointer_to_wire(&self.public_data_presence);
        let (public_data2, public_data2_null_len) = pointer_to_wire(&self.public_data2_presence);
        v1_proto::X942MqvDeriveParams {
            kdf: self.kdf.0,
            other_info,
            public_data,
            private_data_len: self.private_data_len,
            private_data_handle: self.private_data_handle.0,
            public_data2,
            public_key_handle: self.public_key_handle.0,
            other_info_null_len,
            public_data_null_len,
            public_data2_null_len,
        }
    }
}

impl FromWire<v1_proto::X942MqvDeriveParams> for X942MqvDeriveParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::X942MqvDeriveParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            kdf: CkKdf(p.kdf),
            other_info: SecretBytes::copy_from_slice(&p.other_info),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: CkObjectHandle(p.private_data_handle),
            public_data2: p.public_data2.clone(),
            public_key_handle: CkObjectHandle(p.public_key_handle),
            other_info_presence: pointer_from_wire(&p.other_info, p.other_info_null_len, version)?,
            public_data_presence: pointer_from_wire(
                &p.public_data,
                p.public_data_null_len,
                version,
            )?,
            public_data2_presence: pointer_from_wire(
                &p.public_data2,
                p.public_data2_null_len,
                version,
            )?,
        })
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: HkdfParams
// ---------------------------------------------------------------------------

impl From<&HkdfParams> for v1_proto::HkdfParams {
    fn from(p: &HkdfParams) -> Self {
        Self {
            extract: p.extract,
            expand: p.expand,
            prf_hash_mechanism: p.prf_hash_mechanism.0,
            salt_type: p.salt_type,
            salt: secret_to_plain(&p.salt),
            salt_key_handle: p.salt_key_handle.0,
            info: secret_to_plain(&p.info),
            // R16: production encode stays v0-shaped.
            salt_null_len: None,
            info_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::HkdfParams> for HkdfParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::HkdfParams {
        let (salt, salt_null_len) = pointer_to_wire(&self.salt_presence);
        let (info, info_null_len) = pointer_to_wire(&self.info_presence);
        v1_proto::HkdfParams {
            extract: self.extract,
            expand: self.expand,
            prf_hash_mechanism: self.prf_hash_mechanism.0,
            salt_type: self.salt_type,
            salt,
            salt_key_handle: self.salt_key_handle.0,
            info,
            salt_null_len,
            info_null_len,
        }
    }
}

impl FromWire<v1_proto::HkdfParams> for HkdfParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::HkdfParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            extract: p.extract,
            expand: p.expand,
            prf_hash_mechanism: CkMechanismType(p.prf_hash_mechanism),
            salt_type: p.salt_type,
            salt: SecretBytes::copy_from_slice(&p.salt),
            salt_key_handle: CkObjectHandle(p.salt_key_handle),
            info: SecretBytes::copy_from_slice(&p.info),
            salt_presence: pointer_from_wire(&p.salt, p.salt_null_len, version)?,
            info_presence: pointer_from_wire(&p.info, p.info_null_len, version)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: EddsaParams
// ---------------------------------------------------------------------------

impl From<&EddsaParams> for v1_proto::EddsaParams {
    fn from(p: &EddsaParams) -> Self {
        Self {
            ph_flag: p.ph_flag,
            context_data: secret_to_plain(&p.context_data),
            // R16: production encode stays v0-shaped.
            context_data_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::EddsaParams> for EddsaParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::EddsaParams {
        let (context_data, context_data_null_len) = pointer_to_wire(&self.context_data_presence);
        v1_proto::EddsaParams { ph_flag: self.ph_flag, context_data, context_data_null_len }
    }
}

impl FromWire<v1_proto::EddsaParams> for EddsaParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::EddsaParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            ph_flag: p.ph_flag,
            context_data: SecretBytes::copy_from_slice(&p.context_data),
            context_data_presence: pointer_from_wire(
                &p.context_data,
                p.context_data_null_len,
                version,
            )?,
        })
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: Gostr3410DeriveParams
// ---------------------------------------------------------------------------

impl From<&Gostr3410DeriveParams> for v1_proto::Gostr3410DeriveParams {
    fn from(p: &Gostr3410DeriveParams) -> Self {
        Self {
            kdf: p.kdf.0,
            public_data: p.public_data.clone(),
            ukm: p.ukm.clone(),
            // R16: production encode stays v0-shaped.
            public_data_null_len: None,
            ukm_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::Gostr3410DeriveParams> for Gostr3410DeriveParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::Gostr3410DeriveParams {
        let (public_data, public_data_null_len) = pointer_to_wire(&self.public_data_presence);
        let (ukm, ukm_null_len) = pointer_to_wire(&self.ukm_presence);
        v1_proto::Gostr3410DeriveParams {
            kdf: self.kdf.0,
            public_data,
            ukm,
            public_data_null_len,
            ukm_null_len,
        }
    }
}

impl FromWire<v1_proto::Gostr3410DeriveParams> for Gostr3410DeriveParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::Gostr3410DeriveParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            kdf: CkKdf(p.kdf),
            public_data: p.public_data.clone(),
            ukm: p.ukm.clone(),
            public_data_presence: pointer_from_wire(
                &p.public_data,
                p.public_data_null_len,
                version,
            )?,
            ukm_presence: pointer_from_wire(&p.ukm, p.ukm_null_len, version)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: KeaDeriveParams
// ---------------------------------------------------------------------------

impl From<&KeaDeriveParams> for v1_proto::KeaDeriveParams {
    fn from(p: &KeaDeriveParams) -> Self {
        Self {
            is_sender: p.is_sender,
            random_a: p.random_a.clone(),
            random_b: p.random_b.clone(),
            public_data: p.public_data.clone(),
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            random_a_null_len: None,
            random_b_null_len: None,
            public_data_null_len: None,
        }
    }
}

impl From<&v1_proto::KeaDeriveParams> for KeaDeriveParams {
    fn from(p: &v1_proto::KeaDeriveParams) -> Self {
        // R18: unversioned legacy decode — peers mirror Present (FromWire threads versions).
        let random_a = p.random_a.clone();
        let random_b = p.random_b.clone();
        let public_data = p.public_data.clone();
        Self {
            is_sender: p.is_sender,
            random_a_presence: PointerBytes::present_copy(&random_a),
            random_b_presence: PointerBytes::present_copy(&random_b),
            public_data_presence: PointerBytes::present_copy(&public_data),
            random_a,
            random_b,
            public_data,
        }
    }
}

impl FromWire<v1_proto::KeaDeriveParams> for KeaDeriveParams {
    fn from_wire(p: &v1_proto::KeaDeriveParams, version: u32) -> Result<Self, CkRv> {
        let random_a_presence = pointer_from_wire(&p.random_a, p.random_a_null_len, version)?;
        let random_b_presence = pointer_from_wire(&p.random_b, p.random_b_null_len, version)?;
        let public_data_presence =
            pointer_from_wire(&p.public_data, p.public_data_null_len, version)?;
        // RandomA/B share the one C ulRandomLen (v1-only agreement).
        check_shared_len_agreement(version, &[&random_a_presence, &random_b_presence])?;
        Ok(Self {
            is_sender: p.is_sender,
            random_a: p.random_a.clone(),
            random_b: p.random_b.clone(),
            public_data: p.public_data.clone(),
            random_a_presence,
            random_b_presence,
            public_data_presence,
        })
    }
}

impl ToWireV1<v1_proto::KeaDeriveParams> for KeaDeriveParams {
    fn to_wire_v1(&self) -> v1_proto::KeaDeriveParams {
        let (random_a, random_a_null_len) = pointer_to_wire(&self.random_a_presence);
        let (random_b, random_b_null_len) = pointer_to_wire(&self.random_b_presence);
        let (public_data, public_data_null_len) = pointer_to_wire(&self.public_data_presence);
        v1_proto::KeaDeriveParams {
            is_sender: self.is_sender,
            random_a,
            random_b,
            public_data,
            random_a_null_len,
            random_b_null_len,
            public_data_null_len,
        }
    }
}

// ---------------------------------------------------------------------------
// Key Wrapping: EcdhAesKeyWrapParams
// ---------------------------------------------------------------------------

impl From<&EcdhAesKeyWrapParams> for v1_proto::EcdhAesKeyWrapParams {
    fn from(p: &EcdhAesKeyWrapParams) -> Self {
        Self {
            aes_key_bits: p.aes_key_bits,
            kdf: p.kdf.0,
            shared_data: secret_to_plain(&p.shared_data),
            // R16: production encode stays v0-shaped.
            shared_data_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::EcdhAesKeyWrapParams> for EcdhAesKeyWrapParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::EcdhAesKeyWrapParams {
        let (shared_data, shared_data_null_len) = pointer_to_wire(&self.shared_data_presence);
        v1_proto::EcdhAesKeyWrapParams {
            aes_key_bits: self.aes_key_bits,
            kdf: self.kdf.0,
            shared_data,
            shared_data_null_len,
        }
    }
}

impl FromWire<v1_proto::EcdhAesKeyWrapParams> for EcdhAesKeyWrapParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::EcdhAesKeyWrapParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            aes_key_bits: p.aes_key_bits,
            kdf: CkKdf(p.kdf),
            shared_data: SecretBytes::copy_from_slice(&p.shared_data),
            shared_data_presence: pointer_from_wire(
                &p.shared_data,
                p.shared_data_null_len,
                version,
            )?,
        })
    }
}

// ---------------------------------------------------------------------------
// Key Wrapping: RsaAesKeyWrapParams (nested OaepParams)
// ---------------------------------------------------------------------------

impl From<&RsaAesKeyWrapParams> for v1_proto::RsaAesKeyWrapParams {
    fn from(p: &RsaAesKeyWrapParams) -> Self {
        Self {
            aes_key_bits: p.aes_key_bits,
            oaep_params: Some(v1_proto::RsaPkcsOaepParams {
                hash_alg: p.oaep_params.hash_alg.0,
                mgf: p.oaep_params.mgf.0,
                source: p.oaep_params.source.0,
                source_data: secret_to_plain(&p.oaep_params.source_data),
                source_null: p.oaep_params.source_null,
                // R16: production encode stays v0-shaped.
                source_data_null_len: None,
            }),
        }
    }
}

impl ToWireV1<v1_proto::RsaAesKeyWrapParams> for RsaAesKeyWrapParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode). The nested OAEP envelope takes the same
    // presence-only treatment (nested bool forced unset).
    fn to_wire_v1(&self) -> v1_proto::RsaAesKeyWrapParams {
        let (source_data, source_data_null_len) =
            pointer_to_wire(&self.oaep_params.source_data_presence);
        v1_proto::RsaAesKeyWrapParams {
            aes_key_bits: self.aes_key_bits,
            oaep_params: Some(v1_proto::RsaPkcsOaepParams {
                hash_alg: self.oaep_params.hash_alg.0,
                mgf: self.oaep_params.mgf.0,
                source: self.oaep_params.source.0,
                source_data,
                // S2 §3: a v1 encoder MUST leave legacy bools unset.
                source_null: false,
                source_data_null_len,
            }),
        }
    }
}

impl FromWire<v1_proto::RsaAesKeyWrapParams> for RsaAesKeyWrapParams {
    // R16: version-threaded (the nested OAEP envelope decodes under the
    // outer message's stamp; a missing nested message stays PARAM_INVALID).
    fn from_wire(p: &v1_proto::RsaAesKeyWrapParams, version: u32) -> Result<Self, CkRv> {
        let o = p.oaep_params.as_ref().ok_or(CkRv::MECHANISM_PARAM_INVALID)?;
        Ok(Self {
            aes_key_bits: p.aes_key_bits,
            oaep_params: RsaPkcsOaepParams {
                hash_alg: CkMechanismType(o.hash_alg),
                mgf: CkMgf(o.mgf),
                source: CkOaepSource(o.source),
                source_data: SecretBytes::copy_from_slice(&o.source_data),
                source_null: o.source_null,
                source_data_presence: pointer_from_wire_legacy(
                    &o.source_data,
                    o.source_data_null_len,
                    o.source_null,
                    version,
                )?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Key Wrapping: Gostr3410KeyWrapParams
// ---------------------------------------------------------------------------

impl From<&Gostr3410KeyWrapParams> for v1_proto::Gostr3410KeyWrapParams {
    fn from(p: &Gostr3410KeyWrapParams) -> Self {
        Self {
            wrap_oid: p.wrap_oid.clone(),
            ukm: p.ukm.clone(),
            key_handle: p.key_handle.0,
            // R16: production encode stays v0-shaped.
            wrap_oid_null_len: None,
            ukm_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::Gostr3410KeyWrapParams> for Gostr3410KeyWrapParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::Gostr3410KeyWrapParams {
        let (wrap_oid, wrap_oid_null_len) = pointer_to_wire(&self.wrap_oid_presence);
        let (ukm, ukm_null_len) = pointer_to_wire(&self.ukm_presence);
        v1_proto::Gostr3410KeyWrapParams {
            wrap_oid,
            ukm,
            key_handle: self.key_handle.0,
            wrap_oid_null_len,
            ukm_null_len,
        }
    }
}

impl FromWire<v1_proto::Gostr3410KeyWrapParams> for Gostr3410KeyWrapParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::Gostr3410KeyWrapParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            wrap_oid: p.wrap_oid.clone(),
            ukm: p.ukm.clone(),
            key_handle: CkObjectHandle(p.key_handle),
            wrap_oid_presence: pointer_from_wire(&p.wrap_oid, p.wrap_oid_null_len, version)?,
            ukm_presence: pointer_from_wire(&p.ukm, p.ukm_null_len, version)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Key Wrapping: KeyWrapSetOaepParams
// ---------------------------------------------------------------------------

impl From<&KeyWrapSetOaepParams> for v1_proto::KeyWrapSetOaepParams {
    fn from(p: &KeyWrapSetOaepParams) -> Self {
        Self {
            bc: p.bc,
            x: secret_to_plain(&p.x),
            // R16: production encode stays v0-shaped.
            x_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::KeyWrapSetOaepParams> for KeyWrapSetOaepParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::KeyWrapSetOaepParams {
        let (x, x_null_len) = pointer_to_wire(&self.x_presence);
        v1_proto::KeyWrapSetOaepParams { bc: self.bc, x, x_null_len }
    }
}

impl FromWire<v1_proto::KeyWrapSetOaepParams> for KeyWrapSetOaepParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::KeyWrapSetOaepParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            bc: p.bc,
            x: SecretBytes::copy_from_slice(&p.x),
            x_presence: pointer_from_wire(&p.x, p.x_null_len, version)?,
        })
    }
}

// ---------------------------------------------------------------------------
// PBE: PbeParams
// ---------------------------------------------------------------------------

impl From<&PbeParams> for v1_proto::PbeParams {
    fn from(p: &PbeParams) -> Self {
        Self {
            init_vector: secret_to_plain(&p.init_vector),
            password: secret_to_plain(&p.password),
            salt: secret_to_plain(&p.salt),
            iteration: p.iteration,
            // R16: production encode stays v0-shaped.
            init_vector_null_len: None,
            password_null_len: None,
            salt_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::PbeParams> for PbeParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::PbeParams {
        let (init_vector, init_vector_null_len) = pointer_to_wire(&self.init_vector_presence);
        let (password, password_null_len) = pointer_to_wire(&self.password_presence);
        let (salt, salt_null_len) = pointer_to_wire(&self.salt_presence);
        v1_proto::PbeParams {
            init_vector,
            password,
            salt,
            iteration: self.iteration,
            init_vector_null_len,
            password_null_len,
            salt_null_len,
        }
    }
}

impl FromWire<v1_proto::PbeParams> for PbeParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::PbeParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            init_vector: SecretBytes::copy_from_slice(&p.init_vector),
            password: SecretBytes::copy_from_slice(&p.password),
            salt: SecretBytes::copy_from_slice(&p.salt),
            iteration: p.iteration,
            init_vector_presence: pointer_from_wire(
                &p.init_vector,
                p.init_vector_null_len,
                version,
            )?,
            password_presence: pointer_from_wire(&p.password, p.password_null_len, version)?,
            salt_presence: pointer_from_wire(&p.salt, p.salt_null_len, version)?,
        })
    }
}

/// Lenient (legacy, presence) mirror of one taken wire buffer for the
/// owned-adopting conversions below (R16): the take-ownership fast path
/// borrows the sub-message rather than the outer `Mechanism`, so it has
/// no wire version to enforce the v0+presence rule with — transport
/// validation owns consistency for adopted values. On well-formed input
/// this mirrors [`pointer_from_wire`] exactly.
fn adopt_pointer(taken: Vec<u8>, null_len: Option<u64>) -> (SecretBytes, PointerBytes) {
    let legacy = SecretBytes::new(taken);
    let presence = match null_len {
        Some(declared_len) => PointerBytes::null_len(declared_len),
        None => PointerBytes::present_cloned(&legacy),
    };
    (legacy, presence)
}

// Owned-adopting conversion (W1-L2-04): takes ownership of the password
// buffers out of the prost message instead of copying them, so after
// adoption the password bytes exist in exactly one wiped-on-drop owner.
// The source message is left with empty buffers; its drop wipes any
// residual via the derived `ZeroizeOnDrop` impl (see build.rs).
impl From<&mut v1_proto::PbeParams> for PbeParams {
    fn from(p: &mut v1_proto::PbeParams) -> Self {
        let (init_vector, init_vector_presence) =
            adopt_pointer(std::mem::take(&mut p.init_vector), p.init_vector_null_len);
        let (password, password_presence) =
            adopt_pointer(std::mem::take(&mut p.password), p.password_null_len);
        let (salt, salt_presence) = adopt_pointer(std::mem::take(&mut p.salt), p.salt_null_len);
        Self {
            init_vector,
            password,
            salt,
            iteration: p.iteration,
            init_vector_presence,
            password_presence,
            salt_presence,
        }
    }
}

// ---------------------------------------------------------------------------
// PBE: Pkcs5Pbkd2Params
// ---------------------------------------------------------------------------

impl From<&Pkcs5Pbkd2Params> for v1_proto::Pkcs5Pbkd2Params {
    fn from(p: &Pkcs5Pbkd2Params) -> Self {
        Self {
            salt_source: p.salt_source.0,
            salt_source_data: secret_to_plain(&p.salt_source_data),
            iterations: p.iterations,
            prf: p.prf.0,
            prf_data: secret_to_plain(&p.prf_data),
            password: secret_to_plain(&p.password),
            // R16: production encode stays v0-shaped.
            salt_source_data_null_len: None,
            prf_data_null_len: None,
            password_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::Pkcs5Pbkd2Params> for Pkcs5Pbkd2Params {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::Pkcs5Pbkd2Params {
        let (salt_source_data, salt_source_data_null_len) =
            pointer_to_wire(&self.salt_source_data_presence);
        let (prf_data, prf_data_null_len) = pointer_to_wire(&self.prf_data_presence);
        let (password, password_null_len) = pointer_to_wire(&self.password_presence);
        v1_proto::Pkcs5Pbkd2Params {
            salt_source: self.salt_source.0,
            salt_source_data,
            iterations: self.iterations,
            prf: self.prf.0,
            prf_data,
            password,
            salt_source_data_null_len,
            prf_data_null_len,
            password_null_len,
        }
    }
}

impl FromWire<v1_proto::Pkcs5Pbkd2Params> for Pkcs5Pbkd2Params {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::Pkcs5Pbkd2Params, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            salt_source: CkPbkdf2SaltSource(p.salt_source),
            salt_source_data: SecretBytes::copy_from_slice(&p.salt_source_data),
            iterations: p.iterations,
            prf: CkPbkdf2Prf(p.prf),
            prf_data: SecretBytes::copy_from_slice(&p.prf_data),
            password: SecretBytes::copy_from_slice(&p.password),
            salt_source_data_presence: pointer_from_wire(
                &p.salt_source_data,
                p.salt_source_data_null_len,
                version,
            )?,
            prf_data_presence: pointer_from_wire(&p.prf_data, p.prf_data_null_len, version)?,
            password_presence: pointer_from_wire(&p.password, p.password_null_len, version)?,
        })
    }
}

// Owned-adopting conversion (W1-L2-04): takes ownership of the password
// buffers out of the prost message instead of copying them, so after
// adoption the password bytes exist in exactly one wiped-on-drop owner.
// The source message is left with empty buffers; its drop wipes any
// residual via the derived `ZeroizeOnDrop` impl (see build.rs).
impl From<&mut v1_proto::Pkcs5Pbkd2Params> for Pkcs5Pbkd2Params {
    fn from(p: &mut v1_proto::Pkcs5Pbkd2Params) -> Self {
        let (salt_source_data, salt_source_data_presence) =
            adopt_pointer(std::mem::take(&mut p.salt_source_data), p.salt_source_data_null_len);
        let (prf_data, prf_data_presence) =
            adopt_pointer(std::mem::take(&mut p.prf_data), p.prf_data_null_len);
        let (password, password_presence) =
            adopt_pointer(std::mem::take(&mut p.password), p.password_null_len);
        Self {
            salt_source: CkPbkdf2SaltSource(p.salt_source),
            salt_source_data,
            iterations: p.iterations,
            prf: CkPbkdf2Prf(p.prf),
            prf_data,
            password,
            salt_source_data_presence,
            prf_data_presence,
            password_presence,
        }
    }
}

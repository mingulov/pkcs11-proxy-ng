//! Proto <-> Rust conversions for key derivation, key wrapping, and PBE
//! mechanism parameters.

use crate::pkcs11_proxy_ng::v1 as v1_proto;
use pkcs11_proxy_ng_types::{
    CkMechanismType, CkRv, Ecdh2DeriveParams, EcdhAesKeyWrapParams, EcmqvDeriveParams, EddsaParams,
    Gostr3410DeriveParams, Gostr3410KeyWrapParams, HkdfParams, KeaDeriveParams,
    KeyWrapSetOaepParams, PbeParams, Pkcs5Pbkd2Params, RsaAesKeyWrapParams, RsaPkcsOaepParams,
    X942Dh1DeriveParams, X942Dh2DeriveParams, X942MqvDeriveParams,
};

// ---------------------------------------------------------------------------
// Key Derivation: Ecdh2DeriveParams
// ---------------------------------------------------------------------------

impl From<&Ecdh2DeriveParams> for v1_proto::Ecdh2DeriveParams {
    fn from(p: &Ecdh2DeriveParams) -> Self {
        Self {
            kdf: p.kdf,
            shared_data: p.shared_data.clone(),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: p.private_data_handle,
            public_data2: p.public_data2.clone(),
        }
    }
}

impl From<&v1_proto::Ecdh2DeriveParams> for Ecdh2DeriveParams {
    fn from(p: &v1_proto::Ecdh2DeriveParams) -> Self {
        Self {
            kdf: p.kdf,
            shared_data: p.shared_data.clone(),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: p.private_data_handle,
            public_data2: p.public_data2.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: EcmqvDeriveParams
// ---------------------------------------------------------------------------

impl From<&EcmqvDeriveParams> for v1_proto::EcmqvDeriveParams {
    fn from(p: &EcmqvDeriveParams) -> Self {
        Self {
            kdf: p.kdf,
            shared_data: p.shared_data.clone(),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: p.private_data_handle,
            public_data2: p.public_data2.clone(),
            public_key_handle: p.public_key_handle,
        }
    }
}

impl From<&v1_proto::EcmqvDeriveParams> for EcmqvDeriveParams {
    fn from(p: &v1_proto::EcmqvDeriveParams) -> Self {
        Self {
            kdf: p.kdf,
            shared_data: p.shared_data.clone(),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: p.private_data_handle,
            public_data2: p.public_data2.clone(),
            public_key_handle: p.public_key_handle,
        }
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: X942Dh1DeriveParams
// ---------------------------------------------------------------------------

impl From<&X942Dh1DeriveParams> for v1_proto::X942Dh1DeriveParams {
    fn from(p: &X942Dh1DeriveParams) -> Self {
        Self { kdf: p.kdf, other_info: p.other_info.clone(), public_data: p.public_data.clone() }
    }
}

impl From<&v1_proto::X942Dh1DeriveParams> for X942Dh1DeriveParams {
    fn from(p: &v1_proto::X942Dh1DeriveParams) -> Self {
        Self { kdf: p.kdf, other_info: p.other_info.clone(), public_data: p.public_data.clone() }
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: X942Dh2DeriveParams
// ---------------------------------------------------------------------------

impl From<&X942Dh2DeriveParams> for v1_proto::X942Dh2DeriveParams {
    fn from(p: &X942Dh2DeriveParams) -> Self {
        Self {
            kdf: p.kdf,
            other_info: p.other_info.clone(),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: p.private_data_handle,
            public_data2: p.public_data2.clone(),
        }
    }
}

impl From<&v1_proto::X942Dh2DeriveParams> for X942Dh2DeriveParams {
    fn from(p: &v1_proto::X942Dh2DeriveParams) -> Self {
        Self {
            kdf: p.kdf,
            other_info: p.other_info.clone(),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: p.private_data_handle,
            public_data2: p.public_data2.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: X942MqvDeriveParams
// ---------------------------------------------------------------------------

impl From<&X942MqvDeriveParams> for v1_proto::X942MqvDeriveParams {
    fn from(p: &X942MqvDeriveParams) -> Self {
        Self {
            kdf: p.kdf,
            other_info: p.other_info.clone(),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: p.private_data_handle,
            public_data2: p.public_data2.clone(),
            public_key_handle: p.public_key_handle,
        }
    }
}

impl From<&v1_proto::X942MqvDeriveParams> for X942MqvDeriveParams {
    fn from(p: &v1_proto::X942MqvDeriveParams) -> Self {
        Self {
            kdf: p.kdf,
            other_info: p.other_info.clone(),
            public_data: p.public_data.clone(),
            private_data_len: p.private_data_len,
            private_data_handle: p.private_data_handle,
            public_data2: p.public_data2.clone(),
            public_key_handle: p.public_key_handle,
        }
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
            prf_hash_mechanism: p.prf_hash_mechanism,
            salt_type: p.salt_type,
            salt: p.salt.clone(),
            salt_key_handle: p.salt_key_handle,
            info: p.info.clone(),
        }
    }
}

impl From<&v1_proto::HkdfParams> for HkdfParams {
    fn from(p: &v1_proto::HkdfParams) -> Self {
        Self {
            extract: p.extract,
            expand: p.expand,
            prf_hash_mechanism: p.prf_hash_mechanism,
            salt_type: p.salt_type,
            salt: p.salt.clone(),
            salt_key_handle: p.salt_key_handle,
            info: p.info.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: EddsaParams
// ---------------------------------------------------------------------------

impl From<&EddsaParams> for v1_proto::EddsaParams {
    fn from(p: &EddsaParams) -> Self {
        Self { ph_flag: p.ph_flag, context_data: p.context_data.clone() }
    }
}

impl From<&v1_proto::EddsaParams> for EddsaParams {
    fn from(p: &v1_proto::EddsaParams) -> Self {
        Self { ph_flag: p.ph_flag, context_data: p.context_data.clone() }
    }
}

// ---------------------------------------------------------------------------
// Key Derivation: Gostr3410DeriveParams
// ---------------------------------------------------------------------------

impl From<&Gostr3410DeriveParams> for v1_proto::Gostr3410DeriveParams {
    fn from(p: &Gostr3410DeriveParams) -> Self {
        Self { kdf: p.kdf, public_data: p.public_data.clone(), ukm: p.ukm.clone() }
    }
}

impl From<&v1_proto::Gostr3410DeriveParams> for Gostr3410DeriveParams {
    fn from(p: &v1_proto::Gostr3410DeriveParams) -> Self {
        Self { kdf: p.kdf, public_data: p.public_data.clone(), ukm: p.ukm.clone() }
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
        }
    }
}

impl From<&v1_proto::KeaDeriveParams> for KeaDeriveParams {
    fn from(p: &v1_proto::KeaDeriveParams) -> Self {
        Self {
            is_sender: p.is_sender,
            random_a: p.random_a.clone(),
            random_b: p.random_b.clone(),
            public_data: p.public_data.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Key Wrapping: EcdhAesKeyWrapParams
// ---------------------------------------------------------------------------

impl From<&EcdhAesKeyWrapParams> for v1_proto::EcdhAesKeyWrapParams {
    fn from(p: &EcdhAesKeyWrapParams) -> Self {
        Self { aes_key_bits: p.aes_key_bits, kdf: p.kdf, shared_data: p.shared_data.clone() }
    }
}

impl From<&v1_proto::EcdhAesKeyWrapParams> for EcdhAesKeyWrapParams {
    fn from(p: &v1_proto::EcdhAesKeyWrapParams) -> Self {
        Self { aes_key_bits: p.aes_key_bits, kdf: p.kdf, shared_data: p.shared_data.clone() }
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
                mgf: p.oaep_params.mgf,
                source: p.oaep_params.source,
                source_data: p.oaep_params.source_data.clone(),
            }),
        }
    }
}

impl TryFrom<&v1_proto::RsaAesKeyWrapParams> for RsaAesKeyWrapParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::RsaAesKeyWrapParams) -> Result<Self, Self::Error> {
        let o = p.oaep_params.as_ref().ok_or(CkRv::MECHANISM_PARAM_INVALID)?;
        Ok(Self {
            aes_key_bits: p.aes_key_bits,
            oaep_params: RsaPkcsOaepParams {
                hash_alg: CkMechanismType(o.hash_alg),
                mgf: o.mgf,
                source: o.source,
                source_data: o.source_data.clone(),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Key Wrapping: Gostr3410KeyWrapParams
// ---------------------------------------------------------------------------

impl From<&Gostr3410KeyWrapParams> for v1_proto::Gostr3410KeyWrapParams {
    fn from(p: &Gostr3410KeyWrapParams) -> Self {
        Self { wrap_oid: p.wrap_oid.clone(), ukm: p.ukm.clone(), key_handle: p.key_handle }
    }
}

impl From<&v1_proto::Gostr3410KeyWrapParams> for Gostr3410KeyWrapParams {
    fn from(p: &v1_proto::Gostr3410KeyWrapParams) -> Self {
        Self { wrap_oid: p.wrap_oid.clone(), ukm: p.ukm.clone(), key_handle: p.key_handle }
    }
}

// ---------------------------------------------------------------------------
// Key Wrapping: KeyWrapSetOaepParams
// ---------------------------------------------------------------------------

impl From<&KeyWrapSetOaepParams> for v1_proto::KeyWrapSetOaepParams {
    fn from(p: &KeyWrapSetOaepParams) -> Self {
        Self { bc: p.bc, x: p.x.clone() }
    }
}

impl From<&v1_proto::KeyWrapSetOaepParams> for KeyWrapSetOaepParams {
    fn from(p: &v1_proto::KeyWrapSetOaepParams) -> Self {
        Self { bc: p.bc, x: p.x.clone() }
    }
}

// ---------------------------------------------------------------------------
// PBE: PbeParams
// ---------------------------------------------------------------------------

impl From<&PbeParams> for v1_proto::PbeParams {
    fn from(p: &PbeParams) -> Self {
        Self {
            init_vector: p.init_vector.clone(),
            password: p.password.clone(),
            salt: p.salt.clone(),
            iteration: p.iteration,
        }
    }
}

impl From<&v1_proto::PbeParams> for PbeParams {
    fn from(p: &v1_proto::PbeParams) -> Self {
        Self {
            init_vector: p.init_vector.clone(),
            password: p.password.clone(),
            salt: p.salt.clone(),
            iteration: p.iteration,
        }
    }
}

// ---------------------------------------------------------------------------
// PBE: Pkcs5Pbkd2Params
// ---------------------------------------------------------------------------

impl From<&Pkcs5Pbkd2Params> for v1_proto::Pkcs5Pbkd2Params {
    fn from(p: &Pkcs5Pbkd2Params) -> Self {
        Self {
            salt_source: p.salt_source,
            salt_source_data: p.salt_source_data.clone(),
            iterations: p.iterations,
            prf: p.prf,
            prf_data: p.prf_data.clone(),
            password: p.password.clone(),
        }
    }
}

impl From<&v1_proto::Pkcs5Pbkd2Params> for Pkcs5Pbkd2Params {
    fn from(p: &v1_proto::Pkcs5Pbkd2Params) -> Self {
        Self {
            salt_source: p.salt_source,
            salt_source_data: p.salt_source_data.clone(),
            iterations: p.iterations,
            prf: p.prf,
            prf_data: p.prf_data.clone(),
            password: p.password.clone(),
        }
    }
}

//! Proto <-> Rust conversions for TLS/SSL and WTLS mechanism parameters.

use crate::pkcs11_proxy_ng::v1 as v1_proto;
use pkcs11_proxy_ng_types::{
    CkRv, Ssl3KeyMatParams, Ssl3MasterKeyDeriveParams, SslRandomData,
    Tls12ExtendedMasterKeyDeriveParams, Tls12MasterKeyDeriveParams, TlsKdfParams, TlsPrfParams,
    WtlsKeyMatParams, WtlsMasterKeyDeriveParams, WtlsPrfParams, WtlsRandomData,
};

// ---------------------------------------------------------------------------
// Helper: SslRandomData
// ---------------------------------------------------------------------------

fn ssl_random_to_proto(r: &SslRandomData) -> v1_proto::SslRandomData {
    v1_proto::SslRandomData {
        client_random: r.client_random.clone(),
        server_random: r.server_random.clone(),
    }
}

fn ssl_random_from_proto(r: &v1_proto::SslRandomData) -> SslRandomData {
    SslRandomData { client_random: r.client_random.clone(), server_random: r.server_random.clone() }
}

fn required_ssl_random_from_option(
    r: &Option<v1_proto::SslRandomData>,
) -> Result<SslRandomData, CkRv> {
    r.as_ref().map(ssl_random_from_proto).ok_or(CkRv::MECHANISM_PARAM_INVALID)
}

// ---------------------------------------------------------------------------
// Helper: WtlsRandomData
// ---------------------------------------------------------------------------

fn wtls_random_to_proto(r: &WtlsRandomData) -> v1_proto::WtlsRandomData {
    v1_proto::WtlsRandomData {
        client_random: r.client_random.clone(),
        server_random: r.server_random.clone(),
    }
}

fn wtls_random_from_proto(r: &v1_proto::WtlsRandomData) -> WtlsRandomData {
    WtlsRandomData {
        client_random: r.client_random.clone(),
        server_random: r.server_random.clone(),
    }
}

fn required_wtls_random_from_option(
    r: &Option<v1_proto::WtlsRandomData>,
) -> Result<WtlsRandomData, CkRv> {
    r.as_ref().map(wtls_random_from_proto).ok_or(CkRv::MECHANISM_PARAM_INVALID)
}

// ---------------------------------------------------------------------------
// TlsPrfParams
// ---------------------------------------------------------------------------

impl From<&TlsPrfParams> for v1_proto::TlsPrfParams {
    fn from(p: &TlsPrfParams) -> Self {
        Self { seed: p.seed.clone(), label: p.label.clone(), output_len: p.output_len }
    }
}

impl From<&v1_proto::TlsPrfParams> for TlsPrfParams {
    fn from(p: &v1_proto::TlsPrfParams) -> Self {
        Self { seed: p.seed.clone(), label: p.label.clone(), output_len: p.output_len }
    }
}

// ---------------------------------------------------------------------------
// TlsKdfParams
// ---------------------------------------------------------------------------

impl From<&TlsKdfParams> for v1_proto::TlsKdfParams {
    fn from(p: &TlsKdfParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism,
            label: p.label.clone(),
            random_info: Some(ssl_random_to_proto(&p.random_info)),
            context_data: p.context_data.clone(),
        }
    }
}

impl TryFrom<&v1_proto::TlsKdfParams> for TlsKdfParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::TlsKdfParams) -> Result<Self, Self::Error> {
        Ok(Self {
            prf_mechanism: p.prf_mechanism,
            label: p.label.clone(),
            random_info: required_ssl_random_from_option(&p.random_info)?,
            context_data: p.context_data.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Ssl3MasterKeyDeriveParams
// ---------------------------------------------------------------------------

impl From<&Ssl3MasterKeyDeriveParams> for v1_proto::Ssl3MasterKeyDeriveParams {
    fn from(p: &Ssl3MasterKeyDeriveParams) -> Self {
        Self {
            random_info: Some(ssl_random_to_proto(&p.random_info)),
            version_major: p.version_major,
            version_minor: p.version_minor,
        }
    }
}

impl TryFrom<&v1_proto::Ssl3MasterKeyDeriveParams> for Ssl3MasterKeyDeriveParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::Ssl3MasterKeyDeriveParams) -> Result<Self, Self::Error> {
        Ok(Self {
            random_info: required_ssl_random_from_option(&p.random_info)?,
            version_major: p.version_major,
            version_minor: p.version_minor,
        })
    }
}

// ---------------------------------------------------------------------------
// Tls12MasterKeyDeriveParams
// ---------------------------------------------------------------------------

impl From<&Tls12MasterKeyDeriveParams> for v1_proto::Tls12MasterKeyDeriveParams {
    fn from(p: &Tls12MasterKeyDeriveParams) -> Self {
        Self {
            random_info: Some(ssl_random_to_proto(&p.random_info)),
            version_major: p.version_major,
            version_minor: p.version_minor,
            prf_hash_mechanism: p.prf_hash_mechanism,
        }
    }
}

impl TryFrom<&v1_proto::Tls12MasterKeyDeriveParams> for Tls12MasterKeyDeriveParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::Tls12MasterKeyDeriveParams) -> Result<Self, Self::Error> {
        Ok(Self {
            random_info: required_ssl_random_from_option(&p.random_info)?,
            version_major: p.version_major,
            version_minor: p.version_minor,
            prf_hash_mechanism: p.prf_hash_mechanism,
        })
    }
}

// ---------------------------------------------------------------------------
// Tls12ExtendedMasterKeyDeriveParams
// ---------------------------------------------------------------------------

impl From<&Tls12ExtendedMasterKeyDeriveParams> for v1_proto::Tls12ExtendedMasterKeyDeriveParams {
    fn from(p: &Tls12ExtendedMasterKeyDeriveParams) -> Self {
        Self {
            prf_hash_mechanism: p.prf_hash_mechanism,
            session_hash: p.session_hash.clone(),
            version_major: p.version_major,
            version_minor: p.version_minor,
        }
    }
}

impl From<&v1_proto::Tls12ExtendedMasterKeyDeriveParams> for Tls12ExtendedMasterKeyDeriveParams {
    fn from(p: &v1_proto::Tls12ExtendedMasterKeyDeriveParams) -> Self {
        Self {
            prf_hash_mechanism: p.prf_hash_mechanism,
            session_hash: p.session_hash.clone(),
            version_major: p.version_major,
            version_minor: p.version_minor,
        }
    }
}

// ---------------------------------------------------------------------------
// Ssl3KeyMatParams
// ---------------------------------------------------------------------------

impl From<&Ssl3KeyMatParams> for v1_proto::Ssl3KeyMatParams {
    fn from(p: &Ssl3KeyMatParams) -> Self {
        Self {
            mac_size_bits: p.mac_size_bits,
            key_size_bits: p.key_size_bits,
            iv_size_bits: p.iv_size_bits,
            is_export: p.is_export,
            random_info: Some(ssl_random_to_proto(&p.random_info)),
            prf_hash_mechanism: p.prf_hash_mechanism,
        }
    }
}

impl TryFrom<&v1_proto::Ssl3KeyMatParams> for Ssl3KeyMatParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::Ssl3KeyMatParams) -> Result<Self, Self::Error> {
        Ok(Self {
            mac_size_bits: p.mac_size_bits,
            key_size_bits: p.key_size_bits,
            iv_size_bits: p.iv_size_bits,
            is_export: p.is_export,
            random_info: required_ssl_random_from_option(&p.random_info)?,
            prf_hash_mechanism: p.prf_hash_mechanism,
        })
    }
}

// ---------------------------------------------------------------------------
// WtlsMasterKeyDeriveParams
// ---------------------------------------------------------------------------

impl From<&WtlsMasterKeyDeriveParams> for v1_proto::WtlsMasterKeyDeriveParams {
    fn from(p: &WtlsMasterKeyDeriveParams) -> Self {
        Self {
            digest_mechanism: p.digest_mechanism,
            random_info: Some(wtls_random_to_proto(&p.random_info)),
            version: p.version,
        }
    }
}

impl TryFrom<&v1_proto::WtlsMasterKeyDeriveParams> for WtlsMasterKeyDeriveParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::WtlsMasterKeyDeriveParams) -> Result<Self, Self::Error> {
        Ok(Self {
            digest_mechanism: p.digest_mechanism,
            random_info: required_wtls_random_from_option(&p.random_info)?,
            version: p.version,
        })
    }
}

// ---------------------------------------------------------------------------
// WtlsPrfParams
// ---------------------------------------------------------------------------

impl From<&WtlsPrfParams> for v1_proto::WtlsPrfParams {
    fn from(p: &WtlsPrfParams) -> Self {
        Self {
            digest_mechanism: p.digest_mechanism,
            seed: p.seed.clone(),
            label: p.label.clone(),
            output_len: p.output_len,
        }
    }
}

impl From<&v1_proto::WtlsPrfParams> for WtlsPrfParams {
    fn from(p: &v1_proto::WtlsPrfParams) -> Self {
        Self {
            digest_mechanism: p.digest_mechanism,
            seed: p.seed.clone(),
            label: p.label.clone(),
            output_len: p.output_len,
        }
    }
}

// ---------------------------------------------------------------------------
// WtlsKeyMatParams
// ---------------------------------------------------------------------------

impl From<&WtlsKeyMatParams> for v1_proto::WtlsKeyMatParams {
    fn from(p: &WtlsKeyMatParams) -> Self {
        Self {
            digest_mechanism: p.digest_mechanism,
            mac_size_bits: p.mac_size_bits,
            key_size_bits: p.key_size_bits,
            iv_size_bits: p.iv_size_bits,
            sequence_number: p.sequence_number,
            is_export: p.is_export,
            random_info: Some(wtls_random_to_proto(&p.random_info)),
        }
    }
}

impl TryFrom<&v1_proto::WtlsKeyMatParams> for WtlsKeyMatParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::WtlsKeyMatParams) -> Result<Self, Self::Error> {
        Ok(Self {
            digest_mechanism: p.digest_mechanism,
            mac_size_bits: p.mac_size_bits,
            key_size_bits: p.key_size_bits,
            iv_size_bits: p.iv_size_bits,
            sequence_number: p.sequence_number,
            is_export: p.is_export,
            random_info: required_wtls_random_from_option(&p.random_info)?,
        })
    }
}

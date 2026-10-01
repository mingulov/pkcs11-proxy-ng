//! Proto <-> Rust conversions for TLS/SSL and WTLS mechanism parameters.

use crate::pkcs11_proxy_ng::v1 as v1_proto;
// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use super::{
    FromWire, ToWireV1, null_bit_from_wire, null_bit_to_wire, pointer_from_wire, pointer_to_wire,
};
use crate::secret_boundary::secret_to_plain;
use pkcs11_proxy_ng_types::{
    CkMechanismType, CkObjectHandle, CkRv, PointerBytes, SecretBytes, Ssl3KeyMatParams,
    Ssl3MasterKeyDeriveParams, SslRandomData, Tls12ExtendedMasterKeyDeriveParams,
    Tls12MasterKeyDeriveParams, TlsKdfParams, TlsPrfParams, WtlsKeyMatParams,
    WtlsMasterKeyDeriveParams, WtlsPrfParams, WtlsRandomData,
};

// ---------------------------------------------------------------------------
// Helper: SslRandomData
// ---------------------------------------------------------------------------

fn ssl_random_to_proto(r: &SslRandomData) -> v1_proto::SslRandomData {
    v1_proto::SslRandomData {
        client_random: pointer_to_wire(&r.client_random_presence).0,
        server_random: pointer_to_wire(&r.server_random_presence).0,
        // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
        client_random_null_len: None,
        server_random_null_len: None,
    }
}

fn ssl_random_from_proto(r: &v1_proto::SslRandomData) -> SslRandomData {
    // R18: unversioned legacy decode — peers mirror Present (FromWire threads versions).
    let client_random = r.client_random.clone();
    let server_random = r.server_random.clone();
    SslRandomData {
        client_random_presence: PointerBytes::present_copy(&client_random),
        server_random_presence: PointerBytes::present_copy(&server_random),
    }
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
        client_random: pointer_to_wire(&r.client_random_presence).0,
        server_random: pointer_to_wire(&r.server_random_presence).0,
        // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
        client_random_null_len: None,
        server_random_null_len: None,
    }
}

fn wtls_random_from_proto(r: &v1_proto::WtlsRandomData) -> WtlsRandomData {
    // R18: unversioned legacy decode — peers mirror Present (FromWire threads versions).
    let client_random = r.client_random.clone();
    let server_random = r.server_random.clone();
    WtlsRandomData {
        client_random_presence: PointerBytes::present_copy(&client_random),
        server_random_presence: PointerBytes::present_copy(&server_random),
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
        Self {
            seed: pointer_to_wire(&p.seed_presence).0,
            label: pointer_to_wire(&p.label_presence).0,
            output_len: p.output_len,
            output: secret_to_plain(&p.output),
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            seed_null_len: None,
            label_null_len: None,
            output_null: None,
            output_len_null: None,
        }
    }
}

impl From<&v1_proto::TlsPrfParams> for TlsPrfParams {
    fn from(p: &v1_proto::TlsPrfParams) -> Self {
        // R18: unversioned legacy decode — peers mirror Present (FromWire threads versions).
        let seed = SecretBytes::copy_from_slice(&p.seed);
        let label = SecretBytes::copy_from_slice(&p.label);
        Self {
            seed_presence: PointerBytes::present_cloned(&seed),
            label_presence: PointerBytes::present_cloned(&label),
            output_is_null: false,
            output_len_is_null: false,
            output_len: p.output_len,
            output: SecretBytes::copy_from_slice(&p.output),
        }
    }
}

// ---------------------------------------------------------------------------
// TlsKdfParams
// ---------------------------------------------------------------------------

impl From<&TlsKdfParams> for v1_proto::TlsKdfParams {
    fn from(p: &TlsKdfParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism.0,
            label: pointer_to_wire(&p.label_presence).0,
            random_info: Some(ssl_random_to_proto(&p.random_info)),
            context_data: pointer_to_wire(&p.context_data_presence).0,
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            label_null_len: None,
            context_data_null_len: None,
        }
    }
}

impl TryFrom<&v1_proto::TlsKdfParams> for TlsKdfParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::TlsKdfParams) -> Result<Self, Self::Error> {
        // R18: unversioned legacy decode — peers mirror Present (FromWire threads versions).
        let label = SecretBytes::copy_from_slice(&p.label);
        let context_data = SecretBytes::copy_from_slice(&p.context_data);
        Ok(Self {
            prf_mechanism: CkMechanismType(p.prf_mechanism),
            label_presence: PointerBytes::present_cloned(&label),
            random_info: required_ssl_random_from_option(&p.random_info)?,
            context_data_presence: PointerBytes::present_cloned(&context_data),
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
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            version_null: None,
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
            version_is_null: false,
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
            prf_hash_mechanism: p.prf_hash_mechanism.0,
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            version_null: None,
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
            prf_hash_mechanism: CkMechanismType(p.prf_hash_mechanism),
            version_is_null: false,
        })
    }
}

// ---------------------------------------------------------------------------
// Tls12ExtendedMasterKeyDeriveParams
// ---------------------------------------------------------------------------

impl From<&Tls12ExtendedMasterKeyDeriveParams> for v1_proto::Tls12ExtendedMasterKeyDeriveParams {
    fn from(p: &Tls12ExtendedMasterKeyDeriveParams) -> Self {
        Self {
            prf_hash_mechanism: p.prf_hash_mechanism.0,
            session_hash: pointer_to_wire(&p.session_hash_presence).0,
            version_major: p.version_major,
            version_minor: p.version_minor,
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            session_hash_null_len: None,
            version_null: None,
        }
    }
}

impl From<&v1_proto::Tls12ExtendedMasterKeyDeriveParams> for Tls12ExtendedMasterKeyDeriveParams {
    fn from(p: &v1_proto::Tls12ExtendedMasterKeyDeriveParams) -> Self {
        // R18: unversioned legacy decode — peers mirror Present (FromWire threads versions).
        let session_hash = p.session_hash.clone();
        Self {
            prf_hash_mechanism: CkMechanismType(p.prf_hash_mechanism),
            session_hash_presence: PointerBytes::present_copy(&session_hash),
            version_major: p.version_major,
            version_minor: p.version_minor,
            version_is_null: false,
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
            prf_hash_mechanism: p.prf_hash_mechanism.0,
            client_mac_secret_handle: p.client_mac_secret_handle.0,
            server_mac_secret_handle: p.server_mac_secret_handle.0,
            client_key_handle: p.client_key_handle.0,
            server_key_handle: p.server_key_handle.0,
            client_iv: pointer_to_wire(&p.client_iv_presence).0,
            server_iv: pointer_to_wire(&p.server_iv_presence).0,
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            returned_key_material_null: None,
            client_iv_null_len: None,
            server_iv_null_len: None,
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
            prf_hash_mechanism: CkMechanismType(p.prf_hash_mechanism),
            client_mac_secret_handle: CkObjectHandle(p.client_mac_secret_handle),
            server_mac_secret_handle: CkObjectHandle(p.server_mac_secret_handle),
            client_key_handle: CkObjectHandle(p.client_key_handle),
            server_key_handle: CkObjectHandle(p.server_key_handle),
            client_iv_presence: PointerBytes::present_copy(&p.client_iv),
            server_iv_presence: PointerBytes::present_copy(&p.server_iv),
            returned_key_material_is_null: false,
        })
    }
}

// ---------------------------------------------------------------------------
// WtlsMasterKeyDeriveParams
// ---------------------------------------------------------------------------

impl From<&WtlsMasterKeyDeriveParams> for v1_proto::WtlsMasterKeyDeriveParams {
    fn from(p: &WtlsMasterKeyDeriveParams) -> Self {
        Self {
            digest_mechanism: p.digest_mechanism.0,
            random_info: Some(wtls_random_to_proto(&p.random_info)),
            version: p.version,
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            version_null: None,
        }
    }
}

impl TryFrom<&v1_proto::WtlsMasterKeyDeriveParams> for WtlsMasterKeyDeriveParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::WtlsMasterKeyDeriveParams) -> Result<Self, Self::Error> {
        Ok(Self {
            digest_mechanism: CkMechanismType(p.digest_mechanism),
            random_info: required_wtls_random_from_option(&p.random_info)?,
            version: p.version,
            version_is_null: false,
        })
    }
}

// ---------------------------------------------------------------------------
// WtlsPrfParams
// ---------------------------------------------------------------------------

impl From<&WtlsPrfParams> for v1_proto::WtlsPrfParams {
    fn from(p: &WtlsPrfParams) -> Self {
        Self {
            digest_mechanism: p.digest_mechanism.0,
            seed: pointer_to_wire(&p.seed_presence).0,
            label: pointer_to_wire(&p.label_presence).0,
            output_len: p.output_len,
            output: secret_to_plain(&p.output),
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            seed_null_len: None,
            label_null_len: None,
            output_null: None,
            output_len_null: None,
        }
    }
}

impl From<&v1_proto::WtlsPrfParams> for WtlsPrfParams {
    fn from(p: &v1_proto::WtlsPrfParams) -> Self {
        // R18: unversioned legacy decode — peers mirror Present (FromWire threads versions).
        let seed = SecretBytes::copy_from_slice(&p.seed);
        let label = SecretBytes::copy_from_slice(&p.label);
        Self {
            digest_mechanism: CkMechanismType(p.digest_mechanism),
            seed_presence: PointerBytes::present_cloned(&seed),
            label_presence: PointerBytes::present_cloned(&label),
            output_len: p.output_len,
            output: SecretBytes::copy_from_slice(&p.output),
            output_is_null: false,
            output_len_is_null: false,
        }
    }
}

// ---------------------------------------------------------------------------
// WtlsKeyMatParams
// ---------------------------------------------------------------------------

impl From<&WtlsKeyMatParams> for v1_proto::WtlsKeyMatParams {
    fn from(p: &WtlsKeyMatParams) -> Self {
        Self {
            digest_mechanism: p.digest_mechanism.0,
            mac_size_bits: p.mac_size_bits,
            key_size_bits: p.key_size_bits,
            iv_size_bits: p.iv_size_bits,
            sequence_number: p.sequence_number,
            is_export: p.is_export,
            random_info: Some(wtls_random_to_proto(&p.random_info)),
            mac_secret_handle: p.mac_secret_handle.0,
            key_handle: p.key_handle.0,
            iv: pointer_to_wire(&p.iv_presence).0,
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            returned_key_material_null: None,
            iv_null_len: None,
        }
    }
}

impl TryFrom<&v1_proto::WtlsKeyMatParams> for WtlsKeyMatParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::WtlsKeyMatParams) -> Result<Self, Self::Error> {
        Ok(Self {
            digest_mechanism: CkMechanismType(p.digest_mechanism),
            mac_size_bits: p.mac_size_bits,
            key_size_bits: p.key_size_bits,
            iv_size_bits: p.iv_size_bits,
            sequence_number: p.sequence_number,
            is_export: p.is_export,
            random_info: required_wtls_random_from_option(&p.random_info)?,
            mac_secret_handle: CkObjectHandle(p.mac_secret_handle),
            key_handle: CkObjectHandle(p.key_handle),
            iv_presence: PointerBytes::present_copy(&p.iv),
            returned_key_material_is_null: false,
        })
    }
}

// ---------------------------------------------------------------------------
// R18: version-threaded tail conversions (S2 §8)
// ---------------------------------------------------------------------------

impl FromWire<v1_proto::SslRandomData> for SslRandomData {
    fn from_wire(p: &v1_proto::SslRandomData, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            client_random_presence: pointer_from_wire(
                &p.client_random,
                p.client_random_null_len,
                version,
            )?,
            server_random_presence: pointer_from_wire(
                &p.server_random,
                p.server_random_null_len,
                version,
            )?,
        })
    }
}

impl ToWireV1<v1_proto::SslRandomData> for SslRandomData {
    fn to_wire_v1(&self) -> v1_proto::SslRandomData {
        let (client_random, client_random_null_len) = pointer_to_wire(&self.client_random_presence);
        let (server_random, server_random_null_len) = pointer_to_wire(&self.server_random_presence);
        v1_proto::SslRandomData {
            client_random,
            server_random,
            client_random_null_len,
            server_random_null_len,
        }
    }
}

impl FromWire<v1_proto::WtlsRandomData> for WtlsRandomData {
    fn from_wire(p: &v1_proto::WtlsRandomData, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            client_random_presence: pointer_from_wire(
                &p.client_random,
                p.client_random_null_len,
                version,
            )?,
            server_random_presence: pointer_from_wire(
                &p.server_random,
                p.server_random_null_len,
                version,
            )?,
        })
    }
}

impl ToWireV1<v1_proto::WtlsRandomData> for WtlsRandomData {
    fn to_wire_v1(&self) -> v1_proto::WtlsRandomData {
        let (client_random, client_random_null_len) = pointer_to_wire(&self.client_random_presence);
        let (server_random, server_random_null_len) = pointer_to_wire(&self.server_random_presence);
        v1_proto::WtlsRandomData {
            client_random,
            server_random,
            client_random_null_len,
            server_random_null_len,
        }
    }
}

/// Required `random_info` under a version-threaded decode (R18 dual of
/// [`required_ssl_random_from_option`]): absent stays `PARAM_INVALID`
/// at every version (legacy-exact); present threads the version into
/// the submessage envelopes.
fn required_ssl_random_from_wire(
    r: &Option<v1_proto::SslRandomData>,
    version: u32,
) -> Result<SslRandomData, CkRv> {
    match r.as_ref() {
        Some(r) => SslRandomData::from_wire(r, version),
        None => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

/// WTLS variant of [`required_ssl_random_from_wire`].
fn required_wtls_random_from_wire(
    r: &Option<v1_proto::WtlsRandomData>,
    version: u32,
) -> Result<WtlsRandomData, CkRv> {
    match r.as_ref() {
        Some(r) => WtlsRandomData::from_wire(r, version),
        None => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

impl FromWire<v1_proto::TlsPrfParams> for TlsPrfParams {
    fn from_wire(p: &v1_proto::TlsPrfParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            output_len: p.output_len,
            output: SecretBytes::copy_from_slice(&p.output),
            seed_presence: pointer_from_wire(&p.seed, p.seed_null_len, version)?,
            label_presence: pointer_from_wire(&p.label, p.label_null_len, version)?,
            output_is_null: null_bit_from_wire(p.output_null, p.output.is_empty(), version)?,
            output_len_is_null: null_bit_from_wire(p.output_len_null, p.output_len == 0, version)?,
        })
    }
}

impl ToWireV1<v1_proto::TlsPrfParams> for TlsPrfParams {
    fn to_wire_v1(&self) -> v1_proto::TlsPrfParams {
        let (seed, seed_null_len) = pointer_to_wire(&self.seed_presence);
        let (label, label_null_len) = pointer_to_wire(&self.label_presence);
        v1_proto::TlsPrfParams {
            seed,
            label,
            output_len: self.output_len,
            output: secret_to_plain(&self.output),
            seed_null_len,
            label_null_len,
            output_null: null_bit_to_wire(self.output_is_null),
            output_len_null: null_bit_to_wire(self.output_len_is_null),
        }
    }
}

impl FromWire<v1_proto::TlsKdfParams> for TlsKdfParams {
    fn from_wire(p: &v1_proto::TlsKdfParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            prf_mechanism: CkMechanismType(p.prf_mechanism),
            random_info: required_ssl_random_from_wire(&p.random_info, version)?,
            label_presence: pointer_from_wire(&p.label, p.label_null_len, version)?,
            context_data_presence: pointer_from_wire(
                &p.context_data,
                p.context_data_null_len,
                version,
            )?,
        })
    }
}

impl ToWireV1<v1_proto::TlsKdfParams> for TlsKdfParams {
    fn to_wire_v1(&self) -> v1_proto::TlsKdfParams {
        let (label, label_null_len) = pointer_to_wire(&self.label_presence);
        let (context_data, context_data_null_len) = pointer_to_wire(&self.context_data_presence);
        v1_proto::TlsKdfParams {
            prf_mechanism: self.prf_mechanism.0,
            label,
            random_info: Some(self.random_info.to_wire_v1()),
            context_data,
            label_null_len,
            context_data_null_len,
        }
    }
}

impl FromWire<v1_proto::Ssl3MasterKeyDeriveParams> for Ssl3MasterKeyDeriveParams {
    fn from_wire(p: &v1_proto::Ssl3MasterKeyDeriveParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            random_info: required_ssl_random_from_wire(&p.random_info, version)?,
            version_major: p.version_major,
            version_minor: p.version_minor,
            version_is_null: null_bit_from_wire(
                p.version_null,
                p.version_major == 0 && p.version_minor == 0,
                version,
            )?,
        })
    }
}

impl ToWireV1<v1_proto::Ssl3MasterKeyDeriveParams> for Ssl3MasterKeyDeriveParams {
    fn to_wire_v1(&self) -> v1_proto::Ssl3MasterKeyDeriveParams {
        v1_proto::Ssl3MasterKeyDeriveParams {
            random_info: Some(self.random_info.to_wire_v1()),
            version_major: self.version_major,
            version_minor: self.version_minor,
            version_null: null_bit_to_wire(self.version_is_null),
        }
    }
}

impl FromWire<v1_proto::Tls12MasterKeyDeriveParams> for Tls12MasterKeyDeriveParams {
    fn from_wire(p: &v1_proto::Tls12MasterKeyDeriveParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            random_info: required_ssl_random_from_wire(&p.random_info, version)?,
            version_major: p.version_major,
            version_minor: p.version_minor,
            prf_hash_mechanism: CkMechanismType(p.prf_hash_mechanism),
            version_is_null: null_bit_from_wire(
                p.version_null,
                p.version_major == 0 && p.version_minor == 0,
                version,
            )?,
        })
    }
}

impl ToWireV1<v1_proto::Tls12MasterKeyDeriveParams> for Tls12MasterKeyDeriveParams {
    fn to_wire_v1(&self) -> v1_proto::Tls12MasterKeyDeriveParams {
        v1_proto::Tls12MasterKeyDeriveParams {
            random_info: Some(self.random_info.to_wire_v1()),
            version_major: self.version_major,
            version_minor: self.version_minor,
            prf_hash_mechanism: self.prf_hash_mechanism.0,
            version_null: null_bit_to_wire(self.version_is_null),
        }
    }
}

impl FromWire<v1_proto::Tls12ExtendedMasterKeyDeriveParams> for Tls12ExtendedMasterKeyDeriveParams {
    fn from_wire(
        p: &v1_proto::Tls12ExtendedMasterKeyDeriveParams,
        version: u32,
    ) -> Result<Self, CkRv> {
        Ok(Self {
            prf_hash_mechanism: CkMechanismType(p.prf_hash_mechanism),
            version_major: p.version_major,
            version_minor: p.version_minor,
            session_hash_presence: pointer_from_wire(
                &p.session_hash,
                p.session_hash_null_len,
                version,
            )?,
            version_is_null: null_bit_from_wire(
                p.version_null,
                p.version_major == 0 && p.version_minor == 0,
                version,
            )?,
        })
    }
}

impl ToWireV1<v1_proto::Tls12ExtendedMasterKeyDeriveParams> for Tls12ExtendedMasterKeyDeriveParams {
    fn to_wire_v1(&self) -> v1_proto::Tls12ExtendedMasterKeyDeriveParams {
        let (session_hash, session_hash_null_len) = pointer_to_wire(&self.session_hash_presence);
        v1_proto::Tls12ExtendedMasterKeyDeriveParams {
            prf_hash_mechanism: self.prf_hash_mechanism.0,
            session_hash,
            version_major: self.version_major,
            version_minor: self.version_minor,
            session_hash_null_len,
            version_null: null_bit_to_wire(self.version_is_null),
        }
    }
}

impl FromWire<v1_proto::Ssl3KeyMatParams> for Ssl3KeyMatParams {
    fn from_wire(p: &v1_proto::Ssl3KeyMatParams, version: u32) -> Result<Self, CkRv> {
        // A NULL pReturnedKeyMaterial forces every handle zero and both
        // IVs empty (mirrors `check_typed_presence`).
        let returned_forced = p.client_mac_secret_handle == 0
            && p.server_mac_secret_handle == 0
            && p.client_key_handle == 0
            && p.server_key_handle == 0
            && p.client_iv.is_empty()
            && p.server_iv.is_empty();
        Ok(Self {
            mac_size_bits: p.mac_size_bits,
            key_size_bits: p.key_size_bits,
            iv_size_bits: p.iv_size_bits,
            is_export: p.is_export,
            random_info: required_ssl_random_from_wire(&p.random_info, version)?,
            prf_hash_mechanism: CkMechanismType(p.prf_hash_mechanism),
            client_mac_secret_handle: CkObjectHandle(p.client_mac_secret_handle),
            server_mac_secret_handle: CkObjectHandle(p.server_mac_secret_handle),
            client_key_handle: CkObjectHandle(p.client_key_handle),
            server_key_handle: CkObjectHandle(p.server_key_handle),
            client_iv_presence: pointer_from_wire(&p.client_iv, p.client_iv_null_len, version)?,
            server_iv_presence: pointer_from_wire(&p.server_iv, p.server_iv_null_len, version)?,
            returned_key_material_is_null: null_bit_from_wire(
                p.returned_key_material_null,
                returned_forced,
                version,
            )?,
        })
    }
}

impl ToWireV1<v1_proto::Ssl3KeyMatParams> for Ssl3KeyMatParams {
    fn to_wire_v1(&self) -> v1_proto::Ssl3KeyMatParams {
        let (client_iv, client_iv_null_len) = pointer_to_wire(&self.client_iv_presence);
        let (server_iv, server_iv_null_len) = pointer_to_wire(&self.server_iv_presence);
        v1_proto::Ssl3KeyMatParams {
            mac_size_bits: self.mac_size_bits,
            key_size_bits: self.key_size_bits,
            iv_size_bits: self.iv_size_bits,
            is_export: self.is_export,
            random_info: Some(self.random_info.to_wire_v1()),
            prf_hash_mechanism: self.prf_hash_mechanism.0,
            client_mac_secret_handle: self.client_mac_secret_handle.0,
            server_mac_secret_handle: self.server_mac_secret_handle.0,
            client_key_handle: self.client_key_handle.0,
            server_key_handle: self.server_key_handle.0,
            client_iv,
            server_iv,
            returned_key_material_null: null_bit_to_wire(self.returned_key_material_is_null),
            client_iv_null_len,
            server_iv_null_len,
        }
    }
}

impl FromWire<v1_proto::WtlsMasterKeyDeriveParams> for WtlsMasterKeyDeriveParams {
    fn from_wire(p: &v1_proto::WtlsMasterKeyDeriveParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            digest_mechanism: CkMechanismType(p.digest_mechanism),
            random_info: required_wtls_random_from_wire(&p.random_info, version)?,
            version: p.version,
            version_is_null: null_bit_from_wire(p.version_null, p.version == 0, version)?,
        })
    }
}

impl ToWireV1<v1_proto::WtlsMasterKeyDeriveParams> for WtlsMasterKeyDeriveParams {
    fn to_wire_v1(&self) -> v1_proto::WtlsMasterKeyDeriveParams {
        v1_proto::WtlsMasterKeyDeriveParams {
            digest_mechanism: self.digest_mechanism.0,
            random_info: Some(self.random_info.to_wire_v1()),
            version: self.version,
            version_null: null_bit_to_wire(self.version_is_null),
        }
    }
}

impl FromWire<v1_proto::WtlsPrfParams> for WtlsPrfParams {
    fn from_wire(p: &v1_proto::WtlsPrfParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            digest_mechanism: CkMechanismType(p.digest_mechanism),
            output_len: p.output_len,
            output: SecretBytes::copy_from_slice(&p.output),
            seed_presence: pointer_from_wire(&p.seed, p.seed_null_len, version)?,
            label_presence: pointer_from_wire(&p.label, p.label_null_len, version)?,
            output_is_null: null_bit_from_wire(p.output_null, p.output.is_empty(), version)?,
            output_len_is_null: null_bit_from_wire(p.output_len_null, p.output_len == 0, version)?,
        })
    }
}

impl ToWireV1<v1_proto::WtlsPrfParams> for WtlsPrfParams {
    fn to_wire_v1(&self) -> v1_proto::WtlsPrfParams {
        let (seed, seed_null_len) = pointer_to_wire(&self.seed_presence);
        let (label, label_null_len) = pointer_to_wire(&self.label_presence);
        v1_proto::WtlsPrfParams {
            digest_mechanism: self.digest_mechanism.0,
            seed,
            label,
            output_len: self.output_len,
            output: secret_to_plain(&self.output),
            seed_null_len,
            label_null_len,
            output_null: null_bit_to_wire(self.output_is_null),
            output_len_null: null_bit_to_wire(self.output_len_is_null),
        }
    }
}

impl FromWire<v1_proto::WtlsKeyMatParams> for WtlsKeyMatParams {
    fn from_wire(p: &v1_proto::WtlsKeyMatParams, version: u32) -> Result<Self, CkRv> {
        // A NULL pReturnedKeyMaterial forces both handles zero and `iv`
        // empty (mirrors `check_typed_presence`).
        let returned_forced = p.mac_secret_handle == 0 && p.key_handle == 0 && p.iv.is_empty();
        Ok(Self {
            digest_mechanism: CkMechanismType(p.digest_mechanism),
            mac_size_bits: p.mac_size_bits,
            key_size_bits: p.key_size_bits,
            iv_size_bits: p.iv_size_bits,
            sequence_number: p.sequence_number,
            is_export: p.is_export,
            random_info: required_wtls_random_from_wire(&p.random_info, version)?,
            mac_secret_handle: CkObjectHandle(p.mac_secret_handle),
            key_handle: CkObjectHandle(p.key_handle),
            iv_presence: pointer_from_wire(&p.iv, p.iv_null_len, version)?,
            returned_key_material_is_null: null_bit_from_wire(
                p.returned_key_material_null,
                returned_forced,
                version,
            )?,
        })
    }
}

impl ToWireV1<v1_proto::WtlsKeyMatParams> for WtlsKeyMatParams {
    fn to_wire_v1(&self) -> v1_proto::WtlsKeyMatParams {
        let (iv, iv_null_len) = pointer_to_wire(&self.iv_presence);
        v1_proto::WtlsKeyMatParams {
            digest_mechanism: self.digest_mechanism.0,
            mac_size_bits: self.mac_size_bits,
            key_size_bits: self.key_size_bits,
            iv_size_bits: self.iv_size_bits,
            sequence_number: self.sequence_number,
            is_export: self.is_export,
            random_info: Some(self.random_info.to_wire_v1()),
            mac_secret_handle: self.mac_secret_handle.0,
            key_handle: self.key_handle.0,
            iv,
            returned_key_material_null: null_bit_to_wire(self.returned_key_material_is_null),
            iv_null_len,
        }
    }
}

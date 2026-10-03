//! Bidirectional conversions for PKCS#11 3.0/3.2 message-based crypto parameter types
//! and the CK_ASYNC_DATA result structure.
//!
//! The Rust-side structs live here for now; they can migrate to `pkcs11-types` once
//! the message-based API layer stabilises.

use crate::pkcs11_proxy_ng::v1 as v1_proto;
// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use crate::secret_boundary::secret_to_plain;
use pkcs11_proxy_ng_types::{CkObjectHandle, SecretBytes};

// ---------------------------------------------------------------------------
// Rust-side struct definitions
// ---------------------------------------------------------------------------

/// CK_GCM_MESSAGE_PARAMS — per-message GCM parameters for message-based APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcmMessageParams {
    pub iv: Vec<u8>,
    pub iv_null_len: Option<u64>,
    pub iv_fixed_bits: u64,
    pub iv_generator: u64,
    pub tag: Vec<u8>,
    pub tag_null_len: Option<u64>,
    pub tag_bits: u64,
}

/// CK_CCM_MESSAGE_PARAMS — per-message CCM parameters for message-based APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcmMessageParams {
    pub data_len: u64,
    pub nonce: Vec<u8>,
    pub nonce_null_len: Option<u64>,
    pub nonce_fixed_bits: u64,
    pub nonce_generator: u64,
    pub mac: Vec<u8>,
    pub mac_null_len: Option<u64>,
    pub mac_len: u64,
}

/// CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS — per-message Salsa20/ChaCha20-Poly1305 parameters.
///
/// `nonce_bits` carries the caller's `ulNonceLen` VERBATIM (T20): the OASIS
/// text says bits, but the field name, the proxy's legacy path, and shipping
/// backends (kryoptic, NSS) use bytes, so both forms are accepted and the
/// original value round-trips to the backend untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Salsa20ChaCha20Poly1305MessageParams {
    pub nonce: Vec<u8>,
    pub nonce_bits: u64,
    pub nonce_null_len: Option<u64>,
    pub tag: Vec<u8>,
    pub tag_null_len: Option<u64>,
}

/// T20: nonce-length unit tolerance for
/// `CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS.ulNonceLen`. Accepts the bits
/// form (64/96/192, per the OASIS text) and the bytes form (8/12/24, per
/// the field name, backend practice, and the proxy's legacy path). The
/// value itself always round-trips verbatim — only the extent reading is
/// unit-aware. Single home for the accepted sets (shim reader and all
/// validators); keep the two forms disjoint.
pub fn salsa_nonce_len(value: u64) -> Option<u64> {
    match value {
        64 | 96 | 192 => Some(value / 8),
        8 | 12 | 24 => Some(value),
        _ => None,
    }
}

/// Expected nonce extent when `value` and `extent` are a consistent pair
/// in either accepted unit.
pub fn salsa_nonce_extent(value: u64, extent: u64) -> Option<u64> {
    salsa_nonce_len(value).filter(|len| *len == extent)
}

/// CK_ASYNC_DATA — result structure for C_AsyncComplete.
///
/// `value` is `SecretBytes` (ADR-0013): `AsyncData.value` is classified
/// secret and the polymorphic async payload fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncData {
    pub version: u64,
    pub value: SecretBytes,
    pub value_len: u64,
    pub object_handle: CkObjectHandle,
    pub additional_object_handle: CkObjectHandle,
}

/// Rust-side enum for the `MessageParameter` oneof.
///
/// `Raw` is `SecretBytes` (ADR-0013): `MessageParameter.raw` is classified
/// secret (unknown vendor bytes fail closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageParameter {
    Raw(SecretBytes),
    GcmMessage(GcmMessageParams),
    CcmMessage(CcmMessageParams),
    SalaChacha(Salsa20ChaCha20Poly1305MessageParams),
}

const MAX_MESSAGE_PARAMETER_BYTES: u64 = 512 * 1024 * 1024;

/// Highest per-message `parameter_encoding_version` this daemon understands
/// (S2 §3 monotonic capabilities). A version above this on a received
/// message is `FUNCTION_NOT_SUPPORTED` pre-entry (S2 §6 RV table).
pub const SUPPORTED_MESSAGE_PARAMETER_TRANSPORT_VERSION: u32 = 1;

/// 64 KiB outer-parameter cap for v1 opaque message params (S2 §3): the
/// declared extent, not just the materialized buffer, must fit.
const MAX_OPAQUE_MESSAGE_PARAMETER_BYTES: u64 = 64 * 1024;

fn pointer_extent_len(
    bytes_len: usize,
    null_len: Option<u64>,
) -> Result<u64, pkcs11_proxy_ng_types::CkRv> {
    if let Some(extent) = null_len {
        if bytes_len != 0 {
            return Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID);
        }
        return Ok(extent);
    }
    let extent = bytes_len as u64;
    if extent > MAX_MESSAGE_PARAMETER_BYTES {
        return Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID);
    }
    Ok(extent)
}

fn pointer_extent(bytes: &[u8], null_len: Option<u64>) -> Result<u64, pkcs11_proxy_ng_types::CkRv> {
    pointer_extent_len(bytes.len(), null_len)
}

fn validate_generator(generator: u64) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
    if generator <= 4 { Ok(()) } else { Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID) }
}

fn validate_gcm_fields(
    iv_len: usize,
    iv_null_len: Option<u64>,
    iv_fixed_bits: u64,
    iv_generator: u64,
    tag_len: usize,
    tag_null_len: Option<u64>,
    tag_bits: u64,
) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
    let iv_extent = pointer_extent_len(iv_len, iv_null_len)?;
    if iv_fixed_bits.div_ceil(8) > iv_extent || tag_bits > 128 {
        return Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID);
    }
    validate_generator(iv_generator)?;
    if pointer_extent_len(tag_len, tag_null_len)? == tag_bits.div_ceil(8) {
        Ok(())
    } else {
        Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID)
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_ccm_fields(
    nonce_len: usize,
    nonce_null_len: Option<u64>,
    nonce_fixed_bits: u64,
    nonce_generator: u64,
    mac_len_bytes: usize,
    mac_null_len: Option<u64>,
    mac_len: u64,
) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
    let nonce_extent = pointer_extent_len(nonce_len, nonce_null_len)?;
    if !(7..=13).contains(&nonce_extent) {
        return Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID);
    }
    let nonce_bits =
        nonce_extent.checked_mul(8).ok_or(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID)?;
    if nonce_fixed_bits > nonce_bits || !matches!(mac_len, 4 | 6 | 8 | 10 | 12 | 14 | 16) {
        return Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID);
    }
    validate_generator(nonce_generator)?;
    if pointer_extent_len(mac_len_bytes, mac_null_len)? == mac_len {
        Ok(())
    } else {
        Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID)
    }
}

fn validate_salsa_fields(
    nonce_len: usize,
    nonce_bits: u64,
    nonce_null_len: Option<u64>,
    tag_len: usize,
    tag_null_len: Option<u64>,
) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
    let nonce_extent = pointer_extent_len(nonce_len, nonce_null_len)?;
    if salsa_nonce_extent(nonce_bits, nonce_extent).is_none()
        || pointer_extent_len(tag_len, tag_null_len)? != 16
    {
        Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID)
    } else {
        Ok(())
    }
}

impl GcmMessageParams {
    pub fn validate_structured(&self) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
        validate_gcm_fields(
            self.iv.len(),
            self.iv_null_len,
            self.iv_fixed_bits,
            self.iv_generator,
            self.tag.len(),
            self.tag_null_len,
            self.tag_bits,
        )
    }

    pub fn validate_for_native_ulong(&self, max: u64) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
        self.validate_structured()?;
        let iv_len = pointer_extent(&self.iv, self.iv_null_len)?;
        if [iv_len, self.iv_fixed_bits, self.iv_generator, self.tag_bits]
            .into_iter()
            .all(|value| value <= max)
        {
            Ok(())
        } else {
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID)
        }
    }
}

impl CcmMessageParams {
    pub fn validate_structured(&self) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
        validate_ccm_fields(
            self.nonce.len(),
            self.nonce_null_len,
            self.nonce_fixed_bits,
            self.nonce_generator,
            self.mac.len(),
            self.mac_null_len,
            self.mac_len,
        )
    }

    pub fn validate_for_native_ulong(&self, max: u64) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
        self.validate_structured()?;
        let nonce_len = pointer_extent(&self.nonce, self.nonce_null_len)?;
        if [self.data_len, nonce_len, self.nonce_fixed_bits, self.nonce_generator, self.mac_len]
            .into_iter()
            .all(|value| value <= max)
        {
            Ok(())
        } else {
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID)
        }
    }
}

impl Salsa20ChaCha20Poly1305MessageParams {
    pub fn validate_structured(&self) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
        validate_salsa_fields(
            self.nonce.len(),
            self.nonce_bits,
            self.nonce_null_len,
            self.tag.len(),
            self.tag_null_len,
        )
    }

    pub fn validate_for_native_ulong(&self, max: u64) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
        self.validate_structured()?;
        if self.nonce_bits <= max {
            Ok(())
        } else {
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID)
        }
    }
}

impl MessageParameter {
    pub fn same_layout_and_scalars(&self, other: &Self) -> bool {
        match (self, other) {
            // Opaque bytes carry no layout/scalars: identity is byte
            // equality (compared without copying out of the wiping owner).
            (Self::Raw(left), Self::Raw(right)) => left.expose(|a| right.expose(|b| a == b)),
            (Self::GcmMessage(left), Self::GcmMessage(right)) => {
                left.iv.len() == right.iv.len()
                    && left.iv_null_len == right.iv_null_len
                    && left.iv_fixed_bits == right.iv_fixed_bits
                    && left.iv_generator == right.iv_generator
                    && left.tag.len() == right.tag.len()
                    && left.tag_null_len == right.tag_null_len
                    && left.tag_bits == right.tag_bits
            }
            (Self::CcmMessage(left), Self::CcmMessage(right)) => {
                left.data_len == right.data_len
                    && left.nonce.len() == right.nonce.len()
                    && left.nonce_null_len == right.nonce_null_len
                    && left.nonce_fixed_bits == right.nonce_fixed_bits
                    && left.nonce_generator == right.nonce_generator
                    && left.mac.len() == right.mac.len()
                    && left.mac_null_len == right.mac_null_len
                    && left.mac_len == right.mac_len
            }
            (Self::SalaChacha(left), Self::SalaChacha(right)) => {
                left.nonce.len() == right.nonce.len()
                    && left.nonce_bits == right.nonce_bits
                    && left.nonce_null_len == right.nonce_null_len
                    && left.tag.len() == right.tag.len()
                    && left.tag_null_len == right.tag_null_len
            }
            _ => false,
        }
    }

    /// Validate the shape-independent scalar and embedded-buffer contract.
    /// Operation stage and encrypt/decrypt direction are checked at the C ABI
    /// edge; this method rejects malformed wire representations before FFI.
    pub fn validate_structured_shape(
        &self,
        expected: MessageParameterShape,
    ) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
        if !expected.matches(self) {
            return Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID);
        }
        self.validate_structured()
    }

    pub fn validate_structured(&self) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
        match self {
            // Opaque bytes carry no layout/scalars to check; length and cap
            // were enforced at the wire boundary (R3 v1 acceptance).
            Self::Raw(_) => Ok(()),
            Self::GcmMessage(params) => params.validate_structured(),
            Self::CcmMessage(params) => params.validate_structured(),
            Self::SalaChacha(params) => params.validate_structured(),
        }
    }

    /// Validate every scalar that will be converted to a provider-native
    /// `CK_ULONG`. Callers pass the actual target maximum so 64-bit servers
    /// can exercise and test ILP32/LLP64 constraints without allocating a
    /// second set of backing buffers.
    pub fn validate_for_native_ulong(&self, max: u64) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
        match self {
            // Only the byte length crosses into native width; a length that
            // cannot narrow to backend `CK_ULONG` is `FUNCTION_FAILED`
            // (S2 §6 RV table), not a shape violation.
            Self::Raw(bytes) => {
                let len = u64::try_from(bytes.len())
                    .map_err(|_| pkcs11_proxy_ng_types::CkRv::FUNCTION_FAILED)?;
                if len <= max { Ok(()) } else { Err(pkcs11_proxy_ng_types::CkRv::FUNCTION_FAILED) }
            }
            Self::GcmMessage(params) => params.validate_for_native_ulong(max),
            Self::CcmMessage(params) => params.validate_for_native_ulong(max),
            Self::SalaChacha(params) => params.validate_for_native_ulong(max),
        }
    }
}

/// Registry-derived C layout for Encrypt/Decrypt message parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageParameterShape {
    Unmodeled,
    Gcm,
    Ccm,
    SalsaChacha,
}

impl MessageParameterShape {
    pub fn from_registry_name(name: Option<&str>) -> Self {
        match name {
            Some("gcm") => Self::Gcm,
            Some("ccm") => Self::Ccm,
            Some("salsa20_chacha20_poly1305") => Self::SalsaChacha,
            _ => Self::Unmodeled,
        }
    }

    pub fn to_proto_i32(self) -> i32 {
        match self {
            Self::Unmodeled => v1_proto::MessageParameterShape::Unmodeled as i32,
            Self::Gcm => v1_proto::MessageParameterShape::Gcm as i32,
            Self::Ccm => v1_proto::MessageParameterShape::Ccm as i32,
            Self::SalsaChacha => v1_proto::MessageParameterShape::SalsaChacha as i32,
        }
    }

    pub fn try_from_proto_i32(value: i32) -> Result<Self, pkcs11_proxy_ng_types::CkRv> {
        match v1_proto::MessageParameterShape::try_from(value).ok() {
            Some(v1_proto::MessageParameterShape::Unmodeled) => Ok(Self::Unmodeled),
            Some(v1_proto::MessageParameterShape::Gcm) => Ok(Self::Gcm),
            Some(v1_proto::MessageParameterShape::Ccm) => Ok(Self::Ccm),
            Some(v1_proto::MessageParameterShape::SalsaChacha) => Ok(Self::SalsaChacha),
            None => Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
        }
    }

    pub fn matches(self, parameter: &MessageParameter) -> bool {
        matches!(
            (self, parameter),
            (Self::Gcm, MessageParameter::GcmMessage(_))
                | (Self::Ccm, MessageParameter::CcmMessage(_))
                | (Self::SalsaChacha, MessageParameter::SalaChacha(_))
                | (Self::Unmodeled, MessageParameter::Raw(_))
        )
    }
}

// ---------------------------------------------------------------------------
// GcmMessageParams conversions
// ---------------------------------------------------------------------------

impl From<&GcmMessageParams> for v1_proto::GcmMessageParams {
    fn from(p: &GcmMessageParams) -> Self {
        v1_proto::GcmMessageParams {
            iv: p.iv.clone(),
            iv_fixed_bits: p.iv_fixed_bits,
            iv_generator: p.iv_generator,
            tag: p.tag.clone(),
            tag_bits: p.tag_bits,
            iv_null_len: p.iv_null_len,
            tag_null_len: p.tag_null_len,
        }
    }
}

impl From<&v1_proto::GcmMessageParams> for GcmMessageParams {
    fn from(p: &v1_proto::GcmMessageParams) -> Self {
        GcmMessageParams {
            iv: p.iv.clone(),
            iv_null_len: p.iv_null_len,
            iv_fixed_bits: p.iv_fixed_bits,
            iv_generator: p.iv_generator,
            tag: p.tag.clone(),
            tag_null_len: p.tag_null_len,
            tag_bits: p.tag_bits,
        }
    }
}

// ---------------------------------------------------------------------------
// CcmMessageParams conversions
// ---------------------------------------------------------------------------

impl From<&CcmMessageParams> for v1_proto::CcmMessageParams {
    fn from(p: &CcmMessageParams) -> Self {
        v1_proto::CcmMessageParams {
            data_len: p.data_len,
            nonce: p.nonce.clone(),
            nonce_fixed_bits: p.nonce_fixed_bits,
            nonce_generator: p.nonce_generator,
            mac: p.mac.clone(),
            mac_len: p.mac_len,
            nonce_null_len: p.nonce_null_len,
            mac_null_len: p.mac_null_len,
        }
    }
}

impl From<&v1_proto::CcmMessageParams> for CcmMessageParams {
    fn from(p: &v1_proto::CcmMessageParams) -> Self {
        CcmMessageParams {
            data_len: p.data_len,
            nonce: p.nonce.clone(),
            nonce_null_len: p.nonce_null_len,
            nonce_fixed_bits: p.nonce_fixed_bits,
            nonce_generator: p.nonce_generator,
            mac: p.mac.clone(),
            mac_null_len: p.mac_null_len,
            mac_len: p.mac_len,
        }
    }
}

// ---------------------------------------------------------------------------
// Salsa20ChaCha20Poly1305MessageParams conversions
// ---------------------------------------------------------------------------

impl From<&Salsa20ChaCha20Poly1305MessageParams>
    for v1_proto::Salsa20ChaCha20Poly1305MessageParams
{
    fn from(p: &Salsa20ChaCha20Poly1305MessageParams) -> Self {
        v1_proto::Salsa20ChaCha20Poly1305MessageParams {
            nonce: p.nonce.clone(),
            tag: p.tag.clone(),
            nonce_bits: p.nonce_bits,
            nonce_null_len: p.nonce_null_len,
            tag_null_len: p.tag_null_len,
        }
    }
}

impl From<&v1_proto::Salsa20ChaCha20Poly1305MessageParams>
    for Salsa20ChaCha20Poly1305MessageParams
{
    fn from(p: &v1_proto::Salsa20ChaCha20Poly1305MessageParams) -> Self {
        Salsa20ChaCha20Poly1305MessageParams {
            nonce: p.nonce.clone(),
            nonce_bits: p.nonce_bits,
            nonce_null_len: p.nonce_null_len,
            tag: p.tag.clone(),
            tag_null_len: p.tag_null_len,
        }
    }
}

// ---------------------------------------------------------------------------
// AsyncData conversions
// ---------------------------------------------------------------------------

impl From<&AsyncData> for v1_proto::AsyncData {
    fn from(a: &AsyncData) -> Self {
        v1_proto::AsyncData {
            version: a.version,
            value: secret_to_plain(&a.value),
            value_len: a.value_len,
            object_handle: a.object_handle.0,
            additional_object_handle: a.additional_object_handle.0,
        }
    }
}

impl From<&v1_proto::AsyncData> for AsyncData {
    fn from(a: &v1_proto::AsyncData) -> Self {
        AsyncData {
            version: a.version,
            value: SecretBytes::copy_from_slice(&a.value),
            value_len: a.value_len,
            object_handle: CkObjectHandle(a.object_handle),
            additional_object_handle: CkObjectHandle(a.additional_object_handle),
        }
    }
}

// ---------------------------------------------------------------------------
// MessageParameter conversions
// ---------------------------------------------------------------------------

impl From<&MessageParameter> for v1_proto::MessageParameter {
    fn from(p: &MessageParameter) -> Self {
        let params = match p {
            MessageParameter::Raw(data) => {
                v1_proto::message_parameter::Params::Raw(secret_to_plain(data))
            }
            MessageParameter::GcmMessage(p) => {
                v1_proto::message_parameter::Params::GcmMessageParams(p.into())
            }
            MessageParameter::CcmMessage(p) => {
                v1_proto::message_parameter::Params::CcmMessageParams(p.into())
            }
            MessageParameter::SalaChacha(p) => {
                v1_proto::message_parameter::Params::SalsaChachaMessageParams(p.into())
            }
        };
        // R2: legacy encode stays version 0 (v1 emission is R5).
        v1_proto::MessageParameter { params: Some(params), parameter_encoding_version: 0 }
    }
}

impl MessageParameter {
    /// Capability-gated wire encoding (R5/F1; S2 §5: under v1 the shim
    /// never emits legacy `Raw`; legacy capability preserves current
    /// behavior exactly).
    ///
    /// `transport_version` is the negotiated `mechanism_parameter_transport_version`
    /// capability (discovery value, 0 when absent). At capability ≥ 1 —
    /// including capabilities newer than this encoder, which still emits
    /// the v1 form it knows — `Raw` (the Unmodeled shape's representation)
    /// travels as `opaque_message_params` carrying the exact bytes with
    /// `declared_len` set to the byte length and version 1; a declared
    /// extent over the 64 KiB outer cap (S2 §3) fails locally with
    /// `MECHANISM_PARAM_INVALID` without wire emission. At legacy
    /// capability the encoding is bit-identical to the legacy `From`
    /// (legacy `Raw`, version 0). Structured arms always use the legacy
    /// encoding: their contract is unchanged across versions.
    pub fn to_wire_with_transport_version(
        &self,
        transport_version: u32,
    ) -> Result<v1_proto::MessageParameter, pkcs11_proxy_ng_types::CkRv> {
        if transport_version >= SUPPORTED_MESSAGE_PARAMETER_TRANSPORT_VERSION
            && let MessageParameter::Raw(data) = self
        {
            let declared_len = u64::try_from(data.len())
                .map_err(|_| pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID)?;
            if declared_len > MAX_OPAQUE_MESSAGE_PARAMETER_BYTES {
                return Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID);
            }
            return Ok(v1_proto::MessageParameter {
                params: Some(v1_proto::message_parameter::Params::OpaqueMessageParams(
                    v1_proto::OpaqueMessageParams { data: secret_to_plain(data), declared_len },
                )),
                parameter_encoding_version: SUPPORTED_MESSAGE_PARAMETER_TRANSPORT_VERSION,
            });
        }
        Ok(v1_proto::MessageParameter::from(self))
    }
}

/// Per-message version newer than the daemon understands is
/// `FUNCTION_NOT_SUPPORTED` pre-entry (S2 §6 RV table).
fn check_wire_version(version: u32) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
    if version > SUPPORTED_MESSAGE_PARAMETER_TRANSPORT_VERSION {
        return Err(pkcs11_proxy_ng_types::CkRv::FUNCTION_NOT_SUPPORTED);
    }
    Ok(())
}

/// Validate v1 opaque bytes: the encoding is valid only with version 1, the
/// declared extent must fit the 64 KiB outer cap, and the materialized bytes
/// must be exactly the declared extent (S2 §3 + §6 RV table).
fn validate_opaque_wire_params(
    opaque: &v1_proto::OpaqueMessageParams,
    version: u32,
) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
    use pkcs11_proxy_ng_types::CkRv;
    if version != SUPPORTED_MESSAGE_PARAMETER_TRANSPORT_VERSION {
        // No silent downgrade across versions: opaque is the v1 encoding and
        // nothing else. Version 0/absent + opaque present is contradictory
        // metadata; anything newer is beyond this daemon.
        return Err(if version < SUPPORTED_MESSAGE_PARAMETER_TRANSPORT_VERSION {
            CkRv::MECHANISM_PARAM_INVALID
        } else {
            CkRv::FUNCTION_NOT_SUPPORTED
        });
    }
    if opaque.declared_len > MAX_OPAQUE_MESSAGE_PARAMETER_BYTES {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    let declared =
        usize::try_from(opaque.declared_len).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    if opaque.data.len() != declared {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    Ok(())
}

/// Validate an attacker-controlled structured wire parameter by borrowing its
/// protobuf buffers. This must run before cloning them into the owned native
/// representation at the daemon trust boundary.
fn validate_structured_wire_params(
    params: &v1_proto::message_parameter::Params,
    version: u32,
) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
    match params {
        // Legacy `raw` fails closed at every version, including versions
        // newer than this daemon (S2 §3; checked before the version gate).
        v1_proto::message_parameter::Params::Raw(_) => {
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID)
        }
        v1_proto::message_parameter::Params::GcmMessageParams(p) => {
            check_wire_version(version)?;
            validate_gcm_fields(
                p.iv.len(),
                p.iv_null_len,
                p.iv_fixed_bits,
                p.iv_generator,
                p.tag.len(),
                p.tag_null_len,
                p.tag_bits,
            )
        }
        v1_proto::message_parameter::Params::CcmMessageParams(p) => {
            check_wire_version(version)?;
            validate_ccm_fields(
                p.nonce.len(),
                p.nonce_null_len,
                p.nonce_fixed_bits,
                p.nonce_generator,
                p.mac.len(),
                p.mac_null_len,
                p.mac_len,
            )
        }
        v1_proto::message_parameter::Params::SalsaChachaMessageParams(p) => {
            check_wire_version(version)?;
            validate_salsa_fields(
                p.nonce.len(),
                p.nonce_bits,
                p.nonce_null_len,
                p.tag.len(),
                p.tag_null_len,
            )
        }
        // R3 v1 acceptance: opaque bytes are the Unmodeled shape's v1
        // representation (replaces R2's blanket placeholder rejection).
        v1_proto::message_parameter::Params::OpaqueMessageParams(p) => {
            validate_opaque_wire_params(p, version)
        }
    }
}

pub fn validate_structured_wire_parameter(
    parameter: &v1_proto::MessageParameter,
) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
    let params = parameter.params.as_ref().ok_or(super::ABSENT_MESSAGE_ONEOF_RV)?;
    validate_structured_wire_params(params, parameter.parameter_encoding_version)
}

impl TryFrom<&v1_proto::MessageParameter> for MessageParameter {
    type Error = pkcs11_proxy_ng_types::CkRv;

    fn try_from(p: &v1_proto::MessageParameter) -> Result<Self, Self::Error> {
        match &p.params {
            Some(v1_proto::message_parameter::Params::Raw(data)) => {
                Ok(MessageParameter::Raw(SecretBytes::copy_from_slice(data)))
            }
            Some(params @ v1_proto::message_parameter::Params::GcmMessageParams(p)) => {
                // Decode stays version-blind (R2): field validation only;
                // version enforcement is validation behavior, applied by
                // `validate_structured_wire_parameter` pre-entry.
                validate_structured_wire_params(params, 0)?;
                let parameter = MessageParameter::GcmMessage(p.into());
                Ok(parameter)
            }
            Some(params @ v1_proto::message_parameter::Params::CcmMessageParams(p)) => {
                validate_structured_wire_params(params, 0)?;
                let parameter = MessageParameter::CcmMessage(p.into());
                Ok(parameter)
            }
            Some(params @ v1_proto::message_parameter::Params::SalsaChachaMessageParams(p)) => {
                validate_structured_wire_params(params, 0)?;
                let parameter = MessageParameter::SalaChacha(p.into());
                Ok(parameter)
            }
            // R2: decode passes opaque bytes through at any version (unknown
            // versions must not fail decode); enforcement is validation
            // behavior (R3/R4).
            Some(v1_proto::message_parameter::Params::OpaqueMessageParams(p)) => {
                Ok(MessageParameter::Raw(SecretBytes::copy_from_slice(&p.data)))
            }
            None => Err(super::ABSENT_MESSAGE_ONEOF_RV),
        }
    }
}

impl MessageParameter {
    /// T13 owned entry point: identical validation to the borrowed
    /// `TryFrom`, but the secret-classified `Raw` arm adopts the buffer
    /// with `mem::take` instead of copying it. Structured arms convert
    /// from the owned message with the same reviewed copies (their
    /// destinations are FFI-shape structs, not wiping owners). The caller
    /// must own the message.
    pub fn try_from_owned(
        mut p: v1_proto::MessageParameter,
    ) -> Result<Self, pkcs11_proxy_ng_types::CkRv> {
        // Validate structured arms through a shared borrow first (same
        // checks, same errors as the borrowed `TryFrom` — `&mut` is not
        // `Copy`, so the `@` bindings the borrowed form uses cannot move
        // twice), then adopt through `&mut`: payloads cannot move out of
        // the `ZeroizeOnDrop` oneof enum, so the secret arm adopts its
        // buffer with `mem::take`.
        let mut taken = p.params.take();
        if let Some(params) = taken.as_ref()
            && !matches!(
                params,
                v1_proto::message_parameter::Params::Raw(_)
                    | v1_proto::message_parameter::Params::OpaqueMessageParams(_)
            )
        {
            // Decode stays version-blind (R2): field validation only.
            validate_structured_wire_params(params, 0)?;
        }
        match taken.as_mut() {
            Some(v1_proto::message_parameter::Params::Raw(data)) => {
                Ok(MessageParameter::Raw(SecretBytes::new(std::mem::take(data))))
            }
            // R2: owned passthrough mirrors the borrowed decode (no copy).
            Some(v1_proto::message_parameter::Params::OpaqueMessageParams(p)) => {
                Ok(MessageParameter::Raw(SecretBytes::new(std::mem::take(&mut p.data))))
            }
            Some(v1_proto::message_parameter::Params::GcmMessageParams(p)) => {
                Ok(MessageParameter::GcmMessage((&*p).into()))
            }
            Some(v1_proto::message_parameter::Params::CcmMessageParams(p)) => {
                Ok(MessageParameter::CcmMessage((&*p).into()))
            }
            Some(v1_proto::message_parameter::Params::SalsaChachaMessageParams(p)) => {
                Ok(MessageParameter::SalaChacha((&*p).into()))
            }
            None => Err(super::ABSENT_MESSAGE_ONEOF_RV),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_message_params_round_trip() {
        let original = GcmMessageParams {
            iv: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C],
            iv_null_len: None,
            iv_fixed_bits: 32,
            iv_generator: 2,
            tag: vec![0xAA; 16],
            tag_null_len: None,
            tag_bits: 128,
        };
        let proto: v1_proto::GcmMessageParams = (&original).into();
        let back = GcmMessageParams::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn gcm_message_params_empty_iv_and_tag() {
        let original = GcmMessageParams {
            iv: vec![],
            iv_null_len: Some(0),
            iv_fixed_bits: 0,
            iv_generator: 0,
            tag: vec![],
            tag_null_len: Some(0),
            tag_bits: 0,
        };
        let proto: v1_proto::GcmMessageParams = (&original).into();
        let back = GcmMessageParams::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn ccm_message_params_round_trip() {
        let original = CcmMessageParams {
            data_len: 256,
            nonce: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            nonce_null_len: None,
            nonce_fixed_bits: 16,
            nonce_generator: 1,
            mac: vec![0xBB; 8],
            mac_null_len: None,
            mac_len: 8,
        };
        let proto: v1_proto::CcmMessageParams = (&original).into();
        let back = CcmMessageParams::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn ccm_message_params_empty_fields() {
        let original = CcmMessageParams {
            data_len: 0,
            nonce: vec![],
            nonce_null_len: Some(0),
            nonce_fixed_bits: 0,
            nonce_generator: 0,
            mac: vec![],
            mac_null_len: Some(0),
            mac_len: 0,
        };
        let proto: v1_proto::CcmMessageParams = (&original).into();
        let back = CcmMessageParams::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn salsa20_chacha20_poly1305_message_params_round_trip() {
        let original = Salsa20ChaCha20Poly1305MessageParams {
            nonce: vec![0x01; 12],
            nonce_bits: 96,
            nonce_null_len: None,
            tag: vec![0xCC; 16],
            tag_null_len: None,
        };
        let proto: v1_proto::Salsa20ChaCha20Poly1305MessageParams = (&original).into();
        let back = Salsa20ChaCha20Poly1305MessageParams::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn salsa_nonce_len_accepts_bits_and_bytes_forms() {
        // T20: OASIS text says bits (64/96/192); field name, backend
        // practice (kryoptic, NSS), and the legacy path say bytes
        // (8/12/24). Both map to the same extents; anything else rejects.
        for (value, extent) in [(64, 8), (96, 12), (192, 24), (8, 8), (12, 12), (24, 24)] {
            assert_eq!(super::salsa_nonce_len(value), Some(extent), "value {value}");
            assert_eq!(super::salsa_nonce_extent(value, extent), Some(extent));
            assert_eq!(super::salsa_nonce_extent(value, extent + 1), None);
        }
        for value in [0, 7, 11, 13, 16, 32, 48, 95, 97, 128, 191, 193, 256] {
            assert_eq!(super::salsa_nonce_len(value), None, "value {value}");
        }
    }

    #[test]
    fn salsa20_chacha20_poly1305_empty_fields() {
        let original = Salsa20ChaCha20Poly1305MessageParams {
            nonce: vec![],
            nonce_bits: 96,
            nonce_null_len: Some(12),
            tag: vec![],
            tag_null_len: Some(16),
        };
        let proto: v1_proto::Salsa20ChaCha20Poly1305MessageParams = (&original).into();
        let back = Salsa20ChaCha20Poly1305MessageParams::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn async_data_round_trip() {
        let original = AsyncData {
            version: 1,
            value: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
            value_len: 4,
            object_handle: CkObjectHandle(42),
            additional_object_handle: CkObjectHandle(99),
        };
        let proto: v1_proto::AsyncData = (&original).into();
        let back = AsyncData::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn async_data_zero_handles() {
        let original = AsyncData {
            version: 0,
            value: vec![].into(),
            value_len: 0,
            object_handle: CkObjectHandle(0),
            additional_object_handle: CkObjectHandle(0),
        };
        let proto: v1_proto::AsyncData = (&original).into();
        let back = AsyncData::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn async_data_max_handles() {
        let original = AsyncData {
            version: u64::MAX,
            value: vec![0xFF; 32].into(),
            value_len: 32,
            object_handle: CkObjectHandle(u64::MAX),
            additional_object_handle: CkObjectHandle(u64::MAX),
        };
        let proto: v1_proto::AsyncData = (&original).into();
        let back = AsyncData::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn message_parameter_raw_round_trip() {
        let original = MessageParameter::Raw(vec![0x01, 0x02, 0x03].into());
        let proto: v1_proto::MessageParameter = (&original).into();
        let back = MessageParameter::try_from(&proto).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn message_parameter_raw_empty() {
        let original = MessageParameter::Raw(vec![].into());
        let proto: v1_proto::MessageParameter = (&original).into();
        let back = MessageParameter::try_from(&proto).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn message_parameter_gcm_round_trip() {
        let original = MessageParameter::GcmMessage(GcmMessageParams {
            iv: vec![0x01; 12],
            iv_null_len: None,
            iv_fixed_bits: 32,
            iv_generator: 2,
            tag: vec![0xAA; 16],
            tag_null_len: None,
            tag_bits: 128,
        });
        let proto: v1_proto::MessageParameter = (&original).into();
        let back = MessageParameter::try_from(&proto).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn message_parameter_ccm_round_trip() {
        let original = MessageParameter::CcmMessage(CcmMessageParams {
            data_len: 1024,
            nonce: vec![0x02; 7],
            nonce_null_len: None,
            nonce_fixed_bits: 16,
            nonce_generator: 1,
            mac: vec![0xBB; 8],
            mac_null_len: None,
            mac_len: 8,
        });
        let proto: v1_proto::MessageParameter = (&original).into();
        let back = MessageParameter::try_from(&proto).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn message_parameter_salsa_chacha_round_trip() {
        let original = MessageParameter::SalaChacha(Salsa20ChaCha20Poly1305MessageParams {
            nonce: vec![0x03; 12],
            nonce_bits: 96,
            nonce_null_len: None,
            tag: vec![0xCC; 16],
            tag_null_len: None,
        });
        let proto: v1_proto::MessageParameter = (&original).into();
        let back = MessageParameter::try_from(&proto).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn message_parameter_none_returns_error() {
        // W1-C8-03: absent oneof must report the documented sibling-wide RV.
        let proto = v1_proto::MessageParameter { params: None, parameter_encoding_version: 0 };
        assert_eq!(
            MessageParameter::try_from(&proto),
            Err(crate::convert::ABSENT_MESSAGE_ONEOF_RV),
        );
        assert_eq!(
            MessageParameter::try_from(&proto),
            Err(pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD),
        );
    }

    #[test]
    fn message_parameter_shape_comes_only_from_supported_registry_names() {
        assert_eq!(
            MessageParameterShape::from_registry_name(Some("gcm")),
            MessageParameterShape::Gcm
        );
        assert_eq!(
            MessageParameterShape::from_registry_name(Some("ccm")),
            MessageParameterShape::Ccm
        );
        assert_eq!(
            MessageParameterShape::from_registry_name(Some("salsa20_chacha20_poly1305")),
            MessageParameterShape::SalsaChacha,
        );
        assert_eq!(
            MessageParameterShape::from_registry_name(Some("vendor_unknown")),
            MessageParameterShape::Unmodeled,
        );
        assert_eq!(
            MessageParameterShape::from_registry_name(None),
            MessageParameterShape::Unmodeled,
        );
    }

    #[test]
    fn message_parameter_shape_proto_round_trip_preserves_presence_value() {
        for shape in [
            MessageParameterShape::Unmodeled,
            MessageParameterShape::Gcm,
            MessageParameterShape::Ccm,
            MessageParameterShape::SalsaChacha,
        ] {
            let wire = shape.to_proto_i32();
            assert_eq!(MessageParameterShape::try_from_proto_i32(wire), Ok(shape));
        }
        assert!(MessageParameterShape::try_from_proto_i32(99).is_err());
    }

    #[test]
    fn wire_decoder_rejects_dual_pointer_representations() {
        let proto = v1_proto::MessageParameter {
            params: Some(v1_proto::message_parameter::Params::GcmMessageParams(
                v1_proto::GcmMessageParams {
                    iv: vec![0x11; 12],
                    iv_fixed_bits: 0,
                    iv_generator: 0,
                    tag: vec![0x22; 16],
                    tag_bits: 128,
                    iv_null_len: Some(12),
                    tag_null_len: None,
                },
            )),
            parameter_encoding_version: 0,
        };

        assert_eq!(
            MessageParameter::try_from(&proto),
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID)
        );
    }

    #[test]
    fn wire_decoder_rejects_inconsistent_authoritative_lengths() {
        let wrong_gcm_tag = v1_proto::MessageParameter {
            params: Some(v1_proto::message_parameter::Params::GcmMessageParams(
                v1_proto::GcmMessageParams {
                    iv: vec![0x11; 12],
                    iv_fixed_bits: 96,
                    iv_generator: 0,
                    tag: vec![0x22; 12],
                    tag_bits: 128,
                    iv_null_len: None,
                    tag_null_len: None,
                },
            )),
            parameter_encoding_version: 0,
        };
        let wrong_ccm_nonce = v1_proto::MessageParameter {
            params: Some(v1_proto::message_parameter::Params::CcmMessageParams(
                v1_proto::CcmMessageParams {
                    data_len: 0,
                    nonce: vec![0x11; 6],
                    nonce_fixed_bits: 0,
                    nonce_generator: 0,
                    mac: vec![0x22; 8],
                    mac_len: 8,
                    nonce_null_len: None,
                    mac_null_len: None,
                },
            )),
            parameter_encoding_version: 0,
        };

        assert!(MessageParameter::try_from(&wrong_gcm_tag).is_err());
        assert!(MessageParameter::try_from(&wrong_ccm_nonce).is_err());
    }

    #[test]
    fn salsa_nonce_scalar_accepts_bits_and_bytes_forms() {
        // T20: was bits-only; bytes form (12) is what shipping backends
        // accept, so both validate (value round-trips verbatim).
        let valid = v1_proto::MessageParameter {
            params: Some(v1_proto::message_parameter::Params::SalsaChachaMessageParams(
                v1_proto::Salsa20ChaCha20Poly1305MessageParams {
                    nonce: vec![0x33; 12],
                    tag: vec![0x44; 16],
                    nonce_bits: 96,
                    nonce_null_len: None,
                    tag_null_len: None,
                },
            )),
            parameter_encoding_version: 0,
        };
        let mut bytes_form = valid.clone();
        let Some(v1_proto::message_parameter::Params::SalsaChachaMessageParams(params)) =
            bytes_form.params.as_mut()
        else {
            unreachable!()
        };
        params.nonce_bits = 12;

        let mut invalid = valid.clone();
        let Some(v1_proto::message_parameter::Params::SalsaChachaMessageParams(params)) =
            invalid.params.as_mut()
        else {
            unreachable!()
        };
        params.nonce_bits = 13;

        assert!(MessageParameter::try_from(&valid).is_ok());
        assert!(MessageParameter::try_from(&bytes_form).is_ok());
        assert!(MessageParameter::try_from(&invalid).is_err());
    }

    #[test]
    fn native_ulong_bounds_are_validated_separately_from_shape_bounds() {
        let parameter = MessageParameter::CcmMessage(CcmMessageParams {
            data_len: u32::MAX as u64 + 1,
            nonce: vec![0x11; 12],
            nonce_null_len: None,
            nonce_fixed_bits: 96,
            nonce_generator: 0,
            mac: vec![0x22; 16],
            mac_null_len: None,
            mac_len: 16,
        });

        assert!(parameter.validate_structured().is_ok());
        assert_eq!(
            parameter.validate_for_native_ulong(u32::MAX as u64),
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
        );
    }

    #[test]
    fn structured_scalar_bounds_cover_gcm_ccm_and_salsa() {
        let gcm = |tag_bits: u64| {
            MessageParameter::GcmMessage(GcmMessageParams {
                iv: vec![0x11; 12],
                iv_null_len: None,
                iv_fixed_bits: 96,
                iv_generator: 0,
                tag: vec![0x22; tag_bits.div_ceil(8) as usize],
                tag_null_len: None,
                tag_bits,
            })
        };
        assert!(gcm(128).validate_structured().is_ok());
        assert_eq!(
            gcm(129).validate_structured(),
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
        );

        let ccm = |nonce_len: usize, mac_len: u64| {
            MessageParameter::CcmMessage(CcmMessageParams {
                data_len: 0,
                nonce: vec![0x11; nonce_len],
                nonce_null_len: None,
                nonce_fixed_bits: 0,
                nonce_generator: 0,
                mac: vec![0x22; mac_len as usize],
                mac_null_len: None,
                mac_len,
            })
        };
        for nonce_len in 7..=13 {
            assert!(ccm(nonce_len, 16).validate_structured().is_ok());
        }
        for nonce_len in [6, 14] {
            assert_eq!(
                ccm(nonce_len, 16).validate_structured(),
                Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
            );
        }
        for mac_len in [0, 1, 2, 3, 5, 7, 9, 11, 13, 15, 17] {
            assert_eq!(
                ccm(12, mac_len).validate_structured(),
                Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
            );
        }

        let salsa = |nonce_bits: u64| {
            MessageParameter::SalaChacha(Salsa20ChaCha20Poly1305MessageParams {
                nonce: vec![0x33; nonce_bits.div_ceil(8) as usize],
                nonce_bits,
                nonce_null_len: None,
                tag: vec![0x44; 16],
                tag_null_len: None,
            })
        };
        for nonce_bits in [64, 96, 192] {
            assert!(salsa(nonce_bits).validate_structured().is_ok());
        }
        for nonce_bits in [0, 8, 12, 128] {
            assert_eq!(
                salsa(nonce_bits).validate_structured(),
                Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
            );
        }
    }

    #[test]
    fn materialized_extent_over_transport_ceiling_is_rejected_without_allocation() {
        let over = MAX_MESSAGE_PARAMETER_BYTES + 1;
        assert_eq!(
            pointer_extent_len(over as usize, None),
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
        );
    }

    #[test]
    fn null_extent_skips_allocation_ceiling_but_obeys_shape_and_native_width() {
        let over = MAX_MESSAGE_PARAMETER_BYTES + 1;
        assert_eq!(pointer_extent_len(0, Some(over)), Ok(over));
        assert_eq!(
            pointer_extent_len(1, Some(over)),
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
        );

        let gcm = |iv_null_len, iv_fixed_bits| {
            MessageParameter::GcmMessage(GcmMessageParams {
                iv: Vec::new(),
                iv_null_len: Some(iv_null_len),
                iv_fixed_bits,
                iv_generator: 0,
                tag: Vec::new(),
                tag_null_len: Some(16),
                tag_bits: 128,
            })
        };
        assert!(gcm(over, 96).validate_structured().is_ok());
        assert!(gcm(over, 96).validate_for_native_ulong(u32::MAX as u64).is_ok());

        let exceeds_u32 = u32::MAX as u64 + 1;
        assert!(gcm(exceeds_u32, 96).validate_structured().is_ok());
        assert_eq!(
            gcm(exceeds_u32, 96).validate_for_native_ulong(u32::MAX as u64),
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
        );

        assert!(gcm(u64::MAX, u64::MAX).validate_structured().is_ok());
        assert!(gcm(u64::MAX, u64::MAX).validate_for_native_ulong(u64::MAX).is_ok());
    }

    #[test]
    fn server_wire_validator_rejects_raw_before_owned_conversion() {
        for data in [vec![], vec![0xA5]] {
            let wire = v1_proto::MessageParameter {
                params: Some(v1_proto::message_parameter::Params::Raw(data)),
                parameter_encoding_version: 0,
            };
            assert_eq!(
                validate_structured_wire_parameter(&wire),
                Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
            );
        }
    }

    // R2 golden tests: v1 message-opaque wire encoding (S2 §3 + F1 ruling)
    // and the discovery capability. Additive only: legacy encodings must
    // decode bit-identically before and after the v1 fields land.

    #[test]
    fn legacy_version_zero_message_decodes_bit_identically() {
        use prost::Message as _;
        // Golden wire bytes produced by the pre-v1 schema (oneof only, no
        // version field): field 1 (raw, LEN) pins the legacy encoding.
        for (payload, golden) in
            [(&[][..], &[0x0A, 0x00][..]), (b"AB".as_slice(), &[0x0A, 0x02, 0x41, 0x42][..])]
        {
            let decoded = v1_proto::MessageParameter::decode(golden).unwrap();
            assert_eq!(decoded.parameter_encoding_version, 0);
            assert_eq!(
                decoded.params,
                Some(v1_proto::message_parameter::Params::Raw(payload.to_vec())),
            );
            assert_eq!(
                MessageParameter::try_from(&decoded).unwrap(),
                MessageParameter::Raw(SecretBytes::copy_from_slice(payload)),
            );
            // v1 encode of a legacy value emits no new bytes.
            let encoded = v1_proto::MessageParameter::from(&MessageParameter::Raw(
                SecretBytes::copy_from_slice(payload),
            ));
            assert_eq!(encoded.parameter_encoding_version, 0);
            assert_eq!(encoded.encode_to_vec(), golden);
        }
        // Default structured arm: field 2 (LEN, empty) is the whole message.
        let golden = [0x12, 0x00];
        let decoded = v1_proto::MessageParameter::decode(golden.as_slice()).unwrap();
        assert_eq!(decoded.parameter_encoding_version, 0);
        assert_eq!(
            decoded.params,
            Some(v1_proto::message_parameter::Params::GcmMessageParams(
                v1_proto::GcmMessageParams::default(),
            )),
        );
    }

    #[test]
    fn v1_wire_tags_pin_opaque_and_version_placement() {
        use prost::Message as _;
        // Pins MessageParameter tags 5 (opaque, LEN) and 6 (version, varint)
        // plus OpaqueMessageParams tags 1 (data, LEN) and 2 (declared_len,
        // varint). Hand-computed, not round-tripped.
        let golden = [0x2A, 0x06, 0x0A, 0x02, 0x41, 0x42, 0x10, 0x02, 0x30, 0x01];
        let wire = v1_proto::MessageParameter {
            params: Some(v1_proto::message_parameter::Params::OpaqueMessageParams(
                v1_proto::OpaqueMessageParams { data: b"AB".to_vec(), declared_len: 2 },
            )),
            parameter_encoding_version: 1,
        };
        assert_eq!(wire.encode_to_vec(), golden);
        let decoded = v1_proto::MessageParameter::decode(golden.as_slice()).unwrap();
        assert_eq!(decoded, wire);
    }

    #[test]
    fn v1_presence_matrix_round_trips() {
        use prost::Message as _;
        let opaque = || {
            Some(v1_proto::message_parameter::Params::OpaqueMessageParams(
                v1_proto::OpaqueMessageParams { data: vec![0xA5; 16], declared_len: 16 },
            ))
        };
        let structured = || {
            Some(v1_proto::message_parameter::Params::GcmMessageParams(
                v1_proto::GcmMessageParams::default(),
            ))
        };
        for (name, params) in [("absent", None), ("opaque", opaque()), ("structured", structured())]
        {
            for version in [0u32, 1u32] {
                let wire = v1_proto::MessageParameter {
                    params: params.clone(),
                    parameter_encoding_version: version,
                };
                let round_tripped =
                    v1_proto::MessageParameter::decode(wire.encode_to_vec().as_slice()).unwrap();
                assert_eq!(round_tripped, wire, "{name} version {version} must round-trip");
            }
        }
        // Decode passes opaque bytes through at either version; enforcement
        // (including the version-0 contradiction) is validation behavior.
        for version in [0u32, 1u32] {
            let wire = v1_proto::MessageParameter {
                params: opaque(),
                parameter_encoding_version: version,
            };
            assert_eq!(
                MessageParameter::try_from(&wire).unwrap(),
                MessageParameter::Raw(SecretBytes::copy_from_slice(&[0xA5; 16])),
                "version {version} opaque must pass decode",
            );
        }
    }

    #[test]
    fn unknown_version_passes_through_decode() {
        use prost::Message as _;
        // Rejection of too-new versions is enforcement behavior (R4); decode
        // itself must not fail.
        for version in [2u32, 7, 99, u32::MAX] {
            let wire = v1_proto::MessageParameter {
                params: Some(v1_proto::message_parameter::Params::OpaqueMessageParams(
                    v1_proto::OpaqueMessageParams { data: b"AB".to_vec(), declared_len: 2 },
                )),
                parameter_encoding_version: version,
            };
            let decoded =
                v1_proto::MessageParameter::decode(wire.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded.parameter_encoding_version, version);
            assert_eq!(
                MessageParameter::try_from(&decoded).unwrap(),
                MessageParameter::Raw(SecretBytes::copy_from_slice(b"AB")),
                "version {version} must pass borrowed decode",
            );
            assert_eq!(
                MessageParameter::try_from_owned(decoded).unwrap(),
                MessageParameter::Raw(SecretBytes::copy_from_slice(b"AB")),
                "version {version} must pass owned decode",
            );
        }
        // Legacy arms are equally version-blind at decode.
        let legacy = v1_proto::MessageParameter {
            params: Some(v1_proto::message_parameter::Params::Raw(b"AB".to_vec())),
            parameter_encoding_version: 99,
        };
        assert!(MessageParameter::try_from(&legacy).is_ok());
        let missing = v1_proto::MessageParameter { params: None, parameter_encoding_version: 99 };
        assert_eq!(
            MessageParameter::try_from(&missing),
            Err(crate::convert::ABSENT_MESSAGE_ONEOF_RV),
        );
    }

    #[test]
    fn discovery_capability_fields_round_trip() {
        use prost::Message as _;
        // Absent from older daemons: legacy decode yields None/None.
        let legacy = v1_proto::GetBackendInterfacesResponse::decode([].as_slice()).unwrap();
        assert_eq!(legacy.mechanism_parameter_transport_version, None);
        assert_eq!(legacy.backend_mechanism_abi, None);
        // Pins discovery tags 9 (version, varint) and 10 (abi, varint enum).
        let golden = [0x48, 0x01, 0x50, 0x01];
        let wire = v1_proto::GetBackendInterfacesResponse {
            mechanism_parameter_transport_version: Some(1),
            backend_mechanism_abi: Some(v1_proto::MechanismParamAbi::Lp64NativeLe as i32),
            ..Default::default()
        };
        assert_eq!(wire.encode_to_vec(), golden);
        let decoded = v1_proto::GetBackendInterfacesResponse::decode(golden.as_slice()).unwrap();
        assert_eq!(decoded.mechanism_parameter_transport_version, Some(1));
        assert_eq!(
            decoded.backend_mechanism_abi,
            Some(v1_proto::MechanismParamAbi::Lp64NativeLe as i32),
        );
    }

    // R3: v1 opaque acceptance matrix (S2 §3 version/legacy rules + S2 §6
    // RV table). Decode-side only: `TryFrom`/`try_from_owned` still never
    // fail on opaque (R2 passthrough intact); these pins cover
    // `validate_structured_wire_parameter` enforcement.

    fn opaque_wire(data: Vec<u8>, declared_len: u64, version: u32) -> v1_proto::MessageParameter {
        v1_proto::MessageParameter {
            params: Some(v1_proto::message_parameter::Params::OpaqueMessageParams(
                v1_proto::OpaqueMessageParams { data, declared_len },
            )),
            parameter_encoding_version: version,
        }
    }

    fn valid_gcm_wire(version: u32) -> v1_proto::MessageParameter {
        v1_proto::MessageParameter {
            params: Some(v1_proto::message_parameter::Params::GcmMessageParams(
                v1_proto::GcmMessageParams {
                    iv: vec![0x11; 12],
                    iv_fixed_bits: 0,
                    iv_generator: 0,
                    tag: vec![0x22; 16],
                    tag_bits: 128,
                    iv_null_len: None,
                    tag_null_len: None,
                },
            )),
            parameter_encoding_version: version,
        }
    }

    #[test]
    fn r3_v1_opaque_exact_bytes_accept_and_decode_to_raw() {
        for data in [b"AB".to_vec(), vec![], vec![0xA5; 16]] {
            let wire = opaque_wire(data.clone(), data.len() as u64, 1);
            assert_eq!(validate_structured_wire_parameter(&wire), Ok(()));
            assert_eq!(
                MessageParameter::try_from(&wire).unwrap(),
                MessageParameter::Raw(SecretBytes::copy_from_slice(&data)),
            );
            assert_eq!(
                MessageParameter::try_from_owned(wire).unwrap(),
                MessageParameter::Raw(SecretBytes::copy_from_slice(&data)),
            );
        }
    }

    #[test]
    fn r3_legacy_raw_rejected_at_every_version() {
        // Fail-closed preserved: legacy `raw` is never a v1 representation.
        for version in [0u32, 1, 2, 99, u32::MAX] {
            for data in [vec![], vec![0xA5]] {
                let wire = v1_proto::MessageParameter {
                    params: Some(v1_proto::message_parameter::Params::Raw(data)),
                    parameter_encoding_version: version,
                };
                assert_eq!(
                    validate_structured_wire_parameter(&wire),
                    Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
                    "legacy raw must reject at version {version}",
                );
            }
        }
    }

    #[test]
    fn r3_newer_version_is_function_not_supported_pre_entry() {
        use pkcs11_proxy_ng_types::CkRv;
        for version in [2u32, 99, u32::MAX] {
            assert_eq!(
                validate_structured_wire_parameter(&opaque_wire(b"AB".to_vec(), 2, version)),
                Err(CkRv::FUNCTION_NOT_SUPPORTED),
                "opaque at version {version}",
            );
            assert_eq!(
                validate_structured_wire_parameter(&valid_gcm_wire(version)),
                Err(CkRv::FUNCTION_NOT_SUPPORTED),
                "structured at version {version}",
            );
        }
        // The absent oneof is unparsable at any version (existing behavior
        // preserved; T4 parse-failure deferral sees it before any version
        // gate).
        let missing = v1_proto::MessageParameter { params: None, parameter_encoding_version: 99 };
        assert_eq!(
            validate_structured_wire_parameter(&missing),
            Err(crate::convert::ABSENT_MESSAGE_ONEOF_RV),
        );
    }

    #[test]
    fn r3_version_zero_opaque_is_contradictory_metadata() {
        assert_eq!(
            validate_structured_wire_parameter(&opaque_wire(b"AB".to_vec(), 2, 0)),
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
        );
    }

    #[test]
    fn r3_opaque_length_mismatch_is_param_invalid() {
        use pkcs11_proxy_ng_types::CkRv;
        for (data, declared_len) in
            [(b"AB".to_vec(), 3u64), (b"AB".to_vec(), 1u64), (vec![], 1u64), (vec![0xA5; 16], 0u64)]
        {
            assert_eq!(
                validate_structured_wire_parameter(&opaque_wire(data, declared_len, 1)),
                Err(CkRv::MECHANISM_PARAM_INVALID),
            );
        }
    }

    #[test]
    fn r3_opaque_64kib_cap_boundary() {
        use pkcs11_proxy_ng_types::CkRv;
        // Exactly 64 KiB is representable; one byte over is a cap violation.
        let at_cap = vec![0xA5; 64 * 1024];
        assert_eq!(
            validate_structured_wire_parameter(&opaque_wire(at_cap.clone(), 64 * 1024, 1)),
            Ok(())
        );
        let over_cap = vec![0xA5; 64 * 1024 + 1];
        assert_eq!(
            validate_structured_wire_parameter(&opaque_wire(over_cap, 64 * 1024 + 1, 1)),
            Err(CkRv::MECHANISM_PARAM_INVALID),
        );
        // Declared length over the cap rejects even when the bytes are short
        // (cap checked on the declared extent, not the materialized buffer).
        assert_eq!(
            validate_structured_wire_parameter(&opaque_wire(vec![0xA5; 16], 64 * 1024 + 1, 1)),
            Err(CkRv::MECHANISM_PARAM_INVALID),
        );
        assert_eq!(
            validate_structured_wire_parameter(&opaque_wire(vec![], u64::MAX, 1)),
            Err(CkRv::MECHANISM_PARAM_INVALID),
        );
    }

    #[test]
    fn r3_unmodeled_shape_matches_raw_only() {
        let raw = MessageParameter::Raw(vec![0x01; 16].into());
        let gcm = MessageParameter::GcmMessage(GcmMessageParams {
            iv: vec![0x01; 12],
            iv_null_len: None,
            iv_fixed_bits: 0,
            iv_generator: 0,
            tag: vec![0xAA; 16],
            tag_null_len: None,
            tag_bits: 128,
        });
        let ccm = MessageParameter::CcmMessage(CcmMessageParams {
            data_len: 0,
            nonce: vec![0x02; 7],
            nonce_null_len: None,
            nonce_fixed_bits: 0,
            nonce_generator: 0,
            mac: vec![0xBB; 8],
            mac_null_len: None,
            mac_len: 8,
        });
        let salsa = MessageParameter::SalaChacha(Salsa20ChaCha20Poly1305MessageParams {
            nonce: vec![0x03; 12],
            nonce_bits: 96,
            nonce_null_len: None,
            tag: vec![0xCC; 16],
            tag_null_len: None,
        });
        // New arm: opaque bytes are the Unmodeled shape's v1 representation.
        assert!(MessageParameterShape::Unmodeled.matches(&raw));
        // Every other arm unchanged.
        assert!(!MessageParameterShape::Unmodeled.matches(&gcm));
        assert!(!MessageParameterShape::Unmodeled.matches(&ccm));
        assert!(!MessageParameterShape::Unmodeled.matches(&salsa));
        assert!(!MessageParameterShape::Gcm.matches(&raw));
        assert!(!MessageParameterShape::Ccm.matches(&raw));
        assert!(!MessageParameterShape::SalsaChacha.matches(&raw));
        assert!(MessageParameterShape::Gcm.matches(&gcm));
        assert!(MessageParameterShape::Ccm.matches(&ccm));
        assert!(MessageParameterShape::SalsaChacha.matches(&salsa));
        assert!(!MessageParameterShape::Gcm.matches(&ccm));
    }

    #[test]
    fn r3_raw_validates_structured_and_narrows_native_ulong() {
        use pkcs11_proxy_ng_types::CkRv;
        let raw = MessageParameter::Raw(vec![0x01; 16].into());
        // Opaque bytes carry no layout/scalars: shape validation accepts.
        assert_eq!(raw.validate_structured(), Ok(()));
        // Only the byte length crosses into native width (S2 §6: a u64 that
        // cannot narrow to backend CK_ULONG is FUNCTION_FAILED).
        assert_eq!(raw.validate_for_native_ulong(u64::MAX), Ok(()));
        assert_eq!(raw.validate_for_native_ulong(16), Ok(()));
        assert_eq!(raw.validate_for_native_ulong(15), Err(CkRv::FUNCTION_FAILED));
        assert_eq!(raw.validate_for_native_ulong(0), Err(CkRv::FUNCTION_FAILED));
        let empty = MessageParameter::Raw(vec![].into());
        assert_eq!(empty.validate_structured(), Ok(()));
        assert_eq!(empty.validate_for_native_ulong(0), Ok(()));
    }

    #[test]
    fn r3_raw_same_layout_is_byte_equality() {
        let raw = MessageParameter::Raw(vec![0x01; 16].into());
        let identical = MessageParameter::Raw(vec![0x01; 16].into());
        let mutated = MessageParameter::Raw({
            let mut bytes = vec![0x01; 16];
            bytes[0] ^= 0xFF;
            bytes.into()
        });
        let short = MessageParameter::Raw(vec![0x01; 15].into());
        let gcm = MessageParameter::GcmMessage(GcmMessageParams {
            iv: vec![0x01; 12],
            iv_null_len: None,
            iv_fixed_bits: 0,
            iv_generator: 0,
            tag: vec![0xAA; 16],
            tag_null_len: None,
            tag_bits: 128,
        });
        assert!(raw.same_layout_and_scalars(&identical));
        assert!(!raw.same_layout_and_scalars(&mutated));
        assert!(!raw.same_layout_and_scalars(&short));
        assert!(!raw.same_layout_and_scalars(&gcm));
        assert!(!gcm.same_layout_and_scalars(&raw));
    }

    #[test]
    fn mechanism_param_abi_enum_values_are_pinned() {
        use v1_proto::MechanismParamAbi as Abi;
        assert_eq!(Abi::Unspecified as i32, 0);
        assert_eq!(Abi::Lp64NativeLe as i32, 1);
        assert_eq!(Abi::Ilp32NativeLe as i32, 2);
        assert_eq!(Abi::Llp64Packed1Le as i32, 3);
        assert_eq!(Abi::Ilp32Packed1Le as i32, 4);
        for (raw, expected) in [
            (0, Abi::Unspecified),
            (1, Abi::Lp64NativeLe),
            (2, Abi::Ilp32NativeLe),
            (3, Abi::Llp64Packed1Le),
            (4, Abi::Ilp32Packed1Le),
        ] {
            assert_eq!(Abi::try_from(raw), Ok(expected));
        }
        // Value 4 was the unknown-value sentinel until the packed-32
        // (win32) ABI claimed it (cid-fix-3); 5 is the new sentinel.
        assert!(Abi::try_from(5).is_err());
    }

    /// R5/F1 encode matrix: legacy capability emits bit-identical legacy
    /// bytes; capability ≥ 1 emits v1-opaque for `Raw` (exact bytes,
    /// declared length, version 1); newer capabilities still emit the v1
    /// form this encoder knows; over-64 KiB fails locally with
    /// `MECHANISM_PARAM_INVALID`.
    #[test]
    fn r5_to_wire_with_transport_version_matrix() {
        use pkcs11_proxy_ng_types::CkRv;
        let raw16 = MessageParameter::Raw(vec![0xA5; 16].into());

        // Legacy: bit-identical to the legacy `From` (legacy Raw, version 0).
        let wire = raw16.to_wire_with_transport_version(0).expect("legacy encodes");
        assert_eq!(wire, v1_proto::MessageParameter::from(&raw16));
        assert_eq!(wire.parameter_encoding_version, 0);
        assert!(matches!(wire.params, Some(v1_proto::message_parameter::Params::Raw(_))));

        // v1: opaque bytes, exact length, version 1 — never legacy Raw.
        for version in [1, 2, u32::MAX] {
            let wire = raw16.to_wire_with_transport_version(version).expect("v1 encodes Raw");
            assert_eq!(wire.parameter_encoding_version, 1, "capability {version}");
            match &wire.params {
                Some(v1_proto::message_parameter::Params::OpaqueMessageParams(opaque)) => {
                    assert_eq!(opaque.data, vec![0xA5; 16]);
                    assert_eq!(opaque.declared_len, 16);
                }
                other => panic!("capability {version} must emit opaque, got {other:?}"),
            }
        }

        // Empty opaque edge: empty bytes, zero declared length, version 1.
        let empty = MessageParameter::Raw(Vec::new().into());
        let wire = empty.to_wire_with_transport_version(1).expect("empty opaque encodes");
        assert_eq!(wire.parameter_encoding_version, 1);
        match &wire.params {
            Some(v1_proto::message_parameter::Params::OpaqueMessageParams(opaque)) => {
                assert!(opaque.data.is_empty());
                assert_eq!(opaque.declared_len, 0);
            }
            other => panic!("empty Raw must emit empty opaque, got {other:?}"),
        }

        // 64 KiB cap boundary on the encode side (local reject, no wire).
        let at_cap = MessageParameter::Raw(vec![0xA5; 64 * 1024].into());
        let wire = at_cap.to_wire_with_transport_version(1).expect("64 KiB encodes");
        assert_eq!(wire.parameter_encoding_version, 1);
        let over_cap = MessageParameter::Raw(vec![0xA5; 64 * 1024 + 1].into());
        assert_eq!(over_cap.to_wire_with_transport_version(1), Err(CkRv::MECHANISM_PARAM_INVALID),);
        // The cap is v1-only: legacy still emits (the daemon rejects).
        assert!(over_cap.to_wire_with_transport_version(0).is_ok());
    }

    /// R5/F1: structured arms always use the legacy encoding at every
    /// capability — their contract is unchanged across versions.
    #[test]
    fn r5_structured_encode_ignores_transport_version() {
        let gcm = MessageParameter::GcmMessage(GcmMessageParams {
            iv: vec![0x01; 12],
            iv_null_len: None,
            iv_fixed_bits: 32,
            iv_generator: 2,
            tag: vec![0xAA; 16],
            tag_null_len: None,
            tag_bits: 128,
        });
        let legacy = v1_proto::MessageParameter::from(&gcm);
        for version in [0, 1, 2] {
            assert_eq!(
                gcm.to_wire_with_transport_version(version),
                Ok(legacy.clone()),
                "structured encoding is capability-independent (v{version})",
            );
        }
    }
}

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
            Self::Raw(_) => Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
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
            Self::Raw(_) => Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
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
        v1_proto::MessageParameter { params: Some(params) }
    }
}

/// Validate an attacker-controlled structured wire parameter by borrowing its
/// protobuf buffers. This must run before cloning them into the owned native
/// representation at the daemon trust boundary.
fn validate_structured_wire_params(
    params: &v1_proto::message_parameter::Params,
) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
    match params {
        v1_proto::message_parameter::Params::Raw(_) => {
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID)
        }
        v1_proto::message_parameter::Params::GcmMessageParams(p) => validate_gcm_fields(
            p.iv.len(),
            p.iv_null_len,
            p.iv_fixed_bits,
            p.iv_generator,
            p.tag.len(),
            p.tag_null_len,
            p.tag_bits,
        ),
        v1_proto::message_parameter::Params::CcmMessageParams(p) => validate_ccm_fields(
            p.nonce.len(),
            p.nonce_null_len,
            p.nonce_fixed_bits,
            p.nonce_generator,
            p.mac.len(),
            p.mac_null_len,
            p.mac_len,
        ),
        v1_proto::message_parameter::Params::SalsaChachaMessageParams(p) => validate_salsa_fields(
            p.nonce.len(),
            p.nonce_bits,
            p.nonce_null_len,
            p.tag.len(),
            p.tag_null_len,
        ),
    }
}

pub fn validate_structured_wire_parameter(
    parameter: &v1_proto::MessageParameter,
) -> Result<(), pkcs11_proxy_ng_types::CkRv> {
    let params = parameter.params.as_ref().ok_or(super::ABSENT_MESSAGE_ONEOF_RV)?;
    validate_structured_wire_params(params)
}

impl TryFrom<&v1_proto::MessageParameter> for MessageParameter {
    type Error = pkcs11_proxy_ng_types::CkRv;

    fn try_from(p: &v1_proto::MessageParameter) -> Result<Self, Self::Error> {
        match &p.params {
            Some(v1_proto::message_parameter::Params::Raw(data)) => {
                Ok(MessageParameter::Raw(SecretBytes::copy_from_slice(data)))
            }
            Some(params @ v1_proto::message_parameter::Params::GcmMessageParams(p)) => {
                validate_structured_wire_params(params)?;
                let parameter = MessageParameter::GcmMessage(p.into());
                Ok(parameter)
            }
            Some(params @ v1_proto::message_parameter::Params::CcmMessageParams(p)) => {
                validate_structured_wire_params(params)?;
                let parameter = MessageParameter::CcmMessage(p.into());
                Ok(parameter)
            }
            Some(params @ v1_proto::message_parameter::Params::SalsaChachaMessageParams(p)) => {
                validate_structured_wire_params(params)?;
                let parameter = MessageParameter::SalaChacha(p.into());
                Ok(parameter)
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
            && !matches!(params, v1_proto::message_parameter::Params::Raw(_))
        {
            validate_structured_wire_params(params)?;
        }
        match taken.as_mut() {
            Some(v1_proto::message_parameter::Params::Raw(data)) => {
                Ok(MessageParameter::Raw(SecretBytes::new(std::mem::take(data))))
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
        let proto = v1_proto::MessageParameter { params: None };
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
            };
            assert_eq!(
                validate_structured_wire_parameter(&wire),
                Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_PARAM_INVALID),
            );
        }
    }
}

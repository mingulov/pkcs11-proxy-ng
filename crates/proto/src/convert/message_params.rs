//! Bidirectional conversions for PKCS#11 3.0/3.2 message-based crypto parameter types
//! and the CK_ASYNC_DATA result structure.
//!
//! The Rust-side structs live here for now; they can migrate to `pkcs11-types` once
//! the message-based API layer stabilises.

use crate::pkcs11_proxy_ng::v1 as v1_proto;
use pkcs11_proxy_ng_types::CkObjectHandle;

// ---------------------------------------------------------------------------
// Rust-side struct definitions
// ---------------------------------------------------------------------------

/// CK_GCM_MESSAGE_PARAMS — per-message GCM parameters for message-based APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcmMessageParams {
    pub iv: Vec<u8>,
    pub iv_fixed_bits: u64,
    pub iv_generator: u64,
    pub tag: Vec<u8>,
    pub tag_bits: u64,
}

/// CK_CCM_MESSAGE_PARAMS — per-message CCM parameters for message-based APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcmMessageParams {
    pub data_len: u64,
    pub nonce: Vec<u8>,
    pub nonce_fixed_bits: u64,
    pub nonce_generator: u64,
    pub mac: Vec<u8>,
    pub mac_len: u64,
}

/// CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS — per-message Salsa20/ChaCha20-Poly1305 parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Salsa20ChaCha20Poly1305MessageParams {
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
}

/// CK_ASYNC_DATA — result structure for C_AsyncComplete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncData {
    pub version: u64,
    pub value: Vec<u8>,
    pub value_len: u64,
    pub object_handle: CkObjectHandle,
    pub additional_object_handle: CkObjectHandle,
}

/// Rust-side enum for the `MessageParameter` oneof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageParameter {
    Raw(Vec<u8>),
    GcmMessage(GcmMessageParams),
    CcmMessage(CcmMessageParams),
    SalaChacha(Salsa20ChaCha20Poly1305MessageParams),
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
        }
    }
}

impl From<&v1_proto::GcmMessageParams> for GcmMessageParams {
    fn from(p: &v1_proto::GcmMessageParams) -> Self {
        GcmMessageParams {
            iv: p.iv.clone(),
            iv_fixed_bits: p.iv_fixed_bits,
            iv_generator: p.iv_generator,
            tag: p.tag.clone(),
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
        }
    }
}

impl From<&v1_proto::CcmMessageParams> for CcmMessageParams {
    fn from(p: &v1_proto::CcmMessageParams) -> Self {
        CcmMessageParams {
            data_len: p.data_len,
            nonce: p.nonce.clone(),
            nonce_fixed_bits: p.nonce_fixed_bits,
            nonce_generator: p.nonce_generator,
            mac: p.mac.clone(),
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
        }
    }
}

impl From<&v1_proto::Salsa20ChaCha20Poly1305MessageParams>
    for Salsa20ChaCha20Poly1305MessageParams
{
    fn from(p: &v1_proto::Salsa20ChaCha20Poly1305MessageParams) -> Self {
        Salsa20ChaCha20Poly1305MessageParams { nonce: p.nonce.clone(), tag: p.tag.clone() }
    }
}

// ---------------------------------------------------------------------------
// AsyncData conversions
// ---------------------------------------------------------------------------

impl From<&AsyncData> for v1_proto::AsyncData {
    fn from(a: &AsyncData) -> Self {
        v1_proto::AsyncData {
            version: a.version,
            value: a.value.clone(),
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
            value: a.value.clone(),
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
            MessageParameter::Raw(data) => v1_proto::message_parameter::Params::Raw(data.clone()),
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

impl TryFrom<&v1_proto::MessageParameter> for MessageParameter {
    type Error = pkcs11_proxy_ng_types::CkRv;

    fn try_from(p: &v1_proto::MessageParameter) -> Result<Self, Self::Error> {
        match &p.params {
            Some(v1_proto::message_parameter::Params::Raw(data)) => {
                Ok(MessageParameter::Raw(data.clone()))
            }
            Some(v1_proto::message_parameter::Params::GcmMessageParams(p)) => {
                Ok(MessageParameter::GcmMessage(p.into()))
            }
            Some(v1_proto::message_parameter::Params::CcmMessageParams(p)) => {
                Ok(MessageParameter::CcmMessage(p.into()))
            }
            Some(v1_proto::message_parameter::Params::SalsaChachaMessageParams(p)) => {
                Ok(MessageParameter::SalaChacha(p.into()))
            }
            None => Err(pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD),
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
            iv_fixed_bits: 32,
            iv_generator: 2,
            tag: vec![0xAA; 16],
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
            iv_fixed_bits: 0,
            iv_generator: 0,
            tag: vec![],
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
            nonce_fixed_bits: 16,
            nonce_generator: 1,
            mac: vec![0xBB; 8],
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
            nonce_fixed_bits: 0,
            nonce_generator: 0,
            mac: vec![],
            mac_len: 0,
        };
        let proto: v1_proto::CcmMessageParams = (&original).into();
        let back = CcmMessageParams::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn salsa20_chacha20_poly1305_message_params_round_trip() {
        let original =
            Salsa20ChaCha20Poly1305MessageParams { nonce: vec![0x01; 12], tag: vec![0xCC; 16] };
        let proto: v1_proto::Salsa20ChaCha20Poly1305MessageParams = (&original).into();
        let back = Salsa20ChaCha20Poly1305MessageParams::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn salsa20_chacha20_poly1305_empty_fields() {
        let original = Salsa20ChaCha20Poly1305MessageParams { nonce: vec![], tag: vec![] };
        let proto: v1_proto::Salsa20ChaCha20Poly1305MessageParams = (&original).into();
        let back = Salsa20ChaCha20Poly1305MessageParams::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn async_data_round_trip() {
        let original = AsyncData {
            version: 1,
            value: vec![0xDE, 0xAD, 0xBE, 0xEF],
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
            value: vec![],
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
            value: vec![0xFF; 32],
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
        let original = MessageParameter::Raw(vec![0x01, 0x02, 0x03]);
        let proto: v1_proto::MessageParameter = (&original).into();
        let back = MessageParameter::try_from(&proto).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn message_parameter_raw_empty() {
        let original = MessageParameter::Raw(vec![]);
        let proto: v1_proto::MessageParameter = (&original).into();
        let back = MessageParameter::try_from(&proto).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn message_parameter_gcm_round_trip() {
        let original = MessageParameter::GcmMessage(GcmMessageParams {
            iv: vec![0x01; 12],
            iv_fixed_bits: 32,
            iv_generator: 2,
            tag: vec![0xAA; 16],
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
            nonce_fixed_bits: 16,
            nonce_generator: 1,
            mac: vec![0xBB; 8],
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
            tag: vec![0xCC; 16],
        });
        let proto: v1_proto::MessageParameter = (&original).into();
        let back = MessageParameter::try_from(&proto).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn message_parameter_none_returns_error() {
        let proto = v1_proto::MessageParameter { params: None };
        let result = MessageParameter::try_from(&proto);
        assert!(result.is_err());
    }
}

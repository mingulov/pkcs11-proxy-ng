use crate::{CkAttributeType, CkObjectHandle, CkRv};

/// Exact caller-side shape for a simple output byte buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkOutputBufferSpec {
    pub buffer_present: bool,
    pub buffer_len: u64,
}

/// Exact result for a simple output byte buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkOutputBufferResult {
    pub ck_rv: CkRv,
    pub returned_len: u64,
    pub value: Option<Vec<u8>>,
}

impl CkOutputBufferResult {
    /// Build an exact result from convenience bytes (for mock backends).
    ///
    /// Simulates PKCS#11 two-call semantics:
    /// - If the caller's buffer is absent (`!spec.buffer_present`), returns size only.
    /// - If the caller's buffer is large enough, returns the data.
    /// - Otherwise, returns `CKR_BUFFER_TOO_SMALL` with the required length.
    pub fn from_convenience_bytes(bytes: &[u8], spec: &CkOutputBufferSpec) -> Self {
        if !spec.buffer_present {
            Self { ck_rv: CkRv::OK, returned_len: bytes.len() as u64, value: None }
        } else if spec.buffer_len >= bytes.len() as u64 {
            Self { ck_rv: CkRv::OK, returned_len: bytes.len() as u64, value: Some(bytes.to_vec()) }
        } else {
            Self { ck_rv: CkRv::BUFFER_TOO_SMALL, returned_len: bytes.len() as u64, value: None }
        }
    }
}

/// Discriminator for the 18 byte-output PKCS#11 functions that share
/// the `ByteOutputExact` RPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ByteOutputFunction {
    Sign = 1,
    SignFinal = 2,
    SignRecover = 3,
    VerifyRecover = 4,
    Digest = 5,
    DigestFinal = 6,
    Encrypt = 7,
    EncryptUpdate = 8,
    EncryptFinal = 9,
    Decrypt = 10,
    DecryptUpdate = 11,
    DecryptFinal = 12,
    DigestEncryptUpdate = 13,
    DecryptDigestUpdate = 14,
    SignEncryptUpdate = 15,
    DecryptVerifyUpdate = 16,
    WrapKey = 17,
    GetOperationState = 18,
}

impl TryFrom<u32> for ByteOutputFunction {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Sign),
            2 => Ok(Self::SignFinal),
            3 => Ok(Self::SignRecover),
            4 => Ok(Self::VerifyRecover),
            5 => Ok(Self::Digest),
            6 => Ok(Self::DigestFinal),
            7 => Ok(Self::Encrypt),
            8 => Ok(Self::EncryptUpdate),
            9 => Ok(Self::EncryptFinal),
            10 => Ok(Self::Decrypt),
            11 => Ok(Self::DecryptUpdate),
            12 => Ok(Self::DecryptFinal),
            13 => Ok(Self::DigestEncryptUpdate),
            14 => Ok(Self::DecryptDigestUpdate),
            15 => Ok(Self::SignEncryptUpdate),
            16 => Ok(Self::DecryptVerifyUpdate),
            17 => Ok(Self::WrapKey),
            18 => Ok(Self::GetOperationState),
            _ => Err(()),
        }
    }
}

/// Exact caller-side shape for a PKCS#11 parameter buffer used as input/output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkParameterRoundtripSpec {
    pub buffer_present: bool,
    pub buffer_len: u64,
    pub value: Option<Vec<u8>>,
}

/// Exact result for a PKCS#11 parameter buffer used as input/output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkParameterRoundtripResult {
    pub ck_rv: CkRv,
    pub returned_len: u64,
    pub value: Option<Vec<u8>>,
}

/// Exact result for output-producing APIs that also return a handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkOutputAndHandleResult {
    pub ck_rv: CkRv,
    pub returned_len: u64,
    pub value: Option<Vec<u8>>,
    pub object_handle: CkObjectHandle,
}

/// Discriminator for the 7 parameter-output PKCS#11 functions that share
/// the `ParameterOutputExact` RPC.
///
/// These functions return BOTH main output bytes AND parameter write-back bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ParameterOutputFunction {
    EncryptMessage = 1,
    DecryptMessage = 2,
    SignMessage = 3,
    EncryptMessageNext = 4,
    DecryptMessageNext = 5,
    SignMessageNext = 6,
    WrapKeyAuthenticated = 7,
}

impl TryFrom<u32> for ParameterOutputFunction {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::EncryptMessage),
            2 => Ok(Self::DecryptMessage),
            3 => Ok(Self::SignMessage),
            4 => Ok(Self::EncryptMessageNext),
            5 => Ok(Self::DecryptMessageNext),
            6 => Ok(Self::SignMessageNext),
            7 => Ok(Self::WrapKeyAuthenticated),
            _ => Err(()),
        }
    }
}

/// Exact raw caller query for C_GetAttributeValue-style buffer semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkAttributeQuery {
    pub attr_type: CkAttributeType,
    pub buffer_present: bool,
    pub buffer_len: u64,
    pub nested: Option<Vec<CkAttributeQuery>>,
}

/// Exact raw result for a single queried attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkAttributeQueryResult {
    pub attr_type: CkAttributeType,
    pub returned_len: u64,
    pub value: Option<Vec<u8>>,
    pub ck_rv: Option<CkRv>,
    pub nested: Option<Vec<CkAttributeQueryResult>>,
}

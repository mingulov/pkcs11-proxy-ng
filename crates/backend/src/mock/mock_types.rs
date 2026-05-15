use pkcs11_proxy_ng_types::*;

/// Per-attribute slot in the mock attribute store.
///
/// Used with `MockBackend::set_attribute` to configure `get_attribute_value` behavior.
#[derive(Clone)]
pub enum MockAttributeSlot {
    /// The attribute has this value.
    Value(CkAttributeValue),
    /// The attribute is sensitive: `C_GetAttributeValue` must set `ulValueLen =
    /// CK_UNAVAILABLE_INFORMATION` and return `CKR_ATTRIBUTE_SENSITIVE`.
    Sensitive,
    /// The attribute type is invalid for this object: set `ulValueLen =
    /// CK_UNAVAILABLE_INFORMATION` and return `CKR_ATTRIBUTE_TYPE_INVALID`.
    InvalidType,
    /// The attribute is a nested `CK_ATTRIBUTE[]` template (CKF_ARRAY_ATTRIBUTE).
    ///
    /// Each entry is `(attr_type, sub_slot)` where `sub_slot` must be a `Value`.
    NestedTemplate(Vec<(CkAttributeType, MockAttributeSlot)>),
}

/// Per-session active multi-part operation type (PKCS#11 §5.14).
///
/// Only one multi-part operation may be active per session at a time.
/// Attempting to start a second operation returns `CKR_OPERATION_ACTIVE`.
/// Calling update/final without init returns `CKR_OPERATION_NOT_INITIALIZED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiPartOp {
    Sign,
    Verify,
    Digest,
    Encrypt,
    Decrypt,
}

pub mod attribute;
pub mod error;
pub mod info;
pub mod input;
pub mod interface;
pub mod mechanism;
pub mod mechanism_official;
pub mod mechanism_param_manifest;
pub mod mechanism_registry;
pub mod object;
pub mod output;
pub mod secret;
pub mod session;
pub mod shape_descriptors;
pub mod slot;
pub mod width;

#[cfg(kani)]
mod kani_proofs;

pub use attribute::{
    CkAttribute, CkAttributeType, CkAttributeValue, VALUE_BEARING_SECRET, is_value_bearing_secret,
};
pub use error::{CkResult, CkRv};
pub use info::CkInfo;
pub use input::CkInBuf;
pub use interface::{InterfaceCapabilities, InterfaceInfo};
pub use mechanism::{
    AesCbcEncryptDataParams, AesCmacKeyDerivationParams, AesCtrParams, AriaCbcEncryptDataParams,
    CamelliaCbcEncryptDataParams, CamelliaCtrParams, CcmParams, CcmWrapParams, ChaCha20Params,
    CkGeneratorFunction, CkKdf, CkMechanism, CkMechanismFlags, CkMechanismInfo, CkMechanismParams,
    CkMechanismType, CkMgf, CkOaepSource, CkPbkdf2Prf, CkPbkdf2SaltSource, CmsSigParams,
    DesCbcEncryptDataParams, DilithiumParams, Ecdh1DeriveParams, Ecdh2DeriveParams,
    EcdhAesKeyWrapParams, EciesParams, EcmqvDeriveParams, EddsaParams, ExtractParams,
    FixedPointerBytes, FlatParams, GcmParams, GcmWrapParams, Gostr3410DeriveParams,
    Gostr3410KeyWrapParams, HdKeyDeriveParams, HkdfParams, Ike1ExtendedDeriveParams,
    Ike1PrfDeriveParams, Ike2PrfPlusDeriveParams, IkePrfDeriveParams, IvParams, KeaDeriveParams,
    KeyDerivationStringData, KeyWrapSetOaepParams, KipParams, KmacParams, KyberParams,
    MECHANISM_PARAMETER_TRANSPORT_VERSION, MacGeneralParams, MuGenParams, ObjectHandleParam,
    OtpParam, OtpParams, OutputPointerBytes, PbeParams, Pkcs5Pbkd2Params, PointerArray,
    PointerBytes, PrfDataParam, RawMechanismParams, Rc2CbcParams, Rc2MacGeneralParams,
    Rc5CbcParams, Rc5MacGeneralParams, Rc5Params, RsaAesKeyWrapParams, RsaPkcsOaepParams,
    RsaPkcsPssParams, Salsa20ChaCha20Poly1305Params, Salsa20Params, SeedCbcEncryptDataParams,
    SignAdditionalContext, SkipjackPrivateWrapParams, SkipjackRelayxParams, Sp800108DerivedKey,
    Sp800108FeedbackKdfParams, Sp800108KdfParams, Ssl3KeyMatParams, Ssl3MasterKeyDeriveParams,
    SslRandomData, Tls12ExtendedMasterKeyDeriveParams, Tls12MasterKeyDeriveParams, TlsKdfParams,
    TlsMacParams, TlsPrfParams, ValidatedMechanismParams, VendorObjectExtractParams,
    VendorObjectInsertParams, WtlsKeyMatParams, WtlsMasterKeyDeriveParams, WtlsPrfParams,
    WtlsRandomData, X2RatchetInitializeParams, X2RatchetRespondParams, X3dhInitiateParams,
    X3dhRespondParams, X942Dh1DeriveParams, X942Dh2DeriveParams, X942MqvDeriveParams, XeddsaParams,
};
pub use mechanism_official::{PKCS11_3_2_OFFICIAL_MECHANISMS, pkcs11_3_2_official_mechanisms};
pub use mechanism_registry::{DiscoveryMode, EMBEDDED_DEFAULT_REVISION, MechanismRegistry};
pub use object::{CkKeyType, CkObjectClass, CkObjectHandle};
pub use output::{
    ByteOutputFunction, CkAttributeQuery, CkAttributeQueryResult, CkOutputAndHandleResult,
    CkOutputBufferResult, CkOutputBufferSpec, CkParameterRoundtripResult, CkParameterRoundtripSpec,
    OutputContractViolation, ParameterOutputFunction, attribute_outputs_defined,
};
pub use secret::SecretBytes;
pub use session::{
    CkFlags, CkSessionFlags, CkSessionHandle, CkSessionInfo, CkSessionState, CkUserType,
};
pub use slot::{CkSlotFlags, CkSlotId, CkSlotInfo, CkTokenFlags, CkTokenInfo};
pub use width::*;

/// Copy `src` into the fixed-width PKCS#11 field `dest`, space-padding
/// the remainder (W1-L11-12). Overlong values truncate by bytes — a
/// multibyte char may split at the edge, matching the historical
/// backend `space_pad` / shim `pad_string` behavior both crates
/// shared byte-for-byte. This is the single padding implementation;
/// both crates call it directly.
pub fn space_pad_into(dest: &mut [u8], src: &str) {
    let bytes = src.as_bytes();
    let copy_len = bytes.len().min(dest.len());
    dest[..copy_len].copy_from_slice(&bytes[..copy_len]);
    for b in dest[copy_len..].iter_mut() {
        *b = b' ';
    }
}

/// PKCS#11 token-label field width in bytes (`CK_TOKEN_INFO.label` is
/// `CK_UTF8CHAR label[32]`, blank-padded; likewise the `C_InitToken`
/// `pLabel` input). Single home for the width (W1-L12-08) — label
/// buffers, label reads, and label pad widths all use this.
pub const PKCS11_TOKEN_LABEL_LEN: usize = 32;

/// Exact token-label transport capability (Q03 phase 2): the `v1`
/// `exact_token_label_version` discovery value this build speaks.
/// Monotonic maximum capability (S2 §3 style): a newer daemon keeps
/// accepting older requests, and a client gates exact-label emission
/// on `advertised >= 1`, never on equality.
pub const EXACT_TOKEN_LABEL_VERSION: u32 = 1;

/// Exact `C_InitToken` label input (Q03 phase 2): label presence plus
/// the raw 32 caller bytes, carried alongside the legacy string field
/// and gated by the negotiated `exact_token_label_version` capability.
///
/// The proxy NEVER normalizes these: a NULL pointer stays NULL (never
/// an empty-label reinit) and invalid-encoding bytes stay byte-exact
/// (never U+FFFD-substituted). The provider accepts or refuses; its RV
/// propagates unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactTokenLabel {
    /// NULL `pLabel`: forward a null label pointer; the provider decides.
    Null,
    /// Raw 32 caller bytes (valid or not): forward unmodified through a
    /// non-null pointer; the provider decides.
    Bytes([u8; PKCS11_TOKEN_LABEL_LEN]),
}

/// `C_InitToken` label with its legacy and exact forms (Q03 phase 2).
///
/// Pairing invariant: `text` is always populated as the phase-1 string
/// path populates it (NULL → `""`, valid → trailing-space-trimmed,
/// invalid → legacy lossy compat), and `exact` carries the raw input
/// when the caller can express it. Consumers prefer `exact` when the
/// peer negotiated the capability and fall back to `text` otherwise;
/// the fallback is lossless exactly for valid UTF-8 inputs (blank-pad
/// of the trimmed text reproduces the caller bytes), so NULL and
/// invalid-encoding inputs fail closed with `CKR_ARGUMENTS_BAD`
/// against an unnegotiated peer instead of being rewritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitTokenLabel<'a> {
    /// Compat string; authoritative when `exact` is `None` (legacy
    /// string-only requests from old shims and non-shim clients).
    pub text: &'a str,
    /// Exact form; `None` = legacy string-only request.
    pub exact: Option<ExactTokenLabel>,
}

impl<'a> InitTokenLabel<'a> {
    /// Legacy string-only label (old-shim shape): no exact form.
    pub fn text_only(text: &'a str) -> Self {
        Self { text, exact: None }
    }
}

#[cfg(test)]
mod space_pad_tests {
    use super::space_pad_into;

    #[test]
    fn shared_padding_vectors() {
        // Mirrors the backend/shim pins: byte-identical by construction.
        let mut buf = [0u8; 8];
        space_pad_into(&mut buf, "hi");
        assert_eq!(&buf, b"hi      ");
        let mut buf = [0u8; 4];
        space_pad_into(&mut buf, "ABCD");
        assert_eq!(&buf, b"ABCD");
        let mut buf = [0u8; 6];
        space_pad_into(&mut buf, "");
        assert_eq!(&buf, b"      ");
        let mut buf = [0u8; 4];
        space_pad_into(&mut buf, "ABCDEFGH");
        assert_eq!(&buf, b"ABCD");
        let mut buf = [0u8; 4];
        space_pad_into(&mut buf, "héllo");
        assert_eq!(buf, [0x68, 0xC3, 0xA9, 0x6C]);
        let mut label = [0u8; super::PKCS11_TOKEN_LABEL_LEN];
        space_pad_into(&mut label, "My Test Token");
        assert_eq!(&label[..13], b"My Test Token");
        assert!(label[13..].iter().all(|&b| b == b' '));
    }

    // W1-C9-15: width::* and the secret-classification helpers resolve at
    // the crate root.
    #[test]
    fn w1_c9_15_root_reexports() {
        use super::{
            ByteOrder, CANONICAL_UNAVAILABLE, CkAttributeType, VALUE_BEARING_SECRET,
            is_value_bearing_secret, reencode_ulong,
        };
        assert!(VALUE_BEARING_SECRET.contains(&CkAttributeType::VALUE));
        assert!(is_value_bearing_secret(CkAttributeType::PRIVATE_EXPONENT));
        assert!(!is_value_bearing_secret(CkAttributeType::LABEL));
        assert_eq!(CANONICAL_UNAVAILABLE, u64::MAX);
        let back = reencode_ulong(&[1, 0, 0, 0], 4, 8, ByteOrder::Little).unwrap();
        assert_eq!(back, vec![1, 0, 0, 0, 0, 0, 0, 0]);
    }
}

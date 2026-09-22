pub mod attribute;
pub mod error;
pub mod info;
pub mod input;
pub mod interface;
pub mod mechanism;
pub mod mechanism_official;
pub mod mechanism_registry;
pub mod object;
pub mod output;
pub mod secret;
pub mod session;
pub mod slot;
pub mod width;

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
    EcdhAesKeyWrapParams, EciesParams, EcmqvDeriveParams, EddsaParams, ExtractParams, GcmParams,
    GcmWrapParams, Gostr3410DeriveParams, Gostr3410KeyWrapParams, HdKeyDeriveParams, HkdfParams,
    Ike1ExtendedDeriveParams, Ike1PrfDeriveParams, Ike2PrfPlusDeriveParams, IkePrfDeriveParams,
    IvParams, KeaDeriveParams, KeyDerivationStringData, KeyWrapSetOaepParams, KipParams,
    KmacParams, KyberParams, MacGeneralParams, MuGenParams, ObjectHandleParam, OtpParam, OtpParams,
    PbeParams, Pkcs5Pbkd2Params, PrfDataParam, RawMechanismParams, Rc2CbcParams,
    Rc2MacGeneralParams, Rc5CbcParams, Rc5MacGeneralParams, Rc5Params, RsaAesKeyWrapParams,
    RsaPkcsOaepParams, RsaPkcsPssParams, Salsa20ChaCha20Poly1305Params, Salsa20Params,
    SeedCbcEncryptDataParams, SignAdditionalContext, SkipjackPrivateWrapParams,
    SkipjackRelayxParams, Sp800108DerivedKey, Sp800108FeedbackKdfParams, Sp800108KdfParams,
    Ssl3KeyMatParams, Ssl3MasterKeyDeriveParams, SslRandomData, Tls12ExtendedMasterKeyDeriveParams,
    Tls12MasterKeyDeriveParams, TlsKdfParams, TlsMacParams, TlsPrfParams,
    VendorObjectExtractParams, VendorObjectInsertParams, WtlsKeyMatParams,
    WtlsMasterKeyDeriveParams, WtlsPrfParams, WtlsRandomData, X2RatchetInitializeParams,
    X2RatchetRespondParams, X3dhInitiateParams, X3dhRespondParams, X942Dh1DeriveParams,
    X942Dh2DeriveParams, X942MqvDeriveParams, XeddsaParams,
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

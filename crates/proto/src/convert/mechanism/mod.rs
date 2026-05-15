mod advanced_params;
mod derivation_params;
mod tls_params;

use crate::pkcs11_proxy_ng::v1 as v1_proto;
use pkcs11_proxy_ng_types::{
    AesCbcEncryptDataParams, AesCtrParams, AriaCbcEncryptDataParams, CamelliaCbcEncryptDataParams,
    CamelliaCtrParams, CcmParams, CcmWrapParams, ChaCha20Params, CkMechanism, CkMechanismFlags,
    CkMechanismInfo, CkMechanismParams, CkMechanismType, CkRv, DesCbcEncryptDataParams,
    Ecdh1DeriveParams, GcmParams, GcmWrapParams, IvParams, KeyDerivationStringData,
    MacGeneralParams, ObjectHandleParam, RawMechanismParams, Rc2CbcParams, Rc2MacGeneralParams,
    Rc5CbcParams, Rc5MacGeneralParams, Rc5Params, RsaPkcsOaepParams, RsaPkcsPssParams,
    Salsa20ChaCha20Poly1305Params, Salsa20Params, SeedCbcEncryptDataParams, SignAdditionalContext,
    TlsMacParams, XeddsaParams,
};

impl From<&CkMechanism> for v1_proto::Mechanism {
    fn from(m: &CkMechanism) -> Self {
        let params = match &m.params {
            None => None,
            Some(CkMechanismParams::RsaPkcsPss(p)) => {
                Some(v1_proto::mechanism::Params::RsaPkcsPssParams(v1_proto::RsaPkcsPssParams {
                    hash_alg: p.hash_alg.0,
                    mgf: p.mgf,
                    salt_len: p.salt_len,
                }))
            }
            Some(CkMechanismParams::RsaPkcsOaep(p)) => {
                Some(v1_proto::mechanism::Params::RsaPkcsOaepParams(v1_proto::RsaPkcsOaepParams {
                    hash_alg: p.hash_alg.0,
                    mgf: p.mgf,
                    source: p.source,
                    source_data: p.source_data.clone(),
                }))
            }
            Some(CkMechanismParams::Gcm(p)) => {
                Some(v1_proto::mechanism::Params::GcmParams(v1_proto::GcmParams {
                    iv: p.iv.clone(),
                    iv_bits: p.iv_bits,
                    aad: p.aad.clone(),
                    tag_bits: p.tag_bits,
                    iv_buffer_len: p.iv_buffer_len,
                }))
            }
            Some(CkMechanismParams::Ecdh1Derive(p)) => {
                Some(v1_proto::mechanism::Params::Ecdh1DeriveParams(v1_proto::Ecdh1DeriveParams {
                    kdf: p.kdf,
                    shared_data: p.shared_data.clone(),
                    public_data: p.public_data.clone(),
                }))
            }
            Some(CkMechanismParams::Iv(iv)) => {
                Some(v1_proto::mechanism::Params::IvParams(v1_proto::IvParams {
                    iv: iv.iv.clone(),
                }))
            }
            // Trivial scalar-only
            Some(CkMechanismParams::Rc5(p)) => {
                Some(v1_proto::mechanism::Params::Rc5Params(v1_proto::Rc5Params {
                    word_size: p.word_size,
                    rounds: p.rounds,
                }))
            }
            Some(CkMechanismParams::Rc5MacGeneral(p)) => Some(
                v1_proto::mechanism::Params::Rc5MacGeneralParams(v1_proto::Rc5MacGeneralParams {
                    word_size: p.word_size,
                    rounds: p.rounds,
                    mac_length: p.mac_length,
                }),
            ),
            Some(CkMechanismParams::Rc2MacGeneral(p)) => Some(
                v1_proto::mechanism::Params::Rc2MacGeneralParams(v1_proto::Rc2MacGeneralParams {
                    effective_bits: p.effective_bits,
                    mac_length: p.mac_length,
                }),
            ),
            Some(CkMechanismParams::Xeddsa(p)) => {
                Some(v1_proto::mechanism::Params::XeddsaParams(v1_proto::XeddsaParams {
                    hash: p.hash,
                }))
            }
            Some(CkMechanismParams::TlsMac(p)) => {
                Some(v1_proto::mechanism::Params::TlsMacParams(v1_proto::TlsMacParams {
                    prf_hash_mechanism: p.prf_hash_mechanism,
                    mac_length: p.mac_length,
                    server_or_client: p.server_or_client,
                }))
            }
            // Symmetric with fixed IV
            Some(CkMechanismParams::AesCtr(p)) => {
                Some(v1_proto::mechanism::Params::AesCtrParams(v1_proto::AesCtrParams {
                    counter_bits: p.counter_bits,
                    cb: p.cb.clone(),
                }))
            }
            Some(CkMechanismParams::CamelliaCtr(p)) => {
                Some(v1_proto::mechanism::Params::CamelliaCtrParams(v1_proto::CamelliaCtrParams {
                    counter_bits: p.counter_bits,
                    cb: p.cb.clone(),
                }))
            }
            Some(CkMechanismParams::Rc2Cbc(p)) => {
                Some(v1_proto::mechanism::Params::Rc2CbcParams(v1_proto::Rc2CbcParams {
                    effective_bits: p.effective_bits,
                    iv: p.iv.clone(),
                }))
            }
            Some(CkMechanismParams::Rc5Cbc(p)) => {
                Some(v1_proto::mechanism::Params::Rc5CbcParams(v1_proto::Rc5CbcParams {
                    word_size: p.word_size,
                    rounds: p.rounds,
                    iv: p.iv.clone(),
                }))
            }
            // CBC encrypt data
            Some(CkMechanismParams::AesCbcEncryptData(p)) => {
                Some(v1_proto::mechanism::Params::AesCbcEncryptDataParams(
                    v1_proto::AesCbcEncryptDataParams { iv: p.iv.clone(), data: p.data.clone() },
                ))
            }
            Some(CkMechanismParams::DesCbcEncryptData(p)) => {
                Some(v1_proto::mechanism::Params::DesCbcEncryptDataParams(
                    v1_proto::DesCbcEncryptDataParams { iv: p.iv.clone(), data: p.data.clone() },
                ))
            }
            Some(CkMechanismParams::AriaCbcEncryptData(p)) => {
                Some(v1_proto::mechanism::Params::AriaCbcEncryptDataParams(
                    v1_proto::AriaCbcEncryptDataParams { iv: p.iv.clone(), data: p.data.clone() },
                ))
            }
            Some(CkMechanismParams::CamelliaCbcEncryptData(p)) => {
                Some(v1_proto::mechanism::Params::CamelliaCbcEncryptDataParams(
                    v1_proto::CamelliaCbcEncryptDataParams {
                        iv: p.iv.clone(),
                        data: p.data.clone(),
                    },
                ))
            }
            Some(CkMechanismParams::SeedCbcEncryptData(p)) => {
                Some(v1_proto::mechanism::Params::SeedCbcEncryptDataParams(
                    v1_proto::SeedCbcEncryptDataParams { iv: p.iv.clone(), data: p.data.clone() },
                ))
            }
            // AEAD
            Some(CkMechanismParams::Ccm(p)) => {
                Some(v1_proto::mechanism::Params::CcmParams(v1_proto::CcmParams {
                    data_len: p.data_len,
                    nonce: p.nonce.clone(),
                    aad: p.aad.clone(),
                    mac_len: p.mac_len,
                }))
            }
            Some(CkMechanismParams::ChaCha20(p)) => {
                Some(v1_proto::mechanism::Params::Chacha20Params(v1_proto::ChaCha20Params {
                    block_counter: p.block_counter.clone(),
                    block_counter_bits: p.block_counter_bits,
                    nonce: p.nonce.clone(),
                    nonce_bits: p.nonce_bits,
                }))
            }
            Some(CkMechanismParams::Salsa20(p)) => {
                Some(v1_proto::mechanism::Params::Salsa20Params(v1_proto::Salsa20Params {
                    block_counter: p.block_counter.clone(),
                    nonce: p.nonce.clone(),
                    nonce_bits: p.nonce_bits,
                }))
            }
            Some(CkMechanismParams::Salsa20ChaCha20Poly1305(p)) => {
                Some(v1_proto::mechanism::Params::Salsa20Chacha20Poly1305Params(
                    v1_proto::Salsa20ChaCha20Poly1305Params {
                        nonce: p.nonce.clone(),
                        aad: p.aad.clone(),
                    },
                ))
            }
            Some(CkMechanismParams::GcmWrap(p)) => {
                Some(v1_proto::mechanism::Params::GcmWrapParams(v1_proto::GcmWrapParams {
                    iv: p.iv.clone(),
                    iv_fixed_bits: p.iv_fixed_bits,
                    iv_generator: p.iv_generator,
                    aad: p.aad.clone(),
                    tag_bits: p.tag_bits,
                }))
            }
            Some(CkMechanismParams::CcmWrap(p)) => {
                Some(v1_proto::mechanism::Params::CcmWrapParams(v1_proto::CcmWrapParams {
                    data_len: p.data_len,
                    nonce: p.nonce.clone(),
                    nonce_fixed_bits: p.nonce_fixed_bits,
                    nonce_generator: p.nonce_generator,
                    aad: p.aad.clone(),
                    mac_len: p.mac_len,
                }))
            }
            // Key derivation
            Some(CkMechanismParams::Ecdh2Derive(p)) => {
                Some(v1_proto::mechanism::Params::Ecdh2DeriveParams(p.into()))
            }
            Some(CkMechanismParams::EcmqvDerive(p)) => {
                Some(v1_proto::mechanism::Params::EcmqvDeriveParams(p.into()))
            }
            Some(CkMechanismParams::X942Dh1Derive(p)) => {
                Some(v1_proto::mechanism::Params::X942Dh1DeriveParams(p.into()))
            }
            Some(CkMechanismParams::X942Dh2Derive(p)) => {
                Some(v1_proto::mechanism::Params::X942Dh2DeriveParams(p.into()))
            }
            Some(CkMechanismParams::X942MqvDerive(p)) => {
                Some(v1_proto::mechanism::Params::X942MqvDeriveParams(p.into()))
            }
            Some(CkMechanismParams::Hkdf(p)) => {
                Some(v1_proto::mechanism::Params::HkdfParams(p.into()))
            }
            Some(CkMechanismParams::Eddsa(p)) => {
                Some(v1_proto::mechanism::Params::EddsaParams(p.into()))
            }
            Some(CkMechanismParams::Gostr3410Derive(p)) => {
                Some(v1_proto::mechanism::Params::Gostr3410DeriveParams(p.into()))
            }
            Some(CkMechanismParams::KeaDerive(p)) => {
                Some(v1_proto::mechanism::Params::KeaDeriveParams(p.into()))
            }
            // Key wrapping
            Some(CkMechanismParams::EcdhAesKeyWrap(p)) => {
                Some(v1_proto::mechanism::Params::EcdhAesKeyWrapParams(p.into()))
            }
            Some(CkMechanismParams::RsaAesKeyWrap(p)) => {
                Some(v1_proto::mechanism::Params::RsaAesKeyWrapParams(p.into()))
            }
            Some(CkMechanismParams::Gostr3410KeyWrap(p)) => {
                Some(v1_proto::mechanism::Params::Gostr3410KeyWrapParams(p.into()))
            }
            Some(CkMechanismParams::KeyWrapSetOaep(p)) => {
                Some(v1_proto::mechanism::Params::KeyWrapSetOaepParams(p.into()))
            }
            // Password-based encryption
            Some(CkMechanismParams::Pbe(p)) => {
                Some(v1_proto::mechanism::Params::PbeParams(p.into()))
            }
            Some(CkMechanismParams::Pkcs5Pbkd2(p)) => {
                Some(v1_proto::mechanism::Params::Pkcs5Pbkd2Params(p.into()))
            }
            // TLS/SSL
            Some(CkMechanismParams::TlsPrf(p)) => {
                Some(v1_proto::mechanism::Params::TlsPrfParams(p.into()))
            }
            Some(CkMechanismParams::TlsKdf(p)) => {
                Some(v1_proto::mechanism::Params::TlsKdfParams(p.into()))
            }
            Some(CkMechanismParams::Ssl3MasterKeyDerive(p)) => {
                Some(v1_proto::mechanism::Params::Ssl3MasterKeyDeriveParams(p.into()))
            }
            Some(CkMechanismParams::Tls12MasterKeyDerive(p)) => {
                Some(v1_proto::mechanism::Params::Tls12MasterKeyDeriveParams(p.into()))
            }
            Some(CkMechanismParams::Tls12ExtendedMasterKeyDerive(p)) => {
                Some(v1_proto::mechanism::Params::Tls12ExtendedMasterKeyDeriveParams(p.into()))
            }
            Some(CkMechanismParams::Ssl3KeyMat(p)) => {
                Some(v1_proto::mechanism::Params::Ssl3KeyMatParams(p.into()))
            }
            Some(CkMechanismParams::WtlsMasterKeyDerive(p)) => {
                Some(v1_proto::mechanism::Params::WtlsMasterKeyDeriveParams(p.into()))
            }
            Some(CkMechanismParams::WtlsPrf(p)) => {
                Some(v1_proto::mechanism::Params::WtlsPrfParams(p.into()))
            }
            Some(CkMechanismParams::WtlsKeyMat(p)) => {
                Some(v1_proto::mechanism::Params::WtlsKeyMatParams(p.into()))
            }
            // IKE/IPSec
            Some(CkMechanismParams::IkePrfDerive(p)) => {
                Some(v1_proto::mechanism::Params::IkePrfDeriveParams(p.into()))
            }
            Some(CkMechanismParams::Ike1PrfDerive(p)) => {
                Some(v1_proto::mechanism::Params::Ike1PrfDeriveParams(p.into()))
            }
            Some(CkMechanismParams::Ike1ExtendedDerive(p)) => {
                Some(v1_proto::mechanism::Params::Ike1ExtendedDeriveParams(p.into()))
            }
            Some(CkMechanismParams::Ike2PrfPlusDerive(p)) => {
                Some(v1_proto::mechanism::Params::Ike2PrfPlusDeriveParams(p.into()))
            }
            // SP800-108 KDF
            Some(CkMechanismParams::Sp800108Kdf(p)) => {
                Some(v1_proto::mechanism::Params::Sp800108KdfParams(p.into()))
            }
            Some(CkMechanismParams::Sp800108FeedbackKdf(p)) => {
                Some(v1_proto::mechanism::Params::Sp800108FeedbackKdfParams(p.into()))
            }
            // Signal protocol
            Some(CkMechanismParams::X3dhInitiate(p)) => {
                Some(v1_proto::mechanism::Params::X3dhInitiateParams(p.into()))
            }
            Some(CkMechanismParams::X3dhRespond(p)) => {
                Some(v1_proto::mechanism::Params::X3dhRespondParams(p.into()))
            }
            Some(CkMechanismParams::X2RatchetInitialize(p)) => {
                Some(v1_proto::mechanism::Params::X2RatchetInitializeParams(p.into()))
            }
            Some(CkMechanismParams::X2RatchetRespond(p)) => {
                Some(v1_proto::mechanism::Params::X2RatchetRespondParams(p.into()))
            }
            // Miscellaneous
            Some(CkMechanismParams::Otp(p)) => {
                Some(v1_proto::mechanism::Params::OtpParams(p.into()))
            }
            Some(CkMechanismParams::Kip(p)) => {
                let proto_kip: v1_proto::KipParams = p.into();
                Some(v1_proto::mechanism::Params::KipParams(Box::new(proto_kip)))
            }
            Some(CkMechanismParams::CmsSig(p)) => {
                let proto_cms: v1_proto::CmsSigParams = p.into();
                Some(v1_proto::mechanism::Params::CmsSigParams(Box::new(proto_cms)))
            }
            Some(CkMechanismParams::SkipjackPrivateWrap(p)) => {
                Some(v1_proto::mechanism::Params::SkipjackPrivateWrapParams(p.into()))
            }
            Some(CkMechanismParams::SkipjackRelayx(p)) => {
                Some(v1_proto::mechanism::Params::SkipjackRelayxParams(p.into()))
            }
            // Generic / vendor parameter shapes
            Some(CkMechanismParams::MacGeneral(p)) => {
                Some(v1_proto::mechanism::Params::MacGeneralParams(v1_proto::MacGeneralParams {
                    mac_length: p.mac_length,
                }))
            }
            Some(CkMechanismParams::ObjectHandle(p)) => {
                Some(v1_proto::mechanism::Params::ObjectHandleParam(v1_proto::ObjectHandleParam {
                    handle: p.handle,
                }))
            }
            Some(CkMechanismParams::SignAdditionalContext(p)) => {
                Some(v1_proto::mechanism::Params::SignAdditionalContext(
                    v1_proto::SignAdditionalContext {
                        hedge_variant: p.hedge_variant,
                        context: p.context.clone(),
                    },
                ))
            }
            Some(CkMechanismParams::KeyDerivationString(p)) => {
                Some(v1_proto::mechanism::Params::KeyDerivationStringData(
                    v1_proto::KeyDerivationStringData { data: p.data.clone() },
                ))
            }
            Some(CkMechanismParams::Raw(p)) => {
                Some(v1_proto::mechanism::Params::RawMechanismParams(
                    v1_proto::RawMechanismParams { data: p.data.clone() },
                ))
            }
            // Vendor-specific parameter shapes
            Some(CkMechanismParams::Ecies(p)) => {
                let proto_ecies: v1_proto::EciesParams = p.into();
                Some(v1_proto::mechanism::Params::EciesParams(Box::new(proto_ecies)))
            }
            Some(CkMechanismParams::AesCmacKeyDerivation(p)) => {
                Some(v1_proto::mechanism::Params::AesCmacKeyDerivationParams(p.into()))
            }
            Some(CkMechanismParams::Dilithium(p)) => {
                Some(v1_proto::mechanism::Params::DilithiumParams(p.into()))
            }
            Some(CkMechanismParams::Kyber(p)) => {
                Some(v1_proto::mechanism::Params::KyberParams(p.into()))
            }
            Some(CkMechanismParams::HdKeyDerive(p)) => {
                Some(v1_proto::mechanism::Params::HdKeyDeriveParams(p.into()))
            }
            Some(CkMechanismParams::VendorObjectExtract(p)) => {
                Some(v1_proto::mechanism::Params::VendorObjectExtractParams(p.into()))
            }
            Some(CkMechanismParams::VendorObjectInsert(p)) => {
                Some(v1_proto::mechanism::Params::VendorObjectInsertParams(p.into()))
            }
        };
        v1_proto::Mechanism { mechanism_type: m.mechanism_type.0, params }
    }
}

impl TryFrom<&v1_proto::Mechanism> for CkMechanism {
    type Error = CkRv;

    fn try_from(m: &v1_proto::Mechanism) -> Result<Self, Self::Error> {
        let params = match &m.params {
            None => None,
            Some(v1_proto::mechanism::Params::RsaPkcsPssParams(p)) => {
                Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
                    hash_alg: CkMechanismType(p.hash_alg),
                    mgf: p.mgf,
                    salt_len: p.salt_len,
                }))
            }
            Some(v1_proto::mechanism::Params::RsaPkcsOaepParams(p)) => {
                Some(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
                    hash_alg: CkMechanismType(p.hash_alg),
                    mgf: p.mgf,
                    source: p.source,
                    source_data: p.source_data.clone(),
                }))
            }
            Some(v1_proto::mechanism::Params::GcmParams(p)) => {
                Some(CkMechanismParams::Gcm(GcmParams {
                    iv: p.iv.clone(),
                    iv_bits: p.iv_bits,
                    iv_buffer_len: p.iv_buffer_len,
                    aad: p.aad.clone(),
                    tag_bits: p.tag_bits,
                }))
            }
            Some(v1_proto::mechanism::Params::Ecdh1DeriveParams(p)) => {
                Some(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
                    kdf: p.kdf,
                    shared_data: p.shared_data.clone(),
                    public_data: p.public_data.clone(),
                }))
            }
            Some(v1_proto::mechanism::Params::IvParams(p)) => {
                Some(CkMechanismParams::Iv(IvParams { iv: p.iv.clone() }))
            }
            // Trivial scalar-only
            Some(v1_proto::mechanism::Params::Rc5Params(p)) => {
                Some(CkMechanismParams::Rc5(Rc5Params { word_size: p.word_size, rounds: p.rounds }))
            }
            Some(v1_proto::mechanism::Params::Rc5MacGeneralParams(p)) => {
                Some(CkMechanismParams::Rc5MacGeneral(Rc5MacGeneralParams {
                    word_size: p.word_size,
                    rounds: p.rounds,
                    mac_length: p.mac_length,
                }))
            }
            Some(v1_proto::mechanism::Params::Rc2MacGeneralParams(p)) => {
                Some(CkMechanismParams::Rc2MacGeneral(Rc2MacGeneralParams {
                    effective_bits: p.effective_bits,
                    mac_length: p.mac_length,
                }))
            }
            Some(v1_proto::mechanism::Params::XeddsaParams(p)) => {
                Some(CkMechanismParams::Xeddsa(XeddsaParams { hash: p.hash }))
            }
            Some(v1_proto::mechanism::Params::TlsMacParams(p)) => {
                Some(CkMechanismParams::TlsMac(TlsMacParams {
                    prf_hash_mechanism: p.prf_hash_mechanism,
                    mac_length: p.mac_length,
                    server_or_client: p.server_or_client,
                }))
            }
            // Symmetric with fixed IV
            Some(v1_proto::mechanism::Params::AesCtrParams(p)) => {
                Some(CkMechanismParams::AesCtr(AesCtrParams {
                    counter_bits: p.counter_bits,
                    cb: p.cb.clone(),
                }))
            }
            Some(v1_proto::mechanism::Params::CamelliaCtrParams(p)) => {
                Some(CkMechanismParams::CamelliaCtr(CamelliaCtrParams {
                    counter_bits: p.counter_bits,
                    cb: p.cb.clone(),
                }))
            }
            Some(v1_proto::mechanism::Params::Rc2CbcParams(p)) => {
                Some(CkMechanismParams::Rc2Cbc(Rc2CbcParams {
                    effective_bits: p.effective_bits,
                    iv: p.iv.clone(),
                }))
            }
            Some(v1_proto::mechanism::Params::Rc5CbcParams(p)) => {
                Some(CkMechanismParams::Rc5Cbc(Rc5CbcParams {
                    word_size: p.word_size,
                    rounds: p.rounds,
                    iv: p.iv.clone(),
                }))
            }
            // CBC encrypt data
            Some(v1_proto::mechanism::Params::AesCbcEncryptDataParams(p)) => {
                Some(CkMechanismParams::AesCbcEncryptData(AesCbcEncryptDataParams {
                    iv: p.iv.clone(),
                    data: p.data.clone(),
                }))
            }
            Some(v1_proto::mechanism::Params::DesCbcEncryptDataParams(p)) => {
                Some(CkMechanismParams::DesCbcEncryptData(DesCbcEncryptDataParams {
                    iv: p.iv.clone(),
                    data: p.data.clone(),
                }))
            }
            Some(v1_proto::mechanism::Params::AriaCbcEncryptDataParams(p)) => {
                Some(CkMechanismParams::AriaCbcEncryptData(AriaCbcEncryptDataParams {
                    iv: p.iv.clone(),
                    data: p.data.clone(),
                }))
            }
            Some(v1_proto::mechanism::Params::CamelliaCbcEncryptDataParams(p)) => {
                Some(CkMechanismParams::CamelliaCbcEncryptData(CamelliaCbcEncryptDataParams {
                    iv: p.iv.clone(),
                    data: p.data.clone(),
                }))
            }
            Some(v1_proto::mechanism::Params::SeedCbcEncryptDataParams(p)) => {
                Some(CkMechanismParams::SeedCbcEncryptData(SeedCbcEncryptDataParams {
                    iv: p.iv.clone(),
                    data: p.data.clone(),
                }))
            }
            // AEAD
            Some(v1_proto::mechanism::Params::CcmParams(p)) => {
                Some(CkMechanismParams::Ccm(CcmParams {
                    data_len: p.data_len,
                    nonce: p.nonce.clone(),
                    aad: p.aad.clone(),
                    mac_len: p.mac_len,
                }))
            }
            Some(v1_proto::mechanism::Params::Chacha20Params(p)) => {
                Some(CkMechanismParams::ChaCha20(ChaCha20Params {
                    block_counter: p.block_counter.clone(),
                    block_counter_bits: p.block_counter_bits,
                    nonce: p.nonce.clone(),
                    nonce_bits: p.nonce_bits,
                }))
            }
            Some(v1_proto::mechanism::Params::Salsa20Params(p)) => {
                Some(CkMechanismParams::Salsa20(Salsa20Params {
                    block_counter: p.block_counter.clone(),
                    nonce: p.nonce.clone(),
                    nonce_bits: p.nonce_bits,
                }))
            }
            Some(v1_proto::mechanism::Params::Salsa20Chacha20Poly1305Params(p)) => {
                Some(CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
                    nonce: p.nonce.clone(),
                    aad: p.aad.clone(),
                }))
            }
            Some(v1_proto::mechanism::Params::GcmWrapParams(p)) => {
                Some(CkMechanismParams::GcmWrap(GcmWrapParams {
                    iv: p.iv.clone(),
                    iv_fixed_bits: p.iv_fixed_bits,
                    iv_generator: p.iv_generator,
                    aad: p.aad.clone(),
                    tag_bits: p.tag_bits,
                }))
            }
            Some(v1_proto::mechanism::Params::CcmWrapParams(p)) => {
                Some(CkMechanismParams::CcmWrap(CcmWrapParams {
                    data_len: p.data_len,
                    nonce: p.nonce.clone(),
                    nonce_fixed_bits: p.nonce_fixed_bits,
                    nonce_generator: p.nonce_generator,
                    aad: p.aad.clone(),
                    mac_len: p.mac_len,
                }))
            }
            // Key derivation
            Some(v1_proto::mechanism::Params::Ecdh2DeriveParams(p)) => {
                Some(CkMechanismParams::Ecdh2Derive(p.into()))
            }
            Some(v1_proto::mechanism::Params::EcmqvDeriveParams(p)) => {
                Some(CkMechanismParams::EcmqvDerive(p.into()))
            }
            Some(v1_proto::mechanism::Params::X942Dh1DeriveParams(p)) => {
                Some(CkMechanismParams::X942Dh1Derive(p.into()))
            }
            Some(v1_proto::mechanism::Params::X942Dh2DeriveParams(p)) => {
                Some(CkMechanismParams::X942Dh2Derive(p.into()))
            }
            Some(v1_proto::mechanism::Params::X942MqvDeriveParams(p)) => {
                Some(CkMechanismParams::X942MqvDerive(p.into()))
            }
            Some(v1_proto::mechanism::Params::HkdfParams(p)) => {
                Some(CkMechanismParams::Hkdf(p.into()))
            }
            Some(v1_proto::mechanism::Params::EddsaParams(p)) => {
                Some(CkMechanismParams::Eddsa(p.into()))
            }
            Some(v1_proto::mechanism::Params::Gostr3410DeriveParams(p)) => {
                Some(CkMechanismParams::Gostr3410Derive(p.into()))
            }
            Some(v1_proto::mechanism::Params::KeaDeriveParams(p)) => {
                Some(CkMechanismParams::KeaDerive(p.into()))
            }
            // Key wrapping
            Some(v1_proto::mechanism::Params::EcdhAesKeyWrapParams(p)) => {
                Some(CkMechanismParams::EcdhAesKeyWrap(p.into()))
            }
            Some(v1_proto::mechanism::Params::RsaAesKeyWrapParams(p)) => {
                Some(CkMechanismParams::RsaAesKeyWrap(p.try_into()?))
            }
            Some(v1_proto::mechanism::Params::Gostr3410KeyWrapParams(p)) => {
                Some(CkMechanismParams::Gostr3410KeyWrap(p.into()))
            }
            Some(v1_proto::mechanism::Params::KeyWrapSetOaepParams(p)) => {
                Some(CkMechanismParams::KeyWrapSetOaep(p.into()))
            }
            // Password-based encryption
            Some(v1_proto::mechanism::Params::PbeParams(p)) => {
                Some(CkMechanismParams::Pbe(p.into()))
            }
            Some(v1_proto::mechanism::Params::Pkcs5Pbkd2Params(p)) => {
                Some(CkMechanismParams::Pkcs5Pbkd2(p.into()))
            }
            // TLS/SSL
            Some(v1_proto::mechanism::Params::TlsPrfParams(p)) => {
                Some(CkMechanismParams::TlsPrf(p.into()))
            }
            Some(v1_proto::mechanism::Params::TlsKdfParams(p)) => {
                Some(CkMechanismParams::TlsKdf(p.try_into()?))
            }
            Some(v1_proto::mechanism::Params::Ssl3MasterKeyDeriveParams(p)) => {
                Some(CkMechanismParams::Ssl3MasterKeyDerive(p.try_into()?))
            }
            Some(v1_proto::mechanism::Params::Tls12MasterKeyDeriveParams(p)) => {
                Some(CkMechanismParams::Tls12MasterKeyDerive(p.try_into()?))
            }
            Some(v1_proto::mechanism::Params::Tls12ExtendedMasterKeyDeriveParams(p)) => {
                Some(CkMechanismParams::Tls12ExtendedMasterKeyDerive(p.into()))
            }
            Some(v1_proto::mechanism::Params::Ssl3KeyMatParams(p)) => {
                Some(CkMechanismParams::Ssl3KeyMat(p.try_into()?))
            }
            Some(v1_proto::mechanism::Params::WtlsMasterKeyDeriveParams(p)) => {
                Some(CkMechanismParams::WtlsMasterKeyDerive(p.try_into()?))
            }
            Some(v1_proto::mechanism::Params::WtlsPrfParams(p)) => {
                Some(CkMechanismParams::WtlsPrf(p.into()))
            }
            Some(v1_proto::mechanism::Params::WtlsKeyMatParams(p)) => {
                Some(CkMechanismParams::WtlsKeyMat(p.try_into()?))
            }
            // IKE/IPSec
            Some(v1_proto::mechanism::Params::IkePrfDeriveParams(p)) => {
                Some(CkMechanismParams::IkePrfDerive(p.into()))
            }
            Some(v1_proto::mechanism::Params::Ike1PrfDeriveParams(p)) => {
                Some(CkMechanismParams::Ike1PrfDerive(p.into()))
            }
            Some(v1_proto::mechanism::Params::Ike1ExtendedDeriveParams(p)) => {
                Some(CkMechanismParams::Ike1ExtendedDerive(p.into()))
            }
            Some(v1_proto::mechanism::Params::Ike2PrfPlusDeriveParams(p)) => {
                Some(CkMechanismParams::Ike2PrfPlusDerive(p.into()))
            }
            // SP800-108 KDF
            Some(v1_proto::mechanism::Params::Sp800108KdfParams(p)) => {
                Some(CkMechanismParams::Sp800108Kdf(p.into()))
            }
            Some(v1_proto::mechanism::Params::Sp800108FeedbackKdfParams(p)) => {
                Some(CkMechanismParams::Sp800108FeedbackKdf(p.into()))
            }
            // Signal protocol
            Some(v1_proto::mechanism::Params::X3dhInitiateParams(p)) => {
                Some(CkMechanismParams::X3dhInitiate(p.into()))
            }
            Some(v1_proto::mechanism::Params::X3dhRespondParams(p)) => {
                Some(CkMechanismParams::X3dhRespond(p.into()))
            }
            Some(v1_proto::mechanism::Params::X2RatchetInitializeParams(p)) => {
                Some(CkMechanismParams::X2RatchetInitialize(p.into()))
            }
            Some(v1_proto::mechanism::Params::X2RatchetRespondParams(p)) => {
                Some(CkMechanismParams::X2RatchetRespond(p.into()))
            }
            // Miscellaneous
            Some(v1_proto::mechanism::Params::OtpParams(p)) => {
                Some(CkMechanismParams::Otp(p.into()))
            }
            Some(v1_proto::mechanism::Params::KipParams(p)) => {
                Some(CkMechanismParams::Kip(p.as_ref().try_into()?))
            }
            Some(v1_proto::mechanism::Params::CmsSigParams(p)) => {
                Some(CkMechanismParams::CmsSig(p.as_ref().try_into()?))
            }
            Some(v1_proto::mechanism::Params::SkipjackPrivateWrapParams(p)) => {
                Some(CkMechanismParams::SkipjackPrivateWrap(p.into()))
            }
            Some(v1_proto::mechanism::Params::SkipjackRelayxParams(p)) => {
                Some(CkMechanismParams::SkipjackRelayx(p.into()))
            }
            // Generic / vendor parameter shapes
            Some(v1_proto::mechanism::Params::MacGeneralParams(p)) => {
                Some(CkMechanismParams::MacGeneral(MacGeneralParams { mac_length: p.mac_length }))
            }
            Some(v1_proto::mechanism::Params::ObjectHandleParam(p)) => {
                Some(CkMechanismParams::ObjectHandle(ObjectHandleParam { handle: p.handle }))
            }
            Some(v1_proto::mechanism::Params::SignAdditionalContext(p)) => {
                Some(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                    hedge_variant: p.hedge_variant,
                    context: p.context.clone(),
                }))
            }
            Some(v1_proto::mechanism::Params::KeyDerivationStringData(p)) => {
                Some(CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
                    data: p.data.clone(),
                }))
            }
            Some(v1_proto::mechanism::Params::RawMechanismParams(p)) => {
                Some(CkMechanismParams::Raw(RawMechanismParams { data: p.data.clone() }))
            }
            // Vendor-specific parameter shapes
            Some(v1_proto::mechanism::Params::EciesParams(p)) => {
                Some(CkMechanismParams::Ecies(p.as_ref().try_into()?))
            }
            Some(v1_proto::mechanism::Params::AesCmacKeyDerivationParams(p)) => {
                Some(CkMechanismParams::AesCmacKeyDerivation(
                    pkcs11_proxy_ng_types::AesCmacKeyDerivationParams {
                        context: p.context.clone(),
                        label: p.label.clone(),
                    },
                ))
            }
            Some(v1_proto::mechanism::Params::DilithiumParams(p)) => {
                Some(CkMechanismParams::Dilithium(pkcs11_proxy_ng_types::DilithiumParams {
                    version: p.version,
                    mode: p.mode,
                }))
            }
            Some(v1_proto::mechanism::Params::KyberParams(p)) => {
                Some(CkMechanismParams::Kyber(pkcs11_proxy_ng_types::KyberParams {
                    version: p.version,
                    mode: p.mode,
                    secret_handle: p.secret_handle,
                    shared_data: p.shared_data.clone(),
                    blob: p.blob.clone(),
                }))
            }
            Some(v1_proto::mechanism::Params::HdKeyDeriveParams(p)) => {
                Some(CkMechanismParams::HdKeyDerive(pkcs11_proxy_ng_types::HdKeyDeriveParams {
                    derive_type: p.derive_type,
                    child_key_index: p.child_key_index,
                    chain_code: p.chain_code.clone(),
                    version: p.version,
                }))
            }
            Some(v1_proto::mechanism::Params::VendorObjectExtractParams(p)) => {
                Some(CkMechanismParams::VendorObjectExtract(
                    pkcs11_proxy_ng_types::VendorObjectExtractParams {
                        format: p.format,
                        context: p.context.clone(),
                    },
                ))
            }
            Some(v1_proto::mechanism::Params::VendorObjectInsertParams(p)) => {
                Some(CkMechanismParams::VendorObjectInsert(
                    pkcs11_proxy_ng_types::VendorObjectInsertParams {
                        format: p.format,
                        context: p.context.clone(),
                        object_data: p.object_data.clone(),
                    },
                ))
            }
            // Safety catch-all for any future proto variants not yet wired.
            #[allow(unreachable_patterns)]
            Some(_) => return Err(CkRv::MECHANISM_PARAM_INVALID),
        };
        Ok(CkMechanism { mechanism_type: CkMechanismType(m.mechanism_type), params })
    }
}

impl From<&CkMechanismInfo> for v1_proto::MechanismInfo {
    fn from(m: &CkMechanismInfo) -> Self {
        v1_proto::MechanismInfo {
            min_key_size: m.min_key_size,
            max_key_size: m.max_key_size,
            flags: m.flags.0,
        }
    }
}

impl From<&v1_proto::MechanismInfo> for CkMechanismInfo {
    fn from(m: &v1_proto::MechanismInfo) -> Self {
        CkMechanismInfo {
            min_key_size: m.min_key_size,
            max_key_size: m.max_key_size,
            flags: CkMechanismFlags(m.flags),
        }
    }
}

#[cfg(test)]
mod tests;

mod advanced_params;
mod derivation_params;
mod tls_params;

use crate::pkcs11_proxy_ng::v1 as v1_proto;
// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use crate::secret_boundary::secret_to_plain;
use pkcs11_proxy_ng_types::shape_descriptors::ParamAbi;
use pkcs11_proxy_ng_types::{
    AesCbcEncryptDataParams, AesCtrParams, AriaCbcEncryptDataParams, CamelliaCbcEncryptDataParams,
    CamelliaCtrParams, CcmParams, CcmWrapParams, ChaCha20Params, CkGeneratorFunction, CkKdf,
    CkMechanism, CkMechanismFlags, CkMechanismInfo, CkMechanismParams, CkMechanismType, CkMgf,
    CkOaepSource, CkObjectHandle, CkRv, DesCbcEncryptDataParams, Ecdh1DeriveParams,
    Ecdh2DeriveParams, EcdhAesKeyWrapParams, EcmqvDeriveParams, EddsaParams, ExtractParams,
    FlatParams, GcmParams, GcmWrapParams, Gostr3410DeriveParams, Gostr3410KeyWrapParams,
    HkdfParams, Ike1ExtendedDeriveParams, Ike1PrfDeriveParams, Ike2PrfPlusDeriveParams,
    IkePrfDeriveParams, IvParams, KeaDeriveParams, KeyDerivationStringData, KeyWrapSetOaepParams,
    KipParams, KmacParams, MECHANISM_PARAMETER_TRANSPORT_VERSION, MacGeneralParams, MuGenParams,
    ObjectHandleParam, OtpParam, OtpParams, PbeParams, Pkcs5Pbkd2Params, PointerArray,
    PointerBytes, PrfDataParam, RawMechanismParams, Rc2CbcParams, Rc2MacGeneralParams,
    Rc5CbcParams, Rc5MacGeneralParams, Rc5Params, RsaAesKeyWrapParams, RsaPkcsOaepParams,
    RsaPkcsPssParams, Salsa20ChaCha20Poly1305Params, Salsa20Params, SecretBytes,
    SeedCbcEncryptDataParams, SignAdditionalContext, SkipjackPrivateWrapParams,
    SkipjackRelayxParams, Sp800108FeedbackKdfParams, Sp800108KdfParams, Ssl3KeyMatParams,
    Ssl3MasterKeyDeriveParams, Tls12ExtendedMasterKeyDeriveParams, Tls12MasterKeyDeriveParams,
    TlsKdfParams, TlsMacParams, TlsPrfParams, WtlsKeyMatParams, WtlsMasterKeyDeriveParams,
    WtlsPrfParams, X942Dh1DeriveParams, X942Dh2DeriveParams, X942MqvDeriveParams, XeddsaParams,
};

/// Decode one bool-less (bytes, `*_null_len`) wire pair under `version`
/// (R16 typed presence, S2 §3): presence = NULL with exactly that length
/// (bytes must be empty); absence = non-NULL with `len == bytes.len()`
/// (including non-NULL/zero). Presence fields are v1-only: set on a
/// version-0 message they are contradictory metadata (mirrors the R9
/// Flat-with-legacy-stamp rule — no v0 encoder emits them, so only
/// crafted input carries them).
pub(crate) fn pointer_from_wire(
    bytes: &[u8],
    null_len: Option<u64>,
    version: u32,
) -> Result<PointerBytes, CkRv> {
    match null_len {
        Some(declared_len) => {
            if version == 0 || !bytes.is_empty() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            Ok(PointerBytes::null_len(declared_len))
        }
        None => Ok(PointerBytes::present_copy(bytes)),
    }
}

/// Decode one legacy-bool (bytes, `*_null_len`, `*_null`) wire triple
/// (R16: GCM/CCM/OAEP families). v0 keeps the legacy meaning (set bool →
/// NULL/0, unset → present bytes); v1 is presence-only (the top-level R9
/// gate rejects set bools before this runs; the re-check here is defense
/// in depth). Conversion stays total over legacy shapes: a set bool with
/// non-empty bytes still decodes (the bool wins, per legacy meaning) and
/// fails closed later at transport validation.
pub(crate) fn pointer_from_wire_legacy(
    bytes: &[u8],
    null_len: Option<u64>,
    legacy_null: bool,
    version: u32,
) -> Result<PointerBytes, CkRv> {
    match null_len {
        Some(declared_len) => {
            if version == 0 || legacy_null || !bytes.is_empty() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            Ok(PointerBytes::null_len(declared_len))
        }
        None => Ok(PointerBytes::from_legacy(bytes, legacy_null)),
    }
}

/// R16 version-threaded decode of one classic params struct (S2 §3).
/// An inherent `Type::from_wire` is impossible — the types structs live
/// in the types crate — so the convention rides this local trait: each
/// family implements `FromWire<its wire message>` and the `TryFrom`
/// dispatch calls `Type::from_wire(p, version)?`.
pub(crate) trait FromWire<P> {
    fn from_wire(p: &P, version: u32) -> Result<Self, CkRv>
    where
        Self: Sized;
}

/// Encode one presence peer (R17 production direction of the R16 domain
/// conversion, S2 §3): NULL (any length, including zero) travels as
/// empty bytes + `Some(declared_len)`; Present travels as its bytes +
/// `None` (including non-NULL/zero). The peer is authoritative: callers
/// pass the `PointerBytes` member, never the legacy bytes member, so a
/// NULL arm can never ride non-empty bytes.
pub(crate) fn pointer_to_wire(presence: &PointerBytes) -> (Vec<u8>, Option<u64>) {
    match presence {
        PointerBytes::Present(bytes) => (secret_to_plain(bytes), None),
        PointerBytes::Null { declared_len } => (Vec::new(), Some(*declared_len)),
    }
}

/// R17/R18 v1 encode of one classic params struct (S2 §3/§5/§8): the
/// presence dual of [`FromWire`]. Each input-pointer (R17) and tail
/// (R18) family implements `ToWireV1<its wire message>` (inline arms
/// live in [`encode_r17_v1_params`]; delegated families implement this
/// trait in their family module); the version-threaded entry calls it
/// and stamps version 1. Legacy `*_null` bools are forced unset (S2 §3:
/// a v1 encoder MUST leave legacy bools unset). Families whose v1
/// encode is fallible (nested mechanism/template refusal: KIP,
/// OTP/SP800-108) keep inline arms in
/// [`encode_r18_tail_v1_params`] instead of this infallible trait.
pub(crate) trait ToWireV1<W> {
    fn to_wire_v1(&self) -> W;
}

/// Decode one counted-array (`repeated`, `*_null_count`) wire pair (R18
/// tail, S2 §8): `Some(count)` = NULL with exactly that count (the
/// array must be empty); absent = non-NULL with `len == items.len()`
/// (including non-NULL/zero). Count envelopes are v1-only: set on a
/// version-0 message they are contradictory metadata (mirrors
/// [`pointer_from_wire`] — no v0 encoder emits them, so only crafted
/// input carries them). Returns the legacy array alongside the peer so
/// elements convert once (element conversion is fallible: nested
/// templates refuse with `PARAM_INVALID`).
pub(crate) fn pointer_array_from_wire<T, P>(
    items: &[P],
    null_count: Option<u64>,
    version: u32,
    convert: impl FnMut(&P) -> Result<T, CkRv>,
) -> Result<PointerArray<T>, CkRv> {
    match null_count {
        Some(declared_count) => {
            if version == 0 || !items.is_empty() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            Ok(PointerArray::null_count(declared_count))
        }
        None => {
            let converted: Vec<T> = items.iter().map(convert).collect::<Result<Vec<_>, _>>()?;
            Ok(PointerArray::present(converted))
        }
    }
}

/// Encode one array-presence peer (R18 tail production direction of
/// [`pointer_array_from_wire`], S2 §8): NULL (any count, including
/// zero) travels as an empty array + `Some(declared_count)`; Present
/// travels as its converted elements + `None` (including
/// non-NULL/zero). The peer is authoritative: callers pass the
/// `PointerArray` member, never the legacy array, so a NULL arm can
/// never ride non-empty elements. Fallible: the nested-template
/// refusal (W1-C8-01) propagates to the caller.
pub(crate) fn pointer_array_to_wire<T, W>(
    presence: &PointerArray<T>,
    convert: impl FnMut(&T) -> Result<W, CkRv>,
) -> Result<(Vec<W>, Option<u64>), CkRv> {
    match presence {
        PointerArray::Present(items) => {
            let converted: Vec<W> = items.iter().map(convert).collect::<Result<Vec<_>, _>>()?;
            Ok((converted, None))
        }
        PointerArray::Null { declared_count } => Ok((Vec::new(), Some(*declared_count))),
    }
}

/// Decode one length-less `*_null` bool envelope (R18 tail, S2 §8:
/// nested-mechanism, version, output-length, output-handle, and
/// returned-key-material null bits). No v0 encoder emits them, so
/// `Some` at version 0 is contradictory metadata. Canonical v1 form is
/// absent = non-NULL, `Some(true)` = NULL; `Some(false)` is a dual
/// representation of non-NULL (S2 §3 "no dual representations") and is
/// rejected. A claimed NULL additionally requires its forced zero/empty
/// companions (`forced_zero`, e.g. zeroed version scalars), else the
/// message contradicts itself.
pub(crate) fn null_bit_from_wire(
    null: Option<bool>,
    forced_zero: bool,
    version: u32,
) -> Result<bool, CkRv> {
    match null {
        None => Ok(false),
        Some(_) if version == 0 => Err(CkRv::MECHANISM_PARAM_INVALID),
        Some(true) => {
            if forced_zero {
                Ok(true)
            } else {
                Err(CkRv::MECHANISM_PARAM_INVALID)
            }
        }
        // Explicit-false is a second spelling of absent (non-NULL).
        Some(false) => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

/// Encode one null bit (R18 tail production direction of
/// [`null_bit_from_wire`]): NULL travels as `Some(true)`; non-NULL
/// travels as absent (canonical v1 — never explicit `Some(false)`).
pub(crate) fn null_bit_to_wire(is_null: bool) -> Option<bool> {
    is_null.then_some(true)
}

/// Shared-length agreement for companion legs (R18 tail: KEA RandomA/B
/// share the one C `ulRandomLen`, Skipjack PrimeP/BaseG share the one C
/// `ulPAndGLen`). The C struct carries ONE length, so under v1 every
/// companion leg's effective length ([`PointerBytes::declared_len`]:
/// byte count when present, declared length when NULL) MUST agree —
/// any disagreement is crafted input (the shim always emits agreement;
/// no legitimate call disagrees). v0 keeps legacy behavior exactly:
/// legacy members carry no per-leg lengths, so no check runs there.
/// (Enforced here at version-threaded decode only: transport
/// validation sees version-blind domain values, so a validator-side
/// check would newly reject legal v0 traffic with mismatched legacy
/// lengths.)
pub(crate) fn check_shared_len_agreement(version: u32, legs: &[&PointerBytes]) -> Result<(), CkRv> {
    if version != MECHANISM_PARAMETER_TRANSPORT_VERSION {
        return Ok(());
    }
    if let Some((first, rest)) = legs.split_first() {
        let want = first.declared_len();
        if rest.iter().any(|leg| leg.declared_len() != want) {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
    }
    Ok(())
}

impl TryFrom<&CkMechanism> for v1_proto::Mechanism {
    type Error = CkRv;

    fn try_from(m: &CkMechanism) -> Result<Self, Self::Error> {
        let params = match &m.params {
            None => None,
            Some(CkMechanismParams::RsaPkcsPss(p)) => {
                Some(v1_proto::mechanism::Params::RsaPkcsPssParams(v1_proto::RsaPkcsPssParams {
                    hash_alg: p.hash_alg.0,
                    mgf: p.mgf.0,
                    salt_len: p.salt_len,
                }))
            }
            Some(CkMechanismParams::RsaPkcsOaep(p)) => {
                Some(v1_proto::mechanism::Params::RsaPkcsOaepParams(v1_proto::RsaPkcsOaepParams {
                    hash_alg: p.hash_alg.0,
                    mgf: p.mgf.0,
                    source: p.source.0,
                    source_data: pointer_to_wire(&p.source_data_presence).0,
                    source_null: p.source_data_presence.is_null(),
                    // R16: production encode stays v0-shaped (shim emits
                    // v1 in R17); presence fields are decode-side only.
                    source_data_null_len: None,
                }))
            }
            Some(CkMechanismParams::Gcm(p)) => {
                Some(v1_proto::mechanism::Params::GcmParams(v1_proto::GcmParams {
                    iv: pointer_to_wire(&p.iv_presence).0,
                    iv_bits: p.iv_bits,
                    aad: pointer_to_wire(&p.aad_presence).0,
                    tag_bits: p.tag_bits,
                    iv_buffer_len: p.iv_buffer_len,
                    iv_null: p.iv_presence.is_null(),
                    aad_null: p.aad_presence.is_null(),
                    // R16: production encode stays v0-shaped (shim emits
                    // v1 in R17); presence fields are decode-side only.
                    iv_null_len: None,
                    aad_null_len: None,
                }))
            }
            Some(CkMechanismParams::Ecdh1Derive(p)) => {
                Some(v1_proto::mechanism::Params::Ecdh1DeriveParams(v1_proto::Ecdh1DeriveParams {
                    kdf: p.kdf.0,
                    shared_data: pointer_to_wire(&p.shared_data_presence).0,
                    public_data: pointer_to_wire(&p.public_data_presence).0,
                    // R16: production encode stays v0-shaped (shim emits
                    // v1 in R17); presence fields are decode-side only.
                    shared_data_null_len: None,
                    public_data_null_len: None,
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
                    hash: p.hash.0,
                }))
            }
            Some(CkMechanismParams::TlsMac(p)) => {
                Some(v1_proto::mechanism::Params::TlsMacParams(v1_proto::TlsMacParams {
                    prf_hash_mechanism: p.prf_hash_mechanism.0,
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
                    iv: pointer_to_wire(&p.iv_presence).0,
                    // R16: production encode stays v0-shaped (shim emits
                    // v1 in R17); presence fields are decode-side only.
                    iv_null_len: None,
                }))
            }
            // CBC encrypt data
            Some(CkMechanismParams::AesCbcEncryptData(p)) => {
                Some(v1_proto::mechanism::Params::AesCbcEncryptDataParams(
                    v1_proto::AesCbcEncryptDataParams {
                        iv: p.iv.clone(),
                        data: pointer_to_wire(&p.data_presence).0,
                        // R16: production encode stays v0-shaped.
                        data_null_len: None,
                    },
                ))
            }
            Some(CkMechanismParams::DesCbcEncryptData(p)) => {
                Some(v1_proto::mechanism::Params::DesCbcEncryptDataParams(
                    v1_proto::DesCbcEncryptDataParams {
                        iv: p.iv.clone(),
                        data: pointer_to_wire(&p.data_presence).0,
                        // R16: production encode stays v0-shaped.
                        data_null_len: None,
                    },
                ))
            }
            Some(CkMechanismParams::AriaCbcEncryptData(p)) => {
                Some(v1_proto::mechanism::Params::AriaCbcEncryptDataParams(
                    v1_proto::AriaCbcEncryptDataParams {
                        iv: p.iv.clone(),
                        data: pointer_to_wire(&p.data_presence).0,
                        // R16: production encode stays v0-shaped.
                        data_null_len: None,
                    },
                ))
            }
            Some(CkMechanismParams::CamelliaCbcEncryptData(p)) => {
                Some(v1_proto::mechanism::Params::CamelliaCbcEncryptDataParams(
                    v1_proto::CamelliaCbcEncryptDataParams {
                        iv: p.iv.clone(),
                        data: pointer_to_wire(&p.data_presence).0,
                        // R16: production encode stays v0-shaped.
                        data_null_len: None,
                    },
                ))
            }
            Some(CkMechanismParams::SeedCbcEncryptData(p)) => {
                Some(v1_proto::mechanism::Params::SeedCbcEncryptDataParams(
                    v1_proto::SeedCbcEncryptDataParams {
                        iv: p.iv.clone(),
                        data: pointer_to_wire(&p.data_presence).0,
                        // R16: production encode stays v0-shaped.
                        data_null_len: None,
                    },
                ))
            }
            // AEAD
            Some(CkMechanismParams::Ccm(p)) => {
                Some(v1_proto::mechanism::Params::CcmParams(v1_proto::CcmParams {
                    data_len: p.data_len,
                    nonce: pointer_to_wire(&p.nonce_presence).0,
                    aad: pointer_to_wire(&p.aad_presence).0,
                    mac_len: p.mac_len,
                    nonce_null: p.nonce_presence.is_null(),
                    aad_null: p.aad_presence.is_null(),
                    // R16: production encode stays v0-shaped.
                    nonce_null_len: None,
                    aad_null_len: None,
                }))
            }
            Some(CkMechanismParams::ChaCha20(p)) => {
                Some(v1_proto::mechanism::Params::Chacha20Params(v1_proto::ChaCha20Params {
                    block_counter: pointer_to_wire(&p.block_counter_presence).0,
                    block_counter_bits: p.block_counter_bits,
                    nonce: pointer_to_wire(&p.nonce_presence).0,
                    nonce_bits: p.nonce_bits,
                    // R16: production encode stays v0-shaped.
                    block_counter_null_len: None,
                    nonce_null_len: None,
                }))
            }
            Some(CkMechanismParams::Salsa20(p)) => {
                Some(v1_proto::mechanism::Params::Salsa20Params(v1_proto::Salsa20Params {
                    block_counter: pointer_to_wire(&p.block_counter_presence).0,
                    nonce: pointer_to_wire(&p.nonce_presence).0,
                    nonce_bits: p.nonce_bits,
                    // R16: production encode stays v0-shaped.
                    block_counter_null_len: None,
                    nonce_null_len: None,
                }))
            }
            Some(CkMechanismParams::Salsa20ChaCha20Poly1305(p)) => {
                Some(v1_proto::mechanism::Params::Salsa20Chacha20Poly1305Params(
                    v1_proto::Salsa20ChaCha20Poly1305Params {
                        nonce: pointer_to_wire(&p.nonce_presence).0,
                        aad: pointer_to_wire(&p.aad_presence).0,
                        // R16: production encode stays v0-shaped.
                        nonce_null_len: None,
                        aad_null_len: None,
                    },
                ))
            }
            Some(CkMechanismParams::GcmWrap(p)) => {
                Some(v1_proto::mechanism::Params::GcmWrapParams(v1_proto::GcmWrapParams {
                    iv: pointer_to_wire(&p.iv_presence).0,
                    iv_fixed_bits: p.iv_fixed_bits,
                    iv_generator: p.iv_generator.0,
                    aad: pointer_to_wire(&p.aad_presence).0,
                    tag_bits: p.tag_bits,
                    // R16: production encode stays v0-shaped.
                    iv_null_len: None,
                    aad_null_len: None,
                }))
            }
            Some(CkMechanismParams::CcmWrap(p)) => {
                Some(v1_proto::mechanism::Params::CcmWrapParams(v1_proto::CcmWrapParams {
                    data_len: p.data_len,
                    nonce: pointer_to_wire(&p.nonce_presence).0,
                    nonce_fixed_bits: p.nonce_fixed_bits,
                    nonce_generator: p.nonce_generator.0,
                    aad: pointer_to_wire(&p.aad_presence).0,
                    mac_len: p.mac_len,
                    // R16: production encode stays v0-shaped.
                    nonce_null_len: None,
                    aad_null_len: None,
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
                Some(v1_proto::mechanism::Params::Sp800108KdfParams(p.try_into()?))
            }
            Some(CkMechanismParams::Sp800108FeedbackKdf(p)) => {
                Some(v1_proto::mechanism::Params::Sp800108FeedbackKdfParams(p.try_into()?))
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
                let proto_kip: v1_proto::KipParams = p.try_into()?;
                Some(v1_proto::mechanism::Params::KipParams(Box::new(proto_kip)))
            }
            Some(CkMechanismParams::CmsSig(p)) => {
                let proto_cms: v1_proto::CmsSigParams = p.try_into()?;
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
                    handle: p.handle.0,
                }))
            }
            Some(CkMechanismParams::Extract(p)) => {
                Some(v1_proto::mechanism::Params::ExtractParams(v1_proto::ExtractParams {
                    bit_position: p.bit_position,
                }))
            }
            Some(CkMechanismParams::SignAdditionalContext(p)) => {
                Some(v1_proto::mechanism::Params::SignAdditionalContext(
                    v1_proto::SignAdditionalContext {
                        hedge_variant: p.hedge_variant,
                        context: pointer_to_wire(&p.context_presence).0,
                        hash: p.hash.0,
                        // R16: production encode stays v0-shaped.
                        context_null_len: None,
                    },
                ))
            }
            Some(CkMechanismParams::Kmac(p)) => {
                Some(v1_proto::mechanism::Params::KmacParams(v1_proto::KmacParams {
                    key_handle: p.key_handle.0,
                    mac_length: p.mac_length,
                    customization_string: pointer_to_wire(&p.customization_string_presence).0,
                    // R16: production encode stays v0-shaped.
                    customization_string_null_len: None,
                }))
            }
            Some(CkMechanismParams::MuGen(p)) => {
                Some(v1_proto::mechanism::Params::MuGenParams(v1_proto::MuGenParams {
                    key_handle: p.key_handle.0,
                    tr: pointer_to_wire(&p.tr_presence).0,
                    context: pointer_to_wire(&p.context_presence).0,
                    // R16: production encode stays v0-shaped.
                    tr_null_len: None,
                    context_null_len: None,
                }))
            }
            Some(CkMechanismParams::KeyDerivationString(p)) => {
                Some(v1_proto::mechanism::Params::KeyDerivationStringData(
                    v1_proto::KeyDerivationStringData {
                        data: pointer_to_wire(&p.data_presence).0,
                        // R16: production encode stays v0-shaped.
                        data_null_len: None,
                    },
                ))
            }
            Some(CkMechanismParams::Raw(p)) => {
                Some(v1_proto::mechanism::Params::RawMechanismParams(
                    v1_proto::RawMechanismParams { data: secret_to_plain(&p.data) },
                ))
            }
            // Versioned representable parameters (S2 §3/§6; R9): the stored
            // (threaded) version rides out; validation owns its enforcement.
            Some(CkMechanismParams::Flat(p)) => Some(
                v1_proto::mechanism::Params::FlatMechanismParams(v1_proto::FlatMechanismParams {
                    data: secret_to_plain(&p.bytes),
                    declared_len: p.declared_len,
                    source_abi: domain_abi_to_wire(p.source_abi),
                    shape_layout_fingerprint: p.fingerprint,
                }),
            ),
            Some(CkMechanismParams::Null { declared_len, .. }) => {
                Some(v1_proto::mechanism::Params::NullMechanismParams(
                    v1_proto::NullMechanismParams { declared_len: *declared_len },
                ))
            }
            // Vendor-specific parameter shapes
            Some(CkMechanismParams::Ecies(p)) => {
                let proto_ecies: v1_proto::EciesParams = p.try_into()?;
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
        // R9: v1 members emit their stored (threaded) version; every legacy
        // member keeps emitting version 0 (bit-identical to the R6 encoder).
        let version = match &m.params {
            Some(CkMechanismParams::Flat(p)) => p.version,
            Some(CkMechanismParams::Null { version, .. }) => *version,
            _ => 0,
        };
        Ok(v1_proto::Mechanism {
            mechanism_type: m.mechanism_type.0,
            params,
            parameter_encoding_version: version,
        })
    }
}

/// Capability-gated classic wire encoding (R17+R18; S2 §3/§5/§8: the
/// shim emits v1 for the input-pointer and tail families, never legacy
/// `Raw` under v1).
///
/// `transport_version` is the negotiated
/// `mechanism_parameter_transport_version` capability (discovery value, 0
/// when absent). At capability 0 the encoding delegates to the legacy
/// `TryFrom` exactly (bit-identical, version 0). At capability ≥ 1 —
/// including capabilities newer than this encoder, which still emits the
/// v1 form it knows — each R17 input-pointer family and each R18 tail
/// family encodes presence-based (NULL = empty bytes + envelope) with
/// the outer stamp 1; every other variant (scalar, byte-buffer,
/// Flat/Null, absent, KEM, vendor) takes the identical legacy path
/// (Flat/Null keep their stored stamp).
pub fn to_wire_with_transport_version(
    m: &CkMechanism,
    transport_version: u32,
) -> Result<v1_proto::Mechanism, CkRv> {
    if transport_version < MECHANISM_PARAMETER_TRANSPORT_VERSION {
        return v1_proto::Mechanism::try_from(m);
    }
    let stamp_v1 = |params: v1_proto::mechanism::Params| v1_proto::Mechanism {
        mechanism_type: m.mechanism_type.0,
        params: Some(params),
        parameter_encoding_version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
    };
    if let Some(params) = encode_r17_v1_params(m.params.as_ref()) {
        return Ok(stamp_v1(params));
    }
    match encode_r18_tail_v1_params(m.params.as_ref())? {
        Some(params) => Ok(stamp_v1(params)),
        None => v1_proto::Mechanism::try_from(m),
    }
}

/// v1 presence encode for the 37 R17 input-pointer shapes (S2 §8 list +
/// `gcm_compat`, which rides the GCM wire form): `Some` for an R17
/// family, `None` for every other variant (the entry falls back to the
/// identical legacy encode). Reviewer-checked against
/// `R16_PRESENCE_TABLE` and the R17 shim dispatch predicate.
fn encode_r17_v1_params(params: Option<&CkMechanismParams>) -> Option<v1_proto::mechanism::Params> {
    match params {
        Some(CkMechanismParams::RsaPkcsOaep(p)) => {
            let (source_data, source_data_null_len) = pointer_to_wire(&p.source_data_presence);
            Some(v1_proto::mechanism::Params::RsaPkcsOaepParams(v1_proto::RsaPkcsOaepParams {
                hash_alg: p.hash_alg.0,
                mgf: p.mgf.0,
                source: p.source.0,
                source_data,
                // S2 §3: a v1 encoder MUST leave legacy bools unset.
                source_null: false,
                source_data_null_len,
            }))
        }
        Some(CkMechanismParams::Gcm(p)) => {
            let (iv, iv_null_len) = pointer_to_wire(&p.iv_presence);
            let (aad, aad_null_len) = pointer_to_wire(&p.aad_presence);
            Some(v1_proto::mechanism::Params::GcmParams(v1_proto::GcmParams {
                iv,
                iv_bits: p.iv_bits,
                aad,
                tag_bits: p.tag_bits,
                iv_buffer_len: p.iv_buffer_len,
                // S2 §3: a v1 encoder MUST leave legacy bools unset.
                iv_null: false,
                aad_null: false,
                iv_null_len,
                aad_null_len,
            }))
        }
        Some(CkMechanismParams::Ecdh1Derive(p)) => {
            let (shared_data, shared_data_null_len) = pointer_to_wire(&p.shared_data_presence);
            let (public_data, public_data_null_len) = pointer_to_wire(&p.public_data_presence);
            Some(v1_proto::mechanism::Params::Ecdh1DeriveParams(v1_proto::Ecdh1DeriveParams {
                kdf: p.kdf.0,
                shared_data,
                public_data,
                shared_data_null_len,
                public_data_null_len,
            }))
        }
        Some(CkMechanismParams::Ccm(p)) => {
            let (nonce, nonce_null_len) = pointer_to_wire(&p.nonce_presence);
            let (aad, aad_null_len) = pointer_to_wire(&p.aad_presence);
            Some(v1_proto::mechanism::Params::CcmParams(v1_proto::CcmParams {
                data_len: p.data_len,
                nonce,
                aad,
                mac_len: p.mac_len,
                // S2 §3: a v1 encoder MUST leave legacy bools unset.
                nonce_null: false,
                aad_null: false,
                nonce_null_len,
                aad_null_len,
            }))
        }
        Some(CkMechanismParams::ChaCha20(p)) => {
            let (block_counter, block_counter_null_len) =
                pointer_to_wire(&p.block_counter_presence);
            let (nonce, nonce_null_len) = pointer_to_wire(&p.nonce_presence);
            Some(v1_proto::mechanism::Params::Chacha20Params(v1_proto::ChaCha20Params {
                block_counter,
                block_counter_bits: p.block_counter_bits,
                nonce,
                nonce_bits: p.nonce_bits,
                block_counter_null_len,
                nonce_null_len,
            }))
        }
        Some(CkMechanismParams::Salsa20(p)) => {
            let (block_counter, block_counter_null_len) =
                pointer_to_wire(&p.block_counter_presence);
            let (nonce, nonce_null_len) = pointer_to_wire(&p.nonce_presence);
            Some(v1_proto::mechanism::Params::Salsa20Params(v1_proto::Salsa20Params {
                block_counter,
                nonce,
                nonce_bits: p.nonce_bits,
                block_counter_null_len,
                nonce_null_len,
            }))
        }
        Some(CkMechanismParams::Salsa20ChaCha20Poly1305(p)) => {
            let (nonce, nonce_null_len) = pointer_to_wire(&p.nonce_presence);
            let (aad, aad_null_len) = pointer_to_wire(&p.aad_presence);
            Some(v1_proto::mechanism::Params::Salsa20Chacha20Poly1305Params(
                v1_proto::Salsa20ChaCha20Poly1305Params {
                    nonce,
                    aad,
                    nonce_null_len,
                    aad_null_len,
                },
            ))
        }
        Some(CkMechanismParams::GcmWrap(p)) => {
            let (iv, iv_null_len) = pointer_to_wire(&p.iv_presence);
            let (aad, aad_null_len) = pointer_to_wire(&p.aad_presence);
            Some(v1_proto::mechanism::Params::GcmWrapParams(v1_proto::GcmWrapParams {
                iv,
                iv_fixed_bits: p.iv_fixed_bits,
                iv_generator: p.iv_generator.0,
                aad,
                tag_bits: p.tag_bits,
                iv_null_len,
                aad_null_len,
            }))
        }
        Some(CkMechanismParams::CcmWrap(p)) => {
            let (nonce, nonce_null_len) = pointer_to_wire(&p.nonce_presence);
            let (aad, aad_null_len) = pointer_to_wire(&p.aad_presence);
            Some(v1_proto::mechanism::Params::CcmWrapParams(v1_proto::CcmWrapParams {
                data_len: p.data_len,
                nonce,
                nonce_fixed_bits: p.nonce_fixed_bits,
                nonce_generator: p.nonce_generator.0,
                aad,
                mac_len: p.mac_len,
                nonce_null_len,
                aad_null_len,
            }))
        }
        Some(CkMechanismParams::Rc5Cbc(p)) => {
            let (iv, iv_null_len) = pointer_to_wire(&p.iv_presence);
            Some(v1_proto::mechanism::Params::Rc5CbcParams(v1_proto::Rc5CbcParams {
                word_size: p.word_size,
                rounds: p.rounds,
                iv,
                iv_null_len,
            }))
        }
        Some(CkMechanismParams::AesCbcEncryptData(p)) => {
            let (data, data_null_len) = pointer_to_wire(&p.data_presence);
            Some(v1_proto::mechanism::Params::AesCbcEncryptDataParams(
                v1_proto::AesCbcEncryptDataParams { iv: p.iv.clone(), data, data_null_len },
            ))
        }
        Some(CkMechanismParams::DesCbcEncryptData(p)) => {
            let (data, data_null_len) = pointer_to_wire(&p.data_presence);
            Some(v1_proto::mechanism::Params::DesCbcEncryptDataParams(
                v1_proto::DesCbcEncryptDataParams { iv: p.iv.clone(), data, data_null_len },
            ))
        }
        Some(CkMechanismParams::AriaCbcEncryptData(p)) => {
            let (data, data_null_len) = pointer_to_wire(&p.data_presence);
            Some(v1_proto::mechanism::Params::AriaCbcEncryptDataParams(
                v1_proto::AriaCbcEncryptDataParams { iv: p.iv.clone(), data, data_null_len },
            ))
        }
        Some(CkMechanismParams::CamelliaCbcEncryptData(p)) => {
            let (data, data_null_len) = pointer_to_wire(&p.data_presence);
            Some(v1_proto::mechanism::Params::CamelliaCbcEncryptDataParams(
                v1_proto::CamelliaCbcEncryptDataParams { iv: p.iv.clone(), data, data_null_len },
            ))
        }
        Some(CkMechanismParams::SeedCbcEncryptData(p)) => {
            let (data, data_null_len) = pointer_to_wire(&p.data_presence);
            Some(v1_proto::mechanism::Params::SeedCbcEncryptDataParams(
                v1_proto::SeedCbcEncryptDataParams { iv: p.iv.clone(), data, data_null_len },
            ))
        }
        // Delegated families implement `ToWireV1` in their family module.
        Some(CkMechanismParams::Ecdh2Derive(p)) => {
            Some(v1_proto::mechanism::Params::Ecdh2DeriveParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::EcmqvDerive(p)) => {
            Some(v1_proto::mechanism::Params::EcmqvDeriveParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::X942Dh1Derive(p)) => {
            Some(v1_proto::mechanism::Params::X942Dh1DeriveParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::X942Dh2Derive(p)) => {
            Some(v1_proto::mechanism::Params::X942Dh2DeriveParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::X942MqvDerive(p)) => {
            Some(v1_proto::mechanism::Params::X942MqvDeriveParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::Hkdf(p)) => {
            Some(v1_proto::mechanism::Params::HkdfParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::Eddsa(p)) => {
            Some(v1_proto::mechanism::Params::EddsaParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::Gostr3410Derive(p)) => {
            Some(v1_proto::mechanism::Params::Gostr3410DeriveParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::EcdhAesKeyWrap(p)) => {
            Some(v1_proto::mechanism::Params::EcdhAesKeyWrapParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::RsaAesKeyWrap(p)) => {
            Some(v1_proto::mechanism::Params::RsaAesKeyWrapParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::Gostr3410KeyWrap(p)) => {
            Some(v1_proto::mechanism::Params::Gostr3410KeyWrapParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::KeyWrapSetOaep(p)) => {
            Some(v1_proto::mechanism::Params::KeyWrapSetOaepParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::Pbe(p)) => {
            Some(v1_proto::mechanism::Params::PbeParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::Pkcs5Pbkd2(p)) => {
            Some(v1_proto::mechanism::Params::Pkcs5Pbkd2Params(p.to_wire_v1()))
        }
        Some(CkMechanismParams::IkePrfDerive(p)) => {
            Some(v1_proto::mechanism::Params::IkePrfDeriveParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::Ike1PrfDerive(p)) => {
            Some(v1_proto::mechanism::Params::Ike1PrfDeriveParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::Ike1ExtendedDerive(p)) => {
            Some(v1_proto::mechanism::Params::Ike1ExtendedDeriveParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::Ike2PrfPlusDerive(p)) => {
            Some(v1_proto::mechanism::Params::Ike2PrfPlusDeriveParams(p.to_wire_v1()))
        }
        Some(CkMechanismParams::SignAdditionalContext(p)) => {
            let (context, context_null_len) = pointer_to_wire(&p.context_presence);
            Some(v1_proto::mechanism::Params::SignAdditionalContext(
                v1_proto::SignAdditionalContext {
                    hedge_variant: p.hedge_variant,
                    context,
                    hash: p.hash.0,
                    context_null_len,
                },
            ))
        }
        Some(CkMechanismParams::Kmac(p)) => {
            let (customization_string, customization_string_null_len) =
                pointer_to_wire(&p.customization_string_presence);
            Some(v1_proto::mechanism::Params::KmacParams(v1_proto::KmacParams {
                key_handle: p.key_handle.0,
                mac_length: p.mac_length,
                customization_string,
                customization_string_null_len,
            }))
        }
        Some(CkMechanismParams::MuGen(p)) => {
            let (tr, tr_null_len) = pointer_to_wire(&p.tr_presence);
            let (context, context_null_len) = pointer_to_wire(&p.context_presence);
            Some(v1_proto::mechanism::Params::MuGenParams(v1_proto::MuGenParams {
                key_handle: p.key_handle.0,
                tr,
                context,
                tr_null_len,
                context_null_len,
            }))
        }
        Some(CkMechanismParams::KeyDerivationString(p)) => {
            let (data, data_null_len) = pointer_to_wire(&p.data_presence);
            Some(v1_proto::mechanism::Params::KeyDerivationStringData(
                v1_proto::KeyDerivationStringData { data, data_null_len },
            ))
        }
        // Non-R17 variants fall back to the identical legacy encode.
        _ => None,
    }
}

/// v1 presence encode for the 16 R18 tail shapes with envelopes (S2 §8
/// tail: KEA/KIP/OTP/SP800-108/Skipjack/TLS-WTLS; TlsMac is the scalar
/// empty row and stays on the legacy path): `Some` for a tail family,
/// `None` for every other variant (the entry falls back to the
/// identical legacy encode). Reviewer-checked against
/// `R18_TAIL_TABLE` and the R18 shim dispatch predicate. Fallible:
/// the nested-mechanism/template refusals (KIP, SP800-108) propagate —
/// a v1 encoder must refuse exactly where the v0 encoder refuses, never
/// silently drop content.
fn encode_r18_tail_v1_params(
    params: Option<&CkMechanismParams>,
) -> Result<Option<v1_proto::mechanism::Params>, CkRv> {
    match params {
        // Delegated tail families implement `ToWireV1` in their family module.
        Some(CkMechanismParams::KeaDerive(p)) => {
            Ok(Some(v1_proto::mechanism::Params::KeaDeriveParams(p.to_wire_v1())))
        }
        Some(CkMechanismParams::SkipjackPrivateWrap(p)) => {
            Ok(Some(v1_proto::mechanism::Params::SkipjackPrivateWrapParams(p.to_wire_v1())))
        }
        Some(CkMechanismParams::SkipjackRelayx(p)) => {
            Ok(Some(v1_proto::mechanism::Params::SkipjackRelayxParams(p.to_wire_v1())))
        }
        Some(CkMechanismParams::TlsPrf(p)) => {
            Ok(Some(v1_proto::mechanism::Params::TlsPrfParams(p.to_wire_v1())))
        }
        Some(CkMechanismParams::TlsKdf(p)) => {
            Ok(Some(v1_proto::mechanism::Params::TlsKdfParams(p.to_wire_v1())))
        }
        Some(CkMechanismParams::Ssl3MasterKeyDerive(p)) => {
            Ok(Some(v1_proto::mechanism::Params::Ssl3MasterKeyDeriveParams(p.to_wire_v1())))
        }
        Some(CkMechanismParams::Tls12MasterKeyDerive(p)) => {
            Ok(Some(v1_proto::mechanism::Params::Tls12MasterKeyDeriveParams(p.to_wire_v1())))
        }
        Some(CkMechanismParams::Tls12ExtendedMasterKeyDerive(p)) => Ok(Some(
            v1_proto::mechanism::Params::Tls12ExtendedMasterKeyDeriveParams(p.to_wire_v1()),
        )),
        Some(CkMechanismParams::Ssl3KeyMat(p)) => {
            Ok(Some(v1_proto::mechanism::Params::Ssl3KeyMatParams(p.to_wire_v1())))
        }
        Some(CkMechanismParams::WtlsMasterKeyDerive(p)) => {
            Ok(Some(v1_proto::mechanism::Params::WtlsMasterKeyDeriveParams(p.to_wire_v1())))
        }
        Some(CkMechanismParams::WtlsPrf(p)) => {
            Ok(Some(v1_proto::mechanism::Params::WtlsPrfParams(p.to_wire_v1())))
        }
        Some(CkMechanismParams::WtlsKeyMat(p)) => {
            Ok(Some(v1_proto::mechanism::Params::WtlsKeyMatParams(p.to_wire_v1())))
        }
        // Fallible tail families keep inline arms (see `ToWireV1` docs).
        Some(CkMechanismParams::Otp(p)) => {
            let (params, params_null_count) =
                pointer_array_to_wire(&p.params_presence, |item: &OtpParam| Ok(item.to_wire_v1()))?;
            Ok(Some(v1_proto::mechanism::Params::OtpParams(v1_proto::OtpParams {
                params,
                params_null_count,
            })))
        }
        Some(CkMechanismParams::Kip(p)) => {
            let (seed, seed_null_len) = pointer_to_wire(&p.seed_presence);
            // A NULL nested mechanism rides `mechanism_null` with NO
            // nested message; a present one encodes under the negotiated
            // capability (v1-in-v1: a nested SP800-108 NULL template
            // needs its own v1 envelope — nesting v0 would conflate it).
            let mechanism = p
                .mechanism
                .as_deref()
                .map(|m| {
                    to_wire_with_transport_version(m, MECHANISM_PARAMETER_TRANSPORT_VERSION)
                        .map(Box::new)
                })
                .transpose()?;
            Ok(Some(v1_proto::mechanism::Params::KipParams(Box::new(v1_proto::KipParams {
                mechanism,
                key_handle: p.key_handle.0,
                seed,
                mechanism_null: null_bit_to_wire(p.mechanism.is_none()),
                seed_null_len,
            }))))
        }
        Some(CkMechanismParams::Sp800108Kdf(p)) => {
            let (data_params, data_params_null_count) =
                pointer_array_to_wire(&p.data_params_presence, |item: &PrfDataParam| {
                    Ok(item.to_wire_v1())
                })?;
            let (additional_derived_keys, additional_derived_keys_null_count) =
                pointer_array_to_wire(
                    &p.additional_derived_keys_presence,
                    advanced_params::sp800_108_derived_key_to_wire_v1,
                )?;
            Ok(Some(v1_proto::mechanism::Params::Sp800108KdfParams(v1_proto::Sp800108KdfParams {
                prf_type: p.prf_type.0,
                data_params,
                additional_derived_keys,
                data_params_null_count,
                additional_derived_keys_null_count,
            })))
        }
        Some(CkMechanismParams::Sp800108FeedbackKdf(p)) => {
            let (data_params, data_params_null_count) =
                pointer_array_to_wire(&p.data_params_presence, |item: &PrfDataParam| {
                    Ok(item.to_wire_v1())
                })?;
            let (iv, iv_null_len) = pointer_to_wire(&p.iv_presence);
            let (additional_derived_keys, additional_derived_keys_null_count) =
                pointer_array_to_wire(
                    &p.additional_derived_keys_presence,
                    advanced_params::sp800_108_derived_key_to_wire_v1,
                )?;
            Ok(Some(v1_proto::mechanism::Params::Sp800108FeedbackKdfParams(
                v1_proto::Sp800108FeedbackKdfParams {
                    prf_type: p.prf_type.0,
                    data_params,
                    iv,
                    additional_derived_keys,
                    data_params_null_count,
                    iv_null_len,
                    additional_derived_keys_null_count,
                },
            )))
        }
        // Non-tail variants fall back to the identical legacy encode.
        _ => Ok(None),
    }
}

/// Map a wire `MechanismParamAbi` value to the domain ABI: known values
/// map directly; `UNSPECIFIED`/unrecognized values thread through as
/// `None` (transport validation rejects them — validation owns the ABI
/// match, conversion only threads).
fn wire_abi_to_domain(abi: i32) -> Option<ParamAbi> {
    match v1_proto::MechanismParamAbi::try_from(abi).ok()? {
        v1_proto::MechanismParamAbi::Unspecified => None,
        v1_proto::MechanismParamAbi::Lp64NativeLe => Some(ParamAbi::Lp64NativeLe),
        v1_proto::MechanismParamAbi::Ilp32NativeLe => Some(ParamAbi::Ilp32NativeLe),
        v1_proto::MechanismParamAbi::Llp64Packed1Le => Some(ParamAbi::Llp64Packed1Le),
    }
}

/// Map a domain ABI back to the wire: `None` re-encodes as `UNSPECIFIED`
/// (faithful round-trip of an unknown/unspecified sender ABI).
fn domain_abi_to_wire(abi: Option<ParamAbi>) -> i32 {
    match abi {
        None => v1_proto::MechanismParamAbi::Unspecified as i32,
        Some(ParamAbi::Lp64NativeLe) => v1_proto::MechanismParamAbi::Lp64NativeLe as i32,
        Some(ParamAbi::Ilp32NativeLe) => v1_proto::MechanismParamAbi::Ilp32NativeLe as i32,
        Some(ParamAbi::Llp64Packed1Le) => v1_proto::MechanismParamAbi::Llp64Packed1Le as i32,
    }
}

/// Decode a v1 Flat member: valid only with version 1 (S2 §3), with the
/// materialized bytes exactly the declared extent.
fn flat_from_wire(p: &v1_proto::FlatMechanismParams, version: u32) -> Result<FlatParams, CkRv> {
    if version < MECHANISM_PARAMETER_TRANSPORT_VERSION {
        // Flat with a legacy stamp is contradictory metadata (R6-pinned).
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    if version > MECHANISM_PARAMETER_TRANSPORT_VERSION {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    let declared = usize::try_from(p.declared_len).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    if p.data.len() != declared {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    Ok(FlatParams {
        bytes: SecretBytes::copy_from_slice(&p.data),
        declared_len: p.declared_len,
        source_abi: wire_abi_to_domain(p.source_abi),
        fingerprint: p.shape_layout_fingerprint,
        version,
    })
}

/// Decode a v1 Null member: valid only with version 1 (S2 §3); no bytes,
/// so neither the cap nor length equality applies at decode.
fn null_from_wire(
    p: &v1_proto::NullMechanismParams,
    version: u32,
) -> Result<CkMechanismParams, CkRv> {
    if version < MECHANISM_PARAMETER_TRANSPORT_VERSION {
        // Null with a legacy stamp is contradictory metadata (R6-pinned).
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    if version > MECHANISM_PARAMETER_TRANSPORT_VERSION {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    Ok(CkMechanismParams::Null { declared_len: p.declared_len, version })
}

/// Whether a decoded oneof member carries any SET legacy `*_null` bool
/// (S2 §3 NULL-bool reconciliation: v1 is presence-only, so a v1 decoder
/// rejects any set legacy bool as contradictory metadata). Covers every
/// legacy bool site in the classic conversion, including the nested
/// RSA-AES-wrap OAEP params. Nested `Mechanism` messages (ECIES) recurse
/// through the same entry point, so their bools are gated per message.
fn has_set_legacy_null_bool(params: &Option<v1_proto::mechanism::Params>) -> bool {
    match params {
        Some(v1_proto::mechanism::Params::RsaPkcsOaepParams(p)) => p.source_null,
        Some(v1_proto::mechanism::Params::GcmParams(p)) => p.iv_null || p.aad_null,
        Some(v1_proto::mechanism::Params::CcmParams(p)) => p.nonce_null || p.aad_null,
        Some(v1_proto::mechanism::Params::RsaAesKeyWrapParams(p)) => {
            p.oaep_params.as_ref().is_some_and(|o| o.source_null)
        }
        _ => false,
    }
}

impl TryFrom<&v1_proto::Mechanism> for CkMechanism {
    type Error = CkRv;

    fn try_from(m: &v1_proto::Mechanism) -> Result<Self, Self::Error> {
        let version = m.parameter_encoding_version;
        match &m.params {
            // Unencoded messages stay version-blind (R6-pinned): nothing to
            // misread in an absent oneof, and legacy Raw fails closed later
            // at transport validation uniformly across versions.
            None | Some(v1_proto::mechanism::Params::RawMechanismParams(_)) => {}
            Some(_) => {
                // S2 §3: a per-message version newer than this daemon on an
                // encoded member is FUNCTION_NOT_SUPPORTED pre-entry. (R6
                // pinned version-blindness as current behavior with "R9 adds
                // v1 enforcement" — this is that enforcement.)
                if version > MECHANISM_PARAMETER_TRANSPORT_VERSION {
                    return Err(CkRv::FUNCTION_NOT_SUPPORTED);
                }
                // S2 §3 NULL-bool reconciliation (TODO(R9) in the R6
                // contradictory-metadata vectors).
                if version != 0 && has_set_legacy_null_bool(&m.params) {
                    return Err(CkRv::MECHANISM_PARAM_INVALID);
                }
            }
        }
        let params = match &m.params {
            None => None,
            Some(v1_proto::mechanism::Params::RsaPkcsPssParams(p)) => {
                Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
                    hash_alg: CkMechanismType(p.hash_alg),
                    mgf: CkMgf(p.mgf),
                    salt_len: p.salt_len,
                }))
            }
            Some(v1_proto::mechanism::Params::RsaPkcsOaepParams(p)) => {
                Some(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
                    hash_alg: CkMechanismType(p.hash_alg),
                    mgf: CkMgf(p.mgf),
                    source: CkOaepSource(p.source),
                    source_data_presence: pointer_from_wire_legacy(
                        &p.source_data,
                        p.source_data_null_len,
                        p.source_null,
                        version,
                    )?,
                }))
            }
            Some(v1_proto::mechanism::Params::GcmParams(p)) => {
                Some(CkMechanismParams::Gcm(GcmParams {
                    iv_bits: p.iv_bits,
                    iv_buffer_len: p.iv_buffer_len,
                    tag_bits: p.tag_bits,
                    iv_presence: pointer_from_wire_legacy(
                        &p.iv,
                        p.iv_null_len,
                        p.iv_null,
                        version,
                    )?,
                    aad_presence: pointer_from_wire_legacy(
                        &p.aad,
                        p.aad_null_len,
                        p.aad_null,
                        version,
                    )?,
                }))
            }
            Some(v1_proto::mechanism::Params::Ecdh1DeriveParams(p)) => {
                let mut shared_data_presence =
                    pointer_from_wire(&p.shared_data, p.shared_data_null_len, version)?;
                // v0 compat: OASIS mandates NULL shared data when the KDF is
                // CKD_NULL (CK_ECDH1_DERIVE_PARAMS: with CKD_NULL, pSharedData
                // MUST be NULL and ulSharedDataLen zero), and the v0 wire
                // carries no null_len for ECDH1 — so `v0 + CKD_NULL + empty`
                // is unambiguous NULL, canonicalized here. Explicit v1
                // presence always wins (the v1 flip is R23's).
                if version == 0 && p.kdf == CkKdf::NULL.0 && p.shared_data.is_empty() {
                    shared_data_presence = PointerBytes::null_len(0);
                }
                Some(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
                    kdf: CkKdf(p.kdf),
                    shared_data_presence,
                    public_data_presence: pointer_from_wire(
                        &p.public_data,
                        p.public_data_null_len,
                        version,
                    )?,
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
                Some(CkMechanismParams::Xeddsa(XeddsaParams { hash: CkMechanismType(p.hash) }))
            }
            Some(v1_proto::mechanism::Params::TlsMacParams(p)) => {
                Some(CkMechanismParams::TlsMac(TlsMacParams {
                    prf_hash_mechanism: CkMechanismType(p.prf_hash_mechanism),
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
                    iv_presence: pointer_from_wire(&p.iv, p.iv_null_len, version)?,
                }))
            }
            // CBC encrypt data
            Some(v1_proto::mechanism::Params::AesCbcEncryptDataParams(p)) => {
                Some(CkMechanismParams::AesCbcEncryptData(AesCbcEncryptDataParams {
                    iv: p.iv.clone(),
                    data_presence: pointer_from_wire(&p.data, p.data_null_len, version)?,
                }))
            }
            Some(v1_proto::mechanism::Params::DesCbcEncryptDataParams(p)) => {
                Some(CkMechanismParams::DesCbcEncryptData(DesCbcEncryptDataParams {
                    iv: p.iv.clone(),
                    data_presence: pointer_from_wire(&p.data, p.data_null_len, version)?,
                }))
            }
            Some(v1_proto::mechanism::Params::AriaCbcEncryptDataParams(p)) => {
                Some(CkMechanismParams::AriaCbcEncryptData(AriaCbcEncryptDataParams {
                    iv: p.iv.clone(),
                    data_presence: pointer_from_wire(&p.data, p.data_null_len, version)?,
                }))
            }
            Some(v1_proto::mechanism::Params::CamelliaCbcEncryptDataParams(p)) => {
                Some(CkMechanismParams::CamelliaCbcEncryptData(CamelliaCbcEncryptDataParams {
                    iv: p.iv.clone(),
                    data_presence: pointer_from_wire(&p.data, p.data_null_len, version)?,
                }))
            }
            Some(v1_proto::mechanism::Params::SeedCbcEncryptDataParams(p)) => {
                Some(CkMechanismParams::SeedCbcEncryptData(SeedCbcEncryptDataParams {
                    iv: p.iv.clone(),
                    data_presence: pointer_from_wire(&p.data, p.data_null_len, version)?,
                }))
            }
            // AEAD
            Some(v1_proto::mechanism::Params::CcmParams(p)) => {
                Some(CkMechanismParams::Ccm(CcmParams {
                    data_len: p.data_len,
                    mac_len: p.mac_len,
                    nonce_presence: pointer_from_wire_legacy(
                        &p.nonce,
                        p.nonce_null_len,
                        p.nonce_null,
                        version,
                    )?,
                    aad_presence: pointer_from_wire_legacy(
                        &p.aad,
                        p.aad_null_len,
                        p.aad_null,
                        version,
                    )?,
                }))
            }
            Some(v1_proto::mechanism::Params::Chacha20Params(p)) => {
                Some(CkMechanismParams::ChaCha20(ChaCha20Params {
                    block_counter_bits: p.block_counter_bits,
                    nonce_bits: p.nonce_bits,
                    block_counter_presence: pointer_from_wire(
                        &p.block_counter,
                        p.block_counter_null_len,
                        version,
                    )?,
                    nonce_presence: pointer_from_wire(&p.nonce, p.nonce_null_len, version)?,
                }))
            }
            Some(v1_proto::mechanism::Params::Salsa20Params(p)) => {
                Some(CkMechanismParams::Salsa20(Salsa20Params {
                    nonce_bits: p.nonce_bits,
                    block_counter_presence: pointer_from_wire(
                        &p.block_counter,
                        p.block_counter_null_len,
                        version,
                    )?,
                    nonce_presence: pointer_from_wire(&p.nonce, p.nonce_null_len, version)?,
                }))
            }
            Some(v1_proto::mechanism::Params::Salsa20Chacha20Poly1305Params(p)) => {
                Some(CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
                    nonce_presence: pointer_from_wire(&p.nonce, p.nonce_null_len, version)?,
                    aad_presence: pointer_from_wire(&p.aad, p.aad_null_len, version)?,
                }))
            }
            Some(v1_proto::mechanism::Params::GcmWrapParams(p)) => {
                Some(CkMechanismParams::GcmWrap(GcmWrapParams {
                    iv_fixed_bits: p.iv_fixed_bits,
                    iv_generator: CkGeneratorFunction(p.iv_generator),
                    tag_bits: p.tag_bits,
                    iv_presence: pointer_from_wire(&p.iv, p.iv_null_len, version)?,
                    aad_presence: pointer_from_wire(&p.aad, p.aad_null_len, version)?,
                }))
            }
            Some(v1_proto::mechanism::Params::CcmWrapParams(p)) => {
                Some(CkMechanismParams::CcmWrap(CcmWrapParams {
                    data_len: p.data_len,
                    nonce_fixed_bits: p.nonce_fixed_bits,
                    nonce_generator: CkGeneratorFunction(p.nonce_generator),
                    mac_len: p.mac_len,
                    nonce_presence: pointer_from_wire(&p.nonce, p.nonce_null_len, version)?,
                    aad_presence: pointer_from_wire(&p.aad, p.aad_null_len, version)?,
                }))
            }
            // Key derivation
            Some(v1_proto::mechanism::Params::Ecdh2DeriveParams(p)) => {
                Some(CkMechanismParams::Ecdh2Derive(Ecdh2DeriveParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::EcmqvDeriveParams(p)) => {
                Some(CkMechanismParams::EcmqvDerive(EcmqvDeriveParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::X942Dh1DeriveParams(p)) => {
                Some(CkMechanismParams::X942Dh1Derive(X942Dh1DeriveParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::X942Dh2DeriveParams(p)) => {
                Some(CkMechanismParams::X942Dh2Derive(X942Dh2DeriveParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::X942MqvDeriveParams(p)) => {
                Some(CkMechanismParams::X942MqvDerive(X942MqvDeriveParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::HkdfParams(p)) => {
                Some(CkMechanismParams::Hkdf(HkdfParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::EddsaParams(p)) => {
                Some(CkMechanismParams::Eddsa(EddsaParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::Gostr3410DeriveParams(p)) => Some(
                CkMechanismParams::Gostr3410Derive(Gostr3410DeriveParams::from_wire(p, version)?),
            ),
            Some(v1_proto::mechanism::Params::KeaDeriveParams(p)) => {
                Some(CkMechanismParams::KeaDerive(KeaDeriveParams::from_wire(p, version)?))
            }
            // Key wrapping
            Some(v1_proto::mechanism::Params::EcdhAesKeyWrapParams(p)) => Some(
                CkMechanismParams::EcdhAesKeyWrap(EcdhAesKeyWrapParams::from_wire(p, version)?),
            ),
            Some(v1_proto::mechanism::Params::RsaAesKeyWrapParams(p)) => {
                Some(CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::Gostr3410KeyWrapParams(p)) => Some(
                CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams::from_wire(p, version)?),
            ),
            Some(v1_proto::mechanism::Params::KeyWrapSetOaepParams(p)) => Some(
                CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams::from_wire(p, version)?),
            ),
            // Password-based encryption
            Some(v1_proto::mechanism::Params::PbeParams(p)) => {
                Some(CkMechanismParams::Pbe(PbeParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::Pkcs5Pbkd2Params(p)) => {
                Some(CkMechanismParams::Pkcs5Pbkd2(Pkcs5Pbkd2Params::from_wire(p, version)?))
            }
            // TLS/SSL
            Some(v1_proto::mechanism::Params::TlsPrfParams(p)) => {
                Some(CkMechanismParams::TlsPrf(TlsPrfParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::TlsKdfParams(p)) => {
                Some(CkMechanismParams::TlsKdf(TlsKdfParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::Ssl3MasterKeyDeriveParams(p)) => {
                Some(CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams::from_wire(
                    p, version,
                )?))
            }
            Some(v1_proto::mechanism::Params::Tls12MasterKeyDeriveParams(p)) => {
                Some(CkMechanismParams::Tls12MasterKeyDerive(
                    Tls12MasterKeyDeriveParams::from_wire(p, version)?,
                ))
            }
            Some(v1_proto::mechanism::Params::Tls12ExtendedMasterKeyDeriveParams(p)) => {
                Some(CkMechanismParams::Tls12ExtendedMasterKeyDerive(
                    Tls12ExtendedMasterKeyDeriveParams::from_wire(p, version)?,
                ))
            }
            Some(v1_proto::mechanism::Params::Ssl3KeyMatParams(p)) => {
                Some(CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::WtlsMasterKeyDeriveParams(p)) => {
                Some(CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams::from_wire(
                    p, version,
                )?))
            }
            Some(v1_proto::mechanism::Params::WtlsPrfParams(p)) => {
                Some(CkMechanismParams::WtlsPrf(WtlsPrfParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::WtlsKeyMatParams(p)) => {
                Some(CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams::from_wire(p, version)?))
            }
            // IKE/IPSec
            Some(v1_proto::mechanism::Params::IkePrfDeriveParams(p)) => {
                Some(CkMechanismParams::IkePrfDerive(IkePrfDeriveParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::Ike1PrfDeriveParams(p)) => {
                Some(CkMechanismParams::Ike1PrfDerive(Ike1PrfDeriveParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::Ike1ExtendedDeriveParams(p)) => {
                Some(CkMechanismParams::Ike1ExtendedDerive(Ike1ExtendedDeriveParams::from_wire(
                    p, version,
                )?))
            }
            Some(v1_proto::mechanism::Params::Ike2PrfPlusDeriveParams(p)) => {
                Some(CkMechanismParams::Ike2PrfPlusDerive(Ike2PrfPlusDeriveParams::from_wire(
                    p, version,
                )?))
            }
            // SP800-108 KDF
            Some(v1_proto::mechanism::Params::Sp800108KdfParams(p)) => {
                Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::Sp800108FeedbackKdfParams(p)) => {
                Some(CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams::from_wire(
                    p, version,
                )?))
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
                Some(CkMechanismParams::Otp(OtpParams::from_wire(p, version)?))
            }
            Some(v1_proto::mechanism::Params::KipParams(p)) => {
                Some(CkMechanismParams::Kip(KipParams::from_wire(p.as_ref(), version)?))
            }
            Some(v1_proto::mechanism::Params::CmsSigParams(p)) => {
                Some(CkMechanismParams::CmsSig(p.as_ref().try_into()?))
            }
            Some(v1_proto::mechanism::Params::SkipjackPrivateWrapParams(p)) => {
                Some(CkMechanismParams::SkipjackPrivateWrap(SkipjackPrivateWrapParams::from_wire(
                    p, version,
                )?))
            }
            Some(v1_proto::mechanism::Params::SkipjackRelayxParams(p)) => Some(
                CkMechanismParams::SkipjackRelayx(SkipjackRelayxParams::from_wire(p, version)?),
            ),
            // Generic / vendor parameter shapes
            Some(v1_proto::mechanism::Params::MacGeneralParams(p)) => {
                Some(CkMechanismParams::MacGeneral(MacGeneralParams { mac_length: p.mac_length }))
            }
            Some(v1_proto::mechanism::Params::ObjectHandleParam(p)) => {
                Some(CkMechanismParams::ObjectHandle(ObjectHandleParam {
                    handle: CkObjectHandle(p.handle),
                }))
            }
            Some(v1_proto::mechanism::Params::ExtractParams(p)) => {
                Some(CkMechanismParams::Extract(ExtractParams { bit_position: p.bit_position }))
            }
            Some(v1_proto::mechanism::Params::SignAdditionalContext(p)) => {
                Some(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                    hedge_variant: p.hedge_variant,
                    hash: CkMechanismType(p.hash),
                    context_presence: pointer_from_wire(&p.context, p.context_null_len, version)?,
                }))
            }
            Some(v1_proto::mechanism::Params::KmacParams(p)) => {
                Some(CkMechanismParams::Kmac(KmacParams {
                    key_handle: CkObjectHandle(p.key_handle),
                    mac_length: p.mac_length,
                    customization_string_presence: pointer_from_wire(
                        &p.customization_string,
                        p.customization_string_null_len,
                        version,
                    )?,
                }))
            }
            Some(v1_proto::mechanism::Params::MuGenParams(p)) => {
                Some(CkMechanismParams::MuGen(MuGenParams {
                    key_handle: CkObjectHandle(p.key_handle),
                    tr_presence: pointer_from_wire(&p.tr, p.tr_null_len, version)?,
                    context_presence: pointer_from_wire(&p.context, p.context_null_len, version)?,
                }))
            }
            Some(v1_proto::mechanism::Params::KeyDerivationStringData(p)) => {
                Some(CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
                    data_presence: pointer_from_wire(&p.data, p.data_null_len, version)?,
                }))
            }
            Some(v1_proto::mechanism::Params::RawMechanismParams(p)) => {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: SecretBytes::copy_from_slice(&p.data),
                }))
            }
            // Versioned representable parameters (S2 §3/§6; R9).
            Some(v1_proto::mechanism::Params::FlatMechanismParams(p)) => {
                Some(CkMechanismParams::Flat(flat_from_wire(p, m.parameter_encoding_version)?))
            }
            Some(v1_proto::mechanism::Params::NullMechanismParams(p)) => {
                Some(null_from_wire(p, m.parameter_encoding_version)?)
            }
            // Vendor-specific parameter shapes
            Some(v1_proto::mechanism::Params::EciesParams(p)) => {
                Some(CkMechanismParams::Ecies(p.as_ref().try_into()?))
            }
            Some(v1_proto::mechanism::Params::AesCmacKeyDerivationParams(p)) => {
                Some(CkMechanismParams::AesCmacKeyDerivation(
                    pkcs11_proxy_ng_types::AesCmacKeyDerivationParams {
                        context: SecretBytes::copy_from_slice(&p.context),
                        label: SecretBytes::copy_from_slice(&p.label),
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
                    secret_handle: CkObjectHandle(p.secret_handle),
                    shared_data: SecretBytes::copy_from_slice(&p.shared_data),
                    blob: SecretBytes::copy_from_slice(&p.blob),
                }))
            }
            Some(v1_proto::mechanism::Params::HdKeyDeriveParams(p)) => {
                Some(CkMechanismParams::HdKeyDerive(pkcs11_proxy_ng_types::HdKeyDeriveParams {
                    derive_type: p.derive_type,
                    child_key_index: p.child_key_index,
                    chain_code: SecretBytes::copy_from_slice(&p.chain_code),
                    version: p.version,
                }))
            }
            Some(v1_proto::mechanism::Params::VendorObjectExtractParams(p)) => {
                Some(CkMechanismParams::VendorObjectExtract(
                    pkcs11_proxy_ng_types::VendorObjectExtractParams {
                        format: p.format,
                        context: SecretBytes::copy_from_slice(&p.context),
                    },
                ))
            }
            Some(v1_proto::mechanism::Params::VendorObjectInsertParams(p)) => {
                Some(CkMechanismParams::VendorObjectInsert(
                    pkcs11_proxy_ng_types::VendorObjectInsertParams {
                        format: p.format,
                        context: SecretBytes::copy_from_slice(&p.context),
                        object_data: SecretBytes::copy_from_slice(&p.object_data),
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

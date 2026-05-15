//! Proto <-> Rust conversions for IKE/IPSec, SP800-108 KDF, Signal protocol,
//! and miscellaneous mechanism parameters.

use crate::pkcs11_proxy_ng::v1 as v1_proto;
use pkcs11_proxy_ng_types::{
    AesCmacKeyDerivationParams, CkMechanism, CkRv, CmsSigParams, DilithiumParams, EciesParams,
    HdKeyDeriveParams, Ike1ExtendedDeriveParams, Ike1PrfDeriveParams, Ike2PrfPlusDeriveParams,
    IkePrfDeriveParams, KipParams, KyberParams, OtpParam, OtpParams, PrfDataParam,
    SkipjackPrivateWrapParams, SkipjackRelayxParams, Sp800108FeedbackKdfParams, Sp800108KdfParams,
    VendorObjectExtractParams, VendorObjectInsertParams, X2RatchetInitializeParams,
    X2RatchetRespondParams, X3dhInitiateParams, X3dhRespondParams,
};

// ---------------------------------------------------------------------------
// IKE/IPSec: IkePrfDeriveParams
// ---------------------------------------------------------------------------

impl From<&IkePrfDeriveParams> for v1_proto::IkePrfDeriveParams {
    fn from(p: &IkePrfDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism,
            data_as_key: p.data_as_key,
            rekey: p.rekey,
            ni: p.ni.clone(),
            nr: p.nr.clone(),
            new_key_handle: p.new_key_handle,
        }
    }
}

impl From<&v1_proto::IkePrfDeriveParams> for IkePrfDeriveParams {
    fn from(p: &v1_proto::IkePrfDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism,
            data_as_key: p.data_as_key,
            rekey: p.rekey,
            ni: p.ni.clone(),
            nr: p.nr.clone(),
            new_key_handle: p.new_key_handle,
        }
    }
}

// ---------------------------------------------------------------------------
// IKE/IPSec: Ike1PrfDeriveParams
// ---------------------------------------------------------------------------

impl From<&Ike1PrfDeriveParams> for v1_proto::Ike1PrfDeriveParams {
    fn from(p: &Ike1PrfDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism,
            has_prev_key: p.has_prev_key,
            keygxy_handle: p.keygxy_handle,
            prev_key_handle: p.prev_key_handle,
            ckyi: p.ckyi.clone(),
            ckyr: p.ckyr.clone(),
            key_number: p.key_number,
        }
    }
}

impl From<&v1_proto::Ike1PrfDeriveParams> for Ike1PrfDeriveParams {
    fn from(p: &v1_proto::Ike1PrfDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism,
            has_prev_key: p.has_prev_key,
            keygxy_handle: p.keygxy_handle,
            prev_key_handle: p.prev_key_handle,
            ckyi: p.ckyi.clone(),
            ckyr: p.ckyr.clone(),
            key_number: p.key_number,
        }
    }
}

// ---------------------------------------------------------------------------
// IKE/IPSec: Ike1ExtendedDeriveParams
// ---------------------------------------------------------------------------

impl From<&Ike1ExtendedDeriveParams> for v1_proto::Ike1ExtendedDeriveParams {
    fn from(p: &Ike1ExtendedDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism,
            has_keygxy: p.has_keygxy,
            keygxy_handle: p.keygxy_handle,
            extra_data: p.extra_data.clone(),
        }
    }
}

impl From<&v1_proto::Ike1ExtendedDeriveParams> for Ike1ExtendedDeriveParams {
    fn from(p: &v1_proto::Ike1ExtendedDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism,
            has_keygxy: p.has_keygxy,
            keygxy_handle: p.keygxy_handle,
            extra_data: p.extra_data.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// IKE/IPSec: Ike2PrfPlusDeriveParams
// ---------------------------------------------------------------------------

impl From<&Ike2PrfPlusDeriveParams> for v1_proto::Ike2PrfPlusDeriveParams {
    fn from(p: &Ike2PrfPlusDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism,
            has_seed_key: p.has_seed_key,
            seed_key_handle: p.seed_key_handle,
            seed_data: p.seed_data.clone(),
        }
    }
}

impl From<&v1_proto::Ike2PrfPlusDeriveParams> for Ike2PrfPlusDeriveParams {
    fn from(p: &v1_proto::Ike2PrfPlusDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism,
            has_seed_key: p.has_seed_key,
            seed_key_handle: p.seed_key_handle,
            seed_data: p.seed_data.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// SP800-108: PrfDataParam helper
// ---------------------------------------------------------------------------

fn prf_data_to_proto(p: &PrfDataParam) -> v1_proto::PrfDataParam {
    v1_proto::PrfDataParam { r#type: p.type_, value: p.value.clone() }
}

fn prf_data_from_proto(p: &v1_proto::PrfDataParam) -> PrfDataParam {
    PrfDataParam { type_: p.r#type, value: p.value.clone() }
}

// ---------------------------------------------------------------------------
// SP800-108: Sp800108KdfParams
// ---------------------------------------------------------------------------

impl From<&Sp800108KdfParams> for v1_proto::Sp800108KdfParams {
    fn from(p: &Sp800108KdfParams) -> Self {
        Self {
            prf_type: p.prf_type,
            data_params: p.data_params.iter().map(prf_data_to_proto).collect(),
        }
    }
}

impl From<&v1_proto::Sp800108KdfParams> for Sp800108KdfParams {
    fn from(p: &v1_proto::Sp800108KdfParams) -> Self {
        Self {
            prf_type: p.prf_type,
            data_params: p.data_params.iter().map(prf_data_from_proto).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// SP800-108: Sp800108FeedbackKdfParams
// ---------------------------------------------------------------------------

impl From<&Sp800108FeedbackKdfParams> for v1_proto::Sp800108FeedbackKdfParams {
    fn from(p: &Sp800108FeedbackKdfParams) -> Self {
        Self {
            prf_type: p.prf_type,
            data_params: p.data_params.iter().map(prf_data_to_proto).collect(),
            iv: p.iv.clone(),
        }
    }
}

impl From<&v1_proto::Sp800108FeedbackKdfParams> for Sp800108FeedbackKdfParams {
    fn from(p: &v1_proto::Sp800108FeedbackKdfParams) -> Self {
        Self {
            prf_type: p.prf_type,
            data_params: p.data_params.iter().map(prf_data_from_proto).collect(),
            iv: p.iv.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Signal: X3dhInitiateParams
// ---------------------------------------------------------------------------

impl From<&X3dhInitiateParams> for v1_proto::X3dhInitiateParams {
    fn from(p: &X3dhInitiateParams) -> Self {
        Self {
            kdf: p.kdf,
            peer_identity_handle: p.peer_identity_handle,
            peer_prekey_handle: p.peer_prekey_handle,
            prekey_signature: p.prekey_signature.clone(),
            onetime_key_handle: p.onetime_key_handle,
            own_identity_handle: p.own_identity_handle,
            own_ephemeral_handle: p.own_ephemeral_handle,
        }
    }
}

impl From<&v1_proto::X3dhInitiateParams> for X3dhInitiateParams {
    fn from(p: &v1_proto::X3dhInitiateParams) -> Self {
        Self {
            kdf: p.kdf,
            peer_identity_handle: p.peer_identity_handle,
            peer_prekey_handle: p.peer_prekey_handle,
            prekey_signature: p.prekey_signature.clone(),
            onetime_key_handle: p.onetime_key_handle,
            own_identity_handle: p.own_identity_handle,
            own_ephemeral_handle: p.own_ephemeral_handle,
        }
    }
}

// ---------------------------------------------------------------------------
// Signal: X3dhRespondParams
// ---------------------------------------------------------------------------

impl From<&X3dhRespondParams> for v1_proto::X3dhRespondParams {
    fn from(p: &X3dhRespondParams) -> Self {
        Self {
            kdf: p.kdf,
            identity_handle: p.identity_handle,
            prekey_handle: p.prekey_handle,
            onetime_key_handle: p.onetime_key_handle,
            initiator_identity_handle: p.initiator_identity_handle,
            initiator_ephemeral_handle: p.initiator_ephemeral_handle,
        }
    }
}

impl From<&v1_proto::X3dhRespondParams> for X3dhRespondParams {
    fn from(p: &v1_proto::X3dhRespondParams) -> Self {
        Self {
            kdf: p.kdf,
            identity_handle: p.identity_handle,
            prekey_handle: p.prekey_handle,
            onetime_key_handle: p.onetime_key_handle,
            initiator_identity_handle: p.initiator_identity_handle,
            initiator_ephemeral_handle: p.initiator_ephemeral_handle,
        }
    }
}

// ---------------------------------------------------------------------------
// Signal: X2RatchetInitializeParams
// ---------------------------------------------------------------------------

impl From<&X2RatchetInitializeParams> for v1_proto::X2RatchetInitializeParams {
    fn from(p: &X2RatchetInitializeParams) -> Self {
        Self {
            sk: p.sk.clone(),
            peer_public_prekey_handle: p.peer_public_prekey_handle,
            peer_public_identity_handle: p.peer_public_identity_handle,
            own_public_identity_handle: p.own_public_identity_handle,
            encrypted_header: p.encrypted_header,
            curve: p.curve,
            aead_mechanism: p.aead_mechanism,
            kdf_mechanism: p.kdf_mechanism,
        }
    }
}

impl From<&v1_proto::X2RatchetInitializeParams> for X2RatchetInitializeParams {
    fn from(p: &v1_proto::X2RatchetInitializeParams) -> Self {
        Self {
            sk: p.sk.clone(),
            peer_public_prekey_handle: p.peer_public_prekey_handle,
            peer_public_identity_handle: p.peer_public_identity_handle,
            own_public_identity_handle: p.own_public_identity_handle,
            encrypted_header: p.encrypted_header,
            curve: p.curve,
            aead_mechanism: p.aead_mechanism,
            kdf_mechanism: p.kdf_mechanism,
        }
    }
}

// ---------------------------------------------------------------------------
// Signal: X2RatchetRespondParams
// ---------------------------------------------------------------------------

impl From<&X2RatchetRespondParams> for v1_proto::X2RatchetRespondParams {
    fn from(p: &X2RatchetRespondParams) -> Self {
        Self {
            sk: p.sk.clone(),
            own_prekey_handle: p.own_prekey_handle,
            initiator_identity_handle: p.initiator_identity_handle,
            own_identity_handle: p.own_identity_handle,
            encrypted_header: p.encrypted_header,
            curve: p.curve,
            aead_mechanism: p.aead_mechanism,
            kdf_mechanism: p.kdf_mechanism,
        }
    }
}

impl From<&v1_proto::X2RatchetRespondParams> for X2RatchetRespondParams {
    fn from(p: &v1_proto::X2RatchetRespondParams) -> Self {
        Self {
            sk: p.sk.clone(),
            own_prekey_handle: p.own_prekey_handle,
            initiator_identity_handle: p.initiator_identity_handle,
            own_identity_handle: p.own_identity_handle,
            encrypted_header: p.encrypted_header,
            curve: p.curve,
            aead_mechanism: p.aead_mechanism,
            kdf_mechanism: p.kdf_mechanism,
        }
    }
}

// ---------------------------------------------------------------------------
// Misc: OtpParams
// ---------------------------------------------------------------------------

impl From<&OtpParams> for v1_proto::OtpParams {
    fn from(p: &OtpParams) -> Self {
        Self {
            params: p
                .params
                .iter()
                .map(|op| v1_proto::OtpParam { r#type: op.type_, value: op.value.clone() })
                .collect(),
        }
    }
}

impl From<&v1_proto::OtpParams> for OtpParams {
    fn from(p: &v1_proto::OtpParams) -> Self {
        Self {
            params: p
                .params
                .iter()
                .map(|op| OtpParam { type_: op.r#type, value: op.value.clone() })
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Misc: KipParams (nested Mechanism)
// ---------------------------------------------------------------------------

/// Convert a Rust `CkMechanism` reference to a proto `Mechanism`.
fn mechanism_to_proto(m: &CkMechanism) -> v1_proto::Mechanism {
    m.into()
}

/// Convert a required boxed proto `Mechanism` to a Rust `CkMechanism`.
/// Prost uses `Box<T>` for recursive/nested message fields to avoid infinite
/// struct size; absence still means the nested mechanism is malformed.
fn required_mechanism_from_boxed_option(
    m: &Option<Box<v1_proto::Mechanism>>,
) -> Result<CkMechanism, CkRv> {
    let mechanism = m.as_deref().ok_or(CkRv::MECHANISM_PARAM_INVALID)?;
    CkMechanism::try_from(mechanism)
}

impl From<&KipParams> for v1_proto::KipParams {
    fn from(p: &KipParams) -> Self {
        Self {
            mechanism: Some(Box::new(mechanism_to_proto(&p.mechanism))),
            key_handle: p.key_handle,
            seed: p.seed.clone(),
        }
    }
}

impl TryFrom<&v1_proto::KipParams> for KipParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::KipParams) -> Result<Self, Self::Error> {
        Ok(Self {
            mechanism: Box::new(required_mechanism_from_boxed_option(&p.mechanism)?),
            key_handle: p.key_handle,
            seed: p.seed.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Misc: CmsSigParams (nested Mechanisms)
// ---------------------------------------------------------------------------

impl From<&CmsSigParams> for v1_proto::CmsSigParams {
    fn from(p: &CmsSigParams) -> Self {
        Self {
            certificate_handle: p.certificate_handle,
            signing_mechanism: Some(Box::new(mechanism_to_proto(&p.signing_mechanism))),
            digest_mechanism: Some(Box::new(mechanism_to_proto(&p.digest_mechanism))),
            content_type: p.content_type.clone(),
            requested_attributes: p.requested_attributes.clone(),
            required_attributes: p.required_attributes.clone(),
        }
    }
}

impl TryFrom<&v1_proto::CmsSigParams> for CmsSigParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::CmsSigParams) -> Result<Self, Self::Error> {
        Ok(Self {
            certificate_handle: p.certificate_handle,
            signing_mechanism: Box::new(required_mechanism_from_boxed_option(
                &p.signing_mechanism,
            )?),
            digest_mechanism: Box::new(required_mechanism_from_boxed_option(&p.digest_mechanism)?),
            content_type: p.content_type.clone(),
            requested_attributes: p.requested_attributes.clone(),
            required_attributes: p.required_attributes.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Misc: SkipjackPrivateWrapParams
// ---------------------------------------------------------------------------

impl From<&SkipjackPrivateWrapParams> for v1_proto::SkipjackPrivateWrapParams {
    fn from(p: &SkipjackPrivateWrapParams) -> Self {
        Self {
            password: p.password.clone(),
            public_data: p.public_data.clone(),
            password_length: p.password_length,
            random_a: p.random_a.clone(),
            prime_p: p.prime_p.clone(),
            base_g: p.base_g.clone(),
            subprime_q: p.subprime_q.clone(),
        }
    }
}

impl From<&v1_proto::SkipjackPrivateWrapParams> for SkipjackPrivateWrapParams {
    fn from(p: &v1_proto::SkipjackPrivateWrapParams) -> Self {
        Self {
            password: p.password.clone(),
            public_data: p.public_data.clone(),
            password_length: p.password_length,
            random_a: p.random_a.clone(),
            prime_p: p.prime_p.clone(),
            base_g: p.base_g.clone(),
            subprime_q: p.subprime_q.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Misc: SkipjackRelayxParams
// ---------------------------------------------------------------------------

impl From<&SkipjackRelayxParams> for v1_proto::SkipjackRelayxParams {
    fn from(p: &SkipjackRelayxParams) -> Self {
        Self {
            old_wrapped_x: p.old_wrapped_x.clone(),
            old_password: p.old_password.clone(),
            old_public_data: p.old_public_data.clone(),
            old_random_a: p.old_random_a.clone(),
            new_password: p.new_password.clone(),
            new_public_data: p.new_public_data.clone(),
            new_random_a: p.new_random_a.clone(),
        }
    }
}

impl From<&v1_proto::SkipjackRelayxParams> for SkipjackRelayxParams {
    fn from(p: &v1_proto::SkipjackRelayxParams) -> Self {
        Self {
            old_wrapped_x: p.old_wrapped_x.clone(),
            old_password: p.old_password.clone(),
            old_public_data: p.old_public_data.clone(),
            old_random_a: p.old_random_a.clone(),
            new_password: p.new_password.clone(),
            new_public_data: p.new_public_data.clone(),
            new_random_a: p.new_random_a.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Vendor: EciesParams (nested Mechanisms)
// ---------------------------------------------------------------------------

impl From<&EciesParams> for v1_proto::EciesParams {
    fn from(p: &EciesParams) -> Self {
        Self {
            derivation_mechanism: Some(Box::new(mechanism_to_proto(&p.derivation_mechanism))),
            encryption_mechanism: Some(Box::new(mechanism_to_proto(&p.encryption_mechanism))),
            mac_mechanism: Some(Box::new(mechanism_to_proto(&p.mac_mechanism))),
            shared_data: p.shared_data.clone(),
        }
    }
}

impl TryFrom<&v1_proto::EciesParams> for EciesParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::EciesParams) -> Result<Self, Self::Error> {
        Ok(Self {
            derivation_mechanism: Box::new(required_mechanism_from_boxed_option(
                &p.derivation_mechanism,
            )?),
            encryption_mechanism: Box::new(required_mechanism_from_boxed_option(
                &p.encryption_mechanism,
            )?),
            mac_mechanism: Box::new(required_mechanism_from_boxed_option(&p.mac_mechanism)?),
            shared_data: p.shared_data.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Vendor: AesCmacKeyDerivationParams
// ---------------------------------------------------------------------------

impl From<&AesCmacKeyDerivationParams> for v1_proto::AesCmacKeyDerivationParams {
    fn from(p: &AesCmacKeyDerivationParams) -> Self {
        Self { context: p.context.clone(), label: p.label.clone() }
    }
}

impl From<&v1_proto::AesCmacKeyDerivationParams> for AesCmacKeyDerivationParams {
    fn from(p: &v1_proto::AesCmacKeyDerivationParams) -> Self {
        Self { context: p.context.clone(), label: p.label.clone() }
    }
}

// ---------------------------------------------------------------------------
// Vendor: DilithiumParams
// ---------------------------------------------------------------------------

impl From<&DilithiumParams> for v1_proto::DilithiumParams {
    fn from(p: &DilithiumParams) -> Self {
        Self { version: p.version, mode: p.mode }
    }
}

impl From<&v1_proto::DilithiumParams> for DilithiumParams {
    fn from(p: &v1_proto::DilithiumParams) -> Self {
        Self { version: p.version, mode: p.mode }
    }
}

// ---------------------------------------------------------------------------
// Vendor: KyberParams
// ---------------------------------------------------------------------------

impl From<&KyberParams> for v1_proto::KyberParams {
    fn from(p: &KyberParams) -> Self {
        Self {
            version: p.version,
            mode: p.mode,
            secret_handle: p.secret_handle,
            shared_data: p.shared_data.clone(),
            blob: p.blob.clone(),
        }
    }
}

impl From<&v1_proto::KyberParams> for KyberParams {
    fn from(p: &v1_proto::KyberParams) -> Self {
        Self {
            version: p.version,
            mode: p.mode,
            secret_handle: p.secret_handle,
            shared_data: p.shared_data.clone(),
            blob: p.blob.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Vendor: HdKeyDeriveParams
// ---------------------------------------------------------------------------

impl From<&HdKeyDeriveParams> for v1_proto::HdKeyDeriveParams {
    fn from(p: &HdKeyDeriveParams) -> Self {
        Self {
            derive_type: p.derive_type,
            child_key_index: p.child_key_index,
            chain_code: p.chain_code.clone(),
            version: p.version,
        }
    }
}

impl From<&v1_proto::HdKeyDeriveParams> for HdKeyDeriveParams {
    fn from(p: &v1_proto::HdKeyDeriveParams) -> Self {
        Self {
            derive_type: p.derive_type,
            child_key_index: p.child_key_index,
            chain_code: p.chain_code.clone(),
            version: p.version,
        }
    }
}

// ---------------------------------------------------------------------------
// Vendor: VendorObjectExtractParams
// ---------------------------------------------------------------------------

impl From<&VendorObjectExtractParams> for v1_proto::VendorObjectExtractParams {
    fn from(p: &VendorObjectExtractParams) -> Self {
        Self { format: p.format, context: p.context.clone() }
    }
}

impl From<&v1_proto::VendorObjectExtractParams> for VendorObjectExtractParams {
    fn from(p: &v1_proto::VendorObjectExtractParams) -> Self {
        Self { format: p.format, context: p.context.clone() }
    }
}

// ---------------------------------------------------------------------------
// Vendor: VendorObjectInsertParams
// ---------------------------------------------------------------------------

impl From<&VendorObjectInsertParams> for v1_proto::VendorObjectInsertParams {
    fn from(p: &VendorObjectInsertParams) -> Self {
        Self { format: p.format, context: p.context.clone(), object_data: p.object_data.clone() }
    }
}

impl From<&v1_proto::VendorObjectInsertParams> for VendorObjectInsertParams {
    fn from(p: &v1_proto::VendorObjectInsertParams) -> Self {
        Self { format: p.format, context: p.context.clone(), object_data: p.object_data.clone() }
    }
}

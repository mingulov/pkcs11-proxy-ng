//! Proto <-> Rust conversions for IKE/IPSec, SP800-108 KDF, Signal protocol,
//! and miscellaneous mechanism parameters.

use crate::pkcs11_proxy_ng::v1 as v1_proto;
use crate::pkcs11_proxy_ng::v1::sp800108_attribute;
// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use crate::secret_boundary::{secret_to_plain, secret_to_plain_string};
use pkcs11_proxy_ng_types::{
    AesCmacKeyDerivationParams, CkAttribute, CkAttributeType, CkAttributeValue, CkMechanism, CkRv,
    CmsSigParams, DilithiumParams, EciesParams, HdKeyDeriveParams, Ike1ExtendedDeriveParams,
    Ike1PrfDeriveParams, Ike2PrfPlusDeriveParams, IkePrfDeriveParams, KipParams, KyberParams,
    OtpParam, OtpParams, PrfDataParam, SecretBytes, SkipjackPrivateWrapParams,
    SkipjackRelayxParams, Sp800108DerivedKey, Sp800108FeedbackKdfParams, Sp800108KdfParams,
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
            ni: secret_to_plain(&p.ni),
            nr: secret_to_plain(&p.nr),
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
            ni: SecretBytes::copy_from_slice(&p.ni),
            nr: SecretBytes::copy_from_slice(&p.nr),
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
            ckyi: secret_to_plain(&p.ckyi),
            ckyr: secret_to_plain(&p.ckyr),
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
            ckyi: SecretBytes::copy_from_slice(&p.ckyi),
            ckyr: SecretBytes::copy_from_slice(&p.ckyr),
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
            extra_data: secret_to_plain(&p.extra_data),
        }
    }
}

impl From<&v1_proto::Ike1ExtendedDeriveParams> for Ike1ExtendedDeriveParams {
    fn from(p: &v1_proto::Ike1ExtendedDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism,
            has_keygxy: p.has_keygxy,
            keygxy_handle: p.keygxy_handle,
            extra_data: SecretBytes::copy_from_slice(&p.extra_data),
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
            seed_data: secret_to_plain(&p.seed_data),
        }
    }
}

impl From<&v1_proto::Ike2PrfPlusDeriveParams> for Ike2PrfPlusDeriveParams {
    fn from(p: &v1_proto::Ike2PrfPlusDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism,
            has_seed_key: p.has_seed_key,
            seed_key_handle: p.seed_key_handle,
            seed_data: SecretBytes::copy_from_slice(&p.seed_data),
        }
    }
}

// ---------------------------------------------------------------------------
// SP800-108: PrfDataParam helper
// ---------------------------------------------------------------------------

fn prf_data_to_proto(p: &PrfDataParam) -> v1_proto::PrfDataParam {
    v1_proto::PrfDataParam { r#type: p.type_, value: secret_to_plain(&p.value) }
}

fn prf_data_from_proto(p: &v1_proto::PrfDataParam) -> PrfDataParam {
    PrfDataParam { type_: p.r#type, value: SecretBytes::copy_from_slice(&p.value) }
}

fn sp800_108_attribute_to_proto(attr: &CkAttribute) -> Result<v1_proto::Sp800108Attribute, CkRv> {
    let value = match &attr.value {
        None => None,
        Some(CkAttributeValue::Bool(value)) => Some(sp800108_attribute::Value::BoolValue(*value)),
        Some(CkAttributeValue::Ulong(value)) => Some(sp800108_attribute::Value::UlongValue(*value)),
        Some(CkAttributeValue::Bytes(value)) => {
            Some(sp800108_attribute::Value::BytesValue(secret_to_plain(value)))
        }
        Some(CkAttributeValue::String(value)) => {
            Some(sp800108_attribute::Value::StringValue(secret_to_plain_string(value)))
        }
        // A CKA_*_TEMPLATE inside an SP800-108 derived-key sub-template is
        // not representable in Sp800108Attribute (and no real provider
        // consumes one there); refuse loudly rather than silently dropping
        // the template content as value-absent (W1-C8-01).
        Some(CkAttributeValue::NestedTemplate(_)) => {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
    };
    Ok(v1_proto::Sp800108Attribute { attr_type: attr.attr_type.0, value })
}

fn sp800_108_attribute_from_proto(attr: &v1_proto::Sp800108Attribute) -> CkAttribute {
    let value = match &attr.value {
        None => None,
        Some(sp800108_attribute::Value::BoolValue(value)) => Some(CkAttributeValue::Bool(*value)),
        Some(sp800108_attribute::Value::UlongValue(value)) => Some(CkAttributeValue::Ulong(*value)),
        Some(sp800108_attribute::Value::BytesValue(value)) => {
            Some(CkAttributeValue::Bytes(SecretBytes::copy_from_slice(value)))
        }
        Some(sp800108_attribute::Value::StringValue(value)) => {
            Some(CkAttributeValue::String(SecretBytes::copy_from_slice(value.as_bytes())))
        }
    };
    CkAttribute { attr_type: CkAttributeType(attr.attr_type), value }
}

fn sp800_108_derived_key_to_proto(
    key: &Sp800108DerivedKey,
) -> Result<v1_proto::Sp800108DerivedKey, CkRv> {
    Ok(v1_proto::Sp800108DerivedKey {
        template: key
            .template
            .iter()
            .map(sp800_108_attribute_to_proto)
            .collect::<Result<Vec<_>, _>>()?,
        key_handle: key.key_handle,
    })
}

fn sp800_108_derived_key_from_proto(key: &v1_proto::Sp800108DerivedKey) -> Sp800108DerivedKey {
    Sp800108DerivedKey {
        template: key.template.iter().map(sp800_108_attribute_from_proto).collect(),
        key_handle: key.key_handle,
    }
}

// ---------------------------------------------------------------------------
// SP800-108: Sp800108KdfParams
// ---------------------------------------------------------------------------

impl TryFrom<&Sp800108KdfParams> for v1_proto::Sp800108KdfParams {
    type Error = CkRv;

    fn try_from(p: &Sp800108KdfParams) -> Result<Self, Self::Error> {
        Ok(Self {
            prf_type: p.prf_type,
            data_params: p.data_params.iter().map(prf_data_to_proto).collect(),
            additional_derived_keys: p
                .additional_derived_keys
                .iter()
                .map(sp800_108_derived_key_to_proto)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl From<&v1_proto::Sp800108KdfParams> for Sp800108KdfParams {
    fn from(p: &v1_proto::Sp800108KdfParams) -> Self {
        Self {
            prf_type: p.prf_type,
            data_params: p.data_params.iter().map(prf_data_from_proto).collect(),
            additional_derived_keys: p
                .additional_derived_keys
                .iter()
                .map(sp800_108_derived_key_from_proto)
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// SP800-108: Sp800108FeedbackKdfParams
// ---------------------------------------------------------------------------

impl TryFrom<&Sp800108FeedbackKdfParams> for v1_proto::Sp800108FeedbackKdfParams {
    type Error = CkRv;

    fn try_from(p: &Sp800108FeedbackKdfParams) -> Result<Self, Self::Error> {
        Ok(Self {
            prf_type: p.prf_type,
            data_params: p.data_params.iter().map(prf_data_to_proto).collect(),
            iv: p.iv.clone(),
            additional_derived_keys: p
                .additional_derived_keys
                .iter()
                .map(sp800_108_derived_key_to_proto)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl From<&v1_proto::Sp800108FeedbackKdfParams> for Sp800108FeedbackKdfParams {
    fn from(p: &v1_proto::Sp800108FeedbackKdfParams) -> Self {
        Self {
            prf_type: p.prf_type,
            data_params: p.data_params.iter().map(prf_data_from_proto).collect(),
            iv: p.iv.clone(),
            additional_derived_keys: p
                .additional_derived_keys
                .iter()
                .map(sp800_108_derived_key_from_proto)
                .collect(),
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
            sk: secret_to_plain(&p.sk),
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
            sk: SecretBytes::copy_from_slice(&p.sk),
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
            sk: secret_to_plain(&p.sk),
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
            sk: SecretBytes::copy_from_slice(&p.sk),
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
                .map(|op| v1_proto::OtpParam {
                    r#type: op.type_,
                    value: secret_to_plain(&op.value),
                })
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
                .map(|op| OtpParam {
                    type_: op.r#type,
                    value: SecretBytes::copy_from_slice(&op.value),
                })
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Misc: KipParams (nested Mechanism)
// ---------------------------------------------------------------------------

/// Convert a Rust `CkMechanism` reference to a proto `Mechanism`.
/// Fallible: a nested mechanism may carry an unrepresentable nested
/// template (W1-C8-01), which must be refused loudly.
fn mechanism_to_proto(m: &CkMechanism) -> Result<v1_proto::Mechanism, CkRv> {
    v1_proto::Mechanism::try_from(m)
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

impl TryFrom<&KipParams> for v1_proto::KipParams {
    type Error = CkRv;

    fn try_from(p: &KipParams) -> Result<Self, Self::Error> {
        Ok(Self {
            mechanism: Some(Box::new(mechanism_to_proto(&p.mechanism)?)),
            key_handle: p.key_handle,
            seed: secret_to_plain(&p.seed),
        })
    }
}

impl TryFrom<&v1_proto::KipParams> for KipParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::KipParams) -> Result<Self, Self::Error> {
        Ok(Self {
            mechanism: Box::new(required_mechanism_from_boxed_option(&p.mechanism)?),
            key_handle: p.key_handle,
            seed: SecretBytes::copy_from_slice(&p.seed),
        })
    }
}

// ---------------------------------------------------------------------------
// Misc: CmsSigParams (nested Mechanisms)
// ---------------------------------------------------------------------------

impl TryFrom<&CmsSigParams> for v1_proto::CmsSigParams {
    type Error = CkRv;

    fn try_from(p: &CmsSigParams) -> Result<Self, Self::Error> {
        Ok(Self {
            certificate_handle: p.certificate_handle,
            signing_mechanism: Some(Box::new(mechanism_to_proto(&p.signing_mechanism)?)),
            digest_mechanism: Some(Box::new(mechanism_to_proto(&p.digest_mechanism)?)),
            content_type: p.content_type.clone(),
            requested_attributes: secret_to_plain(&p.requested_attributes),
            required_attributes: secret_to_plain(&p.required_attributes),
        })
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
            requested_attributes: SecretBytes::copy_from_slice(&p.requested_attributes),
            required_attributes: SecretBytes::copy_from_slice(&p.required_attributes),
        })
    }
}

// ---------------------------------------------------------------------------
// Misc: SkipjackPrivateWrapParams
// ---------------------------------------------------------------------------

impl From<&SkipjackPrivateWrapParams> for v1_proto::SkipjackPrivateWrapParams {
    fn from(p: &SkipjackPrivateWrapParams) -> Self {
        Self {
            password: secret_to_plain(&p.password),
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
            password: SecretBytes::copy_from_slice(&p.password),
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
            old_wrapped_x: secret_to_plain(&p.old_wrapped_x),
            old_password: secret_to_plain(&p.old_password),
            old_public_data: secret_to_plain(&p.old_public_data),
            old_random_a: secret_to_plain(&p.old_random_a),
            new_password: secret_to_plain(&p.new_password),
            new_public_data: secret_to_plain(&p.new_public_data),
            new_random_a: secret_to_plain(&p.new_random_a),
        }
    }
}

impl From<&v1_proto::SkipjackRelayxParams> for SkipjackRelayxParams {
    fn from(p: &v1_proto::SkipjackRelayxParams) -> Self {
        Self {
            old_wrapped_x: SecretBytes::copy_from_slice(&p.old_wrapped_x),
            old_password: SecretBytes::copy_from_slice(&p.old_password),
            old_public_data: SecretBytes::copy_from_slice(&p.old_public_data),
            old_random_a: SecretBytes::copy_from_slice(&p.old_random_a),
            new_password: SecretBytes::copy_from_slice(&p.new_password),
            new_public_data: SecretBytes::copy_from_slice(&p.new_public_data),
            new_random_a: SecretBytes::copy_from_slice(&p.new_random_a),
        }
    }
}

// ---------------------------------------------------------------------------
// Vendor: EciesParams (nested Mechanisms)
// ---------------------------------------------------------------------------

impl TryFrom<&EciesParams> for v1_proto::EciesParams {
    type Error = CkRv;

    fn try_from(p: &EciesParams) -> Result<Self, Self::Error> {
        Ok(Self {
            derivation_mechanism: Some(Box::new(mechanism_to_proto(&p.derivation_mechanism)?)),
            encryption_mechanism: Some(Box::new(mechanism_to_proto(&p.encryption_mechanism)?)),
            mac_mechanism: Some(Box::new(mechanism_to_proto(&p.mac_mechanism)?)),
            shared_data: secret_to_plain(&p.shared_data),
        })
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
            shared_data: SecretBytes::copy_from_slice(&p.shared_data),
        })
    }
}

// ---------------------------------------------------------------------------
// Vendor: AesCmacKeyDerivationParams
// ---------------------------------------------------------------------------

impl From<&AesCmacKeyDerivationParams> for v1_proto::AesCmacKeyDerivationParams {
    fn from(p: &AesCmacKeyDerivationParams) -> Self {
        Self { context: secret_to_plain(&p.context), label: secret_to_plain(&p.label) }
    }
}

impl From<&v1_proto::AesCmacKeyDerivationParams> for AesCmacKeyDerivationParams {
    fn from(p: &v1_proto::AesCmacKeyDerivationParams) -> Self {
        Self {
            context: SecretBytes::copy_from_slice(&p.context),
            label: SecretBytes::copy_from_slice(&p.label),
        }
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
            shared_data: secret_to_plain(&p.shared_data),
            blob: secret_to_plain(&p.blob),
        }
    }
}

impl From<&v1_proto::KyberParams> for KyberParams {
    fn from(p: &v1_proto::KyberParams) -> Self {
        Self {
            version: p.version,
            mode: p.mode,
            secret_handle: p.secret_handle,
            shared_data: SecretBytes::copy_from_slice(&p.shared_data),
            blob: SecretBytes::copy_from_slice(&p.blob),
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
            chain_code: secret_to_plain(&p.chain_code),
            version: p.version,
        }
    }
}

impl From<&v1_proto::HdKeyDeriveParams> for HdKeyDeriveParams {
    fn from(p: &v1_proto::HdKeyDeriveParams) -> Self {
        Self {
            derive_type: p.derive_type,
            child_key_index: p.child_key_index,
            chain_code: SecretBytes::copy_from_slice(&p.chain_code),
            version: p.version,
        }
    }
}

// ---------------------------------------------------------------------------
// Vendor: VendorObjectExtractParams
// ---------------------------------------------------------------------------

impl From<&VendorObjectExtractParams> for v1_proto::VendorObjectExtractParams {
    fn from(p: &VendorObjectExtractParams) -> Self {
        Self { format: p.format, context: secret_to_plain(&p.context) }
    }
}

impl From<&v1_proto::VendorObjectExtractParams> for VendorObjectExtractParams {
    fn from(p: &v1_proto::VendorObjectExtractParams) -> Self {
        Self { format: p.format, context: SecretBytes::copy_from_slice(&p.context) }
    }
}

// ---------------------------------------------------------------------------
// Vendor: VendorObjectInsertParams
// ---------------------------------------------------------------------------

impl From<&VendorObjectInsertParams> for v1_proto::VendorObjectInsertParams {
    fn from(p: &VendorObjectInsertParams) -> Self {
        Self {
            format: p.format,
            context: secret_to_plain(&p.context),
            object_data: secret_to_plain(&p.object_data),
        }
    }
}

impl From<&v1_proto::VendorObjectInsertParams> for VendorObjectInsertParams {
    fn from(p: &v1_proto::VendorObjectInsertParams) -> Self {
        Self {
            format: p.format,
            context: SecretBytes::copy_from_slice(&p.context),
            object_data: SecretBytes::copy_from_slice(&p.object_data),
        }
    }
}

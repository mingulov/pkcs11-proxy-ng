//! Proto <-> Rust conversions for IKE/IPSec, SP800-108 KDF, Signal protocol,
//! and miscellaneous mechanism parameters.

use crate::pkcs11_proxy_ng::v1 as v1_proto;
use crate::pkcs11_proxy_ng::v1::sp800108_attribute;
// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use super::{
    FromWire, ToWireV1, check_shared_len_agreement, null_bit_from_wire, null_bit_to_wire,
    pointer_array_from_wire, pointer_array_to_wire, pointer_from_wire, pointer_to_wire,
};
use crate::secret_boundary::{secret_to_plain, secret_to_plain_string};
use pkcs11_proxy_ng_types::{
    AesCmacKeyDerivationParams, CkAttribute, CkAttributeType, CkAttributeValue, CkKdf, CkMechanism,
    CkMechanismType, CkObjectHandle, CkRv, CmsSigParams, DilithiumParams, EciesParams,
    HdKeyDeriveParams, Ike1ExtendedDeriveParams, Ike1PrfDeriveParams, Ike2PrfPlusDeriveParams,
    IkePrfDeriveParams, KipParams, KyberParams, OtpParam, OtpParams, PointerArray, PointerBytes,
    PrfDataParam, SecretBytes, SkipjackPrivateWrapParams, SkipjackRelayxParams, Sp800108DerivedKey,
    Sp800108FeedbackKdfParams, Sp800108KdfParams, VendorObjectExtractParams,
    VendorObjectInsertParams, X2RatchetInitializeParams, X2RatchetRespondParams,
    X3dhInitiateParams, X3dhRespondParams,
};

// ---------------------------------------------------------------------------
// IKE/IPSec: IkePrfDeriveParams
// ---------------------------------------------------------------------------

impl From<&IkePrfDeriveParams> for v1_proto::IkePrfDeriveParams {
    fn from(p: &IkePrfDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism.0,
            data_as_key: p.data_as_key,
            rekey: p.rekey,
            ni: pointer_to_wire(&p.ni_presence).0,
            nr: pointer_to_wire(&p.nr_presence).0,
            new_key_handle: p.new_key_handle.0,
            // R16: production encode stays v0-shaped.
            ni_null_len: None,
            nr_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::IkePrfDeriveParams> for IkePrfDeriveParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::IkePrfDeriveParams {
        let (ni, ni_null_len) = pointer_to_wire(&self.ni_presence);
        let (nr, nr_null_len) = pointer_to_wire(&self.nr_presence);
        v1_proto::IkePrfDeriveParams {
            prf_mechanism: self.prf_mechanism.0,
            data_as_key: self.data_as_key,
            rekey: self.rekey,
            ni,
            nr,
            new_key_handle: self.new_key_handle.0,
            ni_null_len,
            nr_null_len,
        }
    }
}

impl FromWire<v1_proto::IkePrfDeriveParams> for IkePrfDeriveParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::IkePrfDeriveParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            prf_mechanism: CkMechanismType(p.prf_mechanism),
            data_as_key: p.data_as_key,
            rekey: p.rekey,
            new_key_handle: CkObjectHandle(p.new_key_handle),
            ni_presence: pointer_from_wire(&p.ni, p.ni_null_len, version)?,
            nr_presence: pointer_from_wire(&p.nr, p.nr_null_len, version)?,
        })
    }
}

// ---------------------------------------------------------------------------
// IKE/IPSec: Ike1PrfDeriveParams
// ---------------------------------------------------------------------------

impl From<&Ike1PrfDeriveParams> for v1_proto::Ike1PrfDeriveParams {
    fn from(p: &Ike1PrfDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism.0,
            has_prev_key: p.has_prev_key,
            keygxy_handle: p.keygxy_handle.0,
            prev_key_handle: p.prev_key_handle.0,
            ckyi: pointer_to_wire(&p.ckyi_presence).0,
            ckyr: pointer_to_wire(&p.ckyr_presence).0,
            key_number: p.key_number,
            // R16: production encode stays v0-shaped.
            ckyi_null_len: None,
            ckyr_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::Ike1PrfDeriveParams> for Ike1PrfDeriveParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::Ike1PrfDeriveParams {
        let (ckyi, ckyi_null_len) = pointer_to_wire(&self.ckyi_presence);
        let (ckyr, ckyr_null_len) = pointer_to_wire(&self.ckyr_presence);
        v1_proto::Ike1PrfDeriveParams {
            prf_mechanism: self.prf_mechanism.0,
            has_prev_key: self.has_prev_key,
            keygxy_handle: self.keygxy_handle.0,
            prev_key_handle: self.prev_key_handle.0,
            ckyi,
            ckyr,
            key_number: self.key_number,
            ckyi_null_len,
            ckyr_null_len,
        }
    }
}

impl FromWire<v1_proto::Ike1PrfDeriveParams> for Ike1PrfDeriveParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::Ike1PrfDeriveParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            prf_mechanism: CkMechanismType(p.prf_mechanism),
            has_prev_key: p.has_prev_key,
            keygxy_handle: CkObjectHandle(p.keygxy_handle),
            prev_key_handle: CkObjectHandle(p.prev_key_handle),
            key_number: p.key_number,
            ckyi_presence: pointer_from_wire(&p.ckyi, p.ckyi_null_len, version)?,
            ckyr_presence: pointer_from_wire(&p.ckyr, p.ckyr_null_len, version)?,
        })
    }
}

// ---------------------------------------------------------------------------
// IKE/IPSec: Ike1ExtendedDeriveParams
// ---------------------------------------------------------------------------

impl From<&Ike1ExtendedDeriveParams> for v1_proto::Ike1ExtendedDeriveParams {
    fn from(p: &Ike1ExtendedDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism.0,
            has_keygxy: p.has_keygxy,
            keygxy_handle: p.keygxy_handle.0,
            extra_data: pointer_to_wire(&p.extra_data_presence).0,
            // R16: production encode stays v0-shaped.
            extra_data_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::Ike1ExtendedDeriveParams> for Ike1ExtendedDeriveParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::Ike1ExtendedDeriveParams {
        let (extra_data, extra_data_null_len) = pointer_to_wire(&self.extra_data_presence);
        v1_proto::Ike1ExtendedDeriveParams {
            prf_mechanism: self.prf_mechanism.0,
            has_keygxy: self.has_keygxy,
            keygxy_handle: self.keygxy_handle.0,
            extra_data,
            extra_data_null_len,
        }
    }
}

impl FromWire<v1_proto::Ike1ExtendedDeriveParams> for Ike1ExtendedDeriveParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::Ike1ExtendedDeriveParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            prf_mechanism: CkMechanismType(p.prf_mechanism),
            has_keygxy: p.has_keygxy,
            keygxy_handle: CkObjectHandle(p.keygxy_handle),
            extra_data_presence: pointer_from_wire(&p.extra_data, p.extra_data_null_len, version)?,
        })
    }
}

// ---------------------------------------------------------------------------
// IKE/IPSec: Ike2PrfPlusDeriveParams
// ---------------------------------------------------------------------------

impl From<&Ike2PrfPlusDeriveParams> for v1_proto::Ike2PrfPlusDeriveParams {
    fn from(p: &Ike2PrfPlusDeriveParams) -> Self {
        Self {
            prf_mechanism: p.prf_mechanism.0,
            has_seed_key: p.has_seed_key,
            seed_key_handle: p.seed_key_handle.0,
            seed_data: pointer_to_wire(&p.seed_data_presence).0,
            // R16: production encode stays v0-shaped.
            seed_data_null_len: None,
        }
    }
}

impl ToWireV1<v1_proto::Ike2PrfPlusDeriveParams> for Ike2PrfPlusDeriveParams {
    // R17: presence-based v1 (peers authoritative; legacy `From` above
    // stays the v0 encode).
    fn to_wire_v1(&self) -> v1_proto::Ike2PrfPlusDeriveParams {
        let (seed_data, seed_data_null_len) = pointer_to_wire(&self.seed_data_presence);
        v1_proto::Ike2PrfPlusDeriveParams {
            prf_mechanism: self.prf_mechanism.0,
            has_seed_key: self.has_seed_key,
            seed_key_handle: self.seed_key_handle.0,
            seed_data,
            seed_data_null_len,
        }
    }
}

impl FromWire<v1_proto::Ike2PrfPlusDeriveParams> for Ike2PrfPlusDeriveParams {
    // R16: fallible + version-threaded (presence needs the outer stamp).
    fn from_wire(p: &v1_proto::Ike2PrfPlusDeriveParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            prf_mechanism: CkMechanismType(p.prf_mechanism),
            has_seed_key: p.has_seed_key,
            seed_key_handle: CkObjectHandle(p.seed_key_handle),
            seed_data_presence: pointer_from_wire(&p.seed_data, p.seed_data_null_len, version)?,
        })
    }
}

// ---------------------------------------------------------------------------
// SP800-108: PrfDataParam helper
// ---------------------------------------------------------------------------

fn prf_data_to_proto(p: &PrfDataParam) -> v1_proto::PrfDataParam {
    v1_proto::PrfDataParam {
        r#type: p.type_,
        value: pointer_to_wire(&p.value_presence).0,
        // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
        value_null_len: None,
    }
}

fn prf_data_from_proto(p: &v1_proto::PrfDataParam) -> PrfDataParam {
    // R18: unversioned legacy decode — peers mirror Present (FromWire threads versions).
    PrfDataParam { type_: p.r#type, value_presence: PointerBytes::present_copy(&p.value) }
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
        template: pointer_array_to_wire(&key.template_presence, sp800_108_attribute_to_proto)?.0,
        key_handle: key.key_handle.0,
        // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
        template_null_count: None,
        ph_key_null: None,
    })
}

fn sp800_108_derived_key_from_proto(key: &v1_proto::Sp800108DerivedKey) -> Sp800108DerivedKey {
    // R18: unversioned legacy decode — peers mirror Present (FromWire threads versions).
    let template: Vec<CkAttribute> =
        key.template.iter().map(sp800_108_attribute_from_proto).collect();
    Sp800108DerivedKey {
        template_presence: PointerArray::present(template.clone()),
        key_handle: CkObjectHandle(key.key_handle),
        ph_key_is_null: false,
    }
}

// ---------------------------------------------------------------------------
// SP800-108: Sp800108KdfParams
// ---------------------------------------------------------------------------

impl TryFrom<&Sp800108KdfParams> for v1_proto::Sp800108KdfParams {
    type Error = CkRv;

    fn try_from(p: &Sp800108KdfParams) -> Result<Self, Self::Error> {
        Ok(Self {
            prf_type: p.prf_type.0,
            data_params: pointer_array_to_wire(&p.data_params_presence, |dp| {
                Ok(prf_data_to_proto(dp))
            })?
            .0,
            additional_derived_keys: pointer_array_to_wire(
                &p.additional_derived_keys_presence,
                sp800_108_derived_key_to_proto,
            )?
            .0,
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            data_params_null_count: None,
            additional_derived_keys_null_count: None,
        })
    }
}

impl From<&v1_proto::Sp800108KdfParams> for Sp800108KdfParams {
    fn from(p: &v1_proto::Sp800108KdfParams) -> Self {
        // R18: unversioned legacy decode — peers mirror Present (FromWire threads versions).
        let data_params: Vec<PrfDataParam> =
            p.data_params.iter().map(prf_data_from_proto).collect();
        let additional_derived_keys: Vec<Sp800108DerivedKey> =
            p.additional_derived_keys.iter().map(sp800_108_derived_key_from_proto).collect();
        Self {
            prf_type: CkMechanismType(p.prf_type),
            data_params_presence: PointerArray::present(data_params.clone()),
            additional_derived_keys_presence: PointerArray::present(
                additional_derived_keys.clone(),
            ),
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
            prf_type: p.prf_type.0,
            data_params: pointer_array_to_wire(&p.data_params_presence, |dp| {
                Ok(prf_data_to_proto(dp))
            })?
            .0,
            iv: pointer_to_wire(&p.iv_presence).0,
            additional_derived_keys: pointer_array_to_wire(
                &p.additional_derived_keys_presence,
                sp800_108_derived_key_to_proto,
            )?
            .0,
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            data_params_null_count: None,
            iv_null_len: None,
            additional_derived_keys_null_count: None,
        })
    }
}

impl From<&v1_proto::Sp800108FeedbackKdfParams> for Sp800108FeedbackKdfParams {
    fn from(p: &v1_proto::Sp800108FeedbackKdfParams) -> Self {
        // R18: unversioned legacy decode — peers mirror Present (FromWire threads versions).
        let data_params: Vec<PrfDataParam> =
            p.data_params.iter().map(prf_data_from_proto).collect();
        let iv = p.iv.clone();
        let additional_derived_keys: Vec<Sp800108DerivedKey> =
            p.additional_derived_keys.iter().map(sp800_108_derived_key_from_proto).collect();
        Self {
            prf_type: CkMechanismType(p.prf_type),
            data_params_presence: PointerArray::present(data_params.clone()),
            iv_presence: PointerBytes::present_copy(&iv),
            additional_derived_keys_presence: PointerArray::present(
                additional_derived_keys.clone(),
            ),
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
            peer_identity_handle: p.peer_identity_handle.0,
            peer_prekey_handle: p.peer_prekey_handle.0,
            prekey_signature: p.prekey_signature.clone(),
            onetime_key_handle: p.onetime_key_handle.0,
            own_identity_handle: p.own_identity_handle.0,
            own_ephemeral_handle: p.own_ephemeral_handle.0,
        }
    }
}

impl From<&v1_proto::X3dhInitiateParams> for X3dhInitiateParams {
    fn from(p: &v1_proto::X3dhInitiateParams) -> Self {
        Self {
            kdf: p.kdf,
            peer_identity_handle: CkObjectHandle(p.peer_identity_handle),
            peer_prekey_handle: CkObjectHandle(p.peer_prekey_handle),
            prekey_signature: p.prekey_signature.clone(),
            onetime_key_handle: CkObjectHandle(p.onetime_key_handle),
            own_identity_handle: CkObjectHandle(p.own_identity_handle),
            own_ephemeral_handle: CkObjectHandle(p.own_ephemeral_handle),
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
            identity_handle: p.identity_handle.0,
            prekey_handle: p.prekey_handle.0,
            onetime_key_handle: p.onetime_key_handle.0,
            initiator_identity_handle: p.initiator_identity_handle.0,
            initiator_ephemeral_handle: p.initiator_ephemeral_handle.0,
        }
    }
}

impl From<&v1_proto::X3dhRespondParams> for X3dhRespondParams {
    fn from(p: &v1_proto::X3dhRespondParams) -> Self {
        Self {
            kdf: p.kdf,
            identity_handle: CkObjectHandle(p.identity_handle),
            prekey_handle: CkObjectHandle(p.prekey_handle),
            onetime_key_handle: CkObjectHandle(p.onetime_key_handle),
            initiator_identity_handle: CkObjectHandle(p.initiator_identity_handle),
            initiator_ephemeral_handle: CkObjectHandle(p.initiator_ephemeral_handle),
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
            peer_public_prekey_handle: p.peer_public_prekey_handle.0,
            peer_public_identity_handle: p.peer_public_identity_handle.0,
            own_public_identity_handle: p.own_public_identity_handle.0,
            encrypted_header: p.encrypted_header,
            curve: p.curve,
            aead_mechanism: p.aead_mechanism.0,
            kdf_mechanism: p.kdf_mechanism.0,
        }
    }
}

impl From<&v1_proto::X2RatchetInitializeParams> for X2RatchetInitializeParams {
    fn from(p: &v1_proto::X2RatchetInitializeParams) -> Self {
        Self {
            sk: SecretBytes::copy_from_slice(&p.sk),
            peer_public_prekey_handle: CkObjectHandle(p.peer_public_prekey_handle),
            peer_public_identity_handle: CkObjectHandle(p.peer_public_identity_handle),
            own_public_identity_handle: CkObjectHandle(p.own_public_identity_handle),
            encrypted_header: p.encrypted_header,
            curve: p.curve,
            aead_mechanism: CkMechanismType(p.aead_mechanism),
            kdf_mechanism: CkKdf(p.kdf_mechanism),
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
            own_prekey_handle: p.own_prekey_handle.0,
            initiator_identity_handle: p.initiator_identity_handle.0,
            own_identity_handle: p.own_identity_handle.0,
            encrypted_header: p.encrypted_header,
            curve: p.curve,
            aead_mechanism: p.aead_mechanism.0,
            kdf_mechanism: p.kdf_mechanism.0,
        }
    }
}

impl From<&v1_proto::X2RatchetRespondParams> for X2RatchetRespondParams {
    fn from(p: &v1_proto::X2RatchetRespondParams) -> Self {
        Self {
            sk: SecretBytes::copy_from_slice(&p.sk),
            own_prekey_handle: CkObjectHandle(p.own_prekey_handle),
            initiator_identity_handle: CkObjectHandle(p.initiator_identity_handle),
            own_identity_handle: CkObjectHandle(p.own_identity_handle),
            encrypted_header: p.encrypted_header,
            curve: p.curve,
            aead_mechanism: CkMechanismType(p.aead_mechanism),
            kdf_mechanism: CkKdf(p.kdf_mechanism),
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
                .params_presence
                .as_present()
                .map(|items| {
                    items
                        .iter()
                        .map(|op| v1_proto::OtpParam {
                            r#type: op.type_,
                            value: pointer_to_wire(&op.value_presence).0,
                            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
                            value_null_len: None,
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            params_null_count: None,
        }
    }
}

impl From<&v1_proto::OtpParams> for OtpParams {
    fn from(p: &v1_proto::OtpParams) -> Self {
        // R18: unversioned legacy decode — peers mirror Present (FromWire threads versions).
        let params: Vec<OtpParam> = p
            .params
            .iter()
            .map(|op| {
                let value = SecretBytes::copy_from_slice(&op.value);
                OtpParam { type_: op.r#type, value_presence: PointerBytes::present_cloned(&value) }
            })
            .collect();
        Self { params_presence: PointerArray::present(params) }
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
            // R19: a NULL nesting encodes no nested message (v0 decodes
            // that as missing-required — loud, like any other
            // unrepresentable nesting — instead of the silent dummy the
            // R18 bool+dummy spelling encoded).
            mechanism: p.mechanism.as_deref().map(mechanism_to_proto).transpose()?.map(Box::new),
            key_handle: p.key_handle.0,
            seed: pointer_to_wire(&p.seed_presence).0,
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            mechanism_null: None,
            seed_null_len: None,
        })
    }
}

impl TryFrom<&v1_proto::KipParams> for KipParams {
    type Error = CkRv;

    fn try_from(p: &v1_proto::KipParams) -> Result<Self, Self::Error> {
        // R18: unversioned legacy decode — peers mirror Present (FromWire threads versions).
        let seed = SecretBytes::copy_from_slice(&p.seed);
        Ok(Self {
            mechanism: Some(Box::new(required_mechanism_from_boxed_option(&p.mechanism)?)),
            key_handle: CkObjectHandle(p.key_handle),
            seed_presence: PointerBytes::present_cloned(&seed),
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
            certificate_handle: p.certificate_handle.0,
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
            certificate_handle: CkObjectHandle(p.certificate_handle),
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
            password: pointer_to_wire(&p.password_presence).0,
            public_data: pointer_to_wire(&p.public_data_presence).0,
            password_length: p.password_length,
            random_a: pointer_to_wire(&p.random_a_presence).0,
            prime_p: pointer_to_wire(&p.prime_p_presence).0,
            base_g: pointer_to_wire(&p.base_g_presence).0,
            subprime_q: pointer_to_wire(&p.subprime_q_presence).0,
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            password_null_len: None,
            public_data_null_len: None,
            random_a_null_len: None,
            prime_p_null_len: None,
            base_g_null_len: None,
            subprime_q_null_len: None,
        }
    }
}

impl From<&v1_proto::SkipjackPrivateWrapParams> for SkipjackPrivateWrapParams {
    fn from(p: &v1_proto::SkipjackPrivateWrapParams) -> Self {
        Self {
            password_length: p.password_length,
            password_presence: PointerBytes::present_copy(&p.password),
            public_data_presence: PointerBytes::present_copy(&p.public_data),
            random_a_presence: PointerBytes::present_copy(&p.random_a),
            prime_p_presence: PointerBytes::present_copy(&p.prime_p),
            base_g_presence: PointerBytes::present_copy(&p.base_g),
            subprime_q_presence: PointerBytes::present_copy(&p.subprime_q),
        }
    }
}

// Owned-adopting conversion (W1-C8-02): takes ownership of the secret
// buffers out of the prost message instead of copying them, so after
// adoption the secret bytes exist in exactly one wiped-on-drop owner.
// The source message is left with empty buffers; its drop wipes any
// residual via the derived `ZeroizeOnDrop` impl (see build.rs).
impl From<&mut v1_proto::SkipjackPrivateWrapParams> for SkipjackPrivateWrapParams {
    fn from(p: &mut v1_proto::SkipjackPrivateWrapParams) -> Self {
        // Take first, then mirror peers from the taken buffers (field
        // inits run in written order — peers must NOT read the emptied
        // source fields).
        let password = SecretBytes::new(std::mem::take(&mut p.password));
        let public_data = std::mem::take(&mut p.public_data);
        let random_a = std::mem::take(&mut p.random_a);
        let prime_p = std::mem::take(&mut p.prime_p);
        let base_g = std::mem::take(&mut p.base_g);
        let subprime_q = std::mem::take(&mut p.subprime_q);
        let password_presence = PointerBytes::present_cloned(&password);
        let public_data_presence = PointerBytes::present_copy(&public_data);
        let random_a_presence = PointerBytes::present_copy(&random_a);
        let prime_p_presence = PointerBytes::present_copy(&prime_p);
        let base_g_presence = PointerBytes::present_copy(&base_g);
        let subprime_q_presence = PointerBytes::present_copy(&subprime_q);
        Self {
            password_length: p.password_length,
            password_presence,
            public_data_presence,
            random_a_presence,
            prime_p_presence,
            base_g_presence,
            subprime_q_presence,
        }
    }
}

// ---------------------------------------------------------------------------
// Misc: SkipjackRelayxParams
// ---------------------------------------------------------------------------

impl From<&SkipjackRelayxParams> for v1_proto::SkipjackRelayxParams {
    fn from(p: &SkipjackRelayxParams) -> Self {
        Self {
            old_wrapped_x: pointer_to_wire(&p.old_wrapped_x_presence).0,
            old_password: pointer_to_wire(&p.old_password_presence).0,
            old_public_data: pointer_to_wire(&p.old_public_data_presence).0,
            old_random_a: pointer_to_wire(&p.old_random_a_presence).0,
            new_password: pointer_to_wire(&p.new_password_presence).0,
            new_public_data: pointer_to_wire(&p.new_public_data_presence).0,
            new_random_a: pointer_to_wire(&p.new_random_a_presence).0,
            // R18: v0 encode stays v0-shaped (shim emits v1 in R18 tail arms).
            old_wrapped_x_null_len: None,
            old_password_null_len: None,
            old_public_data_null_len: None,
            old_random_a_null_len: None,
            new_password_null_len: None,
            new_public_data_null_len: None,
            new_random_a_null_len: None,
        }
    }
}

impl From<&v1_proto::SkipjackRelayxParams> for SkipjackRelayxParams {
    fn from(p: &v1_proto::SkipjackRelayxParams) -> Self {
        Self {
            old_wrapped_x_presence: PointerBytes::present_copy(&p.old_wrapped_x),
            old_password_presence: PointerBytes::present_copy(&p.old_password),
            old_public_data_presence: PointerBytes::present_copy(&p.old_public_data),
            old_random_a_presence: PointerBytes::present_copy(&p.old_random_a),
            new_password_presence: PointerBytes::present_copy(&p.new_password),
            new_public_data_presence: PointerBytes::present_copy(&p.new_public_data),
            new_random_a_presence: PointerBytes::present_copy(&p.new_random_a),
        }
    }
}

// Owned-adopting conversion (W1-C8-02): takes ownership of the secret
// buffers out of the prost message instead of copying them, so after
// adoption the secret bytes exist in exactly one wiped-on-drop owner.
// The source message is left with empty buffers; its drop wipes any
// residual via the derived `ZeroizeOnDrop` impl (see build.rs).
impl From<&mut v1_proto::SkipjackRelayxParams> for SkipjackRelayxParams {
    fn from(p: &mut v1_proto::SkipjackRelayxParams) -> Self {
        // Take first, then mirror peers from the taken buffers (field
        // inits run in written order — peers must NOT read the emptied
        // source fields).
        let old_wrapped_x = SecretBytes::new(std::mem::take(&mut p.old_wrapped_x));
        let old_password = SecretBytes::new(std::mem::take(&mut p.old_password));
        let old_public_data = SecretBytes::new(std::mem::take(&mut p.old_public_data));
        let old_random_a = SecretBytes::new(std::mem::take(&mut p.old_random_a));
        let new_password = SecretBytes::new(std::mem::take(&mut p.new_password));
        let new_public_data = SecretBytes::new(std::mem::take(&mut p.new_public_data));
        let new_random_a = SecretBytes::new(std::mem::take(&mut p.new_random_a));
        let old_wrapped_x_presence = PointerBytes::present_cloned(&old_wrapped_x);
        let old_password_presence = PointerBytes::present_cloned(&old_password);
        let old_public_data_presence = PointerBytes::present_cloned(&old_public_data);
        let old_random_a_presence = PointerBytes::present_cloned(&old_random_a);
        let new_password_presence = PointerBytes::present_cloned(&new_password);
        let new_public_data_presence = PointerBytes::present_cloned(&new_public_data);
        let new_random_a_presence = PointerBytes::present_cloned(&new_random_a);
        Self {
            old_wrapped_x_presence,
            old_password_presence,
            old_public_data_presence,
            old_random_a_presence,
            new_password_presence,
            new_public_data_presence,
            new_random_a_presence,
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
            secret_handle: p.secret_handle.0,
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
            secret_handle: CkObjectHandle(p.secret_handle),
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

// ---------------------------------------------------------------------------
// R18: version-threaded tail conversions (S2 §8)
// ---------------------------------------------------------------------------

impl FromWire<v1_proto::PrfDataParam> for PrfDataParam {
    fn from_wire(p: &v1_proto::PrfDataParam, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            type_: p.r#type,
            value_presence: pointer_from_wire(&p.value, p.value_null_len, version)?,
        })
    }
}

impl ToWireV1<v1_proto::PrfDataParam> for PrfDataParam {
    fn to_wire_v1(&self) -> v1_proto::PrfDataParam {
        let (value, value_null_len) = pointer_to_wire(&self.value_presence);
        v1_proto::PrfDataParam { r#type: self.type_, value, value_null_len }
    }
}

impl FromWire<v1_proto::Sp800108DerivedKey> for Sp800108DerivedKey {
    fn from_wire(p: &v1_proto::Sp800108DerivedKey, version: u32) -> Result<Self, CkRv> {
        // A NULL pTemplate rides Null{n} — this closes the ADR-0010
        // Scope-2 class-4 null-conflation residual.
        let template_presence =
            pointer_array_from_wire(&p.template, p.template_null_count, version, |attr| {
                Ok(sp800_108_attribute_from_proto(attr))
            })?;
        Ok(Self {
            key_handle: CkObjectHandle(p.key_handle),
            template_presence,
            ph_key_is_null: null_bit_from_wire(p.ph_key_null, p.key_handle == 0, version)?,
        })
    }
}

/// v1 encode of one SP800-108 derived key (R18; fallible: the
/// nested-template refusal propagates). `pub(crate)` for the inline
/// SP800-108 arms in [`super::encode_r18_tail_v1_params`].
pub(crate) fn sp800_108_derived_key_to_wire_v1(
    key: &Sp800108DerivedKey,
) -> Result<v1_proto::Sp800108DerivedKey, CkRv> {
    let (template, template_null_count) =
        pointer_array_to_wire(&key.template_presence, sp800_108_attribute_to_proto)?;
    Ok(v1_proto::Sp800108DerivedKey {
        template,
        key_handle: key.key_handle.0,
        template_null_count,
        ph_key_null: null_bit_to_wire(key.ph_key_is_null),
    })
}

impl FromWire<v1_proto::Sp800108KdfParams> for Sp800108KdfParams {
    fn from_wire(p: &v1_proto::Sp800108KdfParams, version: u32) -> Result<Self, CkRv> {
        let data_params_presence =
            pointer_array_from_wire(&p.data_params, p.data_params_null_count, version, |item| {
                PrfDataParam::from_wire(item, version)
            })?;
        let additional_derived_keys_presence = pointer_array_from_wire(
            &p.additional_derived_keys,
            p.additional_derived_keys_null_count,
            version,
            |item| Sp800108DerivedKey::from_wire(item, version),
        )?;
        Ok(Self {
            prf_type: CkMechanismType(p.prf_type),
            data_params_presence,
            additional_derived_keys_presence,
        })
    }
}

impl FromWire<v1_proto::Sp800108FeedbackKdfParams> for Sp800108FeedbackKdfParams {
    fn from_wire(p: &v1_proto::Sp800108FeedbackKdfParams, version: u32) -> Result<Self, CkRv> {
        let data_params_presence =
            pointer_array_from_wire(&p.data_params, p.data_params_null_count, version, |item| {
                PrfDataParam::from_wire(item, version)
            })?;
        let additional_derived_keys_presence = pointer_array_from_wire(
            &p.additional_derived_keys,
            p.additional_derived_keys_null_count,
            version,
            |item| Sp800108DerivedKey::from_wire(item, version),
        )?;
        Ok(Self {
            prf_type: CkMechanismType(p.prf_type),
            data_params_presence,
            iv_presence: pointer_from_wire(&p.iv, p.iv_null_len, version)?,
            additional_derived_keys_presence,
        })
    }
}

impl FromWire<v1_proto::OtpParam> for OtpParam {
    fn from_wire(p: &v1_proto::OtpParam, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            type_: p.r#type,
            value_presence: pointer_from_wire(&p.value, p.value_null_len, version)?,
        })
    }
}

impl ToWireV1<v1_proto::OtpParam> for OtpParam {
    fn to_wire_v1(&self) -> v1_proto::OtpParam {
        let (value, value_null_len) = pointer_to_wire(&self.value_presence);
        v1_proto::OtpParam { r#type: self.type_, value, value_null_len }
    }
}

impl FromWire<v1_proto::OtpParams> for OtpParams {
    fn from_wire(p: &v1_proto::OtpParams, version: u32) -> Result<Self, CkRv> {
        let params_presence =
            pointer_array_from_wire(&p.params, p.params_null_count, version, |item| {
                OtpParam::from_wire(item, version)
            })?;
        Ok(Self { params_presence })
    }
}

impl FromWire<v1_proto::KipParams> for KipParams {
    fn from_wire(p: &v1_proto::KipParams, version: u32) -> Result<Self, CkRv> {
        // The nesting bit claims NULL only with NO nested message; a
        // present message beside any set bit is contradictory, and an
        // absent message without the bit stays missing-required
        // (legacy-exact at v0, still rejected at v1: missing ≠ NULL).
        let mechanism_is_null =
            null_bit_from_wire(p.mechanism_null, p.mechanism.is_none(), version)?;
        let mechanism = match (&p.mechanism, mechanism_is_null) {
            (Some(m), false) => Some(Box::new(CkMechanism::try_from(m.as_ref())?)),
            (None, true) => None,
            _ => return Err(CkRv::MECHANISM_PARAM_INVALID),
        };
        Ok(Self {
            mechanism,
            key_handle: CkObjectHandle(p.key_handle),
            seed_presence: pointer_from_wire(&p.seed, p.seed_null_len, version)?,
        })
    }
}

impl FromWire<v1_proto::SkipjackPrivateWrapParams> for SkipjackPrivateWrapParams {
    fn from_wire(p: &v1_proto::SkipjackPrivateWrapParams, version: u32) -> Result<Self, CkRv> {
        let password_presence = pointer_from_wire(&p.password, p.password_null_len, version)?;
        let public_data_presence =
            pointer_from_wire(&p.public_data, p.public_data_null_len, version)?;
        let random_a_presence = pointer_from_wire(&p.random_a, p.random_a_null_len, version)?;
        let prime_p_presence = pointer_from_wire(&p.prime_p, p.prime_p_null_len, version)?;
        let base_g_presence = pointer_from_wire(&p.base_g, p.base_g_null_len, version)?;
        let subprime_q_presence = pointer_from_wire(&p.subprime_q, p.subprime_q_null_len, version)?;
        // PrimeP/BaseG share the one C ulPAndGLen (v1-only agreement).
        check_shared_len_agreement(version, &[&prime_p_presence, &base_g_presence])?;
        Ok(Self {
            password_length: p.password_length,
            password_presence,
            public_data_presence,
            random_a_presence,
            prime_p_presence,
            base_g_presence,
            subprime_q_presence,
        })
    }
}

impl ToWireV1<v1_proto::SkipjackPrivateWrapParams> for SkipjackPrivateWrapParams {
    fn to_wire_v1(&self) -> v1_proto::SkipjackPrivateWrapParams {
        let (password, password_null_len) = pointer_to_wire(&self.password_presence);
        let (public_data, public_data_null_len) = pointer_to_wire(&self.public_data_presence);
        let (random_a, random_a_null_len) = pointer_to_wire(&self.random_a_presence);
        let (prime_p, prime_p_null_len) = pointer_to_wire(&self.prime_p_presence);
        let (base_g, base_g_null_len) = pointer_to_wire(&self.base_g_presence);
        let (subprime_q, subprime_q_null_len) = pointer_to_wire(&self.subprime_q_presence);
        v1_proto::SkipjackPrivateWrapParams {
            password,
            public_data,
            password_length: self.password_length,
            random_a,
            prime_p,
            base_g,
            subprime_q,
            password_null_len,
            public_data_null_len,
            random_a_null_len,
            prime_p_null_len,
            base_g_null_len,
            subprime_q_null_len,
        }
    }
}

impl FromWire<v1_proto::SkipjackRelayxParams> for SkipjackRelayxParams {
    fn from_wire(p: &v1_proto::SkipjackRelayxParams, version: u32) -> Result<Self, CkRv> {
        Ok(Self {
            old_wrapped_x_presence: pointer_from_wire(
                &p.old_wrapped_x,
                p.old_wrapped_x_null_len,
                version,
            )?,
            old_password_presence: pointer_from_wire(
                &p.old_password,
                p.old_password_null_len,
                version,
            )?,
            old_public_data_presence: pointer_from_wire(
                &p.old_public_data,
                p.old_public_data_null_len,
                version,
            )?,
            old_random_a_presence: pointer_from_wire(
                &p.old_random_a,
                p.old_random_a_null_len,
                version,
            )?,
            new_password_presence: pointer_from_wire(
                &p.new_password,
                p.new_password_null_len,
                version,
            )?,
            new_public_data_presence: pointer_from_wire(
                &p.new_public_data,
                p.new_public_data_null_len,
                version,
            )?,
            new_random_a_presence: pointer_from_wire(
                &p.new_random_a,
                p.new_random_a_null_len,
                version,
            )?,
        })
    }
}

impl ToWireV1<v1_proto::SkipjackRelayxParams> for SkipjackRelayxParams {
    fn to_wire_v1(&self) -> v1_proto::SkipjackRelayxParams {
        let (old_wrapped_x, old_wrapped_x_null_len) = pointer_to_wire(&self.old_wrapped_x_presence);
        let (old_password, old_password_null_len) = pointer_to_wire(&self.old_password_presence);
        let (old_public_data, old_public_data_null_len) =
            pointer_to_wire(&self.old_public_data_presence);
        let (old_random_a, old_random_a_null_len) = pointer_to_wire(&self.old_random_a_presence);
        let (new_password, new_password_null_len) = pointer_to_wire(&self.new_password_presence);
        let (new_public_data, new_public_data_null_len) =
            pointer_to_wire(&self.new_public_data_presence);
        let (new_random_a, new_random_a_null_len) = pointer_to_wire(&self.new_random_a_presence);
        v1_proto::SkipjackRelayxParams {
            old_wrapped_x,
            old_password,
            old_public_data,
            old_random_a,
            new_password,
            new_public_data,
            new_random_a,
            old_wrapped_x_null_len,
            old_password_null_len,
            old_public_data_null_len,
            old_random_a_null_len,
            new_password_null_len,
            new_public_data_null_len,
            new_random_a_null_len,
        }
    }
}

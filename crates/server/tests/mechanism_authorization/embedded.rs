// CK_ULONG constants need widening on ILP32/LLP64, but are already u64 on LP64.
#![allow(clippy::unnecessary_cast)]

use super::*;
use ::pkcs11_proxy_ng::config::{
    ExtractPolicyConfig, GrantSpec, ObjectAclSpec, RichGrantConfig, TokenAccessSpec,
};
use ::pkcs11_proxy_ng::server::context_manager::ClientContextId;
use ::pkcs11_proxy_ng::server::handle_map::{BackendHandle, VirtualHandle};
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockEmbeddedHandles;

/// F1: embedded-handle tests ride KDF mechs bound to their shapes, so
/// the mock must advertise them (the shared SHA-only list would answer
/// `MECHANISM_INVALID` from the mock's support gate).
fn kdf_mechs() -> Vec<CkMechanismType> {
    vec![
        CkMechanismType::SHA256,
        CkMechanismType::SHA384,
        CkMechanismType::HKDF_DERIVE,
        CkMechanismType::SP800_108_COUNTER_KDF,
        CkMechanismType::SP800_108_FEEDBACK_KDF,
    ]
}

/// Grants mirroring `fixture()`'s object policy but with no mechanism
/// restriction (mechanism grants are not this module's subject; the KDF
/// mechs under test are not SHA).
fn unrestricted_mech_grants() -> TokenAccessSpec {
    TokenAccessSpec::Specific(
        ["Token42", "Token1"]
            .into_iter()
            .map(|label| {
                GrantSpec::Rich(RichGrantConfig {
                    token: format!("label:{label}"),
                    classes: None,
                    mechanisms: None,
                    extract: ExtractPolicyConfig::Allow,
                    objects: None,
                })
            })
            .collect(),
    )
}

async fn kdf_fixture() -> MtlsFixture {
    fixture_with_grants_and_mechs(
        [unrestricted_mech_grants(), unrestricted_mech_grants()],
        kdf_mechs(),
    )
    .await
}

async fn embedded_kdf_fixture(class_only: bool) -> MtlsFixture {
    fixture_with_grants_and_mechs(
        [embedded_grants(class_only), embedded_grants(class_only)],
        kdf_mechs(),
    )
    .await
}
use pkcs11_proxy_ng_types::{
    CkObjectHandle, HkdfParams, PointerArray, PointerBytes, PrfDataParam,
    Sp800108FeedbackKdfParams, Sp800108KdfParams,
};

fn hkdf(handle: u64) -> Option<Mechanism> {
    Some(
        Mechanism::try_from(&CkMechanism {
            // F1: HKDF rides CKM_HKDF_DERIVE (hkdf-bound in the default TOML).
            mechanism_type: CkMechanismType(0x402A),
            params: Some(CkMechanismParams::Hkdf(HkdfParams {
                extract: true,
                expand: true,
                prf_hash_mechanism: CkMechanismType::SHA256,
                salt_type: cryptoki_sys::CKF_HKDF_SALT_KEY as u64,
                salt_key_handle: CkObjectHandle(handle),
                salt_presence: PointerBytes::present_copy(&[]),
                info_presence: PointerBytes::present_copy(&[]),
            })),
        })
        .unwrap(),
    )
}

fn sp800108(value: Vec<u8>, feedback: bool) -> Option<Mechanism> {
    // F1: the counter mech engages the mock's counter-mode rule, which
    // needs a counter-format-sized iteration variable (the feedback path
    // accepts empty or format-sized, so one filler serves both).
    let iteration = vec![0u8; std::mem::size_of::<cryptoki_sys::CK_SP800_108_COUNTER_FORMAT>()];
    let data_params = vec![
        PrfDataParam {
            type_: cryptoki_sys::CK_SP800_108_ITERATION_VARIABLE as u64,
            value_presence: PointerBytes::present_copy(&iteration),
        },
        PrfDataParam {
            type_: cryptoki_sys::CK_SP800_108_KEY_HANDLE as u64,
            value_presence: PointerBytes::present_copy(&value),
        },
    ];
    Some(
        Mechanism::try_from(&CkMechanism {
            // F1: SP800-108 rides its bound counter/feedback mech numbers.
            mechanism_type: CkMechanismType(if feedback { 0x03AD } else { 0x03AC }),
            params: Some(if feedback {
                CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                    prf_type: CkMechanismType(cryptoki_sys::CKM_SHA256_HMAC as u64),
                    data_params_presence: PointerArray::present(data_params.clone()),
                    iv_presence: PointerBytes::present_copy(&[]),
                    additional_derived_keys_presence: PointerArray::present(Vec::new()),
                })
            } else {
                CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                    prf_type: CkMechanismType(cryptoki_sys::CKM_SHA256_HMAC as u64),
                    data_params_presence: PointerArray::present(data_params.clone()),
                    additional_derived_keys_presence: PointerArray::present(Vec::new()),
                })
            }),
        })
        .unwrap(),
    )
}

async fn native_handles(f: &MtlsFixture, client: &Client) -> (CkSessionHandle, CkObjectHandle) {
    f.context_manager
        .get_context(&ClientContextId(client.context.clone()), |c| {
            (
                CkSessionHandle(
                    c.session_handles.resolve(VirtualHandle(client.sessions[0])).unwrap().0,
                ),
                CkObjectHandle(c.object_handles.resolve(VirtualHandle(client.keys[0])).unwrap().0),
            )
        })
        .await
        .unwrap()
}

async fn owned_and_foreign_remapping(entry: Entry) {
    let f = kdf_fixture().await;
    // B allocates native objects first, making A's virtual and native handles
    // numerically distinct without fabricating authenticated contexts.
    let mut other = open(&f, true).await;
    let mut client = open(&f, false).await;
    let foreign = other
        .rpc
        .create_object(CreateObjectRequest {
            client_context_id: other.context.clone(),
            session_handle: other.sessions[0],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(foreign.ck_rv, CkRv::OK.0);
    assert_eq!(foreign.object_handle, 3);
    let (_, native) = native_handles(&f, &client).await;
    assert_ne!(native.0, client.keys[0]);
    for handle in [foreign.object_handle, u64::MAX] {
        let before = f.backend.mechanism_entry_count(entry);
        assert_eq!(
            invoke(&mut client, 0, entry, hkdf(handle)).await,
            CkRv::OBJECT_HANDLE_INVALID.0,
            "{entry:?}, handle={handle}"
        );
        assert_eq!(f.backend.mechanism_entry_count(entry), before);
    }
    let key = client.keys[0];
    let before = f.backend.mechanism_entry_count(entry);
    assert_eq!(invoke(&mut client, 0, entry, hkdf(key)).await, CkRv::OK.0);
    assert_eq!(f.backend.mechanism_entry_count(entry), before + 1);
    assert_eq!(
        f.backend.last_embedded_handles(entry),
        Some(MockEmbeddedHandles::HkdfSalt(native.0))
    );
    clean_operation(&mut client, 0, entry).await;
    let before = f.backend.mechanism_entry_count(entry);
    assert_eq!(invoke(&mut client, 0, entry, hkdf(0)).await, CkRv::OK.0);
    assert_eq!(f.backend.mechanism_entry_count(entry), before + 1);
    assert_eq!(f.backend.last_embedded_handles(entry), Some(MockEmbeddedHandles::HkdfSalt(0)));
}

#[tokio::test]
async fn digest_init_remaps_owned_and_rejects_foreign_embedded_handles() {
    owned_and_foreign_remapping(Entry::DigestInit).await;
}

#[tokio::test]
async fn verify_signature_init_remaps_owned_and_rejects_foreign_embedded_handles() {
    owned_and_foreign_remapping(Entry::VerifySignatureInit).await;
}

#[tokio::test]
async fn generate_key_remaps_owned_and_rejects_foreign_embedded_handles() {
    owned_and_foreign_remapping(Entry::GenerateKey).await;
}

#[tokio::test]
async fn generate_key_pair_remaps_owned_and_rejects_foreign_embedded_handles() {
    owned_and_foreign_remapping(Entry::GenerateKeyPair).await;
}

fn embedded_grants(class_only: bool) -> TokenAccessSpec {
    TokenAccessSpec::Specific(
        ["Token42", "Token1"]
            .into_iter()
            .map(|label| {
                GrantSpec::Rich(RichGrantConfig {
                    token: format!("label:{label}"),
                    classes: class_only.then(|| vec!["CKO_SECRET_KEY".into()]),
                    mechanisms: None,
                    extract: ExtractPolicyConfig::Allow,
                    objects: (!class_only).then(|| vec![ObjectAclSpec::Bare("a1".into())]),
                })
            })
            .collect(),
    )
}

// A token handle may remain mapped after its externally managed class/UID has
// changed. Seed that documented stale mapping (without creator exemption) to
// exercise use-time policy; public discovery would correctly filter it out.
async fn stale_token_mapping(
    f: &MtlsFixture,
    client: &Client,
    class: CkObjectClass,
    uid: u8,
) -> (u64, u64) {
    let (session, _) = native_handles(f, client).await;
    // Keep the native object distinct from the native session, detecting use
    // of an object handle in place of the session during metadata lookup.
    for _ in 0..4 {
        f.backend.create_object(session, Some(&[])).unwrap();
    }
    let native = f
        .backend
        .create_object(
            session,
            Some(&[
                CkAttribute {
                    attr_type: CkAttributeType::CLASS,
                    value: Some(CkAttributeValue::Ulong(class.0)),
                },
                CkAttribute {
                    attr_type: CkAttributeType::TOKEN,
                    value: Some(CkAttributeValue::Bool(true)),
                },
                CkAttribute {
                    attr_type: CkAttributeType::UNIQUE_ID,
                    value: Some(CkAttributeValue::Bytes(vec![uid].into())),
                },
            ]),
        )
        .unwrap();
    let virtual_handle = f
        .context_manager
        .get_context(&ClientContextId(client.context.clone()), |c| {
            c.object_handles.insert(BackendHandle(native.0)).0
        })
        .await
        .unwrap();
    assert_ne!(virtual_handle, native.0);
    assert_ne!(session.0, native.0);
    (virtual_handle, native.0)
}

#[tokio::test]
async fn shared_remapper_enforces_class_only_embedded_policy() {
    let f = embedded_kdf_fixture(true).await;
    let mut client = open(&f, false).await;
    let (denied, _) = stale_token_mapping(&f, &client, CkObjectClass::PRIVATE_KEY, 0xa1).await;
    let before = f.backend.mechanism_entry_count(Entry::DeriveKey);
    assert_eq!(
        invoke(&mut client, 0, Entry::DeriveKey, hkdf(denied)).await,
        CkRv::OBJECT_HANDLE_INVALID.0
    );
    assert_eq!(f.backend.mechanism_entry_count(Entry::DeriveKey), before);
    let (allowed, native) = stale_token_mapping(&f, &client, CkObjectClass::SECRET_KEY, 0xa1).await;
    assert_eq!(invoke(&mut client, 0, Entry::DeriveKey, hkdf(allowed)).await, CkRv::OK.0);
    assert_eq!(f.backend.mechanism_entry_count(Entry::DeriveKey), before + 1);
    assert_eq!(
        f.backend.last_embedded_handles(Entry::DeriveKey),
        Some(MockEmbeddedHandles::HkdfSalt(native))
    );
}

async fn sp800108_denied_embedded_key(class_only: bool) {
    let f = embedded_kdf_fixture(class_only).await;
    let mut client = open(&f, false).await;
    let (denied, _) = stale_token_mapping(
        &f,
        &client,
        if class_only { CkObjectClass::PRIVATE_KEY } else { CkObjectClass::SECRET_KEY },
        0xb2,
    )
    .await;
    for feedback in [false, true] {
        for width in [4, 8] {
            let value = if width == 4 {
                (denied as u32).to_ne_bytes().to_vec()
            } else {
                denied.to_ne_bytes().to_vec()
            };
            let before = f.backend.mechanism_entry_count(Entry::DeriveKey);
            assert_eq!(
                invoke(&mut client, 0, Entry::DeriveKey, sp800108(value, feedback)).await,
                CkRv::OBJECT_HANDLE_INVALID.0
            );
            assert_eq!(
                f.backend.mechanism_entry_count(Entry::DeriveKey),
                before,
                "denied nonzero key must not be dispatched or serialized as zero"
            );
        }
    }
}

#[tokio::test]
async fn sp800108_enforces_class_only_embedded_policy() {
    sp800108_denied_embedded_key(true).await;
}

#[tokio::test]
async fn sp800108_denied_nonzero_handle_never_reaches_backend_as_zero() {
    sp800108_denied_embedded_key(false).await;
}

#[tokio::test]
async fn sp800108_allowed_handle_uses_real_session_for_metadata_and_preserves_width() {
    for class_only in [false, true] {
        let f = embedded_kdf_fixture(class_only).await;
        let mut client = open(&f, false).await;
        let (allowed, native) =
            stale_token_mapping(&f, &client, CkObjectClass::SECRET_KEY, 0xa1).await;
        for feedback in [false, true] {
            for value in [(allowed as u32).to_ne_bytes().to_vec(), allowed.to_ne_bytes().to_vec()] {
                let width = value.len();
                let before = f.backend.mechanism_entry_count(Entry::DeriveKey);
                assert_eq!(
                    invoke(&mut client, 0, Entry::DeriveKey, sp800108(value, feedback)).await,
                    CkRv::OK.0
                );
                assert_eq!(f.backend.mechanism_entry_count(Entry::DeriveKey), before + 1);
                assert_eq!(
                    f.backend.last_embedded_handles(Entry::DeriveKey),
                    Some(MockEmbeddedHandles::Sp800108(vec![(native, width)]))
                );
            }
        }
    }
}

#[tokio::test]
async fn sp800108_missing_and_malformed_handles_reject_before_dispatch() {
    let f = kdf_fixture().await;
    let mut client = open(&f, false).await;
    for feedback in [false, true] {
        for (value, expected) in [
            (vec![1, 2, 3], CkRv::MECHANISM_PARAM_INVALID),
            (u64::MAX.to_ne_bytes().to_vec(), CkRv::OBJECT_HANDLE_INVALID),
            (0u32.to_ne_bytes().to_vec(), CkRv::OBJECT_HANDLE_INVALID),
            (0u64.to_ne_bytes().to_vec(), CkRv::OBJECT_HANDLE_INVALID),
        ] {
            let before = f.backend.mechanism_entry_count(Entry::DeriveKey);
            assert_eq!(
                invoke(&mut client, 0, Entry::DeriveKey, sp800108(value, feedback)).await,
                expected.0
            );
            assert_eq!(f.backend.mechanism_entry_count(Entry::DeriveKey), before);
        }
    }
}

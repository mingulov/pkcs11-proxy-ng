//! Public mTLS authorization tests. SHA digest identifiers on KEM/generation
//! deliberately exercise permissive mock dispatch: they are not evidence that
//! real providers support those mechanism/operation combinations.

use std::sync::Arc;

use ::pkcs11_proxy_ng::config::{ExtractPolicyConfig, GrantSpec, RichGrantConfig, TokenAccessSpec};
use ::pkcs11_proxy_ng::server::slot_map::BackendSlotId;
use pkcs11_proxy_ng_backend::mock::{MockBackend, MockMechanismEntry as Entry};
use pkcs11_proxy_ng_proto::*;
use pkcs11_proxy_ng_types::*;

#[path = "support/mtls_fixture.rs"]
mod mtls_fixture;
use mtls_fixture::MtlsFixture;

#[path = "mechanism_authorization/embedded.rs"]
mod embedded;

fn grants(reverse: bool) -> TokenAccessSpec {
    TokenAccessSpec::Specific(
        ["Token42", "Token1"]
            .into_iter()
            .enumerate()
            .map(|(index, label)| {
                GrantSpec::Rich(RichGrantConfig {
                    token: format!("label:{label}"),
                    classes: None,
                    mechanisms: Some(vec![
                        if (index == 1) ^ reverse { "CKM_SHA384" } else { "CKM_SHA256" }.into(),
                    ]),
                    extract: ExtractPolicyConfig::Allow,
                    objects: None,
                })
            })
            .collect(),
    )
}

async fn fixture_with_grants(grants: [TokenAccessSpec; 2]) -> MtlsFixture {
    let backend = Arc::new(MockBackend::new(
        vec![CkSlotId(42), CkSlotId(1)],
        vec![CkMechanismType::SHA256, CkMechanismType::SHA384],
    ));
    backend.set_slot_token_identity(CkSlotId(42), "Token42".into(), "serial42".into());
    backend.set_slot_token_identity(CkSlotId(1), "Token1".into(), "serial1".into());
    mtls_fixture::start_mtls_daemon(backend, grants).await
}

async fn fixture() -> MtlsFixture {
    fixture_with_grants([grants(false), grants(true)]).await
}

struct Client {
    rpc: Pkcs11ProxyClient<tonic::transport::Channel>,
    context: String,
    sessions: [u64; 2],
    keys: [u64; 2],
}

async fn open(f: &MtlsFixture, second: bool) -> Client {
    let mut rpc = f.raw_client(second).await;
    let init = rpc.initialize(InitializeRequest::default()).await.unwrap().into_inner();
    assert_eq!(init.ck_rv, CkRv::OK.0);
    let context = init.client_context_id;
    let slots = rpc
        .get_slot_list(GetSlotListRequest {
            client_context_id: context.clone(),
            token_present: true,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(slots.ck_rv, CkRv::OK.0);
    assert_eq!(slots.slot_ids, [1, 2]);
    let mut sessions = [0; 2];
    let mut keys = [0; 2];
    for (index, slot_id) in slots.slot_ids.into_iter().enumerate() {
        let session = rpc
            .open_session(OpenSessionRequest {
                client_context_id: context.clone(),
                slot_id,
                flags: CkSessionFlags::SERIAL_SESSION | CkSessionFlags::RW_SESSION,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(session.ck_rv, CkRv::OK.0);
        sessions[index] = session.session_handle;
        let key = rpc
            .create_object(CreateObjectRequest {
                client_context_id: context.clone(),
                session_handle: session.session_handle,
                template: [
                    CkAttribute {
                        attr_type: CkAttributeType::CLASS,
                        value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
                    },
                    CkAttribute {
                        attr_type: CkAttributeType::TOKEN,
                        value: Some(CkAttributeValue::Bool(false)),
                    },
                    CkAttribute {
                        attr_type: CkAttributeType::UNIQUE_ID,
                        value: Some(CkAttributeValue::Bytes(vec![0xa1])),
                    },
                ]
                .iter()
                .map(Attribute::from)
                .collect(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(key.ck_rv, CkRv::OK.0);
        keys[index] = key.object_handle;
    }
    Client { rpc, context, sessions, keys }
}

async fn invoke(
    client: &mut Client,
    index: usize,
    entry: Entry,
    mechanism: Option<Mechanism>,
) -> u64 {
    let client_context_id = client.context.clone();
    let session_handle = client.sessions[index];
    let key_handle = client.keys[index];
    match entry {
        Entry::DigestInit => {
            client
                .rpc
                .digest_init(DigestInitRequest { client_context_id, session_handle, mechanism })
                .await
                .unwrap()
                .into_inner()
                .ck_rv
        }
        Entry::VerifySignatureInit => {
            client
                .rpc
                .verify_signature_init(VerifySignatureInitRequest {
                    client_context_id,
                    session_handle,
                    mechanism,
                    key_handle,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner()
                .ck_rv
        }
        Entry::EncapsulateKey => {
            let r = client
                .rpc
                .encapsulate_key(EncapsulateKeyRequest {
                    client_context_id,
                    session_handle,
                    mechanism,
                    public_key_handle: key_handle,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            if r.ck_rv == CkRv::OK.0 {
                assert_ne!(r.key_handle, 0);
            } else {
                assert_eq!(r.key_handle, 0);
                assert!(r.ciphertext.is_empty());
            }
            r.ck_rv
        }
        Entry::EncapsulateKeyExact => {
            let r = client
                .rpc
                .encapsulate_key_exact(EncapsulateKeyExactRequest {
                    exact_output_effects_version: 1,
                    client_context_id,
                    session_handle,
                    mechanism,
                    public_key_handle: key_handle,
                    output_spec: Some(OutputBufferSpec {
                        buffer_present: true,
                        buffer_len: 128,
                        length_pointer_null: false,
                    }),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner()
                .result
                .expect("exact result");
            if r.ck_rv == CkRv::OK.0 {
                assert_ne!(r.object_handle, 0);
            } else {
                assert_eq!(r.object_handle, 0);
                assert_eq!(r.returned_len, 0);
                assert!(r.value.is_none());
            }
            r.ck_rv
        }
        Entry::DecapsulateKey => {
            let r = client
                .rpc
                .decapsulate_key(DecapsulateKeyRequest {
                    client_context_id,
                    session_handle,
                    mechanism,
                    private_key_handle: key_handle,
                    ciphertext: vec![1],
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            if r.ck_rv == CkRv::OK.0 {
                assert_ne!(r.key_handle, 0);
            } else {
                assert_eq!(r.key_handle, 0);
            }
            r.ck_rv
        }
        Entry::SignInit => {
            client
                .rpc
                .sign_init(SignInitRequest {
                    client_context_id,
                    session_handle,
                    mechanism,
                    key_handle,
                })
                .await
                .unwrap()
                .into_inner()
                .ck_rv
        }
        Entry::GenerateKey => {
            let r = client
                .rpc
                .generate_key(GenerateKeyRequest {
                    client_context_id,
                    session_handle,
                    mechanism,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            if r.ck_rv != CkRv::OK.0 {
                assert_eq!(r.key_handle, 0);
                assert!(r.mechanism_out.is_none());
            }
            r.ck_rv
        }
        Entry::GenerateKeyPair => {
            let r = client
                .rpc
                .generate_key_pair(GenerateKeyPairRequest {
                    client_context_id,
                    session_handle,
                    mechanism,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            if r.ck_rv != CkRv::OK.0 {
                assert_eq!((r.public_key_handle, r.private_key_handle), (0, 0));
            }
            r.ck_rv
        }
        Entry::DeriveKey => {
            let r = client
                .rpc
                .derive_key(DeriveKeyRequest {
                    client_context_id,
                    session_handle,
                    mechanism,
                    base_key_handle: key_handle,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            if r.ck_rv != CkRv::OK.0 {
                assert_eq!(r.key_handle, 0);
            }
            r.ck_rv
        }
        _ => panic!("cancellation entries are observed through the initializer"),
    }
}

fn mechanism(kind: CkMechanismType) -> Option<Mechanism> {
    Some(Mechanism { mechanism_type: kind.0, params: None })
}

async fn clean_operation(client: &mut Client, index: usize, entry: Entry) {
    if matches!(entry, Entry::DigestInit | Entry::VerifySignatureInit | Entry::SignInit) {
        assert_eq!(invoke(client, index, entry, None).await, CkRv::OK.0);
    }
}

async fn check_mechanism_grants(entry: Entry) {
    let f = fixture().await;
    for second in [false, true] {
        let mut client = open(&f, second).await;
        for cold in [false, true] {
            for index in 0..2 {
                let (allowed, denied) = if (index == 1) ^ second {
                    (CkMechanismType::SHA384, CkMechanismType::SHA256)
                } else {
                    (CkMechanismType::SHA256, CkMechanismType::SHA384)
                };
                for (kind, want) in [(allowed, CkRv::OK), (denied, CkRv::MECHANISM_INVALID)] {
                    if cold {
                        f.context_manager
                            .invalidate_token_info(BackendSlotId(CkSlotId([42, 1][index])));
                    }
                    let before = f.backend.mechanism_entry_count(entry);
                    let tokens = f.backend.token_info_requested_slots().len();
                    let attrs = f.backend.attr_get_call_count();
                    let rv = invoke(&mut client, index, entry, mechanism(kind)).await;
                    assert_eq!(
                        rv, want.0,
                        "{entry:?}: identity B={second}, slot={index}, cold={cold}"
                    );
                    assert_eq!(
                        f.backend.mechanism_entry_count(entry) - before,
                        usize::from(want == CkRv::OK)
                    );
                    assert_eq!(
                        f.backend.attr_get_call_count(),
                        attrs,
                        "mechanism-only policy must not read objects"
                    );
                    assert_eq!(
                        &f.backend.token_info_requested_slots()[tokens..],
                        if cold { vec![CkSlotId([42, 1][index])] } else { vec![] }
                    );
                    if want == CkRv::OK {
                        clean_operation(&mut client, index, entry).await;
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn digest_init_enforces_warm_and_cold_backend_slot_grants() {
    check_mechanism_grants(Entry::DigestInit).await;
}

#[tokio::test]
async fn verify_signature_init_enforces_warm_and_cold_backend_slot_grants() {
    check_mechanism_grants(Entry::VerifySignatureInit).await;
}

#[tokio::test]
async fn encapsulate_key_enforces_warm_and_cold_backend_slot_grants() {
    check_mechanism_grants(Entry::EncapsulateKey).await;
}

#[tokio::test]
async fn decapsulate_key_enforces_warm_and_cold_backend_slot_grants() {
    check_mechanism_grants(Entry::DecapsulateKey).await;
}

#[tokio::test]
async fn encapsulate_key_exact_enforces_warm_and_cold_backend_slot_grants() {
    check_mechanism_grants(Entry::EncapsulateKeyExact).await;
}

const MISSING_GATES: [Entry; 5] = [
    Entry::DigestInit,
    Entry::VerifySignatureInit,
    Entry::EncapsulateKey,
    Entry::DecapsulateKey,
    Entry::EncapsulateKeyExact,
];

#[tokio::test]
async fn mechanism_policy_fails_closed_when_token_metadata_fails() {
    let f = fixture().await;
    let mut client = open(&f, false).await;
    f.backend.inject_error(CkRv::DEVICE_ERROR);
    for entry in MISSING_GATES {
        f.context_manager.invalidate_token_info(BackendSlotId(CkSlotId(42)));
        let before = f.backend.mechanism_entry_count(entry);
        let tokens = f.backend.token_info_requested_slots().len();
        assert_eq!(
            invoke(&mut client, 0, entry, mechanism(CkMechanismType::SHA256)).await,
            CkRv::MECHANISM_INVALID.0,
            "{entry:?}"
        );
        assert_eq!(f.backend.mechanism_entry_count(entry), before);
        assert_eq!(&f.backend.token_info_requested_slots()[tokens..], [CkSlotId(42)]);
    }
}

#[tokio::test]
async fn null_mechanism_cancellation_bypasses_mechanism_policy() {
    let f = fixture().await;
    let mut client = open(&f, false).await;
    for (entry, cancel) in [
        (Entry::DigestInit, Entry::DigestInitCancel),
        (Entry::VerifySignatureInit, Entry::VerifySignatureCancel),
    ] {
        assert_eq!(
            invoke(&mut client, 0, entry, mechanism(CkMechanismType::SHA256)).await,
            CkRv::OK.0
        );
        f.context_manager.invalidate_token_info(BackendSlotId(CkSlotId(42)));
        let tokens = f.backend.token_info_requested_slots().len();
        let before = f.backend.mechanism_entry_count(cancel);
        // Cancellation ignores an otherwise invalid primary key.
        let key = client.keys[0];
        client.keys[0] = u64::MAX;
        assert_eq!(invoke(&mut client, 0, entry, None).await, CkRv::OK.0);
        client.keys[0] = key;
        assert_eq!(f.backend.mechanism_entry_count(cancel), before + 1);
        assert_eq!(f.backend.token_info_requested_slots().len(), tokens);
    }
}

#[tokio::test]
async fn no_mechanism_policy_preserves_backend_results() {
    let f =
        fixture_with_grants([TokenAccessSpec::All("*".into()), TokenAccessSpec::All("*".into())])
            .await;
    let mut client = open(&f, false).await;
    for entry in MISSING_GATES {
        let before = f.backend.mechanism_entry_count(entry);
        assert_eq!(
            invoke(&mut client, 0, entry, mechanism(CkMechanismType::SHA384)).await,
            CkRv::OK.0
        );
        assert_eq!(f.backend.mechanism_entry_count(entry), before + 1);
        clean_operation(&mut client, 0, entry).await;
    }
    f.backend.inject_error(CkRv::DEVICE_ERROR);
    let before = f.backend.mechanism_entry_count(Entry::EncapsulateKey);
    assert_eq!(
        invoke(&mut client, 0, Entry::EncapsulateKey, mechanism(CkMechanismType::SHA256)).await,
        CkRv::DEVICE_ERROR.0
    );
    assert_eq!(f.backend.mechanism_entry_count(Entry::EncapsulateKey), before + 1);
}

#[tokio::test]
async fn already_guarded_sign_generation_and_derivation_preserve_admission() {
    for entry in [Entry::SignInit, Entry::GenerateKey, Entry::GenerateKeyPair, Entry::DeriveKey] {
        check_mechanism_grants(entry).await;
    }
}

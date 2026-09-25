use std::sync::Arc;

use ::pkcs11_proxy_ng::config::{
    ExtractPolicyConfig, GrantSpec, ObjectAclSpec, RichGrantConfig, TokenAccessSpec,
};
use ::pkcs11_proxy_ng::server::context_manager::ClientContextId;
use ::pkcs11_proxy_ng::server::context_manager::LoginState;
use ::pkcs11_proxy_ng::server::handle_map::VirtualHandle;
use ::pkcs11_proxy_ng::server::slot_map::BackendSlotId;
use pkcs11_proxy_ng_backend::{Pkcs11Backend, mock::MockBackend};
use pkcs11_proxy_ng_proto::*;
use pkcs11_proxy_ng_types::*;

#[path = "support/mtls_fixture.rs"]
mod mtls_fixture;
use mtls_fixture::MtlsFixture;

fn grants(with_object_acl: bool) -> TokenAccessSpec {
    TokenAccessSpec::Specific(vec![
        GrantSpec::Rich(RichGrantConfig {
            token: "label:Token42".into(),
            classes: None,
            mechanisms: Some(vec!["CKM_SHA256".into(), "CKM_RSA_PKCS".into()]),
            extract: ExtractPolicyConfig::Allow,
            objects: with_object_acl.then(|| vec![ObjectAclSpec::Bare("a1".into())]),
        }),
        GrantSpec::Rich(RichGrantConfig {
            token: "label:Token1".into(),
            classes: None,
            mechanisms: Some(vec!["CKM_SHA384".into(), "CKM_RSA_PKCS".into()]),
            extract: ExtractPolicyConfig::Deny,
            objects: with_object_acl.then(|| vec![ObjectAclSpec::Bare("b2".into())]),
        }),
    ])
}

async fn fixture() -> MtlsFixture {
    fixture_with_grants([grants(true), grants(true)]).await
}

async fn fixture_with_grants(client_grants: [TokenAccessSpec; 2]) -> MtlsFixture {
    let backend = Arc::new(MockBackend::new(
        vec![CkSlotId(42), CkSlotId(1)],
        vec![CkMechanismType::SHA256, CkMechanismType::SHA384, CkMechanismType::RSA_PKCS],
    ));
    backend.set_slot_token_identity(CkSlotId(42), "Token42".into(), "serial42".into());
    backend.set_slot_token_identity(CkSlotId(1), "Token1".into(), "serial1".into());
    mtls_fixture::start_mtls_daemon(backend, client_grants).await
}

struct Client {
    rpc: Pkcs11ProxyClient<tonic::transport::Channel>,
    context: String,
    sessions: [u64; 2],
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
    assert_eq!(slots.slot_ids, vec![1, 2]);
    let mut sessions = [0; 2];
    for (index, slot_id) in [1, 2].into_iter().enumerate() {
        let response = rpc
            .open_session(OpenSessionRequest {
                client_context_id: context.clone(),
                slot_id,
                flags: (CkSessionFlags::SERIAL_SESSION | CkSessionFlags::RW_SESSION).0,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.ck_rv, CkRv::OK.0);
        sessions[index] = response.session_handle;
    }
    Client { rpc, context, sessions }
}

async fn native_session(f: &MtlsFixture, client: &Client, index: usize) -> CkSessionHandle {
    f.context_manager
        .get_context(&ClientContextId(client.context.clone()), |ctx| {
            CkSessionHandle(
                ctx.session_handles.resolve(VirtualHandle(client.sessions[index])).unwrap().0,
            )
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn public_open_records_backend_slot_when_virtual_id_matches_another_backend_slot() {
    let f = fixture().await;
    let client = open(&f, false).await;
    for (index, expected) in [42, 1].into_iter().enumerate() {
        let native = native_session(&f, &client, index).await;
        assert_eq!(f.backend.get_session_info(native).unwrap().slot_id, CkSlotId(expected));
        let recorded = f
            .context_manager
            .slot_for_session(
                &ClientContextId(client.context.clone()),
                VirtualHandle(client.sessions[index]),
            )
            .await
            .unwrap();
        assert_eq!(
            recorded,
            ::pkcs11_proxy_ng::server::slot_map::BackendSlotId(CkSlotId(expected)),
            "recorded session owner must be the native backend slot"
        );
    }
}

#[tokio::test]
async fn mechanism_grants_follow_session_backend_slot_with_warm_and_cold_cache() {
    // Neither object nor class restrictions may fetch token identity before
    // SignInit's mechanism gate; the mechanism grant owns this cold-cache probe.
    let f = fixture_with_grants([grants(false), grants(false)]).await;
    preload_objects(&f);
    let mut client = open(&f, false).await;
    // D6(1): USE of find-registered (unknown-privacy) keys while logged out
    // probes CKA_PRIVATE; log into both slots so this mechanism-precedence
    // test keeps its zero-metadata-before-gate profile. Login performs no
    // token-info fetch, so the cold/warm assertions below are unaffected.
    assert_eq!(login(&mut client, 0, b"pin42").await, CkRv::OK.0);
    assert_eq!(login(&mut client, 1, b"pin1").await, CkRv::OK.0);
    let keys = find(&mut client, 0).await;
    assert_eq!(keys.len(), 2);
    for cold in [false, true] {
        for (index, mechanism, expected) in [
            (0, CkMechanismType::SHA384, CkRv::MECHANISM_INVALID),
            (0, CkMechanismType::SHA256, CkRv::OK),
            (1, CkMechanismType::SHA256, CkRv::MECHANISM_INVALID),
            (1, CkMechanismType::SHA384, CkRv::OK),
        ] {
            if cold {
                f.context_manager.invalidate_token_info(BackendSlotId(CkSlotId([42, 1][index])));
            }
            let use_before = f.backend.token_info_requested_slots().len();
            let attributes_before = f.backend.attr_get_call_count();
            let response = client
                .rpc
                .sign_init(SignInitRequest {
                    client_context_id: client.context.clone(),
                    session_handle: client.sessions[index],
                    key_handle: keys[index],
                    mechanism: Some(Mechanism { mechanism_type: mechanism.0, params: None }),
                })
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.ck_rv, expected.0, "slot index {index}, cold={cold}");
            assert_eq!(
                f.backend.attr_get_call_count(),
                attributes_before,
                "object/class metadata must not precede the mechanism-only gate"
            );
            assert_eq!(
                &f.backend.token_info_requested_slots()[use_before..],
                if cold { vec![CkSlotId([42, 1][index])] } else { vec![] },
                "SignInit must independently exercise the requested cache state"
            );
            if expected == CkRv::OK {
                let cancel = client
                    .rpc
                    .sign_init(SignInitRequest {
                        client_context_id: client.context.clone(),
                        session_handle: client.sessions[index],
                        key_handle: keys[index],
                        mechanism: None,
                    })
                    .await
                    .unwrap()
                    .into_inner();
                assert_eq!(cancel.ck_rv, CkRv::OK.0);
            }
        }
    }
}

fn preload_objects(f: &MtlsFixture) -> [CkObjectHandle; 2] {
    use pkcs11_proxy_ng_backend::mock::MockAttributeSlot;
    let objects = [(42, 0xa1), (1, 0xb2)].map(|(slot, uid)| {
        let session = f.backend.open_session(CkSlotId(slot), CkSessionFlags::default()).unwrap();
        let object = f
            .backend
            .create_object(
                session,
                Some(&[
                    CkAttribute {
                        attr_type: CkAttributeType::TOKEN,
                        value: Some(CkAttributeValue::Bool(true)),
                    },
                    CkAttribute {
                        attr_type: CkAttributeType::CLASS,
                        value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
                    },
                ]),
            )
            .unwrap();
        f.backend.set_attribute(
            object,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(vec![uid].into())),
        );
        // F-04: declare CKA_PRIVATE=false (the native default for objects
        // created without it) so the logged-out login filter keeps these
        // authz-policy fixtures visible.
        f.backend.set_attribute(
            object,
            CkAttributeType::PRIVATE,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        object
    });
    f.backend.set_find_objects_result(objects.to_vec());
    objects
}

async fn find(client: &mut Client, index: usize) -> Vec<u64> {
    let context = client.context.clone();
    let session_handle = client.sessions[index];
    let init = client
        .rpc
        .find_objects_init(FindObjectsInitRequest {
            client_context_id: context.clone(),
            session_handle,
            template: vec![],
            template_null: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(init.ck_rv, CkRv::OK.0);
    let found = client
        .rpc
        .find_objects(FindObjectsRequest {
            client_context_id: context.clone(),
            session_handle,
            max_object_count: 10,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(found.ck_rv, CkRv::OK.0);
    let finish = client
        .rpc
        .find_objects_final(FindObjectsFinalRequest { client_context_id: context, session_handle })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(finish.ck_rv, CkRv::OK.0);
    found.object_handles
}

#[tokio::test]
async fn object_grants_follow_session_backend_slot_with_warm_and_cold_cache() {
    let f = fixture().await;
    let native_objects = preload_objects(&f);
    let mut client = open(&f, false).await;
    for cold in [false, true] {
        if cold {
            f.context_manager.invalidate_token_info(BackendSlotId(CkSlotId(42)));
            f.context_manager.invalidate_token_info(BackendSlotId(CkSlotId(1)));
        }
        let before = f.backend.token_info_requested_slots().len();
        let mut handles = [0; 2];
        for index in 0..2 {
            let found = find(&mut client, index).await;
            assert_eq!(found.len(), 1, "exactly the owning token's allowed object is discovered");
            handles[index] = found[0];
            let native = f
                .context_manager
                .get_context(&ClientContextId(client.context.clone()), |ctx| {
                    assert!(!ctx.created_objects.contains(&VirtualHandle(found[0])));
                    ctx.object_handles.resolve(VirtualHandle(found[0])).unwrap().0
                })
                .await
                .unwrap();
            assert_eq!(native, native_objects[index].0);
        }
        // Attribute discovery has its own cold-cache assertion. The use-time
        // probes below must fetch identity independently of this discovery.
        assert_eq!(
            &f.backend.token_info_requested_slots()[before..],
            if cold { &[CkSlotId(42), CkSlotId(1)][..] } else { &[][..] }
        );
        for index in 0..2 {
            for (object_index, &object_handle) in handles.iter().enumerate() {
                if cold {
                    f.context_manager
                        .invalidate_token_info(BackendSlotId(CkSlotId([42, 1][index])));
                }
                let use_before = f.backend.token_info_requested_slots().len();
                let result = client
                    .rpc
                    .get_object_size(GetObjectSizeRequest {
                        client_context_id: client.context.clone(),
                        session_handle: client.sessions[index],
                        object_handle,
                    })
                    .await
                    .unwrap()
                    .into_inner();
                let expected =
                    if index == object_index { CkRv::OK } else { CkRv::OBJECT_HANDLE_INVALID };
                assert_eq!(
                    result.ck_rv, expected.0,
                    "slot={index}, object={object_index}, cold={cold}"
                );
                assert_eq!(
                    &f.backend.token_info_requested_slots()[use_before..],
                    if cold { vec![CkSlotId([42, 1][index])] } else { vec![] },
                    "GetObjectSize must independently exercise the requested cache state"
                );
            }
        }
    }
}

#[tokio::test]
async fn ordinary_wrap_extract_grant_follows_session_backend_slot() {
    let f = fixture().await;
    preload_objects(&f);
    let mut client = open(&f, false).await;
    for (index, expected) in [(0, CkRv::OK), (1, CkRv::KEY_FUNCTION_NOT_PERMITTED)] {
        let objects = find(&mut client, index).await;
        assert_eq!(objects.len(), 1);
        let result = client
            .rpc
            .wrap_key(WrapKeyRequest {
                client_context_id: client.context.clone(),
                session_handle: client.sessions[index],
                wrapping_key_handle: objects[0],
                key_handle: objects[0],
                mechanism: Some(Mechanism {
                    mechanism_type: CkMechanismType::RSA_PKCS.0,
                    params: None,
                }),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(result.ck_rv, expected.0);
        assert_eq!(result.wrapped_key.is_empty(), expected != CkRv::OK);
    }
}

async fn login(client: &mut Client, index: usize, pin: &[u8]) -> u64 {
    client
        .rpc
        .login(LoginRequest {
            client_context_id: client.context.clone(),
            session_handle: client.sessions[index],
            user_type: CkUserType::User as u64,
            pin: Some(pin.to_vec()),
        })
        .await
        .unwrap()
        .into_inner()
        .ck_rv
}

#[tokio::test]
async fn login_state_is_keyed_by_backend_slot_and_second_context_gets_already() {
    // Per-slot logical login state is keyed by backend slot. A second
    // context reaches the backend, whose mock token answers ALREADY without
    // checking the PIN; the proxy must not mint a login for that context.
    let f = fixture().await;
    let mut a = open(&f, false).await;
    let mut b = open(&f, true).await;
    for (index, slot, pin) in [(0, 42, &b"slot42-pin"[..]), (1, 1, &b"slot1-pin"[..])] {
        assert_eq!(login(&mut a, index, pin).await, CkRv::OK.0);
        let state = f
            .context_manager
            .get_context(&ClientContextId(a.context.clone()), |ctx| {
                ctx.login_state.get(&BackendSlotId(CkSlotId(slot))).copied()
            })
            .await
            .unwrap();
        assert_eq!(state, Some(LoginState::User));
    }
    assert_eq!(f.backend.login_call_count(), 2);
    // Both slots are held by `a`: `b` gets the mock backend's ALREADY on
    // both, whatever PIN it presents. All four attempts reach the backend.
    assert_eq!(login(&mut b, 0, b"slot1-pin").await, CkRv::USER_ALREADY_LOGGED_IN.0);
    assert_eq!(login(&mut b, 1, b"slot42-pin").await, CkRv::USER_ALREADY_LOGGED_IN.0);
    assert_eq!(login(&mut b, 0, b"slot42-pin").await, CkRv::USER_ALREADY_LOGGED_IN.0);
    assert_eq!(login(&mut b, 1, b"slot1-pin").await, CkRv::USER_ALREADY_LOGGED_IN.0);
    assert_eq!(f.backend.login_call_count(), 6, "all four refused logins must reach the backend");
    for slot in [42, 1] {
        let state = f
            .context_manager
            .get_context(&ClientContextId(b.context.clone()), |ctx| {
                ctx.login_state.get(&BackendSlotId(CkSlotId(slot))).copied()
            })
            .await
            .unwrap();
        assert_eq!(state, None, "no logical login may be minted for the refused context");
    }
}

#[tokio::test]
async fn close_all_uses_backend_ownership_and_preserves_other_slots_and_contexts() {
    let f = fixture().await;
    let mut a = open(&f, false).await;
    let b = open(&f, true).await;
    let native_a = [native_session(&f, &a, 0).await, native_session(&f, &a, 1).await];
    let native_b = [native_session(&f, &b, 0).await, native_session(&f, &b, 1).await];
    let close = a
        .rpc
        .close_all_sessions(CloseAllSessionsRequest {
            client_context_id: a.context.clone(),
            slot_id: 1,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(close.ck_rv, CkRv::OK.0);
    assert_eq!(f.backend.get_session_info(native_a[0]).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
    for native in [native_a[1], native_b[0], native_b[1]] {
        assert!(f.backend.get_session_info(native).is_ok());
    }
    for (client, index, expected) in
        [(&a, 0, None), (&a, 1, Some(1)), (&b, 0, Some(42)), (&b, 1, Some(1))]
    {
        assert_eq!(
            f.context_manager
                .slot_for_session(
                    &ClientContextId(client.context.clone()),
                    VirtualHandle(client.sessions[index])
                )
                .await,
            expected.map(|id| BackendSlotId(CkSlotId(id)))
        );
    }
}

#[tokio::test]
async fn session_info_returns_virtual_slot_and_preserves_other_provider_fields() {
    let f = fixture().await;
    let mut client = open(&f, false).await;
    for index in 0..2 {
        let native = f.backend.get_session_info(native_session(&f, &client, index).await).unwrap();
        let response = client
            .rpc
            .get_session_info(GetSessionInfoRequest {
                client_context_id: client.context.clone(),
                session_handle: client.sessions[index],
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.ck_rv, CkRv::OK.0);
        let mut expected = SessionInfo::from(&native);
        expected.slot_id = index as u64 + 1;
        assert_eq!(response.info, Some(expected));
    }
}

#[tokio::test]
async fn session_info_rejects_unmapped_or_inconsistent_backend_slot() {
    let f = fixture().await;
    let mut client = open(&f, false).await;
    let native = native_session(&f, &client, 0).await;
    for reported in [999, 1] {
        f.backend.set_session_info_slot_override(native, Some(CkSlotId(reported)));
        let response = client
            .rpc
            .get_session_info(GetSessionInfoRequest {
                client_context_id: client.context.clone(),
                session_handle: client.sessions[0],
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.ck_rv, CkRv::DEVICE_ERROR.0);
        assert!(response.info.is_none(), "provider slot {reported} must not leak");
    }
    f.backend.set_session_info_slot_override(native, None);
    f.backend.close_session(native).unwrap();
    let response = client
        .rpc
        .get_session_info(GetSessionInfoRequest {
            client_context_id: client.context.clone(),
            session_handle: client.sessions[0],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.ck_rv, CkRv::SESSION_HANDLE_INVALID.0);
    assert!(response.info.is_none());
}

#[tokio::test]
async fn slot_queries_and_init_token_resolve_the_requested_virtual_slot() {
    let f = fixture().await;
    let mut client = open(&f, false).await;
    f.backend.set_slot_mechanisms(CkSlotId(42), vec![CkMechanismType::SHA256]);
    f.backend.set_slot_mechanisms(CkSlotId(1), vec![CkMechanismType::SHA384]);
    for (slot_id, native, label, mechanism) in
        [(1, 42, "Token42", CkMechanismType::SHA256), (2, 1, "Token1", CkMechanismType::SHA384)]
    {
        let slot = client
            .rpc
            .get_slot_info(GetSlotInfoRequest {
                client_context_id: client.context.clone(),
                slot_id,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(slot.ck_rv, CkRv::OK.0);
        assert_eq!(slot.info.unwrap().slot_description, format!("Mock Slot {native}"));
        let token = client
            .rpc
            .get_token_info(GetTokenInfoRequest {
                client_context_id: client.context.clone(),
                slot_id,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(token.ck_rv, CkRv::OK.0);
        assert_eq!(token.info.unwrap().label, label);
        let mechanisms = client
            .rpc
            .get_mechanism_list(GetMechanismListRequest {
                client_context_id: client.context.clone(),
                slot_id,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(mechanisms.ck_rv, CkRv::OK.0);
        assert_eq!(mechanisms.mechanism_types, vec![mechanism.0]);
        let info = client
            .rpc
            .get_mechanism_info(GetMechanismInfoRequest {
                client_context_id: client.context.clone(),
                slot_id,
                mechanism_type: mechanism.0,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(info.ck_rv, CkRv::OK.0);
        let init = client
            .rpc
            .init_token(InitTokenRequest {
                client_context_id: client.context.clone(),
                slot_id,
                so_pin: Some(b"test-only-pin".to_vec()),
                label: "reinitialize".into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(init.ck_rv, CkRv::OK.0);
    }
    assert_eq!(f.backend.init_token_requested_slots(), vec![CkSlotId(42), CkSlotId(1)]);
}

async fn init_token(client: &mut Client, slot_id: u64, label: &str) -> u64 {
    client
        .rpc
        .init_token(InitTokenRequest {
            client_context_id: client.context.clone(),
            slot_id,
            so_pin: Some(b"test-only-pin".to_vec()),
            label: label.into(),
        })
        .await
        .unwrap()
        .into_inner()
        .ck_rv
}

async fn token_label(client: &mut Client, slot_id: u64) -> (u64, Option<String>) {
    let response = client
        .rpc
        .get_token_info(GetTokenInfoRequest { client_context_id: client.context.clone(), slot_id })
        .await
        .unwrap()
        .into_inner();
    (response.ck_rv, response.info.map(|info| info.label))
}

#[tokio::test]
async fn init_token_success_invalidates_label_and_refetches() {
    // T09: a successful reinit relabels the token; the daemon must drop
    // the slot's cached label/serial and advance the generation, so the
    // next gated op refetches and decides on the NEW label.
    let f = fixture().await;
    let mut client = open(&f, false).await;
    assert_eq!(token_label(&mut client, 1).await, (CkRv::OK.0, Some("Token42".into())));
    assert_eq!(
        f.context_manager.cached_token_info(BackendSlotId(CkSlotId(42))),
        Some(("Token42".into(), "serial42".into())),
        "authz warms the cache before reinit"
    );
    let generation = f.context_manager.authz_generation();
    let fetched = f.backend.token_info_requested_slots().len();

    assert_eq!(init_token(&mut client, 1, "Reinit42").await, CkRv::OK.0);
    assert_eq!(
        f.context_manager.cached_token_info(BackendSlotId(CkSlotId(42))),
        None,
        "reinit drops the slot cache entry"
    );
    assert_eq!(
        f.context_manager.authz_generation(),
        generation + 1,
        "reinit advances the authz generation"
    );

    // The next gated op refetches (new label), and the old Token42 grant
    // no longer matches: denied, on fresh data.
    assert_eq!(token_label(&mut client, 1).await.0, CkRv::SLOT_ID_INVALID.0);
    assert_eq!(
        &f.backend.token_info_requested_slots()[fetched..],
        &[CkSlotId(42)],
        "denial follows exactly one refetch of the relabeled slot"
    );
    assert_eq!(
        f.context_manager.cached_token_info(BackendSlotId(CkSlotId(42))),
        Some(("Reinit42".into(), "serial42".into())),
        "the refetch publishes the new label at the current generation"
    );
}

#[tokio::test]
async fn init_token_session_exists_leaves_state_intact() {
    // T09: an error return (OASIS SESSION_EXISTS with open sessions)
    // invalidates nothing — sessions, logins, handles, cache and
    // generation all survive.
    let f = fixture().await;
    preload_objects(&f);
    let mut client = open(&f, false).await;
    assert_eq!(login(&mut client, 0, b"pin42").await, CkRv::OK.0);
    assert_eq!(token_label(&mut client, 1).await.0, CkRv::OK.0);
    let generation = f.context_manager.authz_generation();
    let found_before = find(&mut client, 0).await;
    assert_eq!(found_before.len(), 1);

    f.backend.set_init_token_error(CkRv::SESSION_EXISTS);
    assert_eq!(init_token(&mut client, 1, "Nope").await, CkRv::SESSION_EXISTS.0);

    assert_eq!(
        f.context_manager.cached_token_info(BackendSlotId(CkSlotId(42))),
        Some(("Token42".into(), "serial42".into())),
        "error return keeps the cache"
    );
    assert_eq!(
        f.context_manager.authz_generation(),
        generation,
        "error return keeps the generation"
    );
    for session in client.sessions {
        let info = client
            .rpc
            .get_session_info(GetSessionInfoRequest {
                client_context_id: client.context.clone(),
                session_handle: session,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(info.ck_rv, CkRv::OK.0, "sessions survive the failed reinit");
    }
    assert_eq!(
        login(&mut client, 0, b"pin42").await,
        CkRv::USER_ALREADY_LOGGED_IN.0,
        "login state survives the failed reinit"
    );
    let found_after = find(&mut client, 0).await;
    assert_eq!(found_after, found_before, "handles survive the failed reinit");
    assert_eq!(
        token_label(&mut client, 1).await,
        (CkRv::OK.0, Some("Token42".into())),
        "the token identity is untouched by the failed reinit"
    );
}

#[tokio::test]
async fn init_token_leaves_other_slot_unaffected() {
    // T09: reinit invalidates exactly its own backend slot.
    let f = fixture().await;
    let mut client = open(&f, false).await;
    assert_eq!(token_label(&mut client, 1).await.0, CkRv::OK.0);
    assert_eq!(token_label(&mut client, 2).await.0, CkRv::OK.0);
    let generation = f.context_manager.authz_generation();
    let fetched = f.backend.token_info_requested_slots().len();

    assert_eq!(init_token(&mut client, 1, "Reinit42").await, CkRv::OK.0);
    assert_eq!(f.context_manager.cached_token_info(BackendSlotId(CkSlotId(42))), None);
    assert_eq!(
        f.context_manager.cached_token_info(BackendSlotId(CkSlotId(1))),
        Some(("Token1".into(), "serial1".into())),
        "the other slot keeps its cache entry"
    );
    assert_eq!(f.context_manager.authz_generation(), generation + 1);

    // The untouched slot still authorizes from cache: exactly the one
    // unconditional main fetch, zero authz refetches (a dropped entry
    // would fetch twice: authz + main).
    assert_eq!(token_label(&mut client, 2).await, (CkRv::OK.0, Some("Token1".into())));
    assert_eq!(
        &f.backend.token_info_requested_slots()[fetched..],
        &[CkSlotId(1)],
        "no authz refetch for the unaffected slot"
    );
}

// Gated tests park a backend call while other RPCs proceed: like the M5
// rendezvous tests, they need a multi-thread runtime for concurrent
// blocking-pool progress.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn init_token_delayed_success_after_timeout_still_invalidates() {
    // T09: the daemon timeout fires (FUNCTION_FAILED) while the backend
    // reinit is still parked; when the backend later succeeds, the
    // completion-closure invalidation still lands — the new label is
    // visible and no stale entry survives. Daemon-side 5s timeout: every
    // other test in this binary uses instant mock calls, and 5s keeps the
    // refill test's parked window (one init_token RPC under parallel load)
    // far from the timeout. OnceLock: first call in this process wins;
    // only this test configures it.
    ::pkcs11_proxy_ng::server::grpc_service::service_utils::configure_backend_guard(5, 200);
    let f = fixture().await;
    let mut client = open(&f, false).await;
    assert_eq!(token_label(&mut client, 1).await.0, CkRv::OK.0);
    let generation = f.context_manager.authz_generation();

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    f.backend.set_init_token_gate(entered_tx, release_rx);
    assert_eq!(
        init_token(&mut client, 1, "Reinit42").await,
        CkRv::FUNCTION_FAILED.0,
        "the parked reinit outlives the daemon timeout"
    );
    assert_eq!(
        entered_rx.try_recv().expect("backend entered before the timeout fired"),
        CkSlotId(42),
        "the timeout raced a live backend call on the resolved slot"
    );

    // The RPC future is gone; the backend now succeeds late. Await the
    // generation advance (only a real invalidation advances it — TTL
    // expiry also clears the entry, so cache-None alone would race).
    release_tx.send(()).expect("backend parked");
    let start = std::time::Instant::now();
    while f.context_manager.authz_generation() == generation {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "late success must invalidate"
        );
        tokio::task::yield_now().await;
    }
    assert_eq!(
        f.context_manager.cached_token_info(BackendSlotId(CkSlotId(42))),
        None,
        "late success drops the slot entry"
    );
    assert_eq!(
        token_label(&mut client, 1).await.0,
        CkRv::SLOT_ID_INVALID.0,
        "decisions follow the relabeled token"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn init_token_concurrent_old_cache_refill_skipped() {
    // T09: a metadata lookup started before the reinit must not reinsert
    // its stale label/serial after the invalidation. Forced order: fetch
    // parks in the mock (old snapshot) → reinit succeeds → fetch returns
    // stale → publication skipped → next lookup refetches fresh.
    let f = fixture().await;
    let mut client = open(&f, false).await;
    assert_eq!(token_label(&mut client, 1).await.0, CkRv::OK.0);
    f.context_manager.invalidate_token_info(BackendSlotId(CkSlotId(42)));

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    f.backend.set_token_info_gate(entered_tx, release_rx);
    let mut rpc = client.rpc.clone();
    let context = client.context.clone();
    let parked = tokio::spawn(async move {
        rpc.get_token_info(GetTokenInfoRequest { client_context_id: context, slot_id: 1 })
            .await
            .unwrap()
            .into_inner()
    });
    // Blocking-recv off the executor workers so the parked RPC it waits
    // for can always make progress regardless of worker count.
    let entered = tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(std::time::Duration::from_secs(10))
    })
    .await
    .expect("recv task joins")
    .expect("fetch parked in the mock");
    assert_eq!(entered, CkSlotId(42));

    assert_eq!(init_token(&mut client, 1, "Reinit42").await, CkRv::OK.0);
    assert_eq!(
        f.context_manager.cached_token_info(BackendSlotId(CkSlotId(42))),
        None,
        "reinit drops the cache while the old fetch is parked"
    );

    release_tx.send(()).expect("fetch parked");
    let stale_read = parked.await.expect("parked RPC joins").ck_rv;
    assert_eq!(stale_read, CkRv::OK.0, "the parked read itself was authorized pre-reinit");
    assert_eq!(
        f.context_manager.cached_token_info(BackendSlotId(CkSlotId(42))),
        None,
        "the stale snapshot must not be reinserted after invalidation"
    );

    let fetched = f.backend.token_info_requested_slots().len();
    assert_eq!(
        token_label(&mut client, 1).await.0,
        CkRv::SLOT_ID_INVALID.0,
        "the next lookup refetches and decides on the new label"
    );
    assert_eq!(&f.backend.token_info_requested_slots()[fetched..], &[CkSlotId(42)]);
}

#[tokio::test]
async fn slot_events_translate_backend_ids_and_suppress_unknown_or_denied_slots() {
    let f = fixture().await;
    let mut client = open(&f, false).await;
    for (native, expected_rv, expected_slot) in
        [(42, CkRv::OK, 1), (1, CkRv::OK, 2), (999, CkRv::NO_EVENT, 0)]
    {
        f.backend.enqueue_slot_event(CkSlotId(native));
        let response = client
            .rpc
            .wait_for_slot_event(WaitForSlotEventRequest {
                client_context_id: client.context.clone(),
                flags: 1,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!((response.ck_rv, response.slot_id), (expected_rv.0, expected_slot));
    }
    f.backend.set_slot_token_identity(CkSlotId(42), "DeniedToken".into(), "denied".into());
    f.context_manager.invalidate_token_info(BackendSlotId(CkSlotId(42)));
    f.backend.enqueue_slot_event(CkSlotId(42));
    let denied = client
        .rpc
        .wait_for_slot_event(WaitForSlotEventRequest {
            client_context_id: client.context,
            flags: 1,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!((denied.ck_rv, denied.slot_id), (CkRv::NO_EVENT.0, 0));
}

// T16: custom-service boundary pin — the service honors backend
// admission for non-FFI backends exactly as for the real one: a call
// the (mock) backend refuses answers locally with zero dispatch, so
// the queued event survives for the next poll. Custom-backend
// compliance is pinned here, never inferred from FfiBackend tests.
#[tokio::test]
async fn slot_events_refused_before_dispatch_for_custom_backend() {
    let f = fixture().await;
    let mut client = open(&f, false).await;
    f.backend.enqueue_slot_event(CkSlotId(42));
    // Blocking mode: refused by the shared width→mode boundary.
    let refused = client
        .rpc
        .wait_for_slot_event(WaitForSlotEventRequest {
            client_context_id: client.context.clone(),
            flags: 0,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!((refused.ck_rv, refused.slot_id), (CkRv::FUNCTION_NOT_SUPPORTED.0, 0));
    // Zero dispatch on the refusal: the queued event is still there.
    // (Checked-width refusal is pinned in 32-bit-only backend tests —
    // every u64 fits CK_ULONG on 64-bit hosts, so no portable RPC case
    // can exercise it here.)
    let response = client
        .rpc
        .wait_for_slot_event(WaitForSlotEventRequest {
            client_context_id: client.context,
            flags: 1,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!((response.ck_rv, response.slot_id), (CkRv::OK.0, 1));
}

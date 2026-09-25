//! CKA_UNIQUE_ID numeric-oracle authorization tests (T01).
//!
//! The mock backend below is keyed by **literal standard attribute IDs** taken
//! from the pinned `cryptoki-sys` header binding (`CKA_UNIQUE_ID` = `0x04`).
//! It never imports the project's `CkAttributeType::UNIQUE_ID` constant, so a
//! wrong project value cannot hide behind a self-consistent mock: if the daemon
//! requests any ID other than `0x04`, the oracle answers
//! `ATTRIBUTE_TYPE_INVALID` (absent key) and the per-object gate fails closed.
//!
//! Provenance: OASIS `published/3-02/pkcs11t.h`
//! (`CKA_UNIQUE_ID = 0x00000004UL`) and `cryptoki-sys` 0.5 bindings
//! (`CKA_UNIQUE_ID = 4` on every platform). In the CKA namespace `0x2E` is
//! unassigned (the nearby `0x2E` values live in the CKK/CKM namespaces), so
//! INVALID is the conforming answer there too.
use std::sync::Arc;

use ::pkcs11_proxy_ng::config::{
    ExtractPolicyConfig, GrantSpec, ObjectAclSpec, RichGrantConfig, TokenAccessSpec,
};
use ::pkcs11_proxy_ng::server::context_manager::ClientContextId;
use ::pkcs11_proxy_ng::server::handle_map::{BackendHandle, VirtualHandle};
use pkcs11_proxy_ng_backend::mock::MockAttributeSlot;
use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
use pkcs11_proxy_ng_proto::*;
use pkcs11_proxy_ng_types::Gostr3410KeyWrapParams;
use pkcs11_proxy_ng_types::*;

#[path = "support/mtls_fixture.rs"]
mod mtls_fixture;
use mtls_fixture::MtlsFixture;

/// Literal standard attribute ID for CKA_UNIQUE_ID, from the pinned header
/// binding — deliberately NOT the project's `CkAttributeType::UNIQUE_ID`.
// `as u64` is identity on 64-bit targets but widens `CK_ULONG` on 32-bit
// targets; `u64::from` is not `const`, so the cast keeps this oracle
// portable in `const` position.
#[allow(clippy::unnecessary_cast)]
const ORACLE_UNIQUE_ID: u64 = cryptoki_sys::CKA_UNIQUE_ID as u64;

/// The stale wrong value the project constant carried before T01. Nothing is
/// ever stored under it: the oracle rejects it with ATTRIBUTE_TYPE_INVALID.
const REJECTED_LEGACY_ID: u64 = 0x2E;

const UID_A_HEX: &str = "a1";
const UID_A: u8 = 0xa1;
const UID_B: u8 = 0xb2;

#[test]
fn standard_unique_id_anchor_is_0x04() {
    assert_eq!(ORACLE_UNIQUE_ID, 0x04, "pinned header binding must agree with OASIS");
    assert_ne!(ORACLE_UNIQUE_ID, REJECTED_LEGACY_ID);
}

/// Direct oracle contract: the literal standard ID resolves to the stored UID
/// bytes, while the legacy ID is rejected with ATTRIBUTE_TYPE_INVALID. This
/// pins the mock behavior the RPC tests below rely on for their red/green
/// signal (a daemon requesting `0x2E` can never resolve a UID here).
#[test]
fn oracle_accepts_standard_id_and_rejects_legacy_id() {
    let backend = MockBackend::new(vec![CkSlotId(42)], vec![]);
    let session = backend.open_session(CkSlotId(42), CkSessionFlags::default()).unwrap();
    let object = backend.create_object(session, Some(&[])).unwrap();
    backend.set_attribute(
        object,
        CkAttributeType(ORACLE_UNIQUE_ID),
        MockAttributeSlot::Value(CkAttributeValue::Bytes(vec![UID_A].into())),
    );
    let mut accept = [CkAttribute { attr_type: CkAttributeType(ORACLE_UNIQUE_ID), value: None }];
    assert!(matches!(backend.get_attribute_value(session, object, &mut accept), Ok(())));
    let stored = match &accept[0].value {
        Some(CkAttributeValue::Bytes(bytes)) => bytes.expose(|raw| raw.to_vec()),
        other => panic!("standard ID must resolve to UID bytes, got {other:?}"),
    };
    assert_eq!(stored, vec![UID_A]);
    let mut reject = [CkAttribute { attr_type: CkAttributeType(REJECTED_LEGACY_ID), value: None }];
    assert!(matches!(
        backend.get_attribute_value(session, object, &mut reject),
        Err(CkRv::ATTRIBUTE_TYPE_INVALID)
    ));
}

fn uid_grant() -> RichGrantConfig {
    RichGrantConfig {
        token: "label:MockToken".into(),
        classes: None,
        mechanisms: None,
        extract: ExtractPolicyConfig::Allow,
        objects: Some(vec![ObjectAclSpec::Bare(UID_A_HEX.into())]),
    }
}

async fn fixture(grant: RichGrantConfig) -> MtlsFixture {
    let backend = Arc::new(MockBackend::with_official_mechanisms(vec![CkSlotId(42)]));
    mtls_fixture::start_mtls_daemon(
        backend,
        [TokenAccessSpec::Specific(vec![GrantSpec::Rich(grant)]), TokenAccessSpec::All("*".into())],
    )
    .await
}

struct Client {
    rpc: Pkcs11ProxyClient<tonic::transport::Channel>,
    context: String,
    session: u64,
    native_session: u64,
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
    assert_eq!(slots.slot_ids.len(), 1);
    let session = rpc
        .open_session(OpenSessionRequest {
            client_context_id: context.clone(),
            slot_id: slots.slot_ids[0],
            flags: (CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION).0,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(session.ck_rv, CkRv::OK.0);
    let native_session = f
        .context_manager
        .get_context(&ClientContextId(context.clone()), |c| {
            c.session_handles.resolve(VirtualHandle(session.session_handle)).unwrap().0
        })
        .await
        .unwrap();
    // Keep virtual handles, native objects, and native sessions noncolliding:
    // numeric coincidence across namespaces would mask a missing
    // virtual-to-native translation (cf. the exact-wrap suite preamble).
    for _ in 0..8 {
        f.backend.create_object(CkSessionHandle(native_session), Some(&[])).unwrap();
    }
    Client { rpc, context, session: session.session_handle, native_session }
}

/// Provision a backend object and map it into the client's handle map WITHOUT
/// creator exemption, so use-time policy executes (cf. `mapped_object` in the
/// exact-wrap authorization suite). The UID is stored under the literal
/// standard ID; `None` provisions an object with no UID attribute at all.
async fn mapped_object(
    f: &MtlsFixture,
    c: &Client,
    class: CkObjectClass,
    uid: Option<u8>,
) -> (u64, u64) {
    let mut template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(class.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::PRIVATE,
            value: Some(CkAttributeValue::Bool(false)),
        },
    ];
    if let Some(uid) = uid {
        template.push(CkAttribute {
            attr_type: CkAttributeType(ORACLE_UNIQUE_ID),
            value: Some(CkAttributeValue::Bytes(vec![uid].into())),
        });
    }
    let native =
        f.backend.create_object(CkSessionHandle(c.native_session), Some(&template)).unwrap();
    let virtual_key = f
        .context_manager
        .get_context(&ClientContextId(c.context.clone()), |ctx| {
            let vh = ctx.object_handles.insert(BackendHandle(native.0));
            ctx.object_private.insert(vh, false);
            vh.0
        })
        .await
        .unwrap();
    assert_ne!(virtual_key, native.0);
    (virtual_key, native.0)
}

fn wrap_mechanism(embedded: u64) -> Option<Mechanism> {
    Some(
        Mechanism::try_from(&CkMechanism {
            mechanism_type: CkMechanismType::GOSTR3410_KEY_WRAP,
            params: Some(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
                wrap_oid: vec![1, 2, 3],
                ukm: vec![7; 8],
                key_handle: CkObjectHandle(embedded),
            })),
        })
        .unwrap(),
    )
}

/// Wrap with an embedded key handle: the embedded path rejects a denied handle
/// with OBJECT_HANDLE_INVALID *before* backend dispatch, giving a clean
/// proxy-side allow/deny signal (cf. the class-only embedded policy test).
async fn wrap_embedded(c: &mut Client, wrapping: u64, key: u64, embedded: u64) -> u64 {
    c.rpc
        .wrap_key(WrapKeyRequest {
            client_context_id: c.context.clone(),
            session_handle: c.session,
            mechanism: wrap_mechanism(embedded),
            wrapping_key_handle: wrapping,
            key_handle: key,
        })
        .await
        .unwrap()
        .into_inner()
        .ck_rv
}

async fn find(c: &mut Client) -> Vec<u64> {
    let init = c
        .rpc
        .find_objects_init(FindObjectsInitRequest {
            client_context_id: c.context.clone(),
            session_handle: c.session,
            template: vec![],
            template_null: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(init.ck_rv, CkRv::OK.0);
    let found = c
        .rpc
        .find_objects(FindObjectsRequest {
            client_context_id: c.context.clone(),
            session_handle: c.session,
            max_object_count: 10,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(found.ck_rv, CkRv::OK.0);
    let finish = c
        .rpc
        .find_objects_final(FindObjectsFinalRequest {
            client_context_id: c.context.clone(),
            session_handle: c.session,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(finish.ck_rv, CkRv::OK.0);
    found.object_handles
}

async fn resolve_native(f: &MtlsFixture, c: &Client, virtual_handle: u64) -> u64 {
    f.context_manager
        .get_context(&ClientContextId(c.context.clone()), |ctx| {
            ctx.object_handles.resolve(VirtualHandle(virtual_handle)).unwrap().0
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn enumeration_lists_only_allow_listed_uid() {
    let f = fixture(uid_grant()).await;
    // Offset native numbering so virtual/native coincidence cannot mask a
    // missing translation (dummies are never served to find_objects).
    let preamble = f.backend.open_session(CkSlotId(42), CkSessionFlags::default()).unwrap();
    for _ in 0..8 {
        f.backend.create_object(preamble, Some(&[])).unwrap();
    }
    let mut natives = Vec::new();
    for uid in [Some(UID_A), Some(UID_B), None] {
        let session = f.backend.open_session(CkSlotId(42), CkSessionFlags::default()).unwrap();
        let mut template = vec![
            CkAttribute {
                attr_type: CkAttributeType::CLASS,
                value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
            },
            CkAttribute {
                attr_type: CkAttributeType::TOKEN,
                value: Some(CkAttributeValue::Bool(true)),
            },
            // F-04: declare CKA_PRIVATE=false (the native default) so the
            // logged-out login filter keeps these fixtures visible.
            CkAttribute {
                attr_type: CkAttributeType::PRIVATE,
                value: Some(CkAttributeValue::Bool(false)),
            },
        ];
        if let Some(uid) = uid {
            template.push(CkAttribute {
                attr_type: CkAttributeType(ORACLE_UNIQUE_ID),
                value: Some(CkAttributeValue::Bytes(vec![uid].into())),
            });
        }
        natives.push(f.backend.create_object(session, Some(&template)).unwrap());
    }
    f.backend.set_find_objects_result(natives.clone());
    let mut c = open(&f, false).await;
    let attrs_before = f.backend.attr_get_call_count();
    let found = find(&mut c).await;
    assert!(
        f.backend.attr_get_call_count() > attrs_before,
        "enumeration must consult object metadata (no vacuous pass)"
    );
    assert_eq!(found.len(), 1, "only the allow-listed UID may be enumerated");
    assert_eq!(resolve_native(&f, &c, found[0]).await, natives[0].0);
}

#[tokio::test]
async fn use_time_embedded_allows_listed_uid() {
    let f = fixture(uid_grant()).await;
    let mut c = open(&f, false).await;
    let (wrapping, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, Some(UID_A)).await;
    let (key, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, Some(UID_A)).await;
    let (allowed, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, Some(UID_A)).await;
    let before = f.backend.wrap_observations().len();
    assert_eq!(wrap_embedded(&mut c, wrapping, key, allowed).await, CkRv::OK.0);
    assert_eq!(
        f.backend.wrap_observations().len(),
        before + 1,
        "allowed handle must dispatch to the backend"
    );
}

#[tokio::test]
async fn use_time_embedded_denies_unknown_uid() {
    let f = fixture(uid_grant()).await;
    let mut c = open(&f, false).await;
    let (wrapping, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, Some(UID_A)).await;
    let (key, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, Some(UID_A)).await;
    let (denied, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, Some(UID_B)).await;
    let before = f.backend.wrap_observations().len();
    assert_eq!(wrap_embedded(&mut c, wrapping, key, denied).await, CkRv::OBJECT_HANDLE_INVALID.0);
    assert_eq!(
        f.backend.wrap_observations().len(),
        before,
        "denied handle must not dispatch to the backend"
    );
}

#[tokio::test]
async fn use_time_embedded_denies_absent_uid() {
    let f = fixture(uid_grant()).await;
    let mut c = open(&f, false).await;
    let (wrapping, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, Some(UID_A)).await;
    let (key, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, Some(UID_A)).await;
    // A token that does not populate CKA_UNIQUE_ID stays fail-closed.
    let (denied, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, None).await;
    let before = f.backend.wrap_observations().len();
    assert_eq!(wrap_embedded(&mut c, wrapping, key, denied).await, CkRv::OBJECT_HANDLE_INVALID.0);
    assert_eq!(
        f.backend.wrap_observations().len(),
        before,
        "denied handle must not dispatch to the backend"
    );
}

#[tokio::test]
async fn class_restriction_enforced_through_metadata_fetch() {
    let mut grant = uid_grant();
    grant.classes = Some(vec!["CKO_SECRET_KEY".into()]);
    grant.objects = None;
    let f = fixture(grant).await;
    let mut c = open(&f, false).await;
    // UID presence is required for the shared metadata fetch to succeed; the
    // allow/deny signal here comes from the CLASS leg alone.
    let (wrapping, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, Some(UID_A)).await;
    let (key, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, Some(UID_A)).await;
    let (allowed, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, Some(UID_A)).await;
    let (denied, _) = mapped_object(&f, &c, CkObjectClass::PRIVATE_KEY, Some(UID_A)).await;
    assert_eq!(wrap_embedded(&mut c, wrapping, key, allowed).await, CkRv::OK.0);
    let before = f.backend.wrap_observations().len();
    assert_eq!(wrap_embedded(&mut c, wrapping, key, denied).await, CkRv::OBJECT_HANDLE_INVALID.0);
    assert_eq!(f.backend.wrap_observations().len(), before);
}

/// Mint a session object via RPC with no UID attribute. All handles minted
/// this way carry creator exemption, so the bypass test isolates bypass from
/// the metadata-fetch path (mapped primaries would fail pre-fix instead).
async fn mint_session_object(c: &mut Client) -> u64 {
    let created = c
        .rpc
        .create_object(CreateObjectRequest {
            client_context_id: c.context.clone(),
            session_handle: c.session,
            template_null: false,
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
                    attr_type: CkAttributeType::PRIVATE,
                    value: Some(CkAttributeValue::Bool(false)),
                },
            ]
            .iter()
            .map(Attribute::from)
            .collect(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.ck_rv, CkRv::OK.0);
    created.object_handle
}

#[tokio::test]
async fn creator_bypass_minted_object_usable_without_uid() {
    let f = fixture(uid_grant()).await;
    let mut c = open(&f, false).await;
    // Mint every handle via RPC with no UID attribute at all: creator bypass
    // must allow immediate use even though no UID is in the allow-list.
    let wrapping = mint_session_object(&mut c).await;
    let key = mint_session_object(&mut c).await;
    let created = mint_session_object(&mut c).await;
    let before = f.backend.wrap_observations().len();
    assert_eq!(wrap_embedded(&mut c, wrapping, key, created).await, CkRv::OK.0);
    assert_eq!(f.backend.wrap_observations().len(), before + 1);
}

#[tokio::test]
async fn unrestricted_policy_performs_no_metadata_fetch() {
    let backend = Arc::new(MockBackend::with_official_mechanisms(vec![CkSlotId(42)]));
    let f = mtls_fixture::start_mtls_daemon(
        backend,
        [TokenAccessSpec::All("*".into()), TokenAccessSpec::All("*".into())],
    )
    .await;
    let mut c = open(&f, false).await;
    let (wrapping, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, Some(UID_A)).await;
    let (key, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, Some(UID_A)).await;
    // No UID attribute at all: the unrestricted path must not depend on it.
    let (any, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, None).await;
    let before = f.backend.attr_get_call_count();
    assert_eq!(wrap_embedded(&mut c, wrapping, key, any).await, CkRv::OK.0);
    assert_eq!(
        f.backend.attr_get_call_count(),
        before,
        "unrestricted policy must not read object metadata"
    );
}

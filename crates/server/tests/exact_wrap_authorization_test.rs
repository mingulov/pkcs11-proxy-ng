//! Public mTLS wrap policy tests. Mock observations count trait dispatch only;
//! separate FFI stub tests establish native call and pointer semantics.
use std::sync::Arc;

use ::pkcs11_proxy_ng::config::{
    ExtractPolicyConfig, GrantSpec, ObjectAclRichConfig, ObjectAclSpec, RichGrantConfig,
    TokenAccessSpec,
};
use ::pkcs11_proxy_ng::server::context_manager::ClientContextId;
use ::pkcs11_proxy_ng::server::handle_map::{BackendHandle, VirtualHandle};
use pkcs11_proxy_ng_backend::mock::{MockWrapAction, MockWrapEntry as Route};
use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
use pkcs11_proxy_ng_proto::*;
use pkcs11_proxy_ng_proto::{ByteOutputFunction, ParameterOutputFunction};
use pkcs11_proxy_ng_types::Gostr3410KeyWrapParams;
use pkcs11_proxy_ng_types::*;

#[path = "support/mtls_fixture.rs"]
mod mtls_fixture;
use mtls_fixture::MtlsFixture;
#[path = "exact_wrap_authorization/audit.rs"]
mod audit;
#[path = "exact_wrap_authorization/regressions.rs"]
mod regressions;
#[path = "exact_wrap_authorization/typed_output.rs"]
mod typed_output;

const ROUTES: [Route; 4] =
    [Route::Wrap, Route::Authenticated, Route::Exact, Route::AuthenticatedExact];

fn grant() -> RichGrantConfig {
    RichGrantConfig {
        token: "label:MockToken".into(),
        classes: None,
        mechanisms: None,
        extract: ExtractPolicyConfig::Allow,
        objects: None,
    }
}

fn tokens(grant: RichGrantConfig) -> TokenAccessSpec {
    TokenAccessSpec::Specific(vec![GrantSpec::Rich(grant)])
}

async fn fixture(grant: RichGrantConfig) -> MtlsFixture {
    let backend = Arc::new(MockBackend::with_official_mechanisms(vec![CkSlotId(42)]));
    mtls_fixture::start_mtls_daemon(backend, [tokens(grant), TokenAccessSpec::All("*".into())])
        .await
}

async fn fixture_with_audit(
    grant: RichGrantConfig,
    audit: Option<::pkcs11_proxy_ng::server::audit::AuditSink>,
) -> MtlsFixture {
    let backend = Arc::new(MockBackend::with_official_mechanisms(vec![CkSlotId(42)]));
    mtls_fixture::start_mtls_daemon_with_audit(
        backend,
        [tokens(grant), TokenAccessSpec::All("*".into())],
        audit,
        false,
    )
    .await
}

struct Client {
    rpc: Pkcs11ProxyClient<tonic::transport::Channel>,
    context: String,
    session: u64,
    native_session: u64,
    keys: [u64; 3],
    native_keys: [u64; 3],
    aad_null_len: Option<u64>,
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
    // Keep virtual handles, native objects, and native sessions noncolliding.
    for _ in 0..8 {
        f.backend.create_object(CkSessionHandle(native_session), Some(&[])).unwrap();
    }
    let mut c = Client {
        rpc,
        context,
        session: session.session_handle,
        native_session,
        keys: [0; 3],
        native_keys: [0; 3],
        aad_null_len: None,
    };
    for (i, uid) in [0xb1, 0xa1, 0xc1].into_iter().enumerate() {
        (c.keys[i], c.native_keys[i]) = mapped_object(f, &c, CkObjectClass::SECRET_KEY, uid).await;
    }
    c
}

// Model a token object mapped before an external policy/metadata change. These
// mappings deliberately have no creator exemption, so use-time policy executes.
async fn mapped_object(f: &MtlsFixture, c: &Client, class: CkObjectClass, uid: u8) -> (u64, u64) {
    let native = f
        .backend
        .create_object(
            CkSessionHandle(c.native_session),
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
    let virtual_key = f
        .context_manager
        .get_context(&ClientContextId(c.context.clone()), |ctx| {
            let vh = ctx.object_handles.insert(BackendHandle(native.0));
            // D6(1) fixture provisioning: the backend object carries no
            // CKA_PRIVATE (public by default) — record what mint
            // registration would record, so USE needs no backend probe.
            ctx.object_private.insert(vh, false);
            vh.0
        })
        .await
        .unwrap();
    assert_ne!(virtual_key, native.0);
    (virtual_key, native.0)
}

fn mechanism(handle: u64) -> Option<Mechanism> {
    Some(
        Mechanism::try_from(&CkMechanism {
            mechanism_type: CkMechanismType::GOSTR3410_KEY_WRAP,
            params: Some(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
                wrap_oid: vec![1, 2, 3],
                ukm: vec![7; 8],
                key_handle: CkObjectHandle(handle),
            })),
        })
        .unwrap(),
    )
}

fn output_spec() -> OutputBufferSpec {
    OutputBufferSpec { buffer_present: true, buffer_len: 128, length_pointer_null: false }
}

#[derive(Default)]
struct Reply {
    rv: u64,
    len: u64,
    value: Option<Vec<u8>>,
    parameter: Option<Vec<u8>>,
    parameter_len: u64,
    mechanism: Option<Mechanism>,
    authenticated_output: Option<AuthenticatedMechanismOutput>,
    key: u64,
}
impl Reply {
    fn assert_suppressed(&self) {
        assert_eq!((self.len, self.parameter_len, self.key), (0, 0, 0));
        assert!(self.value.as_ref().is_none_or(Vec::is_empty));
        assert!(self.parameter.as_ref().is_none_or(Vec::is_empty));
        assert!(self.mechanism.is_none());
        assert!(self.authenticated_output.is_none());
    }
}

async fn invoke(
    c: &mut Client,
    route: Route,
    mechanism: Option<Mechanism>,
    spec: OutputBufferSpec,
) -> Result<Reply, tonic::Status> {
    let client_context_id = c.context.clone();
    let session_handle = c.session;
    let wrapping_key_handle = c.keys[0];
    let key_handle = c.keys[1];
    let associated_data = b"aad-canary-wrap-policy".to_vec();
    Ok(match route {
        Route::Wrap => {
            // T12: `WrapKeyResponse` is `ZeroizeOnDrop`; take the owned
            // field out with `mem::take` instead of moving it.
            let mut r = c
                .rpc
                .wrap_key(WrapKeyRequest {
                    client_context_id,
                    session_handle,
                    mechanism,
                    wrapping_key_handle,
                    key_handle,
                })
                .await?
                .into_inner();
            Reply {
                rv: r.ck_rv,
                value: Some(std::mem::take(&mut r.wrapped_key)),
                ..Default::default()
            }
        }
        Route::Authenticated => {
            // T12: `WrapKeyAuthenticatedResponse` is `ZeroizeOnDrop`; take
            // owned fields out with `mem::take` instead of moving them.
            let mut r = c
                .rpc
                .wrap_key_authenticated(WrapKeyAuthenticatedRequest {
                    authenticated_parameters: Some(AuthenticatedParameters::default()),
                    client_context_id,
                    session_handle,
                    mechanism,
                    wrapping_key_handle,
                    key_handle,
                    associated_data,
                    associated_data_null_len: c.aad_null_len,
                })
                .await?
                .into_inner();
            Reply {
                rv: r.ck_rv,
                value: Some(std::mem::take(&mut r.wrapped_key)),
                parameter: Some(std::mem::take(&mut r.mechanism_parameter_out)),
                authenticated_output: std::mem::take(&mut r.authenticated_output),
                ..Default::default()
            }
        }
        Route::Exact => {
            // T12: `ByteOutputExactRequest` is `ZeroizeOnDrop`;
            // struct-update syntax is forbidden — all fields spelled out.
            let r = c
                .rpc
                .byte_output_exact(ByteOutputExactRequest {
                    exact_output_effects_version: 1,
                    client_context_id,
                    session_handle,
                    mechanism,
                    wrapping_key_handle,
                    key_handle,
                    function: ByteOutputFunction::WrapKey as i32,
                    output_spec: Some(spec),
                    input_data: Vec::new(),
                    input_data_null_len: None,
                })
                .await?
                .into_inner();
            // T12: `OutputBufferResult` is `ZeroizeOnDrop`; take the owned
            // field out with `mem::take` instead of moving it.
            let mut out = r.result.expect("wrap exact result");
            Reply {
                rv: out.ck_rv,
                len: out.returned_len,
                value: std::mem::take(&mut out.value),
                mechanism: r.mechanism_out,
                ..Default::default()
            }
        }
        Route::AuthenticatedExact => {
            // T12: `ParameterOutputExactRequest` is `ZeroizeOnDrop`;
            // struct-update syntax is forbidden — all fields spelled out.
            let r = c
                .rpc
                .parameter_output_exact(ParameterOutputExactRequest {
                    exact_output_effects_version: 1,
                    authenticated_parameters: Some(AuthenticatedParameters::default()),
                    client_context_id,
                    session_handle,
                    mechanism,
                    wrapping_key_handle,
                    key_handle,
                    associated_data,
                    associated_data_null_len: c.aad_null_len,
                    function: ParameterOutputFunction::WrapKeyAuthenticated as i32,
                    output_spec: Some(spec),
                    parameter_out_spec: Some(ParameterRoundtripSpec {
                        buffer_present: false,
                        buffer_len: 0,
                        value: None,
                    }),
                    input_data: Vec::new(),
                    parameter: Vec::new(),
                    flags: 0,
                    message_parameter: None,
                    input_data_null_len: None,
                })
                .await?
                .into_inner();
            assert!(r.message_parameter_out.is_none());
            // T12: the result carriers are `ZeroizeOnDrop`; take owned
            // fields out with `mem::take` instead of moving them.
            let mut out = r.output_result.expect("authenticated exact output");
            let mut param = r.parameter_result.expect("authenticated exact parameter");
            Reply {
                rv: out.ck_rv,
                len: out.returned_len,
                value: std::mem::take(&mut out.value),
                parameter: std::mem::take(&mut param.value),
                parameter_len: param.returned_len,
                authenticated_output: r.authenticated_output,
                ..Default::default()
            }
        }
        Route::UnwrapAuthenticated => {
            // T12: `UnwrapKeyAuthenticatedResponse` is `ZeroizeOnDrop`; take
            // owned fields out with `mem::take` instead of moving them.
            let mut r = c
                .rpc
                // T12: `UnwrapKeyAuthenticatedRequest` is `ZeroizeOnDrop`;
                // struct-update syntax is forbidden — all fields spelled out.
                .unwrap_key_authenticated(UnwrapKeyAuthenticatedRequest {
                    authenticated_parameters: Some(AuthenticatedParameters::default()),
                    client_context_id,
                    session_handle,
                    mechanism,
                    unwrapping_key_handle: wrapping_key_handle,
                    wrapped_key: vec![1; 16],
                    template: Vec::new(),
                    associated_data,
                    wrapped_key_null_len: None,
                    associated_data_null_len: c.aad_null_len,
                    template_null: false,
                })
                .await?
                .into_inner();
            Reply {
                rv: r.ck_rv,
                key: r.key_handle,
                authenticated_output: std::mem::take(&mut r.authenticated_output),
                parameter: Some(std::mem::take(&mut r.mechanism_parameter_out)),
                ..Default::default()
            }
        }
    })
}

async fn assert_denied(g: RichGrantConfig, want: CkRv) {
    let f = fixture(g).await;
    let mut c = open(&f, false).await;
    for route in ROUTES {
        let before = f.backend.wrap_observations().len();
        let metadata = f.backend.attr_get_call_count();
        let r = invoke(&mut c, route, mechanism(0), output_spec()).await.unwrap();
        assert_eq!(r.rv, want.0, "{route:?}");
        r.assert_suppressed();
        assert_eq!(f.backend.wrap_observations().len(), before, "{route:?}");
        assert_eq!(
            f.backend.attr_get_call_count(),
            metadata,
            "token-only grants need no object metadata"
        );
    }
}

#[tokio::test]
async fn every_wrap_route_denies_mechanism_before_dispatch() {
    let mut g = grant();
    g.mechanisms = Some(vec!["CKM_AES_KEY_WRAP".into()]);
    assert_denied(g, CkRv::MECHANISM_INVALID).await;
}
#[tokio::test]
async fn every_wrap_route_denies_extraction_before_dispatch() {
    let mut g = grant();
    g.extract = ExtractPolicyConfig::Deny;
    assert_denied(g, CkRv::KEY_FUNCTION_NOT_PERMITTED).await;
}
#[tokio::test]
async fn every_wrap_route_uses_wrapped_object_extract_override() {
    for (base, specific, want) in [
        (ExtractPolicyConfig::Allow, ExtractPolicyConfig::Deny, CkRv::KEY_FUNCTION_NOT_PERMITTED),
        (ExtractPolicyConfig::Deny, ExtractPolicyConfig::Allow, CkRv::OK),
    ] {
        let mut g = grant();
        g.extract = base;
        g.objects = Some(vec![
            ObjectAclSpec::Bare("b1".into()),
            ObjectAclSpec::Rich(ObjectAclRichConfig { id: "a1".into(), extract: Some(specific) }),
        ]);
        let f = fixture(g).await;
        let mut c = open(&f, false).await;
        for route in ROUTES {
            let before = f.backend.wrap_observations().len();
            assert_eq!(
                invoke(&mut c, route, mechanism(0), output_spec()).await.unwrap().rv,
                want.0,
                "{route:?}"
            );
            assert_eq!(f.backend.wrap_observations().len() - before, usize::from(want == CkRv::OK));
        }
        assert!(
            f.backend.attr_get_call_count() > 0,
            "object policy performs separate metadata reads"
        );
    }
}

#[tokio::test]
async fn every_wrap_route_remaps_owned_and_rejects_foreign_embedded_handles() {
    let f = fixture(grant()).await;
    let mut c = open(&f, false).await;
    let other = open(&f, true).await;
    let (foreign, _) = mapped_object(&f, &other, CkObjectClass::SECRET_KEY, 0xd1).await;
    for route in ROUTES {
        for handle in [foreign, u64::MAX] {
            let before = f.backend.wrap_observations().len();
            assert_eq!(
                invoke(&mut c, route, mechanism(handle), output_spec()).await.unwrap().rv,
                CkRv::OBJECT_HANDLE_INVALID.0,
                "{route:?}"
            );
            assert_eq!(f.backend.wrap_observations().len(), before);
        }
        let embedded = c.keys[2];
        assert_eq!(
            invoke(&mut c, route, mechanism(embedded), output_spec()).await.unwrap().rv,
            CkRv::OK.0,
            "{route:?}"
        );
        let o = f.backend.wrap_observations().pop().unwrap();
        assert_eq!(o.route, route);
        assert_eq!(o.session, c.native_session);
        assert_eq!(
            (o.wrapping_key, o.key, o.embedded_key),
            (c.native_keys[0], c.native_keys[1], Some(c.native_keys[2]))
        );
    }
}

#[tokio::test]
async fn every_wrap_route_enforces_class_only_embedded_policy() {
    let mut g = grant();
    g.classes = Some(vec!["CKO_SECRET_KEY".into()]);
    let f = fixture(g).await;
    let mut c = open(&f, false).await;
    let (denied, _) = mapped_object(&f, &c, CkObjectClass::PRIVATE_KEY, 0xc1).await;
    for route in ROUTES {
        let before = f.backend.wrap_observations().len();
        assert_eq!(
            invoke(&mut c, route, mechanism(denied), output_spec()).await.unwrap().rv,
            CkRv::OBJECT_HANDLE_INVALID.0,
            "{route:?}"
        );
        assert_eq!(f.backend.wrap_observations().len(), before);
        let allowed = c.keys[2];
        assert_eq!(
            invoke(&mut c, route, mechanism(allowed), output_spec()).await.unwrap().rv,
            CkRv::OK.0
        );
    }
}

#[tokio::test]
async fn direct_denied_and_unknown_keys_forward_zero_and_preserve_provider_rv() {
    let mut g = grant();
    g.objects = Some(vec![ObjectAclSpec::Bare("b1".into()), ObjectAclSpec::Bare("a1".into())]);
    let f = fixture(g).await;
    let mut c = open(&f, false).await;
    let (denied, denied_native) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, 0xd1).await;
    for route in ROUTES {
        for index in [0, 1] {
            let original = c.keys[index];
            for handle in [denied, u64::MAX] {
                c.keys[index] = handle;
                let before = f.backend.wrap_observations().len();
                // Provider-defined precedence must survive proxy denial.
                f.backend.set_wrap_action(MockWrapAction::Return(CkRv::DEVICE_ERROR));
                assert_eq!(
                    invoke(&mut c, route, mechanism(0), output_spec()).await.unwrap().rv,
                    CkRv::DEVICE_ERROR.0,
                    "{route:?}"
                );
                assert_eq!(f.backend.wrap_observations().len(), before + 1);
                let o = f.backend.wrap_observations().pop().unwrap();
                assert_eq!([o.wrapping_key, o.key][index], 0);
                assert!(![o.wrapping_key, o.key].contains(&denied_native));
            }
            c.keys[index] = original;
        }
    }
}

#[tokio::test]
async fn exact_wrap_pointer_classes_dispatch_once() {
    let f = fixture(grant()).await;
    let mut c = open(&f, false).await;
    for route in [Route::Exact, Route::AuthenticatedExact] {
        for (present, len, null_length, want) in [
            (false, 0, false, CkRv::OK),
            (true, 0, false, CkRv::BUFFER_TOO_SMALL),
            (true, 1, false, CkRv::BUFFER_TOO_SMALL),
            (true, 128, false, CkRv::OK),
            (false, 23, true, CkRv::ARGUMENTS_BAD),
            (true, 0, true, CkRv::ARGUMENTS_BAD),
            (true, 128, true, CkRv::ARGUMENTS_BAD),
        ] {
            let before = f.backend.wrap_observations().len();
            let spec = OutputBufferSpec {
                buffer_present: present,
                buffer_len: len,
                length_pointer_null: null_length,
            };
            let r = invoke(&mut c, route, mechanism(0), spec).await.unwrap();
            assert_eq!(r.rv, want.0, "{route:?} ({present},{len},{null_length})");
            assert_eq!(f.backend.wrap_observations().len(), before + 1);
            assert_eq!(
                f.backend.wrap_observations().pop().unwrap().output,
                Some((present, len, null_length))
            );
        }
    }
}

#[tokio::test]
async fn authenticated_unwrap_remaps_embedded_handles_before_native_call() {
    let f = fixture(grant()).await;
    let mut c = open(&f, false).await;
    let embedded = c.keys[2];
    let r = invoke(&mut c, Route::UnwrapAuthenticated, mechanism(embedded), output_spec())
        .await
        .unwrap();
    assert_eq!(r.rv, CkRv::OK.0);
    assert_ne!(r.key, 0);
    assert_eq!(f.backend.wrap_observations().pop().unwrap().embedded_key, Some(c.native_keys[2]));
    let native = f
        .context_manager
        .get_context(&ClientContextId(c.context.clone()), |ctx| {
            ctx.object_handles.resolve(VirtualHandle(r.key)).unwrap().0
        })
        .await
        .unwrap();
    assert_ne!(native, r.key);
    let closed = c
        .rpc
        .close_session(CloseSessionRequest {
            client_context_id: c.context.clone(),
            session_handle: c.session,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(closed.ck_rv, CkRv::OK.0);
    assert!(
        f.context_manager
            .get_context(&ClientContextId(c.context.clone()), |ctx| ctx
                .object_handles
                .resolve(VirtualHandle(r.key)))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn wrap_preparation_preserves_session_then_mechanism_then_policy_precedence() {
    let mut g = grant();
    g.extract = ExtractPolicyConfig::Deny;
    g.mechanisms = Some(vec!["CKM_AES_KEY_WRAP".into()]);
    let f = fixture(g).await;
    let mut c = open(&f, false).await;
    for route in ROUTES {
        let session = c.session;
        c.session = u64::MAX;
        assert_eq!(
            invoke(&mut c, route, None, output_spec()).await.unwrap().rv,
            CkRv::SESSION_HANDLE_INVALID.0,
            "{route:?}"
        );
        c.session = session;
        assert_eq!(
            invoke(&mut c, route, None, output_spec()).await.unwrap().rv,
            CkRv::ARGUMENTS_BAD.0,
            "{route:?}"
        );
        // W1-C1-13 (permitted-before-remap): the GOST wrap type is not in
        // the AES-KW-only grant, so the gate's MECHANISM_INVALID wins over
        // the unknown embedded handle's OBJECT_HANDLE_INVALID.
        assert_eq!(
            invoke(&mut c, route, mechanism(u64::MAX), output_spec()).await.unwrap().rv,
            CkRv::MECHANISM_INVALID.0,
            "{route:?}"
        );
        assert_eq!(
            invoke(&mut c, route, mechanism(0), output_spec()).await.unwrap().rv,
            CkRv::MECHANISM_INVALID.0,
            "{route:?}"
        );
    }
    assert!(f.backend.wrap_observations().is_empty());
}

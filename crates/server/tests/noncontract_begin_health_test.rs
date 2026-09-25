//! Legacy public Begin RPCs must classify native completion, not wire success.
//!
//! Build the exact-output oracle normally and with `missing-message-begin` in
//! separate target directories. Set PKCS11_PROXY_EXACT_ORACLE_LIB and
//! PKCS11_PROXY_MISSING_BEGIN_ORACLE_LIB, then run this ignored integration gate.
#![cfg(unix)]
#![allow(clippy::unnecessary_cast)]

use cryptoki_sys::*;
use libloading::Library;
use pkcs11_proxy_ng::server::{
    context_manager::ContextManager,
    grpc_service::{
        Pkcs11ProxyService,
        service_utils::{BackendHealthEvent, configure_backend_health_events},
    },
};
use pkcs11_proxy_ng_backend::{FfiBackend, Pkcs11Backend};
use pkcs11_proxy_ng_proto as wire;
use std::{path::PathBuf, sync::Arc, time::Duration};

#[allow(dead_code)]
#[path = "../../../tests/ffi_oracles/exact_outputs/src/lib.rs"]
mod oracle_types;
use oracle_types::{ExactOracleObservation, ExactOracleScenario};

struct Harness {
    oracle: Library,
    rpc: wire::Pkcs11ProxyClient<tonic::transport::Channel>,
    context: String,
    session: u64,
    key: u64,
    stop: tokio::sync::oneshot::Sender<()>,
}

impl Harness {
    async fn start(path_variable: &str) -> Self {
        let path = PathBuf::from(std::env::var_os(path_variable).expect(path_variable));
        let oracle = unsafe { Library::new(&path) }.unwrap();
        let backend = Arc::new(FfiBackend::load(&path).unwrap()) as Arc<dyn Pkcs11Backend>;
        backend.initialize().unwrap();
        let contexts = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        contexts.populate_slots(&backend).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(wire::Pkcs11ProxyServer::new(Pkcs11ProxyService::insecure_for_tests(
                    contexts, backend,
                )))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = stopped.await;
                    },
                )
                .await
                .unwrap();
        });
        let mut rpc = wire::Pkcs11ProxyClient::connect(endpoint).await.unwrap();
        let init = rpc.initialize(wire::InitializeRequest::default()).await.unwrap().into_inner();
        assert_eq!(init.ck_rv, CKR_OK as u64);
        let context = init.client_context_id;
        let slots = rpc
            .get_slot_list(wire::GetSlotListRequest {
                client_context_id: context.clone(),
                token_present: true,
            })
            .await
            .unwrap()
            .into_inner();
        let session = rpc
            .open_session(wire::OpenSessionRequest {
                client_context_id: context.clone(),
                slot_id: slots.slot_ids[0],
                flags: (CKF_SERIAL_SESSION | CKF_RW_SESSION) as u64,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(session.ck_rv, CKR_OK as u64);
        let session = session.session_handle;
        let key = rpc
            .create_object(wire::CreateObjectRequest {
                client_context_id: context.clone(),
                session_handle: session,
                template: Vec::new(),
                template_null: false,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(key.ck_rv, CKR_OK as u64);
        Self { oracle, rpc, context, session, key: key.object_handle, stop }
    }

    fn scenario(&self, rv: CK_RV) {
        unsafe {
            let scenario = ExactOracleScenario { rv: rv as u64, ..Default::default() };
            assert_eq!(
                self.oracle
                    .get::<unsafe extern "C" fn(*const ExactOracleScenario) -> u32>(
                        b"ExactOracle_SetScenario\0",
                    )
                    .unwrap()(&scenario),
                0
            );
            assert_eq!(
                self.oracle
                    .get::<unsafe extern "C" fn() -> u32>(b"ExactOracle_ResetObservation\0")
                    .unwrap()(),
                0
            );
        }
    }

    fn observe(&self) -> ExactOracleObservation {
        unsafe {
            let mut observation = ExactOracleObservation::default();
            assert_eq!(
                self.oracle
                    .get::<unsafe extern "C" fn(*mut ExactOracleObservation) -> u32>(
                        b"ExactOracle_GetObservation\0",
                    )
                    .unwrap()(&mut observation),
                0
            );
            observation
        }
    }

    async fn init(&mut self, decrypt: bool) {
        self.scenario(CKR_OK);
        let mechanism =
            Some(wire::Mechanism { mechanism_type: CKM_AES_GCM as u64, ..Default::default() });
        let rv = if decrypt {
            self.rpc
                .message_decrypt_init(wire::MessageDecryptInitRequest {
                    client_context_id: self.context.clone(),
                    session_handle: self.session,
                    mechanism,
                    key_handle: self.key,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner()
                .ck_rv
        } else {
            self.rpc
                .message_encrypt_init(wire::MessageEncryptInitRequest {
                    client_context_id: self.context.clone(),
                    session_handle: self.session,
                    mechanism,
                    key_handle: self.key,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner()
                .ck_rv
        };
        assert_eq!(rv, CKR_OK as u64);
    }

    // No parameter spec or message envelope: exactly the public legacy client
    // shape. Both version-zero clients and version-one clients remain valid.
    async fn begin(&mut self, decrypt: bool, version: u32, parameter: Vec<u8>) -> u64 {
        let (rv, bytes, acknowledgement, old_parameter, effects) = if decrypt {
            let out = self
                .rpc
                .decrypt_message_begin(wire::DecryptMessageBeginRequest {
                    client_context_id: self.context.clone(),
                    session_handle: self.session,
                    parameter,
                    exact_output_effects_version: version,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            (
                out.ck_rv,
                out.parameter_out,
                out.parameter_result,
                out.message_parameter_out,
                out.message_effects,
            )
        } else {
            let out = self
                .rpc
                .encrypt_message_begin(wire::EncryptMessageBeginRequest {
                    client_context_id: self.context.clone(),
                    session_handle: self.session,
                    parameter,
                    exact_output_effects_version: version,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            (
                out.ck_rv,
                out.parameter_out,
                out.parameter_result,
                out.message_parameter_out,
                out.message_effects,
            )
        };
        assert!(bytes.is_empty(), "legacy Begin must not gain a raw output");
        assert!(acknowledgement.is_none(), "legacy Begin must not gain an exact ack");
        assert!(old_parameter.is_none());
        assert!(effects.is_none());
        rv
    }

    async fn establish_down(
        &mut self,
        health: &mut tokio::sync::mpsc::Receiver<BackendHealthEvent>,
    ) {
        while health.try_recv().is_ok() {}
        self.scenario(CKR_DEVICE_REMOVED);
        let out = self
            .rpc
            .byte_output_exact(wire::ByteOutputExactRequest {
                client_context_id: self.context.clone(),
                session_handle: self.session,
                function: wire::ByteOutputFunction::GetOperationState as i32,
                output_spec: Some(wire::OutputBufferSpec {
                    buffer_present: true,
                    buffer_len: 8,
                    length_pointer_null: false,
                }),
                exact_output_effects_version: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(out.result.unwrap().ck_rv, CKR_DEVICE_REMOVED as u64);
        assert!(matches!(health.try_recv(), Ok(BackendHealthEvent::Failure)));
        assert!(health.try_recv().is_err());
    }
}

fn expect_health(
    health: &mut tokio::sync::mpsc::Receiver<BackendHealthEvent>,
    expected: Option<bool>,
    label: &str,
    failures: &mut Vec<String>,
) {
    let actual = health.try_recv().ok();
    println!("{label}: health={actual:?}, expected={expected:?}");
    let matches = matches!(
        (&actual, expected),
        (Some(BackendHealthEvent::Success), Some(true))
            | (Some(BackendHealthEvent::Failure), Some(false))
            | (None, None)
    );
    if !matches {
        failures.push(format!("{label}: {actual:?}, expected {expected:?}"));
    }
    assert!(health.try_recv().is_err(), "one call must not emit multiple health events");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires both explicitly built native oracle variants"]
async fn noncontract_begin_native_health_and_legacy_compatibility() {
    // One test owns the process-global health channel and both native fixtures.
    let (tx, mut health) = tokio::sync::mpsc::channel(64);
    configure_backend_health_events(tx);
    let mut harness = Harness::start("PKCS11_PROXY_EXACT_ORACLE_LIB").await;
    let mut failures = Vec::new();
    for decrypt in [false, true] {
        for provider_rv in [CKR_DEVICE_REMOVED, CKR_HOST_MEMORY] {
            harness.init(decrypt).await;
            harness.establish_down(&mut health).await;
            harness.scenario(provider_rv);
            let rv = harness.begin(decrypt, 1, Vec::new()).await;
            let observation = harness.observe();
            println!(
                "provider-down: decrypt={decrypt}, native={provider_rv:#x}, caller={rv:#x}, {observation:?}"
            );
            assert_eq!(rv, provider_rv as u64);
            assert_eq!(observation.calls, 1);
            assert_eq!(observation.begin_parameter_present, 1);
            assert_eq!(observation.begin_parameter_length, 0);
            expect_health(
                &mut health,
                Some(false),
                &format!("provider-down decrypt={decrypt} rv={provider_rv:#x}"),
                &mut failures,
            );
            // The saved operation survives these non-ambiguous native errors.
            // Version-zero success then demonstrates real recovery, not a
            // fabricated success event caused by constructing an RPC reply.
            harness.scenario(CKR_OK);
            assert_eq!(harness.begin(decrypt, 0, Vec::new()).await, CKR_OK as u64);
            assert_eq!(harness.observe().calls, 1);
            expect_health(&mut health, Some(true), "native recovery", &mut failures);
        }

        for provider_rv in [CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED, CKR_DEVICE_ERROR] {
            harness.init(decrypt).await;
            harness.establish_down(&mut health).await;
            harness.scenario(provider_rv);
            assert_eq!(harness.begin(decrypt, 0, Vec::new()).await, provider_rv as u64);
            assert_eq!(harness.observe().calls, 1);
            expect_health(&mut health, Some(true), "ordinary native error", &mut failures);
            harness.scenario(CKR_OK);
            if provider_rv == CKR_DEVICE_ERROR {
                assert_eq!(
                    harness.begin(decrypt, 1, Vec::new()).await,
                    CKR_OPERATION_NOT_INITIALIZED as u64
                );
                assert_eq!(harness.observe().calls, 0);
                expect_health(&mut health, None, "ambiguous operation cleared", &mut failures);
            } else {
                // Success events are deliberately coalesced while healthy.
                harness.establish_down(&mut health).await;
                harness.scenario(CKR_OK);
                assert_eq!(harness.begin(decrypt, 1, Vec::new()).await, CKR_OK as u64);
                assert_eq!(harness.observe().calls, 1);
                expect_health(
                    &mut health,
                    Some(true),
                    "ordinary error retains operation",
                    &mut failures,
                );
            }
        }

        harness.init(decrypt).await;
        harness.establish_down(&mut health).await;
        harness.scenario(CKR_HOST_MEMORY);
        assert_eq!(harness.begin(decrypt, 0, vec![1]).await, CKR_MECHANISM_PARAM_INVALID as u64);
        assert_eq!(harness.observe().calls, 0);
        expect_health(&mut health, None, "legacy preparation rejection", &mut failures);
        harness.scenario(CKR_OK);
        assert_eq!(harness.begin(decrypt, 0, Vec::new()).await, CKR_OK as u64);
        assert_eq!(harness.observe().calls, 1);
        expect_health(&mut health, Some(true), "preparation retains operation", &mut failures);

        let other_context = harness
            .rpc
            .initialize(wire::InitializeRequest::default())
            .await
            .unwrap()
            .into_inner()
            .client_context_id;
        harness.establish_down(&mut health).await;
        harness.scenario(CKR_HOST_MEMORY);
        let own_context = std::mem::replace(&mut harness.context, other_context);
        assert_eq!(harness.begin(decrypt, 1, Vec::new()).await, CKR_SESSION_HANDLE_INVALID as u64);
        harness.context = own_context;
        assert_eq!(harness.observe().calls, 0);
        expect_health(&mut health, None, "foreign session denied", &mut failures);
    }
    let _ = harness.stop.send(());

    let mut missing = Harness::start("PKCS11_PROXY_MISSING_BEGIN_ORACLE_LIB").await;
    for decrypt in [false, true] {
        missing.init(decrypt).await;
        // No function pointer means no native completion, regardless of the
        // scenario RV; the old ordinary adapter incorrectly reported Success.
        for version in [0, 1] {
            missing.establish_down(&mut health).await;
            missing.scenario(CKR_HOST_MEMORY);
            assert_eq!(
                missing.begin(decrypt, version, Vec::new()).await,
                CKR_FUNCTION_NOT_SUPPORTED as u64
            );
            assert_eq!(missing.observe().calls, 0);
            expect_health(&mut health, None, "missing native Begin function", &mut failures);
        }
    }
    let _ = missing.stop.send(());
    assert!(failures.is_empty(), "legacy Begin completion classification defects: {failures:#?}");
}

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng::server::handle_map::VirtualHandle;
use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend, mock::MockAttributeSlot};
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
use pkcs11_proxy_ng_types::{
    CkAttributeQuery, CkAttributeQueryResult, CkAttributeType, CkAttributeValue, CkMechanismParams,
    CkMechanismType, CkObjectHandle, CkOutputBufferResult, CkOutputBufferSpec,
    CkParameterRoundtripSpec, CkRv, CkSessionFlags, CkSlotId, GcmParams, InterfaceCapabilities,
    InterfaceInfo, ParameterOutputFunction,
};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::watch;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use super::*;

static TEST_DAEMON: OnceLock<TestDaemon> = OnceLock::new();

struct TestDaemon {
    runtime: Runtime,
    endpoint: String,
    backend: Arc<MockBackend>,
    context_manager: Arc<ContextManager>,
    _shutdown: watch::Sender<bool>,
}

impl TestDaemon {
    fn shared() -> &'static Self {
        TEST_DAEMON.get_or_init(Self::start)
    }

    fn start() -> Self {
        let runtime = Runtime::new().expect("test runtime");
        let (endpoint, backend, context_manager, shutdown) = runtime.block_on(async {
            let backend = Arc::new(MockBackend::new(
                vec![CkSlotId(0), CkSlotId(1)],
                vec![CkMechanismType::SHA256, CkMechanismType::RSA_PKCS, CkMechanismType::AES_ECB],
            ));
            backend.set_interface_capabilities(InterfaceCapabilities {
                interfaces: vec![
                    InterfaceInfo { version_major: 2, version_minor: 40, null_functions: vec![] },
                    InterfaceInfo { version_major: 3, version_minor: 0, null_functions: vec![] },
                    InterfaceInfo { version_major: 3, version_minor: 2, null_functions: vec![] },
                ],
            });
            let backend_trait: Arc<dyn Pkcs11Backend> = backend.clone();
            let context_manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
            context_manager.populate_slots(&backend_trait).await.expect("populate_slots");

            let service =
                Pkcs11ProxyService::insecure_for_tests(context_manager.clone(), backend_trait);
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test daemon");
            let addr = listener.local_addr().expect("local addr");
            let endpoint = format!("http://127.0.0.1:{}", addr.port());
            let incoming = TcpListenerStream::new(listener);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);

            tokio::spawn(async move {
                let _ = Server::builder()
                    .add_service(Pkcs11ProxyServer::new(service))
                    .serve_with_incoming_shutdown(incoming, async move {
                        let mut shutdown_rx = shutdown_rx;
                        let _ = shutdown_rx.changed().await;
                    })
                    .await;
            });

            tokio::time::sleep(Duration::from_millis(50)).await;
            (endpoint, backend, context_manager, shutdown_tx)
        });

        Self { runtime, endpoint, backend, context_manager, _shutdown: shutdown }
    }

    fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }
}

struct ShimSession {
    session: CK_SESSION_HANDLE,
    slot_id: CK_SLOT_ID,
}

impl ShimSession {
    fn new() -> Self {
        let daemon = TestDaemon::shared();
        Self::with_endpoint(&daemon.endpoint)
    }

    fn with_endpoint(endpoint: &str) -> Self {
        unsafe {
            std::env::set_var("PKCS11_PROXY_ENDPOINT", endpoint);
        }

        let init_rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
        assert_eq!(init_rv, CKR_OK as CK_RV, "C_Initialize");

        let mut slot_count = 0;
        let slot_count_rv = unsafe {
            dispatch::general::c_get_slot_list(CK_FALSE, std::ptr::null_mut(), &mut slot_count)
        };
        assert_eq!(slot_count_rv, CKR_OK as CK_RV, "C_GetSlotList(count)");
        assert!(slot_count > 0, "expected at least one slot");

        let mut slots = vec![0; slot_count as usize];
        let slot_list_rv = unsafe {
            dispatch::general::c_get_slot_list(CK_FALSE, slots.as_mut_ptr(), &mut slot_count)
        };
        assert_eq!(slot_list_rv, CKR_OK as CK_RV, "C_GetSlotList(data)");

        let mut session = CK_INVALID_HANDLE;
        let open_rv = unsafe {
            dispatch::general::c_open_session(
                slots[0],
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &mut session,
            )
        };
        assert_eq!(open_rv, CKR_OK as CK_RV, "C_OpenSession");

        Self { session, slot_id: slots[0] }
    }

    fn open_additional_session(&self) -> CK_SESSION_HANDLE {
        let mut session = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_open_session(
                self.slot_id,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &mut session,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_OpenSession(additional)");
        session
    }

    fn open_session_on_slot(&self, slot_id: CK_SLOT_ID) -> CK_SESSION_HANDLE {
        let mut session = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_open_session(
                slot_id,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &mut session,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_OpenSession(slot)");
        session
    }
}

impl Drop for ShimSession {
    fn drop(&mut self) {
        if self.session != CK_INVALID_HANDLE {
            let _ = unsafe { dispatch::general::c_close_session(self.session) };
        }
        let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    }
}

fn sha256_mechanism() -> CK_MECHANISM {
    CK_MECHANISM { mechanism: CKM_SHA256, pParameter: std::ptr::null_mut(), ulParameterLen: 0 }
}

fn rsa_pkcs_mechanism() -> CK_MECHANISM {
    CK_MECHANISM { mechanism: CKM_RSA_PKCS, pParameter: std::ptr::null_mut(), ulParameterLen: 0 }
}

fn expected_mock_digest(data: &[u8]) -> [u8; 4] {
    data.iter().fold(0_u32, |sum, byte| sum + u32::from(*byte)).to_be_bytes()
}

fn create_object(session: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let mut object = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_create_object(session, std::ptr::null_mut(), 0, &mut object)
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CreateObject");
    object
}

fn backend_object_handle(daemon: &TestDaemon, object: CK_OBJECT_HANDLE) -> CkObjectHandle {
    daemon.block_on(async {
        let context_ids = daemon.context_manager.context_ids().await;
        assert_eq!(context_ids.len(), 1, "expected one active shim context");
        let backend_handle = daemon
            .context_manager
            .get_context(&context_ids[0], |ctx| ctx.object_handles.resolve(VirtualHandle(object)))
            .await
            .flatten()
            .expect("backend object handle");
        CkObjectHandle(backend_handle.0)
    })
}

fn export_operation_state(
    session: CK_SESSION_HANDLE,
    expected_rv: CK_RV,
    expected_len: usize,
) -> Vec<u8> {
    let mut out = vec![0_u8; expected_len];
    let mut out_len = out.len() as CK_ULONG;
    let rv = unsafe {
        dispatch::general::c_get_operation_state(session, out.as_mut_ptr(), &mut out_len)
    };
    assert_eq!(rv, expected_rv, "C_GetOperationState(data)");
    out.truncate(out_len as usize);
    out
}

fn label_attr(buffer: Option<&mut [u8]>) -> CK_ATTRIBUTE {
    let (p_value, len) = match buffer {
        Some(bytes) => (bytes.as_mut_ptr() as CK_VOID_PTR, bytes.len() as CK_ULONG),
        None => (std::ptr::null_mut(), 0),
    };
    CK_ATTRIBUTE { type_: CKA_LABEL, pValue: p_value, ulValueLen: len }
}

#[test]
fn write_exact_output_rejects_value_larger_than_declared_buffer_without_copy() {
    let mut backing = [0xAA_u8; 4];
    let mut declared_len: CK_ULONG = 2;
    let result =
        CkOutputBufferResult { ck_rv: CkRv::OK, returned_len: 4, value: Some(vec![1, 2, 3, 4]) };

    let rv = unsafe {
        dispatch::general::write_exact_output(&result, backing.as_mut_ptr(), &mut declared_len)
    };

    assert_eq!(rv, CKR_GENERAL_ERROR as CK_RV);
    assert_eq!(declared_len, 4);
    assert_eq!(backing, [0xAA; 4]);
}

#[test]
fn write_exact_output_does_not_copy_value_on_buffer_too_small() {
    let mut backing = [0xAA_u8; 4];
    let mut declared_len: CK_ULONG = 2;
    let result = CkOutputBufferResult {
        ck_rv: CkRv::BUFFER_TOO_SMALL,
        returned_len: 4,
        value: Some(vec![1, 2, 3, 4]),
    };

    let rv = unsafe {
        dispatch::general::write_exact_output(&result, backing.as_mut_ptr(), &mut declared_len)
    };

    assert_eq!(rv, CKR_BUFFER_TOO_SMALL as CK_RV);
    assert_eq!(declared_len, 4);
    assert_eq!(backing, [0xAA; 4]);
}

#[test]
fn shim_get_attribute_value_size_query_returns_exact_length_without_copy() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    let shim = ShimSession::new();
    let object = create_object(shim.session);
    daemon.backend.set_attribute(
        backend_object_handle(daemon, object),
        CkAttributeType::LABEL,
        MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
    );

    let mut attr = label_attr(None);
    attr.ulValueLen = 99;
    let rv =
        unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert_eq!(attr.ulValueLen, 3);
}

#[test]
fn shim_get_attribute_value_exact_fit_copies_bytes() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    let shim = ShimSession::new();
    let object = create_object(shim.session);
    daemon.backend.set_attribute(
        backend_object_handle(daemon, object),
        CkAttributeType::LABEL,
        MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
    );

    let mut bytes = [0xAA_u8; 3];
    let mut attr = label_attr(Some(&mut bytes));
    let rv =
        unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert_eq!(attr.ulValueLen, 3);
    assert_eq!(&bytes, b"key");
}

#[test]
fn shim_get_attribute_value_too_small_preserves_unavailable_information() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    let shim = ShimSession::new();
    let object = create_object(shim.session);
    daemon.backend.set_attribute(
        backend_object_handle(daemon, object),
        CkAttributeType::LABEL,
        MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
    );

    let mut bytes = [0xAA_u8; 2];
    let mut attr = label_attr(Some(&mut bytes));
    let rv =
        unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
    assert_eq!(rv, CKR_BUFFER_TOO_SMALL as CK_RV);
    assert_eq!(attr.ulValueLen, CK_UNAVAILABLE_INFORMATION);
    assert_eq!(bytes, [0xAA, 0xAA]);
}

#[test]
fn shim_get_attribute_value_mixed_template_reflects_backend_semantics() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    let shim = ShimSession::new();
    let object = create_object(shim.session);
    let backend_object = backend_object_handle(daemon, object);
    daemon.backend.set_attribute(
        backend_object,
        CkAttributeType::LABEL,
        MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
    );
    daemon.backend.set_attribute(
        backend_object,
        CkAttributeType::VALUE,
        MockAttributeSlot::Sensitive,
    );
    daemon.backend.set_attribute(
        backend_object,
        CkAttributeType::MODULUS,
        MockAttributeSlot::InvalidType,
    );

    let mut label = [0_u8; 3];
    let mut template = [
        label_attr(Some(&mut label)),
        CK_ATTRIBUTE { type_: CKA_VALUE, pValue: std::ptr::null_mut(), ulValueLen: 0 },
        CK_ATTRIBUTE { type_: CKA_MODULUS, pValue: std::ptr::null_mut(), ulValueLen: 0 },
    ];

    let rv = unsafe {
        dispatch::general::c_get_attribute_value(
            shim.session,
            object,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
        )
    };
    assert_eq!(rv, CKR_ATTRIBUTE_SENSITIVE as CK_RV);
    assert_eq!(&label, b"key");
    assert_eq!(template[0].ulValueLen, 3);
    assert_eq!(template[1].ulValueLen, CK_UNAVAILABLE_INFORMATION);
    assert_eq!(template[2].ulValueLen, CK_UNAVAILABLE_INFORMATION);
}

#[test]
fn shim_get_attribute_value_preserves_fatal_server_rv_when_results_are_empty() {
    let _guard = shim_state_test_guard();
    let _daemon = TestDaemon::shared();
    let shim = ShimSession::new();

    let mut attr = label_attr(None);
    let rv =
        unsafe { dispatch::general::c_get_attribute_value(shim.session, 999_999, &mut attr, 1) };
    assert_eq!(rv, CKR_OBJECT_HANDLE_INVALID as CK_RV);
}

#[test]
fn raw_client_size_query_returns_length_without_bytes() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::start();

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client
            .get_slot_list(false)
            .await
            .expect("C_GetSlotList")
            .into_iter()
            .next()
            .expect("slot");
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");
        let object = client.create_object(session, &[]).await.expect("C_CreateObject");

        daemon.backend.set_attribute(
            object,
            CkAttributeType::LABEL,
            MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
        );

        let (rv, results) = client
            .get_attribute_value_exact(
                session,
                object,
                &[CkAttributeQuery {
                    attr_type: CkAttributeType::LABEL,
                    buffer_present: false,
                    buffer_len: 9,
                    nested: None,
                }],
            )
            .await
            .expect("GetAttributeValueExact RPC");

        assert_eq!(rv, CkRv::OK);
        assert_eq!(
            results,
            vec![CkAttributeQueryResult {
                attr_type: CkAttributeType::LABEL,
                returned_len: 3,
                value: None,
                ck_rv: None,
                nested: None,
            }]
        );

        client.close_session(session).await.expect("C_CloseSession");
        client.finalize().await.expect("C_Finalize");
    });
}

#[test]
fn raw_client_too_small_query_preserves_backend_returned_length() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::start();

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");
        let object = client.create_object(session, &[]).await.expect("C_CreateObject");

        daemon.backend.set_attribute(
            object,
            CkAttributeType::LABEL,
            MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
        );

        let (rv, results) = client
            .get_attribute_value_exact(
                session,
                object,
                &[CkAttributeQuery {
                    attr_type: CkAttributeType::LABEL,
                    buffer_present: true,
                    buffer_len: 2,
                    nested: None,
                }],
            )
            .await
            .expect("GetAttributeValueExact RPC");

        assert_eq!(rv, CkRv::BUFFER_TOO_SMALL);
        assert_eq!(
            results,
            vec![CkAttributeQueryResult {
                attr_type: CkAttributeType::LABEL,
                returned_len: u64::MAX,
                value: None,
                ck_rv: Some(CkRv::BUFFER_TOO_SMALL),
                nested: None,
            }]
        );

        client.close_session(session).await.expect("C_CloseSession");
        client.finalize().await.expect("C_Finalize");
    });
}

#[test]
fn raw_client_exact_fit_query_returns_backend_bytes() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::start();

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");
        let object = client.create_object(session, &[]).await.expect("C_CreateObject");

        daemon.backend.set_attribute(
            object,
            CkAttributeType::LABEL,
            MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
        );

        let (rv, results) = client
            .get_attribute_value_exact(
                session,
                object,
                &[CkAttributeQuery {
                    attr_type: CkAttributeType::LABEL,
                    buffer_present: true,
                    buffer_len: 3,
                    nested: None,
                }],
            )
            .await
            .expect("GetAttributeValueExact RPC");

        assert_eq!(rv, CkRv::OK);
        assert_eq!(
            results,
            vec![CkAttributeQueryResult {
                attr_type: CkAttributeType::LABEL,
                returned_len: 3,
                value: Some(b"key".to_vec()),
                ck_rv: None,
                nested: None,
            }]
        );

        client.close_session(session).await.expect("C_CloseSession");
        client.finalize().await.expect("C_Finalize");
    });
}

#[test]
fn raw_client_mixed_sensitive_and_invalid_preserves_per_attribute_status() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::start();

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");
        let object = client.create_object(session, &[]).await.expect("C_CreateObject");

        daemon.backend.set_attribute(
            object,
            CkAttributeType::LABEL,
            MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
        );
        daemon.backend.set_attribute(object, CkAttributeType::VALUE, MockAttributeSlot::Sensitive);
        daemon.backend.set_attribute(
            object,
            CkAttributeType::MODULUS,
            MockAttributeSlot::InvalidType,
        );

        let (rv, results) = client
            .get_attribute_value_exact(
                session,
                object,
                &[
                    CkAttributeQuery {
                        attr_type: CkAttributeType::LABEL,
                        buffer_present: false,
                        buffer_len: 0,
                        nested: None,
                    },
                    CkAttributeQuery {
                        attr_type: CkAttributeType::VALUE,
                        buffer_present: false,
                        buffer_len: 0,
                        nested: None,
                    },
                    CkAttributeQuery {
                        attr_type: CkAttributeType::MODULUS,
                        buffer_present: false,
                        buffer_len: 0,
                        nested: None,
                    },
                ],
            )
            .await
            .expect("GetAttributeValueExact RPC");

        assert_eq!(rv, CkRv::ATTRIBUTE_SENSITIVE);
        assert_eq!(
            results,
            vec![
                CkAttributeQueryResult {
                    attr_type: CkAttributeType::LABEL,
                    returned_len: 3,
                    value: None,
                    ck_rv: None,
                    nested: None,
                },
                CkAttributeQueryResult {
                    attr_type: CkAttributeType::VALUE,
                    returned_len: u64::MAX,
                    value: None,
                    ck_rv: Some(CkRv::ATTRIBUTE_SENSITIVE),
                    nested: None,
                },
                CkAttributeQueryResult {
                    attr_type: CkAttributeType::MODULUS,
                    returned_len: u64::MAX,
                    value: None,
                    ck_rv: Some(CkRv::ATTRIBUTE_TYPE_INVALID),
                    nested: None,
                },
            ]
        );

        client.close_session(session).await.expect("C_CloseSession");
        client.finalize().await.expect("C_Finalize");
    });
}

#[test]
fn legacy_client_size_query_does_not_synthesize_attribute_bytes() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::start();

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client
            .get_slot_list(false)
            .await
            .expect("C_GetSlotList")
            .into_iter()
            .next()
            .expect("slot");
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");
        let object = client.create_object(session, &[]).await.expect("C_CreateObject");

        daemon.backend.set_attribute(
            object,
            CkAttributeType::LABEL,
            MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
        );

        let (rv, attrs) = client
            .get_attribute_value(
                session,
                object,
                &[pkcs11_proxy_ng_types::CkAttribute {
                    attr_type: CkAttributeType::LABEL,
                    value: None,
                }],
            )
            .await
            .expect("GetAttributeValue RPC");

        assert_eq!(rv, CkRv::OK);
        assert_eq!(attrs.len(), 1);
        assert!(attrs[0].value.is_none());

        client.close_session(session).await.expect("C_CloseSession");
        client.finalize().await.expect("C_Finalize");
    });
}

#[test]
fn cached_size_query_result_is_not_reused_after_digest_reinit() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let mut mechanism = sha256_mechanism();

    let init_rv = unsafe { dispatch::general::c_digest_init(shim.session, &mut mechanism) };
    assert_eq!(init_rv, CKR_OK as CK_RV);

    let first = b"a";
    let mut first_len = 0;
    let first_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            first.as_ptr() as CK_BYTE_PTR,
            first.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut first_len,
        )
    };
    assert_eq!(first_rv, CKR_OK as CK_RV);
    assert_eq!(first_len, 4);

    let reinit_rv = unsafe { dispatch::general::c_digest_init(shim.session, &mut mechanism) };
    assert_eq!(reinit_rv, CKR_OK as CK_RV);

    let second = b"bb";
    let mut out = [0_u8; 4];
    let mut out_len = out.len() as CK_ULONG;
    let second_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            second.as_ptr() as CK_BYTE_PTR,
            second.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_eq!(second_rv, CKR_OK as CK_RV);
    assert_eq!(out_len, out.len() as CK_ULONG);
    assert_eq!(out, expected_mock_digest(second));
}

#[test]
fn finalize_clears_cached_output_state() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let mut mechanism = sha256_mechanism();

    let init_rv = unsafe { dispatch::general::c_digest_init(shim.session, &mut mechanism) };
    assert_eq!(init_rv, CKR_OK as CK_RV);

    let data = b"cache me";
    let mut len = 0;
    let digest_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut len,
        )
    };
    assert_eq!(digest_rv, CKR_OK as CK_RV);

    {
        state::wrap_cache().lock().unwrap().insert(shim.session, vec![0xAA]);
        state::encapsulate_cache().lock().unwrap().insert(shim.session, (vec![0xBB], 77));
    }

    let finalize_rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    assert_eq!(finalize_rv, CKR_OK as CK_RV);

    assert!(state::dig_cache().lock().unwrap().is_empty());
    assert!(state::wrap_cache().lock().unwrap().is_empty());
    assert!(state::encapsulate_cache().lock().unwrap().is_empty());

    std::mem::forget(shim);
}

#[test]
fn close_all_sessions_evicts_only_target_slot_output_caches() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();

    let mut slot_count = 0;
    let count_rv = unsafe {
        dispatch::general::c_get_slot_list(CK_FALSE, std::ptr::null_mut(), &mut slot_count)
    };
    assert_eq!(count_rv, CKR_OK as CK_RV);
    assert!(slot_count >= 2, "test daemon should expose two slots");

    let mut slots = vec![0; slot_count as usize];
    let list_rv = unsafe {
        dispatch::general::c_get_slot_list(CK_FALSE, slots.as_mut_ptr(), &mut slot_count)
    };
    assert_eq!(list_rv, CKR_OK as CK_RV);

    let target_slot = slots[0];
    let other_slot = slots[1];
    let target_session = shim.open_session_on_slot(target_slot);
    let other_session = shim.open_session_on_slot(other_slot);

    state::dig_cache().lock().unwrap().insert(target_session, vec![0xAA]);
    state::wrap_cache().lock().unwrap().insert(target_session, vec![0xBB]);
    state::encapsulate_cache().lock().unwrap().insert(target_session, (vec![0xCC], 7));
    state::dig_cache().lock().unwrap().insert(other_session, vec![0xDD]);
    state::wrap_cache().lock().unwrap().insert(other_session, vec![0xEE]);
    state::encapsulate_cache().lock().unwrap().insert(other_session, (vec![0xFF], 9));

    let close_all_rv = unsafe { dispatch::general::c_close_all_sessions(target_slot) };
    assert_eq!(close_all_rv, CKR_OK as CK_RV);

    assert!(!state::dig_cache().lock().unwrap().contains_key(&target_session));
    assert!(!state::wrap_cache().lock().unwrap().contains_key(&target_session));
    assert!(!state::encapsulate_cache().lock().unwrap().contains_key(&target_session));
    assert!(state::dig_cache().lock().unwrap().contains_key(&other_session));
    assert!(state::wrap_cache().lock().unwrap().contains_key(&other_session));
    assert!(state::encapsulate_cache().lock().unwrap().contains_key(&other_session));

    let mut info = std::mem::MaybeUninit::uninit();
    let stale_rv =
        unsafe { dispatch::general::c_get_session_info(target_session, info.as_mut_ptr()) };
    assert_eq!(stale_rv, CKR_SESSION_HANDLE_INVALID as CK_RV);

    let other_close_rv = unsafe { dispatch::general::c_close_session(other_session) };
    assert_eq!(other_close_rv, CKR_OK as CK_RV);
}

#[test]
fn one_shot_digest_output_is_not_replayed_through_digest_final() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let mut mechanism = sha256_mechanism();

    let init_rv = unsafe { dispatch::general::c_digest_init(shim.session, &mut mechanism) };
    assert_eq!(init_rv, CKR_OK as CK_RV);

    let data = b"replay";
    let mut len = 0;
    let digest_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut len,
        )
    };
    assert_eq!(digest_rv, CKR_OK as CK_RV);
    assert_eq!(len, 4);

    let mut out = [0_u8; 4];
    let mut out_len = out.len() as CK_ULONG;
    let final_rv =
        unsafe { dispatch::general::c_digest_final(shim.session, out.as_mut_ptr(), &mut out_len) };
    assert_eq!(final_rv, CKR_OPERATION_NOT_INITIALIZED as CK_RV);
}

#[test]
fn cached_operation_state_is_not_reused_after_set_operation_state() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let mut digest_mechanism = sha256_mechanism();

    let init_rv = unsafe { dispatch::general::c_digest_init(shim.session, &mut digest_mechanism) };
    assert_eq!(init_rv, CKR_OK as CK_RV);

    let mut cached_len = 0;
    let size_rv = unsafe {
        dispatch::general::c_get_operation_state(
            shim.session,
            std::ptr::null_mut(),
            &mut cached_len,
        )
    };
    assert_eq!(size_rv, CKR_OK as CK_RV);
    assert_eq!(cached_len, 3);

    let second_session = shim.open_additional_session();
    let key = create_object(second_session);
    let mut sign_mechanism = rsa_pkcs_mechanism();
    let sign_init_rv =
        unsafe { dispatch::general::c_sign_init(second_session, &mut sign_mechanism, key) };
    assert_eq!(sign_init_rv, CKR_OK as CK_RV);
    let sign_blob = export_operation_state(second_session, CKR_OK as CK_RV, cached_len as usize);
    let close_rv = unsafe { dispatch::general::c_close_session(second_session) };
    assert_eq!(close_rv, CKR_OK as CK_RV);

    let data = b"digest";
    let mut digest_out = [0_u8; 4];
    let mut digest_len = digest_out.len() as CK_ULONG;
    let digest_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            digest_out.as_mut_ptr(),
            &mut digest_len,
        )
    };
    assert_eq!(digest_rv, CKR_OK as CK_RV);

    let restore_rv = unsafe {
        dispatch::general::c_set_operation_state(
            shim.session,
            sign_blob.as_ptr() as CK_BYTE_PTR,
            sign_blob.len() as CK_ULONG,
            0,
            0,
        )
    };
    assert_eq!(restore_rv, CKR_OK as CK_RV);

    let restored_blob = export_operation_state(shim.session, CKR_OK as CK_RV, sign_blob.len());
    assert_eq!(restored_blob, sign_blob);
}

#[test]
fn restored_operation_clears_stale_output_byte_caches() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let mut digest_mechanism = sha256_mechanism();

    let digest_init_rv =
        unsafe { dispatch::general::c_digest_init(shim.session, &mut digest_mechanism) };
    assert_eq!(digest_init_rv, CKR_OK as CK_RV);

    let stale_data = b"stale";
    let mut stale_len = 0;
    let stale_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            stale_data.as_ptr() as CK_BYTE_PTR,
            stale_data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut stale_len,
        )
    };
    assert_eq!(stale_rv, CKR_OK as CK_RV);
    assert_eq!(stale_len, 4);

    let second_session = shim.open_additional_session();
    let key = create_object(second_session);
    let mut sign_mechanism = rsa_pkcs_mechanism();
    let sign_init_rv =
        unsafe { dispatch::general::c_sign_init(second_session, &mut sign_mechanism, key) };
    assert_eq!(sign_init_rv, CKR_OK as CK_RV);

    let mut sign_blob_len = 0;
    let sign_blob_size_rv = unsafe {
        dispatch::general::c_get_operation_state(
            second_session,
            std::ptr::null_mut(),
            &mut sign_blob_len,
        )
    };
    assert_eq!(sign_blob_size_rv, CKR_OK as CK_RV);
    let sign_blob = export_operation_state(second_session, CKR_OK as CK_RV, sign_blob_len as usize);
    let close_rv = unsafe { dispatch::general::c_close_session(second_session) };
    assert_eq!(close_rv, CKR_OK as CK_RV);

    let restore_rv = unsafe {
        dispatch::general::c_set_operation_state(
            shim.session,
            sign_blob.as_ptr() as CK_BYTE_PTR,
            sign_blob.len() as CK_ULONG,
            0,
            0,
        )
    };
    assert_eq!(restore_rv, CKR_OK as CK_RV);

    let fresh_data = b"fresh";
    let mut digest_out = [0_u8; 4];
    let mut digest_len = digest_out.len() as CK_ULONG;
    let digest_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            fresh_data.as_ptr() as CK_BYTE_PTR,
            fresh_data.len() as CK_ULONG,
            digest_out.as_mut_ptr(),
            &mut digest_len,
        )
    };
    assert_eq!(digest_rv, CKR_OPERATION_NOT_INITIALIZED as CK_RV);
}

#[test]
fn restored_operation_evicts_other_session_scoped_output_caches() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();

    let second_session = shim.open_additional_session();
    let key = create_object(second_session);
    let mut sign_mechanism = rsa_pkcs_mechanism();
    let sign_init_rv =
        unsafe { dispatch::general::c_sign_init(second_session, &mut sign_mechanism, key) };
    assert_eq!(sign_init_rv, CKR_OK as CK_RV);

    let mut sign_blob_len = 0;
    let sign_blob_size_rv = unsafe {
        dispatch::general::c_get_operation_state(
            second_session,
            std::ptr::null_mut(),
            &mut sign_blob_len,
        )
    };
    assert_eq!(sign_blob_size_rv, CKR_OK as CK_RV);
    let sign_blob = export_operation_state(second_session, CKR_OK as CK_RV, sign_blob_len as usize);
    let close_rv = unsafe { dispatch::general::c_close_session(second_session) };
    assert_eq!(close_rv, CKR_OK as CK_RV);

    {
        state::wrap_cache().lock().unwrap().insert(shim.session, vec![0xAA, 0xBB]);
        state::msg_enc_cache().lock().unwrap().insert(shim.session, vec![0xCC, 0xDD]);
        state::encapsulate_cache().lock().unwrap().insert(shim.session, (vec![0xEE], 42));
    }

    let restore_rv = unsafe {
        dispatch::general::c_set_operation_state(
            shim.session,
            sign_blob.as_ptr() as CK_BYTE_PTR,
            sign_blob.len() as CK_ULONG,
            0,
            0,
        )
    };
    assert_eq!(restore_rv, CKR_OK as CK_RV);

    assert!(!state::wrap_cache().lock().unwrap().contains_key(&shim.session));
    assert!(!state::msg_enc_cache().lock().unwrap().contains_key(&shim.session));
    assert!(!state::encapsulate_cache().lock().unwrap().contains_key(&shim.session));
}

#[test]
fn cached_operation_state_is_not_reused_after_operation_reinit() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let mut digest_mechanism = sha256_mechanism();

    let digest_init_rv =
        unsafe { dispatch::general::c_digest_init(shim.session, &mut digest_mechanism) };
    assert_eq!(digest_init_rv, CKR_OK as CK_RV);

    let mut cached_len = 0;
    let size_rv = unsafe {
        dispatch::general::c_get_operation_state(
            shim.session,
            std::ptr::null_mut(),
            &mut cached_len,
        )
    };
    assert_eq!(size_rv, CKR_OK as CK_RV);
    assert_eq!(cached_len, 3);

    let data = b"digest";
    let mut digest_out = [0_u8; 4];
    let mut digest_len = digest_out.len() as CK_ULONG;
    let digest_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            digest_out.as_mut_ptr(),
            &mut digest_len,
        )
    };
    assert_eq!(digest_rv, CKR_OK as CK_RV);

    let key = create_object(shim.session);
    let mut sign_mechanism = rsa_pkcs_mechanism();
    let sign_init_rv =
        unsafe { dispatch::general::c_sign_init(shim.session, &mut sign_mechanism, key) };
    assert_eq!(sign_init_rv, CKR_OK as CK_RV);

    let sign_blob = export_operation_state(shim.session, CKR_OK as CK_RV, cached_len as usize);
    assert_eq!(sign_blob.len(), cached_len as usize);
    assert_ne!(sign_blob, vec![0xC9, 0xEA, 0x03]);
}

#[test]
fn exact_digest_size_query_returns_length_without_copy() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let mut mechanism = sha256_mechanism();

    let init_rv = unsafe { dispatch::general::c_digest_init(shim.session, &mut mechanism) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_DigestInit");

    let data = b"hello";
    // NULL output pointer = size query; pul_digest_len must be initialised but
    // its incoming value is ignored by the exact path.
    let mut out_len: CK_ULONG = 0;
    let size_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut out_len,
        )
    };
    assert_eq!(size_rv, CKR_OK as CK_RV, "C_Digest(size query)");
    // Mock digest returns 4 bytes (sum of input bytes as u32 big-endian)
    assert_eq!(out_len, 4, "returned_len should be 4");
}

#[test]
fn exact_digest_final_size_query_does_not_consume_state() {
    // With the exact (non-caching) path, each call to C_DigestFinal goes
    // directly to the backend.  This test verifies that:
    //   1. A size query (NULL output) returns CKR_OK with the correct length.
    //   2. A subsequent data query on a fresh operation returns the bytes.
    //
    // Note: the MockBackend's digest_final_exact_impl consumes the operation on
    // every call (matching real PKCS#11 semantics where the token may or may not
    // retain state after a size query).  We therefore re-initialise between calls.
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let mut mechanism = sha256_mechanism();

    // --- Step 1: size query ---
    let init_rv = unsafe { dispatch::general::c_digest_init(shim.session, &mut mechanism) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_DigestInit (size query)");

    let part = b"abc";
    let update_rv = unsafe {
        dispatch::general::c_digest_update(
            shim.session,
            part.as_ptr() as CK_BYTE_PTR,
            part.len() as CK_ULONG,
        )
    };
    assert_eq!(update_rv, CKR_OK as CK_RV, "C_DigestUpdate");

    let mut out_len: CK_ULONG = 0;
    let size_rv = unsafe {
        dispatch::general::c_digest_final(shim.session, std::ptr::null_mut(), &mut out_len)
    };
    assert_eq!(size_rv, CKR_OK as CK_RV, "C_DigestFinal(size query)");
    // Mock digest_final always returns MOCK_DIGEST_FINAL_LEN (4) bytes
    assert_eq!(out_len, 4, "size query returned_len should be 4");

    // --- Step 2: data query on a fresh operation ---
    let reinit_rv = unsafe { dispatch::general::c_digest_init(shim.session, &mut mechanism) };
    assert_eq!(reinit_rv, CKR_OK as CK_RV, "C_DigestInit (data query)");

    let update2_rv = unsafe {
        dispatch::general::c_digest_update(
            shim.session,
            part.as_ptr() as CK_BYTE_PTR,
            part.len() as CK_ULONG,
        )
    };
    assert_eq!(update2_rv, CKR_OK as CK_RV, "C_DigestUpdate (second)");

    let mut out = [0_u8; 4];
    let mut data_len = out.len() as CK_ULONG;
    let data_rv =
        unsafe { dispatch::general::c_digest_final(shim.session, out.as_mut_ptr(), &mut data_len) };
    assert_eq!(data_rv, CKR_OK as CK_RV, "C_DigestFinal(data query)");
    assert_eq!(data_len, 4, "data query returned_len should be 4");
    assert_eq!(out, [0u8; 4], "mock digest_final output should be all zeros");
}

#[test]
fn exact_sign_size_query_returns_length_without_copy() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = rsa_pkcs_mechanism();

    let init_rv = unsafe { dispatch::general::c_sign_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_SignInit");

    let data = b"hello";
    // NULL output pointer = size query
    let mut out_len: CK_ULONG = 0;
    let size_rv = unsafe {
        dispatch::general::c_sign(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut out_len,
        )
    };
    assert_eq!(size_rv, CKR_OK as CK_RV, "C_Sign(size query)");
    // MockBackend returns MOCK_SIGN_OUTPUT = [0xDE, 0xAD] = 2 bytes
    assert_eq!(out_len, 2, "returned_len should be 2 for mock sign output");
}

#[test]
fn exact_sign_final_size_query_does_not_consume_state() {
    // With the exact (non-caching) path, each call to C_SignFinal goes
    // directly to the backend.  This test verifies that:
    //   1. A size query (NULL output) returns CKR_OK with the correct length.
    //   2. A subsequent data query on a fresh operation returns the bytes.
    //
    // Note: the MockBackend's sign_final_exact_impl consumes the operation on
    // every call (matching real PKCS#11 semantics).  We therefore re-initialise
    // between calls.
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = rsa_pkcs_mechanism();

    // --- Step 1: size query ---
    let init_rv = unsafe { dispatch::general::c_sign_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_SignInit (size query)");

    let mut out_len: CK_ULONG = 0;
    let size_rv = unsafe {
        dispatch::general::c_sign_final(shim.session, std::ptr::null_mut(), &mut out_len)
    };
    assert_eq!(size_rv, CKR_OK as CK_RV, "C_SignFinal(size query)");
    // MockBackend sign_final returns MOCK_SIGN_OUTPUT = [0xDE, 0xAD] = 2 bytes
    assert_eq!(out_len, 2, "size query returned_len should be 2");

    // --- Step 2: data query on a fresh operation ---
    let reinit_rv = unsafe { dispatch::general::c_sign_init(shim.session, &mut mechanism, key) };
    assert_eq!(reinit_rv, CKR_OK as CK_RV, "C_SignInit (data query)");

    let mut out = [0_u8; 2];
    let mut data_len = out.len() as CK_ULONG;
    let data_rv =
        unsafe { dispatch::general::c_sign_final(shim.session, out.as_mut_ptr(), &mut data_len) };
    assert_eq!(data_rv, CKR_OK as CK_RV, "C_SignFinal(data query)");
    assert_eq!(data_len, 2, "data query returned_len should be 2");
    assert_eq!(out, [0xDE, 0xAD], "mock sign_final output should be [0xDE, 0xAD]");
}

fn aes_ecb_mechanism() -> CK_MECHANISM {
    CK_MECHANISM { mechanism: CKM_AES_ECB, pParameter: std::ptr::null_mut(), ulParameterLen: 0 }
}

fn aes_gcm_mechanism(params: &mut CK_GCM_PARAMS) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: params as *mut CK_GCM_PARAMS as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    }
}

fn generic_mechanism() -> CK_MECHANISM {
    CK_MECHANISM { mechanism: 0x00000001, pParameter: std::ptr::null_mut(), ulParameterLen: 0 }
}

#[test]
fn gcm_generated_iv_round_trips_through_shim_client_and_server() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    let generated_iv = vec![0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB];
    daemon.backend.set_encrypt_init_output(Some(CkMechanismParams::Gcm(GcmParams {
        iv: generated_iv.clone(),
        iv_bits: 96,
        iv_buffer_len: generated_iv.len() as u64,
        aad: b"aad".to_vec(),
        tag_bits: 128,
    })));

    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut iv_buffer = [0_u8; 12];
    let mut aad = *b"aad";
    let mut params = CK_GCM_PARAMS {
        pIv: iv_buffer.as_mut_ptr(),
        ulIvLen: 0,
        ulIvBits: 96,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mut mechanism = aes_gcm_mechanism(&mut params);

    let rv = unsafe { dispatch::general::c_encrypt_init(shim.session, &mut mechanism, key) };

    daemon.backend.set_encrypt_init_output(None);
    assert_eq!(rv, CKR_OK as CK_RV, "C_EncryptInit");
    assert_eq!(params.ulIvLen, generated_iv.len() as CK_ULONG, "provider IV length writeback");
    assert_eq!(params.ulIvBits, 96, "provider IV bit length writeback");
    assert_eq!(params.ulTagBits, 128, "provider tag bit length writeback");
    assert_eq!(iv_buffer.as_slice(), generated_iv.as_slice(), "generated IV writeback");
}

#[test]
fn gcm_delayed_iv_round_trips_after_encrypt_data_query() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    let generated_iv = vec![0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB];
    daemon.backend.set_encrypt_exact_output(Some(CkMechanismParams::Gcm(GcmParams {
        iv: generated_iv.clone(),
        iv_bits: 96,
        iv_buffer_len: generated_iv.len() as u64,
        aad: b"aad".to_vec(),
        tag_bits: 128,
    })));

    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut iv_buffer = [0_u8; 12];
    let mut aad = *b"aad";
    let mut params = CK_GCM_PARAMS {
        pIv: iv_buffer.as_mut_ptr(),
        ulIvLen: 0,
        ulIvBits: 96,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mut mechanism = aes_gcm_mechanism(&mut params);

    let init_rv = unsafe { dispatch::general::c_encrypt_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_EncryptInit");
    assert_eq!(iv_buffer, [0; 12], "delayed IV is not available during init");

    let plaintext = b"hello";
    let mut ciphertext = [0_u8; 5];
    let mut ciphertext_len = ciphertext.len() as CK_ULONG;
    let encrypt_rv = unsafe {
        dispatch::general::c_encrypt(
            shim.session,
            plaintext.as_ptr() as CK_BYTE_PTR,
            plaintext.len() as CK_ULONG,
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
        )
    };

    daemon.backend.set_encrypt_exact_output(None);
    assert_eq!(encrypt_rv, CKR_OK as CK_RV, "C_Encrypt(data)");
    assert_eq!(ciphertext_len, plaintext.len() as CK_ULONG);
    assert_eq!(ciphertext, [0x2A, 0x27, 0x2E, 0x2E, 0x2D], "mock ciphertext");
    assert_eq!(params.ulIvLen, generated_iv.len() as CK_ULONG, "delayed IV length writeback");
    assert_eq!(iv_buffer.as_slice(), generated_iv.as_slice(), "delayed IV writeback");
}

#[test]
fn gcm_delayed_iv_size_query_does_not_consume_writeback() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    let generated_iv = vec![0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB];
    daemon.backend.set_encrypt_exact_output(Some(CkMechanismParams::Gcm(GcmParams {
        iv: generated_iv.clone(),
        iv_bits: 96,
        iv_buffer_len: generated_iv.len() as u64,
        aad: b"aad".to_vec(),
        tag_bits: 128,
    })));

    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut iv_buffer = [0_u8; 12];
    let mut aad = *b"aad";
    let mut params = CK_GCM_PARAMS {
        pIv: iv_buffer.as_mut_ptr(),
        ulIvLen: 0,
        ulIvBits: 96,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mut mechanism = aes_gcm_mechanism(&mut params);

    let init_rv = unsafe { dispatch::general::c_encrypt_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_EncryptInit");

    let plaintext = b"hello";
    let mut size_len = 0;
    let size_rv = unsafe {
        dispatch::general::c_encrypt(
            shim.session,
            plaintext.as_ptr() as CK_BYTE_PTR,
            plaintext.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut size_len,
        )
    };
    assert_eq!(size_rv, CKR_OK as CK_RV, "C_Encrypt(size query)");
    assert_eq!(size_len, plaintext.len() as CK_ULONG);
    assert_eq!(iv_buffer, [0; 12], "size query must not write or consume delayed IV");

    let mut ciphertext = [0_u8; 5];
    let mut ciphertext_len = ciphertext.len() as CK_ULONG;
    let encrypt_rv = unsafe {
        dispatch::general::c_encrypt(
            shim.session,
            plaintext.as_ptr() as CK_BYTE_PTR,
            plaintext.len() as CK_ULONG,
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
        )
    };

    daemon.backend.set_encrypt_exact_output(None);
    assert_eq!(encrypt_rv, CKR_OK as CK_RV, "C_Encrypt(data)");
    assert_eq!(iv_buffer.as_slice(), generated_iv.as_slice(), "delayed IV writeback");
}

#[test]
fn exact_encrypt_size_query_returns_length() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = aes_ecb_mechanism();

    let init_rv = unsafe { dispatch::general::c_encrypt_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_EncryptInit");

    // MockBackend encrypt_impl returns xor_bytes(data): same length as input.
    let data = b"hello";
    // NULL output pointer = size query
    let mut out_len: CK_ULONG = 0;
    let size_rv = unsafe {
        dispatch::general::c_encrypt(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut out_len,
        )
    };
    assert_eq!(size_rv, CKR_OK as CK_RV, "C_Encrypt(size query)");
    // MockBackend xor_bytes returns same-length output as input (5 bytes)
    assert_eq!(out_len, 5, "returned_len should be 5 for 5-byte input");
}

#[test]
fn exact_encrypt_update_exact_fit_copies_bytes() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = aes_ecb_mechanism();

    let init_rv = unsafe { dispatch::general::c_encrypt_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_EncryptInit");

    // MockBackend encrypt_update_impl: returns xor_bytes(part) = part ^ 0x42.
    let part: [u8; 3] = [0x01, 0x02, 0x03];
    let expected: [u8; 3] = [0x01 ^ 0x42, 0x02 ^ 0x42, 0x03 ^ 0x42];
    let mut out = [0_u8; 3];
    let mut out_len = out.len() as CK_ULONG;
    let update_rv = unsafe {
        dispatch::general::c_encrypt_update(
            shim.session,
            part.as_ptr() as CK_BYTE_PTR,
            part.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_eq!(update_rv, CKR_OK as CK_RV, "C_EncryptUpdate");
    assert_eq!(out_len, 3, "returned_len should be 3");
    assert_eq!(out, expected, "encrypted bytes should equal part ^ 0x42");
}

#[test]
fn exact_decrypt_size_query_returns_length() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = aes_ecb_mechanism();

    let init_rv = unsafe { dispatch::general::c_decrypt_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_DecryptInit");

    // MockBackend decrypt_impl returns xor_bytes(data): same length as input.
    let data = b"hello";
    // NULL output pointer = size query
    let mut out_len: CK_ULONG = 0;
    let size_rv = unsafe {
        dispatch::general::c_decrypt(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut out_len,
        )
    };
    assert_eq!(size_rv, CKR_OK as CK_RV, "C_Decrypt(size query)");
    // MockBackend xor_bytes returns same-length output as input (5 bytes)
    assert_eq!(out_len, 5, "returned_len should be 5 for 5-byte input");
}

#[test]
fn exact_decrypt_update_exact_fit_copies_bytes() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = aes_ecb_mechanism();

    let init_rv = unsafe { dispatch::general::c_decrypt_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_DecryptInit");

    // MockBackend decrypt_update_impl: returns xor_bytes(part) = part ^ 0x42.
    let part: [u8; 3] = [0x01, 0x02, 0x03];
    let expected: [u8; 3] = [0x01 ^ 0x42, 0x02 ^ 0x42, 0x03 ^ 0x42];
    let mut out = [0_u8; 3];
    let mut out_len = out.len() as CK_ULONG;
    let update_rv = unsafe {
        dispatch::general::c_decrypt_update(
            shim.session,
            part.as_ptr() as CK_BYTE_PTR,
            part.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_eq!(update_rv, CKR_OK as CK_RV, "C_DecryptUpdate");
    assert_eq!(out_len, 3, "returned_len should be 3");
    assert_eq!(out, expected, "decrypted bytes should equal part ^ 0x42");
}

#[test]
fn exact_wrap_key_size_query_returns_length() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let wrapping_key = create_object(shim.session);
    let mut mechanism = rsa_pkcs_mechanism();

    // NULL output pointer = size query
    let mut out_len: CK_ULONG = 0;
    let size_rv = unsafe {
        dispatch::general::c_wrap_key(
            shim.session,
            &mut mechanism,
            wrapping_key,
            key,
            std::ptr::null_mut(),
            &mut out_len,
        )
    };
    assert_eq!(size_rv, CKR_OK as CK_RV, "C_WrapKey(size query)");
    // MockBackend wrap_key returns MOCK_WRAP_OUTPUT = [0xDE, 0xAD, 0xBE, 0xEF] = 4 bytes
    assert_eq!(out_len, 4, "returned_len should be 4 for mock wrap output");
}

#[test]
fn exact_get_operation_state_size_query_returns_length() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = rsa_pkcs_mechanism();

    // Start a multi-part sign operation so there is operation state to retrieve
    let init_rv = unsafe { dispatch::general::c_sign_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_SignInit");

    // NULL output pointer = size query
    let mut out_len: CK_ULONG = 0;
    let size_rv = unsafe {
        dispatch::general::c_get_operation_state(shim.session, std::ptr::null_mut(), &mut out_len)
    };
    assert_eq!(size_rv, CKR_OK as CK_RV, "C_GetOperationState(size query)");
    // MockBackend operation_state returns 3 bytes (2-byte prefix + 1-byte op code)
    assert_eq!(out_len, 3, "returned_len should be 3 for mock operation state");
}

// =========================================================================
// Track C: ParameterOutputExact RPC tests
// =========================================================================

#[test]
fn exact_encrypt_message_size_query_returns_length() {
    // MockBackend now implements encrypt_message_exact (delegates to encrypt_impl).
    // encrypt_impl requires an active Encrypt operation, so first we call
    // encrypt_init, then verify the exact RPC returns a size-query result.
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::start();

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");

        // Set up an active encrypt operation so the mock can process the call.
        let mechanism = pkcs11_proxy_ng_types::CkMechanism {
            mechanism_type: CkMechanismType::AES_ECB,
            params: None,
        };
        let key = client.create_object(session, &[]).await.expect("C_CreateObject");
        client.encrypt_init(session, &mechanism, key).await.expect("C_EncryptInit");

        let output_spec = CkOutputBufferSpec { buffer_present: false, buffer_len: 0 };
        let param_out_spec = CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: 12,
            value: Some(vec![0xAA; 12]),
        };

        let result = client
            .parameter_output_exact(
                session,
                ParameterOutputFunction::EncryptMessage,
                &output_spec,
                b"plaintext",
                b"aad",
                &[0xAA; 12],
                &param_out_spec,
                0,
                None,
                0,
                0,
                None,
            )
            .await;

        // MockBackend now returns OK with data — size query should yield length.
        match result {
            Ok((output_result, _param_result, _)) => {
                assert_eq!(
                    output_result.ck_rv,
                    CkRv::OK,
                    "encrypt_message_exact size query should return OK from mock backend"
                );
                // Size query: value is None, returned_len > 0.
                assert!(output_result.value.is_none(), "size query should not return data");
                assert!(
                    output_result.returned_len > 0,
                    "size query should return a positive length"
                );
            }
            Err(rv) => {
                panic!("encrypt_message_exact unexpectedly failed with {rv:?}");
            }
        }

        client.close_session(session).await.expect("C_CloseSession");
        client.finalize().await.expect("C_Finalize");
    });
}

#[test]
fn exact_wrap_key_authenticated_size_query_returns_length() {
    // MockBackend now implements wrap_key_authenticated_exact (delegates to wrap_key_impl).
    // Size query should return OK with the wrapped-key length.
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::start();

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");

        let wrapping_key = client.create_object(session, &[]).await.expect("C_CreateObject");
        let key = client.create_object(session, &[]).await.expect("C_CreateObject");

        let output_spec = CkOutputBufferSpec { buffer_present: false, buffer_len: 0 };
        let param_out_spec = CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: 16,
            value: Some(vec![0xBB; 16]),
        };

        let mechanism = pkcs11_proxy_ng_types::CkMechanism {
            mechanism_type: CkMechanismType::AES_ECB,
            params: None,
        };

        let result = client
            .parameter_output_exact(
                session,
                ParameterOutputFunction::WrapKeyAuthenticated,
                &output_spec,
                &[],
                b"aad_data",
                &[0xBB; 16],
                &param_out_spec,
                0,
                Some(&mechanism),
                wrapping_key.0,
                key.0,
                None,
            )
            .await;

        // MockBackend now returns OK with wrapped key bytes.
        match result {
            Ok((output_result, _param_result, _)) => {
                assert_eq!(
                    output_result.ck_rv,
                    CkRv::OK,
                    "wrap_key_authenticated_exact size query should return OK from mock"
                );
                // Size query: value is None, returned_len > 0.
                assert!(output_result.value.is_none(), "size query should not return data");
                assert!(
                    output_result.returned_len > 0,
                    "size query should return a positive length"
                );
            }
            Err(rv) => {
                panic!("wrap_key_authenticated_exact unexpectedly failed with {rv:?}");
            }
        }

        client.close_session(session).await.expect("C_CloseSession");
        client.finalize().await.expect("C_Finalize");
    });
}

// =========================================================================
// Track C Task 2: EncapsulateKeyExact RPC tests
// =========================================================================

#[test]
fn exact_encapsulate_key_size_query_returns_length() {
    // Size query: NULL pCiphertext.  MockBackend now implements encapsulate_key
    // returning 8-byte synthetic ciphertext.  The exact path should report the
    // required length without creating a key (phKey unchanged).
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    // Create an object to serve as the public key handle so that
    // resolve_session_and_key succeeds (otherwise KEY_HANDLE_INVALID).
    let public_key = create_object(shim.session);
    let mut mechanism = generic_mechanism();

    let mut out_len: CK_ULONG = 0;
    let mut key_handle: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_encapsulate_key(
            shim.session,
            &mut mechanism,
            public_key,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(), // NULL ciphertext = size query
            &mut out_len,
            &mut key_handle,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_EncapsulateKey(size query) should return CKR_OK");
    assert_eq!(out_len, 8, "expected ciphertext length of 8 from mock");
    // Size query must NOT create a key — phKey should remain unchanged.
    assert_eq!(key_handle, CK_INVALID_HANDLE, "phKey must remain unchanged on size query");
}

#[test]
fn exact_encapsulate_key_data_query_returns_ciphertext_and_handle() {
    // Data query: buffer of correct size (8 bytes).  Should fill the buffer
    // with mock ciphertext and set phKey to a non-zero handle.
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let public_key = create_object(shim.session);
    let mut mechanism = generic_mechanism();

    let mut buf = [0u8; 8];
    let mut out_len: CK_ULONG = buf.len() as CK_ULONG;
    let mut key_handle: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_encapsulate_key(
            shim.session,
            &mut mechanism,
            public_key,
            std::ptr::null_mut(),
            0,
            buf.as_mut_ptr(),
            &mut out_len,
            &mut key_handle,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_EncapsulateKey(data query) should return CKR_OK");
    assert_eq!(out_len, 8, "returned ciphertext length");
    assert_eq!(
        buf,
        [0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF],
        "ciphertext should match mock output"
    );
    assert_ne!(key_handle, CK_INVALID_HANDLE, "phKey must be set to a non-zero handle");
}

#[test]
fn exact_encapsulate_key_too_small_buffer() {
    // Buffer too small: 4 bytes provided but mock needs 8.  Should return
    // CKR_BUFFER_TOO_SMALL, report the required size, and NOT create a key.
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let public_key = create_object(shim.session);
    let mut mechanism = generic_mechanism();

    let mut buf = [0u8; 4];
    let mut out_len: CK_ULONG = buf.len() as CK_ULONG;
    let mut key_handle: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_encapsulate_key(
            shim.session,
            &mut mechanism,
            public_key,
            std::ptr::null_mut(),
            0,
            buf.as_mut_ptr(),
            &mut out_len,
            &mut key_handle,
        )
    };
    assert_eq!(
        rv, CKR_BUFFER_TOO_SMALL as CK_RV,
        "C_EncapsulateKey(too small) should return CKR_BUFFER_TOO_SMALL"
    );
    assert_eq!(out_len, 8, "required ciphertext length should be reported");
    // Buffer-too-small must NOT create a key — phKey should remain unchanged.
    assert_eq!(key_handle, CK_INVALID_HANDLE, "phKey must remain unchanged on buffer-too-small");
}

// =========================================================================
// Track C Task 3: Nested CKF_ARRAY_ATTRIBUTE tests
// =========================================================================

/// The raw CKA_WRAP_TEMPLATE constant (CKF_ARRAY_ATTRIBUTE | 0x211).
const CKA_WRAP_TEMPLATE_RAW: CK_ATTRIBUTE_TYPE = 0x4000_0211;

#[test]
fn nested_template_attribute_size_query() {
    // Size query: pValue=NULL for an attribute with CKF_ARRAY_ATTRIBUTE.
    // Expected: returned_len = nested_count * size_of::<CK_ATTRIBUTE>()
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    let shim = ShimSession::new();
    let object = create_object(shim.session);
    let backend_object = backend_object_handle(daemon, object);

    // Register a nested template with 2 sub-attributes
    daemon.backend.set_attribute(
        backend_object,
        CkAttributeType::WRAP_TEMPLATE,
        MockAttributeSlot::NestedTemplate(vec![
            (
                CkAttributeType::CLASS,
                MockAttributeSlot::Value(CkAttributeValue::Ulong(3)), // CKO_SECRET_KEY
            ),
            (
                CkAttributeType::KEY_TYPE,
                MockAttributeSlot::Value(CkAttributeValue::Ulong(31)), // CKK_AES
            ),
        ]),
    );

    // Size query: pValue=NULL
    let mut attr =
        CK_ATTRIBUTE { type_: CKA_WRAP_TEMPLATE_RAW, pValue: std::ptr::null_mut(), ulValueLen: 0 };

    let rv =
        unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
    assert_eq!(rv, CKR_OK as CK_RV, "size query should succeed");

    let expected_len = 2 * std::mem::size_of::<CK_ATTRIBUTE>();
    assert_eq!(
        attr.ulValueLen as usize, expected_len,
        "returned_len should be 2 * size_of::<CK_ATTRIBUTE>()"
    );
}

#[test]
fn nested_template_attribute_data_query() {
    // Data query: pValue points to a CK_ATTRIBUTE[2] with sub-buffers.
    // After the call, sub-attribute types/values should match the mock.
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    let shim = ShimSession::new();
    let object = create_object(shim.session);
    let backend_object = backend_object_handle(daemon, object);

    let class_value: u64 = 3; // CKO_SECRET_KEY
    let key_type_value: u64 = 31; // CKK_AES

    daemon.backend.set_attribute(
        backend_object,
        CkAttributeType::WRAP_TEMPLATE,
        MockAttributeSlot::NestedTemplate(vec![
            (
                CkAttributeType::CLASS,
                MockAttributeSlot::Value(CkAttributeValue::Ulong(class_value)),
            ),
            (
                CkAttributeType::KEY_TYPE,
                MockAttributeSlot::Value(CkAttributeValue::Ulong(key_type_value)),
            ),
        ]),
    );

    // Allocate sub-attribute buffers (CK_ULONG = 8 bytes on 64-bit)
    let ulong_size = std::mem::size_of::<CK_ULONG>();
    let mut class_buf = vec![0u8; ulong_size];
    let mut key_type_buf = vec![0u8; ulong_size];

    let mut sub_attrs = [
        CK_ATTRIBUTE {
            type_: 0, // ignored on input per spec
            pValue: class_buf.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: ulong_size as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: 0,
            pValue: key_type_buf.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: ulong_size as CK_ULONG,
        },
    ];

    let mut attr = CK_ATTRIBUTE {
        type_: CKA_WRAP_TEMPLATE_RAW,
        pValue: sub_attrs.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: (sub_attrs.len() * std::mem::size_of::<CK_ATTRIBUTE>()) as CK_ULONG,
    };

    let rv =
        unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
    assert_eq!(rv, CKR_OK as CK_RV, "data query should succeed");

    // Verify sub-attribute types were set on output
    assert_eq!(
        sub_attrs[0].type_,
        CkAttributeType::CLASS.0 as CK_ATTRIBUTE_TYPE,
        "sub-attr[0] type should be CKA_CLASS"
    );
    assert_eq!(
        sub_attrs[1].type_,
        CkAttributeType::KEY_TYPE.0 as CK_ATTRIBUTE_TYPE,
        "sub-attr[1] type should be CKA_KEY_TYPE"
    );

    // Verify sub-attribute values
    let returned_class = CK_ULONG::from_le_bytes(class_buf[..ulong_size].try_into().unwrap());
    let returned_key_type = CK_ULONG::from_le_bytes(key_type_buf[..ulong_size].try_into().unwrap());
    assert_eq!(returned_class, class_value as CK_ULONG, "CLASS value");
    assert_eq!(returned_key_type, key_type_value as CK_ULONG, "KEY_TYPE value");
}

#[test]
fn nested_template_attribute_sub_size_query() {
    // Data query where sub-attributes have pValue=NULL (sub size query).
    // The outer template has 2 entries, but sub pValue is null.
    // Expected: sub ulValueLen is set to the data size, no data copied.
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    let shim = ShimSession::new();
    let object = create_object(shim.session);
    let backend_object = backend_object_handle(daemon, object);

    daemon.backend.set_attribute(
        backend_object,
        CkAttributeType::WRAP_TEMPLATE,
        MockAttributeSlot::NestedTemplate(vec![
            (CkAttributeType::CLASS, MockAttributeSlot::Value(CkAttributeValue::Ulong(3))),
            (
                CkAttributeType::LABEL,
                MockAttributeSlot::Value(CkAttributeValue::String("mykey".into())),
            ),
        ]),
    );

    // Sub-attributes with pValue=NULL (size query for each sub-attr)
    let mut sub_attrs = [
        CK_ATTRIBUTE { type_: 0, pValue: std::ptr::null_mut(), ulValueLen: 0 },
        CK_ATTRIBUTE { type_: 0, pValue: std::ptr::null_mut(), ulValueLen: 0 },
    ];

    let mut attr = CK_ATTRIBUTE {
        type_: CKA_WRAP_TEMPLATE_RAW,
        pValue: sub_attrs.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: (sub_attrs.len() * std::mem::size_of::<CK_ATTRIBUTE>()) as CK_ULONG,
    };

    let rv =
        unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
    assert_eq!(rv, CKR_OK as CK_RV, "sub size query should succeed");

    // Verify types were set
    assert_eq!(sub_attrs[0].type_, CkAttributeType::CLASS.0 as CK_ATTRIBUTE_TYPE);
    assert_eq!(sub_attrs[1].type_, CkAttributeType::LABEL.0 as CK_ATTRIBUTE_TYPE);

    // Verify returned lengths
    let ulong_size = std::mem::size_of::<CK_ULONG>();
    assert_eq!(sub_attrs[0].ulValueLen as usize, ulong_size, "CLASS size");
    assert_eq!(sub_attrs[1].ulValueLen as usize, 5, "LABEL size = len('mykey')");
}

#[test]
fn nested_template_attribute_sub_buffer_too_small_preserves_partial_outputs() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    let shim = ShimSession::new();
    let object = create_object(shim.session);
    let backend_object = backend_object_handle(daemon, object);

    let class_value: u64 = 3;
    daemon.backend.set_attribute(
        backend_object,
        CkAttributeType::WRAP_TEMPLATE,
        MockAttributeSlot::NestedTemplate(vec![
            (
                CkAttributeType::CLASS,
                MockAttributeSlot::Value(CkAttributeValue::Ulong(class_value)),
            ),
            (
                CkAttributeType::LABEL,
                MockAttributeSlot::Value(CkAttributeValue::String("mykey".into())),
            ),
        ]),
    );

    let ulong_size = std::mem::size_of::<CK_ULONG>();
    let mut class_buf = vec![0xAA_u8; ulong_size];
    let mut short_label_buf = [0xBB_u8; 2];
    let mut sub_attrs = [
        CK_ATTRIBUTE {
            type_: 0,
            pValue: class_buf.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: ulong_size as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: 0,
            pValue: short_label_buf.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: short_label_buf.len() as CK_ULONG,
        },
    ];

    let mut attr = CK_ATTRIBUTE {
        type_: CKA_WRAP_TEMPLATE_RAW,
        pValue: sub_attrs.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: (sub_attrs.len() * std::mem::size_of::<CK_ATTRIBUTE>()) as CK_ULONG,
    };

    let rv =
        unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };

    assert_eq!(rv, CKR_BUFFER_TOO_SMALL as CK_RV);
    assert_eq!(
        attr.ulValueLen as usize,
        sub_attrs.len() * std::mem::size_of::<CK_ATTRIBUTE>(),
        "outer array length should still reflect the backend template size",
    );
    assert_eq!(sub_attrs[0].type_, CkAttributeType::CLASS.0 as CK_ATTRIBUTE_TYPE);
    assert_eq!(sub_attrs[0].ulValueLen as usize, ulong_size);
    assert_eq!(
        CK_ULONG::from_le_bytes(class_buf[..ulong_size].try_into().unwrap()),
        class_value as CK_ULONG
    );
    assert_eq!(sub_attrs[1].type_, CkAttributeType::LABEL.0 as CK_ATTRIBUTE_TYPE);
    assert_eq!(sub_attrs[1].ulValueLen, CK_UNAVAILABLE_INFORMATION);
    assert_eq!(short_label_buf, [0xBB; 2], "too-small nested buffer must not be copied");
}

#[test]
fn raw_client_nested_template_size_query() {
    // Test the raw client path for nested template size query
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::start();

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");
        let object = client.create_object(session, &[]).await.expect("C_CreateObject");

        daemon.backend.set_attribute(
            object,
            CkAttributeType::WRAP_TEMPLATE,
            MockAttributeSlot::NestedTemplate(vec![
                (CkAttributeType::CLASS, MockAttributeSlot::Value(CkAttributeValue::Ulong(3))),
                (CkAttributeType::KEY_TYPE, MockAttributeSlot::Value(CkAttributeValue::Ulong(31))),
            ]),
        );

        // Size query: buffer_present=false, no nested sub-queries
        let (rv, results) = client
            .get_attribute_value_exact(
                session,
                object,
                &[CkAttributeQuery {
                    attr_type: CkAttributeType::WRAP_TEMPLATE,
                    buffer_present: false,
                    buffer_len: 0,
                    nested: None,
                }],
            )
            .await
            .expect("GetAttributeValueExact RPC");

        assert_eq!(rv, CkRv::OK);
        assert_eq!(results.len(), 1);
        let expected_len = (2 * std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>()) as u64;
        assert_eq!(results[0].returned_len, expected_len);
        assert!(results[0].value.is_none());
        assert!(results[0].nested.is_none());

        client.close_session(session).await.expect("C_CloseSession");
        client.finalize().await.expect("C_Finalize");
    });
}

#[test]
fn raw_client_nested_template_data_query() {
    // Test the raw client path for nested template data query with sub-buffers
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::start();

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");
        let object = client.create_object(session, &[]).await.expect("C_CreateObject");

        let class_value: u64 = 3;
        let key_type_value: u64 = 31;

        daemon.backend.set_attribute(
            object,
            CkAttributeType::WRAP_TEMPLATE,
            MockAttributeSlot::NestedTemplate(vec![
                (
                    CkAttributeType::CLASS,
                    MockAttributeSlot::Value(CkAttributeValue::Ulong(class_value)),
                ),
                (
                    CkAttributeType::KEY_TYPE,
                    MockAttributeSlot::Value(CkAttributeValue::Ulong(key_type_value)),
                ),
            ]),
        );

        let ulong_size = std::mem::size_of::<cryptoki_sys::CK_ULONG>() as u64;
        let ck_attr_size = std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>() as u64;

        // Data query with nested sub-queries (sub-buffers present)
        let (rv, results) = client
            .get_attribute_value_exact(
                session,
                object,
                &[CkAttributeQuery {
                    attr_type: CkAttributeType::WRAP_TEMPLATE,
                    buffer_present: true,
                    buffer_len: 2 * ck_attr_size,
                    nested: Some(vec![
                        CkAttributeQuery {
                            attr_type: CkAttributeType::CLASS,
                            buffer_present: true,
                            buffer_len: ulong_size,
                            nested: None,
                        },
                        CkAttributeQuery {
                            attr_type: CkAttributeType::KEY_TYPE,
                            buffer_present: true,
                            buffer_len: ulong_size,
                            nested: None,
                        },
                    ]),
                }],
            )
            .await
            .expect("GetAttributeValueExact RPC");

        assert_eq!(rv, CkRv::OK);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].returned_len, 2 * ck_attr_size);

        let nested = results[0].nested.as_ref().expect("should have nested results");
        assert_eq!(nested.len(), 2);

        assert_eq!(nested[0].attr_type, CkAttributeType::CLASS);
        assert_eq!(nested[0].returned_len, ulong_size);
        let class_bytes = nested[0].value.as_ref().expect("CLASS value");
        assert_eq!(class_bytes, &class_value.to_le_bytes()[..ulong_size as usize]);

        assert_eq!(nested[1].attr_type, CkAttributeType::KEY_TYPE);
        assert_eq!(nested[1].returned_len, ulong_size);
        let key_type_bytes = nested[1].value.as_ref().expect("KEY_TYPE value");
        assert_eq!(key_type_bytes, &key_type_value.to_le_bytes()[..ulong_size as usize]);

        client.close_session(session).await.expect("C_CloseSession");
        client.finalize().await.expect("C_Finalize");
    });
}

// ---------------------------------------------------------------------------
// Track D Task 1 — lower-risk output/count API audits
// ---------------------------------------------------------------------------

#[test]
fn slot_list_count_only_returns_correct_count() {
    let _guard = shim_state_test_guard();
    let _daemon = TestDaemon::shared();
    let shim = ShimSession::new();

    // Count-only call: pSlotList == NULL
    let mut count: CK_ULONG = 0;
    let rv =
        unsafe { dispatch::general::c_get_slot_list(CK_FALSE, std::ptr::null_mut(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetSlotList(count-only)");
    // MockBackend is initialised with two slots (CkSlotId(0), CkSlotId(1)).
    assert_eq!(count, 2, "expected 2 slots from MockBackend");

    // Second count-only call with a pre-filled count value — the input value
    // "has no meaning" per spec and should be overwritten.
    let mut count2: CK_ULONG = 999;
    let rv2 =
        unsafe { dispatch::general::c_get_slot_list(CK_FALSE, std::ptr::null_mut(), &mut count2) };
    assert_eq!(rv2, CKR_OK as CK_RV, "C_GetSlotList(count-only #2)");
    assert_eq!(count2, 2, "count should be overwritten regardless of input");

    // Verify that passing a sufficiently large buffer returns the actual slot
    let mut slots = vec![CK_INVALID_HANDLE; count as usize];
    let mut fetch_count = count;
    let rv3 = unsafe {
        dispatch::general::c_get_slot_list(CK_FALSE, slots.as_mut_ptr(), &mut fetch_count)
    };
    assert_eq!(rv3, CKR_OK as CK_RV, "C_GetSlotList(fill)");
    assert_eq!(fetch_count, count, "fill count should match count-only count");
    assert_ne!(slots[0], CK_INVALID_HANDLE, "slot ID should be populated");

    drop(shim);
}

#[test]
fn slot_list_too_small_buffer_returns_buffer_too_small() {
    let _guard = shim_state_test_guard();
    let _daemon = TestDaemon::shared();
    let shim = ShimSession::new();

    // First, get the actual count.
    let mut count: CK_ULONG = 0;
    let rv =
        unsafe { dispatch::general::c_get_slot_list(CK_FALSE, std::ptr::null_mut(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(count >= 1, "need at least 1 slot for this test");

    // Now call with a buffer that is too small (size 0).
    let mut slots = vec![0_u64; 0];
    let mut too_small_count: CK_ULONG = 0;
    let rv2 = unsafe {
        dispatch::general::c_get_slot_list(CK_FALSE, slots.as_mut_ptr(), &mut too_small_count)
    };
    assert_eq!(rv2, CKR_BUFFER_TOO_SMALL as CK_RV, "expected CKR_BUFFER_TOO_SMALL");
    // Spec: *pulCount is set to hold the number of slots in either case.
    assert_eq!(too_small_count, count, "*pulCount must be set to actual count on BUFFER_TOO_SMALL");

    drop(shim);
}

#[test]
fn mechanism_list_count_reflects_filtered_count() {
    let _guard = shim_state_test_guard();
    let _daemon = TestDaemon::shared();
    let shim = ShimSession::new();

    // Count-only call for mechanisms on slot 0.
    let mut count: CK_ULONG = 0;
    let rv = unsafe {
        dispatch::general::c_get_mechanism_list(shim.slot_id, std::ptr::null_mut(), &mut count)
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetMechanismList(count-only)");
    // MockBackend has 3 mechanisms: SHA256, RSA_PKCS, AES_ECB.
    // Default registry is Transparent mode, so all 3 pass through.
    assert_eq!(count, 3, "expected 3 mechanisms from MockBackend (transparent mode)");

    // Fetch into a correctly sized buffer.
    let mut mechs = vec![0_u64; count as usize];
    let mut fill_count = count;
    let rv2 = unsafe {
        dispatch::general::c_get_mechanism_list(shim.slot_id, mechs.as_mut_ptr(), &mut fill_count)
    };
    assert_eq!(rv2, CKR_OK as CK_RV, "C_GetMechanismList(fill)");
    assert_eq!(fill_count, count, "fill count should match count-only count");

    // Buffer-too-small: pass a buffer smaller than the actual count.
    let mut small_mechs = vec![0_u64; 0];
    let mut small_count: CK_ULONG = 0;
    let rv3 = unsafe {
        dispatch::general::c_get_mechanism_list(
            shim.slot_id,
            small_mechs.as_mut_ptr(),
            &mut small_count,
        )
    };
    assert_eq!(rv3, CKR_BUFFER_TOO_SMALL as CK_RV, "expected CKR_BUFFER_TOO_SMALL");
    assert_eq!(
        small_count, count,
        "*pulCount must be set to actual (post-filter) count on BUFFER_TOO_SMALL"
    );

    drop(shim);
}

#[test]
fn find_objects_honors_max_count() {
    let _guard = shim_state_test_guard();
    let _daemon = TestDaemon::shared();
    let shim = ShimSession::new();

    // C_FindObjectsInit with an empty template (find all objects).
    let init_rv =
        unsafe { dispatch::general::c_find_objects_init(shim.session, std::ptr::null_mut(), 0) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_FindObjectsInit");

    // Call C_FindObjects with max_count=5 — MockBackend returns 0 objects.
    let mut objects = [CK_INVALID_HANDLE; 5];
    let mut found_count: CK_ULONG = 99; // deliberately non-zero
    let find_rv = unsafe {
        dispatch::general::c_find_objects(shim.session, objects.as_mut_ptr(), 5, &mut found_count)
    };
    assert_eq!(find_rv, CKR_OK as CK_RV, "C_FindObjects");
    // MockBackend returns empty vec — count should be 0, clamped by min(0, 5) = 0.
    assert_eq!(found_count, 0, "expected 0 objects from MockBackend");

    // Call with max_count=0 — should also succeed and return 0.
    let mut zero_objects = [CK_INVALID_HANDLE; 1];
    let mut zero_count: CK_ULONG = 99;
    let zero_rv = unsafe {
        dispatch::general::c_find_objects(
            shim.session,
            zero_objects.as_mut_ptr(),
            0,
            &mut zero_count,
        )
    };
    assert_eq!(zero_rv, CKR_OK as CK_RV, "C_FindObjects(max=0)");
    assert_eq!(zero_count, 0, "max_count=0 should return 0 objects");

    let final_rv = unsafe { dispatch::general::c_find_objects_final(shim.session) };
    assert_eq!(final_rv, CKR_OK as CK_RV, "C_FindObjectsFinal");

    drop(shim);
}

#[test]
fn generate_random_returns_exact_requested_length() {
    let _guard = shim_state_test_guard();
    let _daemon = TestDaemon::shared();
    let shim = ShimSession::new();

    // Request 16 bytes of random data.
    let mut buf = [0_u8; 16];
    let rv = unsafe {
        dispatch::general::c_generate_random(shim.session, buf.as_mut_ptr(), buf.len() as CK_ULONG)
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GenerateRandom(16)");
    // MockBackend fills with 0x42.
    assert_eq!(buf, [0x42_u8; 16], "random data should be 0x42 (mock pattern)");

    // Request 1 byte.
    let mut one = [0_u8; 1];
    let rv2 = unsafe { dispatch::general::c_generate_random(shim.session, one.as_mut_ptr(), 1) };
    assert_eq!(rv2, CKR_OK as CK_RV, "C_GenerateRandom(1)");
    assert_eq!(one[0], 0x42, "single random byte should be 0x42");

    // Request 0 bytes — valid per spec (no-op).
    let mut empty = [0_u8; 0];
    let rv3 = unsafe { dispatch::general::c_generate_random(shim.session, empty.as_mut_ptr(), 0) };
    assert_eq!(rv3, CKR_OK as CK_RV, "C_GenerateRandom(0)");

    drop(shim);
}

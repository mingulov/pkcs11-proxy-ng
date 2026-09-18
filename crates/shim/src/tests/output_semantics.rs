use std::sync::{Arc, OnceLock};
use std::time::Duration;

use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng::server::handle_map::VirtualHandle;
use pkcs11_proxy_ng_backend::{
    MockBackend, Pkcs11Backend,
    mock::{MockAbi, MockAttributeSlot, MockMessageLifecycleAction},
};
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
use pkcs11_proxy_ng_proto::convert::message_params::MessageParameterShape;
use pkcs11_proxy_ng_types::{
    CkAttributeQuery, CkAttributeQueryResult, CkAttributeType, CkAttributeValue, CkInBuf,
    CkMechanismParams, CkMechanismType, CkObjectHandle, CkOutputBufferResult, CkOutputBufferSpec,
    CkParameterRoundtripResult, CkParameterRoundtripSpec, CkRv, CkSessionFlags, CkSlotId,
    GcmParams, InterfaceCapabilities, InterfaceInfo, ParameterOutputFunction,
};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::watch;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use super::*;

static TEST_DAEMON: OnceLock<TestDaemon> = OnceLock::new();
static TEST_DAEMON_ILP32: OnceLock<TestDaemon> = OnceLock::new();
static TEST_DAEMON_LLP64: OnceLock<TestDaemon> = OnceLock::new();
static TEST_DAEMON_BIG_ENDIAN: OnceLock<TestDaemon> = OnceLock::new();

pub(super) struct TestDaemon {
    runtime: Runtime,
    pub(super) endpoint: String,
    pub(super) backend: Arc<MockBackend>,
    context_manager: Arc<ContextManager>,
    _shutdown: watch::Sender<bool>,
}

impl TestDaemon {
    pub(super) fn shared() -> &'static Self {
        TEST_DAEMON.get_or_init(|| Self::start(MockAbi::host()))
    }

    /// A daemon whose MockBackend emulates the given ABI profile
    /// (ADR-0011): one in-process singleton per profile.
    pub(super) fn shared_with_abi(abi: MockAbi) -> &'static Self {
        match abi {
            MockAbi::Ilp32 => TEST_DAEMON_ILP32.get_or_init(|| Self::start(abi)),
            MockAbi::Llp64 => TEST_DAEMON_LLP64.get_or_init(|| Self::start(abi)),
            _ => Self::shared(),
        }
    }

    /// A daemon whose backend ADVERTISES big-endian (D6 poison config).
    pub(super) fn shared_big_endian() -> &'static Self {
        TEST_DAEMON_BIG_ENDIAN.get_or_init(|| Self::start_configured(MockAbi::host(), true))
    }

    fn start(abi: MockAbi) -> Self {
        Self::start_configured(abi, false)
    }

    fn start_configured(abi: MockAbi, big_endian: bool) -> Self {
        let runtime = Runtime::new().expect("test runtime");
        let (endpoint, backend, context_manager, shutdown) = runtime.block_on(async {
            let mut mock = MockBackend::new(
                vec![CkSlotId(0), CkSlotId(1)],
                vec![
                    CkMechanismType::SHA256,
                    CkMechanismType::RSA_PKCS,
                    CkMechanismType::AES_ECB,
                    CkMechanismType::AES_GCM,
                    CkMechanismType::AES_KEY_GEN,
                ],
            )
            .with_abi(abi);
            if big_endian {
                mock = mock.with_big_endian_advertisement();
            }
            let backend = Arc::new(mock);
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

pub(super) struct ShimSession {
    pub(super) session: CK_SESSION_HANDLE,
    pub(super) slot_id: CK_SLOT_ID,
}

impl ShimSession {
    fn new() -> Self {
        let daemon = TestDaemon::shared();
        Self::with_endpoint(&daemon.endpoint)
    }

    pub(super) fn with_endpoint(endpoint: &str) -> Self {
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

/// SHA-256 digest length — the mechanism these digest tests initialize
/// with (`sha256_mechanism`). The mock now sizes digest output by
/// mechanism (mock::output_lengths), so the expectation follows suit.
const SHA256_DIGEST_LEN: usize = 32;

fn expected_mock_digest(data: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    pkcs11_proxy_ng_backend::mock::echo::echo_bytes("digest", &[data], SHA256_DIGEST_LEN)
        .try_into()
        .expect("SHA-256 length")
}

fn expected_mock_sign(data: &[u8]) -> [u8; 2] {
    pkcs11_proxy_ng_backend::mock::echo::echo_bytes("sign", &[data], 2).try_into().expect("2 bytes")
}

fn expected_mock_sign_final() -> [u8; 2] {
    pkcs11_proxy_ng_backend::mock::echo::echo_bytes("sign-final", &[], 2)
        .try_into()
        .expect("2 bytes")
}

fn expected_mock_digest_final() -> [u8; SHA256_DIGEST_LEN] {
    pkcs11_proxy_ng_backend::mock::echo::echo_bytes("digest-final", &[], SHA256_DIGEST_LEN)
        .try_into()
        .expect("SHA-256 length")
}

pub(super) fn create_object(session: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let mut object = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_create_object(session, std::ptr::null_mut(), 0, &mut object)
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CreateObject");
    object
}

pub(super) fn backend_object_handle(
    daemon: &TestDaemon,
    object: CK_OBJECT_HANDLE,
) -> CkObjectHandle {
    daemon.block_on(async {
        let context_ids = daemon.context_manager.context_ids();
        assert_eq!(context_ids.len(), 1, "expected one active shim context");
        let backend_handle = daemon
            .context_manager
            .get_context(&context_ids[0], |ctx| {
                ctx.object_handles.resolve(VirtualHandle(object as _))
            })
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
    let spec =
        unsafe { dispatch::general::output_buffer_spec(backing.as_mut_ptr(), &mut declared_len) };
    let result = CkOutputBufferResult {
        ck_rv: CkRv::OK,
        returned_len: Some(4),
        value: Some(vec![1, 2, 3, 4].into()),
    };

    let rv = unsafe {
        dispatch::general::write_exact_output(
            &spec,
            &result,
            backing.as_mut_ptr(),
            &mut declared_len,
        )
    };

    assert_eq!(rv, CKR_GENERAL_ERROR as CK_RV);
    assert_eq!(declared_len, 2);
    assert_eq!(backing, [0xAA; 4]);
}

#[test]
fn write_exact_output_validates_all_effects_before_any_store() {
    let mut backing = [0xa5; 8];
    let mut length = 8;
    let spec = unsafe { dispatch::general::output_buffer_spec(backing.as_mut_ptr(), &mut length) };
    let result = CkOutputBufferResult {
        ck_rv: CkRv::OK,
        returned_len: Some(7),
        value: Some(vec![1; 4].into()),
    };
    let rv = unsafe {
        dispatch::general::write_exact_output(&spec, &result, backing.as_mut_ptr(), &mut length)
    };
    assert_eq!(rv, CKR_GENERAL_ERROR as CK_RV);
    assert_eq!(length, 8, "validation must precede all caller stores");
    assert_eq!(backing, [0xa5; 8]);
}

#[test]
fn write_exact_output_size_query_never_reads_incoming_length() {
    let mut length = std::mem::MaybeUninit::<CK_ULONG>::uninit();
    let spec =
        unsafe { dispatch::general::output_buffer_spec(std::ptr::null_mut(), length.as_mut_ptr()) };
    let result = CkOutputBufferResult { ck_rv: CkRv::OK, returned_len: Some(7), value: None };
    let rv = unsafe {
        dispatch::general::write_exact_output(
            &spec,
            &result,
            std::ptr::null_mut(),
            length.as_mut_ptr(),
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert_eq!(unsafe { length.assume_init() }, 7);
}

#[test]
fn write_exact_output_does_not_copy_value_on_buffer_too_small() {
    let mut backing = [0xAA_u8; 4];
    let mut declared_len: CK_ULONG = 2;
    let spec =
        unsafe { dispatch::general::output_buffer_spec(backing.as_mut_ptr(), &mut declared_len) };
    let result = CkOutputBufferResult {
        ck_rv: CkRv::BUFFER_TOO_SMALL,
        returned_len: Some(4),
        value: Some(vec![1, 2, 3, 4].into()),
    };

    let rv = unsafe {
        dispatch::general::write_exact_output(
            &spec,
            &result,
            backing.as_mut_ptr(),
            &mut declared_len,
        )
    };

    assert_eq!(rv, CKR_GENERAL_ERROR as CK_RV);
    assert_eq!(declared_len, 2);
    assert_eq!(backing, [0xAA; 4]);
}

#[test]
fn output_buffer_spec_classifies_all_three_pointer_shapes_without_reading_size_query_cell() {
    let mut length_sentinel: CK_ULONG = 0xA5A5;
    let size_query = unsafe {
        dispatch::general::output_buffer_spec(std::ptr::null_mut(), &mut length_sentinel)
    };
    assert_eq!(
        size_query,
        CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false }
    );

    let mut output = 0_u8;
    let missing_length =
        unsafe { dispatch::general::output_buffer_spec(&mut output, std::ptr::null_mut()) };
    assert_eq!(
        missing_length,
        CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true }
    );

    let mut capacity: CK_ULONG = 7;
    let data = unsafe { dispatch::general::output_buffer_spec(&mut output, &mut capacity) };
    assert_eq!(
        data,
        CkOutputBufferSpec { buffer_present: true, buffer_len: 7, length_pointer_null: false }
    );
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
    // E0793: CK_ATTRIBUTE is packed on Windows; assert on by-value copies.
    let ul_value_len = attr.ulValueLen;
    assert_eq!(ul_value_len, 3);
}

#[test]
fn shim_get_attribute_value_null_zero_reaches_empty_query_backend() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    let shim = ShimSession::new();
    let object = create_object(shim.session);
    daemon.backend.set_attribute(
        backend_object_handle(daemon, object),
        CkAttributeType::LABEL,
        MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
    );
    let calls_before = daemon.backend.attr_get_exact_call_count();

    let rv = unsafe {
        dispatch::general::c_get_attribute_value(shim.session, object, std::ptr::null_mut(), 0)
    };

    assert_eq!(rv, CKR_OK as CK_RV);
    assert_eq!(daemon.backend.attr_get_exact_call_count(), calls_before + 1);
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
    let ul_value_len = attr.ulValueLen;
    assert_eq!(ul_value_len, 3);
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
    let ul_value_len = attr.ulValueLen;
    assert_eq!(ul_value_len, CK_UNAVAILABLE_INFORMATION);
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
    let (len0, len1, len2) =
        (template[0].ulValueLen, template[1].ulValueLen, template[2].ulValueLen);
    assert_eq!(len0, 3);
    assert_eq!(len1, CK_UNAVAILABLE_INFORMATION);
    assert_eq!(len2, CK_UNAVAILABLE_INFORMATION);
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
    let daemon = TestDaemon::start(MockAbi::host());

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
        let object = client.create_object(session, Some(&[])).await.expect("C_CreateObject");

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
                apply_returned_len: true,
                apply_type: false,
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
    let daemon = TestDaemon::start(MockAbi::host());

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");
        let object = client.create_object(session, Some(&[])).await.expect("C_CreateObject");

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
                apply_returned_len: true,
                apply_type: false,
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
    let daemon = TestDaemon::start(MockAbi::host());

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");
        let object = client.create_object(session, Some(&[])).await.expect("C_CreateObject");

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
                apply_returned_len: true,
                apply_type: false,
                attr_type: CkAttributeType::LABEL,
                returned_len: 3,
                value: Some(b"key".to_vec().into()),
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
    let daemon = TestDaemon::start(MockAbi::host());

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");
        let object = client.create_object(session, Some(&[])).await.expect("C_CreateObject");

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
                    apply_returned_len: true,
                    apply_type: false,
                    attr_type: CkAttributeType::LABEL,
                    returned_len: 3,
                    value: None,
                    ck_rv: None,
                    nested: None,
                },
                CkAttributeQueryResult {
                    apply_returned_len: true,
                    apply_type: false,
                    attr_type: CkAttributeType::VALUE,
                    returned_len: u64::MAX,
                    value: None,
                    ck_rv: Some(CkRv::ATTRIBUTE_SENSITIVE),
                    nested: None,
                },
                CkAttributeQueryResult {
                    apply_returned_len: true,
                    apply_type: false,
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
    let daemon = TestDaemon::start(MockAbi::host());

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
        let object = client.create_object(session, Some(&[])).await.expect("C_CreateObject");

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
    assert_eq!(first_len as usize, SHA256_DIGEST_LEN);

    let mut first_out = [0_u8; SHA256_DIGEST_LEN];
    let mut first_out_len = first_out.len() as CK_ULONG;
    let first_data_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            first.as_ptr() as CK_BYTE_PTR,
            first.len() as CK_ULONG,
            first_out.as_mut_ptr(),
            &mut first_out_len,
        )
    };
    assert_eq!(first_data_rv, CKR_OK as CK_RV);

    let reinit_rv = unsafe { dispatch::general::c_digest_init(shim.session, &mut mechanism) };
    assert_eq!(reinit_rv, CKR_OK as CK_RV);

    let second = b"bb";
    let mut out = [0_u8; SHA256_DIGEST_LEN];
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
fn digest_init_null_mechanism_cancels_active_digest_operation() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let mut mechanism = sha256_mechanism();

    let init_rv = unsafe { dispatch::general::c_digest_init(shim.session, &mut mechanism) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_DigestInit");

    let update_rv = unsafe {
        dispatch::general::c_digest_update(
            shim.session,
            b"cancel-me".as_ptr() as CK_BYTE_PTR,
            b"cancel-me".len() as CK_ULONG,
        )
    };
    assert_eq!(update_rv, CKR_OK as CK_RV, "C_DigestUpdate");

    let cancel_rv = unsafe { dispatch::general::c_digest_init(shim.session, std::ptr::null_mut()) };
    assert_eq!(cancel_rv, CKR_OK as CK_RV, "C_DigestInit(NULL_PTR)");

    let mut out = [0_u8; SHA256_DIGEST_LEN];
    let mut out_len = out.len() as CK_ULONG;
    let final_rv =
        unsafe { dispatch::general::c_digest_final(shim.session, out.as_mut_ptr(), &mut out_len) };
    assert_eq!(
        final_rv, CKR_OPERATION_NOT_INITIALIZED as CK_RV,
        "C_DigestFinal after NULL init cancellation"
    );

    let reinit_rv = unsafe { dispatch::general::c_digest_init(shim.session, &mut mechanism) };
    assert_eq!(reinit_rv, CKR_OK as CK_RV, "C_DigestInit after cancellation");
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
    set_test_message_shape(
        shim.session,
        state::MessageOperation::Encrypt,
        MessageParameterShape::Gcm,
    );

    let finalize_rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    assert_eq!(finalize_rv, CKR_OK as CK_RV);

    assert!(state::dig_cache().lock().unwrap().is_empty());
    assert!(state::wrap_cache().lock().unwrap().is_empty());
    assert!(state::encapsulate_cache().lock().unwrap().is_empty());
    assert_eq!(
        test_message_shape(shim.session, state::MessageOperation::Encrypt),
        None,
        "finalize must evict message-operation shapes",
    );

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
    set_test_message_shape(
        target_session,
        state::MessageOperation::Encrypt,
        MessageParameterShape::Gcm,
    );
    set_test_message_shape(
        other_session,
        state::MessageOperation::Encrypt,
        MessageParameterShape::Ccm,
    );

    let close_all_rv = unsafe { dispatch::general::c_close_all_sessions(target_slot) };
    assert_eq!(close_all_rv, CKR_OK as CK_RV);

    assert!(!state::dig_cache().lock().unwrap().contains_key(&target_session));
    assert!(!state::wrap_cache().lock().unwrap().contains_key(&target_session));
    assert!(!state::encapsulate_cache().lock().unwrap().contains_key(&target_session));
    assert!(state::dig_cache().lock().unwrap().contains_key(&other_session));
    assert!(state::wrap_cache().lock().unwrap().contains_key(&other_session));
    assert!(state::encapsulate_cache().lock().unwrap().contains_key(&other_session));
    assert_eq!(
        test_message_shape(target_session, state::MessageOperation::Encrypt),
        None,
        "close-all must evict shapes for the target slot",
    );
    assert_eq!(
        test_message_shape(other_session, state::MessageOperation::Encrypt),
        Some(MessageParameterShape::Ccm),
        "close-all must preserve shapes for another slot",
    );

    let mut info = std::mem::MaybeUninit::uninit();
    let stale_rv =
        unsafe { dispatch::general::c_get_session_info(target_session, info.as_mut_ptr()) };
    assert_eq!(stale_rv, CKR_SESSION_HANDLE_INVALID as CK_RV);

    let other_close_rv = unsafe { dispatch::general::c_close_session(other_session) };
    assert_eq!(other_close_rv, CKR_OK as CK_RV);
}

#[test]
fn failed_close_session_still_evicts_session_output_caches() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let session = shim.open_additional_session();

    state::dig_cache().lock().unwrap().insert(session, vec![0xAA]);
    state::wrap_cache().lock().unwrap().insert(session, vec![0xBB]);
    set_test_message_shape(session, state::MessageOperation::Encrypt, MessageParameterShape::Gcm);

    let daemon = TestDaemon::shared();
    daemon.backend.inject_close_error(CkRv::FUNCTION_FAILED);
    let failed_rv = unsafe { dispatch::general::c_close_session(session) };
    daemon.backend.clear_close_error();
    assert_eq!(failed_rv, CKR_FUNCTION_FAILED as CK_RV);

    // Disposable output caches are dropped on the close attempt, regardless
    // of the server's CK_RV.
    assert!(!state::dig_cache().lock().unwrap().contains_key(&session));
    assert!(!state::wrap_cache().lock().unwrap().contains_key(&session));
    assert_eq!(
        test_message_shape(session, state::MessageOperation::Encrypt),
        Some(MessageParameterShape::Gcm),
        "a decoded transient close failure must preserve authoritative shape state",
    );

    // The transient failure kept the handle valid (M3), so a retry succeeds
    // and simply finds the caches already evicted.
    let retry_rv = unsafe { dispatch::general::c_close_session(session) };
    assert_eq!(retry_rv, CKR_OK as CK_RV);
    assert_eq!(
        test_message_shape(session, state::MessageOperation::Encrypt),
        None,
        "a terminal close must evict authoritative shape state",
    );
}

#[test]
fn failed_close_all_sessions_still_evicts_slot_session_caches() {
    let _guard = shim_state_test_guard();
    let _shim = ShimSession::new();

    let unknown_slot: CK_SLOT_ID = 999;
    let phantom_session: CK_SESSION_HANDLE = 0xDEAD_BEEF;
    state::remember_session_slot(phantom_session, unknown_slot);
    state::dig_cache().lock().unwrap().insert(phantom_session, vec![0xCC]);

    let close_all_rv = unsafe { dispatch::general::c_close_all_sessions(unknown_slot) };
    assert_ne!(close_all_rv, CKR_OK as CK_RV);

    // `state::evict_slot_session_caches` contract: dropped on the attempt,
    // regardless of the server's CK_RV.
    assert!(!state::dig_cache().lock().unwrap().contains_key(&phantom_session));
}

fn set_test_message_shape(
    session: CK_SESSION_HANDLE,
    operation: state::MessageOperation,
    shape: MessageParameterShape,
) {
    state::message_operation_state(session, operation)
        .lock()
        .expect("message-operation state lock")
        .shape = Some(shape);
}

fn test_message_shape(
    session: CK_SESSION_HANDLE,
    operation: state::MessageOperation,
) -> Option<MessageParameterShape> {
    state::message_operation_state(session, operation)
        .lock()
        .expect("message-operation state lock")
        .shape
}

#[test]
fn message_encrypt_decrypt_final_require_and_clear_only_their_active_shape() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);

    for (operation, init_call, final_call) in [
        (
            state::MessageOperation::Encrypt,
            dispatch::general::c_message_encrypt_init
                as unsafe extern "C" fn(
                    CK_SESSION_HANDLE,
                    CK_MECHANISM_PTR,
                    CK_OBJECT_HANDLE,
                ) -> CK_RV,
            dispatch::general::c_message_encrypt_final
                as unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
        ),
        (
            state::MessageOperation::Decrypt,
            dispatch::general::c_message_decrypt_init
                as unsafe extern "C" fn(
                    CK_SESSION_HANDLE,
                    CK_MECHANISM_PTR,
                    CK_OBJECT_HANDLE,
                ) -> CK_RV,
            dispatch::general::c_message_decrypt_final
                as unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
        ),
    ] {
        assert_eq!(
            unsafe { final_call(shim.session) },
            CKR_OPERATION_NOT_INITIALIZED as CK_RV,
            "MessageFinal must reject a missing authoritative operation shape",
        );

        let mut mechanism = aes_ecb_mechanism();
        assert_eq!(unsafe { init_call(shim.session, &mut mechanism, key) }, CKR_OK as CK_RV);
        assert_eq!(
            test_message_shape(shim.session, operation),
            Some(MessageParameterShape::Unmodeled),
        );
        assert_eq!(unsafe { final_call(shim.session) }, CKR_OK as CK_RV);
        assert_eq!(
            test_message_shape(shim.session, operation),
            None,
            "successful MessageFinal must clear its authoritative operation shape",
        );
    }
}

#[test]
fn malformed_post_provider_ack_returns_device_error_and_clears_shim_shape() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut iv = [0x11_u8; 12];
    let mut tag = [0_u8; 16];
    let mut parameter = CK_GCM_MESSAGE_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 96,
        ivGenerator: CKG_NO_GENERATE,
        pTag: tag.as_mut_ptr(),
        ulTagBits: 128,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: (&mut parameter as *mut CK_GCM_MESSAGE_PARAMS).cast(),
        ulParameterLen: std::mem::size_of_val(&parameter) as CK_ULONG,
    };
    assert_eq!(
        unsafe { dispatch::general::c_message_encrypt_init(shim.session, &mut mechanism, key) },
        CKR_OK as CK_RV,
    );
    assert_eq!(
        test_message_shape(shim.session, state::MessageOperation::Encrypt),
        Some(MessageParameterShape::Gcm),
    );

    let daemon = TestDaemon::shared();
    let provider_len = std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as u64;
    daemon.backend.set_next_message_parameter_ack(CkParameterRoundtripResult {
        ck_rv: CkRv::OK,
        returned_len: provider_len + 1,
        value: Some(Vec::new().into()),
    });
    let calls_before = daemon.backend.message_parameter_call_count();
    let input = [0x22_u8; 8];
    let mut output = [0xA5_u8; 8];
    let mut output_len = output.len() as CK_ULONG;
    let rv = unsafe {
        dispatch::general::c_encrypt_message(
            shim.session,
            (&mut parameter as *mut CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&parameter) as CK_ULONG,
            std::ptr::null_mut(),
            0,
            input.as_ptr() as CK_BYTE_PTR,
            input.len() as CK_ULONG,
            output.as_mut_ptr(),
            &mut output_len,
        )
    };

    assert_eq!(rv, CKR_DEVICE_ERROR as CK_RV);
    assert_eq!(daemon.backend.message_parameter_call_count(), calls_before + 1);
    assert_eq!(
        test_message_shape(shim.session, state::MessageOperation::Encrypt),
        None,
        "post-provider acknowledgement ambiguity must clear local authoritative state",
    );
    assert_eq!(output, [0xA5; 8], "malformed response must not write main output");
    assert_eq!(output_len, 8, "malformed response must not write output length");
    assert_eq!(iv, [0x11; 12], "malformed response must not write embedded IV");
    assert_eq!(tag, [0; 16], "malformed response must not write embedded tag");
}

#[test]
fn device_error_close_clears_authoritative_message_shapes() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let session = shim.open_additional_session();
    set_test_message_shape(session, state::MessageOperation::Encrypt, MessageParameterShape::Gcm);

    let daemon = TestDaemon::shared();
    daemon.backend.inject_close_error(CkRv::DEVICE_ERROR);
    let rv = unsafe { dispatch::general::c_close_session(session) };
    daemon.backend.clear_close_error();

    assert_eq!(rv, CKR_DEVICE_ERROR as CK_RV);
    assert_eq!(
        test_message_shape(session, state::MessageOperation::Encrypt),
        None,
        "an outcome-ambiguous close must clear authoritative shape state",
    );
}

#[test]
fn panicked_close_clears_authoritative_message_shapes() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let session = shim.open_additional_session();
    set_test_message_shape(session, state::MessageOperation::Encrypt, MessageParameterShape::Gcm);

    let daemon = TestDaemon::shared();
    let calls_before = daemon.backend.close_session_call_count();
    daemon.backend.set_next_message_lifecycle_action(MockMessageLifecycleAction::Panic);
    let rv = unsafe { dispatch::general::c_close_session(session) };

    assert_eq!(rv, CKR_GENERAL_ERROR as CK_RV);
    assert_eq!(daemon.backend.close_session_call_count(), calls_before + 1);
    assert_eq!(
        test_message_shape(session, state::MessageOperation::Encrypt),
        None,
        "a transport-ambiguous close must clear authoritative shape state",
    );
}

#[test]
fn session_cancel_success_is_bit_selective_for_message_shapes() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();

    for operation in [
        state::MessageOperation::Encrypt,
        state::MessageOperation::Decrypt,
        state::MessageOperation::Sign,
        state::MessageOperation::Verify,
    ] {
        set_test_message_shape(shim.session, operation, MessageParameterShape::Unmodeled);
    }

    let rv = unsafe {
        dispatch::general::c_session_cancel(shim.session, CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_SIGN)
    };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert_eq!(
        test_message_shape(shim.session, state::MessageOperation::Encrypt),
        None,
        "the selected encrypt shape must be cleared",
    );
    assert_eq!(
        test_message_shape(shim.session, state::MessageOperation::Sign),
        None,
        "the selected sign shape must be cleared",
    );
    assert_eq!(
        test_message_shape(shim.session, state::MessageOperation::Decrypt),
        Some(MessageParameterShape::Unmodeled),
        "an unselected decrypt shape must survive",
    );
    assert_eq!(
        test_message_shape(shim.session, state::MessageOperation::Verify),
        Some(MessageParameterShape::Unmodeled),
        "an unselected verify shape must survive",
    );

    let zero_flags_rv = unsafe { dispatch::general::c_session_cancel(shim.session, 0) };
    assert_eq!(zero_flags_rv, CKR_OK as CK_RV);
    assert_eq!(
        test_message_shape(shim.session, state::MessageOperation::Decrypt),
        Some(MessageParameterShape::Unmodeled),
        "flags=0 must clear nothing",
    );
    assert_eq!(
        test_message_shape(shim.session, state::MessageOperation::Verify),
        Some(MessageParameterShape::Unmodeled),
        "flags=0 must clear nothing",
    );
}

#[test]
fn session_cancel_error_origin_controls_selected_shim_shapes() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let daemon = TestDaemon::shared();

    for (action, expected_rv, selected_shape) in [
        (
            MockMessageLifecycleAction::Return(CkRv::FUNCTION_FAILED),
            CKR_FUNCTION_FAILED as CK_RV,
            Some(MessageParameterShape::Unmodeled),
        ),
        (MockMessageLifecycleAction::Return(CkRv::DEVICE_ERROR), CKR_DEVICE_ERROR as CK_RV, None),
        (MockMessageLifecycleAction::Panic, CKR_GENERAL_ERROR as CK_RV, None),
    ] {
        for operation in [
            state::MessageOperation::Encrypt,
            state::MessageOperation::Decrypt,
            state::MessageOperation::Sign,
            state::MessageOperation::Verify,
        ] {
            set_test_message_shape(shim.session, operation, MessageParameterShape::Unmodeled);
        }
        let calls_before = daemon.backend.message_lifecycle_call_count();
        daemon.backend.set_next_message_lifecycle_action(action);

        let rv = unsafe {
            dispatch::general::c_session_cancel(
                shim.session,
                CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_SIGN,
            )
        };

        assert_eq!(rv, expected_rv, "{action:?}");
        assert_eq!(daemon.backend.message_lifecycle_call_count(), calls_before + 1);
        assert_eq!(
            test_message_shape(shim.session, state::MessageOperation::Encrypt),
            selected_shape,
            "{action:?} encrypt",
        );
        assert_eq!(
            test_message_shape(shim.session, state::MessageOperation::Sign),
            selected_shape,
            "{action:?} sign",
        );
        assert_eq!(
            test_message_shape(shim.session, state::MessageOperation::Decrypt),
            Some(MessageParameterShape::Unmodeled),
            "{action:?} unselected decrypt",
        );
        assert_eq!(
            test_message_shape(shim.session, state::MessageOperation::Verify),
            Some(MessageParameterShape::Unmodeled),
            "{action:?} unselected verify",
        );
    }
}

#[test]
fn pointer_safe_message_every_entrypoint_requires_capability_before_pointer_state_or_rpc() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let daemon = TestDaemon::shared();
    for (operation, shape) in [
        (state::MessageOperation::Encrypt, MessageParameterShape::Gcm),
        (state::MessageOperation::Decrypt, MessageParameterShape::Gcm),
        (state::MessageOperation::Sign, MessageParameterShape::Unmodeled),
        (state::MessageOperation::Verify, MessageParameterShape::Unmodeled),
    ] {
        set_test_message_shape(shim.session, operation, shape);
    }
    let backend_counts_before = (
        daemon.backend.data_op_call_count(),
        daemon.backend.message_begin_call_count(),
        daemon.backend.message_init_contract_call_count(),
        daemon.backend.message_lifecycle_call_count(),
        daemon.backend.message_parameter_call_count(),
    );
    crate::interface_probe::invalidate_pointer_safe_message_parameters();

    macro_rules! assert_capability_rejected {
        ($name:literal, $call:expr) => {
            assert_eq!(unsafe { $call }, CKR_FUNCTION_NOT_SUPPORTED as CK_RV, $name,);
        };
    }

    let poison_mechanism: CK_MECHANISM_PTR = std::ptr::dangling_mut();
    let poison_parameter: *mut ::std::os::raw::c_void = std::ptr::dangling_mut();
    let poison_bytes: CK_BYTE_PTR = std::ptr::dangling_mut();
    let poison_len: *mut CK_ULONG = std::ptr::dangling_mut();

    type InitFn =
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV;
    for (name, init) in [
        ("MessageEncryptInit", dispatch::general::c_message_encrypt_init as InitFn),
        ("MessageDecryptInit", dispatch::general::c_message_decrypt_init as InitFn),
        ("MessageSignInit", dispatch::general::c_message_sign_init as InitFn),
        ("MessageVerifyInit", dispatch::general::c_message_verify_init as InitFn),
    ] {
        assert_eq!(
            unsafe { init(shim.session, poison_mechanism, 1) },
            CKR_FUNCTION_NOT_SUPPORTED as CK_RV,
            "{name} must gate before reading a non-NULL mechanism",
        );
        assert_eq!(
            unsafe { init(shim.session, std::ptr::null_mut(), 1) },
            CKR_FUNCTION_NOT_SUPPORTED as CK_RV,
            "{name} cancel must be capability-gated too",
        );
    }

    assert_capability_rejected!(
        "EncryptMessage",
        dispatch::general::c_encrypt_message(
            shim.session,
            poison_parameter,
            1,
            poison_bytes,
            1,
            poison_bytes,
            1,
            poison_bytes,
            poison_len,
        )
    );
    assert_capability_rejected!(
        "EncryptMessageBegin",
        dispatch::general::c_encrypt_message_begin(
            shim.session,
            poison_parameter,
            1,
            poison_bytes,
            1,
        )
    );
    assert_capability_rejected!(
        "EncryptMessageNext",
        dispatch::general::c_encrypt_message_next(
            shim.session,
            poison_parameter,
            1,
            poison_bytes,
            1,
            poison_bytes,
            poison_len,
            CKF_END_OF_MESSAGE,
        )
    );
    assert_capability_rejected!(
        "DecryptMessage",
        dispatch::general::c_decrypt_message(
            shim.session,
            poison_parameter,
            1,
            poison_bytes,
            1,
            poison_bytes,
            1,
            poison_bytes,
            poison_len,
        )
    );
    assert_capability_rejected!(
        "DecryptMessageBegin",
        dispatch::general::c_decrypt_message_begin(
            shim.session,
            poison_parameter,
            1,
            poison_bytes,
            1,
        )
    );
    assert_capability_rejected!(
        "DecryptMessageNext",
        dispatch::general::c_decrypt_message_next(
            shim.session,
            poison_parameter,
            1,
            poison_bytes,
            1,
            poison_bytes,
            poison_len,
            CKF_END_OF_MESSAGE,
        )
    );
    assert_capability_rejected!(
        "SignMessage",
        dispatch::general::c_sign_message(
            shim.session,
            poison_parameter,
            1,
            poison_bytes,
            1,
            poison_bytes,
            poison_len,
        )
    );
    assert_capability_rejected!(
        "SignMessageBegin",
        dispatch::general::c_sign_message_begin(shim.session, poison_parameter, 1)
    );
    assert_capability_rejected!(
        "SignMessageNext",
        dispatch::general::c_sign_message_next(
            shim.session,
            poison_parameter,
            1,
            poison_bytes,
            1,
            poison_bytes,
            poison_len,
        )
    );
    assert_capability_rejected!(
        "SignMessageNext(feed)",
        dispatch::general::c_sign_message_next(
            shim.session,
            poison_parameter,
            1,
            poison_bytes,
            1,
            poison_bytes,
            std::ptr::null_mut(),
        )
    );
    assert_capability_rejected!(
        "VerifyMessage",
        dispatch::general::c_verify_message(
            shim.session,
            poison_parameter,
            1,
            poison_bytes,
            1,
            poison_bytes,
            1,
        )
    );
    assert_capability_rejected!(
        "VerifyMessageBegin",
        dispatch::general::c_verify_message_begin(shim.session, poison_parameter, 1)
    );
    assert_capability_rejected!(
        "VerifyMessageNext",
        dispatch::general::c_verify_message_next(
            shim.session,
            poison_parameter,
            1,
            poison_bytes,
            1,
            poison_bytes,
            1,
        )
    );

    type FinalFn = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
    for (name, final_call) in [
        ("MessageEncryptFinal", dispatch::general::c_message_encrypt_final as FinalFn),
        ("MessageDecryptFinal", dispatch::general::c_message_decrypt_final as FinalFn),
        ("MessageSignFinal", dispatch::general::c_message_sign_final as FinalFn),
        ("MessageVerifyFinal", dispatch::general::c_message_verify_final as FinalFn),
    ] {
        assert_eq!(
            unsafe { final_call(shim.session) },
            CKR_FUNCTION_NOT_SUPPORTED as CK_RV,
            "{name}",
        );
    }
    assert_capability_rejected!(
        "SessionCancel",
        dispatch::general::c_session_cancel(
            shim.session,
            CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_DECRYPT | CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY,
        )
    );
    assert_capability_rejected!(
        "SessionCancel(mixed classic and message)",
        dispatch::general::c_session_cancel(shim.session, CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT,)
    );

    assert_eq!(
        (
            daemon.backend.data_op_call_count(),
            daemon.backend.message_begin_call_count(),
            daemon.backend.message_init_contract_call_count(),
            daemon.backend.message_lifecycle_call_count(),
            daemon.backend.message_parameter_call_count(),
        ),
        backend_counts_before,
        "capability rejection must occur before every covered provider call",
    );

    assert_eq!(
        unsafe { dispatch::general::c_session_cancel(shim.session, 0) },
        CKR_OK as CK_RV,
        "flags=0 remains safe against a legacy daemon",
    );
    assert_eq!(
        unsafe { dispatch::general::c_session_cancel(shim.session, CKF_ENCRYPT) },
        CKR_OK as CK_RV,
        "classic-only cancellation remains safe against a legacy daemon",
    );

    for (operation, shape) in [
        (state::MessageOperation::Encrypt, MessageParameterShape::Gcm),
        (state::MessageOperation::Decrypt, MessageParameterShape::Gcm),
        (state::MessageOperation::Sign, MessageParameterShape::Unmodeled),
        (state::MessageOperation::Verify, MessageParameterShape::Unmodeled),
    ] {
        assert_eq!(
            test_message_shape(shim.session, operation),
            Some(shape),
            "capability rejection must occur before taking or clearing {operation:?} state",
        );
    }
}

#[test]
fn set_operation_state_success_clears_all_message_shapes() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let source_session = shim.open_additional_session();
    let key = create_object(source_session);
    let mut mechanism = rsa_pkcs_mechanism();
    let init_rv = unsafe { dispatch::general::c_sign_init(source_session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV);
    let operation_state = export_operation_state(source_session, CKR_OK as CK_RV, 3);
    assert_eq!(unsafe { dispatch::general::c_close_session(source_session) }, CKR_OK as CK_RV,);

    for operation in [
        state::MessageOperation::Encrypt,
        state::MessageOperation::Decrypt,
        state::MessageOperation::Sign,
        state::MessageOperation::Verify,
    ] {
        set_test_message_shape(shim.session, operation, MessageParameterShape::Unmodeled);
    }

    let restore_rv = unsafe {
        dispatch::general::c_set_operation_state(
            shim.session,
            operation_state.as_ptr() as CK_BYTE_PTR,
            operation_state.len() as CK_ULONG,
            0,
            0,
        )
    };
    assert_eq!(restore_rv, CKR_OK as CK_RV);
    for operation in [
        state::MessageOperation::Encrypt,
        state::MessageOperation::Decrypt,
        state::MessageOperation::Sign,
        state::MessageOperation::Verify,
    ] {
        assert_eq!(
            test_message_shape(shim.session, operation),
            None,
            "successful opaque state restore must clear every message shape",
        );
    }
}

#[test]
fn set_operation_state_error_origin_controls_all_shim_shapes() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let daemon = TestDaemon::shared();
    let operation_state = [0xC9, 0xEA, 2];

    for (action, expected_rv, expected_shape) in [
        (
            MockMessageLifecycleAction::Return(CkRv::FUNCTION_FAILED),
            CKR_FUNCTION_FAILED as CK_RV,
            Some(MessageParameterShape::Unmodeled),
        ),
        (MockMessageLifecycleAction::Return(CkRv::DEVICE_ERROR), CKR_DEVICE_ERROR as CK_RV, None),
        (MockMessageLifecycleAction::Panic, CKR_GENERAL_ERROR as CK_RV, None),
    ] {
        for operation in [
            state::MessageOperation::Encrypt,
            state::MessageOperation::Decrypt,
            state::MessageOperation::Sign,
            state::MessageOperation::Verify,
        ] {
            set_test_message_shape(shim.session, operation, MessageParameterShape::Unmodeled);
        }
        let calls_before = daemon.backend.message_lifecycle_call_count();
        daemon.backend.set_next_message_lifecycle_action(action);

        let rv = unsafe {
            dispatch::general::c_set_operation_state(
                shim.session,
                operation_state.as_ptr() as CK_BYTE_PTR,
                operation_state.len() as CK_ULONG,
                0,
                0,
            )
        };

        assert_eq!(rv, expected_rv, "{action:?}");
        assert_eq!(daemon.backend.message_lifecycle_call_count(), calls_before + 1);
        for operation in [
            state::MessageOperation::Encrypt,
            state::MessageOperation::Decrypt,
            state::MessageOperation::Sign,
            state::MessageOperation::Verify,
        ] {
            assert_eq!(
                test_message_shape(shim.session, operation),
                expected_shape,
                "{action:?} {operation:?}",
            );
        }
    }
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
    assert_eq!(len as usize, SHA256_DIGEST_LEN);

    let mut digest_out = [0_u8; SHA256_DIGEST_LEN];
    let mut digest_out_len = digest_out.len() as CK_ULONG;
    let digest_data_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            digest_out.as_mut_ptr(),
            &mut digest_out_len,
        )
    };
    assert_eq!(digest_data_rv, CKR_OK as CK_RV);

    let mut out = [0_u8; SHA256_DIGEST_LEN];
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
    let mut digest_out = [0_u8; SHA256_DIGEST_LEN];
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
    assert_eq!(stale_len as usize, SHA256_DIGEST_LEN);

    let mut stale_out = [0_u8; SHA256_DIGEST_LEN];
    let mut stale_out_len = stale_out.len() as CK_ULONG;
    let stale_data_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            stale_data.as_ptr() as CK_BYTE_PTR,
            stale_data.len() as CK_ULONG,
            stale_out.as_mut_ptr(),
            &mut stale_out_len,
        )
    };
    assert_eq!(stale_data_rv, CKR_OK as CK_RV);

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
    let mut digest_out = [0_u8; SHA256_DIGEST_LEN];
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
    let mut digest_out = [0_u8; SHA256_DIGEST_LEN];
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
    assert_eq!(out_len as usize, SHA256_DIGEST_LEN, "returned_len is the SHA-256 length");

    let mut too_small = [0_u8; 1];
    let mut too_small_len = too_small.len() as CK_ULONG;
    let too_small_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            too_small.as_mut_ptr(),
            &mut too_small_len,
        )
    };
    assert_eq!(too_small_rv, CKR_BUFFER_TOO_SMALL as CK_RV, "C_Digest(too small)");
    assert_eq!(
        too_small_len as usize, SHA256_DIGEST_LEN,
        "too-small call returns the required length"
    );

    let mut out = [0_u8; SHA256_DIGEST_LEN];
    let mut data_len = out.len() as CK_ULONG;
    let data_rv = unsafe {
        dispatch::general::c_digest(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut data_len,
        )
    };
    assert_eq!(data_rv, CKR_OK as CK_RV, "C_Digest(data query)");
    assert_eq!(data_len as usize, SHA256_DIGEST_LEN, "data query returned_len");
    assert_eq!(out, expected_mock_digest(data), "mock digest output is the echo bytes");
}

#[test]
fn exact_digest_final_size_query_does_not_consume_state() {
    // OASIS specifies that C_DigestFinal does not terminate the active digest
    // operation when it returns CKR_OK for a size query or CKR_BUFFER_TOO_SMALL.
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let mut mechanism = sha256_mechanism();

    let init_rv = unsafe { dispatch::general::c_digest_init(shim.session, &mut mechanism) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_DigestInit");

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
    assert_eq!(out_len as usize, SHA256_DIGEST_LEN, "size query returned_len");

    let mut too_small = [0_u8; 1];
    let mut too_small_len = too_small.len() as CK_ULONG;
    let too_small_rv = unsafe {
        dispatch::general::c_digest_final(shim.session, too_small.as_mut_ptr(), &mut too_small_len)
    };
    assert_eq!(too_small_rv, CKR_BUFFER_TOO_SMALL as CK_RV, "C_DigestFinal(too small)");
    assert_eq!(
        too_small_len as usize, SHA256_DIGEST_LEN,
        "too-small call returns the required length"
    );

    let mut out = [0_u8; SHA256_DIGEST_LEN];
    let mut data_len = out.len() as CK_ULONG;
    let data_rv =
        unsafe { dispatch::general::c_digest_final(shim.session, out.as_mut_ptr(), &mut data_len) };
    assert_eq!(data_rv, CKR_OK as CK_RV, "C_DigestFinal(data query)");
    assert_eq!(data_len as usize, SHA256_DIGEST_LEN, "data query returned_len");
    assert_eq!(out, expected_mock_digest_final(), "mock digest_final output is the echo bytes");
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
    // MockBackend returns a 2-byte deterministic echo signature
    assert_eq!(out_len, 2, "returned_len should be 2 for mock sign output");

    let mut too_small = [0_u8; 1];
    let mut too_small_len = too_small.len() as CK_ULONG;
    let too_small_rv = unsafe {
        dispatch::general::c_sign(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            too_small.as_mut_ptr(),
            &mut too_small_len,
        )
    };
    assert_eq!(too_small_rv, CKR_BUFFER_TOO_SMALL as CK_RV, "C_Sign(too small)");
    assert_eq!(too_small_len, 2, "too-small call should return required length");

    let mut out = [0_u8; 2];
    let mut data_len = out.len() as CK_ULONG;
    let data_rv = unsafe {
        dispatch::general::c_sign(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut data_len,
        )
    };
    assert_eq!(data_rv, CKR_OK as CK_RV, "C_Sign(data query)");
    assert_eq!(data_len, 2, "data query returned_len should be 2");
    assert_eq!(out, expected_mock_sign(data), "mock sign output is the echo bytes");
}

#[test]
fn exact_sign_final_size_query_does_not_consume_state() {
    // OASIS specifies that C_SignFinal does not terminate the active signing
    // operation when it returns CKR_OK for a size query or CKR_BUFFER_TOO_SMALL.
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = rsa_pkcs_mechanism();

    let init_rv = unsafe { dispatch::general::c_sign_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_SignInit");

    let mut out_len: CK_ULONG = 0;
    let size_rv = unsafe {
        dispatch::general::c_sign_final(shim.session, std::ptr::null_mut(), &mut out_len)
    };
    assert_eq!(size_rv, CKR_OK as CK_RV, "C_SignFinal(size query)");
    // MockBackend sign_final returns a 2-byte deterministic echo
    assert_eq!(out_len, 2, "size query returned_len should be 2");

    let mut too_small = [0_u8; 1];
    let mut too_small_len = too_small.len() as CK_ULONG;
    let too_small_rv = unsafe {
        dispatch::general::c_sign_final(shim.session, too_small.as_mut_ptr(), &mut too_small_len)
    };
    assert_eq!(too_small_rv, CKR_BUFFER_TOO_SMALL as CK_RV, "C_SignFinal(too small)");
    assert_eq!(too_small_len, 2, "too-small call should return required length");

    let mut out = [0_u8; 2];
    let mut data_len = out.len() as CK_ULONG;
    let data_rv =
        unsafe { dispatch::general::c_sign_final(shim.session, out.as_mut_ptr(), &mut data_len) };
    assert_eq!(data_rv, CKR_OK as CK_RV, "C_SignFinal(data query)");
    assert_eq!(data_len, 2, "data query returned_len should be 2");
    assert_eq!(out, expected_mock_sign_final(), "mock sign_final output is the echo bytes");
}

#[test]
fn sign_init_null_mechanism_cancels_active_sign_operation() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = rsa_pkcs_mechanism();

    let init_rv = unsafe { dispatch::general::c_sign_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_SignInit");

    let update_rv = unsafe {
        dispatch::general::c_sign_update(
            shim.session,
            b"cancel-me".as_ptr() as CK_BYTE_PTR,
            b"cancel-me".len() as CK_ULONG,
        )
    };
    assert_eq!(update_rv, CKR_OK as CK_RV, "C_SignUpdate");

    let cancel_rv =
        unsafe { dispatch::general::c_sign_init(shim.session, std::ptr::null_mut(), 0) };
    assert_eq!(cancel_rv, CKR_OK as CK_RV, "C_SignInit(NULL_PTR)");

    let mut out = [0_u8; 2];
    let mut out_len = out.len() as CK_ULONG;
    let final_rv =
        unsafe { dispatch::general::c_sign_final(shim.session, out.as_mut_ptr(), &mut out_len) };
    assert_eq!(
        final_rv, CKR_OPERATION_NOT_INITIALIZED as CK_RV,
        "C_SignFinal after NULL init cancellation"
    );
}

#[test]
fn verify_init_null_mechanism_cancels_active_verify_operation() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = rsa_pkcs_mechanism();

    let init_rv = unsafe { dispatch::general::c_verify_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_VerifyInit");

    let update_rv = unsafe {
        dispatch::general::c_verify_update(
            shim.session,
            b"cancel-me".as_ptr() as CK_BYTE_PTR,
            b"cancel-me".len() as CK_ULONG,
        )
    };
    assert_eq!(update_rv, CKR_OK as CK_RV, "C_VerifyUpdate");

    let cancel_rv =
        unsafe { dispatch::general::c_verify_init(shim.session, std::ptr::null_mut(), 0) };
    assert_eq!(cancel_rv, CKR_OK as CK_RV, "C_VerifyInit(NULL_PTR)");

    let signature = [0xDE, 0xAD];
    let final_rv = unsafe {
        dispatch::general::c_verify_final(
            shim.session,
            signature.as_ptr() as CK_BYTE_PTR,
            signature.len() as CK_ULONG,
        )
    };
    assert_eq!(
        final_rv, CKR_OPERATION_NOT_INITIALIZED as CK_RV,
        "C_VerifyFinal after NULL init cancellation"
    );
}

#[test]
fn sign_recover_init_null_mechanism_cancels_active_sign_recover_operation() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = rsa_pkcs_mechanism();

    let init_rv =
        unsafe { dispatch::general::c_sign_recover_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_SignRecoverInit");

    let cancel_rv =
        unsafe { dispatch::general::c_sign_recover_init(shim.session, std::ptr::null_mut(), 0) };
    assert_eq!(cancel_rv, CKR_OK as CK_RV, "C_SignRecoverInit(NULL_PTR)");

    let data = b"cancel-me";
    let mut out = [0_u8; 2];
    let mut out_len = out.len() as CK_ULONG;
    let recover_rv = unsafe {
        dispatch::general::c_sign_recover(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_eq!(
        recover_rv, CKR_OPERATION_NOT_INITIALIZED as CK_RV,
        "C_SignRecover after NULL init cancellation"
    );
}

#[test]
fn verify_recover_init_null_mechanism_cancels_active_verify_recover_operation() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = rsa_pkcs_mechanism();

    let init_rv =
        unsafe { dispatch::general::c_verify_recover_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_VerifyRecoverInit");

    let cancel_rv =
        unsafe { dispatch::general::c_verify_recover_init(shim.session, std::ptr::null_mut(), 0) };
    assert_eq!(cancel_rv, CKR_OK as CK_RV, "C_VerifyRecoverInit(NULL_PTR)");

    let signature = [0xDE, 0xAD];
    let mut out = [0_u8; 2];
    let mut out_len = out.len() as CK_ULONG;
    let recover_rv = unsafe {
        dispatch::general::c_verify_recover(
            shim.session,
            signature.as_ptr() as CK_BYTE_PTR,
            signature.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_eq!(
        recover_rv, CKR_OPERATION_NOT_INITIALIZED as CK_RV,
        "C_VerifyRecover after NULL init cancellation"
    );
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
        aad: b"aad".to_vec().into(),
        tag_bits: 128,

        iv_null: false,
        aad_null: false,
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
    let (ul_iv_len, ul_iv_bits, ul_tag_bits) = (params.ulIvLen, params.ulIvBits, params.ulTagBits);
    assert_eq!(ul_iv_len, generated_iv.len() as CK_ULONG, "provider IV length writeback");
    assert_eq!(ul_iv_bits, 96, "provider IV bit length writeback");
    assert_eq!(ul_tag_bits, 128, "provider tag bit length writeback");
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
        aad: b"aad".to_vec().into(),
        tag_bits: 128,

        iv_null: false,
        aad_null: false,
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
    let ul_iv_len = params.ulIvLen;
    assert_eq!(ul_iv_len, generated_iv.len() as CK_ULONG, "delayed IV length writeback");
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
        aad: b"aad".to_vec().into(),
        tag_bits: 128,

        iv_null: false,
        aad_null: false,
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
fn encrypt_init_null_mechanism_cancels_active_encrypt_operation() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = aes_ecb_mechanism();

    let init_rv = unsafe { dispatch::general::c_encrypt_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_EncryptInit");

    let mut query_len = 0;
    let update_rv = unsafe {
        dispatch::general::c_encrypt_update(
            shim.session,
            b"cancel-me".as_ptr() as CK_BYTE_PTR,
            b"cancel-me".len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut query_len,
        )
    };
    assert_eq!(update_rv, CKR_OK as CK_RV, "C_EncryptUpdate(size query)");

    let cancel_rv =
        unsafe { dispatch::general::c_encrypt_init(shim.session, std::ptr::null_mut(), 0) };
    assert_eq!(cancel_rv, CKR_OK as CK_RV, "C_EncryptInit(NULL_PTR)");

    let mut out = [0_u8; 1];
    let mut out_len = out.len() as CK_ULONG;
    let final_rv =
        unsafe { dispatch::general::c_encrypt_final(shim.session, out.as_mut_ptr(), &mut out_len) };
    assert_eq!(
        final_rv, CKR_OPERATION_NOT_INITIALIZED as CK_RV,
        "C_EncryptFinal after NULL init cancellation"
    );
}

#[test]
fn decrypt_init_null_mechanism_cancels_active_decrypt_operation() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = aes_ecb_mechanism();

    let init_rv = unsafe { dispatch::general::c_decrypt_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_DecryptInit");

    let mut query_len = 0;
    let update_rv = unsafe {
        dispatch::general::c_decrypt_update(
            shim.session,
            b"cancel-me".as_ptr() as CK_BYTE_PTR,
            b"cancel-me".len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut query_len,
        )
    };
    assert_eq!(update_rv, CKR_OK as CK_RV, "C_DecryptUpdate(size query)");

    let cancel_rv =
        unsafe { dispatch::general::c_decrypt_init(shim.session, std::ptr::null_mut(), 0) };
    assert_eq!(cancel_rv, CKR_OK as CK_RV, "C_DecryptInit(NULL_PTR)");

    let mut out = [0_u8; 1];
    let mut out_len = out.len() as CK_ULONG;
    let final_rv =
        unsafe { dispatch::general::c_decrypt_final(shim.session, out.as_mut_ptr(), &mut out_len) };
    assert_eq!(
        final_rv, CKR_OPERATION_NOT_INITIALIZED as CK_RV,
        "C_DecryptFinal after NULL init cancellation"
    );
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

    let mut too_small = [0_u8; 1];
    let mut too_small_len = too_small.len() as CK_ULONG;
    let too_small_rv = unsafe {
        dispatch::general::c_encrypt(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            too_small.as_mut_ptr(),
            &mut too_small_len,
        )
    };
    assert_eq!(too_small_rv, CKR_BUFFER_TOO_SMALL as CK_RV, "C_Encrypt(too small)");
    assert_eq!(too_small_len, 5, "too-small call should return required length");

    let mut out = [0_u8; 5];
    let mut data_len = out.len() as CK_ULONG;
    let data_rv = unsafe {
        dispatch::general::c_encrypt(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut data_len,
        )
    };
    assert_eq!(data_rv, CKR_OK as CK_RV, "C_Encrypt(data query)");
    assert_eq!(data_len, 5, "data query returned_len should be 5");
    assert_eq!(out, [0x2A, 0x27, 0x2E, 0x2E, 0x2D], "mock ciphertext");
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

    let mut too_small = [0_u8; 1];
    let mut too_small_len = too_small.len() as CK_ULONG;
    let too_small_rv = unsafe {
        dispatch::general::c_decrypt(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            too_small.as_mut_ptr(),
            &mut too_small_len,
        )
    };
    assert_eq!(too_small_rv, CKR_BUFFER_TOO_SMALL as CK_RV, "C_Decrypt(too small)");
    assert_eq!(too_small_len, 5, "too-small call should return required length");

    let mut out = [0_u8; 5];
    let mut data_len = out.len() as CK_ULONG;
    let data_rv = unsafe {
        dispatch::general::c_decrypt(
            shim.session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut data_len,
        )
    };
    assert_eq!(data_rv, CKR_OK as CK_RV, "C_Decrypt(data query)");
    assert_eq!(data_len, 5, "data query returned_len should be 5");
    assert_eq!(out, [0x2A, 0x27, 0x2E, 0x2E, 0x2D], "mock plaintext");
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

type CipherInitFn =
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV;
type CipherOutputFn = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV;

fn assert_null_pul_len_terminates_cipher_operation(
    operation_name: &str,
    init: CipherInitFn,
    operation: CipherOutputFn,
) {
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = aes_ecb_mechanism();
    assert_eq!(
        unsafe { init(shim.session, &mut mechanism, key) },
        CKR_OK as CK_RV,
        "{operation_name} init",
    );

    let daemon = TestDaemon::shared();
    let calls_before = daemon.backend.data_op_call_count();
    let input = *b"data";
    let mut output_sentinel = 0xA5;
    let rv = unsafe {
        operation(
            shim.session,
            input.as_ptr() as CK_BYTE_PTR,
            input.len() as CK_ULONG,
            &mut output_sentinel,
            std::ptr::null_mut(),
        )
    };

    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV, "{operation_name} provider RV");
    assert_eq!(output_sentinel, 0xA5, "{operation_name} must not write output bytes");
    assert_eq!(
        daemon.backend.data_op_call_count(),
        calls_before + 1,
        "{operation_name} must reach the provider exactly once",
    );

    let mut mechanism = aes_ecb_mechanism();
    assert_eq!(
        unsafe { init(shim.session, &mut mechanism, key) },
        CKR_OK as CK_RV,
        "{operation_name} must terminate the active provider operation",
    );
    assert_eq!(
        unsafe { init(shim.session, std::ptr::null_mut(), 0) },
        CKR_OK as CK_RV,
        "{operation_name} cleanup",
    );
}

#[test]
fn null_pul_len_encrypt_reaches_provider_once_and_terminates_operation() {
    let _guard = shim_state_test_guard();
    assert_null_pul_len_terminates_cipher_operation(
        "C_Encrypt",
        dispatch::general::c_encrypt_init,
        dispatch::general::c_encrypt,
    );
}

#[test]
fn null_pul_len_encrypt_update_reaches_provider_once_and_terminates_operation() {
    let _guard = shim_state_test_guard();
    assert_null_pul_len_terminates_cipher_operation(
        "C_EncryptUpdate",
        dispatch::general::c_encrypt_init,
        dispatch::general::c_encrypt_update,
    );
}

#[test]
fn null_pul_len_decrypt_reaches_provider_once_and_terminates_operation() {
    let _guard = shim_state_test_guard();
    assert_null_pul_len_terminates_cipher_operation(
        "C_Decrypt",
        dispatch::general::c_decrypt_init,
        dispatch::general::c_decrypt,
    );
}

#[test]
fn null_pul_len_decrypt_update_reaches_provider_once_and_terminates_operation() {
    let _guard = shim_state_test_guard();
    assert_null_pul_len_terminates_cipher_operation(
        "C_DecryptUpdate",
        dispatch::general::c_decrypt_init,
        dispatch::general::c_decrypt_update,
    );
}

#[test]
fn null_pul_len_sign_message_next_remains_a_feed_call() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let key = create_object(shim.session);
    let mut mechanism = rsa_pkcs_mechanism();
    assert_eq!(
        unsafe { dispatch::general::c_message_sign_init(shim.session, &mut mechanism, key) },
        CKR_OK as CK_RV,
        "C_MessageSignInit",
    );

    let daemon = TestDaemon::shared();
    let data_calls_before = daemon.backend.data_op_call_count();
    let parameter_calls_before = daemon.backend.message_parameter_call_count();
    let data = *b"more";
    let mut signature_canary = 0xA5;

    let rv = unsafe {
        dispatch::general::c_sign_message_next(
            shim.session,
            std::ptr::null_mut(),
            0,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            &mut signature_canary,
            std::ptr::null_mut(),
        )
    };

    assert_eq!(rv, CKR_OK as CK_RV, "C_SignMessageNext(feed)");
    assert_eq!(signature_canary, 0xA5, "feed call must not write signature bytes");
    assert_eq!(
        daemon.backend.data_op_call_count(),
        data_calls_before + 1,
        "feed call must reach the provider exactly once",
    );
    assert_eq!(
        daemon.backend.message_parameter_call_count(),
        parameter_calls_before + 1,
        "feed call must use the parameter round-trip contract",
    );
    assert_eq!(
        test_message_shape(shim.session, state::MessageOperation::Sign),
        Some(MessageParameterShape::Unmodeled),
        "feed call must keep the message-sign operation active",
    );
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
    // encrypt_impl requires an active message Encrypt operation, so first we
    // call MessageEncryptInit, then verify the exact RPC size-query result.
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::start(MockAbi::host());

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");

        // Set up an active message-encrypt operation so the mock can process the call.
        let mechanism = pkcs11_proxy_ng_types::CkMechanism {
            mechanism_type: CkMechanismType::AES_ECB,
            params: None,
        };
        let key = client.create_object(session, Some(&[])).await.expect("C_CreateObject");
        client
            .message_encrypt_init(session, Some(&mechanism), None, key)
            .await
            .expect("C_MessageEncryptInit");

        let output_spec =
            CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false };
        let param_out_spec =
            CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None };

        let result = client
            .parameter_output_exact(
                session,
                ParameterOutputFunction::EncryptMessage,
                &output_spec,
                CkInBuf::Bytes(b"plaintext"),
                CkInBuf::Bytes(b"aad"),
                &[],
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
                    output_result.returned_len > Some(0),
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
    let daemon = TestDaemon::start(MockAbi::host());

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");

        let wrapping_key = client.create_object(session, Some(&[])).await.expect("C_CreateObject");
        let key = client.create_object(session, Some(&[])).await.expect("C_CreateObject");

        let output_spec =
            CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false };
        let param_out_spec = CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: 16,
            value: Some(vec![0xBB; 16].into()),
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
                CkInBuf::Bytes(&[]),
                CkInBuf::Bytes(b"aad_data"),
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
                    output_result.returned_len > Some(0),
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

#[test]
fn null_output_length_parameter_rpc_preserves_exact_provider_rv() {
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::start(MockAbi::host());

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");
        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");
        let wrapping_key = client.create_object(session, Some(&[])).await.expect("C_CreateObject");
        let key = client.create_object(session, Some(&[])).await.expect("C_CreateObject");
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None };
        let mechanism = pkcs11_proxy_ng_types::CkMechanism {
            mechanism_type: CkMechanismType::AES_ECB,
            params: None,
        };

        let result = client
            .parameter_output_exact(
                session,
                ParameterOutputFunction::WrapKeyAuthenticated,
                &output_spec,
                CkInBuf::Bytes(&[]),
                CkInBuf::Bytes(b"aad"),
                &[],
                &parameter_spec,
                0,
                Some(&mechanism),
                wrapping_key.0,
                key.0,
                None,
            )
            .await;

        let (output, _, _) = result.expect("completed native result remains an envelope");
        assert_eq!(output.ck_rv, CkRv::ARGUMENTS_BAD);
        assert_eq!(output.returned_len, None);

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

#[test]
fn null_pul_len_encapsulate_key_preserves_output_and_handle_cells() {
    let _guard = shim_state_test_guard();
    let shim = ShimSession::new();
    let public_key = create_object(shim.session);
    let mut mechanism = generic_mechanism();
    let mut output_sentinel = 0xA5;
    let mut key_handle = CK_INVALID_HANDLE;

    let rv = unsafe {
        dispatch::general::c_encapsulate_key(
            shim.session,
            &mut mechanism,
            public_key,
            std::ptr::null_mut(),
            0,
            &mut output_sentinel,
            std::ptr::null_mut(),
            &mut key_handle,
        )
    };

    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
    assert_eq!(output_sentinel, 0xA5);
    assert_eq!(key_handle, CK_INVALID_HANDLE);
}

// =========================================================================
// Track C Task 3: Nested CKF_ARRAY_ATTRIBUTE tests
// =========================================================================

/// The raw CKA_WRAP_TEMPLATE constant (CKF_ARRAY_ATTRIBUTE | 0x211).
pub(super) const CKA_WRAP_TEMPLATE_RAW: CK_ATTRIBUTE_TYPE = 0x4000_0211;

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
    let (sub0_type, sub1_type) = (sub_attrs[0].type_, sub_attrs[1].type_);
    assert_eq!(
        sub0_type,
        CkAttributeType::CLASS.0 as CK_ATTRIBUTE_TYPE,
        "sub-attr[0] type should be CKA_CLASS"
    );
    assert_eq!(
        sub1_type,
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
    let (sub0_type, sub1_type) = (sub_attrs[0].type_, sub_attrs[1].type_);
    assert_eq!(sub0_type, CkAttributeType::CLASS.0 as CK_ATTRIBUTE_TYPE);
    assert_eq!(sub1_type, CkAttributeType::LABEL.0 as CK_ATTRIBUTE_TYPE);

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
    let sub0_type = sub_attrs[0].type_;
    assert_eq!(sub0_type, CkAttributeType::CLASS.0 as CK_ATTRIBUTE_TYPE);
    assert_eq!(sub_attrs[0].ulValueLen as usize, ulong_size);
    assert_eq!(
        CK_ULONG::from_le_bytes(class_buf[..ulong_size].try_into().unwrap()),
        class_value as CK_ULONG
    );
    let (sub1_type, sub1_len) = (sub_attrs[1].type_, sub_attrs[1].ulValueLen);
    assert_eq!(sub1_type, CkAttributeType::LABEL.0 as CK_ATTRIBUTE_TYPE);
    assert_eq!(sub1_len, CK_UNAVAILABLE_INFORMATION);
    assert_eq!(short_label_buf, [0xBB; 2], "too-small nested buffer must not be copied");
}

#[test]
fn raw_client_nested_template_size_query() {
    // Test the raw client path for nested template size query
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::start(MockAbi::host());

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");
        let object = client.create_object(session, Some(&[])).await.expect("C_CreateObject");

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
    let daemon = TestDaemon::start(MockAbi::host());

    daemon.block_on(async {
        let mut client = Pkcs11Client::connect(&daemon.endpoint).await.expect("connect client");
        client.initialize().await.expect("C_Initialize");

        let slot = client.get_slot_list(false).await.expect("C_GetSlotList")[0];
        let session = client
            .open_session(slot, CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .expect("C_OpenSession");
        let object = client.create_object(session, Some(&[])).await.expect("C_CreateObject");

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
        assert!(class_bytes.expose(|raw| raw == &class_value.to_le_bytes()[..ulong_size as usize]));

        assert_eq!(nested[1].attr_type, CkAttributeType::KEY_TYPE);
        assert_eq!(nested[1].returned_len, ulong_size);
        let key_type_bytes = nested[1].value.as_ref().expect("KEY_TYPE value");
        assert!(
            key_type_bytes
                .expose(|raw| raw == &key_type_value.to_le_bytes()[..ulong_size as usize])
        );

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
    let mut slots = vec![0 as CK_SLOT_ID; 0];
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
    // MockBackend has 5 mechanisms: SHA256, RSA_PKCS, AES_ECB, AES_GCM, AES_KEY_GEN.
    // Default registry is Transparent mode, so all 4 pass through.
    assert_eq!(count, 5, "expected 5 mechanisms from MockBackend (transparent mode)");

    // Fetch into a correctly sized buffer.
    let mut mechs = vec![0 as CK_MECHANISM_TYPE; count as usize];
    let mut fill_count = count;
    let rv2 = unsafe {
        dispatch::general::c_get_mechanism_list(shim.slot_id, mechs.as_mut_ptr(), &mut fill_count)
    };
    assert_eq!(rv2, CKR_OK as CK_RV, "C_GetMechanismList(fill)");
    assert_eq!(fill_count, count, "fill count should match count-only count");

    // Buffer-too-small: pass a buffer smaller than the actual count.
    let mut small_mechs = vec![0 as CK_MECHANISM_TYPE; 0];
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

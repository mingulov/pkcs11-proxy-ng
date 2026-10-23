use cryptoki_sys::{
    CK_FUNCTION_LIST_3_0, CK_INTERFACE, CK_VERSION, CKR_ARGUMENTS_BAD, CKR_OK, CKU_USER,
};
use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
use pkcs11_proxy_ng_shim::C_GetInterface;
use pkcs11_proxy_ng_types::{CkSlotId, InterfaceCapabilities, InterfaceInfo};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

// This integration target owns the shim's process-global configuration and
// runs one sequential test. No reset or process-sharing shortcuts are used.
struct TestDaemon {
    runtime: tokio::runtime::Runtime,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<tokio::task::JoinHandle<()>>,
    previous_env: Vec<(&'static str, Option<std::ffi::OsString>)>,
    backend: Arc<MockBackend>,
    requests: Arc<AtomicUsize>,
}

impl TestDaemon {
    fn start() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        backend.initialize().unwrap();
        backend.set_interface_capabilities(InterfaceCapabilities {
            interfaces: vec![InterfaceInfo {
                version_major: 3,
                version_minor: 0,
                null_functions: vec![],
            }],
        });
        let requests = Arc::new(AtomicUsize::new(0));
        let (endpoint, shutdown, server) = runtime.block_on(async {
            let backend_trait: Arc<dyn Pkcs11Backend> = backend.clone();
            let manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
            manager.populate_slots(&backend_trait).await.unwrap();
            let service = Pkcs11ProxyService::insecure_for_tests(manager, backend_trait);
            let counter = requests.clone();
            let service =
                Pkcs11ProxyServer::with_interceptor(service, move |request: tonic::Request<()>| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok(request)
                });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let (tx, rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(service)
                    .serve_with_incoming_shutdown(
                        tokio_stream::wrappers::TcpListenerStream::new(listener),
                        async {
                            let _ = rx.await;
                        },
                    )
                    .await
                    .unwrap();
            });
            (endpoint, tx, server)
        });
        let previous_env =
            ["PKCS11_PROXY_ENDPOINT", "PKCS11_PROXY_CONNECT_ATTEMPTS", "PKCS11_PROXY_SOCKET"]
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect();
        unsafe {
            std::env::set_var("PKCS11_PROXY_ENDPOINT", endpoint);
            std::env::set_var("PKCS11_PROXY_CONNECT_ATTEMPTS", "1");
            std::env::remove_var("PKCS11_PROXY_SOCKET");
        }
        Self {
            runtime,
            shutdown: Some(shutdown),
            server: Some(server),
            previous_env,
            backend,
            requests,
        }
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.server.take() {
            // The shim keeps a process-global transport channel after finalize.
            // All calls have settled; abort this test-only server rather than
            // waiting for that channel to close during graceful server drain.
            task.abort();
            self.runtime.block_on(async {
                let _ = task.await;
            });
        }
        for (key, value) in &self.previous_env {
            unsafe {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }
}

#[test]
fn null_nonzero_credentials_are_refused_at_every_abi_entrypoint() {
    let daemon = TestDaemon::start();
    let mut interface: *mut CK_INTERFACE = std::ptr::null_mut();
    let mut version = CK_VERSION { major: 3, minor: 0 };
    assert_eq!(
        unsafe { C_GetInterface(std::ptr::null_mut(), &mut version, &mut interface, 0) },
        CKR_OK
    );
    assert!(!interface.is_null());
    let table = unsafe { &*((*interface).pFunctionList.cast::<CK_FUNCTION_LIST_3_0>()) };
    let null: *mut u8 = std::ptr::null_mut();
    let mut label = [b' '; 32];
    let mut pin = *b"1234";

    // Positive controls use the same ABI table, live daemon, slot and session.
    // Backend credential entry is observed independently of the returned RV.
    assert_eq!(unsafe { (table.C_Initialize.unwrap())(null.cast()) }, CKR_OK);
    let mut slot = 0;
    let mut count = 1;
    assert_eq!(unsafe { (table.C_GetSlotList.unwrap())(0, &mut slot, &mut count) }, CKR_OK);
    assert_eq!(count, 1);
    assert_eq!(
        unsafe { (table.C_InitToken.unwrap())(slot, pin.as_mut_ptr(), 4, label.as_mut_ptr()) },
        CKR_OK
    );
    let mut session = 0;
    assert_eq!(
        unsafe {
            (table.C_OpenSession.unwrap())(
                slot,
                cryptoki_sys::CKF_SERIAL_SESSION | cryptoki_sys::CKF_RW_SESSION,
                null.cast(),
                None,
                &mut session,
            )
        },
        CKR_OK
    );
    assert_eq!(unsafe { (table.C_InitPIN.unwrap())(session, pin.as_mut_ptr(), 4) }, CKR_OK);
    assert_eq!(
        unsafe { (table.C_SetPIN.unwrap())(session, pin.as_mut_ptr(), 4, pin.as_mut_ptr(), 4) },
        CKR_OK
    );
    assert_eq!(unsafe { (table.C_Login.unwrap())(session, CKU_USER, pin.as_mut_ptr(), 4) }, CKR_OK);
    assert_eq!(daemon.backend.login_call_count(), 1);
    assert_eq!(unsafe { (table.C_Logout.unwrap())(session) }, CKR_OK);
    assert_eq!(
        unsafe {
            (table.C_LoginUser.unwrap())(
                session,
                CKU_USER,
                pin.as_mut_ptr(),
                4,
                pin.as_mut_ptr(),
                4,
            )
        },
        CKR_OK
    );
    assert_eq!(daemon.backend.login_user_call_count(), 1);
    assert_eq!(unsafe { (table.C_Logout.unwrap())(session) }, CKR_OK);
    let before = daemon.requests.load(Ordering::SeqCst);

    // These calls must fail before looking up a client or contacting a token.
    // Replacing any credential reader with the general optional-byte reader
    // would flatten the claimed nonzero length and bypass this boundary.
    let results = unsafe {
        [
            ("C_InitToken", (table.C_InitToken.unwrap())(slot, null, 8, label.as_mut_ptr())),
            ("C_InitPIN", (table.C_InitPIN.unwrap())(session, null, 8)),
            ("C_SetPIN old", (table.C_SetPIN.unwrap())(session, null, 8, pin.as_mut_ptr(), 4)),
            ("C_SetPIN new", (table.C_SetPIN.unwrap())(session, pin.as_mut_ptr(), 4, null, 8)),
            ("C_Login", (table.C_Login.unwrap())(session, CKU_USER, null, 8)),
            (
                "C_LoginUser PIN",
                (table.C_LoginUser.unwrap())(session, CKU_USER, null, 8, pin.as_mut_ptr(), 4),
            ),
            (
                "C_LoginUser username",
                (table.C_LoginUser.unwrap())(session, CKU_USER, pin.as_mut_ptr(), 4, null, 8),
            ),
        ]
    };
    assert_eq!(
        daemon.requests.load(Ordering::SeqCst),
        before,
        "invalid credentials must emit no RPC"
    );
    for (entrypoint, rv) in results {
        assert_eq!(rv, CKR_ARGUMENTS_BAD, "{entrypoint} must reject the unsupported shape");
    }
    assert_eq!(daemon.backend.login_call_count(), 1);
    assert_eq!(daemon.backend.login_user_call_count(), 1);
    assert_eq!(unsafe { (table.C_CloseSession.unwrap())(session) }, CKR_OK);
    assert_eq!(unsafe { (table.C_Finalize.unwrap())(null.cast()) }, CKR_OK);
}

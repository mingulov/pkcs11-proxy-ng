//! Real-kryoptic FIX-1 proof: NULL-vs-empty `C_GetAttributeValue` template
//! classes through the full proxy stack.
//!
//! The `output_semantics.rs` presence test drives the shim against
//! `MockBackend`, which answers empty-equivalently for both classes. These
//! tests drive the same shim FFI (`C_GetAttributeValue`) against a real
//! provider that distinguishes them: an in-process daemon backed by real
//! kryoptic (`FfiBackend`), mirroring the `softhsm_gcm.rs` pattern.
//! Native ground truth (probed directly against the provider):
//! `(NULL, 0)` answers `CKR_ARGUMENTS_BAD` while `(non-NULL, 0)` answers
//! `CKR_OK` — the proxy must reproduce both exactly. Run with:
//!
//! ```text
//! PKCS11_PROXY_KRYOPTIC_MODULE=/path/to/libkryoptic_pkcs11.so \
//!   cargo test -p pkcs11-proxy-ng-shim --lib -- --ignored kryoptic_gav_null
//! ```
//!
//! Both tests are `#[ignore]`, so default CI runs stay green without the
//! provider. If you opt in with `--ignored` but the module is missing, the
//! fixture panics with instructions rather than passing silently (L14).

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::{FfiBackend, Pkcs11Backend};
use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
use pkcs11_proxy_ng_types::{CkSessionFlags, CkUserType};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::watch;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use super::*;

const USER_PIN: &str = "1234";
const SO_PIN: &str = "87654321";
const TOKEN_LABEL: &str = "fix1-proof";

fn kryoptic_module_path() -> PathBuf {
    let path = std::env::var_os("PKCS11_PROXY_KRYOPTIC_MODULE").unwrap_or_else(|| {
        panic!(
            "PKCS11_PROXY_KRYOPTIC_MODULE is not set. This #[ignore] test requires real \
             kryoptic: set it to libkryoptic_pkcs11.so and re-run with `-- --ignored`. \
             (Refusing to pass silently — L14.)"
        )
    });
    let path = PathBuf::from(path);
    assert!(
        path.exists(),
        "PKCS11_PROXY_KRYOPTIC_MODULE points to a missing path: {} (L14)",
        path.display()
    );
    path
}

/// An isolated kryoptic token: tempdir + `token.sql` database path, passed
/// as the provider init args. Token provisioning (init/add PINs) happens
/// through the `Pkcs11Backend` trait during daemon bring-up.
struct KryopticToken {
    _temp_dir: tempfile::TempDir,
    db_path: String,
}

impl KryopticToken {
    fn init() -> Self {
        let temp_dir = tempfile::tempdir().expect("tempdir for kryoptic token");
        let db_path = temp_dir.path().join("token.sql").display().to_string();
        Self { _temp_dir: temp_dir, db_path }
    }
}

/// In-process daemon backed by real kryoptic (one per test process).
/// Mirrors `output_semantics::TestDaemon`, with `FfiBackend` in place of
/// `MockBackend`, and `DaemonHarness::start` for the FFI bring-up order
/// (load → `initialize` → provision → `populate_slots` → serve).
struct KryopticDaemon {
    _runtime: Runtime,
    endpoint: String,
    _backend: Arc<FfiBackend>,
    _token: KryopticToken,
    _shutdown: watch::Sender<bool>,
}

static KRYOPTIC_DAEMON: OnceLock<KryopticDaemon> = OnceLock::new();

fn kryoptic_daemon() -> &'static KryopticDaemon {
    KRYOPTIC_DAEMON.get_or_init(|| {
        let token = KryopticToken::init();
        let module_path = kryoptic_module_path();
        let runtime = Runtime::new().expect("test runtime");
        let (endpoint, backend, shutdown) = runtime.block_on(async {
            let backend = Arc::new(
                FfiBackend::load_with_init_args(&module_path, Some(&token.db_path))
                    .unwrap_or_else(|e| panic!("load {}: {e}", module_path.display())),
            );
            backend.initialize().unwrap_or_else(|rv| panic!("kryoptic C_Initialize failed: {rv}"));
            let slots = backend
                .get_slot_list(false)
                .unwrap_or_else(|rv| panic!("kryoptic C_GetSlotList failed: {rv}"));
            let slot = *slots.first().expect("kryoptic must expose a slot");
            backend
                .init_token(slot, Some(SO_PIN.as_bytes()), TOKEN_LABEL)
                .unwrap_or_else(|rv| panic!("kryoptic C_InitToken failed: {rv}"));
            let flags =
                CkSessionFlags(CkSessionFlags::SERIAL_SESSION.0 | CkSessionFlags::RW_SESSION.0);
            let session = backend
                .open_session(slot, flags)
                .unwrap_or_else(|rv| panic!("kryoptic C_OpenSession failed: {rv}"));
            backend
                .login(session, CkUserType::So, Some(SO_PIN.as_bytes()))
                .unwrap_or_else(|rv| panic!("kryoptic SO C_Login failed: {rv}"));
            backend
                .init_pin(session, Some(USER_PIN.as_bytes()))
                .unwrap_or_else(|rv| panic!("kryoptic C_InitPIN failed: {rv}"));
            backend
                .logout(session)
                .unwrap_or_else(|rv| panic!("kryoptic SO C_Logout failed: {rv}"));
            backend
                .close_session(session)
                .unwrap_or_else(|rv| panic!("kryoptic C_CloseSession failed: {rv}"));
            let backend_obj: Arc<dyn Pkcs11Backend> = backend.clone();
            let context_manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
            context_manager
                .populate_slots(&backend_obj)
                .await
                .unwrap_or_else(|rv| panic!("populate_slots failed: {rv}"));
            let service = Pkcs11ProxyService::insecure_for_tests(context_manager, backend_obj);
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
            (endpoint, backend, shutdown_tx)
        });
        KryopticDaemon {
            _runtime: runtime,
            endpoint,
            _backend: backend,
            _token: token,
            _shutdown: shutdown,
        }
    })
}

/// Logged-in user session on the kryoptic token slot.
struct KryopticSession {
    session: CK_SESSION_HANDLE,
}

impl KryopticSession {
    fn open() -> Self {
        let daemon = kryoptic_daemon();
        unsafe {
            std::env::set_var("PKCS11_PROXY_ENDPOINT", &daemon.endpoint);
        }
        let init_rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
        assert_eq!(init_rv, CKR_OK as CK_RV, "C_Initialize");

        let mut slot_count = 0;
        let slot_count_rv = unsafe {
            dispatch::general::c_get_slot_list(CK_TRUE, std::ptr::null_mut(), &mut slot_count)
        };
        assert_eq!(slot_count_rv, CKR_OK as CK_RV, "C_GetSlotList(count)");
        assert!(slot_count > 0, "expected a token-present slot");
        let mut slots = vec![0 as CK_SLOT_ID; slot_count as usize];
        let slot_list_rv = unsafe {
            dispatch::general::c_get_slot_list(CK_TRUE, slots.as_mut_ptr(), &mut slot_count)
        };
        assert_eq!(slot_list_rv, CKR_OK as CK_RV, "C_GetSlotList(data)");
        let slot = slots[0];

        let mut session = CK_INVALID_HANDLE;
        let open_rv = unsafe {
            dispatch::general::c_open_session(
                slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                std::ptr::null_mut(),
                None,
                &mut session,
            )
        };
        assert_eq!(open_rv, CKR_OK as CK_RV, "C_OpenSession");

        let mut pin = USER_PIN.as_bytes().to_vec();
        let login_rv = unsafe {
            dispatch::general::c_login(session, CKU_USER, pin.as_mut_ptr(), pin.len() as CK_ULONG)
        };
        assert_eq!(login_rv, CKR_OK as CK_RV, "C_Login");
        Self { session }
    }
}

impl Drop for KryopticSession {
    fn drop(&mut self) {
        if self.session != CK_INVALID_HANDLE {
            let _ = unsafe { dispatch::general::c_close_session(self.session) };
        }
        let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    }
}

fn create_generic_secret(session: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let mut class: CK_OBJECT_CLASS = CKO_SECRET_KEY;
    let mut key_type: CK_KEY_TYPE = CKK_GENERIC_SECRET;
    let mut value = *b"0123456789abcdef";
    let mut token: CK_BBOOL = CK_FALSE;
    let mut template = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN,
            pValue: &mut token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut key = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_create_object(
            session,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut key,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CreateObject(generic secret)");
    assert_ne!(key, CK_INVALID_HANDLE, "key handle");
    key
}

/// FIX-1 real-backend proof: kryoptic answers `CKR_ARGUMENTS_BAD` for a
/// caller-NULL template with zero count, and the proxy must reproduce that
/// exact RV (pre-fix the proxy flattened NULL to an empty template and the
/// backend answered `CKR_OK`).
#[ignore] // requires real kryoptic (PKCS11_PROXY_KRYOPTIC_MODULE)
#[test]
fn kryoptic_gav_null_zero_returns_arguments_bad() {
    let _guard = shim_state_test_guard();
    kryoptic_daemon();
    let shim = KryopticSession::open();
    let key = create_generic_secret(shim.session);

    let rv = unsafe {
        dispatch::general::c_get_attribute_value(shim.session, key, std::ptr::null_mut(), 0)
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV, "proxied kryoptic GAV(NULL, 0)");
}

/// FIX-1 real-backend proof (companion): an explicit empty template —
/// non-NULL pointer with zero count — still answers `CKR_OK` through the
/// proxy, exactly as native kryoptic does.
#[ignore] // requires real kryoptic (PKCS11_PROXY_KRYOPTIC_MODULE)
#[test]
fn kryoptic_gav_empty_template_returns_ok() {
    let _guard = shim_state_test_guard();
    kryoptic_daemon();
    let shim = KryopticSession::open();
    let key = create_generic_secret(shim.session);

    let mut empty = [0u8; 1];
    let rv = unsafe {
        dispatch::general::c_get_attribute_value(
            shim.session,
            key,
            empty.as_mut_ptr() as CK_ATTRIBUTE_PTR,
            0,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "proxied kryoptic GAV(ptr, 0)");
}

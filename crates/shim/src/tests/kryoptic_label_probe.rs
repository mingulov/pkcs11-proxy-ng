//! Q03: kryoptic `C_InitToken` label outcomes — DIRECT native ground
//! truth plus the live-provider proxy-stack sweep, in an isolated
//! child process (never a user token).
//!
//! This promotes the throwaway `/tmp` ctypes probe
//! (`record-q03p2-kryoptic-label-outcomes.log`) to an in-tree test.
//! Phase A calls stock kryoptic DIRECTLY — through the provider
//! function table via `libloading`, bypassing both the proxy and
//! `FfiBackend` — against a disposable tempdir `token.sql` database,
//! pinning what the provider itself does with each label vector
//! (notably: kryoptic ACCEPTS a NULL label with `CKR_OK` and stores
//! 32 spaces, where stock SoftHSM2 refuses with
//! `CKR_ARGUMENTS_BAD` — provider-decides ground truth). Phase B
//! runs the same vectors through the full proxy stack (shim
//! `C_InitToken` → daemon → `FfiBackend` → kryoptic, read back
//! through shim `C_GetTokenInfo`) for live-provider exact-label
//! coverage toward the 7-vector sweep.
//!
//! Run the PARENT only (it spawns the child itself):
//!
//! ```text
//! PKCS11_PROXY_KRYOPTIC_MODULE=/path/to/libkryoptic_pkcs11.so \
//! LD_LIBRARY_PATH=/path/to/kryodeps/lib \
//!   cargo test -p pkcs11-proxy-ng-shim --lib -- --ignored \
//!   kryoptic_label_probe::q03_kryoptic_label_outcomes --nocapture
//! ```
//!
//! If the module was built against a non-system OpenSSL, put its
//! `libcrypto.so.4` on the loader path too (same as
//! `kryoptic_gav_null.rs`).
//!
//! Both tests are `#[ignore]`, so default CI runs stay green without
//! the provider. If you opt in with `--ignored` but the module is
//! missing, the fixture panics with instructions rather than passing
//! silently (L14).
//!
//! Process isolation (finding 3 / B3): the parent test spawns a FRESH
//! child process (this same test binary, filtered to the child test)
//! and asserts on its exit status and recording lines. The child
//! owns the kryoptic `C_Initialize`/`C_Finalize` cycles and the
//! in-process daemon alone in its process — no coordination with the
//! `kryoptic_gav_null` / `softhsm_gcm` process-lifetime providers is
//! needed, and parallel execution cannot race provider globals. The
//! child-role guard refuses direct selection before any provider
//! contact.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::{FfiBackend, Pkcs11Backend};
use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
use pkcs11_proxy_ng_types::{InitTokenLabel, PKCS11_TOKEN_LABEL_LEN};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::watch;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use super::output_semantics::ShimSession;
use super::*;

/// Q03: kryoptic label outcomes via a fresh child process (see the
/// module docs). Observed on the recorded kryoptic build (module
/// `sha256:a6fed76a…cdbe`; recording log
/// `record-q03p2-kryoptic-label-outcomes.log`):
///
/// - DIRECT valid vectors (trailing TAB, ASCII, multibyte, full-32,
///   NBSP, all-spaces, embedded/terminal NUL): `CKR_OK`, stored
///   verbatim;
/// - DIRECT invalid UTF-8 (`BAD\xff\xfe`): `CKR_OK`, stored verbatim;
/// - DIRECT NULL label: `CKR_OK`, stores 32 spaces (kryoptic accepts
///   NULL — the SoftHSM2-contrast ground truth);
/// - PROXY sweep: every valid vector round-trips byte-exact through
///   the full stack; invalid bytes store verbatim (read back through
///   the documented lossy `String` path); NULL is accepted and reads
///   back as 32 spaces.
///
/// This parent only spawns the child and checks its exit status plus
/// the `Q03-KRYOPTIC-*` recording lines; the child owns all provider
/// contact. It marks the child with the `Q03_PROBE_CHILD_ROLE`
/// sentinel the child-role guard requires (B3).
#[ignore]
#[test]
fn q03_kryoptic_label_outcomes() {
    let exe = std::env::current_exe().expect("current test binary");
    let output = std::process::Command::new(exe)
        .arg("--exact")
        .arg("tests::kryoptic_label_probe::q03_kryoptic_label_probe_child")
        .arg("--nocapture")
        .arg("--ignored")
        .env(Q03_PROBE_CHILD_ROLE, "1")
        .output()
        .expect("spawn the isolated probe child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "isolated probe child must pass exactly its test (status: {:?}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status.code()
    );
    for line in [
        "Q03-KRYOPTIC-DIRECT valid-trailing-tab: rv=0x0",
        "Q03-KRYOPTIC-DIRECT invalid-utf8: rv=0x0",
        "Q03-KRYOPTIC-DIRECT null-label: rv=0x0",
        "Q03-KRYOPTIC-PROXY sweep-complete",
    ] {
        assert!(stderr.contains(line), "child must record {line}:\n--- stderr ---\n{stderr}");
    }
}

/// Q03 (B3): direct selection of the probe child must refuse
/// BEFORE any provider contact — no kryoptic load, no
/// `C_Initialize`, no `Q03-KRYOPTIC-*` recording lines. Runs
/// un-ignored: the guard fires before the provider search, so no
/// provider is needed.
#[test]
fn q03_kryoptic_label_probe_child_refuses_direct_selection() {
    let exe = std::env::current_exe().expect("current test binary");
    let output = std::process::Command::new(exe)
        .arg("--exact")
        .arg("tests::kryoptic_label_probe::q03_kryoptic_label_probe_child")
        .arg("--nocapture")
        .arg("--ignored")
        .env_remove(Q03_PROBE_CHILD_ROLE)
        .output()
        .expect("spawn the directly selected probe child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "directly selected probe child must refuse (status: {:?}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status.code()
    );
    assert!(
        stderr.contains(Q03_PROBE_CHILD_ROLE),
        "refusal must come from the child-role guard:\n--- stderr ---\n{stderr}"
    );
    assert!(
        !stderr.contains("Q03-KRYOPTIC-"),
        "no probe body may run on the direct path:\n--- stderr ---\n{stderr}"
    );
}

const Q03_KRYOPTIC_SO_PIN: &[u8] = b"87654321";

/// Live sweep vectors: (recording name, label prefix — padded to 32
/// with spaces). The mock 7-vector sweep plus the terminal-NUL
/// boundary (B2).
const Q03_KRYOPTIC_VECTORS: &[(&str, &[u8])] = &[
    ("valid-trailing-tab", b"A\t"),
    ("ascii", b"hello"),
    ("multibyte", "tökén-héllo".as_bytes()),
    ("full-32", b"0123456789abcdef0123456789abcdef"),
    ("trailing-nbsp", "B\u{a0}".as_bytes()),
    ("all-spaces", b""),
    ("embedded-nul", b"C\0D"),
    ("terminal-nul", b"C\0"),
];

fn q03_kryoptic_pad(prefix: &[u8]) -> [u8; PKCS11_TOKEN_LABEL_LEN] {
    assert!(prefix.len() <= PKCS11_TOKEN_LABEL_LEN);
    let mut label = [b' '; PKCS11_TOKEN_LABEL_LEN];
    label[..prefix.len()].copy_from_slice(prefix);
    label
}

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

/// A disposable kryoptic database: tempdir + `token.sql` path, passed
/// as the provider init args. Owns nothing process-global (kryoptic
/// takes its database through `C_Initialize` args, not the
/// environment).
struct Q03KryopticDb {
    _temp_dir: tempfile::TempDir,
    db: std::ffi::CString,
}

impl Q03KryopticDb {
    fn fresh() -> Self {
        let temp_dir = tempfile::tempdir().expect("tempdir for kryoptic token.sql");
        let db_path = temp_dir.path().join("token.sql").display().to_string();
        let db = std::ffi::CString::new(db_path).expect("db path has no interior NUL");
        Self { _temp_dir: temp_dir, db }
    }
}

/// Direct provider table: no proxy, no `FfiBackend` — the table calls are
/// exactly what a native application would issue.
struct Q03KryopticDirect {
    _lib: libloading::Library,
    table: CK_FUNCTION_LIST_PTR,
}

impl Q03KryopticDirect {
    fn load() -> Self {
        let module = kryoptic_module_path();
        let lib = unsafe { libloading::Library::new(&module) }
            .unwrap_or_else(|e| panic!("load {}: {e}", module.display()));
        type GetFunctionList = unsafe extern "C" fn(*mut CK_FUNCTION_LIST_PTR) -> CK_RV;
        let get_list: libloading::Symbol<GetFunctionList> =
            unsafe { lib.get(b"C_GetFunctionList") }.expect("C_GetFunctionList symbol");
        let mut table: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
        let rv = unsafe { get_list(&mut table) };
        assert_eq!(rv, CKR_OK as CK_RV, "direct C_GetFunctionList");
        assert!(!table.is_null(), "provider returned a function table");
        Self { _lib: lib, table }
    }

    fn initialize(&self, db: &std::ffi::CStr) {
        // Same args shape as `FfiBackend::initialize`: OS locking, the
        // database path as the library-parameters string.
        let mut args = CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: CKF_OS_LOCKING_OK,
            pReserved: db.as_ptr() as *mut _,
        };
        let rv = unsafe { (*self.table).C_Initialize.unwrap()(&mut args as *mut _ as CK_VOID_PTR) };
        assert_eq!(rv, CKR_OK as CK_RV, "direct C_Initialize");
    }

    fn finalize(&self) {
        let rv = unsafe { (*self.table).C_Finalize.unwrap()(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_OK as CK_RV, "direct C_Finalize");
    }

    fn token_present_slot(&self) -> CK_SLOT_ID {
        let mut count = 0;
        let rv = unsafe {
            (*self.table).C_GetSlotList.unwrap()(CK_TRUE, std::ptr::null_mut(), &mut count)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "direct C_GetSlotList(count)");
        assert!(count > 0, "kryoptic exposes a token-present slot");
        let mut slots = vec![0 as CK_SLOT_ID; count as usize];
        let rv = unsafe {
            (*self.table).C_GetSlotList.unwrap()(CK_TRUE, slots.as_mut_ptr(), &mut count)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "direct C_GetSlotList(data)");
        slots[0]
    }

    fn init_token_direct(&self, slot: CK_SLOT_ID, so_pin: &[u8], label: *mut CK_UTF8CHAR) -> CK_RV {
        unsafe {
            (*self.table).C_InitToken.unwrap()(
                slot,
                so_pin.as_ptr() as *mut _,
                so_pin.len() as CK_ULONG,
                label,
            )
        }
    }

    fn token_label_bytes(&self, slot: CK_SLOT_ID) -> [u8; PKCS11_TOKEN_LABEL_LEN] {
        let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
        let rv = unsafe { (*self.table).C_GetTokenInfo.unwrap()(slot, &mut info) };
        assert_eq!(rv, CKR_OK as CK_RV, "direct C_GetTokenInfo");
        info.label
    }
}

/// Phase A: DIRECT native outcomes (ground truth, pinned).
#[allow(clippy::print_stderr)]
fn q03_kryoptic_direct_phase() {
    let db_holder = Q03KryopticDb::fresh();
    let provider = Q03KryopticDirect::load();
    provider.initialize(&db_holder.db);
    let slot = provider.token_present_slot();
    let so_pin = Q03_KRYOPTIC_SO_PIN;

    for (name, prefix) in Q03_KRYOPTIC_VECTORS {
        let mut label = q03_kryoptic_pad(prefix);
        let rv = provider.init_token_direct(slot, so_pin, label.as_mut_ptr() as *mut _);
        let back = provider.token_label_bytes(slot);
        eprintln!("Q03-KRYOPTIC-DIRECT {name}: rv={rv:#x} stored={back:02x?}");
        assert_eq!(rv, CKR_OK as CK_RV, "kryoptic accepts {name}");
        assert_eq!(back, label, "kryoptic stores {name} verbatim");
    }

    // Invalid UTF-8 bytes: accepted and stored verbatim.
    let mut bad = q03_kryoptic_pad(b"BAD\xff\xfe");
    let rv_bad = provider.init_token_direct(slot, so_pin, bad.as_mut_ptr() as *mut _);
    let back_bad = provider.token_label_bytes(slot);
    eprintln!("Q03-KRYOPTIC-DIRECT invalid-utf8: rv={rv_bad:#x} stored={back_bad:02x?}");
    assert_eq!(rv_bad, CKR_OK as CK_RV, "kryoptic accepts invalid-UTF-8 label bytes");
    assert_eq!(back_bad, bad, "kryoptic stores invalid-UTF-8 label bytes verbatim");

    // NULL label LAST (crash-risk order): kryoptic ACCEPTS it with
    // `CKR_OK` and stores 32 spaces — the SoftHSM2-contrast ground
    // truth for provider-decides.
    let rv_null = provider.init_token_direct(slot, so_pin, std::ptr::null_mut());
    let back_null = provider.token_label_bytes(slot);
    eprintln!("Q03-KRYOPTIC-DIRECT null-label: rv={rv_null:#x} stored={back_null:02x?}");
    assert_eq!(rv_null, CKR_OK as CK_RV, "kryoptic accepts a NULL label with CKR_OK");
    assert_eq!(back_null, [b' '; PKCS11_TOKEN_LABEL_LEN], "kryoptic NULL-label stores 32 spaces");

    provider.finalize();
}

/// Phase B: live-provider proxy-stack sweep — shim `C_InitToken` →
/// daemon → `FfiBackend` → kryoptic, read back through shim
/// `C_GetTokenInfo`. Own daemon on a fresh database (Phase A
/// finalized); the child process owns every provider global alone.
#[allow(clippy::print_stderr)]
fn q03_kryoptic_proxy_phase() {
    let _guard = shim_state_test_guard();
    let temp_dir = tempfile::tempdir().expect("tempdir for kryoptic proxy token");
    let db_path = temp_dir.path().join("token.sql").display().to_string();
    let module = kryoptic_module_path();
    let runtime = Runtime::new().expect("test runtime");
    let (endpoint, backend, _shutdown) = runtime.block_on(async {
        let backend = Arc::new(
            FfiBackend::load_with_init_args(&module, Some(&db_path))
                .unwrap_or_else(|e| panic!("load {}: {e}", module.display())),
        );
        backend.initialize().unwrap_or_else(|rv| panic!("kryoptic C_Initialize failed: {rv}"));
        let slots =
            backend.get_slot_list(false).unwrap_or_else(|rv| panic!("C_GetSlotList failed: {rv}"));
        let slot = *slots.first().expect("kryoptic must expose a slot");
        backend
            .init_token(slot, Some(Q03_KRYOPTIC_SO_PIN), InitTokenLabel::text_only("Q03BASE"))
            .unwrap_or_else(|rv| panic!("kryoptic provision C_InitToken failed: {rv}"));
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

    // The shim session lives in this scope so its `Drop`
    // (`C_Finalize`, releasing the server context) runs BEFORE the
    // native backend finalizes below.
    {
        let mut shim = ShimSession::with_endpoint(&endpoint);
        // kryoptic (unlike the mock) refuses `C_InitToken` while
        // sessions are open (`CKR_SESSION_EXISTS`): the sweep needs
        // none, so close it up front (neutralized for the `Drop`
        // close below).
        let close_rv = unsafe { dispatch::general::c_close_session(shim.session) };
        assert_eq!(close_rv, CKR_OK as CK_RV, "close the unneeded session");
        shim.session = CK_INVALID_HANDLE;
        let so_pin = Q03_KRYOPTIC_SO_PIN;
        let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };

        for (name, prefix) in Q03_KRYOPTIC_VECTORS {
            let mut label = q03_kryoptic_pad(prefix);
            let rv = unsafe {
                dispatch::general::c_init_token(
                    shim.slot_id,
                    so_pin.as_ptr() as *mut _,
                    so_pin.len() as CK_ULONG,
                    label.as_mut_ptr() as *mut _,
                )
            };
            let get_rv = unsafe { dispatch::general::c_get_token_info(shim.slot_id, &mut info) };
            eprintln!(
                "Q03-KRYOPTIC-PROXY {name}: rv={rv:#x} get_rv={get_rv:#x} stored={:02x?}",
                info.label
            );
            assert_eq!(rv, CKR_OK as CK_RV, "proxy C_InitToken({name}) succeeds");
            assert_eq!(get_rv, CKR_OK as CK_RV, "proxy C_GetTokenInfo({name}) succeeds");
            assert_eq!(info.label, label, "proxy round-trips {name} byte-exact");
        }

        // Invalid UTF-8: stored verbatim, read back through the
        // documented lossy `String` path (live-provider edition of the
        // mock limit pin).
        let mut bad = q03_kryoptic_pad(b"BAD\xff\xfe");
        let rv_bad = unsafe {
            dispatch::general::c_init_token(
                shim.slot_id,
                so_pin.as_ptr() as *mut _,
                so_pin.len() as CK_ULONG,
                bad.as_mut_ptr() as *mut _,
            )
        };
        let get_rv_bad = unsafe { dispatch::general::c_get_token_info(shim.slot_id, &mut info) };
        eprintln!(
            "Q03-KRYOPTIC-PROXY invalid-utf8: rv={rv_bad:#x} get_rv={get_rv_bad:#x} stored={:02x?}",
            info.label
        );
        assert_eq!(rv_bad, CKR_OK as CK_RV, "proxy C_InitToken(invalid-utf8) succeeds");
        assert_eq!(get_rv_bad, CKR_OK as CK_RV, "proxy C_GetTokenInfo(invalid-utf8) succeeds");
        assert_eq!(
            info.label,
            q03_kryoptic_pad("BAD\u{fffd}\u{fffd}".as_bytes()),
            "live readback shows the compat text (documented lossy-readback limit)"
        );

        // NULL: accepted with `CKR_OK`, reads back as 32 spaces.
        let rv_null = unsafe {
            dispatch::general::c_init_token(
                shim.slot_id,
                so_pin.as_ptr() as *mut _,
                so_pin.len() as CK_ULONG,
                std::ptr::null_mut(),
            )
        };
        let get_rv_null = unsafe { dispatch::general::c_get_token_info(shim.slot_id, &mut info) };
        eprintln!(
            "Q03-KRYOPTIC-PROXY null-label: rv={rv_null:#x} get_rv={get_rv_null:#x} stored={:02x?}",
            info.label
        );
        assert_eq!(rv_null, CKR_OK as CK_RV, "proxy C_InitToken(NULL) succeeds (provider accepts)");
        assert_eq!(get_rv_null, CKR_OK as CK_RV, "proxy C_GetTokenInfo(NULL) succeeds");
        assert_eq!(
            info.label, [b' '; PKCS11_TOKEN_LABEL_LEN],
            "NULL-label acceptance reads back as 32 spaces"
        );

        eprintln!("Q03-KRYOPTIC-PROXY sweep-complete");
    }

    // Quiesce the native backend before its final-owner `Drop`: an
    // initialized backend dropped without finalize trips the
    // abnormal-stop guard (exit 70). No native sessions remain (the
    // sweep session closed up front; the shim `Drop` above released
    // the server context).
    backend.finalize().unwrap_or_else(|rv| panic!("kryoptic C_Finalize failed: {rv}"));
}

/// The isolated probe body: runs ONLY in the fresh child process
/// spawned above. Direct selection (explicit filter) refuses via the
/// child-role guard before any provider contact (B3).
///
/// Phase A records DIRECT native outcomes; phase B the live-provider
/// proxy-stack sweep. Recording lines use `eprintln!` (unbuffered) so
/// a provider crash in a later case cannot swallow an earlier case's
/// outcome. Cases run in ascending crash-risk order: valid controls
/// first, NULL last.
#[ignore]
#[test]
// Recording output (read with `-- --nocapture`); production code stays
// under the workspace print/dbg deny.
#[allow(clippy::print_stderr)]
fn q03_kryoptic_label_probe_child() {
    require_q03_probe_child_role();
    q03_kryoptic_direct_phase();
    q03_kryoptic_proxy_phase();
}

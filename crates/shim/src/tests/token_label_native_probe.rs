//! Q03: DIRECT native `C_InitToken` label outcomes on a disposable
//! stock-SoftHSM2 token (never a user token).
//!
//! This probe records what stock SoftHSM2 does with NULL,
//! invalid-encoding, and valid whitespace label bytes when called
//! DIRECTLY — through the provider function table via `libloading`,
//! bypassing both the proxy and `FfiBackend` — so the proxy's
//! provider-decides contract has native ground truth. Run the PARENT
//! only (it spawns the child itself):
//!
//! ```text
//! cargo test -p pkcs11-proxy-ng-shim --lib -- --ignored \
//!   token_label_native_probe::q03_direct_native_init_token_label_outcomes --nocapture
//! ```
//!
//! Selecting the child directly refuses via the child-role guard
//! (B3) — the provider-contact body runs exclusively in the
//! parent-spawned process.
//!
//! Both tests are `#[ignore]`, so default CI runs stay green without
//! the provider. If you opt in with `--ignored` but SoftHSM2 is
//! missing, the fixture panics with instructions rather than passing
//! silently (L14). Observed values are pinned in-code as native
//! ground truth (the kryoptic GAV-NULL precedent); the input-contract
//! note cites the recording log under
//! `doc/plans/evidence/2026-10-13-q03-labels/`.
//!
//! Process isolation (finding 3): the parent test spawns a FRESH
//! child process (this same test binary, filtered to the child test)
//! and asserts on its exit status and recording lines. The child
//! owns `SOFTHSM2_CONF` and the provider lifetime alone in its
//! process — no coordination with other SoftHSM tests' env windows
//! or process-lifetime provider handles is needed, and parallel
//! execution cannot race configuration changes. The parent itself
//! touches no process-global state (it even strips any inherited
//! `SOFTHSM2_CONF` from the child env).
//!
//! The child runs two phases: DIRECT native outcomes (ground truth,
//! pinned) and a live-provider PROXY-stack sweep (shim `C_InitToken`
//! → daemon → `FfiBackend` → SoftHSM2, read back through shim
//! `C_GetTokenInfo`) toward the 7-vector sweep.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::{FfiBackend, Pkcs11Backend};
use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::watch;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use super::output_semantics::ShimSession;
use super::*;

/// System search list for stock `libsofthsm2.so` (same list as the
/// server-suite `ProviderFixture` and `softhsm_gcm.rs`).
const SOFTHSM_MODULE_CANDIDATES: &[&str] = &[
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
    "/usr/lib64/libsofthsm2.so",
];

fn softhsm2_module_path() -> PathBuf {
    SOFTHSM_MODULE_CANDIDATES.iter().map(PathBuf::from).find(|p| p.exists()).unwrap_or_else(|| {
        panic!(
            "libsofthsm2.so not found (tried: {}). This #[ignore] test requires stock \
                 SoftHSM2: install softhsm2 (library + softhsm2-util) and re-run with \
                 `-- --ignored`. (Refusing to pass silently — L14.)",
            SOFTHSM_MODULE_CANDIDATES.join(", ")
        )
    })
}

/// An isolated stock-SoftHSM2 token: tempdir config + token store, created
/// with `softhsm2-util --init-token`. Owns `SOFTHSM2_CONF` for its lifetime.
struct Q03SoftHsmToken {
    _temp_dir: tempfile::TempDir,
    previous_conf: Option<OsString>,
}

impl Q03SoftHsmToken {
    fn init(label: &str) -> Self {
        let temp_dir = tempfile::tempdir().expect("tempdir for SoftHSM2 token");
        let conf_path = temp_dir.path().join("softhsm2.conf");
        let tokens_dir = temp_dir.path().join("tokens");
        std::fs::create_dir_all(&tokens_dir).expect("create SoftHSM2 tokens dir");
        std::fs::write(
            &conf_path,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\n",
                tokens_dir.display()
            ),
        )
        .expect("write softhsm2.conf");
        let previous_conf = std::env::var_os("SOFTHSM2_CONF");
        unsafe {
            std::env::set_var("SOFTHSM2_CONF", &conf_path);
        }
        let output = std::process::Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--slot",
                "0",
                "--label",
                label,
                "--pin",
                "1234",
                "--so-pin",
                "5678",
            ])
            .output()
            .expect("softhsm2-util launch failed — install softhsm2 to run this #[ignore] test");
        assert!(
            output.status.success(),
            "softhsm2-util --init-token failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self { _temp_dir: temp_dir, previous_conf }
    }
}

impl Drop for Q03SoftHsmToken {
    fn drop(&mut self) {
        unsafe {
            match self.previous_conf.take() {
                Some(v) => std::env::set_var("SOFTHSM2_CONF", v),
                None => std::env::remove_var("SOFTHSM2_CONF"),
            }
        }
    }
}

/// Direct provider table: no proxy, no `FfiBackend` — the table calls are
/// exactly what a native application would issue.
struct Q03DirectProvider {
    _lib: libloading::Library,
    table: CK_FUNCTION_LIST_PTR,
}

impl Q03DirectProvider {
    fn load() -> Self {
        let module = softhsm2_module_path();
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

    fn initialize(&self) {
        let rv = unsafe { (*self.table).C_Initialize.unwrap()(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_OK as CK_RV, "direct C_Initialize");
    }

    fn finalize(&self) {
        let rv = unsafe { (*self.table).C_Finalize.unwrap()(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_OK as CK_RV, "direct C_Finalize");
    }

    fn initialized_token_slot(&self) -> CK_SLOT_ID {
        let mut count = 0;
        let rv = unsafe {
            (*self.table).C_GetSlotList.unwrap()(CK_FALSE, std::ptr::null_mut(), &mut count)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "direct C_GetSlotList(count)");
        assert!(count > 0, "disposable provider exposes a slot");
        let mut slots = vec![0 as CK_SLOT_ID; count as usize];
        let rv = unsafe {
            (*self.table).C_GetSlotList.unwrap()(CK_FALSE, slots.as_mut_ptr(), &mut count)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "direct C_GetSlotList(data)");
        for slot in slots {
            let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
            let rv = unsafe { (*self.table).C_GetTokenInfo.unwrap()(slot, &mut info) };
            assert_eq!(rv, CKR_OK as CK_RV, "direct C_GetTokenInfo");
            if info.flags & CKF_TOKEN_INITIALIZED != 0 {
                return slot;
            }
        }
        panic!("no initialized token on the disposable provider");
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

    fn token_label_bytes(&self, slot: CK_SLOT_ID) -> [u8; 32] {
        let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
        let rv = unsafe { (*self.table).C_GetTokenInfo.unwrap()(slot, &mut info) };
        assert_eq!(rv, CKR_OK as CK_RV, "direct C_GetTokenInfo");
        info.label
    }
}

/// Q03: DIRECT native `C_InitToken` label outcomes (native ground
/// truth, pinned) — via a fresh child process.
///
/// Observed on stock SoftHSM2 2.6.1 (`/usr/lib/softhsm/libsofthsm2.so`;
/// recording log `record-q03-direct-native-outcomes.log`):
///
/// - trailing TAB: `CKR_OK`, stored verbatim — the provider accepts the
///   whitespace the pre-fix proxy stripped;
/// - invalid UTF-8 (`BAD\xff\xfe`): `CKR_OK`, stored verbatim — this
///   provider accepts arbitrary label bytes, so the proxy's exact-label
///   path preserves fidelity by forwarding them (see the
///   input-contract note);
/// - NUL-containing labels (`C\0D`, `C\0`): `CKR_OK`, NUL-truncated
///   (C-string semantics: `C` + 31 NULs) — unlike kryoptic's verbatim
///   store;
/// - NULL label: `CKR_ARGUMENTS_BAD` with the stored label unchanged.
///
/// The proxy-stack sweep then round-trips the same vectors through
/// the full stack, asserting provider semantics end to end
/// (byte-exact where the provider stores verbatim, NUL-truncated
/// readback for the NUL vectors, propagated `0x7` for NULL).
///
/// This parent only spawns the child and checks its exit status plus
/// the `Q03-DIRECT` recording lines; the child owns all provider
/// contact. It marks the child with the `Q03_PROBE_CHILD_ROLE`
/// sentinel the child-role guard requires (B3). Finding 3: no
/// process-global `SOFTHSM2_CONF` or provider coordination is needed
/// — the child is a fresh process.
#[ignore]
#[test]
fn q03_direct_native_init_token_label_outcomes() {
    let exe = std::env::current_exe().expect("current test binary");
    let output = std::process::Command::new(exe)
        .arg("--exact")
        .arg("tests::token_label_native_probe::q03_direct_native_probe_child")
        .arg("--nocapture")
        .arg("--ignored")
        .env_remove("SOFTHSM2_CONF")
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
    for (name, rv) in
        [("valid-trailing-tab", "0x0"), ("invalid-utf8", "0x0"), ("null-label", "0x7")]
    {
        assert!(
            stderr.contains(&format!("Q03-DIRECT {name}: rv={rv}")),
            "child must record Q03-DIRECT {name}: rv={rv}:\n--- stderr ---\n{stderr}"
        );
    }
    for line in ["Q03-SOFTHSM-PROXY null-label: rv=0x7", "Q03-SOFTHSM-PROXY sweep-complete"] {
        assert!(stderr.contains(line), "child must record {line}:\n--- stderr ---\n{stderr}");
    }
}

/// Q03 (B3): direct selection of the probe child must refuse
/// BEFORE any provider contact — no `SOFTHSM2_CONF` mutation, no
/// provider load, no `Q03-DIRECT` recording lines. Runs un-ignored:
/// the guard fires before the provider search, so no provider is
/// needed.
#[test]
fn q03_direct_native_probe_child_refuses_direct_selection() {
    let exe = std::env::current_exe().expect("current test binary");
    let output = std::process::Command::new(exe)
        .arg("--exact")
        .arg("tests::token_label_native_probe::q03_direct_native_probe_child")
        .arg("--nocapture")
        .arg("--ignored")
        .env_remove("SOFTHSM2_CONF")
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
        !stderr.contains("Q03-DIRECT"),
        "no probe body may run on the direct path:\n--- stderr ---\n{stderr}"
    );
    assert!(
        !stderr.contains("Q03-SOFTHSM-PROXY"),
        "no proxy sweep may run on the direct path:\n--- stderr ---\n{stderr}"
    );
}

/// The isolated probe body: runs ONLY in the fresh child process
/// spawned above. Direct selection (explicit filter) refuses via the
/// child-role guard before any provider contact (B3) — the body is
/// unreachable without the parent-set sentinel.
///
/// Recording lines use `eprintln!` (unbuffered) so a provider crash in a
/// later case cannot swallow an earlier case's outcome. Cases run in
/// ascending crash-risk order: valid control first, NULL last.
#[ignore]
#[test]
// Recording output (read with `-- --nocapture`); production code stays
// under the workspace print/dbg deny.
#[allow(clippy::print_stderr)]
fn q03_direct_native_probe_child() {
    require_q03_probe_child_role();
    let _token = Q03SoftHsmToken::init("Q03BASE");
    let provider = Q03DirectProvider::load();
    provider.initialize();
    let slot = provider.initialized_token_slot();
    let so_pin = b"5678";

    // (a) Valid control: a trailing TAB the mock round-trips — the real
    // provider accepts it verbatim.
    let mut tab = [b' '; 32];
    tab[0] = b'A';
    tab[1] = b'\t';
    let rv_tab = provider.init_token_direct(slot, so_pin, tab.as_mut_ptr() as *mut _);
    let back_tab = provider.token_label_bytes(slot);
    eprintln!("Q03-DIRECT valid-trailing-tab: rv={rv_tab:#x} stored={back_tab:02x?}");
    assert_eq!(rv_tab, CKR_OK as CK_RV, "SoftHSM2 accepts a trailing-TAB label");
    assert_eq!(back_tab, tab, "SoftHSM2 stores a trailing-TAB label verbatim");

    // (b) Invalid UTF-8 bytes: accepted and stored verbatim.
    let mut bad = [b' '; 32];
    bad[..5].copy_from_slice(b"BAD\xff\xfe");
    let rv_bad = provider.init_token_direct(slot, so_pin, bad.as_mut_ptr() as *mut _);
    let back_bad = provider.token_label_bytes(slot);
    eprintln!("Q03-DIRECT invalid-utf8: rv={rv_bad:#x} stored={back_bad:02x?}");
    assert_eq!(rv_bad, CKR_OK as CK_RV, "SoftHSM2 accepts invalid-UTF-8 label bytes");
    assert_eq!(back_bad, bad, "SoftHSM2 stores invalid-UTF-8 label bytes verbatim");

    // (c) NUL-containing labels: SoftHSM2 stores labels with
    // C-string semantics — bytes from the first NUL on are NUL
    // (truncation + NUL padding), unlike kryoptic's verbatim store.
    // The proxy forwards exactly and reads back exactly what the
    // provider stored.
    let mut nul_truncated = [0u8; 32];
    nul_truncated[0] = b'C';
    for (name, prefix) in [("embedded-nul", &b"C\0D"[..]), ("terminal-nul", &b"C\0"[..])] {
        let mut label = [b' '; 32];
        label[..prefix.len()].copy_from_slice(prefix);
        let rv = provider.init_token_direct(slot, so_pin, label.as_mut_ptr() as *mut _);
        let back = provider.token_label_bytes(slot);
        eprintln!("Q03-DIRECT {name}: rv={rv:#x} stored={back:02x?}");
        assert_eq!(rv, CKR_OK as CK_RV, "SoftHSM2 accepts {name}");
        assert_eq!(back, nul_truncated, "SoftHSM2 NUL-truncates {name}");
    }

    // (d) NULL label: clean refusal, stored label unchanged.
    let rv_null = provider.init_token_direct(slot, so_pin, std::ptr::null_mut());
    let back_null = provider.token_label_bytes(slot);
    eprintln!("Q03-DIRECT null-label: rv={rv_null:#x} stored={back_null:02x?}");
    assert_eq!(
        rv_null, CKR_ARGUMENTS_BAD as CK_RV,
        "SoftHSM2 refuses a NULL label with ARGUMENTS_BAD"
    );
    assert_eq!(
        back_null, nul_truncated,
        "SoftHSM2 NULL-label refusal has no side effects on the stored label"
    );

    provider.finalize();

    q03_softhsm_proxy_phase();
}

/// Live sweep vectors: (recording name, label prefix — padded to 32
/// with spaces). The mock 7-vector sweep plus the terminal-NUL
/// boundary (B2).
const Q03_SOFTHSM_VECTORS: &[(&str, &[u8])] = &[
    ("valid-trailing-tab", b"A\t"),
    ("ascii", b"hello"),
    ("multibyte", "tökén-héllo".as_bytes()),
    ("full-32", b"0123456789abcdef0123456789abcdef"),
    ("trailing-nbsp", "B\u{a0}".as_bytes()),
    ("all-spaces", b""),
    ("embedded-nul", b"C\0D"),
    ("terminal-nul", b"C\0"),
];

fn q03_softhsm_pad(prefix: &[u8]) -> [u8; 32] {
    assert!(prefix.len() <= 32);
    let mut label = [b' '; 32];
    label[..prefix.len()].copy_from_slice(prefix);
    label
}

/// Phase B: live-provider proxy-stack sweep — shim `C_InitToken` →
/// daemon → `FfiBackend` → SoftHSM2, read back through shim
/// `C_GetTokenInfo`. The direct phase finalized; `SOFTHSM2_CONF`
/// still points at the disposable token store.
#[allow(clippy::print_stderr)]
fn q03_softhsm_proxy_phase() {
    let _guard = shim_state_test_guard();
    let module = softhsm2_module_path();
    let runtime = Runtime::new().expect("test runtime");
    let (endpoint, backend, _shutdown) = runtime.block_on(async {
        let backend = Arc::new(
            FfiBackend::load(&module).unwrap_or_else(|e| panic!("load {}: {e}", module.display())),
        );
        backend.initialize().unwrap_or_else(|rv| panic!("SoftHSM2 C_Initialize failed: {rv}"));
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
        // SoftHSM2 (unlike the mock) refuses `C_InitToken` while
        // sessions are open (`CKR_SESSION_EXISTS`): the sweep needs
        // none, so close it up front (neutralized for the `Drop`
        // close below).
        let close_rv = unsafe { dispatch::general::c_close_session(shim.session) };
        assert_eq!(close_rv, CKR_OK as CK_RV, "close the unneeded session");
        shim.session = CK_INVALID_HANDLE;
        let so_pin = b"5678";
        let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };

        for (name, prefix) in Q03_SOFTHSM_VECTORS {
            let mut label = q03_softhsm_pad(prefix);
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
                "Q03-SOFTHSM-PROXY {name}: rv={rv:#x} get_rv={get_rv:#x} stored={:02x?}",
                info.label
            );
            assert_eq!(rv, CKR_OK as CK_RV, "proxy C_InitToken({name}) succeeds");
            assert_eq!(get_rv, CKR_OK as CK_RV, "proxy C_GetTokenInfo({name}) succeeds");
            // SoftHSM2 NUL-truncates (pinned directly above): the proxy
            // forwards exactly and reads back exactly what the provider
            // stored — the B2 NUL-preserving readback reproduces the
            // NULs, never spaces.
            let expected = match *name {
                "embedded-nul" | "terminal-nul" => {
                    let mut truncated = [0u8; 32];
                    truncated[0] = b'C';
                    truncated
                }
                _ => label,
            };
            assert_eq!(info.label, expected, "proxy round-trips {name} per provider semantics");
        }

        // Invalid UTF-8: stored verbatim, read back through the
        // documented lossy `String` path (live-provider edition of
        // the mock limit pin).
        let mut bad = q03_softhsm_pad(b"BAD\xff\xfe");
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
            "Q03-SOFTHSM-PROXY invalid-utf8: rv={rv_bad:#x} get_rv={get_rv_bad:#x} stored={:02x?}",
            info.label
        );
        assert_eq!(rv_bad, CKR_OK as CK_RV, "proxy C_InitToken(invalid-utf8) succeeds");
        assert_eq!(get_rv_bad, CKR_OK as CK_RV, "proxy C_GetTokenInfo(invalid-utf8) succeeds");
        assert_eq!(
            info.label,
            q03_softhsm_pad("BAD\u{fffd}\u{fffd}".as_bytes()),
            "live readback shows the compat text (documented lossy-readback limit)"
        );
        let before_null = info.label;

        // NULL: clean refusal (`CKR_ARGUMENTS_BAD`), stored label
        // unchanged — the refusal-semantics live counterpart to the
        // accepting kryoptic sweep.
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
            "Q03-SOFTHSM-PROXY null-label: rv={rv_null:#x} get_rv={get_rv_null:#x} stored={:02x?}",
            info.label
        );
        assert_eq!(
            rv_null, CKR_ARGUMENTS_BAD as CK_RV,
            "proxy C_InitToken(NULL) propagates the provider refusal"
        );
        assert_eq!(get_rv_null, CKR_OK as CK_RV, "proxy C_GetTokenInfo(NULL) succeeds");
        assert_eq!(
            info.label, before_null,
            "provider NULL refusal leaves the stored label unchanged"
        );

        eprintln!("Q03-SOFTHSM-PROXY sweep-complete");
    }

    // Quiesce the native backend before its final-owner `Drop`: an
    // initialized backend dropped without finalize trips the
    // abnormal-stop guard (exit 70). No native sessions remain (the
    // sweep session closed up front; the shim `Drop` above released
    // the server context).
    backend.finalize().unwrap_or_else(|rv| panic!("SoftHSM2 C_Finalize failed: {rv}"));
}

//! Q03: DIRECT native `C_InitToken` label outcomes on a disposable
//! stock-SoftHSM2 token (never a user token).
//!
//! This probe records what stock SoftHSM2 does with NULL,
//! invalid-encoding, and valid whitespace label bytes when called
//! DIRECTLY — through the provider function table via `libloading`,
//! bypassing both the proxy and `FfiBackend` — so the proxy's
//! provider-decides contract has native ground truth. Run with:
//!
//! ```text
//! cargo test -p pkcs11-proxy-ng-shim --lib -- --ignored token_label_native --nocapture
//! ```
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

use std::ffi::OsString;
use std::path::PathBuf;

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
/// - NULL label: `CKR_ARGUMENTS_BAD` with the stored label unchanged.
///
/// This parent only spawns the child and checks its exit status plus
/// the `Q03-DIRECT` recording lines; the child owns all provider
/// contact. Finding 3: no process-global `SOFTHSM2_CONF` or provider
/// coordination is needed — the child is a fresh process.
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
}

/// The isolated probe body: runs ONLY in the fresh child process
/// spawned above (or when invoked directly with an explicit filter).
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

    // (c) NULL label: clean refusal, stored label unchanged.
    let rv_null = provider.init_token_direct(slot, so_pin, std::ptr::null_mut());
    let back_null = provider.token_label_bytes(slot);
    eprintln!("Q03-DIRECT null-label: rv={rv_null:#x} stored={back_null:02x?}");
    assert_eq!(
        rv_null, CKR_ARGUMENTS_BAD as CK_RV,
        "SoftHSM2 refuses a NULL label with ARGUMENTS_BAD"
    );
    assert_eq!(
        back_null, back_bad,
        "SoftHSM2 NULL-label refusal has no side effects on the stored label"
    );

    provider.finalize();
}

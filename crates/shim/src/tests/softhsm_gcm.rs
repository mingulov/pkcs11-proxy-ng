//! Stock-SoftHSM2 AES-GCM coverage for W1-C6-01 (review follow-up).
//!
//! The `output_semantics.rs` GCM tests drive the shim against `MockBackend`.
//! These tests drive the same shim FFI (`C_EncryptInit`/`C_Encrypt`) against
//! a real provider: an in-process daemon backed by stock `libsofthsm2.so`
//! with an isolated token (mirrors the server-suite `ProviderFixture::soft_hsm`
//! pattern: tempdir `softhsm2.conf` + `softhsm2-util --init-token`).
//!
//! Stock SoftHSM2 never generates IVs server-side — the IV is always
//! caller-supplied — so the app-visible IV buffer must be byte-identical
//! before/after `C_EncryptInit` and after `C_Encrypt`. Run with:
//!
//! ```text
//! cargo test -p pkcs11-proxy-ng-shim --lib -- --ignored softhsm_
//! ```
//!
//! Both tests are `#[ignore]`, so default CI runs stay green without the
//! provider. If you opt in with `--ignored` but SoftHSM2 is missing, the
//! fixture panics with instructions rather than passing silently (L14).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
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

use super::*;

/// System search list for stock `libsofthsm2.so` (same list as the
/// server-suite `ProviderFixture`).
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
struct SoftHsmToken {
    _temp_dir: tempfile::TempDir,
    previous_conf: Option<OsString>,
    user_pin: String,
}

impl SoftHsmToken {
    fn init() -> Self {
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
                "test-token",
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
        Self { _temp_dir: temp_dir, previous_conf, user_pin: "1234".to_string() }
    }
}

impl Drop for SoftHsmToken {
    fn drop(&mut self) {
        unsafe {
            match self.previous_conf.take() {
                Some(v) => std::env::set_var("SOFTHSM2_CONF", v),
                None => std::env::remove_var("SOFTHSM2_CONF"),
            }
        }
    }
}

/// In-process daemon backed by stock SoftHSM2 (one per test process).
/// Mirrors `output_semantics::TestDaemon`, with `FfiBackend` in place of
/// `MockBackend`, and `DaemonHarness::start` for the FFI bring-up order
/// (load → `initialize` → `populate_slots` → serve).
struct SoftHsmDaemon {
    _runtime: Runtime,
    endpoint: String,
    _backend: Arc<FfiBackend>,
    token: SoftHsmToken,
    _shutdown: watch::Sender<bool>,
}

static SOFTHSM_DAEMON: OnceLock<SoftHsmDaemon> = OnceLock::new();

fn softhsm_daemon() -> &'static SoftHsmDaemon {
    SOFTHSM_DAEMON.get_or_init(|| {
        let token = SoftHsmToken::init();
        let module_path = softhsm2_module_path();
        let runtime = Runtime::new().expect("test runtime");
        let (endpoint, backend, shutdown) = runtime.block_on(async {
            let backend = Arc::new(
                FfiBackend::load_with_init_args(&module_path, None)
                    .unwrap_or_else(|e| panic!("load {}: {e}", module_path.display())),
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
        SoftHsmDaemon { _runtime: runtime, endpoint, _backend: backend, token, _shutdown: shutdown }
    })
}

/// Logged-in user session on the SoftHSM2 token slot.
struct SoftHsmSession {
    session: CK_SESSION_HANDLE,
}

impl SoftHsmSession {
    fn open(user_pin: &str) -> Self {
        let daemon = softhsm_daemon();
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

        let mut mech_count = 0;
        let mech_count_rv = unsafe {
            dispatch::general::c_get_mechanism_list(slot, std::ptr::null_mut(), &mut mech_count)
        };
        assert_eq!(mech_count_rv, CKR_OK as CK_RV, "C_GetMechanismList(count)");
        let mut mechs = vec![0 as CK_MECHANISM_TYPE; mech_count as usize];
        let mech_list_rv = unsafe {
            dispatch::general::c_get_mechanism_list(slot, mechs.as_mut_ptr(), &mut mech_count)
        };
        assert_eq!(mech_list_rv, CKR_OK as CK_RV, "C_GetMechanismList(data)");
        assert!(mechs.contains(&CKM_AES_GCM), "stock SoftHSM2 must offer CKM_AES_GCM");

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

        let mut pin = user_pin.as_bytes().to_vec();
        let login_rv = unsafe {
            dispatch::general::c_login(session, CKU_USER, pin.as_mut_ptr(), pin.len() as CK_ULONG)
        };
        assert_eq!(login_rv, CKR_OK as CK_RV, "C_Login");
        Self { session }
    }
}

impl Drop for SoftHsmSession {
    fn drop(&mut self) {
        if self.session != CK_INVALID_HANDLE {
            let _ = unsafe { dispatch::general::c_close_session(self.session) };
        }
        let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    }
}

fn generate_aes256_key(session: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let mut class: CK_OBJECT_CLASS = CKO_SECRET_KEY;
    let mut key_type: CK_KEY_TYPE = CKK_AES;
    let mut value_len: CK_ULONG = 32;
    let mut token: CK_BBOOL = CK_FALSE;
    let mut encrypt: CK_BBOOL = CK_TRUE;
    let mut decrypt: CK_BBOOL = CK_TRUE;
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
            type_: CKA_VALUE_LEN,
            pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN,
            pValue: &mut token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT,
            pValue: &mut encrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT,
            pValue: &mut decrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut key = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_generate_key(
            session,
            &mut mechanism,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut key,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GenerateKey(AES-256)");
    assert_ne!(key, CK_INVALID_HANDLE, "key handle");
    key
}

/// W1-C6-01 real-backend smoke: stock SoftHSM2, caller-supplied GCM IV,
/// single-part encrypt. SoftHSM2 never generates IVs, so the app-visible IV
/// buffer must be byte-identical after `C_EncryptInit` and after `C_Encrypt`,
/// and the ciphertext must round-trip through `C_Decrypt`. Collateral-change
/// detector for the delayed-writeback removal: caller-supplied-IV behavior
/// is unaffected by the fix, so any failure here means the fix broke the
/// common path.
#[ignore] // requires stock SoftHSM2 (lib + softhsm2-util)
#[test]
fn softhsm_gcm_caller_supplied_iv_round_trip() {
    let _guard = shim_state_test_guard();
    let daemon = softhsm_daemon();
    let shim = SoftHsmSession::open(&daemon.token.user_pin);
    let key = generate_aes256_key(shim.session);

    // 12-byte caller-supplied IV (96 bits) — the standard GCM nonce size.
    let caller_iv = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B];
    let mut iv_buffer = caller_iv;
    let mut aad = *b"softhsm2 gcm additional authenticated data";
    let mut params = CK_GCM_PARAMS {
        pIv: iv_buffer.as_mut_ptr(),
        ulIvLen: iv_buffer.len() as CK_ULONG,
        ulIvBits: 96,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: &mut params as *mut CK_GCM_PARAMS as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };

    let init_rv = unsafe { dispatch::general::c_encrypt_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_EncryptInit");
    // Stock SoftHSM2 generates nothing: the caller's IV comes back untouched.
    assert_eq!(iv_buffer, caller_iv, "app-visible IV byte-identical after C_EncryptInit");
    let (ul_iv_len, ul_iv_bits, ul_tag_bits) = (params.ulIvLen, params.ulIvBits, params.ulTagBits);
    assert_eq!(ul_iv_len, caller_iv.len() as CK_ULONG, "ulIvLen untouched by C_EncryptInit");
    assert_eq!(ul_iv_bits, 96, "ulIvBits untouched by C_EncryptInit");
    assert_eq!(ul_tag_bits, 128, "ulTagBits untouched by C_EncryptInit");

    let plaintext = b"AES-GCM stock-SoftHSM2 caller-supplied-IV smoke payload";
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
    // GCM ciphertext = plaintext + 16-byte tag.
    assert_eq!(size_len, (plaintext.len() + 16) as CK_ULONG, "GCM size query");

    let mut ciphertext = vec![0u8; size_len as usize];
    let mut ciphertext_len = size_len;
    let encrypt_rv = unsafe {
        dispatch::general::c_encrypt(
            shim.session,
            plaintext.as_ptr() as CK_BYTE_PTR,
            plaintext.len() as CK_ULONG,
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
        )
    };
    assert_eq!(encrypt_rv, CKR_OK as CK_RV, "C_Encrypt(data)");
    assert_eq!(ciphertext_len, size_len, "ciphertext length");
    assert_eq!(iv_buffer, caller_iv, "app-visible IV byte-identical after C_Encrypt");

    // Decrypt round-trip with the same IV proves the ciphertext is genuine.
    let mut decrypt_iv = caller_iv;
    let mut decrypt_aad = *b"softhsm2 gcm additional authenticated data";
    let mut decrypt_params = CK_GCM_PARAMS {
        pIv: decrypt_iv.as_mut_ptr(),
        ulIvLen: decrypt_iv.len() as CK_ULONG,
        ulIvBits: 96,
        pAAD: decrypt_aad.as_mut_ptr(),
        ulAADLen: decrypt_aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mut decrypt_mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: &mut decrypt_params as *mut CK_GCM_PARAMS as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    let decrypt_init_rv =
        unsafe { dispatch::general::c_decrypt_init(shim.session, &mut decrypt_mechanism, key) };
    assert_eq!(decrypt_init_rv, CKR_OK as CK_RV, "C_DecryptInit");
    let mut plain_len = 0;
    let decrypt_size_rv = unsafe {
        dispatch::general::c_decrypt(
            shim.session,
            ciphertext.as_ptr() as CK_BYTE_PTR,
            ciphertext_len,
            std::ptr::null_mut(),
            &mut plain_len,
        )
    };
    assert_eq!(decrypt_size_rv, CKR_OK as CK_RV, "C_Decrypt(size query)");
    // Stock SoftHSM2 conservatively reports the ciphertext length here (it
    // cannot know the tag split before decrypting); the proxy forwards the
    // provider's exact answer verbatim.
    assert_eq!(plain_len, ciphertext_len, "GCM decrypt size query = ciphertext length");
    let mut recovered = vec![0u8; plain_len as usize];
    let mut recovered_len = plain_len;
    let decrypt_rv = unsafe {
        dispatch::general::c_decrypt(
            shim.session,
            ciphertext.as_ptr() as CK_BYTE_PTR,
            ciphertext_len,
            recovered.as_mut_ptr(),
            &mut recovered_len,
        )
    };
    assert_eq!(decrypt_rv, CKR_OK as CK_RV, "C_Decrypt(data)");
    assert_eq!(recovered_len, plaintext.len() as CK_ULONG, "recovered plaintext length");
    assert_eq!(
        &recovered[..recovered_len as usize],
        plaintext,
        "GCM round-trip recovers plaintext"
    );
}

/// W1-C6-01 real-backend regression leg: the caller-supplied `CK_GCM_PARAMS`
/// and its `pIv` buffer live on mapped pages that become inaccessible
/// (`PROT_NONE`) once `C_EncryptInit` returns. `C_Encrypt` must complete
/// without touching them. Against the pre-fix shim this faults (SIGSEGV):
/// the FFI backend echoes GCM params at Encrypt time, and the old delayed
/// writeback dereferenced the retained Init-scope address.
#[cfg(unix)]
#[ignore] // requires stock SoftHSM2 (lib + softhsm2-util)
#[test]
fn softhsm_gcm_encrypt_does_not_touch_released_init_params() {
    let _guard = shim_state_test_guard();
    let daemon = softhsm_daemon();
    let shim = SoftHsmSession::open(&daemon.token.user_pin);
    let key = generate_aes256_key(shim.session);

    let caller_iv = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B];
    let page_len = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    assert!(page_len >= 4096, "suspicious page size {page_len}");
    let region_len = page_len * 2;
    // SAFETY: anonymous private mapping, page-aligned; checked for MAP_FAILED.
    let region = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            region_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(region, libc::MAP_FAILED, "mmap test region");
    // SAFETY: region is mapped and large enough; params on page 0, IV on page 1.
    let params_ptr = region as *mut CK_GCM_PARAMS;
    let iv_ptr = unsafe { (region as *mut u8).add(page_len) };
    let mut aad = *b"softhsm2 gcm additional authenticated data";
    unsafe {
        params_ptr.write(CK_GCM_PARAMS {
            pIv: iv_ptr,
            ulIvLen: caller_iv.len() as CK_ULONG,
            ulIvBits: 96,
            pAAD: aad.as_mut_ptr(),
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: 128,
        });
        std::ptr::copy_nonoverlapping(caller_iv.as_ptr(), iv_ptr, caller_iv.len());
    }
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: params_ptr as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };

    let init_rv = unsafe { dispatch::general::c_encrypt_init(shim.session, &mut mechanism, key) };
    assert_eq!(init_rv, CKR_OK as CK_RV, "C_EncryptInit");

    // The caller frees its Init-scope memory: any retained-pointer access
    // below faults instead of silently corrupting reused memory.
    // SAFETY: region is a live mapping of region_len bytes.
    let protect_rv = unsafe { libc::mprotect(region, region_len, libc::PROT_NONE) };
    assert_eq!(protect_rv, 0, "mprotect PROT_NONE test region");

    let plaintext = b"hello stock SoftHSM2";
    // Generous buffer (plaintext + 64 slack): exact semantics report the
    // actual length, so over-provisioning is safe and avoids conflating this
    // regression leg with provider size-query behavior.
    let mut ciphertext = vec![0u8; plaintext.len() + 64];
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

    // Teardown: restore access before unmapping. Only reached when
    // `C_Encrypt` did not touch the released pages (on a SIGSEGV the process
    // dies here and the OS reclaims the mapping).
    // SAFETY: region is a live mapping of region_len bytes.
    let unprotect_rv =
        unsafe { libc::mprotect(region, region_len, libc::PROT_READ | libc::PROT_WRITE) };
    assert_eq!(unprotect_rv, 0, "mprotect restore test region");
    // SAFETY: region is a live mapping of region_len bytes.
    let unmap_rv = unsafe { libc::munmap(region, region_len) };
    assert_eq!(unmap_rv, 0, "munmap test region");

    assert_eq!(encrypt_rv, CKR_OK as CK_RV, "C_Encrypt(data)");
    assert_eq!(ciphertext_len, (plaintext.len() + 16) as CK_ULONG, "ciphertext length");
}

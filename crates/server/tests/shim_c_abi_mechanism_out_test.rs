// W1-L12-03: test diagnostics (skip notices, progress, summaries) go to
// stderr by design; the workspace lint table denies this sink elsewhere.
#![allow(clippy::print_stderr)]
//! End-to-end shim C ABI coverage for HSM-mutated mechanism parameters.
//!
//! This test loads `libpkcs11_proxy_ng_shim.so` with `dlopen`, calls through
//! the exported PKCS#11 function list, and verifies that the caller's
//! stack-owned `CK_GCM_PARAMS` receives delayed generated-IV writeback after
//! `C_Encrypt` and `C_WrapKey`, that SP800-108 nested `CK_DERIVED_KEY` handles
//! are written back through `C_DeriveKey` and invalidated when their owning
//! session closes, and that slot-event lifecycle errors survive the loaded shim
//! function-list path. It also verifies that provider mechanism-info flags are
//! returned through a real caller-owned `CK_MECHANISM_INFO` stack struct without
//! inventing workflow flags. Message Begin/Next coverage exercises modelled
//! Encrypt/Decrypt stack structs and the separate empty-only Sign/Verify
//! pointer-class contract.

// CK_MECHANISM_TYPE is u64 on LP64 but u32 on Windows LLP64/ILP32, so the
// `as u64` casts below are live on some targets and vacuous on others.
#![allow(clippy::unnecessary_cast)]

mod common_3x;

use std::mem;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use cryptoki_sys::*;
use libloading::{Library, Symbol};
use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;
use pkcs11_proxy_ng_types::{CkMechanismParams, CkMechanismType, CkSlotId, GcmParams};
use tokio::sync::Mutex;

type CGetFunctionList = unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;
type CGetInterface = unsafe extern "C" fn(
    *mut CK_UTF8CHAR,
    *mut CK_VERSION,
    CK_INTERFACE_PTR_PTR,
    CK_FLAGS,
) -> CK_RV;

static SHIM_C_ABI_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

// Must be declared after Library so unwinding finalizes before dlclose.
// Explicit successful finalization remains asserted; the second finalize on
// normal drop is harmless and its NOT_INITIALIZED result is intentionally ignored.
struct FinalizeOnDrop(unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV);
impl Drop for FinalizeOnDrop {
    fn drop(&mut self) {
        unsafe {
            (self.0)(std::ptr::null_mut());
        }
    }
}

fn find_shim_library() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PKCS11_PROXY_SHIM_LIB")
        && !path.is_empty()
    {
        let path = PathBuf::from(path);
        return path.exists().then_some(path);
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().and_then(|p| p.parent())?;
    [
        workspace_root.join("target/debug/libpkcs11_proxy_ng_shim.so"),
        workspace_root.join("target/release/libpkcs11_proxy_ng_shim.so"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

struct EnvRestore {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvRestore {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(key);
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a built libpkcs11_proxy_ng_shim.so; run cargo build -p pkcs11-proxy-ng-shim first"]
async fn loaded_shim_does_not_export_digest_xof_out_of_band_symbols() {
    let _guard = SHIM_C_ABI_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    let Some(shim_path) = find_shim_library() else {
        eprintln!(
            "[shim_c_abi_mechanism_out_test] shim library not found; \
             run cargo build -p pkcs11-proxy-ng-shim first"
        );
        return;
    };

    unsafe {
        let lib = Library::new(&shim_path).expect("dlopen shim library");
        let _c_get_function_list: Symbol<CGetFunctionList> =
            lib.get(b"C_GetFunctionList\0").expect("C_GetFunctionList symbol");

        for symbol in [
            "C_DigestXof",
            "C_DigestXofExtract",
            "C_DigestXofFinal",
            "C_DigestXofInit",
            "C_DigestXofKeyValue",
            "C_DigestXofUpdate",
        ] {
            let symbol_name = format!("{symbol}\0");
            assert!(
                lib.get::<unsafe extern "C" fn()>(symbol_name.as_bytes()).is_err(),
                "{symbol} must not be exported outside the standard function-list ABI"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a built libpkcs11_proxy_ng_shim.so; run cargo build -p pkcs11-proxy-ng-shim first"]
async fn loaded_shim_reinitializes_against_current_endpoint_after_finalize() {
    let _guard = SHIM_C_ABI_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    let Some(shim_path) = find_shim_library() else {
        eprintln!(
            "[shim_c_abi_mechanism_out_test] shim library not found; \
             run cargo build -p pkcs11-proxy-ng-shim first"
        );
        return;
    };

    unsafe {
        let lib = Library::new(&shim_path).expect("dlopen shim library");
        let c_get_interface: Symbol<CGetInterface> =
            lib.get(b"C_GetInterface\0").expect("C_GetInterface symbol");
        let c_get_function_list: Symbol<CGetFunctionList> =
            lib.get(b"C_GetFunctionList\0").expect("C_GetFunctionList symbol");

        let backend1 = Arc::new(MockBackend::new(
            vec![CkSlotId(0x11)],
            vec![CkMechanismType(CKM_AES_GCM as u64)],
        ));
        let (endpoint1, _shutdown1) = common_3x::mock_daemon(backend1).await;
        let endpoint_guard1 = EnvRestore::set("PKCS11_PROXY_ENDPOINT", &endpoint1);

        let mut interface: CK_INTERFACE_PTR = std::ptr::null_mut();
        assert_eq!(
            c_get_interface(std::ptr::null_mut(), std::ptr::null_mut(), &mut interface, 0,),
            CKR_OK as CK_RV,
            "C_GetInterface(default)"
        );
        assert!(!interface.is_null(), "C_GetInterface returned null");
        let functions_3_2 = &*((*interface).pFunctionList as *const CK_FUNCTION_LIST_3_2);
        let c_initialize_3_2 = functions_3_2.C_Initialize.expect("C_Initialize");
        let c_finalize_3_2 = functions_3_2.C_Finalize.expect("C_Finalize");
        let _finalize_on_drop_3_2 = FinalizeOnDrop(c_finalize_3_2);
        let c_get_slot_list_3_2 = functions_3_2.C_GetSlotList.expect("C_GetSlotList");
        let c_get_mechanism_list_3_2 =
            functions_3_2.C_GetMechanismList.expect("C_GetMechanismList");

        assert_eq!(c_initialize_3_2(std::ptr::null_mut()), CKR_OK as CK_RV, "first C_Initialize");
        let mut slot_count: CK_ULONG = 1;
        let mut first_slots = [0 as CK_SLOT_ID; 1];
        assert_eq!(
            c_get_slot_list_3_2(CK_TRUE, first_slots.as_mut_ptr(), &mut slot_count),
            CKR_OK as CK_RV,
            "first C_GetSlotList"
        );
        assert_eq!(slot_count, 1, "first daemon slot count");
        let mut first_mechanism_count: CK_ULONG = 1;
        let mut first_mechanisms = [0 as CK_MECHANISM_TYPE; 1];
        assert_eq!(
            c_get_mechanism_list_3_2(
                first_slots[0],
                first_mechanisms.as_mut_ptr(),
                &mut first_mechanism_count,
            ),
            CKR_OK as CK_RV,
            "first C_GetMechanismList"
        );
        assert_eq!(first_mechanism_count, 1, "first daemon mechanism count");
        assert_eq!(first_mechanisms[0], CKM_AES_GCM, "first daemon mechanism");
        assert_eq!(c_finalize_3_2(std::ptr::null_mut()), CKR_OK as CK_RV, "first C_Finalize");
        drop(endpoint_guard1);

        let backend2 = Arc::new(MockBackend::new(
            vec![CkSlotId(0x22)],
            vec![CkMechanismType(CKM_AES_CBC as u64)],
        ));
        let (endpoint2, _shutdown2) = common_3x::mock_daemon(backend2).await;
        let _endpoint_guard2 = EnvRestore::set("PKCS11_PROXY_ENDPOINT", &endpoint2);

        let mut function_list: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
        assert_eq!(c_get_function_list(&mut function_list), CKR_OK as CK_RV, "C_GetFunctionList");
        assert!(!function_list.is_null(), "C_GetFunctionList returned null");
        let functions = &*function_list;
        let c_initialize = functions.C_Initialize.expect("C_Initialize");
        let c_finalize = functions.C_Finalize.expect("C_Finalize");
        let _finalize_on_drop = FinalizeOnDrop(c_finalize);
        let c_get_slot_list = functions.C_GetSlotList.expect("C_GetSlotList");
        let c_get_mechanism_list = functions.C_GetMechanismList.expect("C_GetMechanismList");

        assert_eq!(c_initialize(std::ptr::null_mut()), CKR_OK as CK_RV, "second C_Initialize");
        slot_count = 1;
        let mut second_slots = [0 as CK_SLOT_ID; 1];
        assert_eq!(
            c_get_slot_list(CK_TRUE, second_slots.as_mut_ptr(), &mut slot_count),
            CKR_OK as CK_RV,
            "second C_GetSlotList"
        );
        assert_eq!(slot_count, 1, "second daemon slot count");
        let mut second_mechanism_count: CK_ULONG = 1;
        let mut second_mechanisms = [0 as CK_MECHANISM_TYPE; 1];
        assert_eq!(
            c_get_mechanism_list(
                second_slots[0],
                second_mechanisms.as_mut_ptr(),
                &mut second_mechanism_count,
            ),
            CKR_OK as CK_RV,
            "second C_GetMechanismList"
        );
        assert_eq!(second_mechanism_count, 1, "second daemon mechanism count");
        assert_eq!(
            second_mechanisms[0], CKM_AES_CBC,
            "C_Initialize after C_Finalize must use the current endpoint"
        );
        assert_eq!(c_finalize(std::ptr::null_mut()), CKR_OK as CK_RV, "second C_Finalize");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a built libpkcs11_proxy_ng_shim.so; run cargo build -p pkcs11-proxy-ng-shim first"]
#[allow(clippy::unnecessary_cast)] // CK_ULONG is 32 or 64 bits across supported ABIs.
async fn loaded_shim_preserves_provider_mechanism_info_flags() {
    let _guard = SHIM_C_ABI_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    let Some(shim_path) = find_shim_library() else {
        eprintln!(
            "[shim_c_abi_mechanism_out_test] shim library not found; \
             run cargo build -p pkcs11-proxy-ng-shim first"
        );
        return;
    };

    const CKM_BATON_KEY_GEN: CK_MECHANISM_TYPE = 0x0000_1030;
    const CKM_CAMELLIA_CTR: CK_MECHANISM_TYPE = 0x0000_0558;
    // W1-C9-06: bridge the canonical types const (no local hex).
    const CKM_DES_CBC: CK_MECHANISM_TYPE = CkMechanismType::DES_CBC.0 as CK_MECHANISM_TYPE;

    let backend = Arc::new(MockBackend::new(
        vec![CkSlotId(0)],
        vec![
            CkMechanismType(CKM_BATON_KEY_GEN as u64),
            CkMechanismType(CKM_CAMELLIA_CTR as u64),
            CkMechanismType(CKM_DES_CBC as u64),
        ],
    ));
    let expected: Vec<_> = [CKM_BATON_KEY_GEN, CKM_CAMELLIA_CTR, CKM_DES_CBC]
        .into_iter()
        .map(|mechanism| {
            backend.get_mechanism_info(CkSlotId(0), CkMechanismType(mechanism as u64)).unwrap()
        })
        .collect();
    // BATON and DES now have a source-grounded historical registry; Camellia
    // CTR remains the no-source case. Compare native provider facts, not stale
    // pre-registry assumptions about all three returning zero flags.
    assert_eq!(expected[0].flags.0, (CKF_GENERATE | CKF_GENERATE_KEY_PAIR) as u64);
    assert_eq!(expected[1].flags.0, 0);
    let (endpoint, _shutdown) = common_3x::mock_daemon(backend).await;
    let _endpoint_guard = EnvRestore::set("PKCS11_PROXY_ENDPOINT", &endpoint);

    unsafe {
        let lib = Library::new(&shim_path).expect("dlopen shim library");
        let c_get_function_list: Symbol<CGetFunctionList> =
            lib.get(b"C_GetFunctionList\0").expect("C_GetFunctionList symbol");
        let mut function_list: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
        assert_eq!(c_get_function_list(&mut function_list), CKR_OK as CK_RV, "C_GetFunctionList");
        assert!(!function_list.is_null(), "C_GetFunctionList returned null");
        let functions = &*function_list;

        let c_initialize = functions.C_Initialize.expect("C_Initialize");
        let c_finalize = functions.C_Finalize.expect("C_Finalize");
        let _finalize_on_drop = FinalizeOnDrop(c_finalize);
        let c_get_slot_list = functions.C_GetSlotList.expect("C_GetSlotList");
        let c_get_mechanism_info = functions.C_GetMechanismInfo.expect("C_GetMechanismInfo");

        assert_eq!(c_initialize(std::ptr::null_mut()), CKR_OK as CK_RV, "C_Initialize");

        let mut slot_count: CK_ULONG = 0;
        assert_eq!(
            c_get_slot_list(CK_TRUE, std::ptr::null_mut(), &mut slot_count),
            CKR_OK as CK_RV,
            "C_GetSlotList(size)"
        );
        let mut slots = vec![0 as CK_SLOT_ID; slot_count as usize];
        assert_eq!(
            c_get_slot_list(CK_TRUE, slots.as_mut_ptr(), &mut slot_count),
            CKR_OK as CK_RV,
            "C_GetSlotList(data)"
        );

        for ((mechanism, label), expected) in [
            (CKM_BATON_KEY_GEN, "CKM_BATON_KEY_GEN"),
            (CKM_CAMELLIA_CTR, "CKM_CAMELLIA_CTR"),
            (CKM_DES_CBC, "CKM_DES_CBC"),
        ]
        .into_iter()
        .zip(expected)
        {
            let mut info =
                CK_MECHANISM_INFO { ulMinKeySize: 0xCAFE, ulMaxKeySize: 0xBABE, flags: 0xFFFF };
            assert_eq!(
                c_get_mechanism_info(slots[0], mechanism, &mut info),
                CKR_OK as CK_RV,
                "C_GetMechanismInfo({label})"
            );
            assert_eq!(info.ulMinKeySize as u64, expected.min_key_size, "{label} min key size");
            assert_eq!(info.ulMaxKeySize as u64, expected.max_key_size, "{label} max key size");
            assert_eq!(info.flags as u64, expected.flags.0, "{label} provider flags preserved");
        }

        assert_eq!(c_finalize(std::ptr::null_mut()), CKR_OK as CK_RV, "C_Finalize");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a built libpkcs11_proxy_ng_shim.so"]
async fn loaded_shim_finalize_guard_recovers_after_test_panic() {
    let _guard = SHIM_C_ABI_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    let shim_path = find_shim_library().expect("explicit loaded-shim gate needs a library");
    let (endpoint, _shutdown) = common_3x::mock_daemon(Arc::new(MockBackend::default_test())).await;
    let _endpoint_guard = EnvRestore::set("PKCS11_PROXY_ENDPOINT", &endpoint);
    unsafe {
        let library = Library::new(shim_path).unwrap();
        let get = library.get::<CGetFunctionList>(b"C_GetFunctionList\0").unwrap();
        let mut pointer = std::ptr::null_mut();
        assert_eq!(get(&mut pointer), CKR_OK);
        let functions = &*pointer;
        let initialize = functions.C_Initialize.unwrap();
        let finalize = functions.C_Finalize.unwrap();
        assert_eq!(initialize(std::ptr::null_mut()), CKR_OK);
        let panic = std::panic::catch_unwind(|| {
            let _finalize_on_drop = FinalizeOnDrop(finalize);
            panic!("synthetic test failure exercises cleanup, not a provider panic");
        });
        assert!(panic.is_err());
        let _finalize_on_drop = FinalizeOnDrop(finalize);
        assert_eq!(
            initialize(std::ptr::null_mut()),
            CKR_OK,
            "previous panic must not leave the shim initialized"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a built libpkcs11_proxy_ng_shim.so; run cargo build -p pkcs11-proxy-ng-shim first"]
async fn loaded_shim_rejects_unsafe_official_lengthless_parameter_shapes() {
    let _guard = SHIM_C_ABI_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    let Some(shim_path) = find_shim_library() else {
        eprintln!(
            "[shim_c_abi_mechanism_out_test] shim library not found; \
             run cargo build -p pkcs11-proxy-ng-shim first"
        );
        return;
    };

    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
    let (endpoint, _shutdown) = common_3x::mock_daemon(backend).await;
    let _endpoint_guard = EnvRestore::set("PKCS11_PROXY_ENDPOINT", &endpoint);

    unsafe {
        let lib = Library::new(&shim_path).expect("dlopen shim library");
        let c_get_function_list: Symbol<CGetFunctionList> =
            lib.get(b"C_GetFunctionList\0").expect("C_GetFunctionList symbol");
        let mut function_list: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
        assert_eq!(c_get_function_list(&mut function_list), CKR_OK as CK_RV, "C_GetFunctionList");
        assert!(!function_list.is_null(), "C_GetFunctionList returned null");
        let functions = &*function_list;
        let c_initialize = functions.C_Initialize.expect("C_Initialize");
        let c_finalize = functions.C_Finalize.expect("C_Finalize");
        let _finalize_on_drop = FinalizeOnDrop(c_finalize);
        let c_sign_init = functions.C_SignInit.expect("C_SignInit");
        let c_derive_key = functions.C_DeriveKey.expect("C_DeriveKey");
        assert_eq!(c_initialize(std::ptr::null_mut()), CKR_OK as CK_RV, "C_Initialize");

        let mut nested_sign = CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut nested_digest = CK_MECHANISM {
            mechanism: CKM_SHA256,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut content_type = *b"data\0";
        let mut cms = CK_CMS_SIG_PARAMS {
            certificateHandle: 0,
            pSigningMechanism: &mut nested_sign,
            pDigestMechanism: &mut nested_digest,
            pContentType: content_type.as_mut_ptr(),
            pRequestedAttributes: std::ptr::null_mut(),
            ulRequestedAttributesLen: 0,
            pRequiredAttributes: std::ptr::null_mut(),
            ulRequiredAttributesLen: 0,
        };
        let mut cms_mechanism = CK_MECHANISM {
            mechanism: CKM_CMS_SIG,
            pParameter: &mut cms as *mut CK_CMS_SIG_PARAMS as CK_VOID_PTR,
            ulParameterLen: mem::size_of::<CK_CMS_SIG_PARAMS>() as CK_ULONG,
        };
        assert_eq!(
            c_sign_init(1, &mut cms_mechanism, 1),
            CKR_MECHANISM_PARAM_INVALID as CK_RV,
            "C_SignInit should reject CK_CMS_SIG_PARAMS before reading lengthless content type"
        );

        let mut byte = 0xA5_u8;
        let mut derived_key: CK_OBJECT_HANDLE = 0xCAFE_BABE;
        let mut x3dh_initiate = CK_X3DH_INITIATE_PARAMS {
            kdf: 0,
            pPeer_identity: 1,
            pPeer_prekey: 2,
            pPrekey_signature: &mut byte,
            pOnetime_key: &mut byte,
            pOwn_identity: 3,
            pOwn_ephemeral: 4,
        };
        let mut x3dh_respond = CK_X3DH_RESPOND_PARAMS {
            kdf: 0,
            pIdentity_id: &mut byte,
            pPrekey_id: &mut byte,
            pOnetime_id: &mut byte,
            pInitiator_identity: 1,
            pInitiator_ephemeral: &mut byte,
        };
        let mut x2ratchet_initialize = CK_X2RATCHET_INITIALIZE_PARAMS {
            sk: &mut byte,
            peer_public_prekey: 1,
            peer_public_identity: 2,
            own_public_identity: 3,
            bEncryptedHeader: CK_FALSE,
            eCurve: 0,
            aeadMechanism: CKM_AES_GCM,
            kdfMechanism: 0,
        };
        let mut x2ratchet_respond = CK_X2RATCHET_RESPOND_PARAMS {
            sk: &mut byte,
            own_prekey: 1,
            initiator_identity: 2,
            own_public_identity: 3,
            bEncryptedHeader: CK_FALSE,
            eCurve: 0,
            aeadMechanism: CKM_AES_GCM,
            kdfMechanism: 0,
        };

        for (mechanism_type, parameter, parameter_len, label) in [
            (
                CKM_X3DH_INITIALIZE,
                &mut x3dh_initiate as *mut CK_X3DH_INITIATE_PARAMS as CK_VOID_PTR,
                mem::size_of::<CK_X3DH_INITIATE_PARAMS>() as CK_ULONG,
                "CK_X3DH_INITIATE_PARAMS",
            ),
            (
                CKM_X3DH_RESPOND,
                &mut x3dh_respond as *mut CK_X3DH_RESPOND_PARAMS as CK_VOID_PTR,
                mem::size_of::<CK_X3DH_RESPOND_PARAMS>() as CK_ULONG,
                "CK_X3DH_RESPOND_PARAMS",
            ),
            (
                CKM_X2RATCHET_INITIALIZE,
                &mut x2ratchet_initialize as *mut CK_X2RATCHET_INITIALIZE_PARAMS as CK_VOID_PTR,
                mem::size_of::<CK_X2RATCHET_INITIALIZE_PARAMS>() as CK_ULONG,
                "CK_X2RATCHET_INITIALIZE_PARAMS",
            ),
            (
                CKM_X2RATCHET_RESPOND,
                &mut x2ratchet_respond as *mut CK_X2RATCHET_RESPOND_PARAMS as CK_VOID_PTR,
                mem::size_of::<CK_X2RATCHET_RESPOND_PARAMS>() as CK_ULONG,
                "CK_X2RATCHET_RESPOND_PARAMS",
            ),
        ] {
            let mut mechanism = CK_MECHANISM {
                mechanism: mechanism_type,
                pParameter: parameter,
                ulParameterLen: parameter_len,
            };

            assert_eq!(
                c_derive_key(1, &mut mechanism, 1, std::ptr::null_mut(), 0, &mut derived_key,),
                CKR_MECHANISM_PARAM_INVALID as CK_RV,
                "C_DeriveKey should reject {label} before reading lengthless pointer fields"
            );
            assert_eq!(
                derived_key, 0xCAFE_BABE,
                "failed {label} derive must not mutate caller output handle"
            );
        }

        assert_eq!(c_finalize(std::ptr::null_mut()), CKR_OK as CK_RV, "C_Finalize");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a built libpkcs11_proxy_ng_shim.so; run cargo build -p pkcs11-proxy-ng-shim first"]
async fn loaded_shim_writes_mechanism_out_to_caller_stack_after_encrypt_wrap_and_derive() {
    let _guard = SHIM_C_ABI_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    let Some(shim_path) = find_shim_library() else {
        eprintln!(
            "[shim_c_abi_mechanism_out_test] shim library not found; \
             run cargo build -p pkcs11-proxy-ng-shim first"
        );
        return;
    };

    let encrypt_generated_iv =
        vec![0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB];
    let wrap_generated_iv =
        vec![0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB];
    const CKM_BATON_KEY_GEN: CK_MECHANISM_TYPE = 0x0000_1030;
    const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
    const CKM_SHA256_HMAC: CK_SP800_108_PRF_TYPE = 0x0000_0251;
    const CK_SP800_108_ITERATION_VARIABLE: CK_PRF_DATA_TYPE = 0x0000_0001;

    let backend = Arc::new(MockBackend::new(
        vec![CkSlotId(0)],
        vec![
            CkMechanismType::AES_GCM,
            CkMechanismType(CKM_SP800_108_COUNTER_KDF as u64),
            CkMechanismType(CKM_BATON_KEY_GEN as u64),
        ],
    ));
    backend.set_encrypt_exact_output(Some(CkMechanismParams::Gcm(GcmParams {
        iv: encrypt_generated_iv.clone(),
        iv_bits: 96,
        iv_buffer_len: encrypt_generated_iv.len() as u64,
        aad: b"aad".to_vec().into(),
        tag_bits: 128,

        iv_null: false,
        aad_null: false,
    })));
    backend.set_wrap_key_exact_output(Some(CkMechanismParams::Gcm(GcmParams {
        iv: wrap_generated_iv.clone(),
        iv_bits: 96,
        iv_buffer_len: wrap_generated_iv.len() as u64,
        aad: b"wrap-aad".to_vec().into(),
        tag_bits: 128,

        iv_null: false,
        aad_null: false,
    })));
    let (endpoint, _shutdown) = common_3x::mock_daemon(backend).await;
    let _endpoint_guard = EnvRestore::set("PKCS11_PROXY_ENDPOINT", &endpoint);

    unsafe {
        let lib = Library::new(&shim_path).expect("dlopen shim library");
        let c_get_function_list: Symbol<CGetFunctionList> =
            lib.get(b"C_GetFunctionList\0").expect("C_GetFunctionList symbol");
        let mut function_list: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
        assert_eq!(c_get_function_list(&mut function_list), CKR_OK as CK_RV, "C_GetFunctionList");
        assert!(!function_list.is_null(), "C_GetFunctionList returned null");
        let functions = &*function_list;

        let c_initialize = functions.C_Initialize.expect("C_Initialize");
        let c_finalize = functions.C_Finalize.expect("C_Finalize");
        let _finalize_on_drop = FinalizeOnDrop(c_finalize);
        let c_get_slot_list = functions.C_GetSlotList.expect("C_GetSlotList");
        let c_get_mechanism_info = functions.C_GetMechanismInfo.expect("C_GetMechanismInfo");
        let c_open_session = functions.C_OpenSession.expect("C_OpenSession");
        let c_close_session = functions.C_CloseSession.expect("C_CloseSession");
        let c_create_object = functions.C_CreateObject.expect("C_CreateObject");
        let c_destroy_object = functions.C_DestroyObject.expect("C_DestroyObject");
        let c_wait_for_slot_event = functions.C_WaitForSlotEvent.expect("C_WaitForSlotEvent");
        let c_encrypt_init = functions.C_EncryptInit.expect("C_EncryptInit");
        let c_encrypt = functions.C_Encrypt.expect("C_Encrypt");
        let c_wrap_key = functions.C_WrapKey.expect("C_WrapKey");
        let c_derive_key = functions.C_DeriveKey.expect("C_DeriveKey");

        let mut event_slot: CK_SLOT_ID = 0xCAFE_BABE;
        assert_eq!(
            c_wait_for_slot_event(CKF_DONT_BLOCK, &mut event_slot, std::ptr::null_mut()),
            CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV,
            "C_WaitForSlotEvent before C_Initialize"
        );
        assert_eq!(event_slot, 0xCAFE_BABE, "failed wait must not write pSlot");

        assert_eq!(c_initialize(std::ptr::null_mut()), CKR_OK as CK_RV, "C_Initialize");
        assert_eq!(
            c_wait_for_slot_event(CKF_DONT_BLOCK, &mut event_slot, std::ptr::null_mut()),
            CKR_NO_EVENT as CK_RV,
            "C_WaitForSlotEvent nonblocking empty queue"
        );
        assert_eq!(event_slot, 0xCAFE_BABE, "CKR_NO_EVENT must not write pSlot");

        let mut slot_count: CK_ULONG = 0;
        assert_eq!(
            c_get_slot_list(CK_TRUE, std::ptr::null_mut(), &mut slot_count),
            CKR_OK as CK_RV,
            "C_GetSlotList(size)"
        );
        assert!(slot_count > 0, "mock daemon should expose at least one token slot");
        let mut slots = vec![0 as CK_SLOT_ID; slot_count as usize];
        assert_eq!(
            c_get_slot_list(CK_TRUE, slots.as_mut_ptr(), &mut slot_count),
            CKR_OK as CK_RV,
            "C_GetSlotList(data)"
        );

        let mut baton_info =
            CK_MECHANISM_INFO { ulMinKeySize: 0xCAFE, ulMaxKeySize: 0xBABE, flags: 0xFFFF };
        assert_eq!(
            c_get_mechanism_info(slots[0], CKM_BATON_KEY_GEN, &mut baton_info),
            CKR_OK as CK_RV,
            "C_GetMechanismInfo(CKM_BATON_KEY_GEN)"
        );
        // E0793: CK structs are packed on Windows; assert on by-value copies.
        let (min_key_size, max_key_size, flags) =
            (baton_info.ulMinKeySize, baton_info.ulMaxKeySize, baton_info.flags);
        assert_eq!(min_key_size, 2048, "no-source min key size");
        assert_eq!(max_key_size, 4096, "no-source max key size");
        assert_eq!(
            flags,
            CKF_GENERATE | CKF_GENERATE_KEY_PAIR,
            "source-grounded historical BATON flags preserved"
        );

        let mut session: CK_SESSION_HANDLE = 0;
        assert_eq!(
            c_open_session(slots[0], CKF_SERIAL_SESSION, std::ptr::null_mut(), None, &mut session),
            CKR_OK as CK_RV,
            "C_OpenSession"
        );

        let mut object_class = CKO_SECRET_KEY;
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &mut object_class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        }];
        let mut wrapping_key: CK_OBJECT_HANDLE = 0;
        assert_eq!(
            c_create_object(
                session,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut wrapping_key,
            ),
            CKR_OK as CK_RV,
            "C_CreateObject(wrapping key)"
        );
        let mut key: CK_OBJECT_HANDLE = 0;
        assert_eq!(
            c_create_object(session, template.as_mut_ptr(), template.len() as CK_ULONG, &mut key),
            CKR_OK as CK_RV,
            "C_CreateObject(key)"
        );

        let mut encrypt_iv_buffer = [0_u8; 12];
        let mut encrypt_aad = *b"aad";
        let mut encrypt_gcm = CK_GCM_PARAMS {
            pIv: encrypt_iv_buffer.as_mut_ptr(),
            ulIvLen: 0,
            ulIvBits: 96,
            pAAD: encrypt_aad.as_mut_ptr(),
            ulAADLen: encrypt_aad.len() as CK_ULONG,
            ulTagBits: 128,
        };
        let mut encrypt_mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: &mut encrypt_gcm as *mut CK_GCM_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        };
        assert_eq!(
            c_encrypt_init(session, &mut encrypt_mechanism, key),
            CKR_OK as CK_RV,
            "C_EncryptInit"
        );
        assert_eq!(encrypt_iv_buffer, [0_u8; 12], "late IV is not available at init");

        let plaintext = b"loaded shim C ABI";
        let mut ciphertext_len: CK_ULONG = 0;
        assert_eq!(
            c_encrypt(
                session,
                plaintext.as_ptr() as CK_BYTE_PTR,
                plaintext.len() as CK_ULONG,
                std::ptr::null_mut(),
                &mut ciphertext_len,
            ),
            CKR_OK as CK_RV,
            "C_Encrypt(size)"
        );
        assert_eq!(encrypt_iv_buffer, [0_u8; 12], "size query must not consume delayed IV");

        let mut ciphertext = vec![0_u8; ciphertext_len as usize];
        assert_eq!(
            c_encrypt(
                session,
                plaintext.as_ptr() as CK_BYTE_PTR,
                plaintext.len() as CK_ULONG,
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
            ),
            CKR_OK as CK_RV,
            "C_Encrypt(data)"
        );

        let expected_ciphertext = plaintext.iter().map(|byte| byte ^ 0x42).collect::<Vec<_>>();
        ciphertext.truncate(ciphertext_len as usize);
        assert_eq!(ciphertext, expected_ciphertext, "mock ciphertext");
        let (encrypt_iv_len, encrypt_iv_bits) = (encrypt_gcm.ulIvLen, encrypt_gcm.ulIvBits);
        assert_eq!(
            encrypt_iv_len,
            encrypt_generated_iv.len() as CK_ULONG,
            "delayed encrypt IV length"
        );
        assert_eq!(encrypt_iv_bits, 96, "delayed encrypt IV bits");
        assert_eq!(
            encrypt_iv_buffer.as_slice(),
            encrypt_generated_iv.as_slice(),
            "delayed encrypt IV writeback"
        );

        let mut wrap_iv_buffer = [0_u8; 12];
        let mut wrap_aad = *b"wrap-aad";
        let mut wrap_gcm = CK_GCM_PARAMS {
            pIv: wrap_iv_buffer.as_mut_ptr(),
            ulIvLen: 0,
            ulIvBits: 96,
            pAAD: wrap_aad.as_mut_ptr(),
            ulAADLen: wrap_aad.len() as CK_ULONG,
            ulTagBits: 128,
        };
        let mut wrap_mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: &mut wrap_gcm as *mut CK_GCM_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        };

        let mut wrapped_len: CK_ULONG = 0;
        assert_eq!(
            c_wrap_key(
                session,
                &mut wrap_mechanism,
                wrapping_key,
                key,
                std::ptr::null_mut(),
                &mut wrapped_len,
            ),
            CKR_OK as CK_RV,
            "C_WrapKey(size)"
        );
        assert_eq!(wrapped_len, 4, "mock wrapped-key length");
        assert_eq!(wrap_iv_buffer, [0_u8; 12], "size query must not consume delayed IV");

        let mut wrapped = vec![0_u8; wrapped_len as usize];
        assert_eq!(
            c_wrap_key(
                session,
                &mut wrap_mechanism,
                wrapping_key,
                key,
                wrapped.as_mut_ptr(),
                &mut wrapped_len,
            ),
            CKR_OK as CK_RV,
            "C_WrapKey(data)"
        );

        wrapped.truncate(wrapped_len as usize);
        assert_eq!(wrapped, vec![0xDE, 0xAD, 0xBE, 0xEF], "mock wrapped-key bytes");
        let (wrap_iv_len, wrap_iv_bits) = (wrap_gcm.ulIvLen, wrap_gcm.ulIvBits);
        assert_eq!(wrap_iv_len, wrap_generated_iv.len() as CK_ULONG, "delayed wrap IV length");
        assert_eq!(wrap_iv_bits, 96, "delayed wrap IV bits");
        assert_eq!(
            wrap_iv_buffer.as_slice(),
            wrap_generated_iv.as_slice(),
            "delayed wrap IV writeback"
        );

        let mut additional_value_len = 32 as CK_ULONG;
        let mut additional_label = *b"sp800-out";
        let mut additional_template = [
            CK_ATTRIBUTE {
                type_: CKA_VALUE_LEN,
                pValue: &mut additional_value_len as *mut CK_ULONG as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: additional_label.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: additional_label.len() as CK_ULONG,
            },
        ];
        let mut additional_derived_key: CK_OBJECT_HANDLE = 0;
        let mut additional_keys = [CK_DERIVED_KEY {
            pTemplate: additional_template.as_mut_ptr(),
            ulAttributeCount: additional_template.len() as CK_ULONG,
            phKey: &mut additional_derived_key,
        }];
        let mut counter_format =
            CK_SP800_108_COUNTER_FORMAT { bLittleEndian: CK_FALSE, ulWidthInBits: 32 };
        let mut data_params = [CK_PRF_DATA_PARAM {
            type_: CK_SP800_108_ITERATION_VARIABLE,
            pValue: &mut counter_format as *mut CK_SP800_108_COUNTER_FORMAT as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_SP800_108_COUNTER_FORMAT>() as CK_ULONG,
        }];
        let mut sp800_params = CK_SP800_108_KDF_PARAMS {
            prfType: CKM_SHA256_HMAC,
            ulNumberOfDataParams: data_params.len() as CK_ULONG,
            pDataParams: data_params.as_mut_ptr(),
            ulAdditionalDerivedKeys: additional_keys.len() as CK_ULONG,
            pAdditionalDerivedKeys: additional_keys.as_mut_ptr(),
        };
        let mut sp800_mechanism = CK_MECHANISM {
            mechanism: CKM_SP800_108_COUNTER_KDF,
            pParameter: &mut sp800_params as *mut CK_SP800_108_KDF_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
        };
        let mut primary_derived_key: CK_OBJECT_HANDLE = 0;

        assert_eq!(
            c_derive_key(
                session,
                &mut sp800_mechanism,
                key,
                std::ptr::null_mut(),
                0,
                &mut primary_derived_key,
            ),
            CKR_OK as CK_RV,
            "C_DeriveKey(SP800-108)"
        );
        assert_ne!(primary_derived_key, 0, "primary derived key handle");
        assert_ne!(additional_derived_key, 0, "SP800-108 additional derived key writeback");
        assert_ne!(
            primary_derived_key, additional_derived_key,
            "primary and additional derived handles should be distinct"
        );

        let mut failure_good_value_len = 32 as CK_ULONG;
        let mut failure_bad_value_len = 0 as CK_ULONG;
        let mut failure_good_template = [CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN,
            pValue: &mut failure_good_value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        }];
        let mut failure_bad_template = [CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN,
            pValue: &mut failure_bad_value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        }];
        let mut failure_good_handle: CK_OBJECT_HANDLE = 0xCAFE_BABE;
        let mut failure_bad_handle: CK_OBJECT_HANDLE = 0xCAFE_BABE;
        let mut failure_additional_keys = [
            CK_DERIVED_KEY {
                pTemplate: failure_good_template.as_mut_ptr(),
                ulAttributeCount: failure_good_template.len() as CK_ULONG,
                phKey: &mut failure_good_handle,
            },
            CK_DERIVED_KEY {
                pTemplate: failure_bad_template.as_mut_ptr(),
                ulAttributeCount: failure_bad_template.len() as CK_ULONG,
                phKey: &mut failure_bad_handle,
            },
        ];
        let mut failure_sp800_params = CK_SP800_108_KDF_PARAMS {
            prfType: CKM_SHA256_HMAC,
            ulNumberOfDataParams: data_params.len() as CK_ULONG,
            pDataParams: data_params.as_mut_ptr(),
            ulAdditionalDerivedKeys: failure_additional_keys.len() as CK_ULONG,
            pAdditionalDerivedKeys: failure_additional_keys.as_mut_ptr(),
        };
        let mut failure_sp800_mechanism = CK_MECHANISM {
            mechanism: CKM_SP800_108_COUNTER_KDF,
            pParameter: &mut failure_sp800_params as *mut CK_SP800_108_KDF_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
        };
        let mut failure_primary_derived_key: CK_OBJECT_HANDLE = 0xCAFE_BABE;

        assert_eq!(
            c_derive_key(
                session,
                &mut failure_sp800_mechanism,
                key,
                std::ptr::null_mut(),
                0,
                &mut failure_primary_derived_key,
            ),
            CKR_TEMPLATE_INCONSISTENT as CK_RV,
            "C_DeriveKey(SP800-108 template failure)"
        );
        assert_eq!(
            failure_primary_derived_key, 0xCAFE_BABE,
            "failed SP800-108 derive must not write a primary key handle"
        );
        assert_eq!(
            failure_good_handle, 0xCAFE_BABE,
            "non-offending SP800-108 derived key handle remains caller-owned"
        );
        assert_eq!(
            failure_bad_handle, CK_INVALID_HANDLE,
            "offending SP800-108 derived key handle is set to CK_INVALID_HANDLE"
        );

        assert_eq!(c_close_session(session), CKR_OK as CK_RV, "C_CloseSession");
        let mut fresh_session: CK_SESSION_HANDLE = 0;
        assert_eq!(
            c_open_session(
                slots[0],
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &mut fresh_session,
            ),
            CKR_OK as CK_RV,
            "C_OpenSession(fresh)"
        );
        assert_eq!(
            c_destroy_object(fresh_session, additional_derived_key),
            CKR_OBJECT_HANDLE_INVALID as CK_RV,
            "C_DestroyObject(additional SP800-108 key after owner session close)"
        );
        assert_eq!(
            c_destroy_object(fresh_session, primary_derived_key),
            CKR_OBJECT_HANDLE_INVALID as CK_RV,
            "C_DestroyObject(primary SP800-108 key after owner session close)"
        );
        assert_eq!(c_close_session(fresh_session), CKR_OK as CK_RV, "C_CloseSession(fresh)");
        assert_eq!(c_finalize(std::ptr::null_mut()), CKR_OK as CK_RV, "C_Finalize");
        assert_eq!(
            c_wait_for_slot_event(CKF_DONT_BLOCK, &mut event_slot, std::ptr::null_mut()),
            CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV,
            "C_WaitForSlotEvent after C_Finalize"
        );
        assert_eq!(event_slot, 0xCAFE_BABE, "post-finalize wait must not write pSlot");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a built libpkcs11_proxy_ng_shim.so; run cargo build -p pkcs11-proxy-ng-shim first"]
async fn loaded_shim_message_begin_next_round_trips_c_stack_params() {
    let _guard = SHIM_C_ABI_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    let Some(shim_path) = find_shim_library() else {
        eprintln!(
            "[shim_c_abi_mechanism_out_test] shim library not found; \
             run cargo build -p pkcs11-proxy-ng-shim first"
        );
        return;
    };

    const CKM_SYNTHETIC_MESSAGE: CK_MECHANISM_TYPE = CKM_AES_GCM;

    let backend = Arc::new(MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType(CKM_SYNTHETIC_MESSAGE as u64)],
    ));
    let server_backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = backend.clone();
    let (endpoint, _shutdown) = common_3x::mock_daemon(server_backend).await;
    let _endpoint_guard = EnvRestore::set("PKCS11_PROXY_ENDPOINT", &endpoint);

    unsafe {
        let lib = Library::new(&shim_path).expect("dlopen shim library");
        let c_get_interface: Symbol<CGetInterface> =
            lib.get(b"C_GetInterface\0").expect("C_GetInterface symbol");
        let mut interface: CK_INTERFACE_PTR = std::ptr::null_mut();
        assert_eq!(
            c_get_interface(std::ptr::null_mut(), std::ptr::null_mut(), &mut interface, 0,),
            CKR_OK as CK_RV,
            "C_GetInterface(default)"
        );
        assert!(!interface.is_null(), "C_GetInterface returned null");
        assert!(!(*interface).pFunctionList.is_null(), "3.2 function list is null");
        let functions = &*((*interface).pFunctionList as *const CK_FUNCTION_LIST_3_2);
        assert_eq!(functions.version.major, 3, "default interface major version");
        assert_eq!(functions.version.minor, 2, "default interface minor version");

        let c_initialize = functions.C_Initialize.expect("C_Initialize");
        let c_finalize = functions.C_Finalize.expect("C_Finalize");
        let _finalize_on_drop = FinalizeOnDrop(c_finalize);
        let c_get_slot_list = functions.C_GetSlotList.expect("C_GetSlotList");
        let c_open_session = functions.C_OpenSession.expect("C_OpenSession");
        let c_close_session = functions.C_CloseSession.expect("C_CloseSession");
        let c_create_object = functions.C_CreateObject.expect("C_CreateObject");
        let c_message_encrypt_init = functions.C_MessageEncryptInit.expect("C_MessageEncryptInit");
        let c_encrypt_message = functions.C_EncryptMessage.expect("C_EncryptMessage");
        let c_encrypt_message_begin =
            functions.C_EncryptMessageBegin.expect("C_EncryptMessageBegin");
        let c_encrypt_message_next = functions.C_EncryptMessageNext.expect("C_EncryptMessageNext");
        let c_message_encrypt_final =
            functions.C_MessageEncryptFinal.expect("C_MessageEncryptFinal");
        let c_message_decrypt_init = functions.C_MessageDecryptInit.expect("C_MessageDecryptInit");
        let c_decrypt_message = functions.C_DecryptMessage.expect("C_DecryptMessage");
        let c_decrypt_message_begin =
            functions.C_DecryptMessageBegin.expect("C_DecryptMessageBegin");
        let c_decrypt_message_next = functions.C_DecryptMessageNext.expect("C_DecryptMessageNext");
        let c_message_decrypt_final =
            functions.C_MessageDecryptFinal.expect("C_MessageDecryptFinal");

        assert_eq!(c_initialize(std::ptr::null_mut()), CKR_OK as CK_RV, "C_Initialize");

        let mut slot_count: CK_ULONG = 0;
        assert_eq!(
            c_get_slot_list(CK_TRUE, std::ptr::null_mut(), &mut slot_count),
            CKR_OK as CK_RV,
            "C_GetSlotList(size)"
        );
        assert!(slot_count > 0, "mock daemon should expose at least one token slot");
        let mut slots = vec![0 as CK_SLOT_ID; slot_count as usize];
        assert_eq!(
            c_get_slot_list(CK_TRUE, slots.as_mut_ptr(), &mut slot_count),
            CKR_OK as CK_RV,
            "C_GetSlotList(data)"
        );

        let mut session: CK_SESSION_HANDLE = 0;
        assert_eq!(
            c_open_session(slots[0], CKF_SERIAL_SESSION, std::ptr::null_mut(), None, &mut session),
            CKR_OK as CK_RV,
            "C_OpenSession"
        );

        let mut object_class = CKO_SECRET_KEY;
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &mut object_class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        }];
        let mut key: CK_OBJECT_HANDLE = 0;
        assert_eq!(
            c_create_object(session, template.as_mut_ptr(), template.len() as CK_ULONG, &mut key),
            CKR_OK as CK_RV,
            "C_CreateObject(key)"
        );

        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_SYNTHETIC_MESSAGE,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut aad = *b"msg-aad";
        let mut iv = [0x11_u8; 12];
        let mut tag = [0_u8; 16];
        let mut gcm_message = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 96,
            ivGenerator: CKG_NO_GENERATE,
            pTag: tag.as_mut_ptr(),
            ulTagBits: 128,
        };

        mechanism.pParameter = (&mut gcm_message as *mut CK_GCM_MESSAGE_PARAMS).cast();
        mechanism.ulParameterLen = std::mem::size_of_val(&gcm_message) as CK_ULONG;

        let before_init = backend.message_init_contract_call_count();
        assert_eq!(
            c_message_encrypt_init(session, &mut mechanism, key),
            CKR_OK as CK_RV,
            "C_MessageEncryptInit"
        );
        assert_eq!(
            backend.message_init_contract_call_count(),
            before_init + 1,
            "structured Encrypt Init reaches one backend trait method",
        );
        let (init_parameter, init_spec) = backend
            .last_message_init_contract()
            .expect("structured Encrypt Init backend observation");
        assert!(matches!(init_parameter, MessageParameter::GcmMessage(_)));
        assert_eq!(
            init_spec.buffer_len,
            std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as u64,
            "provider receives its daemon-native GCM message struct size",
        );
        assert_eq!(iv, [0x11; 12], "Init does not write caller IV");
        assert_eq!(tag, [0; 16], "Init does not write caller tag");

        let alias_input = [0x31_u8; 8];
        let mut alias_output = [0_u8; 8];
        let mut aliased_output_len = alias_output.len() as CK_ULONG;
        let mut aliased_gcm = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 96,
            ivGenerator: CKG_NO_GENERATE,
            pTag: (&mut aliased_output_len as CK_ULONG_PTR).cast(),
            ulTagBits: (std::mem::size_of::<CK_ULONG>() * 8) as CK_ULONG,
        };
        let before_alias = backend.message_parameter_call_count();
        assert_eq!(
            c_encrypt_message(
                session,
                (&mut aliased_gcm as *mut CK_GCM_MESSAGE_PARAMS).cast(),
                std::mem::size_of_val(&aliased_gcm) as CK_ULONG,
                aad.as_mut_ptr(),
                aad.len() as CK_ULONG,
                alias_input.as_ptr() as CK_BYTE_PTR,
                alias_input.len() as CK_ULONG,
                alias_output.as_mut_ptr(),
                &mut aliased_output_len,
            ),
            CKR_MECHANISM_PARAM_INVALID as CK_RV,
            "output-length alias with embedded tag is rejected"
        );
        assert_eq!(
            backend.message_parameter_call_count(),
            before_alias,
            "alias rejection happens before RPC/backend invocation"
        );

        let mut partial = [0x42_u8; 16];
        let mut partial_output_len = 8 as CK_ULONG;
        assert_eq!(
            c_encrypt_message(
                session,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                partial.as_mut_ptr(),
                8,
                partial.as_mut_ptr().add(1),
                &mut partial_output_len,
            ),
            CKR_MECHANISM_PARAM_INVALID as CK_RV,
            "partial main-buffer overlap is rejected"
        );
        assert_eq!(
            backend.message_parameter_call_count(),
            before_alias,
            "partial-overlap rejection happens before RPC/backend invocation"
        );

        let mut in_place = [0x24_u8; 8];
        let mut in_place_len = in_place.len() as CK_ULONG;
        let in_place_rv = c_encrypt_message(
            session,
            (&mut gcm_message as *mut CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&gcm_message) as CK_ULONG,
            std::ptr::null_mut(),
            0,
            in_place.as_mut_ptr(),
            in_place.len() as CK_ULONG,
            in_place.as_mut_ptr(),
            &mut in_place_len,
        );
        assert_ne!(
            in_place_rv, CKR_MECHANISM_PARAM_INVALID as CK_RV,
            "exact same-base in-place use crosses the transport alias seam"
        );
        assert_eq!(
            backend.message_parameter_call_count(),
            before_alias + 1,
            "accepted in-place call reaches the backend exactly once"
        );

        iv.fill(0x11);
        tag.fill(0x22);
        gcm_message.ulIvFixedBits = 32;
        gcm_message.ivGenerator = CKG_GENERATE;
        let begin_calls = backend.message_begin_call_count();
        assert_eq!(
            c_encrypt_message_begin(
                session,
                &mut gcm_message as *mut CK_GCM_MESSAGE_PARAMS as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                aad.as_mut_ptr(),
                aad.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV,
            "C_EncryptMessageBegin"
        );
        assert_eq!(
            backend.message_begin_call_count(),
            begin_calls + 1,
            "one native Encrypt Begin call reaches exactly one backend trait method"
        );
        let mut generated_iv = [0x7b_u8; 12];
        generated_iv[..4].fill(0x11);
        assert_eq!(iv, generated_iv, "Encrypt Begin writes the generated IV suffix");
        assert_eq!(tag, [0x22; 16], "Encrypt Begin does not write the final tag");

        let plaintext_feed = b"loaded message ";
        let mut feed_ciphertext_len = plaintext_feed.len() as CK_ULONG;
        let mut feed_ciphertext = vec![0_u8; plaintext_feed.len()];
        let before_next = backend.message_parameter_call_count();
        assert_eq!(
            c_encrypt_message_next(
                session,
                &mut gcm_message as *mut CK_GCM_MESSAGE_PARAMS as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                plaintext_feed.as_ptr() as CK_BYTE_PTR,
                plaintext_feed.len() as CK_ULONG,
                feed_ciphertext.as_mut_ptr(),
                &mut feed_ciphertext_len,
                0,
            ),
            CKR_OK as CK_RV,
            "C_EncryptMessageNext(non-final)"
        );
        assert_eq!(
            backend.message_parameter_call_count(),
            before_next + 1,
            "non-final Encrypt Next reaches one backend trait method",
        );
        match backend.last_message_parameter_call().expect("non-final Encrypt Next parameter") {
            MessageParameter::GcmMessage(parameter) => {
                assert_eq!(parameter.iv, generated_iv);
                assert_eq!(parameter.tag, vec![0; 16]);
            }
            other => panic!("unexpected non-final Encrypt Next parameter: {other:?}"),
        }
        feed_ciphertext.truncate(feed_ciphertext_len as usize);
        assert_eq!(tag, [0x22; 16], "non-final Encrypt Next does not write the tag");

        let plaintext_final = b"begin next";
        let mut final_ciphertext_len = plaintext_final.len() as CK_ULONG;
        let mut final_ciphertext = vec![0_u8; plaintext_final.len()];
        let before_next = backend.message_parameter_call_count();
        assert_eq!(
            c_encrypt_message_next(
                session,
                &mut gcm_message as *mut CK_GCM_MESSAGE_PARAMS as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                plaintext_final.as_ptr() as CK_BYTE_PTR,
                plaintext_final.len() as CK_ULONG,
                final_ciphertext.as_mut_ptr(),
                &mut final_ciphertext_len,
                CKF_END_OF_MESSAGE,
            ),
            CKR_OK as CK_RV,
            "C_EncryptMessageNext(final)"
        );
        assert_eq!(
            backend.message_parameter_call_count(),
            before_next + 1,
            "final Encrypt Next reaches one backend trait method",
        );
        match backend.last_message_parameter_call().expect("final Encrypt Next parameter") {
            MessageParameter::GcmMessage(parameter) => {
                assert_eq!(parameter.iv, generated_iv);
                assert_eq!(parameter.tag, vec![0; 16]);
            }
            other => panic!("unexpected final Encrypt Next parameter: {other:?}"),
        }
        final_ciphertext.truncate(final_ciphertext_len as usize);
        let mut ciphertext = feed_ciphertext;
        ciphertext.extend_from_slice(&final_ciphertext);
        let mut plaintext = plaintext_feed.to_vec();
        plaintext.extend_from_slice(plaintext_final);
        assert_eq!(
            ciphertext,
            plaintext.iter().map(|byte| byte ^ 0x42).collect::<Vec<_>>(),
            "mock message ciphertext"
        );
        assert_eq!(tag, [0xA5_u8; 16], "C_EncryptMessageNext writes GCM tag");
        assert_eq!(c_message_encrypt_final(session), CKR_OK as CK_RV, "C_MessageEncryptFinal");

        let mut empty_parameter_sentinel = 0x5a_u8;
        for (direction, init, one_shot, begin, next, final_call) in [
            (
                "Encrypt",
                c_message_encrypt_init,
                c_encrypt_message,
                c_encrypt_message_begin,
                c_encrypt_message_next,
                c_message_encrypt_final,
            ),
            (
                "Decrypt",
                c_message_decrypt_init,
                c_decrypt_message,
                c_decrypt_message_begin,
                c_decrypt_message_next,
                c_message_decrypt_final,
            ),
        ] {
            let empty_parameter_classes = [
                (std::ptr::null_mut(), 0, "NULL/zero"),
                (std::ptr::null_mut(), 7, "NULL/positive"),
                ((&mut empty_parameter_sentinel as *mut u8).cast(), 0, "non-NULL/zero"),
            ];
            for (parameter, parameter_len, class) in empty_parameter_classes {
                mechanism.pParameter = parameter;
                mechanism.ulParameterLen = parameter_len;
                let init_calls = backend.message_init_contract_call_count();
                assert_eq!(
                    init(session, &mut mechanism, key),
                    CKR_OK as CK_RV,
                    "C_Message{direction}Init({class})"
                );
                assert_eq!(
                    backend.message_init_contract_call_count(),
                    init_calls + 1,
                    "{direction} Init {class} reaches the backend exactly once",
                );
                let (p_parameter, ul_parameter_len) =
                    (mechanism.pParameter, mechanism.ulParameterLen);
                assert_eq!(p_parameter, parameter, "{direction} Init {class} pointer echo");
                assert_eq!(ul_parameter_len, parameter_len, "{direction} Init {class} length echo",);

                let input = [0x31_u8];
                let mut output = [0_u8];
                let mut output_len = output.len() as CK_ULONG;
                let one_shot_calls = backend.message_parameter_call_count();
                assert_eq!(
                    one_shot(
                        session,
                        parameter,
                        parameter_len,
                        std::ptr::null_mut(),
                        0,
                        input.as_ptr() as CK_BYTE_PTR,
                        input.len() as CK_ULONG,
                        output.as_mut_ptr(),
                        &mut output_len,
                    ),
                    CKR_OK as CK_RV,
                    "C_{direction}Message({class})",
                );
                assert_eq!(
                    backend.message_parameter_call_count(),
                    one_shot_calls + 1,
                    "{direction} one-shot {class} reaches the backend exactly once",
                );

                let begin_calls = backend.message_begin_call_count();
                assert_eq!(
                    begin(
                        session,
                        parameter,
                        parameter_len,
                        aad.as_mut_ptr(),
                        aad.len() as CK_ULONG,
                    ),
                    CKR_OK as CK_RV,
                    "C_{direction}MessageBegin({class})",
                );
                assert_eq!(
                    backend.message_begin_call_count(),
                    begin_calls + 1,
                    "{direction} Begin {class} reaches the backend exactly once",
                );

                output.fill(0);
                output_len = output.len() as CK_ULONG;
                let next_calls = backend.message_parameter_call_count();
                assert_eq!(
                    next(
                        session,
                        parameter,
                        parameter_len,
                        input.as_ptr() as CK_BYTE_PTR,
                        input.len() as CK_ULONG,
                        output.as_mut_ptr(),
                        &mut output_len,
                        CKF_END_OF_MESSAGE,
                    ),
                    CKR_OK as CK_RV,
                    "C_{direction}MessageNext({class})",
                );
                assert_eq!(
                    backend.message_parameter_call_count(),
                    next_calls + 1,
                    "{direction} Next {class} reaches the backend exactly once",
                );
                assert_eq!(empty_parameter_sentinel, 0x5a, "{direction} {class} caller bytes");
                assert_eq!(
                    final_call(session),
                    CKR_OK as CK_RV,
                    "C_Message{direction}Final({class})",
                );
            }
        }

        mechanism.pParameter = (&mut gcm_message as *mut CK_GCM_MESSAGE_PARAMS).cast();
        mechanism.ulParameterLen = std::mem::size_of_val(&gcm_message) as CK_ULONG;
        let before_init = backend.message_init_contract_call_count();
        assert_eq!(
            c_message_decrypt_init(session, &mut mechanism, key),
            CKR_OK as CK_RV,
            "C_MessageDecryptInit"
        );
        assert_eq!(
            backend.message_init_contract_call_count(),
            before_init + 1,
            "structured Decrypt Init reaches one backend trait method",
        );
        match backend
            .last_message_init_contract()
            .expect("structured Decrypt Init backend observation")
            .0
        {
            MessageParameter::GcmMessage(parameter) => {
                assert_eq!(parameter.iv, generated_iv);
                assert_eq!(parameter.tag, vec![0; 16], "Decrypt Init does not read the tag");
            }
            other => panic!("unexpected Decrypt Init parameter: {other:?}"),
        }
        assert_eq!(tag, [0xA5; 16], "Decrypt Init does not write caller tag");

        let mut one_shot_recovered_len = ciphertext.len() as CK_ULONG;
        let mut one_shot_recovered = vec![0_u8; ciphertext.len()];
        let before_one_shot = backend.message_parameter_call_count();
        assert_eq!(
            c_decrypt_message(
                session,
                (&mut gcm_message as *mut CK_GCM_MESSAGE_PARAMS).cast(),
                std::mem::size_of_val(&gcm_message) as CK_ULONG,
                std::ptr::null_mut(),
                0,
                ciphertext.as_ptr() as CK_BYTE_PTR,
                ciphertext.len() as CK_ULONG,
                one_shot_recovered.as_mut_ptr(),
                &mut one_shot_recovered_len,
            ),
            CKR_OK as CK_RV,
            "C_DecryptMessage",
        );
        assert_eq!(
            backend.message_parameter_call_count(),
            before_one_shot + 1,
            "Decrypt one-shot reaches one backend trait method",
        );
        match backend.last_message_parameter_call().expect("Decrypt one-shot parameter") {
            MessageParameter::GcmMessage(parameter) => {
                assert_eq!(parameter.iv, generated_iv);
                assert_eq!(parameter.tag, vec![0xA5; 16]);
            }
            other => panic!("unexpected Decrypt one-shot parameter: {other:?}"),
        }
        one_shot_recovered.truncate(one_shot_recovered_len as usize);
        assert_eq!(one_shot_recovered, plaintext, "Decrypt one-shot plaintext");
        assert_eq!(tag, [0xA5; 16], "Decrypt one-shot never overwrites caller tag");

        let begin_calls = backend.message_begin_call_count();
        assert_eq!(
            c_decrypt_message_begin(
                session,
                &mut gcm_message as *mut CK_GCM_MESSAGE_PARAMS as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                aad.as_mut_ptr(),
                aad.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV,
            "C_DecryptMessageBegin"
        );
        assert_eq!(
            backend.message_begin_call_count(),
            begin_calls + 1,
            "one native Decrypt Begin call reaches exactly one backend trait method"
        );
        assert_eq!(tag, [0xA5; 16], "Decrypt Begin never overwrites caller tag");

        let feed_len = plaintext_feed.len();
        let mut recovered_feed_len = feed_len as CK_ULONG;
        let mut recovered_feed = vec![0_u8; feed_len];
        let before_next = backend.message_parameter_call_count();
        assert_eq!(
            c_decrypt_message_next(
                session,
                &mut gcm_message as *mut CK_GCM_MESSAGE_PARAMS as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                ciphertext.as_ptr() as CK_BYTE_PTR,
                feed_len as CK_ULONG,
                recovered_feed.as_mut_ptr(),
                &mut recovered_feed_len,
                0,
            ),
            CKR_OK as CK_RV,
            "C_DecryptMessageNext(non-final)"
        );
        assert_eq!(
            backend.message_parameter_call_count(),
            before_next + 1,
            "non-final Decrypt Next reaches one backend trait method",
        );
        match backend.last_message_parameter_call().expect("non-final Decrypt Next parameter") {
            MessageParameter::GcmMessage(parameter) => {
                assert_eq!(parameter.iv, generated_iv);
                assert_eq!(parameter.tag, vec![0; 16]);
            }
            other => panic!("unexpected non-final Decrypt Next parameter: {other:?}"),
        }
        recovered_feed.truncate(recovered_feed_len as usize);
        assert_eq!(tag, [0xA5; 16], "non-final Decrypt Next preserves caller tag");

        let mut recovered_final_len = (ciphertext.len() - feed_len) as CK_ULONG;
        let mut recovered_final = vec![0_u8; ciphertext.len() - feed_len];
        let before_next = backend.message_parameter_call_count();
        assert_eq!(
            c_decrypt_message_next(
                session,
                &mut gcm_message as *mut CK_GCM_MESSAGE_PARAMS as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                ciphertext.as_ptr().add(feed_len) as CK_BYTE_PTR,
                (ciphertext.len() - feed_len) as CK_ULONG,
                recovered_final.as_mut_ptr(),
                &mut recovered_final_len,
                CKF_END_OF_MESSAGE,
            ),
            CKR_OK as CK_RV,
            "C_DecryptMessageNext(final)"
        );
        assert_eq!(
            backend.message_parameter_call_count(),
            before_next + 1,
            "final Decrypt Next reaches one backend trait method",
        );
        match backend.last_message_parameter_call().expect("final Decrypt Next parameter") {
            MessageParameter::GcmMessage(parameter) => {
                assert_eq!(parameter.iv, generated_iv);
                assert_eq!(parameter.tag, vec![0xA5; 16]);
            }
            other => panic!("unexpected final Decrypt Next parameter: {other:?}"),
        }
        recovered_final.truncate(recovered_final_len as usize);
        let mut recovered = recovered_feed;
        recovered.extend_from_slice(&recovered_final);
        assert_eq!(recovered, plaintext, "mock message plaintext");
        assert_eq!(tag, [0xA5_u8; 16], "C_DecryptMessageNext preserves caller GCM tag");
        assert_eq!(c_message_decrypt_final(session), CKR_OK as CK_RV, "C_MessageDecryptFinal");

        assert_eq!(c_close_session(session), CKR_OK as CK_RV, "C_CloseSession");
        assert_eq!(c_finalize(std::ptr::null_mut()), CKR_OK as CK_RV, "C_Finalize");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a built libpkcs11_proxy_ng_shim.so; run cargo build -p pkcs11-proxy-ng-shim first"]
async fn loaded_shim_sign_verify_message_preserves_empty_parameter_classes_once_per_call() {
    let _guard = SHIM_C_ABI_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    let Some(shim_path) = find_shim_library() else {
        eprintln!(
            "[shim_c_abi_mechanism_out_test] shim library not found; \
             run cargo build -p pkcs11-proxy-ng-shim first"
        );
        return;
    };

    let backend =
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType(CKM_AES_GCM as u64)]));
    let server_backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = backend.clone();
    let (endpoint, _shutdown) = common_3x::mock_daemon(server_backend).await;
    let _endpoint_guard = EnvRestore::set("PKCS11_PROXY_ENDPOINT", &endpoint);

    unsafe {
        let lib = Library::new(&shim_path).expect("dlopen shim library");
        let c_get_interface: Symbol<CGetInterface> =
            lib.get(b"C_GetInterface\0").expect("C_GetInterface symbol");
        let mut interface: CK_INTERFACE_PTR = std::ptr::null_mut();
        assert_eq!(
            c_get_interface(std::ptr::null_mut(), std::ptr::null_mut(), &mut interface, 0),
            CKR_OK as CK_RV,
        );
        let functions = &*((*interface).pFunctionList as *const CK_FUNCTION_LIST_3_2);
        let c_initialize = functions.C_Initialize.expect("C_Initialize");
        let c_finalize = functions.C_Finalize.expect("C_Finalize");
        let _finalize_on_drop = FinalizeOnDrop(c_finalize);
        let c_get_slot_list = functions.C_GetSlotList.expect("C_GetSlotList");
        let c_open_session = functions.C_OpenSession.expect("C_OpenSession");
        let c_close_session = functions.C_CloseSession.expect("C_CloseSession");
        let c_create_object = functions.C_CreateObject.expect("C_CreateObject");
        let c_message_sign_init = functions.C_MessageSignInit.expect("C_MessageSignInit");
        let c_sign_message = functions.C_SignMessage.expect("C_SignMessage");
        let c_sign_message_begin = functions.C_SignMessageBegin.expect("C_SignMessageBegin");
        let c_sign_message_next = functions.C_SignMessageNext.expect("C_SignMessageNext");
        let c_message_sign_final = functions.C_MessageSignFinal.expect("C_MessageSignFinal");
        let c_message_verify_init = functions.C_MessageVerifyInit.expect("C_MessageVerifyInit");
        let c_verify_message = functions.C_VerifyMessage.expect("C_VerifyMessage");
        let c_verify_message_begin = functions.C_VerifyMessageBegin.expect("C_VerifyMessageBegin");
        let c_verify_message_next = functions.C_VerifyMessageNext.expect("C_VerifyMessageNext");
        let c_message_verify_final = functions.C_MessageVerifyFinal.expect("C_MessageVerifyFinal");

        assert_eq!(c_initialize(std::ptr::null_mut()), CKR_OK as CK_RV);
        let mut slot_count = 0;
        assert_eq!(
            c_get_slot_list(CK_TRUE, std::ptr::null_mut(), &mut slot_count),
            CKR_OK as CK_RV,
        );
        let mut slots = vec![0; slot_count as usize];
        assert_eq!(c_get_slot_list(CK_TRUE, slots.as_mut_ptr(), &mut slot_count), CKR_OK as CK_RV,);
        let mut session = 0;
        assert_eq!(
            c_open_session(slots[0], CKF_SERIAL_SESSION, std::ptr::null_mut(), None, &mut session,),
            CKR_OK as CK_RV,
        );
        let mut object_class = CKO_SECRET_KEY;
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: (&mut object_class as *mut CK_OBJECT_CLASS).cast(),
            ulValueLen: mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        }];
        let mut key = 0;
        assert_eq!(c_create_object(session, template.as_mut_ptr(), 1, &mut key), CKR_OK as CK_RV,);
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        assert_eq!(c_message_sign_init(session, &mut mechanism, key), CKR_OK as CK_RV);
        let empty_classes = [
            (std::ptr::null_mut(), "NULL/zero"),
            (std::ptr::NonNull::<u8>::dangling().as_ptr().cast(), "non-NULL/zero"),
        ];
        for (parameter, class) in empty_classes {
            let data = b"sign one shot";
            let mut signature = vec![0; data.len()];
            let mut signature_len = signature.len() as CK_ULONG;
            let before = backend.message_parameter_call_count();
            assert_eq!(
                c_sign_message(
                    session,
                    parameter,
                    0,
                    data.as_ptr() as CK_BYTE_PTR,
                    data.len() as CK_ULONG,
                    signature.as_mut_ptr(),
                    &mut signature_len,
                ),
                CKR_OK as CK_RV,
                "C_SignMessage({class})",
            );
            assert_eq!(backend.message_parameter_call_count(), before + 1, "{class} one-shot");
            assert_eq!(signature, data.iter().rev().copied().collect::<Vec<_>>());

            let before = backend.message_parameter_call_count();
            assert_eq!(
                c_sign_message_begin(session, parameter, 0),
                CKR_OK as CK_RV,
                "C_SignMessageBegin({class})",
            );
            assert_eq!(backend.message_parameter_call_count(), before + 1, "{class} begin");

            let nonfinal = b"sign feed";
            let before = backend.message_parameter_call_count();
            assert_eq!(
                c_sign_message_next(
                    session,
                    parameter,
                    0,
                    nonfinal.as_ptr() as CK_BYTE_PTR,
                    nonfinal.len() as CK_ULONG,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ),
                CKR_OK as CK_RV,
                "C_SignMessageNext(feed,{class})",
            );
            assert_eq!(backend.message_parameter_call_count(), before + 1, "{class} feed");

            let final_data = b"sign final";
            let mut final_signature = vec![0; final_data.len()];
            let mut final_signature_len = final_signature.len() as CK_ULONG;
            let before = backend.message_parameter_call_count();
            assert_eq!(
                c_sign_message_next(
                    session,
                    parameter,
                    0,
                    final_data.as_ptr() as CK_BYTE_PTR,
                    final_data.len() as CK_ULONG,
                    final_signature.as_mut_ptr(),
                    &mut final_signature_len,
                ),
                CKR_OK as CK_RV,
                "C_SignMessageNext(final,{class})",
            );
            assert_eq!(backend.message_parameter_call_count(), before + 1, "{class} final");
            assert_eq!(final_signature, final_data.iter().rev().copied().collect::<Vec<_>>());
        }

        let poison = std::ptr::without_provenance_mut::<std::ffi::c_void>(1);
        let poison_data = b"poison";
        let mut poison_signature = vec![0; poison_data.len()];
        let mut poison_signature_len = poison_signature.len() as CK_ULONG;
        let before = backend.message_parameter_call_count();
        assert_eq!(
            c_sign_message(
                session,
                poison,
                1,
                poison_data.as_ptr() as CK_BYTE_PTR,
                poison_data.len() as CK_ULONG,
                poison_signature.as_mut_ptr(),
                &mut poison_signature_len,
            ),
            CKR_MECHANISM_PARAM_INVALID as CK_RV,
        );
        assert_eq!(c_sign_message_begin(session, poison, 1), CKR_MECHANISM_PARAM_INVALID as CK_RV);
        assert_eq!(
            c_sign_message_next(
                session,
                poison,
                1,
                poison_data.as_ptr() as CK_BYTE_PTR,
                poison_data.len() as CK_ULONG,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ),
            CKR_MECHANISM_PARAM_INVALID as CK_RV,
        );
        assert_eq!(
            c_sign_message_next(
                session,
                poison,
                1,
                poison_data.as_ptr() as CK_BYTE_PTR,
                poison_data.len() as CK_ULONG,
                poison_signature.as_mut_ptr(),
                &mut poison_signature_len,
            ),
            CKR_MECHANISM_PARAM_INVALID as CK_RV,
        );
        assert_eq!(
            backend.message_parameter_call_count(),
            before,
            "positive Sign parameters fail before backend invocation",
        );
        assert_eq!(c_message_sign_final(session), CKR_OK as CK_RV);

        assert_eq!(c_message_verify_init(session, &mut mechanism, key), CKR_OK as CK_RV);
        for (parameter, class) in empty_classes {
            let data = b"verify one shot";
            let signature = data.iter().rev().copied().collect::<Vec<_>>();
            let before = backend.message_parameter_call_count();
            assert_eq!(
                c_verify_message(
                    session,
                    parameter,
                    0,
                    data.as_ptr() as CK_BYTE_PTR,
                    data.len() as CK_ULONG,
                    signature.as_ptr() as CK_BYTE_PTR,
                    signature.len() as CK_ULONG,
                ),
                CKR_OK as CK_RV,
                "C_VerifyMessage({class})",
            );
            assert_eq!(backend.message_parameter_call_count(), before + 1, "{class} one-shot");

            let before = backend.message_parameter_call_count();
            assert_eq!(
                c_verify_message_begin(session, parameter, 0),
                CKR_OK as CK_RV,
                "C_VerifyMessageBegin({class})",
            );
            assert_eq!(backend.message_parameter_call_count(), before + 1, "{class} begin");

            let nonfinal = b"verify feed";
            let before = backend.message_parameter_call_count();
            assert_eq!(
                c_verify_message_next(
                    session,
                    parameter,
                    0,
                    nonfinal.as_ptr() as CK_BYTE_PTR,
                    nonfinal.len() as CK_ULONG,
                    std::ptr::null_mut(),
                    0,
                ),
                CKR_OK as CK_RV,
                "C_VerifyMessageNext(feed,{class})",
            );
            assert_eq!(backend.message_parameter_call_count(), before + 1, "{class} feed");

            let final_data = b"verify final";
            let final_signature = final_data.iter().rev().copied().collect::<Vec<_>>();
            let before = backend.message_parameter_call_count();
            assert_eq!(
                c_verify_message_next(
                    session,
                    parameter,
                    0,
                    final_data.as_ptr() as CK_BYTE_PTR,
                    final_data.len() as CK_ULONG,
                    final_signature.as_ptr() as CK_BYTE_PTR,
                    final_signature.len() as CK_ULONG,
                ),
                CKR_OK as CK_RV,
                "C_VerifyMessageNext(final,{class})",
            );
            assert_eq!(backend.message_parameter_call_count(), before + 1, "{class} final");
        }

        let verify_signature = poison_data.iter().rev().copied().collect::<Vec<_>>();
        let before = backend.message_parameter_call_count();
        assert_eq!(
            c_verify_message(
                session,
                poison,
                1,
                poison_data.as_ptr() as CK_BYTE_PTR,
                poison_data.len() as CK_ULONG,
                verify_signature.as_ptr() as CK_BYTE_PTR,
                verify_signature.len() as CK_ULONG,
            ),
            CKR_MECHANISM_PARAM_INVALID as CK_RV,
        );
        assert_eq!(
            c_verify_message_begin(session, poison, 1),
            CKR_MECHANISM_PARAM_INVALID as CK_RV,
        );
        assert_eq!(
            c_verify_message_next(
                session,
                poison,
                1,
                poison_data.as_ptr() as CK_BYTE_PTR,
                poison_data.len() as CK_ULONG,
                std::ptr::null_mut(),
                0,
            ),
            CKR_MECHANISM_PARAM_INVALID as CK_RV,
        );
        assert_eq!(
            c_verify_message_next(
                session,
                poison,
                1,
                poison_data.as_ptr() as CK_BYTE_PTR,
                poison_data.len() as CK_ULONG,
                verify_signature.as_ptr() as CK_BYTE_PTR,
                verify_signature.len() as CK_ULONG,
            ),
            CKR_MECHANISM_PARAM_INVALID as CK_RV,
        );
        assert_eq!(
            backend.message_parameter_call_count(),
            before,
            "positive Verify parameters fail before backend invocation",
        );
        assert_eq!(c_message_verify_final(session), CKR_OK as CK_RV);

        assert_eq!(c_close_session(session), CKR_OK as CK_RV);
        assert_eq!(c_finalize(std::ptr::null_mut()), CKR_OK as CK_RV);
    }
}

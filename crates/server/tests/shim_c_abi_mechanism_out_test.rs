//! End-to-end shim C ABI coverage for HSM-mutated mechanism parameters.
//!
//! This test loads `libpkcs11_proxy_ng_shim.so` with `dlopen`, calls through
//! the exported PKCS#11 function list, and verifies that the caller's
//! stack-owned `CK_GCM_PARAMS` receives delayed generated-IV writeback after
//! `C_Encrypt` and `C_WrapKey`, that SP800-108 nested `CK_DERIVED_KEY` handles
//! are written back through `C_DeriveKey` and invalidated when their owning
//! session closes, and that slot-event lifecycle errors survive the loaded shim
//! function-list path. It also verifies that no-source mechanism-info flags are
//! returned through a real caller-owned `CK_MECHANISM_INFO` stack struct without
//! inventing workflow flags, and that message Begin/Next functions operate
//! through caller-owned raw and typed message parameter buffers.

mod common_3x;

use std::mem;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use cryptoki_sys::*;
use libloading::{Library, Symbol};
use pkcs11_proxy_ng_backend::MockBackend;
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

        let backend1 =
            Arc::new(MockBackend::new(vec![CkSlotId(0x11)], vec![CkMechanismType(CKM_AES_GCM)]));
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

        let backend2 =
            Arc::new(MockBackend::new(vec![CkSlotId(0x22)], vec![CkMechanismType(CKM_AES_CBC)]));
        let (endpoint2, _shutdown2) = common_3x::mock_daemon(backend2).await;
        let _endpoint_guard2 = EnvRestore::set("PKCS11_PROXY_ENDPOINT", &endpoint2);

        let mut function_list: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
        assert_eq!(c_get_function_list(&mut function_list), CKR_OK as CK_RV, "C_GetFunctionList");
        assert!(!function_list.is_null(), "C_GetFunctionList returned null");
        let functions = &*function_list;
        let c_initialize = functions.C_Initialize.expect("C_Initialize");
        let c_finalize = functions.C_Finalize.expect("C_Finalize");
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
async fn loaded_shim_preserves_no_source_mechanism_info_zero_flags() {
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
    const CKM_DES_CBC: CK_MECHANISM_TYPE = 0x0000_0122;

    let backend = Arc::new(MockBackend::new(
        vec![CkSlotId(0)],
        vec![
            CkMechanismType(CKM_BATON_KEY_GEN),
            CkMechanismType(CKM_CAMELLIA_CTR),
            CkMechanismType(CKM_DES_CBC),
        ],
    ));
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

        for (mechanism, label) in [
            (CKM_BATON_KEY_GEN, "CKM_BATON_KEY_GEN"),
            (CKM_CAMELLIA_CTR, "CKM_CAMELLIA_CTR"),
            (CKM_DES_CBC, "CKM_DES_CBC"),
        ] {
            let mut info =
                CK_MECHANISM_INFO { ulMinKeySize: 0xCAFE, ulMaxKeySize: 0xBABE, flags: 0xFFFF };
            assert_eq!(
                c_get_mechanism_info(slots[0], mechanism, &mut info),
                CKR_OK as CK_RV,
                "C_GetMechanismInfo({label})"
            );
            assert_eq!(info.ulMinKeySize, 2048, "{label} min key size");
            assert_eq!(info.ulMaxKeySize, 4096, "{label} max key size");
            assert_eq!(info.flags, 0, "{label} flags must not be inferred");
        }

        assert_eq!(c_finalize(std::ptr::null_mut()), CKR_OK as CK_RV, "C_Finalize");
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
            CkMechanismType(CKM_SP800_108_COUNTER_KDF),
            CkMechanismType(CKM_BATON_KEY_GEN),
        ],
    ));
    backend.set_encrypt_exact_output(Some(CkMechanismParams::Gcm(GcmParams {
        iv: encrypt_generated_iv.clone(),
        iv_bits: 96,
        iv_buffer_len: encrypt_generated_iv.len() as u64,
        aad: b"aad".to_vec(),
        tag_bits: 128,
    })));
    backend.set_wrap_key_exact_output(Some(CkMechanismParams::Gcm(GcmParams {
        iv: wrap_generated_iv.clone(),
        iv_bits: 96,
        iv_buffer_len: wrap_generated_iv.len() as u64,
        aad: b"wrap-aad".to_vec(),
        tag_bits: 128,
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
        assert_eq!(baton_info.ulMinKeySize, 2048, "no-source min key size");
        assert_eq!(baton_info.ulMaxKeySize, 4096, "no-source max key size");
        assert_eq!(baton_info.flags, 0, "no-source mechanism flags must not be inferred");

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
        assert_eq!(
            encrypt_gcm.ulIvLen,
            encrypt_generated_iv.len() as CK_ULONG,
            "delayed encrypt IV length"
        );
        assert_eq!(encrypt_gcm.ulIvBits, 96, "delayed encrypt IV bits");
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
        assert_eq!(wrap_gcm.ulIvLen, wrap_generated_iv.len() as CK_ULONG, "delayed wrap IV length");
        assert_eq!(wrap_gcm.ulIvBits, 96, "delayed wrap IV bits");
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

    const CKM_SYNTHETIC_MESSAGE: CK_MECHANISM_TYPE = 0x0000_0001;

    let backend =
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType(CKM_SYNTHETIC_MESSAGE)]));
    let (endpoint, _shutdown) = common_3x::mock_daemon(backend).await;
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
        let c_get_slot_list = functions.C_GetSlotList.expect("C_GetSlotList");
        let c_open_session = functions.C_OpenSession.expect("C_OpenSession");
        let c_close_session = functions.C_CloseSession.expect("C_CloseSession");
        let c_create_object = functions.C_CreateObject.expect("C_CreateObject");
        let c_message_encrypt_init = functions.C_MessageEncryptInit.expect("C_MessageEncryptInit");
        let c_encrypt_message_begin =
            functions.C_EncryptMessageBegin.expect("C_EncryptMessageBegin");
        let c_encrypt_message_next = functions.C_EncryptMessageNext.expect("C_EncryptMessageNext");
        let c_message_encrypt_final =
            functions.C_MessageEncryptFinal.expect("C_MessageEncryptFinal");
        let c_message_decrypt_init = functions.C_MessageDecryptInit.expect("C_MessageDecryptInit");
        let c_decrypt_message_begin =
            functions.C_DecryptMessageBegin.expect("C_DecryptMessageBegin");
        let c_decrypt_message_next = functions.C_DecryptMessageNext.expect("C_DecryptMessageNext");
        let c_message_decrypt_final =
            functions.C_MessageDecryptFinal.expect("C_MessageDecryptFinal");
        let c_message_sign_init = functions.C_MessageSignInit.expect("C_MessageSignInit");
        let c_sign_message_begin = functions.C_SignMessageBegin.expect("C_SignMessageBegin");
        let c_sign_message_next = functions.C_SignMessageNext.expect("C_SignMessageNext");
        let c_message_sign_final = functions.C_MessageSignFinal.expect("C_MessageSignFinal");
        let c_message_verify_init = functions.C_MessageVerifyInit.expect("C_MessageVerifyInit");
        let c_verify_message_begin = functions.C_VerifyMessageBegin.expect("C_VerifyMessageBegin");
        let c_verify_message_next = functions.C_VerifyMessageNext.expect("C_VerifyMessageNext");
        let c_message_verify_final = functions.C_MessageVerifyFinal.expect("C_MessageVerifyFinal");

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
            ulIvFixedBits: 32,
            ivGenerator: 1,
            pTag: tag.as_mut_ptr(),
            ulTagBits: 128,
        };

        assert_eq!(
            c_message_encrypt_init(session, &mut mechanism, key),
            CKR_OK as CK_RV,
            "C_MessageEncryptInit"
        );
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

        let plaintext = b"loaded message begin next";
        let mut ciphertext_len = plaintext.len() as CK_ULONG;
        let mut ciphertext = vec![0_u8; plaintext.len()];
        assert_eq!(
            c_encrypt_message_next(
                session,
                &mut gcm_message as *mut CK_GCM_MESSAGE_PARAMS as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                plaintext.as_ptr() as CK_BYTE_PTR,
                plaintext.len() as CK_ULONG,
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
                0,
            ),
            CKR_OK as CK_RV,
            "C_EncryptMessageNext"
        );
        ciphertext.truncate(ciphertext_len as usize);
        assert_eq!(
            ciphertext,
            plaintext.iter().map(|byte| byte ^ 0x42).collect::<Vec<_>>(),
            "mock message ciphertext"
        );
        assert_eq!(tag, [0xA5_u8; 16], "C_EncryptMessageNext writes GCM tag");
        assert_eq!(c_message_encrypt_final(session), CKR_OK as CK_RV, "C_MessageEncryptFinal");

        tag.fill(0);
        assert_eq!(
            c_message_decrypt_init(session, &mut mechanism, key),
            CKR_OK as CK_RV,
            "C_MessageDecryptInit"
        );
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

        let mut recovered_len = ciphertext.len() as CK_ULONG;
        let mut recovered = vec![0_u8; ciphertext.len()];
        assert_eq!(
            c_decrypt_message_next(
                session,
                &mut gcm_message as *mut CK_GCM_MESSAGE_PARAMS as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                ciphertext.as_ptr() as CK_BYTE_PTR,
                ciphertext.len() as CK_ULONG,
                recovered.as_mut_ptr(),
                &mut recovered_len,
                0,
            ),
            CKR_OK as CK_RV,
            "C_DecryptMessageNext"
        );
        recovered.truncate(recovered_len as usize);
        assert_eq!(recovered, plaintext, "mock message plaintext");
        assert_eq!(tag, [0xA5_u8; 16], "C_DecryptMessageNext writes GCM tag");
        assert_eq!(c_message_decrypt_final(session), CKR_OK as CK_RV, "C_MessageDecryptFinal");

        let mut sign_parameter = *b"sig-param";
        let nonfinal_data = b"nonfinal";
        let final_data = b"final message";
        assert_eq!(
            c_message_sign_init(session, &mut mechanism, key),
            CKR_OK as CK_RV,
            "C_MessageSignInit"
        );
        assert_eq!(
            c_sign_message_begin(
                session,
                sign_parameter.as_mut_ptr() as CK_VOID_PTR,
                sign_parameter.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV,
            "C_SignMessageBegin"
        );
        assert_eq!(
            c_sign_message_next(
                session,
                sign_parameter.as_mut_ptr() as CK_VOID_PTR,
                sign_parameter.len() as CK_ULONG,
                nonfinal_data.as_ptr() as CK_BYTE_PTR,
                nonfinal_data.len() as CK_ULONG,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ),
            CKR_OK as CK_RV,
            "C_SignMessageNext(nonfinal)"
        );

        let mut signature_len = final_data.len() as CK_ULONG;
        let mut signature = vec![0_u8; final_data.len()];
        assert_eq!(
            c_sign_message_next(
                session,
                sign_parameter.as_mut_ptr() as CK_VOID_PTR,
                sign_parameter.len() as CK_ULONG,
                final_data.as_ptr() as CK_BYTE_PTR,
                final_data.len() as CK_ULONG,
                signature.as_mut_ptr(),
                &mut signature_len,
            ),
            CKR_OK as CK_RV,
            "C_SignMessageNext(final)"
        );
        signature.truncate(signature_len as usize);
        assert_eq!(
            signature,
            final_data.iter().rev().copied().collect::<Vec<_>>(),
            "mock message signature"
        );
        assert_eq!(c_message_sign_final(session), CKR_OK as CK_RV, "C_MessageSignFinal");

        assert_eq!(
            c_message_verify_init(session, &mut mechanism, key),
            CKR_OK as CK_RV,
            "C_MessageVerifyInit"
        );
        assert_eq!(
            c_verify_message_begin(
                session,
                sign_parameter.as_mut_ptr() as CK_VOID_PTR,
                sign_parameter.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV,
            "C_VerifyMessageBegin"
        );
        assert_eq!(
            c_verify_message_next(
                session,
                sign_parameter.as_mut_ptr() as CK_VOID_PTR,
                sign_parameter.len() as CK_ULONG,
                nonfinal_data.as_ptr() as CK_BYTE_PTR,
                nonfinal_data.len() as CK_ULONG,
                std::ptr::null_mut(),
                0,
            ),
            CKR_OK as CK_RV,
            "C_VerifyMessageNext(nonfinal)"
        );
        assert_eq!(
            c_verify_message_next(
                session,
                sign_parameter.as_mut_ptr() as CK_VOID_PTR,
                sign_parameter.len() as CK_ULONG,
                final_data.as_ptr() as CK_BYTE_PTR,
                final_data.len() as CK_ULONG,
                signature.as_mut_ptr(),
                signature.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV,
            "C_VerifyMessageNext(final)"
        );
        assert_eq!(c_message_verify_final(session), CKR_OK as CK_RV, "C_MessageVerifyFinal");

        assert_eq!(c_close_session(session), CKR_OK as CK_RV, "C_CloseSession");
        assert_eq!(c_finalize(std::ptr::null_mut()), CKR_OK as CK_RV, "C_Finalize");
    }
}

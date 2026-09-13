//! Public C-ABI tests also runnable unchanged against the accepted C2B base.
#![allow(clippy::unnecessary_cast)]
use super::*;
use cryptoki_sys::*;
use libloading::Library;
use pkcs11_proxy_ng_backend::FfiBackend;
use std::{path::PathBuf, ptr, sync::OnceLock};

#[allow(dead_code)]
#[path = "../../../../tests/ffi_oracles/exact_outputs/src/lib.rs"]
mod oracle_types;
use oracle_types::{ExactOracleObservation, ExactOracleScenario};

static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn required_path(key: &str) -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os(key)
            .unwrap_or_else(|| panic!("{key} is required for the explicit loaded-shim gate")),
    );
    assert!(path.is_file(), "{key} must identify a built library");
    path
}

struct Harness {
    functions: CK_FUNCTION_LIST_3_2,
    native: CK_FUNCTION_LIST_3_2,
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    oracle: Library,
    _shim: std::mem::ManuallyDrop<Library>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    previous_endpoint: Option<std::ffi::OsString>,
}
impl Harness {
    async fn start() -> Self {
        let oracle_path = required_path("PKCS11_PROXY_EXACT_ORACLE_LIB");
        let backend = Arc::new(FfiBackend::load(&oracle_path).expect("load native exact oracle"));
        let (endpoint, stop) = service(backend).await;
        let previous_endpoint = std::env::var_os("PKCS11_PROXY_ENDPOINT");
        unsafe { std::env::set_var("PKCS11_PROXY_ENDPOINT", endpoint) };
        let shim = unsafe { Library::new(required_path("PKCS11_PROXY_SHIM_LIB")) }
            .expect("load actual shim");
        let oracle = unsafe { Library::new(oracle_path) }.unwrap();
        let tables = |library: &Library| unsafe {
            let get = library
                .get::<unsafe extern "C" fn(
                    CK_UTF8CHAR_PTR,
                    CK_VERSION_PTR,
                    CK_INTERFACE_PTR_PTR,
                    CK_FLAGS,
                ) -> CK_RV>(b"C_GetInterface\0")
                .unwrap();
            let mut interface = ptr::null_mut();
            let mut version = CK_VERSION { major: 3, minor: 2 };
            assert_eq!(get(ptr::null_mut(), &mut version, &mut interface, 0), CKR_OK);
            assert!(!interface.is_null());
            *((*interface).pFunctionList.cast::<CK_FUNCTION_LIST_3_2>())
        };
        let functions = tables(&shim);
        let native = tables(&oracle);
        let mut session = 0;
        let mut key = 0;
        unsafe {
            assert_eq!(functions.C_Initialize.unwrap()(ptr::null_mut()), CKR_OK);
            let mut count = 0;
            assert_eq!(
                functions.C_GetSlotList.unwrap()(CK_TRUE, ptr::null_mut(), &mut count),
                CKR_OK
            );
            let mut slots = vec![0; count as usize];
            assert_eq!(
                functions.C_GetSlotList.unwrap()(CK_TRUE, slots.as_mut_ptr(), &mut count),
                CKR_OK
            );
            assert_eq!(
                functions.C_OpenSession.unwrap()(
                    slots[0],
                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                    ptr::null_mut(),
                    None,
                    &mut session
                ),
                CKR_OK
            );
            assert_eq!(
                functions.C_CreateObject.unwrap()(session, ptr::null_mut(), 0, &mut key),
                CKR_OK
            );
        }
        Self {
            functions,
            native,
            session,
            key,
            oracle,
            _shim: std::mem::ManuallyDrop::new(shim),
            stop: Some(stop),
            previous_endpoint,
        }
    }
    fn scenario(&self, scenario: ExactOracleScenario) {
        unsafe {
            assert_eq!(
                self.oracle
                    .get::<unsafe extern "C" fn(*const ExactOracleScenario) -> u32>(
                        b"ExactOracle_SetScenario\0"
                    )
                    .unwrap()(&scenario),
                0
            );
            assert_eq!(
                self.oracle
                    .get::<unsafe extern "C" fn() -> u32>(b"ExactOracle_ResetObservation\0")
                    .unwrap()(),
                0
            );
        }
    }
    fn observation(&self) -> ExactOracleObservation {
        let mut out = ExactOracleObservation::default();
        unsafe {
            assert_eq!(
                self.oracle
                    .get::<unsafe extern "C" fn(*mut ExactOracleObservation) -> u32>(
                        b"ExactOracle_GetObservation\0"
                    )
                    .unwrap()(&mut out),
                0
            )
        };
        out
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        unsafe {
            (self.functions.C_CloseSession.unwrap())(self.session);
            (self.functions.C_Finalize.unwrap())(ptr::null_mut());
            match &self.previous_endpoint {
                Some(value) => std::env::set_var("PKCS11_PROXY_ENDPOINT", value),
                None => std::env::remove_var("PKCS11_PROXY_ENDPOINT"),
            }
        }
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

unsafe fn prepare_byte(
    functions: &CK_FUNCTION_LIST_3_2,
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    index: usize,
) {
    let mut mechanism =
        CK_MECHANISM { mechanism: CKM_RSA_PKCS, pParameter: ptr::null_mut(), ulParameterLen: 0 };
    let mut init = |function: CK_C_EncryptInit| unsafe {
        assert_eq!(function.unwrap()(session, &mut mechanism, key), CKR_OK)
    };
    match index {
        0 | 1 => init(functions.C_SignInit),
        2 => init(functions.C_SignRecoverInit),
        3 => init(functions.C_VerifyRecoverInit),
        6..=8 => init(functions.C_EncryptInit),
        9..=11 => init(functions.C_DecryptInit),
        12 => init(functions.C_EncryptInit),
        13 => init(functions.C_DecryptInit),
        14 => {
            init(functions.C_SignInit);
            init(functions.C_EncryptInit);
        }
        15 => {
            init(functions.C_DecryptInit);
            init(functions.C_VerifyInit);
        }
        _ => {}
    }
    if matches!(index, 4 | 5 | 12 | 13) {
        unsafe { assert_eq!(functions.C_DigestInit.unwrap()(session, &mut mechanism), CKR_OK) };
    }
}
unsafe fn byte_call(
    functions: &CK_FUNCTION_LIST_3_2,
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    index: usize,
    out: CK_BYTE_PTR,
    length: CK_ULONG_PTR,
) -> CK_RV {
    let input_functions = [
        functions.C_Sign,
        None,
        functions.C_SignRecover,
        functions.C_VerifyRecover,
        functions.C_Digest,
        None,
        functions.C_Encrypt,
        functions.C_EncryptUpdate,
        None,
        functions.C_Decrypt,
        functions.C_DecryptUpdate,
        None,
        functions.C_DigestEncryptUpdate,
        functions.C_DecryptDigestUpdate,
        functions.C_SignEncryptUpdate,
        functions.C_DecryptVerifyUpdate,
    ];
    if index < input_functions.len()
        && let Some(function) = input_functions[index]
    {
        return unsafe { function(session, ptr::null_mut(), 0, out, length) };
    }
    let final_function = match index {
        1 => functions.C_SignFinal,
        5 => functions.C_DigestFinal,
        8 => functions.C_EncryptFinal,
        11 => functions.C_DecryptFinal,
        17 => functions.C_GetOperationState,
        _ => None,
    };
    if let Some(function) = final_function {
        return unsafe { function(session, out, length) };
    }
    let mut mechanism =
        CK_MECHANISM { mechanism: CKM_RSA_PKCS, pParameter: ptr::null_mut(), ulParameterLen: 0 };
    unsafe { functions.C_WrapKey.unwrap()(session, &mut mechanism, key, key, out, length) }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit built shim and native oracle paths required"]
async fn exact_byte_error_effects_roundtrip_through_loaded_shim_and_native_oracle() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    let mut failures = Vec::new();
    for index in 0..18 {
        for present in [false, true] {
            for (action, returned) in [(0, 0), (1, 7), (1, 0), (1, CK_ULONG::MAX as u64)] {
                unsafe { prepare_byte(&harness.functions, harness.session, harness.key, index) };
                let scenario = ExactOracleScenario {
                    rv: CKR_FUNCTION_FAILED as u64,
                    length_action: action,
                    returned_length: returned,
                    ..Default::default()
                };
                let mut output = [0xa5u8; 4];
                let mut length = if present { 4 } else { 77 };
                harness.scenario(scenario);
                let rv = unsafe {
                    byte_call(
                        &harness.functions,
                        harness.session,
                        harness.key,
                        index,
                        if present { output.as_mut_ptr() } else { ptr::null_mut() },
                        &mut length,
                    )
                };
                let observation = harness.observation();
                let expected = if action == 1 && (present || returned != 0) {
                    returned as CK_ULONG
                } else if present {
                    4
                } else {
                    77
                };
                if rv != CKR_FUNCTION_FAILED
                    || length != expected
                    || output != [0xa5u8; 4]
                    || observation.calls != 1
                {
                    failures.push(format!("function={index} present={present} action={action} returned={returned} rv={rv} length={length} expected={expected} calls={}", observation.calls));
                }
                assert_eq!(observation.capacity_read, u32::from(present));
                if present {
                    assert_eq!(observation.incoming_capacity, 4);
                }
                // The direct native oracle confirms store-zero versus no-store;
                // the proxy deliberately reports neither on arbitrary query errors.
                harness.scenario(scenario);
                let mut direct_length = if present { 4 } else { 77 };
                unsafe {
                    byte_call(
                        &harness.native,
                        1,
                        41,
                        index,
                        if present { output.as_mut_ptr() } else { ptr::null_mut() },
                        &mut direct_length,
                    )
                };
                assert_eq!(harness.observation().length_stores, action as u64);
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of 144 exact ABI cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit built shim and native oracle paths required"]
async fn exact_message_error_effects_roundtrip_without_changing_operation_settlement() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    let mut mechanism =
        CK_MECHANISM { mechanism: CKM_AES_GCM, pParameter: ptr::null_mut(), ulParameterLen: 0 };
    unsafe {
        assert_eq!(
            harness.functions.C_MessageEncryptInit.unwrap()(
                harness.session,
                &mut mechanism,
                harness.key
            ),
            CKR_OK
        )
    };
    for _ in 0..2 {
        let mut iv = [0x11; 12];
        let mut tag = [0x22; 16];
        let mut length = 77;
        let mut parameter = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: 12,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_COUNTER_XOR,
            pTag: tag.as_mut_ptr(),
            ulTagBits: 128,
        };
        harness.scenario(ExactOracleScenario {
            rv: CKR_FUNCTION_FAILED as u64,
            length_action: 1,
            returned_length: 7,
            parameter_action: 1,
            ..Default::default()
        });
        let rv = unsafe {
            harness.functions.C_EncryptMessage.unwrap()(
                harness.session,
                (&mut parameter as *mut CK_GCM_MESSAGE_PARAMS).cast(),
                std::mem::size_of_val(&parameter) as CK_ULONG,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut length,
            )
        };
        assert_eq!(harness.observation().calls, 1);
        assert_eq!(rv, CKR_FUNCTION_FAILED);
        assert_eq!(length, 7);
        assert_eq!(iv[0], 0x42);
        assert_eq!(tag, [0x22; 16]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit built shim and native oracle paths required"]
async fn exact_begin_error_effects_preserve_initialized_iv_and_operation() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    let mut mechanism =
        CK_MECHANISM { mechanism: CKM_AES_GCM, pParameter: ptr::null_mut(), ulParameterLen: 0 };
    unsafe {
        assert_eq!(
            harness.functions.C_MessageEncryptInit.unwrap()(
                harness.session,
                &mut mechanism,
                harness.key
            ),
            CKR_OK
        )
    };
    for _ in 0..2 {
        let mut iv = [0x11u8; 12];
        let mut tag = [0xa5u8; 16];
        let mut parameter = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: 12,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_COUNTER_XOR,
            pTag: tag.as_mut_ptr(),
            ulTagBits: 128,
        };
        harness.scenario(ExactOracleScenario {
            rv: CKR_FUNCTION_FAILED as u64,
            parameter_action: 1,
            ..Default::default()
        });
        let rv = unsafe {
            harness.functions.C_EncryptMessageBegin.unwrap()(
                harness.session,
                (&mut parameter as *mut CK_GCM_MESSAGE_PARAMS).cast(),
                std::mem::size_of_val(&parameter) as CK_ULONG,
                ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rv, CKR_FUNCTION_FAILED);
        assert_eq!(harness.observation().calls, 1);
        assert_eq!(iv[0], 0x42, "native initialized Begin IV effect must survive errors");
        assert_eq!(tag, [0xa5; 16]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit built shim and native oracle paths required"]
async fn exported_standard_sign_rejects_nonempty_parameters_before_native_or_memory_access() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    let mut mechanism =
        CK_MECHANISM { mechanism: CKM_SHA256_HMAC, pParameter: ptr::null_mut(), ulParameterLen: 0 };
    unsafe {
        assert_eq!(
            harness.functions.C_MessageSignInit.unwrap()(
                harness.session,
                &mut mechanism,
                harness.key
            ),
            CKR_OK
        )
    };
    let mut output = [0xa5u8; 8];
    let mut length = 8;
    let poison = std::ptr::without_provenance_mut::<std::ffi::c_void>(1);
    harness.scenario(ExactOracleScenario { rv: CKR_OK as u64, ..Default::default() });
    // All standard signing entry points have empty pParameter contracts,
    // including the Next feed form whose signature length pointer is NULL.
    for bytes in [1, std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG] {
        let results = unsafe {
            [
                harness.functions.C_SignMessage.unwrap()(
                    harness.session,
                    poison,
                    bytes,
                    ptr::null_mut(),
                    0,
                    output.as_mut_ptr(),
                    &mut length,
                ),
                harness.functions.C_SignMessageBegin.unwrap()(harness.session, poison, bytes),
                harness.functions.C_SignMessageNext.unwrap()(
                    harness.session,
                    poison,
                    bytes,
                    ptr::null_mut(),
                    0,
                    output.as_mut_ptr(),
                    &mut length,
                ),
                harness.functions.C_SignMessageNext.unwrap()(
                    harness.session,
                    poison,
                    bytes,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                ),
            ]
        };
        assert_eq!(results, [CKR_MECHANISM_PARAM_INVALID; 4]);
        assert_eq!(output, [0xa5; 8]);
        assert_eq!(length, 8);
        assert_eq!(harness.observation().calls, 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit built shim and native oracle paths required"]
async fn exact_auth_wrap_error_effects_use_typed_c2b_outputs() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    let mut iv = [0x11u8; 16];
    let mut length = 77;
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        pParameter: iv.as_mut_ptr().cast(),
        ulParameterLen: 16,
    };
    harness.scenario(ExactOracleScenario {
        rv: CKR_FUNCTION_FAILED as u64,
        length_action: 1,
        returned_length: 7,
        parameter_action: 1,
        ..Default::default()
    });
    let rv = unsafe {
        harness.functions.C_WrapKeyAuthenticated.unwrap()(
            harness.session,
            &mut mechanism,
            harness.key,
            harness.key,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut length,
        )
    };
    assert_eq!(harness.observation().calls, 1);
    assert_eq!(rv, CKR_FUNCTION_FAILED);
    assert_eq!(length, 7);
    assert_eq!(iv[0], 0x42);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit built shim and native oracle paths required"]
async fn invalid_native_parameter_completion_suppresses_all_channels_and_clears_operation() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    for native_rv in [CKR_OK, CKR_FUNCTION_FAILED] {
        let mut mechanism =
            CK_MECHANISM { mechanism: CKM_AES_GCM, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        unsafe {
            assert_eq!(
                harness.functions.C_MessageEncryptInit.unwrap()(
                    harness.session,
                    &mut mechanism,
                    harness.key
                ),
                CKR_OK
            )
        };
        let mut iv = [0x11u8; 12];
        let mut tag = [0xa5u8; 16];
        let mut output = [0xb6u8; 8];
        let mut length = 8;
        let mut parameter = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: 12,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_COUNTER_XOR,
            pTag: tag.as_mut_ptr(),
            ulTagBits: 128,
        };
        harness.scenario(ExactOracleScenario {
            rv: native_rv as u64,
            parameter_action: 2,
            length_action: 1,
            returned_length: 4,
            output_action: 1,
            ..Default::default()
        });
        let call = |parameter: &mut CK_GCM_MESSAGE_PARAMS,
                    output: &mut [u8; 8],
                    length: &mut CK_ULONG| unsafe {
            harness.functions.C_EncryptMessage.unwrap()(
                harness.session,
                (parameter as *mut CK_GCM_MESSAGE_PARAMS).cast(),
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                output.as_mut_ptr(),
                length,
            )
        };
        assert_eq!(call(&mut parameter, &mut output, &mut length), CKR_DEVICE_ERROR);
        assert_eq!(harness.observation().calls, 1);
        assert_eq!(length, 8);
        assert_eq!(output, [0xb6; 8]);
        assert_eq!(iv, [0x11; 12]);
        assert_eq!(tag, [0xa5; 16]);
        assert_eq!(parameter.ulTagBits, 128);
        assert_eq!(call(&mut parameter, &mut output, &mut length), CKR_OPERATION_NOT_INITIALIZED);
        assert_eq!(harness.observation().calls, 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit built shim and native oracle paths required"]
async fn exact_preprovider_rejections_leave_all_caller_outputs_untouched() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    let mut mechanism =
        CK_MECHANISM { mechanism: CKM_RSA_PKCS, pParameter: ptr::null_mut(), ulParameterLen: 0 };
    for valid_session in [false, true] {
        let mut output = [0xa5u8; 8];
        let mut length = 8;
        let mut key = 0x1234;
        harness.scenario(ExactOracleScenario {
            rv: CKR_FUNCTION_FAILED as u64,
            length_action: 1,
            returned_length: 7,
            handle_action: 1,
            ..Default::default()
        });
        let rv = unsafe {
            harness.functions.C_EncapsulateKey.unwrap()(
                if valid_session { harness.session } else { CK_SESSION_HANDLE::MAX },
                &mut mechanism,
                harness.key,
                ptr::null_mut(),
                0,
                output.as_mut_ptr(),
                &mut length,
                &mut key,
            )
        };
        assert_eq!(
            rv,
            if valid_session { CKR_FUNCTION_FAILED } else { CKR_SESSION_HANDLE_INVALID }
        );
        assert_eq!(length, if valid_session { 7 } else { 8 });
        assert_eq!(key, 0x1234);
        assert_eq!(output, [0xa5; 8]);
        assert_eq!(harness.observation().calls, u64::from(valid_session));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit built shim and native oracle paths required"]
async fn exact_attribute_partial_errors_and_nested_bounds_roundtrip() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    for rv in [
        CKR_OK,
        CKR_ATTRIBUTE_SENSITIVE,
        CKR_ATTRIBUTE_TYPE_INVALID,
        CKR_BUFFER_TOO_SMALL,
        CKR_FUNCTION_FAILED,
    ] {
        let mut value = [0xa5u8; 4];
        let mut attribute =
            CK_ATTRIBUTE { type_: CKA_LABEL, pValue: value.as_mut_ptr().cast(), ulValueLen: 4 };
        harness.scenario(ExactOracleScenario {
            rv: rv as u64,
            length_action: 1,
            returned_length: 4,
            output_action: 1,
            ..Default::default()
        });
        let returned = unsafe {
            harness.functions.C_GetAttributeValue.unwrap()(
                harness.session,
                harness.key,
                &mut attribute,
                1,
            )
        };
        assert_eq!(harness.observation().calls, 1);
        assert_eq!(returned, rv);
        assert_eq!(attribute.ulValueLen, 4);
        assert_eq!(
            value,
            if rv == CKR_FUNCTION_FAILED { [0xa5; 4] } else { [0x10, 0x20, 0x30, 0x40] }
        );
    }
    let mut sub_value = [0xa5u8; 4];
    let mut nested =
        CK_ATTRIBUTE { type_: 0x99, pValue: sub_value.as_mut_ptr().cast(), ulValueLen: 4 };
    let mut outer = CK_ATTRIBUTE {
        type_: CKA_WRAP_TEMPLATE,
        pValue: (&mut nested as *mut CK_ATTRIBUTE).cast(),
        ulValueLen: std::mem::size_of_val(&nested) as CK_ULONG,
    };
    harness.scenario(ExactOracleScenario {
        rv: CKR_BUFFER_TOO_SMALL as u64,
        parameter_action: 3,
        ..Default::default()
    });
    let rv = unsafe {
        harness.functions.C_GetAttributeValue.unwrap()(harness.session, harness.key, &mut outer, 1)
    };
    assert_eq!(rv, CKR_BUFFER_TOO_SMALL);
    assert_eq!(harness.observation().calls, 1);
    assert_eq!(outer.ulValueLen, 2 * std::mem::size_of_val(&nested) as CK_ULONG);
    assert_eq!(nested.type_, 0x99);
    assert_eq!(sub_value, [0xa5; 4]);
}

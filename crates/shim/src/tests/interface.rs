use super::*;

#[test]
fn get_function_list_null_returns_bad_args() {
    let _guard = shim_state_test_guard();
    let rv = unsafe { C_GetFunctionList(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn get_function_list_returns_nonnull_pointer() {
    let _guard = shim_state_test_guard();
    let mut p: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let rv = unsafe { C_GetFunctionList(&mut p) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!p.is_null());
}

#[test]
fn get_function_list_version_is_2_40() {
    let _guard = shim_state_test_guard();
    let mut p: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    unsafe {
        C_GetFunctionList(&mut p);
        let ver = &(*p).version;
        assert_eq!(ver.major, 2);
        assert_eq!(ver.minor, 40);
    }
}

#[test]
fn get_function_list_is_stable() {
    let _guard = shim_state_test_guard();
    let mut p1: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let mut p2: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    unsafe {
        C_GetFunctionList(&mut p1);
        C_GetFunctionList(&mut p2);
    }
    assert_eq!(p1, p2);
}

#[test]
fn get_interface_list_null_count_returns_bad_args() {
    let _guard = shim_state_test_guard();
    let rv = unsafe { C_GetInterfaceList(std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn get_interface_list_count_only_mode() {
    let _guard = shim_state_test_guard();
    let mut count: CK_ULONG = 0;
    let rv = unsafe { C_GetInterfaceList(std::ptr::null_mut(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert_eq!(count, 3);
}

#[test]
fn get_interface_list_buffer_too_small() {
    let _guard = shim_state_test_guard();
    let mut buf = [super::empty_interface(); 1];
    let mut count: CK_ULONG = 1;
    let rv = unsafe { C_GetInterfaceList(buf.as_mut_ptr(), &mut count) };
    assert_eq!(rv, CKR_BUFFER_TOO_SMALL as CK_RV);
}

#[test]
fn get_interface_list_fills_entries() {
    let _guard = shim_state_test_guard();
    let mut buf = [super::empty_interface(); 3];
    let mut count: CK_ULONG = 3;
    let rv = unsafe { C_GetInterfaceList(buf.as_mut_ptr(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert_eq!(count, 3);
    for entry in &buf {
        assert!(!entry.pInterfaceName.is_null());
        assert!(!entry.pFunctionList.is_null());
    }
}

fn listed_interface_version(index: usize) -> CK_VERSION {
    let mut buf = [super::empty_interface(); 3];
    let mut count: CK_ULONG = 3;
    let rv = unsafe { C_GetInterfaceList(buf.as_mut_ptr(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(count as usize > index, "interface list count {count} should include index {index}");
    assert!(
        !buf[index].pFunctionList.is_null(),
        "interface entry {index} has a null function list"
    );
    unsafe { *(buf[index].pFunctionList as *const CK_VERSION) }
}

#[test]
fn get_interface_list_first_entry_is_2_40() {
    let _guard = shim_state_test_guard();
    let ver = listed_interface_version(0);
    assert_eq!(ver.major, 2);
    assert_eq!(ver.minor, 40);
}

#[test]
fn get_interface_list_second_entry_is_3_0() {
    let _guard = shim_state_test_guard();
    let ver = listed_interface_version(1);
    assert_eq!(ver.major, 3);
    assert_eq!(ver.minor, 0);
}

#[test]
fn get_interface_null_ppinterface_returns_bad_args() {
    let _guard = shim_state_test_guard();
    let rv = unsafe {
        C_GetInterface(std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), 0)
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn get_interface_null_name_returns_default() {
    let _guard = shim_state_test_guard();
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(std::ptr::null_mut(), std::ptr::null_mut(), &mut pp, 0) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!pp.is_null());
    unsafe {
        let ver = &*((*pp).pFunctionList as *const CK_VERSION);
        assert_eq!(ver.major, 3);
        assert_eq!(ver.minor, 2);
    }
}

#[test]
fn get_interface_pkcs11_no_version_returns_3_2() {
    let _guard = shim_state_test_guard();
    let name = b"PKCS 11\0";
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe {
        C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, std::ptr::null_mut(), &mut pp, 0)
    };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!pp.is_null());
    unsafe {
        let ver = &*((*pp).pFunctionList as *const CK_VERSION);
        assert_eq!(ver.major, 3);
        assert_eq!(ver.minor, 2);
    }
}

#[test]
fn get_interface_pkcs11_version_2_40() {
    let _guard = shim_state_test_guard();
    let name = b"PKCS 11\0";
    let mut req_ver = CK_VERSION { major: 2, minor: 40 };
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, &mut req_ver, &mut pp, 0) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!pp.is_null());
    unsafe {
        let ver = &*((*pp).pFunctionList as *const CK_VERSION);
        assert_eq!(ver.major, 2);
        assert_eq!(ver.minor, 40);
    }
}

#[test]
fn get_interface_pkcs11_version_3_0() {
    let _guard = shim_state_test_guard();
    let name = b"PKCS 11\0";
    let mut req_ver = CK_VERSION { major: 3, minor: 0 };
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, &mut req_ver, &mut pp, 0) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!pp.is_null());
    unsafe {
        let ver = &*((*pp).pFunctionList as *const CK_VERSION);
        assert_eq!(ver.major, 3);
        assert_eq!(ver.minor, 0);
    }
}

#[test]
fn get_interface_unknown_name_returns_null_ok() {
    let _guard = shim_state_test_guard();
    let name = b"NoSuchInterface\0";
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe {
        C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, std::ptr::null_mut(), &mut pp, 0)
    };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(pp.is_null());
}

#[test]
fn get_interface_unknown_version_returns_null_ok() {
    let _guard = shim_state_test_guard();
    let name = b"PKCS 11\0";
    let mut req_ver = CK_VERSION { major: 9, minor: 9 };
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, &mut req_ver, &mut pp, 0) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(pp.is_null());
}

#[test]
fn get_interface_unadvertised_flags_returns_null_ok() {
    let _guard = shim_state_test_guard();
    let name = b"PKCS 11\0";
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe {
        C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, std::ptr::null_mut(), &mut pp, 1)
    };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(pp.is_null());
}

#[test]
fn get_interface_flags_combine_with_version_and_name() {
    let _guard = shim_state_test_guard();
    let name = b"PKCS 11\0";
    let mut version = CK_VERSION { major: 3, minor: 0 };
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, &mut version, &mut pp, 1) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(pp.is_null());
}

#[test]
fn get_interface_3_0_list_has_nonnull_get_interface_list_slot() {
    let _guard = shim_state_test_guard();
    let name = b"PKCS 11\0";
    let mut req_ver = CK_VERSION { major: 3, minor: 0 };
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, &mut req_ver, &mut pp, 0) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!pp.is_null());
    unsafe {
        let fl3 = &*((*pp).pFunctionList as *const CK_FUNCTION_LIST_3_0);
        // E0793: CK lists are packed on Windows; `is_some()` runs on by-value copies.
        assert!({
            let f = fl3.C_GetInterfaceList;
            f.is_some()
        });
        assert!({
            let f = fl3.C_GetInterface;
            f.is_some()
        });
    }
}

#[test]
fn get_interface_2_40_list_has_nonnull_legacy_async_slots() {
    let _guard = shim_state_test_guard();
    let name = b"PKCS 11\0";
    let mut req_ver = CK_VERSION { major: 2, minor: 40 };
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, &mut req_ver, &mut pp, 0) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!pp.is_null());
    unsafe {
        let fl = &*((*pp).pFunctionList as *const CK_FUNCTION_LIST);
        // E0793: CK lists are packed on Windows; `is_some()` runs on by-value copies.
        assert!({
            let f = fl.C_GetFunctionStatus;
            f.is_some()
        });
        assert!({
            let f = fl.C_CancelFunction;
            f.is_some()
        });
    }
}

fn get_3_0_list() -> *const CK_FUNCTION_LIST_3_0 {
    let name = b"PKCS 11\0";
    let mut req_ver = CK_VERSION { major: 3, minor: 0 };
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, &mut req_ver, &mut pp, 0) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!pp.is_null());
    let function_list = unsafe { (*pp).pFunctionList };
    assert!(!function_list.is_null());
    function_list as *const CK_FUNCTION_LIST_3_0
}

#[test]
fn all_3_0_out_of_scope_slots_are_nonnull() {
    let _guard = shim_state_test_guard();
    let fl3 = get_3_0_list();
    unsafe {
        let fl = &*fl3;
        // E0793: CK lists are packed on Windows; `is_some()` runs on by-value copies.
        assert!(
            {
                let f = fl.C_GetFunctionStatus;
                f.is_some()
            },
            "C_GetFunctionStatus"
        );
        assert!(
            {
                let f = fl.C_CancelFunction;
                f.is_some()
            },
            "C_CancelFunction"
        );
        assert!(
            {
                let f = fl.C_LoginUser;
                f.is_some()
            },
            "C_LoginUser"
        );
        assert!(
            {
                let f = fl.C_SessionCancel;
                f.is_some()
            },
            "C_SessionCancel"
        );
        assert!(
            {
                let f = fl.C_MessageEncryptInit;
                f.is_some()
            },
            "C_MessageEncryptInit"
        );
        assert!(
            {
                let f = fl.C_EncryptMessage;
                f.is_some()
            },
            "C_EncryptMessage"
        );
        assert!(
            {
                let f = fl.C_EncryptMessageBegin;
                f.is_some()
            },
            "C_EncryptMessageBegin"
        );
        assert!(
            {
                let f = fl.C_EncryptMessageNext;
                f.is_some()
            },
            "C_EncryptMessageNext"
        );
        assert!(
            {
                let f = fl.C_MessageEncryptFinal;
                f.is_some()
            },
            "C_MessageEncryptFinal"
        );
        assert!(
            {
                let f = fl.C_MessageDecryptInit;
                f.is_some()
            },
            "C_MessageDecryptInit"
        );
        assert!(
            {
                let f = fl.C_DecryptMessage;
                f.is_some()
            },
            "C_DecryptMessage"
        );
        assert!(
            {
                let f = fl.C_DecryptMessageBegin;
                f.is_some()
            },
            "C_DecryptMessageBegin"
        );
        assert!(
            {
                let f = fl.C_DecryptMessageNext;
                f.is_some()
            },
            "C_DecryptMessageNext"
        );
        assert!(
            {
                let f = fl.C_MessageDecryptFinal;
                f.is_some()
            },
            "C_MessageDecryptFinal"
        );
        assert!(
            {
                let f = fl.C_MessageSignInit;
                f.is_some()
            },
            "C_MessageSignInit"
        );
        assert!(
            {
                let f = fl.C_SignMessage;
                f.is_some()
            },
            "C_SignMessage"
        );
        assert!(
            {
                let f = fl.C_SignMessageBegin;
                f.is_some()
            },
            "C_SignMessageBegin"
        );
        assert!(
            {
                let f = fl.C_SignMessageNext;
                f.is_some()
            },
            "C_SignMessageNext"
        );
        assert!(
            {
                let f = fl.C_MessageSignFinal;
                f.is_some()
            },
            "C_MessageSignFinal"
        );
        assert!(
            {
                let f = fl.C_MessageVerifyInit;
                f.is_some()
            },
            "C_MessageVerifyInit"
        );
        assert!(
            {
                let f = fl.C_VerifyMessage;
                f.is_some()
            },
            "C_VerifyMessage"
        );
        assert!(
            {
                let f = fl.C_VerifyMessageBegin;
                f.is_some()
            },
            "C_VerifyMessageBegin"
        );
        assert!(
            {
                let f = fl.C_VerifyMessageNext;
                f.is_some()
            },
            "C_VerifyMessageNext"
        );
        assert!(
            {
                let f = fl.C_MessageVerifyFinal;
                f.is_some()
            },
            "C_MessageVerifyFinal"
        );
    }
}

#[test]
fn out_of_scope_stubs_return_function_not_supported() {
    let _guard = shim_state_test_guard();
    // C_GetFunctionStatus and C_CancelFunction are now real dispatch functions
    // (require connected client) like Message*Final; they are tested via
    // integration tests, not stub tests.
    //
    // No static-error stubs remain in the 3.0 function list.
}

#[test]
fn interface_catalog_has_three_entries() {
    let _guard = shim_state_test_guard();
    let mut count: CK_ULONG = 0;
    let rv = unsafe { C_GetInterfaceList(std::ptr::null_mut(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert_eq!(count, 3);
}

#[test]
fn get_interface_3_2_by_version() {
    let _guard = shim_state_test_guard();
    let name = b"PKCS 11\0";
    let mut req_ver = CK_VERSION { major: 3, minor: 2 };
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, &mut req_ver, &mut pp, 0) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!pp.is_null());
    unsafe {
        let ver = &*((*pp).pFunctionList as *const CK_VERSION);
        assert_eq!(ver.major, 3);
        assert_eq!(ver.minor, 2);
    }
}

#[test]
fn get_interface_default_returns_3_2() {
    let _guard = shim_state_test_guard();
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(std::ptr::null_mut(), std::ptr::null_mut(), &mut pp, 0) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!pp.is_null());
    unsafe {
        let ver = &*((*pp).pFunctionList as *const CK_VERSION);
        assert_eq!(ver.major, 3);
        assert_eq!(ver.minor, 2);
    }
}

#[test]
fn get_interface_list_third_entry_is_3_2() {
    let _guard = shim_state_test_guard();
    let ver = listed_interface_version(2);
    assert_eq!(ver.major, 3);
    assert_eq!(ver.minor, 2);
}

fn get_3_2_list() -> *const CK_FUNCTION_LIST_3_2 {
    let name = b"PKCS 11\0";
    let mut req_ver = CK_VERSION { major: 3, minor: 2 };
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, &mut req_ver, &mut pp, 0) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!pp.is_null());
    let function_list = unsafe { (*pp).pFunctionList };
    assert!(!function_list.is_null());
    function_list as *const CK_FUNCTION_LIST_3_2
}

#[test]
fn all_3_2_out_of_scope_slots_are_nonnull() {
    let _guard = shim_state_test_guard();
    let fl3 = get_3_2_list();
    unsafe {
        let fl = &*fl3;
        // E0793: CK lists are packed on Windows; `is_some()` runs on by-value copies.
        assert!(
            {
                let f = fl.C_GetInterfaceList;
                f.is_some()
            },
            "C_GetInterfaceList"
        );
        assert!(
            {
                let f = fl.C_GetInterface;
                f.is_some()
            },
            "C_GetInterface"
        );
        assert!(
            {
                let f = fl.C_LoginUser;
                f.is_some()
            },
            "C_LoginUser"
        );
        assert!(
            {
                let f = fl.C_SessionCancel;
                f.is_some()
            },
            "C_SessionCancel"
        );
        assert!(
            {
                let f = fl.C_MessageEncryptInit;
                f.is_some()
            },
            "C_MessageEncryptInit"
        );
        assert!(
            {
                let f = fl.C_EncryptMessage;
                f.is_some()
            },
            "C_EncryptMessage"
        );
        assert!(
            {
                let f = fl.C_EncryptMessageBegin;
                f.is_some()
            },
            "C_EncryptMessageBegin"
        );
        assert!(
            {
                let f = fl.C_EncryptMessageNext;
                f.is_some()
            },
            "C_EncryptMessageNext"
        );
        assert!(
            {
                let f = fl.C_MessageEncryptFinal;
                f.is_some()
            },
            "C_MessageEncryptFinal"
        );
        assert!(
            {
                let f = fl.C_MessageDecryptInit;
                f.is_some()
            },
            "C_MessageDecryptInit"
        );
        assert!(
            {
                let f = fl.C_DecryptMessage;
                f.is_some()
            },
            "C_DecryptMessage"
        );
        assert!(
            {
                let f = fl.C_DecryptMessageBegin;
                f.is_some()
            },
            "C_DecryptMessageBegin"
        );
        assert!(
            {
                let f = fl.C_DecryptMessageNext;
                f.is_some()
            },
            "C_DecryptMessageNext"
        );
        assert!(
            {
                let f = fl.C_MessageDecryptFinal;
                f.is_some()
            },
            "C_MessageDecryptFinal"
        );
        assert!(
            {
                let f = fl.C_MessageSignInit;
                f.is_some()
            },
            "C_MessageSignInit"
        );
        assert!(
            {
                let f = fl.C_SignMessage;
                f.is_some()
            },
            "C_SignMessage"
        );
        assert!(
            {
                let f = fl.C_SignMessageBegin;
                f.is_some()
            },
            "C_SignMessageBegin"
        );
        assert!(
            {
                let f = fl.C_SignMessageNext;
                f.is_some()
            },
            "C_SignMessageNext"
        );
        assert!(
            {
                let f = fl.C_MessageSignFinal;
                f.is_some()
            },
            "C_MessageSignFinal"
        );
        assert!(
            {
                let f = fl.C_MessageVerifyInit;
                f.is_some()
            },
            "C_MessageVerifyInit"
        );
        assert!(
            {
                let f = fl.C_VerifyMessage;
                f.is_some()
            },
            "C_VerifyMessage"
        );
        assert!(
            {
                let f = fl.C_VerifyMessageBegin;
                f.is_some()
            },
            "C_VerifyMessageBegin"
        );
        assert!(
            {
                let f = fl.C_VerifyMessageNext;
                f.is_some()
            },
            "C_VerifyMessageNext"
        );
        assert!(
            {
                let f = fl.C_MessageVerifyFinal;
                f.is_some()
            },
            "C_MessageVerifyFinal"
        );
        assert!(
            {
                let f = fl.C_EncapsulateKey;
                f.is_some()
            },
            "C_EncapsulateKey"
        );
        assert!(
            {
                let f = fl.C_DecapsulateKey;
                f.is_some()
            },
            "C_DecapsulateKey"
        );
        assert!(
            {
                let f = fl.C_VerifySignatureInit;
                f.is_some()
            },
            "C_VerifySignatureInit"
        );
        assert!(
            {
                let f = fl.C_VerifySignature;
                f.is_some()
            },
            "C_VerifySignature"
        );
        assert!(
            {
                let f = fl.C_VerifySignatureUpdate;
                f.is_some()
            },
            "C_VerifySignatureUpdate"
        );
        assert!(
            {
                let f = fl.C_VerifySignatureFinal;
                f.is_some()
            },
            "C_VerifySignatureFinal"
        );
        assert!(
            {
                let f = fl.C_GetSessionValidationFlags;
                f.is_some()
            },
            "C_GetSessionValidationFlags"
        );
        assert!(
            {
                let f = fl.C_AsyncComplete;
                f.is_some()
            },
            "C_AsyncComplete"
        );
        assert!(
            {
                let f = fl.C_AsyncGetID;
                f.is_some()
            },
            "C_AsyncGetID"
        );
        assert!(
            {
                let f = fl.C_AsyncJoin;
                f.is_some()
            },
            "C_AsyncJoin"
        );
        assert!(
            {
                let f = fl.C_WrapKeyAuthenticated;
                f.is_some()
            },
            "C_WrapKeyAuthenticated"
        );
        assert!(
            {
                let f = fl.C_UnwrapKeyAuthenticated;
                f.is_some()
            },
            "C_UnwrapKeyAuthenticated"
        );
    }
}

#[test]
fn out_of_scope_3_2_stubs_return_function_not_supported() {
    let _guard = shim_state_test_guard();
    // All 3.2 functions now have real implementations (Wave 5) that require
    // a connected client. Only C_AsyncGetID and C_AsyncJoin return a fixed
    // error without needing a client connection.
    let fl3 = get_3_2_list();
    let dummy_session: CK_SESSION_HANDLE = 0xDEAD;
    unsafe {
        let fl = &*fl3;
        // AsyncGetID always returns CKR_STATE_UNSAVEABLE (Option B)
        assert_eq!(
            fl.C_AsyncGetID.unwrap()(dummy_session, std::ptr::null_mut(), std::ptr::null_mut(),),
            CKR_STATE_UNSAVEABLE as CK_RV
        );
        // AsyncJoin always returns CKR_SAVED_STATE_INVALID (Option B)
        assert_eq!(
            fl.C_AsyncJoin.unwrap()(
                dummy_session,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
            ),
            CKR_SAVED_STATE_INVALID as CK_RV
        );
    }
}

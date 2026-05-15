use super::*;

#[test]
fn get_function_list_null_returns_bad_args() {
    let rv = unsafe { C_GetFunctionList(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn get_function_list_returns_nonnull_pointer() {
    let mut p: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let rv = unsafe { C_GetFunctionList(&mut p) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!p.is_null());
}

#[test]
fn get_function_list_version_is_2_40() {
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
    let rv = unsafe { C_GetInterfaceList(std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn get_interface_list_count_only_mode() {
    let mut count: CK_ULONG = 0;
    let rv = unsafe { C_GetInterfaceList(std::ptr::null_mut(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert_eq!(count, 3);
}

#[test]
fn get_interface_list_buffer_too_small() {
    let mut buf = [super::empty_interface(); 1];
    let mut count: CK_ULONG = 1;
    let rv = unsafe { C_GetInterfaceList(buf.as_mut_ptr(), &mut count) };
    assert_eq!(rv, CKR_BUFFER_TOO_SMALL as CK_RV);
}

#[test]
fn get_interface_list_fills_entries() {
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
    let ver = listed_interface_version(0);
    assert_eq!(ver.major, 2);
    assert_eq!(ver.minor, 40);
}

#[test]
fn get_interface_list_second_entry_is_3_0() {
    let ver = listed_interface_version(1);
    assert_eq!(ver.major, 3);
    assert_eq!(ver.minor, 0);
}

#[test]
fn get_interface_null_ppinterface_returns_bad_args() {
    let rv = unsafe {
        C_GetInterface(std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), 0)
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn get_interface_null_name_returns_default() {
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
    let name = b"PKCS 11\0";
    let mut req_ver = CK_VERSION { major: 9, minor: 9 };
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, &mut req_ver, &mut pp, 0) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(pp.is_null());
}

#[test]
fn get_interface_3_0_list_has_nonnull_get_interface_list_slot() {
    let name = b"PKCS 11\0";
    let mut req_ver = CK_VERSION { major: 3, minor: 0 };
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, &mut req_ver, &mut pp, 0) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!pp.is_null());
    unsafe {
        let fl3 = &*((*pp).pFunctionList as *const CK_FUNCTION_LIST_3_0);
        assert!(fl3.C_GetInterfaceList.is_some());
        assert!(fl3.C_GetInterface.is_some());
    }
}

#[test]
fn get_interface_2_40_list_has_nonnull_legacy_async_slots() {
    let name = b"PKCS 11\0";
    let mut req_ver = CK_VERSION { major: 2, minor: 40 };
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe { C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, &mut req_ver, &mut pp, 0) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!pp.is_null());
    unsafe {
        let fl = &*((*pp).pFunctionList as *const CK_FUNCTION_LIST);
        assert!(fl.C_GetFunctionStatus.is_some());
        assert!(fl.C_CancelFunction.is_some());
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
    let fl3 = get_3_0_list();
    unsafe {
        let fl = &*fl3;
        assert!(fl.C_GetFunctionStatus.is_some(), "C_GetFunctionStatus");
        assert!(fl.C_CancelFunction.is_some(), "C_CancelFunction");
        assert!(fl.C_LoginUser.is_some(), "C_LoginUser");
        assert!(fl.C_SessionCancel.is_some(), "C_SessionCancel");
        assert!(fl.C_MessageEncryptInit.is_some(), "C_MessageEncryptInit");
        assert!(fl.C_EncryptMessage.is_some(), "C_EncryptMessage");
        assert!(fl.C_EncryptMessageBegin.is_some(), "C_EncryptMessageBegin");
        assert!(fl.C_EncryptMessageNext.is_some(), "C_EncryptMessageNext");
        assert!(fl.C_MessageEncryptFinal.is_some(), "C_MessageEncryptFinal");
        assert!(fl.C_MessageDecryptInit.is_some(), "C_MessageDecryptInit");
        assert!(fl.C_DecryptMessage.is_some(), "C_DecryptMessage");
        assert!(fl.C_DecryptMessageBegin.is_some(), "C_DecryptMessageBegin");
        assert!(fl.C_DecryptMessageNext.is_some(), "C_DecryptMessageNext");
        assert!(fl.C_MessageDecryptFinal.is_some(), "C_MessageDecryptFinal");
        assert!(fl.C_MessageSignInit.is_some(), "C_MessageSignInit");
        assert!(fl.C_SignMessage.is_some(), "C_SignMessage");
        assert!(fl.C_SignMessageBegin.is_some(), "C_SignMessageBegin");
        assert!(fl.C_SignMessageNext.is_some(), "C_SignMessageNext");
        assert!(fl.C_MessageSignFinal.is_some(), "C_MessageSignFinal");
        assert!(fl.C_MessageVerifyInit.is_some(), "C_MessageVerifyInit");
        assert!(fl.C_VerifyMessage.is_some(), "C_VerifyMessage");
        assert!(fl.C_VerifyMessageBegin.is_some(), "C_VerifyMessageBegin");
        assert!(fl.C_VerifyMessageNext.is_some(), "C_VerifyMessageNext");
        assert!(fl.C_MessageVerifyFinal.is_some(), "C_MessageVerifyFinal");
    }
}

#[test]
fn out_of_scope_stubs_return_function_not_supported() {
    // C_GetFunctionStatus and C_CancelFunction are now real dispatch functions
    // (require connected client) like Message*Final; they are tested via
    // integration tests, not stub tests.
    //
    // No static-error stubs remain in the 3.0 function list.
}

#[test]
fn interface_catalog_has_three_entries() {
    let mut count: CK_ULONG = 0;
    let rv = unsafe { C_GetInterfaceList(std::ptr::null_mut(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert_eq!(count, 3);
}

#[test]
fn get_interface_3_2_by_version() {
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
    let fl3 = get_3_2_list();
    unsafe {
        let fl = &*fl3;
        assert!(fl.C_GetInterfaceList.is_some(), "C_GetInterfaceList");
        assert!(fl.C_GetInterface.is_some(), "C_GetInterface");
        assert!(fl.C_LoginUser.is_some(), "C_LoginUser");
        assert!(fl.C_SessionCancel.is_some(), "C_SessionCancel");
        assert!(fl.C_MessageEncryptInit.is_some(), "C_MessageEncryptInit");
        assert!(fl.C_EncryptMessage.is_some(), "C_EncryptMessage");
        assert!(fl.C_EncryptMessageBegin.is_some(), "C_EncryptMessageBegin");
        assert!(fl.C_EncryptMessageNext.is_some(), "C_EncryptMessageNext");
        assert!(fl.C_MessageEncryptFinal.is_some(), "C_MessageEncryptFinal");
        assert!(fl.C_MessageDecryptInit.is_some(), "C_MessageDecryptInit");
        assert!(fl.C_DecryptMessage.is_some(), "C_DecryptMessage");
        assert!(fl.C_DecryptMessageBegin.is_some(), "C_DecryptMessageBegin");
        assert!(fl.C_DecryptMessageNext.is_some(), "C_DecryptMessageNext");
        assert!(fl.C_MessageDecryptFinal.is_some(), "C_MessageDecryptFinal");
        assert!(fl.C_MessageSignInit.is_some(), "C_MessageSignInit");
        assert!(fl.C_SignMessage.is_some(), "C_SignMessage");
        assert!(fl.C_SignMessageBegin.is_some(), "C_SignMessageBegin");
        assert!(fl.C_SignMessageNext.is_some(), "C_SignMessageNext");
        assert!(fl.C_MessageSignFinal.is_some(), "C_MessageSignFinal");
        assert!(fl.C_MessageVerifyInit.is_some(), "C_MessageVerifyInit");
        assert!(fl.C_VerifyMessage.is_some(), "C_VerifyMessage");
        assert!(fl.C_VerifyMessageBegin.is_some(), "C_VerifyMessageBegin");
        assert!(fl.C_VerifyMessageNext.is_some(), "C_VerifyMessageNext");
        assert!(fl.C_MessageVerifyFinal.is_some(), "C_MessageVerifyFinal");
        assert!(fl.C_EncapsulateKey.is_some(), "C_EncapsulateKey");
        assert!(fl.C_DecapsulateKey.is_some(), "C_DecapsulateKey");
        assert!(fl.C_VerifySignatureInit.is_some(), "C_VerifySignatureInit");
        assert!(fl.C_VerifySignature.is_some(), "C_VerifySignature");
        assert!(fl.C_VerifySignatureUpdate.is_some(), "C_VerifySignatureUpdate");
        assert!(fl.C_VerifySignatureFinal.is_some(), "C_VerifySignatureFinal");
        assert!(fl.C_GetSessionValidationFlags.is_some(), "C_GetSessionValidationFlags");
        assert!(fl.C_AsyncComplete.is_some(), "C_AsyncComplete");
        assert!(fl.C_AsyncGetID.is_some(), "C_AsyncGetID");
        assert!(fl.C_AsyncJoin.is_some(), "C_AsyncJoin");
        assert!(fl.C_WrapKeyAuthenticated.is_some(), "C_WrapKeyAuthenticated");
        assert!(fl.C_UnwrapKeyAuthenticated.is_some(), "C_UnwrapKeyAuthenticated");
    }
}

#[test]
fn out_of_scope_3_2_stubs_return_function_not_supported() {
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

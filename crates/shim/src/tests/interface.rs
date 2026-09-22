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
fn get_interface_overlong_name_returns_arguments_bad() {
    // W1-C6-06: the caller name scan is bounded (256 bytes); a name with no
    // NUL inside the bound is a loud ARGUMENTS_BAD, never an unbounded read.
    let _guard = shim_state_test_guard();
    let mut name = vec![b'A'; 300];
    name.push(0);
    let mut pp: *mut CK_INTERFACE = std::ptr::null_mut();
    let rv = unsafe {
        C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, std::ptr::null_mut(), &mut pp, 0)
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
    assert!(pp.is_null());
}

#[test]
fn get_interface_boundary_length_name_still_resolves() {
    // W1-C6-06: 255 content bytes + NUL fits the 256 bound, so lookup
    // proceeds (unknown name → OK + NULL per the no-match contract).
    let _guard = shim_state_test_guard();
    let mut name = vec![b'B'; 255];
    name.push(0);
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
    // C_GetFunctionStatus and C_CancelFunction are real dispatch functions
    // (require connected client) like Message*Final; they are tested via
    // integration tests, not stub tests. The remaining out-of-scope
    // fallbacks live in dispatch::general::unsupported: non-null slot
    // fillers with their slots' exact signatures, each answering
    // CKR_FUNCTION_NOT_SUPPORTED. Pin every stub's RV so a vacuous pass
    // is impossible.
    let rvs = unsafe {
        [
            ("c_not_supported", dispatch::general::c_not_supported()),
            ("c_not_supported_session", dispatch::general::c_not_supported_session(0xDEAD)),
            (
                "c_not_supported_msg_init",
                dispatch::general::c_not_supported_msg_init(0xDEAD, std::ptr::null_mut(), 0xBEEF),
            ),
        ]
    };
    assert_eq!(rvs.len(), 3, "every fallback stub must be enumerated");
    for (name, rv) in rvs {
        assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED as CK_RV, "{name}");
    }
}

/// W1-L1-02: `copy_catalog` dereferences a caller buffer, so it is
/// `unsafe` with a documented contract. This pins the contract through
/// the direct call: a valid buffer with sufficient length is filled and
/// the entry count returned; a short buffer fails safe (0, untouched).
/// The `#[deny(unused_unsafe)]` proves the `unsafe` marker is
/// load-bearing — removing it breaks this test at compile time.
#[test]
#[deny(unused_unsafe)]
fn copy_catalog_contract_valid_buffer_filled_short_buffer_safe() {
    let _guard = shim_state_test_guard();
    crate::interface_probe::clear_cache();
    let mut buf = [super::empty_interface(); 4];
    let n = unsafe { crate::interface_probe::copy_catalog(buf.as_mut_ptr(), 4) };
    assert_eq!(n, 3);
    for entry in &buf[..3] {
        assert!(!entry.pInterfaceName.is_null());
        assert!(!entry.pFunctionList.is_null());
    }
    let mut short = [super::empty_interface(); 1];
    let m = unsafe { crate::interface_probe::copy_catalog(short.as_mut_ptr(), 1) };
    assert_eq!(m, 0);
    assert!(short[0].pInterfaceName.is_null() && short[0].pFunctionList.is_null());
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

/// Panic-safe env override for connect-related vars (restored on drop even
/// when an assertion fails, so later tests keep the suite-pinned values).
struct SavedConnectEnv {
    endpoint: Option<String>,
    socket: Option<String>,
    attempts: Option<String>,
}

impl SavedConnectEnv {
    fn capture() -> Self {
        Self {
            endpoint: std::env::var("PKCS11_PROXY_ENDPOINT").ok(),
            socket: std::env::var("PKCS11_PROXY_SOCKET").ok(),
            attempts: std::env::var("PKCS11_PROXY_CONNECT_ATTEMPTS").ok(),
        }
    }

    fn restore_var(name: &str, saved: &Option<String>) {
        unsafe {
            match saved {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
    }
}

impl Drop for SavedConnectEnv {
    fn drop(&mut self) {
        Self::restore_var("PKCS11_PROXY_ENDPOINT", &self.endpoint);
        Self::restore_var("PKCS11_PROXY_SOCKET", &self.socket);
        Self::restore_var("PKCS11_PROXY_CONNECT_ATTEMPTS", &self.attempts);
        crate::state::clear_pre_init_connect_failure();
        crate::interface_probe::clear_cache();
    }
}

/// W1-C7-01: the first pre-init probe against an unreachable daemon runs one
/// dial series; subsequent pre-init probes reuse the cached failure instead
/// of re-dialing. Fails before the fix (second call re-dials: +1 series and
/// backoff-dominated elapsed).
#[test]
fn pre_init_failed_dial_cached_across_probes() {
    let _guard = shim_state_test_guard();
    let _saved = SavedConnectEnv::capture();
    // Guaranteed-refused loopback endpoint: bind an ephemeral port, then drop
    // the listener so nothing answers it.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral loopback port")
        .local_addr()
        .expect("listener addr")
        .port();
    unsafe {
        std::env::set_var("PKCS11_PROXY_ENDPOINT", format!("http://127.0.0.1:{port}"));
        std::env::remove_var("PKCS11_PROXY_SOCKET");
        // 3 attempts => ~100ms + ~200ms backoff per series: slow enough to
        // prove a dial happened, fast enough to keep the suite snappy.
        std::env::set_var("PKCS11_PROXY_CONNECT_ATTEMPTS", "3");
    }
    crate::state::mark_finalized();
    crate::interface_probe::clear_cache();
    crate::state::clear_pre_init_connect_failure();
    // Other tests leak a connected client to their (still alive) in-process
    // daemons; force the reconnect path so this test genuinely dials the
    // refused endpoint below instead of fast-pathing on the stale channel.
    crate::state::mark_client_reconnect_required();
    assert!(!crate::state::is_initialized(), "test requires pre-init state");

    let before = crate::state::connect_series_count();
    let first_start = std::time::Instant::now();
    let first = crate::interface_probe::ensure_probed();
    let first_elapsed = first_start.elapsed();
    assert!(first.is_err(), "probe against a refused endpoint must fail");
    assert_eq!(
        crate::state::connect_series_count() - before,
        1,
        "first pre-init call must run exactly one dial series"
    );
    assert!(
        first_elapsed >= std::time::Duration::from_millis(150),
        "first call must actually dial (backoff-dominated): {first_elapsed:?}"
    );

    let second_start = std::time::Instant::now();
    let second = crate::interface_probe::ensure_probed();
    let second_elapsed = second_start.elapsed();
    assert!(second.is_err(), "cached pre-init failure must still report an error");
    assert_eq!(
        crate::state::connect_series_count() - before,
        1,
        "second pre-init call must reuse the cached failure, not re-dial"
    );
    assert!(
        second_elapsed < std::time::Duration::from_millis(100),
        "cached failure must return fast, without a dial series: {second_elapsed:?}"
    );

    // The cache is keyed by endpoint: a different refused endpoint misses and
    // dials exactly one fresh series, which is then cached in turn.
    let port_b = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind second ephemeral loopback port")
        .local_addr()
        .expect("listener addr")
        .port();
    assert_ne!(port, port_b, "the two refused endpoints must differ");
    unsafe {
        std::env::set_var("PKCS11_PROXY_ENDPOINT", format!("http://127.0.0.1:{port_b}"));
    }
    let third = crate::interface_probe::ensure_probed();
    assert!(third.is_err(), "probe against the second refused endpoint must fail");
    assert_eq!(
        crate::state::connect_series_count() - before,
        2,
        "a changed endpoint must miss the cache and run one fresh dial series"
    );
    let fourth = crate::interface_probe::ensure_probed();
    assert!(fourth.is_err(), "cached failure for the second endpoint must still err");
    assert_eq!(
        crate::state::connect_series_count() - before,
        2,
        "the fresh failure must be cached for subsequent same-endpoint probes"
    );
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

/// W1-L6-29: a steady-state data-plane call consumes the reconnect flag
/// via a fresh dial series. Pre-fix `with_client!` cloned the cached
/// channel without `ensure_client_connected`, so the flag set by a
/// transport failure was never honored outside C_Initialize/probe (no
/// re-dial, no DNS re-resolve, no recovery) — this observed zero new
/// dial series.
#[test]
fn steady_state_call_consumes_reconnect_flag() {
    let _guard = shim_state_test_guard();
    let _saved = SavedConnectEnv::capture();
    // Guaranteed-refused loopback endpoint: the re-dial fails fast and
    // still counts exactly one series; the call then proceeds with the
    // cached (or absent) client and surfaces a transport error.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral loopback port")
        .local_addr()
        .expect("listener addr")
        .port();
    unsafe {
        std::env::set_var("PKCS11_PROXY_ENDPOINT", format!("http://127.0.0.1:{port}"));
        std::env::remove_var("PKCS11_PROXY_SOCKET");
        std::env::set_var("PKCS11_PROXY_CONNECT_ATTEMPTS", "1");
    }
    crate::state::mark_finalized();
    crate::interface_probe::clear_cache();
    crate::state::clear_pre_init_connect_failure();
    crate::state::mark_client_reconnect_required();
    assert!(!crate::state::is_initialized(), "test requires pre-init state");
    assert!(crate::state::mark_initialized(), "test must own the init flag");

    let before = crate::state::connect_series_count();
    let mut slot_count: CK_ULONG = 0;
    // NULL list + valid count: reaches with_client! (count query), fails
    // the RPC on the refused endpoint without further dials.
    let _rv = unsafe {
        dispatch::general::c_get_slot_list(CK_FALSE, std::ptr::null_mut(), &mut slot_count)
    };
    crate::state::mark_finalized();
    assert_eq!(
        crate::state::connect_series_count() - before,
        1,
        "one steady-state call must run exactly one fresh dial series"
    );
}

/// W1-L11-17: the hand-rolled `c_get_info` data-plane path consumes the
/// reconnect flag exactly like `with_client!`, so the next-call rebuild
/// promise holds on every steady-state path — not just the macro one.
/// (Task 4 wired both halves; this pins the hand-rolled half. Removing
/// the `ensure_client_connected` call from `c_get_info` fails this with
/// zero new dial series.)
#[test]
fn get_info_consumes_reconnect_flag() {
    let _guard = shim_state_test_guard();
    let _saved = SavedConnectEnv::capture();
    // Guaranteed-refused loopback endpoint: the re-dial fails fast and
    // still counts exactly one series; the call then proceeds with the
    // cached (or absent) client and surfaces a transport error.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral loopback port")
        .local_addr()
        .expect("listener addr")
        .port();
    unsafe {
        std::env::set_var("PKCS11_PROXY_ENDPOINT", format!("http://127.0.0.1:{port}"));
        std::env::remove_var("PKCS11_PROXY_SOCKET");
        std::env::set_var("PKCS11_PROXY_CONNECT_ATTEMPTS", "1");
    }
    crate::state::mark_finalized();
    crate::interface_probe::clear_cache();
    crate::state::clear_pre_init_connect_failure();
    crate::state::mark_client_reconnect_required();
    assert!(!crate::state::is_initialized(), "test requires pre-init state");
    assert!(crate::state::mark_initialized(), "test must own the init flag");

    let before = crate::state::connect_series_count();
    let mut info: CK_INFO = unsafe { std::mem::zeroed() };
    let _rv = unsafe { dispatch::general::c_get_info(&mut info) };
    crate::state::mark_finalized();
    assert_eq!(
        crate::state::connect_series_count() - before,
        1,
        "one c_get_info call must run exactly one fresh dial series"
    );
}

/// W1-L11-24: every forced reconnect re-reads the endpoint from the
/// environment and runs a fresh dial series — the shim-side mechanism by
/// which a long-lived process follows a daemon whose address changed
/// (each dial builds a fresh `Endpoint::from_shared`, so DNS is
/// re-resolved per reconnect rather than cached with the old `Channel`).
/// A true DNS A-record test needs a DNS rig (per the R2 writeup); this
/// pins what the shim controls: re-resolve inputs are re-read and
/// re-dialed per reconnect, never cached.
///
/// The failure-cache key folds the endpoint string the dial actually
/// used, so observing the second endpoint's key proves the second dial
/// used the re-read value — not a cached copy of the first.
#[test]
fn reconnect_rereads_endpoint_and_redials() {
    let _guard = shim_state_test_guard();
    let _saved = SavedConnectEnv::capture();
    let port_a = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral loopback port")
        .local_addr()
        .expect("listener addr")
        .port();
    let port_b = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind second ephemeral loopback port")
        .local_addr()
        .expect("listener addr")
        .port();
    assert_ne!(port_a, port_b, "the two refused endpoints must differ");
    unsafe {
        std::env::set_var("PKCS11_PROXY_ENDPOINT", format!("http://127.0.0.1:{port_a}"));
        std::env::remove_var("PKCS11_PROXY_SOCKET");
        std::env::set_var("PKCS11_PROXY_CONNECT_ATTEMPTS", "1");
    }
    crate::state::mark_finalized();
    crate::interface_probe::clear_cache();
    crate::state::clear_pre_init_connect_failure();

    let before = crate::state::connect_series_count();
    crate::state::mark_client_reconnect_required();
    let first = crate::state::ensure_client_connected();
    assert!(first.is_err(), "re-dial against a refused endpoint must fail");
    assert!(
        crate::state::pre_init_connect_failed(),
        "the first dial must record its endpoint's failure key"
    );

    unsafe {
        std::env::set_var("PKCS11_PROXY_ENDPOINT", format!("http://127.0.0.1:{port_b}"));
    }
    assert!(
        !crate::state::pre_init_connect_failed(),
        "a changed endpoint must miss the first dial's failure key"
    );
    crate::state::mark_client_reconnect_required();
    let second = crate::state::ensure_client_connected();
    assert!(second.is_err(), "re-dial against the second refused endpoint must fail");
    assert!(
        crate::state::pre_init_connect_failed(),
        "the second dial must record the re-read endpoint's failure key"
    );
    assert_eq!(
        crate::state::connect_series_count() - before,
        2,
        "each forced reconnect must run its own fresh dial series"
    );
}

/// Panic-safe override for PKCS11_PROXY_DISABLE_SERVER_REGISTRY (restored
/// on drop even when an assertion fails, so later tests keep a clean env).
struct SavedDisableRegistry {
    saved: Option<String>,
}

impl SavedDisableRegistry {
    fn capture() -> Self {
        Self { saved: std::env::var("PKCS11_PROXY_DISABLE_SERVER_REGISTRY").ok() }
    }

    fn set(value: Option<&str>) {
        unsafe {
            match value {
                Some(v) => std::env::set_var("PKCS11_PROXY_DISABLE_SERVER_REGISTRY", v),
                None => std::env::remove_var("PKCS11_PROXY_DISABLE_SERVER_REGISTRY"),
            }
        }
    }
}

impl Drop for SavedDisableRegistry {
    fn drop(&mut self) {
        Self::set(self.saved.as_deref());
    }
}

/// Shared buffer capturing tracing output for assertions. Thread-local
/// (`with_default`): the registry-install path emits synchronously on the
/// calling thread, so no global subscriber is needed.
#[derive(Clone, Default)]
struct CapturedWriter {
    buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl std::io::Write for CapturedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedWriter {
    type Writer = CapturedWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture_logs(f: impl FnOnce()) -> String {
    let writer = CapturedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    String::from_utf8_lossy(&writer.buf.lock().unwrap()).to_string()
}

fn registry_payload_with_revision(rev: &str) -> pkcs11_proxy_ng_proto::MechanismRegistryPayload {
    let mut registry =
        pkcs11_proxy_ng_types::MechanismRegistry::load(None).expect("embedded registry loads");
    registry.set_revision(rev.to_string());
    (&registry).into()
}

/// Install the embedded-default registry so `mechanism_registry()` reads
/// below never panic with "not initialized" when this test runs before
/// any `C_Initialize` in a filtered run.
fn ensure_registry_installed() {
    crate::state::replace_mechanism_registry(
        pkcs11_proxy_ng_types::MechanismRegistry::load(None).expect("embedded registry loads"),
    );
}

/// Install `payload` and read back the global revision, retrying while a
/// concurrent unguarded `ensure_registry()` (mechanism-parameter unit
/// tests, which cannot see the shim state guard) clobbers the global
/// registry between our install and read-back. Bounded: 100 consecutive
/// clobbers is impossible without a real bug.
fn install_and_read_back_revision(
    payload: &pkcs11_proxy_ng_proto::MechanismRegistryPayload,
) -> String {
    for _ in 0..100 {
        crate::interface_probe::maybe_install_server_registry(Some(payload));
        let got = crate::state::mechanism_registry().revision().to_string();
        if got == payload.revision {
            return got;
        }
    }
    panic!("global registry clobbered 100x in a row — a real bug, not a flake");
}

/// W1-C7-06: with the disable env unset, a server-published registry
/// payload installs (the fallback is replaced) and the install is logged.
#[test]
fn server_registry_installs_when_disable_env_unset() {
    let _guard = shim_state_test_guard();
    let _saved = SavedDisableRegistry::capture();
    SavedDisableRegistry::set(None);
    ensure_registry_installed();
    crate::interface_probe::reset_registry_revision_for_test();
    let payload = registry_payload_with_revision("c7-06-install-test");
    let output = capture_logs(|| {
        crate::interface_probe::maybe_install_server_registry(Some(&payload));
    });
    assert!(
        output.contains("mechanism registry installed from server")
            && output.contains("c7-06-install-test"),
        "install must be logged with the payload revision: {output:?}"
    );
    assert_eq!(install_and_read_back_revision(&payload), "c7-06-install-test");
}

/// W1-C7-06: with PKCS11_PROXY_DISABLE_SERVER_REGISTRY set, the server
/// payload is ignored and the fallback registry stays (AGENTS.md §13:
/// the env var "forces the fallback path").
#[test]
fn server_registry_ignored_when_disable_env_set() {
    let _guard = shim_state_test_guard();
    let _saved = SavedDisableRegistry::capture();
    ensure_registry_installed();
    crate::interface_probe::reset_registry_revision_for_test();
    SavedDisableRegistry::set(Some("1"));
    let ignored = registry_payload_with_revision("c7-06-must-not-install");
    // State assertion first, retrying past concurrent unguarded
    // `ensure_registry()` clobbers (see install_and_read_back_revision).
    for _ in 0..100 {
        let before = crate::state::mechanism_registry().revision().to_string();
        crate::interface_probe::maybe_install_server_registry(Some(&ignored));
        let after = crate::state::mechanism_registry().revision().to_string();
        assert!(
            after != "c7-06-must-not-install",
            "disabled path must never install the server payload"
        );
        if after == before {
            break;
        }
    }
    let output = capture_logs(|| {
        crate::interface_probe::maybe_install_server_registry(Some(&ignored));
    });
    assert!(
        output.contains("ignoring server-published registry"),
        "fallback must be logged: {output:?}"
    );
    assert!(
        !output.contains("c7-06-must-not-install"),
        "ignored payload revision must never be logged as installed: {output:?}"
    );
}

/// W1-C7-06: consecutive installs with different revisions emit the
/// registry-drift WARN naming both revisions (HA-daemon drift signal).
#[test]
fn registry_revision_drift_warns_with_both_revisions() {
    let _guard = shim_state_test_guard();
    let _saved = SavedDisableRegistry::capture();
    SavedDisableRegistry::set(None);
    ensure_registry_installed();
    crate::interface_probe::reset_registry_revision_for_test();
    let first = registry_payload_with_revision("c7-06-drift-a");
    let second = registry_payload_with_revision("c7-06-drift-b");
    let output = capture_logs(|| {
        crate::interface_probe::maybe_install_server_registry(Some(&first));
        crate::interface_probe::maybe_install_server_registry(Some(&second));
    });
    assert!(
        output.contains("mechanism registry installed from server")
            && output.contains("c7-06-drift-a"),
        "first install must log INFO with its revision: {output:?}"
    );
    assert!(
        output.contains("WARN") && output.contains("changed between probes"),
        "drift must log WARN: {output:?}"
    );
    assert!(
        output.contains("c7-06-drift-a") && output.contains("c7-06-drift-b"),
        "drift WARN must name both revisions: {output:?}"
    );
}

/// W1-C7-06: an absent payload (older daemon predating the field) leaves
/// the registry untouched in both env states — and logs no install.
#[test]
fn absent_registry_payload_keeps_current_registry() {
    let _guard = shim_state_test_guard();
    let _saved = SavedDisableRegistry::capture();
    ensure_registry_installed();
    crate::interface_probe::reset_registry_revision_for_test();
    for env in [None, Some("1")] {
        SavedDisableRegistry::set(env);
        let before = crate::state::mechanism_registry().revision().to_string();
        let output = capture_logs(|| crate::interface_probe::maybe_install_server_registry(None));
        assert!(
            !output.contains("mechanism registry installed from server"),
            "absent payload must not log an install (env={env:?}): {output:?}"
        );
        // A concurrent unguarded `ensure_registry()` may legitimately swap
        // the global here; only our own install would be a bug, and an
        // absent payload cannot install — so a change is tolerable only
        // toward the embedded default, never toward a server revision.
        let after = crate::state::mechanism_registry().revision().to_string();
        assert!(
            after == before || after == "embedded-default",
            "absent payload must not install anything (env={env:?}): {before} -> {after}"
        );
    }
}

/// W1-L8-19: explicit falsy values re-enable the server registry —
/// `=0`/`=false`/`=no`/`=off` must behave like unset, not like `=1`.
#[test]
fn server_registry_installs_when_disable_env_is_falsy() {
    let _guard = shim_state_test_guard();
    let _saved = SavedDisableRegistry::capture();
    ensure_registry_installed();
    crate::interface_probe::reset_registry_revision_for_test();
    for value in ["0", "false", "FALSE", "no", "off"] {
        SavedDisableRegistry::set(Some(value));
        let rev = format!("l8-19-falsy-{value}");
        let payload = registry_payload_with_revision(&rev);
        let output = capture_logs(|| {
            crate::interface_probe::maybe_install_server_registry(Some(&payload));
        });
        // The install logs either the install INFO (first revision) or the
        // drift WARN (later revisions) — both name the payload revision.
        assert!(
            output.contains(&rev) && !output.contains("ignoring server-published registry"),
            "disable env ={value} must re-enable install, got: {output:?}"
        );
        assert_eq!(install_and_read_back_revision(&payload), rev);
    }
}

/// W1-L8-19: truthy or unrecognized values keep the legacy disable
/// (presence semantics) — only explicit falsy values re-enable, and only
/// unset keeps the pure default.
#[test]
fn server_registry_ignored_for_truthy_disable_values() {
    let _guard = shim_state_test_guard();
    let _saved = SavedDisableRegistry::capture();
    ensure_registry_installed();
    crate::interface_probe::reset_registry_revision_for_test();
    for (i, value) in ["1", "true", "TRUE", "yes", ""].into_iter().enumerate() {
        SavedDisableRegistry::set(Some(value));
        let rev = format!("l8-19-truthy-{i}");
        let ignored = registry_payload_with_revision(&rev);
        // State assertion first, retrying past concurrent unguarded
        // `ensure_registry()` clobbers (see install_and_read_back_revision).
        for _ in 0..100 {
            let before = crate::state::mechanism_registry().revision().to_string();
            crate::interface_probe::maybe_install_server_registry(Some(&ignored));
            let after = crate::state::mechanism_registry().revision().to_string();
            assert!(after != rev, "disable env ={value:?} must never install the server payload");
            if after == before {
                break;
            }
        }
        let output = capture_logs(|| {
            crate::interface_probe::maybe_install_server_registry(Some(&ignored));
        });
        assert!(
            output.contains("ignoring server-published registry"),
            "disable env ={value:?} must log the fallback: {output:?}"
        );
    }
}

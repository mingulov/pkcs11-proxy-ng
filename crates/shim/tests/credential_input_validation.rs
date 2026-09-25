use cryptoki_sys::{
    CK_FUNCTION_LIST_3_0, CK_INTERFACE, CK_VERSION, CKR_ARGUMENTS_BAD, CKR_OK, CKU_USER,
};
use pkcs11_proxy_ng_shim::C_GetInterface;

#[test]
fn null_nonzero_credentials_are_refused_at_every_abi_entrypoint() {
    let mut interface: *mut CK_INTERFACE = std::ptr::null_mut();
    let mut version = CK_VERSION { major: 3, minor: 0 };
    assert_eq!(
        unsafe { C_GetInterface(std::ptr::null_mut(), &mut version, &mut interface, 0) },
        CKR_OK
    );
    assert!(!interface.is_null());
    let table = unsafe { &*((*interface).pFunctionList.cast::<CK_FUNCTION_LIST_3_0>()) };
    let null = std::ptr::null_mut();
    let mut label = [b' '; 32];
    let mut pin = *b"1234";

    // These calls must fail before looking up a client or contacting a token.
    // Replacing any credential reader with the general optional-byte reader
    // would flatten the claimed nonzero length and bypass this boundary.
    let results = unsafe {
        [
            ("C_InitToken", (table.C_InitToken.unwrap())(0, null, 8, label.as_mut_ptr())),
            ("C_InitPIN", (table.C_InitPIN.unwrap())(0, null, 8)),
            ("C_SetPIN old", (table.C_SetPIN.unwrap())(0, null, 8, pin.as_mut_ptr(), 4)),
            ("C_SetPIN new", (table.C_SetPIN.unwrap())(0, pin.as_mut_ptr(), 4, null, 8)),
            ("C_Login", (table.C_Login.unwrap())(0, CKU_USER, null, 8)),
            (
                "C_LoginUser PIN",
                (table.C_LoginUser.unwrap())(0, CKU_USER, null, 8, pin.as_mut_ptr(), 4),
            ),
            (
                "C_LoginUser username",
                (table.C_LoginUser.unwrap())(0, CKU_USER, pin.as_mut_ptr(), 4, null, 8),
            ),
        ]
    };
    for (entrypoint, rv) in results {
        assert_eq!(rv, CKR_ARGUMENTS_BAD, "{entrypoint} must reject the unsupported shape");
    }
}

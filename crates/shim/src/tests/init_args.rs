use super::*;

unsafe extern "C" fn dummy_create_mutex(_: *mut CK_VOID_PTR) -> CK_RV {
    CKR_GENERAL_ERROR as CK_RV
}

unsafe extern "C" fn dummy_destroy_mutex(_: CK_VOID_PTR) -> CK_RV {
    CKR_GENERAL_ERROR as CK_RV
}

unsafe extern "C" fn dummy_lock_mutex(_: CK_VOID_PTR) -> CK_RV {
    CKR_GENERAL_ERROR as CK_RV
}

unsafe extern "C" fn dummy_unlock_mutex(_: CK_VOID_PTR) -> CK_RV {
    CKR_GENERAL_ERROR as CK_RV
}

#[test]
fn initialize_p_reserved_nonnull_returns_bad_args() {
    let _guard = shim_state_test_guard();
    let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: 0,
        pReserved: std::ptr::dangling_mut::<std::os::raw::c_void>(),
    };
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn initialize_custom_mutex_callbacks_returns_cant_lock() {
    let _guard = shim_state_test_guard();
    let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: Some(dummy_create_mutex),
        DestroyMutex: Some(dummy_destroy_mutex),
        LockMutex: Some(dummy_lock_mutex),
        UnlockMutex: Some(dummy_unlock_mutex),
        flags: 0,
        pReserved: std::ptr::null_mut(),
    };
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_eq!(rv, CKR_CANT_LOCK as CK_RV);
}

#[test]
fn initialize_os_locking_ok_flag_accepted_before_server() {
    let _guard = shim_state_test_guard();
    let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK,
        pReserved: std::ptr::null_mut(),
    };
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_ne!(rv, CKR_ARGUMENTS_BAD as CK_RV);
    assert_ne!(rv, CKR_CANT_LOCK as CK_RV);
    if rv == CKR_OK as CK_RV {
        let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    }
}

#[test]
fn initialize_mutex_callbacks_with_os_locking_ok_accepted() {
    let _guard = shim_state_test_guard();
    let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: Some(dummy_create_mutex),
        DestroyMutex: Some(dummy_destroy_mutex),
        LockMutex: Some(dummy_lock_mutex),
        UnlockMutex: Some(dummy_unlock_mutex),
        flags: CKF_OS_LOCKING_OK,
        pReserved: std::ptr::null_mut(),
    };
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_ne!(rv, CKR_ARGUMENTS_BAD as CK_RV);
    assert_ne!(rv, CKR_CANT_LOCK as CK_RV);
    if rv == CKR_OK as CK_RV {
        let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    }
}

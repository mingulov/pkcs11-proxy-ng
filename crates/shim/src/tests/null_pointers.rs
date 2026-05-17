use super::*;

#[test]
fn c_init_token_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    let rv = unsafe {
        dispatch::general::c_init_token(0, std::ptr::null_mut(), 0, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_init_pin_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    let rv = unsafe { dispatch::general::c_init_pin(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_set_pin_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    let rv = unsafe {
        dispatch::general::c_set_pin(0, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0)
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_init_pin_rejects_unserializable_pin_length_before_client_use() {
    let _guard = shim_state_test_guard();
    let pin = std::ptr::dangling_mut::<CK_UTF8CHAR>();
    let rv = unsafe { dispatch::general::c_init_pin(0, pin, CK_ULONG::MAX) };
    assert_eq!(rv, CKR_GENERAL_ERROR as CK_RV);
}

#[test]
fn c_get_info_null_p_info_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_get_info(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_slot_list_null_pul_count_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_get_slot_list(0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_slot_info_null_p_info_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_get_slot_info(0, std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_token_info_null_p_info_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_get_token_info(0, std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_mechanism_list_null_pul_count_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_get_mechanism_list(0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_mechanism_info_null_p_info_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_get_mechanism_info(0, 0, std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_open_session_null_ph_session_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_open_session(0, 0, std::ptr::null_mut(), None, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_session_info_null_p_info_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_get_session_info(0, std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_wait_for_slot_event_nonnull_reserved_returns_bad_args() {
    let _guard = shim_state_test_guard();
    let mut slot = 0;
    let mut reserved = 0u8;
    let rv = unsafe {
        dispatch::general::c_wait_for_slot_event(0, &mut slot, (&mut reserved as *mut u8).cast())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_sign_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_sign_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_sign_null_pul_len_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_sign(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_sign_final_null_pul_len_returns_bad_args() {
    let rv =
        unsafe { dispatch::general::c_sign_final(0, std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_verify_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_verify_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_sign_recover_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_sign_recover_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_verify_recover_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_verify_recover_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_sign_recover_null_pul_len_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_sign_recover(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_verify_recover_null_pul_len_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_verify_recover(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_digest_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_digest_init(0, std::ptr::null_mut()) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_digest_null_pul_len_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_digest(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_encrypt_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_encrypt_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_encrypt_null_pul_len_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_encrypt(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_decrypt_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_decrypt_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_decrypt_null_pul_len_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_decrypt(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_find_objects_null_outputs_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_find_objects(0, std::ptr::null_mut(), 0, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_attribute_value_null_template_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_get_attribute_value(0, 0, std::ptr::null_mut(), 1) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_create_object_null_ph_object_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_create_object(0, std::ptr::null_mut(), 0, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_generate_key_pair_null_outputs_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_generate_key_pair(
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_generate_random_null_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_generate_random(0, std::ptr::null_mut(), 32) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_wrap_key_null_pul_len_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_wrap_key(
            0,
            std::ptr::null_mut(),
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_operation_state_null_pul_len_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_get_operation_state(0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

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
    // W1-L3-03: oversize PIN must return CKR_ARGUMENTS_BAD (the documented
    // stable RV for the transport-impossible class, matching classify_input),
    // never panic-to-CKR_GENERAL_ERROR via catch_panics. Asserting
    // ARGUMENTS_BAD (not GENERAL_ERROR) proves the catch_panics panic branch
    // was not taken: any panic would surface as GENERAL_ERROR.
    let _guard = shim_state_test_guard();
    let pin = std::ptr::dangling_mut::<CK_UTF8CHAR>();
    let rv = unsafe { dispatch::general::c_init_pin(0, pin, CK_ULONG::MAX) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_init_token_rejects_unserializable_pin_length_before_client_use() {
    // W1-L3-03: same class as c_init_pin — oversize SO PIN is ARGUMENTS_BAD,
    // never a panic surfaced as GENERAL_ERROR.
    let _guard = shim_state_test_guard();
    let pin = std::ptr::dangling_mut::<CK_UTF8CHAR>();
    let rv =
        unsafe { dispatch::general::c_init_token(0, pin, CK_ULONG::MAX, std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_set_pin_rejects_unserializable_old_pin_length_before_client_use() {
    // W1-L3-03: oversize old PIN is ARGUMENTS_BAD even when the new PIN is valid.
    let _guard = shim_state_test_guard();
    let old_pin = std::ptr::dangling_mut::<CK_UTF8CHAR>();
    let new_pin = *b"5678";
    let rv = unsafe {
        dispatch::general::c_set_pin(0, old_pin, CK_ULONG::MAX, new_pin.as_ptr() as *mut _, 4)
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_set_pin_rejects_unserializable_new_pin_length_before_client_use() {
    // W1-L3-03: oversize new PIN is ARGUMENTS_BAD even when the old PIN is valid.
    let _guard = shim_state_test_guard();
    let old_pin = *b"1234";
    let new_pin = std::ptr::dangling_mut::<CK_UTF8CHAR>();
    let rv = unsafe {
        dispatch::general::c_set_pin(0, old_pin.as_ptr() as *mut _, 4, new_pin, CK_ULONG::MAX)
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_init_pin_valid_pin_reaches_client_state() {
    // W1-L3-03: valid PINs are unaffected — parsing passes through to the
    // client gate (NOT_INITIALIZED here, since C_Initialize was never called).
    let _guard = shim_state_test_guard();
    let pin = *b"1234";
    let rv = unsafe { dispatch::general::c_init_pin(0, pin.as_ptr() as *mut _, 4) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_init_token_valid_pin_reaches_client_state() {
    // W1-L3-03: valid SO PIN is unaffected — parsing passes through.
    let _guard = shim_state_test_guard();
    let pin = *b"1234";
    let rv = unsafe {
        dispatch::general::c_init_token(0, pin.as_ptr() as *mut _, 4, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_set_pin_valid_pins_reach_client_state() {
    // W1-L3-03: valid old/new PINs are unaffected — parsing passes through.
    let _guard = shim_state_test_guard();
    let old_pin = *b"1234";
    let new_pin = *b"5678";
    let rv = unsafe {
        dispatch::general::c_set_pin(
            0,
            old_pin.as_ptr() as *mut _,
            4,
            new_pin.as_ptr() as *mut _,
            4,
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_login_rejects_unserializable_pin_length_before_client_use() {
    // W1-L11-10: same TooLarge class as the L3-03 PIN sites — oversize
    // C_Login PIN is ARGUMENTS_BAD, never a panic surfaced as
    // GENERAL_ERROR via the old panicking reader.
    let _guard = shim_state_test_guard();
    let pin = std::ptr::dangling_mut::<CK_UTF8CHAR>();
    let rv = unsafe { dispatch::general::c_login(0, CKU_SO, pin, CK_ULONG::MAX) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_login_user_rejects_unserializable_pin_length_before_client_use() {
    // W1-L11-10: oversize C_LoginUser PIN is ARGUMENTS_BAD even when the
    // username is valid.
    let _guard = shim_state_test_guard();
    let pin = std::ptr::dangling_mut::<CK_UTF8CHAR>();
    let username = *b"alice";
    let rv = unsafe {
        dispatch::general::c_login_user(
            0,
            CKU_USER,
            pin,
            CK_ULONG::MAX,
            username.as_ptr() as *mut _,
            5,
        )
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_login_user_rejects_unserializable_username_length_before_client_use() {
    // W1-L11-10: oversize C_LoginUser username is ARGUMENTS_BAD even when
    // the PIN is valid.
    let _guard = shim_state_test_guard();
    let pin = *b"1234";
    let username = std::ptr::dangling_mut::<CK_UTF8CHAR>();
    let rv = unsafe {
        dispatch::general::c_login_user(
            0,
            CKU_USER,
            pin.as_ptr() as *mut _,
            4,
            username,
            CK_ULONG::MAX,
        )
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_login_valid_pin_reaches_client_state() {
    // W1-L11-10 pin: valid C_Login PIN is unaffected — parsing passes
    // through to the client gate.
    let _guard = shim_state_test_guard();
    let pin = *b"1234";
    let rv = unsafe { dispatch::general::c_login(0, CKU_SO, pin.as_ptr() as *mut _, 4) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_login_user_valid_inputs_reach_client_state() {
    // W1-L11-10 pin: valid C_LoginUser PIN/username are unaffected —
    // parsing passes through to the client gate.
    let _guard = shim_state_test_guard();
    let pin = *b"1234";
    let username = *b"alice";
    let rv = unsafe {
        dispatch::general::c_login_user(
            0,
            CKU_USER,
            pin.as_ptr() as *mut _,
            4,
            username.as_ptr() as *mut _,
            5,
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_init_token_valid_label_reaches_client_state() {
    // W1-L11-10 pin: the fixed-32 label read is unaffected by the
    // fallible-reader migration — parsing passes through.
    let _guard = shim_state_test_guard();
    let mut label = [b' '; pkcs11_proxy_ng_types::PKCS11_TOKEN_LABEL_LEN];
    label[..8].copy_from_slice(b"test tok");
    let rv = unsafe {
        dispatch::general::c_init_token(0, std::ptr::null_mut(), 0, label.as_ptr() as *mut _)
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
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
fn c_find_objects_init_null_template_nonzero_count_returns_bad_args() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_find_objects_init(0, std::ptr::null_mut(), 5) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_create_object_null_template_nonzero_count_returns_bad_args() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let mut object = CK_INVALID_HANDLE;
    let rv = unsafe { dispatch::general::c_create_object(0, std::ptr::null_mut(), 5, &mut object) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_generate_key_null_template_nonzero_count_returns_bad_args() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut key = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_generate_key(0, &mut mechanism, std::ptr::null_mut(), 5, &mut key)
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_find_objects_init_null_attr_value_nonzero_len_returns_bad_args() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let mut attr = CK_ATTRIBUTE { type_: CKA_LABEL, pValue: std::ptr::null_mut(), ulValueLen: 1 };
    let rv = unsafe { dispatch::general::c_find_objects_init(0, &mut attr, 1) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_create_object_null_attr_value_nonzero_len_returns_bad_args() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let mut attr = CK_ATTRIBUTE { type_: CKA_LABEL, pValue: std::ptr::null_mut(), ulValueLen: 1 };
    let mut object = CK_INVALID_HANDLE;
    let rv = unsafe { dispatch::general::c_create_object(0, &mut attr, 1, &mut object) };
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
fn c_sign_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_sign(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_sign_final_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv =
        unsafe { dispatch::general::c_sign_final(0, std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
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
fn c_sign_recover_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_sign_recover(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_verify_recover_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_verify_recover(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_digest_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_digest_init(0, std::ptr::null_mut()) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_digest_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_digest(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_encrypt_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_encrypt_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_encrypt_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_encrypt(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_decrypt_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_decrypt_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_decrypt_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_decrypt(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_find_objects_null_outputs_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_find_objects(0, std::ptr::null_mut(), 0, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_find_objects_rejects_max_count_above_wire_width_before_client_use() {
    // W1-L3-07: ulMaxObjectCount wider than the u32 wire field must be
    // rejected with CKR_DATA_LEN_RANGE (the c_generate_random convention),
    // never truncated via `as u32`. Recorded pre-fix state: the count was
    // truncated and the call proceeded to the client (NOT_INITIALIZED here).
    if CK_ULONG::BITS <= u32::BITS {
        return;
    }

    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let mut object: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let mut count: CK_ULONG = 0;
    let too_large = (u32::MAX as u64 + 1) as CK_ULONG;

    let rv = unsafe { dispatch::general::c_find_objects(0, &mut object, too_large, &mut count) };

    assert_eq!(rv, CKR_DATA_LEN_RANGE as CK_RV);
    assert_eq!(count, 0, "rejected call must not write the count");
    assert_eq!(object, CK_INVALID_HANDLE, "rejected call must not write handles");
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
fn c_generate_random_null_precedes_unrepresentable_length() {
    if CK_ULONG::BITS <= u32::BITS {
        return;
    }

    let too_large = (u32::MAX as u64 + 1) as CK_ULONG;
    let rv = unsafe { dispatch::general::c_generate_random(0, std::ptr::null_mut(), too_large) };

    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_generate_random_rejects_length_above_wire_width_before_client_use() {
    if CK_ULONG::BITS <= u32::BITS {
        return;
    }

    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let output = std::ptr::dangling_mut::<CK_BYTE>();
    let too_large = (u32::MAX as u64 + 1) as CK_ULONG;

    let rv = unsafe { dispatch::general::c_generate_random(0, output, too_large) };

    assert_eq!(rv, CKR_DATA_LEN_RANGE as CK_RV);
}

#[test]
fn c_wrap_key_null_mechanism_still_precedes_client_state() {
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
fn c_get_operation_state_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_get_operation_state(0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

// ---------------------------------------------------------------------------
// W1-L3-11: session resolution before mechanism validation (native precedence)
// ---------------------------------------------------------------------------

/// A session handle no backend can ever mint (MockBackend/SoftHSM allocate
/// small handles), so it is guaranteed unknown to the shim's session map.
const UNKNOWN_SESSION: CK_SESSION_HANDLE = CK_SESSION_HANDLE::MAX;
/// A second never-minted handle, registered as known for the control test.
const KNOWN_SESSION: CK_SESSION_HANDLE = CK_SESSION_HANDLE::MAX - 1;

/// Build a mechanism `validate_mechanism` must reject deterministically:
/// an overlong parameter length trips the entry gate before any memory is
/// touched, so the dangling pointer is never dereferenced (W1-L12-06
/// convention) and no registry state is needed.
fn overlong_mechanism() -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: std::ptr::dangling_mut::<u8>().cast(),
        ulParameterLen: (dispatch::general::helpers::MAX_MECHANISM_PARAM_STRUCT_LEN + 1)
            as CK_ULONG,
    }
}

/// Dual-defect input (bad session + bad mechanism) must yield the native
/// session error on every digest/cipher init, not the mechanism error.
#[test]
fn init_bad_session_and_bad_mechanism_yields_session_error() {
    let _guard = shim_state_test_guard();
    let _ = state::mark_initialized();
    let mut mech = overlong_mechanism();
    let rv = unsafe { dispatch::general::c_digest_init(UNKNOWN_SESSION, &mut mech) };
    assert_eq!(
        rv, CKR_SESSION_HANDLE_INVALID as CK_RV,
        "W1-L3-11: C_DigestInit with bad session + bad mechanism must return the session error"
    );
    let rv = unsafe { dispatch::general::c_encrypt_init(UNKNOWN_SESSION, &mut mech, 0) };
    assert_eq!(
        rv, CKR_SESSION_HANDLE_INVALID as CK_RV,
        "W1-L3-11: C_EncryptInit with bad session + bad mechanism must return the session error"
    );
    let rv = unsafe { dispatch::general::c_decrypt_init(UNKNOWN_SESSION, &mut mech, 0) };
    assert_eq!(
        rv, CKR_SESSION_HANDLE_INVALID as CK_RV,
        "W1-L3-11: C_DecryptInit with bad session + bad mechanism must return the session error"
    );
    // Leave-no-trace: later tests (e.g. ShimSession fixtures) require the
    // cryptoki flag unset at entry.
    state::mark_finalized();
}

/// Uninitialized cryptoki outranks both: dual-defect input before
/// C_Initialize must answer NOT_INITIALIZED, never MECHANISM_*.
#[test]
fn init_dual_defect_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let mut mech = overlong_mechanism();
    let rv = unsafe { dispatch::general::c_digest_init(UNKNOWN_SESSION, &mut mech) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
    let rv = unsafe { dispatch::general::c_encrypt_init(UNKNOWN_SESSION, &mut mech, 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
    let rv = unsafe { dispatch::general::c_decrypt_init(UNKNOWN_SESSION, &mut mech, 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

/// Control: a KNOWN session with a bad mechanism still reaches mechanism
/// validation (no RPC is sent; characterization, green before and after).
#[test]
fn init_known_session_with_bad_mechanism_still_validates_mechanism() {
    let _guard = shim_state_test_guard();
    let _ = state::mark_initialized();
    state::remember_session_slot(KNOWN_SESSION, 0);
    let mut mech = overlong_mechanism();
    let rv = unsafe { dispatch::general::c_digest_init(KNOWN_SESSION, &mut mech) };
    assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID as CK_RV);
    let rv = unsafe { dispatch::general::c_encrypt_init(KNOWN_SESSION, &mut mech, 0) };
    assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID as CK_RV);
    let rv = unsafe { dispatch::general::c_decrypt_init(KNOWN_SESSION, &mut mech, 0) };
    assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID as CK_RV);
    // Leave-no-trace: unset the cryptoki flag and forget the sentinel.
    state::evict_session_authoritative_state(KNOWN_SESSION);
    state::mark_finalized();
}

// ---------------------------------------------------------------------------
// ADR-0010 Scope 2: NULL-pointer faithfulness end-to-end (c_decrypt exemplar)
//
// These tests require a full shim → client → gRPC → server → MockBackend
// stack and so need a running daemon. They use their own minimal fixture
// rather than the one in output_semantics.rs (which is private).
// ---------------------------------------------------------------------------

mod decrypt_null_e2e {
    use std::sync::Arc;
    use std::time::Duration;

    use pkcs11_proxy_ng::server::context_manager::ContextManager;
    use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
    use pkcs11_proxy_ng_types::{CkMechanismType, CkSlotId, InterfaceCapabilities, InterfaceInfo};
    use tokio::net::TcpListener;
    use tokio::runtime::Runtime;
    use tokio::sync::watch;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    use super::super::*;

    /// A minimal in-process daemon for c_decrypt e2e tests.
    struct DecryptDaemon {
        // Kept to ensure the tokio runtime outlives the daemon.
        _runtime: Runtime,
        endpoint: String,
        _shutdown: watch::Sender<bool>,
    }

    impl DecryptDaemon {
        fn start() -> Self {
            let runtime = Runtime::new().expect("test runtime");
            let (endpoint, shutdown_tx) = runtime.block_on(async {
                let backend = Arc::new(MockBackend::new(
                    vec![CkSlotId(0)],
                    vec![CkMechanismType::AES_ECB, CkMechanismType::AES_GCM],
                ));
                backend.set_interface_capabilities(InterfaceCapabilities {
                    interfaces: vec![
                        InterfaceInfo {
                            version_major: 2,
                            version_minor: 40,
                            null_functions: vec![],
                        },
                        InterfaceInfo {
                            version_major: 3,
                            version_minor: 0,
                            null_functions: vec![],
                        },
                        InterfaceInfo {
                            version_major: 3,
                            version_minor: 2,
                            null_functions: vec![],
                        },
                    ],
                });
                let backend_trait: Arc<dyn Pkcs11Backend> = backend.clone();
                let context_manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
                context_manager.populate_slots(&backend_trait).await.expect("populate_slots");

                let service =
                    Pkcs11ProxyService::insecure_for_tests(context_manager.clone(), backend_trait);
                let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
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
                (endpoint, shutdown_tx)
            });
            Self { _runtime: runtime, endpoint, _shutdown: shutdown_tx }
        }
    }

    impl Drop for DecryptDaemon {
        fn drop(&mut self) {
            let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
            unsafe { std::env::remove_var("PKCS11_PROXY_ENDPOINT") };
        }
    }

    fn aes_ecb_mechanism() -> CK_MECHANISM {
        CK_MECHANISM { mechanism: CKM_AES_ECB, pParameter: std::ptr::null_mut(), ulParameterLen: 0 }
    }

    /// Open a shim session against the daemon, create a key object, and run
    /// C_DecryptInit. Returns the session handle and the key object handle.
    fn init_decrypt_session(endpoint: &str) -> (CK_SESSION_HANDLE, CK_OBJECT_HANDLE) {
        unsafe {
            std::env::set_var("PKCS11_PROXY_ENDPOINT", endpoint);
        }
        let rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_Initialize");

        let mut slot_count: CK_ULONG = 0;
        let rv = unsafe {
            dispatch::general::c_get_slot_list(CK_FALSE, std::ptr::null_mut(), &mut slot_count)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "GetSlotList count");
        assert!(slot_count > 0);

        let mut slots = vec![0 as CK_SLOT_ID; slot_count as usize];
        let rv = unsafe {
            dispatch::general::c_get_slot_list(CK_FALSE, slots.as_mut_ptr(), &mut slot_count)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "GetSlotList data");

        let mut session = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_open_session(
                slots[0],
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &mut session,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_OpenSession");

        // Create a key object (mock accepts any object as a key)
        let mut key = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_create_object(session, std::ptr::null_mut(), 0, &mut key)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_CreateObject");

        // Initialize decrypt
        let mut mech = aes_ecb_mechanism();
        let rv = unsafe { dispatch::general::c_decrypt_init(session, &mut mech, key) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_DecryptInit");

        (session, key)
    }

    /// ADR-0010 Scope 2: NULL input pointer with non-zero len reaches the
    /// MockBackend as `CkInBuf::Null{len}`. MockBackend rejects that with
    /// ARGUMENTS_BAD (strict-token policy), proving the NULL-ness crossed the
    /// full shim → client → server → backend path.
    #[test]
    fn c_decrypt_null_input_with_len_reaches_backend_as_null() {
        let _guard = shim_state_test_guard();
        let daemon = DecryptDaemon::start();
        let (session, _key) = init_decrypt_session(&daemon.endpoint);

        let mut out_len: CK_ULONG = 64;
        let mut out_buf = vec![0u8; 64];
        // NULL input pointer, non-zero claimed length.
        let rv = unsafe {
            dispatch::general::c_decrypt(
                session,
                std::ptr::null_mut(), // NULL input
                16,                   // claimed len > 0
                out_buf.as_mut_ptr(),
                &mut out_len,
            )
        };
        // MockBackend returns ARGUMENTS_BAD for Null{len>0}, proving NULL-ness
        // crossed the full shim → client → server → backend path.
        assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
    }

    /// ADR-0010 Scope 2: TooLarge input is caught by the shim itself (transport
    /// limit RV) and never reaches the daemon. Previously this would panic
    /// (GENERAL_ERROR); now it returns the documented stable RV (ARGUMENTS_BAD).
    #[test]
    fn c_decrypt_too_large_input_shim_rejects_with_arguments_bad() {
        let _guard = shim_state_test_guard();
        let daemon = DecryptDaemon::start();
        let (session, _key) = init_decrypt_session(&daemon.endpoint);

        let mut out_len: CK_ULONG = 64;
        let mut out_buf = vec![0u8; 64];
        // Valid (non-null) pointer but unmaterializable length.
        let dangling: *mut CK_BYTE = std::ptr::dangling_mut::<CK_BYTE>();
        let rv = unsafe {
            dispatch::general::c_decrypt(
                session,
                dangling,
                CK_ULONG::MAX, // TooLarge
                out_buf.as_mut_ptr(),
                &mut out_len,
            )
        };
        assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
    }

    /// ADR-0010 Scope 2 negative control: NULL pointer + len=0 is a valid
    /// "empty input" (Null{len:0}). The MockBackend treats it as an empty
    /// slice and returns OK (or BUFFER_TOO_SMALL on size query) — it must NOT
    /// return ARGUMENTS_BAD from the null-input handler, confirming that only
    /// Null{len>0} triggers the rejection.
    #[test]
    fn c_decrypt_null_input_zero_len_is_not_arguments_bad_from_null_handling() {
        let _guard = shim_state_test_guard();
        let daemon = DecryptDaemon::start();
        let (session, _key) = init_decrypt_session(&daemon.endpoint);

        let mut out_len: CK_ULONG = 64;
        let mut out_buf = vec![0u8; 64];
        // NULL input pointer with zero len — treated as empty, not as an error
        // from our NULL-faithfulness code.
        let rv = unsafe {
            dispatch::general::c_decrypt(
                session,
                std::ptr::null_mut(), // NULL input
                0,                    // len == 0, so Null{len:0}
                out_buf.as_mut_ptr(),
                &mut out_len,
            )
        };
        // NULL input + zero len = empty = mock returns CKR_OK.
        assert_eq!(rv, CKR_OK as CK_RV);
    }
}

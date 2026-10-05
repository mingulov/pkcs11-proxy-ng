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
fn c_find_objects_clamps_max_count_above_wire_width() {
    // T20: ulMaxObjectCount is a CAP — backends accept absurd values
    // (SoftHSM answers OK to 0x100000008), so the shim saturates to the
    // u32 wire field instead of rejecting (the old W1-L3-07 DATA_LEN_RANGE
    // reject diverged from every backend that accepts the call). Caps
    // clamp; exact lengths (c_generate_random) keep the narrowing reject.
    // The saturated call proceeds to the client (NOT_INITIALIZED here).
    if CK_ULONG::BITS <= u32::BITS {
        return;
    }

    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let mut object: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let mut count: CK_ULONG = 0;
    let too_large = (u32::MAX as u64 + 1) as CK_ULONG;

    let rv = unsafe { dispatch::general::c_find_objects(0, &mut object, too_large, &mut count) };

    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
    assert_eq!(count, 0, "uninitialized call must not write the count");
    assert_eq!(object, CK_INVALID_HANDLE, "uninitialized call must not write handles");
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

/// Build a mechanism `read_mechanism_for_transport` must reject deterministically:
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
// Deferred T29 M3: the same session-before-mechanism precedence on the
// session-init siblings outside digest_cipher.rs (sign/verify +
// sign/verify-recover + VerifySignature inits).
// ---------------------------------------------------------------------------

/// Dual-defect input (bad session + bad mechanism) must yield the native
/// session error on every sibling init, not the mechanism error.
#[test]
fn sibling_init_bad_session_and_bad_mechanism_yields_session_error() {
    let _guard = shim_state_test_guard();
    let _ = state::mark_initialized();
    let mut mech = overlong_mechanism();
    let rv = unsafe { dispatch::general::c_sign_init(UNKNOWN_SESSION, &mut mech, 0) };
    assert_eq!(
        rv, CKR_SESSION_HANDLE_INVALID as CK_RV,
        "T29 M3: C_SignInit with bad session + bad mechanism must return the session error"
    );
    let rv = unsafe { dispatch::general::c_verify_init(UNKNOWN_SESSION, &mut mech, 0) };
    assert_eq!(
        rv, CKR_SESSION_HANDLE_INVALID as CK_RV,
        "T29 M3: C_VerifyInit with bad session + bad mechanism must return the session error"
    );
    let rv = unsafe { dispatch::general::c_sign_recover_init(UNKNOWN_SESSION, &mut mech, 0) };
    assert_eq!(
        rv, CKR_SESSION_HANDLE_INVALID as CK_RV,
        "T29 M3: C_SignRecoverInit with bad session + bad mechanism must return the session error"
    );
    let rv = unsafe { dispatch::general::c_verify_recover_init(UNKNOWN_SESSION, &mut mech, 0) };
    assert_eq!(
        rv, CKR_SESSION_HANDLE_INVALID as CK_RV,
        "T29 M3: C_VerifyRecoverInit with bad session + bad mechanism must return the session error"
    );
    let rv = unsafe {
        dispatch::general::c_verify_signature_init(
            UNKNOWN_SESSION,
            &mut mech,
            0,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(
        rv, CKR_SESSION_HANDLE_INVALID as CK_RV,
        "T29 M3: C_VerifySignatureInit with bad session + bad mechanism must return the session error"
    );
    // Leave-no-trace: later tests require the cryptoki flag unset at entry.
    state::mark_finalized();
}

/// Uninitialized cryptoki outranks both on the siblings too: dual-defect
/// input before C_Initialize must answer NOT_INITIALIZED, never MECHANISM_*.
#[test]
fn sibling_init_dual_defect_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let mut mech = overlong_mechanism();
    let rv = unsafe { dispatch::general::c_sign_init(UNKNOWN_SESSION, &mut mech, 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
    let rv = unsafe { dispatch::general::c_verify_init(UNKNOWN_SESSION, &mut mech, 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
    let rv = unsafe { dispatch::general::c_sign_recover_init(UNKNOWN_SESSION, &mut mech, 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
    let rv = unsafe { dispatch::general::c_verify_recover_init(UNKNOWN_SESSION, &mut mech, 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
    let rv = unsafe {
        dispatch::general::c_verify_signature_init(
            UNKNOWN_SESSION,
            &mut mech,
            0,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

/// Control: a KNOWN session with a bad mechanism still reaches mechanism
/// validation on every sibling (no RPC is sent; characterization, green
/// before and after).
#[test]
fn sibling_init_known_session_with_bad_mechanism_still_validates_mechanism() {
    let _guard = shim_state_test_guard();
    let _ = state::mark_initialized();
    state::remember_session_slot(KNOWN_SESSION, 0);
    let mut mech = overlong_mechanism();
    let rv = unsafe { dispatch::general::c_sign_init(KNOWN_SESSION, &mut mech, 0) };
    assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID as CK_RV);
    let rv = unsafe { dispatch::general::c_verify_init(KNOWN_SESSION, &mut mech, 0) };
    assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID as CK_RV);
    let rv = unsafe { dispatch::general::c_sign_recover_init(KNOWN_SESSION, &mut mech, 0) };
    assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID as CK_RV);
    let rv = unsafe { dispatch::general::c_verify_recover_init(KNOWN_SESSION, &mut mech, 0) };
    assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID as CK_RV);
    let rv = unsafe {
        dispatch::general::c_verify_signature_init(
            KNOWN_SESSION,
            &mut mech,
            0,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID as CK_RV);
    // Leave-no-trace: unset the cryptoki flag and forget the sentinel.
    state::evict_session_authoritative_state(KNOWN_SESSION);
    state::mark_finalized();
}

// ---------------------------------------------------------------------------
// ADR-0010 Scope 2: NULL-pointer faithfulness end-to-end (c_decrypt exemplar)
//
// These tests require a full shim → client → gRPC → server → MockBackend
// stack and so need a running daemon. They reuse the shared TestDaemon
// fixture from output_semantics.rs (W1-C7-14) rather than a private
// duplicate.
// ---------------------------------------------------------------------------

#[cfg(not(miri))] // needs a running daemon (sockets); covered natively
mod decrypt_null_e2e {
    use super::super::output_semantics::TestDaemon;
    use super::super::*;

    /// Finalizes the shim when the test ends — including on assertion
    /// unwind — mirroring the shared-daemon [`super::super::output_semantics::ShimSession`]
    /// teardown (the fixture daemon itself is a process-lifetime singleton
    /// and needs no per-test shutdown).
    struct FinalizeOnDrop;

    impl Drop for FinalizeOnDrop {
        fn drop(&mut self) {
            let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
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
        let daemon = TestDaemon::shared();
        let _finalize = FinalizeOnDrop;
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
        let daemon = TestDaemon::shared();
        let _finalize = FinalizeOnDrop;
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
        let daemon = TestDaemon::shared();
        let _finalize = FinalizeOnDrop;
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

// ---------------------------------------------------------------------------
// #30/#31: NULL-shape forwarding on dual-function updates + C_SignRecover.
//
// At a48b60b the shim erased NULL parts to empty (→ CKR_OK) and
// short-circuited NULL out-lengths with AB (no provider call, no
// termination). These full-stack tests (owned fresh daemons, so the
// mock call counters are race-free) prove both shapes now reach the
// backend: AB from the mock's strict Null policy + exactly one
// backend data-op call per shape.
// ---------------------------------------------------------------------------

#[cfg(not(miri))] // needs a running daemon (sockets); covered natively
mod issue3031_null_e2e {
    use super::super::output_semantics::TestDaemon;
    use super::super::*;
    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_types::shape_descriptors::{Operation, ParamAbi};
    use pkcs11_proxy_ng_types::{
        CkInBuf, CkMechanism, CkMechanismType, CkObjectHandle, CkOutputBufferSpec, CkRv,
        CkSessionFlags, CkSessionHandle, CkSlotId, MechanismRegistry, ValidatedMechanismParams,
    };

    struct FinalizeOnDrop;

    impl Drop for FinalizeOnDrop {
        fn drop(&mut self) {
            let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
        }
    }

    /// Panic-safe connect-env override (restored on drop).
    struct SavedConnectEnv {
        endpoint: Option<std::ffi::OsString>,
        socket: Option<std::ffi::OsString>,
    }

    impl SavedConnectEnv {
        fn capture() -> Self {
            Self {
                endpoint: std::env::var_os("PKCS11_PROXY_ENDPOINT"),
                socket: std::env::var_os("PKCS11_PROXY_SOCKET"),
            }
        }
    }

    impl Drop for SavedConnectEnv {
        fn drop(&mut self) {
            unsafe {
                match &self.endpoint {
                    Some(v) => std::env::set_var("PKCS11_PROXY_ENDPOINT", v),
                    None => std::env::remove_var("PKCS11_PROXY_ENDPOINT"),
                }
                match &self.socket {
                    Some(v) => std::env::set_var("PKCS11_PROXY_SOCKET", v),
                    None => std::env::remove_var("PKCS11_PROXY_SOCKET"),
                }
            }
            crate::interface_probe::clear_cache();
        }
    }

    fn rsa_pkcs_mechanism() -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism: CKM_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        }
    }

    fn sha256_mechanism() -> CK_MECHANISM {
        CK_MECHANISM { mechanism: CKM_SHA256, pParameter: std::ptr::null_mut(), ulParameterLen: 0 }
    }

    /// Open a further session + key on the first slot (the shim is
    /// already initialized by `open_session_with_key`).
    fn open_extra_session_with_key() -> (CK_SESSION_HANDLE, CK_OBJECT_HANDLE) {
        let mut slot_count: CK_ULONG = 0;
        let rv = unsafe {
            dispatch::general::c_get_slot_list(CK_FALSE, std::ptr::null_mut(), &mut slot_count)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "GetSlotList count");
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
        let mut key = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_create_object(session, std::ptr::null_mut(), 0, &mut key)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_CreateObject");
        (session, key)
    }

    /// Assert the backend observed exactly this native shape (finding
    /// 2): function identity, input pointer class + claimed length,
    /// output-buffer length, length-pointer presence. (The output
    /// buffer itself is always present in these legs.)
    fn assert_obs(
        daemon: &TestDaemon,
        name: &str,
        function: &str,
        input_null: bool,
        input_len: u64,
        out_len: u64,
        length_pointer_null: bool,
    ) {
        let obs = daemon.backend.last_data_op_observation().expect("shape must be recorded");
        assert_eq!(obs.function, function, "{name}: function identity");
        assert_eq!(obs.input_null, input_null, "{name}: input pointer class");
        assert_eq!(obs.input_len, input_len, "{name}: claimed input length");
        assert!(obs.out_buffer_present, "{name}: output buffer presence");
        assert_eq!(obs.out_buffer_len, out_len, "{name}: output buffer length");
        assert_eq!(obs.length_pointer_null, length_pointer_null, "{name}: length pointer presence");
    }

    /// Initialize against the daemon, open a session, create a key.
    fn open_session_with_key(endpoint: &str) -> (CK_SESSION_HANDLE, CK_OBJECT_HANDLE) {
        unsafe {
            std::env::set_var("PKCS11_PROXY_ENDPOINT", endpoint);
            std::env::remove_var("PKCS11_PROXY_SOCKET");
        }
        let rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_Initialize");

        let mut slot_count: CK_ULONG = 0;
        let rv = unsafe {
            dispatch::general::c_get_slot_list(CK_FALSE, std::ptr::null_mut(), &mut slot_count)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "GetSlotList count");

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

        let mut key = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_create_object(session, std::ptr::null_mut(), 0, &mut key)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_CreateObject");
        (session, key)
    }

    type DualUpdateFn = unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV;

    /// #30: NULL part + NULL out-length reach the backend on all four
    /// dual-function entrypoints. The mock's strict Null policy yields
    /// AB; the +1 call count proves the AB came from the backend, not
    /// from a reintroduced shim short-circuit or erasure — and the
    /// shape observation proves function identity, input class/length,
    /// and output-envelope presence survived intact (finding 2).
    #[test]
    fn dual_null_shapes_reach_backend_all_4_entrypoints() {
        let _guard = shim_state_test_guard();
        let _saved = SavedConnectEnv::capture();
        let daemon = TestDaemon::fresh();
        let _finalize = FinalizeOnDrop;
        let (session, _key) = open_session_with_key(&daemon.endpoint);

        let entries: [(&str, &str, DualUpdateFn); 4] = [
            (
                "DigestEncryptUpdate",
                "digest_encrypt_update",
                dispatch::general::c_digest_encrypt_update,
            ),
            (
                "DecryptDigestUpdate",
                "decrypt_digest_update",
                dispatch::general::c_decrypt_digest_update,
            ),
            ("SignEncryptUpdate", "sign_encrypt_update", dispatch::general::c_sign_encrypt_update),
            (
                "DecryptVerifyUpdate",
                "decrypt_verify_update",
                dispatch::general::c_decrypt_verify_update,
            ),
        ];
        for (name, observed, entry) in entries {
            // NULL part, nonzero length.
            let before = daemon.backend.data_op_call_count();
            let mut out = vec![0u8; 64];
            let mut out_len: CK_ULONG = 64;
            let rv =
                unsafe { entry(session, std::ptr::null_mut(), 16, out.as_mut_ptr(), &mut out_len) };
            assert_eq!(
                rv, CKR_ARGUMENTS_BAD as CK_RV,
                "{name}: null part must be AB, not erased-OK"
            );
            assert_eq!(
                daemon.backend.data_op_call_count(),
                before + 1,
                "{name}: null part must reach the backend"
            );
            assert_obs(&daemon, name, observed, true, 16, 64, false);

            // Valid part, NULL out-length.
            let before = daemon.backend.data_op_call_count();
            let part = [0x41u8; 16];
            let rv = unsafe {
                entry(session, part.as_ptr() as *mut _, 16, out.as_mut_ptr(), std::ptr::null_mut())
            };
            assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV, "{name}: null out-length must be AB");
            assert_eq!(
                daemon.backend.data_op_call_count(),
                before + 1,
                "{name}: null out-length must reach the backend (no short-circuit)"
            );
            // NULL length pointer: no capacity cell exists, so the
            // spec carries buffer_len 0 by design (`output_buffer_spec`).
            assert_obs(&daemon, name, observed, false, 16, 0, true);
        }
    }

    /// #31: NULL data + NULL out-length reach the backend on
    /// C_SignRecover (same forwarding proof as the dual entrypoints).
    /// Each shape initializes on an independent session (finding 4):
    /// the second leg must not depend on the mock retaining the op
    /// after the first malformed call.
    #[test]
    fn sign_recover_null_shapes_reach_backend() {
        let _guard = shim_state_test_guard();
        let _saved = SavedConnectEnv::capture();
        let daemon = TestDaemon::fresh();
        let _finalize = FinalizeOnDrop;
        let (session, key) = open_session_with_key(&daemon.endpoint);

        let mut mech = rsa_pkcs_mechanism();
        let rv = unsafe { dispatch::general::c_sign_recover_init(session, &mut mech, key) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_SignRecoverInit");

        // NULL data, nonzero length.
        let before = daemon.backend.data_op_call_count();
        let mut out = vec![0u8; 512];
        let mut out_len: CK_ULONG = 512;
        let rv = unsafe {
            dispatch::general::c_sign_recover(
                session,
                std::ptr::null_mut(),
                32,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV, "null data must be AB, not erased-OK");
        assert_eq!(
            daemon.backend.data_op_call_count(),
            before + 1,
            "null data must reach the backend"
        );
        assert_obs(&daemon, "SignRecover", "sign_recover", true, 32, 512, false);

        // Valid data, NULL out-length, on an independent session.
        let (session_b, key_b) = open_extra_session_with_key();
        let mut mech_b = rsa_pkcs_mechanism();
        let rv = unsafe { dispatch::general::c_sign_recover_init(session_b, &mut mech_b, key_b) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_SignRecoverInit");
        let before = daemon.backend.data_op_call_count();
        let data = [0x42u8; 32];
        let mut out_b = vec![0u8; 512];
        let rv = unsafe {
            dispatch::general::c_sign_recover(
                session_b,
                data.as_ptr() as *mut _,
                32,
                out_b.as_mut_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV, "null out-length must be AB");
        assert_eq!(
            daemon.backend.data_op_call_count(),
            before + 1,
            "null out-length must reach the backend (no short-circuit)"
        );
        // NULL length pointer: no capacity cell exists, so the
        // spec carries buffer_len 0 by design (`output_buffer_spec`).
        assert_obs(&daemon, "SignRecover", "sign_recover", false, 32, 0, true);
    }

    // --- Joint-termination oracle (finding 3) ---

    /// One dual update entrypoint for the direct leg.
    #[derive(Clone, Copy)]
    enum DualKind {
        DigestEncrypt,
        DecryptDigest,
        SignEncrypt,
        DecryptVerify,
    }

    /// One dual-leg init for both legs.
    #[derive(Clone, Copy)]
    enum InitKind {
        Digest,
        Encrypt,
        Decrypt,
        Sign,
        Verify,
    }

    /// Direct-leg validated mechanism (parameterless → validation is total).
    fn validated_direct(
        registry: &MechanismRegistry,
        abi: ParamAbi,
        mechanism_type: CkMechanismType,
    ) -> ValidatedMechanismParams {
        ValidatedMechanismParams::validate(
            &CkMechanism { mechanism_type, params: None },
            registry,
            Operation::General,
            abi,
            abi,
        )
        .expect("parameterless mechanism validates")
    }

    fn direct_update(
        backend: &MockBackend,
        kind: DualKind,
        session: CkSessionHandle,
        input: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> u64 {
        let result = match kind {
            DualKind::DigestEncrypt => backend.digest_encrypt_update_exact(session, input, spec),
            DualKind::DecryptDigest => backend.decrypt_digest_update_exact(session, input, spec),
            DualKind::SignEncrypt => backend.sign_encrypt_update_exact(session, input, spec),
            DualKind::DecryptVerify => backend.decrypt_verify_update_exact(session, input, spec),
        };
        match result {
            Ok(out) => out.ck_rv.0,
            Err(rv) => rv.0,
        }
    }

    fn direct_recover(
        backend: &MockBackend,
        session: CkSessionHandle,
        input: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> u64 {
        match backend.sign_recover_exact(session, input, spec) {
            Ok(out) => out.ck_rv.0,
            Err(rv) => rv.0,
        }
    }

    fn direct_init(
        backend: &MockBackend,
        kind: InitKind,
        session: CkSessionHandle,
        v_sha: &ValidatedMechanismParams,
        v_rsa: &ValidatedMechanismParams,
        key: CkObjectHandle,
    ) -> u64 {
        let result = match kind {
            InitKind::Digest => backend.digest_init(session, v_sha).map(|()| None),
            InitKind::Encrypt => backend.encrypt_init(session, v_rsa, key),
            InitKind::Decrypt => backend.decrypt_init(session, v_rsa, key),
            InitKind::Sign => backend.sign_init(session, v_rsa, key).map(|()| None),
            InitKind::Verify => backend.verify_init(session, v_rsa, key).map(|()| None),
        };
        match result {
            Ok(_) => CkRv::OK.0,
            Err(rv) => rv.0,
        }
    }

    /// Direct leg of the dual script: init → malformed(null part) →
    /// follow-up → reinit → well-formed → malformed(null outlen) →
    /// follow-up → reinit → well-formed. 12 RVs.
    fn direct_dual_script(
        backend: &MockBackend,
        session: CkSessionHandle,
        init_a: impl Fn() -> u64,
        init_b: impl Fn() -> u64,
        kind: DualKind,
    ) -> Vec<u64> {
        let part = [0x41u8; 16];
        let data_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 64, length_pointer_null: false };
        let null_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 64, length_pointer_null: true };
        vec![
            init_a(),
            init_b(),
            direct_update(backend, kind, session, CkInBuf::Null { len: 16 }, &data_spec),
            direct_update(backend, kind, session, CkInBuf::Bytes(&part), &data_spec),
            init_a(),
            init_b(),
            direct_update(backend, kind, session, CkInBuf::Bytes(&part), &data_spec),
            direct_update(backend, kind, session, CkInBuf::Bytes(&part), &null_spec),
            direct_update(backend, kind, session, CkInBuf::Bytes(&part), &data_spec),
            init_a(),
            init_b(),
            direct_update(backend, kind, session, CkInBuf::Bytes(&part), &data_spec),
        ]
    }

    /// Direct leg of the recover script. 10 RVs.
    fn direct_recover_script(
        backend: &MockBackend,
        session: CkSessionHandle,
        init: impl Fn() -> u64,
    ) -> Vec<u64> {
        let data = [0x42u8; 32];
        let spec = CkOutputBufferSpec {
            buffer_present: true,
            buffer_len: 512,
            length_pointer_null: false,
        };
        let null_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 512, length_pointer_null: true };
        vec![
            init(),
            direct_recover(backend, session, CkInBuf::Null { len: 32 }, &spec),
            direct_recover(backend, session, CkInBuf::Bytes(&data), &spec),
            init(),
            direct_recover(backend, session, CkInBuf::Bytes(&data), &spec),
            init(),
            direct_recover(backend, session, CkInBuf::Bytes(&data), &null_spec),
            direct_recover(backend, session, CkInBuf::Bytes(&data), &spec),
            init(),
            direct_recover(backend, session, CkInBuf::Bytes(&data), &spec),
        ]
    }

    fn proxied_init(kind: InitKind, session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> CK_RV {
        match kind {
            InitKind::Digest => {
                let mut mech = sha256_mechanism();
                unsafe { dispatch::general::c_digest_init(session, &mut mech as *mut _) }
            }
            InitKind::Encrypt => {
                let mut mech = rsa_pkcs_mechanism();
                unsafe { dispatch::general::c_encrypt_init(session, &mut mech as *mut _, key) }
            }
            InitKind::Decrypt => {
                let mut mech = rsa_pkcs_mechanism();
                unsafe { dispatch::general::c_decrypt_init(session, &mut mech as *mut _, key) }
            }
            InitKind::Sign => {
                let mut mech = rsa_pkcs_mechanism();
                unsafe { dispatch::general::c_sign_init(session, &mut mech as *mut _, key) }
            }
            InitKind::Verify => {
                let mut mech = rsa_pkcs_mechanism();
                unsafe { dispatch::general::c_verify_init(session, &mut mech as *mut _, key) }
            }
        }
    }

    fn proxied_dual_call(
        entry: DualUpdateFn,
        session: CK_SESSION_HANDLE,
        part: CK_BYTE_PTR,
        len: CK_ULONG,
        out: &mut Vec<u8>,
        out_len: Option<&mut CK_ULONG>,
    ) -> CK_RV {
        let len_ptr = out_len.map(|slot| slot as *mut _).unwrap_or(std::ptr::null_mut());
        unsafe { entry(session, part, len, out.as_mut_ptr(), len_ptr) }
    }

    /// Proxied leg of the dual script (same 12-call shape as the direct leg).
    fn proxied_dual_script(
        init_a: impl Fn() -> CK_RV,
        init_b: impl Fn() -> CK_RV,
        entry: DualUpdateFn,
        session: CK_SESSION_HANDLE,
    ) -> Vec<CK_RV> {
        let part = [0x41u8; 16];
        let mut out = vec![0u8; 64];
        let live = || part.as_ptr() as *mut _;
        let mut rvs = Vec::with_capacity(12);
        rvs.push(init_a());
        rvs.push(init_b());
        let mut len: CK_ULONG = 64;
        rvs.push(proxied_dual_call(
            entry,
            session,
            std::ptr::null_mut(),
            16,
            &mut out,
            Some(&mut len),
        ));
        let mut len: CK_ULONG = 64;
        rvs.push(proxied_dual_call(entry, session, live(), 16, &mut out, Some(&mut len)));
        rvs.push(init_a());
        rvs.push(init_b());
        let mut len: CK_ULONG = 64;
        rvs.push(proxied_dual_call(entry, session, live(), 16, &mut out, Some(&mut len)));
        rvs.push(proxied_dual_call(entry, session, live(), 16, &mut out, None));
        let mut len: CK_ULONG = 64;
        rvs.push(proxied_dual_call(entry, session, live(), 16, &mut out, Some(&mut len)));
        rvs.push(init_a());
        rvs.push(init_b());
        let mut len: CK_ULONG = 64;
        rvs.push(proxied_dual_call(entry, session, live(), 16, &mut out, Some(&mut len)));
        rvs
    }

    fn proxied_recover_call(
        session: CK_SESSION_HANDLE,
        data: CK_BYTE_PTR,
        len: CK_ULONG,
        out: &mut Vec<u8>,
        out_len: Option<&mut CK_ULONG>,
    ) -> CK_RV {
        let len_ptr = out_len.map(|slot| slot as *mut _).unwrap_or(std::ptr::null_mut());
        unsafe { dispatch::general::c_sign_recover(session, data, len, out.as_mut_ptr(), len_ptr) }
    }

    /// Proxied leg of the recover script (same 10-call shape as the direct leg).
    fn proxied_recover_script(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> Vec<CK_RV> {
        let init = || {
            let mut mech = rsa_pkcs_mechanism();
            unsafe { dispatch::general::c_sign_recover_init(session, &mut mech, key) }
        };
        let data = [0x42u8; 32];
        let mut out = vec![0u8; 512];
        let live = || data.as_ptr() as *mut _;
        let mut rvs = Vec::with_capacity(10);
        rvs.push(init());
        let mut len: CK_ULONG = 512;
        rvs.push(proxied_recover_call(session, std::ptr::null_mut(), 32, &mut out, Some(&mut len)));
        let mut len: CK_ULONG = 512;
        rvs.push(proxied_recover_call(session, live(), 32, &mut out, Some(&mut len)));
        rvs.push(init());
        let mut len: CK_ULONG = 512;
        rvs.push(proxied_recover_call(session, live(), 32, &mut out, Some(&mut len)));
        rvs.push(init());
        rvs.push(proxied_recover_call(session, live(), 32, &mut out, None));
        let mut len: CK_ULONG = 512;
        rvs.push(proxied_recover_call(session, live(), 32, &mut out, Some(&mut len)));
        rvs.push(init());
        let mut len: CK_ULONG = 512;
        rvs.push(proxied_recover_call(session, live(), 32, &mut out, Some(&mut len)));
        rvs
    }

    /// #30/#31 joint-termination oracle (finding 3): with the mock in
    /// terminating-provider mode, the full init → malformed →
    /// follow-up → reinit sequence for every dual entrypoint plus
    /// C_SignRecover must produce identical RV sequences with and
    /// without the proxy in the middle — and both must equal the
    /// pinned terminating-provider script (AB, CNI follow-up, clean
    /// reinit; never a retained op, never a wedged 0x90).
    #[test]
    #[allow(clippy::unnecessary_cast)] // `as u64` is load-bearing on 32-bit CK_ULONG targets
    fn terminating_dual_and_recover_direct_matches_proxied() {
        const OK: u64 = CKR_OK as u64;
        const AB: u64 = CKR_ARGUMENTS_BAD as u64;
        const CNI: u64 = CKR_OPERATION_NOT_INITIALIZED as u64;
        let expected_dual = vec![OK, OK, AB, CNI, OK, OK, OK, AB, CNI, OK, OK, OK];
        let expected_recover = vec![OK, AB, CNI, OK, OK, OK, AB, CNI, OK, OK];

        // Proxied leg: full stack through an owned daemon in
        // terminating mode; one session per script for isolation.
        let _guard = shim_state_test_guard();
        let _saved = SavedConnectEnv::capture();
        let daemon = TestDaemon::fresh();
        daemon.backend.set_terminating_dual_mode(true);
        let _finalize = FinalizeOnDrop;
        let _first = open_session_with_key(&daemon.endpoint);

        // Direct leg: the same provider model with no proxy.
        let direct = MockBackend::default_test();
        direct.initialize().unwrap();
        direct.set_terminating_dual_mode(true);
        let registry = MechanismRegistry::load(None).expect("embedded registry loads");
        let abi = ParamAbi::native().expect("little-endian test host");
        let v_sha = validated_direct(&registry, abi, CkMechanismType::SHA256);
        let v_rsa = validated_direct(&registry, abi, CkMechanismType::RSA_PKCS);

        let duals = [
            (
                "DigestEncryptUpdate",
                DualKind::DigestEncrypt,
                dispatch::general::c_digest_encrypt_update as DualUpdateFn,
                InitKind::Digest,
                InitKind::Encrypt,
            ),
            (
                "DecryptDigestUpdate",
                DualKind::DecryptDigest,
                dispatch::general::c_decrypt_digest_update as DualUpdateFn,
                InitKind::Decrypt,
                InitKind::Digest,
            ),
            (
                "SignEncryptUpdate",
                DualKind::SignEncrypt,
                dispatch::general::c_sign_encrypt_update as DualUpdateFn,
                InitKind::Sign,
                InitKind::Encrypt,
            ),
            (
                "DecryptVerifyUpdate",
                DualKind::DecryptVerify,
                dispatch::general::c_decrypt_verify_update as DualUpdateFn,
                InitKind::Decrypt,
                InitKind::Verify,
            ),
        ];
        for (name, kind, entry, init_a_kind, init_b_kind) in duals {
            let (session, key) = open_extra_session_with_key();
            let proxied: Vec<u64> = proxied_dual_script(
                || proxied_init(init_a_kind, session, key),
                || proxied_init(init_b_kind, session, key),
                entry,
                session,
            )
            .into_iter()
            .map(|rv| rv as u64)
            .collect();
            assert_eq!(proxied, expected_dual, "{name}: proxied sequence");

            let dsession = direct.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let dkey = direct.create_object(dsession, None).unwrap();
            let got = direct_dual_script(
                &direct,
                dsession,
                || direct_init(&direct, init_a_kind, dsession, &v_sha, &v_rsa, dkey),
                || direct_init(&direct, init_b_kind, dsession, &v_sha, &v_rsa, dkey),
                kind,
            );
            assert_eq!(got, expected_dual, "{name}: direct sequence");
        }

        // Recover script on its own session in both legs.
        let (session, key) = open_extra_session_with_key();
        let proxied: Vec<u64> =
            proxied_recover_script(session, key).into_iter().map(|rv| rv as u64).collect();
        assert_eq!(proxied, expected_recover, "SignRecover: proxied sequence");

        let dsession = direct.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let dkey = direct.create_object(dsession, None).unwrap();
        let got = direct_recover_script(&direct, dsession, || {
            match direct.sign_recover_init(dsession, &v_rsa, dkey) {
                Ok(()) => CkRv::OK.0,
                Err(rv) => rv.0,
            }
        });
        assert_eq!(got, expected_recover, "SignRecover: direct sequence");
    }
}

// ---------------------------------------------------------------------------
// #26: read-after-destroy must preserve the caller buffer.
//
// At a48b60b the daemon attached its zero-filled buffer as the attribute
// "value" regardless of RV and the shim wrote it, so a 0x82 error zeroed
// the caller's 64-byte canary. Full-stack pin: RV 0x82, length intact,
// every canary byte untouched. This leg exercises the daemon's
// resolve/tombstone rejection (no backend contact); the backend-`Err`
// arm is pinned server-side by `exact_backend_error_*`. Controlled
// fixture: PKCS#11 permits host-memory modification on failure
// (OASIS §5/§5.7.5), so this pins the proxy's no-value writeback,
// not a universal provider guarantee.
// ---------------------------------------------------------------------------

#[cfg(not(miri))] // needs a running daemon (sockets); covered natively
mod issue26_read_after_destroy {
    use super::super::output_semantics::TestDaemon;
    use super::super::*;

    struct FinalizeOnDrop;

    impl Drop for FinalizeOnDrop {
        fn drop(&mut self) {
            let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
        }
    }

    /// Panic-safe connect-env override (restored on drop).
    struct SavedConnectEnv {
        endpoint: Option<std::ffi::OsString>,
        socket: Option<std::ffi::OsString>,
    }

    impl SavedConnectEnv {
        fn capture() -> Self {
            Self {
                endpoint: std::env::var_os("PKCS11_PROXY_ENDPOINT"),
                socket: std::env::var_os("PKCS11_PROXY_SOCKET"),
            }
        }
    }

    impl Drop for SavedConnectEnv {
        fn drop(&mut self) {
            unsafe {
                match &self.endpoint {
                    Some(v) => std::env::set_var("PKCS11_PROXY_ENDPOINT", v),
                    None => std::env::remove_var("PKCS11_PROXY_ENDPOINT"),
                }
                match &self.socket {
                    Some(v) => std::env::set_var("PKCS11_PROXY_SOCKET", v),
                    None => std::env::remove_var("PKCS11_PROXY_SOCKET"),
                }
            }
            crate::interface_probe::clear_cache();
        }
    }

    /// Initialize against the daemon, open a session, create a key.
    fn open_session_with_key(endpoint: &str) -> (CK_SESSION_HANDLE, CK_OBJECT_HANDLE) {
        unsafe {
            std::env::set_var("PKCS11_PROXY_ENDPOINT", endpoint);
            std::env::remove_var("PKCS11_PROXY_SOCKET");
        }
        let rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_Initialize");

        let mut slot_count: CK_ULONG = 0;
        let rv = unsafe {
            dispatch::general::c_get_slot_list(CK_FALSE, std::ptr::null_mut(), &mut slot_count)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "GetSlotList count");

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

        let mut key = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_create_object(session, std::ptr::null_mut(), 0, &mut key)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_CreateObject");
        (session, key)
    }

    #[test]
    fn read_after_destroy_preserves_canary() {
        let _guard = shim_state_test_guard();
        let _saved = SavedConnectEnv::capture();
        let daemon = TestDaemon::fresh();
        let _finalize = FinalizeOnDrop;
        let (session, key) = open_session_with_key(&daemon.endpoint);

        let rv = unsafe { dispatch::general::c_destroy_object(session, key) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_DestroyObject");

        let mut canary = [0xA5u8; 64];
        let mut attr =
            CK_ATTRIBUTE { type_: CKA_VALUE, pValue: canary.as_mut_ptr().cast(), ulValueLen: 64 };
        let exact_calls_before = daemon.backend.attr_get_exact_call_count();
        let rv = unsafe { dispatch::general::c_get_attribute_value(session, key, &mut attr, 1) };
        assert_eq!(rv, CKR_OBJECT_HANDLE_INVALID as CK_RV, "read-after-destroy RV");
        assert_eq!(canary, [0xA5u8; 64], "canary must survive the 0x82 error");
        assert_eq!(attr.ulValueLen, 64, "length stays 64 (preset, never clobbered)");
        assert_eq!(
            daemon.backend.attr_get_exact_call_count(),
            exact_calls_before,
            "resolve/tombstone rejection must not contact the backend"
        );
    }
}

// ---------------------------------------------------------------------------
// #32: a post-restart stale handle must fault 0x82, not resolve.
//
// At a48b60b the daemon resolved a handle kept across the client's
// Finalize/Init cycle against its live durable store (0x150 BTS into
// the 64-byte buffer); direct returns 0x82. HEAD scopes virtual
// mappings to the client context, so the stale handle is unknown to
// the new context and faults. The object itself stays present
// backend-side (live_object_count() == 1 on the fresh daemon).
// ---------------------------------------------------------------------------

#[cfg(not(miri))] // needs a running daemon (sockets); covered natively
mod issue32_stale_handle {
    use super::super::output_semantics::TestDaemon;
    use super::super::*;

    struct FinalizeOnDrop;

    impl Drop for FinalizeOnDrop {
        fn drop(&mut self) {
            let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
        }
    }

    struct SavedConnectEnv {
        endpoint: Option<std::ffi::OsString>,
        socket: Option<std::ffi::OsString>,
    }

    impl SavedConnectEnv {
        fn capture() -> Self {
            Self {
                endpoint: std::env::var_os("PKCS11_PROXY_ENDPOINT"),
                socket: std::env::var_os("PKCS11_PROXY_SOCKET"),
            }
        }
    }

    impl Drop for SavedConnectEnv {
        fn drop(&mut self) {
            unsafe {
                match &self.endpoint {
                    Some(v) => std::env::set_var("PKCS11_PROXY_ENDPOINT", v),
                    None => std::env::remove_var("PKCS11_PROXY_ENDPOINT"),
                }
                match &self.socket {
                    Some(v) => std::env::set_var("PKCS11_PROXY_SOCKET", v),
                    None => std::env::remove_var("PKCS11_PROXY_SOCKET"),
                }
            }
            crate::interface_probe::clear_cache();
        }
    }

    fn initialize(endpoint: &str) {
        unsafe {
            std::env::set_var("PKCS11_PROXY_ENDPOINT", endpoint);
            std::env::remove_var("PKCS11_PROXY_SOCKET");
        }
        let rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_Initialize");
    }

    fn open_session() -> CK_SESSION_HANDLE {
        let mut slot_count: CK_ULONG = 0;
        let rv = unsafe {
            dispatch::general::c_get_slot_list(CK_FALSE, std::ptr::null_mut(), &mut slot_count)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "GetSlotList count");
        let mut slots = vec![0 as CK_SLOT_ID; slot_count as usize];
        let rv = unsafe {
            dispatch::general::c_get_slot_list(CK_FALSE, slots.as_mut_ptr(), &mut slot_count)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "GetSlotList data");
        let mut session = CK_INVALID_HANDLE;
        // RW session: PKCS#11 §5.7.1 requires read/write for token-object
        // creation (the mock is lenient, but the repro must be spec-shaped).
        let rv = unsafe {
            dispatch::general::c_open_session(
                slots[0],
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                std::ptr::null_mut(),
                None,
                &mut session,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_OpenSession");
        session
    }

    #[test]
    fn stale_handle_across_restart_faults_object_invalid() {
        let _guard = shim_state_test_guard();
        let _saved = SavedConnectEnv::capture();
        let daemon = TestDaemon::fresh();
        let _finalize = FinalizeOnDrop;

        // Epoch 1: create a durable token object (the issue's sqlite
        // shape: token object with a 746-byte value), keep its handle.
        initialize(&daemon.endpoint);
        let session1 = open_session();
        let mut class: CK_ULONG = CKO_DATA;
        let mut token_flag: CK_BBOOL = CK_TRUE;
        let mut value = [0x42u8; 746];
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: (&mut class as *mut CK_ULONG).cast(),
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: (&mut token_flag as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
            CK_ATTRIBUTE { type_: CKA_VALUE, pValue: value.as_mut_ptr().cast(), ulValueLen: 746 },
        ];
        let mut stale = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_create_object(
                session1,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut stale,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_CreateObject");
        let rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_Finalize epoch 1");

        // Epoch 2: fresh session, stale object handle.
        initialize(&daemon.endpoint);
        let session2 = open_session();
        let mut canary = [0xA5u8; 64];
        let mut attr =
            CK_ATTRIBUTE { type_: CKA_VALUE, pValue: canary.as_mut_ptr().cast(), ulValueLen: 64 };
        let rv = unsafe { dispatch::general::c_get_attribute_value(session2, stale, &mut attr, 1) };
        assert_eq!(rv, CKR_OBJECT_HANDLE_INVALID as CK_RV, "stale handle must fault 0x82");
        assert_eq!(canary, [0xA5u8; 64], "canary must survive the 0x82 error");
        assert_eq!(attr.ulValueLen, 64, "length stays 64 (preset, never clobbered)");

        // The object itself is still present backend-side (the mock
        // find is override-scripted and cannot enumerate, so probe the
        // live set directly): only the stale handle faults.
        assert_eq!(
            daemon.backend.live_object_count(),
            1,
            "durable object must survive the client restart"
        );
    }

    // Issue #27, closed as by-design: a memory-store token object
    // created through the proxy survives the client's C_Finalize +
    // C_Initialize cycle, while direct Finalize drops the memory
    // store. Logical Finalize removes only the client context
    // (sessions + best-effort last-holder logout); no native provider
    // C_Finalize runs on the client path (native retirement happens
    // only at daemon shutdown) and backend objects are never
    // enumerated or destroyed, so both memory and SQLite token
    // objects persist for the daemon's lifetime. Per-client teardown
    // is a v0.3 multi-tenancy question, not a v0.2 defect. Locks the
    // survival; the RED probe asserting the reporter's literal 0-match
    // expectation fails with count 1 (verified 2026-10-05).
    #[test]
    fn memory_token_object_survives_client_restart_by_design() {
        let _guard = shim_state_test_guard();
        let _saved = SavedConnectEnv::capture();
        let daemon = TestDaemon::fresh();
        let _finalize = FinalizeOnDrop;

        // Epoch 1: create a memory-store token object.
        initialize(&daemon.endpoint);
        let session1 = open_session();
        let mut class: CK_ULONG = CKO_DATA;
        let mut token_flag: CK_BBOOL = CK_TRUE;
        let mut label = *b"restart-token";
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: (&mut class as *mut CK_ULONG).cast(),
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: (&mut token_flag as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: label.as_mut_ptr().cast(),
                ulValueLen: label.len() as CK_ULONG,
            },
        ];
        let mut handle = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_create_object(
                session1,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut handle,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_CreateObject");
        assert_eq!(daemon.backend.live_object_count(), 1, "setup: object exists");
        let rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_Finalize epoch 1");

        // Epoch 2: by-design survival — the object is still there.
        // (The mock find is override-scripted and cannot enumerate, so
        // probe the live set directly, as the stale-handle test above.)
        initialize(&daemon.endpoint);
        let _session2 = open_session();
        assert_eq!(
            daemon.backend.live_object_count(),
            1,
            "memory token object must survive the client restart (by design, #27)"
        );
    }
}

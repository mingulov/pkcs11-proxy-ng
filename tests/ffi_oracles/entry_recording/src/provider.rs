//! Minimal entry-recording PKCS#11 provider for Q07 shape evidence.
use super::*;
use std::sync::LazyLock;

pub unsafe extern "C" fn initialize(_: CK_VOID_PTR) -> CK_RV {
    lock_state().2.initialized = true;
    CKR_OK
}

pub unsafe extern "C" fn finalize(_: CK_VOID_PTR) -> CK_RV {
    let mut state = lock_state();
    state.2.initialized = false;
    CKR_OK
}

pub unsafe extern "C" fn open_session(
    _: CK_SLOT_ID,
    _: CK_FLAGS,
    _: CK_VOID_PTR,
    _: CK_NOTIFY,
    session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut state = lock_state();
    let handle = state.2.next_session;
    state.2.next_session += 1;
    // Width-generic: the native handle is 32-bit on narrow hosts.
    unsafe { session.write(handle as cryptoki_sys::CK_SESSION_HANDLE) };
    CKR_OK
}

pub unsafe extern "C" fn close_session(_: CK_SESSION_HANDLE) -> CK_RV {
    CKR_OK
}

/// Single synthetic slot so daemon slot population succeeds. Fixture
/// simplification: the slot is always reported present, and a non-null
/// buffer is filled unconditionally (real daemons query-then-fill).
pub unsafe extern "C" fn get_slot_list(
    _: CK_BBOOL,
    slot_list: CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        if slot_list.is_null() {
            count.write(1);
        } else {
            slot_list.write(1);
            count.write(1);
        }
    }
    CKR_OK
}

/// Canned object creation: the controls never use the key for real
/// cryptography, so every creation mints the next canned handle.
pub unsafe extern "C" fn create(
    _: CK_SESSION_HANDLE,
    _: CK_ATTRIBUTE_PTR,
    _: CK_ULONG,
    out: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if out.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut state = lock_state();
    let handle = state.2.next_object;
    state.2.next_object += 1;
    unsafe { out.write(handle as cryptoki_sys::CK_OBJECT_HANDLE) };
    CKR_OK
}

pub unsafe extern "C" fn destroy(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE) -> CK_RV {
    CKR_OK
}

/// The recorded entry: count it, snapshot the mechanism header, then return
/// the scenario RV verbatim — success or error alike.
pub unsafe extern "C" fn encrypt_init(
    _: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut state = lock_state();
    state.1.encrypt_init_calls += 1;
    state.1.init_mech_type = unsafe { (*mechanism).mechanism } as u64;
    state.1.init_param_len = unsafe { (*mechanism).ulParameterLen } as u64;
    state.0.init_rv as CK_RV
}

/// Canned slot info for the synthetic slot. Fixture simplification: fixed
/// description, token present.
pub unsafe extern "C" fn get_slot_info(_: CK_SLOT_ID, info: CK_SLOT_INFO_PTR) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let slot = CK_SLOT_INFO { flags: CKF_TOKEN_PRESENT, ..Default::default() };
        info.write(slot);
    }
    CKR_OK
}

/// Canned token info for the synthetic slot so discovery succeeds. Fixed
/// label/serial, initialized token.
pub unsafe extern "C" fn get_token_info(_: CK_SLOT_ID, info: CK_TOKEN_INFO_PTR) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let mut token = CK_TOKEN_INFO::default();
        let label = b"oracle-test-token";
        token.label[..label.len()].copy_from_slice(label);
        let serial = b"0001";
        token.serialNumber[..serial.len()].copy_from_slice(serial);
        token.flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;
        info.write(token);
    }
    CKR_OK
}

fn table() -> CK_FUNCTION_LIST {
    CK_FUNCTION_LIST {
        version: CK_VERSION { major: 2, minor: 40 },
        C_Initialize: Some(initialize),
        C_Finalize: Some(finalize),
        C_GetSlotInfo: Some(get_slot_info),
        C_GetTokenInfo: Some(get_token_info),
        C_OpenSession: Some(open_session),
        C_CloseSession: Some(close_session),
        C_GetSlotList: Some(get_slot_list),
        C_CreateObject: Some(create),
        C_DestroyObject: Some(destroy),
        C_EncryptInit: Some(encrypt_init),
        ..Default::default()
    }
}

static TABLE: LazyLock<CK_FUNCTION_LIST> = LazyLock::new(table);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(out: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if out.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe { out.write((&*TABLE as *const CK_FUNCTION_LIST).cast_mut()) };
    CKR_OK
}

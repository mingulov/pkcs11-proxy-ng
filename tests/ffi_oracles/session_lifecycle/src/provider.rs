//! Actual native entries below the production FFI backend.
use super::*;
use cryptoki_sys::*;

pub unsafe extern "C" fn initialize(_: CK_VOID_PTR) -> CK_RV {
    let mut state = state();
    if state.initialized {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    state.initialized = true;
    CKR_OK
}

pub unsafe extern "C" fn finalize(_: CK_VOID_PTR) -> CK_RV {
    let mut state = state();
    if !state.pending.is_empty() || state.sessions.iter().any(|s| s.live != 0) {
        return CKR_SESSION_EXISTS;
    }
    state.initialized = false;
    state.logged_in = false;
    CKR_OK
}

pub unsafe extern "C" fn open_session(
    slot: CK_SLOT_ID,
    flags: CK_FLAGS,
    _: CK_VOID_PTR,
    _: CK_NOTIFY,
    output: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if output.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if slot != 1 {
        return CKR_SLOT_ID_INVALID;
    }
    let mut state = state();
    if !state.initialized {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if state.sessions.len() == MAX_SESSIONS {
        return CKR_SESSION_COUNT;
    }
    let raw = match state.next_reuse.take() {
        Some(raw) => raw,
        None => {
            let raw = state.next_raw;
            state.next_raw += 1;
            raw
        }
    };
    let incarnation = state.next_incarnation;
    state.next_incarnation += 1;
    state.sessions.push(SessionV1 { raw, incarnation, flags: flags as u64, live: 1, reserved: 0 });
    state.record(OPEN, COMPLETED, raw, CKR_OK as u64, flags as u64);
    unsafe { output.write(raw as CK_SESSION_HANDLE) };
    CKR_OK
}

pub unsafe extern "C" fn close_session(session: CK_SESSION_HANDLE) -> CK_RV {
    let raw = session as u64;
    let mut state = state();
    state.record(CLOSE, ENTRY, raw, 0, 0);
    let rv = if !state.initialized {
        CKR_CRYPTOKI_NOT_INITIALIZED as u64
    } else if state.live(raw).is_none() {
        CKR_SESSION_HANDLE_INVALID as u64
    } else if let Some(index) = state.close_rvs.iter().position(|(handle, _)| *handle == raw) {
        state.close_rvs.remove(index).1
    } else {
        CKR_OK as u64
    };
    state.pending.push(raw);
    if state.gate_session == raw {
        state.gate_holders += 1;
        while state.gate_session == raw {
            // Condvar releases the only state lock: native observers and release stay live.
            state = RELEASED.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        state.gate_holders -= 1;
    }
    if (rv == CKR_OK as u64
        || rv == CKR_SESSION_HANDLE_INVALID as u64
        || rv == CKR_SESSION_CLOSED as u64)
        && let Some(session) = state.sessions.iter_mut().rev().find(|s| s.raw == raw && s.live == 1)
    {
        session.live = 0;
    }
    if let Some(index) = state.pending.iter().position(|handle| *handle == raw) {
        state.pending.remove(index);
    }
    state.record(CLOSE, COMPLETED, raw, rv, 0);
    rv as CK_RV
}

pub unsafe extern "C" fn get_session_info(
    session: CK_SESSION_HANDLE,
    info: CK_SESSION_INFO_PTR,
) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut state = state();
    let native = state.live(session as u64);
    let rv = if native.is_some() { CKR_OK } else { CKR_SESSION_HANDLE_INVALID };
    if let Some(native) = native {
        let rw = native.flags & CKF_RW_SESSION as u64 != 0;
        let session_state = match (rw, state.logged_in) {
            (true, true) => CKS_RW_USER_FUNCTIONS,
            (true, false) => CKS_RW_PUBLIC_SESSION,
            (false, true) => CKS_RO_USER_FUNCTIONS,
            (false, false) => CKS_RO_PUBLIC_SESSION,
        };
        unsafe {
            info.write(CK_SESSION_INFO {
                slotID: 1,
                state: session_state,
                flags: native.flags as CK_FLAGS,
                ulDeviceError: 0,
            })
        };
    }
    state.record(INFO, COMPLETED, session as u64, rv as u64, 0);
    rv
}

pub unsafe extern "C" fn login(
    session: CK_SESSION_HANDLE,
    user: CK_USER_TYPE,
    pin: CK_UTF8CHAR_PTR,
    length: CK_ULONG,
) -> CK_RV {
    let correct = b"correct-oracle-pin";
    let accepted = !pin.is_null()
        && length as usize == correct.len()
        && unsafe { std::slice::from_raw_parts(pin, correct.len()) } == correct;
    let mut state = state();
    let rv = if state.live(session as u64).is_none() {
        CKR_SESSION_HANDLE_INVALID
    } else if user != CKU_USER {
        CKR_USER_TYPE_INVALID
    } else if !accepted {
        CKR_PIN_INCORRECT
    } else if state.logged_in {
        CKR_USER_ALREADY_LOGGED_IN
    } else {
        state.logged_in = true;
        CKR_OK
    };
    state.record(LOGIN, COMPLETED, session as u64, rv as u64, 0);
    rv
}

pub unsafe extern "C" fn logout(session: CK_SESSION_HANDLE) -> CK_RV {
    let mut state = state();
    let rv = if state.live(session as u64).is_none() {
        CKR_SESSION_HANDLE_INVALID
    } else if !state.logged_in {
        CKR_USER_NOT_LOGGED_IN
    } else {
        state.logged_in = false;
        CKR_OK
    };
    state.record(LOGOUT, COMPLETED, session as u64, rv as u64, 0);
    rv
}

pub unsafe extern "C" fn generate_random(
    session: CK_SESSION_HANDLE,
    output: CK_BYTE_PTR,
    length: CK_ULONG,
) -> CK_RV {
    let mut state = state();
    let native = state.live(session as u64);
    let rv = if native.is_none() {
        CKR_SESSION_HANDLE_INVALID as u64
    } else if length > 32 || (length != 0 && output.is_null()) {
        CKR_ARGUMENTS_BAD as u64
    } else {
        state.random_rv.take().unwrap_or(CKR_OK as u64)
    };
    if rv == CKR_OK as u64 && length != 0 {
        unsafe {
            std::ptr::write_bytes(
                output,
                native.map_or(0, |s| s.incarnation) as u8,
                length as usize,
            )
        };
    }
    state.record(RANDOM, COMPLETED, session as u64, rv, length as u64);
    rv as CK_RV
}

unsafe extern "C" fn close_all(slot: CK_SLOT_ID) -> CK_RV {
    state().record(CLOSE_ALL, COMPLETED, slot as u64, CKR_FUNCTION_NOT_SUPPORTED as u64, 0);
    CKR_FUNCTION_NOT_SUPPORTED
}
unsafe extern "C" fn get_slot_list(
    _: CK_BBOOL,
    slots: CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        if !slots.is_null() {
            if *count < 1 {
                *count = 1;
                return CKR_BUFFER_TOO_SMALL;
            }
            slots.write(1);
        }
        count.write(1);
    }
    CKR_OK
}
unsafe extern "C" fn get_slot_info(slot: CK_SLOT_ID, output: CK_SLOT_INFO_PTR) -> CK_RV {
    if slot != 1 {
        return CKR_SLOT_ID_INVALID;
    }
    if output.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe { output.write(CK_SLOT_INFO { flags: CKF_TOKEN_PRESENT, ..Default::default() }) };
    CKR_OK
}
unsafe extern "C" fn get_token_info(slot: CK_SLOT_ID, output: CK_TOKEN_INFO_PTR) -> CK_RV {
    if slot != 1 {
        return CKR_SLOT_ID_INVALID;
    }
    if output.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut info = CK_TOKEN_INFO::default();
    info.label.fill(b' ');
    info.label[..14].copy_from_slice(b"session-oracle");
    info.serialNumber.fill(b' ');
    info.serialNumber[..4].copy_from_slice(b"0001");
    info.flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;
    unsafe { output.write(info) };
    CKR_OK
}
unsafe extern "C" fn get_info(output: CK_INFO_PTR) -> CK_RV {
    if output.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        output.write(CK_INFO {
            cryptokiVersion: CK_VERSION { major: 2, minor: 40 },
            ..Default::default()
        })
    };
    CKR_OK
}

static TABLE: LazyLock<CK_FUNCTION_LIST> = LazyLock::new(|| CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 40 },
    C_Initialize: Some(initialize),
    C_Finalize: Some(finalize),
    C_GetInfo: Some(get_info),
    C_GetSlotList: Some(get_slot_list),
    C_GetSlotInfo: Some(get_slot_info),
    C_GetTokenInfo: Some(get_token_info),
    C_OpenSession: Some(open_session),
    C_CloseSession: Some(close_session),
    C_CloseAllSessions: Some(close_all),
    C_GetSessionInfo: Some(get_session_info),
    C_Login: Some(login),
    C_Logout: Some(logout),
    C_GenerateRandom: Some(generate_random),
    ..Default::default()
});

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(output: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if output.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe { output.write((&*TABLE as *const CK_FUNCTION_LIST).cast_mut()) };
    CKR_OK
}

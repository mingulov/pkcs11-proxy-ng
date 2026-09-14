//! Minimal deliberately retaining PKCS#11 provider for ownership tests.
use super::*;
use std::sync::LazyLock;

/// Fixed output canary. Never secret material, never caller data.
const CANARY: [u8; 16] = [0xC3; 16];

pub unsafe extern "C" fn initialize(_: CK_VOID_PTR) -> CK_RV {
    lock_state().2.initialized = true;
    CKR_OK
}

pub unsafe extern "C" fn finalize(_: CK_VOID_PTR) -> CK_RV {
    let mut state = lock_state();
    state.2.initialized = false;
    state.2.retained_mech = 0;
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

pub unsafe extern "C" fn encrypt_init(
    _: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // Deliberate retention: keep the caller's root address (and nothing
    // else) for the later operation, like backends that store the pointer
    // instead of copying the parameters.
    let mut state = lock_state();
    state.1.init_calls += 1;
    state.1.init_mech_ptr = mechanism as u64;
    state.1.init_param_len = unsafe { (*mechanism).ulParameterLen } as u64;
    state.2.retained_mech = mechanism as u64;
    CKR_OK
}

pub unsafe extern "C" fn encrypt(
    _: CK_SESSION_HANDLE,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    out: CK_BYTE_PTR,
    length: CK_ULONG_PTR,
) -> CK_RV {
    if length.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    {
        let mut state = lock_state();
        state.1.encrypt_calls += 1;
    }
    // Observable barrier before the retained-root readback. The STATE lock
    // is not held across the wait, so observers stay live while held.
    wait_at_gate(RETAINED_OP_ENCRYPT);
    let mut state = lock_state();
    let scenario = state.0;
    // Use the retained Init root: re-read the parameter extent and the
    // mechanism type through it. The backend must keep this allocation
    // alive across the two native entries.
    let retained = state.2.retained_mech as CK_MECHANISM_PTR;
    if !retained.is_null() {
        state.1.encrypt_mech_ptr = retained as u64;
        state.1.encrypt_param_len = unsafe { (*retained).ulParameterLen } as u64;
        state.1.encrypt_mech_type = unsafe { (*retained).mechanism } as u64;
    }
    state.1.ptr_equal =
        u32::from(state.1.init_mech_ptr != 0 && state.1.init_mech_ptr == state.1.encrypt_mech_ptr);
    let total = scenario.output_len;
    if out.is_null() {
        unsafe { length.write(total as CK_ULONG) };
        return scenario.encrypt_rv as CK_RV;
    }
    let capacity = unsafe { length.read() } as u64;
    let fill = total.min(capacity).min(CANARY.len() as u64) as usize;
    unsafe { std::ptr::copy_nonoverlapping(CANARY.as_ptr(), out, fill) };
    unsafe { length.write(fill as CK_ULONG) };
    scenario.encrypt_rv as CK_RV
}

fn table() -> CK_FUNCTION_LIST {
    CK_FUNCTION_LIST {
        version: CK_VERSION { major: 2, minor: 40 },
        C_Initialize: Some(initialize),
        C_Finalize: Some(finalize),
        C_OpenSession: Some(open_session),
        C_CloseSession: Some(close_session),
        C_EncryptInit: Some(encrypt_init),
        C_Encrypt: Some(encrypt),
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

//! Minimal deliberately retaining PKCS#11 provider for ownership tests.
use super::*;
use std::sync::LazyLock;

/// Fixed output canary. Never secret material, never caller data.
const CANARY: [u8; 16] = [0xC3; 16];

/// Test-only environment override for one scenario field: an
/// out-of-process runner steers the daemon-resident oracle this way
/// because loading the module again in-test must not reach its state.
/// Absent or unparsable values keep the current scenario.
fn env_scenario_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.parse().ok()
}

pub unsafe extern "C" fn initialize(_: CK_VOID_PTR) -> CK_RV {
    {
        let mut state = lock_state();
        state.2.initialized = true;
        if let Some(v) = env_scenario_u64("RETAINED_ORACLE_OUTPUT_LEN") {
            state.0.output_len = v;
        }
        if let Some(v) = env_scenario_u64("RETAINED_ORACLE_ENCRYPT_RV") {
            state.0.encrypt_rv = v;
        }
        if let Some(v) = env_scenario_u64("RETAINED_ORACLE_FAIL_UNLESS_PTR_EQUAL") {
            state.0.fail_unless_ptr_equal = v;
        }
    }
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
    //
    // The integer-to-pointer cast is deliberate exposed provenance: it
    // emulates what a real retaining C provider does with a stored
    // address (Miri flags the cast with a notice for this reason). The
    // provenance-clean party must be the backend under test, not this
    // oracle.
    let retained = state.2.retained_mech as CK_MECHANISM_PTR;
    if !retained.is_null() {
        state.1.encrypt_mech_ptr = retained as u64;
        state.1.encrypt_param_len = unsafe { (*retained).ulParameterLen } as u64;
        state.1.encrypt_mech_type = unsafe { (*retained).mechanism } as u64;
    }
    state.1.ptr_equal =
        u32::from(state.1.init_mech_ptr != 0 && state.1.init_mech_ptr == state.1.encrypt_mech_ptr);
    // Row-12 E2E retention proof: when armed, a mismatched root fails
    // closed here instead of returning the scenario RV. Applies to size
    // queries and fills alike.
    if scenario.fail_unless_ptr_equal != 0 && state.1.ptr_equal == 0 {
        return CKR_DEVICE_ERROR;
    }
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

/// Canned slot info for the synthetic slot. Fixture simplification: fixed
/// description, token present.
pub unsafe extern "C" fn get_slot_info(_: CK_SLOT_ID, info: CK_SLOT_INFO_PTR) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let mut slot = CK_SLOT_INFO::default();
        slot.flags = CKF_TOKEN_PRESENT;
        info.write(slot);
    }
    CKR_OK
}

/// Canned token info for the synthetic slot so daemon authorization and
/// discovery succeed. Fixed label/serial, initialized token.
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

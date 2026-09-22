//! Minimal deterministic PKCS#11 provider for loaded-shim contract tests.
use super::*;
use std::sync::{
    LazyLock,
    atomic::{AtomicU64, Ordering},
};

static MECHANISM: AtomicU64 = AtomicU64::new(CKM_AES_GCM as u64);
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

unsafe extern "C" fn initialize(_: CK_VOID_PTR) -> CK_RV {
    CKR_OK
}
unsafe extern "C" fn close(_: CK_SESSION_HANDLE) -> CK_RV {
    CKR_OK
}
unsafe extern "C" fn info(out: CK_INFO_PTR) -> CK_RV {
    if out.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let info = CK_INFO {
        cryptokiVersion: CK_VERSION { major: 3, minor: 2 },
        manufacturerID: [b' '; 32],
        libraryDescription: [b' '; 32],
        ..Default::default()
    };
    unsafe { out.write(info) };
    CKR_OK
}
unsafe extern "C" fn slots(_: CK_BBOOL, slots: CK_SLOT_ID_PTR, count: CK_ULONG_PTR) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if !slots.is_null() {
        if unsafe { count.read() } < 1 {
            unsafe { count.write(1) };
            return CKR_BUFFER_TOO_SMALL;
        }
        unsafe { slots.write(1) };
    }
    unsafe { count.write(1) };
    CKR_OK
}
unsafe extern "C" fn slot_info(_: CK_SLOT_ID, out: CK_SLOT_INFO_PTR) -> CK_RV {
    if out.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let info = CK_SLOT_INFO { flags: CKF_TOKEN_PRESENT, ..Default::default() };
    unsafe { out.write(info) };
    CKR_OK
}
unsafe extern "C" fn token_info(_: CK_SLOT_ID, out: CK_TOKEN_INFO_PTR) -> CK_RV {
    if out.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let info = CK_TOKEN_INFO {
        flags: CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED,
        ..Default::default()
    };
    unsafe { out.write(info) };
    CKR_OK
}
unsafe extern "C" fn open(
    _: CK_SLOT_ID,
    _: CK_FLAGS,
    _: CK_VOID_PTR,
    _: CK_NOTIFY,
    out: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if out.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe { out.write(NEXT_SESSION.fetch_add(1, Ordering::SeqCst) as CK_SESSION_HANDLE) };
    CKR_OK
}
unsafe extern "C" fn session_info(_: CK_SESSION_HANDLE, out: CK_SESSION_INFO_PTR) -> CK_RV {
    if out.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        out.write(CK_SESSION_INFO {
            slotID: 1,
            state: CKS_RW_USER_FUNCTIONS,
            flags: CKF_SERIAL_SESSION | CKF_RW_SESSION,
            ulDeviceError: 0,
        })
    };
    CKR_OK
}
unsafe extern "C" fn login(
    _: CK_SESSION_HANDLE,
    _: CK_USER_TYPE,
    _: CK_UTF8CHAR_PTR,
    _: CK_ULONG,
) -> CK_RV {
    CKR_OK
}
unsafe extern "C" fn create(
    _: CK_SESSION_HANDLE,
    _: CK_ATTRIBUTE_PTR,
    _: CK_ULONG,
    out: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if out.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe { out.write(41) };
    CKR_OK
}
unsafe extern "C" fn destroy(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE) -> CK_RV {
    CKR_OK
}
unsafe extern "C" fn init(
    _: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    if !mechanism.is_null() {
        MECHANISM.store(unsafe { (*mechanism).mechanism } as u64, Ordering::SeqCst);
    }
    CKR_OK
}
unsafe extern "C" fn digest_init(session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM_PTR) -> CK_RV {
    unsafe { init(session, mechanism, 0) }
}
unsafe extern "C" fn byte(
    _: CK_SESSION_HANDLE,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    out: CK_BYTE_PTR,
    length: CK_ULONG_PTR,
) -> CK_RV {
    unsafe { ExactOracle_ByteOutput(out, length) }
}
unsafe extern "C" fn final_byte(
    _: CK_SESSION_HANDLE,
    out: CK_BYTE_PTR,
    length: CK_ULONG_PTR,
) -> CK_RV {
    unsafe { ExactOracle_ByteOutput(out, length) }
}
unsafe extern "C" fn wrap(
    _: CK_SESSION_HANDLE,
    _: CK_MECHANISM_PTR,
    _: CK_OBJECT_HANDLE,
    _: CK_OBJECT_HANDLE,
    out: CK_BYTE_PTR,
    length: CK_ULONG_PTR,
) -> CK_RV {
    unsafe { ExactOracle_ByteOutput(out, length) }
}

unsafe fn parameter(
    pointer: CK_VOID_PTR,
    length: CK_ULONG,
    encrypt: bool,
    final_part: bool,
    rv: CK_RV,
) {
    let mut state = STATE.lock().unwrap();
    if pointer.is_null() || state.0.parameter_action == 0 {
        return;
    }
    match MECHANISM.load(Ordering::SeqCst) as CK_MECHANISM_TYPE {
        CKM_AES_GCM if length as usize == std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() => {
            let p = unsafe { &mut *pointer.cast::<CK_GCM_MESSAGE_PARAMS>() };
            if state.0.parameter_action == 2 {
                p.ulTagBits = 7;
                state.1.parameter_stores += 1;
                return;
            }
            if encrypt
                && !p.pIv.is_null()
                && p.ulIvLen != 0
                && p.ivGenerator == CKG_GENERATE_COUNTER_XOR
                && p.ulIvFixedBits == 0
            {
                unsafe { p.pIv.write(0x42) };
                state.1.parameter_stores += 1;
            }
            if encrypt
                && state.0.parameter_action == 5
                && rv == CKR_OK
                && p.ivGenerator == CKG_GENERATE_RANDOM
                && !p.pIv.is_null()
            {
                unsafe { std::ptr::write_bytes(p.pIv, 0x42, p.ulIvLen as usize) };
                state.1.parameter_stores += 1;
            }
            if encrypt
                && final_part
                && rv == CKR_OK
                && state.0.parameter_action != 6
                && !p.pTag.is_null()
                && p.ulTagBits >= 8
            {
                unsafe { std::ptr::write_bytes(p.pTag, 0x5a, (p.ulTagBits / 8) as usize) };
                state.1.parameter_stores += 1;
            }
        }
        CKM_AES_CCM if length as usize == std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() => {
            let p = unsafe { &mut *pointer.cast::<CK_CCM_MESSAGE_PARAMS>() };
            if encrypt
                && !p.pNonce.is_null()
                && p.ulNonceLen != 0
                && p.nonceGenerator == CKG_GENERATE_COUNTER_XOR
                && p.ulNonceFixedBits == 0
            {
                unsafe { p.pNonce.write(0x42) };
                state.1.parameter_stores += 1;
            }
            if encrypt
                && state.0.parameter_action == 5
                && rv == CKR_OK
                && p.nonceGenerator == CKG_GENERATE_RANDOM
                && !p.pNonce.is_null()
            {
                unsafe { std::ptr::write_bytes(p.pNonce, 0x42, p.ulNonceLen as usize) };
                state.1.parameter_stores += 1;
            }
            if encrypt
                && final_part
                && rv == CKR_OK
                && state.0.parameter_action != 6
                && !p.pMAC.is_null()
            {
                unsafe { std::ptr::write_bytes(p.pMAC, 0x5a, p.ulMACLen as usize) };
                state.1.parameter_stores += 1;
            }
        }
        CKM_CHACHA20_POLY1305 | CKM_SALSA20_POLY1305
            if length as usize
                == std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>() =>
        {
            let p = unsafe { &mut *pointer.cast::<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>() };
            if encrypt && final_part && rv == CKR_OK && !p.pTag.is_null() {
                unsafe { std::ptr::write_bytes(p.pTag, 0x5a, 16) };
                state.1.parameter_stores += 1;
            }
        }
        _ => {}
    }
}
unsafe extern "C" fn encrypt_message(
    _: CK_SESSION_HANDLE,
    p: CK_VOID_PTR,
    n: CK_ULONG,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    out: CK_BYTE_PTR,
    len: CK_ULONG_PTR,
) -> CK_RV {
    let rv = unsafe { ExactOracle_ByteOutput(out, len) };
    unsafe { parameter(p, n, true, true, rv) };
    rv
}
unsafe extern "C" fn decrypt_message(
    _: CK_SESSION_HANDLE,
    p: CK_VOID_PTR,
    n: CK_ULONG,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    out: CK_BYTE_PTR,
    len: CK_ULONG_PTR,
) -> CK_RV {
    let rv = unsafe { ExactOracle_ByteOutput(out, len) };
    unsafe { parameter(p, n, false, true, rv) };
    rv
}
unsafe extern "C" fn next_message(
    _: CK_SESSION_HANDLE,
    p: CK_VOID_PTR,
    n: CK_ULONG,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    out: CK_BYTE_PTR,
    len: CK_ULONG_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    let rv = unsafe { ExactOracle_ByteOutput(out, len) };
    unsafe { parameter(p, n, true, flags & CKF_END_OF_MESSAGE != 0, rv) };
    rv
}
unsafe extern "C" fn decrypt_next(
    _: CK_SESSION_HANDLE,
    p: CK_VOID_PTR,
    n: CK_ULONG,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    out: CK_BYTE_PTR,
    len: CK_ULONG_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    let rv = unsafe { ExactOracle_ByteOutput(out, len) };
    unsafe { parameter(p, n, false, flags & CKF_END_OF_MESSAGE != 0, rv) };
    rv
}
unsafe extern "C" fn begin(
    _: CK_SESSION_HANDLE,
    p: CK_VOID_PTR,
    n: CK_ULONG,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
) -> CK_RV {
    let rv = unsafe { ExactOracle_ByteOutput(std::ptr::null_mut(), std::ptr::null_mut()) };
    {
        let mut state = STATE.lock().unwrap();
        state.1.begin_parameter_present = u32::from(!p.is_null());
        state.1.begin_parameter_length = n as u64;
    }
    unsafe { parameter(p, n, true, false, rv) };
    rv
}
unsafe extern "C" fn decrypt_begin(
    _: CK_SESSION_HANDLE,
    p: CK_VOID_PTR,
    n: CK_ULONG,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
) -> CK_RV {
    let rv = unsafe { ExactOracle_ByteOutput(std::ptr::null_mut(), std::ptr::null_mut()) };
    {
        let mut state = STATE.lock().unwrap();
        state.1.begin_parameter_present = u32::from(!p.is_null());
        state.1.begin_parameter_length = n as u64;
    }
    unsafe { parameter(p, n, false, false, rv) };
    rv
}
unsafe extern "C" fn sign_message(
    _: CK_SESSION_HANDLE,
    _: CK_VOID_PTR,
    _: CK_ULONG,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    out: CK_BYTE_PTR,
    len: CK_ULONG_PTR,
) -> CK_RV {
    unsafe { ExactOracle_ByteOutput(out, len) }
}
unsafe extern "C" fn sign_begin(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG) -> CK_RV {
    unsafe { ExactOracle_ByteOutput(std::ptr::null_mut(), std::ptr::null_mut()) }
}
unsafe extern "C" fn wrap_authenticated(
    _: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    _: CK_OBJECT_HANDLE,
    _: CK_OBJECT_HANDLE,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    out: CK_BYTE_PTR,
    len: CK_ULONG_PTR,
) -> CK_RV {
    let rv = unsafe { ExactOracle_ByteOutput(out, len) };
    if !mechanism.is_null() {
        let mechanism = unsafe { &*mechanism };
        if mechanism.mechanism == CKM_AES_CBC
            && !mechanism.pParameter.is_null()
            && mechanism.ulParameterLen == 16
            && STATE.lock().unwrap().0.parameter_action == 1
        {
            unsafe { mechanism.pParameter.cast::<u8>().write(0x42) };
            STATE.lock().unwrap().1.parameter_stores += 1;
        } else {
            MECHANISM.store(mechanism.mechanism as u64, Ordering::SeqCst);
            unsafe { parameter(mechanism.pParameter, mechanism.ulParameterLen, true, true, rv) };
        }
    }
    rv
}
unsafe extern "C" fn encapsulate(
    _: CK_SESSION_HANDLE,
    _: CK_MECHANISM_PTR,
    _: CK_OBJECT_HANDLE,
    _: CK_ATTRIBUTE_PTR,
    _: CK_ULONG,
    out: CK_BYTE_PTR,
    len: CK_ULONG_PTR,
    handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let rv = unsafe { ExactOracle_ByteOutput(out, len) };
    let mut state = STATE.lock().unwrap();
    if !handle.is_null() && state.0.handle_action == 1 {
        unsafe { handle.write(91) };
        state.1.handle_stores += 1;
    }
    rv
}

unsafe extern "C" fn attributes(
    _: CK_SESSION_HANDLE,
    _: CK_OBJECT_HANDLE,
    attrs: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    let mut state = STATE.lock().unwrap();
    state.1.calls += 1;
    let scenario = state.0;
    if attrs.is_null() && count != 0 {
        return CKR_ARGUMENTS_BAD;
    }
    // Legal mixed template: an empty readable LABEL (optionally nested), plus
    // a readable VALUE query, a sensitive/missing VALUE, or an undersized VALUE.
    // Nested input type is deliberately never read.
    if scenario.parameter_action == 4 && count == 2 {
        let first = attrs;
        let second = unsafe { attrs.add(1) };
        let nested = unsafe { (*first).type_ == CKA_WRAP_TEMPLATE };
        let empty = if nested {
            let value = unsafe { (*first).pValue };
            if value.is_null()
                || unsafe { (*first).ulValueLen } != std::mem::size_of::<CK_ATTRIBUTE>() as CK_ULONG
            {
                return CKR_ARGUMENTS_BAD;
            }
            let sub = value.cast::<CK_ATTRIBUTE>();
            unsafe { std::ptr::addr_of_mut!((*sub).type_).write(CKA_LABEL) };
            sub
        } else {
            first
        };
        unsafe { std::ptr::addr_of_mut!((*empty).ulValueLen).write(0) };
        let rv = scenario.rv as CK_RV;
        unsafe {
            std::ptr::addr_of_mut!((*second).ulValueLen).write(if rv == CKR_OK {
                4
            } else {
                CK_UNAVAILABLE_INFORMATION
            })
        };
        state.1.length_stores += 2;
        return rv;
    }
    for index in 0..count as usize {
        let pointer = unsafe { attrs.add(index) };
        let attr_type = unsafe { std::ptr::addr_of!((*pointer).type_).read() };
        let value = unsafe { std::ptr::addr_of!((*pointer).pValue).read() };
        let capacity = if value.is_null() {
            0
        } else {
            unsafe { std::ptr::addr_of!((*pointer).ulValueLen).read() }
        };
        state.1.output_present = u32::from(!value.is_null());
        state.1.incoming_capacity = capacity as u64;
        if attr_type == CKA_WRAP_TEMPLATE && !value.is_null() {
            let stride = std::mem::size_of::<CK_ATTRIBUTE>() as CK_ULONG;
            if scenario.parameter_action == 3 {
                unsafe { std::ptr::addr_of_mut!((*pointer).ulValueLen).write(capacity + stride) };
                state.1.length_stores += 1;
                continue;
            }
            for sub_index in 0..(capacity / stride) as usize {
                let sub = unsafe { value.cast::<CK_ATTRIBUTE>().add(sub_index) };
                let sub_value = unsafe { std::ptr::addr_of!((*sub).pValue).read() };
                let sub_capacity = if sub_value.is_null() {
                    0
                } else {
                    unsafe { std::ptr::addr_of!((*sub).ulValueLen).read() }
                };
                if matches!(
                    scenario.rv as CK_RV,
                    CKR_OK
                        | CKR_ATTRIBUTE_SENSITIVE
                        | CKR_ATTRIBUTE_TYPE_INVALID
                        | CKR_BUFFER_TOO_SMALL
                ) {
                    unsafe { std::ptr::addr_of_mut!((*sub).type_).write(CKA_LABEL) };
                }
                if scenario.length_action == 1 {
                    unsafe {
                        std::ptr::addr_of_mut!((*sub).ulValueLen)
                            .write(scenario.returned_length as CK_ULONG)
                    };
                    state.1.length_stores += 1;
                }
                if !sub_value.is_null() && sub_capacity >= 4 && scenario.output_action == 1 {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            [0x10u8, 0x20, 0x30, 0x40].as_ptr(),
                            sub_value.cast::<u8>(),
                            4,
                        )
                    };
                    state.1.output_stores += 1;
                }
            }
        } else {
            if scenario.length_action == 1 {
                unsafe {
                    std::ptr::addr_of_mut!((*pointer).ulValueLen)
                        .write(scenario.returned_length as CK_ULONG)
                };
                state.1.length_stores += 1;
            }
            if !value.is_null() && capacity >= 4 && scenario.output_action == 1 {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        [0x10u8, 0x20, 0x30, 0x40].as_ptr(),
                        value.cast::<u8>(),
                        4,
                    )
                };
                state.1.output_stores += 1;
            }
        }
    }
    scenario.rv as CK_RV
}

fn table(version: CK_VERSION) -> CK_FUNCTION_LIST_3_2 {
    CK_FUNCTION_LIST_3_2 {
        version,
        C_Initialize: Some(initialize),
        C_Finalize: Some(initialize),
        C_GetInfo: Some(info),
        C_GetFunctionList: Some(C_GetFunctionList),
        C_GetSlotList: Some(slots),
        C_GetSlotInfo: Some(slot_info),
        C_GetTokenInfo: Some(token_info),
        C_OpenSession: Some(open),
        C_CloseSession: Some(close),
        C_CloseAllSessions: Some(close),
        C_GetSessionInfo: Some(session_info),
        C_Login: Some(login),
        C_Logout: Some(close),
        C_CreateObject: Some(create),
        C_DestroyObject: Some(destroy),
        C_GetAttributeValue: Some(attributes),
        C_EncryptInit: Some(init),
        C_DecryptInit: Some(init),
        C_DigestInit: Some(digest_init),
        C_SignInit: Some(init),
        C_VerifyInit: Some(init),
        C_SignRecoverInit: Some(init),
        C_VerifyRecoverInit: Some(init),
        C_Encrypt: Some(byte),
        C_EncryptUpdate: Some(byte),
        C_EncryptFinal: Some(final_byte),
        C_Decrypt: Some(byte),
        C_DecryptUpdate: Some(byte),
        C_DecryptFinal: Some(final_byte),
        C_Digest: Some(byte),
        C_DigestFinal: Some(final_byte),
        C_Sign: Some(byte),
        C_SignFinal: Some(final_byte),
        C_SignRecover: Some(byte),
        C_VerifyRecover: Some(byte),
        C_DigestEncryptUpdate: Some(byte),
        C_DecryptDigestUpdate: Some(byte),
        C_SignEncryptUpdate: Some(byte),
        C_DecryptVerifyUpdate: Some(byte),
        C_WrapKey: Some(wrap),
        C_GetOperationState: Some(final_byte),
        C_GetInterfaceList: Some(C_GetInterfaceList),
        C_GetInterface: Some(C_GetInterface),
        C_MessageEncryptInit: Some(init),
        C_EncryptMessage: Some(encrypt_message),
        C_EncryptMessageBegin: (!cfg!(feature = "missing-message-begin")).then_some(begin),
        C_EncryptMessageNext: Some(next_message),
        C_MessageEncryptFinal: Some(close),
        C_MessageDecryptInit: Some(init),
        C_DecryptMessage: Some(decrypt_message),
        C_DecryptMessageBegin: (!cfg!(feature = "missing-message-begin")).then_some(decrypt_begin),
        C_DecryptMessageNext: Some(decrypt_next),
        C_MessageDecryptFinal: Some(close),
        C_MessageSignInit: Some(init),
        C_SignMessage: Some(sign_message),
        C_SignMessageBegin: Some(sign_begin),
        C_SignMessageNext: Some(sign_message),
        C_MessageSignFinal: Some(close),
        C_EncapsulateKey: Some(encapsulate),
        C_WrapKeyAuthenticated: Some(wrap_authenticated),
        ..Default::default()
    }
}
static V240: LazyLock<CK_FUNCTION_LIST_3_2> =
    LazyLock::new(|| table(CK_VERSION { major: 2, minor: 40 }));
static V300: LazyLock<CK_FUNCTION_LIST_3_2> =
    LazyLock::new(|| table(CK_VERSION { major: 3, minor: 0 }));
static V320: LazyLock<CK_FUNCTION_LIST_3_2> =
    LazyLock::new(|| table(CK_VERSION { major: 3, minor: 2 }));

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(out: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    // W1-L1-05: no panic across `extern "C"` even in the test harness.
    catch_or_general_error(|| {
        if out.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        unsafe { out.write((&*V240 as *const CK_FUNCTION_LIST_3_2).cast_mut().cast()) };
        CKR_OK
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInterfaceList(out: CK_INTERFACE_PTR, count: CK_ULONG_PTR) -> CK_RV {
    // W1-L1-05: no panic across `extern "C"` even in the test harness.
    catch_or_general_error(|| {
        if count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if !out.is_null() {
            if unsafe { count.read() } < 3 {
                unsafe { count.write(3) };
                return CKR_BUFFER_TOO_SMALL;
            }
            for (i, table) in [&*V240, &*V300, &*V320].into_iter().enumerate() {
                unsafe {
                    out.add(i).write(CK_INTERFACE {
                        pInterfaceName: c"PKCS 11".as_ptr().cast_mut().cast(),
                        pFunctionList: (table as *const CK_FUNCTION_LIST_3_2).cast_mut().cast(),
                        flags: 0,
                    })
                };
            }
        }
        unsafe { count.write(3) };
        CKR_OK
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInterface(
    _: CK_UTF8CHAR_PTR,
    version: CK_VERSION_PTR,
    out: CK_INTERFACE_PTR_PTR,
    _: CK_FLAGS,
) -> CK_RV {
    // W1-L1-05: no panic across `extern "C"` even in the test harness.
    catch_or_general_error(|| {
        if out.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let version = if version.is_null() {
            CK_VERSION { major: 3, minor: 2 }
        } else {
            unsafe { version.read() }
        };
        let table = match (version.major, version.minor) {
            (2, 40) => &*V240,
            (3, 0) => &*V300,
            (3, 2) => &*V320,
            _ => return CKR_ARGUMENTS_BAD,
        };
        // Process-lifetime interface descriptors model a real static provider table.
        static INTERFACES: std::sync::OnceLock<[usize; 3]> = std::sync::OnceLock::new();
        let interfaces = INTERFACES.get_or_init(|| {
            [&*V240, &*V300, &*V320].map(|table| {
                Box::into_raw(Box::new(CK_INTERFACE {
                    pInterfaceName: c"PKCS 11".as_ptr().cast_mut().cast(),
                    pFunctionList: (table as *const CK_FUNCTION_LIST_3_2).cast_mut().cast(),
                    flags: 0,
                })) as usize
            })
        });
        let index = if table.version.major == 2 {
            0
        } else if table.version.minor == 0 {
            1
        } else {
            2
        };
        unsafe { out.write(interfaces[index] as CK_INTERFACE_PTR) };
        CKR_OK
    })
}

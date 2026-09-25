//! Cross-width runtime smoke client (ADR-0011 Phase D).
//!
//! Loads the built shim module through the **public C ABI** — dlopen /
//! LoadLibrary + `C_GetFunctionList` — exactly like a host application,
//! then runs the same bridge-discriminator assertions as the Phase A
//! live test. Built for `x86_64-pc-windows-msvc` and run under wine,
//! this exercises the real LLP64 edge (32-bit `CK_ULONG`, 64-bit
//! pointers, packed structs) against a live Linux daemon.
//!
//! Usage: cross_width_smoke <path-to-shim-module>
//! Env:   PKCS11_PROXY_ENDPOINT must point at a running daemon whose
//!        token can create public session data objects.
//!
//! Exits 0 only if every assertion holds.

// CK_ULONG is u32 on the Windows target and u64 on 64-bit Unix; the
// `as u64` casts are required on the narrow target.
#![allow(clippy::unnecessary_cast)]

use cryptoki_sys::*;

fn check(cond: bool, what: &str) -> Result<(), String> {
    if cond { Ok(()) } else { Err(format!("FAILED: {what}")) }
}

fn check_rv(rv: CK_RV, what: &str) -> Result<(), String> {
    check(rv == CKR_OK as CK_RV, &format!("{what} returned CK_RV {rv:#x}"))
}

fn run(module_path: &str) -> Result<(), String> {
    println!(
        "cross_width_smoke: CK_ULONG = {} bytes, pointers = {} bytes",
        std::mem::size_of::<CK_ULONG>(),
        std::mem::size_of::<*const u8>()
    );

    let library = unsafe { libloading::Library::new(module_path) }
        .map_err(|e| format!("FAILED: loading {module_path}: {e}"))?;
    type GetFunctionList = unsafe extern "C" fn(*mut CK_FUNCTION_LIST_PTR) -> CK_RV;
    let get_function_list: libloading::Symbol<GetFunctionList> =
        unsafe { library.get(b"C_GetFunctionList\0") }
            .map_err(|e| format!("FAILED: C_GetFunctionList symbol: {e}"))?;

    let mut fl_ptr: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
    check_rv(unsafe { get_function_list(&mut fl_ptr) }, "C_GetFunctionList")?;
    check(!fl_ptr.is_null(), "function list pointer is non-null")?;
    let fl = unsafe { &*fl_ptr };

    let init = fl.C_Initialize.ok_or("FAILED: C_Initialize slot is null")?;
    check_rv(unsafe { init(std::ptr::null_mut()) }, "C_Initialize")?;

    let get_slot_list = fl.C_GetSlotList.ok_or("FAILED: C_GetSlotList slot is null")?;
    let mut slot_count: CK_ULONG = 0;
    check_rv(
        unsafe { get_slot_list(CK_TRUE, std::ptr::null_mut(), &mut slot_count) },
        "C_GetSlotList(count)",
    )?;
    check(slot_count > 0, "daemon exposes at least one token")?;
    let mut slots = vec![0 as CK_SLOT_ID; slot_count as usize];
    check_rv(
        unsafe { get_slot_list(CK_TRUE, slots.as_mut_ptr(), &mut slot_count) },
        "C_GetSlotList(data)",
    )?;
    let slot = slots[0];

    // D10: every token-info CK_ULONG arrives as the client-width
    // sentinel or a plausible value — never a truncated wide value.
    let get_token_info = fl.C_GetTokenInfo.ok_or("FAILED: C_GetTokenInfo slot is null")?;
    let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    check_rv(unsafe { get_token_info(slot, &mut info) }, "C_GetTokenInfo")?;
    for (name, v) in [
        ("ulMaxSessionCount", info.ulMaxSessionCount),
        ("ulSessionCount", info.ulSessionCount),
        ("ulTotalPublicMemory", info.ulTotalPublicMemory),
        ("ulFreePublicMemory", info.ulFreePublicMemory),
    ] {
        check(
            v == CK_UNAVAILABLE_INFORMATION
                || v == CK_EFFECTIVELY_INFINITE
                || (v as u64) < (1 << 31),
            &format!("token info {name} = {v:#x} is sentinel-or-plausible"),
        )?;
    }

    let open_session = fl.C_OpenSession.ok_or("FAILED: C_OpenSession slot is null")?;
    let mut session: CK_SESSION_HANDLE = 0;
    check_rv(
        unsafe {
            open_session(
                slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                std::ptr::null_mut(),
                None,
                &mut session,
            )
        },
        "C_OpenSession",
    )?;

    // Public session data object — no login required.
    let create_object = fl.C_CreateObject.ok_or("FAILED: C_CreateObject slot is null")?;
    let mut class: CK_ULONG = CKO_DATA;
    let mut token_false: CK_BBOOL = CK_FALSE;
    let mut private_false: CK_BBOOL = CK_FALSE;
    let mut value = *b"llp64 smoke probe";
    let mut template = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &mut class as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN,
            pValue: &mut token_false as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: 1,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE,
            pValue: &mut private_false as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: 1,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut object: CK_OBJECT_HANDLE = 0;
    check_rv(
        unsafe {
            create_object(session, template.as_mut_ptr(), template.len() as CK_ULONG, &mut object)
        },
        "C_CreateObject",
    )?;

    // THE bridge discriminator: the 64-bit backend natively reports 8
    // for a CKA_CLASS size query; this client must observe its own
    // width (4 on LLP64).
    let get_attribute_value =
        fl.C_GetAttributeValue.ok_or("FAILED: C_GetAttributeValue slot is null")?;
    let mut attr = CK_ATTRIBUTE { type_: CKA_CLASS, pValue: std::ptr::null_mut(), ulValueLen: 0 };
    check_rv(
        unsafe { get_attribute_value(session, object, &mut attr, 1) },
        "C_GetAttributeValue(CKA_CLASS size query)",
    )?;
    let reported_len = attr.ulValueLen; // copy out of the packed struct
    check(
        reported_len as usize == std::mem::size_of::<CK_ULONG>(),
        &format!(
            "CKA_CLASS size query returned {reported_len} (client CK_ULONG width is {})",
            std::mem::size_of::<CK_ULONG>()
        ),
    )?;

    // Exact-fit data query: value bytes re-encoded to client width.
    let mut class_buf = [0u8; std::mem::size_of::<CK_ULONG>()];
    let mut attr = CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: class_buf.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: class_buf.len() as CK_ULONG,
    };
    check_rv(
        unsafe { get_attribute_value(session, object, &mut attr, 1) },
        "C_GetAttributeValue(CKA_CLASS data query)",
    )?;
    check(
        CK_ULONG::from_ne_bytes(class_buf) == CKO_DATA,
        &format!("CKA_CLASS value round-trips (got {:#x})", CK_ULONG::from_ne_bytes(class_buf)),
    )?;

    // Too-small buffer: verbatim CKR_BUFFER_TOO_SMALL + client-width
    // CK_UNAVAILABLE_INFORMATION sentinel (D10 end-to-end).
    let mut tiny = [0u8; 2];
    let mut attr = CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: tiny.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: tiny.len() as CK_ULONG,
    };
    let rv = unsafe { get_attribute_value(session, object, &mut attr, 1) };
    check(
        rv == CKR_BUFFER_TOO_SMALL as CK_RV,
        &format!("too-small query forwards CKR_BUFFER_TOO_SMALL (got {rv:#x})"),
    )?;
    let sentinel_len = attr.ulValueLen; // copy out of the packed struct
    check(
        sentinel_len == CK_UNAVAILABLE_INFORMATION,
        &format!("sentinel is client-width all-ones (got {sentinel_len:#x})"),
    )?;

    let close_session = fl.C_CloseSession.ok_or("FAILED: C_CloseSession slot is null")?;
    check_rv(unsafe { close_session(session) }, "C_CloseSession")?;
    let finalize = fl.C_Finalize.ok_or("FAILED: C_Finalize slot is null")?;
    check_rv(unsafe { finalize(std::ptr::null_mut()) }, "C_Finalize")?;

    println!("cross_width_smoke: PASS");
    Ok(())
}

fn main() {
    let module_path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: cross_width_smoke <path-to-shim-module>");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(&module_path) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

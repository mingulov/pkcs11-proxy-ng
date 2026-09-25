use super::*;

#[test]
fn ck_ulong_is_pointer_width() {
    assert_eq!(std::mem::size_of::<CK_ULONG>(), std::mem::size_of::<usize>());
}

#[test]
fn ck_ulong_is_at_least_32_bits() {
    assert!(std::mem::size_of::<CK_ULONG>() >= 4);
}

#[test]
fn ck_byte_is_one_byte() {
    assert_eq!(std::mem::size_of::<CK_BYTE>(), 1);
}

#[test]
fn ck_bbool_is_one_byte() {
    assert_eq!(std::mem::size_of::<CK_BBOOL>(), 1);
}

#[test]
fn ck_version_layout() {
    assert_eq!(std::mem::size_of::<CK_VERSION>(), 2);
}

#[test]
fn ck_rv_is_ck_ulong() {
    assert_eq!(std::mem::size_of::<CK_RV>(), std::mem::size_of::<CK_ULONG>());
}

#[test]
fn ck_session_handle_is_ck_ulong() {
    assert_eq!(std::mem::size_of::<CK_SESSION_HANDLE>(), std::mem::size_of::<CK_ULONG>());
}

#[test]
fn ck_object_handle_is_ck_ulong() {
    assert_eq!(std::mem::size_of::<CK_OBJECT_HANDLE>(), std::mem::size_of::<CK_ULONG>());
}

#[test]
fn ck_slot_id_is_ck_ulong() {
    assert_eq!(std::mem::size_of::<CK_SLOT_ID>(), std::mem::size_of::<CK_ULONG>());
}

#[test]
fn ck_mechanism_type_is_ck_ulong() {
    assert_eq!(std::mem::size_of::<CK_MECHANISM_TYPE>(), std::mem::size_of::<CK_ULONG>());
}

/// Align `offset` up to `align` (portable padding rule for the layout gates).
fn align_up(offset: usize, align: usize) -> usize {
    offset.div_ceil(align) * align
}

/// Expected `(field offsets, align, size)` for a 3-field struct under the
/// target's actual repr: the Windows MSVC bindings are `packed` (dense,
/// align 1) while System V targets are aligned. The branch is read off the
/// real `align_of`, so each target pins its exact offsets either way — a
/// field swap or padding change trips the gate on every target.
fn expected_3field_layout(
    actual_align: usize,
    sizes: [usize; 3],
    aligns: [usize; 3],
) -> ([usize; 3], usize, usize) {
    if actual_align == 1 {
        ([0, sizes[0], sizes[0] + sizes[1]], 1, sizes[0] + sizes[1] + sizes[2])
    } else {
        let off1 = align_up(sizes[0], aligns[1]);
        let off2 = align_up(off1 + sizes[1], aligns[2]);
        let align = aligns[0].max(aligns[1]).max(aligns[2]);
        ([0, off1, off2], align, align_up(off2 + sizes[2], align))
    }
}

#[test]
fn ck_attribute_layout() {
    // W1-L10-14: offsets + alignment, not sizeof-only: a field swap that
    // preserves total size must trip this gate.
    let ulong = std::mem::size_of::<CK_ULONG>();
    let ptr = std::mem::size_of::<*mut std::ffi::c_void>();
    let ptr_align = std::mem::align_of::<*mut std::ffi::c_void>();
    let ulong_align = std::mem::align_of::<CK_ULONG>();
    let (off, align, size) = expected_3field_layout(
        std::mem::align_of::<CK_ATTRIBUTE>(),
        [ulong, ptr, ulong],
        [ulong_align, ptr_align, ulong_align],
    );
    assert_eq!(std::mem::offset_of!(CK_ATTRIBUTE, type_), off[0]);
    assert_eq!(std::mem::offset_of!(CK_ATTRIBUTE, pValue), off[1]);
    assert_eq!(std::mem::offset_of!(CK_ATTRIBUTE, ulValueLen), off[2]);
    assert_eq!(std::mem::align_of::<CK_ATTRIBUTE>(), align);
    assert_eq!(std::mem::size_of::<CK_ATTRIBUTE>(), size);
}

#[test]
fn ck_mechanism_layout() {
    // W1-L10-14: offsets + alignment, not sizeof-only.
    let ulong = std::mem::size_of::<CK_ULONG>();
    let ptr = std::mem::size_of::<*mut std::ffi::c_void>();
    let ptr_align = std::mem::align_of::<*mut std::ffi::c_void>();
    let ulong_align = std::mem::align_of::<CK_ULONG>();
    let (off, align, size) = expected_3field_layout(
        std::mem::align_of::<CK_MECHANISM>(),
        [ulong, ptr, ulong],
        [ulong_align, ptr_align, ulong_align],
    );
    assert_eq!(std::mem::offset_of!(CK_MECHANISM, mechanism), off[0]);
    assert_eq!(std::mem::offset_of!(CK_MECHANISM, pParameter), off[1]);
    assert_eq!(std::mem::offset_of!(CK_MECHANISM, ulParameterLen), off[2]);
    assert_eq!(std::mem::align_of::<CK_MECHANISM>(), align);
    assert_eq!(std::mem::size_of::<CK_MECHANISM>(), size);
}

#[test]
fn ck_interface_layout() {
    // W1-L10-14: offsets + alignment, not sizeof-only.
    let ptr = std::mem::size_of::<*mut std::ffi::c_void>();
    let ulong = std::mem::size_of::<CK_ULONG>();
    let ptr_align = std::mem::align_of::<*mut std::ffi::c_void>();
    let ulong_align = std::mem::align_of::<CK_ULONG>();
    let (off, align, size) = expected_3field_layout(
        std::mem::align_of::<CK_INTERFACE>(),
        [ptr, ptr, ulong],
        [ptr_align, ptr_align, ulong_align],
    );
    assert_eq!(std::mem::offset_of!(CK_INTERFACE, pInterfaceName), off[0]);
    assert_eq!(std::mem::offset_of!(CK_INTERFACE, pFunctionList), off[1]);
    assert_eq!(std::mem::offset_of!(CK_INTERFACE, flags), off[2]);
    assert_eq!(std::mem::align_of::<CK_INTERFACE>(), align);
    assert_eq!(std::mem::size_of::<CK_INTERFACE>(), size);
}

#[test]
fn layout_gate_trips_on_offset_drift_with_same_size() {
    // W1-L10-14 negative control: a field swap that preserves total size
    // passes a sizeof-only gate (both layouts sum identically) but must trip
    // the offset gate. The drifted offsets below model CK_ATTRIBUTE with
    // pValue/ulValueLen swapped on LP64: same 24-byte size, wrong offsets.
    let correct = [0, 8, 16];
    let drifted = [0, 16, 8];
    let size_of_both = 24;
    assert_eq!(size_of_both, 24, "sizeof-only check passes both layouts (the blind spot)");
    assert!(
        dense_offsets_deviation("synthetic", &correct, 8).is_none(),
        "correct dense offsets must pass"
    );
    let deviation = dense_offsets_deviation("synthetic", &drifted, 8)
        .expect("offset drift with identical size must trip the gate");
    assert!(deviation.contains("16"), "deviation must name the drifted offset: {deviation}");
}

/// First deviation from dense packing (`offsets[i] == offsets[0] + i*stride`)
/// in a function-pointer table, or `None` when every field sits on stride.
/// Shared by the control above and the module-FFI table walk below.
fn dense_offsets_deviation(name: &str, offsets: &[usize], stride: usize) -> Option<String> {
    let first = *offsets.first()?;
    for (i, &offset) in offsets.iter().enumerate() {
        let expected = first + i * stride;
        if offset != expected {
            return Some(format!(
                "{name}: field {i} at offset {offset}, expected {expected} \
                 (dense stride {stride} from {first})"
            ));
        }
    }
    None
}

#[test]
fn function_list_version_at_offset_zero() {
    let mut p: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    unsafe {
        C_GetFunctionList(&mut p);
        let fl_ptr = p as *const u8;
        let ver_ptr = &(*p).version as *const CK_VERSION as *const u8;
        assert_eq!(fl_ptr, ver_ptr);
    }
}

#[test]
fn function_list_tables_match_module_ffi_offset_facts() {
    // W1-L10-14: full-table offsets, not version-at-zero only. Walk the
    // shim's served 2.40/3.0/3.2 tables with the shared module-FFI offset
    // facts (AGENTS §13): pinned spec field counts (68 + 24 + 12), dense
    // pointer-stride packing from the first function field, a populated
    // pointer at every walked offset, and the surface version at byte 0.
    use pkcs11_module::tables::Surface;

    let _guard = shim_state_test_guard();

    let mut legacy: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    assert_eq!(unsafe { C_GetFunctionList(&mut legacy) }, CKR_OK as CK_RV);
    check_served_function_table(
        "CK_FUNCTION_LIST",
        legacy as *const u8,
        (2, 40),
        Surface::LegacyFunctionList { version: CK_VERSION { major: 2, minor: 40 } },
        std::mem::align_of::<CK_FUNCTION_LIST>(),
        &[68],
    );

    for (major, minor, align) in [
        (3u8, 0u8, std::mem::align_of::<CK_FUNCTION_LIST_3_0>()),
        (3u8, 2u8, std::mem::align_of::<CK_FUNCTION_LIST_3_2>()),
    ] {
        let name = b"PKCS 11\0";
        let mut req_ver = CK_VERSION { major, minor };
        let mut iface: *mut CK_INTERFACE = std::ptr::null_mut();
        let rv = unsafe {
            C_GetInterface(name.as_ptr() as *mut CK_UTF8CHAR, &mut req_ver, &mut iface, 0)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_GetInterface({major}.{minor})");
        assert!(!iface.is_null(), "C_GetInterface({major}.{minor}) returned null");
        let base = unsafe { (*iface).pFunctionList as *const u8 };
        let label = if minor == 0 { "CK_FUNCTION_LIST_3_0" } else { "CK_FUNCTION_LIST_3_2" };
        let expected_spans: &[usize] = if minor == 0 { &[68, 24] } else { &[68, 24, 12] };
        check_served_function_table(
            label,
            base,
            (major, minor),
            Surface::StandardInterface { version: CK_VERSION { major, minor } },
            align,
            expected_spans,
        );
    }
}

/// Walk one served function-list table against the module-FFI offset facts:
/// version bytes at offset 0, pinned per-span field counts, dense packing on
/// a pointer stride (continuing across spans), the first function field right
/// after the 2-byte version header, and a non-null pointer at every offset.
fn check_served_function_table(
    label: &str,
    base: *const u8,
    version: (u8, u8),
    surface: pkcs11_module::tables::Surface,
    table_align: usize,
    expected_span_lens: &[usize],
) {
    use pkcs11_module::tables::{TableSet, detect_null_functions, tables_for};

    assert!(!base.is_null(), "{label}: served table must be non-null");
    // Unaligned-safe: on packed Windows the function fields start at 2.
    let ver = unsafe { (base as *const CK_VERSION).read_unaligned() };
    assert_eq!((ver.major, ver.minor), version, "{label}: version bytes at offset zero");

    let TableSet::Walk(spans) = tables_for(surface) else {
        panic!("{label}: module-FFI facts must walk surface version {version:?}");
    };
    assert_eq!(spans.len(), expected_span_lens.len(), "{label}: span count");
    let stride = std::mem::size_of::<usize>();
    // First function field: dense after the 2-byte version when packed,
    // pointer-aligned on System V.
    let first_expected =
        if table_align == 1 { 2 } else { align_up(std::mem::size_of::<CK_VERSION>(), stride) };
    let mut prev_end: Option<usize> = None;
    for (span, &expected_len) in spans.iter().zip(expected_span_lens) {
        let fields = span.fields();
        assert_eq!(fields.len(), expected_len, "{label}: pinned span field count");
        let offsets: Vec<usize> = fields.iter().map(|field| field.offset).collect();
        assert!(
            dense_offsets_deviation(label, &offsets, stride).is_none(),
            "{label}: {}",
            dense_offsets_deviation(label, &offsets, stride).unwrap_or_default()
        );
        match prev_end {
            None => assert_eq!(offsets[0], first_expected, "{label}: first function offset"),
            Some(prev) => assert_eq!(
                offsets[0], prev,
                "{label}: 3.x extras must continue the base table densely"
            ),
        }
        let nulls = unsafe { detect_null_functions(base, fields) };
        assert!(nulls.is_empty(), "{label}: null function pointers at {nulls:?}");
        prev_end = Some(offsets[offsets.len() - 1] + stride);
    }
}

#[test]
fn proto_u64_can_hold_max_ck_ulong() {
    let max_ck_ulong = CK_ULONG::MAX;
    assert!((max_ck_ulong as u128) <= (u64::MAX as u128));
}

#[test]
fn u64_to_ck_ulong_truncation_detection() {
    let large: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    let converted = large as CK_ULONG;
    if std::mem::size_of::<CK_ULONG>() == 8 {
        assert_eq!(converted as u64, large);
    } else {
        assert_ne!(converted as u64, large);
    }
}

#[test]
fn all_function_list_pointers_are_non_null() {
    let mut p: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let rv = unsafe { C_GetFunctionList(&mut p) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!p.is_null());

    let fl = unsafe { &*p };
    // E0793: CK_FUNCTION_LIST is packed on Windows; each `is_some()` below runs
    // on a by-value copy of its `Option<fn>` field, never on a field reference.
    assert!(
        {
            let f = fl.C_Initialize;
            f.is_some()
        },
        "C_Initialize must be non-null"
    );
    assert!(
        {
            let f = fl.C_Finalize;
            f.is_some()
        },
        "C_Finalize must be non-null"
    );
    assert!(
        {
            let f = fl.C_GetInfo;
            f.is_some()
        },
        "C_GetInfo must be non-null"
    );
    assert!(
        {
            let f = fl.C_GetSlotList;
            f.is_some()
        },
        "C_GetSlotList must be non-null"
    );
    assert!(
        {
            let f = fl.C_GetSlotInfo;
            f.is_some()
        },
        "C_GetSlotInfo must be non-null"
    );
    assert!(
        {
            let f = fl.C_GetTokenInfo;
            f.is_some()
        },
        "C_GetTokenInfo must be non-null"
    );
    assert!(
        {
            let f = fl.C_GetMechanismList;
            f.is_some()
        },
        "C_GetMechanismList must be non-null"
    );
    assert!(
        {
            let f = fl.C_GetMechanismInfo;
            f.is_some()
        },
        "C_GetMechanismInfo must be non-null"
    );
    assert!(
        {
            let f = fl.C_OpenSession;
            f.is_some()
        },
        "C_OpenSession must be non-null"
    );
    assert!(
        {
            let f = fl.C_CloseSession;
            f.is_some()
        },
        "C_CloseSession must be non-null"
    );
    assert!(
        {
            let f = fl.C_CloseAllSessions;
            f.is_some()
        },
        "C_CloseAllSessions must be non-null"
    );
    assert!(
        {
            let f = fl.C_GetSessionInfo;
            f.is_some()
        },
        "C_GetSessionInfo must be non-null"
    );
    assert!(
        {
            let f = fl.C_Login;
            f.is_some()
        },
        "C_Login must be non-null"
    );
    assert!(
        {
            let f = fl.C_Logout;
            f.is_some()
        },
        "C_Logout must be non-null"
    );
    assert!(
        {
            let f = fl.C_InitToken;
            f.is_some()
        },
        "C_InitToken must be non-null"
    );
    assert!(
        {
            let f = fl.C_InitPIN;
            f.is_some()
        },
        "C_InitPIN must be non-null"
    );
    assert!(
        {
            let f = fl.C_SetPIN;
            f.is_some()
        },
        "C_SetPIN must be non-null"
    );
    assert!(
        {
            let f = fl.C_FindObjectsInit;
            f.is_some()
        },
        "C_FindObjectsInit must be non-null"
    );
    assert!(
        {
            let f = fl.C_FindObjects;
            f.is_some()
        },
        "C_FindObjects must be non-null"
    );
    assert!(
        {
            let f = fl.C_FindObjectsFinal;
            f.is_some()
        },
        "C_FindObjectsFinal must be non-null"
    );
    assert!(
        {
            let f = fl.C_GetAttributeValue;
            f.is_some()
        },
        "C_GetAttributeValue must be non-null"
    );
    assert!(
        {
            let f = fl.C_SetAttributeValue;
            f.is_some()
        },
        "C_SetAttributeValue must be non-null"
    );
    assert!(
        {
            let f = fl.C_SignInit;
            f.is_some()
        },
        "C_SignInit must be non-null"
    );
    assert!(
        {
            let f = fl.C_Sign;
            f.is_some()
        },
        "C_Sign must be non-null"
    );
    assert!(
        {
            let f = fl.C_SignUpdate;
            f.is_some()
        },
        "C_SignUpdate must be non-null"
    );
    assert!(
        {
            let f = fl.C_SignFinal;
            f.is_some()
        },
        "C_SignFinal must be non-null"
    );
    assert!(
        {
            let f = fl.C_VerifyInit;
            f.is_some()
        },
        "C_VerifyInit must be non-null"
    );
    assert!(
        {
            let f = fl.C_Verify;
            f.is_some()
        },
        "C_Verify must be non-null"
    );
    assert!(
        {
            let f = fl.C_VerifyUpdate;
            f.is_some()
        },
        "C_VerifyUpdate must be non-null"
    );
    assert!(
        {
            let f = fl.C_VerifyFinal;
            f.is_some()
        },
        "C_VerifyFinal must be non-null"
    );
    assert!(
        {
            let f = fl.C_EncryptInit;
            f.is_some()
        },
        "C_EncryptInit must be non-null"
    );
    assert!(
        {
            let f = fl.C_Encrypt;
            f.is_some()
        },
        "C_Encrypt must be non-null"
    );
    assert!(
        {
            let f = fl.C_EncryptUpdate;
            f.is_some()
        },
        "C_EncryptUpdate must be non-null"
    );
    assert!(
        {
            let f = fl.C_EncryptFinal;
            f.is_some()
        },
        "C_EncryptFinal must be non-null"
    );
    assert!(
        {
            let f = fl.C_DecryptInit;
            f.is_some()
        },
        "C_DecryptInit must be non-null"
    );
    assert!(
        {
            let f = fl.C_Decrypt;
            f.is_some()
        },
        "C_Decrypt must be non-null"
    );
    assert!(
        {
            let f = fl.C_DecryptUpdate;
            f.is_some()
        },
        "C_DecryptUpdate must be non-null"
    );
    assert!(
        {
            let f = fl.C_DecryptFinal;
            f.is_some()
        },
        "C_DecryptFinal must be non-null"
    );
    assert!(
        {
            let f = fl.C_DigestInit;
            f.is_some()
        },
        "C_DigestInit must be non-null"
    );
    assert!(
        {
            let f = fl.C_Digest;
            f.is_some()
        },
        "C_Digest must be non-null"
    );
    assert!(
        {
            let f = fl.C_DigestUpdate;
            f.is_some()
        },
        "C_DigestUpdate must be non-null"
    );
    assert!(
        {
            let f = fl.C_DigestKey;
            f.is_some()
        },
        "C_DigestKey must be non-null"
    );
    assert!(
        {
            let f = fl.C_DigestFinal;
            f.is_some()
        },
        "C_DigestFinal must be non-null"
    );
    assert!(
        {
            let f = fl.C_GenerateKey;
            f.is_some()
        },
        "C_GenerateKey must be non-null"
    );
    assert!(
        {
            let f = fl.C_GenerateKeyPair;
            f.is_some()
        },
        "C_GenerateKeyPair must be non-null"
    );
    assert!(
        {
            let f = fl.C_GenerateRandom;
            f.is_some()
        },
        "C_GenerateRandom must be non-null"
    );
    assert!(
        {
            let f = fl.C_SeedRandom;
            f.is_some()
        },
        "C_SeedRandom must be non-null"
    );
    assert!(
        {
            let f = fl.C_CreateObject;
            f.is_some()
        },
        "C_CreateObject must be non-null"
    );
    assert!(
        {
            let f = fl.C_CopyObject;
            f.is_some()
        },
        "C_CopyObject must be non-null"
    );
    assert!(
        {
            let f = fl.C_DestroyObject;
            f.is_some()
        },
        "C_DestroyObject must be non-null"
    );
    assert!(
        {
            let f = fl.C_GetObjectSize;
            f.is_some()
        },
        "C_GetObjectSize must be non-null"
    );
    assert!(
        {
            let f = fl.C_WrapKey;
            f.is_some()
        },
        "C_WrapKey must be non-null"
    );
    assert!(
        {
            let f = fl.C_UnwrapKey;
            f.is_some()
        },
        "C_UnwrapKey must be non-null"
    );
    assert!(
        {
            let f = fl.C_DeriveKey;
            f.is_some()
        },
        "C_DeriveKey must be non-null"
    );
    assert!(
        {
            let f = fl.C_WaitForSlotEvent;
            f.is_some()
        },
        "C_WaitForSlotEvent must be non-null"
    );
    assert!(
        {
            let f = fl.C_GetOperationState;
            f.is_some()
        },
        "C_GetOperationState must be non-null"
    );
    assert!(
        {
            let f = fl.C_SetOperationState;
            f.is_some()
        },
        "C_SetOperationState must be non-null"
    );
    assert!(
        {
            let f = fl.C_SignRecoverInit;
            f.is_some()
        },
        "C_SignRecoverInit must be non-null"
    );
    assert!(
        {
            let f = fl.C_SignRecover;
            f.is_some()
        },
        "C_SignRecover must be non-null"
    );
    assert!(
        {
            let f = fl.C_VerifyRecoverInit;
            f.is_some()
        },
        "C_VerifyRecoverInit must be non-null"
    );
    assert!(
        {
            let f = fl.C_VerifyRecover;
            f.is_some()
        },
        "C_VerifyRecover must be non-null"
    );
}

#[test]
fn catch_panics_source_coverage() {
    // W1-C7-02: walk the WHOLE src tree (not a hardcoded file list) so a new
    // handler cannot slip an un-gated export past this gate. Mirrors the H5
    // whole-tree walk in `shim_source_never_formats_pin_data` (same
    // `collect_rs_files` helper, sources read from disk).
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let tests_dir = src_dir.join("tests");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    // Test-only `extern "C"` items (dummy callbacks, fn-pointer casts, gate
    // fixtures) are not shipped FFI exports; audit real sources only.
    files.retain(|p| !p.starts_with(&tests_dir));
    assert!(!files.is_empty(), "no shim sources found under {}", src_dir.display());

    let mut checked = 0;
    for path in &files {
        let src = std::fs::read_to_string(path).expect("read shim source");
        if let Some(violation) = catch_panics_violation(&path.display().to_string(), &src) {
            panic!("{violation}");
        }
        if defines_exports(&src) {
            checked += 1;
        }
    }
    assert!(checked > 0, "gate must cover at least one export file");
}

/// Per-export `catch_panics` check shared by the gate and its negative
/// control. Returns `None` when the file defines no exports or every
/// non-stub export's own body contains a `catch_panics(` call; otherwise a
/// violation naming the first ungated export (call-site attribution).
fn catch_panics_violation(name: &str, src: &str) -> Option<String> {
    ungated_exports(src).into_iter().next().map(|(export, lineno)| {
        format!(
            "{name}:{lineno}: export `{export}` has no catch_panics call in its own body \
             (every non-stub extern \"C\" fn must be wrapped)"
        )
    })
}

/// True when the file defines at least one non-stub `pub unsafe extern "C"`
/// export (the gate's coverage signal — e.g. the `catch_panics` definition
/// site and its unit tests define none).
fn defines_exports(src: &str) -> bool {
    src.lines().any(|line| {
        line.contains("pub unsafe extern \"C\" fn") && !line.contains("c_not_supported")
    })
}

/// Non-stub exports whose own brace-matched body contains no `catch_panics(`
/// call, as `(name, definition line)` pairs. A stray call elsewhere in the
/// file (helper, test, duplicated call in a sibling export) does NOT satisfy
/// an export: only a call inside its own `{ ... }` body counts.
fn ungated_exports(src: &str) -> Vec<(String, usize)> {
    let cleaned = strip_comments_and_strings(src);
    let line_starts = line_start_offsets(src);
    let mut ungated = Vec::new();
    for (lineno, line) in src.lines().enumerate() {
        if !line.contains("pub unsafe extern \"C\" fn") || line.contains("c_not_supported") {
            continue;
        }
        let name = export_name_from_line(line).unwrap_or_else(|| "<unknown>".to_string());
        // Scan from the definition line itself: the body's opening `{` may sit
        // on the signature line (signatures carry no braces of their own).
        if !export_body_is_gated(&cleaned, line_starts[lineno]) {
            ungated.push((name, lineno + 1));
        }
    }
    ungated
}

/// Export name from a `pub unsafe extern "C" fn <name>(...)` definition line.
fn export_name_from_line(line: &str) -> Option<String> {
    let after_fn = line.split("fn ").nth(1)?;
    let name = after_fn.split('(').next()?.trim();
    if name.is_empty() { None } else { Some(name.to_string()) }
}

/// True when the first `{ ... }` block at or after `from` (the export's own
/// body, located in comment/string-stripped source so braces in literals do
/// not confuse the match) contains a `catch_panics(` call.
fn export_body_is_gated(cleaned: &str, from: usize) -> bool {
    let bytes = cleaned.as_bytes();
    let mut i = from.min(bytes.len());
    while i < bytes.len() && bytes[i] != b'{' {
        i += 1;
    }
    if i >= bytes.len() {
        return false;
    }
    let mut depth = 0usize;
    let body_start = i;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return cleaned[body_start..=i].contains("catch_panics(");
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Byte offsets at which each source line starts (line `n` starts at index
/// `n - 1`; a trailing empty line is covered by the final push).
fn line_start_offsets(src: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (i, b) in src.bytes().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

/// Source with comments (`//`, `/* */`), string/char literals (`"..."`,
/// `'...'`, raw and byte forms) blanked to spaces, preserving byte offsets.
/// Only code-significant braces remain for body matching.
fn strip_comments_and_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    let blank = |out: &mut [u8], from: usize, to: usize| {
        let len = out.len();
        for b in &mut out[from..to.min(len)] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    };
    while i < bytes.len() {
        let rest = &bytes[i..];
        if rest.starts_with(b"//") {
            let mut end = i + 2;
            while end < bytes.len() && bytes[end] != b'\n' {
                end += 1;
            }
            blank(&mut out, i, end);
            i = end;
        } else if rest.starts_with(b"/*") {
            // Block comments nest in Rust.
            let mut end = i + 2;
            let mut depth = 1;
            while end + 1 < bytes.len() && depth > 0 {
                if bytes[end..].starts_with(b"/*") {
                    depth += 1;
                    end += 2;
                } else if bytes[end..].starts_with(b"*/") {
                    depth -= 1;
                    end += 2;
                } else {
                    end += 1;
                }
            }
            blank(&mut out, i, end.min(bytes.len()));
            i = end.min(bytes.len());
        } else if let Some(len) = raw_string_len(rest) {
            blank(&mut out, i, i + len);
            i += len;
        } else if rest.starts_with(b"\"") || rest.starts_with(b"b\"") {
            let mut end = i + rest.starts_with(b"b\"") as usize + 1;
            while end < bytes.len() {
                if bytes[end] == b'\\' {
                    end += 2;
                } else if bytes[end] == b'"' {
                    end += 1;
                    break;
                } else {
                    end += 1;
                }
            }
            blank(&mut out, i, end.min(bytes.len()));
            i = end.min(bytes.len());
        } else if rest.starts_with(b"'") || rest.starts_with(b"b'") {
            // A char literal only: `'x'`, `'\n'`, `'\''`. A bare `'` starting
            // a lifetime (`'a`) is left alone (lifetimes carry no braces).
            let start = i + rest.starts_with(b"b'") as usize;
            let mut end = start + 1;
            if end < bytes.len() && bytes[end] == b'\\' {
                end += 2;
            } else if end < bytes.len() {
                end += 1;
            }
            if end < bytes.len() && bytes[end] == b'\'' {
                blank(&mut out, i, end + 1);
                i = end + 1;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).expect("blanking preserves UTF-8 boundaries")
}

/// Length of the raw string (`r"..."`, `r#"..."#`, `br"..."`) at the start of
/// `rest`, or `None` when `rest` does not start with one.
fn raw_string_len(rest: &[u8]) -> Option<usize> {
    let mut i = 0;
    if rest.first() == Some(&b'b') {
        i += 1;
    }
    if rest.get(i) != Some(&b'r') {
        return None;
    }
    i += 1;
    let mut hashes = 0;
    while rest.get(i) == Some(&b'#') {
        hashes += 1;
        i += 1;
    }
    if rest.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    while i < rest.len() {
        if rest[i] == b'"' && rest[i + 1..].starts_with(&vec![b'#'; hashes]) {
            return Some(i + 1 + hashes);
        }
        i += 1;
    }
    Some(rest.len())
}

#[test]
fn catch_panics_gate_trips_on_balanced_but_misplaced_calls() {
    // W1-L10-13 negative control: per-file fn-vs-call counts miss an ungated
    // export when a stray `catch_panics(` elsewhere in the file balances the
    // count (2 fns, 2 calls). Per-export attribution must name the ungated
    // export instead of passing.
    let balanced_but_ungated = "pub unsafe extern \"C\" fn c_gated() -> CK_RV {\n    catch_panics(|| {\n        CKR_OK as CK_RV\n    })\n}\nfn helper() {\n    catch_panics(|| {});\n}\npub unsafe extern \"C\" fn c_ungated() -> CK_RV {\n    CKR_OK as CK_RV\n}\n";
    let violation = catch_panics_violation("balanced.rs", balanced_but_ungated);
    assert!(
        violation.as_ref().is_some_and(|v| v.contains("c_ungated")),
        "gate must attribute the missing catch_panics to c_ungated, got {violation:?}"
    );
}

#[test]
fn catch_panics_gate_trips_on_ungated_export() {
    // W1-C7-02 negative control: a newly-added handler file with an un-gated
    // export must trip the gate. The old hardcoded file list missed new files
    // entirely; the whole-tree walk plus this per-file check closes that hole.
    let ungated = "pub unsafe extern \"C\" fn c_new_handler() -> CK_RV {\n    CKR_OK as CK_RV\n}\n";
    assert!(
        catch_panics_violation("new_handler.rs", ungated).is_some(),
        "gate must trip on a newly-added un-gated extern \"C\" export"
    );

    // A gated export passes.
    let gated = "pub unsafe extern \"C\" fn c_new_handler() -> CK_RV {\n    catch_panics(|| {\n        CKR_OK as CK_RV\n    })\n}\n";
    assert!(
        catch_panics_violation("new_handler.rs", gated).is_none(),
        "gate must pass a catch_panics-wrapped export"
    );

    // `c_not_supported` stubs stay exempt.
    let stub = "pub unsafe extern \"C\" fn c_not_supported() -> CK_RV {\n    CKR_FUNCTION_NOT_SUPPORTED as CK_RV\n}\n";
    assert!(
        catch_panics_violation("unsupported.rs", stub).is_none(),
        "gate must keep exempting c_not_supported stubs"
    );

    // A multi-line signature (C_GetInterfaceList shape) still attributes the
    // call inside its body.
    let multiline = "pub unsafe extern \"C\" fn c_multi(\n    a: usize,\n    b: usize,\n) -> CK_RV {\n    catch_panics(|| {\n        CKR_OK as CK_RV\n    })\n}\n";
    assert!(
        catch_panics_violation("multi.rs", multiline).is_none(),
        "gate must follow multi-line signatures into the export body"
    );

    // A comment or string literal mentioning catch_panics does not satisfy
    // the export: only a real call in the body counts.
    let mentioned = "pub unsafe extern \"C\" fn c_mentioned() -> CK_RV {\n    // TODO: wrap this in catch_panics(\n    let _ = \"catch_panics(\";\n    CKR_OK as CK_RV\n}\n";
    assert!(
        catch_panics_violation("mentioned.rs", mentioned)
            .as_ref()
            .is_some_and(|v| v.contains("c_mentioned")),
        "gate must not accept a commented-out or string-literal mention"
    );

    // A stray call in a helper between two exports satisfies neither.
    let helper_only = "pub unsafe extern \"C\" fn c_first() -> CK_RV {\n    helper()\n}\nfn helper() -> CK_RV {\n    catch_panics(|| CKR_OK as CK_RV)\n}\npub unsafe extern \"C\" fn c_second() -> CK_RV {\n    helper()\n}\n";
    let both: Vec<String> =
        ungated_exports(helper_only).into_iter().map(|(name, _)| name).collect();
    assert_eq!(
        both,
        vec!["c_first".to_string(), "c_second".to_string()],
        "a helper-owned call must leave both exports ungated"
    );

    // The walk itself must cover the whole tree: a nested helper file (never
    // in the old hardcoded list) and the crate root must both be visited.
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    assert!(
        files.iter().any(|p| p.ends_with("helpers/message_params.rs")),
        "whole-tree walk must reach nested dispatch helpers"
    );
    assert!(
        files.iter().any(|p| p.ends_with("src/lib.rs")),
        "whole-tree walk must reach the crate root"
    );
}

/// Pinned count of non-stub `extern "C"` exports. Bumped only together with a
/// new row in `per_export_runtime_panic_boundary` (the source-walk set check
/// below fails otherwise, so a new export cannot silently dodge the test).
const EXPECTED_NON_STUB_EXPORT_COUNT: usize = 104;

/// RAII arming of the thread-local panic injection flag: enables on creation,
/// disables on drop — including drops during unwinding, so a boundary
/// violation can never leak an armed flag into a later export.
struct PanicInjectGuard;

impl PanicInjectGuard {
    fn arm() -> Self {
        dispatch::general::helpers::set_panic_inject_for_test(true);
        PanicInjectGuard
    }
}

impl Drop for PanicInjectGuard {
    fn drop(&mut self) {
        dispatch::general::helpers::set_panic_inject_for_test(false);
    }
}

/// Invoke one export with panic injection armed and verify the real `extern
/// "C"` boundary held: the call must return (no unwind escaped — the process
/// is alive to run the next export) with `CKR_GENERAL_ERROR`, which proves a
/// panic fired inside the export and `catch_panics` converted it. Returns the
/// violation description otherwise.
fn check_export_catches_panic(name: &str, invoke: fn() -> CK_RV) -> Result<(), String> {
    let _armed = PanicInjectGuard::arm();
    // The test-side `catch_unwind` only OBSERVES an escaping unwind so it can
    // be reported as a boundary violation; it never masks one.
    match std::panic::catch_unwind(invoke) {
        Ok(rv) => {
            if rv == CKR_GENERAL_ERROR as CK_RV {
                Ok(())
            } else {
                Err(format!(
                    "{name}: returned {rv:#x} under injected panic, expected CKR_GENERAL_ERROR \
                     (panic not routed through catch_panics)"
                ))
            }
        }
        Err(_) => Err(format!("{name}: panic unwound across the extern \"C\" boundary")),
    }
}

#[test]
fn per_export_runtime_panic_boundary() {
    // W1-C7-04: every non-stub export must survive a forced panic inside
    // without unwinding across the real `extern "C"` boundary. Injection fires
    // at the top of `catch_panics`, before any export body reads its arguments,
    // so all-null/zero dummy args are never dereferenced.
    let _guard = shim_state_test_guard();
    type PanicCase<'a> = (&'a str, fn() -> CK_RV);
    let cases: Vec<PanicCase<'_>> = vec![
        ("c_init_token", || unsafe {
            dispatch::general::c_init_token(0, std::ptr::null_mut(), 0, std::ptr::null_mut())
        }),
        ("c_init_pin", || unsafe { dispatch::general::c_init_pin(0, std::ptr::null_mut(), 0) }),
        ("c_set_pin", || unsafe {
            dispatch::general::c_set_pin(0, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0)
        }),
        ("c_async_complete", || unsafe {
            dispatch::general::c_async_complete(0, std::ptr::null_mut(), std::ptr::null_mut())
        }),
        ("c_async_get_id", || unsafe {
            dispatch::general::c_async_get_id(0, std::ptr::null_mut(), std::ptr::null_mut())
        }),
        ("c_async_join", || unsafe {
            dispatch::general::c_async_join(0, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0)
        }),
        ("c_wrap_key_authenticated", || unsafe {
            dispatch::general::c_wrap_key_authenticated(
                0,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_unwrap_key_authenticated", || unsafe {
            dispatch::general::c_unwrap_key_authenticated(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            )
        }),
        ("c_digest_encrypt_update", || unsafe {
            dispatch::general::c_digest_encrypt_update(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_decrypt_digest_update", || unsafe {
            dispatch::general::c_decrypt_digest_update(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_sign_encrypt_update", || unsafe {
            dispatch::general::c_sign_encrypt_update(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_decrypt_verify_update", || unsafe {
            dispatch::general::c_decrypt_verify_update(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_digest_init", || unsafe { dispatch::general::c_digest_init(0, std::ptr::null_mut()) }),
        ("c_digest", || unsafe {
            dispatch::general::c_digest(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_digest_update", || unsafe {
            dispatch::general::c_digest_update(0, std::ptr::null_mut(), 0)
        }),
        ("c_digest_key", || unsafe { dispatch::general::c_digest_key(0, 0) }),
        ("c_digest_final", || unsafe {
            dispatch::general::c_digest_final(0, std::ptr::null_mut(), std::ptr::null_mut())
        }),
        ("c_encrypt_init", || unsafe {
            dispatch::general::c_encrypt_init(0, std::ptr::null_mut(), 0)
        }),
        ("c_encrypt", || unsafe {
            dispatch::general::c_encrypt(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_encrypt_update", || unsafe {
            dispatch::general::c_encrypt_update(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_encrypt_final", || unsafe {
            dispatch::general::c_encrypt_final(0, std::ptr::null_mut(), std::ptr::null_mut())
        }),
        ("c_decrypt_init", || unsafe {
            dispatch::general::c_decrypt_init(0, std::ptr::null_mut(), 0)
        }),
        ("c_decrypt", || unsafe {
            dispatch::general::c_decrypt(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_decrypt_update", || unsafe {
            dispatch::general::c_decrypt_update(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_decrypt_final", || unsafe {
            dispatch::general::c_decrypt_final(0, std::ptr::null_mut(), std::ptr::null_mut())
        }),
        ("c_initialize", || unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) }),
        ("c_finalize", || unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) }),
        ("c_get_info", || unsafe { dispatch::general::c_get_info(std::ptr::null_mut()) }),
        ("c_encapsulate_key", || unsafe {
            dispatch::general::c_encapsulate_key(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_decapsulate_key", || unsafe {
            dispatch::general::c_decapsulate_key(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            )
        }),
        ("c_wrap_key", || unsafe {
            dispatch::general::c_wrap_key(
                0,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_unwrap_key", || unsafe {
            dispatch::general::c_unwrap_key(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            )
        }),
        ("c_derive_key", || unsafe {
            dispatch::general::c_derive_key(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            )
        }),
        ("c_generate_key", || unsafe {
            dispatch::general::c_generate_key(
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            )
        }),
        ("c_generate_key_pair", || unsafe {
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
        }),
        ("c_seed_random", || unsafe {
            dispatch::general::c_seed_random(0, std::ptr::null_mut(), 0)
        }),
        ("c_generate_random", || unsafe {
            dispatch::general::c_generate_random(0, std::ptr::null_mut(), 0)
        }),
        ("c_message_encrypt_init", || unsafe {
            dispatch::general::c_message_encrypt_init(0, std::ptr::null_mut(), 0)
        }),
        ("c_message_encrypt_final", || unsafe { dispatch::general::c_message_encrypt_final(0) }),
        ("c_message_decrypt_init", || unsafe {
            dispatch::general::c_message_decrypt_init(0, std::ptr::null_mut(), 0)
        }),
        ("c_message_decrypt_final", || unsafe { dispatch::general::c_message_decrypt_final(0) }),
        ("c_message_sign_init", || unsafe {
            dispatch::general::c_message_sign_init(0, std::ptr::null_mut(), 0)
        }),
        ("c_message_sign_final", || unsafe { dispatch::general::c_message_sign_final(0) }),
        ("c_message_verify_init", || unsafe {
            dispatch::general::c_message_verify_init(0, std::ptr::null_mut(), 0)
        }),
        ("c_message_verify_final", || unsafe { dispatch::general::c_message_verify_final(0) }),
        ("c_encrypt_message", || unsafe {
            dispatch::general::c_encrypt_message(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_encrypt_message_begin", || unsafe {
            dispatch::general::c_encrypt_message_begin(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
            )
        }),
        ("c_encrypt_message_next", || unsafe {
            dispatch::general::c_encrypt_message_next(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        }),
        ("c_decrypt_message", || unsafe {
            dispatch::general::c_decrypt_message(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_decrypt_message_begin", || unsafe {
            dispatch::general::c_decrypt_message_begin(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
            )
        }),
        ("c_decrypt_message_next", || unsafe {
            dispatch::general::c_decrypt_message_next(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        }),
        ("c_sign_message", || unsafe {
            dispatch::general::c_sign_message(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_sign_message_begin", || unsafe {
            dispatch::general::c_sign_message_begin(0, std::ptr::null_mut(), 0)
        }),
        ("c_sign_message_next", || unsafe {
            dispatch::general::c_sign_message_next(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_verify_message", || unsafe {
            dispatch::general::c_verify_message(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
            )
        }),
        ("c_verify_message_begin", || unsafe {
            dispatch::general::c_verify_message_begin(0, std::ptr::null_mut(), 0)
        }),
        ("c_verify_message_next", || unsafe {
            dispatch::general::c_verify_message_next(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
            )
        }),
        ("c_find_objects_init", || unsafe {
            dispatch::general::c_find_objects_init(0, std::ptr::null_mut(), 0)
        }),
        ("c_find_objects", || unsafe {
            dispatch::general::c_find_objects(0, std::ptr::null_mut(), 0, std::ptr::null_mut())
        }),
        ("c_find_objects_final", || unsafe { dispatch::general::c_find_objects_final(0) }),
        ("c_get_attribute_value", || unsafe {
            dispatch::general::c_get_attribute_value(0, 0, std::ptr::null_mut(), 0)
        }),
        ("c_create_object", || unsafe {
            dispatch::general::c_create_object(0, std::ptr::null_mut(), 0, std::ptr::null_mut())
        }),
        ("c_copy_object", || unsafe {
            dispatch::general::c_copy_object(0, 0, std::ptr::null_mut(), 0, std::ptr::null_mut())
        }),
        ("c_destroy_object", || unsafe { dispatch::general::c_destroy_object(0, 0) }),
        ("c_get_object_size", || unsafe {
            dispatch::general::c_get_object_size(0, 0, std::ptr::null_mut())
        }),
        ("c_set_attribute_value", || unsafe {
            dispatch::general::c_set_attribute_value(0, 0, std::ptr::null_mut(), 0)
        }),
        ("c_open_session", || unsafe {
            dispatch::general::c_open_session(
                0,
                0,
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        }),
        ("c_close_session", || unsafe { dispatch::general::c_close_session(0) }),
        ("c_close_all_sessions", || unsafe { dispatch::general::c_close_all_sessions(0) }),
        ("c_get_session_info", || unsafe {
            dispatch::general::c_get_session_info(0, std::ptr::null_mut())
        }),
        ("c_login", || unsafe { dispatch::general::c_login(0, 0, std::ptr::null_mut(), 0) }),
        ("c_logout", || unsafe { dispatch::general::c_logout(0) }),
        ("c_get_function_status", || unsafe { dispatch::general::c_get_function_status(0) }),
        ("c_cancel_function", || unsafe { dispatch::general::c_cancel_function(0) }),
        ("c_login_user", || unsafe {
            dispatch::general::c_login_user(0, 0, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0)
        }),
        ("c_session_cancel", || unsafe { dispatch::general::c_session_cancel(0, 0) }),
        ("c_get_session_validation_flags", || unsafe {
            dispatch::general::c_get_session_validation_flags(0, 0, std::ptr::null_mut())
        }),
        ("c_sign_init", || unsafe { dispatch::general::c_sign_init(0, std::ptr::null_mut(), 0) }),
        ("c_sign", || unsafe {
            dispatch::general::c_sign(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_sign_update", || unsafe {
            dispatch::general::c_sign_update(0, std::ptr::null_mut(), 0)
        }),
        ("c_sign_final", || unsafe {
            dispatch::general::c_sign_final(0, std::ptr::null_mut(), std::ptr::null_mut())
        }),
        ("c_verify_init", || unsafe {
            dispatch::general::c_verify_init(0, std::ptr::null_mut(), 0)
        }),
        ("c_verify", || unsafe {
            dispatch::general::c_verify(0, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0)
        }),
        ("c_verify_update", || unsafe {
            dispatch::general::c_verify_update(0, std::ptr::null_mut(), 0)
        }),
        ("c_verify_final", || unsafe {
            dispatch::general::c_verify_final(0, std::ptr::null_mut(), 0)
        }),
        ("c_sign_recover_init", || unsafe {
            dispatch::general::c_sign_recover_init(0, std::ptr::null_mut(), 0)
        }),
        ("c_sign_recover", || unsafe {
            dispatch::general::c_sign_recover(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_verify_recover_init", || unsafe {
            dispatch::general::c_verify_recover_init(0, std::ptr::null_mut(), 0)
        }),
        ("c_verify_recover", || unsafe {
            dispatch::general::c_verify_recover(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }),
        ("c_get_slot_list", || unsafe {
            dispatch::general::c_get_slot_list(0, std::ptr::null_mut(), std::ptr::null_mut())
        }),
        ("c_get_slot_info", || unsafe {
            dispatch::general::c_get_slot_info(0, std::ptr::null_mut())
        }),
        ("c_get_token_info", || unsafe {
            dispatch::general::c_get_token_info(0, std::ptr::null_mut())
        }),
        ("c_get_mechanism_list", || unsafe {
            dispatch::general::c_get_mechanism_list(0, std::ptr::null_mut(), std::ptr::null_mut())
        }),
        ("c_get_mechanism_info", || unsafe {
            dispatch::general::c_get_mechanism_info(0, 0, std::ptr::null_mut())
        }),
        ("c_wait_for_slot_event", || unsafe {
            dispatch::general::c_wait_for_slot_event(0, std::ptr::null_mut(), std::ptr::null_mut())
        }),
        ("c_get_operation_state", || unsafe {
            dispatch::general::c_get_operation_state(0, std::ptr::null_mut(), std::ptr::null_mut())
        }),
        ("c_set_operation_state", || unsafe {
            dispatch::general::c_set_operation_state(0, std::ptr::null_mut(), 0, 0, 0)
        }),
        ("c_verify_signature_init", || unsafe {
            dispatch::general::c_verify_signature_init(
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
            )
        }),
        ("c_verify_signature", || unsafe {
            dispatch::general::c_verify_signature(0, std::ptr::null_mut(), 0)
        }),
        ("c_verify_signature_update", || unsafe {
            dispatch::general::c_verify_signature_update(0, std::ptr::null_mut(), 0)
        }),
        ("c_verify_signature_final", || unsafe { dispatch::general::c_verify_signature_final(0) }),
        ("C_GetFunctionList", || unsafe { C_GetFunctionList(std::ptr::null_mut()) }),
        ("C_GetInterfaceList", || unsafe {
            C_GetInterfaceList(std::ptr::null_mut(), std::ptr::null_mut())
        }),
        ("C_GetInterface", || unsafe {
            C_GetInterface(std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), 0)
        }),
    ];

    // No silent omission: the table must name every non-stub export defined in
    // the source tree, exactly (both directions), and match the pinned count.
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let tests_dir = src_dir.join("tests");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    files.retain(|p| !p.starts_with(&tests_dir));
    let mut defined: Vec<String> = files
        .iter()
        .map(|p| std::fs::read_to_string(p).expect("read shim source"))
        .flat_map(|src| source_export_names(&src))
        .collect();
    defined.sort();
    let mut tabled: Vec<String> = cases.iter().map(|(name, _)| name.to_string()).collect();
    tabled.sort();
    assert_eq!(tabled, defined, "panic table must cover every non-stub export exactly");
    assert_eq!(
        cases.len(),
        EXPECTED_NON_STUB_EXPORT_COUNT,
        "pinned export count must match the table"
    );

    // Run every export under injection; collect all violations for one report.
    let mut failures = Vec::new();
    for (name, invoke) in &cases {
        if let Err(violation) = check_export_catches_panic(name, *invoke) {
            failures.push(violation);
        }
    }
    // The process reaching this assert proves it survived every injected panic.
    assert!(failures.is_empty(), "per-export panic boundary violations:\n{}", failures.join("\n"));
}

#[test]
fn panic_gate_trips_on_unwrapped_export() {
    // W1-C7-04 negative control: the checker must fail an export that panics
    // without `catch_panics` (unwind escapes) and one that never panics at all
    // (wrong RV — proves the main test is not vacuous).
    let _guard = shim_state_test_guard();

    fn unwrapped_panicking() -> CK_RV {
        if crate::dispatch::general::helpers::panic_inject_enabled_for_test() {
            panic!("simulated inner panic in an un-wrapped export");
        }
        CKR_OK as CK_RV
    }
    let err = check_export_catches_panic("unwrapped_fixture", unwrapped_panicking)
        .expect_err("gate must fail an un-wrapped export that panics");
    assert!(err.contains("unwound across"), "unexpected violation text: {err}");

    fn unwrapped_quiet() -> CK_RV {
        CKR_OK as CK_RV
    }
    let err = check_export_catches_panic("quiet_fixture", unwrapped_quiet)
        .expect_err("gate must fail an export that never panics");
    assert!(err.contains("expected CKR_GENERAL_ERROR"), "unexpected violation text: {err}");
}

/// Non-stub `extern "C"` export names defined in one source file (same
/// stub-exemption rule as `catch_panics_counts`: `c_not_supported*` only).
fn source_export_names(src: &str) -> Vec<String> {
    src.lines()
        .filter(|line| {
            line.contains("pub unsafe extern \"C\" fn") && !line.contains("c_not_supported")
        })
        .filter_map(|line| {
            let after_fn = line.split("fn ").nth(1)?;
            let name = after_fn.split('(').next()?.trim();
            if name.is_empty() { None } else { Some(name.to_string()) }
        })
        .collect()
}

#[test]
fn shim_source_never_formats_pin_data() {
    // H5: walk the WHOLE dispatch tree (not a hardcoded file list) so a new
    // handler cannot slip PIN logging past this gate, and broaden the patterns.
    let dispatch_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/dispatch");
    let mut files = Vec::new();
    collect_rs_files(&dispatch_dir, &mut files);
    assert!(!files.is_empty(), "no dispatch sources found under {}", dispatch_dir.display());

    // Identifiers whose VALUE is secret. The bare names are legitimate to use
    // (read from a pointer, pass to the client); only *logging* their value leaks.
    const SECRET_IDENTS: &[&str] = &["pin", "so_pin", "new_pin", "old_pin", "password"];
    // Debug/print sinks that would dump any value they are given.
    const DEBUG_SINKS: &[&str] = &["dbg!(", "{:?}", "{:#?}", "println!", "eprintln!"];

    for path in &files {
        let src = std::fs::read_to_string(path).expect("read dispatch source");
        // A file "handles a secret" if it binds/uses a secret identifier as a
        // whole token — only there do Debug sinks risk dumping a PIN.
        let handles_secret = SECRET_IDENTS.iter().any(|id| contains_ident_token(&src, id));

        for (lineno, line) in src.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            let where_ = format!("{}:{}", path.display(), lineno + 1);

            // Tracing field captures / interpolation of a secret value
            // (`?pin`, `%pin`, `{pin}`) leak in ANY macro — info!/trace!/etc.
            for id in SECRET_IDENTS {
                assert!(
                    !logs_secret_sigil(trimmed, id),
                    "{where_}: logs the value of secret '{id}' (?/%/{{}} capture): {trimmed}",
                );
            }
            if handles_secret {
                for sink in DEBUG_SINKS {
                    assert!(
                        !trimmed.contains(sink),
                        "{where_}: Debug/print sink '{sink}' in a secret-handling file may dump a \
                         PIN: {trimmed}",
                    );
                }
            }
        }
    }
}

#[test]
fn pin_gate_trips_on_debug_format_sigil() {
    // W1-C7-03 negative control: Debug-format interpolation of a secret
    // (`{pin:?}`) leaks the value just like `{pin}`; the gate must trip on
    // it for every secret ident.
    for id in ["pin", "so_pin", "new_pin", "old_pin", "password"] {
        assert!(
            logs_secret_sigil(&format!("info!(\"v={{{id}:?}}\")"), id),
            "gate must trip on Debug-format sigil {{{id}:?}}",
        );
        assert!(
            logs_secret_sigil(&format!("info!(\"v={{{id}:#?}}\")"), id),
            "gate must trip on alternate Debug sigil {{{id}:#?}}",
        );
        assert!(
            logs_secret_sigil(&format!("info!(\"v={{{id}}}\")"), id),
            "gate must keep tripping on Display sigil {{{id}}}",
        );
    }

    // Clean code passes: secret-adjacent lines without value capture.
    assert!(!logs_secret_sigil("let pin = read_pin_ptr(p_pin, pin_len);", "pin"));
    assert!(!logs_secret_sigil("info!(\"pin len={}\", pin.len());", "pin"));
    // A longer identifier sharing the prefix must not trip.
    assert!(!logs_secret_sigil("info!(\"{pin_hash}\");", "pin"));
}

/// Recursively collect `.rs` files under `dir`.
fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// True if `ident` appears in `text` as a whole token (not as a substring of a
/// larger identifier such as `pin_hash` or `spinning`).
fn contains_ident_token(text: &str, ident: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(rel) = text[from..].find(ident) {
        let start = from + rel;
        let end = start + ident.len();
        let before_ok = start == 0 || !is_ident_char(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_ident_char(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// True if `line` captures the value of `ident` via a tracing sigil (`?ident`,
/// `%ident`) or interpolates it (`{ident}`, `{ident:?}`, `{ident:#?}`, or any
/// other `{ident:...}` format spec), with `ident` as a whole token.
fn logs_secret_sigil(line: &str, ident: &str) -> bool {
    let bytes = line.as_bytes();
    for sigil in ['?', '%'] {
        let pat = format!("{sigil}{ident}");
        let mut from = 0;
        while let Some(rel) = line[from..].find(&pat) {
            let start = from + rel;
            let end = start + pat.len();
            if end >= bytes.len() || !is_ident_char(bytes[end]) {
                return true;
            }
            from = start + 1;
        }
    }
    // Inline-format interpolation: `{ident}` and any `{ident:...}` spec (all
    // evaluate the secret — Display and every Debug/width/precision form).
    // The char after the ident must close or continue the spec (`}`/`:`) so
    // a longer identifier such as `{pin_hash}` does not trip for `pin`.
    let open_pat = format!("{{{ident}");
    let mut from = 0;
    while let Some(rel) = line[from..].find(&open_pat) {
        let start = from + rel;
        let end = start + open_pat.len();
        if end < bytes.len() && (bytes[end] == b'}' || bytes[end] == b':') {
            return true;
        }
        from = start + 1;
    }
    false
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Code lines of a source file with `//` comments stripped (a commented
/// mention of an attribute or import is not one).
fn code_lines(src: &str) -> Vec<&str> {
    src.lines().map(|line| line.split("//").next().unwrap_or_default()).collect()
}

/// True when the file pairs `#[allow(unused_imports)]` with a glob import
/// (`use ...::*`), hiding unused names instead of importing explicitly.
fn has_allow_paired_glob(src: &str) -> bool {
    let code = code_lines(src);
    if !code.iter().any(|line| line.contains("allow(unused_imports)")) {
        return false;
    }
    code.iter().any(|line| {
        let rest =
            line.trim().strip_prefix("pub use ").or_else(|| line.trim().strip_prefix("use "));
        rest.is_some_and(|path| path.contains("::*"))
    })
}

#[test]
fn dispatch_has_no_allow_paired_glob_imports() {
    // W1-L12-05: every dispatch file imports explicitly — no
    // `use super::*` (or other glob) hiding behind
    // `#[allow(unused_imports)]`, and no such allow left anywhere in the
    // dispatch tree. The walk covers the whole tree so a reintroduced
    // pair in any file (old or new) trips.
    let dispatch_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/dispatch");
    let mut files = Vec::new();
    collect_rs_files(&dispatch_dir, &mut files);
    assert!(!files.is_empty(), "no dispatch sources found under {}", dispatch_dir.display());

    let mut paired = Vec::new();
    let mut bare_allows = Vec::new();
    for path in &files {
        let src = std::fs::read_to_string(path).expect("read dispatch source");
        if has_allow_paired_glob(&src) {
            paired.push(path.display().to_string());
        } else if code_lines(&src).iter().any(|line| line.contains("allow(unused_imports)")) {
            bare_allows.push(path.display().to_string());
        }
    }
    assert!(
        paired.is_empty(),
        "allow(unused_imports)-paired glob imports remain in dispatch (W1-L12-05): {paired:?}"
    );
    assert!(
        bare_allows.is_empty(),
        "bare allow(unused_imports) remains in dispatch (W1-L12-05 hygiene): {bare_allows:?}"
    );
}

#[test]
fn import_gate_trips_on_allow_paired_glob() {
    // W1-L12-05 negative control: the exact pre-fix shape must trip.
    assert!(has_allow_paired_glob(
        "#[allow(unused_imports)]\nuse super::*;\nfn f() { helper(); }\n"
    ));
    assert!(has_allow_paired_glob("#[allow(unused_imports)]\npub use unsupported::*;\n"));
    // A glob without the allow is not this gate's target (other globs
    // such as `use super::helpers::*;` are out of scope for W1-L12-05).
    assert!(!has_allow_paired_glob("use super::helpers::*;\nfn f() { helper(); }\n"));
    // Explicit imports pass, with or without an unrelated allow nearby.
    assert!(!has_allow_paired_glob("use super::helpers::{a, b};\nfn f() { a(); b(); }\n"));
    // A commented-out glob is not an import.
    assert!(!has_allow_paired_glob("#[allow(unused_imports)]\n// use super::*;\nfn f() {}\n"));
    // A commented mention of the allow next to a real glob is not a pair
    // (the mod.rs justification comment shape).
    assert!(!has_allow_paired_glob(
        "// Scoped instead of #[allow(unused_imports)] so no pair remains.\n\
         #[cfg(test)]\npub use unsupported::*;\n"
    ));
}

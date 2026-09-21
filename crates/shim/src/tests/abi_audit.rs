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

#[test]
fn ck_attribute_layout() {
    let expected = std::mem::size_of::<CK_ULONG>()
        + std::mem::size_of::<*mut std::os::raw::c_void>()
        + std::mem::size_of::<CK_ULONG>();
    assert_eq!(std::mem::size_of::<CK_ATTRIBUTE>(), expected);
}

#[test]
fn ck_mechanism_layout() {
    let expected = std::mem::size_of::<CK_ULONG>()
        + std::mem::size_of::<*mut std::os::raw::c_void>()
        + std::mem::size_of::<CK_ULONG>();
    assert_eq!(std::mem::size_of::<CK_MECHANISM>(), expected);
}

#[test]
fn ck_interface_layout() {
    let expected = std::mem::size_of::<*mut CK_UTF8CHAR>()
        + std::mem::size_of::<*mut std::os::raw::c_void>()
        + std::mem::size_of::<CK_ULONG>();
    assert_eq!(std::mem::size_of::<CK_INTERFACE>(), expected);
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
        if catch_panics_counts(&src).is_some() {
            checked += 1;
        }
    }
    assert!(checked > 0, "gate must cover at least one export file");
}

/// Per-file `catch_panics` check shared by the gate and its negative control.
/// Returns `None` when the file defines no exports or every non-stub export
/// is wrapped; otherwise a human-readable violation.
fn catch_panics_violation(name: &str, src: &str) -> Option<String> {
    let (real_fns, catch_calls) = catch_panics_counts(src)?;
    if real_fns == catch_calls {
        None
    } else {
        Some(format!(
            "{name}: every non-stub extern \"C\" fn must use catch_panics \
             ({real_fns} real fns, {catch_calls} catch_panics calls)"
        ))
    }
}

/// Count non-stub `pub unsafe extern "C"` exports and `catch_panics(` calls in
/// one source file. Returns `None` when the file defines no exports (nothing
/// for the gate to check — e.g. the `catch_panics` definition site and its
/// unit tests); otherwise `Some((exports, calls))`.
fn catch_panics_counts(src: &str) -> Option<(usize, usize)> {
    let real_fns = src
        .lines()
        .filter(|line| {
            line.contains("pub unsafe extern \"C\" fn") && !line.contains("c_not_supported")
        })
        .count();
    if real_fns == 0 {
        return None;
    }
    let catch_calls = src.matches("catch_panics(").count();
    Some((real_fns, catch_calls))
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
/// `%ident`) or interpolates it (`{ident}`), with `ident` as a whole token.
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
    line.contains(&format!("{{{ident}}}"))
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

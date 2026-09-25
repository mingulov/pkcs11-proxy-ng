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
    assert!(fl.C_Initialize.is_some(), "C_Initialize must be non-null");
    assert!(fl.C_Finalize.is_some(), "C_Finalize must be non-null");
    assert!(fl.C_GetInfo.is_some(), "C_GetInfo must be non-null");
    assert!(fl.C_GetSlotList.is_some(), "C_GetSlotList must be non-null");
    assert!(fl.C_GetSlotInfo.is_some(), "C_GetSlotInfo must be non-null");
    assert!(fl.C_GetTokenInfo.is_some(), "C_GetTokenInfo must be non-null");
    assert!(fl.C_GetMechanismList.is_some(), "C_GetMechanismList must be non-null");
    assert!(fl.C_GetMechanismInfo.is_some(), "C_GetMechanismInfo must be non-null");
    assert!(fl.C_OpenSession.is_some(), "C_OpenSession must be non-null");
    assert!(fl.C_CloseSession.is_some(), "C_CloseSession must be non-null");
    assert!(fl.C_CloseAllSessions.is_some(), "C_CloseAllSessions must be non-null");
    assert!(fl.C_GetSessionInfo.is_some(), "C_GetSessionInfo must be non-null");
    assert!(fl.C_Login.is_some(), "C_Login must be non-null");
    assert!(fl.C_Logout.is_some(), "C_Logout must be non-null");
    assert!(fl.C_InitToken.is_some(), "C_InitToken must be non-null");
    assert!(fl.C_InitPIN.is_some(), "C_InitPIN must be non-null");
    assert!(fl.C_SetPIN.is_some(), "C_SetPIN must be non-null");
    assert!(fl.C_FindObjectsInit.is_some(), "C_FindObjectsInit must be non-null");
    assert!(fl.C_FindObjects.is_some(), "C_FindObjects must be non-null");
    assert!(fl.C_FindObjectsFinal.is_some(), "C_FindObjectsFinal must be non-null");
    assert!(fl.C_GetAttributeValue.is_some(), "C_GetAttributeValue must be non-null");
    assert!(fl.C_SetAttributeValue.is_some(), "C_SetAttributeValue must be non-null");
    assert!(fl.C_SignInit.is_some(), "C_SignInit must be non-null");
    assert!(fl.C_Sign.is_some(), "C_Sign must be non-null");
    assert!(fl.C_SignUpdate.is_some(), "C_SignUpdate must be non-null");
    assert!(fl.C_SignFinal.is_some(), "C_SignFinal must be non-null");
    assert!(fl.C_VerifyInit.is_some(), "C_VerifyInit must be non-null");
    assert!(fl.C_Verify.is_some(), "C_Verify must be non-null");
    assert!(fl.C_VerifyUpdate.is_some(), "C_VerifyUpdate must be non-null");
    assert!(fl.C_VerifyFinal.is_some(), "C_VerifyFinal must be non-null");
    assert!(fl.C_EncryptInit.is_some(), "C_EncryptInit must be non-null");
    assert!(fl.C_Encrypt.is_some(), "C_Encrypt must be non-null");
    assert!(fl.C_EncryptUpdate.is_some(), "C_EncryptUpdate must be non-null");
    assert!(fl.C_EncryptFinal.is_some(), "C_EncryptFinal must be non-null");
    assert!(fl.C_DecryptInit.is_some(), "C_DecryptInit must be non-null");
    assert!(fl.C_Decrypt.is_some(), "C_Decrypt must be non-null");
    assert!(fl.C_DecryptUpdate.is_some(), "C_DecryptUpdate must be non-null");
    assert!(fl.C_DecryptFinal.is_some(), "C_DecryptFinal must be non-null");
    assert!(fl.C_DigestInit.is_some(), "C_DigestInit must be non-null");
    assert!(fl.C_Digest.is_some(), "C_Digest must be non-null");
    assert!(fl.C_DigestUpdate.is_some(), "C_DigestUpdate must be non-null");
    assert!(fl.C_DigestKey.is_some(), "C_DigestKey must be non-null");
    assert!(fl.C_DigestFinal.is_some(), "C_DigestFinal must be non-null");
    assert!(fl.C_GenerateKey.is_some(), "C_GenerateKey must be non-null");
    assert!(fl.C_GenerateKeyPair.is_some(), "C_GenerateKeyPair must be non-null");
    assert!(fl.C_GenerateRandom.is_some(), "C_GenerateRandom must be non-null");
    assert!(fl.C_SeedRandom.is_some(), "C_SeedRandom must be non-null");
    assert!(fl.C_CreateObject.is_some(), "C_CreateObject must be non-null");
    assert!(fl.C_CopyObject.is_some(), "C_CopyObject must be non-null");
    assert!(fl.C_DestroyObject.is_some(), "C_DestroyObject must be non-null");
    assert!(fl.C_GetObjectSize.is_some(), "C_GetObjectSize must be non-null");
    assert!(fl.C_WrapKey.is_some(), "C_WrapKey must be non-null");
    assert!(fl.C_UnwrapKey.is_some(), "C_UnwrapKey must be non-null");
    assert!(fl.C_DeriveKey.is_some(), "C_DeriveKey must be non-null");
    assert!(fl.C_WaitForSlotEvent.is_some(), "C_WaitForSlotEvent must be non-null");
    assert!(fl.C_GetOperationState.is_some(), "C_GetOperationState must be non-null");
    assert!(fl.C_SetOperationState.is_some(), "C_SetOperationState must be non-null");
    assert!(fl.C_SignRecoverInit.is_some(), "C_SignRecoverInit must be non-null");
    assert!(fl.C_SignRecover.is_some(), "C_SignRecover must be non-null");
    assert!(fl.C_VerifyRecoverInit.is_some(), "C_VerifyRecoverInit must be non-null");
    assert!(fl.C_VerifyRecover.is_some(), "C_VerifyRecover must be non-null");
}

#[test]
fn catch_panics_source_coverage() {
    let shim_export_files: &[(&str, &str)] = &[
        ("lib.rs", include_str!("../lib.rs")),
        ("admin.rs", include_str!("../dispatch/general/admin.rs")),
        ("async_ops.rs", include_str!("../dispatch/general/async_ops.rs")),
        ("authenticated_wrap.rs", include_str!("../dispatch/general/authenticated_wrap.rs")),
        ("combined.rs", include_str!("../dispatch/general/combined.rs")),
        ("digest_cipher.rs", include_str!("../dispatch/general/digest_cipher.rs")),
        ("init_general.rs", include_str!("../dispatch/general/init_general.rs")),
        ("kem.rs", include_str!("../dispatch/general/kem.rs")),
        ("key_ops.rs", include_str!("../dispatch/general/key_ops.rs")),
        ("message_crypto.rs", include_str!("../dispatch/general/message_crypto.rs")),
        ("object.rs", include_str!("../dispatch/general/object.rs")),
        ("session.rs", include_str!("../dispatch/general/session.rs")),
        ("session_3x.rs", include_str!("../dispatch/general/session_3x.rs")),
        ("sign_verify.rs", include_str!("../dispatch/general/sign_verify.rs")),
        ("slot.rs", include_str!("../dispatch/general/slot.rs")),
        ("state_ops.rs", include_str!("../dispatch/general/state_ops.rs")),
        ("unsupported.rs", include_str!("../dispatch/general/unsupported.rs")),
        ("verify_signature.rs", include_str!("../dispatch/general/verify_signature.rs")),
    ];

    for (name, src) in shim_export_files {
        let real_fns: Vec<&str> = src
            .lines()
            .filter(|line| {
                line.contains("pub unsafe extern \"C\" fn") && !line.contains("c_not_supported")
            })
            .collect();

        let catch_calls = src.matches("catch_panics(").count();
        assert_eq!(
            real_fns.len(),
            catch_calls,
            "{name}: every non-stub extern \"C\" fn must use catch_panics \
             ({} real fns, {} catch_panics calls)",
            real_fns.len(),
            catch_calls
        );
    }
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

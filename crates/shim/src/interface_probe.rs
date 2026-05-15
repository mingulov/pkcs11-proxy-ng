//! Dynamic interface probe — queries the backend for interface capabilities
//! and caches patched function lists that NULL-out functions the backend
//! does not support.
//!
//! The probe is lazy: `ensure_probed()` runs the RPC at most once until
//! `clear_cache()` or `reprobe()` is called. Pre-`C_Initialize` callers
//! get the static (all-non-null) function lists; post-`C_Initialize`
//! callers get the patched versions.

use std::sync::RwLock;

use cryptoki_sys::*;

use crate::function_registry::{build_function_list, build_function_list_3_x};
use crate::state;

// ---------------------------------------------------------------------------
// Cached state
// ---------------------------------------------------------------------------

/// Holds the probed function lists and the interface catalog built from them.
struct InterfaceState {
    fl_2_40: CK_FUNCTION_LIST,
    fl_3_0: CK_FUNCTION_LIST_3_0,
    fl_3_2: CK_FUNCTION_LIST_3_2,
    catalog: [CK_INTERFACE; 3],
    /// Number of interfaces the backend actually supports (1, 2, or 3).
    count: CK_ULONG,
    /// Whether the backend reported a 3.0-compatible interface.
    has_3_0: bool,
    /// Whether the backend reported a 3.2-compatible interface.
    has_3_2: bool,
}

// CK_INTERFACE contains raw pointers that are always to `'static` memory
// owned by this module, so Send + Sync are safe.
unsafe impl Send for InterfaceState {}
unsafe impl Sync for InterfaceState {}

static INTERFACE_STATE: RwLock<Option<&'static InterfaceState>> = RwLock::new(None);

/// Null-terminated name used for all interface entries.
static IFACE_NAME_PKCS11: &[u8] = b"PKCS 11\0";

// ---------------------------------------------------------------------------
// Building unpatched function lists (delegates to existing macros)
// ---------------------------------------------------------------------------

fn build_base_function_list() -> CK_FUNCTION_LIST {
    build_function_list!(CK_FUNCTION_LIST, CK_VERSION { major: 2, minor: 40 })
}

fn build_base_function_list_3_0() -> CK_FUNCTION_LIST_3_0 {
    build_function_list_3_x!(CK_FUNCTION_LIST_3_0, CK_VERSION { major: 3, minor: 0 })
}

fn build_base_function_list_3_2() -> CK_FUNCTION_LIST_3_2 {
    build_function_list_3_x!(
        CK_FUNCTION_LIST_3_2,
        CK_VERSION { major: 3, minor: 2 },
        C_EncapsulateKey: Some(crate::dispatch::general::c_encapsulate_key),
        C_DecapsulateKey: Some(crate::dispatch::general::c_decapsulate_key),
        C_VerifySignatureInit: Some(crate::dispatch::general::c_verify_signature_init),
        C_VerifySignature: Some(crate::dispatch::general::c_verify_signature),
        C_VerifySignatureUpdate: Some(crate::dispatch::general::c_verify_signature_update),
        C_VerifySignatureFinal: Some(crate::dispatch::general::c_verify_signature_final),
        C_GetSessionValidationFlags: Some(crate::dispatch::general::c_get_session_validation_flags),
        C_AsyncComplete: Some(crate::dispatch::general::c_async_complete),
        C_AsyncGetID: Some(crate::dispatch::general::c_async_get_id),
        C_AsyncJoin: Some(crate::dispatch::general::c_async_join),
        C_WrapKeyAuthenticated: Some(crate::dispatch::general::c_wrap_key_authenticated),
        C_UnwrapKeyAuthenticated: Some(crate::dispatch::general::c_unwrap_key_authenticated),
    )
}

// ---------------------------------------------------------------------------
// Per-struct patching
// ---------------------------------------------------------------------------

/// Generate a function that patches NULL slots in a function list struct.
///
/// For each field name in the backend's `null_functions` list that matches
/// a field in the struct, the corresponding `Option<fn>` is set to `None`.
macro_rules! define_patch_fn {
    ($fn_name:ident, $struct_type:ty, [ $( $field:ident ),+ $(,)? ]) => {
        fn $fn_name(fl: &mut $struct_type, null_names: &[String]) {
            for name in null_names {
                match name.as_str() {
                    $(
                        stringify!($field) => { fl.$field = None; }
                    )+
                    _ => { /* unknown field — ignore */ }
                }
            }
        }
    };
}

define_patch_fn!(
    patch_function_list,
    CK_FUNCTION_LIST,
    [
        C_Initialize,
        C_Finalize,
        C_GetInfo,
        C_GetFunctionList,
        C_GetSlotList,
        C_GetSlotInfo,
        C_GetTokenInfo,
        C_GetMechanismList,
        C_GetMechanismInfo,
        C_InitToken,
        C_InitPIN,
        C_SetPIN,
        C_OpenSession,
        C_CloseSession,
        C_CloseAllSessions,
        C_GetSessionInfo,
        C_GetOperationState,
        C_SetOperationState,
        C_Login,
        C_Logout,
        C_CreateObject,
        C_CopyObject,
        C_DestroyObject,
        C_GetObjectSize,
        C_GetAttributeValue,
        C_SetAttributeValue,
        C_FindObjectsInit,
        C_FindObjects,
        C_FindObjectsFinal,
        C_EncryptInit,
        C_Encrypt,
        C_EncryptUpdate,
        C_EncryptFinal,
        C_DecryptInit,
        C_Decrypt,
        C_DecryptUpdate,
        C_DecryptFinal,
        C_DigestInit,
        C_Digest,
        C_DigestUpdate,
        C_DigestKey,
        C_DigestFinal,
        C_SignInit,
        C_Sign,
        C_SignUpdate,
        C_SignFinal,
        C_SignRecoverInit,
        C_SignRecover,
        C_VerifyInit,
        C_Verify,
        C_VerifyUpdate,
        C_VerifyFinal,
        C_VerifyRecoverInit,
        C_VerifyRecover,
        C_DigestEncryptUpdate,
        C_DecryptDigestUpdate,
        C_SignEncryptUpdate,
        C_DecryptVerifyUpdate,
        C_GenerateKey,
        C_GenerateKeyPair,
        C_WrapKey,
        C_UnwrapKey,
        C_DeriveKey,
        C_SeedRandom,
        C_GenerateRandom,
        C_GetFunctionStatus,
        C_CancelFunction,
        C_WaitForSlotEvent,
    ]
);

define_patch_fn!(
    patch_function_list_3_0,
    CK_FUNCTION_LIST_3_0,
    [
        // 2.40 fields
        C_Initialize,
        C_Finalize,
        C_GetInfo,
        C_GetFunctionList,
        C_GetSlotList,
        C_GetSlotInfo,
        C_GetTokenInfo,
        C_GetMechanismList,
        C_GetMechanismInfo,
        C_InitToken,
        C_InitPIN,
        C_SetPIN,
        C_OpenSession,
        C_CloseSession,
        C_CloseAllSessions,
        C_GetSessionInfo,
        C_GetOperationState,
        C_SetOperationState,
        C_Login,
        C_Logout,
        C_CreateObject,
        C_CopyObject,
        C_DestroyObject,
        C_GetObjectSize,
        C_GetAttributeValue,
        C_SetAttributeValue,
        C_FindObjectsInit,
        C_FindObjects,
        C_FindObjectsFinal,
        C_EncryptInit,
        C_Encrypt,
        C_EncryptUpdate,
        C_EncryptFinal,
        C_DecryptInit,
        C_Decrypt,
        C_DecryptUpdate,
        C_DecryptFinal,
        C_DigestInit,
        C_Digest,
        C_DigestUpdate,
        C_DigestKey,
        C_DigestFinal,
        C_SignInit,
        C_Sign,
        C_SignUpdate,
        C_SignFinal,
        C_SignRecoverInit,
        C_SignRecover,
        C_VerifyInit,
        C_Verify,
        C_VerifyUpdate,
        C_VerifyFinal,
        C_VerifyRecoverInit,
        C_VerifyRecover,
        C_DigestEncryptUpdate,
        C_DecryptDigestUpdate,
        C_SignEncryptUpdate,
        C_DecryptVerifyUpdate,
        C_GenerateKey,
        C_GenerateKeyPair,
        C_WrapKey,
        C_UnwrapKey,
        C_DeriveKey,
        C_SeedRandom,
        C_GenerateRandom,
        C_GetFunctionStatus,
        C_CancelFunction,
        C_WaitForSlotEvent,
        // 3.0 extras
        C_GetInterfaceList,
        C_GetInterface,
        C_LoginUser,
        C_SessionCancel,
        C_MessageEncryptInit,
        C_EncryptMessage,
        C_EncryptMessageBegin,
        C_EncryptMessageNext,
        C_MessageEncryptFinal,
        C_MessageDecryptInit,
        C_DecryptMessage,
        C_DecryptMessageBegin,
        C_DecryptMessageNext,
        C_MessageDecryptFinal,
        C_MessageSignInit,
        C_SignMessage,
        C_SignMessageBegin,
        C_SignMessageNext,
        C_MessageSignFinal,
        C_MessageVerifyInit,
        C_VerifyMessage,
        C_VerifyMessageBegin,
        C_VerifyMessageNext,
        C_MessageVerifyFinal,
    ]
);

define_patch_fn!(
    patch_function_list_3_2,
    CK_FUNCTION_LIST_3_2,
    [
        // 2.40 fields
        C_Initialize,
        C_Finalize,
        C_GetInfo,
        C_GetFunctionList,
        C_GetSlotList,
        C_GetSlotInfo,
        C_GetTokenInfo,
        C_GetMechanismList,
        C_GetMechanismInfo,
        C_InitToken,
        C_InitPIN,
        C_SetPIN,
        C_OpenSession,
        C_CloseSession,
        C_CloseAllSessions,
        C_GetSessionInfo,
        C_GetOperationState,
        C_SetOperationState,
        C_Login,
        C_Logout,
        C_CreateObject,
        C_CopyObject,
        C_DestroyObject,
        C_GetObjectSize,
        C_GetAttributeValue,
        C_SetAttributeValue,
        C_FindObjectsInit,
        C_FindObjects,
        C_FindObjectsFinal,
        C_EncryptInit,
        C_Encrypt,
        C_EncryptUpdate,
        C_EncryptFinal,
        C_DecryptInit,
        C_Decrypt,
        C_DecryptUpdate,
        C_DecryptFinal,
        C_DigestInit,
        C_Digest,
        C_DigestUpdate,
        C_DigestKey,
        C_DigestFinal,
        C_SignInit,
        C_Sign,
        C_SignUpdate,
        C_SignFinal,
        C_SignRecoverInit,
        C_SignRecover,
        C_VerifyInit,
        C_Verify,
        C_VerifyUpdate,
        C_VerifyFinal,
        C_VerifyRecoverInit,
        C_VerifyRecover,
        C_DigestEncryptUpdate,
        C_DecryptDigestUpdate,
        C_SignEncryptUpdate,
        C_DecryptVerifyUpdate,
        C_GenerateKey,
        C_GenerateKeyPair,
        C_WrapKey,
        C_UnwrapKey,
        C_DeriveKey,
        C_SeedRandom,
        C_GenerateRandom,
        C_GetFunctionStatus,
        C_CancelFunction,
        C_WaitForSlotEvent,
        // 3.0 extras
        C_GetInterfaceList,
        C_GetInterface,
        C_LoginUser,
        C_SessionCancel,
        C_MessageEncryptInit,
        C_EncryptMessage,
        C_EncryptMessageBegin,
        C_EncryptMessageNext,
        C_MessageEncryptFinal,
        C_MessageDecryptInit,
        C_DecryptMessage,
        C_DecryptMessageBegin,
        C_DecryptMessageNext,
        C_MessageDecryptFinal,
        C_MessageSignInit,
        C_SignMessage,
        C_SignMessageBegin,
        C_SignMessageNext,
        C_MessageSignFinal,
        C_MessageVerifyInit,
        C_VerifyMessage,
        C_VerifyMessageBegin,
        C_VerifyMessageNext,
        C_MessageVerifyFinal,
        // 3.2 extras
        C_EncapsulateKey,
        C_DecapsulateKey,
        C_VerifySignatureInit,
        C_VerifySignature,
        C_VerifySignatureUpdate,
        C_VerifySignatureFinal,
        C_GetSessionValidationFlags,
        C_AsyncComplete,
        C_AsyncGetID,
        C_AsyncJoin,
        C_WrapKeyAuthenticated,
        C_UnwrapKeyAuthenticated,
    ]
);

// ---------------------------------------------------------------------------
// Patched function list builders
// ---------------------------------------------------------------------------

/// Build a patched v2.40 function list given a set of null function names.
fn build_patched_function_list(null_names: &[String]) -> CK_FUNCTION_LIST {
    let mut fl = build_base_function_list();
    patch_function_list(&mut fl, null_names);
    fl
}

/// Build a patched v3.0 function list given a set of null function names.
fn build_patched_function_list_3_0(null_names: &[String]) -> CK_FUNCTION_LIST_3_0 {
    let mut fl = build_base_function_list_3_0();
    patch_function_list_3_0(&mut fl, null_names);
    fl
}

/// Build a patched v3.2 function list given a set of null function names.
fn build_patched_function_list_3_2(null_names: &[String]) -> CK_FUNCTION_LIST_3_2 {
    let mut fl = build_base_function_list_3_2();
    patch_function_list_3_2(&mut fl, null_names);
    fl
}

// ---------------------------------------------------------------------------
// Backend probe
// ---------------------------------------------------------------------------

/// Contact the backend and build an `InterfaceState` with patched function
/// lists reflecting the backend's capabilities.
fn probe_backend() -> Result<InterfaceState, String> {
    // Ensure the gRPC channel is up (returns Err(CkRv) on failure).
    state::ensure_client_connected().map_err(|e| format!("connect failed: {e:?}"))?;

    let rt = state::runtime();
    let interfaces = rt.block_on(async {
        let mut client = state::client().lock().await;
        client.get_backend_interfaces().await
    })?;

    // Index null-function lists by (major, minor).
    let mut null_map = std::collections::HashMap::<(u8, u8), Vec<String>>::new();
    for (major, minor, nulls) in &interfaces {
        null_map.insert((*major, *minor), nulls.clone());
    }

    let empty = Vec::new();
    let nulls_2_40 = null_map.get(&(2, 40)).unwrap_or(&empty);
    let nulls_3_0 = null_map.get(&(3, 0)).unwrap_or(&empty);
    let nulls_3_2 = null_map.get(&(3, 2)).unwrap_or(&empty);

    // Determine which interfaces the backend reported.
    let has_3_0 = null_map.contains_key(&(3, 0));
    let has_3_2 = null_map.contains_key(&(3, 2));
    // Always include v2.40 — every PKCS#11 module has it.
    let count: CK_ULONG = 1 + if has_3_0 { 1 } else { 0 } + if has_3_2 { 1 } else { 0 };

    let fl_2_40 = build_patched_function_list(nulls_2_40);
    let fl_3_0 = build_patched_function_list_3_0(nulls_3_0);
    let fl_3_2 = build_patched_function_list_3_2(nulls_3_2);

    // Build a placeholder catalog — pointers will be fixed up after the
    // state is stored in the RwLock (they must point into the RwLock's
    // allocation).  We use null pointers here as sentinels.
    let catalog = [
        CK_INTERFACE {
            pInterfaceName: IFACE_NAME_PKCS11.as_ptr() as *mut CK_CHAR,
            pFunctionList: std::ptr::null_mut(),
            flags: 0,
        },
        CK_INTERFACE {
            pInterfaceName: IFACE_NAME_PKCS11.as_ptr() as *mut CK_CHAR,
            pFunctionList: std::ptr::null_mut(),
            flags: 0,
        },
        CK_INTERFACE {
            pInterfaceName: IFACE_NAME_PKCS11.as_ptr() as *mut CK_CHAR,
            pFunctionList: std::ptr::null_mut(),
            flags: 0,
        },
    ];

    Ok(InterfaceState { fl_2_40, fl_3_0, fl_3_2, catalog, count, has_3_0, has_3_2 })
}

/// Fix up the catalog's `pFunctionList` pointers to point into a leaked
/// `InterfaceState`, so pointers returned to PKCS#11 callers remain stable.
fn fixup_catalog(st: &mut InterfaceState) {
    // Entry 0: always v2.40.
    st.catalog[0].pFunctionList = &st.fl_2_40 as *const CK_FUNCTION_LIST as *mut std::ffi::c_void;
    // Remaining entries: use the flags to determine which interfaces are present,
    // not just the count (e.g. BouncyHSM has 3.2 but no 3.0).
    let mut idx = 1usize;
    if st.has_3_0 {
        st.catalog[idx].pFunctionList =
            &st.fl_3_0 as *const CK_FUNCTION_LIST_3_0 as *mut std::ffi::c_void;
        idx += 1;
    }
    if st.has_3_2 {
        st.catalog[idx].pFunctionList =
            &st.fl_3_2 as *const CK_FUNCTION_LIST_3_2 as *mut std::ffi::c_void;
    }
}

fn leak_fixed_state(st: InterfaceState) -> &'static InterfaceState {
    let leaked = Box::leak(Box::new(st));
    fixup_catalog(leaked);
    leaked
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Ensure the backend has been probed at least once.
///
/// Returns `Ok(())` if the cache is already populated or if the probe
/// succeeds. Returns `Err(msg)` if the probe fails (e.g., no connection).
///
/// This is a no-op if the cache already has data.
pub fn ensure_probed() -> Result<(), String> {
    // Fast path: already cached.
    {
        let guard = INTERFACE_STATE.read().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return Ok(());
        }
    }
    // Slow path: probe and store.
    let st = probe_backend()?;
    let mut guard = INTERFACE_STATE.write().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(leak_fixed_state(st));
    }
    Ok(())
}

/// Force a re-probe of the backend, replacing any cached state.
///
/// Called from `C_Initialize` after a successful server init so that the
/// function lists reflect the current backend.
pub fn reprobe() {
    match probe_backend() {
        Ok(st) => {
            let mut guard = INTERFACE_STATE.write().unwrap_or_else(|e| e.into_inner());
            *guard = Some(leak_fixed_state(st));
        }
        Err(e) => {
            tracing::warn!("interface reprobe failed, keeping previous state: {e}");
        }
    }
}

/// Clear the cached state (called from `C_Finalize`).
///
/// After this, `ensure_probed()` will re-probe on the next call.
pub fn clear_cache() {
    let mut guard = INTERFACE_STATE.write().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

/// Return a pointer to the v2.40 function list.
///
/// If the probe cache is populated, returns the patched version.
/// Otherwise returns the static (all-non-null) version from the
/// existing `function_list` module.
pub fn get_function_list() -> *mut CK_FUNCTION_LIST {
    let guard = INTERFACE_STATE.read().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(st) => &st.fl_2_40 as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST,
        None => crate::function_list::get_function_list(),
    }
}

/// Return the number of interfaces in the catalog.
///
/// After a successful probe, reflects the backend's actual interface set.
/// Before probing, returns 3 (optimistic fallback).
pub fn interface_count() -> CK_ULONG {
    let guard = INTERFACE_STATE.read().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(st) => st.count,
        None => 3, // pre-probe fallback: optimistic
    }
}

/// Copy the interface catalog into a caller-provided buffer.
///
/// If the probe cache is populated, uses the patched catalog.
/// Otherwise falls back to the static (all-non-null) catalog.
///
/// Returns the number of entries written.
pub fn copy_catalog(buf: *mut CK_INTERFACE, buf_len: CK_ULONG) -> CK_ULONG {
    let n = interface_count();
    if buf_len < n {
        return 0; // caller should have checked
    }

    let guard = INTERFACE_STATE.read().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(st) => {
            let n = st.count as usize;
            for i in 0..n {
                unsafe {
                    *buf.add(i) = st.catalog[i];
                }
            }
        }
        None => {
            // Fall back to static function lists.
            let static_catalog: [CK_INTERFACE; 3] = [
                CK_INTERFACE {
                    pInterfaceName: IFACE_NAME_PKCS11.as_ptr() as *mut CK_CHAR,
                    pFunctionList: crate::function_list::get_function_list()
                        as *mut std::ffi::c_void,
                    flags: 0,
                },
                CK_INTERFACE {
                    pInterfaceName: IFACE_NAME_PKCS11.as_ptr() as *mut CK_CHAR,
                    pFunctionList: crate::function_list_3_0::get_function_list_3_0()
                        as *mut std::ffi::c_void,
                    flags: 0,
                },
                CK_INTERFACE {
                    pInterfaceName: IFACE_NAME_PKCS11.as_ptr() as *mut CK_CHAR,
                    pFunctionList: crate::function_list_3_2::get_function_list_3_2()
                        as *mut std::ffi::c_void,
                    flags: 0,
                },
            ];
            for (i, iface) in static_catalog.iter().enumerate() {
                unsafe {
                    *buf.add(i) = *iface;
                }
            }
        }
    }
    n
}

/// Find an interface by name and optional version.
///
/// Returns a pointer to the matching `CK_INTERFACE` (inside the probe
/// cache or a static fallback), or null if no match.
///
/// - `name` = `None` → return the default (highest-version) entry.
/// - `version` = `None` → match any version; highest wins.
pub fn find_interface(
    name: Option<&std::ffi::CStr>,
    version: Option<&CK_VERSION>,
) -> *mut CK_INTERFACE {
    let guard = INTERFACE_STATE.read().unwrap_or_else(|e| e.into_inner());

    // Helper: search a catalog slice and return the best match.
    fn search(
        catalog: &[CK_INTERFACE],
        name: Option<&std::ffi::CStr>,
        version: Option<&CK_VERSION>,
    ) -> Option<*const CK_INTERFACE> {
        // No name → filter by version if specified, else return default (last entry).
        if name.is_none() {
            if let Some(req) = version {
                // Per PKCS#11 spec: NULL name with version returns the matching version.
                for iface in catalog.iter().rev() {
                    let fl_ver = unsafe { &*(iface.pFunctionList as *const CK_VERSION) };
                    if fl_ver.major == req.major && fl_ver.minor == req.minor {
                        return Some(iface as *const CK_INTERFACE);
                    }
                }
                return None;
            }
            return catalog.last().map(|e| e as *const CK_INTERFACE);
        }
        let name = name.unwrap();
        let name_bytes = name.to_bytes();

        let mut found: Option<*const CK_INTERFACE> = None;
        for iface in catalog.iter() {
            let iface_name = unsafe {
                std::ffi::CStr::from_ptr(iface.pInterfaceName as *const std::os::raw::c_char)
            };
            if iface_name.to_bytes() != name_bytes {
                continue;
            }
            if let Some(req) = version {
                let fl_ver = unsafe { &*(iface.pFunctionList as *const CK_VERSION) };
                if fl_ver.major != req.major || fl_ver.minor != req.minor {
                    continue;
                }
            }
            found = Some(iface as *const CK_INTERFACE);
        }
        found
    }

    match guard.as_ref() {
        Some(st) => search(&st.catalog[..st.count as usize], name, version)
            .map(|p| p as *mut CK_INTERFACE)
            .unwrap_or(std::ptr::null_mut()),
        None => {
            // Fall back to static catalog.  We need a stable &'static
            // reference, so delegate to the OnceLock-based catalog in
            // the function_list modules.  Build a temporary stack catalog
            // from the static function lists.
            //
            // NOTE: We cannot return pointers into stack-local data.
            // Instead, use a static OnceLock for the fallback catalog.
            static FALLBACK_CATALOG: std::sync::OnceLock<FallbackCatalog> =
                std::sync::OnceLock::new();
            let fb = FALLBACK_CATALOG.get_or_init(|| {
                FallbackCatalog([
                    CK_INTERFACE {
                        pInterfaceName: IFACE_NAME_PKCS11.as_ptr() as *mut CK_CHAR,
                        pFunctionList: crate::function_list::get_function_list()
                            as *mut std::ffi::c_void,
                        flags: 0,
                    },
                    CK_INTERFACE {
                        pInterfaceName: IFACE_NAME_PKCS11.as_ptr() as *mut CK_CHAR,
                        pFunctionList: crate::function_list_3_0::get_function_list_3_0()
                            as *mut std::ffi::c_void,
                        flags: 0,
                    },
                    CK_INTERFACE {
                        pInterfaceName: IFACE_NAME_PKCS11.as_ptr() as *mut CK_CHAR,
                        pFunctionList: crate::function_list_3_2::get_function_list_3_2()
                            as *mut std::ffi::c_void,
                        flags: 0,
                    },
                ])
            });
            search(&fb.0, name, version)
                .map(|p| p as *mut CK_INTERFACE)
                .unwrap_or(std::ptr::null_mut())
        }
    }
}

/// Wrapper so we can store a `[CK_INTERFACE; 3]` in a `OnceLock` (the raw
/// pointers inside need Send + Sync).
struct FallbackCatalog([CK_INTERFACE; 3]);
unsafe impl Send for FallbackCatalog {}
unsafe impl Sync for FallbackCatalog {}

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use crate::state;

#[allow(unused_imports)]
use super::*;

use std::path::PathBuf;

/// Phase 1 decision for `CK_C_INITIALIZE_ARGS`:
///
/// - `pReserved` non-null → `CKR_ARGUMENTS_BAD` (PKCS#11 §5.4 requirement)
/// - All four mutex callbacks non-null WITHOUT `CKF_OS_LOCKING_OK` →
///   `CKR_CANT_LOCK` (tokio runtime cannot delegate to caller mutexes)
/// - All four mutex callbacks non-null WITH `CKF_OS_LOCKING_OK` → accepted
///   (per §5.4, library may ignore callbacks and use OS locking; this is
///   the combination used by GnuTLS/p11-kit)
/// - `CKF_OS_LOCKING_OK` set, no custom callbacks → accepted
/// - `CKF_LIBRARY_CANT_CREATE_OS_THREADS` → accepted (tokio threads are
///   started at library load time, not at initialize time; the flag
///   arrives too late to change runtime behavior in Phase 1)
/// - null pInitArgs → accepted (spec allows, treated as OS-locking default)
///
/// Returns `None` on success, `Some(rv)` on error.
unsafe fn parse_init_args(p_init_args: CK_VOID_PTR) -> Option<CK_RV> {
    if p_init_args.is_null() {
        return None; // Null is always acceptable.
    }
    let args = unsafe { &*(p_init_args as *const CK_C_INITIALIZE_ARGS) };

    // pReserved must be null (PKCS#11 §5.4).
    if !args.pReserved.is_null() {
        return Some(rv_err(CkRv::ARGUMENTS_BAD));
    }

    // Custom mutex callbacks: if all four are provided, check whether we can
    // fall back to OS locking.  Per PKCS#11 §5.4, if `CKF_OS_LOCKING_OK` is
    // also set, the library may ignore the custom callbacks and use OS locking.
    // GnuTLS/p11-kit passes all four callbacks + CKF_OS_LOCKING_OK; rejecting
    // that combination breaks consumer compatibility.
    let all_mutex = args.CreateMutex.is_some()
        && args.DestroyMutex.is_some()
        && args.LockMutex.is_some()
        && args.UnlockMutex.is_some();
    if all_mutex && (args.flags & CKF_OS_LOCKING_OK) == 0 {
        // Caller demands custom mutexes without allowing OS locking — reject.
        return Some(CKR_CANT_LOCK as CK_RV);
    }
    // If all_mutex && CKF_OS_LOCKING_OK: accept, we'll use OS locking (tokio).

    None // Accept everything else.
}

pub unsafe extern "C" fn c_initialize(p_init_args: CK_VOID_PTR) -> CK_RV {
    catch_panics(|| {
        // Validate pInitArgs before touching state or network.
        if let Some(err_rv) = unsafe { parse_init_args(p_init_args) } {
            return err_rv;
        }

        // Local initialized-flag check (no network round-trip needed).
        if !state::mark_initialized() {
            return rv_err(CkRv::CRYPTOKI_ALREADY_INITIALIZED);
        }

        // Load the mechanism registry from embedded defaults + optional
        // override file.  OnceLock means this only runs on the first
        // C_Initialize; re-init after C_Finalize reuses the same registry.
        let override_path = std::env::var("PKCS11_PROXY_MECHANISMS").ok().map(PathBuf::from);
        match MechanismRegistry::load(override_path.as_deref()) {
            Ok(reg) => {
                // Ignore the error: OnceLock returns Err only if already set,
                // which is fine — the registry persists across finalize/re-init.
                let _ = state::init_mechanism_registry(reg);
            }
            Err(e) => {
                tracing::error!("Failed to load mechanism registry: {e}");
                state::mark_finalized();
                return rv_err(CkRv::GENERAL_ERROR);
            }
        }

        // Establish the gRPC connection outside block_on so that the
        // OnceLock init (which itself uses block_on) does not nest.
        if state::ensure_client_connected().is_err() {
            tracing::error!("Failed to connect to proxy daemon");
            state::mark_finalized();
            return rv_err(CkRv::DEVICE_ERROR);
        }

        let rt = state::runtime();
        let rv = rt.block_on(async {
            let mut client = state::client().lock().await;
            match client.initialize().await {
                Ok(()) => rv_ok(),
                Err(e) => rv_err(e),
            }
        });

        // Roll back the flag if the server call failed.
        if rv != rv_ok() {
            state::mark_finalized();
        } else {
            // Re-probe the backend so function lists reflect actual
            // capabilities (BUG-001).
            crate::interface_probe::reprobe();
        }
        rv
    })
}

pub unsafe extern "C" fn c_finalize(p_reserved: CK_VOID_PTR) -> CK_RV {
    catch_panics(|| {
        if !p_reserved.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }

        // Local flag check — avoids a network call when not initialized.
        if !state::is_initialized() {
            return rv_err(CkRv::CRYPTOKI_NOT_INITIALIZED);
        }

        let rt = state::runtime();
        let rv = rt.block_on(async {
            let mut client = state::client().lock().await;
            match client.finalize().await {
                Ok(()) => rv_ok(),
                Err(e) => rv_err(e),
            }
        });

        // Clear local state regardless of the server result; the context is
        // gone or unreachable either way.
        state::mark_finalized();
        state::mark_client_reconnect_required();
        state::clear_all_caches();
        // Clear the probe cache so the next C_Initialize re-probes (BUG-001).
        crate::interface_probe::clear_cache();
        rv
    })
}

pub unsafe extern "C" fn c_get_info(p_info: CK_INFO_PTR) -> CK_RV {
    catch_panics(|| {
        if p_info.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        if !state::is_initialized() {
            return rv_err(CkRv::CRYPTOKI_NOT_INITIALIZED);
        }
        let rt = state::runtime();
        rt.block_on(async {
            let mut client = state::client().lock().await;
            match client.get_info().await {
                Ok(info) => {
                    unsafe {
                        let out = &mut *p_info;
                        out.cryptokiVersion = CK_VERSION {
                            major: info.cryptoki_version.0,
                            minor: info.cryptoki_version.1,
                        };
                        pad_string(&mut out.manufacturerID, &info.manufacturer_id);
                        out.flags = info.flags as CK_FLAGS;
                        pad_string(&mut out.libraryDescription, &info.library_description);
                        out.libraryVersion = CK_VERSION {
                            major: info.library_version.0,
                            minor: info.library_version.1,
                        };
                    }
                    rv_ok()
                }
                Err(e) => rv_err(e),
            }
        })
    })
}

// ---------------------------------------------------------------------------
// Slot / Token discovery
// ---------------------------------------------------------------------------

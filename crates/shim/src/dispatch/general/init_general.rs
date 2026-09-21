use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use crate::state;

use super::helpers::{catch_panics, rv_err, rv_ok};

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
/// - `CKF_LIBRARY_CANT_CREATE_OS_THREADS` → rejected with
///   `CKR_NEED_TO_CREATE_THREADS` (the shim's tokio runtime spawns OS worker
///   threads on first use, so a caller forbidding library threads cannot be
///   honored)
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
    // Copy each Option<fn> field by value before calling `.is_some()` (which
    // takes `&self`): on Windows (LLP64) CK_C_INITIALIZE_ARGS is `#[repr(packed)]`
    // in the cryptoki-sys binding, so referencing a field in place is E0793. The
    // fields are Copy, so the by-value reads are sound and a no-op elsewhere.
    let create_mutex = args.CreateMutex;
    let destroy_mutex = args.DestroyMutex;
    let lock_mutex = args.LockMutex;
    let unlock_mutex = args.UnlockMutex;
    let all_mutex = create_mutex.is_some()
        && destroy_mutex.is_some()
        && lock_mutex.is_some()
        && unlock_mutex.is_some();
    if all_mutex && (args.flags & CKF_OS_LOCKING_OK) == 0 {
        // Caller demands custom mutexes without allowing OS locking — reject.
        return Some(CKR_CANT_LOCK as CK_RV);
    }
    // If all_mutex && CKF_OS_LOCKING_OK: accept, we'll use OS locking (tokio).

    // The shim's tokio runtime spawns OS worker threads (lazily, on first use),
    // so a caller that forbids library threads cannot be honored.
    if (args.flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS) != 0 {
        return Some(CKR_NEED_TO_CREATE_THREADS as CK_RV);
    }

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

        // Mark the cached gRPC channel for reconnect ONLY on genuine
        // transport failures (FOLLOWUP-dns-reresolve, resolved by
        // W1-L11-24: follow a daemon whose address changed — every
        // reconnect re-reads the endpoint and re-resolves DNS via a
        // fresh `Endpoint`). Registered before any RPC; idempotent. The
        // hook fires inside the client's transport-Status mapping, so a
        // backend `ck_rv` — e.g. kryoptic's CKR_DEVICE_ERROR (OpenSSL
        // catch-all) or CKR_GENERAL_ERROR (internal catch-all), which
        // arrive as ordinary results — never triggers a spurious
        // reconnect.
        pkcs11_proxy_ng_client::set_transport_failure_hook(|| {
            crate::interface_probe::invalidate_pointer_safe_message_parameters();
            state::mark_client_reconnect_required()
        });

        // Seed the mechanism registry from the embedded default (plus
        // the optional PKCS11_PROXY_MECHANISMS override). The probe in
        // reprobe() below will replace this with the server-published
        // registry once the daemon connection is up; this seeding
        // ensures the registry is non-null during the brief
        // C_Initialize → probe window and remains valid as a fallback
        // when the daemon predates the published-registry field.
        let override_path = std::env::var("PKCS11_PROXY_MECHANISMS").ok().map(PathBuf::from);
        match MechanismRegistry::load(override_path.as_deref()) {
            Ok(reg) => {
                state::replace_mechanism_registry(reg);
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
            // CKR_DEVICE_ERROR is not in the OASIS-permitted return set for
            // C_Initialize; use the lifecycle-class CKR_GENERAL_ERROR so the
            // shim matches a native module's error contract (AGENTS.md §2).
            return rv_err(CkRv::GENERAL_ERROR);
        }

        let rt = state::runtime();
        let rv = rt.block_on(async {
            // W1-L11-11: clone-before-RPC (with_client! convention) — no
            // guard held across the await. initialize() stores the
            // context id on the clone, so propagate just the id back
            // under a short lock; a full client writeback could clobber
            // a concurrent reconnect swap's fresh channel.
            let mut client = state::client().lock().await.clone();
            let result = client.initialize().await;
            let context_id = client.context_id_opt();
            state::client().lock().await.restore_context_id(context_id);
            match result {
                Ok(()) => rv_ok(),
                Err(e) => rv_err(e),
            }
        });

        // Roll back the flag if the server call failed.
        if rv != rv_ok() {
            state::mark_finalized();
        } else {
            // Re-probe the backend so function lists reflect actual
            // capabilities (BUG-001). A transient probe failure is
            // tolerated (previous/fallback state stays in use); an ABI
            // refusal (D6 byte-order mismatch) is fatal — every ulong
            // byte from this daemon would be unparseable, so fail the
            // initialization instead of connecting-and-corrupting.
            if let Err(e) = crate::interface_probe::reprobe() {
                tracing::error!(error = %e, "C_Initialize refused: incompatible backend ABI");
                // Best-effort: release the daemon-side context we created.
                // W1-L11-11: clone-before-RPC; propagate the cleared id so
                // the shared client never retains a released context.
                let _ = state::runtime().block_on(async {
                    let mut client = state::client().lock().await.clone();
                    let result = client.finalize().await;
                    let context_id = client.context_id_opt();
                    state::client().lock().await.restore_context_id(context_id);
                    result
                });
                state::mark_finalized();
                // The cached channel points at the refused daemon; force the
                // next C_Initialize to re-read the environment and reconnect,
                // and drop any probe state captured from it.
                state::mark_client_reconnect_required();
                crate::interface_probe::clear_cache();
                return rv_err(CkRv::GENERAL_ERROR);
            }
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
            // W1-L11-11: clone-before-RPC (with_client! convention) — no
            // guard held across the await. Propagate the resulting id
            // (cleared on success, kept on transport failure) so the
            // shared client's lifecycle matches the guarded version
            // exactly; a full writeback could clobber a concurrent
            // reconnect swap's fresh channel.
            // (No ensure_client_connected here: finalize is teardown —
            // re-dialing a stale channel just to say goodbye would add
            // latency for no benefit; the reconnect flag set below
            // forces the next C_Initialize onto a fresh channel.)
            let mut client = state::client().lock().await.clone();
            let result = client.finalize().await;
            let context_id = client.context_id_opt();
            state::client().lock().await.restore_context_id(context_id);
            match result {
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
        // W1-L6-29: same steady-state reconnect consumption as with_client!
        // (this export hand-rolls its runtime/client access). Best-effort:
        // on failure the call below proceeds as before.
        let _ = state::ensure_client_connected();
        let rt = state::runtime();
        rt.block_on(async {
            // W1-L11-11: clone-before-RPC (with_client! convention) — no
            // guard held across the await. get_info only reads the
            // context id, so no state propagates back.
            let mut client = state::client().lock().await.clone();
            match client.get_info().await {
                Ok(info) => {
                    unsafe {
                        let out = &mut *p_info;
                        out.cryptokiVersion = CK_VERSION {
                            major: info.cryptoki_version.0,
                            minor: info.cryptoki_version.1,
                        };
                        space_pad_into(&mut out.manufacturerID, &info.manufacturer_id);
                        out.flags = info.flags as CK_FLAGS;
                        space_pad_into(&mut out.libraryDescription, &info.library_description);
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

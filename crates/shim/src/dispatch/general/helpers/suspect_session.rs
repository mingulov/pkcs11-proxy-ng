//! Lazy per-member reconciliation after a failed close-all batch (Q01-P2).
//!
//! The batch answers one aggregate `CK_RV`, which proves nothing per
//! member: some members may have closed while others survived. Carrying
//! per-member outcomes over the wire would need a protocol change
//! (`CloseAllSessionsResponse` carries only `ck_rv`); instead the shim
//! marks the retained slot sessions suspect
//! ([`crate::state::mark_slot_sessions_suspect`]) and reconciles each
//! one lazily against the next authoritative daemon verdict:
//!
//! * a locally-failed mechanism validation probes the daemon once, so a
//!   dead-but-retained member answers `SESSION_HANDLE_INVALID` (native
//!   error precedence: session resolution before mechanism validation)
//!   instead of the mechanism error;
//! * any daemon RPC outcome settles suspicion directly — success clears
//!   it, a confirmed-dead handle evicts just that member.
//!
//! Survivors — and their message-operation discriminators — are never
//! touched: only a daemon-confirmed dead handle is evicted. Non-suspect
//! sessions keep the exact hot-path behavior (no extra RPC).

use cryptoki_sys::CK_SESSION_HANDLE;
use pkcs11_proxy_ng_types::{CkResult, CkRv, CkSessionHandle};

use crate::state;

/// Authoritatively resolve whether `h_session` is still alive at the
/// daemon. `Some(true)` = alive, `Some(false)` = daemon-confirmed dead,
/// `None` = inconclusive (uninitialized shim, or the probe itself
/// failed below the daemon's verdict — e.g. transport loss).
pub(crate) fn probe_session_alive(h_session: CK_SESSION_HANDLE) -> Option<bool> {
    if !state::is_initialized() {
        return None;
    }
    // Same client dance as `with_client!` (which cannot be reused here:
    // its early `return` targets the enclosing `CK_RV` function).
    let _ = state::ensure_client_connected();
    let outcome = state::runtime().block_on(async {
        let mut client = state::client().lock().await.clone();
        client.get_session_info(CkSessionHandle(h_session as u64)).await
    });
    match outcome {
        Ok(_) => Some(true),
        Err(rv) if rv == CkRv::SESSION_HANDLE_INVALID || rv == CkRv::SESSION_CLOSED => Some(false),
        Err(_) => None,
    }
}

/// Settle a locally-failed mechanism validation on a suspect session:
/// when the session may have died in a retained close-all batch, one
/// authoritative probe restores native error precedence. Non-suspect
/// sessions return the local verdict untouched (no extra RPC).
pub(crate) fn resolve_suspect_mech_error(h_session: CK_SESSION_HANDLE, mech_error: CkRv) -> CkRv {
    if !state::is_session_suspect(h_session) {
        return mech_error;
    }
    match probe_session_alive(h_session) {
        // Alive: the mechanism error stands; suspicion resolved.
        Some(true) => {
            state::clear_session_suspect(h_session);
            mech_error
        }
        // Daemon-confirmed dead: reconcile just this member away and
        // report the session error — survivors keep their state.
        Some(false) => {
            state::clear_session_suspect(h_session);
            state::evict_session_authoritative_state(h_session);
            CkRv::SESSION_HANDLE_INVALID
        }
        // Probe inconclusive (daemon unreachable): keep the local
        // verdict and stay suspect so a later call retries.
        None => mech_error,
    }
}

/// Reconcile a suspect session against one daemon RPC outcome: any
/// success proves the member alive (suspicion resolved); a
/// daemon-confirmed dead handle evicts just that member. Ambiguous
/// outcomes stay suspect. Non-suspect sessions are untouched.
pub(crate) fn reconcile_suspect_session<T>(h_session: CK_SESSION_HANDLE, result: &CkResult<T>) {
    if !state::is_session_suspect(h_session) {
        return;
    }
    match result {
        Ok(_) => state::clear_session_suspect(h_session),
        Err(rv) if *rv == CkRv::SESSION_HANDLE_INVALID || *rv == CkRv::SESSION_CLOSED => {
            state::clear_session_suspect(h_session);
            state::evict_session_authoritative_state(h_session);
        }
        Err(_) => {}
    }
}

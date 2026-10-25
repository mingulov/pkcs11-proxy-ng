use std::sync::Once;

use cryptoki_sys::*;
use pkcs11_proxy_ng_client::MessageCallErrorOrigin;
use pkcs11_proxy_ng_types::*;

use super::helpers::{
    catch_panics, rv_err, rv_ok, try_read_credential_bytes, unit_result_to_rv, with_client,
    write_session_handle_output,
};

static NOTIFY_UNSUPPORTED_ONCE: Once = Once::new();

/// The proxy cannot deliver `CK_NOTIFY` callbacks (`CKN_SURRENDER`): the
/// backend session is opened with a NULL Notify and no callback channel
/// exists back into the application. Warn once per process when an
/// application supplies a non-NULL Notify so the silent drop is visible;
/// a NULL Notify stays silent. Never alters the returned `CK_RV`. The
/// `Once` is injectable so unit tests can exercise the check with a
/// fresh cell instead of the process-global one.
pub(crate) fn warn_notify_unsupported_once(notify: CK_NOTIFY, once: &Once) {
    if notify.is_some() {
        once.call_once(|| {
            tracing::warn!(
                "C_OpenSession Notify callbacks are not supported by the proxy; \
                 sessions work without surrender notifications, which will never be delivered"
            );
        });
    }
}

pub unsafe extern "C" fn c_open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _p_application: CK_VOID_PTR,
    notify: CK_NOTIFY,
    ph_session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    catch_panics(|| {
        warn_notify_unsupported_once(notify, &NOTIFY_UNSUPPORTED_ONCE);
        if ph_session.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.open_session(CkSlotId(slot_id as u64), CkSessionFlags(flags as u64)))
        {
            Ok(handle) => {
                let raw_handle = handle.0 as CK_SESSION_HANDLE;
                unsafe { write_session_handle_output(handle, ph_session) };
                crate::state::remember_session_slot(raw_handle, slot_id);
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_close_session(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        let result = with_client!(client => client.close_session_stateful(
            CkSessionHandle(h_session as u64)
        ));
        // Authoritative session/message state survives every outcome
        // that proves nothing terminal, so a still-valid handle can
        // safely retry or continue. (W1-C6-04: no disposable output
        // caches remain.) Only success and decoded backend RVs that
        // prove the handle dead evict: an ambiguous transport/protocol
        // outcome (deadline, cancel, disconnect) still has the detached
        // server close in flight, which may settle transiently and
        // reactivate a live member — evicting first would answer SHI
        // for a server-live session. (Q01 round 4.)
        let evict_authoritative = match &result {
            Ok(()) => true,
            Err(error) if error.origin != MessageCallErrorOrigin::Backend => false,
            Err(error) => {
                error.ck_rv == CkRv::DEVICE_ERROR
                    || error.ck_rv == CkRv::SESSION_CLOSED
                    || error.ck_rv == CkRv::SESSION_HANDLE_INVALID
            }
        };
        if evict_authoritative {
            crate::state::evict_session_authoritative_state(h_session);
        } else {
            // Q01 round 4 (M1/M2): a retained outcome settles nothing,
            // so the member stays usable and is marked suspect for
            // lazy per-member reconciliation against the next
            // authoritative daemon verdict — never evicted before
            // settlement.
            crate::state::mark_session_suspect(h_session);
        }
        unit_result_to_rv(result.map_err(|error| error.ck_rv))
    })
}

pub unsafe extern "C" fn c_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    catch_panics(|| {
        let result = with_client!(client => client.close_all_sessions_stateful(
            CkSlotId(slot_id as u64)
        ));
        // Q01: settle the slot caches on the decoded outcome (singular-close
        // discipline). The batch answers one aggregate CK_RV, which proves
        // per-session death only for OK (everything closed) and for
        // SLOT_ID_INVALID / CRYPTOKI_NOT_INITIALIZED (no server-side
        // session can exist for the slot / context) — every other
        // outcome leaves survivors possible, so the daemon stays
        // authoritative and the next call reports the true state. An
        // ambiguous transport/protocol outcome (deadline, cancel,
        // disconnect) still has the detached server batch in flight —
        // evicting first would answer SHI for server-live members.
        // (Q01 round 4.)
        let evict_authoritative = match &result {
            Ok(()) => true,
            Err(error) if error.origin != MessageCallErrorOrigin::Backend => false,
            Err(error) => {
                error.ck_rv == CkRv::SLOT_ID_INVALID
                    || error.ck_rv == CkRv::CRYPTOKI_NOT_INITIALIZED
            }
        };
        if evict_authoritative {
            crate::state::evict_slot_session_caches(slot_id);
        } else {
            // Q01-P2, extended to ambiguous outcomes in round 4 (M1): a
            // retained batch proves nothing per member — some members
            // may have closed while others survived (or still settle).
            // Mark the retained slot sessions suspect so the next Init
            // reconciles each against the daemon (lazy per-member
            // settlement without a protocol change).
            crate::state::mark_slot_sessions_suspect(slot_id);
        }
        unit_result_to_rv(result.map_err(|error| error.ck_rv))
    })
}

pub unsafe extern "C" fn c_get_session_info(
    h_session: CK_SESSION_HANDLE,
    p_info: CK_SESSION_INFO_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_info.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.get_session_info(CkSessionHandle(h_session as u64))) {
            Ok(info) => {
                unsafe {
                    let out = &mut *p_info;
                    out.slotID = info.slot_id.0 as CK_SLOT_ID;
                    out.state = info.state as CK_STATE;
                    out.flags = info.flags.0 as CK_FLAGS;
                    out.ulDeviceError = info.device_error.0 as CK_ULONG;
                }
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_login(
    h_session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    p_pin: CK_UTF8CHAR_PTR,
    ul_pin_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let ut = match CkUserType::from_raw(user_type.into()) {
            Some(ut) => ut,
            None => return rv_err(CkRv::USER_TYPE_INVALID),
        };
        let pin = match unsafe { try_read_credential_bytes(p_pin, ul_pin_len) } {
            Ok(pin) => pin,
            Err(e) => return rv_err(e),
        };
        unit_result_to_rv(
            with_client!(client => client.login(CkSessionHandle(h_session as u64), ut, pin)),
        )
    })
}

pub unsafe extern "C" fn c_logout(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(with_client!(client => client.logout(
            CkSessionHandle(h_session as u64)
        )))
    })
}

// ---------------------------------------------------------------------------
// Legacy parallel function status (PKCS#11 2.40)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_get_function_status(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(with_client!(client => client.get_function_status(
            CkSessionHandle(h_session as u64)
        )))
    })
}

pub unsafe extern "C" fn c_cancel_function(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(with_client!(client => client.cancel_function(
            CkSessionHandle(h_session as u64)
        )))
    })
}

// ---------------------------------------------------------------------------
// Token / PIN administration
// ---------------------------------------------------------------------------

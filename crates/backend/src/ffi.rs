use crate::traits::{CkDeriveKeyOutputResult, Pkcs11Backend};
use dashmap::DashMap;
use libloading::Library;
use pkcs11_proxy_ng_types::*;
use std::collections::HashSet;
use std::ffi::CString;

#[path = "ffi/authenticated_typed_ops.rs"]
mod authenticated_typed_ops;
#[path = "ffi/authenticated_wrap_ops.rs"]
mod authenticated_wrap_ops;
#[path = "ffi/call_helpers.rs"]
mod call_helpers;
#[cfg(all(test, unix))]
#[path = "ffi/constructor_child_tests.rs"]
mod constructor_child_tests;
#[path = "ffi/crypto_ops.rs"]
mod crypto_ops;
#[path = "ffi/ffi_conversion/mod.rs"]
mod ffi_conversion;
#[path = "ffi/interface_caps.rs"]
mod interface_caps;
#[path = "ffi/kem_ops.rs"]
mod kem_ops;
#[path = "ffi/key_state_ops.rs"]
mod key_state_ops;
#[cfg(test)]
#[path = "ffi/lifecycle_domain_tests.rs"]
mod lifecycle_domain_tests;
#[path = "ffi/loading.rs"]
mod loading;
#[path = "ffi/mapping.rs"]
mod mapping;
#[path = "ffi/message_ops.rs"]
mod message_ops;
#[path = "ffi/native_allocation.rs"]
mod native_allocation;
#[path = "ffi/native_domain.rs"]
mod native_domain;
#[cfg(test)]
#[path = "ffi/native_domain_tests.rs"]
mod native_domain_tests;
#[path = "ffi/native_stop.rs"]
mod native_stop;
#[cfg(all(test, unix))]
#[path = "ffi/native_stop_tests.rs"]
mod native_stop_tests;
#[path = "ffi/object_ops.rs"]
mod object_ops;
#[path = "ffi/session_3x_ops.rs"]
mod session_3x_ops;
#[path = "ffi/session_fence.rs"]
mod session_fence;
#[path = "ffi/session_ops.rs"]
mod session_ops;
#[path = "ffi/verify_signature_ops.rs"]
mod verify_signature_ops;

#[cfg(all(test, unix))]
#[path = "ffi/wrap_contract_tests.rs"]
mod wrap_contract_tests;

#[cfg(all(test, unix))]
#[path = "ffi/exact_output_contract_tests.rs"]
mod exact_output_contract_tests;

#[cfg(all(test, unix))]
#[path = "ffi/retained_owner_contract_tests.rs"]
mod retained_owner_contract_tests;

use ffi_conversion::{FfiAttributeQueries, FfiAttrs};
use mapping::{
    info_from_ck, mechanism_info_from_ck, session_info_from_ck, slot_info_from_ck,
    token_info_from_ck, update_template_from_ffi,
};

/// Narrow a wire session handle for native dispatch (W1-L11-03): the
/// single session-handle prologue shared by the five call macros below.
/// The macro always expands as the tail of a CK_RV-returning closure:
/// an unrepresentable handle fails the call loudly, never truncates.
macro_rules! narrow_session_handle {
    ($session:expr) => {{
        match Self::session_handle($session) {
            Ok(h) => h,
            Err(_) => return CkRv::FUNCTION_FAILED.0 as cryptoki_sys::CK_RV,
        }
    }};
}
pub(crate) use narrow_session_handle;

macro_rules! session_bytes_input {
    ($session:expr, $input:expr, $function:ident, $output:ident, $output_len:ident) => {{
        let _ck_session = crate::ffi::narrow_session_handle!($session);
        let (_ck_in_ptr, _ck_in_len) = $input.as_ptr_len();
        // W1-C4-05: checked length narrowing, same tail-of-closure
        // loud-failure shape as `narrow_session_handle!` above.
        let _ck_in_len = match Self::ulong_len_u64(_ck_in_len) {
            Ok(len) => len,
            Err(_) => return CkRv::FUNCTION_FAILED.0 as cryptoki_sys::CK_RV,
        };
        unsafe { $function(_ck_session, _ck_in_ptr as *mut _, _ck_in_len, $output, $output_len) }
    }};
}
pub(crate) use session_bytes_input;

macro_rules! session_unit_input {
    ($session:expr, $input:expr, $function:ident) => {{
        let _ck_session = crate::ffi::narrow_session_handle!($session);
        let (_ck_in_ptr, _ck_in_len) = $input.as_ptr_len();
        // W1-C4-05: checked length narrowing, same tail-of-closure
        // loud-failure shape as `narrow_session_handle!` above.
        let _ck_in_len = match Self::ulong_len_u64(_ck_in_len) {
            Ok(len) => len,
            Err(_) => return CkRv::FUNCTION_FAILED.0 as cryptoki_sys::CK_RV,
        };
        unsafe { $function(_ck_session, _ck_in_ptr as *mut _, _ck_in_len) }
    }};
}
pub(crate) use session_unit_input;

macro_rules! mechanism_key_init {
    ($session:expr, $mechanism:expr, $key:expr, $function:ident, $mech:ident) => {{
        let _ck_session = crate::ffi::narrow_session_handle!($session);
        let _ck_key = match Self::object_handle($key) {
            Ok(h) => h,
            Err(_) => return CkRv::FUNCTION_FAILED.0 as cryptoki_sys::CK_RV,
        };
        unsafe { $function(_ck_session, $mech, _ck_key) }
    }};
}
pub(crate) use mechanism_key_init;

macro_rules! session_bytes_final {
    ($session:expr, $function:ident, $output:ident, $output_len:ident) => {{
        let _ck_session = crate::ffi::narrow_session_handle!($session);
        unsafe { $function(_ck_session, $output, $output_len) }
    }};
}
pub(crate) use session_bytes_final;

macro_rules! session_object_unit {
    ($session:expr, $object:expr, $function:ident) => {{
        let _ck_session = crate::ffi::narrow_session_handle!($session);
        let _ck_object = match Self::object_handle($object) {
            Ok(h) => h,
            Err(_) => return CkRv::FUNCTION_FAILED.0 as cryptoki_sys::CK_RV,
        };
        unsafe { $function(_ck_session, _ck_object) }
    }};
}
pub(crate) use session_object_unit;

/// Dispatch a call through a 3.x function list pointer (W1-L11-02).
///
/// Looks like a plain call, but the expansion carries two hidden early
/// returns: `return Err(CkRv::FUNCTION_NOT_SUPPORTED)` when the function
/// list is `None` (module only supports 2.40), and the same return when
/// the specific function slot is `None`. The enclosing function must
/// therefore return [`CkResult`] — using this macro in a non-`CkResult`
/// caller fails to compile (the `return Err(..)` arms do not coerce).
///
/// On success the expansion evaluates to `FfiBackend::ck_result(rv)` for
/// the native return value.
///
/// # Safety
/// The caller must ensure arguments satisfy the PKCS#11 C ABI contract for the
/// target function. The function list pointer must remain valid for the
/// lifetime of `$self` (guaranteed by `_lib` keeping the module loaded).
// The macro and re-export are used by sibling modules that implement 3.x
// backend trait methods (added in subsequent tasks).
#[allow(unused_macros)]
macro_rules! call_3x_fn {
    ($admission:expr, $self:expr, $list_field:ident, $fn_name:ident $(, $arg:expr)*) => {{
        // B2 admission proof (TF01b): the ascription pins at compile time
        // that the caller's ordinary guard reaches this native entry; the
        // guard local stays alive across the call and settlement. A macro
        // (not a choke fn) because call sites evaluate fallible (`?`)
        // argument expressions after table resolution — routing through
        // `call_unit` would force hoisting and change refusal precedence.
        let _admission: &crate::ffi::native_domain::OrdinaryGuard = $admission;
        let fl = match $self.$list_field {
            Some(fl) => fl,
            None => return Err(CkRv::FUNCTION_NOT_SUPPORTED),
        };
        let f = match unsafe { (*fl).$fn_name } {
            Some(f) => f,
            None => return Err(CkRv::FUNCTION_NOT_SUPPORTED),
        };
        let rv = unsafe { f($($arg),*) };
        FfiBackend::ck_result(rv)
    }};
}
#[allow(unused_imports)]
pub(crate) use call_3x_fn;

/// Operation family owning one retained mechanism slot within a session
/// (C3M.3 vocabulary).  The names are internal ownership labels, not a claim
/// about which operations a provider accepts simultaneously.  The five
/// classic families are the existing `mech_cache` users; the recovery
/// families own the cancel-only paths that must not evict a classic slot.
/// Message, VerifySignature and call-scoped (`OneShot`) families arrive with
/// their migration slices.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(super) enum OperationFamily {
    Encrypt,
    Decrypt,
    Digest,
    Sign,
    Verify,
    SignRecover,
    VerifyRecover,
}

impl OperationFamily {
    /// Every family slot a session can hold (W1-L13-16). Session-close
    /// eviction removes these keys directly instead of retain-scanning
    /// the whole cache; keep in sync with the variants (pinned by
    /// `operation_family_all_covers_every_variant`).
    pub(super) const ALL: [OperationFamily; 7] = [
        OperationFamily::Encrypt,
        OperationFamily::Decrypt,
        OperationFamily::Digest,
        OperationFamily::Sign,
        OperationFamily::Verify,
        OperationFamily::SignRecover,
        OperationFamily::VerifyRecover,
    ];
}

/// FFI backend that loads a PKCS#11 shared library via dlopen (ADR-0004 §2).
pub struct FfiBackend {
    object_cleanup: crate::object_cleanup::ObjectCleanupQuarantine,
    _lib: Library, // kept alive to prevent unloading
    func_list: *mut cryptoki_sys::CK_FUNCTION_LIST,
    /// PKCS#11 3.0 function list, if the module supports `C_GetInterface`.
    func_list_3_0: Option<*const cryptoki_sys::CK_FUNCTION_LIST_3_0>,
    /// PKCS#11 3.2 function list, if the module supports `C_GetInterface`.
    func_list_3_2: Option<*const cryptoki_sys::CK_FUNCTION_LIST_3_2>,
    initialize_args: Option<CString>,
    /// Per-session, per-family mechanism parameter cache.  Some backends
    /// (OpenCryptoki) store pointers from the mechanism struct passed to
    /// *Init calls and dereference them during the subsequent operation
    /// (Encrypt/Decrypt/…).  The spec says backends should copy, but for
    /// compatibility we keep the FfiMechanism (and its backing buffers)
    /// alive until the same family's next Init, cancel, or session close
    /// replaces it.  Keying by [`OperationFamily`] (C3M.3) means a later
    /// `*Init` of another family — e.g. Digest after Encrypt, per the pinned
    /// OASIS dual-operation example — never evicts the first family's
    /// retained graph, and a cancel retires only its own family's slot.
    ///
    /// Sharded (`DashMap`) so concurrent sessions doing crypto `*Init` calls on
    /// the shared backend do not serialise on one global lock (L4).
    mech_cache: DashMap<(u64, OperationFamily), ffi_conversion::FfiMechanism>,
    /// Per-session marker naming the family stored by the last `*Init` call.
    /// Preserves the documented [`Pkcs11Backend::session_output_mechanism_params`]
    /// contract ("set by the last `*_init` call") now that retention slots
    /// are per-family: the unscoped read resolves through this marker.
    last_init_family: DashMap<u64, OperationFamily>,
    /// Map of session handle -> slot id. Lets a per-session close path find the
    /// owning slot in O(1) to keep [`slot_sessions`](Self::slot_sessions)
    /// consistent. Populated on successful `ffi_open_session`, drained on close.
    session_slot_map: DashMap<u64, u64>,
    /// Reverse index slot id -> set of session handles open on that slot. Lets
    /// `C_CloseAllSessions` evict exactly the sessions on one slot in
    /// O(sessions-on-slot) instead of scanning every session (L4).
    slot_sessions: DashMap<u64, HashSet<u64>>,
    /// Proof that this instance owns the process construction slot (C3M.4).
    /// The reservation is released when the last owner drops; stale handles
    /// can never free another epoch's slot.
    construction: native_domain::ConstructionPermit,
    /// Locally observed init/finalize/session lifecycle driving the honest
    /// retirement decision in `Drop` (C3M.4).
    lifecycle: native_domain::LifecycleTracker,
    /// F-01 lifecycle domain: module state machine + ordinary admission
    /// (TF01a). Starts `LoadedUninitialized`; the first successful
    /// `C_Initialize` publishes `Open`, which admits ordinary work.
    lifecycle_domain: native_domain::LifecycleDomain,
    /// Per-session generation fences (TF01b/I4): every session-bearing
    /// ordinary path enters its fence under its admission; closes mark.
    session_fences: session_fence::SessionFenceTable,
    /// Last-field retirement sentinel (C3M step 7). MUST stay the last
    /// field: field drops run in declaration order, so its `Drop`
    /// publishes the next `Vacant` only after every other field —
    /// dependent graphs, the `Library` (`dlclose`), the permit and the
    /// lifecycle — has retired. The `Drop` body publishes only `Retiring`
    /// on the Release path. Never read: its only role is its `Drop`.
    #[allow(dead_code)]
    retirement_sentinel: native_domain::RetirementSentinel,
}

// Safety: PKCS#11 spec requires modules loaded with CKF_OS_LOCKING_OK to be
// thread-safe. We enforce this flag in C_Initialize via initialize().
// The raw pointers (func_list, func_list_3_0, func_list_3_2) all point into
// the loaded module's static data; the module is kept alive by `_lib`.
unsafe impl Send for FfiBackend {}
unsafe impl Sync for FfiBackend {}

impl FfiBackend {
    /// Test-only base constructor (W1-L11-13): the single `FfiBackend`
    /// struct literal for stub-backed tests. Per-test `backend_with_*`
    /// installers build their function-list stubs, then delegate here
    /// for the backend half; the table `Box`es stay caller-owned so the
    /// raw pointers cannot dangle. Unmanaged test permit: bypasses the
    /// process reservation without consuming it; never backs production
    /// dispatch (C3M.4). Visible to unit tests plus the
    /// `native-owner-test-hooks` feature (T10 shutdown-lifetime child
    /// tests); default builds observe no such symbol.
    /// Managed variant of [`Self::test_backend_with_tables`] (T10): reserves
    /// and activates the process construction slot, so the instance takes
    /// the final-owner guard path on drop (unmanaged fixtures bypass it).
    /// For shutdown-lifetime child tests that must prove guard behavior
    /// (failed native Finalize → 70). The child must hold no other
    /// backend; reservation/activation failure returns `Err`.
    #[cfg(any(test, feature = "native-owner-test-hooks"))]
    pub fn test_backend_managed_with_tables(
        func_list: *mut cryptoki_sys::CK_FUNCTION_LIST,
    ) -> Result<Self, String> {
        let permit = native_domain::reserve_for_construction()
            .map_err(|e| format!("reserve construction slot: {e:?}"))?;
        permit.activate().map_err(|e| format!("activate construction slot: {e:?}"))?;
        Ok(Self {
            _lib: loading::test_library_handle(),
            func_list,
            func_list_3_0: None,
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            retirement_sentinel: native_domain::RetirementSentinel::for_permit(&permit),
            construction: permit,
            lifecycle: Default::default(),
            lifecycle_domain: Default::default(),
            session_fences: Default::default(),
        })
    }

    #[cfg(any(test, feature = "native-owner-test-hooks"))]
    pub fn test_backend_with_tables(
        func_list: *mut cryptoki_sys::CK_FUNCTION_LIST,
        func_list_3_0: Option<*const cryptoki_sys::CK_FUNCTION_LIST_3_0>,
        func_list_3_2: Option<*const cryptoki_sys::CK_FUNCTION_LIST_3_2>,
    ) -> Self {
        Self {
            _lib: loading::test_library_handle(),
            func_list,
            func_list_3_0,
            func_list_3_2,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            construction: native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            lifecycle_domain: Default::default(),
            session_fences: Default::default(),
            retirement_sentinel: native_domain::RetirementSentinel::unmanaged_test_only(),
        }
    }
}

impl FfiBackend {
    const FUNCTION_NOT_SUPPORTED: CkRv = CkRv::FUNCTION_NOT_SUPPORTED;

    fn ffi_attr_ptr(ffi_attrs: &FfiAttrs) -> *mut cryptoki_sys::CK_ATTRIBUTE {
        // Wave 3.5 D2: a caller-NULL template reaches the provider as NULL.
        // An empty non-NULL template keeps the (dangling) non-NULL address.
        if ffi_attrs.null_template {
            std::ptr::null_mut()
        } else {
            ffi_attrs.attrs.as_ptr() as *mut _
        }
    }

    fn ffi_attr_len(ffi_attrs: &FfiAttrs) -> CkResult<cryptoki_sys::CK_ULONG> {
        Self::ulong_len(ffi_attrs.attrs.len())
    }

    /// Post-seal half of Finalize, shared by `finalize()` and
    /// `finalize_with_grace()` (T10 extraction; behavior unchanged):
    /// enter `Finalizing`, run the exclusive native `C_Finalize`, and on
    /// success publish `Finalized` with the incarnation purge. On native
    /// error the seal is abandoned (incarnation uncertain, bindings
    /// kept) and the provider RV propagates. The caller holds the armed
    /// `DeadlineGuard` across this call.
    fn finish_finalize(&self, seal: native_domain::FinalizeTicket<'_>) -> CkResult<()> {
        // Exclusive native call on this thread, which holds the armed
        // `DeadlineGuard` (no spawned worker; the ticket is detached —
        // write is NOT held across native entry, mirroring Initialize).
        // An `enter_finalizing` failure drops the seal through the Drop
        // backstop, abandoning the seal before the error propagates.
        seal.enter_finalizing()?;
        // Control choke: Finalize holds no read (the seal above took short
        // writes only, never read) — the choke takes no guard, structurally.
        let outcome =
            Self::call_control_unit(unsafe { (*self.func_list).C_Finalize }, |function| unsafe {
                function(std::ptr::null_mut())
            });
        if outcome.is_err() {
            // The failure proves nothing about provider state, so the seal
            // is abandoned (the live incarnation keeps admitting) and every
            // binding stays — but the incarnation is now uncertain, and a
            // later re-initialization is refused until a successful
            // C_Finalize (F-08).
            self.lifecycle_domain.abandon_finalize(seal);
            self.lifecycle.note_finalize_failed();
            return outcome;
        }
        // Record the clean close BEFORE publishing: a (practically
        // unreachable) publish failure must not leave C3M believing an
        // incarnation is live after its provider finalized.
        self.lifecycle.note_finalized();
        // Publish `Finalized` with the incarnation purge INSIDE the publish
        // write section (I2 mirror): `Finalized` implies purged, so a racing
        // re-Initialize observes no dead bindings.
        // This is the daemon/backend finalizer, not the per-client gRPC
        // Finalize path. Per-client Finalize removes only that client context
        // and closes its sessions. Once the underlying module accepts
        // C_Finalize, every cached session binding is out of scope.
        self.lifecycle_domain.publish_finalized_with_purge(seal, || {
            self.drop_all_mech_cache();
        })?;
        Ok(())
    }
}

/// Hooks-gated read of the stop-qualification predicate (T10 review
/// must-fix): reports the REAL [`native_stop::NATIVE_STOP_QUALIFIED`]
/// value instead of a hand-maintained `cfg!` mirror, so cross-target
/// shutdown-lifetime tests (i686, aarch64, macOS, Windows) assert the
/// same qualification the backend enforces and a leg edit cannot
/// desync the oracle. Pure predicate read; no hook state. Visible to
/// unit tests plus the `native-owner-test-hooks` feature; default
/// builds observe no such symbol.
#[cfg(any(test, feature = "native-owner-test-hooks"))]
pub fn stop_qualified_target() -> bool {
    native_stop::NATIVE_STOP_QUALIFIED
}

/// Map a local lifecycle refusal to its caller-visible `CK_RV` (F-08).
/// Neither value is a provider observation; both are fail-closed local
/// denials that reach the caller without any provider contact:
/// - `FailedFinalizeUnresolved` → `CRYPTOKI_ALREADY_INITIALIZED`: after a
///   failed Finalize the old incarnation may still be live, and PKCS#11
///   reports Initialize-against-live as already-initialized. Precedent:
///   `MockBackend::initialize_backend` refuses re-init the same way.
/// - `GenerationExhausted` → `GENERAL_ERROR`: no standard `CK_RV` covers
///   local identifier-space exhaustion, so the generic local failure stands.
fn lifecycle_refusal_rv(refusal: native_domain::LifecycleRefusal) -> CkRv {
    match refusal {
        native_domain::LifecycleRefusal::FailedFinalizeUnresolved => {
            CkRv::CRYPTOKI_ALREADY_INITIALIZED
        }
        native_domain::LifecycleRefusal::GenerationExhausted => CkRv::GENERAL_ERROR,
    }
}

impl Pkcs11Backend for FfiBackend {
    fn initialize(&self) -> CkResult<()> {
        let mut args = cryptoki_sys::CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: cryptoki_sys::CKF_OS_LOCKING_OK,
            pReserved: self
                .initialize_args
                .as_ref()
                .map(|s| s.as_ptr() as *mut std::ffi::c_void)
                .unwrap_or(std::ptr::null_mut()),
        };
        // F-08 gate BEFORE native entry: a refused cycle never touches the
        // provider and records nothing — not even the attempt marker — so
        // the retained-session evidence stays intact.
        self.lifecycle.check_reinitialize().map_err(lifecycle_refusal_rv)?;
        // F-01 control transition (TF01a): short write entering
        // `Initializing`. Never holds read (this path admits nothing), and
        // the ticket is detached — the write is not HELD across the native
        // call below. ACQUIRING write still blocks until in-flight readers
        // drain (a queued writer also stalls new admissions); that blocking
        // is intended (I1 decision — see the design block), unreachable in
        // the daemon flow (init-once-at-startup; per-client Initialize never
        // touches the backend).
        let init_control = self.lifecycle_domain.begin_initialize()?;
        // Fail-closed attempt marker BEFORE native entry (C3M steps 4-5):
        // a failed `C_Initialize` ran provider code, so the reservation
        // must poison instead of recycling.
        self.lifecycle.note_init_attempted();
        // Control choke: Initialize takes the write lock (above) while
        // holding no read — the choke takes no guard, structurally.
        let outcome =
            Self::call_control_unit(unsafe { (*self.func_list).C_Initialize }, |function| unsafe {
                function(&mut args as *mut _ as cryptoki_sys::CK_VOID_PTR)
            });
        if outcome.is_err() {
            // Native failure restores the prior domain state (behavior
            // parity: a failed re-Initialize leaves a live incarnation
            // usable, exactly as before the domain existed).
            self.lifecycle_domain.abandon_initialize(init_control);
            return outcome;
        }
        // A new initialization cycle starts a clean incarnation (C3M.4/row
        // 10): session bindings cached under a dead generation must not
        // survive, or a reused numeric handle would alias stale owners.
        // Re-affirming an already-open incarnation keeps its live bindings.
        let generation_before = self.lifecycle.current_generation();
        // Checked record: the residual refusal (a Finalize failed, or the
        // last generation was claimed, after the gate passed) propagates
        // before the purge, so a refused cycle purges nothing. (The `?`
        // also drops the control ticket, abandoning the domain transition.)
        self.lifecycle.note_initialized().map_err(lifecycle_refusal_rv)?;
        // Publish `Open` with the incarnation purge INSIDE the publish
        // write section (I2): the write acquisition drains pre-publish
        // in-flight readers, and post-publish admissions wait until the
        // purge completes — no admitted reader ever observes a live
        // incarnation's stale bindings. Failure here (poison/epoch
        // exhaustion — practically unreachable) fails closed without
        // purging, like a refused cycle.
        let generation_changed = self.lifecycle.current_generation() != generation_before;
        self.lifecycle_domain.publish_open_with_purge(init_control, || {
            if generation_changed {
                self.drop_all_mech_cache();
            }
        })?;
        Ok(())
    }

    fn finalize(&self) -> CkResult<()> {
        let _deadline = native_stop::arm_shutdown_deadline(native_stop::shutdown_grace());
        // TF01b seal/drain (I3): the two-arm acquisition drains in-flight
        // ordinary work and seals admission (`Draining`) before native
        // entry. Deadline overrun suicides inside `begin_finalize` — this
        // path never runs native unsealed. Denial (no live incarnation,
        // concurrent control, poison, exhaustion) returns WITHOUT native
        // entry; the RV matches what a compliant provider reports outside
        // a live incarnation, so out-of-incarnation callers observe no
        // new RV.
        let seal = self.lifecycle_domain.begin_finalize()?;
        self.finish_finalize(seal)
    }

    fn finalize_with_grace(&self, grace: std::time::Duration) -> CkResult<()> {
        // T10 coordinator path: ONE absolute deadline, sampled once for
        // the seal (`now + grace`); the controller arm takes the same
        // `grace` but re-samples its own clock at arm time, so arm-1
        // and the controller agree on `D` within scheduling jitter.
        let deadline = std::time::Instant::now() + grace;
        let _deadline = native_stop::arm_shutdown_deadline(grace);
        let seal = self.lifecycle_domain.begin_finalize_with_deadline(deadline)?;
        self.finish_finalize(seal)
    }

    fn finalize_is_natively_bounded(&self) -> bool {
        native_stop::NATIVE_STOP_QUALIFIED
    }

    fn get_info(&self) -> CkResult<CkInfo> {
        self.ffi_get_info()
    }

    fn get_slot_list(&self, token_present: bool) -> CkResult<Vec<CkSlotId>> {
        self.ffi_get_slot_list(token_present)
    }

    fn get_slot_info(&self, slot_id: CkSlotId) -> CkResult<CkSlotInfo> {
        self.ffi_get_slot_info(slot_id)
    }

    fn get_token_info(&self, slot_id: CkSlotId) -> CkResult<CkTokenInfo> {
        self.ffi_get_token_info(slot_id)
    }

    fn get_mechanism_list(&self, slot_id: CkSlotId) -> CkResult<Vec<CkMechanismType>> {
        self.ffi_get_mechanism_list(slot_id)
    }

    fn get_mechanism_info(
        &self,
        slot_id: CkSlotId,
        mech: CkMechanismType,
    ) -> CkResult<CkMechanismInfo> {
        self.ffi_get_mechanism_info(slot_id, mech)
    }

    fn init_token(&self, slot_id: CkSlotId, so_pin: Option<&[u8]>, label: &str) -> CkResult<()> {
        self.ffi_init_token(slot_id, so_pin, label)
    }

    fn init_pin(&self, session: CkSessionHandle, pin: Option<&[u8]>) -> CkResult<()> {
        self.ffi_init_pin(session, pin)
    }

    fn set_pin(
        &self,
        session: CkSessionHandle,
        old_pin: Option<&[u8]>,
        new_pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.ffi_set_pin(session, old_pin, new_pin)
    }

    fn open_session(&self, slot_id: CkSlotId, flags: CkSessionFlags) -> CkResult<CkSessionHandle> {
        self.ffi_open_session(slot_id, flags)
    }

    fn close_session(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_close_session(session)
    }

    fn close_all_sessions(&self, slot_id: CkSlotId) -> CkResult<()> {
        self.ffi_close_all_sessions(slot_id)
    }

    fn get_session_info(&self, session: CkSessionHandle) -> CkResult<CkSessionInfo> {
        self.ffi_get_session_info(session)
    }

    fn login(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.ffi_login(session, user_type, pin)
    }

    fn logout(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_logout(session)
    }

    fn find_objects_init(
        &self,
        session: CkSessionHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<()> {
        self.ffi_find_objects_init(session, template)
    }

    fn find_objects(
        &self,
        session: CkSessionHandle,
        max_count: u32,
    ) -> CkResult<Vec<CkObjectHandle>> {
        self.ffi_find_objects(session, max_count)
    }

    fn find_objects_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_find_objects_final(session)
    }

    fn get_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &mut [CkAttribute],
    ) -> CkResult<()> {
        self.ffi_get_attribute_value(session, object, template)
    }
    fn get_attribute_value_exact(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        queries: &[CkAttributeQuery],
    ) -> CkResult<(CkRv, Vec<CkAttributeQueryResult>)> {
        self.ffi_get_attribute_value_exact(session, object, queries)
    }

    fn sign_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_sign_init(session, mechanism, key)
    }

    fn sign_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_sign_init_cancel(session)
    }

    fn sign(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.ffi_sign(session, data)
    }

    fn sign_update(&self, session: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<()> {
        self.ffi_sign_update(session, part)
    }

    fn sign_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        self.ffi_sign_final(session)
    }

    fn sign_recover_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_sign_recover_init(session, mechanism, key)
    }

    fn sign_recover_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_sign_recover_init_cancel(session)
    }

    fn sign_recover(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.ffi_sign_recover(session, data)
    }

    fn sign_exact(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_sign_exact(session, data, spec)
    }

    fn sign_final_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_sign_final_exact(session, spec)
    }

    fn sign_recover_exact(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_sign_recover_exact(session, data, spec)
    }

    fn verify_recover_exact(
        &self,
        session: CkSessionHandle,
        signature: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_verify_recover_exact(session, signature, spec)
    }

    fn verify_recover_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_verify_recover_init(session, mechanism, key)
    }

    fn verify_recover_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_verify_recover_init_cancel(session)
    }

    fn verify_recover(
        &self,
        session: CkSessionHandle,
        signature: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.ffi_verify_recover(session, signature)
    }

    fn verify_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_verify_init(session, mechanism, key)
    }

    fn verify_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_verify_init_cancel(session)
    }

    fn verify(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        self.ffi_verify(session, data, signature)
    }

    fn verify_update(&self, session: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<()> {
        self.ffi_verify_update(session, part)
    }

    fn verify_final(&self, session: CkSessionHandle, signature: CkInBuf<'_>) -> CkResult<()> {
        self.ffi_verify_final(session, signature)
    }

    fn digest_init(&self, session: CkSessionHandle, mechanism: &CkMechanism) -> CkResult<()> {
        self.ffi_digest_init(session, mechanism)
    }

    fn digest_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_digest_init_cancel(session)
    }

    fn digest(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.ffi_digest(session, data)
    }

    fn digest_update(&self, session: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<()> {
        self.ffi_digest_update(session, part)
    }

    fn digest_key(&self, session: CkSessionHandle, key: CkObjectHandle) -> CkResult<()> {
        self.ffi_digest_key(session, key)
    }

    fn digest_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        self.ffi_digest_final(session)
    }

    fn digest_exact(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_digest_exact(session, data, spec)
    }

    fn digest_final_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_digest_final_exact(session, spec)
    }

    fn encrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        self.ffi_encrypt_init_with_output(session, mechanism, key)
    }

    fn encrypt_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_encrypt_init_cancel(session)
    }

    fn encrypt(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.ffi_encrypt(session, data)
    }

    fn encrypt_update(&self, session: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.ffi_encrypt_update(session, part)
    }

    fn encrypt_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        self.ffi_encrypt_final(session)
    }

    fn decrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        self.ffi_decrypt_init(session, mechanism, key)
    }

    fn decrypt_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_decrypt_init_cancel(session)
    }

    fn session_output_mechanism_params(
        &self,
        session: CkSessionHandle,
    ) -> Option<CkMechanismParams> {
        // Last-`*Init`-wins, per the trait contract: resolve the family
        // recorded by the most recent Init, then read that family's slot.
        // A retired marker family yields None rather than a sibling's graph.
        self.last_init_family
            .get(&session.0)
            .and_then(|family| self.cached_mechanism_output_params_for(session, *family))
    }

    fn decrypt(
        &self,
        session: CkSessionHandle,
        encrypted_data: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.ffi_decrypt(session, encrypted_data)
    }

    fn decrypt_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.ffi_decrypt_update(session, encrypted_part)
    }

    fn decrypt_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        self.ffi_decrypt_final(session)
    }

    fn encrypt_exact(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_encrypt_exact(session, data, spec)
    }

    fn encrypt_exact_with_output(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)> {
        self.ffi_encrypt_exact_with_output(session, data, spec)
    }

    fn encrypt_update_exact(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_encrypt_update_exact(session, part, spec)
    }

    fn encrypt_final_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_encrypt_final_exact(session, spec)
    }

    fn decrypt_exact(
        &self,
        session: CkSessionHandle,
        encrypted_data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_decrypt_exact(session, encrypted_data, spec)
    }

    fn decrypt_update_exact(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_decrypt_update_exact(session, encrypted_part, spec)
    }

    fn decrypt_final_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_decrypt_final_exact(session, spec)
    }

    fn derive_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.ffi_derive_key(session, mechanism, base_key, template)
    }

    fn derive_key_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, Option<CkMechanismParams>)> {
        self.ffi_derive_key_with_output(session, mechanism, base_key, template)
    }

    fn derive_key_with_output_result(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkDeriveKeyOutputResult> {
        self.ffi_derive_key_with_output_result(session, mechanism, base_key, template)
    }

    fn wrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
    ) -> CkResult<SecretBytes> {
        self.ffi_wrap_key(session, mechanism, wrapping_key, key)
    }

    fn wrap_key_exact(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_wrap_key_exact(session, mechanism, wrapping_key, key, spec)
    }

    fn wrap_key_exact_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)> {
        self.ffi_wrap_key_exact_with_output(session, mechanism, wrapping_key, key, spec)
    }

    fn unwrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.ffi_unwrap_key(session, mechanism, unwrapping_key, wrapped_key, template)
    }

    fn generate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.ffi_generate_key(session, mechanism, template)
    }

    fn generate_key_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, Option<CkMechanismParams>)> {
        self.ffi_generate_key_with_output(session, mechanism, template)
    }

    fn create_object(
        &self,
        session: CkSessionHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.ffi_create_object(session, template)
    }

    fn copy_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.ffi_copy_object(session, object, template)
    }

    fn destroy_object(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<()> {
        self.ffi_destroy_object(session, object)
    }
    fn destroy_quarantined_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_destroy_object_unadmitted(session, object)
    }

    fn get_object_size(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<u64> {
        self.ffi_get_object_size(session, object)
    }

    fn set_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<()> {
        self.ffi_set_attribute_value(session, object, template)
    }

    fn generate_key_pair(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        pub_template: Option<&[CkAttribute]>,
        priv_template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        self.ffi_generate_key_pair(session, mechanism, pub_template, priv_template)
    }

    fn wait_for_slot_event(&self, flags: u64) -> CkResult<CkSlotId> {
        self.ffi_wait_for_slot_event(flags)
    }

    fn admit_slot_wait(&self, flags: u64) -> CkResult<()> {
        self.ffi_admit_slot_wait(flags)
    }

    fn get_operation_state(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        self.ffi_get_operation_state(session)
    }

    fn get_operation_state_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_get_operation_state_exact(session, spec)
    }

    fn set_operation_state(
        &self,
        session: CkSessionHandle,
        state: CkInBuf<'_>,
        enc_key: CkObjectHandle,
        auth_key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_set_operation_state(session, state, enc_key, auth_key)
    }

    fn seed_random(&self, session: CkSessionHandle, seed: CkInBuf<'_>) -> CkResult<()> {
        self.ffi_seed_random(session, seed)
    }

    fn generate_random(&self, session: CkSessionHandle, len: u32) -> CkResult<SecretBytes> {
        self.ffi_generate_random(session, len)
    }

    fn get_function_status(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_get_function_status(session)
    }

    fn cancel_function(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_cancel_function(session)
    }

    fn digest_encrypt_update(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.ffi_digest_encrypt_update(session, part)
    }

    fn digest_encrypt_update_exact(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_digest_encrypt_update_exact(session, part, spec)
    }

    fn decrypt_digest_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.ffi_decrypt_digest_update(session, encrypted_part)
    }

    fn decrypt_digest_update_exact(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_decrypt_digest_update_exact(session, encrypted_part, spec)
    }

    fn sign_encrypt_update(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.ffi_sign_encrypt_update(session, part)
    }

    fn sign_encrypt_update_exact(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_sign_encrypt_update_exact(session, part, spec)
    }

    fn decrypt_verify_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.ffi_decrypt_verify_update(session, encrypted_part)
    }

    fn decrypt_verify_update_exact(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_decrypt_verify_update_exact(session, encrypted_part, spec)
    }

    // --- PKCS#11 3.0/3.2 overrides ---

    fn login_user(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        username: Option<&[u8]>,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.ffi_login_user(session, user_type, username, pin)
    }

    fn session_cancel(&self, session: CkSessionHandle, flags: CkFlags) -> CkResult<()> {
        self.ffi_session_cancel(session, flags)
    }

    fn get_session_validation_flags(
        &self,
        session: CkSessionHandle,
        flags_type: u64,
    ) -> CkResult<u64> {
        self.ffi_get_session_validation_flags(session, flags_type)
    }

    fn encapsulate_key_exact(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        public_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputAndHandleResult> {
        self.ffi_encapsulate_key_exact(session, mechanism, public_key, template, spec)
    }

    fn encapsulate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        public_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<(SecretBytes, CkObjectHandle)> {
        self.ffi_encapsulate_key(session, mechanism, public_key, template)
    }

    fn decapsulate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        private_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
        ciphertext: CkInBuf<'_>,
    ) -> CkResult<CkObjectHandle> {
        self.ffi_decapsulate_key(session, mechanism, private_key, template, ciphertext)
    }

    // --- PKCS#11 3.0 message init/final overrides ---

    fn message_encrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        init_param: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_message_encrypt_init(session, mechanism, init_param, key)
    }

    fn message_encrypt_init_contract(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        init_param: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        key: CkObjectHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.ffi_message_encrypt_init_contract(session, mechanism, init_param, key, provider_spec)
    }

    fn message_encrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_message_encrypt_final(session)
    }

    fn message_decrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        init_param: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_message_decrypt_init(session, mechanism, init_param, key)
    }

    fn message_decrypt_init_contract(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        init_param: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        key: CkObjectHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.ffi_message_decrypt_init_contract(session, mechanism, init_param, key, provider_spec)
    }

    fn message_decrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_message_decrypt_final(session)
    }

    fn message_sign_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_message_sign_init(session, mechanism, key)
    }

    fn message_sign_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_message_sign_final(session)
    }

    fn message_verify_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_message_verify_init(session, mechanism, key)
    }

    fn message_verify_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_message_verify_final(session)
    }

    // --- PKCS#11 3.0 message one-shot/begin/next overrides ---

    fn encrypt_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: CkInBuf<'_>,
        plaintext: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        self.ffi_encrypt_message(session, parameter, aad, plaintext)
    }

    fn encrypt_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.ffi_encrypt_message_begin(session, parameter, aad)
    }

    fn encrypt_message_begin_exact(
        &self,
        session: CkSessionHandle,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.ffi_encrypt_message_begin_exact(session, aad, provider_spec)
    }

    fn encrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        plaintext_part: CkInBuf<'_>,
        flags: CkFlags,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        self.ffi_encrypt_message_next(session, parameter, plaintext_part, flags)
    }

    fn decrypt_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: CkInBuf<'_>,
        ciphertext: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        self.ffi_decrypt_message(session, parameter, aad, ciphertext)
    }

    fn decrypt_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.ffi_decrypt_message_begin(session, parameter, aad)
    }

    fn decrypt_message_begin_exact(
        &self,
        session: CkSessionHandle,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.ffi_decrypt_message_begin_exact(session, aad, provider_spec)
    }

    fn decrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        ciphertext_part: CkInBuf<'_>,
        flags: CkFlags,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        self.ffi_decrypt_message_next(session, parameter, ciphertext_part, flags)
    }

    fn sign_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        data: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        self.ffi_sign_message(session, parameter, data)
    }

    fn sign_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
    ) -> CkResult<SecretBytes> {
        self.ffi_sign_message_begin(session, parameter)
    }

    fn sign_message_begin_exact(
        &self,
        session: CkSessionHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.ffi_sign_message_begin_exact(session, provider_spec)
    }

    fn sign_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        data_part: CkInBuf<'_>,
        request_signature: bool,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        self.ffi_sign_message_next(session, parameter, data_part, request_signature)
    }

    fn sign_message_next_feed_exact(
        &self,
        session: CkSessionHandle,
        data_part: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.ffi_sign_message_next_feed_exact(session, data_part, provider_spec)
    }

    fn verify_message(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data: CkInBuf<'_>,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        self.ffi_verify_message(session, parameter, data, signature)
    }

    fn verify_message_exact(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        signature: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.ffi_verify_message_exact(session, data, signature, provider_spec)
    }

    fn verify_message_begin(&self, session: CkSessionHandle, parameter: &[u8]) -> CkResult<()> {
        self.ffi_verify_message_begin(session, parameter)
    }

    fn verify_message_begin_exact(
        &self,
        session: CkSessionHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.ffi_verify_message_begin_exact(session, provider_spec)
    }

    fn verify_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data_part: CkInBuf<'_>,
        is_final: bool,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        self.ffi_verify_message_next(session, parameter, data_part, is_final, signature)
    }

    fn verify_message_next_exact(
        &self,
        session: CkSessionHandle,
        data_part: CkInBuf<'_>,
        is_final: bool,
        signature: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.ffi_verify_message_next_exact(session, data_part, is_final, signature, provider_spec)
    }

    // --- PKCS#11 3.2 VerifySignature overrides ---

    fn verify_signature_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        self.ffi_verify_signature_init(session, mechanism, key, signature)
    }

    fn verify_signature(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<()> {
        self.ffi_verify_signature(session, data)
    }

    fn verify_signature_update(
        &self,
        session: CkSessionHandle,
        data_part: CkInBuf<'_>,
    ) -> CkResult<()> {
        self.ffi_verify_signature_update(session, data_part)
    }

    fn verify_signature_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_verify_signature_final(session)
    }

    // --- PKCS#11 3.2 Authenticated wrap overrides ---

    fn wrap_key_authenticated(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        self.ffi_wrap_key_authenticated(session, mechanism, wrapping_key, key, aad)
    }

    fn wrap_key_authenticated_typed(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput)>
    {
        self.ffi_wrap_authenticated_typed(session, mechanism, parameter, wrapping_key, key, aad)
    }

    fn wrap_key_authenticated_exact_typed(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput,
    )> {
        self.ffi_wrap_authenticated_exact_typed(
            session,
            mechanism,
            parameter,
            wrapping_key,
            key,
            aad,
            spec,
        )
    }

    fn unwrap_key_authenticated_typed(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: Option<&[CkAttribute]>,
        aad: CkInBuf<'_>,
    ) -> CkResult<(
        CkObjectHandle,
        pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput,
    )> {
        self.ffi_unwrap_authenticated_typed(
            session,
            mechanism,
            parameter,
            unwrapping_key,
            wrapped_key,
            template,
            aad,
        )
    }

    fn unwrap_key_authenticated(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: Option<&[CkAttribute]>,
        aad: CkInBuf<'_>,
    ) -> CkResult<(CkObjectHandle, SecretBytes)> {
        self.ffi_unwrap_key_authenticated(
            session,
            mechanism,
            unwrapping_key,
            wrapped_key,
            template,
            aad,
        )
    }

    // --- Track C: Exact parameter-output overrides ---

    fn encrypt_message_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: CkInBuf<'_>,
        plaintext: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_encrypt_message_exact(
            session,
            parameter,
            aad,
            plaintext,
            output_spec,
            param_out_spec,
        )
    }

    fn decrypt_message_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: CkInBuf<'_>,
        ciphertext: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_decrypt_message_exact(
            session,
            parameter,
            aad,
            ciphertext,
            output_spec,
            param_out_spec,
        )
    }

    fn sign_message_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_sign_message_exact(session, parameter, data, output_spec, param_out_spec)
    }

    fn encrypt_message_next_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        plaintext_part: CkInBuf<'_>,
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_encrypt_message_next_exact(
            session,
            parameter,
            plaintext_part,
            flags,
            output_spec,
            param_out_spec,
        )
    }

    fn decrypt_message_next_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        ciphertext_part: CkInBuf<'_>,
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_decrypt_message_next_exact(
            session,
            parameter,
            ciphertext_part,
            flags,
            output_spec,
            param_out_spec,
        )
    }

    fn sign_message_next_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data_part: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_sign_message_next_exact(session, parameter, data_part, output_spec, param_out_spec)
    }

    fn wrap_key_authenticated_exact(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_wrap_key_authenticated_exact(
            session,
            mechanism,
            wrapping_key,
            key,
            aad,
            output_spec,
            param_out_spec,
        )
    }

    // --- Structured message parameter variants ---

    fn encrypt_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        aad: CkInBuf<'_>,
        plaintext: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        self.ffi_encrypt_message_exact_msg(
            session,
            msg_param,
            aad,
            plaintext,
            output_spec,
            provider_spec,
        )
    }

    fn decrypt_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        aad: CkInBuf<'_>,
        ciphertext: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        self.ffi_decrypt_message_exact_msg(
            session,
            msg_param,
            aad,
            ciphertext,
            output_spec,
            provider_spec,
        )
    }

    fn encrypt_message_begin_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        self.ffi_encrypt_message_begin_msg(session, msg_param, aad, provider_spec)
    }

    fn decrypt_message_begin_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        self.ffi_decrypt_message_begin_msg(session, msg_param, aad, provider_spec)
    }

    fn sign_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        data: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        self.ffi_sign_message_exact_msg(session, msg_param, data, output_spec)
    }

    fn encrypt_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        plaintext_part: CkInBuf<'_>,
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        self.ffi_encrypt_message_next_exact_msg(
            session,
            msg_param,
            plaintext_part,
            flags,
            output_spec,
            provider_spec,
        )
    }

    fn decrypt_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        ciphertext_part: CkInBuf<'_>,
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        self.ffi_decrypt_message_next_exact_msg(
            session,
            msg_param,
            ciphertext_part,
            flags,
            output_spec,
            provider_spec,
        )
    }

    fn sign_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        data_part: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        self.ffi_sign_message_next_exact_msg(session, msg_param, data_part, output_spec)
    }

    // --- BUG-001: Interface version transparency ---

    fn get_interface_capabilities(&self) -> InterfaceCapabilities {
        self.detect_interface_capabilities()
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    unsafe extern "C" fn finalize_ok(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn finalize_fails(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_GENERAL_ERROR
    }

    unsafe extern "C" fn initialize_ok(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    std::thread_local! {
        static INITIALIZE_CALL_COUNT: std::cell::Cell<usize> =
            const { std::cell::Cell::new(0) };
    }

    /// Counting `C_Initialize` stub: proves refused cycles never reach the
    /// provider. Thread-local because libtest runs each `#[test]` on its own
    /// thread, so parallel tests cannot pollute each other's count.
    unsafe extern "C" fn initialize_counting_ok(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
        INITIALIZE_CALL_COUNT.with(|count| count.set(count.get() + 1));
        cryptoki_sys::CKR_OK
    }

    fn initialize_call_count() -> usize {
        INITIALIZE_CALL_COUNT.with(|count| count.get())
    }

    unsafe extern "C" fn initialize_fails(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_GENERAL_ERROR
    }

    fn backend_with_finalize(
        finalize: cryptoki_sys::CK_C_Finalize,
    ) -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        backend_with_init_and_finalize(None, finalize)
    }

    fn backend_with_init_and_finalize(
        initialize: cryptoki_sys::CK_C_Initialize,
        finalize: cryptoki_sys::CK_C_Finalize,
    ) -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_Initialize = initialize;
        functions.C_Finalize = finalize;

        let backend = FfiBackend::test_backend_with_tables(functions.as_mut(), None, None);

        (backend, functions)
    }

    #[test]
    fn initialize_publishes_open_admitting_ordinary() {
        // TF01a control wiring: a fresh backend denies ordinary work; a
        // successful native C_Initialize publishes Open, which admits.
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_ok), Some(finalize_ok));
        assert_eq!(
            backend.lifecycle_domain.admit_ordinary().unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
        backend.initialize().expect("initialize succeeds");
        backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
    }

    #[test]
    fn failed_initialize_restores_prior_domain_state() {
        // Behavior parity: native failure restores the prior state — a
        // failed first attempt keeps denying, a failed re-attempt keeps a
        // live incarnation usable — and the native RV propagates exactly.
        let (backend, mut functions) =
            backend_with_init_and_finalize(Some(initialize_fails), Some(finalize_ok));
        assert_eq!(backend.initialize().unwrap_err(), CkRv::GENERAL_ERROR);
        assert_eq!(
            backend.lifecycle_domain.admit_ordinary().unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
        functions.C_Initialize = Some(initialize_ok);
        backend.initialize().expect("retry succeeds");
        backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
        functions.C_Initialize = Some(initialize_fails);
        assert_eq!(backend.initialize().unwrap_err(), CkRv::GENERAL_ERROR);
        backend.lifecycle_domain.admit_ordinary().expect("live incarnation still admits");
    }

    fn seed_cache(backend: &FfiBackend) {
        let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
        let ffi_mechanism = ffi_conversion::mechanism_to_ffi(&mechanism).unwrap();
        backend.mech_cache.insert((7, OperationFamily::Sign), ffi_mechanism);
        backend.last_init_family.insert(7, OperationFamily::Sign);
        // Use the public path so the forward map and reverse index stay in sync.
        backend.remember_session_slot(CkSessionHandle(7), CkSlotId(11));
    }

    #[test]
    fn reinit_purge_never_visible_to_admitted_readers() {
        // I2 settling test: the re-Initialize incarnation purge runs INSIDE
        // the publish write section, so no admitted reader can ever observe
        // a live incarnation's bindings after the generation moved. Spinner
        // threads admit continuously across finalize/re-initialize cycles;
        // a (admitted, new generation, stale entry present) triple is the
        // exact race the subsystem exists to close.
        //
        // Each spinner triple is atomic w.r.t. the domain write lock (the
        // held guard blocks begin/publish mid-check), so post-fix the count
        // is deterministically zero; pre-fix the publish-then-purge gap lets
        // spinners catch the stale entry (red evidence: violations > 0).
        // Bulk seeding widens that gap (a 2000-entry clear holds the purge
        // window open while 4 hot spinners check it), so the red is reliable
        // instead of a coin flip per cycle.
        use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_ok), Some(finalize_ok));
        backend.initialize().expect("first initialize opens the incarnation");
        let violations = AtomicUsize::new(0);
        // Counting gate: only the current cycle's NEW generation judges.
        // Admits before the cycle (old generation, pre-purge bindings
        // legitimately present) and reseeds between cycles never count.
        let target_generation = AtomicU64::new(0);
        let observing = AtomicBool::new(false);
        let done = AtomicBool::new(false);
        let ready = AtomicUsize::new(0);
        // Whole-struct borrow: closures must capture `&FfiBackend` (covered
        // by its `unsafe impl Sync`), never `&mech_cache` directly (the
        // `FfiMechanism` values are !Send/!Sync by design).
        let backend = &backend;
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    ready.fetch_add(1, Ordering::SeqCst);
                    while !done.load(Ordering::SeqCst) {
                        if let Ok(_guard) = backend.lifecycle_domain.admit_ordinary() {
                            let generation = backend.lifecycle.current_generation();
                            let stale_present =
                                backend.mech_cache.contains_key(&(7, OperationFamily::Sign));
                            if observing.load(Ordering::SeqCst)
                                && generation == target_generation.load(Ordering::SeqCst)
                                && stale_present
                            {
                                violations.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                });
            }
            // All spinners hot before the first cycle: without this the
            // main thread can finish every cycle before a spinner is even
            // scheduled, hiding the race the test exists to catch.
            while ready.load(Ordering::SeqCst) < 4 {
                std::thread::yield_now();
            }
            for _ in 0..30 {
                backend.finalize().expect("finalize between cycles");
                // Each loop cycle is new (finalized_ok set): the generation
                // advances exactly once per initialize below.
                target_generation
                    .store(backend.lifecycle.current_generation() + 1, Ordering::SeqCst);
                seed_cache(backend);
                seed_bulk_cache(backend);
                observing.store(true, Ordering::SeqCst);
                backend.initialize().expect("re-initialize with generation change");
                observing.store(false, Ordering::SeqCst);
            }
            done.store(true, Ordering::SeqCst);
        });
        assert_eq!(
            violations.load(Ordering::SeqCst),
            0,
            "admitted readers must never observe stale bindings at a new generation"
        );
    }

    /// Bulk `mech_cache` ballast for the re-init race test: 2000 extra
    /// entries (cache-only, no slot-map bookkeeping — the purge clears every
    /// map unconditionally) so the purge window stays open long enough for
    /// spinning readers to observe it pre-fix.
    fn seed_bulk_cache(backend: &FfiBackend) {
        let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
        for session in 1000..3000u64 {
            let ffi_mechanism = ffi_conversion::mechanism_to_ffi(&mechanism).unwrap();
            backend.mech_cache.insert((session, OperationFamily::Sign), ffi_mechanism);
        }
    }

    #[test]
    fn ffi_attr_ptr_passes_null_for_null_templates() {
        // F3/D2: a caller-NULL template reaches the provider as NULL; an
        // empty non-NULL template keeps the (dangling) array address.
        let none = FfiAttrs::from_opt_slice(None).unwrap();
        assert!(FfiBackend::ffi_attr_ptr(&none).is_null());
        let empty = FfiAttrs::from_opt_slice(Some(&[])).unwrap();
        assert!(!FfiBackend::ffi_attr_ptr(&empty).is_null());
    }

    #[test]
    fn failed_initialize_poisons_instead_of_recycling() {
        // C3M steps 4-5: a failed `C_Initialize` ran native code, so the
        // reservation must never recycle — the retirement decision is
        // Poison (retain ownership), never Vacant.
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_fails), Some(finalize_ok));
        assert_eq!(backend.initialize().unwrap_err(), CkRv::GENERAL_ERROR);
        assert_eq!(
            backend.lifecycle.retirement_decision(),
            crate::ffi::native_domain::RetirementDecision::Poison,
            "failed Initialize must poison, never recycle"
        );
        assert_eq!(backend.lifecycle.open_session_count_for_tests(), 0);
        assert_eq!(backend.lifecycle.current_generation(), 0);
    }

    #[test]
    fn never_attempted_initialize_releases() {
        // Control leg: a backend whose `C_Initialize` was never attempted
        // stays on the Release path (C1 at the decision level).
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_fails), Some(finalize_ok));
        assert_eq!(
            backend.lifecycle.retirement_decision(),
            crate::ffi::native_domain::RetirementDecision::Release,
            "never-attempted backend must stay on the Release path"
        );
    }

    #[test]
    fn finalize_preserves_mechanism_cache_when_underlying_finalize_fails() {
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_ok), Some(finalize_fails));
        // Sealed paths need a live incarnation: establish post-Initialize
        // state, then plant the residue (a pre-init seed would not survive
        // the first-Initialize purge).
        backend.initialize().expect("initialize opens the incarnation");
        seed_cache(&backend);

        assert_eq!(backend.finalize().unwrap_err(), CkRv::GENERAL_ERROR);

        assert!(backend.mech_cache.contains_key(&(7, OperationFamily::Sign)));
        assert_eq!(backend.last_init_family.get(&7).as_deref(), Some(&OperationFamily::Sign));
        assert_eq!(backend.session_slot_map.get(&7).as_deref(), Some(&11));
    }

    #[test]
    fn finalize_clears_mechanism_cache_after_underlying_finalize_succeeds() {
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_ok), Some(finalize_ok));
        // Sealed paths need a live incarnation: establish post-Initialize
        // state, then plant the residue (a pre-init seed would not survive
        // the first-Initialize purge).
        backend.initialize().expect("initialize opens the incarnation");
        seed_cache(&backend);

        backend.finalize().unwrap();

        assert!(backend.mech_cache.is_empty());
        assert!(backend.last_init_family.is_empty());
        assert!(backend.session_slot_map.is_empty());
        assert!(backend.slot_sessions.is_empty());
    }

    #[test]
    fn initialize_after_failed_finalize_is_refused() {
        // F-08/MISS 2 (re-review-blessed rewrite of
        // `initialize_after_failed_finalize_starts_a_clean_incarnation`,
        // which pinned the violating behavior): re-initialization after a
        // failed Finalize is REFUSED — the provider state is unknown, so no
        // new generation opens, nothing purges, and the retained-session
        // evidence (open count) is not reset. The refusal lands before
        // native entry: the provider's C_Initialize is never called.
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_counting_ok), Some(finalize_fails));
        backend.initialize().expect("first initialization succeeds");
        assert_eq!(backend.lifecycle.current_generation(), 1);
        assert_eq!(initialize_call_count(), 1);
        backend.remember_session_slot(CkSessionHandle(7), CkSlotId(11));
        backend.lifecycle.note_session_opened();
        backend.lifecycle.note_session_opened();
        assert_eq!(backend.finalize().unwrap_err(), CkRv::GENERAL_ERROR);
        // Failed Finalize retains everything (existing contract).
        assert!(backend.session_slot_map.contains_key(&7));
        assert_eq!(backend.lifecycle.open_session_count_for_tests(), 2);

        assert_eq!(
            backend.initialize().unwrap_err(),
            CkRv::CRYPTOKI_ALREADY_INITIALIZED,
            "re-init after failed Finalize must be refused"
        );
        assert_eq!(backend.lifecycle.current_generation(), 1);
        assert_eq!(initialize_call_count(), 1, "refused re-init must not reach the provider");
        assert_eq!(backend.session_slot_map.get(&7).as_deref(), Some(&11));
        assert!(!backend.slot_sessions.is_empty());
        assert_eq!(backend.lifecycle.open_session_count_for_tests(), 2);
        assert_eq!(
            backend.lifecycle.retirement_decision(),
            crate::ffi::native_domain::RetirementDecision::Poison,
            "unresolved failed Finalize still poisons"
        );
    }

    #[test]
    fn initialize_at_generation_exhaustion_is_refused_before_native_entry() {
        // F-08/MISS 1 at the dispatch boundary: with no fresh generation
        // left, initialize() is refused with zero provider contact and zero
        // lifecycle side effects — not even the init-attempt marker, so the
        // refusal itself records no exposure.
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_counting_ok), Some(finalize_ok));
        backend.lifecycle.set_generation_for_tests(u64::MAX);
        assert_eq!(backend.initialize().unwrap_err(), CkRv::GENERAL_ERROR);
        assert_eq!(initialize_call_count(), 0, "exhausted init must not reach the provider");
        assert_eq!(backend.lifecycle.current_generation(), u64::MAX);
        assert_eq!(
            backend.lifecycle.retirement_decision(),
            crate::ffi::native_domain::RetirementDecision::Release,
            "pre-native refusal records no attempt"
        );
    }

    #[test]
    fn initialize_after_successful_finalize_starts_a_clean_incarnation() {
        // Interplay control for F-08/MISS 2: re-init after a SUCCESSFUL
        // Finalize still opens a fresh generation and purges dead bindings.
        // The stale residue planted between Finalize and re-init proves the
        // new-cycle purge runs on the legitimate path.
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_ok), Some(finalize_ok));
        backend.initialize().expect("first initialization succeeds");
        assert_eq!(backend.lifecycle.current_generation(), 1);
        backend.finalize().expect("finalize succeeds");
        seed_cache(&backend);
        backend.lifecycle.note_session_opened();
        backend.lifecycle.note_session_opened();

        backend.initialize().expect("re-initialization after successful finalize succeeds");
        assert_eq!(backend.lifecycle.current_generation(), 2);
        assert!(backend.session_slot_map.is_empty());
        assert!(backend.slot_sessions.is_empty());
        assert!(backend.mech_cache.is_empty());
        assert!(backend.last_init_family.is_empty());
        assert_eq!(backend.lifecycle.open_session_count_for_tests(), 0);
    }

    #[test]
    fn stale_init_completion_does_not_publish_into_new_incarnation() {
        // C3M.4/row 10: an Init whose native call ran under a dead
        // incarnation must not publish its owner into the new one, even
        // when the numeric session handle was reused and the native call
        // itself succeeded.
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_ok), Some(finalize_ok));
        backend.initialize().expect("first initialization succeeds");
        let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
        // Ordinary choke under test: admit like the `ffi_*` boundary would.
        let admission = backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
        let err = backend
            .call_init_with_mechanism(
                &admission,
                CkSessionHandle(7),
                OperationFamily::Sign,
                Some(0u8),
                &mechanism,
                |_, _| {
                    // Deterministic race simulation: the incarnation turns
                    // over while the native Init runs (successful Finalize,
                    // then a new Initialize — a failed Finalize can no
                    // longer turn the incarnation over, F-08).
                    backend.lifecycle.note_finalized();
                    backend.lifecycle.note_initialized().expect("legitimate turnover opens");
                    cryptoki_sys::CKR_OK
                },
            )
            .unwrap_err();
        assert_eq!(err, CkRv::SESSION_HANDLE_INVALID);
        assert!(backend.mech_cache.is_empty());
        assert!(backend.last_init_family.is_empty());
    }

    #[test]
    fn stale_init_completion_with_output_does_not_publish() {
        // Same dead-incarnation refusal through the output-bearing Init
        // choke point: extracted native output is discarded with the
        // retired owner, never published.
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_ok), Some(finalize_ok));
        backend.initialize().expect("first initialization succeeds");
        let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
        // Ordinary choke under test: admit like the `ffi_*` boundary would.
        let admission = backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
        let err = backend
            .call_init_with_mechanism_output(
                &admission,
                CkSessionHandle(7),
                OperationFamily::Sign,
                Some(0u8),
                &mechanism,
                |_, _| {
                    // Same legitimate turnover as above (F-08: failed
                    // Finalize can no longer open a new cycle).
                    backend.lifecycle.note_finalized();
                    backend.lifecycle.note_initialized().expect("legitimate turnover opens");
                    cryptoki_sys::CKR_OK
                },
            )
            .unwrap_err();
        assert_eq!(err, CkRv::SESSION_HANDLE_INVALID);
        assert!(backend.mech_cache.is_empty());
        assert!(backend.last_init_family.is_empty());
    }

    #[test]
    fn double_initialize_without_finalize_keeps_current_incarnation() {
        // Re-affirming an already-open incarnation must not evict its live
        // session bindings or reset its open count.
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_ok), Some(finalize_fails));
        backend.initialize().expect("first initialization succeeds");
        backend.remember_session_slot(CkSessionHandle(7), CkSlotId(11));
        backend.lifecycle.note_session_opened();

        backend.initialize().expect("second initialization succeeds");
        assert_eq!(backend.lifecycle.current_generation(), 1);
        assert_eq!(backend.session_slot_map.get(&7).as_deref(), Some(&11));
        assert_eq!(backend.lifecycle.open_session_count_for_tests(), 1);
    }

    #[test]
    fn drop_mech_cache_for_slot_evicts_only_that_slots_sessions() {
        // L4: per-slot eviction drops exactly the sessions open on the target
        // slot (resolved via the reverse index) and leaves other slots intact.
        let (backend, _functions) = backend_with_finalize(Some(finalize_ok));
        for (session, slot) in [(7u64, 11u64), (8, 11), (9, 22)] {
            let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
            backend.mech_cache.insert(
                (session, OperationFamily::Sign),
                ffi_conversion::mechanism_to_ffi(&mechanism).unwrap(),
            );
            backend.remember_session_slot(CkSessionHandle(session as u64), CkSlotId(slot as u64));
        }
        // Session 7 holds a second family slot: per-slot eviction must drop
        // every family of the evicted sessions, not just one entry.
        backend.mech_cache.insert(
            (7, OperationFamily::Encrypt),
            ffi_conversion::mechanism_to_ffi(&CkMechanism {
                mechanism_type: CkMechanismType::RSA_PKCS,
                params: None,
            })
            .unwrap(),
        );

        backend.drop_mech_cache_for_slot(CkSlotId(11));

        for evicted in [7u64, 8] {
            assert!(!backend.mech_cache.contains_key(&(evicted, OperationFamily::Sign)));
            assert!(backend.session_slot_map.get(&evicted).is_none());
        }
        assert!(!backend.mech_cache.contains_key(&(7, OperationFamily::Encrypt)));
        assert!(backend.mech_cache.contains_key(&(9, OperationFamily::Sign)));
        assert_eq!(backend.session_slot_map.get(&9).as_deref(), Some(&22));
        // The emptied slot-11 reverse entry is pruned; slot 22 still maps to {9}.
        assert!(backend.slot_sessions.get(&11).is_none());
        assert!(backend.slot_sessions.get(&22).is_some());
    }

    #[test]
    fn drop_mech_cache_session_evicts_all_families_only_for_that_session() {
        // W1-L13-16 pin: single-session eviction drops every family slot
        // plus the last-Init marker of exactly that session; sibling
        // sessions are untouched. Must pass before AND after the
        // retain-scan removal (mappings identical).
        let (backend, _functions) = backend_with_finalize(Some(finalize_ok));
        for family in OperationFamily::ALL {
            backend.mech_cache.insert(
                (7, family),
                ffi_conversion::mechanism_to_ffi(&CkMechanism {
                    mechanism_type: CkMechanismType::RSA_PKCS,
                    params: None,
                })
                .unwrap(),
            );
        }
        backend.mech_cache.insert(
            (8, OperationFamily::Sign),
            ffi_conversion::mechanism_to_ffi(&CkMechanism {
                mechanism_type: CkMechanismType::RSA_PKCS,
                params: None,
            })
            .unwrap(),
        );
        backend.last_init_family.insert(7, OperationFamily::Sign);
        backend.last_init_family.insert(8, OperationFamily::Sign);

        backend.drop_mech_cache_session(CkSessionHandle(7));

        for family in OperationFamily::ALL {
            assert!(
                !backend.mech_cache.contains_key(&(7, family)),
                "family {family:?} of session 7 evicted"
            );
        }
        assert!(backend.last_init_family.get(&7).is_none());
        assert!(backend.mech_cache.contains_key(&(8, OperationFamily::Sign)));
        assert_eq!(backend.last_init_family.get(&8).as_deref(), Some(&OperationFamily::Sign));
    }

    #[test]
    fn operation_family_all_covers_every_variant() {
        // W1-L13-16: `ALL` drives eviction; a new family must land in
        // it or session close would leak that family's slot. The
        // exhaustive match (no wildcard) breaks compilation on a new
        // variant; the length pins the set size.
        fn name(f: OperationFamily) -> &'static str {
            match f {
                OperationFamily::Encrypt => "encrypt",
                OperationFamily::Decrypt => "decrypt",
                OperationFamily::Digest => "digest",
                OperationFamily::Sign => "sign",
                OperationFamily::Verify => "verify",
                OperationFamily::SignRecover => "sign_recover",
                OperationFamily::VerifyRecover => "verify_recover",
            }
        }
        assert_eq!(OperationFamily::ALL.len(), 7);
        for family in OperationFamily::ALL {
            let _ = name(family);
        }
    }

    #[test]
    fn forget_session_slot_prunes_the_reverse_index() {
        // L4: forgetting a session removes it from the reverse index, and the
        // slot entry itself is dropped once its last session is gone.
        let (backend, _functions) = backend_with_finalize(Some(finalize_ok));
        backend.remember_session_slot(CkSessionHandle(7), CkSlotId(11));
        backend.remember_session_slot(CkSessionHandle(8), CkSlotId(11));

        backend.forget_session_slot(CkSessionHandle(7));
        assert_eq!(backend.slot_sessions.get(&11).map(|s| s.len()), Some(1));
        assert!(backend.slot_sessions.get(&11).unwrap().contains(&8));

        backend.forget_session_slot(CkSessionHandle(8));
        assert!(backend.slot_sessions.get(&11).is_none());
        assert!(backend.session_slot_map.is_empty());
    }

    // --- TF01b Finalize seal/drain (I3), backend level ---
    //
    // The seal tests share one process-wide finalize counter: every test
    // asserting absolute counts holds the lock from reset through final
    // read (repo-wide TEST_LOCK convention).
    static SEAL_FINALIZE_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static SEAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn finalize_counting_ok(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
        SEAL_FINALIZE_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        cryptoki_sys::CKR_OK
    }

    #[test]
    fn finalize_seals_new_admissions_after_success() {
        // I3: a successful Finalize seals the domain — new ordinary
        // admissions deny, and a second Finalize is refused without a
        // second provider entry.
        use std::sync::atomic::Ordering;
        let _lock = SEAL_TEST_LOCK.lock().unwrap();
        SEAL_FINALIZE_CALLS.store(0, Ordering::SeqCst);
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_ok), Some(finalize_counting_ok));
        backend.initialize().expect("initialize opens the incarnation");
        backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
        backend.finalize().expect("finalize succeeds");
        assert_eq!(SEAL_FINALIZE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(
            backend.lifecycle_domain.admit_ordinary().unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED,
            "sealed domain denies new ordinary admissions"
        );
        assert_eq!(
            backend.finalize().unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED,
            "second Finalize refused without provider contact"
        );
        assert_eq!(SEAL_FINALIZE_CALLS.load(Ordering::SeqCst), 1, "refused cycle never re-enters");
    }

    #[test]
    fn finalize_denied_without_open_incarnation_never_reaches_provider() {
        // I3: with no live incarnation there is nothing to seal — the
        // denial lands before native entry with the same RV a compliant
        // provider reports.
        use std::sync::atomic::Ordering;
        let _lock = SEAL_TEST_LOCK.lock().unwrap();
        SEAL_FINALIZE_CALLS.store(0, Ordering::SeqCst);
        let (backend, _functions) = backend_with_finalize(Some(finalize_counting_ok));
        assert_eq!(backend.finalize().unwrap_err(), CkRv::CRYPTOKI_NOT_INITIALIZED);
        assert_eq!(SEAL_FINALIZE_CALLS.load(Ordering::SeqCst), 0, "denied seal never enters");
    }

    #[test]
    fn failed_finalize_restores_open_incarnation() {
        // Behavior parity pin (not red-able: restore matches the pre-seal
        // shape by design): a failed native Finalize abandons the seal —
        // the live incarnation keeps admitting, nothing purges, the
        // native RV propagates exactly.
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_ok), Some(finalize_fails));
        backend.initialize().expect("initialize opens the incarnation");
        seed_cache(&backend);
        assert_eq!(backend.finalize().unwrap_err(), CkRv::GENERAL_ERROR);
        backend.lifecycle_domain.admit_ordinary().expect("live incarnation still admits");
        assert!(
            backend.mech_cache.contains_key(&(7, OperationFamily::Sign)),
            "failed Finalize purges nothing"
        );
    }

    #[test]
    fn finalize_drains_parked_ordinary_before_native_entry() {
        // Blocked-stub exclusion shape for the seal: a parked ordinary
        // holder (standing in for a thread inside a provider call) blocks
        // the seal until release; the native Finalize is not entered
        // while the holder is parked and runs promptly after.
        use std::sync::atomic::Ordering;
        let _lock = SEAL_TEST_LOCK.lock().unwrap();
        SEAL_FINALIZE_CALLS.store(0, Ordering::SeqCst);
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_ok), Some(finalize_counting_ok));
        backend.initialize().expect("initialize opens the incarnation");
        let parked = backend.lifecycle_domain.admit_ordinary().expect("admits while open");
        let backend = &backend;
        std::thread::scope(|scope| {
            let sealer = scope.spawn(|| backend.finalize());
            std::thread::sleep(std::time::Duration::from_millis(200));
            assert_eq!(
                SEAL_FINALIZE_CALLS.load(Ordering::SeqCst),
                0,
                "native Finalize must not run while ordinary work is parked"
            );
            drop(parked);
            sealer.join().expect("sealer joins").expect("seal completes after release");
            assert_eq!(SEAL_FINALIZE_CALLS.load(Ordering::SeqCst), 1);
        });
        assert_eq!(
            backend.lifecycle_domain.admit_ordinary().unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED,
            "sealed domain denies after the drained Finalize"
        );
    }

    #[test]
    fn finalize_under_continuous_ordinary_load_completes_and_seals() {
        // I3 termination pin: Finalize under continuous ordinary load
        // completes — the suite itself would die at the shutdown deadline
        // otherwise — and the domain is sealed afterwards. Spinners stay
        // hot across the seal window (ready gate + done-after-finalize),
        // so the drain genuinely overlaps live admissions.
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let _lock = SEAL_TEST_LOCK.lock().unwrap();
        SEAL_FINALIZE_CALLS.store(0, Ordering::SeqCst);
        let (backend, _functions) =
            backend_with_init_and_finalize(Some(initialize_ok), Some(finalize_counting_ok));
        backend.initialize().expect("initialize opens the incarnation");
        let done = AtomicBool::new(false);
        let ready = AtomicUsize::new(0);
        let admitted: [AtomicUsize; 4] = Default::default();
        let backend = &backend;
        std::thread::scope(|scope| {
            for spinner in admitted.iter() {
                scope.spawn(|| {
                    ready.fetch_add(1, Ordering::SeqCst);
                    // Publish admissions live (each spinner owns its slot,
                    // so no inter-spinner contention): the seal loop reads
                    // the running total to prove overlap on any scheduler.
                    while !done.load(Ordering::SeqCst) {
                        if backend.lifecycle_domain.admit_ordinary().is_ok() {
                            spinner.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                });
            }
            while ready.load(Ordering::SeqCst) < 4 {
                std::thread::yield_now();
            }
            // Count-boxed ping-pong with an overlap floor, not a fixed
            // time window. A bare 300 ms window fits 1 seal on an
            // oversubscribed CI runner (T2run: 6/7 CI executions red with
            // "got 1"), while a bare fixed count can finish before a
            // descheduled spinner runs once on a quiet box. Loop until 6
            // seals AND 5000 spinner admissions overlap them, so both the
            // seal count and the genuine-load overlap hold on any
            // scheduler. The 60 s assert bounds the loop between
            // iterations only — a hang inside finalize() itself never
            // reaches it and dies at the shutdown deadline instead
            // (see the test header), so either way a true stall fails
            // loud instead of hanging the suite.
            let start = std::time::Instant::now();
            let mut seals = 0usize;
            while seals < 6
                || admitted.iter().map(|spinner| spinner.load(Ordering::SeqCst)).sum::<usize>()
                    < 5_000
            {
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(60),
                    "seal window stalled under load after {seals} seals"
                );
                backend.finalize().expect("finalize completes under load");
                backend.initialize().expect("re-initialize reopens");
                seals += 1;
            }
            backend.finalize().expect("final seal completes under load");
            done.store(true, Ordering::SeqCst);
            assert!(seals > 5, "sanity: many seals completed under load, got {seals}");
            assert_eq!(SEAL_FINALIZE_CALLS.load(Ordering::SeqCst), seals + 1);
        });
        // Aggregate, not per-spinner: a descheduled spinner may sit out
        // whole windows (the I2 test trusts scheduling the same way). The
        // sum proves live admissions overlapped the seals.
        let total: usize = admitted.iter().map(|spinner| spinner.load(Ordering::SeqCst)).sum();
        assert!(
            total > 5_000,
            "spinners must observe genuine load across the seal windows, got {total}"
        );
        assert_eq!(
            backend.lifecycle_domain.admit_ordinary().unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED,
            "sealed domain denies after Finalize under load"
        );
    }
}

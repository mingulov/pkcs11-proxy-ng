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
pub(crate) mod ffi_conversion;
// R13: test-only funnel so backend tests outside `ffi/` can feed retyped
// trait/entries (typed/`None` test mechanisms pass the local backstop).
#[cfg(test)]
pub(crate) use ffi_conversion::mechanism::validated_mechanism_for_tests;
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
#[path = "ffi/object_lifetime.rs"]
mod object_lifetime;
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
    // Issue #28 review finding 1: 3.0-family dispatch resolves the
    // slot from the lowest-version table serving it (3.0, then the
    // explicit 3.1 answer, then the 3.2 table's 3.0 prefix — Task
    // 1.5 Step 3), so every advertised function stays callable.
    // 3.1 shares the 3.0 layout, hence the same field names, and
    // the 3.2 table carries the 3.0 layout as a prefix;
    // cross-table dispatch within the 3.x family follows the
    // BouncyHSM primary-fallback precedent. Each link fires only
    // where every lower table lacks the slot — consistent modules
    // (all known) keep today's behavior bit-for-bit, and refusal
    // still precedes argument evaluation exactly like the generic
    // arm below (which keeps serving the 3.2 sites).
    ($admission:expr, $self:expr, func_list_3_0, $fn_name:ident $(, $arg:expr)*) => {{
        // B2 admission proof (TF01b): the ascription pins at compile time
        // that the caller's ordinary guard reaches this native entry; the
        // guard local stays alive across the call and settlement. A macro
        // (not a choke fn) because call sites evaluate fallible (`?`)
        // argument expressions after table resolution — routing through
        // `call_unit` would force hoisting and change refusal precedence.
        let _admission: &crate::ffi::native_domain::OrdinaryGuard = $admission;
        let f = [$self.func_list_3_0, $self.func_list_3_1, $self.func_list_3_2_as_3_0_prefix()]
            .into_iter()
            .flatten()
            .find_map(|fl| unsafe { (*fl).$fn_name });
        let f = match f {
            Some(f) => f,
            None => return Err(CkRv::FUNCTION_NOT_SUPPORTED),
        };
        let rv = unsafe { f($($arg),*) };
        FfiBackend::ck_result(rv)
    }};
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

impl FfiBackend {
    /// The 3.2 table viewed as a 3.0-prefix table for 3.0-family
    /// dispatch fallback (Task 1.5 Step 3): the last link of the
    /// 3.0→3.1→3.2 chain, so a function the (3,2) advertisement
    /// shows as callable stays callable. `None` when no 3.2 table
    /// was discovered.
    ///
    /// Soundness: `CK_FUNCTION_LIST_3_2` extends
    /// `CK_FUNCTION_LIST_3_0` with additional trailing fields
    /// (PKCS#11 ABI; both `repr(C)` through cryptoki-sys), so
    /// reading 3.0-prefix fields through the retyped pointer is a
    /// prefix read — the same reliance as the leading-`CK_VERSION`
    /// reads. The pointer stays module-owned with the 3.2 slot's
    /// lifetime (kept alive by `_lib`).
    pub(crate) fn func_list_3_2_as_3_0_prefix(
        &self,
    ) -> Option<*const cryptoki_sys::CK_FUNCTION_LIST_3_0> {
        self.func_list_3_2.map(|fl| fl as *const cryptoki_sys::CK_FUNCTION_LIST_3_0)
    }
}

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
    /// Provenance of [`Self::func_list_3_0`] (RF-3.0-manufacture):
    /// `true` when the slot holds an explicit versioned {3,0} answer
    /// (any stamp the module put on its reply), `false` when it holds
    /// the primary-interface fallback (explicit {3,0} was NULL).
    /// Advertisement-only: dispatch uses the slot either way, but
    /// only an explicit answer proves the module serves {3,0}. Read
    /// only when the slot is `Some`.
    func_list_3_0_explicit: bool,
    /// PKCS#11 3.1 function list from an explicit {3,1} query that
    /// passed the OASIS exact-match proof gate (3.1 stamp), if the
    /// module served one. Feeds the (3,1) advertisement null-walk and
    /// the 3.0-family dispatch fallback. 3.1 shares the 3.0 layout,
    /// hence the shared `CK_FUNCTION_LIST_3_0` type.
    func_list_3_1: Option<*const cryptoki_sys::CK_FUNCTION_LIST_3_0>,
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
    /// Per-object lifetime ids for late-mint settlement binding.
    object_lifetimes: object_lifetime::ObjectLifetimeTable,
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
            func_list_3_0_explicit: false,
            func_list_3_1: None,
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
            object_lifetimes: Default::default(),
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
            // A caller-provided table reads as a literal answer; tests
            // mimicking the primary fallback declare it explicitly via
            // `with_3_0_explicit(false)`.
            func_list_3_0_explicit: func_list_3_0.is_some(),
            func_list_3_0,
            func_list_3_1: None,
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
            object_lifetimes: Default::default(),
            retirement_sentinel: native_domain::RetirementSentinel::unmanaged_test_only(),
        }
    }

    /// Test-only installer for the 3.1 discovery slot (issue #28): the
    /// base constructor leaves `func_list_3_1` as `None`; stub tests for
    /// modules answering an explicit {3,1} query set it here. The table
    /// `Box` stays caller-owned so the raw pointer cannot dangle.
    #[cfg(any(test, feature = "native-owner-test-hooks"))]
    pub fn with_3_1_table(
        mut self,
        func_list_3_1: Option<*const cryptoki_sys::CK_FUNCTION_LIST_3_0>,
    ) -> Self {
        self.func_list_3_1 = func_list_3_1;
        self
    }

    /// Test-only provenance installer for the 3.0 slot
    /// (RF-3.0-manufacture): the base constructor reads a provided
    /// table as a literal answer; stub tests mimicking the
    /// primary-interface fallback (explicit {3,0} NULL) set `false`
    /// here.
    #[cfg(any(test, feature = "native-owner-test-hooks"))]
    pub fn with_3_0_explicit(mut self, explicit: bool) -> Self {
        self.func_list_3_0_explicit = explicit;
        self
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
        // Codex R11 seal bound: snapshot completed initializations NOW —
        // after the seal, before the native call. A stale Initialize whose
        // native call succeeds after this point increments the count, and
        // the bounded publish record below then keeps its attempt
        // exposure instead of clearing it. Snapshotting after the native
        // call would be wrong (it would absorb exactly those completions);
        // completions landing between the seal and this snapshot ran
        // before the native Finalize, which tears them down, so including
        // them is precise — and any residual race errs toward Poison.
        let completions_at_seal = self.lifecycle.init_completion_count();
        // No lifetime lock across the native call: lifecycle write is
        // acquired again by abandon/publish below, and holding the leaf
        // lifetime lock into either would invert the global
        // lifecycle -> lifetime order (an admitted mint holds lifecycle
        // read while waiting for the lifetime lock). The purge takes
        // the lifetime lock briefly inside the publish section instead.
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
            // C_Finalize (F-08). The failure fact is recorded INSIDE the
            // abandon write section, and only when this seal is still
            // current: a stale failure (a newer cycle already completed)
            // must not set `finalize_failed` over the newer incarnation's
            // finalized facts, which would strand the backend (Initialize
            // refusing already-initialized while Finalize reports
            // not-initialized, with no cycle able to clear it).
            self.lifecycle_domain.abandon_finalize_with_record(seal, |current| {
                if current {
                    self.lifecycle.note_finalize_failed();
                }
            });
            return outcome;
        }
        // Publish `Finalized` with the incarnation purge INSIDE the publish
        // write section (I2 mirror): `Finalized` implies purged, so a racing
        // re-Initialize observes no dead bindings. The publish is
        // currency-validated inside that section; only a current ticket
        // seals or purges.
        // This is the daemon/backend finalizer, not the per-client gRPC
        // Finalize path. Per-client Finalize removes only that client context
        // and closes its sessions. Once the underlying module accepts
        // C_Finalize, every cached session binding is out of scope.
        //
        // Publish-failure reasoning (replaces the former note-before-
        // publish): if the publish fails, this completion is either stale
        // (superseded — a newer incarnation owns the domain and the
        // tracker facts, so nothing is recorded) or epoch-exhausted
        // (domain Uncertain — leaving the tracker unrecorded poisons the
        // retirement decision conservatively instead of releasing on a
        // finalized proof whose sealed publish never landed). The purge
        // closure runs only after that currency validation succeeds and
        // still under the publish write, so recording the tracker facts
        // as the closure's first step makes them atomic with the
        // validated publish: no new Initialize can begin (its begin needs
        // the same write) between the publish and the record, and a
        // stale or exhausted publish records nothing. Recording after
        // the publish instead would let a completed re-Initialize
        // re-affirm the still-unfinalized tracker (no generation bump,
        // no count reset), after which the resumed record would zero
        // the new incarnation's sessions and prove `Release` over live
        // native state.
        self.lifecycle_domain.publish_finalized_with_purge(seal, || {
            self.lifecycle.note_finalized_bounded(completions_at_seal);
            // Brief leaf hold under the publish write (lifecycle ->
            // lifetime), mirroring the incarnation purge above it.
            let mut lifetimes = self.object_lifetimes.lock_entries();
            self.drop_all_mech_cache_in(&mut lifetimes);
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
        // No lifetime lock across the native call: abandon/publish below
        // re-acquire lifecycle write, and holding the leaf lifetime lock
        // into either would invert the global lifecycle -> lifetime
        // order (an admitted mint holds lifecycle read while waiting
        // for the lifetime lock — see the overlap regression test). The
        // purge takes the lifetime lock briefly inside publish instead.
        // Control choke: Initialize takes the write lock (above) while
        // holding no read — the choke takes no guard, structurally.
        let outcome =
            Self::call_control_unit(unsafe { (*self.func_list).C_Initialize }, |function| unsafe {
                function(&mut args as *mut _ as cryptoki_sys::CK_VOID_PTR)
            });
        if outcome.is_err() {
            // Native failure restores the prior domain state (behavior
            // parity: a failed re-Initialize leaves a live incarnation
            // usable, exactly as before the domain existed). The attempt
            // exposure is re-asserted INSIDE the abandon write section,
            // unconditionally: when this ticket is current no Finalize can
            // have completed since the pre-entry marker, so re-asserting
            // is harmless, and when it is stale the re-assert restores
            // exactly the evidence an interleaved successful Finalize
            // cleared — this attempt's native code ran after that
            // Finalize, so retirement must poison instead of releasing.
            self.lifecycle_domain.abandon_initialize_with_record(init_control, |_current| {
                self.lifecycle.note_init_attempted();
            });
            return outcome;
        }
        // A new initialization cycle starts a clean incarnation (C3M.4/row
        // 10): session bindings cached under a dead generation must not
        // survive, or a reused numeric handle would alias stale owners.
        // Re-affirming an already-open incarnation keeps its live bindings.
        let generation_before = self.lifecycle.current_generation();
        // Checked record: the residual refusal (a Finalize failed, or the
        // last generation was claimed, after the gate passed) propagates
        // before the purge, so a refused cycle purges nothing. Native
        // state is LIVE on this path (`C_Initialize` succeeded), so the
        // ticket settles through the recording abandon with the same
        // unconditional re-assert as the native-failure path — dropping
        // it would let an interleaved successful Finalize's cleared
        // exposure stand, and retirement would release over live state.
        if let Err(refusal) = self.lifecycle.note_initialized() {
            self.lifecycle_domain.abandon_initialize_with_record(init_control, |_current| {
                self.lifecycle.note_init_attempted();
            });
            return Err(lifecycle_refusal_rv(refusal));
        }
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
                // Brief leaf hold under the publish write (lifecycle
                // -> lifetime): the new incarnation starts with a clean
                // lifetime table inside the same section as the rest of
                // the incarnation purge.
                let mut lifetimes = self.object_lifetimes.lock_entries();
                self.drop_all_mech_cache_in(&mut lifetimes);
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

    fn init_token(
        &self,
        slot_id: CkSlotId,
        so_pin: Option<&[u8]>,
        label: InitTokenLabel<'_>,
    ) -> CkResult<()> {
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
        queries: Option<&[CkAttributeQuery]>,
    ) -> CkResult<(CkRv, Vec<CkAttributeQueryResult>)> {
        self.ffi_get_attribute_value_exact(session, object, queries)
    }

    fn sign_init(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
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
        mechanism: &ValidatedMechanismParams,
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
        mechanism: &ValidatedMechanismParams,
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
        mechanism: &ValidatedMechanismParams,
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

    fn digest_init(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
    ) -> CkResult<()> {
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
        mechanism: &ValidatedMechanismParams,
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
        mechanism: &ValidatedMechanismParams,
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
        mechanism: &ValidatedMechanismParams,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.ffi_derive_key(session, mechanism, base_key, template)
    }

    fn derive_key_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, Option<CkMechanismParams>)> {
        self.ffi_derive_key_with_output(session, mechanism, base_key, template)
    }

    fn derive_key_with_output_result(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkDeriveKeyOutputResult> {
        self.ffi_derive_key_with_output_result(session, mechanism, base_key, template)
    }

    fn wrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
    ) -> CkResult<SecretBytes> {
        self.ffi_wrap_key(session, mechanism, wrapping_key, key)
    }

    fn wrap_key_exact(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_wrap_key_exact(session, mechanism, wrapping_key, key, spec)
    }

    fn wrap_key_exact_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)> {
        self.ffi_wrap_key_exact_with_output(session, mechanism, wrapping_key, key, spec)
    }

    fn unwrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.ffi_unwrap_key(session, mechanism, unwrapping_key, wrapped_key, template)
    }

    fn generate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.ffi_generate_key(session, mechanism, template)
    }

    fn generate_key_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
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
    fn session_incarnation(&self, session: CkSessionHandle) -> Option<u64> {
        self.ffi_session_incarnation(session)
    }
    fn destroy_object_if_incarnation(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        incarnation: Option<u64>,
    ) -> CkResult<()> {
        self.ffi_destroy_object_if_incarnation(session, object, incarnation)
    }
    fn object_lifetime(&self, session: CkSessionHandle, object: CkObjectHandle) -> Option<u64> {
        self.ffi_object_lifetime(session, object)
    }
    fn tracks_object_lifetimes(&self) -> bool {
        true
    }
    fn destroy_object_if_bound(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        incarnation: Option<u64>,
        object_lifetime: Option<u64>,
    ) -> CkResult<()> {
        self.ffi_destroy_object_if_bound(session, object, incarnation, object_lifetime)
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
        mechanism: &ValidatedMechanismParams,
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
        mechanism: &ValidatedMechanismParams,
        public_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputAndHandleResult> {
        self.ffi_encapsulate_key_exact(session, mechanism, public_key, template, spec)
    }

    fn encapsulate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        public_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<(SecretBytes, CkObjectHandle)> {
        self.ffi_encapsulate_key(session, mechanism, public_key, template)
    }

    fn decapsulate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
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
        mechanism: Option<&ValidatedMechanismParams>,
        init_param: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_message_encrypt_init(session, mechanism, init_param, key)
    }

    fn message_encrypt_init_contract(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
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
        mechanism: Option<&ValidatedMechanismParams>,
        init_param: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_message_decrypt_init(session, mechanism, init_param, key)
    }

    fn message_decrypt_init_contract(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
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
        mechanism: Option<&ValidatedMechanismParams>,
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
        mechanism: Option<&ValidatedMechanismParams>,
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
        mechanism: Option<&ValidatedMechanismParams>,
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
        mechanism: &ValidatedMechanismParams,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        self.ffi_wrap_key_authenticated(session, mechanism, wrapping_key, key, aad)
    }

    fn wrap_key_authenticated_typed(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
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
        mechanism: &ValidatedMechanismParams,
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
        mechanism: &ValidatedMechanismParams,
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
        mechanism: &ValidatedMechanismParams,
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
        mechanism: &ValidatedMechanismParams,
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

    // --- Overlapping-Initialize / admitted-mint deadlock regression ---
    //
    // Two Initialize calls overlap: B parks inside its native call, A
    // begins behind B as the current ticket. A then succeeds and
    // publishes `Open`, an ordinary mint admits (lifecycle read) and
    // reaches for the object-lifetime lock, and B's native call returns
    // ALREADY_INITIALIZED so B must abandon (lifecycle write). If B
    // holds the lifetime lock across its
    // native call — the shape this pins against — the cycle is
    // permanent: B waits for lifecycle write behind the mint's read
    // while the mint waits for B's lifetime lock. All three calls must
    // complete; every wait below is channel-bounded so the buggy shape
    // fails fast instead of hanging the suite (workers are detached:
    // a deadlocked run leaks its threads and reports, never wedges).

    static OVERLAP_INIT_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static OVERLAP_INIT_FIRST_GATE: std::sync::Mutex<
        Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    > = std::sync::Mutex::new(None);
    static OVERLAP_INIT_SECOND_GATE: std::sync::Mutex<
        Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    > = std::sync::Mutex::new(None);
    static OVERLAP_INIT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static OVERLAP_CREATE_GATE: std::sync::Mutex<
        Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    > = std::sync::Mutex::new(None);

    fn park_overlap_gate(
        gate: &std::sync::Mutex<
            Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
        >,
    ) -> bool {
        let gate = gate.lock().unwrap().take();
        match gate {
            Some((entered, release)) => {
                let _ = entered.send(());
                // Bounded: a test bug (release never sent) fails the
                // stub loudly instead of parking the suite forever.
                release.recv_timeout(std::time::Duration::from_secs(10)).is_ok()
            }
            None => false,
        }
    }

    unsafe extern "C" fn initialize_overlapping_parkable(
        _: *mut std::ffi::c_void,
    ) -> cryptoki_sys::CK_RV {
        // The first-begun overlapping call is stale under the fenced
        // publish (a newer begin owns the epoch) and reports
        // already-initialized on release; the second-begun (current)
        // call succeeds and publishes the incarnation.
        match OVERLAP_INIT_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
            0 => {
                if park_overlap_gate(&OVERLAP_INIT_FIRST_GATE) {
                    cryptoki_sys::CKR_CRYPTOKI_ALREADY_INITIALIZED
                } else {
                    cryptoki_sys::CKR_FUNCTION_FAILED
                }
            }
            _ => {
                if park_overlap_gate(&OVERLAP_INIT_SECOND_GATE) {
                    cryptoki_sys::CKR_OK
                } else {
                    cryptoki_sys::CKR_FUNCTION_FAILED
                }
            }
        }
    }

    unsafe extern "C" fn create_object_overlap_parkable(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _template: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _count: cryptoki_sys::CK_ULONG,
        handle: *mut cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        // Parked inside the native call, the mint provably holds its
        // OrdinaryGuard read and the object-lifetime lock (the lock
        // spans the native call in call_object_output).
        if park_overlap_gate(&OVERLAP_CREATE_GATE) {
            if !handle.is_null() {
                unsafe { *handle = 43 };
            }
            cryptoki_sys::CKR_OK
        } else {
            cryptoki_sys::CKR_FUNCTION_FAILED
        }
    }

    unsafe extern "C" fn create_object_overlap_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _template: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _count: cryptoki_sys::CK_ULONG,
        handle: *mut cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        if !handle.is_null() {
            unsafe { *handle = 43 };
        }
        cryptoki_sys::CKR_OK
    }

    #[test]
    fn overlapping_initialize_abandon_does_not_deadlock_admitted_mint() {
        use std::sync::atomic::Ordering;
        use std::sync::{Arc, mpsc};
        use std::time::Duration;
        let _lock = OVERLAP_INIT_TEST_LOCK.lock().unwrap();
        OVERLAP_INIT_CALLS.store(0, Ordering::SeqCst);
        let (first_entered_tx, first_entered_rx) = mpsc::channel();
        let (first_release_tx, first_release_rx) = mpsc::channel();
        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let (second_release_tx, second_release_rx) = mpsc::channel();
        *OVERLAP_INIT_FIRST_GATE.lock().unwrap() = Some((first_entered_tx, first_release_rx));
        *OVERLAP_INIT_SECOND_GATE.lock().unwrap() = Some((second_entered_tx, second_release_rx));
        let (create_entered_tx, create_entered_rx) = mpsc::channel();
        let (create_release_tx, create_release_rx) = mpsc::channel();
        *OVERLAP_CREATE_GATE.lock().unwrap() = Some((create_entered_tx, create_release_rx));

        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_Initialize = Some(initialize_overlapping_parkable);
        functions.C_Finalize = Some(finalize_ok);
        functions.C_CreateObject = Some(create_object_overlap_parkable);
        // Leaked on purpose: detached workers must never meet a freed
        // table, including on the RED timeout path where the buggy
        // shape leaves them deadlocked past the end of this test.
        let func_list = Box::leak(functions) as *mut cryptoki_sys::CK_FUNCTION_LIST;
        let backend = Arc::new(FfiBackend::test_backend_with_tables(func_list, None, None));

        let (a_tx, a_rx) = mpsc::channel();
        let (b_tx, b_rx) = mpsc::channel();
        let (mint_tx, mint_rx) = mpsc::channel();

        // Initializer B (stale abandoner) parks inside its native call
        // first, so it holds the older ticket.
        {
            let backend = Arc::clone(&backend);
            std::thread::spawn(move || {
                let _ = b_tx.send(backend.initialize());
            });
        }
        first_entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("initializer B parks inside native C_Initialize");
        // Initializer A (current publisher) overlaps B. A signals nothing
        // before its native call in the buggy shape (it blocks on the
        // lifetime lock B holds), so this settle window is what
        // guarantees A began before B abandons — the same
        // unobservable-queue pattern as
        // `queued_writer_stalls_new_admissions`.
        {
            let backend = Arc::clone(&backend);
            std::thread::spawn(move || {
                let _ = a_tx.send(backend.initialize());
            });
        }
        std::thread::sleep(Duration::from_millis(300));
        // A is inside its native call in both shapes now (the buggy A
        // acquires the lifetime lock the moment B releases it).
        second_entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("initializer A parks inside native C_Initialize");
        // A succeeds and publishes Open as the current ticket.
        second_release_tx.send(()).expect("release initializer A");
        assert_eq!(
            a_rx.recv_timeout(Duration::from_secs(5)).expect("initializer A must complete"),
            Ok(())
        );
        // The admitted mint races B's abandon path. Its native-entry
        // receipt proves it is admitted (lifecycle read) and holds the
        // object-lifetime lock (held across the native call) before B
        // is released — no sleep-based ordering.
        {
            let backend = Arc::clone(&backend);
            std::thread::spawn(move || {
                let _ = mint_tx.send(backend.create_object(CkSessionHandle(7), Some(&[])));
            });
        }
        create_entered_rx.recv_timeout(Duration::from_secs(5)).expect(
            "admitted mint parks inside native C_CreateObject holding admission and lifetime lock",
        );
        first_release_tx.send(()).expect("release initializer B into its abandon path");
        // B's abandon needs lifecycle write behind the mint's live read,
        // so it cannot complete until the mint is released below. The
        // bounded non-completion check pins that contention; the final
        // completion assertions stay bounded as well.
        assert!(
            b_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "initializer B abandon must wait behind the admitted mint"
        );
        create_release_tx.send(()).expect("release the admitted mint");
        assert_eq!(
            mint_rx.recv_timeout(Duration::from_secs(10)).expect("admitted mint must complete"),
            Ok(CkObjectHandle(43))
        );
        assert_eq!(
            b_rx.recv_timeout(Duration::from_secs(10)).expect(
                "initializer B abandon must complete: deadlock \u{2014} B waits for \
                 lifecycle write while holding the lifetime lock the admitted mint waits for"
            ),
            Err(CkRv::CRYPTOKI_ALREADY_INITIALIZED)
        );
        backend.lifecycle_domain.admit_ordinary().expect("domain stays open after B abandons");
        // The publish-move keeps purge semantics: the mint's lifetime is
        // tracked under the live incarnation, and a successful Finalize
        // still clears the table at publish.
        assert!(backend.object_lifetime(CkSessionHandle(7), CkObjectHandle(43)).is_some());
        backend.finalize().expect("finalize succeeds");
        assert_eq!(backend.object_lifetime(CkSessionHandle(7), CkObjectHandle(43)), None);
    }

    static BRIDGE_FINALIZE_GATE: std::sync::Mutex<
        Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    > = std::sync::Mutex::new(None);
    static BRIDGE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn finalize_bridge_parkable(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
        if park_overlap_gate(&BRIDGE_FINALIZE_GATE) {
            cryptoki_sys::CKR_OK
        } else {
            cryptoki_sys::CKR_FUNCTION_FAILED
        }
    }

    #[test]
    fn late_finalize_after_resurrection_preserves_new_incarnation_lifetime() {
        // Section-2.2 bridge at backend level: a Finalize seals and parks
        // inside its native call; a newer Open incarnation is then
        // published underneath it (simulated by injection, as in
        // finalize_stale_abandon_is_noop_epoch_mismatch — production
        // begins are denied from the sealed domain, so no gated stub can
        // begin the resurrecting Initialize while sealed). The late
        // Finalize completion must be refused as stale: it seals nothing,
        // purges nothing, and records no finalized tracker facts, so the
        // new incarnation's lifetime entry and admission survive.
        use std::sync::{Arc, mpsc};
        use std::time::Duration;
        let _lock = BRIDGE_TEST_LOCK.lock().unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *BRIDGE_FINALIZE_GATE.lock().unwrap() = Some((entered_tx, release_rx));

        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_Initialize = Some(initialize_ok);
        functions.C_Finalize = Some(finalize_bridge_parkable);
        functions.C_CreateObject = Some(create_object_overlap_ok);
        let func_list = Box::leak(functions) as *mut cryptoki_sys::CK_FUNCTION_LIST;
        let backend = Arc::new(FfiBackend::test_backend_with_tables(func_list, None, None));
        backend.initialize().expect("initial initialize opens the incarnation");
        assert_eq!(backend.create_object(CkSessionHandle(7), Some(&[])), Ok(CkObjectHandle(43)));
        assert!(backend.object_lifetime(CkSessionHandle(7), CkObjectHandle(43)).is_some());
        backend.lifecycle.note_session_opened();
        assert_eq!(backend.lifecycle.current_generation(), 1);

        let (fin_tx, fin_rx) = mpsc::channel();
        {
            let backend = Arc::clone(&backend);
            std::thread::spawn(move || {
                let _ = fin_tx.send(backend.finalize());
            });
        }
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("finalize parks inside native C_Finalize");
        // Resurrection / newer Open publish simulated by injection: the
        // domain moves to Open at a newer epoch and the tracker moves to
        // generation 2, exactly as a successful newer Initialize publish
        // would leave them. A mint under that incarnation records 99.
        let injected_epoch = backend.lifecycle_domain.epoch_for_tests() + 1;
        backend
            .lifecycle_domain
            .set_state_for_tests(native_domain::ModuleState::Open, injected_epoch);
        backend.lifecycle.set_generation_for_tests(2);
        backend.record_object_lifetime_fresh(CkSessionHandle(7), CkObjectHandle(99));
        assert!(backend.object_lifetime(CkSessionHandle(7), CkObjectHandle(99)).is_some());

        release_tx.send(()).expect("release the parked finalize");
        assert_eq!(
            fin_rx.recv_timeout(Duration::from_secs(5)).expect("late finalize must complete"),
            Err(CkRv::GENERAL_ERROR),
            "stale Finalize completion is visibly refused, not silently sealed"
        );
        assert_eq!(
            backend.lifecycle_domain.state_for_tests(),
            native_domain::ModuleState::Open,
            "stale Finalize publish leaves the newer Open standing"
        );
        assert_eq!(
            backend.lifecycle_domain.epoch_for_tests(),
            injected_epoch,
            "stale settle consumes no epoch"
        );
        assert!(
            backend.object_lifetime(CkSessionHandle(7), CkObjectHandle(99)).is_some(),
            "stale purge must not wipe the new incarnation's lifetime entry"
        );
        backend
            .lifecycle_domain
            .admit_ordinary()
            .expect("new incarnation still admits ordinary work");
        assert_eq!(backend.lifecycle.current_generation(), 2);
        assert_eq!(
            backend.lifecycle.open_session_count_for_tests(),
            1,
            "stale completion must not zero the new incarnation's open sessions"
        );
    }

    static TRACKER_FINALIZE_GATE: std::sync::Mutex<
        Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    > = std::sync::Mutex::new(None);
    static TRACKER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn finalize_tracker_parkable(
        _: *mut std::ffi::c_void,
    ) -> cryptoki_sys::CK_RV {
        if park_overlap_gate(&TRACKER_FINALIZE_GATE) {
            cryptoki_sys::CKR_OK
        } else {
            cryptoki_sys::CKR_FUNCTION_FAILED
        }
    }

    #[test]
    fn finalize_records_tracker_inside_publish_before_reinit_with_live_session() {
        // Regression for the Finalize tracker race: the tracker facts
        // (`note_finalized`: finalized proof + zeroed open count) must be
        // recorded INSIDE the validated publish write section, before that
        // write is released. Otherwise a re-Initialize + session open that
        // completes in the gap after the publish sees `finalized_ok` still
        // clear (so it re-affirms instead of opening a new generation) and
        // the resumed Finalize zeroes the new incarnation's count and
        // leaves `Release` while native state is live.
        //
        // Deterministic composition point: the publish purge takes the
        // object-lifetime leaf lock inside the write section. Holding that
        // leaf lock parks the publisher inside its purge closure with the
        // lifecycle write still held, so the tracker state observable at
        // that moment is exactly what any re-Initialize released after
        // the publish would inherit. The gate below polls the open-session
        // count, not `try_state_for_tests`: `None` there only proves a
        // writer holds *or queues*, so it can fire before the record runs.
        // The count starts at 1 and only `note_finalized` zeroes it, so
        // observing 0 while still holding the leaf lock proves the record
        // already ran inside the publish section (the publisher cannot
        // leave that section without the leaf lock). No sleeps order this
        // test; every wait is a channel/condition wait or a bounded poll
        // whose timeout is only a failure bound.
        use std::sync::{Arc, mpsc};
        use std::time::{Duration, Instant};
        let _lock = TRACKER_TEST_LOCK.lock().unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *TRACKER_FINALIZE_GATE.lock().unwrap() = Some((entered_tx, release_rx));

        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_Initialize = Some(initialize_ok);
        functions.C_Finalize = Some(finalize_tracker_parkable);
        // Leaked on purpose, mirroring the bridge test: a detached worker
        // must never meet a freed table on a failure path.
        let func_list = Box::leak(functions) as *mut cryptoki_sys::CK_FUNCTION_LIST;
        let backend = Arc::new(FfiBackend::test_backend_with_tables(func_list, None, None));
        backend.initialize().expect("initial initialize opens the incarnation");
        backend.lifecycle.note_session_opened();
        assert_eq!(backend.lifecycle.current_generation(), 1);
        assert_eq!(backend.lifecycle.open_session_count_for_tests(), 1);

        let (fin_tx, fin_rx) = mpsc::channel();
        {
            let backend = Arc::clone(&backend);
            std::thread::spawn(move || {
                let _ = fin_tx.send(backend.finalize());
            });
        }
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("finalize parks inside native C_Finalize");
        // Hold the leaf lock the publish purge needs. Releasing the native
        // stub now lets the publisher enter its write section, flip
        // `Finalized`, and park inside the purge closure on this lock —
        // still holding the lifecycle write.
        let lifetimes_guard = backend.object_lifetimes.lock_entries();
        release_tx.send(()).expect("release the parked finalize into its publish");
        // Bounded-poll until the record provably happened: the count was
        // seeded to 1 above and only `note_finalized` zeroes it. Do NOT
        // gate on `try_state_for_tests()` being `None` — that also fires
        // for a merely queued writer, before the publish section (and its
        // first-step record) runs. While this test holds the leaf lock,
        // the publisher cannot leave the publish section, so once 0 is
        // observed the record is inside the section and the write is
        // still held. On the pre-fix shape the record runs only after the
        // publish returns (which needs this leaf lock), so the count
        // never reaches 0 here and the bound expires as RED.
        let deadline = Instant::now() + Duration::from_secs(5);
        while backend.lifecycle.open_session_count_for_tests() != 0 {
            assert!(
                Instant::now() < deadline,
                "tracker finalized fact (zeroed open count) must be recorded inside \
                 the publish section, before the lifecycle write is released"
            );
            std::thread::yield_now();
        }
        assert_eq!(
            backend.lifecycle.open_session_count_for_tests(),
            0,
            "tracker finalized fact (zeroed open count) must be recorded inside \
             the publish section, before the lifecycle write is released"
        );
        assert!(
            backend.lifecycle_domain.try_state_for_tests().is_none(),
            "publish write must still be held after the in-section record: \
             the publisher cannot leave the publish section without the \
             object-lifetime leaf lock this test still holds"
        );
        assert_eq!(
            backend.lifecycle.retirement_decision(),
            native_domain::RetirementDecision::Release,
            "a completed publish must already carry its finalized proof while \
             the write is still held, so no later tracker record can be stale"
        );
        drop(lifetimes_guard);
        assert_eq!(
            fin_rx.recv_timeout(Duration::from_secs(5)).expect("finalize must complete"),
            Ok(())
        );
        assert_eq!(backend.lifecycle.current_generation(), 1);

        // The brief's invariant, sequentially: a completed re-Initialize
        // plus a live session in the new incarnation keeps its count, the
        // generation has advanced, and retirement stays Poison.
        backend.initialize().expect("re-initialize after successful finalize succeeds");
        assert_eq!(
            backend.lifecycle.current_generation(),
            2,
            "re-Initialize after a recorded Finalize opens a new generation"
        );
        backend.lifecycle.note_session_opened();
        assert_eq!(backend.lifecycle.open_session_count_for_tests(), 1);
        assert_eq!(
            backend.lifecycle.retirement_decision(),
            native_domain::RetirementDecision::Poison,
            "new incarnation with a live session must never retire as Release"
        );
    }

    fn seed_cache(backend: &FfiBackend) {
        let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
        let ffi_mechanism = ffi_conversion::mechanism_to_ffi(
            &ffi_conversion::validated_mechanism_for_tests(&mechanism),
        )
        .unwrap();
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
            let ffi_mechanism = ffi_conversion::mechanism_to_ffi(
                &ffi_conversion::validated_mechanism_for_tests(&mechanism),
            )
            .unwrap();
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

    static REFUSAL_INIT_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static REFUSAL_INIT_GATE: std::sync::Mutex<
        Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    > = std::sync::Mutex::new(None);
    static REFUSAL_INIT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn initialize_refusal_parkable(
        _: *mut std::ffi::c_void,
    ) -> cryptoki_sys::CK_RV {
        // The first call (initializer A) parks until the test releases it;
        // every later call (initializer B) succeeds immediately.
        match REFUSAL_INIT_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
            0 => {
                if park_overlap_gate(&REFUSAL_INIT_GATE) {
                    cryptoki_sys::CKR_OK
                } else {
                    cryptoki_sys::CKR_FUNCTION_FAILED
                }
            }
            _ => cryptoki_sys::CKR_OK,
        }
    }

    #[test]
    fn post_native_initialize_refusal_records_attempt_after_interleaved_finalize() {
        // Codex round 10 boundary: A passes the pre-native gate, then B
        // claims the last generation and successfully finalizes (clearing
        // `init_attempted_since_finalize`). A's native Initialize then
        // succeeds — native state is live — but its checked record refuses
        // at `u64::MAX`. The refusal must re-assert A's attempt through the
        // recording abandon, or retirement observes `Release` over live
        // native state. Deterministic: A parks inside its native call on
        // channels while B's whole cycle runs; no sleeps order the test.
        use std::sync::atomic::Ordering;
        use std::sync::{Arc, mpsc};
        use std::time::Duration;
        let _lock = REFUSAL_INIT_TEST_LOCK.lock().unwrap();
        REFUSAL_INIT_CALLS.store(0, Ordering::SeqCst);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *REFUSAL_INIT_GATE.lock().unwrap() = Some((entered_tx, release_rx));

        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_Initialize = Some(initialize_refusal_parkable);
        functions.C_Finalize = Some(finalize_ok);
        // Leaked on purpose, mirroring the overlap harness: detached
        // workers must never meet a freed table on a failure path.
        let func_list = Box::leak(functions) as *mut cryptoki_sys::CK_FUNCTION_LIST;
        let backend = Arc::new(FfiBackend::test_backend_with_tables(func_list, None, None));
        backend.lifecycle.set_generation_for_tests(u64::MAX - 1);

        let (a_tx, a_rx) = mpsc::channel();
        {
            let backend = Arc::clone(&backend);
            std::thread::spawn(move || {
                let _ = a_tx.send(backend.initialize());
            });
        }
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("initializer A parks inside native C_Initialize");

        // B claims the last generation and finalizes, clearing A's
        // pre-native attempt exposure exactly as the brief describes.
        backend.initialize().expect("initializer B claims the last generation");
        assert_eq!(backend.lifecycle.current_generation(), u64::MAX);
        backend.finalize().expect("interleaved finalize succeeds");
        assert_eq!(
            backend.lifecycle.retirement_decision(),
            crate::ffi::native_domain::RetirementDecision::Release,
            "precondition: interleaved finalize cleared A's exposure"
        );

        release_tx.send(()).expect("release initializer A's native call");
        assert_eq!(
            a_rx.recv_timeout(Duration::from_secs(5)).expect("initializer A must complete"),
            Err(CkRv::GENERAL_ERROR),
            "post-native refusal RV is unchanged (GenerationExhausted)"
        );
        assert_eq!(backend.lifecycle.current_generation(), u64::MAX);
        assert_eq!(
            backend.lifecycle_domain.state_for_tests(),
            native_domain::ModuleState::Finalized,
            "stale refusal abandon leaves the finalized domain standing"
        );
        assert_eq!(
            backend.lifecycle.retirement_decision(),
            crate::ffi::native_domain::RetirementDecision::Poison,
            "post-native refusal must record the attempt: retirement poisons over live native state"
        );
    }

    // --- Codex R11: Finalize publish must not erase a post-seal Initialize ---
    static FINPROOF_INIT_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static FINPROOF_INIT_GATE: std::sync::Mutex<
        Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    > = std::sync::Mutex::new(None);
    static FINPROOF_FIN_GATE: std::sync::Mutex<
        Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    > = std::sync::Mutex::new(None);
    static FINPROOF_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn initialize_finproof_parkable(
        _: *mut std::ffi::c_void,
    ) -> cryptoki_sys::CK_RV {
        // Initializer A (first call) parks until released; B succeeds at once.
        match FINPROOF_INIT_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
            0 => {
                if park_overlap_gate(&FINPROOF_INIT_GATE) {
                    cryptoki_sys::CKR_OK
                } else {
                    cryptoki_sys::CKR_FUNCTION_FAILED
                }
            }
            _ => cryptoki_sys::CKR_OK,
        }
    }

    unsafe extern "C" fn finalize_finproof_parkable(
        _: *mut std::ffi::c_void,
    ) -> cryptoki_sys::CK_RV {
        if park_overlap_gate(&FINPROOF_FIN_GATE) {
            cryptoki_sys::CKR_OK
        } else {
            cryptoki_sys::CKR_FUNCTION_FAILED
        }
    }

    #[test]
    fn finalize_publish_does_not_erase_initialization_completed_after_seal() {
        // Codex round 11: A begins (attempt recorded) and parks inside its
        // native Initialize; B initializes and publishes Open; F seals,
        // its native Finalize succeeds, and F pauses BEFORE publication
        // (the test holds the lifecycle write, so F's publish blocks);
        // A's native Initialize then succeeds — the provider is live
        // again — records a re-affirm (no generation bump) and its stale
        // publish is refused. F's publish must not clear A's attempt
        // exposure: A completed after F sealed, so retirement poisons.
        // Deterministic: every ordering point is a channel or the recorded
        // completion count; no sleeps.
        use std::sync::atomic::Ordering;
        use std::sync::{Arc, mpsc};
        use std::time::{Duration, Instant};
        let _lock = FINPROOF_TEST_LOCK.lock().unwrap();
        FINPROOF_INIT_CALLS.store(0, Ordering::SeqCst);
        let (init_entered_tx, init_entered_rx) = mpsc::channel();
        let (init_release_tx, init_release_rx) = mpsc::channel();
        *FINPROOF_INIT_GATE.lock().unwrap() = Some((init_entered_tx, init_release_rx));
        let (fin_entered_tx, fin_entered_rx) = mpsc::channel();
        let (fin_release_tx, fin_release_rx) = mpsc::channel();
        *FINPROOF_FIN_GATE.lock().unwrap() = Some((fin_entered_tx, fin_release_rx));

        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_Initialize = Some(initialize_finproof_parkable);
        functions.C_Finalize = Some(finalize_finproof_parkable);
        // Leaked on purpose, mirroring the refusal harness: detached
        // workers must never meet a freed table on a failure path.
        let func_list = Box::leak(functions) as *mut cryptoki_sys::CK_FUNCTION_LIST;
        let backend = Arc::new(FfiBackend::test_backend_with_tables(func_list, None, None));

        // 1: A begins and parks inside its native Initialize.
        let (a_tx, a_rx) = mpsc::channel();
        {
            let backend = Arc::clone(&backend);
            std::thread::spawn(move || {
                let _ = a_tx.send(backend.initialize());
            });
        }
        init_entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("initializer A parks inside native C_Initialize");

        // 2: B initializes successfully and publishes Open.
        backend.initialize().expect("initializer B opens the incarnation");
        assert_eq!(backend.lifecycle.current_generation(), 1);
        assert_eq!(backend.lifecycle.init_completion_count(), 1);

        // 3: F seals and parks inside its native Finalize.
        let (f_tx, f_rx) = mpsc::channel();
        {
            let backend = Arc::clone(&backend);
            std::thread::spawn(move || {
                let _ = f_tx.send(backend.finalize());
            });
        }
        fin_entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("finalize parks inside native C_Finalize");
        assert_eq!(
            backend.lifecycle_domain.state_for_tests(),
            native_domain::ModuleState::Finalizing,
            "sealed finalize is in its exclusive native phase"
        );

        // Hold the lifecycle write so F, once its native call returns,
        // pauses BEFORE publication.
        let (held_tx, held_rx) = mpsc::channel();
        let (unhold_tx, unhold_rx) = mpsc::channel::<()>();
        {
            let backend = Arc::clone(&backend);
            std::thread::spawn(move || {
                backend.lifecycle_domain.hold_write_across_for_tests(|| {
                    let _ = held_tx.send(());
                    let _ = unhold_rx.recv_timeout(Duration::from_secs(10));
                });
            });
        }
        held_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("test holds the lifecycle write across F's publication");
        fin_release_tx.send(()).expect("release F's native Finalize into its blocked publish");

        // 4: A's native Initialize succeeds after F's native Finalize.
        init_release_tx.send(()).expect("release initializer A's native call");
        let deadline = Instant::now() + Duration::from_secs(5);
        while backend.lifecycle.init_completion_count() != 2 {
            assert!(
                Instant::now() < deadline,
                "A's post-seal completion must be recorded before F publishes"
            );
            std::thread::yield_now();
        }
        // Precondition: the post-seal completion is on record while F is
        // still unpublished (both settlements block on the held write).
        assert!(f_rx.try_recv().is_err(), "F must still be paused before publication");
        assert!(a_rx.try_recv().is_err(), "A's stale publish must wait for the held write");

        // 5: F publishes. Whichever settlement takes the released write
        // first, A is stale and F's bounded record must keep A's exposure.
        unhold_tx.send(()).expect("release the lifecycle write for publication");
        assert_eq!(
            f_rx.recv_timeout(Duration::from_secs(5)).expect("finalize must complete"),
            Ok(())
        );
        assert_eq!(
            a_rx.recv_timeout(Duration::from_secs(5)).expect("initializer A must complete"),
            Err(CkRv::GENERAL_ERROR),
            "A's stale publish is refused (its native success stays live)"
        );
        assert_eq!(backend.lifecycle.current_generation(), 1, "A re-affirmed, never bumped");
        assert_eq!(
            backend.lifecycle_domain.state_for_tests(),
            native_domain::ModuleState::Finalized,
            "F's publication lands"
        );
        assert_eq!(
            backend.lifecycle.retirement_decision(),
            native_domain::RetirementDecision::Poison,
            "post-seal completion survives F's publish: retirement poisons over live native state"
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
        let validated = ffi_conversion::validated_mechanism_for_tests(&mechanism);
        let err = backend
            .call_init_with_mechanism(
                &admission,
                CkSessionHandle(7),
                OperationFamily::Sign,
                Some(0u8),
                &validated,
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
        let validated = ffi_conversion::validated_mechanism_for_tests(&mechanism);
        let err = backend
            .call_init_with_mechanism_output(
                &admission,
                CkSessionHandle(7),
                OperationFamily::Sign,
                Some(0u8),
                &validated,
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
                ffi_conversion::mechanism_to_ffi(&ffi_conversion::validated_mechanism_for_tests(
                    &mechanism,
                ))
                .unwrap(),
            );
            backend.remember_session_slot(CkSessionHandle(session as u64), CkSlotId(slot as u64));
        }
        // Session 7 holds a second family slot: per-slot eviction must drop
        // every family of the evicted sessions, not just one entry.
        backend.mech_cache.insert(
            (7, OperationFamily::Encrypt),
            ffi_conversion::mechanism_to_ffi(&ffi_conversion::validated_mechanism_for_tests(
                &CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None },
            ))
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
                ffi_conversion::mechanism_to_ffi(&ffi_conversion::validated_mechanism_for_tests(
                    &CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None },
                ))
                .unwrap(),
            );
        }
        backend.mech_cache.insert(
            (8, OperationFamily::Sign),
            ffi_conversion::mechanism_to_ffi(&ffi_conversion::validated_mechanism_for_tests(
                &CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None },
            ))
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

    #[test]
    fn q16_ffi_async_complete_unsupported() {
        // Q16 box 3: native AsyncComplete support remains
        // unimplemented — `FfiBackend` keeps the trait default, so a
        // provider async operation can never be polled to completion
        // through the FFI backend.
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let backend = FfiBackend::test_backend_with_tables(functions.as_mut(), None, None);
        assert_eq!(
            Pkcs11Backend::async_complete(&backend, CkSessionHandle(1), "C_Sign"),
            Err(CkRv::FUNCTION_NOT_SUPPORTED)
        );
    }
}

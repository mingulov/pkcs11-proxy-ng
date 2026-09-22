//! Dynamic interface probe — queries the backend for interface capabilities
//! and caches patched function lists that NULL-out functions the backend
//! does not support.
//!
//! The probe is lazy: `ensure_probed()` runs the RPC at most once until
//! `clear_cache()` or `reprobe()` is called. Pre-`C_Initialize` callers
//! get the static (all-non-null) function lists; post-`C_Initialize`
//! callers get the patched versions.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};

use cryptoki_sys::*;
use pkcs11_proxy_ng_client::BackendInterface;
use pkcs11_proxy_ng_types::MechanismRegistry;

use crate::function_registry::{build_function_list, build_function_list_3_x};
use crate::state;

/// Tracks the registry revision the shim most-recently installed. Used
/// only to log a WARN when consecutive probes deliver different
/// revisions in the same shim lifetime — usually an HA-daemon
/// `mechanism_params.toml` drift, occasionally an operator-driven
/// SIGHUP reload that landed between probes.
static LAST_REGISTRY_REVISION: Mutex<Option<String>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Cached state
// ---------------------------------------------------------------------------

/// Holds the probed function lists and the interface catalog built from them.
struct InterfaceState {
    fl_2_40: CK_FUNCTION_LIST,
    fl_3_0: CK_FUNCTION_LIST_3_0,
    /// PKCS#11 3.1 is layout-identical to 3.0 (no new functions), so the
    /// 3.1 entry reuses the 3.0 list type stamped with version {3,1}.
    fl_3_1: CK_FUNCTION_LIST_3_0,
    fl_3_2: CK_FUNCTION_LIST_3_2,
    catalog: [CK_INTERFACE; 4],
    /// Number of interfaces the backend actually supports (1 to 4).
    count: CK_ULONG,
    /// Whether the backend reported a 3.0-compatible interface.
    has_3_0: bool,
    /// Whether the backend reported a 3.1 interface (W1-L5-01).
    has_3_1: bool,
    /// Whether the backend reported a 3.2-compatible interface.
    has_3_2: bool,
    /// Advertised separately from function-list availability because every
    /// message call must fail closed against an older daemon.
    pointer_safe_message_parameters: bool,
}

// CK_INTERFACE contains raw pointers that are always to `'static` memory
// owned by this module, so Send + Sync are safe.
unsafe impl Send for InterfaceState {}
unsafe impl Sync for InterfaceState {}

static INTERFACE_STATE: RwLock<Option<&'static InterfaceState>> = RwLock::new(None);

/// Serializes probe-and-install sequences (W1-C7-10).
///
/// A probe has global side effects — backend-ABI recording and registry
/// install happen inside `probe_backend`, before the function lists are
/// installed. Two concurrent probes could otherwise cross-pair: the
/// loser's ABI/registry with the winner's function lists. `ensure_probed`
/// and `reprobe` hold this across probe + install, and `clear_cache`
/// holds it across the clear, so install/clear never interleave. Always
/// the outermost lock (taken before `INTERFACE_STATE`).
static PROBE_INSTALL_LOCK: Mutex<()> = Mutex::new(());

/// Backend `sizeof(CK_ULONG)` advertised by the daemon at probe (ADR-0011 D2).
/// `0` = not yet probed, or a daemon predating the advertisement; readers fall
/// back to 8 bytes (D9).
static BACKEND_ULONG_SIZE: AtomicUsize = AtomicUsize::new(0);
static BACKEND_ATTRIBUTE_STRIDE: AtomicUsize = AtomicUsize::new(0);
static POINTER_SAFE_MESSAGE_PARAMETERS: AtomicBool = AtomicBool::new(false);

/// Whether the daemon acknowledged the shape-bound message-parameter contract.
/// Absence and an in-progress/failed reprobe are both fail-closed.
pub fn pointer_safe_message_parameters() -> bool {
    POINTER_SAFE_MESSAGE_PARAMETERS.load(Ordering::Acquire)
}

fn record_pointer_safe_message_parameters(advertised: bool) {
    POINTER_SAFE_MESSAGE_PARAMETERS.store(advertised, Ordering::Release);
}

fn clear_pointer_safe_message_parameters() {
    record_pointer_safe_message_parameters(false);
}

pub(crate) fn invalidate_pointer_safe_message_parameters() {
    clear_pointer_safe_message_parameters();
}

/// The backend's `CK_ULONG` width in bytes for the value bridge (ADR-0011).
///
/// Returns the daemon-advertised width, or 8 (LP64) when talking to a daemon
/// that predates the D2 advertisement (D9 graceful fallback — correct for every
/// supported x86_64 Linux server). Compare against the shim's own
/// `size_of::<CK_ULONG>()`: the bridge engages only when they differ.
// Consumed by the attribute-value width bridge (ADR-0011 task #4), wired next.
#[allow(dead_code)]
pub fn backend_ulong_size() -> usize {
    match BACKEND_ULONG_SIZE.load(Ordering::Relaxed) {
        0 => 8,
        n => n,
    }
}

/// The backend's native `sizeof(CK_ATTRIBUTE)` — the stride of nested
/// `CKA_*_TEMPLATE` byte lengths on the wire (ADR-0011 D2 extension).
///
/// Falls back to `3 * backend_ulong_size()` (correct for LP64/ILP32 Unix
/// layouts) when the daemon predates the advertisement; an LLP64 backend's
/// packed stride (16) requires the advertisement.
pub fn backend_attribute_stride() -> usize {
    match BACKEND_ATTRIBUTE_STRIDE.load(Ordering::Relaxed) {
        0 => 3 * backend_ulong_size(),
        n => n,
    }
}

/// Resolve the advertised `CK_ATTRIBUTE` stride (pure policy, unit tested).
///
/// Absent => `3 * width` fallback. Advertised values are sanity-bounded:
/// a stride below 12 (the smallest real layout) or above 64 is hostile.
fn resolve_backend_attribute_stride(stride: Option<u32>, width: usize) -> Result<usize, String> {
    match stride {
        None => Ok(3 * width),
        Some(n @ 12..=64) => Ok(n as usize),
        Some(other) => Err(format!(
            "backend advertised an implausible CK_ATTRIBUTE stride {other} (expected 12..=64)"
        )),
    }
}

/// Resolve the backend `CK_ULONG` width to store from a daemon's advertised
/// `(size, byte_order)` (ADR-0011 D2/D6/D9) — pure, so the policy is unit
/// tested without touching the global state.
///
/// - D6: a byte-order mismatch is refused (`Err`) — the wire carries native
///   ulong bytes, so a mismatch would corrupt every multi-byte ulong. All
///   supported targets are little-endian. Out-of-contract orders (anything
///   but 1/2/absent) are likewise refused, never fallen through (W1-C7-08).
/// - D2: a valid advertised width (4 or 8) is used; any other value is hostile
///   and refused.
/// - D9: an absent width falls back to 8 (LP64) — correct for every supported
///   x86_64 Linux daemon. `Ok(None)` signals "fell back" so the caller can warn.
pub(crate) fn resolve_backend_ulong_size(
    size: Option<u32>,
    order: Option<u32>,
) -> Result<(usize, bool), String> {
    match order {
        Some(2) if cfg!(target_endian = "little") => {
            return Err("backend advertises big-endian CK_ULONG but this client is \
                        little-endian; refusing to avoid silent corruption (ADR-0011 D6)"
                .to_string());
        }
        Some(1) if cfg!(target_endian = "big") => {
            return Err("backend advertises little-endian CK_ULONG but this client is \
                        big-endian; refusing (ADR-0011 D6)"
                .to_string());
        }
        // Contract orders (host_abi.rs): 1 = little, 2 = big, absent =
        // unspecified (older daemon). Anything else is out of contract
        // and refused loudly instead of falling through (W1-C7-08).
        None | Some(1) | Some(2) => {}
        Some(other) => {
            return Err(format!(
                "backend advertised an invalid CK_ULONG byte order {other} \
                 (expected 1 (little-endian) or 2 (big-endian); ADR-0011 D6)"
            ));
        }
    }
    match size {
        Some(n @ (4 | 8)) => Ok((n as usize, false)),
        Some(other) => {
            Err(format!("backend advertised an invalid CK_ULONG size {other} (expected 4 or 8)"))
        }
        None => Ok((8, true)),
    }
}

/// Record the backend's advertised ABI (ADR-0011 D2/D6): `CK_ULONG`
/// width/byte order and the `CK_ATTRIBUTE` stride.
fn record_backend_abi(
    size: Option<u32>,
    order: Option<u32>,
    stride: Option<u32>,
) -> Result<(), String> {
    let (width, fell_back) = resolve_backend_ulong_size(size, order)?;
    let stride = resolve_backend_attribute_stride(stride, width)?;
    BACKEND_ULONG_SIZE.store(width, Ordering::Relaxed);
    BACKEND_ATTRIBUTE_STRIDE.store(stride, Ordering::Relaxed);
    if fell_back && std::mem::size_of::<CK_ULONG>() != 8 {
        tracing::warn!(
            "daemon does not advertise its backend CK_ULONG width; assuming 8 bytes \
             (ADR-0011 D9). This narrow client cannot verify the backend width — \
             upgrade the daemon to advertise it."
        );
    }
    Ok(())
}

/// Null-terminated name used for all interface entries.
const IFACE_NAME_PKCS11: &[u8] = b"PKCS 11\0";

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

fn build_base_function_list_3_1() -> CK_FUNCTION_LIST_3_0 {
    build_function_list_3_x!(CK_FUNCTION_LIST_3_0, CK_VERSION { major: 3, minor: 1 })
}

/// Build a patched v3.1 function list given a set of null function names.
/// Same layout and patch table as 3.0; only the version stamp differs.
fn build_patched_function_list_3_1(null_names: &[String]) -> CK_FUNCTION_LIST_3_0 {
    let mut fl = build_base_function_list_3_1();
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

/// Why a probe failed — the two classes propagate differently.
///
/// A transient failure (transport, daemon restart) keeps the previous
/// state and is retried later. An ABI refusal (D6 byte-order mismatch,
/// hostile advertisement) is a hard incompatibility: every ulong byte
/// the daemon would send is unparseable, so `C_Initialize` must fail.
pub(crate) enum ProbeFailure {
    Transient(String),
    AbiMismatch(String),
}

impl std::fmt::Display for ProbeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(e) => write!(f, "{e}"),
            Self::AbiMismatch(e) => write!(f, "incompatible backend ABI: {e}"),
        }
    }
}

/// Contact the backend and build an `InterfaceState` with patched function
/// lists reflecting the backend's capabilities. Also pulls the server's
/// mechanism registry payload (when provided) and atomically swaps the
/// shim's in-memory registry to match.
///
/// The caller must hold [`PROBE_INSTALL_LOCK`]: the probe has global
/// side effects (backend-ABI recording, registry install) that must not
/// interleave with another probe's install (W1-C7-10). The guard
/// parameter enforces that at compile time.
fn probe_backend(_install: &std::sync::MutexGuard<'_, ()>) -> Result<InterfaceState, ProbeFailure> {
    // W1-C7-01: pre-init probes share one failed dial outcome. A failed dial
    // series (~21 s at default attempts/backoff) is cached in state; later
    // pre-init probes to the same endpoint fail fast instead of re-dialing.
    // C_Initialize always dials: it sets INITIALIZED before connecting, so
    // this gate never engages there (nor in post-init reprobes), and any
    // successful connect clears the cache.
    if !state::is_initialized() && state::pre_init_connect_failed() {
        return Err(ProbeFailure::Transient(
            "connect failed (cached pre-init dial outcome; C_Initialize retries)".to_string(),
        ));
    }
    // Ensure the gRPC channel is up (returns Err(CkRv) on failure).
    state::ensure_client_connected()
        .map_err(|e| ProbeFailure::Transient(format!("connect failed: {e:?}")))?;

    let rt = state::runtime();
    let probe = rt
        .block_on(async {
            let mut client = state::client().lock().await;
            client.get_backend_interfaces().await
        })
        .map_err(|e| ProbeFailure::Transient(e.to_string()))?;

    // Record the backend CK_ULONG width/byte order for the value bridge
    // (ADR-0011 D2/D6) before anything else uses it. A refusal here is
    // FATAL: the wire representation itself is incompatible.
    record_backend_abi(
        probe.backend_ulong_size,
        probe.backend_byte_order,
        probe.backend_attribute_stride,
    )
    .map_err(ProbeFailure::AbiMismatch)?;

    maybe_install_server_registry(probe.mechanism_registry.as_ref());

    Ok(build_interface_state(&probe.interfaces, probe.pointer_safe_message_parameters))
}

/// Build the cached interface state from one probe response. Pure over the
/// reported [`BackendInterface`] entries so the version mapping is unit
/// tested without a daemon.
///
/// Catalog order is ascending by version; entries exist only for versions
/// the backend actually reported — a 3.1 report yields a {3,1} entry and no
/// {3,0} alias (W1-L5-01).
fn build_interface_state(
    interfaces: &[BackendInterface],
    pointer_safe_message_parameters: bool,
) -> InterfaceState {
    // Index null-function lists by (major, minor).
    let mut null_map = std::collections::HashMap::<(u8, u8), Vec<String>>::new();
    for iface in interfaces {
        null_map.insert((iface.version_major, iface.version_minor), iface.null_functions.clone());
    }

    let empty = Vec::new();
    let nulls_2_40 = null_map.get(&(2, 40)).unwrap_or(&empty);
    let nulls_3_0 = null_map.get(&(3, 0)).unwrap_or(&empty);
    let nulls_3_1 = null_map.get(&(3, 1)).unwrap_or(&empty);
    let nulls_3_2 = null_map.get(&(3, 2)).unwrap_or(&empty);

    // Determine which interfaces the backend reported.
    let has_3_0 = null_map.contains_key(&(3, 0));
    let has_3_1 = null_map.contains_key(&(3, 1));
    let has_3_2 = null_map.contains_key(&(3, 2));
    // Always include v2.40 — every PKCS#11 module has it.
    let count: CK_ULONG =
        1 + if has_3_0 { 1 } else { 0 } + if has_3_1 { 1 } else { 0 } + if has_3_2 { 1 } else { 0 };

    let fl_2_40 = build_patched_function_list(nulls_2_40);
    let fl_3_0 = build_patched_function_list_3_0(nulls_3_0);
    let fl_3_1 = build_patched_function_list_3_1(nulls_3_1);
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
        CK_INTERFACE {
            pInterfaceName: IFACE_NAME_PKCS11.as_ptr() as *mut CK_CHAR,
            pFunctionList: std::ptr::null_mut(),
            flags: 0,
        },
    ];

    InterfaceState {
        fl_2_40,
        fl_3_0,
        fl_3_1,
        fl_3_2,
        catalog,
        count,
        has_3_0,
        has_3_1,
        has_3_2,
        pointer_safe_message_parameters,
    }
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
    if st.has_3_1 {
        st.catalog[idx].pFunctionList =
            &st.fl_3_1 as *const CK_FUNCTION_LIST_3_0 as *mut std::ffi::c_void;
        idx += 1;
    }
    if st.has_3_2 {
        st.catalog[idx].pFunctionList =
            &st.fl_3_2 as *const CK_FUNCTION_LIST_3_2 as *mut std::ffi::c_void;
        idx += 1;
    }
    debug_assert_eq!(idx as CK_ULONG, st.count, "catalog entries must match count");
}

/// Whether the server-published registry is disabled via
/// `PKCS11_PROXY_DISABLE_SERVER_REGISTRY` (W1-L8-19).
///
/// Canonical value parsing (the operator runbook defers to this doc):
/// unset keeps the default (install the server payload). An explicit falsy
/// value (`0`, `false`, `no`, `off`, case-insensitive) re-enables the
/// install so operators can flip the flag off without unsetting it. Any
/// other set value — including `1`, `true`, the empty string, unrecognized
/// text, and non-UTF8 bytes — keeps the legacy presence-means-disabled
/// behavior. That fail-legacy choice is deliberate: a value the parser
/// cannot understand must not silently re-enable the install.
pub(crate) fn server_registry_disabled() -> bool {
    match std::env::var_os("PKCS11_PROXY_DISABLE_SERVER_REGISTRY") {
        None => false,
        Some(value) => match value.to_str() {
            Some(text) => {
                !matches!(text.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off")
            }
            // Non-UTF8 value: fail-legacy, per the doc comment above.
            None => true,
        },
    }
}

/// Install the server-published registry whenever the daemon includes
/// one. Older daemons predate the field — in that case we keep whatever
/// the shim's embedded-default fallback already installed (see
/// init_general.rs). `PKCS11_PROXY_DISABLE_SERVER_REGISTRY` (test/debug
/// use, see AGENTS.md) forces the fallback path even when the daemon
/// publishes a registry; see [`server_registry_disabled`] for the
/// value parsing (explicit `0`/`false` re-enables).
pub(crate) fn maybe_install_server_registry(
    payload: Option<&pkcs11_proxy_ng_proto::MechanismRegistryPayload>,
) {
    if !server_registry_disabled() {
        if let Some(payload) = payload {
            // W1-C8-10: a duplicate-ID payload is malformed; keep the
            // previously installed registry instead of installing a
            // last-wins corruption, and say so loudly.
            let registry = match MechanismRegistry::try_from(payload) {
                Ok(registry) => registry,
                Err(duplicate) => {
                    tracing::error!(
                        "{duplicate}; ignoring server-published registry, keeping previous"
                    );
                    return;
                }
            };
            let new_revision = registry.revision().to_string();
            log_registry_change(&new_revision);
            state::replace_mechanism_registry(registry);
        }
    } else {
        tracing::debug!(
            "PKCS11_PROXY_DISABLE_SERVER_REGISTRY set; ignoring server-published registry"
        );
    }
}

/// Reset the revision tracker so drift tests start from a known state.
/// Test-only; production resets happen in `clear_cache` (W1-C7-11).
#[cfg(test)]
pub(crate) fn reset_registry_revision_for_test() {
    *LAST_REGISTRY_REVISION.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Record the latest registry revision and emit a log line. A change
/// across probes is normal after a daemon SIGHUP reload; an unexpected
/// flap (different revisions in quick succession against a supposedly
/// stable daemon) suggests HA daemon replicas serving inconsistent
/// `mechanism_params.toml` files, so it is escalated to WARN.
fn log_registry_change(new_revision: &str) {
    let mut guard = LAST_REGISTRY_REVISION.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_deref() {
        Some(prev) if prev == new_revision => {
            tracing::debug!(revision = %new_revision, "mechanism registry unchanged");
        }
        Some(prev) => {
            tracing::warn!(
                previous = %prev,
                current = %new_revision,
                "mechanism registry revision changed between probes — \
                 expected after a daemon SIGHUP or new daemon replica; \
                 if unintentional, check HA daemon mechanism_params.toml consistency"
            );
        }
        None => {
            tracing::info!(
                revision = %new_revision,
                "mechanism registry installed from server"
            );
        }
    }
    *guard = Some(new_revision.to_string());
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
    // W1-C7-10: serialize probe + install so two concurrent callers cannot
    // cross-pair one probe's ABI/registry with another's function lists.
    let install = PROBE_INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Fast path: already cached.
    {
        let guard = INTERFACE_STATE.read().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return Ok(());
        }
    }
    // Slow path: probe and store.
    let st = probe_backend(&install).map_err(|e| e.to_string())?;
    let mut guard = INTERFACE_STATE.write().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(leak_fixed_state(st));
    }
    // A losing concurrent probe publishes the capability of the state that
    // actually won installation, never its own stale response.
    record_pointer_safe_message_parameters(
        guard.as_ref().is_some_and(|state| state.pointer_safe_message_parameters),
    );
    Ok(())
}

/// Force a re-probe of the backend, replacing any cached state.
///
/// Called from `C_Initialize` after a successful server init so that the
/// function lists reflect the current backend.
pub fn reprobe() -> Result<(), String> {
    // W1-C7-10: same install lock as ensure_probed — a reprobe racing an
    // initial probe must not interleave side effects with the install.
    let install = PROBE_INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // A reprobe can be talking to a restarted or downgraded daemon. Do not let
    // a transient failure retain permission for stateful message operations.
    clear_pointer_safe_message_parameters();
    // A re-probe always dials fresh: drop any cached pre-init failure (W1-C7-01).
    state::clear_pre_init_connect_failure();
    match probe_backend(&install) {
        Ok(st) => {
            let mut guard = INTERFACE_STATE.write().unwrap_or_else(|e| e.into_inner());
            *guard = Some(leak_fixed_state(st));
            record_pointer_safe_message_parameters(
                guard.as_ref().is_some_and(|state| state.pointer_safe_message_parameters),
            );
            Ok(())
        }
        Err(ProbeFailure::Transient(e)) => {
            // BUG-001 contract: a transient probe failure must not fail
            // C_Initialize; the cached (or fallback) state stays in use.
            tracing::warn!("interface reprobe failed, keeping previous state: {e}");
            Ok(())
        }
        Err(fatal @ ProbeFailure::AbiMismatch(_)) => {
            tracing::error!("{fatal}; refusing to operate against this daemon (ADR-0011 D6)");
            Err(fatal.to_string())
        }
    }
}

/// Clear the cached state (called from `C_Finalize`).
///
/// After this, `ensure_probed()` will re-probe on the next call.
pub fn clear_cache() {
    // W1-C7-10: hold the install lock so a clear cannot interleave with a
    // concurrent probe's side effects or install.
    let _install = PROBE_INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_pointer_safe_message_parameters();
    // Cache-clear (e.g. C_Finalize) also drops the dial-failure cache (W1-C7-01).
    state::clear_pre_init_connect_failure();
    let mut guard = INTERFACE_STATE.write().unwrap_or_else(|e| e.into_inner());
    *guard = None;
    // Drop the advertised backend ABI so a fresh probe re-reads it (D2).
    BACKEND_ULONG_SIZE.store(0, Ordering::Relaxed);
    BACKEND_ATTRIBUTE_STRIDE.store(0, Ordering::Relaxed);
    // W1-C7-11: reset the revision tracker — the next Initialize may talk
    // to a different daemon, and that must log a fresh install INFO, not
    // a spurious drift WARN against the previous lifetime's revision.
    *LAST_REGISTRY_REVISION.lock().unwrap_or_else(|e| e.into_inner()) = None;
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
///
/// W1-L5-03: the pre-probe answer is an intentional transient — the
/// optimistic [2.40, 3.0, 3.2] shape — because the backend's real set is
/// unknowable before first contact. The first successful probe replaces
/// it with the backend's actual shape, which may legitimately differ
/// (fewer entries, or a 3.1 entry with no 3.0 alias). Pinned by
/// `pre_probe_fallback_catalog_shape_is_pinned_transient`.
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
/// Otherwise falls back to the static (all-non-null) catalog — the
/// W1-L5-03 optimistic transient; see [`interface_count`].
///
/// Returns the number of entries written.
///
/// # Safety
///
/// `buf` must be valid for writes of `buf_len` `CK_INTERFACE` entries.
/// A short buffer (`buf_len` below the catalog count) fails safe —
/// nothing is written and 0 is returned — as does a null `buf`
/// (W1-C7-12 in-callee hardening: direct misuse fails safe instead of
/// faulting). A non-null buffer smaller than the claimed `buf_len` is
/// still immediate undefined behavior; the caller must uphold it.
pub unsafe fn copy_catalog(buf: *mut CK_INTERFACE, buf_len: CK_ULONG) -> CK_ULONG {
    if buf.is_null() {
        return 0; // W1-C7-12: direct misuse fails safe, no caller guard needed
    }
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
    flags: CK_FLAGS,
) -> *mut CK_INTERFACE {
    let guard = INTERFACE_STATE.read().unwrap_or_else(|e| e.into_inner());

    match guard.as_ref() {
        Some(st) => {
            find_interface_in_catalog(&st.catalog[..st.count as usize], name, version, flags)
                .map(|p| p as *mut CK_INTERFACE)
                .unwrap_or(std::ptr::null_mut())
        }
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
            find_interface_in_catalog(&fb.0, name, version, flags)
                .map(|p| p as *mut CK_INTERFACE)
                .unwrap_or(std::ptr::null_mut())
        }
    }
}

/// Find the last catalog entry satisfying the optional name/version and flag subset.
fn find_interface_in_catalog(
    catalog: &[CK_INTERFACE],
    name: Option<&std::ffi::CStr>,
    version: Option<&CK_VERSION>,
    flags: CK_FLAGS,
) -> Option<*const CK_INTERFACE> {
    catalog.iter().enumerate().rev().find_map(|(index, iface)| {
        if iface.flags & flags != flags {
            return None;
        }
        if let Some(requested_name) = name {
            let iface_name = unsafe {
                std::ffi::CStr::from_ptr(iface.pInterfaceName as *const std::ffi::c_char)
            };
            if iface_name != requested_name {
                return None;
            }
        }
        if let Some(requested_version) = version {
            let function_list_version = unsafe { &*(iface.pFunctionList as *const CK_VERSION) };
            if function_list_version.major != requested_version.major
                || function_list_version.minor != requested_version.minor
            {
                return None;
            }
        }
        Some(&catalog[index] as *const CK_INTERFACE)
    })
}

/// Wrapper so we can store a `[CK_INTERFACE; 3]` in a `OnceLock` (the raw
/// pointers inside need Send + Sync).
struct FallbackCatalog([CK_INTERFACE; 3]);
unsafe impl Send for FallbackCatalog {}
unsafe impl Sync for FallbackCatalog {}

#[cfg(test)]
mod backend_abi_tests {
    use cryptoki_sys::{CK_INTERFACE, CK_VERSION};

    use super::{
        BackendInterface, clear_pointer_safe_message_parameters, find_interface_in_catalog,
        pointer_safe_message_parameters, record_pointer_safe_message_parameters,
        resolve_backend_attribute_stride, resolve_backend_ulong_size,
    };

    fn iface(major: u8, minor: u8, nulls: Vec<String>) -> BackendInterface {
        BackendInterface { version_major: major, version_minor: minor, null_functions: nulls }
    }

    fn synthetic_catalog() -> [CK_INTERFACE; 2] {
        static NAME: &[u8] = b"PKCS 11\0";
        [
            CK_INTERFACE {
                pInterfaceName: NAME.as_ptr() as *mut _,
                pFunctionList: crate::function_list_3_0::get_function_list_3_0() as *mut _,
                flags: 0b0011,
            },
            CK_INTERFACE {
                pInterfaceName: NAME.as_ptr() as *mut _,
                pFunctionList: crate::function_list_3_2::get_function_list_3_2() as *mut _,
                flags: 0b0011,
            },
        ]
    }

    #[test]
    fn synthetic_interface_catalog_applies_flag_subset_to_all_selectors() {
        let catalog = synthetic_catalog();
        let name = c"PKCS 11";
        let version = CK_VERSION { major: 3, minor: 0 };

        for flags in [0, 0b0001, 0b0011] {
            assert!(find_interface_in_catalog(&catalog, Some(name), None, flags).is_some());
            assert!(find_interface_in_catalog(&catalog, None, None, flags).is_some());
            assert!(
                find_interface_in_catalog(&catalog, Some(name), Some(&version), flags).is_some()
            );
            assert!(find_interface_in_catalog(&catalog, None, Some(&version), flags).is_some());
        }
        for (name, version) in
            [(Some(name), None), (None, None), (Some(name), Some(&version)), (None, Some(&version))]
        {
            assert!(find_interface_in_catalog(&catalog, name, version, 0b0100).is_none());
        }
    }

    /// W1-L5-01: a BouncyHSM-class probe — backend offers 3.1 (and 3.2) but
    /// no literal 3.0 — must answer {3,1} with the real interface and {3,0}
    /// with NULL, exactly like the native module. No invented {3,0} alias.
    #[test]
    fn bouncyhsm_probe_answers_3_1_and_not_3_0() {
        let probe =
            vec![iface(2, 40, Vec::new()), iface(3, 1, Vec::new()), iface(3, 2, Vec::new())];
        let mut st = super::build_interface_state(&probe, false);
        super::fixup_catalog(&mut st);
        assert_eq!(st.count, 3);
        let catalog = &st.catalog[..st.count as usize];
        let name = c"PKCS 11";

        // {3,1} → the real interface, stamped 3.1.
        let v31 = CK_VERSION { major: 3, minor: 1 };
        let hit = find_interface_in_catalog(catalog, Some(name), Some(&v31), 0)
            .expect("{3,1} must resolve when the backend offers 3.1");
        let stamped = unsafe { *((&*hit).pFunctionList as *const CK_VERSION) };
        assert_eq!((stamped.major, stamped.minor), (3, 1));

        // {3,0} → honest NULL: the backend offers no literal 3.0.
        let v30 = CK_VERSION { major: 3, minor: 0 };
        assert!(
            find_interface_in_catalog(catalog, Some(name), Some(&v30), 0).is_none(),
            "no invented {{3,0}} alias for a 3.1-only backend"
        );

        // {3,2} still resolves, and the default (no version) is the highest.
        let v32 = CK_VERSION { major: 3, minor: 2 };
        assert!(find_interface_in_catalog(catalog, Some(name), Some(&v32), 0).is_some());
        let default = find_interface_in_catalog(catalog, Some(name), None, 0)
            .expect("default interface must resolve");
        let default_stamped = unsafe { *((&*default).pFunctionList as *const CK_VERSION) };
        assert_eq!((default_stamped.major, default_stamped.minor), (3, 2));
    }

    /// Control: a classic probe — backend answers literal 3.0 — keeps
    /// answering {3,0} and must not gain a phantom {3,1}.
    #[test]
    fn literal_3_0_probe_answers_3_0_and_not_3_1() {
        let probe =
            vec![iface(2, 40, Vec::new()), iface(3, 0, Vec::new()), iface(3, 2, Vec::new())];
        let mut st = super::build_interface_state(&probe, false);
        super::fixup_catalog(&mut st);
        assert_eq!(st.count, 3);
        let catalog = &st.catalog[..st.count as usize];
        let name = c"PKCS 11";

        let v30 = CK_VERSION { major: 3, minor: 0 };
        let hit = find_interface_in_catalog(catalog, Some(name), Some(&v30), 0)
            .expect("{3,0} must resolve when the backend offers literal 3.0");
        let stamped = unsafe { *((&*hit).pFunctionList as *const CK_VERSION) };
        assert_eq!((stamped.major, stamped.minor), (3, 0));

        let v31 = CK_VERSION { major: 3, minor: 1 };
        assert!(
            find_interface_in_catalog(catalog, Some(name), Some(&v31), 0).is_none(),
            "no phantom {{3,1}} for a literal-3.0 backend"
        );
    }

    /// W1-C7-05: the patched-function-list path NULLs exactly the
    /// backend-reported slots. Non-empty `null_functions` fixtures pin the
    /// patch branch per struct version (2.40 + 3.0 here; 3.2 below).
    #[test]
    fn patched_function_list_nulls_reported_slots_only() {
        let probe = vec![
            iface(2, 40, vec!["C_Encrypt".to_string(), "C_Decrypt".to_string()]),
            iface(3, 0, vec!["C_LoginUser".to_string()]),
            iface(3, 2, Vec::new()),
        ];
        let st = super::build_interface_state(&probe, false);
        // E0793: CK lists are packed on Windows; `is_some()`/`is_none()`
        // run on by-value copies.
        assert!(
            {
                let f = st.fl_2_40.C_Encrypt;
                f.is_none()
            },
            "C_Encrypt nulled"
        );
        assert!(
            {
                let f = st.fl_2_40.C_Decrypt;
                f.is_none()
            },
            "C_Decrypt nulled"
        );
        assert!(
            {
                let f = st.fl_2_40.C_SignInit;
                f.is_some()
            },
            "C_SignInit stays"
        );
        assert!(
            {
                let f = st.fl_3_0.C_LoginUser;
                f.is_none()
            },
            "C_LoginUser nulled"
        );
        assert!(
            {
                let f = st.fl_3_0.C_SessionCancel;
                f.is_some()
            },
            "C_SessionCancel stays"
        );
        assert!(
            {
                let f = st.fl_3_2.C_EncapsulateKey;
                f.is_some()
            },
            "3.2 unpatched stays"
        );
    }

    /// W1-C7-05: unknown names in `null_functions` are ignored — a newer
    /// daemon's function names must not break an older shim's patch loop
    /// or NULL unrelated slots.
    #[test]
    fn patched_function_list_ignores_unknown_names() {
        let probe = vec![iface(2, 40, vec!["C_NoSuchFunction".to_string(), String::new()])];
        let st = super::build_interface_state(&probe, false);
        assert!(
            {
                let f = st.fl_2_40.C_Encrypt;
                f.is_some()
            },
            "C_Encrypt stays"
        );
        assert!(
            {
                let f = st.fl_2_40.C_Login;
                f.is_some()
            },
            "C_Login stays"
        );
        assert!(
            {
                let f = st.fl_3_0.C_LoginUser;
                f.is_some()
            },
            "3.0 C_LoginUser stays"
        );
    }

    /// W1-C7-05: a 3.2-without-3.0 probe (BouncyHSM class) patches the 3.2
    /// list from its own null set and catalogs exactly {2.40, 3.2} — no
    /// invented {3,0} entry, and {3,0} lookups honestly miss.
    #[test]
    fn patched_3_2_without_3_0_catalogs_exactly_two_entries() {
        let probe =
            vec![iface(2, 40, Vec::new()), iface(3, 2, vec!["C_EncapsulateKey".to_string()])];
        let mut st = super::build_interface_state(&probe, false);
        super::fixup_catalog(&mut st);
        assert_eq!(st.count, 2);
        assert!(
            {
                let f = st.fl_3_2.C_EncapsulateKey;
                f.is_none()
            },
            "3.2 patch applies"
        );
        assert!(
            {
                let f = st.fl_3_2.C_DecapsulateKey;
                f.is_some()
            },
            "3.2 sibling stays"
        );
        let catalog = &st.catalog[..st.count as usize];
        let name = c"PKCS 11";
        let v32 = CK_VERSION { major: 3, minor: 2 };
        let hit = find_interface_in_catalog(catalog, Some(name), Some(&v32), 0)
            .expect("{3,2} must resolve when the backend offers 3.2");
        let stamped = unsafe { *((&*hit).pFunctionList as *const CK_VERSION) };
        assert_eq!((stamped.major, stamped.minor), (3, 2));
        let v30 = CK_VERSION { major: 3, minor: 0 };
        assert!(
            find_interface_in_catalog(catalog, Some(name), Some(&v30), 0).is_none(),
            "no invented {{3,0}} alias for a 3.2-without-3.0 backend"
        );
    }

    #[test]
    fn message_parameter_capability_is_cleared_before_reprobe() {
        record_pointer_safe_message_parameters(true);
        clear_pointer_safe_message_parameters();
        assert!(!pointer_safe_message_parameters());
    }

    #[test]
    fn stride_absent_falls_back_to_three_ulongs() {
        assert_eq!(resolve_backend_attribute_stride(None, 8), Ok(24));
        assert_eq!(resolve_backend_attribute_stride(None, 4), Ok(12));
    }

    #[test]
    fn stride_advertised_value_wins() {
        // LLP64: packed CK_ATTRIBUTE stride 16 with a 4-byte ulong.
        assert_eq!(resolve_backend_attribute_stride(Some(16), 4), Ok(16));
        assert_eq!(resolve_backend_attribute_stride(Some(24), 8), Ok(24));
    }

    #[test]
    fn stride_rejects_hostile_values() {
        assert!(resolve_backend_attribute_stride(Some(0), 8).is_err());
        assert!(resolve_backend_attribute_stride(Some(7), 8).is_err(), "below any real layout");
        assert!(resolve_backend_attribute_stride(Some(300), 8).is_err());
    }

    /// This client's own D2 byte-order code: 1 on LE, 2 on BE.
    fn native_order() -> Option<u32> {
        Some(if cfg!(target_endian = "little") { 1 } else { 2 })
    }

    #[test]
    fn valid_advertised_widths_pass_through() {
        assert_eq!(resolve_backend_ulong_size(Some(4), native_order()), Ok((4, false)));
        assert_eq!(resolve_backend_ulong_size(Some(8), native_order()), Ok((8, false)));
        // Byte order may be unspecified (older daemon set the size only).
        assert_eq!(resolve_backend_ulong_size(Some(8), None), Ok((8, false)));
    }

    #[test]
    fn absent_width_falls_back_to_eight_d9() {
        // D9: no advertisement → assume 8 (LP64), flagged so the caller can warn.
        assert_eq!(resolve_backend_ulong_size(None, None), Ok((8, true)));
        assert_eq!(resolve_backend_ulong_size(None, native_order()), Ok((8, true)));
    }

    #[test]
    fn invalid_width_is_refused() {
        // Native order throughout so these pin the WIDTH refusal, not D6.
        assert!(resolve_backend_ulong_size(Some(2), native_order()).is_err());
        assert!(resolve_backend_ulong_size(Some(16), native_order()).is_err());
        assert!(resolve_backend_ulong_size(Some(0), native_order()).is_err());
    }

    /// W1-C7-08: out-of-contract byte orders are refused loudly — the
    /// contract is 1 (little) / 2 (big) / unspecified only (host_abi.rs).
    /// Falling through as "unspecified" would silently accept garbage.
    #[test]
    fn out_of_contract_byte_orders_refused() {
        for order in [0, 3, 99, u32::MAX] {
            let result = resolve_backend_ulong_size(Some(8), Some(order));
            assert!(result.is_err(), "order {order} is out of contract and must be refused");
            let err = result.unwrap_err();
            assert!(err.contains("byte order"), "refusal must name the field: {err}");
        }
    }

    /// W1-L5-08: unknown byte orders are refused at every size arm — the
    /// order check precedes the width check, so even an absent or
    /// invalid size cannot smuggle an out-of-contract order through.
    /// Confirms the W1-C7-08 (Task 12) shape; the refusal names the
    /// byte-order field on every arm.
    #[test]
    fn out_of_contract_byte_orders_refused_at_every_size_arm() {
        for order in [0, 3, 99, u32::MAX] {
            for size in [None, Some(4), Some(8), Some(0), Some(16)] {
                let result = resolve_backend_ulong_size(size, Some(order));
                assert!(result.is_err(), "order {order} with size {size:?} must be refused");
                let err = result.unwrap_err();
                assert!(err.contains("byte order"), "refusal must name the field: {err}");
            }
        }
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn big_endian_backend_refused_on_le_client_d6() {
        // D6: the wire carries native ulong bytes; a BE backend would corrupt
        // every multi-byte ulong for this LE client.
        assert!(resolve_backend_ulong_size(Some(8), Some(2)).is_err());
        // A little-endian or unspecified order is accepted.
        assert!(resolve_backend_ulong_size(Some(8), Some(1)).is_ok());
        assert!(resolve_backend_ulong_size(Some(8), None).is_ok());
    }

    #[test]
    #[cfg(target_endian = "big")]
    fn little_endian_backend_refused_on_be_client_d6() {
        // D6 mirror: on a BE client it is the LE advertisement that must be
        // refused, while BE (native) and unspecified pass.
        assert!(resolve_backend_ulong_size(Some(8), Some(1)).is_err());
        assert!(resolve_backend_ulong_size(Some(8), Some(2)).is_ok());
        assert!(resolve_backend_ulong_size(Some(8), None).is_ok());
    }
}

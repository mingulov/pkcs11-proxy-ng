use super::*;
use std::sync::{Mutex, MutexGuard, Once};

static SHIM_STATE_TEST_GUARD: Mutex<()> = Mutex::new(());
static FAST_CONNECT_ENV: Once = Once::new();

/// Serializes tests that touch the shim's process-global state (client
/// connection, probe caches, `PKCS11_PROXY_*` env vars) and pins the
/// connect-retry loop to a single attempt. Without the pin, any test
/// that observes a missing or dead endpoint (parallel tests race on the
/// process-global env vars) sleeps through the full production backoff
/// (~21 s), and victims queue behind the client-init lock — the whole
/// suite degraded to ~10 min per run on every architecture.
/// `pub(crate)` so R11 reader tests (which gather the global capability
/// snapshot through the production entry / nested helper) serialize
/// against the capability-mutating suites (R5/R10).
pub(crate) fn shim_state_test_guard() -> MutexGuard<'static, ()> {
    FAST_CONNECT_ENV.call_once(|| unsafe {
        std::env::set_var("PKCS11_PROXY_CONNECT_ATTEMPTS", "1");
    });
    SHIM_STATE_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner())
}

/// Q03 probe child-role sentinel (B3): subprocess-isolated
/// native-probe parents set this on the spawned child command; the
/// child body refuses unless it is present, so direct selection can
/// never run provider contact in the shared harness process.
#[cfg(not(miri))]
pub(crate) const Q03_PROBE_CHILD_ROLE: &str = "Q03_PROBE_CHILD_ROLE";

/// Q03 probe child-role guard (B3): call as the FIRST statement of
/// an isolated probe-child body, before any fixture or provider
/// contact. Panics (loud refusal) unless the parent-set
/// [`Q03_PROBE_CHILD_ROLE`] sentinel is present.
#[cfg(not(miri))]
pub(crate) fn require_q03_probe_child_role() {
    assert!(
        std::env::var_os(Q03_PROBE_CHILD_ROLE).is_some(),
        "refusing direct selection: {Q03_PROBE_CHILD_ROLE} is not set (this probe body runs \
         only in the parent-spawned child process, never in the shared test harness)"
    );
}

mod abi_audit;
mod attribute_classification;
#[cfg(unix)]
#[cfg(not(miri))] // live hook-daemon Unix socket; covered natively
mod control_channel_live;
#[cfg(not(miri))] // in-process daemon stack (sockets); covered natively
mod cross_abi;
#[cfg(not(miri))] // in-process daemon stack (sockets); covered natively
mod cross_width_live;
mod dispatch_shape;
mod endpoint;
#[cfg(not(miri))] // C_Initialize spins a tokio runtime + daemon dial; covered natively
mod init_args;
#[cfg(not(miri))] // binds TcpListeners / dials daemons; covered natively
mod interface;
#[cfg(not(miri))] // real kryoptic provider + daemon; covered natively
mod kryoptic_gav_null;
#[cfg(not(miri))] // real kryoptic provider via libloading + daemon; covered natively
mod kryoptic_label_probe;
mod null_pointers;
#[cfg(not(miri))] // binds TcpListeners (tokio); covered natively
mod output_semantics;
mod poison_recovery;
mod regression;
mod resource_limits;
#[cfg(not(miri))] // live oracle daemon; covered natively
mod retained_oracle_live;
#[cfg(not(miri))] // real SoftHSM2 provider + daemon; covered natively
mod softhsm_gcm;
#[cfg(not(miri))] // threaded interleave hammer; covered natively
mod suspect_interleave;
#[cfg(not(miri))] // real SoftHSM2 provider via libloading; covered natively
mod token_label_native_probe;
#[cfg(not(miri))] // shared daemon fixture; covered natively
mod wait_matrix;

fn empty_interface() -> CK_INTERFACE {
    CK_INTERFACE {
        pInterfaceName: std::ptr::null_mut(),
        pFunctionList: std::ptr::null_mut(),
        flags: 0,
    }
}

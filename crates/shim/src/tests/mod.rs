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
fn shim_state_test_guard() -> MutexGuard<'static, ()> {
    FAST_CONNECT_ENV.call_once(|| unsafe {
        std::env::set_var("PKCS11_PROXY_CONNECT_ATTEMPTS", "1");
    });
    SHIM_STATE_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner())
}

mod abi_audit;
mod attribute_classification;
#[cfg(unix)]
mod control_channel_live;
mod cross_abi;
mod cross_width_live;
mod init_args;
mod interface;
mod null_pointers;
mod output_semantics;
mod regression;
mod resource_limits;
mod retained_oracle_live;
mod wait_matrix;

fn empty_interface() -> CK_INTERFACE {
    CK_INTERFACE {
        pInterfaceName: std::ptr::null_mut(),
        pFunctionList: std::ptr::null_mut(),
        flags: 0,
    }
}

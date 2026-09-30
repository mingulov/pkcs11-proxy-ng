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
mod null_pointers;
#[cfg(not(miri))] // binds TcpListeners (tokio); covered natively
mod output_semantics;
#[cfg(not(miri))] // thread-scope + panic-join too slow under Miri (>90 s/test); covered natively
mod poison_recovery;
mod regression;
mod resource_limits;
#[cfg(not(miri))] // live oracle daemon; covered natively
mod retained_oracle_live;
#[cfg(not(miri))] // real SoftHSM2 provider + daemon; covered natively
mod softhsm_gcm;
#[cfg(not(miri))] // shared daemon fixture; covered natively
mod wait_matrix;

fn empty_interface() -> CK_INTERFACE {
    CK_INTERFACE {
        pInterfaceName: std::ptr::null_mut(),
        pFunctionList: std::ptr::null_mut(),
        flags: 0,
    }
}

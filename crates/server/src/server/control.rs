//! Hook-gated daemon control plane (C3M.6 row 18).
//!
//! Compiled only behind the `native-owner-test-hooks` feature (default
//! off) via `crate::server::control`. Lets subprocess/topology
//! fault-injection tests interrogate a RUNNING daemon: its instance
//! identity (telling restarts apart), the last mechanism bytes a native
//! owner received, and a close-fault injector. Same hand-rolled
//! HTTP/1.1-on-mode-0600-Unix-socket shape as the resilience metrics
//! endpoint; zero new deps.
//!
//! Routes (all local-only, authenticated by socket perms):
//! - `GET /hooks/instance` → `{"instance_id":N}`
//! - `GET /hooks/last-mechanism` → `{"seq":S,"mechanism":M,"parameter":"<hex>"}` or `{"none":true}`
//! - `POST /hooks/fail-next-close` → arms one injected close failure → `{"armed":true}`
//! - anything else → 404.

#[cfg(unix)]
mod endpoint;
#[cfg(unix)]
pub use endpoint::spawn_control_endpoint;

#[cfg(not(unix))]
pub async fn spawn_control_endpoint(_path: std::path::PathBuf) -> Result<(), String> {
    Err("test_hooks.control_socket requires Unix-domain socket support".to_string())
}

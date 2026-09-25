//! W1-L8-02: endpoint resolution must reject a malformed `tls://`
//! `PKCS11_PROXY_SOCKET` loudly instead of silently falling back to the
//! default plaintext endpoint.

use super::*;

/// Panic-safe save/restore for the endpoint env vars (mirrors the
/// `SavedConnectEnv` pattern in `interface.rs`, scoped to the vars these
/// tests mutate).
struct SavedEndpointEnv {
    endpoint: Option<String>,
    socket: Option<String>,
}

impl SavedEndpointEnv {
    fn capture() -> Self {
        Self {
            endpoint: std::env::var("PKCS11_PROXY_ENDPOINT").ok(),
            socket: std::env::var("PKCS11_PROXY_SOCKET").ok(),
        }
    }
}

impl Drop for SavedEndpointEnv {
    fn drop(&mut self) {
        unsafe {
            match &self.endpoint {
                Some(v) => std::env::set_var("PKCS11_PROXY_ENDPOINT", v),
                None => std::env::remove_var("PKCS11_PROXY_ENDPOINT"),
            }
            match &self.socket {
                Some(v) => std::env::set_var("PKCS11_PROXY_SOCKET", v),
                None => std::env::remove_var("PKCS11_PROXY_SOCKET"),
            }
        }
    }
}

fn set_socket_only(socket: &str) {
    unsafe {
        std::env::remove_var("PKCS11_PROXY_ENDPOINT");
        std::env::set_var("PKCS11_PROXY_SOCKET", socket);
    }
}

/// W1-L8-02: a `tls://` socket is a loud error — no connection string
/// is produced at all, so no fallback dial to the default plaintext
/// endpoint is possible. The message names the variable and the
/// offending value class. Failed before the fix (silent fall-through
/// to `http://127.0.0.1:7512`, connecting to the wrong daemon with no
/// TLS).
#[test]
fn tls_socket_is_rejected_loudly_with_no_fallback() {
    let _guard = shim_state_test_guard();
    let _saved = SavedEndpointEnv::capture();
    for socket in ["tls://daemon:7512", "tls://", "tls://daemon:7512/extra?query=1"] {
        set_socket_only(socket);
        let resolved = crate::state::resolve_endpoint_from_env();
        let err = resolved.expect_err(&format!(
            "W1-L8-02: PKCS11_PROXY_SOCKET={socket:?} must be rejected, not resolved"
        ));
        assert!(err.contains("PKCS11_PROXY_SOCKET"), "error must name the variable: {err}");
        assert!(err.contains("tls://"), "error must name the offending value class: {err}");
        assert!(
            !err.contains("http://127.0.0.1:7512"),
            "error must not smuggle in the default fallback: {err}"
        );
    }
}

/// All documented well-formed endpoint forms parse exactly as before
/// (guards the W1-L8-02 fix against changing them).
#[test]
fn well_formed_endpoints_parse_unchanged() {
    let _guard = shim_state_test_guard();
    let _saved = SavedEndpointEnv::capture();

    // Canonical endpoint passes through verbatim.
    for endpoint in ["http://daemon:7512", "https://daemon:7512", "http://127.0.0.1:7512"] {
        unsafe {
            std::env::set_var("PKCS11_PROXY_ENDPOINT", endpoint);
            std::env::remove_var("PKCS11_PROXY_SOCKET");
        }
        assert_eq!(crate::state::resolve_endpoint_from_env().as_deref(), Ok(endpoint));
    }

    // Legacy tcp:// socket translates to http://.
    unsafe {
        std::env::remove_var("PKCS11_PROXY_ENDPOINT");
        std::env::set_var("PKCS11_PROXY_SOCKET", "tcp://daemon:7512");
    }
    assert_eq!(crate::state::resolve_endpoint_from_env().as_deref(), Ok("http://daemon:7512"));

    // Endpoint wins when both are set.
    unsafe {
        std::env::set_var("PKCS11_PROXY_ENDPOINT", "https://daemon:7512");
        std::env::set_var("PKCS11_PROXY_SOCKET", "tcp://other:9999");
    }
    assert_eq!(crate::state::resolve_endpoint_from_env().as_deref(), Ok("https://daemon:7512"));

    // Nothing set: the documented default.
    unsafe {
        std::env::remove_var("PKCS11_PROXY_ENDPOINT");
        std::env::remove_var("PKCS11_PROXY_SOCKET");
    }
    assert_eq!(crate::state::resolve_endpoint_from_env().as_deref(), Ok("http://127.0.0.1:7512"));
}

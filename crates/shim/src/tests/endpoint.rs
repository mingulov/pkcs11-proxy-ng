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

/// Log capture for the redaction tests (mirrors the `CapturedWriter`
/// pattern in `interface.rs`).
#[derive(Clone, Default)]
struct CapturedWriter {
    buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl std::io::Write for CapturedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedWriter {
    type Writer = CapturedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture_logs(f: impl FnOnce()) -> String {
    let writer = CapturedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    String::from_utf8_lossy(&writer.buf.lock().unwrap()).to_string()
}

/// Resolver logs must redact socket userinfo: tcp translation, tls
/// rejection, and bad-scheme warnings all emitted raw socket values
/// (external review round 3; the exhausted-connect summary already
/// redacts at its choke point). The host stays visible for diagnosis.
#[test]
fn resolver_logs_redact_socket_userinfo() {
    let _guard = shim_state_test_guard();
    let _saved = SavedEndpointEnv::capture();
    for socket in [
        "tcp://review_user:R3_LEGACY_SECRET@daemon:7512",
        "tls://review_user:R3_TLS_SECRET@daemon:7512",
        "bad://review_user:R3_BAD_SECRET@daemon:7512",
        // A later "://" must not defeat scheme recognition (round 4).
        "tcp://review_user:R3_PATH_SECRET@daemon:7512/path://segment",
        "//review_user:R3_BAD2_SECRET@daemon:7512/path://segment",
        // Invalid but tonic-accepted schemes (round 5).
        "1http://review_user:R3_NUMSCHEME_SECRET@daemon:7512",
        "bad_scheme://review_user:R3_UNDERSCORE_SECRET@daemon:7512",
        // Schemeless with a later "://" (round 6).
        "review_user:R3_SCHEMELESS_PATH_SECRET@daemon:7512/path://segment",
        "review_user:R3_SCHEMELESS_QUERY_SECRET@daemon:7512?next=https://other.invalid/",
        // Credentials preceding "://" (round 7).
        "early_user:R3_EARLY_AT_SECRET@daemon:7512://segment",
    ] {
        set_socket_only(socket);
        let logs = capture_logs(|| {
            let _ = crate::state::resolve_endpoint_from_env();
        });
        for sentinel in [
            "R3_LEGACY_SECRET",
            "R3_TLS_SECRET",
            "R3_BAD_SECRET",
            "R3_PATH_SECRET",
            "R3_BAD2_SECRET",
            "R3_NUMSCHEME_SECRET",
            "R3_UNDERSCORE_SECRET",
            "R3_SCHEMELESS_PATH_SECRET",
            "R3_SCHEMELESS_QUERY_SECRET",
            "R3_EARLY_AT_SECRET",
            "review_user",
            "early_user",
        ] {
            assert!(
                !logs.contains(sentinel),
                "socket {socket:?} leaked {sentinel} into logs: {logs}"
            );
        }
        assert!(
            logs.contains("daemon:7512"),
            "socket {socket:?} must keep the host visible in logs: {logs}"
        );
    }
}

/// The tls-rejection error message redacts userinfo while still naming
/// the variable and the offending value class.
#[test]
fn tls_rejection_error_redacts_socket_userinfo() {
    let _guard = shim_state_test_guard();
    let _saved = SavedEndpointEnv::capture();
    set_socket_only("tls://review_user:R3_TLS_SECRET@daemon:7512");
    let err = crate::state::resolve_endpoint_from_env()
        .expect_err("tls:// socket must be rejected, not resolved");
    assert!(
        !err.contains("R3_TLS_SECRET") && !err.contains("review_user"),
        "rejection error must redact userinfo: {err}"
    );
    assert!(
        err.contains("PKCS11_PROXY_SOCKET") && err.contains("tls://"),
        "rejection error must still name the variable and value class: {err}"
    );
}

pub mod attestation;
pub mod audit;
pub mod auth;
pub mod context_manager;
#[cfg(feature = "native-owner-test-hooks")]
pub mod control;
pub mod grpc_service;
pub mod handle_map;
pub mod health;
pub mod rate_limit;
pub mod rate_quota;
pub mod resilience;
mod slot_map;
pub mod trace_id;
pub mod transport;

/// Whether the hook-gated daemon control plane is compiled in (C3M.6
/// row 18). Default-off; normal builds observe `false` here with no
/// control listener, no hook symbols, and a fail-closed startup error
/// if `[test_hooks]` is configured anyway.
pub const CONTROL_PLANE_ENABLED: bool = cfg!(feature = "native-owner-test-hooks");

/// Fail-closed validation for `[test_hooks]` (C3M.6 row 18): a configured
/// control socket without a hook-enabled build is a startup error, never
/// silently ignored. Hook builds honour the field.
pub fn validate_test_hooks_config(config: &crate::config::DaemonConfig) -> Result<(), String> {
    if config.test_hooks.control_socket.is_some() && !CONTROL_PLANE_ENABLED {
        return Err("test_hooks.control_socket is set but this daemon was built \
             without the `native-owner-test-hooks` feature; the hook-gated \
             control plane is absent. Rebuild with \
             `--features native-owner-test-hooks` or remove [test_hooks]"
            .into());
    }
    Ok(())
}

#[cfg(test)]
mod control_gate_tests {
    use super::*;

    fn parse_config(toml: &str) -> crate::config::DaemonConfig {
        toml::from_str(toml).expect("test config should parse")
    }

    const NO_HOOKS: &str = r#"
[backend]
module = "/dev/null"
"#;

    const WITH_HOOKS: &str = r#"
[backend]
module = "/dev/null"

[test_hooks]
control_socket = "/tmp/pkcs11-proxy-ng-test-hooks.sock"
"#;

    #[test]
    fn unset_control_socket_always_valid() {
        validate_test_hooks_config(&parse_config(NO_HOOKS)).expect("unset control socket is valid");
    }

    #[test]
    #[cfg(not(feature = "native-owner-test-hooks"))]
    #[allow(clippy::assertions_on_constants)]
    fn default_build_has_no_control_plane() {
        assert!(!CONTROL_PLANE_ENABLED);
        let err = validate_test_hooks_config(&parse_config(WITH_HOOKS)).unwrap_err().to_string();
        assert!(
            err.contains("native-owner-test-hooks"),
            "rejection must name the missing feature build: {err}"
        );
    }

    #[test]
    #[cfg(feature = "native-owner-test-hooks")]
    #[allow(clippy::assertions_on_constants)]
    fn hook_build_honours_control_socket() {
        assert!(CONTROL_PLANE_ENABLED);
        validate_test_hooks_config(&parse_config(WITH_HOOKS))
            .expect("hook builds honour a configured control socket");
    }
}

use super::*;

// NOTE (T2run win32): `module`/`ca_cert`/`server_cert`/`server_key` stubs
// below use `"."` (the test-process cwd, which always exists) rather than
// `/dev/null`, which does not exist on Windows and red-lined the win32
// lib suites (validation existence-checks these paths). Intent unchanged:
// every stub means "an existing path whose content is irrelevant here".

/// Verify that both resilience env vars introduced in the metrics-endpoint
/// feature appear in the help table. This test enforces the "keep in sync"
/// invariant stated at `apply_env_overrides` so that adding a new env var
/// without updating `env_var_help()` is caught immediately.
#[test]
fn env_var_help_contains_resilience_vars() {
    let help = env_var_help();
    assert!(
        help.contains("PKCS11_PROXY_RESILIENCE_METRICS_SOCKET"),
        "env_var_help must list PKCS11_PROXY_RESILIENCE_METRICS_SOCKET: {help}"
    );
    assert!(
        help.contains("PKCS11_PROXY_RESILIENCE_FIND_THRESHOLD"),
        "env_var_help must list PKCS11_PROXY_RESILIENCE_FIND_THRESHOLD: {help}"
    );
}

#[test]
fn parse_minimal_config() {
    let toml = r#"
[backend]
module = "."
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.backend.module.to_str().unwrap(), ".");
    assert!(config.backend.initialize_args.is_none());
    assert_eq!(config.proxy.mechanism_discovery, MechanismDiscovery::Transparent);
    assert_eq!(config.proxy.lease_seconds, 30);
    assert_eq!(config.proxy.eviction_interval_secs, 5);
    assert_eq!(config.proxy.max_contexts, 1000);
    assert_eq!(config.proxy.http2_keepalive_interval_secs, 15);
    assert_eq!(config.proxy.http2_keepalive_timeout_secs, 5);
}

#[test]
fn parse_full_config() {
    let toml = r#"
[backend]
module = "."
initialize_args = "configdir='sql:/tmp/nssdb' tokenDescription='test-token'"

[proxy]
mechanism_discovery = "transparent"
lease_seconds = 600

[listener.local]
path = "/tmp/pkcs11-proxy-ng.sock"
auth = "peer_cred"

[auth]
allow_all_authenticated = true
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.mechanism_discovery, MechanismDiscovery::Transparent);
    assert_eq!(config.proxy.lease_seconds, 600);
    assert_eq!(
        config.backend.initialize_args.as_deref(),
        Some("configdir='sql:/tmp/nssdb' tokenDescription='test-token'")
    );
    assert!(config.listener.local.is_some());
    assert!(config.auth.allow_all_authenticated);
}

#[test]
fn debug_redacts_sensitive_config_values() {
    let toml = r#"
[backend]
module = "."
initialize_args = "pin='SuperSecretInitArg' password='AnotherSecret'"

[listener.remote]
bind = "127.0.0.1:50051"
auth = "mtls"
ca_cert = "/tmp/ca.pem"
server_cert = "/tmp/cert.pem"
server_key = "/tmp/SuperSecretServerKey.pem"
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();

    let debug = format!("{config:?}");

    assert!(
        !debug.contains("SuperSecretInitArg"),
        "Debug output must not include backend initialize_args: {debug}"
    );
    assert!(
        !debug.contains("AnotherSecret"),
        "Debug output must not include backend initialize_args: {debug}"
    );
    assert!(
        !debug.contains("SuperSecretServerKey"),
        "Debug output must not include TLS server key paths: {debug}"
    );
    assert!(debug.contains("<redacted>"), "Debug output should show redaction markers: {debug}");
}

#[test]
fn validate_tcp_mtls_requires_certs() {
    let toml = r#"
[backend]
module = "."

[listener.remote]
bind = "0.0.0.0:50051"
auth = "mtls"
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("auth='mtls'"), "error should mention mTLS mode: {err}");
    assert!(err.contains("ca_cert"), "error should mention ca_cert: {err}");
    assert!(err.contains("server_cert"), "error should mention server_cert: {err}");
    assert!(err.contains("server_key"), "error should mention server_key: {err}");
}

#[test]
fn validate_tcp_insecure_requires_opt_in() {
    let toml = r#"
[backend]
module = "."

[listener.remote]
bind = "0.0.0.0:50051"
auth = "none"
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("auth='none'"), "error should mention disabled auth: {err}");
    assert!(
        err.contains("allow_insecure_tcp=true"),
        "error should mention explicit insecure TCP opt-in: {err}"
    );
}

#[test]
fn validate_unix_insecure_requires_opt_in() {
    let toml = r#"
[backend]
module = "."

[listener.local]
path = "/tmp/pkcs11-proxy-ng-test.sock"
auth = "none"
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("auth='none'"), "error should mention disabled auth: {err}");
    assert!(
        err.contains("allow_insecure_unix=true"),
        "error should mention explicit insecure Unix opt-in: {err}"
    );
}

#[test]
fn validate_unix_insecure_with_opt_in_accepted() {
    let toml = r#"
[backend]
module = "."

[listener.local]
path = "/tmp/pkcs11-proxy-ng-test.sock"
auth = "none"
allow_insecure_unix = true
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(config.validate().is_ok(), "explicit opt-in should validate");
}

#[test]
fn validate_invalid_mechanism_discovery() {
    let toml = r#"
[backend]
module = "."

[proxy]
mechanism_discovery = "bogus"
"#;
    let err = toml::from_str::<DaemonConfig>(toml).unwrap_err().to_string();
    assert!(err.contains("mechanism_discovery"), "error should mention field: {err}");
}

#[test]
fn validate_zero_lease_seconds_rejected() {
    let toml = r#"
[backend]
module = "."

[proxy]
lease_seconds = 0
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("lease_seconds"), "error should mention field: {err}");
}

#[test]
fn validate_missing_backend_module_rejected() {
    let toml = r#"
[backend]
module = "/nonexistent/path/to/module.so"
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("does not exist"), "error should mention missing file: {err}");
}

#[test]
fn load_missing_config_error_mentions_path() {
    let path = std::path::Path::new("/tmp/pkcs11-proxy-ng-missing-config-test.toml");

    let err = DaemonConfig::load(path).unwrap_err();

    assert!(
        err.contains(path.to_str().unwrap()),
        "error should include the config path operators supplied: {err}"
    );
}

#[test]
fn validate_transparent_discovery_accepted() {
    let toml = r#"
[backend]
module = "."

[proxy]
mechanism_discovery = "transparent"

[listener.local]
path = "/tmp/test.sock"
auth = "none"
allow_insecure_unix = true
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_no_listeners_rejected() {
    let toml = r#"
[backend]
module = "."
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("No listeners"), "error should mention missing listeners: {err}");
}

#[test]
fn validate_invalid_unix_auth_rejected() {
    let toml = r#"
[backend]
module = "."

[listener.local]
path = "/tmp/test.sock"
auth = "magic"
"#;
    let err = toml::from_str::<DaemonConfig>(toml).unwrap_err().to_string();
    assert!(err.contains("unknown variant `magic`"), "error should mention variant: {err}");
    assert!(err.contains("peer_cred"), "error should mention expected variants: {err}");
}

#[test]
fn validate_invalid_tcp_auth_rejected() {
    let toml = r#"
[backend]
module = "."

[listener.remote]
bind = "0.0.0.0:50051"
auth = "kerberos"
"#;
    let err = toml::from_str::<DaemonConfig>(toml).unwrap_err().to_string();
    assert!(err.contains("unknown variant `kerberos`"), "error should mention variant: {err}");
    assert!(err.contains("mtls"), "error should mention expected variants: {err}");
}

#[test]
fn validate_tcp_bind_requires_port() {
    let toml = r#"
[backend]
module = "."

[listener.remote]
bind = "localhost"
auth = "none"
allow_insecure_tcp = true
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("host:port"), "error should mention format: {err}");
}

#[test]
fn validate_mtls_cert_files_must_exist() {
    let toml = r#"
[backend]
module = "."

[listener.remote]
bind = "0.0.0.0:50051"
auth = "mtls"
ca_cert = "/nonexistent/ca.pem"
server_cert = "/nonexistent/cert.pem"
server_key = "/nonexistent/key.pem"
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("does not exist"), "error should mention missing file: {err}");
}

#[test]
fn validate_unix_peer_cred_accepted() {
    let toml = r#"
[backend]
module = "."

[listener.local]
path = "/tmp/test.sock"
auth = "peer_cred"

[auth]
allow_all_authenticated = true
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_policy_rejects_non_all_scalar_tokens() {
    let toml = r#"
[backend]
module = "."

[listener.local]
path = "/tmp/test.sock"
auth = "peer_cred"

[auth]
allow_all_authenticated = false

[[auth.policy]]
identity = "uid=1000"
tokens = "label:app-signing"
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("tokens"), "error should mention tokens field: {err}");
    assert!(err.contains("all"), "error should mention the all-token keyword: {err}");
}

#[test]
fn validate_policy_rejects_invalid_selector_array() {
    let toml = r#"
[backend]
module = "."

[listener.local]
path = "/tmp/test.sock"
auth = "peer_cred"

[auth]
allow_all_authenticated = false

[[auth.policy]]
identity = "uid=1000"
tokens = ["lable:app-signing"]
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("invalid selector"), "error should mention invalid selector: {err}");
    assert!(err.contains("lable:app-signing"), "error should include selector value: {err}");
}

#[test]
fn validate_mtls_policy_identity_must_use_x509_key() {
    let toml = r#"
[backend]
module = "."

[listener.remote]
bind = "0.0.0.0:50051"
auth = "mtls"
ca_cert = "."
server_cert = "."
server_key = "."

[auth]
allow_all_authenticated = false

[[auth.policy]]
identity = "CN=app-service,O=Example Corp"
tokens = ["label:app-signing"]
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("auth.policy[0].identity"), "error should name field: {err}");
    assert!(err.contains("CN=app-service,O=Example Corp"), "error should include identity: {err}");
    assert!(err.contains("listener.remote.auth = 'mtls'"), "error should mention mtls mode: {err}");
    assert!(err.contains("x509:issuer="), "error should show expected x509 format: {err}");
}

#[test]
fn validate_peer_cred_policy_identity_must_use_uid_key() {
    let toml = r#"
[backend]
module = "."

[listener.local]
path = "/tmp/test.sock"
auth = "peer_cred"

[auth]
allow_all_authenticated = false

[[auth.policy]]
identity = "x509:issuer=CN=Root;subject=CN=client"
tokens = ["label:app-signing"]
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("auth.policy[0].identity"), "error should name field: {err}");
    assert!(
        err.contains("x509:issuer=CN=Root;subject=CN=client"),
        "error should include identity: {err}"
    );
    assert!(
        err.contains("listener.local.auth = 'peer_cred'"),
        "error should mention peer_cred mode: {err}"
    );
    assert!(err.contains("uid="), "error should show expected uid format: {err}");
}

#[test]
fn validate_policy_identity_can_match_any_configured_authenticated_listener() {
    let toml = r#"
[backend]
module = "."

[listener.local]
path = "/tmp/test.sock"
auth = "peer_cred"

[listener.remote]
bind = "0.0.0.0:50051"
auth = "mtls"
ca_cert = "."
server_cert = "."
server_key = "."

[auth]
allow_all_authenticated = false

[[auth.policy]]
identity = "uid=1000"
tokens = ["label:local-token"]

[[auth.policy]]
identity = "x509:issuer=CN=Root;subject=CN=client"
tokens = ["label:remote-token"]
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_policy_entries_require_authenticated_listener() {
    let toml = r#"
[backend]
module = "."

[listener.remote]
bind = "127.0.0.1:50051"
auth = "none"
allow_insecure_tcp = true

[auth]
allow_all_authenticated = false

[[auth.policy]]
identity = "uid=1000"
tokens = ["label:local-token"]
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    // The policy+unauthenticated check fires before validate_policy_identities,
    // giving a dedicated startup-refusal message.
    assert!(
        err.contains("[auth.policy]") || err.contains("auth.policy"),
        "error should explain policy cannot apply: {err}"
    );
    assert!(
        err.contains("unauthenticated") || err.to_lowercase().contains("auth = \"none\""),
        "error should mention unauthenticated access: {err}"
    );
}

#[test]
fn validate_unix_none_auth_accepted() {
    let toml = r#"
[backend]
module = "."

[listener.local]
path = "/tmp/test.sock"
auth = "none"
allow_insecure_unix = true
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn default_max_message_bytes() {
    let toml = r#"
[backend]
module = "."
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.max_message_bytes, 4 * 1024 * 1024);
}

#[test]
fn default_request_timeout_secs() {
    let toml = r#"
[backend]
module = "."
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.request_timeout_secs, 60);
}

#[test]
fn custom_max_message_bytes() {
    let toml = r#"
[backend]
module = "."

[proxy]
max_message_bytes = 1048576
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.max_message_bytes, 1_048_576);
}

#[test]
fn custom_request_timeout_secs() {
    let toml = r#"
[backend]
module = "."

[proxy]
request_timeout_secs = 60
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.request_timeout_secs, 60);
}

#[test]
fn validate_zero_max_message_bytes_rejected() {
    let toml = r#"
[backend]
module = "."

[proxy]
max_message_bytes = 0
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_message_bytes"), "error: {err}");
}

#[test]
fn validate_huge_max_message_bytes_rejected() {
    let toml = r#"
[backend]
module = "."

[proxy]
max_message_bytes = 100000000
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_message_bytes"), "error: {err}");
}

#[test]
fn validate_max_message_bytes_at_limit_accepted() {
    let toml = r#"
[backend]
module = "."

[proxy]
max_message_bytes = 67108864

[listener.local]
path = "/tmp/test.sock"
auth = "none"
allow_insecure_unix = true
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_zero_request_timeout_rejected() {
    let toml = r#"
[backend]
module = "."

[proxy]
request_timeout_secs = 0
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("request_timeout_secs"), "error: {err}");
}

#[test]
fn default_max_concurrent_backend_calls() {
    let toml = r#"
[backend]
module = "."
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.max_concurrent_backend_calls, 200);
}

#[test]
fn custom_max_concurrent_backend_calls() {
    let toml = r#"
[backend]
module = "."

[proxy]
max_concurrent_backend_calls = 20
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.max_concurrent_backend_calls, 20);
}

#[test]
fn validate_zero_max_concurrent_backend_calls_rejected() {
    let toml = r#"
[backend]
module = "."

[proxy]
max_concurrent_backend_calls = 0
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_concurrent_backend_calls"), "error: {err}");
}

#[test]
fn validate_max_concurrent_backend_calls_must_not_exceed_max_blocking_threads() {
    // A config in which the circuit-breaker limit is allowed
    // to exceed the tokio blocking-pool size could deadlock the
    // daemon — every blocking thread holds a backend call that's
    // waiting for some resource only released by another backend
    // call we no longer have threads to schedule. The validation
    // catches this at startup so it never reaches production.
    let toml = r#"
[backend]
module = "."

[proxy]
max_concurrent_backend_calls = 200
max_blocking_threads = 100
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("max_concurrent_backend_calls") && err.contains("max_blocking_threads"),
        "error must mention both knobs: {err}"
    );
}

#[test]
fn validate_zero_eviction_interval_secs_rejected() {
    let toml = r#"
[backend]
module = "."

[proxy]
eviction_interval_secs = 0
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("eviction_interval_secs"), "error: {err}");
}

#[test]
fn default_eviction_and_keepalive_fields() {
    let toml = r#"
[backend]
module = "."
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.eviction_interval_secs, 5);
    assert_eq!(config.proxy.max_contexts, 1000);
    assert_eq!(config.proxy.http2_keepalive_interval_secs, 15);
    assert_eq!(config.proxy.http2_keepalive_timeout_secs, 5);
}

#[test]
fn max_stuck_backend_calls_defaults_to_none() {
    let toml = r#"
[backend]
module = "."
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.max_stuck_backend_calls, None);
}

#[test]
fn max_stuck_backend_calls_parses_when_set() {
    let toml = r#"
[backend]
module = "."

[proxy]
max_stuck_backend_calls = 16

[listener.remote]
bind = "127.0.0.1:7512"
auth = "none"
allow_insecure_tcp = true
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.max_stuck_backend_calls, Some(16));
    config.validate().expect("positive limit is valid");
}

#[test]
fn max_stuck_backend_calls_zero_is_rejected() {
    let toml = r#"
[backend]
module = "."

[proxy]
max_stuck_backend_calls = 0
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_stuck_backend_calls"), "{err}");
}

#[test]
fn should_exit_on_stuck_calls_policy() {
    // Disabled: never exit.
    assert!(!should_exit_on_stuck_calls(0, None));
    assert!(!should_exit_on_stuck_calls(1_000_000, None));
    // Enabled: exit strictly above the limit.
    assert!(!should_exit_on_stuck_calls(3, Some(3)));
    assert!(should_exit_on_stuck_calls(4, Some(3)));
    assert!(!should_exit_on_stuck_calls(0, Some(1)));
}

#[test]
fn resilience_absent_defaults_to_inert() {
    let toml = "[backend]\nmodule = \".\"\n";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(cfg.resilience.find_result_warn_threshold.is_none());
    assert!(cfg.resilience.metrics_socket.is_none());
}

#[test]
fn resilience_section_parses() {
    let toml = "\
[backend]
module = \".\"
[resilience]
find_result_warn_threshold = 500
metrics_socket = \"/run/pkcs11-proxy/metrics.sock\"
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.resilience.find_result_warn_threshold, Some(500));
    assert_eq!(
        cfg.resilience.metrics_socket.as_deref(),
        Some(std::path::Path::new("/run/pkcs11-proxy/metrics.sock"))
    );
}

#[test]
fn test_hooks_absent_defaults_to_inert() {
    let toml = "[backend]\nmodule = \".\"\n";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(cfg.test_hooks.control_socket.is_none());
}

#[test]
fn test_hooks_section_parses() {
    let toml = "\
[backend]
module = \".\"
[test_hooks]
control_socket = \"/run/pkcs11-proxy/control.sock\"
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(
        cfg.test_hooks.control_socket.as_deref(),
        Some(std::path::Path::new("/run/pkcs11-proxy/control.sock"))
    );
}

#[test]
fn audit_absent_defaults_to_off() {
    let cfg: DaemonConfig = toml::from_str("[backend]\nmodule = \".\"\n").unwrap();
    assert!(cfg.audit.dir.is_none());
    assert!(cfg.audit.signing_key.is_none());
    assert_eq!(cfg.audit.rotate_max_bytes, 64 * 1024 * 1024);
    assert_eq!(cfg.audit.rotate_keep_files, 10);
}

#[test]
fn audit_section_parses() {
    let toml = "\
[backend]
module = \".\"
[audit]
dir = \"/var/log/pkcs11-proxy/audit\"
signing_key = \"/etc/pkcs11-proxy/audit-ed25519.key\"
rotate_max_bytes = 1048576
rotate_keep_files = 3
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.audit.dir.as_deref(), Some(std::path::Path::new("/var/log/pkcs11-proxy/audit")));
    assert_eq!(cfg.audit.rotate_max_bytes, 1_048_576);
    assert_eq!(cfg.audit.rotate_keep_files, 3);
}

#[test]
fn policy_with_unauthenticated_listener_is_rejected() {
    // A policy entry + a local listener with auth = "none" must refuse to start:
    // an authorization policy cannot meaningfully apply to an unauthenticated peer.
    let toml = "\
[backend]
module = \".\"
[[auth.policy]]
identity = \"uid=1000\"
tokens = \"all\"
[listener.local]
path = \"/run/p.sock\"
auth = \"none\"
allow_insecure_unix = true
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("auth") && err.to_lowercase().contains("policy"), "got: {err}");
}

#[test]
fn policy_with_authenticated_listener_is_allowed() {
    // peer_cred is an authenticated mode; uid= identities match peer_cred.
    let toml = "\
[backend]
module = \".\"
[[auth.policy]]
identity = \"uid=1000\"
tokens = \"all\"
[listener.local]
path = \"/run/p.sock\"
auth = \"peer_cred\"
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(cfg.validate().is_ok());
}

#[test]
#[cfg(unix)]
fn check_not_group_or_world_writable_enforces_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let path = std::path::PathBuf::from(format!(
        "/tmp/pkcs11-proxy-ng-perm-test-{}.tmp",
        std::process::id()
    ));
    std::fs::write(&path, b"test").expect("write temp file");
    // Group+world writable (mode 0662) must be rejected.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o662)).expect("chmod 0662");
    let err = check_not_group_or_world_writable(&path, "test file").unwrap_err();
    assert!(err.contains("group/world-writable"), "got: {err}");
    assert!(err.contains("chmod go-w"), "got: {err}");
    // Mode 0644 (not writable by group/world) must be accepted.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 0644");
    assert!(check_not_group_or_world_writable(&path, "test file").is_ok());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn login_lock_timeout_secs_defaults_to_10() {
    let toml = "[backend]\nmodule = \".\"\n";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.proxy.login_lock_timeout_secs, 10);
}

#[test]
fn allow_all_authenticated_with_unauthenticated_listener_is_rejected() {
    // H1: allow_all_authenticated=true + auth="none" listener must refuse to start.
    // TokenPolicy::allows short-circuits to true for any identity including
    // Unauthenticated, so this combo blanket-authorizes no-auth peers.
    let toml = "\
[backend]
module = \".\"
[auth]
allow_all_authenticated = true
[listener.local]
path = \"/run/p.sock\"
auth = \"none\"
allow_insecure_unix = true
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("allow_all_authenticated"),
        "error must mention allow_all_authenticated, got: {err}"
    );
}

#[test]
fn audit_with_unauthenticated_listener_is_rejected() {
    // H2: [audit] dir + auth="none" listener must refuse to start.
    // Every operation would be recorded with identity=None, giving false
    // compliance assurance.
    let toml = "\
[backend]
module = \".\"
[audit]
dir = \"/var/log/pkcs11-proxy/audit\"
[listener.local]
path = \"/run/p.sock\"
auth = \"none\"
allow_insecure_unix = true
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("audit"), "error must mention audit, got: {err}");
}

#[test]
fn audit_with_authenticated_listener_is_allowed() {
    // Positive control: [audit] + peer_cred listener is a valid config.
    let toml = "\
[backend]
module = \".\"
[audit]
dir = \"/var/log/pkcs11-proxy/audit\"
[auth]
allow_all_authenticated = true
[listener.local]
path = \"/run/p.sock\"
auth = \"peer_cred\"
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(cfg.validate().is_ok());
}

// --- G2-PR2: anonymous_principal config tests ---

#[test]
fn anonymous_principal_parses() {
    let toml = "\
[backend]
module = \".\"
[auth]
anonymous_principal = \"anon-client\"
[listener.local]
path = \"/run/p.sock\"
auth = \"none\"
allow_insecure_unix = true
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.auth.anonymous_principal.as_deref(), Some("anon-client"));
}

#[test]
fn anonymous_principal_absent_defaults_to_none() {
    let cfg: DaemonConfig = toml::from_str("[backend]\nmodule = \".\"\n").unwrap();
    assert!(cfg.auth.anonymous_principal.is_none());
}

#[test]
fn anonymous_principal_also_in_policy_is_rejected() {
    // anonymous_principal is audit-only; it must not also appear as a grant key.
    let toml = "\
[backend]
module = \".\"
[auth]
anonymous_principal = \"uid=1000\"
[[auth.policy]]
identity = \"uid=1000\"
tokens = \"all\"
[listener.local]
path = \"/run/p.sock\"
auth = \"peer_cred\"
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("anonymous_principal") && err.contains("uid=1000"),
        "error must mention anonymous_principal and the conflicting identity, got: {err}"
    );
}

#[test]
fn audit_with_unauthenticated_listener_and_anonymous_principal_is_allowed() {
    // H2 guard is RELAXED when anonymous_principal is set: the operator has named
    // the audit identity for unauthenticated peers, so the compliance gap is addressed.
    let toml = "\
[backend]
module = \".\"
[audit]
dir = \"/var/log/pkcs11-proxy/audit\"
[auth]
anonymous_principal = \"anon-client\"
[listener.local]
path = \"/run/p.sock\"
auth = \"none\"
allow_insecure_unix = true
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(
        cfg.validate().is_ok(),
        "audit + auth=none + anonymous_principal must be allowed (H2 guard relaxed)"
    );
}

// --- G3 Task 1: per-class grants now accepted; per-mechanism still rejected ---

#[test]
fn validate_accepts_grant_with_classes_field() {
    // Classes enforcement is now wired (G3 Task 1). A rich grant with `classes`
    // must be accepted by validate() — operators can now safely restrict by class.
    let toml = "\
[backend]
module = \".\"
[listener.local]
path = \"/tmp/test.sock\"
auth = \"peer_cred\"
[auth]
allow_all_authenticated = false
[[auth.policy]]
identity = \"uid=1000\"
tokens = [{ token = \"label:MyToken\", classes = [\"secret_key\"], extract = \"deny\" }]
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(
        cfg.validate().is_ok(),
        "grant with classes field must be accepted now that per-class enforcement is wired"
    );
}

#[test]
fn validate_accepts_grant_with_mechanisms_field() {
    // A rich grant with `mechanisms` set is now fully enforced at every
    // crypto-init RPC (G3 Task 3). Validate must accept it.
    let toml = "\
[backend]
module = \".\"
[listener.local]
path = \"/tmp/test.sock\"
auth = \"peer_cred\"
[auth]
allow_all_authenticated = false
[[auth.policy]]
identity = \"uid=1000\"
tokens = [{ token = \"label:MyToken\", mechanisms = [\"CKM_AES_GCM\"] }]
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(
        cfg.validate().is_ok(),
        "rich grant with mechanisms field must now validate successfully (G3 Task 3 enforcement wired)"
    );
}

#[test]
fn validate_accepts_rich_grant_with_extract_deny_only() {
    // A rich grant that uses only `extract = "deny"` (no classes/mechanisms)
    // is fully enforced today and must pass validate().
    let toml = "\
[backend]
module = \".\"
[listener.local]
path = \"/tmp/test.sock\"
auth = \"peer_cred\"
[auth]
allow_all_authenticated = false
[[auth.policy]]
identity = \"uid=1000\"
tokens = [{ token = \"label:MyToken\", extract = \"deny\" }]
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(cfg.validate().is_ok(), "rich grant with extract=deny only must validate successfully");
}

#[test]
fn validate_accepts_rich_grant_with_objects_field() {
    // A rich grant with `objects` set is the G3 per-object allow-list feature.
    // Unlike classes/mechanisms (blocked by the I2 guard until Task 3 enforcement
    // is wired), objects has a functional allows_object_use() policy method and
    // must NOT be rejected at validate().
    let toml = "\
[backend]
module = \".\"
[listener.local]
path = \"/tmp/test.sock\"
auth = \"peer_cred\"
[auth]
allow_all_authenticated = false
[[auth.policy]]
identity = \"uid=1000\"
tokens = [{ token = \"label:MyToken\", objects = [\"a1b2\"] }]
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(cfg.validate().is_ok(), "rich grant with objects field must validate successfully");
}

#[test]
fn validate_rejects_rich_grant_with_objects_bad_hex() {
    // Malformed hex in the objects list must produce an Err at validate() time.
    let toml = "\
[backend]
module = \".\"
[listener.local]
path = \"/tmp/test.sock\"
auth = \"peer_cred\"
[auth]
allow_all_authenticated = false
[[auth.policy]]
identity = \"uid=1000\"
tokens = [{ token = \"label:MyToken\", objects = [\"xyz\"] }]
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("xyz"), "error must name the bad hex value: {err}");
}

#[test]
fn audit_with_unauthenticated_listener_without_anonymous_principal_is_rejected() {
    // H2 guard: audit + auth=none WITHOUT anonymous_principal still refused.
    // (The existing `audit_with_unauthenticated_listener_is_rejected` test covers
    // the same code path; this test names the negative case explicitly for clarity.)
    let toml = "\
[backend]
module = \".\"
[audit]
dir = \"/var/log/pkcs11-proxy/audit\"
[listener.local]
path = \"/run/p.sock\"
auth = \"none\"
allow_insecure_unix = true
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("audit"), "error must mention audit, got: {err}");
}

// --- G2-PR3: rate_limit Some(0) footgun tests ---

/// Helper that builds a minimal valid config string with an optional `[rate_limit]` block
/// and an insecure unix listener (so everything except the tested field validates).
fn rate_limit_toml(rate_limit_block: &str) -> String {
    format!(
        "\
[backend]
module = \".\"
[listener.local]
path = \"/tmp/test.sock\"
auth = \"none\"
allow_insecure_unix = true
{rate_limit_block}"
    )
}

#[test]
fn rate_limit_per_principal_max_in_flight_zero_is_rejected() {
    let toml = rate_limit_toml("[rate_limit]\nper_principal_max_in_flight = 0\n");
    let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("per_principal_max_in_flight"), "error must name the field, got: {err}");
    assert!(err.contains("> 0"), "error must say must be > 0, got: {err}");
}

#[test]
fn rate_limit_per_principal_max_sessions_zero_is_rejected() {
    let toml = rate_limit_toml("[rate_limit]\nper_principal_max_sessions = 0\n");
    let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("per_principal_max_sessions"), "error must name the field, got: {err}");
    assert!(err.contains("> 0"), "error must say must be > 0, got: {err}");
}

#[test]
fn rate_limit_per_slot_failed_login_budget_zero_is_rejected() {
    let toml = rate_limit_toml("[rate_limit]\nper_slot_failed_login_budget = 0\n");
    let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("per_slot_failed_login_budget"), "error must name the field, got: {err}");
    assert!(err.contains("> 0"), "error must say must be > 0, got: {err}");
}

// W1-C3-21: per_slot_failed_login_cooldown_secs=Some(0) arms an
// already-expired lockout, silently neutering the failed-login budget —
// reject it like the other three rate_limit fields. (Pin: the validate()
// rejection predates this task via Task 9 W1-L8-16; the regression test
// was missing.)
#[test]
fn rate_limit_per_slot_failed_login_cooldown_zero_is_rejected() {
    let toml = rate_limit_toml("[rate_limit]\nper_slot_failed_login_cooldown_secs = 0\n");
    let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("per_slot_failed_login_cooldown_secs"),
        "error must name the field, got: {err}"
    );
    assert!(err.contains("> 0"), "error must say must be > 0, got: {err}");
}

#[test]
fn rate_limit_per_slot_failed_login_cooldown_nonzero_validates_ok() {
    let toml = rate_limit_toml("[rate_limit]\nper_slot_failed_login_cooldown_secs = 5\n");
    let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
    assert!(cfg.validate().is_ok(), "positive cooldown must validate OK");
    assert_eq!(cfg.rate_limit.per_slot_failed_login_cooldown_secs, Some(5));
}

#[test]
fn rate_limit_absent_fields_validate_ok() {
    // All rate_limit fields absent (None) is the opt-out default; must be valid.
    let toml = rate_limit_toml("");
    let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
    assert!(cfg.validate().is_ok(), "absent rate_limit fields must validate OK");
    assert!(cfg.rate_limit.per_principal_max_in_flight.is_none());
    assert!(cfg.rate_limit.per_principal_max_sessions.is_none());
    assert!(cfg.rate_limit.per_slot_failed_login_budget.is_none());
}

#[test]
fn rate_limit_some_nonzero_fields_validate_ok() {
    // Some(5) for each field is a valid positive limit.
    let toml = rate_limit_toml(
        "[rate_limit]\nper_principal_max_in_flight = 5\nper_principal_max_sessions = 5\nper_slot_failed_login_budget = 5\n",
    );
    let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
    assert!(cfg.validate().is_ok(), "positive rate_limit fields must validate OK");
    assert_eq!(cfg.rate_limit.per_principal_max_in_flight, Some(5));
    assert_eq!(cfg.rate_limit.per_principal_max_sessions, Some(5));
    assert_eq!(cfg.rate_limit.per_slot_failed_login_budget, Some(5));
}

// ---------------------------------------------------------------------------
// M3: `objects` grant + auth="none" listener must be rejected at startup
// ---------------------------------------------------------------------------

#[test]
fn objects_grant_with_unauthenticated_listener_is_rejected() {
    // M3: allows_object_use() returns true for Unauthenticated, so an `objects`
    // grant combined with auth="none" is silently inert (false security).
    // The daemon must refuse to start.
    let toml = "\
[backend]
module = \".\"
[listener.local]
path = \"/run/p.sock\"
auth = \"none\"
allow_insecure_unix = true
[auth]
allow_all_authenticated = false
[[auth.policy]]
identity = \"uid=1000\"
tokens = [{ token = \"label:MyToken\", objects = [\"aabbcc\"] }]
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("objects") || err.contains("auth"),
        "error must mention 'objects' or 'auth', got: {err}"
    );
}

#[test]
fn objects_grant_with_authenticated_listener_accepted() {
    // M3 positive case: per-object grant + peer_cred auth must be accepted.
    let toml = "\
[backend]
module = \".\"
[listener.local]
path = \"/run/p.sock\"
auth = \"peer_cred\"
[auth]
allow_all_authenticated = false
[[auth.policy]]
identity = \"uid=1000\"
tokens = [{ token = \"label:MyToken\", objects = [\"aabbcc\"] }]
";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(cfg.validate().is_ok(), "objects grant + peer_cred must be accepted");
}

// ---------------------------------------------------------------------------
// FIX #1: AuditConfig::validate() wired into DaemonConfig::validate()
// ---------------------------------------------------------------------------

/// Helper: minimal valid DaemonConfig string with an insecure unix listener so
/// all other fields pass — only the [audit] block is varied by the caller.
fn audit_validate_toml(audit_block: &str) -> String {
    format!(
        "\
[backend]
module = \".\"
[listener.local]
path = \"/tmp/test.sock\"
auth = \"none\"
allow_insecure_unix = true
{audit_block}"
    )
}

#[test]
fn daemon_validate_rejects_audit_channel_capacity_zero() {
    // channel_capacity = 0 panics at runtime (tokio channel(0) panics);
    // DaemonConfig::validate() must catch it before startup.
    // No `dir` here: audit.validate() runs unconditionally regardless of dir;
    // omitting dir avoids the H2 guard (audit+auth=none without anonymous_principal)
    // which would fire first and mask the channel_capacity error.
    let toml = audit_validate_toml("[audit]\nchannel_capacity = 0\n");
    let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("channel_capacity"), "error must mention channel_capacity, got: {err}");
    assert!(err.contains("> 0"), "error must say must be > 0, got: {err}");
}

#[test]
fn daemon_validate_rejects_fail_closed_reserve_ge_channel_capacity() {
    // fail_closed_reserve >= channel_capacity means 100% of data-plane records
    // would be silently dropped; DaemonConfig::validate() must refuse to start.
    // No `dir`: avoids H2 guard masking the error (see above).
    let toml = audit_validate_toml("[audit]\nchannel_capacity = 10\nfail_closed_reserve = 10\n");
    let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("fail_closed_reserve"),
        "error must mention fail_closed_reserve, got: {err}"
    );
    assert!(err.contains("channel_capacity"), "error must mention channel_capacity, got: {err}");
}

#[test]
fn daemon_validate_accepts_audit_defaults() {
    // The shipped defaults (channel_capacity=4096, fail_closed_reserve=256)
    // must pass DaemonConfig::validate() without error.
    // No `dir`: avoids H2 guard (see above); the invariant checks are on the
    // capacity/reserve fields which are validated regardless of whether dir is set.
    let toml = audit_validate_toml("[audit]\n");
    let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
    assert_eq!(cfg.audit.channel_capacity, 4096);
    assert_eq!(cfg.audit.fail_closed_reserve, 256);
    assert!(cfg.validate().is_ok(), "audit defaults must validate OK");
}

// W1-L8-01: the documented env mapping promises PKCS11_PROXY_ALLOW_INSECURE
// overrides `listener.remote.allow_insecure_tcp` (env > TOML), including
// when the TOML already carries a [listener.remote] block (the `Some`
// branch of `apply_env_overrides`).
//
// Hermetic by construction: the fake env below never touches the process
// environment, so this test cannot race parallel tests in the same binary
// that call `load()` (e.g. the example-config consistency test).
fn fake_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: std::collections::HashMap<String, String> =
        pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect();
    move |key: &str| map.get(key).cloned()
}

#[test]
fn allow_insecure_env_overrides_existing_remote_block() {
    let toml = r#"
[backend]
module = "."

[proxy]

[listener.remote]
bind = "127.0.0.1:7512"
auth = "none"
allow_insecure_tcp = false
"#;
    // Env set: the override must be honored in the `Some` branch.
    let mut config: DaemonConfig = toml::from_str(toml).unwrap();
    config
        .apply_env_overrides_with(fake_env(&[
            ("PKCS11_PROXY_BIND", "0.0.0.0:9999"),
            ("PKCS11_PROXY_ALLOW_INSECURE", "1"),
        ]))
        .expect("overrides must apply");
    let tcp = config.listener.remote.as_ref().unwrap();
    assert_eq!(tcp.bind, "0.0.0.0:9999");
    assert!(
        tcp.allow_insecure_tcp,
        "PKCS11_PROXY_ALLOW_INSECURE=1 must override TOML allow_insecure_tcp=false (W1-L8-01)"
    );
    // Env set to a falsy value: env still wins (secure direction).
    let toml_true = toml.replace("allow_insecure_tcp = false", "allow_insecure_tcp = true");
    let mut config: DaemonConfig = toml::from_str(&toml_true).unwrap();
    config
        .apply_env_overrides_with(fake_env(&[
            ("PKCS11_PROXY_BIND", "0.0.0.0:9999"),
            ("PKCS11_PROXY_ALLOW_INSECURE", "0"),
        ]))
        .expect("overrides must apply");
    assert!(
        !config.listener.remote.as_ref().unwrap().allow_insecure_tcp,
        "PKCS11_PROXY_ALLOW_INSECURE=0 must override TOML allow_insecure_tcp=true"
    );
    // Env unset: the TOML value must be preserved — no insecure default.
    let mut config: DaemonConfig = toml::from_str(toml).unwrap();
    config
        .apply_env_overrides_with(fake_env(&[("PKCS11_PROXY_BIND", "0.0.0.0:9999")]))
        .expect("overrides must apply");
    let tcp = config.listener.remote.as_ref().unwrap();
    assert_eq!(tcp.bind, "0.0.0.0:9999");
    assert!(
        !tcp.allow_insecure_tcp,
        "unset PKCS11_PROXY_ALLOW_INSECURE must leave TOML allow_insecure_tcp=false untouched"
    );
}

// W1-L8-05: rich-grant tables must reject unknown keys loudly. A typo like
// `extrat = "deny"` was silently ignored while `extract` fell back to its
// `Allow` default — permitting key extraction the operator believed denied.
#[test]
fn rich_grant_typo_rejected_loudly_naming_key() {
    let toml = r#"
[backend]
module = "."

[listener.local]
path = "/tmp/test.sock"
auth = "peer_cred"

[auth]
allow_all_authenticated = false

[[auth.policy]]
identity = "uid=1000"
tokens = [{ token = "label:MyToken", extrat = "deny" }]
"#;
    let err = toml::from_str::<DaemonConfig>(toml).unwrap_err().to_string();
    assert!(
        err.contains("extrat"),
        "typo'd grant key must be named loudly in the parse error (no silent Allow fallback): {err}"
    );
}

// W1-L8-05 (same finding, objects allow-list): a typo in a rich
// `{ id, extract }` entry must also fail loudly, not inherit silently.
#[test]
fn object_acl_rich_typo_rejected_loudly_naming_key() {
    let toml = r#"
[backend]
module = "."

[listener.local]
path = "/tmp/test.sock"
auth = "peer_cred"

[auth]
allow_all_authenticated = false

[[auth.policy]]
identity = "uid=1000"
tokens = [{ token = "label:MyToken", objects = [{ id = "a1b2", extrac = "deny" }] }]
"#;
    let err = toml::from_str::<DaemonConfig>(toml).unwrap_err().to_string();
    assert!(
        err.contains("extrac"),
        "typo'd objects key must be named loudly in the parse error: {err}"
    );
}

// W1-L8-05: every example daemon config in the repo must still parse after
// deny_unknown_fields lands on the grant tables. Parse-only (not
// validate/load): placeholders like /CHANGE_ME and @BACKEND_MODULE@ are
// intentionally not real paths.
#[test]
fn all_example_daemon_configs_still_parse() {
    use std::collections::BTreeSet;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // Pinned inventory of every daemon-config TOML in the repo. Mechanism
    // registries (examples/cloudhsm-mechanisms.toml, fips/mechanism_params.toml,
    // examples/vendors/*.toml, packaging mechanism examples) are NOT daemon
    // configs and are excluded.
    let pinned: &[&str] = &[
        "examples/config-loopback-dev.toml",
        "examples/config-mtls.toml",
        "examples/config-multi-user.toml",
        "examples/config-unix-local.toml",
        "examples/configs/dev/proxy.toml",
        "examples/configs/staging/proxy.toml",
        "examples/configs/prod/proxy.toml",
        "examples/configs/fips/proxy.toml",
        "packaging/config/proxy.toml.default",
        "tests/consumers/proxy.toml",
    ];
    for rel in pinned {
        let path = root.join(rel);
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read pinned example config {rel}: {e}"));
        toml::from_str::<DaemonConfig>(&content)
            .unwrap_or_else(|e| panic!("example config {rel} must still parse: {e}"));
    }
    // Completeness: any daemon-config-shaped file under examples/ that is
    // not in the pinned list fails here, forcing triage instead of silent
    // omission from coverage.
    let pinned_set: BTreeSet<String> = pinned.iter().map(|s| s.to_string()).collect();
    let mut discovered: BTreeSet<String> = BTreeSet::new();
    for entry in std::fs::read_dir(root.join("examples")).expect("read examples/") {
        let path = entry.expect("dir entry").path();
        let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") && name.starts_with("config") {
            discovered.insert(format!("examples/{name}"));
        }
    }
    for tier in ["dev", "staging", "prod", "fips"] {
        let rel = format!("examples/configs/{tier}/proxy.toml");
        assert!(root.join(&rel).exists(), "expected tier config missing: {rel}");
        discovered.insert(rel);
    }
    for rel in &discovered {
        assert!(
            pinned_set.contains(rel),
            "daemon config {rel} exists but is not in the pinned parse list — add it"
        );
    }
}

// ---------------------------------------------------------------------------
// W1-C3-04: the M3 objects+auth=none guard must be reachable (not shadowed by
// the earlier generic policy+auth=none reject), preserving all current rejects.
// ---------------------------------------------------------------------------

#[test]
fn m3_objects_grant_with_none_listener_hits_m3_error() {
    let toml = "\
[backend]\nmodule = \".\"\n[listener.local]\npath = \"/run/p.sock\"\nauth = \"none\"\nallow_insecure_unix = true\n[auth]\nallow_all_authenticated = false\n[[auth.policy]]\nidentity = \"uid=1000\"\ntokens = [{ token = \"label:MyToken\", objects = [\"aabbcc\"] }]\n";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("silently inert") && err.contains("objects"),
        "M3 combo must hit the M3-specific error, got: {err}"
    );
}

#[test]
fn generic_policy_with_none_listener_still_rejected() {
    // Preservation control: a non-objects policy + auth=none must still be
    // rejected (by the generic guard) after the M3 reorder.
    let toml = "\
[backend]\nmodule = \".\"\n[listener.local]\npath = \"/run/p.sock\"\nauth = \"none\"\nallow_insecure_unix = true\n[auth]\nallow_all_authenticated = false\n[[auth.policy]]\nidentity = \"uid=1000\"\ntokens = [\"label:MyToken\"]\n";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("cannot apply to unauthenticated peers"),
        "generic policy+none must keep the generic error, got: {err}"
    );
}

// W1-C3-16: a policy with no authenticated listener behind it must hit
// the generic policy+auth=none reject above — the "no authenticated
// listeners" arm inside validate_policy_identities is unreachable (every
// such config trips an earlier return) and must never surface.
#[test]
fn policy_with_no_authenticated_listeners_hits_generic_reject() {
    let toml = "\
[backend]\nmodule = \".\"\n[listener.local]\npath = \"/run/p.sock\"\nauth = \"none\"\nallow_insecure_unix = true\n[auth]\nallow_all_authenticated = false\n[[auth.policy]]\nidentity = \"uid=1000\"\ntokens = [\"label:MyToken\"]\n";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("cannot apply to unauthenticated peers"),
        "must hit the generic reject, got: {err}"
    );
    assert!(
        !err.contains("no authenticated listeners"),
        "unreachable dead-branch message must never surface, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// W1-C3-06: policy identity uid forms must be normalized so accepted
// identities can match runtime keys (uid=01000 vs uid=1000).
// ---------------------------------------------------------------------------

#[test]
fn non_canonical_uid_identity_matches_runtime_key() {
    // uid=01000 parses as uid 1000; the runtime key is "uid=1000", so the
    // configured identity must match it after normalization.
    let auth = AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![PolicyEntry {
            identity: "uid=01000".into(),
            tokens: TokenAccessSpec::Specific(vec![GrantSpec::Bare("label:my-token".into())]),
        }],
    };
    let policy = crate::server::auth::policy::TokenPolicy::from_config(&auth).expect("must load");
    let id = crate::server::auth::identity::AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(
        policy.allows(&id, "my-token", "any"),
        "normalized uid=01000 must match runtime uid=1000"
    );
}

#[test]
fn plus_prefixed_uid_identity_matches_runtime_key() {
    // "+1000" parses as u32 1000 but never equals the "uid=1000" runtime key.
    let auth = AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![PolicyEntry {
            identity: "uid=+1000".into(),
            tokens: TokenAccessSpec::Specific(vec![GrantSpec::Bare("label:my-token".into())]),
        }],
    };
    let policy = crate::server::auth::policy::TokenPolicy::from_config(&auth).expect("must load");
    let id = crate::server::auth::identity::AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(
        policy.allows(&id, "my-token", "any"),
        "normalized uid=+1000 must match runtime uid=1000"
    );
}

#[test]
fn canonical_uid_identity_still_matches() {
    // Preservation control: canonical forms behave exactly as before.
    let auth = AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![PolicyEntry {
            identity: "uid=1000".into(),
            tokens: TokenAccessSpec::Specific(vec![GrantSpec::Bare("label:my-token".into())]),
        }],
    };
    let policy = crate::server::auth::policy::TokenPolicy::from_config(&auth).expect("must load");
    let id = crate::server::auth::identity::AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows(&id, "my-token", "any"));
    let other = crate::server::auth::identity::AuthenticatedIdentity::PeerCred { uid: 2000 };
    assert!(!policy.allows(&other, "my-token", "any"));
}

// ---------------------------------------------------------------------------
// W1-C3-08: unparseable RESILIENCE_FIND_THRESHOLD must error loudly.
// ---------------------------------------------------------------------------

#[test]
fn unparseable_find_threshold_env_errors_loudly() {
    let toml = r#"
[backend]
module = "."
"#;
    let mut config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config
        .apply_env_overrides_with(fake_env(&[(
            "PKCS11_PROXY_RESILIENCE_FIND_THRESHOLD",
            "not-a-number",
        )]))
        .unwrap_err();
    assert!(
        err.contains("PKCS11_PROXY_RESILIENCE_FIND_THRESHOLD"),
        "error must name the var, got: {err}"
    );
    assert!(err.contains("not-a-number"), "error must name the value, got: {err}");
}

#[test]
fn valid_find_threshold_env_still_applies() {
    // Preservation control: valid values behave as before.
    let toml = r#"
[backend]
module = "."
"#;
    let mut config: DaemonConfig = toml::from_str(toml).unwrap();
    config
        .apply_env_overrides_with(fake_env(&[("PKCS11_PROXY_RESILIENCE_FIND_THRESHOLD", "500")]))
        .expect("valid threshold must apply");
    assert_eq!(config.resilience.find_result_warn_threshold, Some(500));
    // Unset: TOML value (here absent) is preserved.
    let mut config: DaemonConfig = toml::from_str(toml).unwrap();
    config.apply_env_overrides_with(fake_env(&[])).expect("unset var must be a no-op");
    assert_eq!(config.resilience.find_result_warn_threshold, None);
}

// ---------------------------------------------------------------------------
// W1-C3-13: bind must validate as a real SocketAddr, not contains(':').
// ---------------------------------------------------------------------------

#[test]
fn hostname_bind_rejected_at_validate_time() {
    let toml = r#"
[backend]
module = "."

[listener.remote]
bind = "localhost:50051"
auth = "none"
allow_insecure_tcp = true
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost:50051"),
        "error must name the offending bind value, got: {err}"
    );
}

#[test]
fn ip_binds_still_validate() {
    // Preservation control: IP:port binds (v4 + v6) pass as before.
    for bind in ["127.0.0.1:7512", "0.0.0.0:50051", "[::1]:7512"] {
        let toml = format!(
            "[backend]\nmodule = \".\"\n\n[listener.remote]\nbind = \"{bind}\"\nauth = \"none\"\nallow_insecure_tcp = true\n"
        );
        let config: DaemonConfig = toml::from_str(&toml).unwrap();
        assert!(config.validate().is_ok(), "bind {bind} must validate");
    }
}

/// W1-L6-20: transport concurrency knobs ship with safe bounded defaults.
#[test]
fn parse_transport_limits_defaults() {
    let toml = r#"
[backend]
module = "."
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.grpc_concurrency_limit_per_connection, 256);
    assert_eq!(config.proxy.grpc_max_concurrent_streams, 256);
    assert!(config.proxy.grpc_load_shed);
}

/// W1-L6-20: operators can tune the transport concurrency knobs.
#[test]
fn parse_transport_limits_when_set() {
    let toml = r#"
[backend]
module = "."

[proxy]
grpc_concurrency_limit_per_connection = 64
grpc_max_concurrent_streams = 128
grpc_load_shed = false
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.grpc_concurrency_limit_per_connection, 64);
    assert_eq!(config.proxy.grpc_max_concurrent_streams, 128);
    assert!(!config.proxy.grpc_load_shed);
}

/// W1-L6-20: zero transport limits are rejected (a zero limit would
/// either refuse everything or silently restore the unbounded default).
#[test]
fn validate_zero_transport_limits_rejected() {
    for field in ["grpc_concurrency_limit_per_connection", "grpc_max_concurrent_streams"] {
        let toml = format!("[backend]\nmodule = \".\"\n\n[proxy]\n{field} = 0\n");
        let config: DaemonConfig = toml::from_str(&toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.contains(field), "error should mention field: {err}");
    }
}

// ---------------------------------------------------------------------------
// Task 9 (W1-L8-06..17) helpers: read submodule-root files for doc-honesty
// tests (same pattern as `all_example_daemon_configs_still_parse`).
// ---------------------------------------------------------------------------

/// Read a file relative to the submodule root (`pkcs11-proxy-ng/`).
fn submodule_file(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../").join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// Slice `text` between the first lines starting with `start` and `end`
/// (exclusive of the marker lines); panics when either marker is absent.
fn section_between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let from = text.find(start).unwrap_or_else(|| panic!("missing section marker {start:?}"));
    let from = text[from..].find('\n').map(|i| from + i + 1).unwrap_or(text.len());
    let rest = &text[from..];
    let to = rest.find(end).unwrap_or_else(|| panic!("missing section marker {end:?}"));
    &rest[..to]
}

/// The (var, TOML field) pairs `env_var_help()` documents, parsed from
/// its own output so the doc-sync tests below derive the expected set
/// instead of hardcoding it.
fn documented_env_vars() -> Vec<(String, String)> {
    let help = env_var_help();
    let mut vars = Vec::new();
    for line in help.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("PKCS11_PROXY_") {
            let var = format!("PKCS11_PROXY_{}", rest.split_whitespace().next().unwrap_or(""));
            let field = line
                .split('→')
                .nth(1)
                .unwrap_or("")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            assert!(!field.is_empty(), "help line must map {var} to a TOML field: {line}");
            vars.push((var, field));
        }
    }
    vars
}

// ---------------------------------------------------------------------------
// W1-C3-15: the apply_env_overrides doc list must name every var the body
// reads, including PKCS11_PROXY_ALLOW_INSECURE (it drives
// listener.remote.allow_insecure_tcp in both listener branches). (Pin:
// the entry itself predates this task via P0/P1 W1-L8-01.)
// ---------------------------------------------------------------------------

/// This crate's own `config.rs` source, for doc-sync pins.
fn own_config_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config.rs");
    std::fs::read_to_string(&path).expect("read own src/config.rs")
}

#[test]
fn env_override_doc_list_names_allow_insecure() {
    let text = own_config_source();
    let doc = section_between(&text, "/// Documented env vars:", "pub fn apply_env_overrides");
    assert!(
        doc.contains("PKCS11_PROXY_ALLOW_INSECURE"),
        "env doc list must name PKCS11_PROXY_ALLOW_INSECURE:\n{doc}"
    );
    assert!(
        doc.contains("listener.remote.allow_insecure_tcp"),
        "env doc list must map ALLOW_INSECURE to listener.remote.allow_insecure_tcp:\n{doc}"
    );
}

// ---------------------------------------------------------------------------
// W1-C3-19: tokens = "*" is accepted as an alias of "all" (pinned by
// from_config_with_all_access); the TokenAccessSpec schema docs must say so.
// ---------------------------------------------------------------------------

#[test]
fn tokens_star_alias_documented_in_schema_docs() {
    let text = own_config_source();
    let doc = section_between(&text, "Three valid forms:", "pub enum TokenAccessSpec");
    assert!(doc.contains("\"all\""), "schema docs must document tokens = \"all\":\n{doc}");
    assert!(doc.contains("\"*\""), "schema docs must document the tokens = \"*\" alias:\n{doc}");
}

// ---------------------------------------------------------------------------
// T27-m1: the TokenAccessSpec type-mismatch error must name both accepted
// scalar forms ("all" and its "*" alias) so it agrees with the schema docs.
// ---------------------------------------------------------------------------

#[test]
fn tokens_type_mismatch_error_names_all_and_star() {
    let toml = r#"
[backend]
module = "."

[listener.local]
path = "/tmp/test.sock"
auth = "peer_cred"

[auth]
allow_all_authenticated = false

[[auth.policy]]
identity = "uid=1000"
tokens = 42
"#;
    let err = toml::from_str::<DaemonConfig>(toml).unwrap_err().to_string();
    assert!(err.contains("\"all\""), "type-mismatch error must name \"all\": {err}");
    assert!(err.contains("\"*\""), "type-mismatch error must name the \"*\" alias: {err}");
}

// ---------------------------------------------------------------------------
// W1-L8-07: runbook §8a must list all 8 daemon env vars var-for-var with
// --print-env-vars.
// ---------------------------------------------------------------------------

#[test]
fn runbook_daemon_env_table_matches_print_env_vars() {
    let vars = documented_env_vars();
    assert_eq!(vars.len(), 8, "expected 8 documented daemon env vars, got: {vars:?}");
    let runbook = submodule_file("doc/runbooks/operating-pkcs11-proxy-ng.md");
    let table = section_between(&runbook, "## 8a.", "## 8b.");
    for (var, field) in &vars {
        assert!(table.contains(var), "runbook §8a must list {var} (--print-env-vars documents it)");
        assert!(table.contains(field), "runbook §8a must map {var} to TOML field {field}");
    }
}

// ---------------------------------------------------------------------------
// W1-L8-08: runbook §8b mTLS section must match tls.rs reality (TLS_DOMAIN
// optional; 3 vars required together) and document CONNECT_ATTEMPTS.
// ---------------------------------------------------------------------------

#[test]
fn runbook_mtls_section_matches_client_tls_behavior() {
    let runbook = submodule_file("doc/runbooks/operating-pkcs11-proxy-ng.md");
    let mtls = section_between(&runbook, "### mTLS (client side)", "### Mechanism registry");
    assert!(
        !mtls.contains("All four are required together"),
        "runbook must not claim all four mTLS vars are required (TLS_DOMAIN is optional)"
    );
    assert!(
        mtls.contains("PKCS11_PROXY_TLS_DOMAIN"),
        "runbook mTLS section must document PKCS11_PROXY_TLS_DOMAIN"
    );
    assert!(
        mtls.to_lowercase().contains("optional"),
        "runbook mTLS section must say TLS_DOMAIN is optional"
    );
    let conn = section_between(&runbook, "### Connection", "### mTLS (client side)");
    assert!(
        conn.contains("PKCS11_PROXY_CONNECT_ATTEMPTS"),
        "runbook connection table must document PKCS11_PROXY_CONNECT_ATTEMPTS"
    );
}

// ---------------------------------------------------------------------------
// W1-L8-09: proxy.toml.default must not claim every value is env-overridable
// (only the 8 documented vars are) and must leave config_path unset so the
// default is the embedded registry.
// ---------------------------------------------------------------------------

#[test]
fn default_config_header_is_honest_about_env_overrides() {
    let content = submodule_file("packaging/config/proxy.toml.default");
    assert!(
        !content.contains("Every value below can also be overridden"),
        "default config must not claim every value is env-overridable"
    );
    for (var, _) in documented_env_vars() {
        assert!(
            content.contains(&var),
            "default config header must list the 8 overridable vars (missing {var})"
        );
    }
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("config_path") {
            panic!(
                "default config must leave config_path unset (embedded default), \
                 found active line: {line}"
            );
        }
    }
    assert!(
        content.contains("embedded default"),
        "default config must document that unset config_path serves the embedded default"
    );
}

// ---------------------------------------------------------------------------
// W1-L8-10: example mTLS headers must describe the wired transport, not the
// stale "not wired yet" shape.
// ---------------------------------------------------------------------------

#[test]
fn example_mtls_headers_describe_wired_transport() {
    for rel in ["examples/config-mtls.toml", "examples/config-multi-user.toml"] {
        let content = submodule_file(rel);
        assert!(
            !content.contains("not wired"),
            "{rel} header must not claim mTLS is unwired (transport.rs enforces it)"
        );
        let head: String = content.lines().take(12).collect::<Vec<_>>().join("\n");
        assert!(
            head.contains("wired") || head.contains("enforced"),
            "{rel} header must describe the wired mTLS transport"
        );
    }
}

// ---------------------------------------------------------------------------
// W1-L8-11: examples must point at the default daemon port (:7512) and
// config paths (/etc/pkcs11-proxy-ng/*) so copy-paste connects.
// ---------------------------------------------------------------------------

#[test]
fn examples_use_default_daemon_paths() {
    for rel in [
        "examples/config-loopback-dev.toml",
        "examples/config-mtls.toml",
        "examples/config-multi-user.toml",
    ] {
        let content = submodule_file(rel);
        assert!(content.contains("7512"), "{rel} must use the default daemon port :7512");
        assert!(!content.contains("50051"), "{rel} must not use the stale :50051 port");
        for line in content.lines() {
            if line.contains("/etc/pkcs11-proxy/") && !line.contains("/etc/pkcs11-proxy-ng/") {
                panic!("{rel} uses the stale /etc/pkcs11-proxy path: {line}");
            }
        }
    }
}

// The W1-L8-12/13 ADR checks moved with ADR-0005 to the umbrella workspace's
// scripts/test_planning_docs.py. Runtime/configuration checks remain here.

// ---------------------------------------------------------------------------
// W1-L8-14: AGENTS.md must not claim a default registry file path — with
// config_path unset the daemon serves the embedded default.
// ---------------------------------------------------------------------------

#[test]
fn agents_registry_path_claims_match_embedded_default() {
    let agents = submodule_file("AGENTS.md");
    assert!(
        !agents.contains("mechanism_params.toml` by default"),
        "AGENTS.md must not claim /etc/pkcs11-proxy-ng/mechanism_params.toml is the default path"
    );
    assert!(
        agents.contains("config_path` is unset"),
        "AGENTS.md must document that unset config_path serves the embedded default"
    );
}

// ---------------------------------------------------------------------------
// W1-L8-16: validate() must reject degenerate zeros (rate window, login
// cooldown, login-lock timeout) and duplicate policy identities (via the
// C3-05 mechanism in TokenPolicy::from_config, which validate() calls).
// ---------------------------------------------------------------------------

#[test]
fn validate_rejects_zero_rate_limit_window() {
    let toml = rate_limit_toml("[proxy]\nrate_limit_window_secs = 0\n");
    let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("rate_limit_window_secs"), "error must name the field, got: {err}");
}

#[test]
fn validate_rejects_zero_login_cooldown() {
    let toml = rate_limit_toml(
        "[rate_limit]\nper_slot_failed_login_budget = 3\nper_slot_failed_login_cooldown_secs = 0\n",
    );
    let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("per_slot_failed_login_cooldown_secs"),
        "error must name the field, got: {err}"
    );
}

#[test]
fn validate_rejects_zero_login_lock_timeout() {
    let toml = rate_limit_toml("[proxy]\nlogin_lock_timeout_secs = 0\n");
    let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("login_lock_timeout_secs"), "error must name the field, got: {err}");
}

#[test]
fn validate_rejects_zero_audit_rotation_knobs() {
    // Authenticated listener: the H2 guard (audit + auth=none) must not
    // fire before the rotation-knob check under test.
    for field in ["rotate_max_bytes", "rotate_keep_files"] {
        let toml = format!(
            "[backend]\nmodule = \".\"\n[listener.local]\npath = \"/tmp/test.sock\"\n\
             auth = \"peer_cred\"\n[auth]\nallow_all_authenticated = true\n\
             [audit]\ndir = \".\"\n{field} = 0\n"
        );
        let cfg: DaemonConfig = toml::from_str(&toml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains(field), "error must name the field, got: {err}");
    }
}

#[test]
fn validate_rejects_duplicate_policy_identity() {
    // W1-L8-16 reuses the W1-C3-05 mechanism: validate() routes through
    // TokenPolicy::from_config, which rejects duplicate identities naming
    // the identity. This pins the validate()-level rejection.
    let toml = r#"
[backend]
module = "."

[listener.local]
path = "/tmp/test.sock"
auth = "peer_cred"

[auth]
allow_all_authenticated = false

[[auth.policy]]
identity = "uid=1000"
tokens = ["label:TokenA"]

[[auth.policy]]
identity = "uid=1000"
tokens = ["label:TokenB"]
"#;
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("duplicate") && err.contains("uid=1000"),
        "validate() must reject duplicate policy identities naming the identity, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// W1-L8-17: the x509:spki= identity form must be taught as primary (docs +
// one working example) alongside the legacy DN form (marked deprecated),
// and the taught form must validate.
// ---------------------------------------------------------------------------

#[test]
fn spki_identity_taught_in_docs_and_example() {
    let default_cfg = submodule_file("packaging/config/proxy.toml.default");
    assert!(
        default_cfg.contains("x509:spki="),
        "shipped default config must teach the x509:spki= identity form"
    );
    let prod = submodule_file("examples/configs/prod/proxy.toml");
    assert!(prod.contains("x509:spki="), "prod example must teach the x509:spki= identity form");
    assert!(
        prod.to_lowercase().contains("deprecat"),
        "prod example must mark the legacy DN identity form deprecated"
    );
}

#[test]
fn validate_accepts_spki_policy_identity() {
    // The SPKI form taught by the W1-L8-17 docs must validate end to end
    // ("." stands in for the mTLS cert paths, which only need to exist).
    let toml = r#"
[backend]
module = "."

[listener.remote]
bind = "127.0.0.1:7512"
auth = "mtls"
ca_cert = "."
server_cert = "."
server_key = "."

[auth]
allow_all_authenticated = false

[[auth.policy]]
identity = "x509:spki=9f2c4a8e1b5d6f0391a4c7e2b5d8f0a1c4e7b0d3f6a9c2e5b8d1f4a7c0e3b6d9f"
tokens = ["label:Prod"]
"#;
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    cfg.validate().expect("taught SPKI policy identity must validate");
}

// ---------------------------------------------------------------------------
// W1-L8-18: 'host:badport' must fail at validate with a friendly,
// value-naming error (confirms the W1-C3-13 SocketAddr-grade check holds).
// ---------------------------------------------------------------------------

#[test]
fn host_colon_badport_bind_rejected_with_friendly_error() {
    let toml = r#"
[backend]
module = "."

[listener.remote]
bind = "host:badport"
auth = "none"
allow_insecure_tcp = true
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("host:badport"), "error must name the offending value, got: {err}");
    assert!(
        err.contains("IP:port") || err.contains("SocketAddr"),
        "error must steer toward IP:port, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// W1-L8-20: the k8s ConfigMap's mechanism stub must teach merge semantics
// (an override merged over the shipped embedded default), not claim to BE
// the embedded default.
// ---------------------------------------------------------------------------

#[test]
fn k8s_configmap_teaches_registry_merge_not_replace() {
    let yaml = submodule_file("examples/k8s/10-configmap.yaml");
    assert!(
        !yaml.contains("Shipped embedded default"),
        "stub must not claim to be the embedded default:\n{yaml}"
    );
    assert!(
        yaml.to_ascii_lowercase().contains("merge"),
        "stub comment must teach merge semantics:\n{yaml}"
    );
}

// ---------------------------------------------------------------------------
// W1-L8-21: the apply_env_overrides doc list, env_var_help(), and the
// override body must agree on the full env-var set (all 8 incl.
// ALLOW_INSECURE) — an omission in any surface is a doc/behavior lie, and
// in test ALL_VARS it is an env-bleed risk.
// ---------------------------------------------------------------------------

/// Every `PKCS11_PROXY_*` var token on `///` doc lines between markers.
fn doc_listed_env_vars(source: &str, start: &str, end: &str) -> Vec<String> {
    let doc = section_between(source, start, end);
    let mut vars = Vec::new();
    for line in doc.lines() {
        let mut rest = line;
        while let Some(i) = rest.find("PKCS11_PROXY_") {
            let token: String = rest[i..]
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            if token.len() > "PKCS11_PROXY_".len() && !vars.contains(&token) {
                vars.push(token);
            }
            rest = &rest[i + "PKCS11_PROXY_".len()..];
        }
    }
    vars
}

#[test]
fn env_var_surfaces_agree_on_all_vars() {
    let source = own_config_source();
    let doc_vars =
        doc_listed_env_vars(&source, "/// Documented env vars:", "pub fn apply_env_overrides");
    assert_eq!(doc_vars.len(), 8, "doc list must name all 8 daemon env vars: {doc_vars:?}");
    let help = env_var_help();
    for var in &doc_vars {
        assert!(help.contains(var), "env_var_help() must list {var}:\n{help}");
        assert!(source.contains(&format!("get(\"{var}\")")), "override body must read {var}");
    }
    // And help must not advertise vars the body ignores.
    for (var, _field) in documented_env_vars() {
        assert!(
            source.contains(&format!("get(\"{var}\")")),
            "help-advertised {var} must be read by the override body"
        );
    }
}

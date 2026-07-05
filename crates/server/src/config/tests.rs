use super::*;

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
module = "/dev/null"
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.backend.module.to_str().unwrap(), "/dev/null");
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
module = "/dev/null"
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
module = "/dev/null"
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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("No listeners"), "error should mention missing listeners: {err}");
}

#[test]
fn validate_invalid_unix_auth_rejected() {
    let toml = r#"
[backend]
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

[listener.remote]
bind = "0.0.0.0:50051"
auth = "mtls"
ca_cert = "/dev/null"
server_cert = "/dev/null"
server_key = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

[listener.local]
path = "/tmp/test.sock"
auth = "peer_cred"

[listener.remote]
bind = "0.0.0.0:50051"
auth = "mtls"
ca_cert = "/dev/null"
server_cert = "/dev/null"
server_key = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.max_message_bytes, 4 * 1024 * 1024);
}

#[test]
fn default_request_timeout_secs() {
    let toml = r#"
[backend]
module = "/dev/null"
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.request_timeout_secs, 60);
}

#[test]
fn custom_max_message_bytes() {
    let toml = r#"
[backend]
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.max_concurrent_backend_calls, 200);
}

#[test]
fn custom_max_concurrent_backend_calls() {
    let toml = r#"
[backend]
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"

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
module = "/dev/null"
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
module = "/dev/null"
"#;
    let config: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.max_stuck_backend_calls, None);
}

#[test]
fn max_stuck_backend_calls_parses_when_set() {
    let toml = r#"
[backend]
module = "/dev/null"

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
module = "/dev/null"

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
    let toml = "[backend]\nmodule = \"/dev/null\"\n";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert!(cfg.resilience.find_result_warn_threshold.is_none());
    assert!(cfg.resilience.metrics_socket.is_none());
}

#[test]
fn resilience_section_parses() {
    let toml = "\
[backend]
module = \"/dev/null\"
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
fn audit_absent_defaults_to_off() {
    let cfg: DaemonConfig = toml::from_str("[backend]\nmodule = \"/dev/null\"\n").unwrap();
    assert!(cfg.audit.dir.is_none());
    assert!(cfg.audit.signing_key.is_none());
    assert_eq!(cfg.audit.rotate_max_bytes, 64 * 1024 * 1024);
    assert_eq!(cfg.audit.rotate_keep_files, 10);
}

#[test]
fn audit_section_parses() {
    let toml = "\
[backend]
module = \"/dev/null\"
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
module = \"/dev/null\"
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
module = \"/dev/null\"
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
    let toml = "[backend]\nmodule = \"/dev/null\"\n";
    let cfg: DaemonConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.proxy.login_lock_timeout_secs, 10);
}

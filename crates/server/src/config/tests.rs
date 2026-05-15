use super::*;

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
    assert!(
        err.contains("no authenticated listeners"),
        "error should explain policy cannot apply: {err}"
    );
    assert!(
        err.contains("auth = 'none' bypasses auth policy"),
        "error should mention bypass: {err}"
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

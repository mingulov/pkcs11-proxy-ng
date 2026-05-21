//! Example configs dry-run + forward-compat check.
//!
//! For each `examples/configs/<tier>/proxy.toml`, verify that the
//! daemon's `DaemonConfig::load` parses it cleanly. We patch the
//! backend.module path to a known-existing file so validate()'s
//! existence check passes (the shipped paths point at vendor .sos
//! that may not be present on every test host).
//!
//! Forward-compat: round-trip the resilience-fixture's proxy.toml
//! (the oldest TOML we ship) through the current daemon's parser.
//! Any schema drift that breaks older deployments shows up here.

use std::path::PathBuf;

fn submodule_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn dummy_backend_module() -> String {
    if PathBuf::from("/bin/sh").exists() {
        "/bin/sh".to_string()
    } else {
        "/usr/bin/env".to_string()
    }
}

fn rewrite_for_test(orig: &str) -> String {
    // Patch backend.module to a known-existing file (the shipped paths
    // point at vendor .sos that may not exist). Also strip the
    // mechanisms.config_path = "..." line if present (would otherwise
    // fail the file-exists check; mechanism registry handling is
    // tested elsewhere).
    let mut out = String::with_capacity(orig.len());
    for line in orig.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("module ") || trimmed.starts_with("module=") {
            out.push_str(&format!("module = \"{}\"\n", dummy_backend_module()));
        } else if trimmed.starts_with("config_path ") || trimmed.starts_with("config_path=") {
            out.push_str("# config_path = stripped for test\n");
        } else if trimmed.starts_with("ca_cert ")
            || trimmed.starts_with("ca_cert=")
            || trimmed.starts_with("server_cert ")
            || trimmed.starts_with("server_cert=")
            || trimmed.starts_with("server_key ")
            || trimmed.starts_with("server_key=")
        {
            // mTLS files don't exist on the test host; the
            // permission check + actual TLS load run only when
            // server_tls_config is invoked, not during config parse.
            // Strip these so DaemonConfig::load doesn't reject them
            // via a future cert-existence check.
            out.push_str(&format!("# {line}\n"));
        } else if trimmed.starts_with("auth = \"mtls\"") {
            // With certs stripped, switch to insecure-tcp so the
            // config validates as a "syntactically OK" example.
            out.push_str("auth = \"none\"\n");
        } else if trimmed.starts_with("allow_insecure_tcp ")
            || trimmed.starts_with("allow_insecure_tcp=")
        {
            // Force allow_insecure_tcp = true to pair with the
            // auth = "none" rewrite above.
            out.push_str("allow_insecure_tcp = true\n");
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn write_temp(toml: &str) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(toml.as_bytes()).unwrap();
    f
}

#[test]
fn example_dev_parses() {
    let p = submodule_root().join("examples/configs/dev/proxy.toml");
    let raw = std::fs::read_to_string(&p).expect("dev/proxy.toml");
    let patched = rewrite_for_test(&raw);
    let tmp = write_temp(&patched);
    pkcs11_proxy_ng::config::DaemonConfig::load(tmp.path()).expect("dev parses");
}

#[test]
fn example_staging_parses() {
    let p = submodule_root().join("examples/configs/staging/proxy.toml");
    let raw = std::fs::read_to_string(&p).expect("staging/proxy.toml");
    let patched = rewrite_for_test(&raw);
    let tmp = write_temp(&patched);
    pkcs11_proxy_ng::config::DaemonConfig::load(tmp.path()).expect("staging parses");
}

#[test]
fn example_prod_parses() {
    let p = submodule_root().join("examples/configs/prod/proxy.toml");
    let raw = std::fs::read_to_string(&p).expect("prod/proxy.toml");
    let patched = rewrite_for_test(&raw);
    let tmp = write_temp(&patched);
    pkcs11_proxy_ng::config::DaemonConfig::load(tmp.path()).expect("prod parses");
}

#[test]
fn example_fips_parses() {
    let p = submodule_root().join("examples/configs/fips/proxy.toml");
    let raw = std::fs::read_to_string(&p).expect("fips/proxy.toml");
    let patched = rewrite_for_test(&raw);
    let tmp = write_temp(&patched);
    pkcs11_proxy_ng::config::DaemonConfig::load(tmp.path()).expect("fips parses");
}

#[test]
fn example_fips_mechanism_params_parses() {
    use pkcs11_proxy_ng_types::MechanismRegistry;
    let p = submodule_root().join("examples/configs/fips/mechanism_params.toml");
    let registry =
        MechanismRegistry::load(Some(&p)).expect("fips/mechanism_params.toml must parse");
    // The FIPS allow-list must be in Filtered discovery mode (the
    // whole point — without it the daemon would advertise more than
    // the FIPS subset).
    assert_eq!(
        registry.discovery_mode(),
        pkcs11_proxy_ng_types::DiscoveryMode::Filtered,
        "fips registry must enable filtered discovery"
    );
}

/// Forward-compat: an older shipped proxy.toml (the one used by the
/// resilience fixture, predating later-added fields) must still
/// parse cleanly with the current daemon. New fields default.
#[test]
fn forward_compat_r2_fixture_proxy_toml_parses() {
    // The resilience fixture embeds its proxy.toml directly in the daemon
    // Dockerfile (heredoc). We reproduce the same TOML body here so
    // the test is independent of Docker.
    let older_toml = r#"
[backend]
module = "/bin/sh"

[proxy]
request_timeout_secs = 60
startup_timeout_secs = 30
shutdown_grace_secs = 5
backend_health_consecutive_failures = 3

[listener.remote]
bind = "0.0.0.0:7512"
auth = "none"
allow_insecure_tcp = true

[auth]
"#;
    let tmp = write_temp(older_toml);
    let cfg = pkcs11_proxy_ng::config::DaemonConfig::load(tmp.path())
        .expect("older proxy.toml must still parse");
    // Spot-check a few fields filled in from defaults:
    assert!(cfg.proxy.rate_limit_window_secs > 0);
    assert_eq!(cfg.proxy.rate_limit_get_backend_interfaces, 0);
}

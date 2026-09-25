//! Env-var override precedence table-driven test.
//!
//! Verifies that each documented daemon env var overrides the
//! corresponding TOML field. Tests:
//!   - env unset: TOML value wins
//!   - env set: env wins (conflicting TOML value is overridden)
//!
//! Env vars covered:
//!   - PKCS11_PROXY_BIND              → listener.remote.bind
//!   - PKCS11_PROXY_BACKEND_MODULE    → backend.module
//!   - PKCS11_PROXY_BACKEND_ARGS      → backend.initialize_args
//!   - PKCS11_PROXY_MECHANISMS_CONFIG → mechanisms.config_path
//!
//! Note: each #[test] runs in its own process so env-var bleed
//! between cases is contained. We further unset every relevant var
//! at the start of each case to guard against ambient pollution
//! from the harness or from `--test-threads > 1`.

use pkcs11_proxy_ng::config::DaemonConfig;
use std::path::{Path, PathBuf};

const ALL_VARS: &[&str] = &[
    "PKCS11_PROXY_BIND",
    "PKCS11_PROXY_BACKEND_MODULE",
    "PKCS11_PROXY_BACKEND_ARGS",
    "PKCS11_PROXY_MECHANISMS_CONFIG",
];

fn clear_all_env() {
    for v in ALL_VARS {
        unsafe { std::env::remove_var(v) };
    }
}

fn baseline_toml(backend_module: &str, mech_path: Option<&str>) -> String {
    let mech_block = match mech_path {
        Some(p) => format!("\n[mechanisms]\nconfig_path = \"{p}\"\n"),
        None => "\n[mechanisms]\n".to_string(),
    };
    format!(
        r#"
[backend]
module = "{backend_module}"
initialize_args = "toml-args"

[proxy]

[listener.remote]
bind = "127.0.0.1:7512"
auth = "none"
allow_insecure_tcp = true

[auth]
{mech_block}
"#
    )
}

fn write_temp_config(toml: &str) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(toml.as_bytes()).expect("write");
    f
}

/// Helper: produce a path that satisfies the backend-module
/// existence check in `validate()`. We use /bin/sh which exists on
/// any Linux test host. validate() only checks `.exists()`, not
/// that it's a valid PKCS#11 module.
fn dummy_backend_module() -> PathBuf {
    if Path::new("/bin/sh").exists() {
        PathBuf::from("/bin/sh")
    } else if Path::new("/usr/bin/env").exists() {
        PathBuf::from("/usr/bin/env")
    } else {
        panic!("test host has neither /bin/sh nor /usr/bin/env");
    }
}

#[test]
fn env_unset_toml_wins() {
    clear_all_env();
    let dummy = dummy_backend_module();
    // Use an actual file path for the mechanism config so validate() accepts it.
    let mech_path = tempfile::NamedTempFile::new().expect("mech tempfile");
    let mech_path_str = mech_path.path().to_string_lossy().into_owned();
    std::fs::write(mech_path.path(), b"").unwrap();
    let toml = baseline_toml(dummy.to_str().unwrap(), Some(&mech_path_str));
    let cfg_file = write_temp_config(&toml);
    let cfg = DaemonConfig::load(cfg_file.path()).expect("load");
    assert_eq!(cfg.backend.module, dummy);
    assert_eq!(cfg.backend.initialize_args.as_deref(), Some("toml-args"));
    assert_eq!(cfg.mechanisms.config_path.as_deref(), Some(mech_path.path()));
    assert_eq!(cfg.listener.remote.as_ref().unwrap().bind, "127.0.0.1:7512");
}

#[test]
fn env_pkcs11_proxy_bind_overrides_toml() {
    clear_all_env();
    let dummy = dummy_backend_module();
    let toml = baseline_toml(dummy.to_str().unwrap(), None);
    let cfg_file = write_temp_config(&toml);
    unsafe { std::env::set_var("PKCS11_PROXY_BIND", "0.0.0.0:9999") };
    let cfg = DaemonConfig::load(cfg_file.path()).expect("load");
    assert_eq!(cfg.listener.remote.as_ref().unwrap().bind, "0.0.0.0:9999");
    clear_all_env();
}

#[test]
fn env_pkcs11_proxy_backend_module_overrides_toml() {
    clear_all_env();
    let toml_path = dummy_backend_module();
    let toml = baseline_toml("/tmp/nonexistent-toml-backend.so", None);
    let cfg_file = write_temp_config(&toml);
    unsafe { std::env::set_var("PKCS11_PROXY_BACKEND_MODULE", toml_path.to_str().unwrap()) };
    // Without the override the load would fail at validate()
    // (path doesn't exist); the env override fixes that.
    let cfg = DaemonConfig::load(cfg_file.path()).expect("load");
    assert_eq!(cfg.backend.module, toml_path);
    clear_all_env();
}

#[test]
fn env_pkcs11_proxy_backend_args_overrides_toml() {
    clear_all_env();
    let dummy = dummy_backend_module();
    let toml = baseline_toml(dummy.to_str().unwrap(), None);
    let cfg_file = write_temp_config(&toml);
    unsafe { std::env::set_var("PKCS11_PROXY_BACKEND_ARGS", "env-supplied-args") };
    let cfg = DaemonConfig::load(cfg_file.path()).expect("load");
    assert_eq!(cfg.backend.initialize_args.as_deref(), Some("env-supplied-args"));
    clear_all_env();
}

#[test]
fn env_pkcs11_proxy_mechanisms_config_overrides_toml() {
    clear_all_env();
    let dummy = dummy_backend_module();
    let env_mech = tempfile::NamedTempFile::new().expect("env mech tempfile");
    std::fs::write(env_mech.path(), b"").unwrap();
    let toml = baseline_toml(dummy.to_str().unwrap(), None);
    let cfg_file = write_temp_config(&toml);
    unsafe { std::env::set_var("PKCS11_PROXY_MECHANISMS_CONFIG", env_mech.path()) };
    let cfg = DaemonConfig::load(cfg_file.path()).expect("load");
    assert_eq!(cfg.mechanisms.config_path.as_deref(), Some(env_mech.path()));
    clear_all_env();
}

#[test]
fn env_bind_creates_tcp_listener_when_toml_omits_it() {
    clear_all_env();
    let dummy = dummy_backend_module();
    // TOML with NO [listener.remote] block at all.
    let toml = format!(
        r#"
[backend]
module = "{}"

[proxy]

[auth]
"#,
        dummy.to_str().unwrap()
    );
    let cfg_file = write_temp_config(&toml);
    unsafe { std::env::set_var("PKCS11_PROXY_BIND", "0.0.0.0:8888") };
    let cfg = DaemonConfig::load(cfg_file.path()).expect("load");
    let tcp = cfg.listener.remote.as_ref().expect("env should create the listener");
    assert_eq!(tcp.bind, "0.0.0.0:8888");
    assert!(tcp.allow_insecure_tcp);
    clear_all_env();
}

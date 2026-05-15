use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pkcs11-proxy-ng-cli", about = "PKCS#11 proxy CLI", version)]
pub(crate) struct Cli {
    /// Daemon endpoint (e.g., http://127.0.0.1:7512)
    #[arg(long, env = "PKCS11_PROXY_ENDPOINT", default_value = "http://127.0.0.1:7512")]
    pub(crate) endpoint: String,

    /// CA certificate used to verify the daemon for mTLS connections.
    #[arg(long, env = "PKCS11_PROXY_TLS_CA_CERT", value_hint = clap::ValueHint::FilePath)]
    pub(crate) tls_ca_cert: Option<PathBuf>,

    /// Client certificate presented to the daemon for mTLS connections.
    #[arg(long, env = "PKCS11_PROXY_TLS_CLIENT_CERT", value_hint = clap::ValueHint::FilePath)]
    pub(crate) tls_client_cert: Option<PathBuf>,

    /// Client private key presented to the daemon for mTLS connections.
    #[arg(
        long,
        env = "PKCS11_PROXY_TLS_CLIENT_KEY",
        value_hint = clap::ValueHint::FilePath,
        hide_env_values = true
    )]
    pub(crate) tls_client_key: Option<PathBuf>,

    /// TLS SNI and certificate verification name for the daemon.
    #[arg(long, env = "PKCS11_PROXY_TLS_DOMAIN")]
    pub(crate) tls_domain: Option<String>,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    ListSlots {
        #[arg(long)]
        token_present: bool,
    },
    SlotInfo {
        slot_id: u64,
    },
    TokenInfo {
        slot_id: u64,
    },
    ListMechanisms {
        slot_id: u64,
    },
    FindObjects {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: Option<String>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        verbose: bool,
    },
    Sign {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: String,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        mechanism: String,
        #[arg(long)]
        input: String,
    },
    Digest {
        #[arg(long)]
        slot_id: u64,
        #[arg(long)]
        mechanism: String,
        #[arg(long)]
        input: String,
    },
    Encrypt {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: String,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        mechanism: String,
        #[arg(long)]
        input: String,
    },
    Decrypt {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: String,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        mechanism: String,
        #[arg(long)]
        input: String,
    },
    DestroyObject {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: Option<String>,
        #[arg(long)]
        object_handle: u64,
    },
    GetObjectSize {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: Option<String>,
        #[arg(long)]
        object_handle: u64,
    },
    CreateObject {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        value: Option<String>,
    },
    WrapKey {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: String,
        #[arg(long)]
        mechanism: String,
        #[arg(long)]
        wrapping_key_handle: u64,
        #[arg(long)]
        key_handle: u64,
    },
    UnwrapKey {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: String,
        #[arg(long)]
        mechanism: String,
        #[arg(long)]
        unwrapping_key_handle: u64,
        #[arg(long)]
        wrapped_key: String,
        #[arg(long)]
        label: Option<String>,
    },
    DeriveKey {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: String,
        #[arg(long)]
        mechanism: String,
        #[arg(long)]
        base_key_handle: u64,
        #[arg(long)]
        label: Option<String>,
    },
    GenerateKey {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: String,
        #[arg(long)]
        mechanism: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        key_size: Option<u64>,
    },
    GenerateKeyPair {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: String,
        #[arg(long)]
        mechanism: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        key_size: Option<u64>,
    },
    InitToken {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_SO_PIN", hide_env_values = true)]
        so_pin: String,
        #[arg(long)]
        label: String,
    },
    InitPin {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_SO_PIN", hide_env_values = true)]
        so_pin: String,
        #[arg(long, env = "PKCS11_PROXY_NEW_PIN", hide_env_values = true)]
        new_pin: String,
    },
    SeedRandom {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: String,
        #[arg(long, env = "PKCS11_PROXY_SEED", hide_env_values = true)]
        seed: String,
    },
    SetPin {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: String,
        #[arg(long, env = "PKCS11_PROXY_NEW_PIN", hide_env_values = true)]
        new_pin: String,
    },
    ListMechanismNames,
    GetInfo,
    SessionInfo {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: Option<String>,
    },
    Verify {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        mechanism: String,
        #[arg(long)]
        data: String,
        #[arg(long)]
        signature: String,
    },
    Random {
        #[arg(long)]
        slot_id: u64,
        #[arg(long)]
        len: u32,
        #[arg(long, default_value = "hex")]
        format: String,
    },
    GetAttribute {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: Option<String>,
        #[arg(long)]
        object_handle: u64,
        #[arg(long)]
        attr: Vec<String>,
    },
    ImportCertificate {
        #[arg(long)]
        slot_id: u64,
        #[arg(long, env = "PKCS11_PROXY_PIN", hide_env_values = true)]
        pin: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        file: std::path::PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env_vars<T>(vars: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        let previous: Vec<(&str, Option<OsString>)> =
            vars.iter().map(|(name, _)| (*name, std::env::var_os(name))).collect();

        for (name, value) in vars {
            unsafe {
                std::env::set_var(name, value);
            }
        }
        let result = f();

        for (name, value) in previous {
            unsafe {
                match value {
                    Some(previous) => std::env::set_var(name, previous),
                    None => std::env::remove_var(name),
                }
            }
        }

        result
    }

    #[test]
    fn required_user_pin_can_come_from_environment() {
        with_env_vars(&[("PKCS11_PROXY_PIN", "env-user-pin")], || {
            let cli = Cli::try_parse_from([
                "pkcs11-proxy-ng-cli",
                "sign",
                "--slot-id",
                "1",
                "--key-label",
                "signing-key",
                "--mechanism",
                "CKM_SHA256_RSA_PKCS",
                "--input",
                "hello",
            ])
            .unwrap();

            match cli.command {
                Commands::Sign { pin, .. } => assert_eq!(pin, "env-user-pin"),
                _ => panic!("expected sign command"),
            }
        });
    }

    #[test]
    fn optional_user_pin_can_come_from_environment() {
        with_env_vars(&[("PKCS11_PROXY_PIN", "env-optional-pin")], || {
            let cli =
                Cli::try_parse_from(["pkcs11-proxy-ng-cli", "find-objects", "--slot-id", "1"])
                    .unwrap();

            match cli.command {
                Commands::FindObjects { pin, .. } => {
                    assert_eq!(pin.as_deref(), Some("env-optional-pin"));
                }
                _ => panic!("expected find-objects command"),
            }
        });
    }

    #[test]
    fn administrative_secrets_can_come_from_environment() {
        with_env_vars(
            &[("PKCS11_PROXY_SO_PIN", "env-so-pin"), ("PKCS11_PROXY_NEW_PIN", "env-new-pin")],
            || {
                let cli =
                    Cli::try_parse_from(["pkcs11-proxy-ng-cli", "init-pin", "--slot-id", "1"])
                        .unwrap();

                match cli.command {
                    Commands::InitPin { so_pin, new_pin, .. } => {
                        assert_eq!(so_pin, "env-so-pin");
                        assert_eq!(new_pin, "env-new-pin");
                    }
                    _ => panic!("expected init-pin command"),
                }
            },
        );
    }

    #[test]
    fn seed_random_seed_can_come_from_environment() {
        with_env_vars(
            &[("PKCS11_PROXY_PIN", "env-user-pin"), ("PKCS11_PROXY_SEED", "env-seed-data")],
            || {
                let cli =
                    Cli::try_parse_from(["pkcs11-proxy-ng-cli", "seed-random", "--slot-id", "1"])
                        .unwrap();

                match cli.command {
                    Commands::SeedRandom { pin, seed, .. } => {
                        assert_eq!(pin, "env-user-pin");
                        assert_eq!(seed, "env-seed-data");
                    }
                    _ => panic!("expected seed-random command"),
                }
            },
        );
    }

    #[test]
    fn version_flag_reports_package_version_without_requiring_command() {
        let err = match Cli::try_parse_from(["pkcs11-proxy-ng-cli", "--version"]) {
            Ok(_) => panic!("--version should render version and exit early"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        let rendered = err.to_string();
        assert!(
            rendered.contains(env!("CARGO_PKG_VERSION")),
            "version output should include crate version: {rendered}"
        );
    }
}

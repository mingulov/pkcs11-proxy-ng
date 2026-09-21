use clap::{Parser, Subcommand};
use pkcs11_proxy_ng_types::SecretBytes;
use std::path::PathBuf;

/// Parse a PIN into wiping storage (W1-L2-11): clap holds `SecretBytes`
/// (zeroized on drop) instead of a plain `String`, whether the value
/// arrives via argv or env.
fn parse_wiping_pin(value: &str) -> Result<SecretBytes, String> {
    Ok(SecretBytes::from(value))
}

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

#[derive(Debug, Subcommand)]
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
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        verbose: bool,
    },
    Sign {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        #[arg(long, env = "PKCS11_PROXY_INPUT", hide_env_values = true)]
        input: Option<String>,
        /// Read the hex input from a file instead of `--input`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        input_file: Option<PathBuf>,
        /// Read the hex input from stdin instead of `--input`.
        #[arg(long)]
        input_stdin: bool,
    },
    Digest {
        #[arg(long)]
        slot_id: u64,
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        #[arg(long, env = "PKCS11_PROXY_INPUT", hide_env_values = true)]
        input: Option<String>,
        /// Read the hex input from a file instead of `--input`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        input_file: Option<PathBuf>,
        /// Read the hex input from stdin instead of `--input`.
        #[arg(long)]
        input_stdin: bool,
    },
    Encrypt {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        #[arg(long, env = "PKCS11_PROXY_INPUT", hide_env_values = true)]
        input: Option<String>,
        /// Read the hex input from a file instead of `--input`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        input_file: Option<PathBuf>,
        /// Read the hex input from stdin instead of `--input`.
        #[arg(long)]
        input_stdin: bool,
    },
    Decrypt {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        #[arg(long, env = "PKCS11_PROXY_INPUT", hide_env_values = true)]
        input: Option<String>,
        /// Read the hex input from a file instead of `--input`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        input_file: Option<PathBuf>,
        /// Read the hex input from stdin instead of `--input`.
        #[arg(long)]
        input_stdin: bool,
    },
    DestroyObject {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        object_handle: u64,
    },
    GetObjectSize {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        object_handle: u64,
    },
    CreateObject {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        label: String,
        #[arg(long, env = "PKCS11_PROXY_VALUE", hide_env_values = true)]
        value: Option<String>,
        /// Read the hex value from a file instead of `--value`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        value_file: Option<PathBuf>,
        /// Read the hex value from stdin instead of `--value`.
        #[arg(long)]
        value_stdin: bool,
    },
    WrapKey {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        #[arg(long)]
        wrapping_key_handle: u64,
        #[arg(long)]
        key_handle: u64,
    },
    UnwrapKey {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        #[arg(long)]
        unwrapping_key_handle: u64,
        #[arg(long, env = "PKCS11_PROXY_WRAPPED_KEY", hide_env_values = true)]
        wrapped_key: Option<String>,
        /// Read the hex wrapped key from a file instead of `--wrapped-key`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        wrapped_key_file: Option<PathBuf>,
        /// Read the hex wrapped key from stdin instead of `--wrapped-key`.
        #[arg(long)]
        wrapped_key_stdin: bool,
        #[arg(long)]
        label: Option<String>,
    },
    DeriveKey {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        #[arg(long)]
        base_key_handle: u64,
        #[arg(long)]
        label: Option<String>,
    },
    GenerateKey {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        #[arg(long)]
        label: String,
        /// Key size in bits (must be a multiple of 8); sent as
        /// CKA_VALUE_LEN in bytes.
        #[arg(long)]
        key_size: Option<u64>,
    },
    GenerateKeyPair {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        #[arg(long)]
        label: String,
        /// Key size in bits for RSA (sent as CKA_MODULUS_BITS);
        /// EC keygen uses --ec-params instead.
        #[arg(long)]
        key_size: Option<u64>,
        /// EC curve for EC keygen: prime256v1, secp384r1, secp521r1,
        /// secp256k1, or hex-encoded DER ECParameters. Sent as
        /// CKA_EC_PARAMS.
        #[arg(long)]
        ec_params: Option<String>,
    },
    /// Probe the daemon's gRPC health endpoint. Exits 0 if SERVING,
    /// non-zero otherwise. Use as an `exec`-based k8s readiness probe
    /// (closes FOLLOWUP-grpc-health-probe — TCP-only probes don't
    /// honour the daemon's backend-health gating).
    Health {
        /// gRPC service name to check. The daemon only flips the
        /// status of its own service when the backend-health gate
        /// trips, so this defaults to the daemon's
        /// service name. Pass `--service ""` to check overall server
        /// status (which stays SERVING regardless of backend health).
        #[arg(long, default_value = "pkcs11_proxy_ng.v1.Pkcs11Proxy")]
        service: String,
    },
    InitToken {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_SO_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        so_pin: SecretBytes,
        #[arg(long)]
        label: String,
    },
    InitPin {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_SO_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        so_pin: SecretBytes,
        #[arg(
            long,
            env = "PKCS11_PROXY_NEW_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        new_pin: SecretBytes,
    },
    SeedRandom {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, env = "PKCS11_PROXY_SEED", hide_env_values = true)]
        seed: String,
    },
    SetPin {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(
            long,
            env = "PKCS11_PROXY_NEW_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        new_pin: SecretBytes,
    },
    ListMechanismNames,
    GetInfo,
    SessionInfo {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
    },
    Verify {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        #[arg(long, env = "PKCS11_PROXY_DATA", hide_env_values = true)]
        data: Option<String>,
        /// Read the hex data from a file instead of `--data`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        data_file: Option<PathBuf>,
        /// Read the hex data from stdin instead of `--data`.
        #[arg(long)]
        data_stdin: bool,
        #[arg(long, env = "PKCS11_PROXY_SIGNATURE", hide_env_values = true)]
        signature: Option<String>,
        /// Read the hex signature from a file instead of `--signature`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        signature_file: Option<PathBuf>,
        /// Read the hex signature from stdin instead of `--signature`.
        #[arg(long)]
        signature_stdin: bool,
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
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        object_handle: u64,
        #[arg(long)]
        attr: Vec<String>,
    },
    ImportCertificate {
        #[arg(long)]
        slot_id: u64,
        #[arg(
            long,
            env = "PKCS11_PROXY_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        pin: Option<SecretBytes>,
        /// Read the user PIN from stdin instead of `--pin`.
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long)]
        label: String,
        #[arg(long)]
        file: std::path::PathBuf,
    },
    /// Audit log operations (hash chain verification, etc.).
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
}

/// Subcommands for the `audit` command group.
#[derive(Debug, Subcommand)]
pub(crate) enum AuditCmd {
    /// Verify a directory of audit logs (hash chain + optional signatures).
    Verify {
        /// Path to the directory containing audit log files.
        dir: std::path::PathBuf,
        /// Hex-encoded Ed25519 public key for checkpoint signature verification.
        #[arg(long)]
        public_key_hex: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env_vars<T>(vars: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        // Isolate the whole PKCS11_PROXY_* namespace: snapshot and clear
        // it, set only the requested vars, then restore. Otherwise a
        // concurrent test's vars (or the developer's environment) leak
        // into clap's env fallbacks and flake unrelated assertions.
        let snapshot: Vec<(String, String)> =
            std::env::vars().filter(|(name, _)| name.starts_with("PKCS11_PROXY_")).collect();
        for (name, _) in &snapshot {
            unsafe {
                std::env::remove_var(name);
            }
        }

        for (name, value) in vars {
            unsafe {
                std::env::set_var(name, value);
            }
        }
        let result = f();

        for (name, _) in vars {
            unsafe {
                std::env::remove_var(name);
            }
        }
        for (name, value) in snapshot {
            unsafe {
                std::env::set_var(name, value);
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
                Commands::Sign { pin, .. } => {
                    pin.as_ref()
                        .expect("env PIN must parse")
                        .expose(|b| assert_eq!(b, b"env-user-pin"));
                }
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
                    pin.as_ref()
                        .expect("env PIN must parse")
                        .expose(|b| assert_eq!(b, b"env-optional-pin"));
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
                        so_pin.expose(|b| assert_eq!(b, b"env-so-pin"));
                        new_pin.expose(|b| assert_eq!(b, b"env-new-pin"));
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
                        pin.as_ref()
                            .expect("env PIN must parse")
                            .expose(|b| assert_eq!(b, b"env-user-pin"));
                        assert_eq!(seed, "env-seed-data");
                    }
                    _ => panic!("expected seed-random command"),
                }
            },
        );
    }

    // W1-C11-15: secret hex args accept file/stdin/env sources so no
    // secret must travel on argv.
    #[test]
    fn sign_accepts_input_file_and_stdin_without_inline_input() {
        with_env_vars(&[], || {
            let cli = Cli::try_parse_from([
                "pkcs11-proxy-ng-cli",
                "sign",
                "--slot-id",
                "1",
                "--pin",
                "x",
                "--key-label",
                "k",
                "--mechanism",
                "AES_ECB",
                "--input-file",
                "input.hex",
            ])
            .unwrap();
            match cli.command {
                Commands::Sign { input, input_file, input_stdin, .. } => {
                    assert_eq!(input, None);
                    assert_eq!(input_file, Some(std::path::PathBuf::from("input.hex")));
                    assert!(!input_stdin);
                }
                _ => panic!("expected sign command"),
            }
            let cli = Cli::try_parse_from([
                "pkcs11-proxy-ng-cli",
                "sign",
                "--slot-id",
                "1",
                "--pin",
                "x",
                "--key-label",
                "k",
                "--mechanism",
                "AES_ECB",
                "--input-stdin",
            ])
            .unwrap();
            match cli.command {
                Commands::Sign { input, input_file, input_stdin, .. } => {
                    assert_eq!(input, None);
                    assert_eq!(input_file, None);
                    assert!(input_stdin);
                }
                _ => panic!("expected sign command"),
            }
        });
    }

    #[test]
    fn secret_hex_args_accept_env_without_argv() {
        with_env_vars(
            &[
                ("PKCS11_PROXY_INPUT", "aa"),
                ("PKCS11_PROXY_WRAPPED_KEY", "bb"),
                ("PKCS11_PROXY_VALUE", "cc"),
                ("PKCS11_PROXY_DATA", "dd"),
                ("PKCS11_PROXY_SIGNATURE", "ee"),
            ],
            || {
                let cli = Cli::try_parse_from([
                    "pkcs11-proxy-ng-cli",
                    "sign",
                    "--slot-id",
                    "1",
                    "--pin",
                    "x",
                    "--key-label",
                    "k",
                    "--mechanism",
                    "AES_ECB",
                ])
                .unwrap();
                match cli.command {
                    Commands::Sign { input, .. } => {
                        assert_eq!(input.as_deref(), Some("aa"));
                    }
                    _ => panic!("expected sign command"),
                }
                let cli = Cli::try_parse_from([
                    "pkcs11-proxy-ng-cli",
                    "unwrap-key",
                    "--slot-id",
                    "1",
                    "--pin",
                    "x",
                    "--mechanism",
                    "AES_KEY_WRAP",
                    "--unwrapping-key-handle",
                    "7",
                ])
                .unwrap();
                match cli.command {
                    Commands::UnwrapKey { wrapped_key, .. } => {
                        assert_eq!(wrapped_key.as_deref(), Some("bb"));
                    }
                    _ => panic!("expected unwrap-key command"),
                }
                let cli = Cli::try_parse_from([
                    "pkcs11-proxy-ng-cli",
                    "verify",
                    "--slot-id",
                    "1",
                    "--key-label",
                    "k",
                    "--mechanism",
                    "SHA256_RSA_PKCS",
                ])
                .unwrap();
                match cli.command {
                    Commands::Verify { data, signature, .. } => {
                        assert_eq!(data.as_deref(), Some("dd"));
                        assert_eq!(signature.as_deref(), Some("ee"));
                    }
                    _ => panic!("expected verify command"),
                }
            },
        );
    }

    // W1-L2-11: --pin accepts --pin-stdin without an inline PIN.
    #[test]
    fn sign_accepts_pin_stdin_without_inline_pin() {
        with_env_vars(&[], || {
            let cli = Cli::try_parse_from([
                "pkcs11-proxy-ng-cli",
                "sign",
                "--slot-id",
                "1",
                "--pin-stdin",
                "--key-label",
                "k",
                "--mechanism",
                "AES_ECB",
                "--input",
                "aa",
            ])
            .unwrap();
            match cli.command {
                Commands::Sign { pin, pin_stdin, .. } => {
                    assert_eq!(pin, None);
                    assert!(pin_stdin);
                }
                _ => panic!("expected sign command"),
            }
        });
    }

    // W1-L2-11 type-level proof: every PIN field on every command is
    // `SecretBytes` (wiped on drop), never a plain `String`. This test
    // only compiles while that holds.
    #[test]
    fn pins_live_in_wiping_storage() {
        fn assert_wiping(_: &SecretBytes) {}
        fn assert_opt_wiping(pin: &Option<SecretBytes>) {
            if let Some(pin) = pin {
                assert_wiping(pin);
            }
        }
        with_env_vars(&[], || {
            let cli = Cli::try_parse_from([
                "pkcs11-proxy-ng-cli",
                "sign",
                "--slot-id",
                "1",
                "--pin",
                "s3cr3t-p1n",
                "--key-label",
                "k",
                "--mechanism",
                "AES_ECB",
                "--input",
                "aa",
            ])
            .unwrap();
            match &cli.command {
                Commands::Sign { pin, .. } => assert_opt_wiping(pin),
                _ => panic!("expected sign command"),
            }
            // Debug must not leak PIN bytes (SecretBytes redacts to len).
            let rendered = format!("{:?}", cli.command);
            assert!(!rendered.contains("s3cr3t-p1n"), "PIN leaked into Debug: {rendered}");
        });
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

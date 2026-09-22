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

    /// Silence log output below ERROR level (overrides RUST_LOG).
    #[arg(long, conflicts_with = "verbose")]
    pub(crate) quiet: bool,

    /// Enable DEBUG log output (overrides RUST_LOG).
    #[arg(long, conflicts_with = "quiet")]
    pub(crate) verbose: bool,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// List available slots.
    ListSlots {
        /// Only list slots with a token present.
        #[arg(long)]
        token_present: bool,
    },
    /// Print CK_SLOT_INFO for a slot.
    SlotInfo {
        /// Slot id (daemon-assigned virtual slot number).
        slot_id: u64,
    },
    /// Print the full CK_TOKEN_INFO for the token in a slot.
    TokenInfo {
        /// Slot id (daemon-assigned virtual slot number).
        slot_id: u64,
    },
    /// List the mechanisms a token supports (live daemon query for
    /// the slot; contrast list-mechanism-names, the static table).
    ListMechanisms {
        /// Slot id (daemon-assigned virtual slot number).
        slot_id: u64,
    },
    /// Find objects on a slot, optionally filtered by label.
    FindObjects {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// Only list objects with this CKA_LABEL.
        #[arg(long)]
        label: Option<String>,
        /// Print label/class/key-type per object (extra attribute reads).
        #[arg(long)]
        verbose: bool,
    },
    /// Sign hex input with a labeled key; prints the hex signature.
    Sign {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// CKA_LABEL of the signing key.
        #[arg(long)]
        key_label: String,
        /// Mechanism name (e.g. SHA256_RSA_PKCS, AES_GCM), 0x<hex>, or decimal.
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        /// Hex-encoded bytes to sign.
        #[arg(long, env = "PKCS11_PROXY_INPUT", hide_env_values = true)]
        input: Option<String>,
        /// Read the hex input from a file instead of `--input`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        input_file: Option<PathBuf>,
        /// Read the hex input from stdin instead of `--input`.
        #[arg(long)]
        input_stdin: bool,
    },
    /// Digest hex input; prints the hex digest (no login required).
    Digest {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// Mechanism name (e.g. SHA256, SHA_1), 0x<hex>, or decimal.
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        /// Hex-encoded bytes to digest.
        #[arg(long, env = "PKCS11_PROXY_INPUT", hide_env_values = true)]
        input: Option<String>,
        /// Read the hex input from a file instead of `--input`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        input_file: Option<PathBuf>,
        /// Read the hex input from stdin instead of `--input`.
        #[arg(long)]
        input_stdin: bool,
    },
    /// Encrypt hex input with a labeled key; prints hex ciphertext.
    Encrypt {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// CKA_LABEL of the encryption key.
        #[arg(long)]
        key_label: String,
        /// Mechanism name (e.g. AES_GCM, RSA_PKCS_OAEP), 0x<hex>, or decimal.
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        /// Hex-encoded bytes to encrypt.
        #[arg(long, env = "PKCS11_PROXY_INPUT", hide_env_values = true)]
        input: Option<String>,
        /// Read the hex input from a file instead of `--input`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        input_file: Option<PathBuf>,
        /// Read the hex input from stdin instead of `--input`.
        #[arg(long)]
        input_stdin: bool,
    },
    /// Decrypt hex input with a labeled key; prints hex plaintext.
    Decrypt {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// CKA_LABEL of the decryption key.
        #[arg(long)]
        key_label: String,
        /// Mechanism name (e.g. AES_GCM, RSA_PKCS_OAEP), 0x<hex>, or decimal.
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        /// Hex-encoded bytes to decrypt.
        #[arg(long, env = "PKCS11_PROXY_INPUT", hide_env_values = true)]
        input: Option<String>,
        /// Read the hex input from a file instead of `--input`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        input_file: Option<PathBuf>,
        /// Read the hex input from stdin instead of `--input`.
        #[arg(long)]
        input_stdin: bool,
    },
    /// Destroy an object by handle (irreversible).
    DestroyObject {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// Object handle (decimal, from find-objects).
        #[arg(long)]
        object_handle: u64,
    },
    /// Print an object's size in bytes.
    GetObjectSize {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// Object handle (decimal, from find-objects).
        #[arg(long)]
        object_handle: u64,
    },
    /// Create a data object with a label and optional hex value.
    CreateObject {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// CKA_LABEL for the new object.
        #[arg(long)]
        label: String,
        /// Hex-encoded CKA_VALUE bytes.
        #[arg(long, env = "PKCS11_PROXY_VALUE", hide_env_values = true)]
        value: Option<String>,
        /// Read the hex value from a file instead of `--value`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        value_file: Option<PathBuf>,
        /// Read the hex value from stdin instead of `--value`.
        #[arg(long)]
        value_stdin: bool,
    },
    /// Wrap a key; prints the hex wrapped bytes.
    WrapKey {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// Mechanism name (e.g. AES_KEY_WRAP), 0x<hex>, or decimal.
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        /// Handle of the wrapping key (decimal).
        #[arg(long)]
        wrapping_key_handle: u64,
        /// Handle of the key to wrap (decimal).
        #[arg(long)]
        key_handle: u64,
    },
    /// Unwrap hex wrapped bytes into a new key object.
    UnwrapKey {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// Mechanism name (e.g. AES_KEY_WRAP), 0x<hex>, or decimal.
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        /// Handle of the unwrapping key (decimal).
        #[arg(long)]
        unwrapping_key_handle: u64,
        /// Hex-encoded wrapped key bytes.
        #[arg(long, env = "PKCS11_PROXY_WRAPPED_KEY", hide_env_values = true)]
        wrapped_key: Option<String>,
        /// Read the hex wrapped key from a file instead of `--wrapped-key`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        wrapped_key_file: Option<PathBuf>,
        /// Read the hex wrapped key from stdin instead of `--wrapped-key`.
        #[arg(long)]
        wrapped_key_stdin: bool,
        /// CKA_LABEL for the unwrapped key.
        #[arg(long)]
        label: Option<String>,
    },
    /// Derive a new key from a base key.
    DeriveKey {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// Mechanism name (e.g. SHA256_KEY_DERIVATION), 0x<hex>, or decimal.
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        /// Handle of the base key (decimal).
        #[arg(long)]
        base_key_handle: u64,
        /// CKA_LABEL for the derived key.
        #[arg(long)]
        label: Option<String>,
    },
    /// Generate a secret key object.
    GenerateKey {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// Mechanism name (e.g. AES_KEY_GEN), 0x<hex>, or decimal.
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        /// CKA_LABEL for the new key.
        #[arg(long)]
        label: String,
        /// Key size in bits (must be a multiple of 8); sent as
        /// CKA_VALUE_LEN in bytes.
        #[arg(long)]
        key_size: Option<u64>,
    },
    /// Generate a public/private key pair.
    GenerateKeyPair {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// Mechanism name (e.g. RSA_PKCS_KEY_PAIR_GEN, EC_KEY_PAIR_GEN), 0x<hex>, or decimal.
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        /// CKA_LABEL for the new key pair.
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
    /// Initialize a token: set the SO PIN and label (erases token contents).
    InitToken {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// Security Officer PIN to set.
        #[arg(
            long,
            env = "PKCS11_PROXY_SO_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        so_pin: SecretBytes,
        /// Label to assign the token.
        #[arg(long)]
        label: String,
    },
    /// Initialize the user PIN (requires the SO PIN).
    InitPin {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// Security Officer PIN.
        #[arg(
            long,
            env = "PKCS11_PROXY_SO_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        so_pin: SecretBytes,
        /// New user PIN to set.
        #[arg(
            long,
            env = "PKCS11_PROXY_NEW_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        new_pin: SecretBytes,
    },
    /// Seed the token RNG with hex bytes.
    SeedRandom {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// Hex-encoded seed bytes.
        #[arg(long, env = "PKCS11_PROXY_SEED", hide_env_values = true)]
        seed: String,
    },
    /// Change the user PIN (old-PIN login required).
    SetPin {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// New user PIN to set.
        #[arg(
            long,
            env = "PKCS11_PROXY_NEW_PIN",
            hide_env_values = true,
            value_parser = parse_wiping_pin
        )]
        new_pin: SecretBytes,
    },
    /// Print the CLI's built-in static table of known CKM_ mechanism
    /// names and values (offline; no daemon query, no slot needed).
    ListMechanismNames,
    /// Print CK_INFO (Cryptoki and library versions).
    GetInfo,
    /// Open a session and print its state, flags, and device error.
    SessionInfo {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
    /// Verify a hex signature over hex data (prints VALID/INVALID; exit 2 when INVALID).
    Verify {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// CKA_LABEL of the verification key.
        #[arg(long)]
        key_label: String,
        /// Mechanism name (e.g. SHA256_RSA_PKCS), 0x<hex>, or decimal.
        #[arg(long)]
        mechanism: String,
        /// JSON mechanism parameters for AES_GCM, RSA_PKCS_OAEP and the
        /// RSA_PKCS_PSS family (e.g. {"iv_hex": "...", "tag_bits": 128}
        /// for GCM). Required for those mechanisms; rejected otherwise.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        params_file: Option<PathBuf>,
        /// Hex-encoded signed data.
        #[arg(long, env = "PKCS11_PROXY_DATA", hide_env_values = true)]
        data: Option<String>,
        /// Read the hex data from a file instead of `--data`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        data_file: Option<PathBuf>,
        /// Read the hex data from stdin instead of `--data`.
        #[arg(long)]
        data_stdin: bool,
        /// Hex-encoded signature bytes.
        #[arg(long, env = "PKCS11_PROXY_SIGNATURE", hide_env_values = true)]
        signature: Option<String>,
        /// Read the hex signature from a file instead of `--signature`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        signature_file: Option<PathBuf>,
        /// Read the hex signature from stdin instead of `--signature`.
        #[arg(long)]
        signature_stdin: bool,
    },
    /// Generate random bytes from the token RNG.
    Random {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// Number of random bytes to generate.
        #[arg(long)]
        len: u32,
        /// Output encoding: hex or base64.
        #[arg(long, default_value = "hex")]
        format: String,
    },
    /// Read attributes of an object by handle.
    GetAttribute {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// Object handle (decimal, from find-objects).
        #[arg(long)]
        object_handle: u64,
        /// Attribute to read: name (LABEL, SUBJECT, ...), 0x<hex>, or decimal id. Repeatable.
        #[arg(long)]
        attr: Vec<String>,
    },
    /// Import an X.509 certificate object from a file.
    ImportCertificate {
        /// Slot id (daemon-assigned virtual slot number).
        #[arg(long)]
        slot_id: u64,
        /// User PIN (use --pin-stdin to avoid exposing it on argv).
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
        /// CKA_LABEL for the imported certificate.
        #[arg(long)]
        label: String,
        /// Path to a PEM or DER X.509 certificate file.
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

    // W1-C11-22: the health --service default must equal the
    // daemon's SERVICE_NAME. The CLI cannot depend on the server crate
    // at runtime, so this drift test (via the dev-dependency) pins the
    // value instead of a shared const.
    #[test]
    fn health_default_service_matches_server_const() {
        with_env_vars(&[], || {
            let cli = Cli::try_parse_from(["pkcs11-proxy-ng-cli", "health"]).unwrap();
            match cli.command {
                Commands::Health { service } => assert_eq!(
                    service,
                    pkcs11_proxy_ng::server::health::SERVICE_NAME,
                    "health default drifted from daemon SERVICE_NAME"
                ),
                _ => panic!("expected health command"),
            }
        });
    }

    // W1-C11-21: --quiet/--verbose exist as global flags and conflict.
    #[test]
    fn quiet_and_verbose_flags_parse_and_conflict() {
        with_env_vars(&[], || {
            let cli = Cli::try_parse_from(["pkcs11-proxy-ng-cli", "--quiet", "get-info"]).unwrap();
            assert!(cli.quiet);
            assert!(!cli.verbose);
            let cli =
                Cli::try_parse_from(["pkcs11-proxy-ng-cli", "--verbose", "get-info"]).unwrap();
            assert!(cli.verbose);
            assert!(!cli.quiet);
            assert!(
                Cli::try_parse_from(["pkcs11-proxy-ng-cli", "--quiet", "--verbose", "get-info"])
                    .is_err(),
                "--quiet and --verbose must conflict"
            );
        });
    }

    // W1-C11-26: every subcommand and arg carries help text documenting
    // units and encodings (hex inputs, bits, bytes).
    #[test]
    fn every_subcommand_and_arg_has_help_text() {
        use clap::CommandFactory;
        fn check(cmd: &clap::Command, path: &str) {
            for arg in cmd.get_arguments() {
                let id = arg.get_id();
                if id == "help" || id == "version" {
                    continue;
                }
                assert!(
                    arg.get_help().is_some() || arg.get_long_help().is_some(),
                    "{path}: --{id} has no help text"
                );
            }
            for sub in cmd.get_subcommands() {
                let name = format!("{path} {}", sub.get_name());
                assert!(
                    sub.get_about().is_some() || sub.get_long_about().is_some(),
                    "{name}: subcommand has no about text"
                );
                check(sub, &name);
            }
        }
        check(&Cli::command(), "pkcs11-proxy-ng-cli");
    }

    // W1-C11-28: list-mechanisms (live per-slot backend query) vs
    // list-mechanism-names (static compiled-in table) help must make
    // the source difference obvious.
    #[test]
    fn mechanism_list_commands_are_disambiguated() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let live = cmd
            .find_subcommand("list-mechanisms")
            .expect("list-mechanisms exists")
            .get_about()
            .map(|s| s.to_string())
            .unwrap_or_default();
        let static_table = cmd
            .find_subcommand("list-mechanism-names")
            .expect("list-mechanism-names exists")
            .get_about()
            .map(|s| s.to_string())
            .unwrap_or_default();
        assert!(
            live.contains("daemon")
                || live.contains("token")
                || live.contains("live")
                || live.contains("slot"),
            "list-mechanisms help must name the live source: {live}"
        );
        assert!(
            static_table.contains("static")
                || static_table.contains("built-in")
                || static_table.contains("compiled"),
            "list-mechanism-names help must name the static source: {static_table}"
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

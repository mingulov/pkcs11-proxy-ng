// W1-L12-03: the CLI's whole job is user output on stdout/stderr
// (allowed once at the bin root, covering `handlers/`); secret display
// itself is W1-L2-12 (P3), not this gate.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use clap::{CommandFactory, FromArgMatches};
use pkcs11_proxy_ng_client::{Pkcs11Client, tls::ClientTlsFiles};
use tracing_subscriber::EnvFilter;

mod cli;
mod handlers;
mod mech_params;
mod mechanisms;
mod pkcs11_names;
mod secrets;

use cli::{AuditCmd, Cli, Commands};
use handlers::run_command;
use mechanisms::MECHANISM_NAMES;

/// Build the gRPC endpoint for the `health` probe.
///
/// `tls_files` carries the daemon TLS material from the `--tls-*` flags
/// (`None` = plaintext). The probe must present TLS whenever the flags do,
/// otherwise it fails against a TLS-gated daemon.
fn build_health_endpoint(
    endpoint: &str,
    tls_files: Option<ClientTlsFiles>,
) -> Result<tonic::transport::Endpoint, String> {
    let mut builder = tonic::transport::Endpoint::from_shared(endpoint.to_owned())
        .map_err(|e| format!("invalid endpoint: {e}"))?
        .connect_timeout(std::time::Duration::from_secs(2));
    if let Some(tls_files) = tls_files {
        builder = builder
            .tls_config(tls_files.into_tonic_config()?)
            .map_err(|e| format!("invalid TLS config: {e}"))?;
    }
    Ok(builder)
}

/// Resolve the CLI log filter directive (W1-C11-21):
/// `--quiet`/`--verbose` override `RUST_LOG`; otherwise `RUST_LOG` wins;
/// unset falls back to `"info"` (matching the daemon default).
fn resolve_log_directive(quiet: bool, verbose: bool, rust_log: Option<&str>) -> String {
    if quiet {
        "error".to_string()
    } else if verbose {
        "debug".to_string()
    } else {
        rust_log.unwrap_or("info").to_string()
    }
}

/// Install tracing with `RUST_LOG` honored (W1-C11-21): same shape as
/// the daemon's `init_tracing` (`EnvFilter`, `"info"` default, loud
/// warning on a set-but-invalid `RUST_LOG`), plus `--quiet`/`--verbose`
/// overrides. Logs go to stderr so stdout stays plumbable.
#[allow(clippy::print_stderr)]
fn init_logging(cli: &Cli) {
    let rust_log_raw = std::env::var("RUST_LOG").ok();
    let directive = resolve_log_directive(cli.quiet, cli.verbose, rust_log_raw.as_deref());
    let filter = match EnvFilter::try_new(&directive) {
        Ok(filter) => filter,
        Err(_) => {
            // Only reachable via a set-but-invalid RUST_LOG (flag
            // directives are constants): warn loudly, fall back to info.
            if let Some(value) = rust_log_raw.as_deref() {
                eprintln!(
                    "pkcs11-proxy-ng-cli: RUST_LOG={value:?} is not a valid tracing filter; \
                     using default \"info\""
                );
            }
            EnvFilter::new("info")
        }
    };
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn core::error::Error>> {
    // T14: parse through `ArgMatches` so explicit-argv secret metadata
    // (`SecretOrigins`) is captured during clap parsing (`--help` /
    // `--version` / parse errors behave exactly as `Cli::parse`).
    let raw_matches = Cli::command().get_matches();
    let origins = secrets::SecretOrigins::from_subcommand_matches(
        raw_matches.subcommand().map(|(_, sub)| sub),
    );
    let cli = Cli::from_arg_matches(&raw_matches).unwrap_or_else(|e| e.exit());
    init_logging(&cli);

    if let Commands::Audit { cmd: AuditCmd::Verify { dir, public_key_hex } } = &cli.command {
        return handlers::audit::verify(dir, public_key_hex.as_deref());
    }

    if let Commands::ListMechanismNames = &cli.command {
        println!("{:<12}  Name", "Value");
        println!("{}", "-".repeat(50));
        for (val, name) in MECHANISM_NAMES {
            println!("0x{val:08X}  {name}");
        }
        return Ok(());
    }

    // FOLLOWUP-grpc-health-probe: a no-side-effects health check that
    // honours the daemon's backend-health gating (the daemon registers
    // its main service and flips NOT_SERVING on N consecutive backend
    // failures). Exits 0 if SERVING, 1 if NOT_SERVING, 2 if the probe
    // itself fails, so k8s exec probes (and scripts) can interpret.
    if let Commands::Health { service } = &cli.command {
        use tonic_health::pb::HealthCheckRequest;
        use tonic_health::pb::health_check_response::ServingStatus;
        use tonic_health::pb::health_client::HealthClient;
        let tls_files = match ClientTlsFiles::from_optional_paths(
            cli.tls_ca_cert.clone(),
            cli.tls_client_cert.clone(),
            cli.tls_client_key.clone(),
            cli.tls_domain.clone(),
        )
        .map_err(|e| format!("invalid TLS flags: {e}"))
        {
            Ok(tls_files) => tls_files,
            Err(e) => {
                eprintln!("health probe setup failed: {e}");
                std::process::exit(2);
            }
        };
        let endpoint = match build_health_endpoint(&cli.endpoint, tls_files) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                eprintln!("health probe setup failed: {e}");
                std::process::exit(2);
            }
        };
        let channel = match endpoint.connect().await {
            Ok(channel) => channel,
            Err(e) => {
                eprintln!("health probe connection failed: {e}");
                std::process::exit(2);
            }
        };
        let mut hc = HealthClient::new(channel);
        let resp = match hc.check(HealthCheckRequest { service: service.clone() }).await {
            Ok(resp) => resp.into_inner(),
            Err(e) => {
                eprintln!("health probe check failed: {e}");
                std::process::exit(2);
            }
        };
        let status = ServingStatus::try_from(resp.status).unwrap_or(ServingStatus::Unknown);
        if status == ServingStatus::Serving {
            println!("SERVING");
            return Ok(());
        }
        if status == ServingStatus::NotServing {
            eprintln!("NOT_SERVING");
        } else {
            eprintln!("health probe indeterminate: {status:?}");
        }
        std::process::exit(health_exit_code(status));
    }

    let tls_files = ClientTlsFiles::from_optional_paths(
        cli.tls_ca_cert.clone(),
        cli.tls_client_cert.clone(),
        cli.tls_client_key.clone(),
        cli.tls_domain.clone(),
    )?;
    let mut client = match tls_files {
        Some(tls_files) => Pkcs11Client::connect_with_tls_files(&cli.endpoint, tls_files).await,
        None => Pkcs11Client::connect(&cli.endpoint).await,
    }
    .map_err(|e| format!("Connection failed: {e}"))?;
    client.initialize().await.map_err(crate::handlers::cli_err("C_Initialize"))?;

    let result = run_command(&mut client, cli.command, &origins).await;

    let _ = client.finalize().await;

    // W1-C11-12: signature-INVALID exits 2 (after finalize) so scripts
    // can distinguish it from generic failures (exit 1). The handler
    // already printed the verdict and released its session.
    if let Err(err) = &result
        && let Some(code) = exit_code_for_error(err.as_ref())
    {
        std::process::exit(code);
    }

    result
}

/// Map a CLI error to an explicit process exit code (W1-C11-12):
/// `VerifyInvalid` → 2; anything else → `None` (the runtime reports
/// `Err` with exit code 1).
fn exit_code_for_error(err: &(dyn core::error::Error + 'static)) -> Option<i32> {
    if err.downcast_ref::<handlers::VerifyInvalid>().is_some() { Some(2) } else { None }
}

/// Map a gRPC health status to the documented probe exit code
/// (W1-C11-19): 0 = SERVING, 1 = the daemon answered NOT_SERVING, 2 =
/// indeterminate (UNKNOWN/SERVICE_UNKNOWN — a probe failure, not a
/// verdict, like a transport error).
fn health_exit_code(status: tonic_health::pb::health_check_response::ServingStatus) -> i32 {
    use tonic_health::pb::health_check_response::ServingStatus;
    match status {
        ServingStatus::Serving => 0,
        ServingStatus::NotServing => 1,
        ServingStatus::Unknown | ServingStatus::ServiceUnknown => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_health_endpoint, exit_code_for_error, health_exit_code, resolve_log_directive,
    };
    use pkcs11_proxy_ng_client::tls::ClientTlsFiles;
    use std::path::PathBuf;

    // W1-C11-21: RUST_LOG controls CLI verbosity; --quiet/--verbose
    // override it; unset falls back to "info" (daemon-matching).
    #[test]
    fn log_directive_honors_rust_log_with_flag_overrides() {
        assert_eq!(resolve_log_directive(false, false, None), "info");
        assert_eq!(resolve_log_directive(false, false, Some("debug")), "debug");
        assert_eq!(
            resolve_log_directive(false, false, Some("pkcs11_proxy_ng_cli=trace")),
            "pkcs11_proxy_ng_cli=trace"
        );
        assert_eq!(resolve_log_directive(true, false, Some("debug")), "error");
        assert_eq!(resolve_log_directive(false, true, Some("warn")), "debug");
        assert_eq!(resolve_log_directive(true, false, None), "error");
        assert_eq!(resolve_log_directive(false, true, None), "debug");
    }

    // W1-C11-12: signature-INVALID exits 2 (distinct from generic
    // failures, which exit 1 via the runtime).
    #[test]
    fn verify_invalid_maps_to_exit_2() {
        let invalid: Box<dyn core::error::Error> = Box::new(crate::handlers::VerifyInvalid);
        assert_eq!(exit_code_for_error(invalid.as_ref()), Some(2));
        let generic: Box<dyn core::error::Error> = std::io::Error::other("boom").into();
        assert_eq!(exit_code_for_error(generic.as_ref()), None);
    }

    // W1-C11-19: the health probe exits 0 when SERVING, 1 when the
    // daemon answers NOT_SERVING, and 2 when the probe itself is
    // indeterminate (UNKNOWN/SERVICE_UNKNOWN) or fails.
    #[test]
    fn health_exit_code_pins_all_statuses() {
        use tonic_health::pb::health_check_response::ServingStatus;
        assert_eq!(health_exit_code(ServingStatus::Serving), 0);
        assert_eq!(health_exit_code(ServingStatus::NotServing), 1);
        assert_eq!(health_exit_code(ServingStatus::Unknown), 2);
        assert_eq!(health_exit_code(ServingStatus::ServiceUnknown), 2);
    }

    #[test]
    fn health_endpoint_without_tls_flags_stays_plaintext() {
        let endpoint = build_health_endpoint("http://127.0.0.1:7512", None).unwrap();
        assert_eq!(
            endpoint.uri(),
            &"http://127.0.0.1:7512".parse::<tonic::transport::Uri>().unwrap()
        );
    }

    #[test]
    fn health_endpoint_with_tls_flags_consults_flag_material() {
        // TLS material that cannot load must fail the probe setup: a probe
        // that silently ignored `--tls-*` would return Ok here.
        let tls_files = ClientTlsFiles {
            ca_cert: PathBuf::from("/nonexistent/ca.pem"),
            client_cert: PathBuf::from("/nonexistent/client.pem"),
            client_key: PathBuf::from("/nonexistent/client-key.pem"),
            domain_name: Some("localhost".to_string()),
        };
        let err = build_health_endpoint("https://127.0.0.1:7512", Some(tls_files))
            .expect_err("health probe must honor --tls-* flags");
        assert!(err.contains("ca.pem"), "unexpected error: {err}");
    }

    #[test]
    fn health_endpoint_with_valid_tls_material_builds() {
        let dir = tempfile::tempdir().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "test");
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        let ca_path = dir.path().join("ca.pem");
        let client_cert_path = dir.path().join("client.pem");
        let client_key_path = dir.path().join("client-key.pem");
        std::fs::write(&ca_path, &cert_pem).unwrap();
        std::fs::write(&client_cert_path, &cert_pem).unwrap();
        std::fs::write(&client_key_path, &key_pem).unwrap();
        let tls_files = ClientTlsFiles {
            ca_cert: ca_path,
            client_cert: client_cert_path,
            client_key: client_key_path,
            domain_name: Some("localhost".to_string()),
        };
        build_health_endpoint("https://127.0.0.1:7512", Some(tls_files)).unwrap();
    }
}

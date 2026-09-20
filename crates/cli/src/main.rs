use clap::Parser;
use pkcs11_proxy_ng_client::{Pkcs11Client, tls::ClientTlsFiles};

mod cli;
mod handlers;
mod mechanisms;
mod pkcs11_names;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn core::error::Error>> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

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
    // failures). Exits 0/1/2 so k8s exec probes can interpret.
    if let Commands::Health { service } = &cli.command {
        use tonic_health::pb::HealthCheckRequest;
        use tonic_health::pb::health_check_response::ServingStatus;
        use tonic_health::pb::health_client::HealthClient;
        let tls_files = ClientTlsFiles::from_optional_paths(
            cli.tls_ca_cert.clone(),
            cli.tls_client_cert.clone(),
            cli.tls_client_key.clone(),
            cli.tls_domain.clone(),
        )
        .map_err(|e| format!("invalid TLS flags: {e}"))?;
        let channel = build_health_endpoint(&cli.endpoint, tls_files)
            .map_err(|e| format!("health probe setup failed: {e}"))?
            .connect()
            .await?;
        let mut hc = HealthClient::new(channel);
        let resp = hc.check(HealthCheckRequest { service: service.clone() }).await?.into_inner();
        let status = ServingStatus::try_from(resp.status).unwrap_or(ServingStatus::Unknown);
        match status {
            ServingStatus::Serving => {
                println!("SERVING");
                return Ok(());
            }
            other => {
                eprintln!("NOT_SERVING: {other:?}");
                std::process::exit(1);
            }
        }
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

    let result = run_command(&mut client, cli.command).await;

    let _ = client.finalize().await;

    result
}

#[cfg(test)]
mod tests {
    use super::build_health_endpoint;
    use pkcs11_proxy_ng_client::tls::ClientTlsFiles;
    use std::path::PathBuf;

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

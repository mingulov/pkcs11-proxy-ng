use clap::Parser;
use pkcs11_proxy_ng_client::{Pkcs11Client, tls::ClientTlsFiles};

mod cli;
mod handlers;
mod mechanisms;
mod pkcs11_names;

use cli::{Cli, Commands};
use handlers::run_command;
use mechanisms::MECHANISM_NAMES;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    if let Commands::ListMechanismNames = &cli.command {
        println!("{:<12}  Name", "Value");
        println!("{}", "-".repeat(50));
        for (val, name) in MECHANISM_NAMES {
            println!("0x{val:08X}  {name}");
        }
        return Ok(());
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
    client.initialize().await.map_err(|e| format!("C_Initialize failed: CKR 0x{:08X}", e.0))?;

    let result = run_command(&mut client, cli.command).await;

    let _ = client.finalize().await;

    result
}

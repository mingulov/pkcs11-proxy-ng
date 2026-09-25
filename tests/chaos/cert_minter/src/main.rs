//! Sub-day cert minter for chaos scenario 6.
//!
//! Replaces the day-granular `openssl x509 -days N` invocation in
//! `scenario6_tls_cert_expiry.sh` so the scenario can observe an
//! actual expiry transition within its 90-second probe window.
//!
//! Writes six PEM files into `--out-dir`:
//! `ca.crt`, `ca.key`, `server.crt`, `server.key`,
//! `client.crt`, `client.key`. The server key file is `chmod 0600`
//! to satisfy the mTLS-private-key permissions check.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use time::{Duration, OffsetDateTime};

#[derive(Parser)]
#[command(about = "Mint CA + server (short-lived) + client cert chain for chaos scenario 6.")]
struct Cli {
    /// Where to write the six PEM files. Must already exist.
    #[arg(long)]
    out_dir: PathBuf,

    /// Server cert lifetime in seconds, measured from now.
    #[arg(long, default_value = "15")]
    server_expires_in_seconds: i64,

    /// Client cert lifetime in seconds.
    #[arg(long, default_value = "600")]
    client_expires_in_seconds: i64,

    /// CA cert lifetime in seconds.
    #[arg(long, default_value = "3600")]
    ca_expires_in_seconds: i64,

    /// Server SAN DNS names (comma-separated).
    #[arg(long, default_value = "chaos-daemon,localhost")]
    server_dns: String,

    /// Server SAN IPv4 (comma-separated).
    #[arg(long, default_value = "127.0.0.1")]
    server_ip: String,
}

fn main() -> Result<()> {
    let args = Cli::parse();
    let now = OffsetDateTime::now_utc();

    fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("create_dir_all {}", args.out_dir.display()))?;

    let mut ca_params = CertificateParams::new(Vec::new())?;
    ca_params.not_before = now;
    ca_params.not_after = now + Duration::seconds(args.ca_expires_in_seconds);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.distinguished_name.push(DnType::CommonName, "r8-test-ca");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_pem = ca_cert.pem();
    let ca_key_pem = ca_key.serialize_pem();
    // rcgen 0.14 signs via an Issuer handle instead of (cert, key) pairs.
    let ca_issuer = Issuer::from_params(&ca_params, ca_key);

    let server_sans = build_sans(&args.server_dns, &args.server_ip)?;
    let mut server_params = CertificateParams::new(Vec::new())?;
    server_params.subject_alt_names = server_sans;
    server_params.not_before = now;
    server_params.not_after = now + Duration::seconds(args.server_expires_in_seconds);
    server_params.distinguished_name = DistinguishedName::new();
    server_params.distinguished_name.push(DnType::CommonName, "chaos-daemon");
    server_params.use_authority_key_identifier_extension = true;
    server_params.key_usages =
        vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    server_params.extended_key_usages =
        vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    let server_key = KeyPair::generate()?;
    let server_cert = server_params.signed_by(&server_key, &ca_issuer)?;

    let mut client_params = CertificateParams::new(Vec::new())?;
    client_params.not_before = now;
    client_params.not_after = now + Duration::seconds(args.client_expires_in_seconds);
    client_params.distinguished_name = DistinguishedName::new();
    client_params.distinguished_name.push(DnType::CommonName, "r8-test-client");
    client_params.use_authority_key_identifier_extension = true;
    client_params.key_usages =
        vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate()?;
    let client_cert = client_params.signed_by(&client_key, &ca_issuer)?;

    write_pem(&args.out_dir, "ca.crt", &ca_pem, 0o644)?;
    write_pem(&args.out_dir, "ca.key", &ca_key_pem, 0o600)?;
    write_pem(&args.out_dir, "server.crt", &server_cert.pem(), 0o644)?;
    write_pem(&args.out_dir, "server.key", &server_key.serialize_pem(), 0o600)?;
    write_pem(&args.out_dir, "client.crt", &client_cert.pem(), 0o644)?;
    write_pem(&args.out_dir, "client.key", &client_key.serialize_pem(), 0o600)?;

    let server_expiry = now + Duration::seconds(args.server_expires_in_seconds);
    println!("ca expires:     {}", now + Duration::seconds(args.ca_expires_in_seconds));
    println!("server expires: {server_expiry}  (in {} s)", args.server_expires_in_seconds);
    println!("client expires: {}", now + Duration::seconds(args.client_expires_in_seconds));
    Ok(())
}

fn build_sans(dns: &str, ip: &str) -> Result<Vec<SanType>> {
    let mut sans = Vec::new();
    for name in dns.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        sans.push(SanType::DnsName(name.to_owned().try_into()?));
    }
    for addr in ip.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let parsed: Ipv4Addr = addr.parse().with_context(|| format!("parse IPv4 {addr}"))?;
        sans.push(SanType::IpAddress(IpAddr::V4(parsed)));
    }
    Ok(sans)
}

fn write_pem(dir: &PathBuf, name: &str, pem: &str, mode: u32) -> Result<()> {
    let path = dir.join(name);
    fs::write(&path, pem).with_context(|| format!("write {}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

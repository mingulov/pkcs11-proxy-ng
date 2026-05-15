use std::path::Path;
use std::time::Duration;

use tonic::transport::{Certificate, Identity, ServerTlsConfig};

use crate::config::{TcpAuthMode, TcpListenerConfig};

pub fn server_tls_config(tcp: &TcpListenerConfig) -> Result<Option<ServerTlsConfig>, String> {
    match tcp.auth {
        TcpAuthMode::None => Ok(None),
        TcpAuthMode::Mtls => {
            let ca = read_required(tcp.ca_cert.as_deref(), "listener.remote.ca_cert")?;
            let cert = read_required(tcp.server_cert.as_deref(), "listener.remote.server_cert")?;
            let key = read_required(tcp.server_key.as_deref(), "listener.remote.server_key")?;

            Ok(Some(
                ServerTlsConfig::new()
                    .identity(Identity::from_pem(cert, key))
                    .client_ca_root(Certificate::from_pem(ca))
                    .timeout(Duration::from_secs(10)),
            ))
        }
    }
}

fn read_required(path: Option<&Path>, field: &str) -> Result<Vec<u8>, String> {
    let path = path.ok_or_else(|| format!("{field} is required"))?;
    std::fs::read(path).map_err(|e| format!("failed to read {field} '{}': {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crate::config::{TcpAuthMode, TcpListenerConfig};

    #[test]
    fn insecure_tcp_has_no_tls_config() {
        let tcp = TcpListenerConfig {
            bind: "127.0.0.1:7512".into(),
            auth: TcpAuthMode::None,
            ca_cert: None,
            server_cert: None,
            server_key: None,
            allow_insecure_tcp: true,
        };

        assert!(super::server_tls_config(&tcp).unwrap().is_none());
    }

    #[test]
    fn mtls_requires_all_certificate_paths() {
        let tcp = TcpListenerConfig {
            bind: "127.0.0.1:7512".into(),
            auth: TcpAuthMode::Mtls,
            ca_cert: None,
            server_cert: None,
            server_key: None,
            allow_insecure_tcp: false,
        };

        let err = super::server_tls_config(&tcp).unwrap_err();
        assert!(err.contains("listener.remote.ca_cert"), "error should name missing CA: {err}");
    }

    #[test]
    fn mtls_reads_certificate_files() {
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        let mut cert = tempfile::NamedTempFile::new().unwrap();
        let mut key = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
        cert.write_all(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
        key.write_all(b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n").unwrap();

        let tcp = TcpListenerConfig {
            bind: "127.0.0.1:7512".into(),
            auth: TcpAuthMode::Mtls,
            ca_cert: Some(ca.path().to_path_buf()),
            server_cert: Some(cert.path().to_path_buf()),
            server_key: Some(key.path().to_path_buf()),
            allow_insecure_tcp: false,
        };

        assert!(super::server_tls_config(&tcp).unwrap().is_some());
    }
}

use std::path::PathBuf;
use std::time::Duration;

use tonic::transport::{Certificate, ClientTlsConfig, Identity};

use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use pkcs11_proxy_ng_types::SecretBytes;

/// Default mTLS handshake timeout (W1-C10-12): 10 s, matching the
/// previously hardcoded value. Override per-connection with
/// [`ClientTlsFiles::into_tonic_config_with_handshake_timeout`].
pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientTlsFiles {
    pub ca_cert: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub domain_name: Option<String>,
}

impl ClientTlsFiles {
    pub fn from_optional_paths(
        ca_cert: Option<PathBuf>,
        client_cert: Option<PathBuf>,
        client_key: Option<PathBuf>,
        domain_name: Option<String>,
    ) -> Result<Option<Self>, String> {
        match (ca_cert, client_cert, client_key) {
            (None, None, None) => Ok(None),
            (Some(ca_cert), Some(client_cert), Some(client_key)) => {
                Ok(Some(Self { ca_cert, client_cert, client_key, domain_name }))
            }
            _ => Err("set PKCS11_PROXY_TLS_CA_CERT, PKCS11_PROXY_TLS_CLIENT_CERT, and \
                 PKCS11_PROXY_TLS_CLIENT_KEY together"
                .into()),
        }
    }

    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_optional_paths(
            std::env::var_os("PKCS11_PROXY_TLS_CA_CERT").map(PathBuf::from),
            std::env::var_os("PKCS11_PROXY_TLS_CLIENT_CERT").map(PathBuf::from),
            std::env::var_os("PKCS11_PROXY_TLS_CLIENT_KEY").map(PathBuf::from),
            std::env::var("PKCS11_PROXY_TLS_DOMAIN").ok(),
        )
    }

    pub fn into_tonic_config(self) -> Result<ClientTlsConfig, String> {
        self.into_tonic_config_with_handshake_timeout(DEFAULT_TLS_HANDSHAKE_TIMEOUT)
    }

    /// Build the tonic TLS config with an explicit handshake timeout
    /// (W1-C10-12 operator knob). [`into_tonic_config`][Self::into_tonic_config]
    /// delegates here with [`DEFAULT_TLS_HANDSHAKE_TIMEOUT`].
    pub fn into_tonic_config_with_handshake_timeout(
        self,
        handshake_timeout: Duration,
    ) -> Result<ClientTlsConfig, String> {
        let ca = std::fs::read(&self.ca_cert).map_err(|e| {
            format!("failed to read PKCS11_PROXY_TLS_CA_CERT '{}': {e}", self.ca_cert.display())
        })?;
        let cert = std::fs::read(&self.client_cert).map_err(|e| {
            format!(
                "failed to read PKCS11_PROXY_TLS_CLIENT_CERT '{}': {e}",
                self.client_cert.display()
            )
        })?;
        // ADR-0013 §5: the PEM key file is adopted into the wiping owner
        // immediately; only the copy forced by tonic's `Vec<u8>` API is
        // plain, built at the call with no retained duplicate. (rustls
        // retains its own parsed copy past this point, outside the wiping
        // guarantee, like tonic/prost transport buffers.)
        let key = SecretBytes::new(std::fs::read(&self.client_key).map_err(|e| {
            format!(
                "failed to read PKCS11_PROXY_TLS_CLIENT_KEY '{}': {e}",
                self.client_key.display()
            )
        })?);

        let mut config = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(cert, secret_to_plain(&key)))
            .timeout(handshake_timeout);
        if let Some(domain_name) = self.domain_name {
            config = config.domain_name(domain_name);
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::ClientTlsFiles;

    #[test]
    fn optional_tls_paths_accept_all_absent() {
        assert!(ClientTlsFiles::from_optional_paths(None, None, None, None).unwrap().is_none());
    }

    #[test]
    fn optional_tls_paths_reject_partial_configuration() {
        let err = ClientTlsFiles::from_optional_paths(
            Some(PathBuf::from("ca.pem")),
            None,
            Some(PathBuf::from("client.key")),
            None,
        )
        .unwrap_err();

        assert!(err.contains("PKCS11_PROXY_TLS_CLIENT_CERT"), "error: {err}");
    }

    /// W1-C10-12: the TLS handshake timeout is an operator knob, not a
    /// hardcoded literal — both constructors build a tonic TLS config
    /// from the same files, the default with the documented 10 s value.
    #[test]
    fn t32_tls_handshake_timeout_is_configurable() {
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("t32-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = dir.join("ca.pem");
        let cert = dir.join("client.pem");
        let key = dir.join("client-key.pem");
        std::fs::write(&ca, b"dummy-ca").unwrap();
        std::fs::write(&cert, b"dummy-cert").unwrap();
        std::fs::write(&key, b"dummy-key").unwrap();
        let files = || ClientTlsFiles {
            ca_cert: ca.clone(),
            client_cert: cert.clone(),
            client_key: key.clone(),
            domain_name: None,
        };
        assert!(files().into_tonic_config().is_ok());
        assert!(files().into_tonic_config_with_handshake_timeout(Duration::from_secs(3)).is_ok());
        assert!(
            files()
                .into_tonic_config_with_handshake_timeout(super::DEFAULT_TLS_HANDSHAKE_TIMEOUT)
                .is_ok()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn optional_tls_paths_accept_complete_configuration() {
        let files = ClientTlsFiles::from_optional_paths(
            Some(PathBuf::from("ca.pem")),
            Some(PathBuf::from("client.pem")),
            Some(PathBuf::from("client.key")),
            Some("localhost".into()),
        )
        .unwrap()
        .expect("complete TLS config should be present");

        assert_eq!(files.ca_cert, PathBuf::from("ca.pem"));
        assert_eq!(files.client_cert, PathBuf::from("client.pem"));
        assert_eq!(files.client_key, PathBuf::from("client.key"));
        assert_eq!(files.domain_name.as_deref(), Some("localhost"));
    }
}

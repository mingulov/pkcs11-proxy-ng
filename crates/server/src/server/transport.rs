use std::path::Path;
use std::time::Duration;

use tonic::transport::{Certificate, Identity, ServerTlsConfig};

use crate::config::{TcpAuthMode, TcpListenerConfig};

pub fn server_tls_config(tcp: &TcpListenerConfig) -> Result<Option<ServerTlsConfig>, String> {
    match tcp.auth {
        TcpAuthMode::None => Ok(None),
        TcpAuthMode::Mtls => {
            let ca_path = tcp
                .ca_cert
                .as_deref()
                .ok_or_else(|| "listener.remote.ca_cert is required".to_string())?;
            let cert_path = tcp
                .server_cert
                .as_deref()
                .ok_or_else(|| "listener.remote.server_cert is required".to_string())?;
            let key_path = tcp
                .server_key
                .as_deref()
                .ok_or_else(|| "listener.remote.server_key is required".to_string())?;
            check_public_file_perms(ca_path, "listener.remote.ca_cert")?;
            check_public_file_perms(cert_path, "listener.remote.server_cert")?;
            check_key_perms(key_path)?;
            let ca = read_file(ca_path, "listener.remote.ca_cert")?;
            let cert = read_file(cert_path, "listener.remote.server_cert")?;
            let key = std::fs::read(key_path).map_err(|e| {
                format!("failed to read listener.remote.server_key '{}': {e}", key_path.display())
            })?;

            Ok(Some(
                ServerTlsConfig::new()
                    .identity(Identity::from_pem(cert, key))
                    .client_ca_root(Certificate::from_pem(ca))
                    .timeout(Duration::from_secs(10)),
            ))
        }
    }
}

/// Refuse to start when the mTLS private key file is readable by anyone
/// other than the owner. Closes the "file permissions" verification.
///
/// The check is unix-only; on other platforms it's a no-op since file
/// modes don't map cleanly.
fn check_key_perms(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| {
            format!("failed to stat listener.remote.server_key '{}': {e}", path.display())
        })?;
        let mode = meta.permissions().mode() & 0o777;
        // Allow only owner permissions (any of r/w/x). Group + other must
        // be 0. So acceptable modes: 0400, 0600, 0500, 0700.
        if mode & 0o077 != 0 {
            return Err(format!(
                "listener.remote.server_key '{}' has too-permissive mode {:04o}; \
                 mTLS private keys must be 0600 (or stricter — no group/other \
                 access). Fix with: chmod 0600 {}",
                path.display(),
                mode,
                path.display()
            ));
        }
    }
    let _ = path;
    Ok(())
}

fn read_file(path: &Path, field: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("failed to read {field} '{}': {e}", path.display()))
}

/// Refuse to start when a public certificate file (CA root or server
/// cert) is world-writable. The contents are not secret, but any
/// process able to swap them silently changes the proxy's trust
/// anchors — a clear tamper signal that should fail closed.
///
/// World-readable is allowed (these are public material). Group-
/// writable is allowed for kubernetes-style group-shared mounts.
fn check_public_file_perms(path: &Path, field: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("failed to stat {field} '{}': {e}", path.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o002 != 0 {
            return Err(format!(
                "{field} '{}' is world-writable (mode {:04o}); refuse to use \
                 since anyone could tamper with the trust anchor. Fix with: \
                 chmod o-w {}",
                path.display(),
                mode,
                path.display()
            ));
        }
    }
    let _ = (path, field);
    Ok(())
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

        // tempfile defaults to 0600 — that's what we need for mTLS keys.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        }

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

    #[cfg(unix)]
    #[test]
    fn mtls_refuses_world_readable_private_key() {
        use std::os::unix::fs::PermissionsExt;
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        let mut cert = tempfile::NamedTempFile::new().unwrap();
        let mut key = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
        cert.write_all(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
        key.write_all(b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n").unwrap();
        std::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o644)).unwrap();

        let tcp = TcpListenerConfig {
            bind: "127.0.0.1:7512".into(),
            auth: TcpAuthMode::Mtls,
            ca_cert: Some(ca.path().to_path_buf()),
            server_cert: Some(cert.path().to_path_buf()),
            server_key: Some(key.path().to_path_buf()),
            allow_insecure_tcp: false,
        };

        let err = super::server_tls_config(&tcp).unwrap_err();
        assert!(err.contains("too-permissive"), "error should flag mode: {err}");
        assert!(err.contains("0644"), "error should name the offending mode: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn mtls_refuses_world_writable_ca_cert() {
        use std::os::unix::fs::PermissionsExt;
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        let mut cert = tempfile::NamedTempFile::new().unwrap();
        let mut key = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
        cert.write_all(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
        key.write_all(b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n").unwrap();
        std::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(cert.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        // World-writable CA: tamper signal.
        std::fs::set_permissions(ca.path(), std::fs::Permissions::from_mode(0o646)).unwrap();

        let tcp = TcpListenerConfig {
            bind: "127.0.0.1:7512".into(),
            auth: TcpAuthMode::Mtls,
            ca_cert: Some(ca.path().to_path_buf()),
            server_cert: Some(cert.path().to_path_buf()),
            server_key: Some(key.path().to_path_buf()),
            allow_insecure_tcp: false,
        };

        let err = super::server_tls_config(&tcp).unwrap_err();
        assert!(err.contains("world-writable"), "error should flag tamper risk: {err}");
        assert!(err.contains("ca_cert"), "error should name the offending field: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn mtls_refuses_world_writable_server_cert() {
        use std::os::unix::fs::PermissionsExt;
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        let mut cert = tempfile::NamedTempFile::new().unwrap();
        let mut key = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
        cert.write_all(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
        key.write_all(b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n").unwrap();
        std::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(ca.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(cert.path(), std::fs::Permissions::from_mode(0o646)).unwrap();

        let tcp = TcpListenerConfig {
            bind: "127.0.0.1:7512".into(),
            auth: TcpAuthMode::Mtls,
            ca_cert: Some(ca.path().to_path_buf()),
            server_cert: Some(cert.path().to_path_buf()),
            server_key: Some(key.path().to_path_buf()),
            allow_insecure_tcp: false,
        };

        let err = super::server_tls_config(&tcp).unwrap_err();
        assert!(err.contains("world-writable"), "error should flag tamper risk: {err}");
        assert!(err.contains("server_cert"), "error should name the offending field: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn mtls_allows_world_readable_cert_and_ca() {
        use std::os::unix::fs::PermissionsExt;
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        let mut cert = tempfile::NamedTempFile::new().unwrap();
        let mut key = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
        cert.write_all(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
        key.write_all(b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n").unwrap();
        // Public material — world-readable is the expected default.
        std::fs::set_permissions(ca.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(cert.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o600)).unwrap();

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

    #[cfg(unix)]
    #[test]
    fn mtls_refuses_group_readable_private_key() {
        use std::os::unix::fs::PermissionsExt;
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        let mut cert = tempfile::NamedTempFile::new().unwrap();
        let mut key = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
        cert.write_all(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
        key.write_all(b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n").unwrap();
        std::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o640)).unwrap();

        let tcp = TcpListenerConfig {
            bind: "127.0.0.1:7512".into(),
            auth: TcpAuthMode::Mtls,
            ca_cert: Some(ca.path().to_path_buf()),
            server_cert: Some(cert.path().to_path_buf()),
            server_key: Some(key.path().to_path_buf()),
            allow_insecure_tcp: false,
        };

        let err = super::server_tls_config(&tcp).unwrap_err();
        assert!(err.contains("too-permissive"), "error should flag mode: {err}");
    }
}

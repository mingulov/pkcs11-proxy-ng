use std::path::Path;
use std::time::Duration;

use tonic::transport::{Certificate, Identity, ServerTlsConfig};

use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use pkcs11_proxy_ng_types::SecretBytes;

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
            // W1-C3-03: refuse expired / not-yet-valid certificates at
            // startup. Without this the daemon would serve (or trust) with
            // bad material indefinitely. The private key is not a
            // certificate and is intentionally not passed through cert
            // validation.
            let ca_subject = super::auth::mtls::validate_cert_file(ca_path)
                .map_err(|e| format!("listener.remote.ca_cert invalid: {e}"))?;
            tracing::debug!(subject = %ca_subject, "validated listener.remote.ca_cert");
            let server_subject = super::auth::mtls::validate_cert_file(cert_path)
                .map_err(|e| format!("listener.remote.server_cert invalid: {e}"))?;
            tracing::debug!(subject = %server_subject, "validated listener.remote.server_cert");
            let ca = read_file(ca_path, "listener.remote.ca_cert")?;
            let cert = read_file(cert_path, "listener.remote.server_cert")?;
            // ADR-0013 §5: the PEM key file is adopted into the wiping owner
            // immediately; only the copy forced by tonic's `Vec<u8>` API is
            // plain, and it is built at the call with no retained duplicate.
            // (rustls necessarily retains its own parsed copy past this point,
            // like tonic/prost transport buffers: outside the wiping guarantee.)
            let key = SecretBytes::new(std::fs::read(key_path).map_err(|e| {
                format!("failed to read listener.remote.server_key '{}': {e}", key_path.display())
            })?);

            Ok(Some(
                ServerTlsConfig::new()
                    .identity(Identity::from_pem(cert, secret_to_plain(&key)))
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

/// Refuse to load a PRIVATE key file that is accessible to group or other.
///
/// Unlike [`check_public_file_perms`] (which permits world/group *readable*
/// public material), private key material — such as the Ed25519 audit signing
/// seed — must be owner-only. On unix, rejects any file whose mode has any
/// group/other bit set (`mode & 0o077 != 0`). Non-unix platforms are a no-op
/// since file modes don't map cleanly.
pub(crate) fn check_private_file_perms(path: &Path, field: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("failed to stat {field} '{}': {e}", path.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "refuse to load private key {field} '{}': group/other-accessible \
                 (mode {:04o}); private key material must be owner-only. \
                 Fix with: chmod 600 {}",
                path.display(),
                mode,
                path.display()
            ));
        }
    }
    let _ = (path, field);
    Ok(())
}

/// Refuse to start when a public certificate file (CA root or server
/// cert) is world-writable. The contents are not secret, but any
/// process able to swap them silently changes the proxy's trust
/// anchors — a clear tamper signal that should fail closed.
///
/// World-readable is allowed (these are public material). Group-
/// writable is allowed for kubernetes-style group-shared mounts.
pub(crate) fn check_public_file_perms(path: &Path, field: &str) -> Result<(), String> {
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

/// Bind a Unix-domain-socket listener for the local transport.
///
/// Security (ADR-0005): a stale socket from a prior run is removed, but a path
/// that exists and is *not* a socket is never clobbered. The socket is created
/// `0600` (owner-only) atomically via a restrictive umask around `bind()`
/// (D3 — no umask-default window), with an explicit `chmod` as defense in depth.
/// This is a local-user transport (peer-cred records the connecting uid;
/// broadening access is out of scope). The accept loop only starts later in
/// `serve_*`, so no peer is processed before the socket exists.
#[cfg(unix)]
pub fn bind_unix_listener(path: &std::path::Path) -> Result<tokio::net::UnixListener, String> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(|e| {
                format!("failed to remove stale unix socket {}: {e}", path.display())
            })?;
        }
        Ok(_) => {
            return Err(format!(
                "refusing to bind unix socket: {} exists and is not a socket",
                path.display()
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!("cannot stat unix socket path {}: {e}", path.display()));
        }
    }

    // D3: create the socket with a restrictive umask so it is 0600 from the
    // instant of bind(), closing the brief window between bind() and the chmod
    // below where the socket would otherwise carry umask-default (possibly
    // group/other-accessible) permissions. Restore the prior umask immediately,
    // even if bind() fails.
    let prev_umask = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o177));
    let bind_result = tokio::net::UnixListener::bind(path);
    nix::sys::stat::umask(prev_umask);
    let listener =
        bind_result.map_err(|e| format!("failed to bind unix socket {}: {e}", path.display()))?;
    // Defense in depth: assert 0600 explicitly (a no-op given the umask above,
    // but it guarantees the result even if the process umask is unusual).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to chmod unix socket {} to 0600: {e}", path.display()))?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crate::config::{TcpAuthMode, TcpListenerConfig};

    // W1-C3-03 helpers: generate real PEM certificates so the startup path
    // can validate their validity periods (dummy PEM text cannot).
    fn gen_pem_with_validity(
        cn: &str,
        not_before: ::time::OffsetDateTime,
        not_after: ::time::OffsetDateTime,
    ) -> String {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        params.not_before = not_before;
        params.not_after = not_after;
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    fn write_temp(content: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        f.flush().unwrap();
        f
    }

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
        // W1-C3-03: startup validates the certs, so this positive-path test
        // needs real, currently-valid certificates (not dummy PEM text).
        let now = ::time::OffsetDateTime::now_utc();
        let ca_pem = gen_pem_with_validity(
            "test-ca",
            now - ::time::Duration::days(30),
            now + ::time::Duration::days(365),
        );
        let cert_pem = gen_pem_with_validity(
            "test-server",
            now - ::time::Duration::days(1),
            now + ::time::Duration::days(365),
        );
        let ca = write_temp(ca_pem.as_bytes());
        let cert = write_temp(cert_pem.as_bytes());
        let key = write_temp(b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n");

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
        // W1-C3-03: startup validates the certs, so this positive-path test
        // needs real, currently-valid certificates (not dummy PEM text).
        let now = ::time::OffsetDateTime::now_utc();
        let ca_pem = gen_pem_with_validity(
            "test-ca",
            now - ::time::Duration::days(30),
            now + ::time::Duration::days(365),
        );
        let cert_pem = gen_pem_with_validity(
            "test-server",
            now - ::time::Duration::days(1),
            now + ::time::Duration::days(365),
        );
        let ca = write_temp(ca_pem.as_bytes());
        let cert = write_temp(cert_pem.as_bytes());
        let key = write_temp(b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n");
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

    // W1-C3-03: the production startup path (server_tls_config) must
    // refuse expired / not-yet-valid certificates loudly instead of
    // starting with them.
    #[test]
    fn mtls_startup_refuses_expired_server_cert() {
        let now = ::time::OffsetDateTime::now_utc();
        let ca_pem = gen_pem_with_validity(
            "test-ca",
            now - ::time::Duration::days(30),
            now + ::time::Duration::days(365),
        );
        let expired_pem = gen_pem_with_validity(
            "expired-server",
            now - ::time::Duration::days(365),
            now - ::time::Duration::hours(1),
        );
        let ca = write_temp(ca_pem.as_bytes());
        let cert = write_temp(expired_pem.as_bytes());
        let key = write_temp(b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n");
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
        let err = super::server_tls_config(&tcp).unwrap_err();
        assert!(err.contains("expired"), "expired cert must fail startup: {err}");
        assert!(err.contains("server_cert"), "error must name the field: {err}");
    }

    #[test]
    fn mtls_startup_refuses_not_yet_valid_ca_cert() {
        let now = ::time::OffsetDateTime::now_utc();
        let future_ca = gen_pem_with_validity(
            "future-ca",
            now + ::time::Duration::hours(1),
            now + ::time::Duration::days(365),
        );
        let cert_pem = gen_pem_with_validity(
            "test-server",
            now - ::time::Duration::days(1),
            now + ::time::Duration::days(365),
        );
        let ca = write_temp(future_ca.as_bytes());
        let cert = write_temp(cert_pem.as_bytes());
        let key = write_temp(b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n");
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
        let err = super::server_tls_config(&tcp).unwrap_err();
        assert!(err.contains("not yet valid"), "future cert must fail startup: {err}");
        assert!(err.contains("ca_cert"), "error must name the field: {err}");
    }

    #[test]
    fn mtls_startup_accepts_valid_bundle() {
        let now = ::time::OffsetDateTime::now_utc();
        let ca_pem = gen_pem_with_validity(
            "test-ca",
            now - ::time::Duration::days(30),
            now + ::time::Duration::days(365),
        );
        let cert_pem = gen_pem_with_validity(
            "test-server",
            now - ::time::Duration::days(1),
            now + ::time::Duration::days(365),
        );
        let ca = write_temp(ca_pem.as_bytes());
        let cert = write_temp(cert_pem.as_bytes());
        let key = write_temp(b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n");
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

    // W1-L7-07: the UDS listener socket is created mode-0600 (owner-only).
    // Task 3 (C3-11) deleted the stale peer_cred helpers whose docs floated
    // group/world-readable deployment modes (0660 and wider); this pins the
    // surviving contract. (The wider mode is spelled out — never as bare
    // digits — so a naive residual-grep for it does not trip on this pin;
    // exclude test comments when auditing historical modes.)
    #[cfg(unix)]
    #[tokio::test]
    async fn bind_unix_listener_creates_mode_0600_socket() {
        use std::os::unix::fs::PermissionsExt;
        // Final-review F7: `bind_unix_listener` sets process-global
        // umask(0177) around bind(), and sibling lib tests (e.g. the
        // metrics-endpoint tests) bind concurrently. A sibling's umask
        // window landing inside OUR tempdir creation leaves a 0600
        // (un-traversable) dir, so the bind stats EACCES. Repair the
        // dir mode deterministically and retry with a fresh dir on
        // EACCES so the test is hermetic. Production hardening of the
        // global-umask window is out of scope.
        let mut attempts = 0;
        let (dir, _listener) = loop {
            attempts += 1;
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let sock = dir.path().join("t31-0600.sock");
            match super::bind_unix_listener(&sock) {
                Ok(listener) => break (dir, listener),
                Err(e) if e.contains("Permission denied") && attempts < 10 => continue,
                Err(e) => panic!("bind: {e}"),
            }
        };
        let sock = dir.path().join("t31-0600.sock");
        let mode = std::fs::symlink_metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "unix socket must be created 0600, got {mode:o}");
    }
}

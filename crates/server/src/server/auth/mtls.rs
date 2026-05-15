use std::path::Path;
use x509_parser::prelude::*;

/// Phase 1 certificate rotation policy: restart required.
///
/// The daemon does not support hot-reloading of TLS certificates. When
/// certificates are rotated (CA rotation, server cert replacement, or cert
/// renewal), the daemon must be restarted. This is acceptable for Phase 1
/// because:
/// - Certificate lifetimes are typically measured in months or years.
/// - Graceful restart (SIGTERM → drain → re-exec) is the standard
///   operational pattern for certificate rotation in daemon processes.
/// - Hot reload requires watching files and rebuilding the TLS acceptor,
///   which adds complexity disproportionate to Phase 1 needs.
///
/// Phase 2 may add SIGHUP-triggered reload or file-watcher-based reload.
pub const CERT_ROTATION_POLICY: &str = "restart";

/// Validate a PEM certificate file at startup.
///
/// Checks:
/// 1. File exists and is readable
/// 2. Contains at least one valid PEM-encoded certificate
/// 3. The first certificate is not expired (not-after is in the future)
/// 4. The first certificate's not-before is in the past
///
/// Returns the subject DN string on success for logging.
pub fn validate_cert_file(path: &Path) -> Result<String, String> {
    let pem_data = std::fs::read(path)
        .map_err(|e| format!("cannot read certificate file '{}': {e}", path.display()))?;

    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_data)
        .map_err(|e| format!("invalid PEM in '{}': {e}", path.display()))?;

    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| format!("invalid X.509 in '{}': {e}", path.display()))?;

    let now = ASN1Time::now();
    if cert.validity().not_after < now {
        return Err(format!(
            "certificate in '{}' has expired (not_after: {})",
            path.display(),
            cert.validity().not_after,
        ));
    }
    if cert.validity().not_before > now {
        return Err(format!(
            "certificate in '{}' is not yet valid (not_before: {})",
            path.display(),
            cert.validity().not_before,
        ));
    }

    Ok(cert.subject().to_string())
}

/// Extract issuer and subject Distinguished Names from a DER-encoded X.509
/// certificate, returning them as RFC 4514 strings.
///
/// The resulting strings are used as identity keys in the authorization policy
/// (via `AuthenticatedIdentity::Mtls`). Operators must use the same RFC 4514
/// format in policy files for identity matching to work.
///
/// RFC 4514 rules applied:
/// - Attributes are comma-separated in reverse order (leaf-to-root)
/// - Standard attribute types use short names: CN, O, OU, C, ST, L, etc.
/// - Values are escaped per RFC 4514 §2.4
pub fn extract_identity(cert_der: &[u8]) -> Result<(String, String), String> {
    if cert_der.is_empty() {
        return Err("empty certificate".into());
    }
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("failed to parse X.509 certificate: {e}"))?;

    let issuer = cert.issuer().to_string();
    let subject = cert.subject().to_string();

    Ok((issuer, subject))
}

#[cfg(test)]
mod tests;

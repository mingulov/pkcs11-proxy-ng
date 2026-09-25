use sha2::{Digest, Sha256};
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

    let now = ASN1Time::now();
    // A PEM file may carry a whole chain (leaf + intermediate(s) + CA). Validate
    // EVERY certificate in it, not just the first — an expired or not-yet-valid
    // entry anywhere in the bundle must be rejected at startup (L3).
    let mut leaf_subject: Option<String> = None;
    for pem in x509_parser::pem::Pem::iter_from_buffer(&pem_data) {
        let pem = pem.map_err(|e| format!("invalid PEM in '{}': {e}", path.display()))?;
        if pem.label != "CERTIFICATE" {
            continue; // ignore non-certificate PEM blocks
        }
        let (_, cert) = X509Certificate::from_der(&pem.contents)
            .map_err(|e| format!("invalid X.509 in '{}': {e}", path.display()))?;
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
        // Conventionally the leaf is first; report its subject for logging.
        if leaf_subject.is_none() {
            leaf_subject = Some(cert.subject().to_string());
        }
    }

    leaf_subject.ok_or_else(|| format!("no certificate found in '{}'", path.display()))
}

/// Extract issuer, subject Distinguished Names and SPKI fingerprint from a
/// DER-encoded X.509 certificate. The DN strings are produced by
/// `x509-parser`'s RFC 4514 serializer (comma-separated, leaf-to-root, short
/// attribute names, values escaped per RFC 4514 §2.4 — this function does not
/// re-implement that).
///
/// Returns a triple `(issuer, subject, spki_sha256)` where:
/// - `issuer` and `subject` are the RFC 4514 DN strings used in legacy identity keys.
/// - `spki_sha256` is the hex-encoded SHA-256 digest of the certificate's
///   SubjectPublicKeyInfo (SPKI) DER bytes — the cryptographic identity key
///   used for SPKI-pinned policy entries (`x509:spki=<fingerprint>`).
///
/// These strings become identity keys in the authorization policy (via
/// `AuthenticatedIdentity::Mtls`); the identity's *own* string form additionally
/// escapes its `;subject=` join delimiter so distinct DN pairs cannot collide
/// (see `identity.rs`). Operators must use the same DN serialization in policy
/// files for identity matching to work.
///
/// Fails closed when the subject DN is empty: such a certificate would rely on
/// its SubjectAltName for identity, which Phase 1 does not consult, and would
/// otherwise collapse every empty-subject cert from a CA onto one ambiguous
/// identity. (SAN-based identity is a deliberate Phase 1 gap.)
pub fn extract_identity(cert_der: &[u8]) -> Result<(String, String, String), String> {
    if cert_der.is_empty() {
        return Err("empty certificate".into());
    }
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("failed to parse X.509 certificate: {e}"))?;

    let issuer = cert.issuer().to_string();
    let subject = cert.subject().to_string();

    if subject.is_empty() {
        return Err("certificate has an empty subject DN; SubjectAltName-based identity is not \
             supported in Phase 1"
            .into());
    }

    let spki_sha256 = hex::encode(Sha256::digest(cert.public_key().raw));

    Ok((issuer, subject, spki_sha256))
}

#[cfg(test)]
mod tests;

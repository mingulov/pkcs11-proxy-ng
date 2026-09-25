use super::*;
use ::time::{Duration, OffsetDateTime};
use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair};

fn gen_self_signed(dn: &DistinguishedName) -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name = dn.clone();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

fn gen_ca_signed(ca_dn: &DistinguishedName, subject_dn: &DistinguishedName) -> Vec<u8> {
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = ca_dn.clone();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

    let mut client_params = CertificateParams::default();
    client_params.distinguished_name = subject_dn.clone();
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();
    client_cert.der().to_vec()
}

fn gen_self_signed_pem_with_validity(
    cn: &str,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> String {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.not_before = not_before;
    params.not_after = not_after;
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.pem()
}

fn write_pem_to_tempfile(pem: &str) -> tempfile::NamedTempFile {
    use std::io::Write;

    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(pem.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

#[test]
fn empty_cert_is_error() {
    assert!(extract_identity(b"").is_err());
}

#[test]
fn invalid_der_is_error() {
    let err = extract_identity(b"not-a-certificate").unwrap_err();
    assert!(err.contains("failed to parse"), "error: {err}");
}

#[test]
fn empty_subject_dn_is_rejected() {
    // G1: a cert with no subject DN would rely on the SubjectAltName for its
    // identity, which Phase 1 does not consult. Accepting it would collapse
    // every such cert from a CA onto one ambiguous empty-subject identity, so
    // it must be rejected (fail closed) rather than silently shared.
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "Root CA");
    let empty_subject = DistinguishedName::new();
    let der = gen_ca_signed(&ca_dn, &empty_subject);
    let err = extract_identity(&der).unwrap_err();
    assert!(err.contains("empty subject"), "error: {err}");
}

#[test]
fn self_signed_cn_only() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "TestCA");
    let der = gen_self_signed(&dn);

    let (issuer, subject, _) = extract_identity(&der).unwrap();
    assert_eq!(issuer, subject);
    assert!(subject.contains("CN=TestCA"), "subject: {subject}");
}

#[test]
fn ca_signed_distinct_issuer_and_subject() {
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "Root CA");
    ca_dn.push(DnType::OrganizationName, "Test Org");

    let mut client_dn = DistinguishedName::new();
    client_dn.push(DnType::CommonName, "client1");

    let der = gen_ca_signed(&ca_dn, &client_dn);
    let (issuer, subject, _) = extract_identity(&der).unwrap();

    assert!(issuer.contains("CN=Root CA"), "issuer: {issuer}");
    assert!(issuer.contains("O=Test Org"), "issuer: {issuer}");
    assert!(subject.contains("CN=client1"), "subject: {subject}");
    assert_ne!(issuer, subject);
}

#[test]
fn multi_attribute_dn_ordering() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "US");
    dn.push(DnType::OrganizationName, "ACME Corp");
    dn.push(DnType::OrganizationalUnitName, "Engineering");
    dn.push(DnType::CommonName, "service-a");

    let der = gen_self_signed(&dn);
    let (_, subject, _) = extract_identity(&der).unwrap();

    assert!(subject.contains("C=US"), "subject: {subject}");
    assert!(subject.contains("O=ACME Corp"), "subject: {subject}");
    assert!(subject.contains("OU=Engineering"), "subject: {subject}");
    assert!(subject.contains("CN=service-a"), "subject: {subject}");
}

#[test]
fn policy_key_roundtrip() {
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "Root CA");

    let mut client_dn = DistinguishedName::new();
    client_dn.push(DnType::CommonName, "client1");

    let der = gen_ca_signed(&ca_dn, &client_dn);
    let (issuer, subject, spki_sha256) = extract_identity(&der).unwrap();

    let identity = super::super::identity::AuthenticatedIdentity::Mtls {
        issuer: issuer.clone(),
        subject: subject.clone(),
        spki_sha256: spki_sha256.clone(),
    };
    let display = identity.to_string();

    // With SPKI present and DN present, display is enriched form starting with "x509:spki="
    assert!(display.starts_with("x509:spki="), "display starts with spki prefix: {display}");
    // The SPKI hash should be in the display
    assert!(display.contains(&spki_sha256), "display contains spki_sha256");
}

#[test]
fn special_characters_in_cn() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test+service");
    let der = gen_self_signed(&dn);
    let (_, subject, _) = extract_identity(&der).unwrap();
    assert!(
        subject.contains("test") && subject.contains("service"),
        "subject should contain the CN value: {subject}"
    );
}

#[test]
fn identity_deterministic_across_calls() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "stable-identity");
    let der = gen_self_signed(&dn);

    let (issuer1, subject1, _) = extract_identity(&der).unwrap();
    let (issuer2, subject2, _) = extract_identity(&der).unwrap();
    assert_eq!(issuer1, issuer2, "identity extraction must be deterministic");
    assert_eq!(subject1, subject2, "identity extraction must be deterministic");
}

#[test]
fn empty_cn_is_valid() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "");
    let der = gen_self_signed(&dn);
    let result = extract_identity(&der);
    assert!(result.is_ok(), "empty CN should parse: {:?}", result.err());
}

#[test]
fn unicode_cn_handled() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "München-Server-ä");
    let der = gen_self_signed(&dn);
    let (_, subject, _) = extract_identity(&der).unwrap();
    assert!(
        subject.contains("München") || subject.contains("M"),
        "unicode should be preserved or safely encoded: {subject}"
    );
}

#[test]
fn cert_rotation_policy_is_restart() {
    assert_eq!(super::CERT_ROTATION_POLICY, "restart");
}

#[test]
fn validate_cert_file_valid() {
    let now = OffsetDateTime::now_utc();
    let pem = gen_self_signed_pem_with_validity(
        "valid-cert",
        now - Duration::hours(1),
        now + Duration::days(365),
    );
    let f = write_pem_to_tempfile(&pem);
    let result = super::validate_cert_file(f.path());
    assert!(result.is_ok(), "valid cert should pass: {:?}", result.err());
    let subject = result.unwrap();
    assert!(subject.contains("valid-cert"), "subject: {subject}");
}

#[test]
fn validate_cert_file_expired() {
    let now = OffsetDateTime::now_utc();
    let pem = gen_self_signed_pem_with_validity(
        "expired-cert",
        now - Duration::days(365),
        now - Duration::hours(1),
    );
    let f = write_pem_to_tempfile(&pem);
    let err = super::validate_cert_file(f.path()).unwrap_err();
    assert!(err.contains("expired"), "error should mention expiry: {err}");
}

#[test]
fn validate_cert_file_rejects_expired_cert_in_a_bundle() {
    // L3: a PEM file may hold a chain (leaf + intermediate/CA). EVERY
    // certificate must be validated, not just the first — an expired second
    // entry must be rejected rather than silently accepted.
    let now = OffsetDateTime::now_utc();
    let leaf = gen_self_signed_pem_with_validity(
        "leaf",
        now - Duration::hours(1),
        now + Duration::days(30),
    );
    let expired_ca = gen_self_signed_pem_with_validity(
        "intermediate",
        now - Duration::days(365),
        now - Duration::hours(1),
    );
    let bundle = format!("{leaf}{expired_ca}");
    let f = write_pem_to_tempfile(&bundle);
    let err = super::validate_cert_file(f.path()).unwrap_err();
    assert!(err.contains("expired"), "an expired cert in the bundle must be rejected: {err}");
}

#[test]
fn validate_cert_file_not_yet_valid() {
    let now = OffsetDateTime::now_utc();
    let pem = gen_self_signed_pem_with_validity(
        "future-cert",
        now + Duration::hours(1),
        now + Duration::days(365),
    );
    let f = write_pem_to_tempfile(&pem);
    let err = super::validate_cert_file(f.path()).unwrap_err();
    assert!(err.contains("not yet valid"), "error should mention not_before: {err}");
}

#[test]
fn validate_cert_file_nonexistent() {
    let err = super::validate_cert_file(std::path::Path::new("/nonexistent/cert.pem")).unwrap_err();
    assert!(err.contains("cannot read"), "error: {err}");
}

#[test]
fn validate_cert_file_not_pem() {
    use std::io::Write;

    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(b"this is not a PEM file").unwrap();
    f.flush().unwrap();
    // A file with no certificate PEM blocks is rejected (the message changed
    // from "invalid PEM" to "no certificate" when validation began iterating the
    // whole bundle — L3).
    let err = super::validate_cert_file(f.path()).unwrap_err();
    assert!(
        err.contains("no certificate") || err.contains("invalid PEM"),
        "a non-certificate file must be rejected: {err}"
    );
}

#[test]
fn validate_cert_file_invalid_der_in_pem() {
    let pem_str = "-----BEGIN CERTIFICATE-----\nAQIDBAUGBwgJ\n-----END CERTIFICATE-----\n";
    let f = write_pem_to_tempfile(pem_str);
    let err = super::validate_cert_file(f.path()).unwrap_err();
    assert!(err.contains("invalid X.509"), "error: {err}");
}

#[test]
fn policy_lookup_with_real_cert() {
    use std::collections::HashMap;

    use super::super::identity::AuthenticatedIdentity;
    use super::super::policy::{TokenAccess, TokenPolicy};

    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "PolicyTestCA");

    let mut client_dn = DistinguishedName::new();
    client_dn.push(DnType::CommonName, "authorized-client");

    let der = gen_ca_signed(&ca_dn, &client_dn);
    let (issuer, subject, spki_sha256) = extract_identity(&der).unwrap();

    let identity = AuthenticatedIdentity::Mtls {
        issuer: issuer.clone(),
        subject: subject.clone(),
        spki_sha256: spki_sha256.clone(),
    };
    // Policy key is the SPKI form (short)
    let spki_policy_key = format!("x509:spki={spki_sha256}");
    let mut rules = HashMap::new();
    rules.insert(spki_policy_key, TokenAccess::All);
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };

    assert!(
        policy.allows(&identity, "any-token", "any-serial"),
        "policy should match identity derived from real cert"
    );

    let other = AuthenticatedIdentity::Mtls {
        issuer: issuer.clone(),
        subject: "CN=unauthorized-client".into(),
        spki_sha256: "different_spki_hash_000000000000000000000000000000000000000000000000".into(),
    };
    assert!(
        !policy.allows(&other, "any-token", "any-serial"),
        "different SPKI hash should be denied"
    );
}

#[test]
fn extract_identity_provides_spki_sha256() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test-cert");
    let der = gen_self_signed(&dn);

    let (_, _, spki_sha256) = extract_identity(&der).unwrap();
    assert!(!spki_sha256.is_empty(), "SPKI hash must be non-empty");
    assert_eq!(spki_sha256.len(), 64, "SHA-256 hex is 64 chars");
    assert!(
        spki_sha256.chars().all(|c| c.is_ascii_hexdigit()),
        "SPKI hash must be hex: {spki_sha256}"
    );

    // Identity to_string() starts with x509:spki=
    let identity = super::super::identity::AuthenticatedIdentity::Mtls {
        issuer: "CN=test-cert".into(),
        subject: "CN=test-cert".into(),
        spki_sha256: spki_sha256.clone(),
    };
    assert!(identity.to_string().starts_with("x509:spki="), "primary key: {identity}");
}

#[test]
fn spki_hash_differs_for_different_keypairs_same_dn() {
    // Two certs with identical subject DN but different keypairs produce different SPKI hashes.
    // This is the spoof that DN-keyed identity allowed: a CA minting a second cert with the
    // victim's subject inherits the victim's grants. SPKI-keyed identity closes this.
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "shared-dn");
    let der_a = gen_self_signed(&dn);
    let der_b = gen_self_signed(&dn); // different key pair, same DN

    let (_, subject_a, spki_a) = extract_identity(&der_a).unwrap();
    let (_, subject_b, spki_b) = extract_identity(&der_b).unwrap();

    // Same subject DN (the attacker can clone it)
    assert_eq!(subject_a, subject_b, "subject DNs must be identical");
    // But DIFFERENT SPKI (bound to the keypair — cannot be cloned)
    assert_ne!(spki_a, spki_b, "SPKI hashes must differ for different keypairs");
}

#[test]
fn dual_accept_spki_policy_authorizes() {
    use super::super::identity::AuthenticatedIdentity;
    use super::super::policy::{TokenAccess, TokenPolicy};
    use std::collections::HashMap;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "dual-accept-client");
    let der = gen_self_signed(&dn);

    let (issuer, subject, spki_sha256) = extract_identity(&der).unwrap();
    let identity =
        AuthenticatedIdentity::Mtls { issuer, subject, spki_sha256: spki_sha256.clone() };

    // Policy keyed by SPKI (new form)
    let mut rules = HashMap::new();
    rules.insert(format!("x509:spki={spki_sha256}"), TokenAccess::All);
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };

    assert!(policy.allows(&identity, "any", "any"), "SPKI-keyed policy must authorize");
}

#[test]
fn dual_accept_legacy_dn_policy_authorizes_with_deprecation_warning() {
    use super::super::identity::AuthenticatedIdentity;
    use super::super::policy::{TokenAccess, TokenPolicy};
    use std::collections::HashMap;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "legacy-dn-client-unique-test");
    let der = gen_self_signed(&dn);

    let (issuer, subject, spki_sha256) = extract_identity(&der).unwrap();
    let identity = AuthenticatedIdentity::Mtls {
        issuer: issuer.clone(),
        subject: subject.clone(),
        spki_sha256,
    };

    // Policy keyed by legacy DN (old form) — dual-accept must still authorize
    let legacy_key = format!("x509:issuer={};subject={}", issuer, subject);
    let mut rules = HashMap::new();
    rules.insert(legacy_key, TokenAccess::All);
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };

    // The deprecated DN path is accepted (with a one-time tracing::warn! emitted)
    assert!(
        policy.allows(&identity, "any", "any"),
        "legacy DN-keyed policy must still authorize during transition"
    );
}

// ---------------------------------------------------------------------------
// W1-L7-04: the validate_cert_file doc must describe every-certificate
// validation — the code checks ALL certs in the bundle, so the stale
// "first certificate" wording must not come back (R3: Task 31 owns it).
// ---------------------------------------------------------------------------

#[test]
fn validate_cert_file_doc_describes_every_certificate_validation() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server/auth/mtls.rs");
    let text = std::fs::read_to_string(&path).expect("read own mtls.rs");
    let start =
        text.find("/// Validate a PEM certificate file at startup.").expect("doc head present");
    let end =
        start + text[start..].find("pub fn validate_cert_file").expect("fn present after doc");
    let doc = &text[start..end];
    assert!(
        !doc.contains("first certificate"),
        "stale first-cert-only wording must be gone:\n{doc}"
    );
    assert!(
        doc.contains("Every certificate"),
        "doc must state every-certificate validation:\n{doc}"
    );
}

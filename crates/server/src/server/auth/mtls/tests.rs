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
fn self_signed_cn_only() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "TestCA");
    let der = gen_self_signed(&dn);

    let (issuer, subject) = extract_identity(&der).unwrap();
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
    let (issuer, subject) = extract_identity(&der).unwrap();

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
    let (_, subject) = extract_identity(&der).unwrap();

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
    let (issuer, subject) = extract_identity(&der).unwrap();

    let identity = super::super::identity::AuthenticatedIdentity::Mtls {
        issuer: issuer.clone(),
        subject: subject.clone(),
    };
    let display = identity.to_string();

    assert!(display.contains(&issuer), "display '{display}' must contain issuer '{issuer}'");
    assert!(display.contains(&subject), "display '{display}' must contain subject '{subject}'");
}

#[test]
fn special_characters_in_cn() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test+service");
    let der = gen_self_signed(&dn);
    let (_, subject) = extract_identity(&der).unwrap();
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

    let (issuer1, subject1) = extract_identity(&der).unwrap();
    let (issuer2, subject2) = extract_identity(&der).unwrap();
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
    let (_, subject) = extract_identity(&der).unwrap();
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
    let err = super::validate_cert_file(f.path()).unwrap_err();
    assert!(err.contains("invalid PEM"), "error: {err}");
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
    let (issuer, subject) = extract_identity(&der).unwrap();

    let identity = AuthenticatedIdentity::Mtls { issuer: issuer.clone(), subject: subject.clone() };

    let policy_key = identity.to_string();
    let mut rules = HashMap::new();
    rules.insert(policy_key, TokenAccess::All);
    let policy = TokenPolicy { rules, allow_all_authenticated: false };

    assert!(
        policy.allows(&identity, "any-token", "any-serial"),
        "policy should match identity derived from real cert"
    );

    let other = AuthenticatedIdentity::Mtls {
        issuer: issuer.clone(),
        subject: "CN=unauthorized-client".into(),
    };
    assert!(
        !policy.allows(&other, "any-token", "any-serial"),
        "different subject should be denied"
    );
}

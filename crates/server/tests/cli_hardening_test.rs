//! CLI command hardening tests (items 27-30).
//!
//! These tests start a real SoftHSM2-backed daemon, run the `pkcs11-cli`
//! binary as a subprocess, and validate command output.
//!
//! All tests require SoftHSM2 and are marked `#[ignore]`.

mod support;

use support::*;
use tokio::process::Command;

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn find_cli_binary() -> Option<std::path::PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir).parent().and_then(|p| p.parent())?;

    let candidates = [
        workspace_root.join("target/debug/pkcs11-proxy-ng-cli"),
        workspace_root.join("target/release/pkcs11-proxy-ng-cli"),
    ];

    candidates.into_iter().find(|p| p.exists())
}

/// Run the CLI binary with the given args, returning (stdout, stderr, success).
async fn run_cli(endpoint: &str, args: &[&str]) -> (String, String, bool) {
    let cli =
        find_cli_binary().expect("pkcs11-proxy-ng-cli binary not found — run cargo build first");
    let output = Command::new(&cli)
        .arg("--endpoint")
        .arg(endpoint)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .expect("failed to spawn pkcs11-cli");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

// ── Item 27: get-info command ─────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn cli_get_info_shows_library_fields() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;

    let (stdout, stderr, success) = run_cli(daemon.endpoint(), &["get-info"]).await;
    eprintln!("=== get-info stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }

    assert!(success, "get-info should succeed");
    // Should show library info fields
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("library")
            || combined.contains("Library")
            || combined.contains("PKCS#11"),
        "get-info output should contain library information"
    );

    daemon.shutdown().await
}

// ── Item 28: session-info command ─────────────────────────────────────

#[tokio::test]
#[ignore]
async fn cli_session_info_shows_session_state() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;

    // Open a session to the slot
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;

    let (stdout, stderr, success) = run_cli(
        daemon.endpoint(),
        &["session-info", "--slot-id", &slot.0.to_string(), "--pin", &fixture.user_pin],
    )
    .await;
    eprintln!("=== session-info stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }

    assert!(success, "session-info should succeed");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("session")
            || combined.contains("Session")
            || combined.contains("state")
            || combined.contains("State"),
        "session-info output should contain session state information"
    );

    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await
}

// ── Item 30: random command ───────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn cli_random_hex_output() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;

    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    client.finalize().await.map_err(|rv| rv.to_string())?;

    let (stdout, stderr, success) =
        run_cli(daemon.endpoint(), &["random", "--slot-id", &slot.0.to_string(), "--len", "16"])
            .await;
    eprintln!("=== random (hex) stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }

    assert!(success, "random --format hex should succeed");
    let hex_str = stdout.trim();
    assert_eq!(hex_str.len(), 32, "16 random bytes should produce 32 hex chars");
    assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()), "output should be valid hex");

    daemon.shutdown().await
}

#[tokio::test]
#[ignore]
async fn cli_random_base64_output() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;

    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    client.finalize().await.map_err(|rv| rv.to_string())?;

    let (stdout, stderr, success) = run_cli(
        daemon.endpoint(),
        &["random", "--slot-id", &slot.0.to_string(), "--len", "32", "--format", "base64"],
    )
    .await;
    eprintln!("=== random (base64) stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }

    assert!(success, "random --format base64 should succeed");
    let b64_str = stdout.trim();
    // 32 bytes → 44 chars in standard base64 (with padding)
    assert!(!b64_str.is_empty(), "base64 output should not be empty");
    assert!(
        b64_str.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
        "output should be valid base64 characters"
    );

    daemon.shutdown().await
}

#[tokio::test]
#[ignore]
async fn cli_random_different_lengths() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;

    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    client.finalize().await.map_err(|rv| rv.to_string())?;

    // 1 byte
    let (stdout1, _, success1) =
        run_cli(daemon.endpoint(), &["random", "--slot-id", &slot.0.to_string(), "--len", "1"])
            .await;
    assert!(success1, "1-byte random should succeed");
    assert_eq!(stdout1.trim().len(), 2, "1 byte = 2 hex chars");

    // 64 bytes
    let (stdout64, _, success64) =
        run_cli(daemon.endpoint(), &["random", "--slot-id", &slot.0.to_string(), "--len", "64"])
            .await;
    assert!(success64, "64-byte random should succeed");
    assert_eq!(stdout64.trim().len(), 128, "64 bytes = 128 hex chars");

    // Two calls should produce different output (with overwhelming probability)
    let (stdout_a, _, _) =
        run_cli(daemon.endpoint(), &["random", "--slot-id", &slot.0.to_string(), "--len", "32"])
            .await;
    let (stdout_b, _, _) =
        run_cli(daemon.endpoint(), &["random", "--slot-id", &slot.0.to_string(), "--len", "32"])
            .await;
    assert_ne!(
        stdout_a.trim(),
        stdout_b.trim(),
        "two random calls should produce different output"
    );

    daemon.shutdown().await
}

// ── Item 29: verify command (fully CLI-driven) ───────────────────────

#[tokio::test]
#[ignore]
async fn cli_verify_rsa_pkcs_sign_then_verify() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    let slot_str = slot.0.to_string();

    let label = unique_label("cli-verify");
    let data_hex = hex_encode(b"test data for verify");

    // Step 1: Generate key pair via CLI
    let (stdout_kg, stderr_kg, success_kg) = run_cli(
        daemon.endpoint(),
        &[
            "generate-key-pair",
            "--slot-id",
            &slot_str,
            "--pin",
            &fixture.user_pin,
            "--mechanism",
            "RSA_PKCS_KEY_PAIR_GEN",
            "--label",
            &label,
            "--key-size",
            "2048",
        ],
    )
    .await;
    eprintln!("=== generate-key-pair stdout ===\n{stdout_kg}");
    if !stderr_kg.is_empty() {
        eprintln!("=== stderr ===\n{stderr_kg}");
    }
    assert!(success_kg, "generate-key-pair should succeed");

    // Step 2: Sign via CLI
    let (sig_stdout, sig_stderr, sig_success) = run_cli(
        daemon.endpoint(),
        &[
            "sign",
            "--slot-id",
            &slot_str,
            "--pin",
            &fixture.user_pin,
            "--key-label",
            &label,
            "--mechanism",
            "RSA_PKCS",
            "--input",
            &data_hex,
        ],
    )
    .await;
    eprintln!("=== sign stdout ===\n{sig_stdout}");
    if !sig_stderr.is_empty() {
        eprintln!("=== sign stderr ===\n{sig_stderr}");
    }
    assert!(sig_success, "sign should succeed");
    let sig_hex = sig_stdout.trim().to_string();
    assert!(!sig_hex.is_empty(), "signature should not be empty");

    // Step 3: Verify valid signature via CLI
    let (stdout, stderr, success) = run_cli(
        daemon.endpoint(),
        &[
            "verify",
            "--slot-id",
            &slot_str,
            "--pin",
            &fixture.user_pin,
            "--key-label",
            &label,
            "--mechanism",
            "RSA_PKCS",
            "--data",
            &data_hex,
            "--signature",
            &sig_hex,
        ],
    )
    .await;
    eprintln!("=== verify (valid sig) stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }
    assert!(success, "verify with valid signature should succeed");

    // Step 4: Verify with bad signature — should fail
    let bad_sig = "de".repeat(sig_hex.len() / 2);
    let (_stdout2, _stderr2, success2) = run_cli(
        daemon.endpoint(),
        &[
            "verify",
            "--slot-id",
            &slot_str,
            "--pin",
            &fixture.user_pin,
            "--key-label",
            &label,
            "--mechanism",
            "RSA_PKCS",
            "--data",
            &data_hex,
            "--signature",
            &bad_sig,
        ],
    )
    .await;
    assert!(!success2, "verify with bad signature should fail");

    daemon.shutdown().await
}

// ── Item 32: import-certificate command ───────────────────────────────

#[tokio::test]
#[ignore]
async fn cli_import_certificate_der_and_pem() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    let slot_str = slot.0.to_string();

    // Generate a self-signed certificate using rcgen
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| format!("rcgen failed: {e}"))?;
    let der_bytes = cert.cert.der().to_vec();
    let pem_string = cert.cert.pem();

    // Write DER file
    let tmp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let der_path = tmp.path().join("test.der");
    let pem_path = tmp.path().join("test.pem");
    std::fs::write(&der_path, &der_bytes).map_err(|e| format!("write DER: {e}"))?;
    std::fs::write(&pem_path, &pem_string).map_err(|e| format!("write PEM: {e}"))?;

    // Import DER certificate
    let (stdout, stderr, success) = run_cli(
        daemon.endpoint(),
        &[
            "import-certificate",
            "--slot-id",
            &slot_str,
            "--pin",
            &fixture.user_pin,
            "--label",
            "test-cert-der",
            "--file",
            der_path.to_str().unwrap(),
        ],
    )
    .await;
    eprintln!("=== import-certificate (DER) stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }
    assert!(success, "import-certificate DER should succeed");
    assert!(
        stdout.contains("imported") || stdout.contains("handle"),
        "output should confirm import"
    );

    // Import PEM certificate
    let (stdout2, stderr2, success2) = run_cli(
        daemon.endpoint(),
        &[
            "import-certificate",
            "--slot-id",
            &slot_str,
            "--pin",
            &fixture.user_pin,
            "--label",
            "test-cert-pem",
            "--file",
            pem_path.to_str().unwrap(),
        ],
    )
    .await;
    eprintln!("=== import-certificate (PEM) stdout ===\n{stdout2}");
    if !stderr2.is_empty() {
        eprintln!("=== stderr ===\n{stderr2}");
    }
    assert!(success2, "import-certificate PEM should succeed");

    daemon.shutdown().await
}

//! Consumer interoperability tests using Python PyKCS11.
//!
//! These tests start a real SoftHSM2-backed daemon, point a Python script
//! using PyKCS11 at the proxy shim library, and validate that the Python
//! consumer can exercise core PKCS#11 operations through the proxy.
//!
//! All tests require SoftHSM2 and PyKCS11 to be installed and are
//! marked `#[ignore]` for normal `cargo test` runs.

mod support;

use std::path::PathBuf;
use support::*;
use tokio::process::Command;

fn find_test_script() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");

    workspace_root.join("scripts/test-python-consumer.py")
}

fn python_pkcs11_available() -> bool {
    if !tool_available("python3") {
        return false;
    }
    // Check if PyKCS11 is importable
    std::process::Command::new("python3")
        .args(["-c", "import PyKCS11"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── Item 74: Python PKCS#11 consumer coverage ────────────────────────

#[tokio::test]
#[ignore]
async fn python_pkcs11_full_workflow() -> Result<(), String> {
    let shim = find_shim_library().expect("shim .so not found — run cargo build first");
    let script = find_test_script();
    if !script.exists() {
        return Err(format!("test script not found: {}", script.display()));
    }
    if !python_pkcs11_available() {
        record_skip!(SkipReason::ToolMissing("python3 + PyKCS11"));
        return Ok(());
    }

    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;

    let output = Command::new("python3")
        .arg(&script)
        .arg(&fixture.user_pin)
        .env("PKCS11_MODULE", &shim)
        .env("PKCS11_PROXY_ENDPOINT", daemon.endpoint())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .expect("failed to spawn python3");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    eprintln!("=== Python consumer stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }

    // Check for SKIP (PyKCS11 not installed)
    if stdout.contains("SKIP:") {
        record_skip!(SkipReason::ToolMissing("PyKCS11"));
        return Ok(());
    }

    // Parse results line
    let results_line =
        stdout.lines().rfind(|l| l.starts_with("Results:")).unwrap_or("Results: unknown");
    eprintln!("Python consumer: {results_line}");

    // Count individual test results
    let fail_count = stdout.lines().filter(|l| l.starts_with("[FAIL]")).count();
    let pass_count = stdout.lines().filter(|l| l.starts_with("[PASS]")).count();
    eprintln!("Parsed: {pass_count} PASS, {fail_count} FAIL");

    assert!(output.status.success(), "Python consumer script failed: {results_line}");
    assert!(pass_count > 0, "should have at least one passing test");

    daemon.shutdown().await
}

#[tokio::test]
#[ignore]
async fn python_pkcs11_direct_backend_baseline() -> Result<(), String> {
    let script = find_test_script();
    if !script.exists() {
        return Err(format!("test script not found: {}", script.display()));
    }
    if !python_pkcs11_available() {
        record_skip!(SkipReason::ToolMissing("python3 + PyKCS11"));
        return Ok(());
    }

    // Run against the direct SoftHSM2 module (no proxy) as a baseline
    let fixture = ProviderFixture::soft_hsm().await?;

    let output = Command::new("python3")
        .arg(&script)
        .arg(&fixture.user_pin)
        .env("PKCS11_MODULE", &fixture.module_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .expect("failed to spawn python3");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    eprintln!("=== Python consumer (direct backend) stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }

    if stdout.contains("SKIP:") {
        record_skip!(SkipReason::ToolMissing("PyKCS11"));
        return Ok(());
    }

    let pass_count = stdout.lines().filter(|l| l.starts_with("[PASS]")).count();
    eprintln!("Direct backend baseline: {pass_count} PASS");

    assert!(output.status.success(), "Python consumer against direct backend failed");

    // Release the lock by dropping fixture
    drop(fixture);
    Ok(())
}

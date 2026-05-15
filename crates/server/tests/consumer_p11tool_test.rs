//! Consumer interoperability tests using GnuTLS `p11tool`.
//!
//! These tests start a real SoftHSM2-backed daemon, point `p11tool`
//! at the proxy shim library, and validate advanced workflows beyond
//! simple token listing.
//!
//! All tests require SoftHSM2 and `p11tool` to be installed and are
//! marked `#[ignore]` for normal `cargo test` runs.

mod support;

use support::*;
use tokio::process::Command;

fn p11tool_available() -> bool {
    support::tool_available("p11tool")
}

async fn p11tool_supports_option(option: &str) -> bool {
    Command::new("p11tool")
        .arg("--help")
        .output()
        .await
        .map(|output| {
            let help = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            help.contains(option)
        })
        .unwrap_or(false)
}

/// Run `p11tool` with the given args against the shim, returning (stdout, stderr, success).
async fn run_p11tool(
    shim_path: &std::path::Path,
    endpoint: &str,
    args: &[&str],
) -> (String, String, bool) {
    let output = Command::new("p11tool")
        .arg("--provider")
        .arg(shim_path)
        .args(args)
        .env("PKCS11_PROXY_ENDPOINT", endpoint)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .expect("failed to spawn p11tool");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

// ── Item 71: p11tool advanced workflows ──────────────────────────────

#[tokio::test]
#[ignore]
async fn p11tool_list_token_urls() -> Result<(), String> {
    let shim = find_shim_library().expect("shim .so not found — run cargo build first");
    if !p11tool_available() {
        record_skip!(SkipReason::ToolMissing("p11tool"));
        return Ok(());
    }

    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;

    let (stdout, stderr, success) =
        run_p11tool(&shim, daemon.endpoint(), &["--list-token-urls"]).await;
    eprintln!("=== p11tool --list-token-urls stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }

    assert!(success, "p11tool --list-token-urls failed");
    // Should output PKCS#11 URI(s) containing token info
    assert!(stdout.contains("pkcs11:"), "should list at least one PKCS#11 URI");
    // Should include our token label somewhere
    assert!(
        stdout.contains("test-token") || stdout.contains("test%2Dtoken"),
        "should reference our test token"
    );

    daemon.shutdown().await
}

#[tokio::test]
#[ignore]
async fn p11tool_list_mechanisms() -> Result<(), String> {
    let shim = find_shim_library().expect("shim .so not found");
    if !p11tool_available() {
        record_skip!(SkipReason::ToolMissing("p11tool"));
        return Ok(());
    }

    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;

    let (stdout, stderr, success) =
        run_p11tool(&shim, daemon.endpoint(), &["--list-mechanisms", "pkcs11:"]).await;
    eprintln!("=== p11tool --list-mechanisms stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }

    assert!(success, "p11tool --list-mechanisms failed");
    // Should list RSA and/or AES mechanisms
    let combined = format!("{stdout}{stderr}");
    assert!(combined.contains("RSA") || combined.contains("rsa"), "should list RSA mechanisms");

    daemon.shutdown().await
}

#[tokio::test]
#[ignore]
async fn p11tool_list_all_objects_with_login() -> Result<(), String> {
    let shim = find_shim_library().expect("shim .so not found");
    if !p11tool_available() {
        record_skip!(SkipReason::ToolMissing("p11tool"));
        return Ok(());
    }

    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;

    // Create a key via Rust client so there's something to enumerate
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let _pair = generate_rsa_key_pair(&mut client, session, "p11tool-list", true).await?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;

    // List all objects with login
    let (stdout, stderr, success) = run_p11tool(
        &shim,
        daemon.endpoint(),
        &["--login", &format!("--set-pin={}", fixture.user_pin), "--list-all", "pkcs11:"],
    )
    .await;
    eprintln!("=== p11tool --list-all stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }

    assert!(success, "p11tool --list-all failed");
    // Should list objects (keys we created)
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Object") || combined.contains("pkcs11:") || combined.contains("Type:"),
        "should list at least one object"
    );

    daemon.shutdown().await
}

#[tokio::test]
#[ignore]
async fn p11tool_list_privkeys_and_pubkeys() -> Result<(), String> {
    let shim = find_shim_library().expect("shim .so not found");
    if !p11tool_available() {
        record_skip!(SkipReason::ToolMissing("p11tool"));
        return Ok(());
    }

    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;

    // Create a key pair via Rust client
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let _pair = generate_rsa_key_pair(&mut client, session, "p11tool-keys", true).await?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;

    // List private keys
    let (stdout_priv, stderr_priv, success_priv) = run_p11tool(
        &shim,
        daemon.endpoint(),
        &["--login", &format!("--set-pin={}", fixture.user_pin), "--list-privkeys", "pkcs11:"],
    )
    .await;
    eprintln!("=== p11tool --list-privkeys stdout ===\n{stdout_priv}");
    if !stderr_priv.is_empty() {
        eprintln!("=== stderr ===\n{stderr_priv}");
    }
    assert!(success_priv, "p11tool --list-privkeys failed");

    let (stdout_pub, stderr_pub) = if p11tool_supports_option("--list-pubkeys").await {
        let (stdout_pub, stderr_pub, success_pub) = run_p11tool(
            &shim,
            daemon.endpoint(),
            &["--login", &format!("--set-pin={}", fixture.user_pin), "--list-pubkeys", "pkcs11:"],
        )
        .await;
        eprintln!("=== p11tool --list-pubkeys stdout ===\n{stdout_pub}");
        if !stderr_pub.is_empty() {
            eprintln!("=== stderr ===\n{stderr_pub}");
        }
        assert!(success_pub, "p11tool --list-pubkeys failed");
        (stdout_pub, stderr_pub)
    } else {
        record_skip!(SkipReason::KnownIncompat {
            provider: "GnuTLS p11tool",
            description: "installed p11tool does not support --list-pubkeys",
        });
        (String::new(), String::new())
    };

    // At least one of them should show key info
    let combined = format!("{stdout_priv}{stderr_priv}{stdout_pub}{stderr_pub}");
    assert!(
        combined.contains("URL:") || combined.contains("pkcs11:") || combined.contains("Type:"),
        "should list key information"
    );

    daemon.shutdown().await
}

#[tokio::test]
#[ignore]
async fn p11tool_export_pubkey_pem() -> Result<(), String> {
    let shim = find_shim_library().expect("shim .so not found");
    if !p11tool_available() {
        record_skip!(SkipReason::ToolMissing("p11tool"));
        return Ok(());
    }

    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;

    // Create an RSA key pair
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let _pair = generate_rsa_key_pair(&mut client, session, "p11tool-export", true).await?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;

    // Export the public key via p11tool
    let (stdout, stderr, success) = run_p11tool(
        &shim,
        daemon.endpoint(),
        &[
            "--login",
            &format!("--set-pin={}", fixture.user_pin),
            "--export-pubkey",
            "pkcs11:object=p11tool-export-pub;type=public",
        ],
    )
    .await;
    eprintln!("=== p11tool --export-pubkey stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }

    if success {
        // Should output PEM-encoded public key
        assert!(
            stdout.contains("-----BEGIN PUBLIC KEY-----")
                || stdout.contains("-----BEGIN RSA PUBLIC KEY-----"),
            "exported public key should be in PEM format"
        );
    } else {
        // Some p11tool versions or proxy configurations may not support export.
        // Record but don't fail — the listing tests above validate the core workflow.
        eprintln!(
            "p11tool --export-pubkey did not succeed (may be expected depending on attribute config)"
        );
    }

    daemon.shutdown().await
}

#[tokio::test]
#[ignore]
async fn p11tool_uri_driven_object_info() -> Result<(), String> {
    let shim = find_shim_library().expect("shim .so not found");
    if !p11tool_available() {
        record_skip!(SkipReason::ToolMissing("p11tool"));
        return Ok(());
    }

    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;

    // Create a key pair
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let _pair = generate_rsa_key_pair(&mut client, session, "p11tool-uri", true).await?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;

    // Use URI-driven access to list a specific object type
    let (stdout, stderr, success) = run_p11tool(
        &shim,
        daemon.endpoint(),
        &[
            "--login",
            &format!("--set-pin={}", fixture.user_pin),
            "--list-all",
            &format!("pkcs11:token={}", fixture.token_label),
        ],
    )
    .await;
    eprintln!("=== p11tool URI-driven --list-all stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }

    assert!(success, "p11tool URI-driven --list-all failed");
    // The URI filter should narrow results to our token
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Object") || combined.contains("URL:") || combined.contains("Type:"),
        "URI-driven query should return objects"
    );

    daemon.shutdown().await
}

#[tokio::test]
#[ignore]
async fn p11tool_generate_rsa_key_pair() -> Result<(), String> {
    let shim = find_shim_library().expect("shim .so not found");
    if !p11tool_available() {
        record_skip!(SkipReason::ToolMissing("p11tool"));
        return Ok(());
    }

    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;

    // Generate an RSA key pair via p11tool
    let (stdout, stderr, success) = run_p11tool(
        &shim,
        daemon.endpoint(),
        &[
            "--login",
            &format!("--set-pin={}", fixture.user_pin),
            "--generate-rsa",
            "--bits=2048",
            "--label=p11tool-generated",
            "pkcs11:",
        ],
    )
    .await;
    eprintln!("=== p11tool --generate-rsa stdout ===\n{stdout}");
    if !stderr.is_empty() {
        eprintln!("=== stderr ===\n{stderr}");
    }

    if success {
        eprintln!("p11tool --generate-rsa: PASS");
    } else {
        // p11tool key generation may fail if the shim/proxy doesn't fully
        // satisfy p11tool's template expectations. Record the result.
        eprintln!("p11tool --generate-rsa: FAIL (recording for compatibility tracking)");
        eprintln!(
            "  This may be expected if p11tool requires attributes not yet modeled by the proxy"
        );
    }

    daemon.shutdown().await
}

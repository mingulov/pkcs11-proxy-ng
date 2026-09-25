// Task-40 fix round 1 (review I1): a health probe whose `--tls-*` flags
// are unusable must exit 2 (probe failure, like the setup/connect/check
// arms), matching the documented 0/1/2 codes — never exit 1 via `?`.
use std::process::Command;

#[test]
fn health_with_partial_tls_flags_exits_2() {
    let bin = env!("CARGO_BIN_EXE_pkcs11-proxy-ng-cli");
    // Only one of the three TLS file flags: from_optional_paths rejects
    // this before any network I/O, so no daemon is needed.
    let out = Command::new(bin)
        .args(["--tls-ca-cert", "/nonexistent/ca.pem", "health"])
        .output()
        .expect("run health probe binary");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "TLS setup failure must exit 2, stderr: {stderr}");
    assert!(stderr.contains("health probe setup failed"), "must mirror siblings: {stderr}");
}

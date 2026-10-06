// Diagnostics probe failure arms (no daemon needed): unusable TLS
// flags, refused endpoints, bad --format, and zero timeouts must
// all exit 2 (probe failure), matching the `health` codes.
use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pkcs11-proxy-ng-cli"))
}

#[test]
fn diagnostics_with_partial_tls_flags_exits_2() {
    let out = cli()
        .args(["--tls-ca-cert", "/nonexistent/ca.pem", "diagnostics"])
        .output()
        .expect("run diagnostics binary");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "TLS setup failure must exit 2, stderr: {stderr}");
    assert!(stderr.contains("diagnostics probe setup failed"), "must mirror health: {stderr}");
}

#[test]
fn diagnostics_with_refused_endpoint_exits_2() {
    let out = cli()
        .args(["--endpoint", "http://127.0.0.1:1", "diagnostics", "--timeout-secs", "5"])
        .output()
        .expect("run diagnostics binary");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "refused endpoint must exit 2, stderr: {stderr}");
    assert!(stderr.contains("diagnostics connection failed"), "must name the phase: {stderr}");
}

#[test]
fn diagnostics_with_bad_format_exits_2() {
    let out =
        cli().args(["diagnostics", "--format", "yaml"]).output().expect("run diagnostics binary");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "bad format must exit 2, stderr: {stderr}");
    assert!(stderr.contains("--format must be"), "must name the flag: {stderr}");
}

#[test]
fn diagnostics_with_zero_timeout_exits_2() {
    let out = cli()
        .args(["diagnostics", "--timeout-secs", "0"])
        .output()
        .expect("run diagnostics binary");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "zero timeout must exit 2, stderr: {stderr}");
    assert!(stderr.contains("--timeout-secs must be positive"), "must name the flag: {stderr}");
}

use std::process::Command;

#[test]
fn daemon_help_exits_successfully_without_reading_config() {
    let output = Command::new(env!("CARGO_BIN_EXE_pkcs11-proxy-ng"))
        .arg("--help")
        .output()
        .expect("run daemon --help");

    assert!(
        output.status.success(),
        "status: {:?}, stderr: {}",
        output.status.code(),
        stderr(&output)
    );
    let stdout = stdout(&output);
    assert!(stdout.contains("Usage:"), "help should include usage: {stdout}");
    assert!(
        stdout.contains("CONFIG"),
        "help should describe the daemon config path argument: {stdout}"
    );
}

#[test]
fn daemon_version_exits_successfully_without_reading_config() {
    let output = Command::new(env!("CARGO_BIN_EXE_pkcs11-proxy-ng"))
        .arg("--version")
        .output()
        .expect("run daemon --version");

    assert!(
        output.status.success(),
        "status: {:?}, stderr: {}",
        output.status.code(),
        stderr(&output)
    );
    let stdout = stdout(&output);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "version output should include crate version: {stdout}"
    );
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

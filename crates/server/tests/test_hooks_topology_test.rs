//! Subprocess/topology tests for the hook-gated control plane (C3M.6 row 18).
//!
//! Spawns the REAL daemon binary (hook build) as a child process against
//! SoftHSM and drives its control socket over the wire: instance identity
//! must be stable within one daemon and change across a restart, and the
//! fault injector must arm remotely. This is the runner later topology
//! and fault-injection scenarios build on.
//!
//! Requires SoftHSM2 tools and library (`#[ignore]` by repo convention;
//! run with `cargo test -- --ignored`).

#![cfg(feature = "native-owner-test-hooks")]

mod support;
use support::ProviderFixture;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

#[path = "support/bounded_child.rs"]
mod bounded_child;
use bounded_child::BoundedChild;

/// A live hook-enabled daemon child plus its control-socket path.
/// Kills the child on drop so a failed assert cannot leak a daemon.
struct HookDaemon {
    _child: BoundedChild,
    control: PathBuf,
    _dir: tempfile::TempDir,
}

impl HookDaemon {
    fn spawn(fixture: &ProviderFixture, tag: &str) -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir failed: {e}"))?;
        let proxy_sock = dir.path().join("proxy.sock");
        let control_sock = dir.path().join(format!("control-{tag}.sock"));
        let config_path = dir.path().join("daemon.toml");
        std::fs::write(
            &config_path,
            format!(
                "[backend]\nmodule = \"{}\"\n\n\
                 [listener.local]\npath = \"{}\"\nauth = \"peer_cred\"\n\n\
                 [auth]\nallow_all_authenticated = true\n\n\
                 [test_hooks]\ncontrol_socket = \"{}\"\n",
                fixture.module_path.display(),
                proxy_sock.display(),
                control_sock.display(),
            ),
        )
        .map_err(|e| format!("write daemon.toml failed: {e}"))?;

        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11-proxy-ng"));
        command.arg(&config_path);
        let mut child = BoundedChild::spawn(&mut command)?;
        child.wait_for_ready(Duration::from_secs(15), || {
            UnixStream::connect(&control_sock).is_ok()
        })?;
        Ok(Self { _child: child, control: control_sock, _dir: dir })
    }

    /// Raw HTTP/1.1 round trip over the control socket.
    fn round_trip(&self, method: &str, path: &str) -> Result<(String, String), String> {
        let mut s =
            UnixStream::connect(&self.control).map_err(|e| format!("connect failed: {e}"))?;
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("set timeout failed: {e}"))?;
        write!(s, "{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .map_err(|e| format!("write failed: {e}"))?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).map_err(|e| format!("read failed: {e}"))?;
        let resp = String::from_utf8_lossy(&resp).into_owned();
        let mut lines = resp.lines();
        let status = lines.next().unwrap_or("").to_string();
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        Ok((status, body))
    }

    fn instance_id(&self) -> Result<u64, String> {
        let (status, body) = self.round_trip("GET", "/hooks/instance")?;
        if !status.contains("200") {
            return Err(format!("instance endpoint: {status} {body}"));
        }
        body.trim()
            .trim_start_matches("{\"instance_id\":")
            .trim_end_matches('}')
            .parse()
            .map_err(|e| format!("instance body parses: {body} ({e})"))
    }
}

#[tokio::test]
#[ignore] // requires SoftHSM2 tools and library
async fn restart_changes_daemon_instance_identity() {
    let fixture = ProviderFixture::soft_hsm().await.expect("softhsm fixture");

    let first = HookDaemon::spawn(&fixture, "gen1").expect("first daemon comes up");
    let id1 = first.instance_id().expect("first instance id");
    assert_ne!(id1, 0, "instance id must be nonzero");
    drop(first);

    let second = HookDaemon::spawn(&fixture, "gen2").expect("second daemon comes up");
    let id2 = second.instance_id().expect("second instance id");
    assert_ne!(id2, 0, "instance id must be nonzero");
    assert_ne!(id1, id2, "a restarted daemon must report a different instance identity");
}

#[tokio::test]
#[ignore] // requires SoftHSM2 tools and library
async fn control_plane_arms_close_fault_remotely() {
    let fixture = ProviderFixture::soft_hsm().await.expect("softhsm fixture");
    let daemon = HookDaemon::spawn(&fixture, "fault").expect("daemon comes up");

    // Fresh daemon: no mechanism echo recorded yet.
    let (status, body) = daemon.round_trip("GET", "/hooks/last-mechanism").expect("round trip");
    assert!(status.contains("200"), "status: {status} body: {body}");
    assert_eq!(body.trim(), "{\"none\":true}");

    // Arm one injected close failure over the wire.
    let (status, body) = daemon.round_trip("POST", "/hooks/fail-next-close").expect("round trip");
    assert!(status.contains("200"), "status: {status} body: {body}");
    assert_eq!(body.trim(), "{\"armed\":true}");

    // Unknown routes stay 404.
    let (status, _) = daemon.round_trip("GET", "/hooks/nope").expect("round trip");
    assert!(status.contains("404"), "status: {status}");
}

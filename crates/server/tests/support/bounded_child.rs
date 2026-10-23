//! Test-owned children with bounded readiness/exit and file-backed diagnostics.
#![allow(dead_code)] // Each integration target uses only its required operations.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

const DIAGNOSTIC_LIMIT: u64 = 8192;

pub struct BoundedChild {
    child: Child,
    stdout: File,
    stderr: File,
}

impl BoundedChild {
    pub fn spawn(command: &mut Command) -> Result<Self, String> {
        let stdout = tempfile::tempfile().map_err(|e| format!("stdout log: {e}"))?;
        let stderr = tempfile::tempfile().map_err(|e| format!("stderr log: {e}"))?;
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout.try_clone().map_err(|e| e.to_string())?))
            .stderr(Stdio::from(stderr.try_clone().map_err(|e| e.to_string())?))
            .spawn()
            .map_err(|e| format!("spawn child: {e}"))?;
        // Ownership is established immediately after spawn, before readiness.
        Ok(Self { child, stdout, stderr })
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    fn output(&mut self, status: ExitStatus) -> Result<Output, String> {
        fn read_prefix(file: &mut File) -> Result<Vec<u8>, String> {
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut bytes = Vec::new();
            file.take(DIAGNOSTIC_LIMIT).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
            Ok(bytes)
        }
        Ok(Output {
            status,
            stdout: read_prefix(&mut self.stdout)?,
            stderr: read_prefix(&mut self.stderr)?,
        })
    }

    fn stop(&mut self) -> Result<Output, String> {
        let _ = self.child.kill();
        let status = self.child.wait().map_err(|e| format!("reap child: {e}"))?;
        self.output(status)
    }

    fn failure(&mut self, reason: &str) -> String {
        match self.stop() {
            Ok(output) => format!(
                "{reason}; status={} stdout={:?} stderr={:?}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => format!("{reason}; cleanup: {error}"),
        }
    }

    pub fn wait_for_ready(
        &mut self,
        timeout: Duration,
        mut ready: impl FnMut() -> bool,
    ) -> Result<(), String> {
        let start = Instant::now();
        loop {
            if self.child.try_wait().map_err(|e| format!("poll child: {e}"))?.is_some() {
                return Err(self.failure("child exited before readiness"));
            }
            if ready() {
                return Ok(());
            }
            if start.elapsed() >= timeout {
                return Err(self.failure("child never ready before deadline"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn wait(mut self, timeout: Duration) -> Result<Output, String> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().map_err(|e| format!("poll child: {e}"))? {
                // try_wait reaped the child. Logs are regular files, so neither
                // verbose output nor a descendant inheriting them can block EOF.
                return self.output(status);
            }
            if start.elapsed() >= timeout {
                return Err(self.failure("child did not exit before deadline"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for BoundedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

//! Server-side loader for the mechanism registry served to shims.
//!
//! The daemon reads its mechanism config TOML at startup (and on
//! `SIGHUP`), computes a short content-derived revision string, and
//! pre-renders the proto payload. The payload is held in an
//! [`std::sync::RwLock`] so SIGHUP can swap it atomically while
//! readers serving `GetBackendInterfaces` are in flight.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use pkcs11_proxy_ng_proto::MechanismRegistryPayload;
use pkcs11_proxy_ng_types::{EMBEDDED_DEFAULT_REVISION, MechanismRegistry};
use sha2::{Digest, Sha256};

/// Holds the registry payload the daemon serves, plus the file path it
/// was loaded from (so a SIGHUP reload knows where to re-read).
#[derive(Clone)]
pub struct MechanismRegistrySource {
    payload: Arc<RwLock<Arc<MechanismRegistryPayload>>>,
    config_path: Option<PathBuf>,
}

impl MechanismRegistrySource {
    /// Load the registry from the configured file path (or the embedded
    /// default if `config_path` is `None`).
    pub fn load(config_path: Option<&Path>) -> Result<Self, String> {
        let payload = load_payload(config_path)?;
        Ok(Self {
            payload: Arc::new(RwLock::new(Arc::new(payload))),
            config_path: config_path.map(Path::to_path_buf),
        })
    }

    /// Return a cheap clone of the current payload — suitable for
    /// returning in a gRPC response.
    pub fn current(&self) -> Arc<MechanismRegistryPayload> {
        self.payload.read().expect("MechanismRegistrySource RwLock poisoned").clone()
    }

    /// Reload the registry from disk. Used by the daemon's SIGHUP
    /// handler. On failure the current payload is retained and the
    /// error is returned for logging — the daemon must not crash if
    /// the operator ships a malformed registry.
    pub fn reload(&self) -> Result<Arc<MechanismRegistryPayload>, String> {
        let payload = load_payload(self.config_path.as_deref())?;
        let new = Arc::new(payload);
        *self.payload.write().expect("poisoned") = new.clone();
        Ok(new)
    }

    /// The file path the daemon will re-read on SIGHUP, or `None` if
    /// the embedded default is being served.
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }
}

fn load_payload(config_path: Option<&Path>) -> Result<MechanismRegistryPayload, String> {
    match config_path {
        Some(path) => {
            let content = std::fs::read_to_string(path).map_err(|e| {
                format!("failed to read mechanism registry {}: {e}", path.display())
            })?;
            let mut registry = MechanismRegistry::load(Some(path))?;
            registry.set_revision(compute_revision(&content));
            Ok((&registry).into())
        }
        None => {
            // Embedded default; revision is set automatically by load().
            let registry = MechanismRegistry::load(None)?;
            debug_assert_eq!(registry.revision(), EMBEDDED_DEFAULT_REVISION);
            Ok((&registry).into())
        }
    }
}

fn compute_revision(content: &str) -> String {
    let digest = Sha256::digest(content.as_bytes());
    let mut s = String::with_capacity(16);
    for &byte in &digest[..8] {
        const HEX: &[u8] = b"0123456789abcdef";
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn embedded_default_when_no_path() {
        let src = MechanismRegistrySource::load(None).unwrap();
        let payload = src.current();
        assert_eq!(payload.revision, EMBEDDED_DEFAULT_REVISION);
        assert!(!payload.parameterless.is_empty());
        assert!(!payload.params.is_empty());
    }

    #[test]
    fn file_path_revision_is_content_hash() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
            discovery_mode = "filtered"
            [[params]]
            shape = "gcm"
            mechanisms = [0x80000001]
        "#
        )
        .unwrap();
        let src = MechanismRegistrySource::load(Some(f.path())).unwrap();
        let payload = src.current();
        assert_eq!(payload.revision.len(), 16);
        assert_ne!(payload.revision, EMBEDDED_DEFAULT_REVISION);
        assert_eq!(payload.discovery_mode, "filtered");
    }

    #[test]
    fn reload_picks_up_new_content() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
            [[params]]
            shape = "gcm"
            mechanisms = [0x80000001]
        "#
        )
        .unwrap();
        let src = MechanismRegistrySource::load(Some(f.path())).unwrap();
        let first_rev = src.current().revision.clone();

        // Overwrite with new content.
        let path = f.path().to_path_buf();
        std::fs::write(
            &path,
            r#"
            [[params]]
            shape = "iv"
            mechanisms = [0x80000002]
        "#,
        )
        .unwrap();

        let reloaded = src.reload().unwrap();
        assert_ne!(reloaded.revision, first_rev);
        assert!(
            reloaded.params.iter().any(|e| e.shape == "iv" && e.mechanisms.contains(&0x80000002))
        );
    }

    #[test]
    fn reload_failure_retains_current_payload() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "[[params]]\nshape=\"gcm\"\nmechanisms=[1]\n").unwrap();
        let src = MechanismRegistrySource::load(Some(f.path())).unwrap();
        let before = src.current();

        // Delete the file so reload fails.
        let path = f.path().to_path_buf();
        drop(f);
        std::fs::remove_file(&path).ok();
        // Re-create directly to remove (NamedTempFile drop already may unlink, but be sure).
        let _ = std::fs::remove_file(&path);

        let err = src.reload().err().expect("reload must fail without file");
        assert!(err.contains("failed to read mechanism registry"), "actual: {err}");

        let after = src.current();
        // Same Arc instance: payload was not replaced on failure.
        assert!(Arc::ptr_eq(&before, &after), "payload must not change on reload failure");
    }
}

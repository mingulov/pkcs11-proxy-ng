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
    snapshot: Arc<RwLock<Arc<RegistrySnapshot>>>,
    config_path: Option<PathBuf>,
}

struct RegistrySnapshot {
    registry: Arc<MechanismRegistry>,
    payload: Arc<MechanismRegistryPayload>,
}

impl MechanismRegistrySource {
    /// Load the registry from the configured file path (or the embedded
    /// default if `config_path` is `None`).
    pub fn load(config_path: Option<&Path>) -> Result<Self, String> {
        let snapshot = load_snapshot(config_path)?;
        Ok(Self {
            snapshot: Arc::new(RwLock::new(Arc::new(snapshot))),
            config_path: config_path.map(Path::to_path_buf),
        })
    }

    /// Return a cheap clone of the current payload — suitable for
    /// returning in a gRPC response.
    pub fn current(&self) -> Arc<MechanismRegistryPayload> {
        self.snapshot.read().expect("MechanismRegistrySource RwLock poisoned").payload.clone()
    }

    /// Return the parsed registry from the same atomic snapshot as `current`.
    pub fn current_registry(&self) -> Arc<MechanismRegistry> {
        self.snapshot.read().expect("MechanismRegistrySource RwLock poisoned").registry.clone()
    }

    /// Reload the registry from disk. Used by the daemon's SIGHUP
    /// handler. On failure the current payload is retained and the
    /// error is returned for logging — the daemon must not crash if
    /// the operator ships a malformed registry.
    pub fn reload(&self) -> Result<Arc<MechanismRegistryPayload>, String> {
        let snapshot = Arc::new(load_snapshot(self.config_path.as_deref())?);
        let payload = snapshot.payload.clone();
        *self.snapshot.write().expect("poisoned") = snapshot;
        Ok(payload)
    }

    /// The file path the daemon will re-read on SIGHUP, or `None` if
    /// the embedded default is being served.
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }
}

fn load_snapshot(config_path: Option<&Path>) -> Result<RegistrySnapshot, String> {
    let registry = match config_path {
        Some(path) => {
            // W1-C3-02: read the file ONCE. Both the revision hash and the
            // parsed registry derive from this single snapshot, so a
            // concurrent edit (or a SIGHUP racing an operator write) cannot
            // pair a hash of content A with a parse of content B.
            let content = std::fs::read_to_string(path).map_err(|e| {
                format!("failed to read mechanism registry {}: {e}", path.display())
            })?;
            let mut registry = MechanismRegistry::load_from_content(
                &content,
                path.parent().unwrap_or_else(|| Path::new(".")),
            )?;
            registry.set_revision(compute_revision(&content));
            registry
        }
        None => {
            // Embedded default; revision is set automatically by load().
            let registry = MechanismRegistry::load(None)?;
            debug_assert_eq!(registry.revision(), EMBEDDED_DEFAULT_REVISION);
            registry
        }
    };
    let payload = Arc::new((&registry).into());
    Ok(RegistrySnapshot { registry: Arc::new(registry), payload })
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

    /// W1-C3-02: revision hash and parsed registry must come from a single
    /// snapshot read. A writer atomically swapping the file between two
    /// valid registries (rename is atomic, so readers never see torn
    /// content) must never produce a snapshot whose revision names content
    /// A while the payload parses content B.
    #[test]
    fn revision_and_payload_always_pair_from_single_snapshot() {
        use sha2::Digest;
        use std::sync::atomic::{AtomicBool, Ordering};

        fn rev_of(bytes: &[u8]) -> String {
            let digest = sha2::Sha256::digest(bytes);
            let mut s = String::with_capacity(16);
            for &byte in &digest[..8] {
                const HEX: &[u8] = b"0123456789abcdef";
                s.push(HEX[(byte >> 4) as usize] as char);
                s.push(HEX[(byte & 0x0f) as usize] as char);
            }
            s
        }

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("registry.toml");
        // Vendor-range mechanism IDs that the embedded default does not
        // define, so each marker proves which file content was parsed.
        let content_a = "[[params]]\nshape = \"gcm\"\nmechanisms = [0x8000C302]\n";
        let content_b = "[[params]]\nshape = \"iv\"\nmechanisms = [0x8000C303]\n";
        let rev_a = rev_of(content_a.as_bytes());
        let rev_b = rev_of(content_b.as_bytes());
        assert_ne!(rev_a, rev_b);
        std::fs::write(&target, content_a).unwrap();

        const ITERATIONS: usize = 1500;
        let stop = Arc::new(AtomicBool::new(false));
        let writer_stop = stop.clone();
        let writer_target = target.clone();
        let writer = std::thread::spawn(move || {
            let tmp = writer_target.with_extension("toml.tmp");
            for i in 0..ITERATIONS {
                let content = if i % 2 == 0 { content_b } else { content_a };
                std::fs::write(&tmp, content).unwrap();
                std::fs::rename(&tmp, &writer_target).unwrap();
                if writer_stop.load(Ordering::Relaxed) {
                    break;
                }
            }
        });

        let mut checked = 0usize;
        for _ in 0..ITERATIONS {
            let src = match MechanismRegistrySource::load(Some(target.as_path())) {
                Ok(src) => src,
                // A rename landing mid-read can only yield complete A or B
                // (atomic rename); any error here is unexpected but must not
                // mask a pairing violation, so fail loudly instead of skipping.
                Err(e) => panic!("load must succeed on atomically-swapped valid files: {e}"),
            };
            let payload = src.current();
            let has_a = payload.params.iter().any(|e| e.mechanisms.contains(&0x8000C302));
            let has_b = payload.params.iter().any(|e| e.mechanisms.contains(&0x8000C303));
            if payload.revision == rev_a {
                assert!(
                    has_a && !has_b,
                    "W1-C3-02: revision names content A but payload parsed differently"
                );
            } else if payload.revision == rev_b {
                assert!(
                    has_b && !has_a,
                    "W1-C3-02: revision names content B but payload parsed differently"
                );
            } else {
                panic!("W1-C3-02: revision {} matches neither swapped content", payload.revision);
            }
            checked += 1;
        }
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
        assert_eq!(checked, ITERATIONS);
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

        let err = src.reload().expect_err("reload must fail without file");
        assert!(err.contains("failed to read mechanism registry"), "actual: {err}");

        let after = src.current();
        // Same Arc instance: payload was not replaced on failure.
        assert!(Arc::ptr_eq(&before, &after), "payload must not change on reload failure");
    }
}

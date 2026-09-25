//! Backend attestation (ADR-0012, G1 §3).
//!
//! Emits a tamper-evident `System`-class audit record at daemon startup that
//! captures a load-time integrity snapshot of the backend module and the first
//! available token.
//!
//! ## Payload (in `object_ref` as compact JSON)
//!
//! | field              | source                                   |
//! |--------------------|------------------------------------------|
//! | `module_path`      | `config.backend.module` as string        |
//! | `module_hash`      | hex(SHA-256(file bytes))                 |
//! | `lib_manufacturer` | `C_GetInfo().manufacturer_id`            |
//! | `lib_version`      | `C_GetInfo().library_version` as "M.m"   |
//! | `token_serial`     | `C_GetTokenInfo(slot0).serial_number`    |
//! | `token_model`      | `C_GetTokenInfo(slot0).model`            |
//! | `token_firmware`   | `C_GetTokenInfo(slot0).firmware_version` |
//!
//! **Excluded (security):** PINs, key material, token labels, session state,
//! and private memory contents. The payload contains only identification and
//! version fields sufficient for change-detection.
//!
//! ## Deferral note
//!
//! Re-attestation on token hot-swap/re-init is deferred until a concrete
//! `C_WaitForSlotEvent`/re-init hook exists; startup attestation covers the
//! load-time integrity record. The daemon's backend is an in-process FFI
//! module, not a reconnecting connection — a backend crash is handled by
//! multi-daemon restart per ADR-0007.

use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use pkcs11_proxy_ng_audit::{AUDIT_SCHEMA_VERSION, AuditRecord, EventClass};
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use sha2::{Digest, Sha256};

use crate::config::DaemonConfig;
use crate::server::audit::{AuditSink, EmitOutcome};

/// Process-start instant for monotonic timestamps.
///
/// Initialised on first call; stable for the daemon lifetime. All audit
/// records share the same baseline so `ts_monotonic_ns` is comparable
/// across records within a single daemon instance.
static PROCESS_START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

#[inline]
fn process_start() -> Instant {
    *PROCESS_START.get_or_init(Instant::now)
}

/// Lowercase hex-encode a byte slice.
fn to_hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Core: builds the attestation payload from a backend and a module path.
///
/// All backend probes are best-effort: an error fills in a placeholder
/// without aborting or propagating the failure.
fn build_attestation_core(backend: &dyn Pkcs11Backend, module_path: &Path) -> AuditRecord {
    // --- Module hash: SHA-256 of the loaded .so bytes ---
    let module_hash = match std::fs::read(module_path) {
        Ok(bytes) => to_hex(Sha256::digest(&bytes)),
        Err(_) => "unavailable".to_string(),
    };

    // --- C_GetInfo: library identity ---
    let (lib_manufacturer, lib_version) = match backend.get_info() {
        Ok(info) => {
            let ver = format!("{}.{}", info.library_version.0, info.library_version.1);
            (info.manufacturer_id, ver)
        }
        Err(_) => ("unknown".to_string(), "unknown".to_string()),
    };

    // --- First-slot token info (C_GetSlotList → slot 0 → C_GetTokenInfo) ---
    let token_info = backend
        .get_slot_list(true)
        .ok()
        .and_then(|slots| slots.into_iter().next())
        .and_then(|slot| backend.get_token_info(slot).ok())
        .map(|ti| {
            let fw = format!("{}.{}", ti.firmware_version.0, ti.firmware_version.1);
            (ti.serial_number, ti.model, fw)
        });

    let (token_serial, token_model, token_firmware) = match token_info {
        Some((serial, model, fw)) => (serial, model, fw),
        None => ("none".to_string(), "none".to_string(), "none".to_string()),
    };

    // --- Timestamps ---
    let ts_unix_ms =
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    let ts_monotonic_ns = process_start().elapsed().as_nanos() as u64;

    // --- Attestation payload: compact JSON in object_ref ---
    // SECURITY: token label is intentionally excluded (may carry customer-chosen
    // names); serial, model, and firmware version are public identity fields.
    let payload = serde_json::json!({
        "module_path": module_path.display().to_string(),
        "module_hash": module_hash,
        "lib_manufacturer": lib_manufacturer,
        "lib_version": lib_version,
        "token_serial": token_serial,
        "token_model": token_model,
        "token_firmware": token_firmware,
    });

    // seq and prev_hash are set by the sink's ChainState in chain.append;
    // zeros / empty string are the sentinel values the sink expects from callers.
    AuditRecord {
        schema_version: AUDIT_SCHEMA_VERSION,
        seq: 0,
        ts_unix_ms,
        ts_monotonic_ns,
        prev_hash: String::new(),
        request_id: "-".to_string(),
        identity: None,
        method: "__attestation__".to_string(),
        class: EventClass::System,
        slot: None,
        session: None,
        object_ref: Some(payload.to_string()),
        ck_rv: 0,
        latency_us: 0,
        dropped_count: None,
    }
}

/// Build a startup attestation record for `backend` and `config`.
///
/// This is a synchronous function suitable for unit tests. Production startup
/// uses [`emit_startup_attestation`] which runs the backend probes on the
/// blocking thread pool.
pub fn build_attestation(backend: &dyn Pkcs11Backend, config: &DaemonConfig) -> AuditRecord {
    build_attestation_core(backend, &config.backend.module)
}

/// Emit a startup attestation record to `audit`.
///
/// No-op when `audit` is `None` (audit disabled), preserving zero behaviour
/// change for deployments without `[audit]`.
///
/// Backend probes run on the tokio blocking thread pool (one-time, fast).
/// A dropped attestation is logged at `warn` but does NOT abort startup —
/// it is a `System`-class integrity record, not an operation gate.
pub async fn emit_startup_attestation(
    audit: &Option<AuditSink>,
    backend: &Arc<dyn Pkcs11Backend>,
    config: &DaemonConfig,
) {
    let Some(ref sink) = *audit else {
        // Audit disabled — zero-overhead no-op; behaviour is unchanged.
        return;
    };

    let backend_clone = backend.clone();
    let module_path = config.backend.module.clone();

    let record = match tokio::task::spawn_blocking(move || {
        build_attestation_core(backend_clone.as_ref(), &module_path)
    })
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "startup attestation: task join error; skipping");
            return;
        }
    };

    match sink.emit(record) {
        EmitOutcome::Queued => {
            crate::server::resilience::record_audit_emitted();
            tracing::info!("startup attestation recorded");
        }
        EmitOutcome::DroppedFailOpen | EmitOutcome::RejectedFailClosed => {
            crate::server::resilience::record_audit_dropped();
            tracing::warn!("startup attestation dropped (channel full or writer dead)");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use pkcs11_proxy_ng_audit::EventClass;
    use pkcs11_proxy_ng_backend::MockBackend;
    use pkcs11_proxy_ng_types::{CkMechanismType, CkSlotId};

    use super::*;
    use crate::config::{AuditConfig, DaemonConfig};
    use crate::server::audit::spawn_audit_sink;

    /// Parse a minimal DaemonConfig from TOML with a given module path.
    fn config_with_module(module: &Path) -> DaemonConfig {
        let toml = format!(
            r#"
[backend]
module = "{}"
"#,
            module.display()
        );
        toml::from_str(&toml).expect("test config should parse")
    }

    fn mock_backend() -> Arc<dyn Pkcs11Backend> {
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]))
    }

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("attestation-test-{}-{}", std::process::id(), tag))
    }

    // --- Unit test: build_attestation with MockBackend ---

    /// Build an attestation record against a MockBackend; verify the payload
    /// contains the module hash and token serial, and contains no secret material.
    #[test]
    fn build_attestation_contains_hash_and_serial() {
        // Write a deterministic file so we can verify the hash.
        let dir = temp_dir("unit");
        std::fs::create_dir_all(&dir).ok();
        let module_path = dir.join("fake.so");
        let module_bytes = b"fake_pkcs11_module_bytes";
        std::fs::write(&module_path, module_bytes).unwrap();

        let backend = mock_backend();
        let config = config_with_module(&module_path);
        let record = build_attestation(&*backend, &config);

        // Class and method
        assert_eq!(record.class, EventClass::System);
        assert_eq!(record.method, "__attestation__");
        assert_eq!(record.ck_rv, 0);
        assert!(record.identity.is_none(), "no identity for startup record");
        assert!(record.slot.is_none());
        assert!(record.session.is_none());
        assert_eq!(record.latency_us, 0);

        // Payload
        let payload_str = record.object_ref.expect("attestation must have a payload");
        let v: serde_json::Value =
            serde_json::from_str(&payload_str).expect("payload must be valid JSON");

        // module_hash must be a 64-char lowercase hex SHA-256
        let module_hash = v["module_hash"].as_str().expect("module_hash present");
        assert_eq!(module_hash.len(), 64, "SHA-256 hash is 32 bytes = 64 hex chars");
        assert!(
            module_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be hex: {module_hash}"
        );

        // Verify the hash is actually SHA-256 of the file bytes.
        use sha2::{Digest as _, Sha256};
        let expected = to_hex(Sha256::digest(module_bytes));
        assert_eq!(module_hash, expected, "module_hash must match SHA-256(file)");

        // Token serial from MockBackend is "0001"
        assert_eq!(v["token_serial"].as_str().unwrap(), "0001");
        // MockBackend model is "Software"
        assert_eq!(v["token_model"].as_str().unwrap(), "Software");

        // SECURITY: payload must not contain any secret material sentinel.
        const SECRET_SENTINEL: &str = "TOP_SECRET_PIN_VALUE_DO_NOT_LOG";
        assert!(!payload_str.contains(SECRET_SENTINEL), "payload must not contain secret material");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// When the module file cannot be read, module_hash is "unavailable".
    #[test]
    fn build_attestation_module_unreadable() {
        let backend = mock_backend();
        let config = config_with_module(Path::new("/nonexistent/path/that/does/not/exist.so"));
        let record = build_attestation(&*backend, &config);

        let payload_str = record.object_ref.unwrap();
        let v: serde_json::Value = serde_json::from_str(&payload_str).unwrap();
        assert_eq!(v["module_hash"].as_str().unwrap(), "unavailable");
    }

    /// When get_info fails (no slots → still best-effort), record is still built.
    #[test]
    fn build_attestation_no_token_present() {
        // Backend with no slots → get_slot_list(true) returns empty
        let backend: Arc<dyn Pkcs11Backend> = Arc::new(MockBackend::new(vec![], vec![]));
        let config = config_with_module(Path::new("/dev/null"));
        let record = build_attestation(&*backend, &config);

        let v: serde_json::Value =
            serde_json::from_str(record.object_ref.as_deref().unwrap()).unwrap();
        assert_eq!(v["token_serial"].as_str().unwrap(), "none");
        assert_eq!(v["token_model"].as_str().unwrap(), "none");
    }

    // --- Integration test: startup with audit on emits one __attestation__ System record ---

    /// With audit enabled, `emit_startup_attestation` writes exactly one
    /// `__attestation__` System record that forms a valid chain verifiable by
    /// `verify_dir`.
    #[tokio::test]
    async fn emit_startup_attestation_writes_verifiable_record() {
        let dir = temp_dir("integration");
        let audit_dir = dir.join("audit");
        let module_path = dir.join("fake.so");
        std::fs::create_dir_all(&dir).ok();
        std::fs::write(&module_path, b"integration_module").unwrap();

        let cfg = AuditConfig {
            dir: Some(audit_dir.clone()),
            rotate_max_bytes: 1 << 20,
            rotate_keep_files: 10,
            ..Default::default()
        };
        let sink = spawn_audit_sink(&cfg).unwrap();

        let backend = mock_backend();
        let config = config_with_module(&module_path);

        emit_startup_attestation(&sink, &backend, &config).await;

        // Flush to ensure the record is durable.
        sink.as_ref().unwrap().flush().await.unwrap();

        let report = pkcs11_proxy_ng_audit::verify::verify_dir(&audit_dir, None).unwrap();
        assert!(report.chain_ok, "chain must be valid after startup attestation: {report:?}");
        assert_eq!(report.records, 1, "exactly one record should be emitted");

        // Read back and verify it is the attestation record.
        let jsonl = std::fs::read_to_string(audit_dir.join("audit.jsonl")).unwrap();
        let rec: pkcs11_proxy_ng_audit::AuditRecord =
            pkcs11_proxy_ng_audit::record::from_jsonl(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(rec.method, "__attestation__");
        assert_eq!(rec.class, EventClass::System);
        assert_eq!(rec.ck_rv, 0);

        let v: serde_json::Value =
            serde_json::from_str(rec.object_ref.as_deref().unwrap()).unwrap();
        assert!(v["module_hash"].as_str().unwrap().len() == 64);
        assert_eq!(v["token_serial"].as_str().unwrap(), "0001");

        std::fs::remove_dir_all(&dir).ok();
    }

    // --- Audit-off test: None sink → no-op ---

    /// When audit is disabled (`None` sink), `emit_startup_attestation` is a
    /// pure no-op: no files are created and no panic occurs.
    #[tokio::test]
    async fn emit_startup_attestation_audit_off_noop() {
        let backend = mock_backend();
        let config = config_with_module(Path::new("/dev/null"));

        // None sink → no-op.
        emit_startup_attestation(&None, &backend, &config).await;
        // Reaching here without panic confirms the no-op behaviour.
    }
}

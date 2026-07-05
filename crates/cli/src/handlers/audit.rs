//! `audit verify <dir>` subcommand handler (ADR-0012 G1 Task 6).
//!
//! Reads local audit log files — no daemon connection required.

use std::path::Path;

use pkcs11_proxy_ng_audit::verify::verify_dir;

use super::CliResult;

/// Verify a directory of audit log files.
///
/// Calls [`verify_dir`], prints a human-readable summary, and returns a
/// non-zero exit code (via `Err`) if the hash chain is broken or any
/// checkpoint signature failed, so CI pipelines can gate on it.
pub(crate) fn verify(dir: &Path, public_key_hex: Option<&str>) -> CliResult {
    let report =
        verify_dir(dir, public_key_hex).map_err(|e| format!("audit verify failed: {e}"))?;

    println!("Audit directory: {}", dir.display());
    println!("  files       : {}", report.files);
    println!("  records     : {}", report.records);
    if report.records > 0 {
        println!("  seq range   : {}..={}", report.first_seq, report.last_seq);
    } else {
        println!("  seq range   : (empty)");
    }
    println!("  chain_ok    : {}", report.chain_ok);
    println!("  anchor      : {}", if report.head_matches_anchor { "matches" } else { "MISMATCH" });
    println!("  gaps        : {}", report.gaps.len());
    if !report.gaps.is_empty() {
        println!("  gap seqs    : {:?}", report.gaps);
    }
    if report.signature_checked {
        println!(
            "  checkpoints : {} verified, {} failed",
            report.checkpoints_verified, report.checkpoints_failed
        );
    } else {
        println!("  checkpoints : (signatures not checked — no key supplied or no sidecar)");
    }

    if !report.chain_ok {
        return Err("audit verify: hash chain is broken".into());
    }
    if report.checkpoints_failed > 0 {
        return Err(format!(
            "audit verify: {} checkpoint(s) failed (signature or content-binding)",
            report.checkpoints_failed
        )
        .into());
    }

    println!("OK");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use pkcs11_proxy_ng_audit::chain::ChainState;
    use pkcs11_proxy_ng_audit::record::{AuditRecord, EventClass, to_jsonl};

    use super::*;

    fn make_record(method: &str, ck_rv: u64) -> AuditRecord {
        AuditRecord {
            schema_version: pkcs11_proxy_ng_audit::AUDIT_SCHEMA_VERSION,
            seq: 0,
            ts_unix_ms: 1_000,
            ts_monotonic_ns: 1_000,
            prev_hash: String::new(),
            request_id: "test-req-id".into(),
            identity: Some("uid=1000".into()),
            method: method.into(),
            class: EventClass::Auth,
            slot: Some(0),
            session: Some(1),
            object_ref: None,
            ck_rv,
            latency_us: 10,
        }
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cli-audit-verify-{}-{}", std::process::id(), tag))
    }

    #[test]
    fn valid_chain_returns_ok() {
        let dir = temp_dir("valid");
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut r0 = make_record("C_Login", 0);
        let mut r1 = make_record("C_Logout", 0);
        st.append(&mut r0);
        st.append(&mut r1);

        fs::write(dir.join("audit.jsonl"), format!("{}{}", to_jsonl(&r0), to_jsonl(&r1))).unwrap();

        let result = verify(&dir, None);
        fs::remove_dir_all(&dir).unwrap();
        assert!(result.is_ok(), "valid chain must return Ok, got: {result:?}");
    }

    #[test]
    fn corrupted_record_returns_err() {
        let dir = temp_dir("corrupt");
        fs::create_dir_all(&dir).unwrap();

        let mut st = ChainState::genesis();
        let mut r0 = make_record("C_Login", 0);
        let mut r1 = make_record("C_Logout", 0);
        st.append(&mut r0);
        st.append(&mut r1);

        // Tamper with r0 after chain construction — flipped ck_rv breaks the hash.
        let mut tampered = r0.clone();
        tampered.ck_rv = 0xFF;

        fs::write(dir.join("audit.jsonl"), format!("{}{}", to_jsonl(&tampered), to_jsonl(&r1)))
            .unwrap();

        let result = verify(&dir, None);
        fs::remove_dir_all(&dir).unwrap();
        assert!(result.is_err(), "corrupted chain must return Err, got: Ok(())");
    }
}

//! Audit emission helpers for auth/key-management operations (G1-PR2, ADR-0012).
//!
//! All security-sensitive PKCS#11 operations (auth, key-mgmt, system lifecycle)
//! emit a tamper-evident audit record via the `AuditSink` held on
//! `HandlerContext`. The sink applies per-class fail policy: Auth/KeyMgmt/System
//! are fail-closed, so if the channel is full or the writer is dead the
//! operation is REJECTED with `CKR_FUNCTION_FAILED` rather than silently
//! proceeding unaudited.
//!
//! SECURITY: audit records MUST NOT contain PINs, keys, labels, or any other
//! sensitive request payload — only method/identity/slot/session/ck_rv/latency.
//! (CLAUDE.md §4.)

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use pkcs11_proxy_ng_audit::{AUDIT_SCHEMA_VERSION, AuditRecord, EventClass};

use super::context::HandlerContext;
use crate::server::context_manager::ClientContextId;

/// Process-start instant for monotonic timestamps.
///
/// Initialised on first call; stable for the daemon lifetime. All audit
/// records share the same baseline, so `ts_monotonic_ns` is comparable
/// across records within a single daemon instance.
static PROCESS_START: OnceLock<Instant> = OnceLock::new();

#[inline]
fn process_start() -> Instant {
    *PROCESS_START.get_or_init(Instant::now)
}

/// Emit a single audit record for an auth/key-management operation.
///
/// # Fail-closed contract
///
/// Returns `Ok(())` when audit is disabled (`ctx.audit` is `None`) — a
/// zero-overhead no-op that preserves byte-identical behaviour for deployments
/// without `[audit]` — or when the sink accepted the record.
///
/// Returns `Err(())` when the sink rejected the record. The per-class fail
/// policy lives in `AuditSink::emit`, not here: fail-open classes (DataPlane)
/// drop and return `Ok` under back-pressure, while fail-closed classes (Auth,
/// KeyMgmt, System) return `Err` when the channel is full or the writer is dead.
/// Callers MUST respond with `CKR_FUNCTION_FAILED` on `Err` — never silently
/// return the original ck_rv for an unaudited security operation.
///
/// ## Fail-closed-after-side-effect (accepted divergence, ADR-0012)
///
/// The wired handlers perform the backend operation FIRST, then emit. If a
/// fail-closed emit fails (sink saturated or writer dead) the handler returns
/// `CKR_FUNCTION_FAILED` even though the operation may ALREADY have committed on
/// the shared backend (e.g. `C_Login` logged the token in; `C_OpenSession`
/// opened a session that is now leaked from the client's view). The
/// client-visible failure can therefore diverge from backend state. This is a
/// deliberate trade-off: under audit saturation we refuse to *confirm* an
/// unaudited security action rather than report success for something we could
/// not record. It occurs only when audit is enabled and the sink is saturated.
///
/// # PIN safety
///
/// This function accepts only `method`, `class`, `slot`, `session`, `ck_rv`,
/// and timing. It MUST NOT be called with any PIN, key, label, or sensitive
/// request payload in any parameter.
pub(super) fn emit_auth_event(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    method: &'static str,
    class: EventClass,
    slot: Option<u64>,
    session: Option<u64>,
    ck_rv: u64,
    started_at: Instant,
) -> Result<(), ()> {
    let Some(ref sink) = ctx.audit else {
        // Audit disabled — zero-overhead no-op; behaviour is unchanged.
        return Ok(());
    };

    let ts_unix_ms =
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;

    // ts_monotonic_ns: nanoseconds since process start on the monotonic clock.
    let ts_monotonic_ns = process_start().elapsed().as_nanos() as u64;
    let latency_us = started_at.elapsed().as_micros() as u64;

    // Identity: looked up from the live context map.  Absent for finalize
    // (context already removed) or unknown ctx_id — both resolve to None.
    // When an anonymous_principal is configured, audit_identity() substitutes
    // its name for unauthenticated peers ("unauthenticated" / None) so audit
    // records carry a meaningful label instead of the raw marker.
    let identity =
        ctx.token_policy.audit_identity(ctx.context_manager.context_identity(ctx_id).as_deref());

    // seq and prev_hash are set by the sink's ChainState in chain.append;
    // zeros are the sentinel values the sink expects from callers.
    let rec = AuditRecord {
        schema_version: AUDIT_SCHEMA_VERSION,
        seq: 0,
        ts_unix_ms,
        ts_monotonic_ns,
        prev_hash: String::new(),
        request_id: "-".to_string(),
        identity,
        method: method.to_string(),
        class,
        slot,
        session,
        object_ref: None,
        ck_rv,
        latency_us,
    };

    // NOTE: when data-plane fail-OPEN emission lands, a silently-dropped fail-open
    // record returns Ok here and would be miscounted as emitted — that path must
    // increment record_audit_dropped (or a separate counter) at the sink drop site.
    // Tracked in the 2026-07-06 gap analysis.
    match sink.emit(rec) {
        Ok(()) => {
            crate::server::resilience::record_audit_emitted();
            Ok(())
        }
        Err(_dropped) => {
            crate::server::resilience::record_audit_dropped();
            Err(())
        }
    }
}

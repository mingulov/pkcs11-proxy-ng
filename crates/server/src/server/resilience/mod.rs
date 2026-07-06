//! Opt-in, count-only detection of pathological object populations, plus a
//! snapshot for the local metrics endpoint. Pure in-process observation: never
//! issues a backend call and never changes client-visible behaviour (design V15).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

mod metrics_endpoint;
pub use metrics_endpoint::spawn_metrics_endpoint;

#[cfg(test)]
mod tests;

/// Configured find-result threshold. `None` => detection off. Set once at startup.
static FIND_WARN_THRESHOLD: OnceLock<Option<usize>> = OnceLock::new();

static FIND_OBJECTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static FIND_OBJECTS_OVER_THRESHOLD_TOTAL: AtomicU64 = AtomicU64::new(0);
static FIND_RESULT_SIZE_MAX: AtomicUsize = AtomicUsize::new(0);
static GET_ATTRIBUTE_VALUE_TOTAL: AtomicU64 = AtomicU64::new(0);
static AUDIT_EMITTED: AtomicU64 = AtomicU64::new(0);
static AUDIT_DROPPED: AtomicU64 = AtomicU64::new(0);
static RATE_LIMIT_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static SESSION_QUOTA_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static LOGIN_BUDGET_TRIPPED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Install the configured threshold once at startup. First call wins.
pub fn configure(find_result_warn_threshold: Option<usize>) {
    let _ = FIND_WARN_THRESHOLD.set(find_result_warn_threshold);
}

fn threshold() -> Option<usize> {
    FIND_WARN_THRESHOLD.get().copied().flatten()
}

/// Pure: is `count` strictly greater than a configured `threshold`?
/// `None` threshold (detection off) is never over.
fn is_over_threshold(count: usize, threshold: Option<usize>) -> bool {
    matches!(threshold, Some(t) if count > t)
}

/// Observe one `C_FindObjects` result size. Returns true if it crossed the
/// configured threshold (caller may emit a structured log). Count-only.
pub fn observe_find_result(count: usize) -> bool {
    FIND_OBJECTS_TOTAL.fetch_add(1, Ordering::Relaxed);
    FIND_RESULT_SIZE_MAX.fetch_max(count, Ordering::Relaxed);
    if is_over_threshold(count, threshold()) {
        FIND_OBJECTS_OVER_THRESHOLD_TOTAL.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// Record one `C_GetAttributeValue` call (standard and exact paths).
pub fn record_get_attribute_value() {
    GET_ATTRIBUTE_VALUE_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record one successfully enqueued audit record.
pub fn record_audit_emitted() {
    AUDIT_EMITTED.fetch_add(1, Ordering::Relaxed);
}

/// Record one audit record that was dropped or rejected by the fail policy.
pub fn record_audit_dropped() {
    AUDIT_DROPPED.fetch_add(1, Ordering::Relaxed);
}

/// Record one operation rejected by the per-principal in-flight cap.
pub fn record_rate_limit_rejected() {
    RATE_LIMIT_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record one session-open rejected by the per-principal session quota.
pub fn record_session_quota_rejected() {
    SESSION_QUOTA_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record one per-slot failed-login budget that tripped into cooldown.
pub fn record_login_budget_tripped() {
    LOGIN_BUDGET_TRIPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Immutable counter snapshot for the metrics endpoint.
#[derive(Debug, Clone, Copy)]
pub struct Snapshot {
    pub find_objects_total: u64,
    pub find_objects_over_threshold_total: u64,
    pub find_result_size_max: usize,
    pub get_attribute_value_total: u64,
    pub audit_emitted_total: u64,
    pub audit_dropped_total: u64,
    pub rate_limit_rejected_total: u64,
    pub session_quota_rejected_total: u64,
    pub login_budget_tripped_total: u64,
}

pub fn snapshot() -> Snapshot {
    Snapshot {
        find_objects_total: FIND_OBJECTS_TOTAL.load(Ordering::Relaxed),
        find_objects_over_threshold_total: FIND_OBJECTS_OVER_THRESHOLD_TOTAL
            .load(Ordering::Relaxed),
        find_result_size_max: FIND_RESULT_SIZE_MAX.load(Ordering::Relaxed),
        get_attribute_value_total: GET_ATTRIBUTE_VALUE_TOTAL.load(Ordering::Relaxed),
        audit_emitted_total: AUDIT_EMITTED.load(Ordering::Relaxed),
        audit_dropped_total: AUDIT_DROPPED.load(Ordering::Relaxed),
        rate_limit_rejected_total: RATE_LIMIT_REJECTED_TOTAL.load(Ordering::Relaxed),
        session_quota_rejected_total: SESSION_QUOTA_REJECTED_TOTAL.load(Ordering::Relaxed),
        login_budget_tripped_total: LOGIN_BUDGET_TRIPPED_TOTAL.load(Ordering::Relaxed),
    }
}

/// Render a snapshot in Prometheus text exposition format (v0.0.4).
pub fn render_prometheus(s: &Snapshot) -> String {
    let mut o = String::new();
    o.push_str("# HELP pkcs11_proxy_find_objects_total Successful C_FindObjects calls observed.\n");
    o.push_str("# TYPE pkcs11_proxy_find_objects_total counter\n");
    o.push_str(&format!("pkcs11_proxy_find_objects_total {}\n", s.find_objects_total));
    o.push_str("# HELP pkcs11_proxy_find_objects_over_threshold_total C_FindObjects results over the configured threshold.\n");
    o.push_str("# TYPE pkcs11_proxy_find_objects_over_threshold_total counter\n");
    o.push_str(&format!(
        "pkcs11_proxy_find_objects_over_threshold_total {}\n",
        s.find_objects_over_threshold_total
    ));
    o.push_str(
        "# HELP pkcs11_proxy_find_result_size_max Largest single C_FindObjects result observed.\n",
    );
    o.push_str("# TYPE pkcs11_proxy_find_result_size_max gauge\n");
    o.push_str(&format!("pkcs11_proxy_find_result_size_max {}\n", s.find_result_size_max));
    o.push_str(
        "# HELP pkcs11_proxy_get_attribute_value_total Total C_GetAttributeValue calls observed.\n",
    );
    o.push_str("# TYPE pkcs11_proxy_get_attribute_value_total counter\n");
    o.push_str(&format!(
        "pkcs11_proxy_get_attribute_value_total {}\n",
        s.get_attribute_value_total
    ));
    o.push_str("# HELP pkcs11_proxy_audit_emitted_total Audit records successfully enqueued.\n");
    o.push_str("# TYPE pkcs11_proxy_audit_emitted_total counter\n");
    o.push_str(&format!("pkcs11_proxy_audit_emitted_total {}\n", s.audit_emitted_total));
    o.push_str(
        "# HELP pkcs11_proxy_audit_dropped_total Audit records dropped or rejected by the fail policy.\n",
    );
    o.push_str("# TYPE pkcs11_proxy_audit_dropped_total counter\n");
    o.push_str(&format!("pkcs11_proxy_audit_dropped_total {}\n", s.audit_dropped_total));
    o.push_str("# HELP pkcs11_proxy_rate_limit_rejected_total Operations rejected by the per-principal in-flight cap.\n");
    o.push_str("# TYPE pkcs11_proxy_rate_limit_rejected_total counter\n");
    o.push_str(&format!(
        "pkcs11_proxy_rate_limit_rejected_total {}\n",
        s.rate_limit_rejected_total
    ));
    o.push_str("# HELP pkcs11_proxy_session_quota_rejected_total Session opens rejected by the per-principal session quota.\n");
    o.push_str("# TYPE pkcs11_proxy_session_quota_rejected_total counter\n");
    o.push_str(&format!(
        "pkcs11_proxy_session_quota_rejected_total {}\n",
        s.session_quota_rejected_total
    ));
    o.push_str("# HELP pkcs11_proxy_login_budget_tripped_total Per-slot failed-login budgets that have entered cooldown.\n");
    o.push_str("# TYPE pkcs11_proxy_login_budget_tripped_total counter\n");
    o.push_str(&format!(
        "pkcs11_proxy_login_budget_tripped_total {}\n",
        s.login_budget_tripped_total
    ));
    o
}

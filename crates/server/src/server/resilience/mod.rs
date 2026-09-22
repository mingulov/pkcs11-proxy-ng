//! Opt-in, count-only detection of pathological object populations, plus a
//! snapshot for the local metrics endpoint. Pure in-process observation: never
//! issues a backend call and never changes client-visible behaviour (design V15).

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[cfg(unix)]
mod metrics_endpoint;
#[cfg(unix)]
pub use metrics_endpoint::spawn_metrics_endpoint;

#[cfg(not(unix))]
pub async fn spawn_metrics_endpoint(_path: std::path::PathBuf) -> Result<(), String> {
    Err("resilience.metrics_socket requires Unix-domain socket support".to_string())
}

#[cfg(test)]
mod tests;

/// Process-global resilience configuration, installed once at startup.
/// `None` => unconfigured (detection off, coalescer disabled).
///
/// W1-C2-11: a `Mutex<Option<…>>` (not `OnceLock`) so tests can reset to a
/// known baseline under `CONFIG_TEST_GUARD` (test-only). Production
/// semantics are unchanged: [`configure`] is still first-wins.
static CONFIG: Mutex<Option<ResilienceConfig>> = Mutex::new(None);

#[derive(Clone, Copy)]
struct ResilienceConfig {
    /// Configured find-result threshold. `None` => detection off.
    find_warn_threshold: Option<usize>,
    /// Whether the session-scoped attribute coalescer is enabled (R2).
    coalesce_attributes: bool,
}

/// Serializes all tests that mutate the process-global [`CONFIG`] (W1-C2-11).
///
/// Every configure-touching test holds this guard across its whole body:
/// the holder's `configure` value cannot be reset mid-test by another
/// test. An async mutex: awaiting it never blocks an executor thread, so
/// holding it across `.await` in async tests is safe (each test runs on
/// its own thread/runtime; sync tests use `blocking_lock`).
#[cfg(test)]
pub(crate) static CONFIG_TEST_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Clear [`CONFIG`] back to unconfigured (test only).
///
/// Call with [`CONFIG_TEST_GUARD`] held; reconfigure afterwards so tests
/// that never call `configure` keep observing the ambient state.
#[cfg(test)]
pub(crate) fn reset_config_for_test() {
    *CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

static FIND_OBJECTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static FIND_OBJECTS_OVER_THRESHOLD_TOTAL: AtomicU64 = AtomicU64::new(0);
static FIND_RESULT_SIZE_MAX: AtomicUsize = AtomicUsize::new(0);
static GET_ATTRIBUTE_VALUE_TOTAL: AtomicU64 = AtomicU64::new(0);
static AUDIT_EMITTED: AtomicU64 = AtomicU64::new(0);
static AUDIT_DROPPED: AtomicU64 = AtomicU64::new(0);
static RATE_LIMIT_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static SESSION_QUOTA_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static LOGIN_BUDGET_TRIPPED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Attribute coalescer cache hits (R2). Incremented by the serving path.
static ATTR_COALESCE_HITS: AtomicU64 = AtomicU64::new(0);
/// Attribute coalescer cache misses (R2). Incremented by the serving path.
static ATTR_COALESCE_MISSES: AtomicU64 = AtomicU64::new(0);

/// Install the configured thresholds and feature flags once at startup. First call wins.
pub fn configure(find_result_warn_threshold: Option<usize>, coalesce_attributes: bool) {
    let mut guard = CONFIG.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(ResilienceConfig {
            find_warn_threshold: find_result_warn_threshold,
            coalesce_attributes,
        });
    }
}

/// Whether the session-scoped attribute coalescer is active (R2).
/// Returns `false` when [`configure`] has not been called (safe default: no caching).
pub fn coalesce_enabled() -> bool {
    CONFIG.lock().unwrap_or_else(|e| e.into_inner()).map(|c| c.coalesce_attributes).unwrap_or(false)
}

/// Record one attribute coalescer cache hit (R2). Called by the serving path.
pub fn record_attr_coalesce_hit() {
    ATTR_COALESCE_HITS.fetch_add(1, Ordering::Relaxed);
}

/// Record one attribute coalescer cache miss (R2). Called by the serving path.
pub fn record_attr_coalesce_miss() {
    ATTR_COALESCE_MISSES.fetch_add(1, Ordering::Relaxed);
}

fn threshold() -> Option<usize> {
    CONFIG.lock().unwrap_or_else(|e| e.into_inner()).and_then(|c| c.find_warn_threshold)
}

/// Pure: is `count` strictly greater than a configured `threshold`?
/// `None` threshold (detection off) is never over.
fn is_over_threshold(count: usize, threshold: Option<usize>) -> bool {
    matches!(threshold, Some(t) if count > t)
}

/// Configured find-result threshold, if detection is on. `find_objects`
/// reuses it as its filter-scan bound (W1-C1-07); `None` means unbounded.
pub fn find_scan_bound() -> Option<usize> {
    threshold()
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
    /// R2 attribute coalescer: reads served from the session cache.
    pub attr_coalesce_hits_total: u64,
    /// R2 attribute coalescer: cacheable reads that missed and hit the backend.
    pub attr_coalesce_misses_total: u64,
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
        attr_coalesce_hits_total: ATTR_COALESCE_HITS.load(Ordering::Relaxed),
        attr_coalesce_misses_total: ATTR_COALESCE_MISSES.load(Ordering::Relaxed),
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
        "# HELP pkcs11_proxy_audit_dropped_total Fail-open DataPlane records dropped \
         (channel near capacity) OR fail-closed Auth/KeyMgmt/System/Deny records rejected \
         (channel full or writer dead).\n",
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
    o.push_str("# HELP pkcs11_proxy_attr_coalesce_hits_total Attribute reads served from the session cache.\n");
    o.push_str("# TYPE pkcs11_proxy_attr_coalesce_hits_total counter\n");
    o.push_str(&format!("pkcs11_proxy_attr_coalesce_hits_total {}\n", s.attr_coalesce_hits_total));
    o.push_str("# HELP pkcs11_proxy_attr_coalesce_misses_total Cacheable attribute reads that missed the cache and hit the backend.\n");
    o.push_str("# TYPE pkcs11_proxy_attr_coalesce_misses_total counter\n");
    o.push_str(&format!(
        "pkcs11_proxy_attr_coalesce_misses_total {}\n",
        s.attr_coalesce_misses_total
    ));
    o
}

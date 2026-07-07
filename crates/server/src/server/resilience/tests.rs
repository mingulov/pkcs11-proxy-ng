use super::*;

#[test]
fn coalesce_enabled_reflects_configure() {
    // configure() sets the OnceLock; first call wins for the process lifetime.
    // We call configure(true) here; since no other test in this binary calls
    // configure(), this is the first call and coalesce_enabled() must be true.
    // The record_attr_coalesce_{hit,miss} functions must also be callable
    // without panicking (they are reserved for Task 2/3).
    configure(None, true);
    assert!(coalesce_enabled(), "coalesce_enabled must be true after configure(…, true)");
    // Smoke-test the reserved record fns (no assertion — they just must not panic).
    record_attr_coalesce_hit();
    record_attr_coalesce_miss();
}

#[test]
fn over_threshold_classification() {
    assert!(!is_over_threshold(0, None)); // detection off => never
    assert!(!is_over_threshold(10_000, None));
    assert!(!is_over_threshold(5, Some(5))); // strictly greater
    assert!(is_over_threshold(6, Some(5)));
    assert!(!is_over_threshold(0, Some(0)));
    assert!(is_over_threshold(1, Some(0)));
}

#[test]
fn prometheus_render_contains_all_series() {
    let s = Snapshot {
        find_objects_total: 3,
        find_objects_over_threshold_total: 1,
        find_result_size_max: 2106,
        get_attribute_value_total: 4213,
        audit_emitted_total: 57,
        audit_dropped_total: 2,
        rate_limit_rejected_total: 11,
        session_quota_rejected_total: 5,
        login_budget_tripped_total: 3,
    };
    let text = render_prometheus(&s);
    assert!(text.contains("pkcs11_proxy_find_objects_total 3\n"));
    assert!(text.contains("pkcs11_proxy_find_objects_over_threshold_total 1\n"));
    assert!(text.contains("pkcs11_proxy_find_result_size_max 2106\n"));
    assert!(text.contains("pkcs11_proxy_get_attribute_value_total 4213\n"));
    assert!(text.contains("# TYPE pkcs11_proxy_find_objects_total counter"));
    // Audit counters
    assert!(text.contains("pkcs11_proxy_audit_emitted_total 57\n"));
    assert!(text.contains("pkcs11_proxy_audit_dropped_total 2\n"));
    assert!(text.contains("# TYPE pkcs11_proxy_audit_emitted_total counter"));
    assert!(text.contains("# TYPE pkcs11_proxy_audit_dropped_total counter"));
    // Rate-quota counters
    assert!(text.contains("pkcs11_proxy_rate_limit_rejected_total 11\n"));
    assert!(text.contains("pkcs11_proxy_session_quota_rejected_total 5\n"));
    assert!(text.contains("pkcs11_proxy_login_budget_tripped_total 3\n"));
    assert!(text.contains("# TYPE pkcs11_proxy_rate_limit_rejected_total counter"));
    assert!(text.contains("# TYPE pkcs11_proxy_session_quota_rejected_total counter"));
    assert!(text.contains("# TYPE pkcs11_proxy_login_budget_tripped_total counter"));
}

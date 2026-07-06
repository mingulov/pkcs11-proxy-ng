use super::*;

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

use super::*;

#[test]
fn coalesce_enabled_reflects_configure() {
    // W1-C2-11: hold the serial guard and reset first — no reliance on
    // "no other test calls configure()" (attributes/auth tests call it
    // too). configure() is first-wins; with a reset baseline this test
    // owns the value it asserts regardless of order/parallelism.
    let _guard = CONFIG_TEST_GUARD.blocking_lock();
    reset_config_for_test();
    configure(None, true);
    assert!(coalesce_enabled(), "coalesce_enabled must be true after configure(…, true)");
    // Smoke-test the reserved record fns (no assertion — they just must not panic).
    record_attr_coalesce_hit();
    record_attr_coalesce_miss();
}

#[test]
fn configure_test_isolation_reset_restores_defaults() {
    // W1-C2-11: per-test reset restores the unconfigured defaults, then
    // reconfigures the all-tests-agree state — the suite never depends
    // on which test configured first.
    let _guard = CONFIG_TEST_GUARD.blocking_lock();
    reset_config_for_test();
    assert!(!coalesce_enabled(), "reset must restore the coalesce default (false)");
    assert_eq!(threshold(), None, "reset must restore the threshold default (None)");
    configure(None, true);
    assert!(coalesce_enabled(), "reconfigure after reset must take effect");
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
        attr_coalesce_hits_total: 42,
        attr_coalesce_misses_total: 7,
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
    // R2 attribute coalescer counters
    assert!(text.contains("pkcs11_proxy_attr_coalesce_hits_total 42\n"));
    assert!(text.contains("pkcs11_proxy_attr_coalesce_misses_total 7\n"));
    assert!(text.contains("# TYPE pkcs11_proxy_attr_coalesce_hits_total counter"));
    assert!(text.contains("# TYPE pkcs11_proxy_attr_coalesce_misses_total counter"));
}

fn main() {
    // R10: declare the test-only v1-enable custom cfg (S2 §11 Phase 2) so
    // stable/MSRV builds stay warning-free under `-D warnings`. Done here —
    // not via `[lints.rust] unexpected_cfgs.check-cfg` in the manifest —
    // because cargo strips `check-cfg` when packaging, which trips the
    // archive manifest-identity gate (types/build.rs precedent).
    println!("cargo::rustc-check-cfg=cfg(pkcs11_proxy_test_mechanism_params_v1)");
}

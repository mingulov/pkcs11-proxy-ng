fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/service.proto");
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/types.proto");
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/mechanism_params.proto");

    // FOLLOWUP-proto-bytes (deferred, multi-PR project)
    //
    // Enabling `.bytes(".")` here would make prost decode `bytes`
    // fields as `prost::bytes::Bytes` (Arc'd, zero-copy from the
    // network buffer) instead of `Vec<u8>`. Per-call allocation cuts
    // are real for big payloads (`C_Sign`/`C_Decrypt`/`CKA_VALUE`
    // attributes, wrapped-key blobs) — potentially MB per call.
    //
    // Why this is deferred to a focused PR rather than done piecemeal:
    //
    // 1. The benefit ONLY materialises if the native Rust mirrors in
    //    `crates/types/src/{mechanism,attribute,output}.rs` ALSO
    //    switch from `Vec<u8>` to `Bytes`. Without that cascade,
    //    every From/TryFrom conversion site allocates a fresh
    //    `Vec<u8>` via `.to_vec()` — same per-call allocation count
    //    as today, just with extra `.into()` / `.to_vec()` noise.
    //
    // 2. Per-field `bytes_type` overrides (e.g. switching only the
    //    `signature` / `plaintext` / `wrapped_key` fields) give
    //    inconsistent native types across sibling fields. A handler
    //    matching on one message would have `Bytes`-typed and
    //    `Vec<u8>`-typed neighbours: harder to maintain than either
    //    extreme, and confuses the audit signal for shim consumers
    //    that match on attribute types uniformly.
    //
    // 3. Verified experimentally that the build.rs flip alone
    //    produces 299 type-mismatch errors across
    //    `crates/proto/src/convert/*`,
    //    `crates/server/src/server/grpc_service/`, and `crates/shim/`,
    //    every one a Vec↔Bytes mismatch. Total touched-file scope is
    //    ~50 files.
    //
    // Recommended rollout (separate PR):
    //   (a) Add a `Bytes`-using alias module in `crates/types`
    //       behind a feature flag (off by default).
    //   (b) Migrate one type at a time (e.g. `CkAttributeValue::Bytes`
    //       first, then `mechanism::*::data/iv/aad` byte fields),
    //       each as a self-contained commit that compiles and
    //       passes the full test suite.
    //   (c) Add the bench harness from
    //       FOLLOWUP-shim-multiplex-bench to measure the per-payload-size
    //       win.
    //   (d) Flip `.bytes(".")` once every native consumer is on Bytes.
    //
    // Until that PR lands, keep `Vec<u8>` everywhere — the consistency
    // is more valuable than a half-measure.
    tonic_prost_build::configure().build_server(true).build_client(true).compile_protos(
        &[
            "../../proto/pkcs11-proxy-ng/v1/service.proto",
            "../../proto/pkcs11-proxy-ng/v1/types.proto",
            "../../proto/pkcs11-proxy-ng/v1/mechanism_params.proto",
        ],
        &["../../proto"],
    )?;
    Ok(())
}

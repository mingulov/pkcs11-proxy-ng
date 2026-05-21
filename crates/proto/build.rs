fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/service.proto");
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/types.proto");
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/mechanism_params.proto");

    // FOLLOWUP-proto-bytes: enabling
    //     .bytes(".")
    // here would make prost decode `bytes` fields as
    // `prost::bytes::Bytes` (Arc'd, zero-copy from the network
    // buffer) instead of `Vec<u8>`. The benefit only materializes if
    // the native Rust mirrors in `crates/types/src/{mechanism,
    // attribute, output}.rs` ALSO switch from `Vec<u8>` to `Bytes` —
    // otherwise every From/TryFrom conversion site re-allocates a
    // `Vec<u8>` via `.to_vec()`, leaving the total per-call
    // allocation count unchanged. Verified experimentally that the
    // build.rs flip alone produces 299 type-mismatch errors across
    // crates/proto/src/convert/*, crates/server/src/server/, and
    // crates/shim/, every one of which is a Vec/Bytes mismatch.
    //
    // A proper rollout needs:
    //   1. Switch the ~120 `Vec<u8>` fields in `crates/types` to
    //      `Bytes`.
    //   2. Update FFI conversion in `crates/backend/src/ffi/` to
    //      take `&Bytes` (which derefs to `&[u8]`) wherever it
    //      reads bytes-typed fields today.
    //   3. Update tests, mock backend, and consumer-matrix harnesses.
    //
    // Scope ~50 files. Out of scope for this maintenance window;
    // tracked as FOLLOWUP-proto-bytes.
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

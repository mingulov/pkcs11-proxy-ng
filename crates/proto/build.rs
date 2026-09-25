fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/service.proto");
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/types.proto");
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/mechanism_params.proto");

    // FOLLOWUP-proto-bytes (deferred, multi-PR project)
    //
    // Migrating selected `bytes` proto fields from `Vec<u8>` to
    // `prost::bytes::Bytes` saves one full-payload memcpy on the
    // gRPC decode path (tonic delivers a `Bytes` slice over the
    // network receive buffer; prost can reference it directly).
    // The win is meaningful for large payloads — `C_Sign` /
    // `C_Decrypt` results, `CKA_VALUE` attribute reads, wrapped-key
    // blobs — potentially MB per call. Negligible for small fields
    // (IVs, nonces, AADs, handles, mechanism IDs).
    //
    // ------------------------------------------------------------------
    // SECURITY: 11 `bytes` fields hold PIN / password material and are
    // wrapped in `Zeroizing<Vec<u8>>` on the server, or live inside
    // `ZeroizeOnDrop`-deriving Rust types in `crates/types`. The
    // `bytes::Bytes` type has NO `Zeroize` impl, and its backing buffer
    // lives in tonic's network receive pool that we cannot reach to
    // wipe. These fields MUST stay `Vec<u8>` to preserve PIN-zeroization
    // (see AGENTS.md §4 and the `panic = "abort"` ban):
    //
    //   * service.proto: LoginRequest.pin
    //   * service.proto: LoginUserRequest.{pin, username}
    //   * service.proto: InitTokenRequest.so_pin
    //   * service.proto: InitPinRequest.pin
    //   * service.proto: SetPinRequest.{old_pin, new_pin}
    //   * mechanism_params.proto: PbeParams.password
    //   * mechanism_params.proto: Pkcs5Pbkd2Params.password
    //   * mechanism_params.proto: SkipjackPrivateWrapParams.password
    //   * mechanism_params.proto: SkipjackRelayxParams.{old_password,
    //                                                     new_password}
    //
    // A global `.bytes(".")` flip would silently regress all of these.
    // That is NOT the destination of this migration.
    // ------------------------------------------------------------------
    //
    // The right shape of the migration:
    //
    // 1. Add a `criterion` bench in `crates/proto` measuring decode-side
    //    allocations at 4 KiB / 64 KiB / 1 MiB / 4 MiB payloads.
    //    Commit baseline numbers BEFORE any flip. Without this, every
    //    per-field migration is unverified.
    //
    // 2. Migrate one field per PR via prost-build's per-field path
    //    override:
    //
    //        tonic_prost_build::configure()
    //            .bytes(&[".pkcs11_proxy_ng.v1.ByteOutputExactResponse.value",
    //                     ...])
    //            ...
    //
    //    NOT `.bytes(".")` — the destination is per-field forever.
    //
    // 3. Each per-field PR MUST land the full cascade together so the
    //    client public API doesn't reintroduce the memcpy via
    //    `Bytes::to_vec()` to preserve its `Vec<u8>` signature:
    //
    //    a. proto field override (this build.rs)
    //    b. the corresponding `crates/types` field
    //       (e.g. `CkOutputBufferResult.value`, `CkAttributeValue::Bytes`)
    //    c. proto `From`/`TryFrom` conversion code
    //    d. client public API return types
    //       (e.g. `client/src/client/crypto/sign_verify.rs`)
    //    e. shim helper signatures
    //       (`shim/src/dispatch/general/helpers.rs::write_exact_output`)
    //    f. all `vec![..]` test literals on that field
    //       → `Bytes::from(vec![..])`
    //
    // Quick-win candidates (large payload, non-sensitive, isolated):
    //
    //   * `ByteOutputExactResponse.value` — covers Sign / Decrypt /
    //     Digest / Encrypt / WrapKey and 13 more via the exact path.
    //   * `AttributeQueryResult.value` — `C_GetAttributeValueExact`.
    //
    // Skip per the security list above. Skip every mechanism-param
    // byte field that is an IV / nonce / AAD / short scalar — no win.
    //
    // Until that PR series lands, keep `Vec<u8>` everywhere — the
    // consistency is more valuable than a half-measure.
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

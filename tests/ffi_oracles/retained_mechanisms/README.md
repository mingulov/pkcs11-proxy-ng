# Retained-mechanism native oracle

This Rust test library implements a PKCS#11 2.40 module that keeps the
`CK_MECHANISM` pointer and its parameter storage per session from `C_EncryptInit`. It reads
them again during `C_Encrypt` to test backends that retain pointers instead of
copying the values. It is not a cryptographic provider; do not use real keys or
data with it.

`RetainedOracle_SetScenario`, `RetainedOracle_ResetObservation`, and
`RetainedOracle_GetObservation` control and inspect the fixture. Observations
record native calls, the retained pointer address, and values read through it.
The test compares recorded addresses to check pointer identity. Outputs are
fixed public canary bytes. Scenarios run serially. The dynamic-loading test
needs an explicit library path; an explicitly selected ignored test fails if it is missing.

The legacy scenario and observation structs and getters retain their original ABI.
`RetainedOracle_GetDeepObservationV1` writes the distinct fixed-size
`RetainedOracleDeepObservationV1` layout declared in `src/lib.rs`; it records
Init and delayed snapshots of CBC IV, GCM IV/AAD and scalars, and nested KIP
mechanism/seed legs. Pointer addresses, NULL/empty presence, lengths, and exact
public canary bytes are compared. The fixture limits observations to five
mechanism nodes, 32 bytes per leg, and 64 retained sessions. Unsupported or
oversized graphs are invalid observations. Those bounds do not validate arbitrary
foreign pointers: every graph must remain live, including negative controls.

`RetainedOracle_RequireDeepEqualV1(1)` opts into `CKR_DEVICE_ERROR` for absent,
invalid, or changed graphs; `(0)` disables this control. Observation reset clears
retained sessions and this control. Session close and finalize remove retained
roots. The legacy root-only fail control remains available independently.

The ordinary backend suite exercises the real native materializer with 30 bounded
GCM/KIP presence/nesting cases (including NULL nested mechanisms), interleaved CBC sessions, dropped source domain
objects, exact output/RV/count cases, and still-live IV/AAD/seed corruption and
wrong-session controls. These synthetic tests establish the fixture contract,
not cryptographic provider qualification. The loaded test emits its completion
marker only after assertions and successful session/finalize cleanup.

From the standalone repository root:

```sh
cargo build --locked --manifest-path tests/ffi_oracles/retained_mechanisms/Cargo.toml
cargo test --locked -p pkcs11-proxy-ng-backend --lib ffi::retained
PKCS11_PROXY_RETAINED_ORACLE_LIB="$PWD/tests/ffi_oracles/retained_mechanisms/target/debug/libpkcs11_retained_mechanism_oracle.so" \
cargo test --locked -p pkcs11-proxy-ng-backend --lib ffi::retained \
  -- --ignored --test-threads=1
```

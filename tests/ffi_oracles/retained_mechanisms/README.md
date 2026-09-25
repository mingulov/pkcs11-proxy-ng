# Retained-mechanism native oracle

This Rust test library implements a PKCS#11 2.40 module that keeps the
`CK_MECHANISM` pointer and its parameter storage from `C_EncryptInit`. It reads
them again during `C_Encrypt` to test backends that retain pointers instead of
copying the values. It is not a cryptographic provider; do not use real keys or
data with it.

`RetainedOracle_SetScenario`, `RetainedOracle_ResetObservation`, and
`RetainedOracle_GetObservation` control and inspect the fixture. Observations
record native calls, the retained pointer address, and values read through it.
The test compares recorded addresses to check pointer identity. Outputs are
fixed public canary bytes. Scenarios run serially. The dynamic-loading test
needs an explicit library path; without it, that test skips with a notice.

From the standalone repository root:

```sh
cargo build --locked --manifest-path tests/ffi_oracles/retained_mechanisms/Cargo.toml
cargo test --locked -p pkcs11-proxy-ng-backend --lib ffi::retained
PKCS11_PROXY_RETAINED_ORACLE_LIB="$PWD/tests/ffi_oracles/retained_mechanisms/target/debug/libpkcs11_retained_mechanism_oracle.so" \
cargo test --locked -p pkcs11-proxy-ng-backend --lib ffi::retained \
  -- --ignored --test-threads=1
```

# Exact-output native oracle

This isolated, unpublished Rust cdylib implements a deterministic test PKCS#11
provider. It is not a cryptographic provider and must not hold real keys or data.
It exposes 2.40, 3.0, and 3.2 function lists for caller-ABI integration tests.

`ExactOracle_SetScenario`, `ExactOracle_ResetObservation`, and
`ExactOracle_GetObservation` are test-only sideband controls. Observations count
native entries and stores and record the supplied pointer class/capacity. They
never influence production proxy behavior. In particular, only the oracle can
distinguish query store-zero from no-store; the proxy intentionally cannot.

The fixture writes bytes only within the supplied capacity. Oversized results
change the returned scalar only. Tests use synthetic public canaries, serialize
fixture scenarios, and require explicit library paths (missing paths fail).

From the standalone repository root:

```sh
cargo build --locked --manifest-path tests/ffi_oracles/exact_outputs/Cargo.toml
cargo build --locked -p pkcs11-proxy-ng-shim
PKCS11_PROXY_SHIM_LIB="$PWD/target/debug/libpkcs11_proxy_ng_shim.so" \
PKCS11_PROXY_EXACT_ORACLE_LIB="$PWD/tests/ffi_oracles/exact_outputs/target/debug/libpkcs11_exact_output_oracle.so" \
cargo test --locked -p pkcs11-proxy-ng --test exact_output_error_test \
  -- --ignored --test-threads=1
```

Use a private task-owned `TMPDIR` and `umask 077` when retaining evidence. The
native oracle covers deterministic output behavior, not real mechanism support,
performance, hostile provider memory writes, or the full provider matrix.

The backend's ignored
`classic_gcm_initialized_error_iv_effect_pending_provenance_prerequisite` test is
a deliberately retained Phase B RED, not part of this passing oracle gate.

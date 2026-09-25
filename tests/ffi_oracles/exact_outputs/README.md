# Exact-output native oracle

This Rust test library implements a deterministic PKCS#11 module with 2.40,
3.0, and 3.2 function lists. It is for ABI and output tests; do not use it for
cryptography or real keys and data.

`ExactOracle_SetScenario`, `ExactOracle_ResetObservation`, and
`ExactOracle_GetObservation` control and inspect the fixture. Observations
count native calls and writes, and record the caller's pointer class and
capacity. Only the fixture can distinguish a zero-byte write during a length
query from no write; the proxy has no such observation. These controls do not
affect production behavior.

The fixture writes only within the supplied capacity. For an oversized result,
it changes the returned length without writing past the buffer. Its
`length_action` and `output_action` settings model unusual provider writes as
bounded writes plus observations; see `ExactOracle_ByteOutput`. The tests use
public canary bytes, run scenarios serially, and require explicit library
paths.

From the standalone repository root:

```sh
cargo build --locked --manifest-path tests/ffi_oracles/exact_outputs/Cargo.toml
cargo build --locked -p pkcs11-proxy-ng-shim
PKCS11_PROXY_SHIM_LIB="$PWD/target/debug/libpkcs11_proxy_ng_shim.so" \
PKCS11_PROXY_EXACT_ORACLE_LIB="$PWD/tests/ffi_oracles/exact_outputs/target/debug/libpkcs11_exact_output_oracle.so" \
cargo test --locked -p pkcs11-proxy-ng --test exact_output_error_test \
  -- --ignored --test-threads=1
```

When retaining test artifacts, use a private `TMPDIR` and `umask 077`. The
fixture tests deterministic output behavior. It does not test real mechanism
support, performance, out-of-bounds writes, or provider compatibility.

The tests compare direct and proxied query and data calls for GCM, CCM,
Salsa20, and ChaCha20-Poly1305. They also check generated Begin output,
mixed attribute templates, and readiness events for each exact-output adapter.
Readiness is process-wide, so those cases share one test and drain setup events
before each measurement. Oversized-capacity cases test rejection before a
native call; their small canary buffer is never accessed.

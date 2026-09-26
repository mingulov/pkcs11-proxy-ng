# Exact-output native oracle

This Rust test library implements a deterministic PKCS#11 module with 2.40,
3.0, and 3.2 function lists. It is for ABI and output tests; do not use it for
cryptography or real keys and data.

`ExactOracle_SetScenario`, `ExactOracle_ResetObservation`, and
`ExactOracle_GetObservation` are test-only sideband controls. Observations count
native entries and stores and record the supplied pointer class/capacity. They
never influence production proxy behavior. In particular, only the oracle can
distinguish query store-zero from no-store; the proxy intentionally cannot.

The fixture writes bytes only within the supplied capacity. Oversized results
change the returned scalar only. Hostile, zero-length, and oversized provider
writes are modeled as bounded writes plus recorded observations
(`length_action`/`output_action` 0–4; see `ExactOracle_ByteOutput`): a true
out-of-bounds write cannot be modeled — it would be UB in a real provider too.
Tests use synthetic public canaries, serialize fixture scenarios, and require
explicit library paths (missing paths fail).
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

Use a private task-owned `TMPDIR` and `umask 077` when retaining evidence. The
native oracle covers deterministic output behavior, not real mechanism support,
performance, true out-of-bounds provider writes, or the full provider matrix.

The fix-round tests include direct/proxy query/data comparisons for GCM, CCM,
Salsa20 and ChaCha20-Poly1305; generated Begin versus query effects; legal mixed
attribute templates; and readiness events for every exact adapter family.
Readiness is process-global, so its cases share one test and drain setup events
before measuring each native call. The oversized-capacity cases exercise proven
pre-native rejection only: their small canary backing is never dereferenced.
When retaining test artifacts, use a private `TMPDIR` and `umask 077`. The
fixture tests deterministic output behavior. It does not test real mechanism
support, performance, out-of-bounds writes, or provider compatibility.

The tests compare direct and proxied query and data calls for GCM, CCM,
Salsa20, and ChaCha20-Poly1305. They also check generated Begin output,
mixed attribute templates, and readiness events for each exact-output adapter.
Readiness is process-wide, so those cases share one test and drain setup events
before each measurement. Oversized-capacity cases test rejection before a
native call; their small canary buffer is never accessed.

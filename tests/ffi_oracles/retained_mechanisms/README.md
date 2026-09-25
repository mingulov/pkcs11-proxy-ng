# Retained-mechanism native oracle

This isolated, unpublished Rust cdylib implements a deterministic test PKCS#11
provider that deliberately retains the `CK_MECHANISM` root (and parameter
extent) received at `C_EncryptInit` and reads back through that same root
during the later `C_Encrypt` call — emulating backends that store mechanism
pointers instead of copying them. It is not a cryptographic provider and must
not hold real keys or data. It exposes a 2.40 function list only.

`RetainedOracle_SetScenario`, `RetainedOracle_ResetObservation`, and
`RetainedOracle_GetObservation` are test-only sideband controls. Observations
count native entries and record the retained root address plus the values
re-read through it; pointer-identity equality is computed test-side from those
recorded addresses. Outputs are a fixed canary. Tests use synthetic public
canaries, serialize fixture scenarios, and require an explicit library path
for the dlopen leg (missing paths skip that leg with a notice).

From the standalone repository root:

```sh
cargo build --locked --manifest-path tests/ffi_oracles/retained_mechanisms/Cargo.toml
cargo test --locked -p pkcs11-proxy-ng-backend --lib ffi::retained
PKCS11_PROXY_RETAINED_ORACLE_LIB="$PWD/tests/ffi_oracles/retained_mechanisms/target/debug/libpkcs11_retained_mechanism_oracle.so" \
cargo test --locked -p pkcs11-proxy-ng-backend --lib ffi::retained \
  -- --ignored --test-threads=1
```

Gate/phase controls (`ArmGate`/`ReleaseGate`) and the daemon-resident control
socket arrive with the row-9 barrier slice, not here.

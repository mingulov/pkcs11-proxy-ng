# Entry-recording oracle (Q07 shape evidence)

Minimal native PKCS#11 provider that records `C_EncryptInit` entries
independently of the return value, then returns the scenario RV verbatim —
including error RVs bit-identical to server-local and backend-local rejects.
The entry count is what distinguishes "the provider said no" from "we never
got there".

Build from the standalone repository root:

```sh
cargo build --locked --manifest-path tests/ffi_oracles/entry_recording/Cargo.toml
```

(`cargo build` creates `Cargo.lock` on the first build; keep it committed so
`--locked` stays reproducible.)

Then run the ignored shape-evidence lane:

```sh
PKCS11_PROXY_ENTRY_RECORDING_ORACLE_LIB="$PWD/tests/ffi_oracles/entry_recording/target/debug/libpkcs11_entry_recording_oracle.so" \
  cargo test --locked -p pkcs11-proxy-ng --test shape_evidence_test \
  -- --ignored --test-threads=1 --nocapture
```

Neither fixture is a real cryptographic provider; this gate tests evidence
taxonomy (attempted vs native-entered vs success), not crypto behavior.

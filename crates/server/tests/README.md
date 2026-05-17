# Test Matrix

This crate now uses a layered test strategy instead of a single broad ignored test.

## Rust integration suites

- `integration_test.rs`
  - SoftHSM2-backed end-to-end smoke workflow
  - SHA-256 digest coverage
  - RSA-PSS and RSA-OAEP coverage when supported by the backend
- `concurrency_and_recovery_test.rs`
  - multi-client workload
  - handle isolation across contexts
  - lease expiry
  - daemon restart and reconnect behavior
- `provider_matrix_test.rs`
  - real NSS softokn smoke coverage with a custom per-test config directory
  - optional Kryoptic smoke suite when a module is available
  - provider capability probes for advertised and unadvertised mechanisms
  - `CKR_MECHANISM_INVALID` checks for unadvertised mechanism-info and digest-init probes
  - token-object persistence across session reopen
  - attribute round-trips (`CKA_LABEL`, `CKA_ID`)
  - modeled parameterized mechanisms when the backend advertises them

Run them individually because real PKCS#11 modules often depend on process-global
state and environment variables:

```bash
cargo test -p pkcs11-proxy-ng --test integration_test -- --ignored --test-threads=1
cargo test -p pkcs11-proxy-ng --test concurrency_and_recovery_test -- --ignored --test-threads=1
cargo test -p pkcs11-proxy-ng --test provider_matrix_test -- --ignored --test-threads=1
```

## Ignored test taxonomy

All ignored Rust integration lanes are ignored because they need real PKCS#11
providers, process-global provider state, or external consumer tools. No stale
ignores are currently safe to remove from these lanes.

Run `cargo build --workspace` first for lanes that require built workspace
binaries or the shim library. To run a consumer lane against an existing shim
build, set `PKCS11_PROXY_SHIM_LIB=/path/to/libpkcs11_proxy_ng_shim.so`.

| File | Reason | Requirements | Command |
|------|--------|--------------|---------|
| `crates/server/tests/cli_hardening_test.rs` | SoftHSM2-backed CLI subprocess coverage | SoftHSM2 module and softhsm2-util; built workspace binaries | `cargo test -p pkcs11-proxy-ng --test cli_hardening_test -- --ignored --test-threads=1` |
| `crates/server/tests/concurrency_and_recovery_test.rs` | SoftHSM2-backed multi-client and recovery coverage | SoftHSM2 module and softhsm2-util | `cargo test -p pkcs11-proxy-ng --test concurrency_and_recovery_test -- --ignored --test-threads=1` |
| `crates/server/tests/consumer_p11tool_test.rs` | SoftHSM2-backed GnuTLS p11tool consumer coverage | SoftHSM2 module and softhsm2-util; GnuTLS p11tool; built workspace binaries | `cargo test -p pkcs11-proxy-ng --test consumer_p11tool_test -- --ignored --test-threads=1` |
| `crates/server/tests/consumer_pkcs11_tool_test.rs` | SoftHSM2-backed OpenSC pkcs11-tool consumer coverage | SoftHSM2 module and softhsm2-util; OpenSC pkcs11-tool; built workspace binaries | `cargo test -p pkcs11-proxy-ng --test consumer_pkcs11_tool_test -- --ignored --test-threads=1` |
| `crates/server/tests/consumer_python_test.rs` | SoftHSM2-backed Python PyKCS11 consumer coverage | SoftHSM2 module and softhsm2-util; python3 with PyKCS11; built workspace binaries | `cargo test -p pkcs11-proxy-ng --test consumer_python_test -- --ignored --test-threads=1` |
| `crates/server/tests/integration_test.rs` | Split SoftHSM2 and NSS real-backend smoke coverage | SoftHSM2 module and softhsm2-util; NSS softokn libsoftokn3.so and certutil | `cargo test -p pkcs11-proxy-ng --test integration_test softhsm_smoke_workflow -- --ignored --test-threads=1`<br>`cargo test -p pkcs11-proxy-ng --test integration_test nss_sign_recover_and_verify_recover -- --ignored --test-threads=1` |
| `crates/server/tests/kryoptic_mechanism_test.rs` | Kryoptic provider mechanism coverage | Kryoptic module via PKCS11_PROXY_KRYOPTIC_MODULE | `cargo test -p pkcs11-proxy-ng --test kryoptic_mechanism_test -- --ignored --test-threads=1` |
| `crates/server/tests/mechanism_out_gcm_iv_test.rs` | Patched-SoftHSM2-backed AES-GCM init-time generated-IV coverage for the Wave 1 + Wave 2 mechanism_out work | Patched libsofthsm2.so built from pkcs11-check/docker/softhsm2/patches/ with SOFTHSM2_GCM_IV_SIM_LIB pointing at it; softhsm2-util | `SOFTHSM2_GCM_IV_SIM_LIB=/path/to/patched/libsofthsm2.so cargo test -p pkcs11-proxy-ng --test mechanism_out_gcm_iv_test -- --ignored --test-threads=1` |
| `crates/server/tests/shim_c_abi_mechanism_out_test.rs` | Loaded-shim C ABI mechanism-output, C_GetMechanismInfo zero-flag, and C_WaitForSlotEvent lifecycle coverage | Built shim shared library from cargo build -p pkcs11-proxy-ng-shim or PKCS11_PROXY_SHIM_LIB | `cargo build -p pkcs11-proxy-ng-shim && cargo test -p pkcs11-proxy-ng --test shim_c_abi_mechanism_out_test -- --ignored --test-threads=1` |
| `crates/server/tests/nss_mechanism_coverage_test.rs` | NSS softokn mechanism coverage | NSS softokn libsoftokn3.so and certutil | `cargo test -p pkcs11-proxy-ng --test nss_mechanism_coverage_test -- --ignored --test-threads=1` |
| `crates/server/tests/parameterized_mechanism_test.rs` | SoftHSM2-backed parameterized mechanism coverage | SoftHSM2 module and softhsm2-util | `cargo test -p pkcs11-proxy-ng --test parameterized_mechanism_test -- --ignored --test-threads=1` |
| `crates/server/tests/provider_matrix_test.rs` | Optional NSS and Kryoptic provider matrix smoke coverage | NSS softokn libsoftokn3.so and certutil; Kryoptic module via PKCS11_PROXY_KRYOPTIC_MODULE | `cargo test -p pkcs11-proxy-ng --test provider_matrix_test nss_softokn_smoke_suite -- --ignored --test-threads=1`<br>`cargo test -p pkcs11-proxy-ng --test provider_matrix_test kryoptic_smoke_suite -- --ignored --test-threads=1` |
| `crates/server/tests/softhsm_fixture_test.rs` | SoftHSM2 fixture variant coverage | SoftHSM2 module and softhsm2-util | `cargo test -p pkcs11-proxy-ng --test softhsm_fixture_test -- --ignored --test-threads=1` |
| `crates/server/tests/template_compat_test.rs` | SoftHSM2-backed template compatibility coverage | SoftHSM2 module and softhsm2-util | `cargo test -p pkcs11-proxy-ng --test template_compat_test -- --ignored --test-threads=1` |

## Environment variables for optional providers

### NSS softokn

- auto-detected when `libsoftokn3.so` is present on the system
- or override with:
  - `PKCS11_PROXY_NSS_MODULE`
  - `PKCS11_PROXY_NSS_INIT_ARGS`
- `PKCS11_PROXY_NSS_TOKEN_LABEL`
- `PKCS11_PROXY_NSS_USER_PIN`
- `PKCS11_PROXY_NSS_SO_PIN`
- `PKCS11_PROXY_NSS_INIT_TOKEN`
- `PKCS11_PROXY_NSS_EMPTY_SO_PIN`

Example initialize args for NSS softoken:

```text
configDir='sql:/path/to/nssdb' tokenDescription='test-token'
```

### Kryoptic

- `PKCS11_PROXY_KRYOPTIC_MODULE`
- `PKCS11_PROXY_KRYOPTIC_INIT_ARGS`
- `PKCS11_PROXY_KRYOPTIC_TOKEN_LABEL`
- `PKCS11_PROXY_KRYOPTIC_USER_PIN`
- `PKCS11_PROXY_KRYOPTIC_SO_PIN`
- `PKCS11_PROXY_KRYOPTIC_INIT_TOKEN`

## Shell harness

For a local parity run of the same Tier 0 checks used by CI, use:

```bash
scripts/test-matrix.sh --fast-only
```

Use:

```bash
scripts/test-matrix.sh
```

That script runs:
- fast workspace checks
- SoftHSM2 Rust suites
- optional provider suites when env vars are present
- external consumer smoke tests via `scripts/test-consumers.sh`
  - direct OpenSC `pkcs11-tool` against SoftHSM2
  - proxied `pkcs11-tool` against the shim
  - curated `pkcs11test` subset direct and proxied
  - `p11tool` listing via direct and proxied paths
  - OpenSSL provider smoke via the shim when `pkcs11prov` is installed

For real software-token backend validation without requiring host-specific
environment variables, use:

```bash
scripts/test-provider-backends.sh
```

The curated `pkcs11test` selection lives in:

```text
scripts/pkcs11test-filter.txt
```

That suite is intentionally a compatibility subset, not a full conformance
claim. `pkcs11test` is useful as independent prior tooling, but it assumes a
broader PKCS#11 v2.20 feature surface than the Phase 1 proxy currently targets.

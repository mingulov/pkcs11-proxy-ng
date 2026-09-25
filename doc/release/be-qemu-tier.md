# Big-endian proven tier (s390x/QEMU, T6a)

v0.2.0 proves big-endian at the **build + QEMU-suite tier**: the workspace
compiles for `s390x-unknown-linux-gnu` and the portable suites pass under
`qemu-user`. This is deliberately one tier below a runtime claim — live
native FFI on a BE host stays excluded (see below). Re-run any time with
`scripts/run-be-qemu-test.sh` (no CI job: TX-12, 2026-09-19 — no BE leg in
`cross-platform.yml`, which is a provider-parity gate and BE has no
provider-parity claim; this script stays the proof vehicle).

## Proven (2026-09-18)

Toolchain: `Dockerfile.be-qemu` (Debian 13.6) with rustc 1.98.1,
`s390x-linux-gnu-gcc` 14.2.0, `qemu-s390x-static` 10.0.13, `protoc`
3.21.12, `python3` 3.13.5. QEMU emulates userspace only; no s390x
hardware was involved.

- **Build:** `cargo check --workspace --all-targets` for s390x clean
  (only pre-existing `dead_code` warnings where the x86-only stop
  machinery cfgs out), plus the `pkcs11-proxy-ng-shim` cdylib and the
  s390x `CK_GCM_MESSAGE_PARAMS` 48-byte layout assertion.
- **Unit suites:** types 124, proto 211, client 31, audit 20, cli 8 —
  all green, including the native byte-order pins.
- **Backend lib:** 409 green (57 `native_stop*`/`native_domain*`
  skipped — unqualified-target exclusions, see below).
- **Shim lib:** 349 green — in-process mock daemons over gRPC,
  cross-width bridge both directions against emulated narrow ABIs,
  D6 refusal of the foreign order end to end.
- **Shim integration:** `stress_registry` and (ignored-by-default)
  `fork_after_init` green.
- **Server package:** lib 650 + bin 8 + every runnable mock-based
  integration target green (`local_quality_gate` 61,
  `exact_wrap_authorization` 23, `wave6_3x` 23, `mechanism_authorization`
  18, `fault_injection` 16, `wave1_session_3x` 10, `slot_ownership` 10,
  `mechanism_out_derive_mock` 9, `stress` 9, `wave2_kem` 8,
  `example_configs_parse` 8, `env_var_precedence` 7, `mtls_authorization`
  3, `uds_transport`/`daemon_cli_ux`/`protected_decode_live` 2 each,
  `exact_output_error`/`pin_leak`/`rate_quota_login` 1 each).
- **C ABI:** 7 of 8 `shim_c_abi_mechanism_out` tests green against the
  cross-built s390x cdylib via `dlopen` (the 8th is skipped — a
  pre-existing dev failure, byte-identical on the LE baseline; see the
  script header).

## Still excluded

- **Live native FFI on BE hosts is NOT claimed.** s390x is not a
  qualified native-FFI target (`NATIVE_FFI_QUALIFIED=false`): the
  abnormal-stop arms are x86/x86_64 asm only, and no BE provider
  hardware exists here. The backend correctly refuses FFI construction
  on s390x, and the qualification tests are excluded from the BE suite
  for that reason. Qualifying s390x needs new stop arms plus
  hardware-backed provider validation.
- **Mixed-endian topologies (LE↔BE bridging) are refused by design**
  (ADR-0011 D6); only same-endian pairs interoperate.
- **No BE provider-parity claim.** The direct-vs-proxied matrix stays
  x86_64-only; BE coverage is mock-backed.

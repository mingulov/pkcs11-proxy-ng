# Big-endian proven tier (s390x/QEMU, T6a)

v0.2.0 proves big-endian at the **build + QEMU-suite tier**: the workspace
compiles for `s390x-unknown-linux-gnu` and the portable suites pass under
`qemu-user`. This is deliberately one tier below a runtime claim — live
native FFI on a BE host stays excluded (see below). Re-run any time with
`scripts/run-be-qemu-test.sh` (no CI job: TX-12, 2026-09-19 — no BE leg in
`cross-platform.yml`, which is a provider-parity gate and BE has no
provider-parity claim; this script stays the proof vehicle).

## Proven (2026-09-23)

Toolchain: `Dockerfile.be-qemu` (Debian 13.6) with rustc 1.98.1,
`s390x-linux-gnu-gcc` 14.2.0, `qemu-s390x-static` 10.0.13, `protoc`
3.21.12, `python3` 3.13.5. QEMU emulates userspace only; no s390x
hardware was involved.

- **Build:** `cargo check --workspace --all-targets` for s390x clean
  (only pre-existing `dead_code` warnings where the x86-only stop
  machinery cfgs out), plus the `pkcs11-proxy-ng-shim` cdylib and the
  s390x `CK_GCM_MESSAGE_PARAMS` 48-byte layout assertion.
- **Unit suites:** types 159, proto 253, client 77, audit 57, cli 108
  (+1 `health_tls_exit_code`) — all green, including the native
  byte-order pins.
- **Backend lib:** 602 green (91 `native_stop*`/`native_domain*`/
  `constructor_child*` skipped — unqualified-target exclusions, see
  below; the TO26a constructor battery joined the exclusion in T20).
- **Shim lib:** 490 green — in-process mock daemons over gRPC,
  cross-width bridge both directions against emulated narrow ABIs,
  D6 refusal of the foreign order end to end.
- **Shim integration:** (ignored-by-default) `fork_after_init` 3
  green; `stress_registry` 0-run (ignored by default).
- **Server package:** lib 877 + bin 18 + every runnable mock-based
  integration target green (`local_quality_gate` 94,
  `exact_wrap_authorization`/`wave6_3x` 23 each,
  `mechanism_authorization` 18, `fault_injection`/`slot_ownership` 16
  each, `parameterized_mechanism` 12, `wave1_session_3x` 11,
  `mechanism_out_derive_mock`/`stress`/`unique_id_authorization`/
  `example_configs_parse` 9 each, `wave2_kem`/`print_sink_gate`/
  `env_var_precedence` 8 each, `shutdown_lifetime` 6,
  `auth_combo_harness`/`exact_output_error` 5 each,
  `noncontract_begin_health` 4, `mtls_authorization` 3,
  `uds_transport`/`daemon_cli_ux`/`protected_decode_live`/`pin_leak` 2
  each, `rate_quota_login`/`provider_matrix`/`mechanism_info_mock`/
  `kryoptic_mechanism`/`consumer_pkcs11_tool`/
  `concurrency_and_recovery` 1 each; provider-gated targets report
  ignored only).
- **C ABI:** 8 of 9 `shim_c_abi_mechanism_out` tests green against the
  cross-built s390x cdylib via `dlopen` (the 9th is skipped — a
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

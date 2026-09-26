# s390x Build and QEMU Coverage

A recorded `v0.2.0` test built for `s390x-unknown-linux-gnu` and ran the
portable suites under QEMU user-mode emulation. This establishes build and
emulated test coverage for that source, not live big-endian provider support
or qualification of later changes. Run `scripts/run-be-qemu-test.sh` to
repeat the check. There is no big-endian CI leg.

## Proven (2026-09-23)
## Recorded result (2026-09-23)

The script used `Dockerfile.be-qemu` with a cross compiler and
`qemu-s390x-static`; no s390x hardware was involved. It checked the
workspace and built the shim library. The types, protobuf, client, audit,
CLI, backend, shim, and server suites passed under QEMU, including byte-order
and cross-width tests. The C ABI suite passed for eight of nine cases; its
remaining case was skipped because it also failed on the little-endian
baseline. Native lifetime and provider-gated tests were excluded from this
tier.

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
## Limits

- The backend refuses native FFI construction on s390x:
  `NATIVE_FFI_QUALIFIED=false`. The required abnormal-stop implementation
  and live provider validation are absent.
- Mixed-endian client/daemon pairs are refused; the supported bridge is
  between peers of the same byte order.
- These tests use mock backends. There is no big-endian direct/proxy provider
  comparison.

The [support matrix](beta-support-matrix.md) separates this historical test
record from public support and current-candidate qualification.

# Native ownership inventory

Historical inventory of native provider owners and stop coverage, compiled
2026-09-19 at `f6920ff` (plus the TO26b battery commits). The tables retain
that review's evidence and verdicts; they do not qualify later source revisions.
Refresh the inventory when the stop-arm matrix or consumer set changes. See
[native-mechanism-ownership.md](native-mechanism-ownership.md) for the current
contract and target-admission boundary.

## Consumers (who can own native lifetime)

| Consumer | Native owner? | Mechanism | Evidence |
|---|---|---|---|
| Daemon `pkcs11-proxy-ng` | YES (sole production owner) | `FfiBackend::load` (managed process reservation) + final-owner guard + shutdown-deadline controller; shutdown order serve → finalize → drop | Codegen review; STOP suites; live runners |
| Shim `libpkcs11_proxy_ng_shim.so` | NO (pure gRPC client) | Loads no provider; caller-maps proofs assert the oracle/provider never maps in the caller | Oracle/cross-width runners (maps receipts) |
| CLI `pkcs11-proxy-ng-cli` | NO (pure client) | Never dlopens; drives the daemon over gRPC | musl smoke (static CLI live ops) |
| Direct Rust embedders | YES (same contract) | `FfiBackend::load` + whole-process stop acceptance (borrowed-reference workers) | S17 (genuine waiter + controller drop → 70) |

## Variants (stop-arm × execution matrix)

Stop arms (`native_stop.rs`): (1) Linux x86_64 GNU/musl,
(2) Linux x86 GNU/musl, (3) Windows MSVC x86_64/x86,
(4) macOS aarch64/x86_64, (5) Linux aarch64 GNU/musl,
(6) fallback (refuse load).

| Variant | Arm | Load? | Codegen reviewed | Natively executed |
|---|---|---|---|---|
| linux/x86_64/gnu debug+release | 1 | yes | yes (symbols + stripped ship pattern + twin) | yes (STOP 50/50) |
| linux/x86/gnu debug+release | 2 | yes | yes (symbols + stripped ship pattern) | yes (STOP 50/50) |
| linux/x86_64/musl release (static+dynamic) | 1 | yes | yes (static pattern; libc wrapper distinguished) | yes, Alpine 3.23 (STOP 48/48, M9 N/A) |
| linux/x86/musl release | 2 | yes | yes (dynamic pattern, Alpine rustc 1.91.1) | yes, linux/386 Alpine (STOP 48/48, M9 N/A) |
| MSRV 1.88 debug (x86_64+x86) | 1, 2 | yes | yes (symbols; shape matches stable) | no (MSRV CI builds only) |
| linux/aarch64/gnu release | 5 | yes | yes (qualification review) | no (stop stub; load path runs on the xplat ARM leg) |
| windows/msvc x86_64+x86 | 3 | yes | no (out of TO26b scope) | wine smoke only (existing) |
| macos aarch64+x86_64 | 4 | yes | no (out of TO26b scope) | no (no macOS runner here) |
| other (s390x, riscv64, …) | 6 fallback | NO (`NATIVE_FFI_QUALIFIED=false`) | n/a (compile-only) | no (`be-qemu-tier.md` covers qemu) |

M9 `on_exit` pair is `cfg(all(linux, gnu))` — glibc-only "where
available"; musl handler suppression is covered by the M3 `atexit`
pair instead. Detail: `doc/release/native-stop-codegen-review.md`.

## Wait blocking-scope classification (group 7 rule)

"Native provider neighbors/parity classify blocking Wait as excluded
scope and separately qualify nonblocking events; crypto-only success
or a provider's own unsupported Wait proves no event path."

| Provider | Blocking Wait | Nonblocking events |
|---|---|---|
| SoftHSM2 (x86_64 + i386) | Excluded (contract limit; local `FUNCTION_NOT_SUPPORTED`) | QUALIFIED: live `NO_EVENT` + canary roundtrip at all four width pairs |
| NSS softokn (i386) | Excluded (same) | NO EVENT PATH: provider-natively `FUNCTION_NOT_SUPPORTED` (inferred from end-to-end passthrough + mapped-module receipt, canary intact) |
| Retained oracle / exact oracle | Excluded (same) | N/A: no `C_WaitForSlotEvent` entry (mechanism/output oracles by design) |
| MockBackend | Fault model only | Parks/hangs scripted for abort/timeout coverage; never the deployed backend |

## Exact-output effects, created-object cleanup, cancellation/retirement

- Exact-output effects: `exact_output_contract_tests` (14),
  `retained_owner_contract_tests`, and the loaded
  `exact_output_error_test` suite (15 tests, real shim .so +
  deterministic oracle, repaired teardown — see the TO26b report).
- Created-object cleanup: `object_cleanup::{ensure_clear,
  PendingNativeObject}` + user tests (retained-owner contracts,
  failed-close keeps-owners).
- Cancellation/retirement: `ffi_cancel_function` + session-fence
  retirement tests (`successful_close_session_retires_owners`,
  failed-close keeps-owners), server close taxonomy tests
  (transient-keep / quarantine / terminal-drop), mock cancel tests.
- Receipts: full-suite runs recorded in the TO26b report.

## Historical acceptance records

These records identify the development revisions tested on 2026-09-19.
They are retained for traceability and do not qualify later source revisions.

Historical receipts cover the cases below (TO26a groups 1+4+5+6,
`cd0b6e7f4cbafd38536d00407a195b85c2b392ae..d57d2cdfda608406c7619acf475d7bc178034ff4`;
TO26b groups 2+3+7 plus carry items and the trailing paragraph,
`0ae0effd78e9d4ff7ab9e0da2700e2267c3ec6a7..1519ed3e5beb14dfabd6f0b054b97d5961861675`;
recorded 2026-09-19). Every new run must use synthetic canaries,
deterministic gates, actual production owner seams and immutable
same-source binaries, hashes, ELF widths, commands/test counts,
toolchains, libc/kernel/environment records and child wait/marker
results. Per-group evidence map:

- Group 1 (constructor battery): TO26a report + `native_domain_tests`,
  `constructor_child_tests`.
- Group 2 (wait matrices): `WaiterDomain` + `slot_wait_tests`
  (direct-backend), `session/tests.rs` wait cases (gRPC),
  `shim/tests/wait_matrix.rs` (loaded shim), `types::width` helper
  matrix; live legs in the group-3 runners.
- Group 3 (width pairs): `run-retained-oracle-live-test.sh` (12 legs:
  retention ×8 + control-loop ×4, hook daemons, maps/width/instance
  receipts, production-build negative) and
  `run-cross-width-live-test.sh` + `run-cross-width-nss32-live-test.sh`
  (SoftHSM all four pairs + NSS32, bridging + live-wait receipts).
- Groups 4–6 (stop/markers/signals): TO26a report (S1–S16, M1–M11,
  N1); the group-4 gated-waiter case is S17 (TO26b I1), which
  supersedes S11's parked-thread analog as waiter coverage.
- Group 7 (codegen + native exec + classification):
  `doc/release/native-stop-codegen-review.md` (8 codegen/final-link
  variants, 4 native execution variants) and the wait-scope table in
  `doc/release/native-ownership-inventory.md`.

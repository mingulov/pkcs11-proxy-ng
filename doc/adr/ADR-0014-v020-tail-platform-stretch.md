# ADR-0014: Re-admit Windows native and 32-bit/mixed scope to the v0.2.0 tail stretch

- **Status:** Implemented (2026-09-17)
- **Amended (in part):** 2026-09-20 — Linux ARM64 runtime claims
  re-admitted (native-FFI qualification extended to Linux aarch64;
  cross-platform ubuntu-26.04-arm leg blocking with full compare).
- **Reverses (in part):** the 2026-09-13 P0 amendment deferral of Windows
  native-provider daemon support (ADR-0011/ADR-0006) and of the 32-bit/mixed
  support claim (`doc/release/beta-support-matrix.md`).

## Context

The P0 amendment deferred Windows native daemon work and the 32-bit/mixed
claim out of v0.2.0 as lower-priority stretch that could be dropped. The
v0.2.0 release program (`doc/plans/2026-09-13-v0.2.0-release-program-design.md`,
workstreams 9-10, gates 5/7) already describes both Windows directions as
conditional W2 topology legs. The user decision of 2026-09-14 re-admits the
deferred platform scope to v0.2.0 — at the end of the program, low priority,
after the Linux correction/parity work — instead of dropping it.

## Decision

The following are committed v0.2.0 **tail stretch**, ordered after the
candidate gate and before the comprehensive provider-matrix gate (so the
full matrix validates the new legs), with publication last:

1. **Windows x64/MSVC native daemon** consuming Windows provider DLLs.
2. **Windows x64 PKCS#11 client shim** (`pkcs11-proxy-ng-shim` DLL) for
   Windows applications, interoperating with a qualified Linux daemon.
3. **Linux-daemon/Windows-shim and Windows-daemon/Linux-shim legs** (W2),
   including narrowing failures and exact output/writeback in both
   directions.
4. **32-bit/mixed support claim**: Linux i686 runtime qualification beyond
   the single `softhsm2-i386` lane plus the four §9 ABI topologies.

Still excluded from v0.2.0: Windows GNU and Wine as conformance
evidence (Linux ARM64 runtime claims were re-admitted 2026-09-20:
qualification extended, ARM leg blocking). 32-bit
Windows (PE32) is qualified at the win32 CI tier: `i686-pc-windows-msvc`
build, lib suites executed on WOW64, and a stub C provider compiled
with x86 `cl.exe` live-loaded through `FfiBackend::load`
(`C_GetFunctionList` resolution plus a `C_GetInfo` call) — the stub
boundary: no production 32-bit provider runs in CI. macOS aarch64 is
runtime-qualified by T2run's first green macOS leg (compare green plus
backend/shim lib suites, STOP child receipts included); macOS x86_64
stays load-qualified only (no CI runtime leg).
Message/VerifySignature/OneShot owner slots were never deferred — they are
C3M plan scope. Tag/push/publication remain separately authorized actions,
not scope items.

Big-endian sits one tier below a runtime claim since T6a: the s390x
workspace build and the QEMU suites in
`scripts/run-be-qemu-test.sh` are green (see
[be-qemu-tier.md](../release/be-qemu-tier.md)), while live native FFI on
BE hosts stays excluded — s390x is not native-FFI-qualified (no stop
arm, no provider hardware).

## Consequences

- Until tail implementation lands, nonqualified-host constructor refusal
  (`DomainError::UnsupportedPlatform`, fail before loading/discovery) stays
  in force; Windows compile CI and no-loader-attempt coverage are retained.
- Tail work follows the same evidence rules: no PASS on skipped artifacts,
  named receipts per leg, no generalization beyond named providers.
- The staged gate list gains a committed tail gate; gate 5 is no longer
  droppable.

## Implementation (2026-09-17)

Accepted 2026-09-14 (user scope decision); all four decision items are now
implemented with named receipts — no item was waived or handed off:

1. Windows x64/MSVC native daemon — T6 leg A (Windows daemon + SoftHSM2-win
   DLL over mTLS, Linux client) and leg C (BouncyHsm-win second provider),
   workspace-root `artifacts/v020-tail-windows-2026-09-16/`.
2. Windows x64 client shim — T6 leg B (Windows shim DLL +
   `cross_width_smoke.exe` vs Linux daemon, exit 0, LLP64 width line).
3. Both W2 directions — legs A and B above, including the `[listener.local]`
   rejection negative (leg B) and the `[listener.local]`-absent mTLS config
   (leg A).
4. 32-bit/mixed claim — `scripts/run-cross-width-live-test.sh` legs 1–4 plus
   the NSS-i386 second-provider legs in
   `scripts/run-cross-width-nss32-live-test.sh`, both run in nightly via
   `scripts/run-test-tiers.sh live`; the §9 "single `softhsm2-i386` lane"
   proviso is discharged by the second provider.

§9 ABI-topology → script-leg mapping (leg numbers verified against
`scripts/run-cross-width-live-test.sh`; the script runs the narrow-client
leg first):

| §9 row (client / daemon) | Script leg |
|---|---|
| x86_64 / x86_64 | leg 2 (same-width control) |
| i686 / x86_64 (32c/64b) | leg 1 (narrow-client bridge) |
| x86_64 / i686 (64c/32b) | leg 3 (reverse bridge + D4 narrowing) |
| i686 / i686 (32/32) | leg 4 (narrow-native control) |

The Consequences interim rule is discharged: tail implementation has landed,
so nonqualified-host refusal now applies only to the still-excluded hosts
(Windows GNU, Linux ARM64) plus big-endian for live FFI (BE is
build-and-QEMU proven only — see [be-qemu-tier.md](../release/be-qemu-tier.md)),
and Windows compile CI continues via the per-PR Tier 0f
`windows-client-llp64` job. PE32 left the refusal set —
`NATIVE_FFI_QUALIFIED` admits MSVC x86/32-bit with the same
`TerminateProcess` stop arm as x64 — and T2run's first green win32 run
landed the runtime qualification at the win32 CI tier stated in the
Decision section above.

Note: the Context section's
`doc/plans/2026-09-13-v0.2.0-release-program-design.md` reference is dangling
— no `doc/plans/` directory exists in this repo. It is superseded by the
release program plan and the Windows tail plan held at the workspace root;
the §9 row order above is quoted from that program design.

# ADR-0014: Re-admit Windows native and 32-bit/mixed scope to the v0.2.0 tail stretch

- **Status:** Accepted (2026-09-14, user scope decision)
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
comprehensive provider-matrix gate and before the publication gate:

1. **Windows x64/MSVC native daemon** consuming Windows provider DLLs.
2. **Windows x64 PKCS#11 client shim** (`pkcs11-proxy-ng-shim` DLL) for
   Windows applications, interoperating with a qualified Linux daemon.
3. **Linux-daemon/Windows-shim and Windows-daemon/Linux-shim legs** (W2),
   including narrowing failures and exact output/writeback in both
   directions.
4. **32-bit/mixed support claim**: Linux i686 runtime qualification beyond
   the single `softhsm2-i386` lane plus the four §9 ABI topologies.

Still excluded from v0.2.0: Windows GNU, 32-bit Windows (PE32),
macOS/ARM/big-endian runtime claims, and Wine as conformance evidence.
Message/VerifySignature/OneShot owner slots were never deferred — they are
C3M plan scope. Tag/push/publication remain separately authorized actions,
not scope items.

## Consequences

- Until tail implementation lands, nonqualified-host constructor refusal
  (`DomainError::UnsupportedPlatform`, fail before loading/discovery) stays
  in force; Windows compile CI and no-loader-attempt coverage are retained.
- Tail work follows the same evidence rules: no PASS on skipped artifacts,
  named receipts per leg, no generalization beyond named providers.
- The staged gate list gains a committed tail gate; gate 5 is no longer
  droppable.

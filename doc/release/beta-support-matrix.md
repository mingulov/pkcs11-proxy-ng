# Beta Support Matrix (`v0.1.0` public release)

This is the authoritative statement of what public `v0.1.0` supports. It
is intentionally narrow and evidence-backed: claims here are tied to repeatable
direct-vs-proxied validation, not to aspiration. Anything not listed as
**Supported** is out of scope for the beta support claim, even if it happens to
work.

The local `v0.2.0` target is unreleased. Its gateway, authorization, resilience,
and audit work is implemented locally and partially covered, but local unit and
integration coverage is not a provenance-complete transparency matrix. Therefore
this document makes no `v0.2.0` parity or public support claim.

## Selected v0.2 boundary (implementation and qualification pending)

The [native ownership contract](native-mechanism-ownership.md) qualifies live
production FFI on Linux GNU/musl x86_64/64-bit and x86/32-bit (i686), and —
via the implemented tail stretch
— on Windows x64
MSVC (`NATIVE_FFI_QUALIFIED` includes the Windows MSVC x86_64 and x86 hosts;
`crates/backend/src/ffi/native_domain.rs`). All four Linux caller/daemon
width combinations run as loaded-shim legs in
`scripts/run-cross-width-live-test.sh` (legs 1–4: 32c/64b, 64/64, 64c/32b,
32/32), with a second 32-bit provider leg in
`scripts/run-cross-width-nss32-live-test.sh` (NSS i386 softokn, 64c/32b +
32/32); nightly runs both via `scripts/run-test-tiers.sh live`, extracting
the i386 SoftHSM2 and NSS/NSPR/SQLite closures. The Windows x64 daemon plus
the Windows x64 client shim, in both interoperation directions, passed on
real Windows Server 2022: workspace-root
`artifacts/v020-tail-windows-2026-09-16/` leg A (Windows daemon +
SoftHSM2-win DLL over mTLS, driven by a Linux client), leg B (Windows shim
DLL + smoke client vs a Linux daemon, plus the `[listener.local]` rejection
negative), and leg C (BouncyHsm-win second provider, full set green).
Windows compile coverage is the per-PR Tier 0f `windows-client-llp64` job
(`cargo xwin build --target x86_64-pc-windows-msvc --all-targets`).
Still excluded: Windows GNU. Linux ARM64 is runtime-qualified
(cross-platform ubuntu-26.04-arm leg enabled, blocking). 32-bit Windows
(PE32) is qualified
at the win32 CI tier: `i686-pc-windows-msvc` build, lib suites executed
on WOW64, and a stub C provider live-loaded through `FfiBackend::load`
— the stub boundary (no production 32-bit provider runs in CI). macOS
aarch64 is runtime-qualified (T2run first green macOS leg: compare plus
backend/shim lib suites, STOP receipts included); macOS x86_64 is
load-qualified only (no CI runtime leg).
Big-endian is proven one tier below a runtime claim —
s390x build plus the QEMU suites in
[be-qemu-tier.md](be-qemu-tier.md) are green; live native FFI on BE
hosts stays excluded (s390x is not native-FFI-qualified).

v0.2 supports slot waiting only with `CKF_DONT_BLOCK`; blocking mode is local
`CKR_FUNCTION_NOT_SUPPORTED`, without polling. One supported waiter uses the
ordinary lifecycle gate. Logical clients compete for shared native per-slot
pending flags; logical Initialize does not establish an independent event
bitmap. No full native per-application event equivalence is claimed. Checked
flag/RV/slot widths and unchanged caller output on errors are mandatory.

One managed provider chain per embedding process is required, shared via Arc.
The host supplies one linked backend runtime with exclusive provider access;
unmanaged calls, another runtime copy or shared downstream aggregator aliases
are excluded. Independent chains need separate processes. Unresolved native
lifetime selects qualified raw Linux `exit_group(70)`, affecting all threads
and co-located clients without cleanup, wiping or an audit-tail guarantee.
All of this enforcement remains implementation/qualification work; the v0.1.0
support statement below is unchanged.

## Platform

| Dimension | Beta support |
| --- | --- |
| OS | Linux |
| Architecture | `x86_64` |
| 32-bit / mixed 32-64-bit | **Deferred** — not supported for the public v0.1.0 beta |

## Transport
# Beta Support Matrix

## Public v0.1.0 support

This is the support claim for the published `v0.1.0` beta. Behavior outside
this matrix may work, but has not been validated to the same standard.

| Area | Supported scope |
| --- | --- |
| SoftHSM2 | **Validated** |
| NSS softokn | **Validated** |
| Kryoptic | **Validated** |

Other providers (e.g. OpenCryptoki, TPM2, BouncyHSM) are exercised during
development but are **not** part of the beta support claim. They may work; they
are not validated to the parity bar below.

## The parity claim

> For the validated provider matrix, `pkcs11-proxy-ng` does not materially change
> observed PKCS#11 behavior compared with loading the backend module directly.

This is established by running an external PKCS#11 conformance/behavior suite
(`pkcs11-check`) twice against the same provider — once directly, once through
the proxy shim — and comparing outcomes. See
[parity-validation.md](./parity-validation.md) for the methodology and the
mismatch-triage rules.

Outcome classes compared: `passed`, `failed`, `skipped`, `xfailed`, `xpassed`,
`errors/crashes`. A mismatch is **release-blocking** unless it is proven to be
caused by test-harness/environment drift or by provider-specific behavior that is
also present without the proxy.

## Explicit non-goals for the public beta

These remain valuable but do **not** block or qualify the beta:

- General production-readiness or operational guarantees
- 32-bit and mixed-architecture support
- Provider/HSM support beyond the validated matrix
- Performance/throughput guarantees

## Known limitations

- **Backend-crash blast radius:** multiple logical clients share a backend; a
  hard backend crash can affect co-located clients. Mitigated operationally (run
  multiple daemon instances + client reconnect); see the
  [crash-isolation runbook](../runbooks/operating-pkcs11-proxy-ng.md#4a-crash-isolation--blast-radius--run-multiple-instances).
- Error semantics follow the backend; the proxy preserves exact `CK_RV` values
  and does not normalize provider-specific error precedence. See
  [doc/error-reference.md](../error-reference.md).

## How to report incompatibilities

Open an issue with: provider + version, the operation, the `CK_RV` observed
direct vs. proxied, and (if possible) the `pkcs11-check` direct and proxied
reports. Differences that are provider-specific (present without the proxy) are
documented as known issues rather than treated as proxy bugs.
| Operating system and architecture | Linux `x86_64` |
| Transport | TCP with mutual TLS; Unix-domain socket with peer-credential authentication |
| Providers | SoftHSM2, NSS softokn, Kryoptic |

Plain TCP without mTLS has no public support claim. The beta does not claim
32-bit or mixed-width support, other providers, production readiness, or
performance guarantees. See [mTLS setup](mtls-setup.md) for deployment details.

For the listed providers, the claim is that loading the proxy shim does not
materially change observed PKCS#11 behavior compared with loading the same
provider directly. [Parity validation](parity-validation.md) explains the
comparison and how differences are handled. The proxy preserves backend
`CK_RV` values, including provider-specific error precedence.

A hard backend crash can affect clients sharing that backend. The
[operator runbook](../runbooks/operating-pkcs11-proxy-ng.md#4a-crash-isolation--blast-radius--run-multiple-instances)
describes the multiple-instance and reconnect approach.

## Unreleased v0.2.0 testing scope

`v0.2.0` is a testing candidate, not a public support claim. Use one logical
client in one trusted security domain per daemon and provider instance.
Restart the daemon and provider before switching to an independent client or
domain. Do not share an instance between mutually untrusted clients.
`[proxy] max_contexts = 1` limits admission; it does not isolate native
authentication state. [Multi-client isolation](v0.3.0-scope.md) remains planned.

The candidate supports `C_WaitForSlotEvent` only with `CKF_DONT_BLOCK`.
Blocking mode returns local `CKR_FUNCTION_NOT_SUPPORTED`; clients share
native per-slot pending flags. It requires one managed provider chain per
embedding process. Independent chains require separate processes. The
[native ownership contract](native-mechanism-ownership.md) gives the exact
host, lifetime, and abnormal-stop conditions.

## What existing platform tests show

These are historical results from specific revisions. They do not qualify the
current `v0.2.0` candidate. A build, stub load, runtime test, and provider
comparison each establish a different level of coverage.

| Platform | Historical coverage and limit |
| --- | --- |
| Linux x86_64/i686 | All four loaded-shim caller/daemon width combinations, plus NSS-i386 legs. The cross-width scripts are configured in the nightly live tier; that configuration is not a current result. |
| Linux aarch64 | A runtime comparison and a configured blocking CI leg. No native stop-fire receipt. |
| Windows x64/MSVC | Real Windows daemon/shim interoperation with SoftHSM2 and BouncyHsm in historical development runs. The separate per-PR client job compiles only. |
| Windows x86/MSVC | Build, WOW64 suites, and stub-provider live load. No production 32-bit provider qualification. |
| macOS aarch64 | Runtime comparison and backend/shim library and stop tests. |
| macOS x86_64 | Load coverage only. |
| Linux s390x | [Build and QEMU suites](be-qemu-tier.md). Live native FFI and provider parity are excluded. |

Windows GNU and live big-endian FFI are excluded. The
[musl tier](musl-tier.md) has its own build, Alpine execution, and SoftHSM2
smoke evidence; it is not a full provider comparison.

The last 30-provider comparison run finished with all provider comparisons
incomplete. New candidate-bound direct/proxy results are needed before
expanding the public claim.

## Reporting an incompatibility

Open an issue with the provider and version, operation, direct and proxied
`CK_RV` values, and the direct/proxied
[pkcs11-check](https://github.com/mingulov/pkcs11-check) reports if available.
A failure also seen directly is a provider finding; a proxy-introduced
difference is investigated as a proxy defect.

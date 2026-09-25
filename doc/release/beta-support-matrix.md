# Beta Support Matrix

## Public v0.1.0 support

This is the support claim for the published `v0.1.0` beta. Behavior outside
this matrix may work, but has not been validated to the same standard.

| Area | Supported scope |
| --- | --- |
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

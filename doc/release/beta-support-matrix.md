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

The [native ownership contract](native-mechanism-ownership.md) limits live
production FFI to qualified Linux GNU/musl x86_64/64-bit and x86/32-bit (i686).
All four Linux caller/daemon width combinations require actual loaded-shim
receipts; assembly/cross-compilation and old bridge runs are insufficient.
Windows native-provider daemon support was deferred for v0.2 in ADR-0011/0006
and is re-admitted as committed tail stretch (low priority, after the
provider-matrix gate) per [ADR-0014](../adr/ADR-0014-v020-tail-platform-stretch.md):
Windows x64 daemon plus Windows x64
client shim, both interoperation directions, and the 32-bit/mixed claim.
Portable Windows client/shim/proto/types and mock-only
backend/server builds remain, including Windows-client/Linux-daemon use under
the existing client contract.

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
| 32-bit / mixed 32-64-bit | **Deferred** — not supported for the beta (see [ADR-0006](../adr/ADR-0006-32-64-bit-cross-platform-compatibility.md)) |

## Transport

| Mode | Beta support | Notes |
| --- | --- | --- |
| TCP + mTLS | **Supported (baseline)** | Mutual TLS; see [mtls-setup.md](./mtls-setup.md) |
| Unix-domain socket + peer-credential auth | **Supported** | Same-host deployments; no certificates required |
| Plain TCP without mTLS | **Not a public claim** | Intentionally undecided; only meaningful when transport security is provided externally. Do not document or advertise it as supported until an explicit decision is made. |

## Backend providers

The beta claim is **direct-vs-proxied behavioral parity** for these providers:

| Provider | Beta support |
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
  multiple daemon instances + client reconnect); see
  [ADR-0007](../adr/ADR-0007-backend-process-isolation.md).
- Error semantics follow the backend; the proxy preserves exact `CK_RV` values
  and does not normalize provider-specific error precedence. See
  [doc/error-reference.md](../error-reference.md).

## How to report incompatibilities

Open an issue with: provider + version, the operation, the `CK_RV` observed
direct vs. proxied, and (if possible) the `pkcs11-check` direct and proxied
reports. Differences that are provider-specific (present without the proxy) are
documented as known issues rather than treated as proxy bugs.

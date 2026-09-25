# Parity Validation for public `v0.1.0` (direct vs. proxied)

Public `v0.1.0`'s core claim is behavioral transparency: for the validated providers,
running through `pkcs11-proxy-ng` produces the same observable PKCS#11 behavior
as loading the backend module directly. This document describes how that is
established and how mismatches are triaged. It is reproducible by anyone with the
provider module and a PKCS#11 behavior suite (`pkcs11-check`).

The local `v0.2.0` target is unreleased. Its local unit and integration coverage
does not constitute a provenance-complete transparency matrix, so it has no
parity or public support claim. A candidate must preserve the intended check
commit, clean framework/test-data provenance, dated direct/proxied/comparison
artifacts for the three representative providers, and an explicit 30-provider
non-mock matrix before public-release language is considered.

## Method

For each validated provider, run the **same full suite twice** against the same
token and compare:

1. **Direct** — point the suite at the provider's own module
   (e.g. `/usr/lib/softhsm/libsofthsm2.so`).
2. **Proxied** — point the suite at the shim
   (`libpkcs11_proxy_ng_shim.so`) with the daemon configured to use that same
   provider as its backend.

Compare the outcome classes between the two runs:

`passed`, `failed`, `skipped`, `xfailed`, `xpassed`, `errors/crashes`.

The gate is **parity of outcome classes**, not a curated subset and not a
smoke profile. Any count mismatch is release-blocking unless it is explained
(see triage).

## Triage of mismatches

Classify every direct-vs-proxied difference as exactly one of:

- **Provider-specific behavior** already present without the proxy (e.g. a
  provider's own error-precedence choice). Not a proxy bug → document as a known
  difference.
- **Proxy bug** that blocks the beta → fix before release. Do **not** relax the
  comparison to make it pass.
- **Acceptable beta-known issue** that does not invalidate the published support
  claim → document explicitly in the [support matrix](./beta-support-matrix.md).

Exact-`CK_RV` equality with one specific provider is **not** itself the goal:
different conformant providers may legitimately return different valid
error-precedence results. The proxy's job is not to normalize those — it is to
not introduce differences of its own.

## What the proxy must not do

(See [AGENTS.md](../../AGENTS.md) §2.) The shim uses exact/raw output semantics:
it must not locally reconstruct `CKR_BUFFER_TOO_SMALL`, fabricate output lengths,
invent per-attribute results, or collapse distinct `CK_RV` values. Parity is a
property of preserving the backend's behavior, not of re-implementing it.

## Reporting

Capture, per provider, the intended check commit, clean framework/test-data
provenance, dated direct report, proxied report, and comparison result.
Differences that survive triage as proxy bugs block the release; the rest are
recorded as known differences/limitations with evidence.

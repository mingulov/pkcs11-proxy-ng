# Provider Parity Validation

For the providers in the public [v0.1.0 support matrix](beta-support-matrix.md),
the proxy should preserve the behavior observed when an application loads the
provider directly. The unreleased `v0.2.0` candidate needs fresh comparisons
before it can make the same claim.

Use [pkcs11-check](https://github.com/mingulov/pkcs11-check) for these comparisons.

## Compare direct and proxied runs

Run the same full test selection against the same provider and configuration:

1. Load the provider module directly.
2. Load `libpkcs11_proxy_ng_shim.so`, with the daemon using that provider.

Retain the exact proxy commit, test-suite and test-data revisions, provider
version, configuration, selection, and dated direct, proxied, and comparison
reports. Compare `passed`, `failed`, `skipped`, `xfailed`, `xpassed`, and
`errors/crashes` by test case. A smoke run or matching totals alone cannot
establish parity. Investigate every changed outcome before accepting a release.

## Triage of mismatches

- A failure reproduced in the direct run belongs to the provider or test
  environment. Preserve it and report provider conformance issues upstream.
- A difference introduced by the proxy is a proxy defect. Fix it before release
  if it affects the published support claim.
- An accepted limitation must be explained in the
  [support matrix](beta-support-matrix.md) with its evidence.

Do not change the proxy to hide a provider result. The proxy must preserve
backend `CK_RV` values and exact output behavior; valid providers may choose
different error precedence. See the [contributor rules](../../AGENTS.md) for
the raw-output contract.

For `v0.2.0`, the release gate also requires an explicit 30-provider non-mock
comparison matrix. Every provider must have a completed result and a recorded
disposition; incomplete runs do not count as parity evidence.

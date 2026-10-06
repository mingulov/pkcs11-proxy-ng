# Provider Parity Validation

For the providers in the public [v0.1.0 support matrix](beta-support-matrix.md),
the proxy should preserve the behavior observed when an application loads the
provider directly. The unreleased candidate needs fresh comparisons
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
- A provider family whose backend emits mechanism output only after the `*Init`
  call (delayed output) needs its own direct-vs-proxied evidence before the
  support matrix may claim it, per the delayed-output boundary recorded there.

Do not change the proxy to hide a provider result. The proxy must preserve
backend `CK_RV` values and exact output behavior; valid providers may choose
different error precedence. See the [contributor rules](../../AGENTS.md) for
the raw-output contract.

For the current candidate, the release gate also requires an explicit 30-provider non-mock
comparison matrix. Every provider must have a completed result and a recorded
disposition; incomplete runs do not count as parity evidence.

## Machine-readable evidence export

The [support matrix](beta-support-matrix.md) carries a generated
"Current pooled comparison evidence" table. Its source is the
versioned `pool-evidence/v1` export in
[`pool-evidence.json`](pool-evidence.json): one run identity, the
proxy candidate and framework commits, and one final-verdict row
per provider. `scripts/release/support_matrix.py` (stdlib only)
validates the export fail-closed — a mixed-run merge, a malformed
identity, a timestamp without an offset, a verdict/completion
contradiction (a PASS with regressions, a reasonless incomplete
row, a dispositionless FAIL), or any mock row refuses — and
rewrites only the marked table region. Regeneration PRs update the export and the
table together; `ci.yml` runs the generator in `--check` mode so
a stale table fails the gate. The export itself is produced from
the pooled runner's `matrix-summary.json` by maintainer tooling;
that merge-preserving file is never consumed directly.

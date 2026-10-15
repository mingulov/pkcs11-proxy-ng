# Qualification binding contract

The release qualification binding proves that the frozen release
subject completed provider acceptance — not just code-quality gates —
before any publication credential is used or any external mutation
happens. A quality-only URL, a mutable or unbound provider record, a
missing provider row, an incomplete or failed comparison, a wrong
source/tree/lock, a changed referenced artifact, or a mismatched
framework/provider/config/test selection refuses at the
`qualification-preflight` gate.

This contract is enforced by `scripts/release/package_qualification.py`
via `scripts/release_checks.py qualification-preflight`, with one gate
step in each pre-mutation release job (`cut-release.yml` verify,
`publish.yml` preflight, `release.yml` recover). Each gate step runs
next to that job's Q11 `environments-preflight` step: authorization
and evidence are separate gates, and both refuse before credentials
or mutations. The gate is read-only and offline: it validates local
evidence bytes against independently supplied expectations and never
calls the network.

## Evidence layout (enforced)

The qualification producer (see Q15) uploads one immutable artifact
named `provider-qualification` on the qualification run. Each gate
step downloads it read-only with `gh run download` and validates this
layout:

```text
evidence/
  receipt.json          # portable candidate-bound comparison receipt
  bundle/
    Cargo.lock          # exact release source lockfile bytes
    framework.json      # {"commit": "<pkcs11-check framework commit>"}
    corpora.json       # JSON object describing the test corpora
    provider.json       # {"providers": [<30-provider matrix>]}
    config.json         # {"config": "<effective configuration name>"}
    selection.json      # {"run_id": "<qual run>", "test_selection": "<name>"}
    comparison.json     # per-provider comparison payload
    pool-evidence.json  # the provider-selection record (pool-evidence/v1)
```

`receipt.json` follows the [portable evidence schema](./evidence-schema.md):
`schema_version` 1, kind `comparison`, classification
`candidate-bound`, and complete/passed completion. Its `artifacts`
must bind `pool-evidence.json` under the `pool_evidence` role, so the
provider-selection record sits inside the receipt's own digest
envelope. All five identity manifests must be bound artifact
references; a `not_applicable` identity is unbound and refuses.

`comparison.json` carries the `pool-comparison/v1` payload the gate
parses and reconciles with the record:

```json
{
  "format": "pool-comparison/v1",
  "run_id": "<qualification run id>",
  "config": "<effective configuration name>",
  "test_selection": "<test selection name>",
  "providers": {
    "<provider>": {"gate": "PASS", "complete": true}
  }
}
```

The receipt must bind it under the `comparison` artifact role, so
its bytes sit inside the receipt's own digest envelope alongside the
record. The qualification producer (see Q15) emits this payload; the
portable envelope hash-checks the bytes while the gate enforces the
semantics below.

## Gate policy (enforced)

Every expectation is supplied independently of the record being
validated: source commit/tree/lock from the release checkout's own git
objects (`HEAD` in `cut-release.yml` verify, `HEAD~1` — the frozen
pre-receipt parent — in `publish.yml`/`release.yml`), and the
framework commit, run identity, receipt/record digests, and
qualification URL from the workflow inputs. Nothing is copied out of
the evidence under test.

The gate requires:

- an immutable qualification record URL: credential-free HTTPS whose
  path carries an immutable subject/version marker (a full hex SHA, a
  release download/tag, a `/vX.Y.Z` segment, or an
  `/actions/runs/<id>` locator) and no floating ref segment (`main`,
  `master`, `HEAD`, `latest`, `trunk`, `stable`, `default`). The
  published v0.2.2 `/blob/main/` quality-receipt URL refuses here.
- the receipt digest and the record digest to match the pinned
  `qualification-receipt-sha256` / `qualification-record-sha256`
  inputs, and every referenced artifact byte to match the receipt.
- the receipt's source commit/tree/lock to match the frozen subject
  expectations (`validate_receipt.py`, candidate-bound).
- the provider-selection record (`support_matrix.py` validation) to
  name the frozen subject, the expected framework commit, and the
  expected run id — and to hold exactly the required 30-provider
  non-mock matrix with every row a completed `PASS`. Missing,
  swapped, extra, or mock rows refuse; `INCOMPLETE` and `FAIL` rows
  refuse, even with a recorded disposition.
- the digest-bound comparison payload (`pool-comparison/v1`) to name
  the expected run id and to hold the same required 30-provider
  matrix with every provider a completed `PASS` — reconciled row by
  row with the record. A missing `comparison` artifact role,
  unparsable bytes, a wrong format, or any incomplete, failed,
  missing, or extra row refuses even when every digest matches.
- the config/selection identity to agree across all three carriers:
  the record, the comparison, and the selection manifest all name
  the expected run id; the config manifest and the comparison name
  the same nonempty configuration; the selection manifest and the
  comparison name the same nonempty test selection.
  `framework.json` names the expected framework commit and
  `provider.json` names the required matrix.

## 30-provider matrix (enforced)

The current release policy requires this exact non-mock set. The
implementation pins it as `REQUIRED_PROVIDERS`; the pooled-runner
matrix minus `pkcs11-mock` and minus the heavy/manual OP-TEE targets:

```text
bouncyhsm corepkcs11 corepkcs11-main cosmian craton-hsm cryptech
freehsm-c jcardsim kmsp11 kryoptic kryoptic-fips kryoptic-main
nethsm nss nss-main nss-main-slot0 nss-pqc nss-pqc-slot0 nss-slot0
opencryptoki opencryptoki-master pico-hsm softhsm2
softhsm2-generated-iv softhsm2-main tpm2 wolfpkcs11 wolfpkcs11-master
wolfpkcs11-tpm wolfpkcs11-tpm-release
```

## Waiver policy

There is no waiver flag. If a narrower release claim is requested
later, it is a separate explicit product decision: the approved
scope, waivers, and unresolved rows must be recorded explicitly and
must never be represented as matrix success. Until such a decision
exists, the gate enforces the full 30-provider pass above.

## Binding schema (enforced)

`evidence-bind` writes `format_version` 2, pinning the immutable
qualification identity alongside the frozen source/candidate
identities:

```json
{
  "format_version": 2,
  "artifact": "crates-candidate-<tagCommit>-<runId>",
  "tag_commit": "<tag commit>",
  "run_id": "<candidate run id>",
  "qualification_url": "<immutable qualification URL>",
  "qualification_subject": "<frozen subject SHA>",
  "qualification_receipt_sha256": "<receipt digest>",
  "qualification_record_sha256": "<record digest>",
  "qualification_run_id": "<qualification run id>",
  "qualification_framework": "<framework commit>"
}
```

Reader compatibility is explicit: readers accept `format_version` 1
and 2 and refuse anything else. Version 1 (pre-Q12 URL-only) bindings
still read and verify their legacy fields, but any qualification
expectation refuses them — URL-only evidence no longer satisfies
publication. Unknown future versions refuse rather than silently
misreading an augmented binding. The release attestation predicate
carries the same qualification identity under its `qualification`
block.

## Durable retention

Validated evidence is archived alongside provenance with a recorded
long-term location: `release.yml` stages the exact gate-verified
bytes as `qualification-record.json`, `qualification-receipt.json`,
and `qualification-evidence.tar.gz` release assets next to
`inventory.json` and `qualification-binding.json`. The archive holds
the complete evidence directory (`receipt.json` plus the `bundle/`
lockfile, five identity manifests, comparison, and record),
preserving the relative layout the portable validator expects.
Release assets do not expire, unlike the 90-day run artifacts; the
complete acceptance record survives without depending on run
retention. The published `assets.json` manifest pins the archive's
own digest, and the binding pins the receipt/record digests inside
it, so content stays bound to the release.

To revalidate from the release assets alone: extract
`qualification-evidence.tar.gz`, take the frozen subject, framework,
run, and receipt/record digests from `qualification-binding.json`,
derive the expected tree/lock from the subject's git objects, and
rerun `qualification-preflight` as below. No qualification-run
artifact access is needed.

## Local verification

Run the gate against local fixtures (no credentials, no network, no
external mutation) with independently derived expectations:

```bash
EXPECT_TREE="$(git rev-parse 'HEAD~1^{tree}')"
EXPECT_LOCK="$(git show 'HEAD~1:Cargo.lock' | sha256sum | cut -d' ' -f1)"
python3 scripts/release_checks.py qualification-preflight \
  --evidence-dir /tmp/qual-evidence \
  --expect-commit "$FROZEN_SUBJECT" \
  --expect-tree "$EXPECT_TREE" \
  --expect-lock-sha256 "$EXPECT_LOCK" \
  --expect-framework "$FRAMEWORK_COMMIT" \
  --expect-run-id "$QUAL_RUN_ID" \
  --expect-url "$QUALIFICATION_URL" \
  --expect-record-sha256 "$RECORD_SHA256" \
  --expect-receipt-sha256 "$RECEIPT_SHA256"
```

Every negative fixture in `tests/scripts/test_release_qualification.py`
refuses through this same command. Actual production authorization
follows Q11; this gate never touches live environments, secrets, or
releases.

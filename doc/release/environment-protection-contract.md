# Production environment protection contract

The three production release jobs are each bound to a protected GitHub
environment, and each pre-mutation job re-verifies that binding against
a live API readback before any credential use or mutation:

| Release step | Environment | Gated job | Preflight gate runs in |
| --- | --- | --- | --- |
| Cut receipt commit and tag | `release-tag` | `cut` (`cut-release.yml`) | `verify` |
| Upload crates to crates.io | `crates-io` | `upload` (`publish.yml`) | `preflight` |
| Publish GitHub release assets | `release` | `publish` (`release.yml`) | `recover` |

An `environment:` declaration in YAML alone does not create a reviewer
wait. The wait exists only when the live environment carries the
protection contract below. The gate steps re-check that contract on
every run; the approval itself is granted by the required reviewer in
the Actions UI before the gated job starts.

## Protection contract (enforced)

Each production environment must satisfy all of these, verified from
the Environments API readback:

- It exists in the `GET /repos/{owner}/{repo}/environments` listing.
- Its `protection_rules` include a `required_reviewers` rule with at
  least one reviewer, where every reviewer entry is a recognized
  `User`/`Team` object with a valid type-appropriate identifier: a
  `User` carries a non-blank login or a positive id, a `Team` a
  non-blank slug or a positive id (null, mistyped, identifier-less,
  display name-only, blank-handle, or non-positive-id entries refuse,
  as does a present-but-invalid handle or id).
- Its `deployment_branch_policy` selects exactly the intended refs:
  `protected_branches: false` with `custom_branch_policies: true`
  (never null, never unrestricted, never contradictory, never
  missing/non-boolean flags), with custom name patterns matching
  exactly:

| Environment | Required reviewers | Deployment refs (selected branches/tags) |
| --- | --- | --- |
| `release-tag` | at least 1 | branch `main` only (the orchestrator runs from `main`) |
| `crates-io` | at least 1 | tag `v*` only (publication dispatches from the release tag) |
| `release` | at least 1 | tag `v*` only (release runs from the release tag) |

The `v*` tag patterns are intentionally broad at the environment layer;
the workflows additionally require full stable `refs/tags/vX.Y.Z` refs,
annotated-tag identity, and the quality receipt, which is where the
exact version check lives.

## Proposed settings (for review — not yet applied)

The exact live settings below are proposed for operator review. They
are **not** applied by any commit or workflow in this repository;
applying them is a separately authorized operator action, followed by
a dated readback and a reviewer-wait demonstration on each production
environment. Until then the next production publication must not run.

Per environment (`release-tag`, `crates-io`, `release`):

- Required reviewers: `mingulov` (repository owner; single reviewer).
- Allow specified reviewers to bypass pull-request requirements: not
  applicable (no branch protection interaction).
- Prevent self-review: off (a solo maintainer approves their own
  dispatch; the wait still blocks unattended/automated publication).
- Allow admins to bypass: off, so the reviewer wait cannot be skipped.
- Deployment branches and tags: "Selected branches and tags" with
  exactly the patterns from the contract table above and nothing else.
- No wait timer, no custom deployment protection rules.
- Preserve all unrelated environment rules and secrets, including
  `CARGO_REGISTRY_BOOTSTRAP_TOKEN` on `crates-io`, and every existing
  release and tag.

`crates-io-staging` already carries a required reviewer plus a branch
policy and is out of scope: staging success never implies production
readiness, and a staging rehearsal cannot close this production gate.

## Read-only preflight helper

`scripts/release_checks.py environments-preflight` consumes captured
API JSON and returns a fail-closed verdict. It performs no network
calls and no mutations; the workflow gate steps fetch the readback
with read-only `gh api` GETs first. To reproduce a gate locally:

```bash
REPO=owner/pkcs11-proxy-ng
gh api "repos/$REPO/environments" > /tmp/env-list.json
for env in release-tag crates-io release; do
  gh api "repos/$REPO/environments/$env/deployment-branch-policies" \
    > "/tmp/env-$env-policies.json"
done
python3 scripts/release_checks.py environments-preflight \
  --api-json /tmp/env-list.json \
  --policies-json "release-tag=/tmp/env-release-tag-policies.json" \
  --policies-json "crates-io=/tmp/env-crates-io-policies.json" \
  --policies-json "release=/tmp/env-release-policies.json"
```

Each workflow gate checks only its own environment
(`--environment <name>` with the matching `--policies-json` file).
Any of the following refuses with a nonzero exit before the gated
job's credential/mutation steps run:

| Readback defect | Verdict |
| --- | --- |
| Environment missing from the listing | refuse |
| No `required_reviewers` rule, or an empty reviewer list | refuse |
| Malformed reviewer entry (null, unrecognized type, no identifier, display name-only, blank handle, zero/negative id) | refuse |
| Null or unrestricted `deployment_branch_policy` (permissive) | refuse |
| Contradictory or malformed policy flags (both true, missing, non-boolean) | refuse |
| Custom patterns differ from the contract (mismatched, extra, or empty) | refuse |
| Policy detail unavailable while custom policies are enabled | refuse |
| Truncated policy readback (`total_count` disagrees with captured entries) | refuse |
| API JSON missing, unreadable, or unrecognized (unavailable API) | refuse |

## Plan and API limits (handled explicitly)

- This is a public repository, so required reviewers and deployment
  branch/tag policies are available on all current GitHub plans. If
  the repository ever goes private on a plan without reviewer rules,
  the rules cannot be configured and the preflight fails closed by
  design; that failure must be resolved by restoring the contract,
  never by weakening the check.
- The list-environments, get-environment, and
  list-deployment-branch-policy endpoints are readable by anyone with
  repository read access, so the default `GITHUB_TOKEN` (`contents:
  read`) suffices for the gate steps. If the API denies the readback
  for any reason, the gate fails closed with the endpoint named in
  the error; the operator re-runs the readback commands above to
  diagnose.
- Unknown extra API fields are ignored; missing required fields
  refuse. A future API shape change therefore fails loudly instead
  of passing silently.
- The deployment-branch-policy endpoint paginates
  (`per_page`/`page`). The helper verifies one captured readback and
  requires its `total_count` to equal the captured entries; a
  truncated capture refuses with the environment and endpoint named
  instead of fetching further pages. Capture with `?per_page=100`
  (or re-capture every page into one readback) so the verdict
  covers the complete policy. Production environments carry exactly
  one pattern each, so a single page always suffices; the check
  exists to fail closed rather than silently accept a partial read.
- The gate verifies configuration, not identity: it cannot prove who
  approved a past release, and the historical approval status of
  earlier releases remains unverified.

## Known gap at capture time

A read-only capture of `GET /repos/{owner}/{repo}/environments` on
2026-10-13 reported: `release-tag` and `crates-io` carry a branch
policy only with no required reviewers, and `release` carries no
protection rules and no deployment restriction. Only
`crates-io-staging` has a required reviewer. The contract above and
the gate steps close the enforcement gap once the proposed settings
are applied and demonstrated.

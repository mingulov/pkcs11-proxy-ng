# crates.io publication guide

How the eight `pkcs11-proxy-ng` crates reach crates.io, how staging
validates the path first, and how registry-source GitHub binaries follow.
This guide describes the checked-in workflows (`.github/workflows/`) and
the maintainer steps around them.

Status: release candidate. The crates are **not published** and the
source is **not release-qualified**; nothing here claims otherwise.
Package checks, smokes, and dry-runs are pre-publication gates, not
qualification or provider acceptance.

## The eight crates and four entry points

All crates publish at one synchronized version with exact `=X.Y.Z`
internal requirements (mirrored from the workspace version — see
`scripts/sync-versions.sh`). Users touch four entry points; the
other four crates are dependencies that cargo resolves automatically.

| Crate | Entry point | Install / use |
| --- | --- | --- |
| `pkcs11-proxy-ng` | gRPC proxy daemon | `cargo install pkcs11-proxy-ng --locked` |
| `pkcs11-proxy-ng-cli` | Admin/smoke CLI | `cargo install pkcs11-proxy-ng-cli --locked` |
| `pkcs11-proxy-ng-shim` | PKCS#11 module (`.so`/`.dll`) | Release bundle or OS package only — see below |
| `pkcs11-proxy-ng-client` | Rust client library | `pkcs11-proxy-ng-client = "=X.Y.Z"` dependency (substitute the release you use) |
| `pkcs11-proxy-ng-types` | (dependency) | Resolved automatically |
| `pkcs11-proxy-ng-proto` | (dependency) | Resolved automatically |
| `pkcs11-proxy-ng-backend` | (dependency) | Resolved automatically |
| `pkcs11-proxy-ng-audit` | (dependency) | Resolved automatically |

The shim is a loadable PKCS#11 module, not a Rust library: never
`cargo install` it as one. Take the shim from a GitHub release bundle
(tarball/ZIP, with provenance and notices) or an OS carrier package,
and point the application at the module file (for example
`/usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so`).

After publication the crates live at `https://crates.io/crates/<name>`
with API docs at `https://docs.rs/<name>/latest`. The docs.rs follow-up
is a maintainer step: after each release, confirm the docs build
succeeded for all eight crates and fix any rustdoc failure with a
patch release — docs failures never block the crates upload itself.

## Build prerequisites

- Rust **1.98.1** for release builds and packaging; **1.88.0** is the
  MSRV and the registry-consumer gate. `rust-toolchain.toml` pins the
  default channel; CI and publication workflows pin both explicitly.
- `protoc` **36.2** (`mise.toml` is canonical). No vendored protoc and
  no alternate code-generation path.
- Native dependencies per lane: SoftHSM2/OpenSC for provider smokes;
  clang/lld/nasm plus `cargo-xwin 0.23.1` for the Windows MSVC
  cross-build. See `doc/development.md` for the full local setup.
- Release profile (enforced on release binaries): thin LTO, symbols
  stripped, one codegen unit, unwinding panic, no incremental. Debug
  and source-build profiles are for development and CI speed, never
  for release assets.
- Fresh target/build-dir hygiene: the global Cargo
  `build.build-dir` configuration makes a fresh target directory
  alone insufficient. Every workflow job that runs cargo isolates
  **both** `CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR`; do the
  same for any local release-equivalent run.

## Stable tags only

Publication accepts only clean annotated stable tags
`vMAJOR.MINOR.PATCH` whose version equals the workspace version and
whose commit has `origin/main` ancestry. Pre-release suffixes
(`-rc1`, …) are rejected by preflight, as are lightweight tags,
dirty checkouts, and tags that do not point at the checked-out HEAD.
The frozen subject is `HEAD~1`: the tag commit itself may only add
the `CHANGELOG.md` entry and the quality receipt.

## Workflows

### Continuous gates and artifact smokes (`ci.yml`)

Every pull request executes the full CI: formatting, audit/deny,
packaging smoke, shellcheck, build-and-test
(with Clippy), MSRV, i686/LLP64/musl lanes, plus source-bound
package/archive/consumer gates and archive-mode binary builds with
notices and bundles. A fail-closed aggregate refuses unless every
required job succeeds.

Three artifact-smoke lanes run on the packaged output (never on
workspace binaries):

- Alpine APK: real carrier build, per-package install/remove
  round-trip, notice/provenance/material carriage, installed-hash
  verification against APK payload bytes, and a SoftHSM
  session/login/keygen/RSA-sign flow through the installed daemon
  plus shim. Workspace APK output is CI smoke evidence, not a
  release asset; full Amazon RPM build/install is not covered by
  the GitHub gate.
- Linux tarball: extracts the exact staged bundle, verifies
  hashes/materials, and runs daemon/shim/CLI plus a provider-backed
  operation from the extracted paths.
- Windows ZIP: on a native Windows runner, extracts the exact ZIP and
  executes the packaged daemon/CLI and shim DLL through a real
  provider-backed session. Cross-compiled LLP64 coverage is not a
  substitute for this native lane.

Limits: the broader cross-platform lane stays a KAT-only
direct/proxied differential (pinned `pkcs11-check`), not general
equality; no full provider-matrix sweep runs here. Smokes prove the
packaged artifacts work; they are not provider qualification.

### Release orchestrator (`cut-release.yml`)

One GUI dispatch (Actions → cut-release → Run workflow) carries the
whole pre-publication path, so the tag, the receipt, and the publish
inputs are produced once instead of typed three times. Inputs:
`version` (stable `MAJOR.MINOR.PATCH`, no `v` prefix), `mode`,
`package`, and the qualification URL/subject (required for upload
modes). Prepare `main` first with a normal PR containing the dated
`CHANGELOG.md` entry; the orchestrator adds or refreshes only the receipt.

1. `verify` checks out `main`, validates the inputs, refuses if the
   tag already exists, runs all eight receipt gates (fmt, check,
   test, clippy, msrv, audit, deny, release_dry_run) plus the
   subject/version/CHANGELOG/packaging-mirror checks, then writes
   the quality receipt for the recorded HEAD SHA and uploads it.
2. `cut` waits on the protected `release-tag` environment (create it
   with required reviewers — this is the separate approval to tag),
   re-verifies HEAD is unchanged and the tag still absent, commits
   the receipt-only delta, re-verifies it with
   `verify-quality-receipt.sh`, creates the annotated tag, pushes
   commit plus tag, then starts CI on the new tag (token pushes
   trigger no runs, and publish refuses until that aggregate is
   green). Plain pushes only; races and drift refuse, tags are
   never moved.
3. `dispatch-publish` waits for the green `CI success (fail-closed
   aggregate)` check on the new tag commit via the pinned
   `lewagon/wait-on-check-action` (success-only conclusions; red,
   missing, or timed-out CI refuses before anything dispatches),
   then runs `publish.yml` from the new tag with the inputs passed
   through. Upload and release approvals still gate their own
   environments there; nothing here bypasses them.

The cut job pushes with `GITHUB_TOKEN`, which works while `main` is
unprotected (tag pushes from automation do not trigger the
tag-push validation run; the orchestrator's own checks plus
publish's preflight cover that ground). Protecting `main` later
requires swapping in an App token with bypass for the cut job.

Partial states recover by hand: tag pushed but publish never
dispatched → dispatch `publish.yml` manually; commit pushed but tag
missing → push the annotated tag manually, then dispatch.

### Production publication (`publish.yml`)

Manual dispatch only, run **from the tag** (or a ref whose HEAD equals
the tag commit). Inputs: `mode` (`dry-run` default, `bootstrap`,
`trusted`), `package` (`workspace` default, or exactly one crate),
exact `tag`, and the qualification URL/subject for upload modes. A tag
push runs validation only and can never upload.

1. Preflight validates ref/source/version/receipt/ancestry/qualification,
   publishes the approval inputs to the run summary, then requires the
   tag commit to already carry a green fail-closed aggregate from a CI
   run (reusable calls cannot schedule here, so publication reuses the
   tag commit's own CI instead of re-running the matrix).
2. The candidate job stages exactly one immutable pre-auth artifact,
   `crates-candidate-<tagCommit>-<runId>` — all eight archives,
   inventory, SHA256SUMS, and the qualification-binding JSON —
   with overwrite disabled and 90-day retention. It refuses unless
   the CI-built archives bind to the tag commit.
3. The upload job (the only `id-token: write` holder, under the
   protected `crates-io` environment) re-checks every guard, repackages
   all eight archives without compiling, byte-compares them against the
   pre-auth inventory, classifies registry state, uploads the bounded
   selection in dependency order, and reads back published checksums.
   Post-upload evidence is retained even on failure.
4. A separate read-only job verifies all eight published checksums and
   runs full registry consumers, then emits explicit `complete=true`.

Only that complete success may automatically call the release
workflow. Partial publication never starts binaries.

### Environments, bootstrap, and trust

- `crates-io`: protected environment with required reviewers and tag
  restrictions, bound to the source-specific qualification record
  (exact HTTPS URL plus the frozen-subject SHA). Approval happens
  against the preflight summary, never against descriptions.
- First publication uses `bootstrap` mode with the
  `CARGO_REGISTRY_BOOTSTRAP_TOKEN` secret. Afterwards, configure one
  trusted-publishing trust record per crate (eight records) and use
  `trusted` mode, which authenticates via the pinned official
  OIDC action. No credentials appear in logs or artifacts.
- `crates-io-staging`: separate protected environment, separate
  staging account/endpoint and token. Staging uploads only the
  generated dependency-free probe crate after main-only manual
  dispatch, source/ref/probe rechecks, endpoint binding, and a
  dry-run that proves the endpoint resolves. Ordinary dry-runs stay
  upload-free. Staging success does not imply production readiness.

### Registry-source binaries and GitHub release (`release.yml`)

No tag-push trigger. The workflow runs via API dispatch after
explicit complete success (reusable calls cannot schedule here), or
as an exact-tag manual retry with `candidate_run_id` plus matching
qualification inputs; the manual path never republishes crates.

Recovery validates the referenced publish run (same repository,
publish workflow path, manual event, tag-peeled head SHA) and
requires exactly one matching unexpired pre-auth artifact through
read-only access — missing, expired, or ambiguous evidence refuses,
and expected hashes are never reconstructed from registry data.
The job then rechecks source, tag object and peeled commit,
receipt, qualification, candidate binding, registry state, and
consumers before any binary job starts.

Binary jobs build both targets from the exact published crates.io
archives plus their original packaged locks (checkout source is
never an input), generate notices, and stage deterministic bundles
(tag-date-pinned) with provenance. They carry no registry token
and no OIDC permission. Native Linux/Windows smokes run the
staged bundles before publication.

The final `publish` step runs under the separately approved
protected `release` environment and is the only writer. Assets
publish through one combined path: the prepared bundles and
candidate evidence are compared against the exact-tag release —
identical assets are retained, missing assets are added, and
divergent bytes refuse with both digests named. Retries never
replace or delete assets and never move tags; a retry where
everything already matches uploads nothing.

Every published bundle carries a Sigstore attestation binding it
to the release tag, tag commit, and qualification — generated in
the `publish` job after the compare gate, over the full prepared
set including retained assets, so retries attest every bundle on
the release. The predicate claims release binding only, never
"built by this workflow run" (binaries come from registry
archives). Verify a downloaded bundle with:

```bash
gh attestation verify <bundle> \
  -R mingulov/pkcs11-proxy-ng \
  --predicate-type https://github.com/mingulov/pkcs11-proxy-ng/release-binding/v1 \
  --signer-workflow mingulov/pkcs11-proxy-ng/.github/workflows/release.yml
```

## Recovery

- Individual member: dispatch `publish.yml` with `package` set to the
  one crate name (same tag and qualification inputs). The upload job
  prints the exact full follow-up dispatch command afterwards.
- Last-member recovery obeys the same complete-success rule: binaries
  start only after a later run verifies all eight plus consumers.
- Partial state vs hash mismatch: `registry-verify` distinguishes
  missing versions (absent) from network failures (errors) and from
  published-but-divergent bytes (refusal). Re-run the readback before
  assuming registry state.
- Full registry-only check without uploading: run `registry-verify`
  plus `registry-consumer` locally against the candidate inventory (or
  rely on a real dispatch's `verify` job, or the release
  `registry-recheck`) to confirm all eight published checksums and
  consumer builds at any time. A `dry-run` dispatch validates guards,
  CI, and the candidate only — its `verify` job is skipped because
  `upload` never runs.

## Evidence retention and escrow

The pre-auth candidate, post-upload evidence, recovered evidence,
smoke logs, and staging evidence upload as run artifacts with
90-day retention and overwrite disabled. Ninety days is a floor,
not an archive: before it lapses, the maintainer must escrow a
copy of the pre-auth candidate artifact (eight archives, inventory,
SHA256SUMS, qualification binding) plus the published release
assets into maintainer-controlled long-term storage, recorded in
the release notes. Longer-term recovery from escrow is a
separately reviewed procedure — there is no automatic
reconstruction of expected hashes from registry data.

## Checklist pointer

The freeze/tag/approval/receipt procedure, including the exact
verification commands and the per-release evidence boxes, lives in
the [`0.x` beta release checklist](./0.x-beta-release-checklist.md).
This guide explains the machinery; the checklist records the run.

# Release recovery runbook

How to recover a failed or wedged GitHub release without tribal
knowledge. The normal pipeline is described in
[crates-io-publishing.md](crates-io-publishing.md); this page is only
about what to do when it breaks.

## Pipeline recap

`cut-release.yml` qualifies a candidate, `publish.yml` stages it, and
a manual `release.yml` dispatch (`tag`, `candidate_run_id`,
`qualification-url`, `qualification-subject`) rebuilds every bundle,
rechecks evidence, and uploads assets with
`scripts/release-upload.sh`. The release goes **live on creation** —
there is no draft step — so a failed run still leaves a public
release behind; recovery adds the missing assets to it, it never
restarts publication.

## Golden rules

1. **Never re-run after a workflow fix.** A rerun reuses the
   workflow file frozen at the original run, so it replays the same
   bug. After a workflow-file or uploader-script change, merge to
   `main` and start a **fresh dispatch**
   (`gh workflow run release.yml --ref main ...`). That picks up the
   workflow file from `main` plus `scripts/release-upload.sh`
   (fetched from the workflow ref) — but every other helper
   (`release_checks.py`, smoke and verify scripts) still runs from
   the tag checkout, so a fix to any of those requires re-cutting
   the tag to include it.
2. **Dispatch inputs are exact.** `release.yml` accepts exactly four
   `workflow_dispatch` inputs; anything else is rejected with HTTP 422.
   Recover them from the `dispatch-inputs-<tag>-<run>-<attempt>`
   artifact the `publish.yml` run uploaded (see below; only the
   publish run knows its own run id, which is the `candidate_run_id`),
   or — for runs that predate it — from the failed run's first job
   log, which echoes `CANDIDATE_RUN_ID`, `QUALIFICATION_URL`, and
   `QUALIFICATION_SUBJECT` in its environment.
3. **Uploads are idempotent.** The compare step stages only missing
   assets and refuses divergent bytes; the uploader rewrites identical
   bytes via `--clobber` and retries transient stalls (5 attempts,
   600 s per-attempt window). Re-dispatching is always safe.

## Failure playbook

**Divergent refusal in the compare step.** Some staged asset differs
from the bytes already on the release. Identify the asset in the step
output: if the released copy is poisoned (v0.2.2 shipped an
`assets.json` containing a self-entry with an empty hash), delete just
that asset and dispatch fresh — the run retains the good assets and
uploads the rest:

```bash
gh release delete-asset <tag> <asset>
gh workflow run release.yml --ref main \
  -f tag=<tag> -f candidate_run_id=<id> \
  -f qualification-url=<url> -f qualification-subject=<sha>
```

**Exit 127 in the publish job.** A repo script is missing from the
workspace. The publish job checks out the release *tag* for notes,
and the tag predates any file added after it was cut — workflow
scripts must come from the workflow ref via the side checkout (see
`.release-uploader` in `release.yml`), never from the tag checkout.

**Upload timeouts.** `uploads.github.com` stalls are retried inside
the uploader; a persistent stall fails the run only after all
attempts. Just dispatch fresh — completed assets are retained.

## dispatch-inputs artifact

`publish.yml`'s `dispatch-release` job uploads a
`dispatch-inputs-<tag>-<run>-<attempt>` artifact holding the exact
`gh workflow run` arguments above, so recovery never requires
log-diving. Download it, review the values, paste the command. It
targets `main` (see the in-file comment) so post-tag workflow fixes
apply. The name carries the publish run id and attempt so a retried
dispatch job never collides with an earlier attempt's artifact.

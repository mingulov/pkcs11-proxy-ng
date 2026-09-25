# Receipt tooling decision (T7): deleted release-prep line expired

Normative input routing for TX (G-3 quality receipt) and T9 (matrix
receipts). Verified 2026-09-19 on `dev`.

## Decision

The deleted release-prep line (tip `b28753c`) is formally **expired**.
It is provably unrecoverable, and nothing pending depends on it: the
current tree already carries working receipt tooling.

Unrecoverability proof (re-run on `dev`):

```text
$ git cat-file -t b28753c
fatal: Not a valid object name b28753c        # exit 128: no such object
$ git for-each-ref
882ba3e ... refs/heads/dev
f1a06e6 ... refs/heads/main
a2aab6c ... refs/remotes/origin/dev
a48b60b ... refs/remotes/origin/main
a840418 ... refs/tags/v0.1.0                  # no codex/* ref anywhere
```

No object, no origin ref, no reflog trace. "Recover it" is not an option.

## Current-tree tooling works (no fix needed)

- `tests/scripts/test_release_receipts.py`: **26 passed, 219 subtests
  passed** (`python3 -m pytest tests/scripts/test_release_receipts.py -q`).
- End-to-end CLI exercises against
  `tests/scripts/fixtures/release-receipts/`:
  - PASS: exit 0, `valid candidate-bound proxy-provider receipt`.
  - FAIL (wrong `--source-commit`): exit 1,
    `invalid receipt: source.commit mismatch with expected candidate binding`.
  - FAIL (tampered artifact byte): exit 1,
    `invalid receipt: artifacts.comparison artifact sha256 mismatch: comparison.json`.

## TX / G-3: build fresh, consume nothing from `scripts/release/`

G-3 (umbrella `doc/plans/2026-09-16-v020-gates.md`, Task G-3) is a
**markdown receipt plus a workflow shell step** — exact-commit SHA
equality (`subject_sha` vs `git rev-parse HEAD`) and a `pass`-prefix
check on every gate field. It does not use the JSON evidence envelope
and does not invoke `validate_receipt.py` in any form.

- TX creates fresh: `doc/release/v0.2.0-quality-receipt.md` (template,
  values `TBD-BY-G7`) and the `Verify quality receipt` step in
  `.github/workflows/release.yml`, exactly per the G-3 spec.
- TX consumes from the current tree: **nothing** under
  `scripts/release/` or `doc/release/evidence-schema.md` (read them
  only for naming consistency if desired).

## T9: consume the current-tree JSON tooling as-is

T9's matrix receipts use the version-1 envelope. Consume, do not rebuild:

- Schema contract: `doc/release/evidence-schema.md`.
- Validator: `scripts/release/validate_receipt.py` (stdlib only,
  Python 3.9+; CLI exit 0 valid / 1 invalid / 2 usage).
- Shape example: `tests/scripts/fixtures/release-receipts/complete-candidate.json`
  plus its adjacent `bundle/` (envelope illustration only, not evidence).
- Regression tests: `tests/scripts/test_release_receipts.py`.

Canonical candidate validation command (bindings from the independently
selected candidate, never copied out of the receipt):

```bash
python3 scripts/release/validate_receipt.py /evidence/receipt.json \
  --artifact-root /evidence/bundle --require-candidate \
  --source-commit "$CANDIDATE_COMMIT" --source-tree "$CANDIDATE_TREE" \
  --lock-sha256 "$CANDIDATE_LOCK_SHA256"
```

## Dangling references

Grep of the submodule for `forthcoming`, `release-prep`, `b28753c`,
`codex/`, and receipt `TBD` claims returns nothing: no dangling
"forthcoming receipt tooling" reference exists. No cleanup needed.

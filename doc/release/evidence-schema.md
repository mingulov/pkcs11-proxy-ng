# Portable release evidence receipts

Schema version **1** is the shared envelope for release evidence. The validator
is `scripts/release/validate_receipt.py`; it uses only the Python 3.9+ standard
library and requires neither the planning workspace nor a Git checkout.
Receipts and their artifacts belong in a separate, immutable evidence bundle.

## Envelope

The following fields are required. Unknown fields, duplicate JSON keys,
nonstandard JSON numbers, and unsupported versions or kinds are rejected.

| Field | Version 1 contract |
| --- | --- |
| `schema_version` | Integer `1` (not a boolean). |
| `kind` | `environment`, `build`, `direct-provider`, `proxy-provider`, `comparison`, `abi`, `transport`, `privacy`, `performance`, `package`, or `standalone`. |
| `classification` | `diagnostic` or `candidate-bound`. |
| `source` | Object containing `commit`, `tree`, and `lock`. Commit/tree are full lowercase Git object IDs (40 or 64 hex characters); `lock` is an artifact reference to the exact release source `Cargo.lock`. |
| `toolchain` | Object containing nonempty strings `rustc`, `cargo`, and `target`. Record complete version output and the exact target triple. Other tool versions belong in a hashed environment manifest. |
| `binaries` | Object mapping role names, e.g. `daemon` and `shim`, to artifact references. An empty object explicitly records that no release binary was used. |
| `identities` | Object with exactly `framework`, `corpora`, `provider`, `config`, and `selection`. Each value is an artifact reference or `{ "not_applicable": "specific reason" }`. Omitting a category is invalid. |
| `completion` | Object with boolean `complete` and `outcome`: `passed`, `failed`, or `incomplete`. |
| `artifacts` | Nonempty object mapping evidence role names to artifact references. Include raw results, execution/resource receipts, comparisons, and logs as applicable. |

An artifact reference is exactly `{ "path": "relative/file", "sha256":
"64-lowercase-hex-digits" }`. Paths are relative to the explicitly supplied
artifact root, using `/` separators. Every component is validated using the
same rules on every host. Absolute paths, empty components, `.`, `..`, ASCII
control characters U+0000–U+001F and U+007F, Windows-forbidden characters
`< > : " \ | ? *`, and components ending in a dot or space are rejected.
Device basenames are rejected case-insensitively, including before an extension:
`CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, and `COM`/`LPT` followed by
one of `1`–`9`, `¹`, `²`, or `³`. Before this check, trailing ASCII spaces are
removed from the stem preceding the first dot, so `CON .json` and `NUL  .txt`
are also rejected. These rules also reject drive prefixes.
Symlinks and non-regular files are rejected.

Across all lock, binary, identity and artifact references, distinct path
spellings must not collide after Unicode `str.casefold()`. Thus `Result.json`
and `result.JSON` cannot coexist in a receipt, even on a case-sensitive host.
Trailing-dot/space normalization cannot introduce another alias because those
components are already forbidden. Exact repeated path spellings remain valid;
no Unicode canonical normalization is applied.
All references, including locks, binaries and identity manifests, are read back
and SHA-256 checked. Distinct roles can reference the same file. Do not modify
the evidence directory concurrently with validation.

Identity manifests retain the applicable structured facts: framework commit,
tree and lock; each corpus revision/archive digest and acquisition status;
provider image digest, module digest and token/slot identity; effective
configuration; and collection/selection locks identifying exact work units.
The envelope hashes these files without interpreting their inner schemas.
Provider planners and release gates must validate those schemas and determine
whether a `not_applicable` declaration is appropriate for the requested claim.
No secrets or authentication credentials belong in these manifests.

The small [test fixture](../../tests/scripts/fixtures/release-receipts/complete-candidate.json)
illustrates the shape. Its adjacent `bundle/` contains distinct dummy payloads
and digests for the lock, binary, five identities and comparison. A local
`.gitattributes` prevents line-ending conversion from changing those bytes.
These fixtures exercise the envelope only; they are not real release evidence.

## Classification and completion

`diagnostic` records are historical or exploratory evidence. They may record
failed or incomplete work and do not satisfy candidate gates. Validation never
edits or promotes a receipt. Historical evidence must be rerun against the
candidate inputs to create a new candidate receipt; changing its label is not
promotion. A failed parent round remains failed even if an individually
completed provider has a diagnostic receipt.

`candidate-bound` requires `complete: true`, `outcome: "passed"`, and independent
expected source commit, source tree, and Cargo.lock digest. A failed candidate
attempt is retained as diagnostic evidence. Here `passed` means the receipt's
evidence check succeeded according to its kind, not that every provider test
returned PASS. Expected provider FAIL/XFAIL results require the corresponding
comparison and classification evidence. Totals and finalization flags alone
do not prove completion.

## Validation

For a candidate, supply values from the independently selected release source
and lockfile, not values copied out of the receipt being validated:

```bash
python3 scripts/release/validate_receipt.py /evidence/receipt.json \
  --artifact-root /evidence/bundle --require-candidate \
  --source-commit "$CANDIDATE_COMMIT" --source-tree "$CANDIDATE_TREE" \
  --lock-sha256 "$CANDIDATE_LOCK_SHA256"
```

`--require-candidate` rejects diagnostic classification. Even without this
flag, a candidate-bound receipt requires all three independent expected
bindings. Diagnostic integrity checks can omit them, or supply any expected
binding to enforce it. Paths are independent of the process working directory.

Exit status is `0` for a valid envelope with intact referenced artifacts, `1`
for invalid evidence/read errors, and `2` for command-line usage errors.
The importable `validate_receipt(receipt, artifact_root, *, expected_commit=None,
expected_tree=None, expected_lock_sha256=None, require_candidate=False)` raises
`ReceiptError` on invalid evidence and returns `None` on success.

This is an integrity check, not a signature or full release authorization.
The caller must trust the receipt producer and pin the receipt's own hash in
the release manifest. An attacker able to rewrite both receipt and evidence
can replace their hashes. Release policy additionally checks required kinds,
targets, binaries, manifest contents, provenance, resource limits, test-unit
completion, and comparison results. Validation here alone does not establish
those claims or prove that a claimed source produced a binary.

## Invalidation

Changing source commit/tree, Cargo.lock, toolchain/target, any release binary,
framework or corpus lock, provider image/module/slot, effective configuration,
or exact selection invalidates affected evidence. Create a fresh receipt after
rerunning the affected check; do not rewrite a previous receipt's bindings.
Changing or removing any referenced bytes makes the existing receipt invalid.
Copying an intact bundle preserves validity because paths are relative.
New envelope fields or kinds require a schema/version implementation change;
writers must not silently invent extensions that older validators ignore.

#!/usr/bin/env python3
"""Regenerate the pooled-evidence table in beta-support-matrix.md.

The private pooled runner compares direct-vs-proxied ``pkcs11-check``
runs per provider and writes ``matrix-summary.json``. That file
merges rows across invocations, so it is not directly consumable:
the pipeline exports a versioned ``pool-evidence/v1`` document with
one run identity, and this script (stdlib only, no private imports)
validates the export and rewrites only the marked table region of
``doc/release/beta-support-matrix.md``.

Export contract (``pool-evidence/v1``)::

    {
      "format": "pool-evidence/v1",
      "run_id": "pooled-2026-10-06-03-00",
      "candidate": {"commit": "<40-hex>", "describe": "v0.2.3-4-g1234abcd"},
      "framework": {"commit": "<40-hex>"},
      "generated_at": "2026-10-06T03:14:00Z",
      "evidence_root": "https://example.invalid/runs/pooled-.../",
      "providers": {
        "<provider>": {
          "run_id": "<must equal the top-level run_id>",
          "gate": "PASS" | "FAIL" | "INCOMPLETE",
          "complete": true | false,
          "regressions": 0, "known": 0, "improvements": 0,
          "both_nonpass": 0, "direct_only": 0, "proxy_only": 0,
          "incomplete": 0,
          "incomplete_reasons": ["..."],
          "disposition": "recorded triage for FAIL rows",
          "evidence": "relative link to comparison.json"
        }
      }
    }

Validation is fail-closed: a wrong ``format``, a row whose
``run_id`` differs (mixed-run merge), a malformed commit, a bad
gate, a negative or boolean count, a timestamp without an explicit
offset, or any ``pkcs11-mock`` row refuses. Verdict and
completion must agree: ``PASS`` needs a completed row with zero
regressions, zero incompletes, no reasons, and no disposition;
``FAIL`` needs a completed row with a recorded disposition (a
zero-count FAIL is allowed — the disposition explains it, e.g. a
crash mismatch outside these counts); ``INCOMPLETE`` needs an
incomplete row with reasons and no disposition. Any row with a
nonzero ``incomplete`` count needs reasons. An empty ``providers``
map is valid and renders a "no evidence yet" placeholder; run
identity is then vacuous and unchecked.

Usage::

    python3 scripts/release/support_matrix.py [--evidence PATH]
        [--matrix PATH] [--check]

``--check`` exits nonzero when the checked-in table differs from a
fresh render (the ``ci.yml`` gate). Paths default to the
``doc/release/`` files and resolve against the repository root.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

FORMAT = "pool-evidence/v1"
GATES = ("PASS", "FAIL", "INCOMPLETE")
COUNTS = ("regressions", "known", "improvements", "both_nonpass",
          "direct_only", "proxy_only", "incomplete")
PROVIDER_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
BEGIN = "<!-- pool-evidence:begin -->"
END = "<!-- pool-evidence:end -->"


class SupportMatrixError(ValueError):
    """A fail-closed export validation refusal."""


def load_evidence(path):
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as error:
        raise SupportMatrixError(f"cannot read {path}: {error}")
    try:
        evidence = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SupportMatrixError(f"{path} is not valid JSON: {error}")
    return validate(evidence)


def validate(evidence):
    if not isinstance(evidence, dict):
        raise SupportMatrixError("export must be a JSON object")
    if evidence.get("format") != FORMAT:
        raise SupportMatrixError(f"format must be {FORMAT!r}")
    providers = evidence.get("providers")
    if not isinstance(providers, dict):
        raise SupportMatrixError("providers must be an object")
    if not providers:
        return evidence
    run_id = evidence.get("run_id")
    if not run_id or not isinstance(run_id, str):
        raise SupportMatrixError("run_id must be a non-empty string")
    for section in ("candidate", "framework"):
        commit = evidence.get(section, {}).get("commit")
        if not isinstance(commit, str) or not COMMIT_RE.match(commit):
            raise SupportMatrixError(
                f"{section}.commit must be a 40-char hex SHA")
    generated_at = evidence.get("generated_at")
    if not isinstance(generated_at, str) or not _parse_time(generated_at):
        raise SupportMatrixError("generated_at must be an RFC 3339 time")
    for name, row in providers.items():
        _validate_row(name, row, run_id)
    return evidence


def _parse_time(value):
    # An explicit offset is required: a bare date or a naive
    # timestamp leaves the run's instant ambiguous, so it refuses
    # even though fromisoformat would accept it.
    try:
        parsed = datetime.datetime.fromisoformat(
            value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def _validate_row(name, row, run_id):
    where = f"provider {name!r}"
    if not PROVIDER_RE.match(name):
        raise SupportMatrixError(f"{where}: invalid provider name")
    if name == "pkcs11-mock":
        raise SupportMatrixError(f"{where}: mock is never parity evidence")
    if not isinstance(row, dict):
        raise SupportMatrixError(f"{where}: row must be an object")
    if row.get("run_id") != run_id:
        raise SupportMatrixError(
            f"{where}: run_id {row.get('run_id')!r} does not match "
            f"export run {run_id!r} (mixed-run merge)")
    gate = row.get("gate")
    if gate not in GATES:
        raise SupportMatrixError(f"{where}: gate must be one of {GATES}")
    if not isinstance(row.get("complete"), bool):
        raise SupportMatrixError(f"{where}: complete must be a boolean")
    for count in COUNTS:
        value = row.get(count)
        if isinstance(value, bool) or not isinstance(value, int):
            raise SupportMatrixError(f"{where}: {count} must be an integer")
        if value < 0:
            raise SupportMatrixError(f"{where}: {count} must be >= 0")
    reasons = row.get("incomplete_reasons", [])
    if (not isinstance(reasons, list)
            or not all(isinstance(each, str) and each
                       for each in reasons)):
        raise SupportMatrixError(
            f"{where}: incomplete_reasons must be a list of non-empty strings")
    disposition = row.get("disposition", "")
    if not isinstance(disposition, str):
        raise SupportMatrixError(f"{where}: disposition must be a string")
    complete = row["complete"]
    if gate == "PASS":
        if not complete:
            raise SupportMatrixError(f"{where}: PASS needs complete=true")
        if row["regressions"] != 0 or row["incomplete"] != 0:
            raise SupportMatrixError(
                f"{where}: PASS needs zero regressions and zero incompletes")
        if reasons:
            raise SupportMatrixError(f"{where}: PASS takes no incomplete_reasons")
        if disposition:
            raise SupportMatrixError(f"{where}: PASS takes no disposition")
    elif gate == "FAIL":
        if not complete:
            raise SupportMatrixError(f"{where}: FAIL needs complete=true")
        if not disposition:
            raise SupportMatrixError(
                f"{where}: FAIL rows need a recorded disposition")
    else:  # INCOMPLETE
        if complete:
            raise SupportMatrixError(f"{where}: INCOMPLETE needs complete=false")
        if not reasons:
            raise SupportMatrixError(
                f"{where}: incomplete rows need incomplete_reasons")
        if disposition:
            raise SupportMatrixError(f"{where}: INCOMPLETE takes no disposition")
    if row["incomplete"] > 0 and not reasons:
        raise SupportMatrixError(
            f"{where}: nonzero incomplete count needs incomplete_reasons")
    evidence = row.get("evidence", "")
    if evidence is None:
        raise SupportMatrixError(f"{where}: evidence must be a string")
    if evidence and not isinstance(evidence, str):
        raise SupportMatrixError(f"{where}: evidence must be a string")


def _cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render(evidence):
    providers = evidence.get("providers", {})
    if not providers:
        return "*No pooled comparison evidence recorded yet.*\n"
    candidate = evidence["candidate"]
    describe = candidate.get("describe", candidate["commit"][:12])
    lines = [
        f"*Pooled comparison evidence — run `{evidence['run_id']}` · "
        f"candidate `{describe}` (`{candidate['commit']}`) · "
        f"framework `{evidence['framework']['commit']}` · "
        f"generated {evidence['generated_at']}. Counts on incomplete "
        "rows are lower bounds, not parity evidence.*",
        "",
        "| Provider | Gate | Regr | Known | Improv | D-only | P-only | "
        "Incompl | Notes |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    root = evidence.get("evidence_root", "")
    for name in sorted(providers):
        row = providers[name]
        notes = row.get("disposition", "")
        if not notes and row.get("incomplete_reasons"):
            notes = row["incomplete_reasons"][0]
        link = row.get("evidence", "")
        if link and root:
            notes = f"{notes} [evidence]({root.rstrip('/')}/{link})".strip()
        elif link:
            notes = f"{notes} ({link})".strip()
        lines.append(
            f"| `{_cell(name)}` | {row['gate']} | {row['regressions']} | "
            f"{row['known']} | {row['improvements']} | "
            f"{row['direct_only']} | {row['proxy_only']} | "
            f"{row['incomplete']} | {_cell(notes)} |")
    lines.append("")
    return "\n".join(lines)


def replace_region(text, fragment):
    if text.count(BEGIN) != 1 or text.count(END) != 1:
        raise SupportMatrixError("matrix must contain each marker once")
    if text.index(BEGIN) > text.index(END):
        raise SupportMatrixError("markers out of order")
    before, rest = text.split(BEGIN, 1)
    _, after = rest.split(END, 1)
    return f"{before}{BEGIN}\n{fragment}{END}{after}"


def repo_root():
    return Path(__file__).resolve().parents[2]


def resolve(path):
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return repo_root() / candidate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence",
                        default="doc/release/pool-evidence.json")
    parser.add_argument("--matrix",
                        default="doc/release/beta-support-matrix.md")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when the table differs from a render")
    args = parser.parse_args(argv)
    try:
        evidence = load_evidence(resolve(args.evidence))
        matrix_path = resolve(args.matrix)
        current = matrix_path.read_text(encoding="utf-8")
        updated = replace_region(current, render(evidence))
    except (SupportMatrixError, OSError) as error:
        print(f"support_matrix: error: {error}", file=sys.stderr)
        return 1
    if updated == current:
        return 0
    if args.check:
        print("support_matrix: error: generated table is stale; "
              "regenerate with scripts/release/support_matrix.py",
              file=sys.stderr)
        return 1
    matrix_path.write_text(updated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
